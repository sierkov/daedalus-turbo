/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/cardano/network.hpp>
#include <dt/config.hpp>
#include <dt/sync/p2p.hpp>

namespace daedalus_turbo::sync::p2p {
    using namespace daedalus_turbo::cardano::network;
    using namespace daedalus_turbo::cardano;

    struct syncer::impl {
        impl(indexer::incremental &cr, cardano::network::client &client, peer_selection &ps)
            : _cr { cr }, _client { client }, _peer_selection { ps }, _raw_dir { _cr.data_dir() / "raw" }
        {
            std::filesystem::create_directories(_raw_dir);
        }

        void sync(std::optional<cardano::slot> max_slot)
        {
            std::optional<blockchain_point> local_tip {};
            auto last_chunk = _cr.last_chunk();
            if (last_chunk)
                local_tip = blockchain_point { last_chunk->last_block_hash, last_chunk->last_slot };
            for (;;) {
                const auto continue_from = _fetch_iteration(local_tip, max_slot);
                if (!continue_from)
                    break;
                local_tip = continue_from;
            }
            _save_last_chunk(true);
        }
    private:
        struct ready_chunk {
            std::string path {};
            std::string name {};
            uint64_t size {};
            block_hash hash {};
        };

        indexer::incremental &_cr;
        cardano::network::client &_client;
        peer_selection &_peer_selection;
        std::filesystem::path _raw_dir;
        uint8_vector _last_chunk {};
        std::optional<uint64_t> _last_chunk_id {};
        std::vector<ready_chunk> _ready_chunks {};
        uint64_t _ready_data_size = 0;

        std::optional<blockchain_point> _fetch_iteration(const std::optional<blockchain_point> &start_point, const std::optional<slot> &max_slot)
        {
            static constexpr size_t batch_size = 21600 / 20;
            static constexpr size_t max_retries = 3;

            std::optional<blockchain_point> continue_from {};
            for (size_t retry = 0; retry < max_retries; ++retry) {
                try {
                    logger::run_and_log_errors([&] {
                        const auto addr = _peer_selection.next_cardano();
                        const auto [headers, tip] = _client.fetch_headers_sync(addr, start_point, 1);
                        if (!start_point || start_point != tip) {
                            const auto blocks = _client.fetch_blocks_sync(addr, headers.front(), tip, batch_size);
                            for (auto &&b: blocks) {
                                if (!max_slot || b.blk->slot() <= *max_slot)
                                    _add_block(*b.blk);
                            }
                            const auto last_point = blockchain_point{ blocks.back().blk->hash(), blocks.back().blk->slot() };
                            if (last_point != tip && (!max_slot || last_point.slot < *max_slot))
                                continue_from = last_point;
                        }
                    });
                    break;
                } catch (...) {
                    // the error is already logged so can simply continue
                    continue;
                }
            }
            return continue_from;
        }

        void _schedule_validation(const bool force=false)
        {
            if (_ready_chunks.empty())
                return;
            if (!force && _ready_chunks.size() < scheduler::default_worker_count())
                return;
            uint64_t start_offset = _cr.valid_end_offset();
            _cr.start_tx(start_offset, start_offset + _ready_data_size);
            for (auto &chunk: _ready_chunks) {
                _cr.add(start_offset, chunk.path, chunk.hash, chunk.name);
                start_offset += chunk.size;
            }
            _cr.prepare_tx();
            _cr.commit_tx();
            _ready_chunks.clear();
            _ready_data_size = 0;
        }

        void _add_chunk(const std::string &path, const std::string &name, const uint64_t size, const buffer &hash)
        {
            _ready_chunks.emplace_back(path, name, size, hash);
            _ready_data_size += size;
            logger::info("added chunk {} of {} bytes", path, size);
        }

        void _save_last_chunk(const bool force_validation=false)
        {
            if (!_last_chunk.empty()) {
                auto chunk_name = fmt::format("{:05d}.zstd", *_last_chunk_id);
                auto chunk_path = (_raw_dir / chunk_name).string();
                file::write_zstd(chunk_path, _last_chunk);
                _add_chunk(chunk_path, chunk_name, _last_chunk.size(), daedalus_turbo::blake2b<cardano::block_hash>(_last_chunk));
                _last_chunk.clear();
            }
            _schedule_validation(force_validation);
        }

        void _add_block(const cardano::block_base &blk)
        {
            auto blk_chunk_id = blk.slot().chunk_id();
            if (!_last_chunk_id)
                _last_chunk_id = blk_chunk_id;
            if (_last_chunk_id != blk_chunk_id && !_last_chunk.empty()) {
                _save_last_chunk();
                _last_chunk_id = blk_chunk_id;
            }
            _last_chunk << blk.raw_data();
        }
    };

    syncer::syncer(indexer::incremental &cr, cardano::network::client &cnc, peer_selection &ps)
        : _impl { std::make_unique<impl>(cr, cnc, ps) }
    {
    }

    syncer::~syncer() =default;

    void syncer::sync(std::optional<cardano::slot> max_slot)
    {
        _impl->sync(max_slot);
    }
}