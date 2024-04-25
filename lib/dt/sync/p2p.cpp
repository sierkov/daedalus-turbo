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
        impl(indexer::incremental &cr, client &client, peer_selection &ps)
            : _cr { cr }, _client { client }, _peer_selection { ps }, _raw_dir { _cr.data_dir() / "raw" }
        {
            std::filesystem::create_directories(_raw_dir);
        }

        // Todo ensure that the same TCP connection is reused during all queries to a single client!!!
        // Finds a peer and the best possible intersection at a chunk boundary
        [[nodiscard]] peer_info find_peer() const
        {
            // Try to fit into a single packet of 1.5KB
            static constexpr size_t max_points = 24;
            auto addr = _peer_selection.next_cardano();
            if (_cr.num_chunks() == 0) {
                auto tip = _client.find_tip_sync(addr);
                return { std::move(addr), std::move(tip) };
            }

            // first check against the most recent chunks (most likely to succeed)
            blockchain_point_list points {};
            for (auto rit = _cr.chunks().rbegin(), rend = _cr.chunks().rend(); rit != rend && points.size() < max_points; ++rit) {
                points.emplace_back(rit->second.last_block_hash, rit->second.last_slot);
            }

            auto intersection = _client.find_intersection_sync(addr, points);
            if (intersection.isect)
                return { std::move(addr), std::move(intersection.tip), std::move(intersection.isect) };

            // select equidistant points
            std::vector<uint64_t> offsets {};
            points.clear();
            const auto step_size = std::max(static_cast<size_t>(1), _cr.num_chunks() / max_points);
            for (auto rit = _cr.chunks().rbegin(), rend = _cr.chunks().rend(); rit != rend && points.size() < max_points; ++rit) {
                points.emplace_back(rit->second.last_block_hash, rit->second.first_slot);
                offsets.emplace_back(rit->second.offset);
                for (size_t i = 0; i < step_size; ++i) {
                    if (++rit == rend)
                        break;
                }
            }
            // explicitly add the first block
            {
                const auto &first_chunk = _cr.chunks().begin()->second;
                points.emplace_back(first_chunk.last_block_hash);
                offsets.emplace_back(first_chunk.offset);
            }

            intersection = _client.find_intersection_sync(addr, points);
            // no shared blocks
            if (!intersection.isect)
                return { std::move(addr), std::move(intersection.tip) };

            // find the exact chunk
            std::optional<std::pair<uint64_t, uint64_t>> offset_range {};
            for (size_t i = 0; i < points.size(); ++i) {
                if (*intersection.isect == points[i]) {
                    offset_range = std::make_pair(offsets[i], i + 1 < points.size() ? offsets[i + 1] : _cr.num_bytes());
                    break;
                }
            }
            if (!offset_range)
                throw error("internal issue: failed to find an offset range for the intersection!");
            points.clear();
            offsets.clear();

            for (auto chunk_it = _cr.find_it(offset_range->first); chunk_it != _cr.chunks().end() && chunk_it->second.offset < offset_range->second; ++chunk_it) {
                points.emplace_back(chunk_it->second.last_block_hash);
                offsets.emplace_back(chunk_it->second.offset);
            }

            intersection = _client.find_intersection_sync(addr, points);
            if (!intersection.isect)
                throw error("internal issue: failed to locate an intersection at the chunk boundary!");

            return { std::move(addr), std::move(intersection.tip), std::move(intersection.isect) };
        }

        void sync(std::optional<peer_info> peer, const std::optional<slot> max_slot)
        {
            std::optional<blockchain_point> local_tip {};
            if (const auto last_chunk = _cr.last_chunk())
                local_tip = blockchain_point { last_chunk->last_block_hash, last_chunk->last_slot };
            if (!peer)
                peer = find_peer();
            for (;;) {
                const auto continue_from = _fetch_iteration(*peer, local_tip, max_slot);
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
        client &_client;
        peer_selection &_peer_selection;
        std::filesystem::path _raw_dir;
        uint8_vector _last_chunk {};
        std::optional<uint64_t> _last_chunk_id {};
        std::vector<ready_chunk> _ready_chunks {};
        uint64_t _ready_data_size = 0;

        bool _is_chain_better(const peer_info &peer, const std::optional<blockchain_point> &start_point)
        {
            static constexpr size_t batch_size = 21600 / 20;
            static constexpr size_t max_retries = 3;

            // Any chain is better than an empty one
            if (!start_point)
                return true;
            const auto last_slot = start_point->slot + cardano::density_default_window;
            size_t num_data_blocks = 0;
            const auto [headers, tip] = _client.fetch_headers_sync(peer.addr, start_point, 1);
            std::optional continue_from = headers.front();
            while (continue_from && *continue_from != tip && continue_from->slot <= last_slot) {
                for (size_t retry = 0; retry < max_retries; ++retry) {
                    if (!logger::run_log_errors([&] {
                            const auto blocks = _client.fetch_blocks_sync(peer.addr, *continue_from, tip, batch_size);
                            for (auto &&b: blocks) {
                                if (b.blk->slot() > last_slot)
                                    break;
                                if (b.blk->era() > 0)
                                    ++num_data_blocks;
                            }
                            continue_from = blockchain_point { blocks.back().blk->hash(), blocks.back().blk->slot() };
                            }))
                        break;
                }
            }
            const auto local_num_blocks = _cr.count_blocks_in_window(start_point->slot, cardano::density_default_window);
            return num_data_blocks > local_num_blocks;
        }

        std::optional<blockchain_point> _fetch_iteration(const peer_info &peer, const std::optional<blockchain_point> &start_point, const std::optional<slot> &max_slot)
        {
            static constexpr size_t batch_size = 21600 / 20;
            static constexpr size_t max_retries = 3;

            std::optional<blockchain_point> continue_from {};
            for (size_t retry = 0; retry < max_retries; ++retry) {
                if (!logger::run_log_errors([&] {
                    const auto [headers, tip] = _client.fetch_headers_sync(peer.addr, start_point, 1);
                    if (!start_point || start_point != tip) {
                        const auto blocks = _client.fetch_blocks_sync(peer.addr, headers.front(), tip, batch_size);
                        for (auto &&b: blocks) {
                            if (!max_slot || b.blk->slot() <= *max_slot)
                                _add_block(*b.blk);
                        }
                        const auto last_point = blockchain_point{ blocks.back().blk->hash(), blocks.back().blk->slot() };
                        if (last_point != tip && (!max_slot || last_point.slot < *max_slot))
                            continue_from = last_point;
                    }
                }))
                    break;
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

        void _add_block(const block_base &blk)
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

    syncer::syncer(indexer::incremental &cr, client &cnc, peer_selection &ps)
        : _impl { std::make_unique<impl>(cr, cnc, ps) }
    {
    }

    syncer::~syncer() =default;

    [[nodiscard]] peer_info syncer::find_peer() const
    {
        return _impl->find_peer();
    }

    void syncer::sync(std::optional<peer_info> peer, const std::optional<slot> max_slot)
    {
        _impl->sync(peer, max_slot);
    }
}