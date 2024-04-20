/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_SYNC_P2P_HPP
#define DAEDALUS_TURBO_CLI_SYNC_P2P_HPP

#include "dt/cardano/network.hpp"
#include "dt/cli.hpp"
#include "dt/peer-selection.hpp"
#include "dt/validator.hpp"

namespace daedalus_turbo::cli::sync_p2p {
    using namespace daedalus_turbo::cardano::network;
    using namespace daedalus_turbo::cardano;

    struct cmd: command {
        const command_info &info() const override
        {
            static const command_info i {
                "sync-p2p", "<data-dir> [--max-epoch=<epoch>]",
                "synchronize the blockchain with the Cardano P2P network"
            };
            return i;
        }

        void run(const arguments &args) const override
        {
            if (args.empty())
                _throw_usage();
            impl syncer { args.at(0) };
            syncer.sync();
        }
    private:
        struct impl {
            explicit impl(const std::string &data_dir, cardano::network::client &c=cardano::network::client_async::get())
                : _data_dir { data_dir }, _raw_dir { _data_dir + "/raw" },
                    _cr { _data_dir }, _client { c }
            {
                std::filesystem::create_directories(_raw_dir);
            }

            void sync()
            {
                static constexpr size_t batch_size = 21600 / 20;
                std::optional<blockchain_point> local_tip {};
                auto last_chunk = _cr.last_chunk();
                if (last_chunk)
                    local_tip = blockchain_point { last_chunk->last_block_hash, last_chunk->last_slot };
                for (;;) {
                    try {
                        auto addr = peer_selection_simple::get().next_cardano();
                        auto [headers, tip] = _client.fetch_headers_sync(addr, local_tip, 1);
                        if (local_tip && *local_tip == tip)
                            break;
                        auto blocks = _client.fetch_blocks_sync(addr, headers.front(), tip, batch_size);
                        for (auto &&b: blocks)
                            _add_block(*b.blk);
                        local_tip = blockchain_point { blocks.back().blk->hash(), blocks.back().blk->slot() };
                        logger::info("fetched {} blocks till slot {}", blocks.size(), local_tip->slot);
                    } catch (const std::exception &ex) {
                        logger::warn("P2P request failed: {}", ex.what());
                    } catch (...) {
                        logger::warn("P2P request failed with an unknown error");
                    }
                }
                _schedule_validation(true);
            }
        private:
            struct ready_chunk {
                std::string path {};
                std::string name {};
                uint64_t size {};
                block_hash hash {};
            };

            std::string _data_dir;
            std::string _raw_dir;
            validator::incremental _cr;
            cardano::network::client &_client;
            uint8_vector _last_chunk {};
            std::optional<uint64_t> _last_chunk_id {};
            std::vector<ready_chunk> _ready_chunks {};
            uint64_t _ready_data_size = 0;

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
                _schedule_validation();
            }

            void _add_block(const cardano::block_base &blk)
            {
                auto blk_chunk_id = blk.slot().chunk_id();
                if (!_last_chunk_id)
                    _last_chunk_id = blk_chunk_id;
                if (_last_chunk_id != blk_chunk_id && !_last_chunk.empty()) {
                    auto chunk_name = fmt::format("{:05d}.zstd", *_last_chunk_id);
                    auto chunk_path = fmt::format("{}/{}", _raw_dir, chunk_name);
                    file::write_zstd(chunk_path, _last_chunk);
                    _add_chunk(chunk_path, chunk_name, _last_chunk.size(), daedalus_turbo::blake2b<cardano::block_hash>(_last_chunk));
                    _last_chunk.clear();
                    _last_chunk_id = blk_chunk_id;
                }
                _last_chunk << blk.raw_data();
            }
        };
    };
}

#endif // !DAEDALUS_TURBO_CLI_SYNC_P2P_HPP