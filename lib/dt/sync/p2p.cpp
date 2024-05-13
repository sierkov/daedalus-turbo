/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <algorithm>
#include <dt/cardano.hpp>
#include <dt/cardano/network.hpp>
#include <dt/config.hpp>
#include <dt/sync/p2p.hpp>

namespace daedalus_turbo::sync::p2p {
    using namespace daedalus_turbo::cardano::network;
    using namespace daedalus_turbo::cardano;

    struct syncer::impl {
        impl(indexer::incremental &cr, client_manager &cm, peer_selection &ps)
            : _cr { cr }, _client_manager { cm }, _peer_selection { ps }, _raw_dir { _cr.data_dir() / "raw" }
        {
            std::filesystem::create_directories(_raw_dir);
            const auto valid_size = _cr.valid_end_offset();
            if (valid_size != _cr.num_bytes()) {
                _cr.start_tx(valid_size, valid_size);
                _cr.prepare_tx();
                _cr.commit_tx();
            }
        }

        // Finds a peer and the best intersection point
        [[nodiscard]] peer_info find_peer(std::optional<cardano::network::address> addr) const
        {
            if (!addr)
                addr = _peer_selection.next_cardano();
            // Try to fit into a single packet of 1.5KB
            auto client = _client_manager.connect(*addr);
            if (_cr.num_chunks() == 0) {
                auto tip = client->find_tip_sync();
                return { std::move(client), std::move(tip) };
            }

            // iteratively determine the chunk containing the intersection point
            auto first_chunk_it = _cr.chunks().begin();
            auto last_chunk_it = _cr.chunks().end();
            static constexpr size_t points_per_query = 24;
            for (uint64_t chunk_dist = std::distance(first_chunk_it, last_chunk_it); chunk_dist > 1; chunk_dist = std::distance(first_chunk_it, last_chunk_it)) {
                const auto step_size = std::max(static_cast<uint64_t>(1), chunk_dist / points_per_query);
                point_list points {};
                for (auto chunk_it = first_chunk_it; chunk_it != last_chunk_it; std::ranges::advance(chunk_it, step_size, last_chunk_it)) {
                    points.emplace_back(chunk_it->second.first_block_hash(), chunk_it->second.first_slot);
                }
                // ensure that the last chunk is always present
                if (points.back().hash != _cr.last_chunk()->first_block_hash())
                    points.emplace_back(_cr.last_chunk()->first_block_hash(), _cr.last_chunk()->first_slot);

                // points must be in the reverse order
                std::reverse(points.begin(), points.end());
                const auto intersection = client->find_intersection_sync(points);
                if (!intersection.isect)
                    return { std::move(client), std::move(intersection.tip) };

                first_chunk_it = _cr.find_slot_it(intersection.isect->slot);
                last_chunk_it = first_chunk_it;
                std::ranges::advance(last_chunk_it, step_size, _cr.chunks().end());
            }
            if (std::distance(first_chunk_it, last_chunk_it) != 1)
                throw error("internal error: wasn't able to find a chunk for the intersection point!");

            // determine the block of the intersection point
            point_list points {};
            for (const auto &block: first_chunk_it->second.blocks)
                points.emplace_back(block.hash, block.slot);
            std::reverse(points.begin(), points.end());
            const auto intersection = client->find_intersection_sync(points);
            if (!intersection.isect)
                throw error("internal error: wasn't able to narrow down the intersection point to a block!");
            return { std::move(client), std::move(intersection.tip), std::move(intersection.isect) };
        }

        bool sync(std::optional<peer_info> peer, const std::optional<slot> max_slot)
        {
            if (!peer)
                peer = find_peer({});
            logger::info("trying to sync with {} starting from {}", peer->addr(), peer->isect);
            // target offset is unbounded since the cardano network protocol does not provide the size information
            const auto ex_ptr = logger::run_log_errors([&] {
                _validation_failed = false;
                _next_chunk_offset = 0;
                if (peer->isect)
                    _next_chunk_offset = _cr.find_block(peer->isect->slot, peer->isect->hash).end_offset();
                const auto tx_ex_ptr = _cr.transact(_next_chunk_offset, [&] {
                    _sync(*peer, peer->isect, max_slot);
                    _save_last_chunk();
                    _cr.sched().process();
                });
                if (tx_ex_ptr)
                    std::rethrow_exception(tx_ex_ptr);
            });
            return !ex_ptr;
        }
    private:
        static constexpr size_t max_retries = 3;

        struct ready_chunk {
            std::string path {};
            std::string name {};
            uint64_t size {};
            block_hash hash {};
        };

        indexer::incremental &_cr;
        client_manager &_client_manager;
        peer_selection &_peer_selection;
        std::filesystem::path _raw_dir;
        uint8_vector _last_chunk {};
        std::optional<uint64_t> _last_chunk_id {};
        uint64_t _next_chunk_offset = 0;
        std::atomic_bool _validation_failed = false;

        void _sync(const peer_info &peer, const std::optional<point> &local_tip, const std::optional<slot> &max_slot)
        {
            const size_t local_num_blocks = _cr.count_blocks_in_window(local_tip, cardano::density_default_window);
            // the intersection point is included in the count
            size_t remote_num_blocks = local_tip ? 1 : 0;
            const auto density_first_slot = local_tip ? local_tip->slot : cardano::slot { 0 };
            const auto density_last_slot = density_first_slot + cardano::density_default_window;
            cardano::network::block_list density_blocks {};
            const auto add_density_blocks = [&] {
                for (const auto &block: density_blocks)
                    _add_block(*block.blk);
                density_blocks.clear();
            };
            std::optional<point> continue_from = local_tip;
            for (size_t retry = 0; retry < max_retries; ++retry) {
                const auto ex_ptr = logger::run_log_errors([&] {
                    const auto [headers, tip] = peer.client->fetch_headers_sync(continue_from, 1, true);
                    if (!headers.empty() && (!max_slot || headers.front().slot <= *max_slot)) {
                        // current implementation of fetch_blocks does not leave its connection in a working state
                        std::optional<std::string> err {};
                        peer.client->fetch_blocks(headers.front(), tip, [&](auto &&resp) {
                            if (resp.err) {
                                err = std::move(*resp.err);
                                return false;
                            }
                            if (_validation_failed.load() || (max_slot && resp.block->blk->slot() > *max_slot))
                                return false;
                            if (resp.block->blk->slot() <= density_last_slot) {
                                if (resp.block->blk->era() > 0)
                                    ++remote_num_blocks;
                                density_blocks.emplace_back(std::move(*resp.block));
                            } else {
                                if (!density_blocks.empty()) {
                                    if (remote_num_blocks <= local_num_blocks)
                                        return false;
                                    add_density_blocks();
                                }
                                _add_block(*resp.block->blk);
                                continue_from = point{ resp.block->blk->hash(), resp.block->blk->slot(), resp.block->blk->height() };
                            }
                            return true;
                        });
                        peer.client->process(&_cr.sched());
                        if (err)
                            throw error("fetch_block has failed with error: {}", err);
                    }
                });
                logger::info("sync cycle ended continue_from: {}, error: {}, retry: {}", continue_from, static_cast<bool>(ex_ptr), retry);
                if (!ex_ptr)
                    break;
                peer.client->reset();
            }
            if (remote_num_blocks <= local_num_blocks)
                throw error("the local chain has better properties than the remote one - refusing to sync");
            if (!density_blocks.empty())
                add_density_blocks();
        }

        void _save_last_chunk()
        {
            if (!_last_chunk.empty()) {
                const auto chunk_data = std::make_shared<uint8_vector>(std::move(_last_chunk));
                const auto chunk_name = fmt::format("{:05d}.zstd", *_last_chunk_id);
                const auto chunk_path = (_raw_dir / chunk_name).string();
                const auto chunk_offset = _next_chunk_offset;
                _last_chunk.clear();
                _cr.sched().submit_void("parse", 100, [this, chunk_offset, chunk_data, chunk_name, chunk_path] {
                    try {
                        const auto chunk_hash = blake2b<cardano::block_hash>(*chunk_data);
                        file::write_zstd(chunk_path, *chunk_data);
                        _cr.add(chunk_offset, chunk_path, chunk_hash, chunk_name);
                    } catch (...) {
                        _validation_failed = true;
                        throw;
                    }
                });
                _next_chunk_offset += chunk_data->size();
            }
        }

        void _add_block(const block_base &blk)
        {
            const auto blk_chunk_id = blk.slot().chunk_id();
            if (!_last_chunk_id || _last_chunk_id != blk_chunk_id) {
                logger::info("block from a new chunk: slot: {} hash: {} height: {}", blk.slot(), blk.hash(), blk.height());
                _save_last_chunk();
                _last_chunk_id = blk_chunk_id;
            }
            _last_chunk << blk.raw_data();
        }
    };

    syncer::syncer(indexer::incremental &cr, client_manager &ccm, peer_selection &ps)
        : _impl { std::make_unique<impl>(cr, ccm, ps) }
    {
    }

    syncer::~syncer() =default;

    [[nodiscard]] peer_info syncer::find_peer(std::optional<cardano::network::address> addr) const
    {
        return _impl->find_peer(addr);
    }

    bool syncer::sync(std::optional<peer_info> peer, const std::optional<slot> max_slot)
    {
        return _impl->sync(std::move(peer), max_slot);
    }
}