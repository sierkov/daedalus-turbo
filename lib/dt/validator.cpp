/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <zpp_bits.h>
#include <dt/cardano/common.hpp>
#include <dt/cardano/state/vrf.hpp>
#include <dt/container.hpp>
#include <dt/index/block-fees.hpp>
#include <dt/index/stake-delta.hpp>
#include <dt/index/timed-update.hpp>
#include <dt/index/txo.hpp>
#include <dt/index/vrf.hpp>
#include <dt/mutex.hpp>
#include <dt/validator.hpp>
#include <dt/validator/state.hpp>
#include <dt/validator/subchain.hpp>

namespace daedalus_turbo::validator {
    indexer::indexer_map default_indexers(const std::string &data_dir, scheduler &sched)
    {
        const auto idx_dir = indexer::incremental::storage_dir(data_dir);
        auto indexers = indexer::default_list(data_dir, sched);
        indexers.emplace(std::make_shared<index::block_fees::indexer>(idx_dir, "block-fees", sched));
        indexers.emplace(std::make_shared<index::timed_update::indexer>(idx_dir, "timed-update", sched));
        indexers.emplace(std::make_shared<index::stake_delta::indexer>(idx_dir, "inflow", sched));
        indexers.emplace(std::make_shared<index::vrf::indexer>(idx_dir, "vrf", sched));
        return indexers;
    }

    struct incremental::impl {
        impl(incremental &cr, const configs &cfg, bool on_the_go)
        : _cr { cr }, _cfg { cfg },
            _validate_dir { chunk_registry::init_db_dir((_cr.data_dir() / "validate").string()) },
            _state_path { (_validate_dir / "state.json").string() },
            _state_pre_path { (_validate_dir / "state-pre.json").string() },
            _pbft_pools { _parse_pbft_pools(_cfg) },
            _state { _pbft_pools, _cr.sched() },
            _on_the_go { on_the_go }
        {
            uint64_t end_offset = 0;
            _snapshots.clear();
            file_set known_files {};
            if (std::filesystem::exists(_state_path)) {
                known_files.emplace(_state_path);
                auto j_snapshots = json::load(_state_path).as_array();
                for (const auto &j_s: j_snapshots) {
                    auto snap = snapshot::from_json(j_s.as_object());
                    bool ok = true;
                    for (const auto &prefix: { "kes", "ledger", "vrf" }) {
                        auto snap_path = _storage_path(prefix, snap.end_offset);
                        if (!std::filesystem::exists(snap_path)) {
                            logger::warn("missing snapshot file: {} - ignoring the snapshot for end offset {}", snap_path, snap.end_offset);
                            ok = false;
                            break;
                        }
                    }
                    if (ok) {
                        _snapshots.emplace(std::move(snap));
                        for (const auto &prefix: { "kes", "ledger", "vrf" }) {
                            known_files.insert(_storage_path(prefix, snap.end_offset));
                        }
                    }
                }
                if (!_snapshots.empty())
                    end_offset = _load_state_snapshot(_snapshots.rbegin()->end_offset);
            }
            for (auto &e: std::filesystem::directory_iterator(_validate_dir)) {
                auto canon_path = std::filesystem::weakly_canonical(e.path()).string();
                if (e.is_regular_file() && !known_files.contains(canon_path))
                    _cr.remover().mark(canon_path);
            }
            logger::info("validator snapshot has data up to offset: {}", end_offset);
        }

        void truncate_impl(uint64_t max_end_offset)
        {
            timer t { "validator::truncate" };
            _cr._parent_truncate_impl(max_end_offset);
            if (std::max(_subchains.valid_size(), _state.end_offset()) <= max_end_offset)
                return;
            if (!_snapshots.empty() && _snapshots.rbegin()->end_offset > max_end_offset) {
                for (auto it = _snapshots.begin(); it != _snapshots.end(); ) {
                    if (it->end_offset > max_end_offset) {
                        for (const auto &prefix: { "kes", "ledger", "vrf" })
                            _cr.remover().mark(_storage_path(prefix, it->end_offset));
                        it = _snapshots.erase(it);
                    } else {
                        ++it;
                    }
                }
                if (!_snapshots.empty()) {
                    const auto &last_snapshot = *_snapshots.rbegin();
                    logger::info("validator's closest snapshot is for epoch {} and end_offset: {}", last_snapshot.epoch, last_snapshot.end_offset);
                    _load_state_snapshot(last_snapshot.end_offset);
                } else {
                    logger::info("validator has no applicable snapshots, the new end_offset: 0");
                }
                _apply_ledger_updates_fast();
                _remove_temporary_data();
            }
        }

        uint64_t valid_end_offset_impl()
        {
            return std::min(std::min(_subchains.valid_size(), _state.end_offset()), _cr._parent_valid_end_offset_impl());
        }

        void start_tx_impl()
        {
            _cr._parent_start_tx_impl();
            _next_end_offset = _state.end_offset();
            _next_last_epoch = _state.epoch();
        }

        void prepare_tx_impl()
        {
            timer t { "validator::_prepare_tx" };
            _cr._parent_prepare_tx_impl();
            // previous validation task must be finished by now
            if (_cr.num_bytes() > _state.end_offset()) {
                mutex::unique_lock lk { _next_task_mutex };
                _schedule_validation(std::move(lk), false);
                _cr.sched().process(true);
            }
            if (_cr.num_bytes() > 0) {
                _subchains.merge_valid();
                if (_subchains.size() != 1 || !_subchains.begin()->second)
                    throw error("The provided data contains unmergeable blockchain segments!");
                _save_kes_snapshot(_subchains.begin()->second);
            }
            {
                if (_snapshots.empty() || _state.end_offset() > _snapshots.rbegin()->end_offset) {
                    _save_state_snapshot();
                    _cr.sched().process(true);
                }
                if (_snapshots.size() > 5) {
                    logger::info("removing unnecessary snapshots of the validator state");
                    uint64_t last_offset = 0;
                    const uint64_t end_offset = _snapshots.rbegin()->end_offset;
                    for (auto it = _snapshots.begin(); it != _snapshots.end(); ) {
                        if (((end_offset - it->end_offset <= snapshot_hifreq_end_offset_range && it->end_offset - last_offset < snapshot_hifreq_distance)
                            || (end_offset - it->end_offset > snapshot_hifreq_end_offset_range && it->end_offset - last_offset < snapshot_normal_distance))
                            && it->end_offset != end_offset)
                        {
                            for (const auto &prefix: { "kes", "ledger", "vrf" }) {
                                std::filesystem::remove(_storage_path(prefix, it->end_offset));
                            }
                            it = _snapshots.erase(it);
                        } else {
                            last_offset = it->end_offset;
                            ++it;
                        }
                    }
                }
            }
            _remove_temporary_data();
        }

        void rollback_tx_impl()
        {
            throw error("not implemented!");
        }

        void commit_tx_impl()
        {
            _cr._parent_commit_tx_impl();
            /*if (!std::filesystem::exists(_state_pre_path))
                throw error("the prepared chunk_registry state file is missing: {}!", _state_pre_path);
            std::filesystem::rename(_state_pre_path, _state_path);*/
        }

        cardano::amount unspent_reward(const cardano::stake_ident &id) const
        {
            return _state.unspent_reward(id);
        }

        std::map<cardano::slot, double> tail_relative_stake() const
        {
            timer t { "tail_relative_stake", logger::level::info };
            struct stake_info {
                cardano::pool_hash pool_hash {};
                double rel_stake = 0;
            };
            std::map<cardano::slot, stake_info> slot_rel_stake {};
            uint64_t min_epoch = _state.epoch() > 1 ? _state.epoch() - 1 : 0;
            for (auto rit = _cr.chunks().rbegin(), rend = _cr.chunks().rend(); rit != rend && rit->second.epoch() >= min_epoch; ++rit) {
                const auto &chunk = rit->second;
                auto chunk_path = _cr.full_path(chunk.rel_path());
                logger::debug("tail_relative_stake analyzing chunk {} from epoch {}", chunk_path, chunk.epoch());
                auto chunk_data = file::read(chunk_path);
                const auto &stake_dist = chunk.epoch() == _state.epoch() ? _state.pool_dist_set() : _state.pool_dist_go();
                cbor_parser parser { chunk_data };
                cbor_value block_tuple {};
                while (!parser.eof()) {
                    parser.read(block_tuple);
                    auto blk = cardano::make_block(block_tuple, chunk.offset + block_tuple.data - chunk_data.data());
                    auto pool_hash = blk->issuer_hash();
                    slot_rel_stake[blk->slot()] = stake_info { pool_hash, static_cast<double>(stake_dist.get(pool_hash)) / stake_dist.total_stake() };
                }
                if (slot_rel_stake.size() >= 21600)
                    break;
            }
            double rel_stake = 0.0;
            std::set<cardano::pool_hash> seen_pools {};
            std::map<cardano::slot, double> slot_cum_rel_stake {};
            for (auto rit = slot_rel_stake.rbegin(), rend = slot_rel_stake.rend(); rit != rend; ++rit) {
                if (!seen_pools.contains(rit->second.pool_hash)) {
                    rel_stake += rit->second.rel_stake;
                    seen_pools.emplace(rit->second.pool_hash);
                }
                slot_cum_rel_stake[rit->first] = rel_stake;
            }
            return slot_cum_rel_stake;
        }

        chunk_registry::chunk_info parse(uint64_t offset, const std::string &rel_path,
            const buffer &raw_data, size_t compressed_size, const block_processor &blk_proc) const
        {
            subchain sc { offset, raw_data.size() };
            auto chunk = _cr._parent_parse(offset, rel_path, raw_data, compressed_size, [&](const auto &blk) {
                blk_proc(blk);
                auto slot = blk.slot();
                if (!blk.signature_ok())
                    throw error("validation of the block signature at slot {} failed!", slot);
                if (blk.era() >= 2 && !blk.body_hash_ok())
                    throw error("validation of the block body hash at slot {} failed!", slot);
                _parse_update_subchain(sc, blk, rel_path);
            });
            _parse_register_subchain(std::move(sc), rel_path);
            return chunk;
        }

        void on_slice_ready(uint64_t first_epoch, uint64_t last_epoch, const indexer::merger::slice &slice)
        {
            _cr._parent_on_slice_ready(first_epoch, last_epoch, slice);
            // only one thread at a time must work on this
            mutex::unique_lock lk { _next_task_mutex };
            // slice merge notifications may arrive out of order even though the are scheduled in order
            if (slice.end_offset() > _next_end_offset)
                _next_end_offset = slice.end_offset();
            if (last_epoch > _next_last_epoch)
                _next_last_epoch = last_epoch;
            if (_on_the_go)
                _schedule_validation(std::move(lk), false);
        }
    private:
        static constexpr uint64_t snapshot_hifreq_end_offset_range = static_cast<uint64_t>(1) << 30;
        static constexpr uint64_t snapshot_hifreq_distance = static_cast<uint64_t>(1) << 27;
        static constexpr uint64_t snapshot_normal_distance = indexer::merger::part_size * 2;

        using timed_update_list = vector<index::timed_update::item>;
        struct snapshot {
            uint64_t epoch = 0;
            uint64_t end_offset = 0;

            static snapshot from_json(const json::value &j)
            {
                return snapshot { json::value_to<uint64_t>(j.at("epoch")), json::value_to<uint64_t>(j.at("endOffset")) };
            }

            bool operator<(const auto &b) const
            {
                return end_offset < b.end_offset;
            }

            json::object to_json() const
            {
                return json::object {
                    { "epoch", epoch },
                    { "endOffset", end_offset }
                };
            }
        };
        using snapshot_list = std::set<snapshot>;

        incremental &_cr;
        const configs &_cfg;
        const std::filesystem::path _validate_dir;
        const std::string _state_path;
        const std::string _state_pre_path;
        const state::pool_set _pbft_pools;
        state _state;
        cardano::state::vrf _vrf_state {};
        alignas(mutex::padding) mutable mutex::unique_lock::mutex_type _subchains_mutex {};
        mutable subchain_list _subchains { [this](const auto &sc) { _save_kes_snapshot(sc); } };
        std::atomic_bool _validation_running { false };
        alignas(mutex::padding) mutable mutex::unique_lock::mutex_type _next_task_mutex {};
        uint64_t _next_end_offset = 0;
        uint64_t _next_last_epoch = 0;
        snapshot_list _snapshots {};
        bool _on_the_go = true;

        static std::set<cardano::pool_hash> _parse_pbft_pools(const configs &cfg)
        {
            std::set<cardano::pool_hash> pools {};
            const config &gen_shelley = cfg.at("genesis-shelley");
            for (const auto &[id, meta]: gen_shelley.at("genDelegs").as_object()) {
                pools.emplace(cardano::pool_hash::from_hex(meta.at("delegate").as_string()));
            }
            return pools;
        }

        void _save_json_snapshots(const std::string &path)
        {
            json::array j_snapshots {};
            for (const auto &j_snap: _snapshots)
                j_snapshots.emplace_back(j_snap.to_json());
            json::save_pretty(path, j_snapshots);
        }

        uint64_t _load_state_snapshot(uint64_t end_offset)
        {
            _vrf_state.load(_storage_path("vrf", end_offset));
            _state.load(_storage_path("ledger", end_offset));
            {
                auto zpp_data = file::read(_storage_path("kes", _state.end_offset()));
                zpp::bits::in in { zpp_data };
                subchain sc {};
                in(sc).or_throw();
                _subchains.clear();
                _subchains.add(std::move(sc));
            }
            return _state.end_offset();
        }

        std::string _storage_path(const std::string_view &prefix, uint64_t end_offset) const
        {
            return std::filesystem::weakly_canonical(_validate_dir / fmt::format("{}-{:013}.bin", prefix, end_offset)).string();
        }

        void _save_state_snapshot()
        {
            logger::debug("initiating the saving of the validator state snapshot epoch: {} end_offset: {}", _state.epoch(), _state.end_offset());
            timer t {
                fmt::format("saved the ledger's state snapshot epoch: {} end_offset: {}", _state.epoch(), _state.end_offset()),
                    logger::level::info };
            logger::debug("saving VRF state");
            _vrf_state.save(_storage_path("vrf", _state.end_offset()));
            logger::debug("saving the validator state");
            _state.save(_storage_path("ledger", _state.end_offset()));
            logger::debug("recording the new snapshot");
            snapshot latest { _state.epoch(), _state.end_offset() };
            _snapshots.emplace(std::move(latest));
            // experimental support for on-the-go checkpointing
            _save_json_snapshots(_state_path);
        }

        // _suchain_mutex must be heldby the caller!
        void _save_kes_snapshot(const subchain &sc) const
        {
            logger::debug("saving KES state snapshot for end_offset: {}", sc.end_offset());
            timer t { fmt::format("saving KES state snapshot for end_offset: {}", sc.end_offset()) };
            uint8_vector zpp_data {};
            zpp::bits::out out { zpp_data };
            out(sc).or_throw();
            file::write(_storage_path("kes", sc.end_offset()), zpp_data);
        }

        void _remove_temporary_data()
        {
            timer t { "validator::remove_temporary_data" };
            for (auto &[name, idxr_ptr]: _cr.indexers()) {
                if (!idxr_ptr->mergeable()) {
                    std::filesystem::remove_all(idxr_ptr->chunk_dir());
                    idxr_ptr->reset();
                }
            }
            for (const auto &name: { "epoch-delta", "outflow" }) {
                std::filesystem::remove_all(_cr.idx_dir() / name);
                if (_cr.indexers().contains(name))
                    _cr.indexers().at(name)->reset();
            }
        }

        // Compressed data is there and most indices have already been created and merged
        // Recreate only temporary indices and apply updates without revalidating the data
        // since it already has been validated up to this point
        void _apply_ledger_updates_fast()
        {
            std::vector<index::indexer_base *> idxrs {
                _cr.indexers().at("block-fees").get(),
                _cr.indexers().at("timed-update").get(),
                _cr.indexers().at("inflow").get(),
                _cr.indexers().at("vrf").get()
            };
            _next_end_offset = _cr.num_bytes();
            _next_last_epoch = _cr.max_slot().epoch();
            for (auto it = _cr.chunks().lower_bound(_state.end_offset()); it != _cr.chunks().end(); ++it) {
                auto chunk_offset = it->second.offset;
                auto chunk_path = _cr.full_path(it->second.rel_path());
                _cr.sched().submit_void("parse-fast", 100, [this, chunk_offset, chunk_path, &idxrs] {
                    indexer::chunk_indexer_list chunk_indexers {};
                    for (auto *idxr_ptr: idxrs)
                        chunk_indexers.emplace_back(idxr_ptr->make_chunk_indexer("update", chunk_offset));
                    auto raw_data = file::read(chunk_path);
                    cbor_parser parser { raw_data };
                    cbor_value block_tuple {};
                    subchain sc { chunk_offset, raw_data.size() };
                    while (!parser.eof()) {
                        parser.read(block_tuple);
                        auto blk = cardano::make_block(block_tuple, chunk_offset + block_tuple.data - raw_data.data());
                        for (auto &idxr: chunk_indexers)
                            idxr->index(*blk);
                        _parse_update_subchain(sc, *blk, chunk_path);
                    }
                    sc.ok_eligibility = sc.num_blocks;
                    _parse_register_subchain(std::move(sc), chunk_path);
                });
            }
            _cr.sched().process(true);
            mutex::unique_lock lk { _next_task_mutex };
            _schedule_validation(std::move(lk), true);
            _cr.sched().process(true);
        }

        void _schedule_validation(mutex::unique_lock &&next_task_lk, bool fast)
        {
            // move, so that it unlocks on stack unrolling
            mutex::unique_lock lk { std::move(next_task_lk) };
            bool exp_false = false;
            if (_validation_running.compare_exchange_strong(exp_false, true)) {
                _cr.sched().submit_void("validate", 400, [this, fast] {
                    try {
                        mutex::unique_lock lk2 { _next_task_mutex };
                        while (_state.end_offset() < _next_end_offset) {
                            logger::debug("acquired _naxt_task mutex and configuring the validation task");
                            auto start_offset = _state.end_offset();
                            auto end_offset = _next_end_offset;
                            auto first_epoch = _state.epoch();
                            auto last_epoch = _next_last_epoch;
                            auto ready_slices = _cr.slices(end_offset);
                            lk2.unlock();
                            logger::info("pre-aggregating data for ledger state updates between epochs {} and {}", first_epoch, last_epoch);
                            auto num_outflow_parts = _prepare_outflows(start_offset, end_offset, ready_slices);
                            logger::debug("outflows ready, preparing the per-epoch deltas");
                            _process_updates(num_outflow_parts, first_epoch, last_epoch);
                            logger::debug("per-epoch deltas are ready, merging subchains from the same epoch");
                            {
                                mutex::scoped_lock sc_lk { _subchains_mutex };
                                _subchains.merge_same_epoch();
                            }
                            logger::debug("begin applying ledger state updates");
                            _apply_ledger_state_updates(first_epoch, last_epoch, ready_slices, fast);
                            logger::debug("done applying ledger state updates, acquiring _next_task lock");
                            lk2.lock();
                        }
                        _validation_running = false;
                    } catch (const std::exception &ex) {
                        logger::error("validation has failed: {}", ex.what());
                        _validation_running = false;
                        throw;
                    }
                });
            }
        }

        void _parse_register_subchain(subchain &&sc, const std::string &rel_path) const
        {
            if (sc.num_blocks == 0)
                throw error("chunk {} contains no blocks!", rel_path);
            {
                mutex::unique_lock sc_lk { _subchains_mutex };
                _subchains.add(std::move(sc));
                uint64_t valid = _subchains.valid_size();
                sc_lk.unlock();
                progress::get().update("validate", (valid - _cr.tx()->start_offset), _cr.tx()->target_offset - _cr.tx()->start_offset);
            }
        }

        void _parse_update_subchain(subchain &sc, const cardano::block_base &blk, const std::string &rel_path) const
        {
            auto slot = blk.slot();
            switch (blk.era()) {
                case 0: {
                    static auto boundary_issuer_vkey = cardano::vkey::from_hex("0000000000000000000000000000000000000000000000000000000000000000");
                    if (blk.issuer_vkey() != boundary_issuer_vkey)
                        throw error("boundary block contains an unexpected issuer_vkey: {}", blk.issuer_vkey());
                    ++sc.ok_eligibility;
                    break;
                }
                case 1: {
                    static std::set<cardano::vkey> byron_issuers {
                        cardano::vkey::from_hex("0BDB1F5EF3D994037593F2266255F134A564658BB2DF814B3B9CEFB96DA34FA9"),
                        cardano::vkey::from_hex("1BC97A2FE02C297880CE8ECFD997FE4C1EC09EE10FEEEE9F686760166B05281D"),
                        cardano::vkey::from_hex("26566E86FC6B9B177C8480E275B2B112B573F6D073F9DEEA53B8D99C4ED976B3"),
                        cardano::vkey::from_hex("50733161FDAFB6C8CB6FAE0E25BDF9555105B3678EFB08F1775B9E90DE4F5C77"),
                        cardano::vkey::from_hex("993A8F056D2D3E50B0AC60139F10DF8F8123D5F7C4817B40DAC2B5DD8AA94A82"),
                        cardano::vkey::from_hex("9A6FA343C8C6C36DE1A3556FEB411BFDF8708D5AF88DE8626D0FC6BFA4EEBB6D"),
                        cardano::vkey::from_hex("D2965C869901231798C5D02D39FCA2A79AA47C3E854921B5855C82FD14708915"),
                    };
                    if (!byron_issuers.contains(blk.issuer_vkey()))
                        throw error("unexpected Byron issuer_vkey: {}", blk.issuer_vkey());
                    ++sc.ok_eligibility;
                    break;
                }
                case 2:
                case 3:
                case 4:
                case 5:
                case 6: {
                    auto kes = blk.kes();
                    auto pool_id = blk.issuer_hash();
                    kes_interval pool_kes { kes.counter, kes.counter };
                    auto [kes_it, kes_created] = sc.kes_intervals.try_emplace(pool_id, pool_kes);
                    if (!kes_created)
                        kes_it->second.merge(pool_kes, pool_id, blk.offset());
                    break;
                }
                default:
                    throw error("unsupported block era: {}", blk.era());
            }
            if (sc.num_blocks > 0) {
                    if (sc.epoch != slot.epoch())
                        throw error("chunks must contains blocks from one era only but got rel_path: {} block slot: {}", rel_path, slot);
                } else {
                    sc.epoch = slot.epoch();
                }
            ++sc.num_blocks;
        }

        void _prepare_outflows_part(index::reader_multi_mt<index::txo_use::item> &txo_use_reader,
            index::reader_multi_mt<index::txo::item> &txo_reader, size_t part_no,
            uint64_t validate_start_offset, uint64_t validate_end_offset) const
        {
            auto txo_use_data = txo_use_reader.init_thread(part_no);
            auto txo_data = txo_reader.init_thread(part_no);
            std::optional<index::txo_use::item> txo_use_item {};
            if (!txo_use_reader.eof_part(part_no, txo_use_data)) {
                txo_use_item.emplace();
                txo_use_reader.read_part(part_no, *txo_use_item, txo_use_data);
            }
            std::optional<index::txo::item> txo_item {};
            if (!txo_reader.eof_part(part_no, txo_data)) {
                txo_item.emplace();
                txo_reader.read_part(part_no, *txo_item, txo_data);
            }
            // TODO: RAM use is unconstrained. Not a problem right now, but needs to be reworked in the future.
            std::map<uint64_t, std::map<cardano::stake_ident_hybrid, int64_t>> epoch_idxs {};

            // this is an inner join so can ignore non-matching elements from any reader
            while (txo_use_item && txo_item) {
                int cmp = memcmp(txo_use_item->hash.data(), txo_item->hash.data(), txo_use_item->hash.size());
                if (cmp == 0)
                    cmp = static_cast<int>(txo_use_item->out_idx) - static_cast<int>(txo_item->out_idx);
                if (cmp == 0 && txo_use_item->offset >= validate_start_offset && txo_use_item->offset < validate_end_offset && txo_item->stake_id) {
                    epoch_idxs[txo_use_item->epoch][*txo_item->stake_id] -= static_cast<int64_t>(txo_item->amount);
                }
                if (cmp <= 0 && !txo_use_reader.read_part(part_no, *txo_use_item, txo_use_data))
                    txo_use_item.reset();
                if (cmp >= 0 && !txo_reader.read_part(part_no, *txo_item, txo_data))
                    txo_item.reset();
            }

            size_t ram_used = 0;
            for (const auto &[epoch, deltas]: epoch_idxs) {
                auto epoch_path = index::indexer_base::chunk_path(_cr.idx_dir().string(), "outflow", std::to_string(epoch), part_no);
                index::writer<index::stake_delta::item> writer { epoch_path, 1 };
                for (const auto &[stake_id, delta]: deltas)
                    writer.emplace(stake_id, delta);
                ram_used += deltas.size() * sizeof(std::map<cardano::stake_ident_hybrid, int64_t>::value_type);
            }
            logger::trace("prepare_outflows part {}: consumed {} MB of RAM", part_no, ram_used / 1'000'000);
        }

        size_t _prepare_outflows(uint64_t validate_start_offset, uint64_t validate_end_offset, const indexer::slice_list &slices) const
        {
            timer t { "validator/prepare_outflows" };
            logger::info("determining outflow transactions between offsets {} and {} ...", validate_start_offset, validate_end_offset);
            indexer::slice_list txo_use_slices {};
            for (const auto &slice: slices) {
                if (slice.offset + slice.size > validate_start_offset && slice.offset < validate_end_offset)
                    txo_use_slices.emplace_back(slice);
            }
            auto txo_use_reader = std::make_shared<index::reader_multi_mt<index::txo_use::item>>(_cr.reader_paths("txo-use", txo_use_slices));
            auto txo_reader = std::make_shared<index::reader_multi_mt<index::txo::item>>(_cr.reader_paths("txo", slices));
            auto num_parts = txo_use_reader->num_parts();
            _cr.sched().wait_for_count("prepare-outflows", num_parts, [&] {
                for (size_t pi = 0; pi < num_parts; pi++) {
                    _cr.sched().submit("prepare-outflows", 500, [this, txo_use_reader, txo_reader, pi, validate_start_offset, validate_end_offset] {
                        _prepare_outflows_part(*txo_use_reader, *txo_reader, pi, validate_start_offset, validate_end_offset);
                        return pi;
                    });
                }
            });
            return num_parts;
        }

        void _process_epoch_updates(uint64_t epoch, const vector<uint64_t> &inflow_chunks, size_t num_outflow_parts) const
        {
            std::map<cardano::stake_ident_hybrid, int64_t> dist {};
            for (const uint64_t chunk_id: inflow_chunks) {
                if (chunk_id < _state.end_offset())
                    continue;
                auto chunk_path = fmt::format("{}-{}.bin", _cr.indexers().at("inflow")->chunk_path("update", chunk_id), epoch);
                vector<index::stake_delta::item> deltas {};
                file::read_zpp(deltas, chunk_path);
                for (const auto &delta: deltas) {
                    dist[delta.stake_id] += delta.delta;
                }
            }

            for (size_t pi = 0; pi < num_outflow_parts; pi++) {
                auto outflow_path = index::indexer_base::chunk_path(_cr.idx_dir().string(), "outflow", std::to_string(epoch), pi);
                if (std::filesystem::exists(outflow_path)) {
                    index::reader<index::stake_delta::item> reader { outflow_path };
                    index::stake_delta::item item {};
                    while (reader.read(item)) {
                        dist[item.stake_id] += item.delta;
                    }
                }
            }

            auto delta_path = index::indexer_base::reader_path(_cr.idx_dir().string(), "epoch-delta", std::to_string(epoch));
            logger::trace("saving {} deltas to {}", dist.size(), delta_path);
            index::writer<index::stake_delta::item> writer { delta_path, 1 };
            for (const auto &[id, delta]: dist)
                writer.emplace(id, delta);
        }

        void _process_updates(size_t num_outflow_parts, uint64_t first_epoch, uint64_t last_epoch)
        {
            timer t { "validator/process_updates" };
            _cr.sched().wait_for_count("epoch-updates", last_epoch - first_epoch + 1, [&] {
                for (auto epoch = first_epoch; epoch <= last_epoch; ++epoch) {
                    _cr.sched().submit("epoch-updates", 600 + static_cast<int>(last_epoch - epoch), [this, epoch, num_outflow_parts] {
                        const auto inflow_chunks = dynamic_cast<index::stake_delta::indexer &>(*_cr.indexers().at("inflow")).epoch_chunks(epoch);
                        if (!inflow_chunks.empty())
                            _process_epoch_updates(epoch, inflow_chunks, num_outflow_parts);
                        return epoch;
                    });
                }
            });
        }

        template<typename T>
        std::optional<uint64_t> _gather_updates(vector<T> &updates, uint64_t epoch, uint64_t min_offset,
            const std::string &name, const index::chunk_list &updated_chunks)
        {
            updates.clear();
            std::optional<uint64_t> min_chunk_id {};
            if (!updated_chunks.empty()) {
                for (const uint64_t chunk_id: updated_chunks) {
                    if (chunk_id >= min_offset) {
                        if (!min_chunk_id || *min_chunk_id > chunk_id)
                            min_chunk_id = chunk_id;
                        auto chunk_path = fmt::format("{}-{}.bin", _cr.indexers().at(name)->chunk_path("update", chunk_id), epoch);
                        vector<T> chunk_updates {};
                        file::read_zpp(chunk_updates, chunk_path);
                        for (const auto &u: chunk_updates)
                            updates.emplace_back(std::move(u));
                    }
                }
            }
            return min_chunk_id;
        }

        void _apply_ledger_state_updates_for_epoch(uint64_t e, index::reader_multi<index::txo::item> &txo_reader,
            const vector<uint64_t> &snapshot_offsets, bool fast)
        {
            timer te { fmt::format("apply_ledger_state_updates for epoch {}", e) };
            try {
                auto last_epoch = _state.epoch();
                auto last_offset = _state.end_offset();
                if (last_epoch < e) {
                    if (!_state.reward_dist().empty() && !_state.epoch_finished())
                        _state.finish_epoch();
                    _state.start_epoch(e);
                    if (_vrf_state.epoch_updates() > 0)
                        _vrf_state.finish_epoch(_state.params().extra_entropy);
                    switch (e) {
                        case 208: // First Shelley/Ouroboros Praos epoch - set the reserves based on the final Byron UTXO balance
                            _state.reserves(13'888'022'852'926'644);
                            break;
                        case 236: // Allegra fork - return byron redeemer addresses to reserves
                            _state.reserves(_state.reserves() + 318'200'635'000'000);
                            break;
                    }
                }

                vector<index::block_fees::item> fee_updates {};
                auto min_epoch_offset = _gather_updates(fee_updates, e, last_offset, "block-fees", dynamic_cast<index::block_fees::indexer &>(*_cr.indexers().at("block-fees")).epoch_chunks(e));
                if (!min_epoch_offset)
                    return;
                {
                    std::map<cardano::pool_hash, size_t> pool_blocks {};
                    for (const auto &[issuer_id, fees, end_offset, era]: fee_updates) {
                        _state.add_fees(fees);
                        _state.end_offset(end_offset);
                        if (era > 1)
                            pool_blocks[issuer_id]++;
                    }
                    for (const auto &[pool_id, num_blocks]: pool_blocks)
                        _state.add_pool_blocks(pool_id, num_blocks);
                }

                {
                    timed_update_list timed_updates {};
                    timer tp { fmt::format("validator epoch: {} process {} timed updates", e, timed_updates.size()) };
                    _gather_updates(timed_updates, e, last_offset, "timed-update", dynamic_cast<index::timed_update::indexer &>(*_cr.indexers().at("timed-update")).epoch_chunks(e));
                    std::sort(timed_updates.begin(), timed_updates.end());
                    for (const auto &upd: timed_updates) {
                        switch (upd.update.index()) {
                            case 0: {
                                const auto &u = std::get<index::timed_update::stake_reg>(upd.update);
                                _state.register_stake(upd.slot, u.stake_id, upd.tx_idx, upd.cert_idx);
                                break;
                            }
                            case 1: {
                                const auto &pr = std::get<cardano::pool_reg>(upd.update);
                                _state.register_pool(pr.pool_id, pr.reward_id, pr.owners, pr.pledge, pr.cost, rational_u64 { pr.margin_num, pr.margin_denom });
                                break;
                            }
                            case 2: {
                                const auto &ir = std::get<index::timed_update::instant_reward_single>(upd.update);
                                if (ir.source == cardano::reward_source::reserves)
                                    _state.instant_reward_reserves(upd.slot, ir.stake_id, ir.amount);
                                else if (ir.source == cardano::reward_source::treasury)
                                    _state.instant_reward_treasury(upd.slot, ir.stake_id, ir.amount);
                                break;
                            }
                            case 3: {
                                const auto &u = std::get<index::timed_update::stake_deleg>(upd.update);
                                _state.delegate_stake(u.stake_id, u.pool_id);
                                break;
                            }
                            case 4: {
                                const auto &u = std::get<index::timed_update::stake_withdraw>(upd.update);
                                _state.withdraw_reward(upd.slot, u.stake_id, u.amount);
                                break;
                            }
                            case 5: {
                                const auto &u = std::get<index::timed_update::stake_del>(upd.update);
                                _state.retire_stake(upd.slot, u.stake_id);
                                break;
                            }
                            case 6: {
                                const auto &pd = std::get<cardano::pool_unreg>(upd.update);
                                _state.retire_pool(pd.pool_id, pd.epoch);
                                break;
                            }
                            case 7: {
                                const auto &pupd = std::get<cardano::param_update>(upd.update);
                                _state.propose_update(upd.slot, pupd);
                                break;
                            }
                            case 8: {
                                const auto &cc = std::get<index::timed_update::collected_collateral>(upd.update);
                                index::txo::item search_item { cc.tx_hash, cc.txo_idx };
                                auto [ txo_count, txo_item ] = txo_reader.find(search_item);
                                if (txo_count != 1)
                                    throw error("each input used as a collateral must be present exactly once but got: {} for {} #{}", txo_count, cc.tx_hash, cc.txo_idx);
                                _state.add_fees(txo_item.amount);
                                break;
                            }
                            default:
                                throw error("internal error: unexpected pool update variant: {}", upd.update.index());
                        }
                    }
                }
                {
                    timer td { fmt::format("validator epoch: {} process stake delta update", e) };
                    auto delta_path = index::indexer_base::reader_path(_cr.idx_dir().string(), "epoch-delta", std::to_string(e));
                    if (std::filesystem::exists(delta_path)) {
                        index::reader<index::stake_delta::item> reader { delta_path };
                        logger::trace("validator epoch: {} {} stake delta updates available", e, reader.size());
                        index::stake_delta::item d {};
                        while (reader.read(d)) {
                            if (std::holds_alternative<cardano::stake_ident>(d.stake_id))
                                _state.update_stake(std::get<cardano::stake_ident>(d.stake_id), d.delta);
                            else if (std::holds_alternative<cardano::stake_pointer>(d.stake_id))
                                _state.update_pointer(std::get<cardano::stake_pointer>(d.stake_id), d.delta);
                            else
                                throw error("unsupported stake_ident_hybrid index: {}", d.stake_id.index());
                        }
                    }
                }
                const auto vrf_chunks = dynamic_cast<index::vrf::indexer &>(*_cr.indexers().at("vrf")).epoch_chunks(e);
                if (!vrf_chunks.empty())
                    _process_vrf_update_chunks(*min_epoch_offset, _vrf_state, vrf_chunks, fast);
                if (!_state.reward_dist().empty() && _state.epoch() < _cr.max_slot().epoch()) {
                    _state.finish_epoch();
                    if (_on_the_go) {
                        auto einfo = _cr.epoch(_state.epoch());
                        for (uint64_t off: snapshot_offsets) {
                            if (einfo.end_offset() >= off && (_snapshots.empty() || _snapshots.rbegin()->end_offset < off)) {
                                _save_state_snapshot();
                                break;
                            }
                        }
                    }
                }
            } catch (const daedalus_turbo::error &ex) {
                logger::error("apply_updates for epoch: {} dt::error: {}", e, ex);
                throw;
            } catch (const std::exception &ex) {
                logger::error("apply_updates for epoch: {} std::exception: {}", e, ex.what());
                throw error("failed to process epoch {} updates: {}", e, ex.what());
            } catch (...) {
                logger::error("apply_updates for epoch: {} unknown exception", e);
                throw;
            }
        }

        void _apply_ledger_state_updates(uint64_t first_epoch, uint64_t last_epoch, const indexer::slice_list &slices, const bool fast)
        {
            timer t { fmt::format("validator::_apply_ledger_state_updates first_epoch: {} last_epoch: {} fast: {}", first_epoch, last_epoch, fast), logger::level::debug };
            // add extra snapshots closer to the tip since rollbacks are more likely there
            vector<uint64_t> snapshot_offsets {};
            for (const auto &slice: slices) {
                if ((_cr.tx()->target_offset - slice.end_offset()) < indexer::merger::part_size)
                    snapshot_offsets.emplace_back(slice.end_offset());
            }
            index::reader_multi<index::txo::item> txo_reader { _cr.reader_paths("txo", slices) };
            for (uint64_t e = first_epoch; e <= last_epoch; e++) {
                timer te { fmt::format("apply ledger updates for epoch: {}", e) };
                try {
                    _apply_ledger_state_updates_for_epoch(e, txo_reader, snapshot_offsets, fast);
                    logger::info("applied ledger updates for epoch: {} end offset: {}", _state.epoch(), _state.end_offset());
                } catch (const std::exception &ex) {
                    logger::error("failed to process epoch {} updates: {}", e, ex.what());
                    throw error("failed to process epoch {} updates: {}", e, ex.what());
                } catch (...) {
                    logger::error("failed to process epoch {} updates: unknown exception", e);
                    throw;
                }
            }
        }

        void _validate_epoch_leaders(uint64_t epoch, uint64_t epoch_min_offset, const std::shared_ptr<vector<index::vrf::item>> &vrf_updates_ptr,
            const std::shared_ptr<pool_stake_distribution> &pool_dist_ptr,
            const cardano::vrf_nonce &nonce_epoch, const cardano::vrf_nonce &uc_nonce, const cardano::vrf_nonce &uc_leader,
            size_t start_idx, size_t end_idx)
        {
            timer t { fmt::format("validate_leaders for epoch {} block indices from {} to {}", epoch, start_idx, end_idx), logger::level::trace };
            for (size_t vi = start_idx; vi < end_idx; ++vi) {
                const auto &item = vrf_updates_ptr->at(vi);
                if (item.era < 6) {
                    auto leader_input = vrf_make_seed(uc_leader, item.slot, nonce_epoch);
                    if (!vrf03_verify(item.leader_result, item.vkey, item.leader_proof, leader_input))
                        throw error("leader VRF verification failed at slot {} epoch {} era {}", item.slot, item.slot.epoch(), (uint64_t)item.era);
                    auto nonce_input = vrf_make_seed(uc_nonce, item.slot, nonce_epoch);
                    if (!vrf03_verify(item.nonce_result, item.vkey, item.nonce_proof, nonce_input))
                        throw error("nonce VRF verification failed at slot {} epoch {} era {}", item.slot, item.slot.epoch(), (uint64_t)item.era);
                } else {
                    auto vrf_input = vrf_make_input(item.slot, nonce_epoch);
                    if (!vrf03_verify(item.leader_result, item.vkey, item.leader_proof, vrf_input))
                        throw error("VRF verification failed at slot {} epoch {} era {}", item.slot, item.slot.epoch(), (uint64_t)item.era);
                }
                if (!_pbft_pools.contains(item.pool_id)) {
                    auto pool_it = pool_dist_ptr->find(item.pool_id);
                    if (pool_it == pool_dist_ptr->end())
                        throw error("epoch {} pool-stake distribution misses block-issuing pool id {}!", epoch, item.pool_id);
                    rational rel_stake { pool_it->second, pool_dist_ptr->total_stake() };
                    if (item.era < 6) {
                        if (!vrf_leader_is_eligible(item.leader_result, 0.05, rel_stake))
                            throw error("Leader-eligibility check failed for block at slot {} issued by {}: leader_result: {} rel_stake: {}",
                                item.slot, item.pool_id, item.leader_result, rel_stake);
                    } else {
                        if (!vrf_leader_is_eligible(vrf_leader_value(item.leader_result), 0.05, rel_stake))
                            throw error("era 6 Leader-eligibility check failed for block at slot {} issued by {}: leader_result: {} rel_stake: {}",
                                item.slot, item.pool_id, item.leader_result, rel_stake);
                    }
                }
            }
            mutex::unique_lock sc_lk { _subchains_mutex };
            auto sc_it = _subchains.find(epoch_min_offset);
            sc_it->second.ok_eligibility += end_idx - start_idx;
            if (sc_it->second) {
                logger::debug("subchain became valid epoch: {} start_offset: {} end_offset: {}",
                    epoch, sc_it->second.offset, sc_it->second.end_offset());
                _subchains.merge_valid();
                const auto valid = _subchains.valid_size();
                sc_lk.unlock();
                logger::debug("new valid chain size: {}", valid);
                progress::get().update("validate", (valid - _cr.tx()->start_offset), _cr.tx()->target_offset - _cr.tx()->start_offset);
            }
        }

        void _process_vrf_update_chunks(uint64_t epoch_min_offset, cardano::state::vrf &vrf_state, const vector<uint64_t> &chunks, bool fast)
        {
            auto epoch = _state.epoch();
            timer t { fmt::format("processed VRF nonce updates for epoch {}", epoch) };
            auto vrf_updates_ptr = std::make_shared<vector<index::vrf::item>>();
            for (const uint64_t chunk_id: chunks) {
                auto chunk_path = fmt::format("{}-{}.bin", _cr.indexers().at("vrf")->chunk_path("update", chunk_id), epoch);
                vector<index::vrf::item> chunk_updates {};
                file::read_zpp(chunk_updates, chunk_path);
                vrf_updates_ptr->reserve(vrf_updates_ptr->size() + chunk_updates.size());
                for (const auto &u: chunk_updates)
                    vrf_updates_ptr->emplace_back(u);
            }
            if (!vrf_updates_ptr->empty()) {
                std::sort(vrf_updates_ptr->begin(), vrf_updates_ptr->end());
                if (!fast) {
                    auto pool_dist_ptr = std::make_shared<pool_stake_distribution>(_state.pool_dist_set());
                    const auto &nonce_epoch = vrf_state.epoch_nonce();
                    const auto &uc_nonce = vrf_state.uc_nonce();
                    const auto &uc_leader = vrf_state.uc_leader();
                    static constexpr size_t batch_size = 250;
                    for (size_t start = 0; start < vrf_updates_ptr->size(); start += batch_size) {
                        auto end = std::min(start + batch_size, vrf_updates_ptr->size());
                        _cr.sched().submit_void("validate-epoch", -epoch, [this, epoch, epoch_min_offset, vrf_updates_ptr, pool_dist_ptr, nonce_epoch, uc_nonce, uc_leader, start, end] {
                            _validate_epoch_leaders(epoch, epoch_min_offset, vrf_updates_ptr, pool_dist_ptr, nonce_epoch, uc_nonce, uc_leader, start, end);
                        });
                    }
                }
                vrf_state.process_updates(*vrf_updates_ptr);
            }
        }
    };

    incremental::incremental(const std::string &data_dir, const configs &cfg, bool on_the_go, bool strict, scheduler &sched, file_remover &fr)
        : indexer::incremental { default_indexers(data_dir), data_dir, strict, sched, fr },
            _impl { std::make_unique<impl>(*this, cfg, on_the_go) }
    {
    }

    incremental::~incremental() =default;

    void incremental::_truncate_impl(uint64_t max_end_offset)
    {
        _impl->truncate_impl(max_end_offset);
    }

    uint64_t incremental::_valid_end_offset_impl()
    {
        return _impl->valid_end_offset_impl();
    }

    void incremental::_start_tx_impl()
    {
        _impl->start_tx_impl();
    }

    void incremental::_prepare_tx_impl()
    {
        _impl->prepare_tx_impl();
    }

    void incremental::_rollback_tx_impl()
    {
        _impl->rollback_tx_impl();
    }

    void incremental::_commit_tx_impl()
    {
        _impl->commit_tx_impl();
    }

    cardano::amount incremental::unspent_reward(const cardano::stake_ident &id) const
    {
        return _impl->unspent_reward(id);
    }

    tail_relative_stake_map incremental::tail_relative_stake() const
    {
        return _impl->tail_relative_stake();
    }

    chunk_registry::chunk_info incremental::_parse(uint64_t offset, const std::string &rel_path,
        const buffer &raw_data, size_t compressed_size, const block_processor &extra_proc) const
    {
        return _impl->parse(offset, rel_path, raw_data, compressed_size, extra_proc);
    }

    void incremental::_on_slice_ready(uint64_t first_epoch, uint64_t last_epoch, const indexer::merger::slice &slice)
    {
        _impl->on_slice_ready(first_epoch, last_epoch, slice);
    }

    chunk_registry::chunk_info incremental::_parent_parse(uint64_t offset, const std::string &rel_path,
        const buffer &raw_data, size_t compressed_size, const block_processor &extra_proc) const
    {
        return indexer::incremental::_parse(offset, rel_path, raw_data, compressed_size, extra_proc);
    }

    void incremental::_parent_on_slice_ready(uint64_t first_epoch, uint64_t last_epoch, const indexer::merger::slice &slice)
    {
        indexer::incremental::_on_slice_ready(first_epoch, last_epoch, slice);
    }

    void incremental::_parent_truncate_impl(uint64_t max_end_offset)
    {
        indexer::incremental::_truncate_impl(max_end_offset);
    }

    uint64_t incremental::_parent_valid_end_offset_impl()
    {
        return indexer::incremental::_valid_end_offset_impl();
    }

    void incremental::_parent_start_tx_impl()
    {
        indexer::incremental::_start_tx_impl();
    }

    void incremental::_parent_prepare_tx_impl()
    {
        indexer::incremental::_prepare_tx_impl();
    }

    void incremental::_parent_rollback_tx_impl()
    {
        indexer::incremental::_rollback_tx_impl();
    }

    void incremental::_parent_commit_tx_impl()
    {
        indexer::incremental::_commit_tx_impl();
    }
}