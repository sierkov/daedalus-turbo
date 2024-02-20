/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <zpp_bits.h>
#include <dt/cardano/common.hpp>
#include <dt/index/block-fees.hpp>
#include <dt/index/vrf.hpp>
#include <dt/validator.hpp>

namespace daedalus_turbo::validator {
    indexer::indexer_map default_indexers(scheduler &sched, const std::string &data_dir)
    {
        const auto idx_dir = indexer::incremental::storage_dir(data_dir);
        auto indexers = indexer::default_list(sched, data_dir);
        indexers.emplace(std::make_unique<index::block_fees::indexer>(sched, idx_dir, "block-fees"));
        indexers.emplace(std::make_unique<index::timed_update::indexer>(sched, idx_dir, "timed-update"));
        indexers.emplace(std::make_unique<index::stake_delta::indexer>(sched, idx_dir, "inflow"));
        indexers.emplace(std::make_unique<index::txo::indexer>(sched, idx_dir, "txo"));
        indexers.emplace(std::make_unique<index::vrf::indexer>(sched, idx_dir, "vrf"));
        return indexers;
    }

    incremental::incremental(scheduler &sched, const std::string &data_dir, indexer::indexer_map &indexers, bool on_the_go)
        : indexer::incremental { sched, data_dir, indexers },
            _validate_dir { chunk_registry::init_db_dir(data_dir + "/validate") },
            _state_path { _validate_dir / "state.json" },
            _state { _sched }, _on_the_go { on_the_go }
    {
    }

    uint64_t incremental::_load_state_snapshot(const std::string &path)
    {
        _subchains.clear();
        auto zpp_data = file::read(path);
        zpp::bits::in in { zpp_data };
        in(_state, _vrf_state, _subchains).or_throw();
        _next_end_offset = _state.end_offset();
        _next_last_epoch = _state.epoch();
        return _state.end_offset();
    }

    std::pair<uint64_t, chunk_registry::file_set> incremental::_load_state(bool strict)
    {
        uint64_t end_offset = 0;
        auto [idxr_truncate_offset, deletable] = indexer::incremental::_load_state(strict);
        _snapshots.clear();
        if (std::filesystem::exists(_state_path)) {
            auto j_snapshots = json::load(_state_path).as_array();
            for (const auto &j_s: j_snapshots) {
                auto snap = snapshot::from_json(j_s.as_object());
                auto snap_path = _snapshot_path(snap.epoch);
                if (std::filesystem::exists(snap_path))
                    _snapshots.emplace(std::move(snap));
                else
                    logger::warn("missing snapshot: {} - ignoring it", snap_path);
            }
            if (!_snapshots.empty())
                end_offset = _load_state_snapshot(_snapshot_path(_snapshots.rbegin()->epoch));
        }
        logger::info("validator snapshot has data up to offset: {}", end_offset);
        return std::make_pair(std::min(idxr_truncate_offset, end_offset), deletable);
    }

    std::string incremental::_snapshot_path(uint64_t epoch) const
    {
        return (_validate_dir / fmt::format("state-{}.bin", epoch)).string();
    }

    chunk_registry::file_set incremental::truncate(size_t max_end_offset, bool del)
    {
        timer t { "validator::truncate" };
        chunk_registry::file_set deletable {};
        // TODO:
        // - round down the max_end offset to the end of the most recent still complete epoch
        // - drop stake deltas for the truncated epochs
        if (max_end_offset < _state.end_offset()) {
            for (auto it = _snapshots.begin(); it != _snapshots.end(); ) {
                if (it->end_offset <= max_end_offset) {
                    ++it;
                } else {
                    auto path = _snapshot_path(it->epoch);
                    deletable.emplace(path);
                    if (del)
                        std::filesystem::remove(path);
                    it = _snapshots.erase(it);
                }
            }
            if (!_snapshots.empty()) {
                const auto &last_snapshot = *_snapshots.rbegin();
                logger::info("validator's closest snapshot is for epoch {} and end_offset: {}", last_snapshot.epoch, last_snapshot.end_offset);
                max_end_offset = last_snapshot.end_offset;
                _load_state_snapshot(_snapshot_path(last_snapshot.epoch));
            } else {
                logger::info("validator has no applicable snapshots, the new end_offset: 0");
                max_end_offset = 0;
            }
        }
        for (auto &&file: indexer::incremental::truncate(max_end_offset, del))
            deletable.emplace(std::move(file));
        return deletable;
    }

    void incremental::_save_state_snapshot()
    {
        timer t {
            fmt::format("saved the ledger's state snapshot epoch: {} end_offset: {}", _state.epoch(), _state.end_offset()),
                logger::level::info };
        uint8_vector zpp_data {};
        zpp::bits::out out { zpp_data };
        out(_state, _vrf_state, _subchains).or_throw();
        file::write(_snapshot_path(_state.epoch()), zpp_data);
        snapshot latest { _state.epoch(), _state.end_offset() };
        _snapshots.emplace(std::move(latest));
    }

    void incremental::save_state()
    {
        timer t { "validator::save_state" };
        indexer::incremental::save_state();
        // previous validation task must be finished by now
        if (_next_end_offset > _state.end_offset()) {
            std::unique_lock lk { _next_task_mutex };
            _schedule_validation(std::move(lk));
            _sched.process(true);
        }
        if (_subchains.size() > 1)
            throw error("The provided data contains unmergeable blockchain segments!");
        {
            if (_snapshots.empty() || _state.end_offset() > _snapshots.rbegin()->end_offset)
                _save_state_snapshot();
            std::ostringstream json_s {};
            json_s << "[\n";
            for (auto it = _snapshots.begin(); it != _snapshots.end(); ++it) {
                json_s << "  " << json::serialize(it->to_json());
                if (std::next(it) != _snapshots.end())
                    json_s << ',';
                json_s << '\n';
            }
            json_s << "]\n";
            file::write(_state_path, json_s.str());
        }
        {
            timer t { "validator::remove_updated_chunks" };
            for (auto &[name, idxr_ptr]: _indexers) {
                if (!idxr_ptr->mergeable())
                    std::filesystem::remove_all(idxr_ptr->chunk_dir());
            }
            std::filesystem::remove_all(_idx_dir / "epoch-delta");
            std::filesystem::remove_all(_idx_dir / "outflow");
            std::filesystem::remove_all(_idx_dir / "vrf");
        }
    }

    void incremental::_on_slice_ready(uint64_t first_epoch, uint64_t last_epoch, const indexer::merger::slice &slice)
    {
        // only one thread at a time must work on this
        indexer::incremental::_on_slice_ready(first_epoch, last_epoch, slice);
        std::unique_lock lk { _next_task_mutex };
        // slice merge even though scheduled in order may complete out of order
        if (slice.end_offset() > _next_end_offset)
            _next_end_offset = slice.end_offset();
        if (last_epoch > _next_last_epoch)
            _next_last_epoch = last_epoch;
        if (_on_the_go)
            _schedule_validation(std::move(lk));
    }

    void incremental::_schedule_validation(std::unique_lock<std::mutex> &&next_task_lk)
    {
        // move, so that it is unlock on stack unrolling
        std::unique_lock<std::mutex> lk { std::move(next_task_lk) };
        bool exp_false = false;
        if (_validation_running.compare_exchange_strong(exp_false, true)) {
            _sched.submit("validate", 400, [this] {
                std::unique_lock lk2 { _next_task_mutex };
                while (_state.end_offset() < _next_end_offset) {
                    auto start_offset = _state.end_offset();
                    auto end_offset = _next_end_offset;
                    auto first_epoch = _state.epoch();
                    auto last_epoch = _next_last_epoch;
                    auto ready_slices = slices(end_offset);
                    lk2.unlock();
                    logger::info("validating leader-eligibility for epochs from {} to {}", first_epoch, last_epoch);
                    auto num_outflow_parts = _prepare_outflows(start_offset, end_offset, ready_slices);
                    _process_updates(num_outflow_parts, first_epoch, last_epoch);
                    _merge_epoch_subchains();
                    _apply_ledger_state_updates(first_epoch, last_epoch, ready_slices);
                    lk2.lock();
                }
                bool exp_true = true;
                if (!_validation_running.compare_exchange_strong(exp_true, false))
                    throw error("internal error: failed to notify that the validation is not running!");
                return true;
            });
        }
    }

    chunk_registry::chunk_info incremental::_parse_normal(uint64_t offset, const std::string &rel_path,
        const buffer &raw_data, size_t compressed_size, const block_processor &extra_proc) const
    {
        timer t { fmt::format("validator::parse chunk: {} offset: {}", rel_path, offset) };
        subchain sc { offset, raw_data.size() };
        auto chunk = indexer::incremental::_parse_normal(offset, rel_path, raw_data, compressed_size, [&](const auto &blk) {
            auto slot = blk.slot();
            if (!blk.signature_ok())
                throw error("validation of the block signature at slot {} failed!");
            if (blk.era() >= 2) {
                auto kes = blk.kes();
                auto pool_id = blk.issuer_hash();
                auto [kes_it, kes_created] = sc.kes_intervals.try_emplace(pool_id);
                if (kes_created) {
                    kes_it->second.first_counter = kes.counter;
                    kes_it->second.last_counter = kes.counter;
                } else {
                    _merge_kes_check(kes_it->second, kes_interval { kes.counter, kes.counter }, pool_id, blk.offset());
                    kes_it->second.last_counter = kes.counter;
                }
            }
            sc.ok_sigs++;
            if (blk.era() < 2)
                sc.ok_eligibility++;
            if (sc.num_blocks > 0) {
                 if (sc.epoch != slot.epoch())
                    throw error("chunks must contains blocks from one era only but got rel_path: {} block slot: {}", rel_path, slot);
            } else {
                sc.epoch = slot.epoch();
            }
            sc.num_blocks++;
            extra_proc(blk);
        });
        if (sc.num_blocks == 0)
            throw error("chunk {} contains no blocks!", rel_path);
        _add_subchain(std::move(sc));
        return chunk;
    }

    void incremental::_merge_kes_check(const kes_interval &left, const kes_interval &right, const cardano::pool_hash &pool_id, const uint64_t chunk_offset)
    {
        if (left.last_counter > right.first_counter)
            throw error("KES intervals from chunk at offset: {} do not merge for pool: {}", chunk_offset, pool_id);
    }

    void incremental::_merge_kes_left(kes_interval_map &left, const kes_interval_map &right, const uint64_t chunk_offset)
    {
        for (const auto &[pool_id, right_interval]: right) {
            auto [left_it, created] = left.try_emplace(pool_id, right_interval);
            if (!created) {
                _merge_kes_check(left_it->second, right_interval, pool_id, chunk_offset);
                left_it->second.last_counter = right_interval.last_counter;
            }
        }
    }

    void incremental::_merge_kes_right(const kes_interval_map &left, kes_interval_map &right, const uint64_t chunk_offset)
    {
        for (const auto &[pool_id, left_interval]: left) {
            auto [right_it, created] = right.try_emplace(pool_id, left_interval);
            if (!created) {
                _merge_kes_check(left_interval, right_it->second, pool_id, chunk_offset);
                right_it->second.first_counter = left_interval.first_counter;
            }
        }
    }

    // Expected to be called when _subchains_mutex is already held by the caller
    incremental::subchain_map::iterator incremental::_merge_with_neighbors(subchain_map::iterator it, const std::function<bool(const subchain &, const subchain &)> &ok_to_merge) const
    {
        auto &sc = it->second;
        auto prev_it = _subchains.lower_bound(sc.offset - 1);
        while (prev_it != _subchains.end() && ok_to_merge(prev_it->second, sc) && prev_it->second.offset + prev_it->second.num_bytes == sc.offset) {
            sc.offset = prev_it->second.offset;
            sc.num_bytes += prev_it->second.num_bytes;
            sc.num_blocks += prev_it->second.num_blocks;
            sc.ok_sigs += prev_it->second.ok_sigs;
            sc.ok_eligibility += prev_it->second.ok_eligibility;
            _merge_kes_right(prev_it->second.kes_intervals, sc.kes_intervals, sc.offset);
            _subchains.erase(prev_it);
            prev_it = _subchains.lower_bound(sc.offset - 1);
        }
        auto next_it = _subchains.lower_bound(sc.offset + sc.num_bytes);
        while (next_it != _subchains.end() && ok_to_merge(sc, next_it->second) && sc.offset + sc.num_bytes == next_it->second.offset) {
            sc.num_bytes += next_it->second.num_bytes;
            sc.num_blocks += next_it->second.num_blocks;
            sc.ok_sigs += next_it->second.ok_sigs;
            sc.ok_eligibility += next_it->second.ok_eligibility;
            _merge_kes_left(sc.kes_intervals, next_it->second.kes_intervals, next_it->second.offset);
            _subchains.erase(next_it);
            next_it = _subchains.lower_bound(sc.offset + sc.num_bytes);
        }
        uint64_t last_offset = it->second.offset + it->second.num_bytes - 1;
        if (it->first != last_offset) {
            auto node = _subchains.extract(it);
            node.key() = last_offset;
            auto [new_it, created, nt] = _subchains.insert(std::move(node));
            if (!created)
                throw error("duplicate subchain found with last_offset {}", last_offset);
            it = std::move(new_it);
        }
        if (_target_offset && it->second && it->second.offset == 0 && it->second.ok_eligibility == it->second.num_blocks)
            progress::get().update("leaders", it->second.num_bytes, *_target_offset);
        return it;
    }

    void incremental::_add_subchain(subchain &&sc) const
    {
        std::scoped_lock lk { _subchains_mutex };
        auto [it, created] = _subchains.emplace(sc.offset + sc.num_bytes - 1, std::move(sc));
        if (!created)
            throw error("duplicate subchain starting a offset {} size {}", sc.offset, sc.num_bytes);
        _merge_with_neighbors(it, [](const auto &l, const auto &r) { return l && r; });
    }

    void incremental::_add_subchain_eligibility(uint64_t sc_offset, size_t ok_eligibility)
    {
        std::scoped_lock lk { _subchains_mutex };
        auto it = _subchains.lower_bound(sc_offset);
        if (it == _subchains.end() || !(it->second.offset <= sc_offset && it->first >= sc_offset))
            throw error("internal error: can't find subchain for blockchain offset {}", sc_offset);
        it->second.ok_eligibility += ok_eligibility;
        _merge_with_neighbors(it, [](const auto &l, const auto &r) { return l && r; });
    }

    void incremental::_merge_epoch_subchains()
    {
        std::scoped_lock lk { _subchains_mutex };
        uint64_t offset = 0;
        while (_subchains.size() > 1 && offset <= _subchains.rbegin()->first) {
            auto it = _subchains.lower_bound(offset);
            it = _merge_with_neighbors(it, [](const auto &l, const auto &r) {
                return l.epoch == r.epoch;
            });
            offset = it->second.offset + it->second.num_bytes;
        }
    }
    
    void incremental::_prepare_outflows_part(index::reader_multi_mt<index::txo_use::item> &txo_use_reader,
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

        // this is an inner join so can ignore non-matching elements from any readers
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
            auto epoch_path = index::indexer_base::chunk_path(_idx_dir, "outflow", std::to_string(epoch), part_no);
            index::writer<index::stake_delta::item> writer { epoch_path, 1 };
            for (const auto &[stake_id, delta]: deltas)
                writer.emplace(stake_id, delta);
            ram_used += deltas.size() * sizeof(std::map<cardano::stake_ident_hybrid, int64_t>::value_type);
        }
        logger::trace("prepare_outflows part {}: consumed {} MB of RAM", part_no, ram_used / 1'000'000);
    }

    std::vector<std::string> incremental::_index_slice_paths(const std::string &name, const indexer::slice_list &slices) const
    {
        std::vector<std::string> paths {};
        for (const auto &slice: slices)
            paths.emplace_back(_indexers.at(name)->reader_path(slice.slice_id));
        logger::trace("slice paths for index {}: {}", name, paths);
        return paths;
    }

    size_t incremental::_prepare_outflows(uint64_t validate_start_offset, uint64_t validate_end_offset, const indexer::slice_list &slices) const
    {
        timer t { "validator/prepare_outflows" };
        logger::info("determining outflow transactions between offsets {} and {} ...", validate_start_offset, validate_end_offset);
        auto txo_use_reader = std::make_shared<index::reader_multi_mt<index::txo_use::item>>(_index_slice_paths("txo-use", slices));
        auto txo_reader = std::make_shared<index::reader_multi_mt<index::txo::item>>(_index_slice_paths("txo", slices));
        auto num_parts = txo_use_reader->num_parts();
        _sched.wait_for_count("prepare-outflows", num_parts, [&] {
            for (size_t pi = 0; pi < num_parts; pi++) {
                _sched.submit("prepare-outflows", 500, [this, txo_use_reader, txo_reader, pi, validate_start_offset, validate_end_offset] {
                    _prepare_outflows_part(*txo_use_reader, *txo_reader, pi, validate_start_offset, validate_end_offset);
                    return pi;
                });
            }
        });
        return num_parts;
    }

    void incremental::_process_epoch_updates(uint64_t epoch, const std::vector<uint64_t> &inflow_chunks, size_t num_outflow_parts) const
    {
        std::map<cardano::stake_ident_hybrid, int64_t> dist {};
        for (const uint64_t chunk_id: inflow_chunks) {
            if (chunk_id < _state.end_offset())
                continue;
            auto chunk_path = fmt::format("{}-{}.bin", _indexers.at("inflow")->chunk_path("update", chunk_id), epoch);
            std::vector<index::stake_delta::item> deltas {};
            file::read_zpp(deltas, chunk_path);
            for (const auto &delta: deltas) {
                dist[delta.stake_id] += delta.delta;
            }
        }

        for (size_t pi = 0; pi < num_outflow_parts; pi++) {
            auto outflow_path = index::indexer_base::chunk_path(_idx_dir, "outflow", std::to_string(epoch), pi);
            if (index::writer<index::stake_delta::item>::exists(outflow_path)) {
                index::reader<index::stake_delta::item> reader { outflow_path };
                index::stake_delta::item item {};
                while (reader.read(item)) {
                    dist[item.stake_id] += item.delta;
                }
            }
        }

        auto delta_path = index::indexer_base::reader_path(_idx_dir, "epoch-delta", std::to_string(epoch));
        logger::trace("saving {} deltas to {}", dist.size(), delta_path);
        index::writer<index::stake_delta::item> writer { delta_path, 1 };
        for (const auto &[id, delta]: dist)
            writer.emplace(id, delta);
    }

    void incremental::_process_updates(size_t num_outflow_parts, uint64_t first_epoch, uint64_t last_epoch)
    {
        timer t { "validator/process_updates" };
        const auto &inflow_updates = dynamic_cast<index::stake_delta::indexer &>(*_indexers.at("inflow")).updated_epochs();
        _sched.wait_for_count("epoch-updates", last_epoch - first_epoch + 1, [&] {
            for (auto epoch = first_epoch; epoch <= last_epoch; ++epoch) {
                _sched.submit("epoch-updates", 600 + last_epoch - epoch, [this, epoch, inflow_updates, num_outflow_parts] {
                    if (inflow_updates.contains(epoch))
                        _process_epoch_updates(epoch, inflow_updates.at(epoch), num_outflow_parts);
                    return epoch;
                });
            }
        });
    }

    template<typename T>
    std::optional<uint64_t> incremental::_gather_updates(std::vector<T> &updates, uint64_t epoch, uint64_t min_offset,
        const std::string &name, const index::epoch_chunks &updated_chunks)
    {
        updates.clear();
        std::optional<uint64_t> min_chunk_id {};
        auto it = updated_chunks.find(epoch);
        if (it != updated_chunks.end()) {
            for (const uint64_t chunk_id: it->second) {
                if (chunk_id >= min_offset) {
                    if (!min_chunk_id || *min_chunk_id > chunk_id)
                        min_chunk_id = chunk_id;
                    auto chunk_path = fmt::format("{}-{}.bin", _indexers.at(name)->chunk_path("update", chunk_id), epoch);
                    std::vector<T> chunk_updates {};
                    file::read_zpp(chunk_updates, chunk_path);
                    for (const auto &u: chunk_updates)
                        updates.emplace_back(std::move(u));
                }
            }
        }
        return min_chunk_id;
    }

    void incremental::_apply_ledger_state_updates_for_epoch(uint64_t e, index::reader_multi<index::txo::item> &txo_reader,
        const index::epoch_chunks &vrf_updates, const std::vector<uint64_t> &snapshot_offsets)
    {
        timer te { fmt::format("apply_ledger_state_updates for epoch {}", e) };
        try {
            auto last_epoch = _state.epoch();
            auto last_offset = _state.end_offset();
            if (last_epoch < e) {
                if (!_state.reward_dist().empty()) {
                    _state.finish_epoch();
                    if (_on_the_go) {
                        auto einfo = epoch(_state.epoch());
                        for (uint64_t off: snapshot_offsets) {
                            if (einfo.end_offset >= off && (_snapshots.empty() || _snapshots.rbegin()->end_offset < off)) {
                                _save_state_snapshot();
                                break;
                            }
                        }
                    }
                }
                _state.start_epoch(e);
                if (_vrf_state.epoch_updates() > 0)
                    _vrf_state.finish_epoch(_state.params().extra_entropy);
                switch (e) {
                    case 208: // Learn to compute from UTXO balance
                        _state.reserves(13'888'022'852'926'644);
                        break;
                    case 236: // Allegra fork - return byron redeemer addresses to reserves
                        _state.reserves(_state.reserves() + 318'200'635'000'000);
                        break;
                }
            }
            
            std::vector<index::block_fees::item> fee_updates {};
            auto min_epoch_offset = _gather_updates(fee_updates, e, last_offset, "block-fees", dynamic_cast<index::block_fees::indexer &>(*_indexers.at("block-fees")).updated_epochs());
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
                _gather_updates(timed_updates, e, last_offset, "timed-update", dynamic_cast<index::timed_update::indexer &>(*_indexers.at("timed-update")).updated_epochs());
                std::sort(timed_updates.begin(), timed_updates.end());
                struct collateral_id {
                    uint64_t slot = 0;
                    uint64_t tx_idx = 0;
                    bool operator<(const collateral_id &b) const
                    {
                        if (slot != b.slot)
                            return slot < b.slot;
                        return tx_idx < b.tx_idx;
                    }
                };
                std::map<collateral_id, uint64_t> collateral_fees {};
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
                            auto &c_fees = collateral_fees[collateral_id { upd.slot, upd.tx_idx }];
                            if (txo_count != 1)
                                throw error("each input used as a collateral must be present exactly once but got: {} for {} #{}", txo_count, cc.tx_hash, cc.txo_idx);
                            c_fees += txo_item.amount;
                            break;
                        }
                        default:
                            throw error("internal error: unexpected pool update variant: {}", upd.update.index());
                    }
                }
                for (const auto &[c_id, c_fees]: collateral_fees) {
                    logger::trace("epoch: {} collateral from slot: {} tx_idx: {} amount: {}", e, c_id.slot, c_id.tx_idx, c_fees);
                    _state.add_fees(c_fees);
                }
            }
            {
                timer td { fmt::format("validator epoch: {} process stake delta update", e) };
                auto delta_path = index::indexer_base::reader_path(_idx_dir, "epoch-delta", std::to_string(e));
                if (index::writer<index::stake_delta::item>::exists(delta_path)) {
                    index::reader<index::stake_delta::item> reader { delta_path };
                    logger::debug("validator epoch: {} {} stake delta updates available", e, reader.size());
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
            if (vrf_updates.contains(e))
                _process_vrf_update_chunks(*min_epoch_offset, _vrf_state, vrf_updates.at(e));
        } catch (std::exception &ex) {
            throw error("failed to process epoch {} updates: {}", e, ex.what());
        }
    }

    void incremental::_apply_ledger_state_updates(uint64_t first_epoch, uint64_t last_epoch, const indexer::slice_list &slices)
    {
        timer t { "validator::_update_pool_stake_distributions" };
        std::vector<uint64_t> snapshot_offsets {};
        snapshot_offsets.reserve(3);
        if (_target_offset && *_target_offset >= indexer::merger::part_size * 2) {
            snapshot_offsets.emplace_back(*_target_offset / 2);
            while (snapshot_offsets.size() < 3) {
                snapshot_offsets.emplace_back(snapshot_offsets.back() + (*_target_offset - snapshot_offsets.back()) / 2);
            }
        }
        index::reader_multi<index::txo::item> txo_reader { _index_slice_paths("txo", slices) };
        auto vrf_updates = dynamic_cast<index::vrf::indexer &>(*_indexers.at("vrf")).updated_epochs();
        for (uint64_t e = first_epoch; e <= last_epoch; e++) {
            try {
                _apply_ledger_state_updates_for_epoch(e, txo_reader, vrf_updates, snapshot_offsets);
                logger::info("applied ledger updates for epoch: {} end offset: {}", _state.epoch(), _state.end_offset());
            } catch (std::exception &ex) {
                throw error("failed to process epoch {} updates: {}", e, ex.what());
            }
        }
    }

    void incremental::_validate_epoch_leaders(uint64_t epoch, uint64_t epoch_min_offset, const std::shared_ptr<std::vector<index::vrf::item>> &vrf_updates_ptr,
        const std::shared_ptr<pool_stake_distribution> &pool_dist_ptr,
        const cardano::vrf_nonce &nonce_epoch, const cardano::vrf_nonce &uc_nonce, const cardano::vrf_nonce &uc_leader,
        size_t start_idx, size_t end_idx)
    {
        timer t { fmt::format("validate_leaders for epoch {} block indices from {} to {}", epoch, start_idx, end_idx), logger::level::trace };
        static const std::set<cardano::pool_hash> pbft_pools {
            cardano_hash_28 { 0xd9, 0xe5, 0xc7, 0x6a, 0xd5, 0xee, 0x77, 0x89, 0x60, 0x80, 0x40, 0x94, 0xa3, 0x89, 0xf0, 0xb5,
                            0x46, 0xb5, 0xc2, 0xb1, 0x40, 0xa6, 0x2f, 0x8e, 0xc4, 0x3e, 0xa5, 0x4d },
            cardano_hash_28 { 0x85, 0x5d, 0x6f, 0xc1, 0xe5, 0x42, 0x74, 0xe3, 0x31, 0xe3, 0x44, 0x78, 0xee, 0xac, 0x8d, 0x06,
                            0x0b, 0x0b, 0x90, 0xc1, 0xf9, 0xe8, 0xa2, 0xb0, 0x11, 0x67, 0xc0, 0x48 },
            cardano_hash_28 { 0x7f, 0x72, 0xa1, 0x82, 0x6a, 0xe3, 0xb2, 0x79, 0x78, 0x2a, 0xb2, 0xbc, 0x58, 0x2d, 0x0d, 0x29,
                            0x58, 0xde, 0x65, 0xbd, 0x86, 0xb2, 0xc4, 0xf8, 0x2d, 0x8b, 0xa9, 0x56 },
            cardano_hash_28 { 0x69, 0xae, 0x12, 0xf9, 0xe4, 0x5c, 0x0c, 0x91, 0x22, 0x35, 0x6c, 0x8e, 0x62, 0x4b, 0x1f, 0xbb,
                            0xed, 0x6c, 0x22, 0xa2, 0xe3, 0xb4, 0x35, 0x8c, 0xf0, 0xcb, 0x50, 0x11 },
            cardano_hash_28 { 0x44, 0x85, 0x70, 0x80, 0x22, 0x83, 0x9a, 0x7b, 0x9b, 0x8b, 0x63, 0x9a, 0x93, 0x9c, 0x85, 0xec,
                            0x0e, 0xd6, 0x99, 0x9b, 0x5b, 0x6d, 0xc6, 0x51, 0xb0, 0x3c, 0x43, 0xf6 },
            cardano_hash_28 { 0x65, 0x35, 0xdb, 0x26, 0x34, 0x72, 0x83, 0x99, 0x0a, 0x25, 0x23, 0x13, 0xa7, 0x90, 0x3a, 0x45,
                            0xe3, 0x52, 0x6e, 0xc2, 0x5d, 0xdb, 0xa3, 0x81, 0xc0, 0x71, 0xb2, 0x5b },
            cardano_hash_28 { 0x1d, 0x4f, 0x2e, 0x1f, 0xda, 0x43, 0x07, 0x0d, 0x71, 0xbb, 0x22, 0xa5, 0x52, 0x2f, 0x86, 0x94,
                            0x3c, 0x7c, 0x18, 0xae, 0xb4, 0xfa, 0x47, 0xa3, 0x62, 0xc2, 0x7e, 0x23 }
        };
        
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
            // replace with genesis pools
            if (!pbft_pools.contains(item.pool_id)) {
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
        _add_subchain_eligibility(epoch_min_offset, end_idx - start_idx);
    }

    void incremental::_process_vrf_update_chunks(uint64_t epoch_min_offset, cardano::state::vrf &vrf_state, const std::vector<uint64_t> &chunks)
    {
        auto epoch = _state.epoch();
        timer t { fmt::format("processed VRF nonce updates for epoch {}", epoch) };
        auto vrf_updates_ptr = std::make_shared<std::vector<index::vrf::item>>();
        for (const uint64_t chunk_id: chunks) {
            auto chunk_path = fmt::format("{}-{}.bin", _indexers.at("vrf")->chunk_path("update", chunk_id), epoch);
            std::vector<index::vrf::item> chunk_updates {};
            file::read_zpp(chunk_updates, chunk_path);
            vrf_updates_ptr->reserve(vrf_updates_ptr->size() + chunk_updates.size());
            for (const auto &u: chunk_updates)
                vrf_updates_ptr->emplace_back(u);
        }
        if (!vrf_updates_ptr->empty()) {
            auto pool_dist_ptr = std::make_shared<pool_stake_distribution>(_state.pool_dist_set());
            std::sort(vrf_updates_ptr->begin(), vrf_updates_ptr->end());
            const auto &nonce_epoch = vrf_state.epoch_nonce();
            const auto &uc_nonce = vrf_state.uc_nonce();
            const auto &uc_leader = vrf_state.uc_leader();
            static constexpr size_t batch_size = 250;
            for (size_t start = 0; start < vrf_updates_ptr->size(); start += batch_size) {
                auto end = std::min(start + batch_size, vrf_updates_ptr->size());
                _sched.submit("validate-epoch", -epoch, [this, epoch, epoch_min_offset, vrf_updates_ptr, pool_dist_ptr, nonce_epoch, uc_nonce, uc_leader, start, end] {
                    _validate_epoch_leaders(epoch, epoch_min_offset, vrf_updates_ptr, pool_dist_ptr, nonce_epoch, uc_nonce, uc_leader, start, end);
                    return epoch;
                });
            }
            vrf_state.process_updates(*vrf_updates_ptr);
        }
    }
}