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
            _state_path { (_validate_dir / "state.json").string() },
            _state { _sched }, _on_the_go { on_the_go }
    {
    }

    uint64_t incremental::_load_state_snapshot(uint64_t end_offset)
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
        _validate_start_offset = _next_end_offset = _state.end_offset();
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
                bool ok = true;
                for (const auto &prefix: { "kes", "ledger", "vrf" }) {
                    auto snap_path = _storage_path(prefix, snap.end_offset);
                    if (!std::filesystem::exists(snap_path)) {
                        logger::warn("missing snapshot file: {} - ignoring the snapshot for end offset {}", snap_path, snap.end_offset);
                        ok = false;
                        break;
                    }
                }
                if (ok)
                    _snapshots.emplace(std::move(snap));
            }
            if (!_snapshots.empty())
                end_offset = _load_state_snapshot(_snapshots.rbegin()->end_offset);
        }
        logger::info("validator snapshot has data up to offset: {}", end_offset);
        return std::make_pair(std::min(idxr_truncate_offset, end_offset), deletable);
    }

    std::string incremental::_storage_path(const std::string_view &prefix, uint64_t end_offset) const
    {
        return (_validate_dir / fmt::format("{}-{:013}.bin", prefix, end_offset)).string();
    }

    chunk_registry::file_set incremental::truncate(size_t max_end_offset, bool del)
    {
        timer t { "validator::truncate" };
        chunk_registry::file_set deletable {};
        while (max_end_offset < _state.end_offset()) {
            for (auto it = _snapshots.begin(); it != _snapshots.end(); ) {
                if (it->end_offset <= max_end_offset) {
                    ++it;
                } else {
                    for (const auto &prefix: { "kes", "ledger", "vrf" }) {
                        auto snap_path = _storage_path(prefix, it->end_offset);
                        deletable.emplace(snap_path);
                        if (del)
                            std::filesystem::remove(snap_path);
                    }
                    it = _snapshots.erase(it);
                }
            }
            if (!_snapshots.empty()) {
                const auto &last_snapshot = *_snapshots.rbegin();
                logger::info("validator's closest snapshot is for epoch {} and end_offset: {}", last_snapshot.epoch, last_snapshot.end_offset);
                max_end_offset = last_snapshot.end_offset;
                _load_state_snapshot(last_snapshot.end_offset);
            } else {
                logger::info("validator has no applicable snapshots, the new end_offset: 0");
                max_end_offset = 0;
                _validate_start_offset = _next_end_offset = 0;
                _next_last_epoch = 0;
                _state.clear();
                _vrf_state.clear();
                _subchains.clear();
            }
        }
        if (!deletable.empty())
            logger::info("validator removed snapshots after blockchain offset: {}", max_end_offset);
        for (auto &&file: indexer::incremental::truncate(max_end_offset, del))
            deletable.emplace(std::move(file));
        return deletable;
 }

    void incremental::_save_state_snapshot(bool record)
    {
        timer t {
            fmt::format("saved the ledger's state snapshot epoch: {} end_offset: {}", _state.epoch(), _state.end_offset()),
                logger::level::info };
        _vrf_state.save(_storage_path("vrf", _state.end_offset()));
        _state.save(_storage_path("ledger", _state.end_offset()));
        if (record) {
            snapshot latest { _state.epoch(), _state.end_offset() };
            _snapshots.emplace(std::move(latest));
        }
    }

    void incremental::_save_subchains_snapshot(const subchain &sc) const
    {
        uint8_vector zpp_data {};
        zpp::bits::out out { zpp_data };
        out(sc).or_throw();
        file::write(_storage_path("kes", sc.end_offset()), zpp_data);
    }

    void incremental::clean_up()
    {
        indexer::incremental::clean_up();
        std::set<std::string> known_files {};
        known_files.emplace(std::filesystem::weakly_canonical(_state_path).string());
        for (const auto &snap: _snapshots) {
            for (const auto &prefix: { "kes", "ledger", "vrf" }) {
                known_files.emplace(std::filesystem::weakly_canonical(_storage_path(prefix, snap.end_offset)).string());
            }
        }
        for (auto &entry: std::filesystem::directory_iterator(_validate_dir)) {
            auto canon_path = std::filesystem::weakly_canonical(entry.path());
            if (entry.is_regular_file() && !known_files.contains(canon_path.string()))
                std::filesystem::remove(canon_path);
        }
    }

    void incremental::save_state()
    {
        timer t { "validator::save_state" };
        indexer::incremental::save_state();
        // previous validation task must be finished by now
        if (_end_offset > _state.end_offset()) {
            std::unique_lock lk { _next_task_mutex };
            _next_end_offset = _end_offset;
            _next_last_epoch =  epochs().rbegin()->first;
            _schedule_validation(std::move(lk));
            _sched.process(true);
        }
        if (_end_offset > 0) {
            _subchains.merge_valid();
            if (_subchains.size() != 1 || !_subchains.begin()->second)
                throw error("The provided data contains unmergeable blockchain segments!");
            _save_subchains_snapshot(_subchains.begin()->second);
        }
        {
            if (_snapshots.empty() || _state.end_offset() > _snapshots.rbegin()->end_offset)
                _save_state_snapshot();
            if (_snapshots.size() > 5) {
                uint64_t last_offset = 0;
                uint64_t end_offset = _snapshots.rbegin()->end_offset;
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

            json::array j_snapshots {};
            for (const auto &j_snap: _snapshots)
                j_snapshots.emplace_back(j_snap.to_json());
            json::save_pretty(_state_path, j_snapshots);
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
        _validate_start_offset = _next_end_offset;
    }

    void incremental::_on_slice_ready(uint64_t first_epoch, uint64_t last_epoch, const indexer::merger::slice &slice)
    {
        indexer::incremental::_on_slice_ready(first_epoch, last_epoch, slice);
        // only one thread at a time must work on this
        std::unique_lock lk { _next_task_mutex };
        // slice merge notifications may arrive out of order even though the are scheduled in order
        if (slice.end_offset() > _next_end_offset)
            _next_end_offset = slice.end_offset();
        if (last_epoch > _next_last_epoch)
            _next_last_epoch = last_epoch;
        if (_on_the_go)
            _schedule_validation(std::move(lk));
    }

    void incremental::_schedule_validation(std::unique_lock<std::mutex> &&next_task_lk)
    {
        // move, so that it unlocks on stack unrolling
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
                    {
                        std::scoped_lock sc_lk { _subchains_mutex };
                        _subchains.merge_same_epoch();
                    }
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

    chunk_registry::chunk_info incremental::_parse(uint64_t offset, const std::string &rel_path,
        const buffer &raw_data, size_t compressed_size, const block_processor &blk_proc) const
    {
        subchain sc { offset, raw_data.size() };
        auto chunk = indexer::incremental::_parse(offset, rel_path, raw_data, compressed_size, [&](const auto &blk) {
            blk_proc(blk);
            auto slot = blk.slot();
            if (!blk.signature_ok())
                throw error("validation of the block signature at slot {} failed!", slot);
            if (blk.era() >= 2 && !blk.body_hash_ok())
                throw error("validation of the block body hash at slot {} failed!", slot);
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
        });
        if (sc.num_blocks == 0)
            throw error("chunk {} contains no blocks!", rel_path);
        {
            std::unique_lock sc_lk { _subchains_mutex };
            _subchains.add(std::move(sc));
            uint64_t valid = _subchains.valid_size();
            sc_lk.unlock();
            if (_target_offset)
                progress::get().update("validate", (valid - _validate_start_offset), (*_target_offset - _validate_start_offset));
        }
        return chunk;
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
            auto epoch_path = index::indexer_base::chunk_path(_idx_dir.string(), "outflow", std::to_string(epoch), part_no);
            index::writer<index::stake_delta::item> writer { epoch_path, 1 };
            for (const auto &[stake_id, delta]: deltas)
                writer.emplace(stake_id, delta);
            ram_used += deltas.size() * sizeof(std::map<cardano::stake_ident_hybrid, int64_t>::value_type);
        }
        logger::trace("prepare_outflows part {}: consumed {} MB of RAM", part_no, ram_used / 1'000'000);
    }

    vector<std::string> incremental::_index_slice_paths(const std::string &name, const indexer::slice_list &slices) const
    {
        vector<std::string> paths {};
        for (const auto &slice: slices)
            paths.emplace_back(_indexers.at(name)->reader_path(slice.slice_id));
        logger::trace("slice paths for index {}: {}", name, paths);
        return paths;
    }

    size_t incremental::_prepare_outflows(uint64_t validate_start_offset, uint64_t validate_end_offset, const indexer::slice_list &slices) const
    {
        timer t { "validator/prepare_outflows" };
        logger::info("determining outflow transactions between offsets {} and {} ...", validate_start_offset, validate_end_offset);
        indexer::slice_list txo_use_slices {};
        for (const auto &slice: slices) {
            if (slice.offset + slice.size > validate_start_offset && slice.offset < validate_end_offset)
                txo_use_slices.emplace_back(slice);
        }
        auto txo_use_reader = std::make_shared<index::reader_multi_mt<index::txo_use::item>>(_index_slice_paths("txo-use", txo_use_slices));
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

    void incremental::_process_epoch_updates(uint64_t epoch, const vector<uint64_t> &inflow_chunks, size_t num_outflow_parts) const
    {
        std::map<cardano::stake_ident_hybrid, int64_t> dist {};
        for (const uint64_t chunk_id: inflow_chunks) {
            if (chunk_id < _state.end_offset())
                continue;
            auto chunk_path = fmt::format("{}-{}.bin", _indexers.at("inflow")->chunk_path("update", chunk_id), epoch);
            vector<index::stake_delta::item> deltas {};
            file::read_zpp(deltas, chunk_path);
            for (const auto &delta: deltas) {
                dist[delta.stake_id] += delta.delta;
            }
        }

        for (size_t pi = 0; pi < num_outflow_parts; pi++) {
            auto outflow_path = index::indexer_base::chunk_path(_idx_dir.string(), "outflow", std::to_string(epoch), pi);
            if (index::writer<index::stake_delta::item>::exists(outflow_path)) {
                index::reader<index::stake_delta::item> reader { outflow_path };
                index::stake_delta::item item {};
                while (reader.read(item)) {
                    dist[item.stake_id] += item.delta;
                }
            }
        }

        auto delta_path = index::indexer_base::reader_path(_idx_dir.string(), "epoch-delta", std::to_string(epoch));
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
    std::optional<uint64_t> incremental::_gather_updates(vector<T> &updates, uint64_t epoch, uint64_t min_offset,
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
                    vector<T> chunk_updates {};
                    file::read_zpp(chunk_updates, chunk_path);
                    for (const auto &u: chunk_updates)
                        updates.emplace_back(std::move(u));
                }
            }
        }
        return min_chunk_id;
    }

    void incremental::_apply_ledger_state_updates_for_epoch(uint64_t e, index::reader_multi<index::txo::item> &txo_reader,
        const index::epoch_chunks &vrf_updates, const vector<uint64_t> &snapshot_offsets)
    {
        timer te { fmt::format("apply_ledger_state_updates for epoch {}", e) };
        try {
            auto last_epoch = _state.epoch();
            auto last_offset = _state.end_offset();
            if (last_epoch < e) {
                if (!_state.reward_dist().empty()) {
                    _state.finish_epoch();
                    auto einfo = epoch(_state.epoch());
                    if (_on_the_go) {
                        for (uint64_t off: snapshot_offsets) {
                            if (einfo.end_offset() >= off && (_snapshots.empty() || _snapshots.rbegin()->end_offset < off)) {
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
                    case 208: // First Shelley/Ouroboros Praos epoch - set the reserves based on the final Byron UTXO balance
                        _state.reserves(13'888'022'852'926'644);
                        break;
                    case 236: // Allegra fork - return byron redeemer addresses to reserves
                        _state.reserves(_state.reserves() + 318'200'635'000'000);
                        break;
                }
            }
            
            vector<index::block_fees::item> fee_updates {};
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
                auto delta_path = index::indexer_base::reader_path(_idx_dir.string(), "epoch-delta", std::to_string(e));
                if (index::writer<index::stake_delta::item>::exists(delta_path)) {
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
            if (vrf_updates.contains(e))
                _process_vrf_update_chunks(*min_epoch_offset, _vrf_state, vrf_updates.at(e));
        } catch (std::exception &ex) {
            throw error("failed to process epoch {} updates: {}", e, ex.what());
        }
    }

    void incremental::_apply_ledger_state_updates(uint64_t first_epoch, uint64_t last_epoch, const indexer::slice_list &slices)
    {
        timer t { "validator::_update_pool_stake_distributions" };
        vector<uint64_t> snapshot_offsets {};
        if (_target_offset) {
            std::scoped_lock lk { _subchains_mutex };
            snapshot_offsets.emplace_back(*_target_offset / 2);
            uint64_t max_offset = num_bytes();
            while (snapshot_offsets.back() < max_offset) {
                uint64_t last_offset = snapshot_offsets.back();
                uint64_t next_offset = std::min(last_offset + std::max((*_target_offset - last_offset) / 2, snapshot_normal_distance), max_offset);
                if (*_target_offset - next_offset <= snapshot_hifreq_end_offset_range)
                    next_offset = std::min(last_offset + std::max((*_target_offset - last_offset) / 2, snapshot_hifreq_distance), max_offset);
                auto einfo = epoch(find(next_offset - 1).epoch());
                auto it = _subchains.find(einfo.end_offset() - 1);
                it->second.snapshot = true;
                snapshot_offsets.emplace_back(einfo.end_offset());
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

    void incremental::_validate_epoch_leaders(uint64_t epoch, uint64_t epoch_min_offset, const std::shared_ptr<vector<index::vrf::item>> &vrf_updates_ptr,
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
        std::unique_lock sc_lk { _subchains_mutex };
        auto sc_it = _subchains.find(epoch_min_offset);
        sc_it->second.ok_eligibility += end_idx - start_idx;
        if (sc_it->second) {
            _subchains.merge_valid();
            auto valid = _subchains.valid_size();
            sc_lk.unlock();
            if (_target_offset)
                progress::get().update("validate", (valid - _validate_start_offset), (*_target_offset - _validate_start_offset));
        }
    }

    void incremental::_process_vrf_update_chunks(uint64_t epoch_min_offset, cardano::state::vrf &vrf_state, const vector<uint64_t> &chunks)
    {
        auto epoch = _state.epoch();
        timer t { fmt::format("processed VRF nonce updates for epoch {}", epoch) };
        auto vrf_updates_ptr = std::make_shared<vector<index::vrf::item>>();
        for (const uint64_t chunk_id: chunks) {
            auto chunk_path = fmt::format("{}-{}.bin", _indexers.at("vrf")->chunk_path("update", chunk_id), epoch);
            vector<index::vrf::item> chunk_updates {};
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