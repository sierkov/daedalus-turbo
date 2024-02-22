/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_VALIDATOR_HPP
#define DAEDALUS_TURBO_VALIDATOR_HPP

#include <dt/cardano/state/vrf.hpp>
#include <dt/index/timed-update.hpp>
#include <dt/index/txo.hpp>
#include <dt/indexer.hpp>
#include <dt/mutex.hpp>
#include <dt/validator/state.hpp>
#include <dt/validator/subchain.hpp>

namespace daedalus_turbo::validator {
    extern indexer::indexer_map default_indexers(scheduler &sched, const std::string &data_dir);
    static constexpr size_t snapshot_hifreq_end_offset_range = static_cast<uint64_t>(1) << 30;
    static constexpr size_t snapshot_hifreq_distance = static_cast<uint64_t>(1) << 27;;
    static constexpr size_t snapshot_normal_distance = indexer::merger::part_size * 2;

    struct incremental: indexer::incremental {
        incremental(scheduler &sched, const std::string &data_dir, indexer::indexer_map &indexers, bool on_the_go=true);
        void clean_up() override;
        file_set truncate(size_t max_end_offset, bool del=true) override;
        void save_state() override;
    protected:
        std::pair<uint64_t, file_set> _load_state(bool strict=true) override;
        chunk_info _parse_normal(uint64_t offset, const std::string &rel_path,
            const buffer &raw_data, size_t compressed_size, const block_processor &extra_proc) const override;
    private:
        using timed_update_list = std::vector<index::timed_update::item>;
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
        
        const std::filesystem::path _validate_dir;
        const std::string _state_path;
        state _state;
        cardano::state::vrf _vrf_state {};
        alignas(mutex::padding) mutable std::mutex _subchains_mutex {};
        mutable subchain_list _subchains { [this](const auto &sc) { _save_subchains_snapshot(sc); } };
        std::atomic_bool _validation_running { false };
        alignas(mutex::padding) mutable std::mutex _next_task_mutex {};
        uint64_t _validate_start_offset = 0;
        uint64_t _next_end_offset = 0;
        uint64_t _next_last_epoch = 0;
        snapshot_list _snapshots {};
        bool _on_the_go = true;
        
        uint64_t _load_state_snapshot(uint64_t end_offset);
        void _save_state_snapshot(bool record=true);
        void _save_subchains_snapshot(const subchain &sc) const;
        std::string _storage_path(const std::string_view &prefix, uint64_t end_offset) const;
        void _on_slice_ready(uint64_t first_epoch, uint64_t last_epoch, const indexer::merger::slice &slice) override;
        void _schedule_validation(std::unique_lock<std::mutex> &&next_task_lk);
        std::vector<std::string> _index_slice_paths(const std::string &name, const indexer::slice_list &slices) const;
        void _prepare_outflows_part(index::reader_multi_mt<index::txo_use::item> &txo_use_reader,
            index::reader_multi_mt<index::txo::item> &txo_reader, size_t part_no,
            uint64_t validate_start_offset, uint64_t validate_end_offset) const;
        size_t _prepare_outflows(uint64_t validate_start_offset, uint64_t validate_end_offset, const indexer::slice_list &slices) const;
        void _process_epoch_updates(uint64_t epoch, const std::vector<uint64_t> &inflow_chunks, size_t num_outflow_parts) const;
        void _process_updates(size_t num_outflow_parts, uint64_t first_epoch, uint64_t last_epoch);
        template<typename T>
        std::optional<uint64_t> _gather_updates(std::vector<T> &updates, uint64_t epoch, uint64_t min_offset, const std::string &name, const index::epoch_chunks &updated_chunks);
        void _apply_ledger_state_updates_for_epoch(uint64_t e, index::reader_multi<index::txo::item> &txo_reader,
            const index::epoch_chunks &vrf_updates, const std::vector<uint64_t> &snapshot_offsets);
        void _apply_ledger_state_updates(uint64_t first_epoch, uint64_t last_epoch, const indexer::slice_list &slices);
        void _validate_epoch_leaders(uint64_t epoch, uint64_t epoch_min_offset, const std::shared_ptr<std::vector<index::vrf::item>> &vrf_updates_ptr,
            const std::shared_ptr<pool_stake_distribution> &pool_dist_ptr,
            const cardano::vrf_nonce &nonce_epoch, const cardano::vrf_nonce &uc_nonce, const cardano::vrf_nonce &uc_leader,
            size_t start_idx, size_t end_idx);        
        void _process_vrf_update_chunks(uint64_t epoch_min_offset, cardano::state::vrf &vrf_state, const std::vector<uint64_t> &chunks);
    };
}

#endif // !DAEDALUS_TURBO_VALIDATOR_HPP