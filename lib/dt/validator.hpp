/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_VALIDATOR_HPP
#define DAEDALUS_TURBO_VALIDATOR_HPP

#include <dt/indexer.hpp>

namespace daedalus_turbo::cardano::ledger {
    struct state;
}

namespace daedalus_turbo::validator {
    static constexpr std::string_view validate_leaders_task { "validate-epoch" };

    struct snapshot {
        uint64_t epoch;
        uint64_t end_offset;
        uint64_t last_slot;
        bool exportable;

        static snapshot from_json(const json::value &j);
        snapshot(const cardano::ledger::state &st);
        snapshot(uint64_t epoch_, uint64_t end_offset_, uint64_t last_slot_, bool exportable_);
        json::object to_json() const;

        bool operator==(const snapshot &o) const
        {
            return epoch == o.epoch && end_offset == o.end_offset && last_slot == o.last_slot && exportable == o.exportable;
        }

        bool operator<(const snapshot &b) const
        {
            return end_offset < b.end_offset;
        }
    };

    struct snapshot_set: set<snapshot> {
        using set::set;

        using action_t = std::function<void(const snapshot &)>;
        using const_iterator = typename set<snapshot>::const_iterator;

        const_iterator next_excessive() const;
        void remove_excessive(const action_t &on_remove, const action_t &on_keep);
    };

    extern indexer::indexer_map default_indexers(const std::string &data_dir, scheduler &sched=scheduler::get());

    struct incremental {
        incremental(chunk_registry &cr);
        ~incremental();
        [[nodiscard]] cardano::amount unspent_reward(const cardano::stake_ident &id) const;
        [[nodiscard]] cardano::tail_relative_stake_map tail_relative_stake() const;
        [[nodiscard]] cardano::optional_point core_tip() const;
        [[nodiscard]] cardano::optional_point tip() const;
        [[nodiscard]] cardano::optional_slot can_export(const cardano::optional_point &immutable_tip) const;
        std::string node_export(const std::filesystem::path &ledger_dir, const cardano::optional_point &immutable_tip, int prio=1000) const;
        [[nodiscard]] const cardano::ledger::state &state() const;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_VALIDATOR_HPP
