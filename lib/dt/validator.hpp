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
