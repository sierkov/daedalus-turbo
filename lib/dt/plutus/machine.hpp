/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_MACHINE_HPP
#define DAEDALUS_TURBO_PLUTUS_MACHINE_HPP

#include <memory_resource>
#include <dt/memory.hpp>
#include <dt/plutus/builtins.hpp>
#include <dt/plutus/costs.hpp>
#include <dt/plutus/types.hpp>

namespace daedalus_turbo::plutus {
    using optional_budget = std::optional<cardano::ex_units>;

    struct machine {
        struct result {
            const term expr;
            const cardano::ex_units cost;

            bool operator==(const result& o) const
            {
                return *expr == *o.expr && cost == o.cost;
            }
        };

        static uint64_t mem_usage(const value &v);

        machine(allocator &alloc, const costs::parsed_model &model=costs::defaults().v3.value(),
                const builtin_map &semantics=builtins::semantics_v2(), const optional_budget &budget={});
        ~machine();
        term apply_args(const term &expr, const term_list &args);
        result evaluate(const term &expr);
        void evaluate_no_res(const term &expr);
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif //DAEDALUS_TURBO_PLUTUS_MACHINE_HPP