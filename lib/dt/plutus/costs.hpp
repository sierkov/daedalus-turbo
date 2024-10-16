/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_COSTS_HPP
#define DAEDALUS_TURBO_PLUTUS_COSTS_HPP

#include <dt/cardano/types.hpp>
#include <dt/plutus/types.hpp>

namespace daedalus_turbo::plutus::costs {
    using startup_tag = std::monostate;
    using op_tag = std::variant<term_tag, builtin_tag, startup_tag>;

    using arg_sizes = vector<uint64_t>;
    struct cost_fun {
        virtual ~cost_fun() =default;
        virtual uint64_t cost(const arg_sizes &sizes, const value_list &args) const =0;
    };
    using cost_fun_ptr = std::unique_ptr<cost_fun>;

    struct op_model {
        cost_fun_ptr cpu {};
        cost_fun_ptr mem {};
    };

    struct parsed_model {
        cardano::ex_units startup_op;
        cardano::ex_units apply_op;
        cardano::ex_units builtin_op;
        cardano::ex_units case_op;
        cardano::ex_units constant_op;
        cardano::ex_units constr_op;
        cardano::ex_units delay_op;
        cardano::ex_units force_op;
        cardano::ex_units lambda_op;
        cardano::ex_units variable_op;
        unordered_map<builtin_tag, op_model> builtin_fun {};
    };

    struct parsed_models {
        std::optional<parsed_model> v1 {};
        std::optional<parsed_model> v2 {};
        std::optional<parsed_model> v3 {};
    };

    extern parsed_models parse(const cardano::plutus_cost_models &);
    extern const parsed_models &defaults();
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::plutus::costs::op_tag>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::costs::op_tag &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus::costs;
            return std::visit([&ctx](const auto &vv) {
                using T = std::decay_t<decltype(vv)>;
                if constexpr (std::is_same_v<T, startup_tag>)
                    return fmt::format_to(ctx.out(), "startup");
                else
                    return fmt::format_to(ctx.out(), "{}", vv);
            }, v);
        }
    };
}

#endif //DAEDALUS_TURBO_PLUTUS_BUILTINS_HPP