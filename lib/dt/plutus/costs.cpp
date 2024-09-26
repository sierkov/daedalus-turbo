/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/config.hpp>
#include <dt/plutus/costs.hpp>
#include <dt/plutus/machine.hpp>

namespace daedalus_turbo::plutus::costs {
    using arg_map = map<std::string, std::string>;

    // the names of the classes match the names in the builtinCostModel config JSON
    struct constant_cost: cost_fun {
        constant_cost(const arg_map &args)
            : _cost { std::stoull(args.at("arguments")) }
        {
        }

        uint64_t cost(const arg_sizes &, const value_list &) const override
        {
            return _cost;
        }
    protected:
        const uint64_t _cost;
    };

    struct linear_in_x: cost_fun {
        linear_in_x(const arg_map &args):
            _intercept { std::stoull(args.at("arguments-intercept")) },
            _slope { std::stoull(args.at("arguments-slope")) }
        {
        }

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            return _intercept + _slope * sizes.at(0);
        }
    protected:
        const uint64_t _intercept, _slope;
    };

    struct linear_in_y: linear_in_x {
        using linear_in_x::linear_in_x;

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            return _intercept + _slope * sizes.at(1);
        }
    };

    struct linear_in_z: linear_in_x {
        using linear_in_x::linear_in_x;

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            return _intercept + _slope * sizes.at(2);
        }
    };

    struct linear_in_max_yz: linear_in_x {
        using linear_in_x::linear_in_x;

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            return _intercept + _slope * std::max(sizes.at(1), sizes.at(2));
        }
    };

    struct literal_in_y_or_linear_in_z: linear_in_x {
        using linear_in_x::linear_in_x;

        uint64_t cost(const arg_sizes &sizes, const value_list &args) const override
        {
            if (const auto &y_val = static_cast<uint64_t>(args.at(1).as_int()); y_val != 0)
                return (y_val + 7) / 8;
            return _intercept + _slope * sizes.at(2);
        }
    };

    struct linear_in_y_and_z: cost_fun {
        linear_in_y_and_z(const arg_map &args):
            _intercept { std::stoull(args.at("arguments-intercept")) },
            _slope1 { std::stoull(args.at("arguments-slope1")) },
            _slope2 { std::stoull(args.at("arguments-slope2")) }
        {
        }

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            return _intercept + _slope1 * sizes.at(1) + _slope2 * sizes.at(2);
        }
    protected:
        const uint64_t _intercept, _slope1, _slope2;
    };

    struct quadratic_in_y: cost_fun {
        quadratic_in_y(const arg_map &args):
            _c0 { std::stoull(args.at("arguments-c0")) },
            _c1 { std::stoull(args.at("arguments-c1")) },
            _c2 { std::stoull(args.at("arguments-c2")) }
        {
        }

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            const auto &y = sizes.at(1);
            return _c0 + _c1 * y + _c2 * y * y;
        }
    protected:
        const uint64_t _c0, _c1, _c2;
    };

    struct quadratic_in_z: quadratic_in_y {
        using quadratic_in_y::quadratic_in_y;

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            const auto &z = sizes.at(2);
            return _c0 + _c1 * z + _c2 * z * z;
        }
    };

    struct quadratic_in_x_and_y: cost_fun {
        quadratic_in_x_and_y(const arg_map &args):
            _c00 { std::stoll(args.at("arguments-c00")) },
            _c10 { std::stoll(args.at("arguments-c10")) },
            _c01 { std::stoll(args.at("arguments-c01")) },
            _c20 { std::stoll(args.at("arguments-c20")) },
            _c11 { std::stoll(args.at("arguments-c11")) },
            _c02 { std::stoll(args.at("arguments-c02")) }
        {
        }

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            const int64_t x = sizes.at(0);
            const int64_t y = sizes.at(1);
            const int64_t res = _c00 + _c10 * x + _c01 * y + _c20 * x * x + _c11 * x * y + _c02 * y * y;
            if (res >= 0) [[likely]]
                return static_cast<uint64_t>(res);
            throw error("quadratic_in_y_or_linear_in_z results in a negative cost!");
        }
    protected:
        const int64_t _c00, _c10, _c01, _c20, _c11, _c02;
    };

    struct added_sizes: linear_in_x {
        using linear_in_x::linear_in_x;

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            if (sizes.size() < 2) [[unlikely]]
                throw error("added_sizes costing function requires at least two arguments");
            const auto sum = std::accumulate(sizes.begin(), sizes.end(), uint64_t { 0 });
            return _intercept + _slope * sum;
        }
    };

    struct subtracted_sizes: linear_in_x {
        subtracted_sizes(const arg_map &args):
            linear_in_x { args },
            _minimum { std::stoull(args.at("arguments-minimum")) }
        {
        }

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            return _intercept + _slope * std::max(_minimum, (sizes.at(0) - sizes.at(1)));
        }
    protected:
        const uint64_t _minimum;
    };

    struct max_size: linear_in_x {
        using linear_in_x::linear_in_x;

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            if (sizes.size() < 2) [[unlikely]]
                throw error("max_size costing function requires at least two arguments");
            const auto max = std::max_element(sizes.begin(), sizes.end());
            return _intercept + _slope * (*max);
        }
    };

    struct min_size: linear_in_x {
        using linear_in_x::linear_in_x;

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            if (sizes.size() < 2) [[unlikely]]
                throw error("max_size costing function requires at least two arguments");
            const auto min = std::min_element(sizes.begin(), sizes.end());
            return _intercept + _slope * (*min);
        }
    };

    struct multiplied_sizes: linear_in_x {
        using linear_in_x::linear_in_x;

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            if (sizes.size() < 2) [[unlikely]]
                throw error("added_sizes costing function requires at least two arguments");
            const auto prod = std::accumulate(sizes.begin(), sizes.end(), uint64_t { 1 }, std::multiplies<uint64_t>());
            return _intercept + _slope * prod;
        }
    };

    static cost_fun_ptr cost_fun_from_prefixed_args(const arg_map &prefixed_args, const std::string &prefix);

    struct const_above_diagonal: cost_fun {
        const_above_diagonal(const arg_map &args):
            _cost { std::stoull(args.at("arguments-constant")) },
            _model { cost_fun_from_prefixed_args(args, "arguments-model-") }
        {
        }

        uint64_t cost(const arg_sizes &sizes, const value_list &args) const override
        {
            const auto &x = sizes.at(0);
            const auto &y = sizes.at(1);
            if (x < y)
                return _cost;
            return _model->cost(sizes, args);
        }
    protected:
        const uint64_t _cost;
        const cost_fun_ptr _model;
    };

    struct const_below_diagonal: const_above_diagonal {
        using const_above_diagonal::const_above_diagonal;

        uint64_t cost(const arg_sizes &sizes, const value_list &args) const override
        {
            const auto &x = sizes.at(0);
            const auto &y = sizes.at(1);
            if (x > y)
                return _cost;
            return _model->cost(sizes, args);
        }
    };

    struct linear_on_diagonal: linear_in_x {
        linear_on_diagonal(const arg_map &args):
            linear_in_x { args },
            _cost { std::stoull(args.at("arguments-constant")) }
        {
        }

        uint64_t cost(const arg_sizes &sizes, const value_list &) const override
        {
            const auto &x = sizes.at(0);
            const auto &y = sizes.at(1);
            if (x == y)
                return _intercept + _slope * x;
            return _cost;
        }
    protected:
        const uint64_t _cost;
    };

    static op_tag op_tag_from_cek_name(const std::string &name) {
        if (name == "cekApplyCost")
            return term_tag::apply;
        if (name == "cekBuiltinCost")
            return term_tag::builtin;
        if (name == "cekCaseCost")
            return term_tag::acase;
        if (name == "cekConstCost")
            return term_tag::constant;
        if (name == "cekConstrCost")
            return term_tag::constr;
        if (name == "cekDelayCost")
            return term_tag::delay;
        if (name == "cekForceCost")
            return term_tag::force;
        if (name == "cekLamCost")
            return term_tag::lambda;
        if (name == "cekStartupCost")
            return other_tag::startup;
        if (name == "cekVarCost")
            return term_tag::variable;
        throw error("unsupported CEK cost item: {}", name);
    }

    static cost_fun_ptr cost_fun_from_args(const arg_map &args)
    {
        const auto &typ = args.at("type");
        if (typ == "constant_cost")
            return std::make_unique<constant_cost>(args);
        if (typ == "added_sizes")
            return std::make_unique<added_sizes>(args);
        if (typ == "min_size")
            return std::make_unique<min_size>(args);
        if (typ == "max_size")
            return std::make_unique<max_size>(args);
        if (typ == "multiplied_sizes")
            return std::make_unique<multiplied_sizes>(args);
        if (typ == "linear_in_x")
            return std::make_unique<linear_in_x>(args);
        if (typ == "linear_in_y")
            return std::make_unique<linear_in_y>(args);
        if (typ == "linear_in_z")
            return std::make_unique<linear_in_z>(args);
        if (typ == "quadratic_in_y")
            return std::make_unique<quadratic_in_y>(args);
        if (typ == "quadratic_in_z")
            return std::make_unique<quadratic_in_z>(args);
        if (typ == "quadratic_in_x_and_y")
            return std::make_unique<quadratic_in_x_and_y>(args);
        if (typ == "literal_in_y_or_linear_in_z")
            return std::make_unique<literal_in_y_or_linear_in_z>(args);
        if (typ == "linear_in_max_yz")
            return std::make_unique<linear_in_max_yz>(args);
        if (typ == "linear_in_y_and_z")
            return std::make_unique<linear_in_y_and_z>(args);
        if (typ == "subtracted_sizes")
            return std::make_unique<subtracted_sizes>(args);
        if (typ == "const_above_diagonal")
            return std::make_unique<const_above_diagonal>(args);
        if (typ == "const_below_diagonal")
            return std::make_unique<const_below_diagonal>(args);
        if (typ == "linear_on_diagonal")
            return std::make_unique<linear_on_diagonal>(args);
        throw error("unsupported cost model type: {}", typ);
    }

    static cost_fun_ptr cost_fun_from_prefixed_args(const arg_map &prefixed_args, const std::string &prefix)
    {
        arg_map args {};
        for (const auto &[k, v]: prefixed_args) {
            if (k.starts_with(prefix)) {
                const auto [it, created] = args.try_emplace(k.substr(prefix.size()), v);
                if (!created) [[unlikely]]
                    throw error("duplicate argument {}", k);
            }
        }
        return cost_fun_from_args(args);
    }

    static op_model op_model_from_args(const arg_map &args)
    {
        if (args.empty()) [[unlikely]]
            throw error("cost arguments must be non-empty!");
        arg_map cpu_args {};
        arg_map mem_args {};
        for (const auto &[k, v]: args) {
            const auto pos = k.find('-');
            if (pos == k.npos) {
                if (k == "exBudgetCPU") {
                    cpu_args.emplace("arguments", v);
                    cpu_args.emplace("type", "constant_cost");
                } else if (k == "exBudgetMemory") {
                    mem_args.emplace("arguments", v);
                    mem_args.emplace("type", "constant_cost");
                } else {
                    throw error("unsupported cost argument name: {}", k);
                }
            } else {
                const auto cat_name = k.substr(0, pos);
                const auto sub_name = k.substr(pos + 1);
                if (cat_name == "cpu") {
                    cpu_args.emplace(sub_name, v);
                } else if (cat_name == "memory") {
                    mem_args.emplace(sub_name, v);
                } else {
                    throw error("unsupported cost argument category: {}", cat_name);
                }
            }
        }
        return { cost_fun_from_args(cpu_args), cost_fun_from_args(mem_args) };
    }

    static arg_map cost_args_from_json(const std::string &prefix, const json::object &o)
    {
        arg_map args {};
        for (const auto &[k, v]: o) {
            switch (v.kind()) {
                case json::kind::object: {
                    auto sub_args = cost_args_from_json(fmt::format("{}{}-", prefix, static_cast<std::string_view>(k)), v.as_object());
                    for (auto &&[k, v]: sub_args)
                        args.try_emplace(k, std::move(v));
                    break;
                }
                case json::kind::uint64:
                case json::kind::int64:
                    args.try_emplace(fmt::format("{}{}", prefix, static_cast<std::string_view>(k)), fmt::format("{}", json::value_to<int64_t>(v)));
                    break;
                case json::kind::string:
                    args.try_emplace(fmt::format("{}{}", prefix, static_cast<std::string_view>(k)), fmt::format("{}", json::value_to<std::string>(v)));
                    break;
                default: throw error("unsupported json kind at {}{}: {}", prefix, static_cast<std::string_view>(k), static_cast<int>(v.kind()));
            }
        }
        return args;
    }

    static arg_map load_cost_args(const std::string &cek_path, const std::string &builtin_path)
    {
        auto args = cost_args_from_json("", json::load(builtin_path).as_object());
        auto sub_args = cost_args_from_json("", json::load(cek_path).as_object());
        for (auto &&[k, v]: sub_args)
            args.try_emplace(k, std::move(v));
        return args;
    }

    static arg_map plutus_costs_to_args(const cardano::plutus_cost_model &model, const arg_map &defaults)
    {
        arg_map args { defaults };
        for (const auto &[k, v]: model) {
            const auto pos = k.find('-');
            if (pos == 0 || pos == k.npos) [[unlikely]]
                throw error("invalid cost model item: {}", k);
            auto op_name = k.substr(0, pos);
            switch (op_name[0]) {
                case 'b':
                    if (op_name == "blake2b")
                        op_name = "blake2b_256";
                    break;
                case 'v':
                    if (op_name == "verifySignature")
                        op_name = "verifyEd25519Signature";
                    break;
                default: break;
            }
            const auto arg_name = k.substr(pos + 1);
            args.try_emplace(fmt::format("{}-{}", op_name, arg_name), fmt::format("{}", v));
        }
        return args;
    }

    static parsed_model parse(const arg_map &args)
    {
        using tmp_model = map<op_tag, arg_map>;
        tmp_model tmp {};
        set<std::string> unknown_builtins {};
        for (const auto &[k, v]: args) {
            const auto pos = k.find('-');
            if (pos == k.npos) [[unlikely]]
                throw error("invalid cost model item: {}", k);
            const auto op_name = k.substr(0, pos);
            const auto arg_name = k.substr(pos + 1);
            if (op_name.starts_with("cek")) {
                const auto [it, created] = tmp[op_tag_from_cek_name(op_name)].try_emplace(arg_name, v);
                if (!created) [[unlikely]]
                            throw error("duplicate argument {} for op {}", arg_name, op_name);
            } else if (builtin_tag_known_name(op_name)) {
                const auto [it, created] = tmp[builtin_tag_from_name(op_name)].try_emplace(arg_name, v);
                if (!created) [[unlikely]]
                            throw error("duplicate argument {} for op {}", arg_name, op_name);
            } else {
                // configs do contain builtins that are not on mainnet, such as addByteString
                // log each unsupported builtin only once
                if (const auto [it, created] = unknown_builtins.emplace(op_name); created)
                    logger::debug("found cost model for an unsupported builtin: {}", op_name);
            }
        }
        parsed_model m {};
        for (const auto &[t, args]: tmp) {
            const auto [it, created] = m.try_emplace(t, op_model_from_args(args));
            if (!created) [[unlikely]]
                throw error("internal error: duplicate tag in the parsed cost model!");
        }
        return m;
    }

    static const arg_map &default_cost_args_v1()
    {
        static auto args = load_cost_args("./etc/plutus/cekMachineCostsA.json", "./etc/plutus/builtinCostModelA.json");
        return args;
    }

    static const arg_map &default_cost_args_v2()
    {
        static auto args = load_cost_args("./etc/plutus/cekMachineCostsB.json", "./etc/plutus/builtinCostModelB.json");
        return args;
    }

    static const arg_map &default_cost_args_v3()
    {
        static auto args = load_cost_args("./etc/plutus/cekMachineCostsC.json", "./etc/plutus/builtinCostModelC.json");
        return args;
    }

    parsed_models parse(const cardano::plutus_cost_models &models)
    {
        parsed_models res {};
        res.v1.emplace(parse(models.v1 ? plutus_costs_to_args(*models.v1, default_cost_args_v1()) : default_cost_args_v1()));
        res.v2.emplace(parse(models.v2 ? plutus_costs_to_args(*models.v2, default_cost_args_v2()) : default_cost_args_v2()));
        res.v3.emplace(parse(models.v3 ? plutus_costs_to_args(*models.v3, default_cost_args_v3()) : default_cost_args_v3()));
        return res;
    }

    const parsed_models &defaults()
    {
        static auto models = parse(cardano::config::get().plutus_all_cost_models);
        return models;
    }
}