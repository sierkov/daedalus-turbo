/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/config.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/plutus/builtins.hpp>
#include <dt/plutus/machine.hpp>

namespace daedalus_turbo::plutus {
    struct machine::impl {
        static uint64_t mem_usage(const value &v)
        {
            return _mem_usage(*v);
        }

        impl(allocator &alloc, const costs::parsed_model &model, const builtin_map &semantics, const optional_budget &budget):
            _alloc { alloc }, _cost_model { model }, _budget { budget }, _semantics { semantics }
        {
        }

        void evaluate_no_res(const term &expr)
        {
            _eval(expr);
        }

        result evaluate(const term &expr)
        {
            const auto res_v = _eval(expr);
            return { _discharge(*res_v), _cost };
        }

        term apply_args(const term &expr, const term_list &args)
        {
            //file::write(install_path("tmp/script-args-my.txt"), fmt::format("{}\n", args));
            term t = expr;
            for (const auto &arg: *args)
                t = term { _alloc, apply { t, arg } };
            return t;
        }
    private:
        allocator &_alloc;
        const costs::parsed_model &_cost_model;
        optional_budget _budget;
        cardano::ex_units _cost {};
        value_list _empty_args { _alloc };
        const builtin_map &_semantics;

        static uint64_t _mem_usage(const bint_type &i)
        {
            if (*i > 0)
                return boost::multiprecision::msb(*i) / 64 + 1;
            if (*i < 0) {
                if (const auto i_adj = *i + 1; i_adj != 0) [[likely]]
                    return boost::multiprecision::msb(i_adj * -1) / 64 + 1;
                return 1;
            }
            return 1;
        }

        static uint64_t _mem_usage(const uint64_t i)
        {
            if (i > 0)
                return boost::multiprecision::msb(i) / 64 + 1;
            return 1;
        }

        static uint64_t _mem_usage(const buffer b)
        {
            if (!b.empty()) [[likely]]
                return (b.size() - 1) / 8 + 1;
            return 1;
        }

        static uint64_t _mem_usage(const std::string_view s)
        {
            return s.size();
        }

        static uint64_t _mem_usage(const data::list_type &l)
        {
            uint64_t sum = 0;
            for (const auto &d: l)
                sum += _mem_usage(d);
            return sum;
        }

        static uint64_t _mem_usage(const data &d)
        {
            return std::visit([](const auto &v) {
                using t = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<t, data_constr>) {
                    return 4 + _mem_usage(v->second);
                } else if constexpr (std::is_same_v<t, data::map_type>) {
                    uint64_t sum = 4;
                    for (const auto &p: v)
                        sum += _mem_usage(p->first) + _mem_usage(p->second);
                    return sum;
                } else if constexpr (std::is_same_v<t, data::bstr_type>) {
                    return 4 + _mem_usage(*v);
                } else {
                    return 4 + _mem_usage(v);
                }
            }, *d);
        }

        static uint64_t _mem_usage(const constant &c)
        {
            return std::visit([](const auto &v) {
                using T = std::decay_t<decltype(v)>;
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, std::monostate>) {
                    return static_cast<uint64_t>(1);
                } else if constexpr (std::is_same_v<T, bool>) {
                    return static_cast<uint64_t>(1);
                } else if constexpr (std::is_same_v<T, bstr_type>) {
                    return _mem_usage(buffer { *v });
                } else if constexpr (std::is_same_v<T, data>) {
                    return _mem_usage(v);
                } else if constexpr (std::is_same_v<T, str_type>) {
                    return _mem_usage(std::string_view { *v });
                } else if constexpr (std::is_same_v<T, bls12_381_g1_element>) {
                    return static_cast<uint64_t>(sizeof(bls12_381_g1_element) / 8);
                } else if constexpr (std::is_same_v<T, bls12_381_g2_element>) {
                    return static_cast<uint64_t>(sizeof(bls12_381_g2_element) / 8);
                } else if constexpr (std::is_same_v<T, bls12_381_ml_result>) {
                    return static_cast<uint64_t>(sizeof(bls12_381_ml_result) / 8);
                } else if constexpr (std::is_same_v<T, constant_list>) {
                    uint64_t sum = 0;
                    for (const auto &ci: v->vals)
                        sum += _mem_usage(ci);
                    return sum;
                } else if constexpr (std::is_same_v<T, constant_pair>) {
                    return _mem_usage(v->first) + _mem_usage(v->second);
                } else {
                    return _mem_usage(v);
                }
            }, *c);
        }

        static uint64_t _mem_usage(const value::value_type &val)
        {
            if (std::holds_alternative<constant>(val))
                return _mem_usage(std::get<constant>(val));
            return 1;
        }

        value _eval(const term &expr)
        {
            _cost = {};
            _spend(_cost_model.startup_op);
            const environment empty_env {};
            return _compute(empty_env, expr);
        }

        void _check_budget() const
        {
            if (_budget) {
                if (_cost.steps > _budget->steps) [[unlikely]]
                    throw error("plutus program CPU cost has exceeded it's budget: {}", _budget->steps);
                if (_cost.mem > _budget->mem) [[unlikely]]
                    throw error("plutus program memory has exceeded it's budget: {}", _budget->mem);
            }
        }

        void _spend(const uint64_t mem_cost, const uint64_t cpu_cost)
        {
            _cost.steps += cpu_cost;
            _cost.mem += mem_cost;
            //logger::info("SPEND cpu: {} mem: {} TOTAL cpu: {} mem: {}", cpu_cost, mem_cost, _cost.steps, _cost.mem);
            _check_budget();
        }

        void _spend(const cardano::ex_units &c)
        {
            _spend(c.mem, c.steps);
        }

        void _spend(const builtin_tag tag, const value_list &args)
        {
            costs::arg_sizes sizes {};
            for (const auto &arg: *args) {
                sizes.emplace_back(_mem_usage(*arg));
            }
            const auto &op_model = _cost_model.builtin_fun.at(tag);
            const auto cpu_cost = op_model.cpu->cost(sizes, args);
            const auto mem_cost = op_model.mem->cost(sizes, args);
            _spend(mem_cost, cpu_cost);
        }

        void _spend(const builtin_tag tag)
        {
            _spend(tag, _empty_args);
        }

        std::optional<value> _lookup_opt(const environment &env, const size_t var_idx) const
        {
            for (const auto *node = env.get(); node != nullptr; node = node->parent.get()) {
                if (node->var_idx == var_idx)
                    return node->val;
            }
            return {};
        }

        value _lookup(const environment &env, const size_t var_idx) const
        {
            if (auto ptr_opt = _lookup_opt(env, var_idx); ptr_opt)
                return std::move(*ptr_opt);
            throw error("reference to a free variable: v{}", var_idx);
        }

        term _discharge_term(const environment &env, const term &t, const int64_t level, const int64_t var_idx_diff) const
        {
            return std::visit<term>([&](const auto &v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, variable>) {
                    if (const auto ptr_opt = _lookup_opt(env, v.idx); ptr_opt)
                        return _discharge(**ptr_opt, level, var_idx_diff);
                    return term { _alloc, variable { narrow_cast<size_t>(static_cast<int64_t>(v.idx) + var_idx_diff) } };
                } else if constexpr (std::is_same_v<T, t_lambda>) {
                    return term { _alloc, t_lambda { narrow_cast<size_t>(level), _discharge_term(env, v.expr, level + 1, level - static_cast<int64_t>(v.var_idx)) } };
                } else if constexpr (std::is_same_v<T, apply>) {
                    return term { _alloc, apply { _discharge_term(env, v.func, level, var_idx_diff), _discharge_term(env, v.arg, level, var_idx_diff) } };
                } else if constexpr (std::is_same_v<T, force>) {
                    return term { _alloc, force { _discharge_term(env, v.expr, level, var_idx_diff) } };
                } else if constexpr (std::is_same_v<T, t_delay>) {
                    return term { _alloc, t_delay { _discharge_term(env, v.expr, level, var_idx_diff) } };
                } else if constexpr (std::is_same_v<T, t_case>) {
                    term_list::value_type l { _alloc };
                    l.reserve(v.cases->size());
                    for (auto &c: *v.cases)
                        l.emplace_back(_discharge_term(env, c, level, var_idx_diff));
                    return term { _alloc, t_case { _discharge_term(env, v.arg, level, var_idx_diff), term_list { _alloc, std::move(l) } } };
                } else if constexpr (std::is_same_v<T, t_constr>) {
                    term_list::value_type l { _alloc };
                    l.reserve(v.args->size());
                    for (auto &a: *v.args)
                        l.emplace_back(_discharge_term(env, a, level, var_idx_diff));
                    return term { _alloc, t_constr { v.tag, term_list { _alloc, std::move(l) } } };
                } else {
                    return t;
                }
            }, *t);
        }

        term _discharge(const value::value_type &val, const int64_t level=0, const int64_t &var_idx_diff=0) const
        {
            return std::visit<term>([&](const auto &v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, constant>) {
                    return term { _alloc, v };
                } else if constexpr (std::is_same_v<T, v_delay>) {
                    return _discharge_term(v.env, { _alloc, t_delay { v.expr } }, level, var_idx_diff);
                } else if constexpr (std::is_same_v<T, v_lambda>) {
                    return _discharge_term(v.env, { _alloc, t_lambda { v.var_idx, v.body } }, level, var_idx_diff);
                } else if constexpr (std::is_same_v<T, v_builtin>) {
                    auto t = term { _alloc, v.b };
                    for (size_t i = 0; i < v.forces; ++i)
                        t = term { _alloc, force { std::move(t) } };
                    for (const auto &arg: *v.args)
                        t = term { _alloc, apply { std::move(t), _discharge(*arg, level, var_idx_diff) } };
                    return t;
                } else if constexpr (std::is_same_v<T, v_constr>) {
                    term_list::value_type args { _alloc };
                    for (const auto &arg: *v.args)
                        args.emplace_back(_discharge(*arg, level, var_idx_diff));
                    t_constr pc { v.tag, term_list { _alloc, std::move(args) } };
                    return term { _alloc, std::move(pc) };
                } else {
                    throw error("an unsupported value type to discharge: {}", typeid(v).name());
                }
            }, val);
        }

        builtin_any _get_builtin_func(const builtin_tag b)
        {
            return _semantics.at(b).func;
        }

        value _apply_builtin(const v_builtin &b)
        {
            const auto num_args = b.b.num_args();
            if (b.args->size() != num_args) [[unlikely]]
                throw error("can't apply builtin {} to {} arguments: {} arguments are required!", b.b.tag, b.args->size(), num_args);
            _spend(b.b.tag, b.args);
            const auto func = _get_builtin_func(b.b.tag);
            switch (num_args) {
                case 1: return std::get<builtin_one_arg>(func)(_alloc, b.args->at(0));
                case 2: return std::get<builtin_two_arg>(func)(_alloc, b.args->at(0), b.args->at(1));
                case 3: return std::get<builtin_three_arg>(func)(_alloc, b.args->at(0), b.args->at(1), b.args->at(2));
                case 6: return std::get<builtin_six_arg>(func)(_alloc, b.args->at(0), b.args->at(1), b.args->at(2), b.args->at(3), b.args->at(4), b.args->at(5));
                default: throw error("unsupported number of arguments: {}!", num_args);
            }
        }

        value _apply(const value::value_type &func, const value &arg)
        {
            return std::visit([&arg, this](const auto &f) {
                using T = std::decay_t<decltype(f)>;
                if constexpr (std::is_same_v<T, v_lambda>) {
                    const environment new_env { _alloc, f.env, f.var_idx, arg };
                    return _compute(new_env, f.body);
                }
                if constexpr (std::is_same_v<T, v_builtin>) {
                    value_list::value_type new_args { _alloc };
                    for (const auto &arg: *f.args)
                        new_args.emplace_back(arg);
                    new_args.emplace_back(arg);
                    v_builtin new_b { f.b, { _alloc, std::move(new_args) }, f.forces };
                    if (new_b.b.polymorphic_args() != new_b.forces)
                        throw error("an application of an polymorphic builtin with an incorrect number of forces: {}", new_b.b.tag);
                    if (new_b.args->size() < new_b.b.num_args()) [[likely]]
                        return value { _alloc, std::move(new_b) };
                    return _apply_builtin(new_b);
                }
                throw error("only lambdas and builtins can be applied but got: {}", typeid(T).name());
                return value { _alloc, constant { _alloc, std::monostate {} } };
            }, func);
        }

        value _force(const value &val)
        {
            return std::visit([this](const auto &v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, v_delay>)
                    return _compute(v.env, v.expr);
                if constexpr (std::is_same_v<T, v_builtin>) {
                    if (v.args->size() == v.b.num_args())
                        return _apply_builtin(v);
                    if (v.forces < v.b.polymorphic_args()) {
                        auto new_b = v;
                        ++new_b.forces;
                        return value { _alloc, std::move(new_b) };
                    }
                    throw error("an unexpected force of a builtin: {} polymorhpic_args: {} num_forces: {}", v.b.tag, v.b.polymorphic_args(), v.forces);
                }
                throw error("unsupported value for force: {}", typeid(T).name());
                return value { _alloc, constant { _alloc, std::monostate {} } };
            }, *val);
        }

        value _compute(const environment &env, const variable &e)
        {
            _spend(_cost_model.variable_op);
            return _lookup(env, e.idx);
        }

        value _compute(const environment &, const constant &e)
        {
            _spend(_cost_model.constant_op);
            return { _alloc, e };
        }

        value _compute(const environment &env, const t_lambda &e)
        {
            _spend(_cost_model.lambda_op);
            return { _alloc, v_lambda { env, e.var_idx, e.expr } };
        }

        value _compute(const environment &env, const t_delay &e)
        {
            _spend(_cost_model.delay_op);
            return { _alloc, v_delay { env, e.expr } };
        }

        value _compute(const environment &, const t_builtin &e)
        {
            _spend(_cost_model.builtin_op);
            return { _alloc, v_builtin { e, { _alloc } } };
        }

        value _compute(const environment &env, const force &e)
        {
            _spend(_cost_model.force_op);
            return _force(_compute(env, e.expr));
        }

        value _compute(const environment &env, const apply &e)
        {
            _spend(_cost_model.apply_op);
            const auto fun = _compute(env, e.func);
            const auto arg = _compute(env, e.arg);
            return _apply(*fun, arg);
        }

        value _compute(const environment &env, const t_constr &e)
        {
            _spend(_cost_model.constr_op);
            value_list::value_type v_args { _alloc };
            for (const auto &arg: *e.args)
                v_args.emplace_back(_compute(env, arg));
            return value { _alloc, v_constr { e.tag, { _alloc, std::move(v_args) } } };
        }

        value _compute(const environment &env, const t_case &e)
        {
            _spend(_cost_model.case_op);
            const auto v_arg = _compute(env, e.arg);
            const auto &cc = v_arg.as_constr();
            if (cc.tag >= e.cases->size())
                throw error("a case argument must have been less than {} but got {}!", e.cases->size(), cc.tag);
            auto res = _compute(env, e.cases->at(cc.tag));
            for (size_t i = 0; i < cc.args->size(); ++i)
                res = _apply(*res, cc.args->at(i));
            return res;
        }

        value _compute(const environment &, const failure &)
        {
            throw error("the plutus script reported an error!");
        }

        value _compute(const environment &env, const term &t)
        {
            return std::visit([&env, this](const auto &e) {
                return _compute(env, e);
            }, *t);
        }
    };

    uint64_t machine::mem_usage(const value &v)
    {
        return impl::mem_usage(v);
    }

    machine::machine(allocator &alloc, const cardano::script_type typ, const optional_budget &budget)
    {
        using cardano::script_type;
        switch (typ) {
            case script_type::plutus_v1:
                _impl = std::make_unique<impl>(alloc, costs::defaults().v1.value(), builtins::semantics_v1(), budget);
                break;
            case script_type::plutus_v2:
                _impl = std::make_unique<impl>(alloc, costs::defaults().v2.value(), builtins::semantics_v1(), budget);
                break;
            case script_type::plutus_v3:
                _impl = std::make_unique<impl>(alloc, costs::defaults().v3.value(), builtins::semantics_v2(), budget);
                break;
            default: throw error("unsupported script type: {}", typ);
        }
    }

    machine::machine(allocator &alloc, const costs::parsed_model &model, const builtin_map &semantics, const optional_budget &budget):
        _impl { std::make_unique<impl>(alloc, model, semantics, budget) }
    {
    }

    machine::~machine() =default;

    machine::result machine::evaluate(const term &expr)
    {
        return _impl->evaluate(expr);
    }

    void machine::evaluate_no_res(const term &expr)
    {
        _impl->evaluate_no_res(expr);
    }
}
