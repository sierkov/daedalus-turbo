/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cbor/zero.hpp>
#include <dt/plutus/builtins.hpp>
#include <dt/plutus/machine.hpp>

namespace daedalus_turbo::plutus {
    struct machine::impl {
        impl(allocator &alloc, const version &ver, const optional_budget &budget, const costs::parsed_models &models):
            _alloc { alloc }, _cost_model { _cost_model_for_ver(models, ver) }, _budget { budget }
        {
        }

        result evaluate(const term_ptr &expr, const term_list &args)
        {
            term_ptr t = expr;
            for (const auto &arg: args)
                t = term::make_ptr(_alloc, apply { t, arg });
            return evaluate(t);
        }

        result evaluate(const term_ptr &expr)
        {
            _cost = {};
            _spend(_cost_model.startup_op);
            const environment empty_env {};
            const auto res_v = _compute(empty_env, *expr);
            auto res_t = _discharge(*res_v);
            return { std::move(res_t), _cost };
        }

        uint64_t mem_usage(const constant &val)
        {
            return _mem_usage(val);
        }
    private:
        allocator &_alloc;
        const costs::parsed_model &_cost_model;
        optional_budget _budget;
        cardano::ex_units _cost {};

        static const costs::parsed_model &_cost_model_for_ver(const costs::parsed_models &models, const version &ver)
        {
            if (ver.major == 1 && ver.minor == 0)
                return models.v1.value();
            return models.v3.value();
        }

        static uint64_t _mem_usage(const cpp_int &i)
        {
            if (i > 0)
                return boost::multiprecision::msb(i) / 64 + 1;
            if (i < 0) {
                if (const auto i_adj = i + 1; i_adj != 0) [[likely]]
                    return boost::multiprecision::msb(i_adj * -1) / 64 + 1;
                return 1;
            }
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
                    return 4 + _mem_usage(v->first) + _mem_usage(v->second);
                } else if constexpr (std::is_same_v<t, data::map_type>) {
                    uint64_t sum = 4;
                    for (const auto &p: v)
                        sum += _mem_usage(p->first) + _mem_usage(p->second);
                    return sum;
                } else {
                    return 4 + _mem_usage(v);
                }
            }, d.val);
        }

        static uint64_t _mem_usage(const constant &c)
        {
            return std::visit([](const auto &v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, std::monostate>) {
                    return static_cast<uint64_t>(1);
                } else if constexpr (std::is_same_v<T, bool>) {
                    return static_cast<uint64_t>(1);
                } else if constexpr (std::is_same_v<T, uint8_vector>) {
                    return _mem_usage(buffer { v });
                } else if constexpr (std::is_same_v<T, data>) {
                    return _mem_usage(v);
                } else if constexpr (std::is_same_v<T, std::string>) {
                    return _mem_usage(std::string_view { v });
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

        void _check_budget() const
        {
            if (_budget) {
                if (_cost.steps > _budget->steps) [[unlikely]]
                    throw error("plutus program CPU cost: {} has exceeded it's budget: {}", _cost.steps, _budget->steps);
                if (_cost.mem > _budget->mem) [[unlikely]]
                    throw error("plutus program memory cost: {} has exceeded it's budget: {}", _cost.mem, _budget->mem);
            }
        }

        void _spend(const cardano::ex_units &c)
        {
            _cost.steps += c.steps;
            _cost.mem += c.mem;
            _check_budget();
        }

        void _spend(const builtin_tag tag, const value_list &args={})
        {
            costs::arg_sizes sizes {};
            for (const auto &arg: args)
                sizes.emplace_back(_mem_usage(*arg));
            const auto &op_model = _cost_model.builtin_fun.at(tag);
            const auto cpu_cost = op_model.cpu->cost(sizes, args);
            _cost.steps += cpu_cost;
            const auto mem_cost = op_model.mem->cost(sizes, args);
            _cost.mem += mem_cost;
            _check_budget();
        }

        std::optional<value> _lookup_opt(const environment &env, const std::string_view &name) const
        {
            for (const auto *node = env.get(); node != nullptr; node = node->parent.get()) {
                if (node->name == name)
                    return node->val;
            }
            return {};
        }

        value _lookup(const environment &env, const std::pmr::string &name) const
        {
            if (auto ptr_opt = _lookup_opt(env, name); ptr_opt)
                return std::move(*ptr_opt);
            throw error("reference to free variable: {}", name);
        }

        term_ptr _discharge_term(const environment &env, const term_ptr &t, const size_t level=0) const
        {
            return std::visit([&](const auto &v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, variable>) {
                    if (const auto ptr_opt = _lookup_opt(env, v.name); ptr_opt)
                        return _discharge(**ptr_opt);
                    return t;
                } else if constexpr (std::is_same_v<T, t_lambda>) {
                    return term::make_ptr(_alloc, t_lambda { _alloc, v.name, _discharge_term(env, v.expr, level + 1) });
                } else if constexpr (std::is_same_v<T, apply>) {
                    return term::make_ptr(_alloc, apply { _discharge_term(env, v.func, level), _discharge_term(env, v.arg, level) });
                } else if constexpr (std::is_same_v<T, force>) {
                    return term::make_ptr(_alloc, force { _discharge_term(env, v.expr, level) });
                } else if constexpr (std::is_same_v<T, t_delay>) {
                    return term::make_ptr(_alloc, t_delay { _discharge_term(env, v.expr, level) });
                } else {
                    return t;
                }
            }, t->expr);
        }

        term_ptr _discharge(const value::value_type &val) const
        {
            return std::visit([this](const auto &v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, constant>) {
                    return term::make_ptr(_alloc, v);
                } else if constexpr (std::is_same_v<T, v_delay>) {
                    return _discharge_term(v.env, term::make_ptr(_alloc, t_delay { v.expr }));
                } else if constexpr (std::is_same_v<T, v_lambda>) {
                    return _discharge_term(v.env, term::make_ptr(_alloc, t_lambda { _alloc, v.name, v.body }));
                } else if constexpr (std::is_same_v<T, v_builtin>) {
                    auto t = term::make_ptr(_alloc, v.b);
                    for (size_t i = 0; i < v.forces; ++i)
                        t = term::make_ptr(_alloc, force { std::move(t) });
                    for (const auto &arg: v.args)
                        t = term::make_ptr(_alloc, apply { std::move(t), _discharge(*arg) });
                    return t;
                } else if constexpr (std::is_same_v<T, v_constr>) {
                    term_list args { _alloc.resource() };
                    for (const auto &arg: v.args)
                        args.emplace_back(_discharge(*arg));
                    t_constr pc { v.tag, std::move(args) };
                    return term::make_ptr(_alloc, std::move(pc));
                } else {
                    throw error("an unsupported value type to discharge: {}", typeid(v).name());
                    // never reached but makes Visual C++ happy
                    return term::make_ptr(_alloc, false);
                }
            }, val);
        }

        value _apply_builtin(const v_builtin &b)
        {
            const auto num_args = b.b.num_args();
            if (b.args.size() != num_args) [[unlikely]]
                throw error("can't apply builtin {} to {} arguments: {} arguments are required!", b.b.tag, b.args.size(), num_args);
            _spend(b.b.tag, b.args);
            const auto func = b.b.func();
            switch (num_args) {
                case 1: return std::get<builtin_one_arg>(func)(_alloc, b.args.at(0));
                case 2: return std::get<builtin_two_arg>(func)(_alloc, b.args.at(0), b.args.at(1));
                case 3: return std::get<builtin_three_arg>(func)(_alloc, b.args.at(0), b.args.at(1), b.args.at(2));
                case 6: return std::get<builtin_six_arg>(func)(_alloc, b.args.at(0), b.args.at(1), b.args.at(2), b.args.at(3), b.args.at(4), b.args.at(5));
                default: throw error("unsupported number of arguments: {}!", num_args);
            }
        }

        value _apply(const value::value_type &func, const value &arg)
        {
            return std::visit([&arg, this](const auto &f) {
                using T = std::decay_t<decltype(f)>;
                if constexpr (std::is_same_v<T, v_lambda>) {
                    const environment new_env { _alloc, f.env, f.name, arg };
                    return _compute(new_env, *f.body);
                }
                if constexpr (std::is_same_v<T, v_builtin>) {
                    v_builtin new_b { f };
                    if (new_b.b.polymorphic_args() != new_b.forces)
                        throw error("an application of an polymorphic builtin with an incorrect number of forces: {}", new_b.b.tag);
                    new_b.args.emplace_back(arg);
                    if (new_b.args.size() < new_b.b.num_args()) [[likely]]
                        return value { _alloc, std::move(new_b) };
                    auto res = _apply_builtin(new_b);
                    //logger::info("{}({}) => {}", new_b.b.name(), new_b.args, *res);
                    return res;
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
                    return _compute(v.env, *v.expr);
                if constexpr (std::is_same_v<T, v_builtin>) {
                    if (v.args.size() == v.b.num_args())
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
            return _lookup(env, e.name);
        }

        value _compute(const environment &, const constant &e)
        {
            _spend(_cost_model.constant_op);
            return { _alloc, e };
        }

        value _compute(const environment &env, const t_lambda &e)
        {
            _spend(_cost_model.lambda_op);
            return { _alloc, v_lambda { _alloc, env, e.name, e.expr } };
        }

        value _compute(const environment &env, const t_delay &e)
        {
            _spend(_cost_model.delay_op);
            return { _alloc, v_delay { env, e.expr } };
        }

        value _compute(const environment &, const t_builtin &e)
        {
            _spend(_cost_model.builtin_op);
            return { _alloc, v_builtin { e } };
        }

        value _compute(const environment &env, const force &e)
        {
            _spend(_cost_model.force_op);
            return _force(_compute(env, *e.expr));
        }

        value _compute(const environment &env, const apply &e)
        {
            _spend(_cost_model.apply_op);
            const auto arg = _compute(env, *e.arg);
            const auto fun = _compute(env, *e.func);
            return _apply(*fun, arg);
        }

        value _compute(const environment &env, const t_constr &e)
        {
            _spend(_cost_model.constr_op);
            value_list v_args {};
            for (const auto &arg: e.args)
                v_args.emplace_back(_compute(env, *arg));
            return value { _alloc, v_constr { e.tag, std::move(v_args) } };
        }

        value _compute(const environment &env, const t_case &e)
        {
            _spend(_cost_model.case_op);
            const auto v_arg = _compute(env, *e.arg);
            const auto &cc = v_arg.as_constr();
            if (cc.tag >= e.cases.size())
                throw error("a case argument must have been less than {} but got {}!", e.cases.size(), cc.tag);
            auto res = _compute(env, *e.cases.at(cc.tag));
            for (size_t i = 0; i < cc.args.size(); ++i)
                res = _apply(*res, cc.args.at(i));
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
            }, t.expr);
        }
    };

    machine::machine(allocator &alloc, const version &ver, const optional_budget &budget, const costs::parsed_models &models):
        _impl { std::make_unique<impl>(alloc, ver, budget, models) }
    {
    }

    machine::~machine() =default;

    machine::result machine::evaluate(const term_ptr &expr)
    {
        return _impl->evaluate(expr);
    }

    machine::result machine::evaluate(const term_ptr &expr, const term_list &args)
    {
        return _impl->evaluate(expr, args);
    }

    value::value(value &&v): _ptr { std::move(v._ptr) }
    {
    }

    value::value(const value &v): _ptr { v._ptr }
    {
    }

    value::value(allocator &alloc, const blst_p1 &b): value { alloc, value_type { constant { alloc, bls12_381_g1_element { b } } } }
    {
    }

    value::value(allocator &alloc, const blst_p2 &b): value { alloc, value_type { constant { alloc, bls12_381_g2_element { b } } } }
    {
    }

    value::value(allocator &alloc, const blst_fp12 &b): value { alloc, value_type { constant { alloc, bls12_381_ml_result { b } } } }
    {
    }

    value::value(allocator &alloc, data &&d): value { alloc, value_type { constant { alloc, std::move(d) } } }
    {
    }

    value::value(allocator &alloc, cpp_int &&i): value { alloc, constant { alloc, std::move(i) } }
    {
    }

    value::value(allocator &alloc, const cpp_int &i): value { alloc, constant { alloc, i } }
    {
    }

    value::value(allocator &alloc, const int64_t i): value { alloc, cpp_int { i } }
    {
    }

    value::value(allocator &alloc, std::string &&s): value { alloc, constant { alloc, std::move(s) } }
    {
    }

    value::value(allocator &alloc, const std::string_view &s): value { alloc, std::string { s } }
    {
    }

    value::value(allocator &alloc, uint8_vector &&b): value { alloc, constant { alloc, std::move(b) } }
    {
    }

    value::value(allocator &alloc, const buffer &b): value { alloc, uint8_vector { b } }
    {
    }

    value::value(allocator &alloc, value_type &&v): _ptr { alloc.make<value_type>(std::move(v)) }
    {
    }

    value::value(allocator &alloc, const value_type &v): value { alloc, value_type { v } }
    {
    }

    value::value(allocator &alloc, constant &&v): value { alloc, value_type { std::move(v) }  }
    {
    }

    value::value(allocator &alloc, const constant &v): value { alloc, value_type { v }  }
    {
    }

    value::value(allocator &alloc, constant_list &&v): value { alloc, constant { alloc, std::move(v) } }
    {
    }

    value &value::operator=(const value &o)
    {
        _ptr = o._ptr;
        return *this;
    }

    const value::value_type &value::operator*() const
    {
        return *_ptr;
    }

    const value::value_type *value::operator->() const
    {
        return _ptr.get();
    }

    const constant &value::as_const() const
    {
        return std::get<constant>(*_ptr);
    }

    const v_constr &value::as_constr() const
    {
        return std::get<v_constr>(*_ptr);
    }

    void value::as_unit() const
    {
        const auto &c = as_const();
        if (!std::holds_alternative<std::monostate>(*c))
            throw error("expected a unit but got: {}", c);
    }

    bool value::as_bool() const
    {
        return as_const().as_bool();
    }

    const cpp_int &value::as_int() const
    {
        return as_const().as_int();
    }

    const std::string &value::as_str() const
    {
        return as_const().as_str();
    }

    const uint8_vector &value::as_bstr() const
    {
        return as_const().as_bstr();
    }

    const bls12_381_g1_element &value::as_bls_g1() const
    {
        return std::get<bls12_381_g1_element>(*as_const());
    }

    const bls12_381_g2_element &value::as_bls_g2() const
    {
        return std::get<bls12_381_g2_element>(*as_const());
    }

    const bls12_381_ml_result &value::as_bls_ml_res() const
    {
        return std::get<bls12_381_ml_result>(*as_const());
    }

    const data &value::as_data() const
    {
        return as_const().as_data();
    }

    const constant_pair::value_type &value::as_pair() const
    {
        return as_const().as_pair();
    }

    const constant_list &value::as_list() const
    {
        return as_const().as_list();
    }

    value value::boolean(allocator &alloc, const bool b)
    {
        return { alloc, value_type { constant { alloc, b } } };
    }

    value value::unit(allocator &alloc)
    {
        return { alloc, constant { alloc, std::monostate {} } };
    }

    value value::make_list(allocator &alloc, constant_type &&typ, constant_list::list_type &&cl)
    {
        return { alloc, constant { alloc, constant_list { alloc, std::move(typ), std::move(cl) } } };
    }

    value value::make_list(allocator &alloc, constant_list::list_type &&vals)
    {
        if (vals.empty())
            throw error("value must not be empty!");
        return { alloc, constant { alloc, constant_list { alloc, constant_type::from_val(alloc, vals.at(0)), std::move(vals) } } };
    }

    value value::make_pair(allocator &alloc, constant &&fst, constant &&snd)
    {
        return { alloc, constant { alloc, constant_pair { alloc, std::move(fst), std::move(snd) } } };
    }

    bool value::operator==(const value &o) const
    {
        return _ptr && o._ptr && *_ptr == *o._ptr;
    }

    bool v_builtin::operator==(const v_builtin &o) const
    {
        return b == o.b && args == o.args && forces == o.forces;
    }

    bool v_constr::operator==(const v_constr &o) const
    {
        return tag == o.tag && args == o.args;
    }

    bool v_delay::operator==(const v_delay &o) const
    {
        return env == o.env && expr && o.expr && *expr == *o.expr;
    }

    bool v_lambda::operator==(const v_lambda &o) const
    {
        return env == o.env && name == o.name && body && o.body && *body == *o.body;
    }
}
