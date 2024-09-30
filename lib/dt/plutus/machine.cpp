/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cbor/zero.hpp>
#include <dt/plutus/builtins.hpp>
#include <dt/plutus/machine.hpp>

namespace daedalus_turbo::plutus {
    struct machine::impl {
        impl(const version &ver, const optional_budget &budget, const costs::parsed_models &models):
            _cost_model { _cost_model_for_ver(models, ver) }, _budget { budget }
        {
        }

        result evaluate(const term_ptr &expr)
        {
            _cost = {};
            _spend(costs::other_tag::startup);
            return { _discharge(*_compute({}, *expr)), _cost };
        }

        uint64_t mem_usage(const constant &val)
        {
            return _mem_usage(val);
        }
    private:
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
                    for (const auto &ci: v.vals)
                        sum += _mem_usage(ci);
                    return sum;
                } else if constexpr (std::is_same_v<T, constant_pair>) {
                    return _mem_usage(v->first) + _mem_usage(v->second);
                } else {
                    return _mem_usage(v);
                }
            }, c.val);
        }

        static uint64_t _mem_usage(const value::value_type &val)
        {
            if (std::holds_alternative<constant>(val))
                return _mem_usage(std::get<constant>(val));
            return 1;
        }

        void _spend(const costs::op_tag tag, const value_list &args={})
        {
            costs::arg_sizes sizes {};
            for (const auto &arg: args)
                sizes.emplace_back(_mem_usage(*arg));
            const auto &op_model = _cost_model.at(tag);
            const auto cpu_cost = op_model.cpu->cost(sizes, args);
            _cost.steps += cpu_cost;
            const auto mem_cost = op_model.mem->cost(sizes, args);
            _cost.mem += mem_cost;
            if (_budget) {
                if (_cost.steps > _budget->steps) [[unlikely]]
                    throw error("plutus program CPU cost: {} has exceeded it's budget: {}", _cost.steps, _budget->steps);
                if (_cost.mem > _budget->mem) [[unlikely]]
                    throw error("plutus program memory cost: {} has exceeded it's budget: {}", _cost.mem, _budget->mem);
            }
        }

        std::optional<value> _lookup_opt(const environment &env, const std::string &name) const
        {
            for (const auto *node = env.get(); node != nullptr; node = node->parent.get()) {
                if (node->name == name)
                    return node->val;
            }
            return {};
        }

        value _lookup(const environment &env, const std::string &name) const
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
                    return term::make_ptr(t_lambda { v.name, _discharge_term(env, v.expr, level + 1) });
                } else if constexpr (std::is_same_v<T, apply>) {
                    return term::make_ptr(apply { _discharge_term(env, v.func, level), _discharge_term(env, v.arg, level) });
                } else if constexpr (std::is_same_v<T, force>) {
                    return term::make_ptr(force { _discharge_term(env, v.expr, level) });
                } else if constexpr (std::is_same_v<T, t_delay>) {
                    return term::make_ptr(t_delay { _discharge_term(env, v.expr, level) });
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
                    return term::make_ptr(v);
                } else if constexpr (std::is_same_v<T, v_delay>) {
                    return _discharge_term(v.env, term::make_ptr(t_delay { v.expr }));
                } else if constexpr (std::is_same_v<T, v_lambda>) {
                    return _discharge_term(v.env, term::make_ptr(t_lambda { v.name, v.body }));
                } else if constexpr (std::is_same_v<T, v_builtin>) {
                    auto t = term::make_ptr(v.b);
                    for (size_t i = 0; i < v.forces; ++i)
                        t = term::make_ptr(force { std::move(t) });
                    for (const auto &arg: v.args)
                        t = term::make_ptr(apply { std::move(t), _discharge(*arg) });
                    return t;
                } else if constexpr (std::is_same_v<T, v_constr>) {
                    t_constr pc { v.tag };
                    for (const auto &arg: v.args)
                        pc.args.emplace_back(_discharge(*arg));
                    return term::make_ptr(std::move(pc));
                } else {
                    throw error("an unsupported value type to discharge: {}", typeid(v).name());
                    // never reached but makes Visual C++ happy
                    return term::make_ptr(false);
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
                case 1: return std::get<builtin_one_arg>(func)(b.args.at(0));
                case 2: return std::get<builtin_two_arg>(func)(b.args.at(0), b.args.at(1));
                case 3: return std::get<builtin_three_arg>(func)(b.args.at(0), b.args.at(1), b.args.at(2));
                case 6: return std::get<builtin_six_arg>(func)(b.args.at(0), b.args.at(1), b.args.at(2), b.args.at(3), b.args.at(4), b.args.at(5));
                default: throw error("unsupported number of arguments: {}!", num_args);
            }
        }

        value _apply(const value::value_type &func, const value &arg)
        {
            return std::visit([&arg, this](const auto &f) {
                using T = std::decay_t<decltype(f)>;
                if constexpr (std::is_same_v<T, v_lambda>) {
                    const environment new_env { f.env, f.name, arg };
                    return _compute(new_env, *f.body);
                }
                if constexpr (std::is_same_v<T, v_builtin>) {
                    v_builtin new_b { f };
                    if (new_b.b.polymorphic_args() != new_b.forces)
                        throw error("an application of an polymorphic builtin with an incorrect number of forces: {}", new_b.b.tag);
                    new_b.args.emplace_back(arg);
                    if (new_b.args.size() < new_b.b.num_args()) [[likely]]
                        return value { std::move(new_b) };
                    auto res = _apply_builtin(new_b);
                    //logger::info("{}({}) => {}", new_b.b.name(), new_b.args, *res);
                    return res;
                }
                throw error("only lambdas and builtins can be applied but got: {}", typeid(T).name());
                return value { constant { std::monostate {} } };
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
                        return value { std::move(new_b) };
                    }
                    throw error("an unexpected force of a builtin: {} polymorhpic_args: {} num_forces: {}", v.b.tag, v.b.polymorphic_args(), v.forces);
                }
                throw error("unsupported value for force: {}", typeid(T).name());
                return value { constant { std::monostate {} } };
            }, *val);
        }

        value _compute(const environment &env, const variable &e)
        {
            _spend(term_tag::variable);
            return _lookup(env, e.name);
        }

        value _compute(const environment &, const constant &e)
        {
            _spend(term_tag::constant);
            return { e };
        }

        value _compute(const environment &env, const t_lambda &e)
        {
            _spend(term_tag::lambda);
            return { v_lambda { env, e.name, e.expr } };
        }

        value _compute(const environment &env, const t_delay &e)
        {
            _spend(term_tag::delay);
            return { v_delay { env, e.expr } };
        }

        value _compute(const environment &, const t_builtin &e)
        {
            _spend(term_tag::builtin);
            return { v_builtin { e } };
        }

        value _compute(const environment &env, const force &e)
        {
            _spend(term_tag::force);
            return _force(_compute(env, *e.expr));
        }

        value _compute(const environment &env, const apply &e)
        {
            _spend(term_tag::apply);
            const auto arg = _compute(env, *e.arg);
            const auto fun = _compute(env, *e.func);
            return _apply(*fun, arg);
        }

        value _compute(const environment &env, const t_constr &e)
        {
            _spend(term_tag::constr);
            value_list v_args {};
            for (const auto &arg: e.args)
                v_args.emplace_back(_compute(env, *arg));
            return value { v_constr { e.tag, std::move(v_args) } };
        }

        value _compute(const environment &env, const acase &e)
        {
            _spend(term_tag::acase);
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
            _spend(term_tag::error);
            throw error("the plutus script reported an error!");
        }

        value _compute(const environment &env, const term &t)
        {
            return std::visit([&](const auto &e) {
                return _compute(env, e);
            }, t.expr);
        }
    };

    machine::machine(const version &ver, const optional_budget &budget, const costs::parsed_models &models):
        _impl { std::make_unique<impl>(ver, budget, models) }
    {
    }

    machine::~machine() =default;

    machine::result machine::evaluate(const term_ptr &expr)
    {
        return _impl->evaluate(expr);
    }

    machine::result machine::evaluate(const term_ptr &expr, const term_list &args)
    {
        term_ptr t = expr;
        for (const auto &arg: args)
            t = term::make_ptr(apply { t, arg });
        return _impl->evaluate(t);
    }

    value::value(const blst_p1 &b): value { value_type { constant { bls12_381_g1_element { b } } } }
    {
    }

    value::value(const blst_p2 &b): value { value_type { constant { bls12_381_g2_element { b } } } }
    {
    }

    value::value(const blst_fp12 &b): value { value_type { constant { bls12_381_ml_result { b } } } }
    {
    }

    value::value(data &&d): value { value_type { constant { std::move(d) } } }
    {
    }

    value::value(cpp_int &&i): value { constant { std::move(i) } }
    {
    }

    value::value(const cpp_int &i): value { constant { i } }
    {
    }

    value::value(const int64_t i): value { cpp_int { i } }
    {
    }

    value::value(std::string &&s): value { constant { std::move(s) } }
    {
    }

    value::value(const std::string_view &s): value { std::string { s } }
    {
    }

    value::value(uint8_vector &&b): value { constant { std::move(b) } }
    {
    }

    value::value(const buffer &b): value { uint8_vector { b } }
    {
    }

    value::value(value_type &&v): _ptr { std::make_shared<value_type>(std::move(v)) }
    {
    }

    value::value(const value_type &v): _ptr { std::make_shared<value_type>(v) }
    {
    }

    value::value(constant &&v): value { value_type { std::move(v) }  }
    {
    }

    value::value(const constant &v): value { value_type { v }  }
    {
    }

    value::value(constant_list &&v): value { constant { std::move(v) } }
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
        if (!std::holds_alternative<std::monostate>(c.val))
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
        return std::get<bls12_381_g1_element>(as_const().val);
    }

    const bls12_381_g2_element &value::as_bls_g2() const
    {
        return std::get<bls12_381_g2_element>(as_const().val);
    }

    const bls12_381_ml_result &value::as_bls_ml_res() const
    {
        return std::get<bls12_381_ml_result>(as_const().val);
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

    value value::boolean(const bool b)
    {
        return { value_type { constant { b } } };
    }

    const value &value::unit()
    {
        static value v { constant { std::monostate {} } };
        return v;
    }

    value value::make_list(constant_type &&typ, vector<constant> &&cl)
    {
        return { constant { constant_list { std::move(typ), std::move(cl) } } };
    }

    value value::make_list(vector<constant> &&vals)
    {
        if (vals.empty())
            throw error("value must not be empty!");
        return { constant { constant_list { constant_type::from_val(vals.at(0)), std::move(vals) } } };
    }

    value value::make_pair(constant &&fst, constant &&snd)
    {
        return { constant { constant_pair { std::move(fst), std::move(snd) } } };
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
