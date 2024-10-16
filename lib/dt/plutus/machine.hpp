/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_MACHINE_HPP
#define DAEDALUS_TURBO_PLUTUS_MACHINE_HPP

#include <memory_resource>
#include <dt/memory.hpp>
#include <dt/plutus/costs.hpp>
#include <dt/plutus/types.hpp>

namespace daedalus_turbo::plutus {
    struct v_builtin;
    struct v_constr;
    struct v_delay;
    struct v_lambda;

    struct value {
        using value_type = std::variant<constant, v_delay, v_lambda, v_builtin, v_constr>;
        using ptr_type = allocator::ptr_type<value_type>;

        static value make_list(allocator &, constant_list::list_type &&);
        static value make_list(allocator &, constant_type &&, constant_list::list_type &&={});
        static value make_pair(allocator &, constant &&, constant &&);
        static value unit(allocator &);
        static value boolean(allocator &, bool); // a factory method to disambiguate with value(int64_t) which is more frequent

        value() =delete;
        value(const value &);
        value(value &&);
        value(allocator &, value_type &&);
        value(allocator &, const value_type &);
        value(allocator &, constant &&);
        value(allocator &, const constant &);
        value(allocator &, constant_list &&);
        value(allocator &, cpp_int &&);
        value(allocator &, const cpp_int &);
        value(allocator &, int64_t);
        value(allocator &, data &&);
        value(allocator &, std::string &&);
        value(allocator &, const std::string_view &);
        value(allocator &, uint8_vector &&);
        value(allocator &, const buffer &);
        value(allocator &, const blst_p1 &);
        value(allocator &, const blst_p2 &);
        value(allocator &, const blst_fp12 &);

        value &operator=(const value &);

        const constant &as_const() const;
        const v_constr &as_constr() const;
        void as_unit() const;
        bool as_bool() const;
        const cpp_int &as_int() const;
        const std::string &as_str() const;
        const uint8_vector &as_bstr() const;
        const bls12_381_g1_element &as_bls_g1() const;
        const bls12_381_g2_element &as_bls_g2() const;
        const bls12_381_ml_result &as_bls_ml_res() const;
        const data &as_data() const;
        const constant_pair::value_type &as_pair() const;
        const constant_list &as_list() const;
        bool operator==(const value &o) const;
        const value_type &operator*() const;
        const value_type *operator->() const;
    private:
        ptr_type _ptr;
    };

    struct environment {
        struct node {
            using ptr_type = allocator::ptr_type<node>;
            const ptr_type parent;
            const std::string name;
            const value val;

            node(const ptr_type &parent, const std::string_view &name, const value &val):
                parent { parent }, name { name }, val { val }
            {
            }

            node(const node &) =default;
            node(node &&) =default;

            bool operator==(const node &o) const
            {
                return name == o.name && val == o.val
                    && ((!parent && !o.parent) || (parent && o.parent && *parent == *o.parent));
            }
        };

        environment() =default;
        ~environment() =default;
        environment(allocator &alloc, const environment &parent, const std::string_view &name, const value &val);
        environment(environment &&);
        environment(const environment &);

        const node *get() const
        {
            return _tail.get();
        }

        bool operator==(const environment &o) const
        {
            return (!_tail && !o._tail) || (_tail && o._tail && *_tail == *o._tail);
        }
    private:
        const node::ptr_type _tail;
    };

    inline environment::environment(allocator &alloc, const environment &parent, const std::string_view &name, const value &val):
            _tail { alloc.make<node>(parent._tail, name, val) }
    {
    }

    inline environment::environment(environment &&o): _tail { std::move(o._tail) }
    {
    }

    inline environment::environment(const environment &o): _tail { o._tail }
    {
    }

    struct v_builtin {
        const t_builtin b;
        value_list args {};
        size_t forces = 0;

        bool operator==(const v_builtin &o) const;
    };

    struct v_constr {
        const size_t tag;
        const value_list args;

        bool operator==(const v_constr &o) const;
    };

    struct v_delay {
        const environment env;
        const term_ptr expr;

        bool operator==(const v_delay &o) const;
    };

    struct v_lambda {
        const environment env;
        const std::pmr::string name;
        const term_ptr body;

        v_lambda() =delete;
        v_lambda(const v_lambda &o)=default;

        v_lambda(allocator &alloc, const environment &e, const std::pmr::string &n, const term_ptr &b):
            env { e }, name { n, alloc.resource() }, body { b }
        {
        }

        bool operator==(const v_lambda &o) const;
    };

    using optional_budget = std::optional<cardano::ex_units>;

    struct machine {
        struct result {
            const term_ptr expr = nullptr;
            const cardano::ex_units cost {};

            bool operator==(const result& o) const
            {
                return expr && o.expr && *expr == *o.expr && cost == o.cost;
            }
        };

        machine(allocator &alloc, const version &ver={}, const optional_budget &budget={}, const costs::parsed_models &models=costs::defaults());
        ~machine();
        result evaluate(const term_ptr &expr);
        result evaluate(const term_ptr &expr, const term_list &args);
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::plutus::environment::node>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::environment::node &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            auto out_it = fmt::format_to(ctx.out(), "{}={}", v.name, v.val);
            if (v.parent)
                out_it = fmt::format_to(out_it, ", {}", *v.parent);
            return out_it;
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::environment>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::environment &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            if (const auto *node = v.get(); node)
                fmt::format_to(ctx.out(), "env [{}]", *node);
            return fmt::format_to(ctx.out(), "env []");
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::value>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::value &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            return fmt::format_to(ctx.out(), "{}", *v);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::v_builtin>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::v_builtin &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            return fmt::format_to(ctx.out(), "(builtin {} {})", v.b.name(), v.args);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::v_constr>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::v_constr &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            return fmt::format_to(ctx.out(), "(constr {} {})", v.tag, v.args);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::v_delay>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::v_delay &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            return fmt::format_to(ctx.out(), "(delay ({}) {})", v.env, *v.expr);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::v_lambda>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::v_lambda &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            return fmt::format_to(ctx.out(), "(lam {} ({}) {})", v.name, v.env, *v.body);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::value::value_type>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::value::value_type &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return std::visit([&ctx](const auto &vv) { return fmt::format_to(ctx.out(), "{}", vv); }, v);
        }
    };
}

#endif //DAEDALUS_TURBO_PLUTUS_MACHINE_HPP