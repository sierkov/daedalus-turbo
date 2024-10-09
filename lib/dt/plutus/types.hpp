/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_TYPES_HPP
#define DAEDALUS_TURBO_PLUTUS_TYPES_HPP

#include <any>
#include <memory_resource>
#include <variant>
#include <dt/big_int.hpp>
#include <dt/crypto/blst.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/cbor-encoder.hpp>
#include <dt/error.hpp>
#include <dt/format.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::plutus {
    struct version {
        uint64_t major = 1;
        uint64_t minor = 1;
        uint64_t patch = 0;

        operator std::string() const
        {
            return fmt::format("{}.{}.{}", major, minor, patch);
        }
    };

    enum class term_tag: uint8_t {
        variable = 0,
        delay    = 1,
        lambda   = 2,
        apply    = 3,
        constant = 4,
        force    = 5,
        error    = 6,
        builtin  = 7,
        constr   = 8,
        acase    = 9
    };

    enum class type_tag: uint8_t {
        integer              = 0,
        bytestring           = 1,
        string               = 2,
        unit                 = 3,
        boolean              = 4,
        list                 = 5,
        pair                 = 6,
        application          = 7,
        data                 = 8,
        bls12_381_g1_element = 9,
        bls12_381_g2_element = 10,
        bls12_381_ml_result   = 11
    };

    enum class builtin_tag: uint8_t {
        add_integer = 0,
        subtract_integer = 1,
        multiply_integer = 2,
        divide_integer = 3,
        quotient_integer = 4,
        remainder_integer = 5,
        mod_integer = 6,
        equals_integer = 7,
        less_than_integer = 8,
        less_than_equals_integer = 9,
        append_byte_string = 10,
        cons_byte_string = 11,
        slice_byte_string = 12,
        length_of_byte_string = 13,
        index_byte_string = 14,
        equals_byte_string = 15,
        less_than_byte_string = 16,
        less_than_equals_byte_string = 17,
        sha2_256 = 18,
        sha3_256 = 19,
        blake2b_256 = 20,
        verify_ed25519_signature = 21,
        append_string = 22,
        equals_string = 23,
        encode_utf8 = 24,
        decode_utf8 = 25,
        if_then_else = 26,
        choose_unit = 27,
        trace = 28,
        fst_pair = 29,
        snd_pair = 30,
        choose_list = 31,
        mk_cons = 32,
        head_list = 33,
        tail_list = 34,
        null_list = 35,
        choose_data = 36,
        constr_data = 37,
        map_data = 38,
        list_data = 39,
        i_data = 40,
        b_data = 41,
        un_constr_data = 42,
        un_map_data = 43,
        un_list_data = 44,
        un_i_data = 45,
        un_b_data = 46,
        equals_data = 47,
        mk_pair_data = 48,
        mk_nil_data = 49,
        mk_nil_pair_data = 50,
        // Plutus v2
        serialise_data = 51,
        verify_ecdsa_secp_256k1_signature = 52,
        verify_schnorr_secp_256k1_signature = 53,
        // Plutus v3
        bls12_381_g1_add = 54,
        bls12_381_g1_neg = 55,
        bls12_381_g1_scalar_mul = 56,
        bls12_381_g1_equal = 57,
        bls12_381_g1_hash_to_group = 58,
        bls12_381_g1_compress = 59,
        bls12_381_g1_uncompress = 60,
        bls12_381_g2_add = 61,
        bls12_381_g2_neg = 62,
        bls12_381_g2_scalar_mul = 63,
        bls12_381_g2_equal = 64,
        bls12_381_g2_hash_to_group = 65,
        bls12_381_g2_compress = 66,
        bls12_381_g2_uncompress = 67,
        bls12_381_miller_loop = 68,
        bls12_381_mul_ml_result = 69,
        bls12_381_final_verify = 70,
        keccak_256 = 71,
        blake2b_224 = 72,
        integer_to_byte_string = 73,
        byte_string_to_integer = 74,
        // Future
        and_byte_string = 75,
        or_byte_string = 76,
        xor_byte_string = 77,
        complement_byte_string = 78,
        read_bit = 79,
        write_bits = 80,
        replicate_byte = 81,
        shift_byte_string = 82,
        rotate_byte_string = 83,
        count_set_bits = 84,
        find_first_set_bit = 85,
        ripemd_160 = 86,
        exp_mod_integer = 87
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::plutus::term_tag>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::term_tag &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using term = daedalus_turbo::plutus::term_tag;
            switch (v) {
                case term::variable: return fmt::format_to(ctx.out(), "term::variable");
                case term::delay: return fmt::format_to(ctx.out(), "term::delay");
                case term::lambda: return fmt::format_to(ctx.out(), "term::lambda");
                case term::apply: return fmt::format_to(ctx.out(), "term::apply");
                case term::constant: return fmt::format_to(ctx.out(), "term::constant");
                case term::force: return fmt::format_to(ctx.out(), "term::force");
                case term::error: return fmt::format_to(ctx.out(), "term::error");
                case term::builtin: return fmt::format_to(ctx.out(), "term::builtin");
                case term::constr: return fmt::format_to(ctx.out(), "term::constr");
                case term::acase: return fmt::format_to(ctx.out(), "term::case");
                default: return fmt::format_to(ctx.out(), "term::unknown({})", static_cast<int>(v));
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::type_tag>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::type_tag &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using type = daedalus_turbo::plutus::type_tag;
            switch (v) {
                case type::integer: return fmt::format_to(ctx.out(), "integer");
                case type::bytestring: return fmt::format_to(ctx.out(), "bytestring");
                case type::string: return fmt::format_to(ctx.out(), "string");
                case type::unit: return fmt::format_to(ctx.out(), "unit");
                case type::boolean: return fmt::format_to(ctx.out(), "bool");
                case type::list: return fmt::format_to(ctx.out(), "list");
                case type::pair: return fmt::format_to(ctx.out(), "pair");
                case type::application: return fmt::format_to(ctx.out(), "apply");
                case type::data: return fmt::format_to(ctx.out(), "data");
                case type::bls12_381_g1_element: return fmt::format_to(ctx.out(), "bls12_381_g1_element");
                case type::bls12_381_g2_element: return fmt::format_to(ctx.out(), "bls12_381_g2_element");
                case type::bls12_381_ml_result: return fmt::format_to(ctx.out(), "bls12_381_ml_result");
                default: throw daedalus_turbo::error("unknown type: {}", static_cast<int>(v));
            }
        }
    };
}

namespace daedalus_turbo::plutus {
    typedef daedalus_turbo::error error;

    // The idea behind the faster allocation is to release all objects at once
    // and save on the incremental deallocation and calls to destructors.
    // For that to work all internal objects must also be allocated using the same allocator,
    // so that there are no memory leaks
    struct allocator {
        template<typename T>
        struct ptr_type {
            ptr_type() =default;

            ptr_type(const T *ptr): _ptr { ptr }
            {
            }

            /*ptr_type(const ptr_type &o): _ptr { o._ptr }
            {
            }*/

            const T *get() const
            {
                return _ptr;
            }

            const T *operator->() const
            {
                return _ptr;
            }

            const T &operator*() const
            {
                return *_ptr;
            }

            operator bool() const
            {
                return _ptr;
            }
        private:
            const T *_ptr = nullptr;
        };

        ~allocator()
        {
            for (const auto &[p, dtr]: _ptrs) {
                dtr(p);
            }
        }

#if defined(__GNUC__) && !defined(__clang__)
        // GCC 13 reacts oddly to the libc++ implementation of std::pmr::string
#       pragma GCC diagnostic push
#       pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
        // For types that either:
        // 1. Do not contain nested data structures
        // 2. Contains nested data structures that are recursively allocated with this allocator only
        template<typename T, typename... Args>
        ptr_type<T> make_no_destroy(Args&&... a)
        {
            return new (_mr.allocate(sizeof(T))) T { std::forward<Args>(a)... };
        }

        // For types that require their destructor to be called before deallocation
        template<typename T, typename... Args>
        ptr_type<T> make(Args&&... a)
        {
            T *p = new (_mr.allocate(sizeof(T))) T { std::forward<Args>(a)... };
            try {
                _ptrs.emplace_back(p, [](const void* x) { static_cast<const T*>(x)->~T(); });
            } catch (...) {
                // Call the destructor to release the memory allocated with alternative allocators.
                // There is no need to deallocate in _mr since all its buffers will be released at the end of its lifetime.
                p->~T();
                throw;
            }
            return p;
        }
#if defined(__GNUC__) && !defined(__clang__)
#       pragma GCC diagnostic pop
#endif

        std::pmr::memory_resource *resource()
        {
            return &_mr;
        }
    private:
        struct any_ptr {
            void *ptr = nullptr;
            void(*dtr)(const void*);
        };

        std::pmr::monotonic_buffer_resource _mr {};
        std::pmr::vector<any_ptr> _ptrs { &_mr };
    };

    struct term;
    // shared_ptr is used to make terms copyable while allowing for a recursive definition of "term"
    using term_ptr = allocator::ptr_type<term>;
    using term_list = std::pmr::vector<term_ptr>;

    struct variable {
        std::pmr::string name;

        variable() =delete;
        variable(const variable &) =delete;

        variable(variable &&o): name { std::move(o.name) }
        {
        }

        variable(allocator &alloc, std::string_view n): name { n, alloc.resource() }
        {
        }

        variable(allocator &alloc, const variable &other): name { other.name, alloc.resource() }
        {
        }

        variable &operator=(variable &&o)
        {
            name = std::move(o.name);
            return *this;
        }

        bool operator==(const variable &o) const
        {
            return name == o.name;
        }
    };

    struct force {
        term_ptr expr;

        bool operator==(const force &o) const;
    };

    struct apply {
        term_ptr func;
        term_ptr arg;

        bool operator==(const apply &o) const;
    };

    struct failure {
        bool operator==(const failure &) const
        {
            return true;
        }
    };

    struct t_delay {
        term_ptr expr;

        bool operator==(const t_delay &o) const;
    };

    struct t_lambda {
        std::pmr::string name;
        term_ptr expr;

        t_lambda() =delete;

        t_lambda(t_lambda &&o): name { std::move(o.name) }, expr { std::move(o.expr) }
        {
        }

        t_lambda(allocator &alloc, const std::string_view n, const term_ptr &e): name { n, alloc.resource() }, expr { e }
        {
        }

        t_lambda(allocator &alloc, const t_lambda &o): name { o.name, alloc.resource() }, expr { o.expr }
        {
        }

        t_lambda &operator=(t_lambda &&o)
        {
            name = std::move(o.name);
            expr = std::move(o.expr);
            return *this;
        }

        bool operator==(const t_lambda &o) const;
    };

    struct constant;

    struct constant_type {
        using list_type = std::pmr::vector<constant_type>;
        struct value_type {
            type_tag typ;
            list_type nested;
        };

        static constant_type make_pair(allocator &alloc, constant_type &&fst, constant_type &&snd)
        {
            list_type n {};
            n.emplace_back(std::move(fst));
            n.emplace_back(std::move(snd));
            return { alloc, type_tag::pair, std::move(n) };
        }

        static constant_type from_val(allocator &alloc, const constant &);

        constant_type() =delete;

        constant_type(const constant_type &o): _ptr { o._ptr }
        {
        }

        constant_type(constant_type &&o): _ptr { std::move(o._ptr) }
        {
        }

        constant_type(allocator &alloc, value_type &&v): _ptr { alloc.make_no_destroy<value_type>(std::move(v) ) }
        {
        }

        constant_type(allocator &alloc, const type_tag t): constant_type { alloc, value_type { t, list_type { alloc.resource() } } }
        {
        }

        constant_type(allocator &alloc, const type_tag t, std::pmr::vector<constant_type> &&n):
            constant_type { alloc, value_type { t, std::move(n) } }
        {
        }

        constant_type &operator=(constant_type &&o)
        {
            _ptr = std::move(o._ptr);
            return *this;
        }

        constant_type &operator=(const constant_type &o)
        {
            _ptr = o._ptr;
            return *this;
        }

        bool operator==(const constant_type &o) const
        {
            return _ptr->typ == o._ptr->typ && _ptr->nested == o._ptr->nested;
        }

        const value_type *operator->() const
        {
            return _ptr.get();
        }
    private:
        allocator::ptr_type<value_type> _ptr;
    };

    struct bls12_381_g1_element {
        blst_p1 val {};

        bool operator==(const bls12_381_g1_element &o) const
        {
            return blst_p1_is_equal(&val, &o.val);
        }
    };

    struct bls12_381_g2_element {
        blst_p2 val {};

        bool operator==(const bls12_381_g2_element &o) const
        {
            return blst_p2_is_equal(&val, &o.val);
        }
    };

    struct bls12_381_ml_result {
        blst_fp12 val {};

        bool operator==(const bls12_381_ml_result &o) const
        {
            return memcmp(&val, &o.val, sizeof(val)) == 0;
        }
    };

    struct data;

    struct data_pair {
        using value_type = std::pair<data, data>;
        data_pair(data &&, data &&);
        bool operator==(const data_pair &o) const;
        const value_type &operator*() const;
        const value_type *operator->() const;
    private:
        std::shared_ptr<value_type> _val;
    };

    struct data_constr {
        using value_type = std::pair<uint64_t, vector<data>>;
        data_constr(uint64_t, vector<data> &&);
        data_constr(const cpp_int &, vector<data> &&);
        bool operator==(const data_constr &o) const;
        const value_type &operator*() const;
        const value_type *operator->() const;
    private:
        std::shared_ptr<value_type> _val;
    };

    struct data {
        using int_type = cpp_int;
        using bstr_type = uint8_vector;
        using list_type = vector<data>;
        using map_type = vector<data_pair>;
        using value_type = std::variant<data_constr, map_type, list_type, int_type, bstr_type>;
        value_type val;

        static data from_cbor(buffer);
        static data bstr(buffer);
        static data bint(cpp_int &&);
        static data bint(const cpp_int &);
        static data constr(cpp_int &&, list_type &&);
        static data list(list_type &&);
        static data map(map_type &&);
        bool operator==(const data &o) const;
        uint8_vector as_cbor() const;
        std::string as_string(const size_t shift=0) const;
    };

    struct constant_pair {
        using value_type = std::pair<constant, constant>;

        constant_pair() =delete;

        constant_pair(const constant_pair &o): _ptr { o._ptr }
        {
        }

        constant_pair(constant_pair &&o): _ptr { std::move(o._ptr) }
        {
        }

        constant_pair(allocator &alloc, constant &&fst, constant &&snd): _ptr { alloc.make<value_type>(std::move(fst), std::move(snd)) }
        {
        }

        constant_pair(allocator &alloc, const constant &fst, const constant &snd);

        constant_pair &operator=(const constant_pair &o)
        {
            _ptr = o._ptr;
            return *this;
        }

        bool operator==(const constant_pair &o) const;

        const value_type &operator*() const;

        const value_type *operator->() const
        {
            return _ptr.get();
        }
    private:
         allocator::ptr_type<value_type> _ptr;
    };

    struct constant_list {
        using list_type = std::pmr::vector<constant>;
        struct value_type {
            constant_type typ;
            list_type vals;
        };

        static constant_list make_one(allocator &alloc, constant &&);

        constant_list() =delete;

        constant_list(allocator &alloc, value_type &&v): _ptr { alloc.make<value_type>(std::move(v)) }
        {
        }

        constant_list(allocator &alloc, constant_type &&t, list_type &&l);

        constant_list(constant_list &&o): _ptr { std::move(o._ptr) }
        {
        }

        constant_list(const constant_list &o): _ptr { o._ptr }
        {
        }

        constant_list &operator=(constant_list &&o)
        {
            _ptr = std::move(o._ptr);
            return *this;
        }

        constant_list &operator=(const constant_list &o)
        {
            _ptr = o._ptr;
            return *this;
        }

        bool operator==(const constant_list &o) const;
        const value_type *operator->() const;
    private:
        allocator::ptr_type<value_type> _ptr;
    };

    struct constant {
        using value_type = std::variant<cpp_int, uint8_vector, std::string, bool, constant_list, constant_pair,
            data, bls12_381_g1_element, bls12_381_g2_element, bls12_381_ml_result, std::monostate>;

        constant() =delete;

        constant(allocator &alloc, value_type &&v)
            : _ptr { alloc.make<value_type>(std::move(v)) }
        {
        }

        constant(const constant &o): _ptr { o._ptr }
        {
        }

        constant(constant &&o): _ptr { std::move(o._ptr) }
        {
        }

        constant &operator=(constant &&o)
        {
            _ptr = std::move(o._ptr);
            return *this;
        }

        constant &operator=(const constant &o)
        {
            _ptr = o._ptr;
            return *this;
        }

        const cpp_int &as_int() const
        {
            return std::get<cpp_int>(*_ptr);
        }

        bool as_bool() const
        {
            return std::get<bool>(*_ptr);
        }

        const uint8_vector &as_bstr() const
        {
            return std::get<uint8_vector>(*_ptr);
        }

        const std::string &as_str() const
        {
            return std::get<std::string>(*_ptr);
        }

        const data &as_data() const
        {
            return std::get<data>(*_ptr);
        }

        const constant_pair::value_type &as_pair() const
        {
            return *std::get<constant_pair>(*_ptr);
        }

        bool operator==(const constant &o) const
        {
            return *_ptr == *o._ptr;
        }

        const constant_list &as_list() const
        {
            return std::get<constant_list>(*_ptr);
        }

        const value_type &operator*() const
        {
            return *_ptr;
        }
    private:
        allocator::ptr_type<value_type> _ptr;
    };

    // this type is needed only for a prettier formatting; see the formatter definitions below
    struct constant_list_values_only {
        const constant_list::list_type &vals;
    };

    struct builtin_one_arg;
    struct builtin_two_arg;
    struct builtin_three_arg;
    struct builtin_six_arg;
    using builtin_any = std::variant<builtin_one_arg, builtin_two_arg, builtin_three_arg, builtin_six_arg>;

    struct t_builtin {
        builtin_tag tag {};

        static t_builtin from_name(const std::string &);

        bool operator==(const t_builtin &o) const
        {
            return tag == o.tag;
        }

        size_t num_args() const;
        builtin_any func() const;
        const std::string &name() const;
        size_t polymorphic_args() const;
    };

    struct t_constr {
        uint64_t tag;
        term_list args;

        t_constr() =delete;

        t_constr(const uint64_t t, term_list &&a): tag { t }, args { std::move(a) }
        {
        }

        t_constr(t_constr &&o): tag { o.tag }, args { std::move(o.args) }
        {
        }

        t_constr &operator=(t_constr &&o)
        {
            tag = o.tag;
            args = std::move(o.args);
            return *this;
        }

        bool operator==(const t_constr &o) const;
    };

    struct t_case {
        term_ptr arg;
        term_list cases;

        t_case() =delete;

        t_case(const term_ptr &arg_, term_list &&cases_): arg { arg_ }, cases { std::move(cases_) }
        {
        }

        t_case(t_case &&o): arg { std::move(o.arg) }, cases { std::move(o.cases) }
        {
        }

        t_case &operator=(t_case &&o)
        {
            arg = std::move(o.arg);
            cases = std::move(o.cases);
            return *this;
        }

        bool operator==(const t_case &o) const;
    };

    struct term {
        using expr_type = std::variant<variable, t_delay, force, t_lambda, apply, constant, failure, t_builtin, t_constr, t_case>;
        expr_type expr;

        template<typename T>
        static term_ptr make_ptr(allocator &alloc, T &&v)
        {
            return alloc.make<term>(std::move(v));
        }

        term() =delete;
        term(const term &) =delete;

        term(expr_type &&e): expr { std::move(e) }
        {
        }

        term(term &&o): expr { std::move(o.expr) }
        {
        }

        term &operator=(term &&o)
        {
            expr = std::move(o.expr);
            return *this;
        }

        bool operator==(const term &o) const
        {
            return expr == o.expr;
        }
    };

    struct value;
    using value_list = vector<value>;

    extern bool builtin_tag_known_name(const std::string &name);
    extern builtin_tag builtin_tag_from_name(const std::string &name);
    extern uint8_vector bls_g1_compress(const bls12_381_g1_element &val);
    extern uint8_vector bls_g2_compress(const bls12_381_g2_element &val);
    extern bls12_381_g1_element bls_g1_decompress(const buffer &bytes);
    extern bls12_381_g2_element bls_g2_decompress(const buffer &bytes);
    extern std::string escape_utf8_string(const std::string &);
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::plutus::builtin_tag>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::builtin_tag &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", daedalus_turbo::plutus::t_builtin { v }.name());
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::bls12_381_g1_element>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::bls12_381_g1_element &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            daedalus_turbo::array<uint8_t, 48> comp {};
            blst_p1_compress(reinterpret_cast<byte *>(comp.data()), &v.val);
            return fmt::format_to(ctx.out(), "0x{}", comp);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::bls12_381_g2_element>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::bls12_381_g2_element &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            daedalus_turbo::array<uint8_t, 96> comp {};
            blst_p2_compress(reinterpret_cast<byte *>(comp.data()), &v.val);
            return fmt::format_to(ctx.out(), "0x{}", comp);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::bls12_381_ml_result>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::bls12_381_ml_result &, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "opaque");
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::data>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &vv, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
#ifdef NDEBUG
            return fmt::format_to(ctx.out(), "{}", vv.as_string(0));
#else
            return fmt::format_to(ctx.out(), "{}", vv.as_string(4));
#endif
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::constant::value_type>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &vv, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo;
            using namespace daedalus_turbo::plutus;
            return std::visit([&ctx](const auto &v) {
                using T = std::decay_t<decltype(v)>;
                if constexpr (std::is_same_v<T, std::monostate>) {
                    return fmt::format_to(ctx.out(), "()");
                } else if constexpr (std::is_same_v<T, bool>) {
                    return fmt::format_to(ctx.out(), "{}", v ? "True" : "False");
                } else if constexpr (std::is_same_v<T, uint8_vector>) {
                    return fmt::format_to(ctx.out(), "#{}", buffer_lowercase { v.span() });
                } else if constexpr (std::is_same_v<T, data>) {
                    return fmt::format_to(ctx.out(), "({})", v);
                } else if constexpr (std::is_same_v<T, std::string>) {
                    return fmt::format_to(ctx.out(), "\"{}\"", escape_utf8_string(v));
                } else if constexpr (std::is_same_v<T, constant_pair>) {
                    return fmt::format_to(ctx.out(), "({}, {})", *v->first, *v->second);
                } else if constexpr (std::is_same_v<T, constant_list>) {
                    return fmt::format_to(ctx.out(), "{}", constant_list_values_only { v->vals });
                } else {
                    return fmt::format_to(ctx.out(), "{}", v);
                }
            }, vv);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::constant_list_values_only>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = fmt::format_to(ctx.out(), "(");
            for (auto it = v.vals.begin(); it != v.vals.end(); ++it) {
                const std::string_view sep { std::next(it) == v.vals.end() ? "" : ", " };
                out_it = fmt::format_to(out_it, "{}{}", **it, sep);
            }
            return fmt::format_to(out_it, ")");
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::constant_type>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            if (v->nested.empty())
                return fmt::format_to(ctx.out(), "{}", v->typ);
            if (v->typ == type_tag::list)
                return fmt::format_to(ctx.out(), "({} {})", v->typ, v->nested.at(0));
            if (v->typ == type_tag::pair)
                return fmt::format_to(ctx.out(), "({} {} {})", v->typ, v->nested.at(0), v->nested.at(1));
            throw daedalus_turbo::error("unsupported constant_type: {}!", v->typ);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::constant>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::constant &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            daedalus_turbo::plutus::allocator alloc {};
            return fmt::format_to(ctx.out(), "(con {} {})", daedalus_turbo::plutus::constant_type::from_val(alloc, v), *v);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::variable>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::variable &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", v.name);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::t_delay>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::t_delay &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "(delay {})", *v.expr);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::t_lambda>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::t_lambda &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "(lam {} {})", v.name, *v.expr);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::apply>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::apply &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "[{} {}]", *v.func, *v.arg);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::force>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::force &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "(force {})", *v.expr);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::failure>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::failure &, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "error");
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::t_builtin>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::t_builtin &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "(builtin {})", v.name());
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::t_constr>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::t_constr &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "(constr {} {})", v.tag, v.args);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::t_case>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::t_case &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "(case {} {})", v.arg, v.cases);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::term::expr_type>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::term::expr_type &vv, FormatContext &ctx) const -> decltype(ctx.out()) {
            return std::visit([&ctx](const auto &v) {
                return fmt::format_to(ctx.out(), "{}", v);
            }, vv);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::term>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::term &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", v.expr);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::term_ptr>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::term_ptr &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", *v);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::version>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::version &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "{}", static_cast<std::string>(v));
        }
    };
}

#endif //!DAEDALUS_TURBO_PLUTUS_TYPES_HPP