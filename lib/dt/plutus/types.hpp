/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_TYPES_HPP
#define DAEDALUS_TURBO_PLUTUS_TYPES_HPP

#include <dt/big_int.hpp>
#include <dt/cbor.hpp>
#include <dt/error.hpp>
#include <dt/format.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo::plutus {
    enum class term_tag: uint8_t {
        variable  = 0,
        delay     = 1,
        lambda    = 2,
        apply     = 3,
        constant  = 4,
        force     = 5,
        error     = 6,
        builtin   = 7,
        construct = 8,
        acase     = 9
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
        bls12_381_m1_result   = 11
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
        verify_ecdsa_secp256k1_signature = 52,
        verify_schnorr_secp256k1_signature = 53,
        // Future
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
        blake2b_224 = 72
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
                case term::construct: return fmt::format_to(ctx.out(), "term::construct");
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
                case type::bls12_381_m1_result: return fmt::format_to(ctx.out(), "bls12_381_m1_result");
                default: throw daedalus_turbo::error("unknown type: {}", static_cast<int>(v));
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::builtin_tag>: formatter<int> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::plutus::builtin_tag &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using builtin = daedalus_turbo::plutus::builtin_tag;
            switch (v) {
                case builtin::add_integer: return fmt::format_to(ctx.out(), "addInteger");
                case builtin::subtract_integer: return fmt::format_to(ctx.out(), "subtractInteger");
                case builtin::multiply_integer: return fmt::format_to(ctx.out(), "multiplyInteger");
                case builtin::divide_integer: return fmt::format_to(ctx.out(), "divideInteger");
                case builtin::quotient_integer: return fmt::format_to(ctx.out(), "quotientInteger");
                case builtin::remainder_integer: return fmt::format_to(ctx.out(), "remainderInteger");
                case builtin::mod_integer: return fmt::format_to(ctx.out(), "modInteger");
                case builtin::equals_integer: return fmt::format_to(ctx.out(), "equalsInteger");
                case builtin::less_than_integer: return fmt::format_to(ctx.out(), "lessThanInteger");
                case builtin::less_than_equals_integer: return fmt::format_to(ctx.out(), "lessThanEqualsInteger");
                case builtin::append_byte_string: return fmt::format_to(ctx.out(), "appendByteString");
                case builtin::cons_byte_string: return fmt::format_to(ctx.out(), "consByteString");
                case builtin::slice_byte_string: return fmt::format_to(ctx.out(), "sliceByteString");
                case builtin::length_of_byte_string: return fmt::format_to(ctx.out(), "lengthOfByteString");
                case builtin::index_byte_string: return fmt::format_to(ctx.out(), "indexByteString");
                case builtin::equals_byte_string: return fmt::format_to(ctx.out(), "equalsByteString");
                case builtin::less_than_byte_string: return fmt::format_to(ctx.out(), "lessThanByteString");
                case builtin::less_than_equals_byte_string: return fmt::format_to(ctx.out(), "lessThanEqualsByteString");
                case builtin::sha2_256: return fmt::format_to(ctx.out(), "sha2_256");
                case builtin::sha3_256: return fmt::format_to(ctx.out(), "sha3_256");
                case builtin::blake2b_256: return fmt::format_to(ctx.out(), "blake2b_256");
                case builtin::verify_ed25519_signature: return fmt::format_to(ctx.out(), "verifyEd25519Signature");
                case builtin::append_string: return fmt::format_to(ctx.out(), "appendString");
                case builtin::equals_string: return fmt::format_to(ctx.out(), "equalsString");
                case builtin::encode_utf8: return fmt::format_to(ctx.out(), "encodeUTF8");
                case builtin::decode_utf8: return fmt::format_to(ctx.out(), "decodeUTF8");
                case builtin::if_then_else: return fmt::format_to(ctx.out(), "ifThenElse");
                case builtin::choose_unit: return fmt::format_to(ctx.out(), "chooseUnit");
                case builtin::trace: return fmt::format_to(ctx.out(), "trace");
                case builtin::fst_pair: return fmt::format_to(ctx.out(), "fstPair");
                case builtin::snd_pair: return fmt::format_to(ctx.out(), "sndPair");
                case builtin::choose_list: return fmt::format_to(ctx.out(), "chooseList");
                case builtin::mk_cons: return fmt::format_to(ctx.out(), "mkCons");
                case builtin::head_list: return fmt::format_to(ctx.out(), "headList");
                case builtin::tail_list: return fmt::format_to(ctx.out(), "tailList");
                case builtin::null_list: return fmt::format_to(ctx.out(), "nullList");
                case builtin::choose_data: return fmt::format_to(ctx.out(), "chooseData");
                case builtin::constr_data: return fmt::format_to(ctx.out(), "constrData");
                case builtin::map_data: return fmt::format_to(ctx.out(), "mapData");
                case builtin::list_data: return fmt::format_to(ctx.out(), "listData");
                case builtin::i_data: return fmt::format_to(ctx.out(), "IData");
                case builtin::b_data: return fmt::format_to(ctx.out(), "BData");
                case builtin::un_constr_data: return fmt::format_to(ctx.out(), "unConstrData");
                case builtin::un_map_data: return fmt::format_to(ctx.out(), "unMapData");
                case builtin::un_list_data: return fmt::format_to(ctx.out(), "unListData");
                case builtin::un_i_data: return fmt::format_to(ctx.out(), "unIData");
                case builtin::un_b_data: return fmt::format_to(ctx.out(), "unBData");
                case builtin::equals_data: return fmt::format_to(ctx.out(), "equalsData");
                case builtin::mk_pair_data: return fmt::format_to(ctx.out(), "mkPairData");
                case builtin::mk_nil_data: return fmt::format_to(ctx.out(), "mkNilData");
                case builtin::mk_nil_pair_data: return fmt::format_to(ctx.out(), "mkNilPairData");
                    // Plutus v2
                case builtin::serialise_data: return fmt::format_to(ctx.out(), "serialiseData");
                case builtin::verify_ecdsa_secp256k1_signature: return fmt::format_to(ctx.out(), "verify_ecdsa_secp256k1_signature");
                case builtin::verify_schnorr_secp256k1_signature: return fmt::format_to(ctx.out(), "verify_schnorr_secp256k1_signature");
                    // Future
                case builtin::bls12_381_g1_add: return fmt::format_to(ctx.out(), "bls12_381_g1_add");
                case builtin::bls12_381_g1_neg: return fmt::format_to(ctx.out(), "bls12_381_g1_neg");
                case builtin::bls12_381_g1_scalar_mul: return fmt::format_to(ctx.out(), "bls12_381_g1_scalar_mul");
                case builtin::bls12_381_g1_equal: return fmt::format_to(ctx.out(), "bls12_381_g1_equal");
                case builtin::bls12_381_g1_hash_to_group: return fmt::format_to(ctx.out(), "bls12_381_g1_hash_to_group");
                case builtin::bls12_381_g1_compress: return fmt::format_to(ctx.out(), "bls12_381_g1_compress");
                case builtin::bls12_381_g1_uncompress: return fmt::format_to(ctx.out(), "bls12_381_g1_uncompress");
                case builtin::bls12_381_g2_add: return fmt::format_to(ctx.out(), "bls12_381_g2_add");
                case builtin::bls12_381_g2_neg: return fmt::format_to(ctx.out(), "bls12_381_g2_neg");
                case builtin::bls12_381_g2_scalar_mul: return fmt::format_to(ctx.out(), "bls12_381_g2_scalar_mul");
                case builtin::bls12_381_g2_equal: return fmt::format_to(ctx.out(), "bls12_381_g2_equal");
                case builtin::bls12_381_g2_hash_to_group: return fmt::format_to(ctx.out(), "bls12_381_g2_hash_to_group");
                case builtin::bls12_381_g2_compress: return fmt::format_to(ctx.out(), "bls12_381_g2_compress");
                case builtin::bls12_381_g2_uncompress: return fmt::format_to(ctx.out(), "bls12_381_g2_uncompress");
                case builtin::bls12_381_miller_loop: return fmt::format_to(ctx.out(), "bls12_381_miller_loop");
                case builtin::bls12_381_mul_ml_result: return fmt::format_to(ctx.out(), "bls12_381_mul_ml_result");
                case builtin::bls12_381_final_verify: return fmt::format_to(ctx.out(), "bls12_381_final_verify");
                case builtin::keccak_256: return fmt::format_to(ctx.out(), "keccak_256");
                case builtin::blake2b_224: return fmt::format_to(ctx.out(), "blake2b_224");
                default: throw daedalus_turbo::error("unknown builtin: {}", static_cast<int>(v));
            }
        }
    };
}

namespace daedalus_turbo::plutus {
    typedef daedalus_turbo::error error;

    struct variable {
        size_t idx = 0;
        //size_t rel_idx = 0;

        bool operator==(const auto &o) const
        {
            return idx == o.idx;
        }
    };

    struct term;
    // shared_ptr is used to make terms copyable
    using term_ptr = std::shared_ptr<const term>;

    struct delay {
        term_ptr expr {};

        bool operator==(const auto &o) const
        {
            return expr && o.expr && *expr == *o.expr;
        }
    };

    struct force {
        term_ptr expr {};

        bool operator==(const auto &o) const
        {
            return expr && o.expr && *expr == *o.expr;
        }
    };

    struct lambda {
        size_t var_idx = 0;
        term_ptr expr {};

        bool operator==(const auto &o) const
        {
            return expr && o.expr && *expr == *o.expr && var_idx == o.var_idx;
        }
    };

    struct apply {
        term_ptr func {};
        term_ptr arg {};

        bool operator==(const auto &o) const
        {
            return func && o.func && *func == *o.func && arg && o.arg && *arg == *o.arg;
        }
    };

    struct constant_type {
        type_tag typ {};
        std::vector<constant_type> nested {};

        static constant_type make_pair(constant_type &&fst, constant_type &&snd)
        {
            constant_type t { type_tag::pair };
            t.nested.emplace_back(std::move(fst));
            t.nested.emplace_back(std::move(snd));
            return t;
        }

        bool operator==(const auto &o) const
        {
            return typ == o.typ && nested == o.nested;
        }
    };
    using constant_type_list = std::vector<constant_type>;

    struct constant {
        using value_type = std::variant<cpp_int, uint8_vector, std::string, bool, std::vector<constant>>;
        constant_type typ {};
        value_type val {};

        static constant make_data(const buffer &data)
        {
            return { constant_type { type_tag::data }, uint8_vector { data } };
        }

        static constant make_int(const cpp_int &val)
        {
            return { constant_type { type_tag::integer }, val };
        }

        static constant make_bstr(const buffer &bytes)
        {
            return { constant_type { type_tag::bytestring }, bytes };
        }

        static constant make_bstr(uint8_vector &&bytes)
        {
            return { constant_type { type_tag::bytestring }, std::move(bytes) };
        }

        static constant make_str(const std::string_view &s)
        {
            return { constant_type { type_tag::string }, std::string { s } };
        }

        static constant make_list(constant_type &&nested_type, std::vector<constant> &&vals)
        {
            for (const auto &val: vals) {
                if (val.typ != nested_type)
                    throw plutus::error("all values in a list must be of the same type");
            }
            constant_type_list nested {};
            nested.emplace_back(std::move(nested_type));
            return { constant_type { type_tag::list, std::move(nested) }, std::move(vals) };
        }

        static constant make_list(constant_type &&nested_type)
        {
            std::vector<constant> vals {};
            return make_list(std::move(nested_type), std::move(vals));
        }

        static constant make_list(std::vector<constant> &&vals)
        {
            if (vals.empty())
                throw plutus::error("either non empty list or a nested data type must be specified!");
            const auto &head = vals.at(0).typ;
            constant_type nested_type { head.typ };
            std::copy(head.nested.begin(), head.nested.end(), std::back_inserter(nested_type.nested));
            return make_list(std::move(nested_type), std::move(vals));
        }

        static constant make_pair(constant &&fst, constant &&snd)
        {
            constant_type typ { type_tag::pair };
            typ.nested.emplace_back(fst.typ);
            typ.nested.emplace_back(snd.typ);
            std::vector<constant> vals {};
            vals.emplace_back(std::move(fst));
            vals.emplace_back(std::move(snd));
            return { std::move(typ), std::move(vals) };
        }

        bool operator==(const auto &o) const
        {
            return typ == o.typ && val == o.val;
        }

        const cpp_int &as_int() const
        {
            return std::get<cpp_int>(val);
        }

        const uint8_vector &as_data() const
        {
            return std::get<uint8_vector>(val);
        }
    };
    using constant_list = std::vector<constant>;

    // this type is needed only for a prettier formatting; see the formatter definitions below
    struct constant_list_values_only {
        const constant_list &list;
    };
    struct constant_list_types_only {
        const constant_list &list;
    };

    struct failure {
        bool operator==(const auto &) const
        {
            return true;
        }
    };

    struct builtin_one_arg;
    struct builtin_two_arg;
    struct builtin_three_arg;
    struct builtin_six_arg;
    using builtin_any = std::variant<builtin_one_arg, builtin_two_arg, builtin_three_arg, builtin_six_arg>;

    struct builtin {
        struct info {
            const size_t num_args;
            const builtin_any &func;
        };

        builtin_tag tag {};

        bool operator==(const auto &o) const
        {
            return tag == o.tag;
        }

        const info &meta() const;
    };

    struct term {
        using expr_type = std::variant<variable, delay, force, lambda, apply, constant_list, failure, builtin>;
        term_tag tag {};
        expr_type expr {};

        static term_ptr make_ptr(term &&t)
        {
            return std::make_shared<const term>(std::move(t));
        }

        static term make_constant(constant &&c)
        {
            constant_list cl {};
            cl.emplace_back(std::move(c));
            return term { term_tag::constant, std::move(cl) };
        }

        static term make_pair(constant &&fst, constant &&snd)
        {
            return term::make_constant(constant::make_pair(std::move(fst), std::move(snd)));
        }

        static term make_list(constant_type &&nested_type)
        {
            return term::make_constant(constant::make_list(std::move(nested_type)));
        }

        static term make_list(constant_list &&vals)
        {
            return term::make_constant(constant::make_list(std::move(vals)));
        }

        static term make_list(constant_type &&nested_type, constant_list &&vals)
        {
            return term::make_constant(constant::make_list(std::move(nested_type), std::move(vals)));
        }

        static term make_list(constant &&fst)
        {
            constant_list vals {};
            vals.emplace_back(std::move(fst));
            return make_list(std::move(vals));
        }

        static term make_list(constant &&fst, constant &&snd)
        {
            constant_list vals {};
            vals.emplace_back(std::move(fst));
            vals.emplace_back(std::move(snd));
            return make_list(std::move(vals));
        }

        static term make_unit()
        {
            return term::make_constant(plutus::constant { constant_type { type_tag::unit } });
        }

        static term make_bool(const bool val)
        {
            return term::make_constant(plutus::constant { constant_type { type_tag::boolean }, val });
        }

        static term make_int(const cpp_int &val)
        {
            return term::make_constant(constant::make_int(val));
        }

        static term make_str(const std::string_view &val)
        {
            return term::make_constant(constant::make_str(val));
        }

        static term make_bstr(const buffer &val)
        {
            return term::make_constant(constant::make_bstr(val));
        }

        static term make_bstr(uint8_vector &&val)
        {
            return term::make_constant(constant::make_bstr(std::move(val)));
        }

        static term make_data(const buffer &val)
        {
            return term::make_constant(constant::make_data(val));
        }

        bool operator==(const auto &o) const
        {
            return tag == o.tag && expr == o.expr;
        }

        const constant &as_constant() const
        {
            const auto &c_list = std::get<constant_list>(expr);
            if (c_list.size() != 1)
                throw plutus::error("the computation didn't result in a single constant!");
            return c_list.at(0);
        }

        const constant &must_be(const type_tag &typ) const
        {
            const auto &c = as_constant();
            const auto act_typ = c.typ.typ;
            if (act_typ != typ)
                throw plutus::error("expected type {} but got {}", typ, act_typ);
            return c;
        }

        bool as_bool() const
        {
            const auto &c = must_be(type_tag::boolean);
            return std::get<bool>(c.val);
        }

        const cpp_int &as_int() const
        {
            const auto &c = must_be(type_tag::integer);
            return std::get<cpp_int>(c.val);
        }

        const std::vector<constant> &as_pair() const
        {
            const auto &c = must_be(type_tag::pair);
            return std::get<std::vector<constant>>(c.val);
        }

        const std::vector<constant> &as_list() const
        {
            const auto &c = must_be(type_tag::list);
            return std::get<std::vector<constant>>(c.val);
        }

        const std::string &as_str() const
        {
            const auto &c = must_be(type_tag::string);
            return std::get<std::string>(c.val);
        }

        const uint8_vector &as_bstr() const
        {
            const auto &c = must_be(type_tag::bytestring);
            return std::get<uint8_vector>(c.val);
        }

        const uint8_vector &as_data() const
        {
            const auto &c = must_be(type_tag::data);
            return std::get<uint8_vector>(c.val);
        }
    };
    using term_list = vector<term>;
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::plutus::constant::value_type>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            switch (v.index()) {
                case 0: return fmt::format_to(ctx.out(), "{}", std::get<daedalus_turbo::cpp_int>(v));
                case 1: return fmt::format_to(ctx.out(), "{}", std::get<daedalus_turbo::uint8_vector>(v));
                case 2: return fmt::format_to(ctx.out(), "{}", std::get<std::string>(v));
                case 3: return fmt::format_to(ctx.out(), "{}", std::get<bool>(v) ? "True" : "False");
                case 4: return fmt::format_to(ctx.out(), "{}", constant_list_values_only { std::get<constant_list>(v) });
                default: return fmt::format_to(ctx.out(), "(unknown value type {})", v.index());
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::constant_list_values_only>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = fmt::format_to(ctx.out(), "(");
            for (auto it = v.list.begin(); it != v.list.end(); it++) {
                const std::string_view sep { std::next(it) == v.list.end() ? "" : ", " };
                if (it->typ.typ == daedalus_turbo::plutus::type_tag::unit)
                    out_it = fmt::format_to(out_it, "(){}", sep);
                else
                    out_it = fmt::format_to(out_it, "{}{}", it->val, sep);
            }
            return fmt::format_to(out_it, ")");
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::constant_list_types_only>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            auto out_it = fmt::format_to(ctx.out(), "(");
            for (auto it = v.list.begin(); it != v.list.end(); it++) {
                const std::string_view sep { std::next(it) == v.list.end() ? "" : ", " };
                out_it = fmt::format_to(out_it, "{}{}", it->typ, sep);
            }
            return fmt::format_to(out_it, ")");
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::constant_type>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            if (v.nested.empty())
                return fmt::format_to(ctx.out(), "{}", v.typ);
            if (v.typ == type_tag::list)
                return fmt::format_to(ctx.out(), "({} {})", v.typ, v.nested.at(0));
            if (v.typ == type_tag::pair)
                return fmt::format_to(ctx.out(), "({} {} {})", v.typ, v.nested.at(0), v.nested.at(1));
            throw daedalus_turbo::error("unsupported constant_type: {}!", v.typ);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::constant>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            switch (v.typ.typ) {
                case type_tag::unit: return fmt::format_to(ctx.out(), "(con {} ())", v.typ.typ);
                case type_tag::bytestring: return fmt::format_to(ctx.out(), "(con {} #{})", v.typ.typ, v.val);
                case type_tag::data:
                    return fmt::format_to(ctx.out(), "(con {} ({}))", v.typ.typ,
                                          daedalus_turbo::cbor::parse(std::get<daedalus_turbo::uint8_vector>(v.val)));
                case type_tag::pair: {
                    const auto &vals = std::get<constant_list>(v.val);
                    return fmt::format_to(ctx.out(), "(con (pair {} {}) ({}, {}))",
                                          v.typ.nested.at(0), v.typ.nested.at(1), vals.at(0).val, vals.at(1).val);
                }
                case type_tag::list: {
                    const auto &vals = std::get<constant_list>(v.val);
                    return fmt::format_to(ctx.out(), "(con (list {}) ({}))",
                                          v.typ.nested.at(0), constant_list_values_only { vals });
                }
                default: return fmt::format_to(ctx.out(), "(con {} {})", v.typ.typ, v.val);
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::term>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using namespace daedalus_turbo::plutus;
            switch (v.tag) {
                case term_tag::variable: return fmt::format_to(ctx.out(), "v{}", std::get<variable>(v.expr).idx);
                case term_tag::delay: return fmt::format_to(ctx.out(), "(delay {})", *std::get<delay>(v.expr).expr);
                case term_tag::lambda: return fmt::format_to(ctx.out(), "(lam v{} {})", std::get<lambda>(v.expr).var_idx, *std::get<lambda>(v.expr).expr);
                case term_tag::apply: return fmt::format_to(ctx.out(), "[{} {}]", *std::get<apply>(v.expr).func, *std::get<apply>(v.expr).arg);
                case term_tag::constant: {
                    const auto consts = std::get<constant_list>(v.expr);
                    if (consts.size() == 1) [[likely]]
                        return fmt::format_to(ctx.out(), "{}", consts.at(0));
                    return fmt::format_to(ctx.out(), "{}", consts);
                }
                case term_tag::force: return fmt::format_to(ctx.out(), "(force {})", *std::get<force>(v.expr).expr);
                case term_tag::error: return fmt::format_to(ctx.out(), "error");
                case term_tag::builtin: return fmt::format_to(ctx.out(), "(builtin {})", std::get<builtin>(v.expr).tag);
                //case term_tag::construct: return fmt::format_to(ctx.out(), "term::construct");
                //case term_tag::acase: return fmt::format_to(ctx.out(), "term::case");
                default: return fmt::format_to(ctx.out(), "(unknown {})", static_cast<int>(v.tag));
            }
        }
    };
}

#endif //!DAEDALUS_TURBO_PLUTUS_TYPES_HPP
