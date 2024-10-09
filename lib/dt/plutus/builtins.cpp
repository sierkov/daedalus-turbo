/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <utfcpp/utf8.h>
#include <dt/crypto/secp256k1.hpp>
#include <dt/plutus/builtins.hpp>
#include <dt/blake2b.hpp>
#include <dt/ed25519.hpp>
#include <dt/crypto/keccak.hpp>
#include <dt/crypto/sha2.hpp>
#include <dt/crypto/sha3.hpp>

namespace daedalus_turbo::plutus::builtins {
    using namespace crypto;

    value add_integer(allocator &alloc, const value &x, const value &y)
    {
        return { alloc, x.as_int() + y.as_int() };
    }

    value subtract_integer(allocator &alloc, const value &x, const value &y)
    {
        return { alloc, x.as_int() - y.as_int() };
    }

    value multiply_integer(allocator &alloc, const value &x, const value &y)
    {
        return { alloc, x.as_int() * y.as_int() };
    }

    value divide_integer(allocator &alloc, const value &x, const value &y)
    {
        const auto &y_val = y.as_int();
        if (y_val == 0) [[unlikely]]
            throw error("division by zero is not allowed!");
        const auto &x_val = x.as_int();
        cpp_int div, rem;
        boost::multiprecision::divide_qr(x_val, y_val, div, rem);
        if (rem != 0 && ((x_val < 0) ^ (y_val < 0)))
            --div;
        return { alloc, std::move(div) };
    }

    value mod_integer(allocator &alloc, const value &x, const value &y)
    {
        const auto &y_val = y.as_int();
        if (y_val == 0) [[unlikely]]
            throw error("division by zero is not allowed!");
        const auto &x_val = x.as_int();
        return { alloc, ((x_val % y_val) + y_val) % y_val };
    }

    value quotient_integer(allocator &alloc, const value &x, const value &y)
    {
        const auto &y_val = y.as_int();
        if (y_val == 0) [[unlikely]]
            throw error("division by zero is not allowed!");
        return { alloc, x.as_int() / y_val };
    }

    value remainder_integer(allocator &alloc, const value &x, const value &y)
    {
        const auto &y_val = y.as_int();
        if (y_val == 0) [[unlikely]]
            throw error("division by zero is not allowed!");
        return { alloc, x.as_int() % y_val };
    }

    value equals_integer(allocator &alloc, const value &x, const value &y)
    {
        return value::boolean(alloc, x.as_int() == y.as_int());
    }

    value less_than_integer(allocator &alloc, const value &x, const value &y)
    {
        return value::boolean(alloc, x.as_int() < y.as_int());
    }

    value less_than_equals_integer(allocator &alloc, const value &x, const value &y)
    {
        return value::boolean(alloc, x.as_int() <= y.as_int());
    }

    value append_byte_string(allocator &alloc, const value &x, const value &y)
    {
        uint8_vector res {};
        const auto &x_val = x.as_bstr();
        const auto &y_val = y.as_bstr();
        res.reserve(x_val.size() + y_val.size());
        res << x_val << y_val;
        return { alloc, std::move(res) };
    }

    value cons_byte_string(allocator &alloc, const value &c, const value &s)
    {
        const auto &c_val = c.as_int();
        const auto &s_val = s.as_bstr();
        uint8_vector res {};
        res.reserve(1 + s_val.size());
        if (c_val < 0 || c_val > 255)
            throw error("cons_byte_string's first parameter must be between 0 and 255: {}!", c_val);
        res << static_cast<uint8_t>(c_val) << s_val;
        return { alloc, std::move(res) };
    }

    value slice_byte_string(allocator &alloc, const value &pos_raw, const value &sz_raw, const value &s_raw)
    {
        auto pos = pos_raw.as_int();
        auto sz = sz_raw.as_int();
        const auto &s = s_raw.as_bstr();
        if (pos < 0)
            pos = 0;
        if (pos > s.size())
            pos = s.size();
        if (pos + sz > s.size())
            sz = s.size() - pos;
        if (pos + sz < pos)
            sz = 0;
        return { alloc, s.span().subspan(static_cast<size_t>(pos), static_cast<size_t>(sz)) };
    }

    value length_of_byte_string(allocator &alloc, const value &s)
    {
        return { alloc, cpp_int { s.as_bstr().size() } };
    }

    value index_byte_string(allocator &alloc, const value &s_t, const value &i_t)
    {
        const auto &s = s_t.as_bstr();
        const auto &i_bi = i_t.as_int();
        if (i_bi < 0 || i_bi >= std::numeric_limits<size_t>::max()) [[unlikely]]
            throw error("byte_string index out of the allowed range: {}", i_bi);
        const auto i = static_cast<size_t>(i_bi);
        if (i >= s.size()) [[unlikely]]
            throw error("byte_string index too big: {}", i);
        return { alloc, cpp_int { s[i] } };
    }

    value equals_byte_string(allocator &alloc, const value &s1, const value &s2)
    {
        return value::boolean(alloc, s1.as_bstr() == s2.as_bstr());
    }

    value less_than_byte_string(allocator &alloc, const value &s1, const value &s2)
    {
        return value::boolean(alloc, s1.as_bstr() < s2.as_bstr());
    }

    value less_than_equals_byte_string(allocator &alloc, const value &s1_t, const value &s2_t)
    {
        const auto &s1 = s1_t.as_bstr();
        const auto &s2 = s2_t.as_bstr();
        return value::boolean(alloc, s1 < s2 || s1 == s2);
    }

    value append_string(allocator &alloc, const value &s1, const value &s2)
    {
        std::string res = s1.as_str();
        res += s2.as_str();
        return { alloc, std::move(res) };
    }

    value equals_string(allocator &alloc, const value &s1, const value &s2)
    {
        return value::boolean(alloc, s1.as_str() == s2.as_str());
    }

    value encode_utf8(allocator &alloc, const value &s)
    {
        return { alloc, uint8_vector { s.as_str() } };
    }

    value decode_utf8(allocator &alloc, const value &b)
    {
        const auto s = b.as_bstr().str();
        if (const auto it = utf8::find_invalid(s.begin(), s.end()); it == s.end()) [[likely]]
            return { alloc, std::string { s } };
        throw error("an invalid utf8 sequence: {}", b.as_bstr());
    }

    value if_then_else(allocator &, const value &condition, const value &yes, const value &no)
    {
        if (const auto cond = condition.as_bool(); cond)
            return yes;
        return no;
    }

    value sha2_256(allocator &alloc, const value &s)
    {
        uint8_vector res(sizeof(sha2::hash_256));
        sha2::digest(res, s.as_bstr());
        return { alloc, std::move(res) };
    }

    value sha3_256(allocator &alloc, const value &s)
    {
        uint8_vector res(sizeof(sha3::hash_256));
        sha3::digest(res, s.as_bstr());
        return { alloc, std::move(res) };
    }

    value blake2b_256(allocator &alloc, const value &s)
    {
        uint8_vector res(sizeof(blake2b_256_hash));
        blake2b(res, s.as_bstr());
        return { alloc, std::move(res) };
    }

    value blake2b_224(allocator &alloc, const value &s)
    {
        uint8_vector res(sizeof(blake2b_224_hash));
        blake2b(res, s.as_bstr());
        return { alloc, std::move(res) };
    }

    value keccak_256(allocator &alloc, const value &s)
    {
        uint8_vector res(sizeof(keccak::hash_256));
        keccak::digest(res, s.as_bstr());
        return { alloc, std::move(res) };
    }

    value verify_ed25519_signature(allocator &alloc, const value &vk, const value &msg, const value &sig)
    {
        return value::boolean(alloc, ed25519::verify(sig.as_bstr(), vk.as_bstr(), msg.as_bstr()));
    }

    value choose_unit(allocator &, const value &u, const value &v)
    {
        u.as_unit();
        return v;
    }

    value fst_pair(allocator &alloc, const value &p)
    {
        return { alloc, p.as_pair().first };
    }

    value snd_pair(allocator &alloc, const value &p)
    {
        return { alloc, p.as_pair().second };
    }

    value choose_list(allocator &, const value &a, const value &t1, const value &t2)
    {
        if (const auto &cl = a.as_list(); !cl->vals.empty())
            return t2;
        return t1;
    }

    value mk_cons(allocator &alloc, const value &x, const value &l)
    {
        const auto &cx = x.as_const();
        const auto &cl = l.as_const().as_list();
        if (const auto cx_typ = constant_type::from_val(alloc, cx); cx_typ != cl->typ) [[unlikely]]
            throw error("mkCons requires both arguments to be of the same type but got {} and {}", cx_typ, cl->typ);
        constant_list::list_type vals { alloc.resource() };
        vals.emplace_back(cx);
        std::copy(cl->vals.begin(), cl->vals.end(), std::back_inserter(vals));
        return { alloc, constant_list { alloc, constant_type::from_val(alloc, cx), std::move(vals) } };
    }

    value head_list(allocator &alloc, const value &l)
    {
        const auto &cl = l.as_list();
        if (!cl->vals.empty()) [[likely]]
            return { alloc, cl->vals.front() };
        throw error("head_list builtin called with an empty list!");
    }

    value tail_list(allocator &alloc, const value &l)
    {
        const auto &cl = l.as_list();
        if (cl->vals.empty()) [[unlikely]]
            throw error("calling tail_list on an empty list!");
        constant_list::list_type vals { alloc.resource() };
        std::copy(cl->vals.begin() + 1, cl->vals.end(), std::back_inserter(vals));
        return { alloc, constant_list { alloc, constant_type { cl->typ }, std::move(vals) } };
    }

    value null_list(allocator &alloc, const value &l)
    {
        return value::boolean(alloc, l.as_list()->vals.empty());
    }

    value trace(allocator &, const value &s, const value &t)
    {
        logger::debug("plutus builtins::trace: {}", s);
        return t;
    }

    value choose_data(allocator &, const value &d, const value &c, const value &m, const value &l, const value &i, const value &b)
    {
        return std::visit([&](const auto &v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, data::int_type>) {
                return i;
            } else if constexpr (std::is_same_v<T, data::bstr_type>) {
                return b;
            } else if constexpr (std::is_same_v<T, data::list_type>) {
                return l;
            } else if constexpr (std::is_same_v<T, data::map_type>) {
                return m;
            } else if constexpr (std::is_same_v<T, data_constr>) {
                return c;
            } else {
                throw error("unsupported data type: {}!", typeid(T).name());
            }
        }, d.as_data().val);
    }

    value constr_data(allocator &alloc, const value &c, const value &l)
    {
        data::list_type dl {};
        for (const auto &d: l.as_list()->vals)
            dl.emplace_back(d.as_data());
        return { alloc, data::constr(cpp_int { c.as_int() }, std::move(dl)) };
    }

    value map_data(allocator &alloc, const value &m)
    {
        data::map_type dm {};
        for (const auto &c: m.as_list()->vals) {
            const auto &p = c.as_pair();
            dm.emplace_back(data_pair { data { p.first.as_data() }, data { p.second.as_data() } });
        }
        return { alloc, data::map(std::move(dm)) };
    }

    value list_data(allocator &alloc, const value &l)
    {
        data::list_type dl {};
        for (const auto &d: l.as_list()->vals)
            dl.emplace_back(d.as_data());
        return { alloc, data::list(std::move(dl)) };
    }

    value i_data(allocator &alloc, const value &i)
    {
        return { alloc, data::bint(cpp_int { i.as_int() } ) };
    }

    value b_data(allocator &alloc, const value &b)
    {
        return { alloc, data::bstr(b.as_bstr()) };
    }

    value un_constr_data(allocator &alloc, const value &t)
    {
        if (const auto &d = t.as_data(); std::holds_alternative<data_constr>(d.val)) {
            const auto &c = std::get<data_constr>(d.val);
            constant_list::list_type cl {};
            for (const auto &d: c->second)
                cl.emplace_back(alloc, d);
            return { alloc, constant { alloc, constant_pair { alloc, constant { alloc, c->first },
                constant { alloc, constant_list { alloc, constant_type { alloc, type_tag::data }, std::move(cl) } } } } };
        }
        throw error("invalid input for un_constr_data: {}!", t);
    }

    value un_map_data(allocator &alloc, const value &t)
    {
        if (const auto &d = t.as_data(); std::holds_alternative<data::map_type>(d.val)) {
            const auto &m = std::get<data::map_type>(d.val);
            constant_list::list_type cl {};
            constant_type typ { alloc, type_tag::pair, { constant_type { alloc, type_tag::data }, constant_type { alloc, type_tag::data } } };
            for (const auto &p: m)
                cl.emplace_back(alloc, constant_pair { alloc, constant { alloc, p->first }, constant { alloc, p->second } });
            return { alloc, constant_list { alloc, std::move(typ) , std::move(cl) } };
        }
        throw error("invalid input for un_map_data: {}!", t);
    }

    value un_list_data(allocator &alloc, const value &t) {
        if (const auto &d = t.as_data(); std::holds_alternative<data::list_type>(d.val)) {
            const auto &l = std::get<data::list_type>(d.val);
            constant_list::list_type cl {};
            for (const auto &d: l)
                cl.emplace_back(alloc, d);
            return { alloc, constant_list { alloc, constant_type { alloc, type_tag::data }, std::move(cl) } };
        }
        throw error("invalid input for un_list_data: {}!", t);
    }

    value un_i_data(allocator &alloc, const value &t)
    {
        if (const auto &d = t.as_data(); std::holds_alternative<data::int_type>(d.val))
            return { alloc, std::get<data::int_type>(d.val) };
        throw error("invalid input for un_i_data: {}!", t);
    }

    value un_b_data(allocator &alloc, const value &t) {
        if (const auto &d = t.as_data(); std::holds_alternative<data::bstr_type>(d.val))
            return { alloc, std::get<data::bstr_type>(d.val) };
        throw error("invalid input for un_b_data: {}!", t);
    }

    value equals_data(allocator &alloc, const value &d1, const value &d2)
    {
        return value::boolean(alloc, d1.as_data() == d2.as_data());
    }

    value mk_pair_data(allocator &alloc, const value &fst, const value &snd)
    {
        return { alloc, constant { alloc, constant_pair { alloc, constant { alloc, fst.as_data() }, constant { alloc, snd.as_data() } } } };
    }

    value mk_nil_data(allocator &alloc, const value &)
    {
        return value::make_list(alloc, constant_type { alloc, type_tag::data });
    }

    value mk_nil_pair_data(allocator &alloc, const value &)
    {
        constant_type::list_type nested { alloc.resource() };
        nested.emplace_back(alloc, type_tag::data);
        nested.emplace_back(alloc, type_tag::data);
        return value::make_list(alloc, constant_type { alloc, type_tag::pair, std::move(nested) });
    }

    value serialize_data(allocator &alloc, const value &d)
    {
        return { alloc, d.as_data().as_cbor() };
    }

    value verify_ecdsa_secp_256k1_signature(allocator &alloc, const value &vk, const value &msg, const value &sig)
    {
        return value::boolean(alloc, crypto::secp256k1::ecdsa::verify(sig.as_bstr(), vk.as_bstr(), msg.as_bstr()));
    }

    value verify_schnorr_secp_256k1_signature(allocator &alloc, const value &vk, const value &msg, const value &sig)
    {
        return value::boolean(alloc, crypto::secp256k1::schnorr::verify(sig.as_bstr(), vk.as_bstr(), msg.as_bstr()));
    }

    value integer_to_byte_string(allocator &alloc, const value &msb_t, const value &w_t, const value &val)
    {
        static cpp_int max_val { boost::multiprecision::pow(cpp_int { 2 }, 65536) };
        const auto msb = msb_t.as_bool();
        const auto w = static_cast<size_t>(w_t.as_int());
        const auto &v = val.as_int();
        if (v < 0) [[unlikely]]
            throw error("integer_to_byte_string requires non-negative integers but got: {}", v);
        if (v >= max_val) [[unlikely]]
            throw error("integer_to_byte_string allows only values less than 2^65536 but got: {}", v);
        uint8_vector bytes {};
        if (v > 0) [[likely]]
            boost::multiprecision::export_bits(val.as_int(), std::back_inserter(bytes), 8, msb);
        if (w) {
            if (w > 8192)
                throw error("maximum allowed width is 8192 but got {}!", w);
            if (bytes.size() > w) [[unlikely]]
                throw error("expected {} bytes but got {}", bytes.size(), w);
            if (bytes.size() < w) {
                uint8_vector padding(w - bytes.size());
                if (msb) {
                    padding << bytes;
                    bytes = std::move(padding);
                } else {
                    bytes << padding;
                }
            }
        }
        return { alloc, std::move(bytes) };
    }

    value byte_string_to_integer(allocator &alloc, const value &msb_t, const value &b)
    {
        const auto msb = msb_t.as_bool();
        const auto &bytes = b.as_bstr();
        cpp_int val {};
        if (!bytes.empty()) [[likely]]
            boost::multiprecision::import_bits(val, bytes.begin(), bytes.end(), 8, msb);
        return { alloc, std::move(val) };
    }

    value bls12_381_g1_add(allocator &alloc, const value &a, const value &b)
    {
        blst_p1 out;
        blst_p1_add(&out, &a.as_bls_g1().val, &b.as_bls_g1().val);
        return { alloc, out };
    }

    value bls12_381_g1_neg(allocator &alloc, const value &a)
    {
        blst_p1 out { a.as_bls_g1().val };
        blst_p1_cneg(&out, true);
        return { alloc, out };
    }

    static blst_scalar bls12_381_make_scalar(const value &k_t)
    {
        static const cpp_int scalar_period { "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001" };
        cpp_int k { k_t.as_int() % scalar_period };
        if (k < 0)
            k += scalar_period;
        uint8_vector k_bytes {};
        boost::multiprecision::export_bits(k, std::back_inserter(k_bytes), 8, false);
        while (k_bytes.size() < 32)
            k_bytes.emplace_back(0);
        if (k_bytes.size() > 32) [[unlikely]]
            throw error("expected {} scalar must be not more than 32 bytes but got {}!", k_bytes.size(), k);
        blst_scalar k_s {};
        blst_scalar_from_lendian(&k_s, k_bytes.data());
        return k_s;
    }

    value bls12_381_g1_scalar_mul(allocator &alloc, const value &k_t, const value &v_t)
    {
        blst_p1 out;
        const auto k_s = bls12_381_make_scalar(k_t);
        blst_p1_mult(&out, &v_t.as_bls_g1().val, reinterpret_cast<const byte *>(&k_s), sizeof(k_s) * 8);
        return { alloc, out };
    }

    value bls12_381_g1_equal(allocator &alloc, const value &a, const value &b)
    {
        return value::boolean(alloc, blst_p1_is_equal(&a.as_bls_g1().val, &b.as_bls_g1().val));
    }

    value bls12_381_g1_hash_to_group(allocator &alloc, const value &msg_t, const value &dst_t)
    {
        const auto &msg = msg_t.as_bstr();
        const auto &dst = dst_t.as_bstr();
        if (dst.size() > 255) [[unlikely]]
            throw error("dst must be less than 256 bytes but got {}!", dst.size());
        blst_p1 out;
        blst_hash_to_g1(&out, msg.data(), msg.size(), dst.data(), dst.size());
        return { alloc, out };
    }

    value bls12_381_g1_compress(allocator &alloc, const value &v)
    {
        return { alloc, bls_g1_compress(v.as_bls_g1()) };
    }

    value bls12_381_g1_uncompress(allocator &alloc, const value &v)
    {
        return { alloc, bls_g1_decompress(v.as_bstr()).val };
    }

    value bls12_381_g2_add(allocator &alloc, const value &a, const value &b)
    {
        blst_p2 out;
        blst_p2_add(&out, &a.as_bls_g2().val, &b.as_bls_g2().val);
        return { alloc, out };
    }

    value bls12_381_g2_neg(allocator &alloc, const value &a)
    {
        blst_p2 out { a.as_bls_g2().val };
        blst_p2_cneg(&out, true);
        return { alloc, out };
    }

    value bls12_381_g2_scalar_mul(allocator &alloc, const value &k_t, const value &v_t)
    {
        blst_p2 out;
        const auto k_s = bls12_381_make_scalar(k_t);
        blst_p2_mult(&out, &v_t.as_bls_g2().val, reinterpret_cast<const byte *>(&k_s), sizeof(k_s) * 8);
        return { alloc, out };
    }

    value bls12_381_g2_equal(allocator &alloc, const value &a, const value &b)
    {
        return value::boolean(alloc, blst_p2_is_equal(&a.as_bls_g2().val, &b.as_bls_g2().val));
    }

    value bls12_381_g2_hash_to_group(allocator &alloc, const value &msg_t, const value &dst_t)
    {
        const auto &msg = msg_t.as_bstr();
        const auto &dst = dst_t.as_bstr();
        if (dst.size() > 255) [[unlikely]]
            throw error("dst must be less than 256 bytes but got {}!", dst.size());
        blst_p2 out;
        blst_hash_to_g2(&out, msg.data(), msg.size(), dst.data(), dst.size());
        return { alloc, out };
    }

    value bls12_381_g2_compress(allocator &alloc, const value &v)
    {
        return { alloc, bls_g2_compress(v.as_bls_g2()) };
    }

    value bls12_381_g2_uncompress(allocator &alloc, const value &v)
    {
        return { alloc, bls_g2_decompress(v.as_bstr()).val };
    }

    value bls12_381_miller_loop(allocator &alloc, const value &g1, const value &g2)
    {
        blst_p1_affine g1_a {};
        blst_p1_to_affine(&g1_a, &g1.as_bls_g1().val);
        blst_p2_affine g2_a {};
        blst_p2_to_affine(&g2_a, &g2.as_bls_g2().val);
        blst_fp12 out;
        blst_miller_loop(&out, &g2_a, &g1_a);
        return { alloc, out };
    }

    value bls12_381_mul_ml_result(allocator &alloc, const value &a, const value &b)
    {
        blst_fp12 out;
        blst_fp12_mul(&out, &a.as_bls_ml_res().val,  &b.as_bls_ml_res().val);
        return { alloc, out };
    }

    value bls12_381_final_verify(allocator &alloc, const value &a, const value &b)
    {
        return value::boolean(alloc, blst_fp12_finalverify(&a.as_bls_ml_res().val, &b.as_bls_ml_res().val));
    }
}