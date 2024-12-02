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
        return { alloc, bint_type { alloc, *x.as_int() + *y.as_int() } };
    }

    value subtract_integer(allocator &alloc, const value &x, const value &y)
    {
        return { alloc, bint_type { alloc, *x.as_int() - *y.as_int() } };
    }

    value multiply_integer(allocator &alloc, const value &x, const value &y)
    {
        return { alloc, bint_type { alloc, *x.as_int() * *y.as_int() } };
    }

    value divide_integer(allocator &alloc, const value &x, const value &y)
    {
        const auto &y_val = y.as_int();
        if (y_val == 0) [[unlikely]]
            throw error("division by zero is not allowed!");
        const auto &x_val = x.as_int();
        bint_type::value_type div, rem;
        boost::multiprecision::divide_qr(*x_val, *y_val, div, rem);
        if (rem != 0 && ((*x_val < 0) ^ (*y_val < 0)))
            --div;
        return { alloc, bint_type { alloc, std::move(div) } };
    }

    static cpp_int mod_integer_int(const cpp_int &x, const cpp_int &y)
    {
        return ((x % y) + y) % y;
    }

    value mod_integer(allocator &alloc, const value &x, const value &y)
    {
        const auto &y_val = y.as_int();
        if (y_val == 0) [[unlikely]]
            throw error("division by zero is not allowed!");
        const auto &x_val = x.as_int();
        return { alloc, bint_type { alloc, mod_integer_int(*x_val, *y_val) } };
    }

    value quotient_integer(allocator &alloc, const value &x, const value &y)
    {
        const auto &y_val = y.as_int();
        if (y_val == 0) [[unlikely]]
            throw error("division by zero is not allowed!");
        return { alloc, bint_type { alloc, *x.as_int() / *y_val } };
    }

    value remainder_integer(allocator &alloc, const value &x, const value &y)
    {
        const auto &y_val = y.as_int();
        if (y_val == 0) [[unlikely]]
            throw error("division by zero is not allowed!");
        return { alloc, bint_type { alloc, *x.as_int() % *y_val } };
    }

    value equals_integer(allocator &alloc, const value &x, const value &y)
    {
        return value::boolean(alloc, x.as_int() == y.as_int());
    }

    value less_than_integer(allocator &alloc, const value &x, const value &y)
    {
        return value::boolean(alloc, *x.as_int() < *y.as_int());
    }

    value less_than_equals_integer(allocator &alloc, const value &x, const value &y)
    {
        return value::boolean(alloc, *x.as_int() <= *y.as_int());
    }

    value append_byte_string(allocator &alloc, const value &x, const value &y)
    {
        bstr_type::value_type res { alloc };
        const auto &x_val = x.as_bstr();
        const auto &y_val = y.as_bstr();
        res.reserve(x_val->size() + y_val->size());
        res << *x_val <<* y_val;
        return { alloc, std::move(res) };
    }

    value cons_byte_string(allocator &alloc, const value &c, const value &s)
    {
        cpp_int c_val { *c.as_int() };
        const auto &s_val = s.as_bstr();
        bstr_type::value_type res { alloc };
        res.reserve(1 + s_val->size());
        if (c_val < 0 || c_val > 255)
            c_val = mod_integer_int(c_val, 256);
        res << static_cast<uint8_t>(c_val) << *s_val;
        return { alloc, std::move(res) };
    }

    value cons_byte_string_v2(allocator &alloc, const value &c, const value &s)
    {
        const auto &c_val = c.as_int();
        const auto &s_val = s.as_bstr();
        bstr_type::value_type res { alloc };
        res.reserve(1 + s_val->size());
        if (*c_val < 0 || *c_val > 255)
            throw error("cons_byte_string's first parameter must be between 0 and 255: {}!", c_val);
        res << static_cast<uint8_t>(*c_val) << *s_val;
        return { alloc, std::move(res) };
    }

    value slice_byte_string(allocator &alloc, const value &pos_raw, const value &sz_raw, const value &s_raw)
    {
        auto pos = static_cast<int64_t>(*pos_raw.as_int());
        auto sz = static_cast<int64_t>(*sz_raw.as_int());
        const auto &s = s_raw.as_bstr();
        const auto s_sz = static_cast<int64_t>(s->size());
        if (pos < 0)
            pos = 0;
        if (pos > s_sz)
            pos = s->size();
        if (pos + sz > s_sz)
            sz = s_sz - pos;
        if (pos + sz < pos)
            sz = 0;
        return { alloc, s->span().subspan(pos, sz) };
    }

    value length_of_byte_string(allocator &alloc, const value &s)
    {
        return { alloc, bint_type { alloc, s.as_bstr()->size() } };
    }

    value index_byte_string(allocator &alloc, const value &s_t, const value &i_t)
    {
        const auto &s = s_t.as_bstr();
        const auto &i_bi = i_t.as_int();
        if (*i_bi < 0 || *i_bi >= std::numeric_limits<size_t>::max()) [[unlikely]]
            throw error("byte_string index out of the allowed range: {}", i_bi);
        const auto i = static_cast<size_t>(*i_bi);
        if (i >= s->size()) [[unlikely]]
            throw error("byte_string index too big: {}", i);
        return { alloc, bint_type { alloc, (*s)[i] } };
    }

    value equals_byte_string(allocator &alloc, const value &s1, const value &s2)
    {
        return value::boolean(alloc, s1.as_bstr() == s2.as_bstr());
    }

    value less_than_byte_string(allocator &alloc, const value &s1, const value &s2)
    {
        return value::boolean(alloc, *s1.as_bstr() < *s2.as_bstr());
    }

    value less_than_equals_byte_string(allocator &alloc, const value &s1_t, const value &s2_t)
    {
        const auto &s1 = s1_t.as_bstr();
        const auto &s2 = s2_t.as_bstr();
        return value::boolean(alloc, *s1 < *s2 || s1 == s2);
    }

    value append_string(allocator &alloc, const value &s1, const value &s2)
    {
        str_type::value_type res { *s1.as_str(), alloc.resource() };
        res += *s2.as_str();
        return { alloc, std::move(res) };
    }

    value equals_string(allocator &alloc, const value &s1, const value &s2)
    {
        return value::boolean(alloc, s1.as_str() == s2.as_str());
    }

    value encode_utf8(allocator &alloc, const value &s)
    {
        return { alloc, buffer { *s.as_str() } };
    }

    value decode_utf8(allocator &alloc, const value &b)
    {
        const auto s = b.as_bstr()->str();
        if (const auto it = utf8::find_invalid(s.begin(), s.end()); it == s.end()) [[likely]]
            return { alloc, str_type { alloc, s } };
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
        bstr_type::value_type res { alloc, sizeof(sha2::hash_256) };
        sha2::digest(res, *s.as_bstr());
        return { alloc, std::move(res) };
    }

    value sha3_256(allocator &alloc, const value &s)
    {
        bstr_type::value_type res { alloc, sizeof(sha3::hash_256) };
        sha3::digest(res, *s.as_bstr());
        return { alloc, std::move(res) };
    }

    value blake2b_256(allocator &alloc, const value &s)
    {
        bstr_type::value_type res { alloc, sizeof(blake2b_256_hash) };
        blake2b(res, *s.as_bstr());
        return { alloc, std::move(res) };
    }

    value blake2b_224(allocator &alloc, const value &s)
    {
        bstr_type::value_type res { alloc, sizeof(blake2b_224_hash) };
        blake2b(res, *s.as_bstr());
        return { alloc, std::move(res) };
    }

    value keccak_256(allocator &alloc, const value &s)
    {
        bstr_type::value_type res { alloc, sizeof(keccak::hash_256) };
        keccak::digest(res, *s.as_bstr());
        return { alloc, std::move(res) };
    }

    value verify_ed25519_signature(allocator &alloc, const value &vk, const value &msg, const value &sig)
    {
        return value::boolean(alloc, ed25519::verify(*sig.as_bstr(), *vk.as_bstr(), *msg.as_bstr()));
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
        constant_list::list_type vals { alloc };
        vals.emplace_back(cx);
        std::copy(cl->vals.begin(), cl->vals.end(), std::back_inserter(vals));
        return value::make_list(alloc, constant_type::from_val(alloc, cx), std::move(vals));
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
        constant_list::list_type vals { alloc };
        std::copy(std::next(cl->vals.begin(), 1), cl->vals.end(), std::back_inserter(vals));
        return value::make_list(alloc, constant_type { cl->typ }, std::move(vals));
    }

    value null_list(allocator &alloc, const value &l)
    {
        return value::boolean(alloc, l.as_list()->vals.empty());
    }

    value trace(allocator &, const value &s, const value &t)
    {
        logger::trace("plutus builtins::trace: {}", s);
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
        }, *d.as_data());
    }

    value constr_data(allocator &alloc, const value &c, const value &l)
    {
        data::list_type dl { alloc };
        for (const auto &d: l.as_list()->vals)
            dl.emplace_back(d.as_data());
        return { alloc, data::constr(alloc, c.as_int(), std::move(dl)) };
    }

    value map_data(allocator &alloc, const value &m)
    {
        data::map_type dm { alloc };
        for (const auto &c: m.as_list()->vals) {
            const auto &p = c.as_pair();
            dm.emplace_back(data_pair { alloc, data { p.first.as_data() }, data { p.second.as_data() } });
        }
        return { alloc, data::map(alloc, std::move(dm)) };
    }

    value list_data(allocator &alloc, const value &l)
    {
        data::list_type dl { alloc };
        for (const auto &d: l.as_list()->vals)
            dl.emplace_back(d.as_data());
        return { alloc, data::list(alloc, std::move(dl)) };
    }

    value i_data(allocator &alloc, const value &i)
    {
        return { alloc, data::bint(alloc, bint_type { i.as_int() } ) };
    }

    value b_data(allocator &alloc, const value &b)
    {
        return { alloc, data::bstr(alloc, *b.as_bstr()) };
    }

    value un_constr_data(allocator &alloc, const value &t)
    {
        if (const auto &d = t.as_data(); std::holds_alternative<data_constr>(*d)) {
            const auto &c = std::get<data_constr>(*d);
            constant_list::list_type cl { alloc };
            for (const auto &d: c->second)
                cl.emplace_back(alloc, d);
            return { alloc, constant { alloc, constant_pair { alloc, constant { alloc, bint_type { alloc, c->first } },
                constant { alloc, constant_list { alloc, constant_type { alloc, type_tag::data }, std::move(cl) } } } } };
        }
        throw error("invalid input for un_constr_data: {}!", t);
    }

    value un_map_data(allocator &alloc, const value &t)
    {
        if (const auto &d = t.as_data(); std::holds_alternative<data::map_type>(*d)) {
            const auto &m = std::get<data::map_type>(*d);
            constant_list::list_type cl { alloc };
            constant_type typ { alloc, type_tag::pair, { constant_type { alloc, type_tag::data }, constant_type { alloc, type_tag::data } } };
            for (const auto &p: m)
                cl.emplace_back(alloc, constant_pair { alloc, constant { alloc, p->first }, constant { alloc, p->second } });
            return value::make_list(alloc, std::move(typ) , std::move(cl));
        }
        throw error("invalid input for un_map_data: {}!", t);
    }

    value un_list_data(allocator &alloc, const value &t) {
        if (const auto &d = t.as_data(); std::holds_alternative<data::list_type>(*d)) {
            const auto &l = std::get<data::list_type>(*d);
            constant_list::list_type cl { alloc };
            for (const auto &d: l)
                cl.emplace_back(alloc, d);
            return value::make_list(alloc, constant_type { alloc, type_tag::data }, std::move(cl));
        }
        throw error("invalid input for un_list_data: {}!", t);
    }

    value un_i_data(allocator &alloc, const value &t)
    {
        if (const auto &d = t.as_data(); std::holds_alternative<data::int_type>(*d))
            return { alloc, std::get<data::int_type>(*d) };
        throw error("invalid input for un_i_data: {}!", t);
    }

    value un_b_data(allocator &alloc, const value &t) {
        if (const auto &d = t.as_data(); std::holds_alternative<data::bstr_type>(*d))
            return { alloc, *std::get<data::bstr_type>(*d) };
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
        constant_type::list_type nested { alloc };
        nested.emplace_back(alloc, type_tag::data);
        nested.emplace_back(alloc, type_tag::data);
        return value::make_list(alloc, constant_type { alloc, type_tag::pair, std::move(nested) });
    }

    value serialize_data(allocator &alloc, const value &d)
    {
        return { alloc, d.as_data().as_cbor(alloc) };
    }

    value verify_ecdsa_secp_256k1_signature(allocator &alloc, const value &vk, const value &msg, const value &sig)
    {
        return value::boolean(alloc, crypto::secp256k1::ecdsa::verify(*sig.as_bstr(), *vk.as_bstr(), *msg.as_bstr()));
    }

    value verify_schnorr_secp_256k1_signature(allocator &alloc, const value &vk, const value &msg, const value &sig)
    {
        return value::boolean(alloc, crypto::secp256k1::schnorr::verify(*sig.as_bstr(), *vk.as_bstr(), *msg.as_bstr()));
    }

    value integer_to_byte_string(allocator &alloc, const value &msb_t, const value &w_t, const value &val)
    {
        static cpp_int max_val { boost::multiprecision::pow(cpp_int { 2 }, 65536) };
        const auto msb = msb_t.as_bool();
        const auto w = static_cast<size_t>(*w_t.as_int());
        const auto &v = val.as_int();
        if (*v < 0) [[unlikely]]
            throw error("integer_to_byte_string requires non-negative integers but got: {}", v);
        if (*v >= max_val) [[unlikely]]
            throw error("integer_to_byte_string allows only values less than 2^65536 but got: {}", v);
        std::pmr::vector<uint8_t> bytes { alloc.resource() };
        if (*v > 0) [[likely]]
            boost::multiprecision::export_bits(*val.as_int(), std::back_inserter(bytes), 8, msb);
        if (w) {
            if (w > 8192)
                throw error("maximum allowed width is 8192 but got {}!", w);
            if (bytes.size() > w) [[unlikely]]
                throw error("expected {} bytes but got {}", bytes.size(), w);
            if (bytes.size() < w) {
                const auto orig_size = bytes.size();
                const auto padding_size = w - orig_size;
                bytes.resize(w); // fills the new elements with 0, so nothing to do in the lsb case
                if (msb) {
                    // do in reverse to not override the data before it has been copied
                    for (int64_t i = orig_size - 1; i >= 0; --i)
                        bytes[i + padding_size] = bytes[i];
                    std::fill(bytes.begin(), bytes.begin() + padding_size, 0);
                }
            }
        }
        return { alloc, std::move(bytes) };
    }

    value byte_string_to_integer(allocator &alloc, const value &msb_t, const value &b)
    {
        const auto msb = msb_t.as_bool();
        const auto &bytes = b.as_bstr();
        bint_type::value_type val;
        if (!bytes->empty()) [[likely]]
            boost::multiprecision::import_bits(val, bytes->begin(), bytes->end(), 8, msb);
        return { alloc, bint_type { alloc, std::move(val) } };
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
        cpp_int k { *k_t.as_int() % scalar_period };
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
        if (dst->size() > 255) [[unlikely]]
            throw error("dst must be less than 256 bytes but got {}!", dst->size());
        blst_p1 out;
        blst_hash_to_g1(&out, msg->data(), msg->size(), dst->data(), dst->size());
        return { alloc, out };
    }

    value bls12_381_g1_compress(allocator &alloc, const value &v)
    {
        return { alloc, bls_g1_compress(alloc, v.as_bls_g1()) };
    }

    value bls12_381_g1_uncompress(allocator &alloc, const value &v)
    {
        return { alloc, bls_g1_decompress(*v.as_bstr()).val };
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
        if (dst->size() > 255) [[unlikely]]
            throw error("dst must be less than 256 bytes but got {}!", dst->size());
        blst_p2 out;
        blst_hash_to_g2(&out, msg->data(), msg->size(), dst->data(), dst->size());
        return { alloc, out };
    }

    value bls12_381_g2_compress(allocator &alloc, const value &v)
    {
        return { alloc, bls_g2_compress(alloc, v.as_bls_g2()) };
    }

    value bls12_381_g2_uncompress(allocator &alloc, const value &v)
    {
        return { alloc, bls_g2_decompress(*v.as_bstr()).val };
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

    static void init_builtin_map(builtin_map &m)
    {
        m.try_emplace(builtin_tag::add_integer, 2, add_integer, "addInteger");
        m.try_emplace(builtin_tag::subtract_integer, 2, subtract_integer, "subtractInteger");
        m.try_emplace(builtin_tag::multiply_integer, 2, multiply_integer, "multiplyInteger");
        m.try_emplace(builtin_tag::divide_integer, 2, divide_integer, "divideInteger");
        m.try_emplace(builtin_tag::quotient_integer, 2, quotient_integer, "quotientInteger");
        m.try_emplace(builtin_tag::remainder_integer, 2, remainder_integer, "remainderInteger");
        m.try_emplace(builtin_tag::mod_integer, 2, mod_integer, "modInteger");
        m.try_emplace(builtin_tag::equals_integer, 2, equals_integer, "equalsInteger");
        m.try_emplace(builtin_tag::less_than_integer, 2, less_than_integer, "lessThanInteger");
        m.try_emplace(builtin_tag::less_than_equals_integer, 2, less_than_equals_integer, "lessThanEqualsInteger");
        m.try_emplace(builtin_tag::append_byte_string, 2, append_byte_string,  "appendByteString");
        m.try_emplace(builtin_tag::cons_byte_string, 2, cons_byte_string,  "consByteString");
        m.try_emplace(builtin_tag::slice_byte_string, 3, slice_byte_string,  "sliceByteString");
        m.try_emplace(builtin_tag::length_of_byte_string, 1, length_of_byte_string,  "lengthOfByteString");
        m.try_emplace(builtin_tag::index_byte_string, 2, index_byte_string, "indexByteString");
        m.try_emplace(builtin_tag::equals_byte_string, 2, equals_byte_string, "equalsByteString");
        m.try_emplace(builtin_tag::less_than_byte_string, 2, less_than_byte_string, "lessThanByteString");
        m.try_emplace(builtin_tag::less_than_equals_byte_string, 2, less_than_equals_byte_string, "lessThanEqualsByteString");
        m.try_emplace(builtin_tag::sha2_256, 1, sha2_256, "sha2_256");
        m.try_emplace(builtin_tag::sha3_256, 1, sha3_256, "sha3_256");
        m.try_emplace(builtin_tag::blake2b_256, 1, blake2b_256, "blake2b_256");
        m.try_emplace(builtin_tag::verify_ed25519_signature, 3, verify_ed25519_signature, "verifyEd25519Signature");
        m.try_emplace(builtin_tag::append_string, 2, append_string, "appendString");
        m.try_emplace(builtin_tag::equals_string, 2, equals_string, "equalsString");
        m.try_emplace(builtin_tag::encode_utf8, 1, encode_utf8, "encodeUtf8");
        m.try_emplace(builtin_tag::decode_utf8, 1, decode_utf8, "decodeUtf8");
        m.try_emplace(builtin_tag::if_then_else, 3, if_then_else, "ifThenElse", 1);
        m.try_emplace(builtin_tag::choose_unit, 2, choose_unit, "chooseUnit", 1);
        m.try_emplace(builtin_tag::trace, 2, trace, "trace", 1);
        m.try_emplace(builtin_tag::fst_pair, 1, fst_pair, "fstPair", 2);
        m.try_emplace(builtin_tag::snd_pair, 1, snd_pair, "sndPair", 2);
        m.try_emplace(builtin_tag::choose_list, 3, choose_list, "chooseList", 2);
        m.try_emplace(builtin_tag::mk_cons, 2, mk_cons, "mkCons", 1);
        m.try_emplace(builtin_tag::head_list, 1, head_list, "headList", 1);
        m.try_emplace(builtin_tag::tail_list, 1, tail_list, "tailList", 1);
        m.try_emplace(builtin_tag::null_list, 1, null_list, "nullList", 1);
        m.try_emplace(builtin_tag::choose_data, 6, choose_data, "chooseData", 1);
        m.try_emplace(builtin_tag::constr_data, 2, constr_data, "constrData");
        m.try_emplace(builtin_tag::map_data, 1, map_data, "mapData");
        m.try_emplace(builtin_tag::list_data, 1, list_data, "listData");
        m.try_emplace(builtin_tag::i_data, 1, i_data, "iData");
        m.try_emplace(builtin_tag::b_data, 1, b_data, "bData");
        m.try_emplace(builtin_tag::un_constr_data, 1, un_constr_data, "unConstrData");
        m.try_emplace(builtin_tag::un_map_data, 1, un_map_data, "unMapData");
        m.try_emplace(builtin_tag::un_list_data, 1, un_list_data, "unListData");
        m.try_emplace(builtin_tag::un_i_data, 1, un_i_data, "unIData");
        m.try_emplace(builtin_tag::un_b_data, 1, un_b_data, "unBData");
        m.try_emplace(builtin_tag::equals_data, 2, equals_data, "equalsData");
        m.try_emplace(builtin_tag::mk_pair_data, 2, mk_pair_data, "mkPairData");
        m.try_emplace(builtin_tag::mk_nil_data, 1, mk_nil_data, "mkNilData");
        m.try_emplace(builtin_tag::mk_nil_pair_data, 1, mk_nil_pair_data, "mkNilPairData");
        m.try_emplace(builtin_tag::serialise_data, 1, serialize_data, "serialiseData", 0, 2);
        m.try_emplace(builtin_tag::verify_ecdsa_secp_256k1_signature, 3, verify_ecdsa_secp_256k1_signature, "verifyEcdsaSecp256k1Signature", 0, 3);
        m.try_emplace(builtin_tag::verify_schnorr_secp_256k1_signature, 3, verify_schnorr_secp_256k1_signature, "verifySchnorrSecp256k1Signature", 0, 3);
        m.try_emplace(builtin_tag::blake2b_224, 1, blake2b_224, "blake2b_224", 0, 4);
        m.try_emplace(builtin_tag::keccak_256, 1, keccak_256, "keccak_256", 0, 4);
        m.try_emplace(builtin_tag::integer_to_byte_string, 3, integer_to_byte_string, "integerToByteString", 0, 4);
        m.try_emplace(builtin_tag::byte_string_to_integer, 2, byte_string_to_integer, "byteStringToInteger", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g1_add, 2, bls12_381_g1_add, "bls12_381_G1_add", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g1_neg, 1, bls12_381_g1_neg, "bls12_381_G1_neg", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g1_scalar_mul, 2, bls12_381_g1_scalar_mul, "bls12_381_G1_scalarMul", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g1_equal, 2, bls12_381_g1_equal, "bls12_381_G1_equal", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g1_hash_to_group, 2, bls12_381_g1_hash_to_group, "bls12_381_G1_hashToGroup", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g1_compress, 1, bls12_381_g1_compress, "bls12_381_G1_compress", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g1_uncompress, 1, bls12_381_g1_uncompress, "bls12_381_G1_uncompress", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g2_add, 2, bls12_381_g2_add, "bls12_381_G2_add", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g2_neg, 1, bls12_381_g2_neg, "bls12_381_G2_neg", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g2_scalar_mul, 2, bls12_381_g2_scalar_mul, "bls12_381_G2_scalarMul", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g2_equal, 2, bls12_381_g2_equal, "bls12_381_G2_equal", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g2_hash_to_group, 2, bls12_381_g2_hash_to_group, "bls12_381_G2_hashToGroup", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g2_compress, 1, bls12_381_g2_compress, "bls12_381_G2_compress", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_g2_uncompress, 1, bls12_381_g2_uncompress, "bls12_381_G2_uncompress", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_miller_loop, 2, bls12_381_miller_loop, "bls12_381_millerLoop", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_mul_ml_result, 2, bls12_381_mul_ml_result, "bls12_381_mulMlResult", 0, 4);
        m.try_emplace(builtin_tag::bls12_381_final_verify, 2, bls12_381_final_verify, "bls12_381_finalVerify", 0, 4);
    }

    static builtin_map make_semantics_v1()
    {
        builtin_map m {};
        init_builtin_map(m);
        return m;
    }

    const builtin_map &semantics_v1()
    {
        static builtin_map m { make_semantics_v1() };
        return m;
    }

    static builtin_map make_semantics_v2()
    {
        builtin_map m {};
        init_builtin_map(m);
        m.at(builtin_tag::cons_byte_string).func = cons_byte_string_v2;
        return m;
    }

    const builtin_map &semantics_v2()
    {
        static builtin_map m { make_semantics_v2() };
        return m;
    }
}