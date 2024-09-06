/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_BUILTINS_HPP
#define DAEDALUS_TURBO_PLUTUS_BUILTINS_HPP

#include <functional>
#include <dt/cbor-encoder.hpp>
#include <dt/plutus/types.hpp>
#include <dt/blake2b.hpp>
#include <dt/ed25519.hpp>
#include <dt/sha2.hpp>
#include <dt/sha3.hpp>

namespace daedalus_turbo::plutus {
    struct builtin_one_arg: std::function<term(const term &)> {
        using std::function<term(const term &)>::function;
    };
    struct builtin_two_arg: std::function<term(const term &, const term &)> {
        using std::function<term(const term &, const term &)>::function;
    };
    struct builtin_three_arg: std::function<term(const term &, const term &, const term &)> {
        using std::function<term(const term &, const term &, const term &)>::function;
    };
    struct builtin_six_arg: std::function<term(const term &, const term &, const term &, const term &, const term &, const term &)> {
        using std::function<term(const term &, const term &, const term &, const term &, const term &, const term &)>::function;
    };

    struct builtins {
        static term add_integer(const term &x, const term &y)
        {
            return term::make_int(x.as_int() + y.as_int());
        }

        static term subtract_integer(const term &x, const term &y)
        {
            return term::make_int(x.as_int() - y.as_int());
        }

        static term multiply_integer(const term &x, const term &y)
        {
            return term::make_int(x.as_int() * y.as_int());
        }

        static term divide_integer(const term &x, const term &y)
        {
            const auto &y_val = y.as_int();
            if (y_val == 0) [[unlikely]]
                throw error("division by zero is not allowed!");
            const auto &x_val = x.as_int();
            cpp_int div, rem;
            boost::multiprecision::divide_qr(x_val, y_val, div, rem);
            if (rem != 0 && ((x_val < 0) ^ (y_val < 0)))
                --div;
            return term::make_int(div);
        }

        static term mod_integer(const term &x, const term &y)
        {
            const auto &y_val = y.as_int();
            if (y_val == 0) [[unlikely]]
                throw error("division by zero is not allowed!");
            const auto &x_val = x.as_int();
            return term::make_int(((x_val % y_val) + y_val) % y_val);
        }

        static term quotient_integer(const term &x, const term &y)
        {
            const auto &y_val = y.as_int();
            if (y_val == 0) [[unlikely]]
                throw error("division by zero is not allowed!");
            return term::make_int(x.as_int() / y_val);
        }

        static term remainder_integer(const term &x, const term &y)
        {
            const auto &y_val = y.as_int();
            if (y_val == 0) [[unlikely]]
                throw error("division by zero is not allowed!");
            return term::make_int(x.as_int() % y_val);
        }

        static term equals_integer(const term &x, const term &y)
        {
            return term::make_bool(x.as_int() == y.as_int());
        }

        static term less_than_integer(const term &x, const term &y)
        {
            return term::make_bool(x.as_int() < y.as_int());
        }

        static term less_than_equals_integer(const term &x, const term &y)
        {
            return term::make_bool(x.as_int() <= y.as_int());
        }

        static term append_byte_string(const term &x, const term &y)
        {
            uint8_vector res {};
            const auto &x_val = x.as_bstr();
            const auto &y_val = y.as_bstr();
            res.reserve(x_val.size() + y_val.size());
            res << x_val << y_val;
            return term::make_bstr(std::move(res));
        }

        static term cons_byte_string(const term &c, const term &s)
        {
            const auto &c_val = c.as_int();
            const auto &s_val = s.as_bstr();
            uint8_vector res {};
            res.reserve(1 + s_val.size());
            if (c_val < 0 || c_val > 255)
                throw error("cons_byte_string's first parameter must be between 0 and 255: {}!", c_val);
            res << static_cast<uint8_t>(c_val) << s_val;
            return term::make_bstr(std::move(res));
        }

        static term slice_byte_string(const term &pos_raw, const term &sz_raw, const term &s_raw)
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
            return term::make_bstr(s.span().subspan(static_cast<size_t>(pos), static_cast<size_t>(sz)));
        }

        static term length_of_byte_string(const term &s)
        {
            return term::make_int(s.as_bstr().size());
        }

        static term index_byte_string(const term &s_t, const term &i_t)
        {
            const auto &s = s_t.as_bstr();
            const auto &i_bi = i_t.as_int();
            if (i_bi < 0 || i_bi >= std::numeric_limits<size_t>::max()) [[unlikely]]
                throw error("byte_string index out of the allowed range: {}", i_bi);
            const auto i = static_cast<size_t>(i_bi);
            if (i >= s.size()) [[unlikely]]
                throw error("byte_string index too big: {}", i);
            return term::make_int(s[i]);
        }

        static term equals_byte_string(const term &s1, const term &s2)
        {
            return term::make_bool(s1.as_bstr() == s2.as_bstr());
        }

        static term less_than_byte_string(const term &s1, const term &s2)
        {
            return term::make_bool(s1.as_bstr() < s2.as_bstr());
        }

        static term less_than_equals_byte_string(const term &s1_t, const term &s2_t)
        {
            const auto &s1 = s1_t.as_bstr();
            const auto &s2 = s2_t.as_bstr();
            return term::make_bool(s1 < s2 || s1 == s2);
        }

        static term append_string(const term &s1, const term &s2)
        {
            std::string res = s1.as_str();
            res += s2.as_str();
            return term::make_str(std::move(res));
        }

        static term equals_string(const term &s1, const term &s2)
        {
            return term::make_bool(s1.as_str() == s2.as_str());
        }

        static term encode_utf8(const term &s)
        {
            return term::make_bstr(s.as_str());
        }

        static term decode_utf8(const term &b)
        {
            // must throw on invalid utf8
            return term::make_str(b.as_bstr().str());
        }

        static const term &if_then_else(const term &condition, const term &yes, const term &no)
        {
            if (const auto cond = condition.as_bool(); cond)
                return yes;
            return no;
        }

        static term sha2_256(const term &s)
        {
            return term::make_bstr(sha2::digest(s.as_bstr()));
        }

        static term sha3_256(const term &s)
        {
            return term::make_bstr(sha3::digest(s.as_bstr()));
        }

        static term blake2b_256(const term &s)
        {
            return term::make_bstr(blake2b<blake2b_256_hash>(s.as_bstr()));
        }

        static term verify_ed25519_signature(const term &sig, const term &msg, const term &vk)
        {
            return term::make_bool(ed25519::verify(sig.as_bstr(), vk.as_bstr(), msg.as_bstr()));
        }

        static const term &choose_unit(const term &u, const term &v)
        {
            u.must_be(type_tag::unit);
            return v;
        }

        static term fst_pair(const term &p)
        {
            auto val = p.as_pair().at(0);
            return term::make_constant(std::move(val));
        }

        static term snd_pair(const term &p)
        {
            auto val = p.as_pair().at(1);
            return term::make_constant(std::move(val));
        }

        static const term &choose_list(const term &a, const term &t1, const term &t2)
        {
            if (const auto &vals = a.as_list(); !vals.empty())
                return t2;
            return t1;
        }

        static term mk_cons(const term &x, const term &l)
        {
            constant_list vals {};
            vals.emplace_back(x.as_constant());
            const auto &l_vals = l.as_list();
            std::copy(l_vals.begin(), l_vals.end(), std::back_inserter(vals));
            return term::make_list(std::move(vals));
        }

        static term head_list(const term &l)
        {
            auto head = l.as_list().at(0);
            return term::make_constant(std::move(head));
        }

        static term tail_list(const term &l)
        {
            const auto &l_vals = l.as_list();
            if (l_vals.empty()) [[unlikely]]
                throw error("calling tail_list on an empty list!");
            constant_list tail {};
            std::copy(l_vals.begin() + 1, l_vals.end(), std::back_inserter(tail));
            return term::make_list(constant_type { l.as_constant().typ.nested.at(0) }, std::move(tail));
        }

        static term null_list(const term &l)
        {
            return term::make_bool(l.as_list().empty());
        }

        static const term &trace(const term &s, const term &t)
        {
            logger::debug("plutus builtins::trace: {}", s);
            return t;
        }

        static const term &choose_data(const term &d, const term &c, const term &m, const term &l, const term &i, const term &b)
        {
            const auto item = cbor::parse(d.as_data());
            switch (item.type) {
                case CBOR_TAG: {
                    const auto &tag = item.tag();
                    if (tag.first == 2 || tag.first == 3)
                        return i;
                    return c;
                }
                case CBOR_MAP: return m;
                case CBOR_ARRAY: return l;
                case CBOR_BYTES: return b;
                case CBOR_UINT: return i;
                case CBOR_NINT: return i;
                default: throw error("unsupported CBOR type {}!", item.type);
            }
        }

        static term constr_data(const term &c, const term &l)
        {
            cbor::encoder enc {};
            const auto &id = c.as_int();
            if (id >= 0 && id <= 6) {
                enc.tag(static_cast<uint64_t>(id) + 121ULL);
            } else if (id >= 7 && id <= 127) {
                enc.tag(static_cast<uint64_t>(id - 7) + 1'280ULL);
            } else {
                enc.tag(102);
                enc.array(2);
                _to_cbor(enc, c.as_constant());
            }
            _to_cbor(enc, l.as_constant());
            return term::make_data(std::move(enc.cbor()));
        }

        static term map_data(const term &m)
        {
            cbor::encoder enc {};
            const auto &vals = m.as_list();
            enc.map(vals.size());
            for (const auto &pair: vals) {
                if (pair.typ.typ != type_tag::pair) [[unlikely]]
                    throw error("map must consist of pairs but got {}!", pair.typ.typ);
                const auto &p_vals = std::get<constant_list>(pair.val);
                _to_cbor(enc, p_vals.at(0));
                _to_cbor(enc, p_vals.at(1));
            }
            return term::make_data(std::move(enc.cbor()));
        }

        static term list_data(const term &m)
        {
            cbor::encoder enc {};
            const auto &vals = m.as_list();
            enc.array(vals.size());
            for (const auto &vc: vals) {
                _to_cbor(enc, vc);
            }
            return term::make_data(std::move(enc.cbor()));
        }

        static term i_data(const term &t)
        {
            cbor::encoder enc {};
            _to_cbor_int(enc, t.as_int());
            return term::make_data(std::move(enc.cbor()));
        }

        static term b_data(const term &t)
        {
            cbor::encoder enc {};
            _to_cbor_bstr(enc, t.as_bstr());
            return term::make_data(std::move(enc.cbor()));
        }

        static term un_constr_data(const term &t)
        {

            if (auto res = _from_cbor(t.as_data()); res.typ.typ == type_tag::pair) [[likely]]
                return term::make_constant(std::move(res));
            throw error("invalid input for un_constr_data!");
        }

        static term un_map_data(const term &t)
        {
            if (auto res = _from_cbor(t.as_data()); res.typ.typ == type_tag::list) [[likely]]
                return term::make_constant(std::move(res));
            throw error("invalid input for un_map_data!");
        }

        static term un_list_data(const term &t)
        {
            if (auto res = _from_cbor(t.as_data()); res.typ.typ == type_tag::list) [[likely]]
                return term::make_constant(std::move(res));
            throw error("invalid input for un_list_data!");
        }

        static term un_i_data(const term &t)
        {
            if (auto res = _from_cbor(t.as_data()); res.typ.typ == type_tag::integer) [[likely]]
                return term::make_constant(std::move(res));
            throw error("invalid input for un_i_data!");
        }

        static term un_b_data(const term &t)
        {
            if (auto res = _from_cbor(t.as_data()); res.typ.typ == type_tag::bytestring) [[likely]]
                return term::make_constant(std::move(res));
            throw error("invalid input for un_b_data!");
        }

        static term equals_data(const term &d1, const term &d2)
        {
            return term::make_bool(d1.as_data() == d2.as_data());
        }

        static term mk_pair_data(const term &fst, const term &snd)
        {
            return term::make_pair(constant::make_data(fst.as_data()), constant::make_data(snd.as_data()));
        }

        static term mk_nil_data(const term &)
        {
            return term::make_list(constant_type { type_tag::data });
        }

        static term mk_nil_pair_data(const term &)
        {
            constant_type_list nested {};
            nested.emplace_back(type_tag::data);
            nested.emplace_back(type_tag::data);
            return term::make_list(constant_type { type_tag::pair, std::move(nested) });
        }

        static term serialize_data(const term &d)
        {
            return term::make_bstr(d.as_data());
        }

        static cpp_int _from_cbor_bigint(const buffer &data)
        {
            if (data.size() > 64) [[unlikely]]
                throw error("integers requiring more than 64 bytes for representation are not supported!");
            cpp_int val {};
            size_t base_idx = 0;
            for (uint8_t b: data) {
                val |= cpp_int { b & 0x7F } << base_idx;
                base_idx += 7;
            }
            return val;
        }
    private:
        static constant _from_cbor_tag(const cbor_value &item)
        {
            switch (const auto &tag = item.tag(); tag.first) {
                case 2:
                    return constant::make_int(_from_cbor_bigint(tag.second->buf()));
                case 3:
                    return constant::make_int((_from_cbor_bigint(tag.second->buf()) + 1) * -1);
                default: {
                    cpp_int id;
                    const cbor_value *val;
                    if (tag.first >= 121 && tag.first < 128) {
                        id = tag.first - 121;
                        val = tag.second.get();
                    } else if (tag.first >= 1280 && tag.first < 1280 + 128) {
                        id = tag.first - 1280 + 7;
                        val = tag.second.get();
                    } else {
                        id = tag.second->array().at(0).uint();
                        val = &tag.second->array().at(1);
                    }
                    constant_list vals {};
                    for (const auto &lv: val->array()) {
                        vals.emplace_back(_from_cbor(lv));
                    }
                    if (!vals.empty())
                        return constant::make_pair(constant::make_int(id), constant::make_list(std::move(vals)));
                    return constant::make_pair(constant::make_int(id), constant::make_list(constant_type { type_tag::data }));
                }
            }
        }

        static constant _from_cbor_list(const cbor_value &item)
        {
            constant_list vals {};
            for (const auto &lv: item.array()) {
                vals.emplace_back(constant::make_data(lv.data_buf()));
            }
            return constant::make_list(constant_type { type_tag::data }, std::move(vals));
        }

        static constant _from_cbor_map(const cbor_value &item)
        {
            constant_list vals {};
            for (const auto &[key, val]: item.map()) {
                vals.emplace_back(constant::make_pair(constant::make_data(key.data_buf()), constant::make_data(val.data_buf())));
            }
            constant_type nested_type { type_tag::pair };
            nested_type.nested.emplace_back(type_tag::data);
            nested_type.nested.emplace_back(type_tag::data);
            return constant::make_list(std::move(nested_type), std::move(vals));
        }

        static constant _from_cbor_bstr(const cbor_value &item)
        {
            const auto buf = item.span();
            if (buf.size() > 64) [[unlikely]]
                throw error("bytestrings must be limited to 64 bytes but got {}!", buf.size());
            return constant::make_bstr(buf);
        }

        static constant _from_cbor_uint(const cbor_value &item)
        {
            return constant::make_int(item.uint());
        }

        static constant _from_cbor_nint(const cbor_value &item)
        {
            cpp_int val { item.nint_raw() };
            val += 1;
            val *= -1;
            return constant::make_int(std::move(val));
        }

        static constant _from_cbor(const cbor_value &item)
        {
            switch (item.type) {
                case CBOR_TAG: return _from_cbor_tag(item);
                case CBOR_ARRAY: return _from_cbor_list(item);
                case CBOR_MAP: return _from_cbor_map(item);
                case CBOR_BYTES: return _from_cbor_bstr(item);
                case CBOR_UINT: return _from_cbor_uint(item);
                case CBOR_NINT: return _from_cbor_nint(item);
                default: throw error("unsupported CBOR type {}!", item.type);
            }
        }

        static constant _from_cbor(const buffer &data)
        {
            return _from_cbor(cbor::parse(data));
        }

        static void _to_cbor_int(cbor::encoder &enc, const cpp_int &val)
        {
            static cpp_int neg_max = (cpp_int { 1 } << 64) * -1;
            if (val >= 0 && val <= std::numeric_limits<uint64_t>::max()) {
                enc.uint(static_cast<uint64_t>(val));
            } else if (val < 0 && val >= neg_max) {
                enc.nint(static_cast<uint64_t>(cpp_int { val * -1 - 1 }));
            } else {
                const bool negative = val < 0;
                cpp_int tmp { val };
                if (negative) {
                    tmp *= -1;
                    tmp -= 1;
                }
                uint8_vector data {};
                for (;;) {
                    uint8_t val_bits = static_cast<uint8_t>(tmp & 0x7F);
                    tmp >>= 7;
                    if (tmp != 0)
                        val_bits |= 0x80;
                    data.emplace_back(val_bits);
                    if (tmp == 0)
                        break;
                    if (data.size() >= 64)
                        throw error("all integers must fit into a 64-byte representation!");
                }
                enc.tag(negative ? 3 : 2);
                enc.bytes(data);
            }
        }

        static void _to_cbor_bstr(cbor::encoder &enc, const buffer &data)
        {
            if (data.size() > 64)  [[unlikely]]
                throw error("bytestrings over 64 bytes are not allowed!");
            enc.bytes(data);
        }

        static void _to_cbor(cbor::encoder &enc, const constant &c, const size_t level=0)
        {
            static constexpr size_t max_nesting_level = 1024;
            if (level >= max_nesting_level) [[unlikely]]
                throw error("only 1024 levels of CBOR nesting are supported!");
            switch (c.typ.typ) {
                case type_tag::data:
                    enc.raw_cbor(std::get<uint8_vector>(c.val));
                    break;
                case type_tag::list: {
                    const auto &vals = std::get<constant_list>(c.val);
                    enc.array(vals.size());
                    for (const auto &vc: vals)
                        _to_cbor(enc, vc, level + 1);
                    break;
                }
                case type_tag::bytestring: return _to_cbor_bstr(enc, std::get<uint8_vector>(c.val));
                case type_tag::integer: return _to_cbor_int(enc, std::get<cpp_int>(c.val));
                default:
                    throw error("CBOR encoding type {} is not supported!", c.typ.typ);
            }
        }
    };
}

#endif //DAEDALUS_TURBO_PLUTUS_BUILTINS_HPP