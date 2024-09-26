/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <utfcpp/utf8.h>
#include <dt/plutus/types.hpp>
#include <dt/plutus/builtins.hpp>

namespace daedalus_turbo::plutus {
    struct builtin_info {
        size_t num_args;
        builtin_any func;
        std::string name;
        size_t polymorphic_args = 0;
    };
    using builtin_map = map<builtin_tag, const builtin_info>;

    const builtin_map &known_builtins()
    {
        static builtin_map info_map {};
        if (info_map.empty()) [[unlikely]] {
            info_map.try_emplace(builtin_tag::add_integer, 2, builtins::add_integer, "addInteger");
            info_map.try_emplace(builtin_tag::subtract_integer, 2, builtins::subtract_integer, "subtractInteger");
            info_map.try_emplace(builtin_tag::multiply_integer, 2, builtins::multiply_integer, "multiplyInteger");
            info_map.try_emplace(builtin_tag::divide_integer, 2, builtins::divide_integer, "divideInteger");
            info_map.try_emplace(builtin_tag::quotient_integer, 2, builtins::quotient_integer, "quotientInteger");
            info_map.try_emplace(builtin_tag::remainder_integer, 2, builtins::remainder_integer, "remainderInteger");
            info_map.try_emplace(builtin_tag::mod_integer, 2, builtins::mod_integer, "modInteger");
            info_map.try_emplace(builtin_tag::equals_integer, 2, builtins::equals_integer, "equalsInteger");
            info_map.try_emplace(builtin_tag::less_than_integer, 2, builtins::less_than_integer, "lessThanInteger");
            info_map.try_emplace(builtin_tag::less_than_equals_integer, 2, builtins::less_than_equals_integer, "lessThanEqualsInteger");
            info_map.try_emplace(builtin_tag::append_byte_string, 2, builtins::append_byte_string,  "appendByteString");
            info_map.try_emplace(builtin_tag::cons_byte_string, 2, builtins::cons_byte_string,  "consByteString");
            info_map.try_emplace(builtin_tag::slice_byte_string, 3, builtins::slice_byte_string,  "sliceByteString");
            info_map.try_emplace(builtin_tag::length_of_byte_string, 1, builtins::length_of_byte_string,  "lengthOfByteString");
            info_map.try_emplace(builtin_tag::index_byte_string, 2, builtins::index_byte_string, "indexByteString");
            info_map.try_emplace(builtin_tag::equals_byte_string, 2, builtins::equals_byte_string, "equalsByteString");
            info_map.try_emplace(builtin_tag::less_than_byte_string, 2, builtins::less_than_byte_string, "lessThanByteString");
            info_map.try_emplace(builtin_tag::less_than_equals_byte_string, 2, builtins::less_than_equals_byte_string, "lessThanEqualsByteString");
            info_map.try_emplace(builtin_tag::sha2_256, 1, builtins::sha2_256, "sha2_256");
            info_map.try_emplace(builtin_tag::sha3_256, 1, builtins::sha3_256, "sha3_256");
            info_map.try_emplace(builtin_tag::blake2b_256, 1, builtins::blake2b_256, "blake2b_256");
            info_map.try_emplace(builtin_tag::verify_ed25519_signature, 3, builtins::verify_ed25519_signature, "verifyEd25519Signature");
            info_map.try_emplace(builtin_tag::append_string, 2, builtins::append_string, "appendString");
            info_map.try_emplace(builtin_tag::equals_string, 2, builtins::equals_string, "equalsString");
            info_map.try_emplace(builtin_tag::encode_utf8, 1, builtins::encode_utf8, "encodeUtf8");
            info_map.try_emplace(builtin_tag::decode_utf8, 1, builtins::decode_utf8, "decodeUtf8");
            info_map.try_emplace(builtin_tag::if_then_else, 3, builtins::if_then_else, "ifThenElse", 1);
            info_map.try_emplace(builtin_tag::choose_unit, 2, builtins::choose_unit, "chooseUnit", 1);
            info_map.try_emplace(builtin_tag::trace, 2, builtins::trace, "trace", 1);
            info_map.try_emplace(builtin_tag::fst_pair, 1, builtins::fst_pair, "fstPair", 2);
            info_map.try_emplace(builtin_tag::snd_pair, 1, builtins::snd_pair, "sndPair", 2);
            info_map.try_emplace(builtin_tag::choose_list, 3, builtins::choose_list, "chooseList", 2);
            info_map.try_emplace(builtin_tag::mk_cons, 2, builtins::mk_cons, "mkCons", 1);
            info_map.try_emplace(builtin_tag::head_list, 1, builtins::head_list, "headList", 1);
            info_map.try_emplace(builtin_tag::tail_list, 1, builtins::tail_list, "tailList", 1);
            info_map.try_emplace(builtin_tag::null_list, 1, builtins::null_list, "nullList", 1);
            info_map.try_emplace(builtin_tag::choose_data, 6, builtins::choose_data, "chooseData", 1);
            info_map.try_emplace(builtin_tag::constr_data, 2, builtins::constr_data, "constrData");
            info_map.try_emplace(builtin_tag::map_data, 1, builtins::map_data, "mapData");
            info_map.try_emplace(builtin_tag::list_data, 1, builtins::list_data, "listData");
            info_map.try_emplace(builtin_tag::i_data, 1, builtins::i_data, "iData");
            info_map.try_emplace(builtin_tag::b_data, 1, builtins::b_data, "bData");
            info_map.try_emplace(builtin_tag::un_constr_data, 1, builtins::un_constr_data, "unConstrData");
            info_map.try_emplace(builtin_tag::un_map_data, 1, builtins::un_map_data, "unMapData");
            info_map.try_emplace(builtin_tag::un_list_data, 1, builtins::un_list_data, "unListData");
            info_map.try_emplace(builtin_tag::un_i_data, 1, builtins::un_i_data, "unIData");
            info_map.try_emplace(builtin_tag::un_b_data, 1, builtins::un_b_data, "unBData");
            info_map.try_emplace(builtin_tag::equals_data, 2, builtins::equals_data, "equalsData");
            info_map.try_emplace(builtin_tag::mk_pair_data, 2, builtins::mk_pair_data, "mkPairData");
            info_map.try_emplace(builtin_tag::mk_nil_data, 1, builtins::mk_nil_data, "mkNilData");
            info_map.try_emplace(builtin_tag::mk_nil_pair_data, 1, builtins::mk_nil_pair_data, "mkNilPairData");
            info_map.try_emplace(builtin_tag::serialise_data, 1, builtins::serialize_data, "serialiseData");
            info_map.try_emplace(builtin_tag::verify_ecdsa_secp_256k1_signature, 3, builtins::verify_ecdsa_secp_256k1_signature, "verifyEcdsaSecp256k1Signature");
            info_map.try_emplace(builtin_tag::verify_schnorr_secp_256k1_signature, 3, builtins::verify_schnorr_secp_256k1_signature, "verifySchnorrSecp256k1Signature");
            info_map.try_emplace(builtin_tag::blake2b_224, 1, builtins::blake2b_224, "blake2b_224");
            info_map.try_emplace(builtin_tag::keccak_256, 1, builtins::keccak_256, "keccak_256");
            info_map.try_emplace(builtin_tag::integer_to_byte_string, 3, builtins::integer_to_byte_string, "integerToByteString");
            info_map.try_emplace(builtin_tag::byte_string_to_integer, 2, builtins::byte_string_to_integer, "byteStringToInteger");
            info_map.try_emplace(builtin_tag::bls12_381_g1_add, 2, builtins::bls12_381_g1_add, "bls12_381_G1_add");
            info_map.try_emplace(builtin_tag::bls12_381_g1_neg, 1, builtins::bls12_381_g1_neg, "bls12_381_G1_neg");
            info_map.try_emplace(builtin_tag::bls12_381_g1_scalar_mul, 2, builtins::bls12_381_g1_scalar_mul, "bls12_381_G1_scalarMul");
            info_map.try_emplace(builtin_tag::bls12_381_g1_equal, 2, builtins::bls12_381_g1_equal, "bls12_381_G1_equal");
            info_map.try_emplace(builtin_tag::bls12_381_g1_hash_to_group, 2, builtins::bls12_381_g1_hash_to_group, "bls12_381_G1_hashToGroup");
            info_map.try_emplace(builtin_tag::bls12_381_g1_compress, 1, builtins::bls12_381_g1_compress, "bls12_381_G1_compress");
            info_map.try_emplace(builtin_tag::bls12_381_g1_uncompress, 1, builtins::bls12_381_g1_uncompress, "bls12_381_G1_uncompress");
            info_map.try_emplace(builtin_tag::bls12_381_g2_add, 2, builtins::bls12_381_g2_add, "bls12_381_G2_add");
            info_map.try_emplace(builtin_tag::bls12_381_g2_neg, 1, builtins::bls12_381_g2_neg, "bls12_381_G2_neg");
            info_map.try_emplace(builtin_tag::bls12_381_g2_scalar_mul, 2, builtins::bls12_381_g2_scalar_mul, "bls12_381_G2_scalarMul");
            info_map.try_emplace(builtin_tag::bls12_381_g2_equal, 2, builtins::bls12_381_g2_equal, "bls12_381_G2_equal");
            info_map.try_emplace(builtin_tag::bls12_381_g2_hash_to_group, 2, builtins::bls12_381_g2_hash_to_group, "bls12_381_G2_hashToGroup");
            info_map.try_emplace(builtin_tag::bls12_381_g2_compress, 1, builtins::bls12_381_g2_compress, "bls12_381_G2_compress");
            info_map.try_emplace(builtin_tag::bls12_381_g2_uncompress, 1, builtins::bls12_381_g2_uncompress, "bls12_381_G2_uncompress");
            info_map.try_emplace(builtin_tag::bls12_381_miller_loop, 2, builtins::bls12_381_miller_loop, "bls12_381_millerLoop");
            info_map.try_emplace(builtin_tag::bls12_381_mul_ml_result, 2, builtins::bls12_381_mul_ml_result, "bls12_381_mulMlResult");
            info_map.try_emplace(builtin_tag::bls12_381_final_verify, 2, builtins::bls12_381_final_verify, "bls12_381_finalVerify");
        }
        return info_map;
    }

    using builtin_name_map = map<std::string, builtin_tag>;
    static const builtin_name_map &builtin_names()
    {
        static builtin_name_map name_map {};
        if (name_map.empty()) [[unlikely]] {
            const auto &info_map = known_builtins();
            for (const auto &[tag, info]: info_map) {
                name_map.try_emplace(info.name, tag);
            }
        }
        return name_map;
    }

    bool builtin_tag_known_name(const std::string &name)
    {
        return builtin_names().contains(name);
    }

    builtin_tag builtin_tag_from_name(const std::string &name)
    {
        const auto &name_map = builtin_names();
        if (const auto it = name_map.find(name); it != name_map.end()) [[likely]]
            return it->second;
        throw error("unknown builtin: {}", name);
    }

    static const builtin_info &_builtin_info(const builtin_tag &tag)
    {
        const auto &info_map = known_builtins();
        if (const auto it = info_map.find(tag); it != info_map.end()) [[likely]] {
            switch (it->second.num_args) {
                case 1:
                    if (!std::holds_alternative<builtin_one_arg>(it->second.func))
                        throw error("internal error: invalid plutus builtin configuration!");
                    break;
                case 2:
                    if (!std::holds_alternative<builtin_two_arg>(it->second.func))
                        throw error("internal error: invalid plutus builtin configuration!");
                    break;
                case 3:
                    if (!std::holds_alternative<builtin_three_arg>(it->second.func))
                        throw error("internal error: invalid plutus builtin configuration!");
                    break;
                case 6:
                    if (!std::holds_alternative<builtin_six_arg>(it->second.func))
                        throw error("internal error: invalid plutus builtin configuration!");
                    break;
                default:
                    throw error("internal error: invalid plutus builtin configuration: num_args: {}!", it->second.num_args);
            }
            return it->second;
        }
        throw error("not implemented: {}", tag);
    }

    size_t t_builtin::num_args() const
    {
        return _builtin_info(tag).num_args;
    }

    builtin_any t_builtin::func() const
    {
        return _builtin_info(tag).func;
    }

    const std::string &t_builtin::name() const
    {
        return _builtin_info(tag).name;
    }

    size_t t_builtin::polymorphic_args() const
    {
        return _builtin_info(tag).polymorphic_args;
    }

    t_builtin t_builtin::from_name(const std::string &name)
    {
        return { builtin_tag_from_name(name) };
    }

    bool t_delay::operator==(const t_delay &o) const
    {
        return expr && o.expr && *expr == *o.expr;
    }

    bool t_constr::operator==(const t_constr &o) const
    {
        if (tag != o.tag || args.size() != o.args.size())
            return false;
        for (size_t i = 0; i < args.size(); i++) {
            if (*args[i] != *o.args[i])
                return false;
        }
        return true;
    }

    bool force::operator==(const force &o) const
    {
        return expr && o.expr && *expr == *o.expr;
    }

    bool t_lambda::operator==(const t_lambda &o) const
    {
        return expr && o.expr && *expr == *o.expr && name == o.name;
    }

    bool apply::operator==(const apply &o) const
    {
        return func && o.func && *func == *o.func && arg && o.arg && *arg == *o.arg;
    }

    constant_pair::constant_pair(constant &&fst, constant &&snd):
        _vals { std::make_shared<value_type>(std::move(fst), std::move(snd)) }
    {
        if (!_vals) [[unlikely]]
            throw error("values must be defined!");
    }

    const constant_pair::value_type &constant_pair::operator*() const
    {
        return *_vals;
    }

    const constant_pair::value_type *constant_pair::operator->() const
    {
        return _vals.get();
    }

    bool constant_pair::operator==(const constant_pair &o) const
    {
        return _vals && o._vals && *_vals == *o._vals;
    }

    bool constant_list::operator==(const constant_list &o) const
    {
        return typ == o.typ && vals == o.vals;
    }

    constant_type constant_type::from_val(const constant &c)
    {
        return std::visit([](const auto &v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, std::monostate>) {
                return constant_type { type_tag::unit };
            } else if constexpr (std::is_same_v<T, bool>) {
                return constant_type { type_tag::boolean };
            } else if constexpr (std::is_same_v<T, cpp_int>) {
                return constant_type { type_tag::integer };
            } else if constexpr (std::is_same_v<T, std::string>) {
                return constant_type { type_tag::string };
            } else if constexpr (std::is_same_v<T, uint8_vector>) {
                return constant_type { type_tag::bytestring };
            } else if constexpr (std::is_same_v<T, data>) {
                return constant_type { type_tag::data };
            } else if constexpr (std::is_same_v<T, bls12_381_g1_element>) {
                return constant_type { type_tag::bls12_381_g1_element };
            } else if constexpr (std::is_same_v<T, bls12_381_g2_element>) {
                return constant_type { type_tag::bls12_381_g2_element };
            } else if constexpr (std::is_same_v<T, bls12_381_ml_result>) {
                return constant_type { type_tag::bls12_381_ml_result };
            } else if constexpr (std::is_same_v<T, constant_list>) {
                return constant_type { type_tag::list, { v.typ } };
            } else if constexpr (std::is_same_v<T, constant_pair>) {
                return constant_type { type_tag::pair, { from_val(v->first), from_val(v->second) } };
            } else {
                throw error("unsupported constant value: {}!", typeid(T).name());
                // Noop to make Visual C++ happy
                return constant_type { type_tag::unit };
            }
        }, c.val);
    }

    constant_list constant_list::make_empty(constant_type &&typ)
    {
        return { std::move(typ), {} };
    }

    constant_list constant_list::make_empty(const constant_type &typ)
    {
        return { constant_type { typ }, {} };
    }

    constant_list constant_list::make_one(constant &&c)
    {
        auto typ = constant_type::from_val(c);
        return { std::move(typ), { std::move(c) } };
    }

    data_pair::data_pair(data &&fst, data &&snd):
        _val { std::make_unique<value_type>(std::move(fst), std::move(snd)) }
    {
    }

    bool data_pair::operator==(const data_pair &o) const
    {
        return *_val == *o._val;
    }

    const data_pair::value_type &data_pair::operator*() const
    {
        return *_val;
    }
    const data_pair::value_type *data_pair::operator->() const
    {
        return _val.get();
    }

    static uint64_t _cast_to_uint64(const cpp_int &i)
    {
        if (i >= 0 && i <= std::numeric_limits<uint64_t>::max()) [[likely]]
            return static_cast<uint64_t>(i);
        throw error("integer to big to be casted into a 64-bit uint: {}", i);
    }

    data_constr::data_constr(const uint64_t id, vector<data> &&l)
        : _val { std::make_shared<value_type>(id, std::move(l)) }
    {
    }

    data_constr::data_constr(const cpp_int &id, vector<data> &&l)
        : data_constr(_cast_to_uint64(id), std::move(l))
    {
    }

    bool data_constr::operator==(const data_constr &o) const
    {
        return *_val == *o._val;
    }

    const data_constr::value_type &data_constr::operator*() const
    {
        return *_val;
    }

    const data_constr::value_type *data_constr::operator->() const
    {
        return _val.get();
    }

    data data::bstr(const buffer b)
    {
        return { uint8_vector { b } };
    }

    data data::bint(cpp_int &&i)
    {
        return { std::move(i) };
    }

    data data::bint(const cpp_int &i)
    {
        return bint(cpp_int { i });
    }

    data data::constr(cpp_int &&i, list_type &&d)
    {
        return { data_constr { std::move(i), std::move(d) } };
    }

    data data::list(list_type &&l)
    {
        return { std::move(l) };
    }

    data data::map(map_type &&m)
    {
        return { std::move(m) };
    }

    bool data::operator==(const data &o) const
    {
        return val == o.val;
    }

    static data _from_cbor(cbor::zero::value item);

    static data::list_type _from_cbor(cbor::zero::value::array_iterator it)
    {
        data::list_type dl {};
        while (!it.done()) {
            dl.emplace_back(_from_cbor(it.next()));
        }
        return dl;
    }

    static data _from_cbor(const cbor::zero::value v)
    {
        switch (const auto typ = v.type(); typ) {
            case cbor::major_type::tag: {
                auto [id, val] = v.tag();
                switch (id) {
                    case 2:
                    case 3:
                        return { v.big_int() };
                    default: {
                        if (id >= 121 && id < 128) {
                            id -= 121;
                        } else if (id >= 1280 && id < 1280 + 128) {
                            id -= 1280 - 7;
                        } else if (id == 102) {
                            auto it = v.array();
                            id = it.next().uint();
                            val = it.next();
                        } else {
                            throw error("unsupported tag id: {}", id);
                        }
                        return { data_constr { cpp_int { id }, _from_cbor(val.array()) } };
                    }
                }
            }
            case cbor::major_type::array: return { _from_cbor(v.array()) };
            case cbor::major_type::map: {
                data::map_type m {};
                auto it = v.map();
                while (!it.done()) {
                    auto [k, v] = it.next();
                    auto kd = _from_cbor(k);
                    auto vd = _from_cbor(v);
                    m.emplace_back(std::move(kd), std::move(vd));
                }
                return { std::move(m) };
            }
            case cbor::major_type::bytes: return { uint8_vector { v.bytes() } };
            case cbor::major_type::uint: return { v.big_int() };
            case cbor::major_type::nint: return { v.big_int() };
            default: throw error("unsupported CBOR type {}!", typ);
        }
    }

    data data::from_cbor(const buffer bytes)
    {
        return _from_cbor(cbor::zero::parse(bytes));
    }

    static void _to_cbor(cbor::encoder &enc, const data &c, size_t level=0);

    static void _to_cbor(cbor::encoder &enc, const cpp_int &i, const size_t)
    {
        enc.bigint(i);
    }

    static void _to_cbor(cbor::encoder &enc, const uint8_vector &b, const size_t)
    {
        enc.bytes(b);
    }

    static void _to_cbor(cbor::encoder &enc, const data::list_type &l, const size_t level)
    {
        enc.array();
        for (const auto &d: l)
            _to_cbor(enc, d, level + 1);
        enc.s_break();
    }

    static void _to_cbor(cbor::encoder &enc, const data &c, const size_t level)
    {
        static constexpr size_t max_nesting_level = 1024;
        if (level >= max_nesting_level) [[unlikely]]
            throw error("only 1024 levels of CBOR nesting are supported!");
        std::visit([&](const auto &v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, data::map_type>) {
                enc.map();
                for (const auto &p: v) {
                    _to_cbor(enc, p->first, level + 1);
                    _to_cbor(enc, p->second, level + 1);
                }
                enc.s_break();
            } else if constexpr (std::is_same_v<T, data_constr>) {
                if (v->first < std::numeric_limits<uint64_t>::max()) [[likely]] {
                    const auto id = static_cast<uint64_t>(v->first);
                    if (id <= 6) {
                        enc.tag(id + 121);
                    } else if (id <= 127) {
                        enc.tag(id - 7 + 1280);
                    } else {
                        enc.tag(102);
                        enc.array(2);
                    }
                    _to_cbor(enc, v->second, level + 1);
                }
                throw error("constr id is too big: {}", v->first);
            } else {
                _to_cbor(enc, v, level);
            }
        }, c.val);
    }

    uint8_vector data::as_cbor() const
    {
        cbor::encoder enc {};
        _to_cbor(enc, *this);
        return { std::move(enc.cbor()) };
    }

    uint8_vector bls_g1_compress(const bls12_381_g1_element &v)
    {
        uint8_vector comp(48);
        blst_p1_compress(comp.data(), &v.val);
        return comp;
    }

    uint8_vector bls_g2_compress(const bls12_381_g2_element &v)
    {
        uint8_vector comp(96);
        blst_p2_compress(comp.data(), &v.val);
        return comp;
    }

    bls12_381_g1_element bls_g1_decompress(const buffer &bytes)
    {
        if (bytes.size() != 48) [[unlikely]]
            throw error("bls12_381_g1 elements must provide 48 bytes but got: {}", bytes.size());
        blst_p1_affine out_a;
        if (const auto err = blst_p1_uncompress(&out_a, reinterpret_cast<const byte *>(bytes.data())); err != BLST_SUCCESS) [[unlikely]]
            throw error("blst12_381_g1 element decoding failed for 0x{}", bytes);
        if (!blst_p1_affine_in_g1(&out_a)) [[unlikely]]
            throw error("blst12_381_g1 element is invalid 0x{}", bytes);
        bls12_381_g1_element out;
        blst_p1_from_affine(&out.val, &out_a);
        return out;
    }

    bls12_381_g2_element bls_g2_decompress(const buffer &bytes)
    {
        if (bytes.size() != 96) [[unlikely]]
            throw error("bls12_381_g2 elements must provide 86 bytes but got: {}", bytes.size());
        blst_p2_affine out_a;
        if (const auto err = blst_p2_uncompress(&out_a, reinterpret_cast<const byte *>(bytes.data())); err != BLST_SUCCESS) [[unlikely]]
            throw error("blst12_381_g2 element decoding failed at for 0x{}", bytes);
        if (!blst_p2_affine_in_g2(&out_a)) [[unlikely]]
            throw error("blst12_381_g2 element is invalid 0x{}", bytes);
        bls12_381_g2_element out;
        blst_p2_from_affine(&out.val, &out_a);
        return out;
    }

    std::string escape_utf8_string(const std::string &s)
    {
        std::string res {};
        auto res_it = std::back_inserter(res);
        for (auto it = s.begin(), end = s.end(); it != end;) {
            const auto k = utf8::next(it, end);
            if (k >= 127) {
                fmt::format_to(res_it, "\\{}", static_cast<int>(k));
            } else if (k >= 32) {
                res_it++ = k;
            } else {
                fmt::format_to(res_it, "\\x{:02X}", static_cast<int>(k));
            }
        }
        return res;
    }
}