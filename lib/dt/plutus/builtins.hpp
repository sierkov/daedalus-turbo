/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_BUILTINS_HPP
#define DAEDALUS_TURBO_PLUTUS_BUILTINS_HPP

#include <functional>
#include <dt/plutus/machine.hpp>

namespace daedalus_turbo::plutus {
    struct builtin_one_arg: std::function<value(const value &)> {
        using std::function<value(const value &)>::function;
    };
    struct builtin_two_arg: std::function<value(const value &, const value &)> {
        using std::function<value(const value &, const value &)>::function;
    };
    struct builtin_three_arg: std::function<value(const value &, const value &, const value &)> {
        using std::function<value(const value &, const value &, const value &)>::function;
    };
    struct builtin_six_arg: std::function<value(const value &, const value &, const value &, const value &, const value &, const value &)> {
        using std::function<value(const value &, const value &, const value &, const value &, const value &, const value &)>::function;
    };

    namespace builtins {
        extern value add_integer(const value &x, const value &y);
        extern value subtract_integer(const value &x, const value &y);
        extern value multiply_integer(const value &x, const value &y);
        extern value divide_integer(const value &x, const value &y);
        extern value mod_integer(const value &x, const value &y);
        extern value quotient_integer(const value &x, const value &y);
        extern value remainder_integer(const value &x, const value &y);
        extern value equals_integer(const value &x, const value &y);
        extern value less_than_integer(const value &x, const value &y);
        extern value less_than_equals_integer(const value &x, const value &y);
        extern value append_byte_string(const value &x, const value &y);
        extern value cons_byte_string(const value &c, const value &s);
        extern value slice_byte_string(const value &pos_raw, const value &sz_raw, const value &s_raw);
        extern value length_of_byte_string(const value &s);
        extern value index_byte_string(const value &s_t, const value &i_t);
        extern value equals_byte_string(const value &s1, const value &s2);
        extern value less_than_byte_string(const value &s1, const value &s2);
        extern value less_than_equals_byte_string(const value &s1_t, const value &s2_t);
        extern value append_string(const value &s1, const value &s2);
        extern value equals_string(const value &s1, const value &s2);
        extern value encode_utf8(const value &s);
        extern value decode_utf8(const value &b);
        extern value if_then_else(const value &condition, const value &yes, const value &no);
        extern value sha2_256(const value &s);
        extern value sha3_256(const value &s);
        extern value blake2b_256(const value &s);
        extern value verify_ed25519_signature(const value &sig, const value &msg, const value &vk);
        extern value choose_unit(const value &u, const value &v);
        extern value fst_pair(const value &p);
        extern value snd_pair(const value &p);
        extern value choose_list(const value &a, const value &t1, const value &t2);
        extern value mk_cons(const value &x, const value &l);
        extern value head_list(const value &l);
        extern value tail_list(const value &l);
        extern value null_list(const value &l);
        extern value trace(const value &s, const value &t);
        extern value choose_data(const value &d, const value &c, const value &m, const value &l, const value &i, const value &b);
        extern value constr_data(const value &c, const value &l);
        extern value map_data(const value &m);
        extern value list_data(const value &m);
        extern value i_data(const value &t);
        extern value b_data(const value &t);
        extern value un_constr_data(const value &t);
        extern value un_map_data(const value &t);
        extern value un_list_data(const value &t);
        extern value un_i_data(const value &t);
        extern value un_b_data(const value &t);
        extern value equals_data(const value &d1, const value &d2);
        extern value mk_pair_data(const value &fst, const value &snd);
        extern value mk_nil_data(const value &);
        extern value mk_nil_pair_data(const value &);
        extern value serialize_data(const value &d);
        extern value verify_ecdsa_secp_256k1_signature(const value &, const value &, const value &);
        extern value verify_schnorr_secp_256k1_signature(const value &, const value &, const value &);
        extern value blake2b_224(const value &);
        extern value keccak_256(const value &);
        extern value integer_to_byte_string(const value &, const value &, const value &);
        extern value byte_string_to_integer(const value &, const value &);
        extern value bls12_381_g1_add(const value &, const value &);
        extern value bls12_381_g1_neg(const value &);
        extern value bls12_381_g1_scalar_mul(const value &, const value &);
        extern value bls12_381_g1_equal(const value &, const value &);
        extern value bls12_381_g1_hash_to_group(const value &, const value &);
        extern value bls12_381_g1_compress(const value &);
        extern value bls12_381_g1_uncompress(const value &);
        extern value bls12_381_g2_add(const value &, const value &);
        extern value bls12_381_g2_neg(const value &);
        extern value bls12_381_g2_scalar_mul(const value &, const value &);
        extern value bls12_381_g2_equal(const value &, const value &);
        extern value bls12_381_g2_hash_to_group(const value &, const value &);
        extern value bls12_381_g2_compress(const value &);
        extern value bls12_381_g2_uncompress(const value &);
        extern value bls12_381_miller_loop(const value &, const value &);
        extern value bls12_381_mul_ml_result(const value &, const value &);
        extern value bls12_381_final_verify(const value &, const value &);
    }
}

#endif //DAEDALUS_TURBO_PLUTUS_BUILTINS_HPP