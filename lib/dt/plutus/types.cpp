/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/plutus/types.hpp>
#include <dt/plutus/builtins.hpp>

namespace daedalus_turbo::plutus {
    static const builtin::info &_builtin_info(const builtin_tag &tag)
    {
        static map<builtin_tag, builtin::info> info_map {};
        if (info_map.empty()) [[unlikely]] {
            info_map.try_emplace(builtin_tag::add_integer, 2, builtins::add_integer);
            info_map.try_emplace(builtin_tag::subtract_integer, 2, builtins::subtract_integer);
            info_map.try_emplace(builtin_tag::subtract_integer, 2, builtins::subtract_integer);
            info_map.try_emplace(builtin_tag::multiply_integer, 2, builtins::multiply_integer);
            info_map.try_emplace(builtin_tag::divide_integer, 2, builtins::divide_integer);
            info_map.try_emplace(builtin_tag::quotient_integer, 2, builtins::quotient_integer);
            info_map.try_emplace(builtin_tag::remainder_integer, 2, builtins::remainder_integer);
            info_map.try_emplace(builtin_tag::equals_integer, 2, builtins::equals_integer);
            info_map.try_emplace(builtin_tag::less_than_integer, 2, builtins::less_than_integer);
            info_map.try_emplace(builtin_tag::less_than_equals_integer, 2, builtins::less_than_equals_integer);
            info_map.try_emplace(builtin_tag::append_byte_string, 2, builtins::append_byte_string);
            info_map.try_emplace(builtin_tag::cons_byte_string, 2, builtins::cons_byte_string);
            info_map.try_emplace(builtin_tag::slice_byte_string, 3, builtins::slice_byte_string);
            info_map.try_emplace(builtin_tag::length_of_byte_string, 1, builtins::length_of_byte_string);
            info_map.try_emplace(builtin_tag::index_byte_string, 2, builtins::index_byte_string);
            info_map.try_emplace(builtin_tag::equals_byte_string, 2, builtins::equals_byte_string);
            info_map.try_emplace(builtin_tag::less_than_byte_string, 2, builtins::less_than_byte_string);
            info_map.try_emplace(builtin_tag::less_than_equals_byte_string, 2, builtins::less_than_equals_byte_string);
            info_map.try_emplace(builtin_tag::sha2_256, 1, builtins::sha2_256);
            info_map.try_emplace(builtin_tag::sha3_256, 1, builtins::sha3_256);
            info_map.try_emplace(builtin_tag::blake2b_256, 1, builtins::blake2b_256);
            info_map.try_emplace(builtin_tag::verify_ed25519_signature, 3, builtins::verify_ed25519_signature);
            info_map.try_emplace(builtin_tag::append_string, 2, builtins::append_string);
            info_map.try_emplace(builtin_tag::equals_string, 2, builtins::equals_string);
            info_map.try_emplace(builtin_tag::encode_utf8, 1, builtins::encode_utf8);
            info_map.try_emplace(builtin_tag::decode_utf8, 1, builtins::decode_utf8);
            info_map.try_emplace(builtin_tag::if_then_else, 3, builtins::if_then_else);
            info_map.try_emplace(builtin_tag::choose_unit, 2, builtins::choose_unit);
            info_map.try_emplace(builtin_tag::trace, 2, builtins::trace);
            info_map.try_emplace(builtin_tag::fst_pair, 1, builtins::fst_pair);
            info_map.try_emplace(builtin_tag::snd_pair, 1, builtins::snd_pair);
            info_map.try_emplace(builtin_tag::choose_list, 3, builtins::choose_list);
            info_map.try_emplace(builtin_tag::mk_cons, 2, builtins::mk_cons);
            info_map.try_emplace(builtin_tag::head_list, 1, builtins::head_list);
            info_map.try_emplace(builtin_tag::tail_list, 1, builtins::tail_list);
            info_map.try_emplace(builtin_tag::null_list, 1, builtins::null_list);
            info_map.try_emplace(builtin_tag::choose_data, 6, builtins::choose_data);
            info_map.try_emplace(builtin_tag::constr_data, 2, builtins::constr_data);
            info_map.try_emplace(builtin_tag::map_data, 1, builtins::map_data);
            info_map.try_emplace(builtin_tag::list_data, 1, builtins::list_data);
            info_map.try_emplace(builtin_tag::i_data, 1, builtins::i_data);
            info_map.try_emplace(builtin_tag::b_data, 1, builtins::b_data);
            info_map.try_emplace(builtin_tag::un_constr_data, 1, builtins::un_constr_data);
            info_map.try_emplace(builtin_tag::un_map_data, 1, builtins::un_map_data);
            info_map.try_emplace(builtin_tag::un_list_data, 1, builtins::un_list_data);
            info_map.try_emplace(builtin_tag::un_i_data, 1, builtins::un_i_data);
            info_map.try_emplace(builtin_tag::un_b_data, 1, builtins::un_b_data);
            info_map.try_emplace(builtin_tag::equals_data, 2, builtins::equals_data);
            info_map.try_emplace(builtin_tag::mk_pair_data, 2, builtins::mk_pair_data);
            info_map.try_emplace(builtin_tag::mk_nil_data, 1, builtins::mk_nil_data);
            info_map.try_emplace(builtin_tag::mk_nil_pair_data, 1, builtins::mk_nil_pair_data);
            info_map.try_emplace(builtin_tag::serialise_data, 1, builtins::serialize_data);
        }
        if (const auto it = info_map.find(tag); it != info_map.end()) [[likely]]
            return it->second;
        throw error("not implemented: {}", tag);
    }

    const builtin::info &builtin::meta() const
    {
        return _builtin_info(tag);
    }
}