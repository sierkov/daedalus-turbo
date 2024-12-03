/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_NATIVE_SCRIPT_HPP
#define DAEDALUS_TURBO_CARDANO_NATIVE_SCRIPT_HPP

#include <dt/cbor.hpp>
#include <dt/cardano/types.hpp>

namespace daedalus_turbo::cardano::native_script {
    using optional_error_string = std::optional<std::string>;
    extern optional_error_string validate(const cbor::value &script, const uint64_t slot, const set<key_hash> &vkeys);
}

#endif // !DAEDALUS_TURBO_CARDANO_NATIVE_SCRIPT_HPP