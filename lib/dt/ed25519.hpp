/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_ED25519_HPP
#define DAEDALUS_TURBO_ED25519_HPP 1

#include <array>
#include <span>

extern "C" {
#   include <monocypher-ed25519.h>
};

namespace daedalus_turbo {

    using ed25519_vkey = std::array<uint8_t, 32>;
    using ed25519_signature = std::array<uint8_t, 64>;

    inline bool ed25519_verify(const std::span<const uint8_t> &signature, const std::span<const uint8_t> &public_key, const std::span<const uint8_t> &message)
    {
        if (signature.size() != 64) throw error_fmt("signature must have 64 bytes but got: {}!", signature.size());
        if (public_key.size() != 32) throw error_fmt("public key must have 32 bytes but got: {}!", public_key.size());
        return crypto_ed25519_check(signature.data(), public_key.data(), message.data(), message.size()) == 0;
    }

}

#endif // !DAEDALUS_TURBO_ED25519_HPP
