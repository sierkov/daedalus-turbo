/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ED25519_HPP
#define DAEDALUS_TURBO_ED25519_HPP

#include <array>
#include <span>
extern "C" {
#   include <sodium.h>
};
#include <dt/util.hpp>

namespace daedalus_turbo {
    using ed25519_vkey = std::array<uint8_t, 32>;
    using ed25519_signature = std::array<uint8_t, 64>;

    namespace ed25519 {
        struct _sodium_initializer {
            _sodium_initializer()
            {
                if (sodium_init() == -1) throw error("Failed to initialize libsodium!");
            }
        };

        inline bool verify(const buffer &sig, const buffer &vk, const buffer &msg)
        {
            static _sodium_initializer init {};
            if (sig.size() != 64) throw error("signature must have 64 bytes but got: {}!", sig.size());
            if (vk.size() != 32) throw error("public key must have 32 bytes but got: {}!", vk.size());
            return crypto_sign_verify_detached(sig.data(), msg.data(), msg.size(), vk.data()) == 0;
        }
    }
}

#endif // !DAEDALUS_TURBO_ED25519_HPP