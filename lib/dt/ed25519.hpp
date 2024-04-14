/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ED25519_HPP
#define DAEDALUS_TURBO_ED25519_HPP

extern "C" {
#   include <sodium.h>
};
#include <dt/array.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {
    namespace ed25519 {
        using vkey = array<uint8_t, 32>;
        using skey = array<uint8_t, 64>;
        using signature = array<uint8_t, 64>;

        extern void ensure_initialized();

        inline void create(skey &sk, vkey &vk)
        {
            ensure_initialized();
            crypto_sign_keypair(vk.data(), sk.data());
        }

        inline void sign(signature &sig, const buffer &msg, const buffer &sk)
        {
            if (sk.size() != sizeof(skey))
                throw error("private key must have {} bytes but got: {}!", sizeof(skey), sk.size());
            ensure_initialized();
            crypto_sign_detached(sig.data(), NULL, msg.data(), msg.size(), sk.data());
        }

        inline bool verify(const buffer &sig, const buffer &vk, const buffer &msg)
        {
            if (sig.size() != sizeof(signature))
                throw error("signature must have {} bytes but got: {}!", sizeof(signature), sig.size());
            if (vk.size() != sizeof(vkey))
                throw error("public key must have {} bytes but got: {}!", sizeof(vkey), vk.size());
            ensure_initialized();
            return crypto_sign_verify_detached(sig.data(), msg.data(), msg.size(), vk.data()) == 0;
        }
    }

    using ed25519_vkey = ed25519::vkey;
    using ed25519_signature = ed25519::signature;
}

#endif // !DAEDALUS_TURBO_ED25519_HPP