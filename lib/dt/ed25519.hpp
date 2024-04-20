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
        using seed = array<uint8_t, 32>;

        extern void ensure_initialized();

        inline void create(const std::span<uint8_t> &sk, const std::span<uint8_t> &vk)
        {
            if (sk.size() != sizeof(skey))
                throw error("private key must have {} bytes but got: {}!", sizeof(skey), sk.size());
            if (vk.size() != sizeof(vkey))
                throw error("verification key must have {} bytes but got: {}!", sizeof(vkey), vk.size());
            ensure_initialized();
            if (crypto_sign_keypair(vk.data(), sk.data()) != 0)
                throw error("failed to generate a cryptographic key pair!");
        }

        inline void create_from_seed(const std::span<uint8_t> &sk, const std::span<uint8_t> &vk, const buffer &sd)
        {
            if (sk.size() != sizeof(skey))
                throw error("private key must have {} bytes but got: {}!", sizeof(skey), sk.size());
            if (vk.size() != sizeof(vkey))
                throw error("verification key must have {} bytes but got: {}!", sizeof(vkey), vk.size());
            if (sd.size() != sizeof(seed))
                throw error("seed must have {} bytes but got: {}!", sizeof(seed), sd.size());
            ensure_initialized();
            if (crypto_sign_seed_keypair(vk.data(), sk.data(), sd.data()) != 0)
                throw error("failed to generate a cryptographic key pair!");
        }

        // a convenience method
        inline ed25519::skey create_sk_from_seed(const buffer &sd)
        {
            ed25519::skey sk {};
            ed25519::vkey vk {};
            if (sd.size() != sizeof(seed))
                throw error("seed must have {} bytes but got: {}!", sizeof(seed), sd.size());
            ed25519::create_from_seed(sk, vk, sd);
            return sk;
        }

        inline void extract_vk(const std::span<uint8_t> &vk, const buffer &sk)
        {
            if (sk.size() != sizeof(skey))
                throw error("private key must have {} bytes but got: {}!", sizeof(skey), sk.size());
            if (vk.size() != sizeof(vkey))
                throw error("verification key must have {} bytes but got: {}!", sizeof(vkey), vk.size());
            if (crypto_sign_ed25519_sk_to_pk(vk.data(), sk.data()) != 0)
                throw error("failed to extract the verification key from a secret key!");
        }

        inline vkey extract_vk(const buffer &sk)
        {
            vkey vk {};
            extract_vk(vk, sk);
            return vk;
        }

        inline void sign(const std::span<uint8_t> &sig, const buffer &msg, const buffer &sk)
        {
            if (sk.size() != sizeof(skey))
                throw error("private key must have {} bytes but got: {}!", sizeof(skey), sk.size());
            if (sig.size() != sizeof(signature))
                throw error("signature buffer must have {} bytes but got: {}!", sizeof(signature), sig.size());
            ensure_initialized();
            if (crypto_sign_detached(sig.data(), NULL, msg.data(), msg.size(), sk.data()) != 0)
                throw error("failed to cryptographically sign a message!");
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