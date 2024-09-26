/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CRYPTO_SECP256K1_HPP
#define DAEDALUS_TURBO_CRYPTO_SECP256K1_HPP

#include <dt/util.hpp>

namespace daedalus_turbo::crypto::secp256k1
{
    namespace ecdsa {
        extern bool verify(const buffer &sig, const buffer &vk, const buffer &msg);
    }

    namespace schnorr {
        extern bool verify(const buffer &sig, const buffer &vk, const buffer &msg);
    }
}

#endif // !DAEDALUS_TURBO_CRYPTO_SECP256K1_HPP