/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

extern "C" {
#   include <sodium.h>
}
#include <dt/blake2b.hpp>
#include <dt/ed25519.hpp>

namespace daedalus_turbo {
    static_assert(sizeof(blake2b_256_hash) == crypto_hash_sha256_BYTES);

    void blake2b_sodium(void *out, const size_t out_len, const void *in, const size_t in_len)
    {
        ed25519::ensure_initialized();
        if (crypto_generichash(reinterpret_cast<unsigned char*>(out), out_len, reinterpret_cast<const unsigned char *>(in), in_len, nullptr, 0) != 0)
            throw error("libsodium error: can't compute hash!");
    }
}