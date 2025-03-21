/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

extern "C" {
#   include <sodium.h>
}
#include <dt/crypto/sha2.hpp>
#include <dt/ed25519.hpp>

namespace daedalus_turbo::crypto::sha2 {
    void digest(const std::span<uint8_t> &out, const buffer &in)
    {
        if (out.size() != sizeof(hash_256))
            throw error(fmt::format("output size must be {} but got {}", sizeof(hash_256), out.size()));
        ed25519::ensure_initialized();
        if (crypto_hash_sha256(out.data(), in.data(), in.size()) != 0)
            throw error("sha2 computation hash failed!");
    }
}