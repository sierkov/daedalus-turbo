/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/test.hpp>
#include <dt/crypto/blst.hpp>

using namespace daedalus_turbo;

suite crypto_blst_suite = [] {
    "crypto::blst"_test = [] {
        uint64_t in[4] {1, 2, 3, 4};
        blst_scalar out {};
        blst_scalar_from_uint64(&out, in);
    };
};