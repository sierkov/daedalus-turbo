/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/crypto/secp256k1.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::crypto::secp256k1;

suite crypto_secp256k1_suite = [] {
    "crypto::secp256k1"_test = [] {
        struct test_vec {
            const char *vk;
            const char *msg;
            const char *sig;
        };
        "ecdsa"_test = [] {
            for (const auto &vec: {
                test_vec { "02599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b", "0000000000000000000000000000000000000000000000000000000000000000",
                    "354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a06254f0915935f33b91bceb16d46ff2814f659e9b6791a4a21ff8764b78d7e114" }
            }) {
                test_same(true, ecdsa::verify(uint8_vector::from_hex(vec.sig), uint8_vector::from_hex(vec.vk), uint8_vector::from_hex(vec.msg)));
            }
            for (const auto &vec: {
                test_vec { "02599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b", "0000000000000000000000000000000000000000000000000000000000000000",
                    "354b868c757ef0b796003f7c23dd754d2d1726629145be2c7b7794a25fec80a09dab0f6ea6ca0cc46e4314e92b900d7d6b493e4b47b6fb999fd9e841575e602d" }
            }) {
                test_same(false, ecdsa::verify(uint8_vector::from_hex(vec.sig), uint8_vector::from_hex(vec.vk), uint8_vector::from_hex(vec.msg)));
            }
        };
        "schnorr"_test = [] {
            for (const auto &vec: {
                test_vec { "599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b", "0000000000000000000000000000000000000000000000000000000000000000",
                    "5a56da88e6fd8419181dec4d3dd6997bab953d2fc71ab65e23cfc9e7e3d1a310613454a60f6703819a39fdac2a410a094442afd1fc083354443e8d8bb4461a9b" }
            }) {
                test_same(true, schnorr::verify(uint8_vector::from_hex(vec.sig), uint8_vector::from_hex(vec.vk), uint8_vector::from_hex(vec.msg)));
            }
            for (const auto &vec: {
                test_vec { "599de3e582e2a3779208a210dfeae8f330b9af00a47a7fb22e9bb8ef596f301b", "0000000000000000000000000000000000000000000000000000000000000001",
                    "5a56da88e6fd8419181dec4d3dd6997bab953d2fc71ab65e23cfc9e7e3d1a310613454a60f6703819a39fdac2a410a094442afd1fc083354443e8d8bb4461a9b" }
            }) {
                test_same(false, schnorr::verify(uint8_vector::from_hex(vec.sig), uint8_vector::from_hex(vec.vk), uint8_vector::from_hex(vec.msg)));
            }
        };
    };
};