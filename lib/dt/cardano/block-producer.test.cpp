/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/block-producer.hpp>
#include <dt/cardano.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano;

suite cardano_block_producer_suite = [] {
    "cardano::block_producer"_test = [] {
        "one empty block"_test = [] {
            ed25519::skey cold_sk {};
            ed25519::vkey cold_vk {};
            ed25519::create(cold_sk, cold_vk);
            auto seed = blake2b<ed25519::seed>(std::string_view { "1" });
            const auto vrf_sk = vrf03_create_sk_from_seed(seed);
            block_producer bp { cold_sk, seed, vrf_sk };
            const auto raw_data = bp.cbor();
            expect(raw_data.size() >= 512);
            const auto block_tuple = cbor::parse(raw_data);
            const auto blk = make_block(block_tuple, 123);
            expect(blk->era() == 6_ull);
            expect(blk->offset() == 123_ull);
            expect(blk->height() == 0_ull);
            expect(blk->slot() == 0_ull);
            expect(blk->signature_ok());
        };
        "two producers"_test = [] {
            uint8_vector chain {};

            auto seed1 = blake2b<ed25519::seed>(std::string_view { "1" });
            auto sk1 = ed25519::create_sk_from_seed(seed1);
            const auto vrf_sk1 = vrf03_create_sk_from_seed(seed1);
            block_producer bp1 { sk1, seed1, vrf_sk1 };

            auto seed2 = blake2b<ed25519::seed>(std::string_view { "2" });
            auto sk2 = ed25519::create_sk_from_seed(seed2);
            const auto vrf_sk2 = vrf03_create_sk_from_seed(seed1);
            block_producer bp2 { sk2, seed2, vrf_sk2 };

            block_hash prev_hash {};
            uint64_t height = 0;
            for (uint64_t slot: { 0, 13, 44, 57 }) {
                auto &bp = slot % 2 == 0 ? bp1 : bp2;
                bp.height = height;
                bp.slot = slot;
                bp.prev_hash = prev_hash;
                const auto block_data = bp.cbor();
                const auto block_tuple = cbor::parse(block_data);
                const auto blk = make_block(block_tuple, chain.size());
                expect(blk->era() == 6_ull);
                expect(blk->offset() == chain.size());
                expect(blk->height() == height);
                expect(blk->slot() == slot);
                expect(blk->prev_hash() == prev_hash);
                expect(blk->signature_ok());
                chain << block_data;
                prev_hash = blk->hash();
                ++height;
            }
        };
    };
};