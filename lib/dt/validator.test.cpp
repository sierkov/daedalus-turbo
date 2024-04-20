/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/block-producer.hpp>
#include <dt/validator.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano;

namespace {
    struct chain_info {
        uint64_t size = 0;
        block_hash hash {};
        configs_mock configs;
    };

    static chain_info gen_chain1(const std::string &path, const buffer &genesis_hash)
    {
        uint8_vector chain {};

        auto seed1 = blake2b<ed25519::seed>(std::string_view { "1" });
        auto sk1 = ed25519::create_sk_from_seed(seed1);
        const auto vrf_sk1 = vrf03_create_sk_from_seed(seed1);
        block_producer bp1 { sk1, seed1, vrf_sk1 };

        auto seed2 = blake2b<ed25519::seed>(std::string_view { "2" });
        auto sk2 = ed25519::create_sk_from_seed(seed2);
        const auto vrf_sk2 = vrf03_create_sk_from_seed(seed1);
        block_producer bp2 { sk2, seed2, vrf_sk2 };

        block_hash prev_hash = genesis_hash;
        uint64_t height = 0;
        for (uint64_t slot: { 0, 13, 44, 57 }) {
            auto &bp = slot % 2 == 0 ? bp1 : bp2;
            bp.height = height;
            bp.slot = slot;
            bp.prev_hash = prev_hash;
            const auto block_data = bp.cbor();
            const auto block_tuple = cbor::parse(block_data);
            const auto blk = make_block(block_tuple, chain.size());
            chain << block_data;
            prev_hash = blk->hash();
            ++height;
        }
        file::write_zstd(path, chain);
        configs_mock::map_type cfg {};
        cfg.emplace("genesis-shelley", json::object {
            { "genDelegs", json::object {
                { "1", json::object {
                    { "delegate", fmt::format("{}", blake2b<pool_hash>(ed25519::extract_vk(sk1))) },
                    { "vrf", fmt::format("{}", vrf03_extract_vk(vrf_sk1)) }
                } },
                { "2", json::object {
                    { "delegate", fmt::format("{}", blake2b<pool_hash>(ed25519::extract_vk(sk2))) },
                    { "vrf", fmt::format("{}", vrf03_extract_vk(vrf_sk2)) }
                } }
            } }
        });
        return chain_info { chain.size(), blake2b<block_hash>(chain), configs_mock { std::move(cfg) } };
    }
}

suite validator_suite = [] {
    "validator"_test = [] {
        "success"_test = [] {
            static std::string data_dir { "tmp/validator" };
            std::filesystem::remove_all(data_dir);
            const auto genesis_hash = block_hash::from_hex("5F20DF933584822601F9E3F8C024EB5EB252FE8CEFB24D1317DC3D432E940EBB");
            const std::string chunk1_name { "chunk1.chunk" };
            const auto chunk1_path = fmt::format("{}/{}", data_dir, chunk1_name);
            auto chain1 = gen_chain1(chunk1_path, genesis_hash);
            validator::incremental cr { data_dir, chain1.configs };
            cr.start_tx(0, chain1.size);
            cr.add(0, chunk1_path, chain1.hash, chunk1_name);
            cr.prepare_tx();
            cr.commit_tx();
        };
    };
};