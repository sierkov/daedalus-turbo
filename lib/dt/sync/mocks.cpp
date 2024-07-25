/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/sync/mocks.hpp>

namespace daedalus_turbo::sync {
    mock_chain gen_chain(const mock_chain_config &mock_cfg)
    {
        const auto seed1 = blake2b<ed25519::seed>(std::string_view { "1" });
        const auto sk1 = ed25519::create_sk_from_seed(seed1);
        const auto vrf_sk1 = vrf03_create_sk_from_seed(seed1);
        const auto seed2 = blake2b<ed25519::seed>(std::string_view { "2" });
        const auto sk2 = ed25519::create_sk_from_seed(seed2);
        const auto vrf_sk2 = vrf03_create_sk_from_seed(seed1);

        configs_mock::map_type cfg { mock_cfg.cfg };
        {
            auto byron_genesis = json::load("./etc/mainnet/byron-genesis.json").as_object();
            byron_genesis.insert_or_assign("startTime", 1506203091);
            byron_genesis.insert_or_assign("avvmDistr", json::object {});
            cfg.emplace("byron-genesis", std::move(byron_genesis));
        }
        {
            auto shelley_genesis = json::load("./etc/mainnet/shelley-genesis.json").as_object();
            shelley_genesis.insert_or_assign("genDelegs", json::object {
                { "00000000000000000000000000000000000000000000000000000000", json::object {
                    { "delegate", fmt::format("{}", blake2b<pool_hash>(ed25519::extract_vk(sk1))) },
                    { "vrf", fmt::format("{}", vrf03_extract_vk(vrf_sk1)) }
                } },
                { "11111111111111111111111111111111111111111111111111111111", json::object {
                    { "delegate", fmt::format("{}", blake2b<pool_hash>(ed25519::extract_vk(sk2))) },
                    { "vrf", fmt::format("{}", vrf03_extract_vk(vrf_sk2)) }
                } }
            });
            cfg.emplace("shelley-genesis", std::move(shelley_genesis));
        }
        cfg.emplace("alonzo-genesis", json::load("./etc/mainnet/alonzo-genesis.json").as_object());
        cfg.emplace("conway-genesis", json::object {});
        cfg.emplace("config", json::object {
            { "ByronGenesisFile", "byron-genesis" },
            { "ByronGenesisHash", fmt::format("{}", blake2b<block_hash>(json::serialize_canon(cfg.at("byron-genesis").json()))) },
            { "ShelleyGenesisFile", "shelley-genesis" },
            { "ShelleyGenesisHash", fmt::format("{}", blake2b<block_hash>(cfg.at("shelley-genesis").bytes())) },
            { "AlonzoGenesisFile", "alonzo-genesis" },
            { "AlonzoGenesisHash", fmt::format("{}", blake2b<block_hash>(cfg.at("alonzo-genesis").bytes())) },
            { "ConwayGenesisFile", "conway-genesis" },
            { "ConwayGenesisHash", fmt::format("{}", blake2b<block_hash>(cfg.at("conway-genesis").bytes())) }
        });

        mock_chain chain { configs_mock { std::move(cfg) } };
        block_hash prev_hash = chain.cardano_cfg.byron_genesis_hash;
        uint64_t height = 0;
        uint64_t slot = 0;
        block_producer bp1 { sk1, seed1, vrf_sk1 };
        block_producer bp2 { sk2, seed2, vrf_sk2 };
        std::seed_seq seed { 0, 1, 2, 3, 4, 5 };
        std::default_random_engine rnd { seed };
        std::uniform_int_distribution<uint64_t> dist { 0, 40 };
        while (height < mock_cfg.height) {
            auto &bp = slot % 2 == 0 ? bp1 : bp2;
            bp.height = height;
            bp.slot = slot;
            bp.prev_hash = prev_hash;
            if (mock_cfg.failure_height && *mock_cfg.failure_height == height) {
                switch (mock_cfg.failure_type) {
                    case failure_type::prev_hash:
                        bp.prev_hash = block_hash {};
                        break;
                    case failure_type::slot_no:
                        if (chain.blocks.empty())
                            throw error("slot_no failure cannot be set up in the first block!");
                        if (!chain.blocks.back().blk->slot())
                            throw error("slot_no failure cannot be set up when the previous block has a slot of 0!");
                        bp.slot = chain.blocks.back().blk->slot() - 1;
                        break;
                    default:
                        throw error("unsupported failure_type: {}", static_cast<int>(mock_cfg.failure_type));
                }
            }
            block_parsed pblock {};
            pblock.data = std::make_unique<uint8_vector>(bp.cbor());
            pblock.cbor = std::make_unique<cbor::value>(cbor::parse(*pblock.data));
            pblock.blk = make_block(*pblock.cbor, chain.data.size(), chain.cardano_cfg);
            chain.data << *pblock.data;
            prev_hash = pblock.blk->hash();
            chain.tip = { pblock.blk->hash(), pblock.blk->slot(), pblock.blk->height() };
            chain.blocks.emplace_back(std::move(pblock));
            ++height;
            slot += dist(rnd);
        }
        chain.data_hash = blake2b<block_hash>(chain.data);
        return chain;
    }

    void write_turbo_metadata(const std::string &www_dir, const mock_chain &chain, const ed25519::skey &sk)
    {
        std::filesystem::remove_all(www_dir);
        std::filesystem::create_directories(www_dir);
        json::object j_chain {};
        j_chain.emplace("api", json::object {
            { "version", 2 },
            { "metadataLifespanSec", 3600 },
            { "volatileDataLifespanSec", 21600 }
        });
        struct epoch {
            uint8_vector data {};
            vector<const block_parsed *> blocks {};
            uint64_t last_slot = 0;
            block_hash last_block_hash {};
        };
        vector<epoch> epochs {};
        for (const auto &blk: chain.blocks) {
            const auto block_epoch = blk.blk->slot_object().epoch();
            if (block_epoch == epochs.size())
                epochs.emplace_back();
            else if (block_epoch > epochs.size()) [[unlikely]]
                throw error("nonconsecutive epochs: epoch {} came after {}", block_epoch, epochs.size());
            auto &epoch_data = epochs.at(block_epoch);
            epoch_data.blocks.emplace_back(&blk);
            epoch_data.data << *blk.data;
            epoch_data.last_slot = blk.blk->slot();
            epoch_data.last_block_hash = blk.blk->hash();
        }
        block_hash prev_hash = chain.cardano_cfg.byron_genesis_hash;
        json::array j_epochs {};
        for (size_t epoch_no = 0; epoch_no < epochs.size(); ++epoch_no) {
            const auto &epoch = epochs.at(epoch_no);
            j_epochs.emplace_back(json::object {
                { "lastSlot", epoch.last_slot },
                { "lastBlockHash", fmt::format("{}", epoch.last_block_hash) },
                { "size", epoch.data.size() }
            });
            const auto data_hash = blake2b<block_hash>(epoch.data);
            const auto compressed = zstd::compress(epoch.data, 3);
            file::write(fmt::format("{}/{}.zstd", www_dir, data_hash), compressed);
            json::array j_chunks {};
            j_chunks.emplace_back(json::object {
                { "relPath", fmt::format("immutable/chunk-{}-0.chunk", epoch_no) },
                { "size", epoch.data.size() },
                { "compressedSize", compressed.size() },
                { "numBlocks", epoch.blocks.size() },
                { "firstSlot", epoch.blocks.front()->blk->slot() },
                { "lastSlot", epoch.blocks.back()->blk->slot() },
                { "hash", fmt::format("{}", data_hash) },
                { "prevBlockHash", fmt::format("{}", epoch.blocks.front()->blk->prev_hash()) },
                { "lastBlockHash", fmt::format("{}", epoch.blocks.back()->blk->hash()) },
            });
            json::object j_epoch {
                { "lastSlot", epoch.last_slot },
                { "lastBlockHash", epoch.last_slot },
                { "prevBlockHash", fmt::format("{}", prev_hash) },
                { "size", epoch.data.size() },
                { "compressedSize", compressed.size() },
                { "chunks", std::move(j_chunks) }
            };
            json::save_pretty_signed(fmt::format("{}/epoch-{}-{}.json", www_dir, epoch_no, epoch.last_block_hash), j_epoch, sk);
            prev_hash = epoch.last_block_hash;
        }
        j_chain.emplace("epochs", std::move(j_epochs));
        json::save_pretty_signed(fmt::format("{}/{}", www_dir, "chain.json"), j_chain, sk);
    }
}