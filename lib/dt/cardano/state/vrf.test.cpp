/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/state/vrf.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite cardano_state_vrf_suite = [] {
    "cardano::state::vrf"_test = [] {
        "epoch_nonce default"_test = [] {
            const cardano::state::vrf vrf_state { cardano::config::get() };
            test_same(vrf_state.nonce_epoch(), cardano::vrf_nonce::from_hex("1a3be38bcbb7911969283716ad7aa550250226b76a61fc51cc9a9a35d9276d81"));
            test_same(vrf_state.uc_nonce(), cardano::vrf_nonce::from_hex("81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c"));
            test_same(vrf_state.uc_leader(), cardano::vrf_nonce::from_hex("12dd0a6a7d0e222a97926da03adb5a7768d31cc7c5c2bd6828e14a7d25fa3a60"));
        };
        "epoch_nonce manual"_test = [] {
            configs_mock::map_type cfg {};
            cfg.emplace("byron-genesis", json::load("./etc/mainnet/byron-genesis.json").as_object());
            {
                auto shelley_genesis = json::load("./etc/mainnet/shelley-genesis.json").as_object();
                shelley_genesis.insert_or_assign("startTime", 1234567890);
                cfg.emplace("shelley-genesis", std::move(shelley_genesis));
            }
            cfg.emplace("alonzo-genesis", json::load("./etc/mainnet/alonzo-genesis.json").as_object());
            cfg.emplace("conway-genesis", json::object {});
            cfg.emplace("config", json::object {
                { "ByronGenesisFile", "byron-genesis" },
                { "ByronGenesisHash", fmt::format("{}", blake2b<cardano::block_hash>(json::serialize_canon(cfg.at("byron-genesis").json()))) },
                { "ShelleyGenesisFile", "shelley-genesis" },
                { "ShelleyGenesisHash", fmt::format("{}", blake2b<cardano::block_hash>(cfg.at("shelley-genesis").bytes())) },
                { "AlonzoGenesisFile", "alonzo-genesis" },
                { "AlonzoGenesisHash", fmt::format("{}", blake2b<cardano::block_hash>(cfg.at("alonzo-genesis").bytes())) },
                { "ConwayGenesisFile", "conway-genesis" },
                { "ConwayGenesisHash", fmt::format("{}", blake2b<cardano::block_hash>(cfg.at("conway-genesis").bytes())) }
            });
            cardano::config c_cfg { configs_mock { std::move(cfg) } };
            const cardano::state::vrf vrf_state { c_cfg };
            test_same(vrf_state.nonce_epoch(), cardano::vrf_nonce::from_hex("5403C5AA8CB9B076BB54809BF7E44333EE1B8B662C80D8EEB2C9414E631CD006"));
        };
    };
};