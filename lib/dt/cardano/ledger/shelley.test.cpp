/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/test.hpp>
#include <dt/cbor/compare.hpp>
#include <dt/cardano/ledger/shelley.hpp>
#include <dt/cardano/ledger/state.hpp>
#include <dt/json.hpp>

namespace {
    using namespace daedalus_turbo;
    using namespace cardano;
    using namespace ledger;
}

suite cardano_ledger_shelley_suite = [] {
    using boost::ext::ut::v2_1_0::nothrow;
    using daedalus_turbo::array;
    "cardano::ledger::shelley"_test = [] {
        //auto &sched = scheduler::get();
        "max_epoch_slot"_test = [] {
            ledger::shelley::vrf_state st {};
            test_same(432000 - 129600, st.max_epoch_slot());
        };
        "cbor load/save"_test = [&] {
            const auto exp_bytes = file::read(install_path("data/shelley/ledger-0.cbor"));
            state st {};
            const auto tip = st.deserialize_node(exp_bytes);
            const auto ser = st.to_cbor(tip);
            const auto res_bytes = ser.flat();
            if (exp_bytes != res_bytes) {
                file::write(install_path("tmp/test-cardano-ledger-shelley/ledger-out.cbor"), res_bytes);
                logger::error("ledger diff: {}", cbor::compare(res_bytes, exp_bytes));
            } else {
                expect(true);
            }
        };
        "epoch_nonce default"_test = [] {
            const ledger::shelley::vrf_state vrf_state {};
            test_same(
                vrf_state.nonce_epoch(),
                vrf_nonce::from_hex("1a3be38bcbb7911969283716ad7aa550250226b76a61fc51cc9a9a35d9276d81")
            );
            test_same(vrf_state.uc_nonce(), vrf_nonce::from_hex("81e47a19e6b29b0a65b9591762ce5143ed30d0261e5d24a3201752506b20f15c"));
            test_same(vrf_state.uc_leader(), vrf_nonce::from_hex("12dd0a6a7d0e222a97926da03adb5a7768d31cc7c5c2bd6828e14a7d25fa3a60"));
        };
        "epoch_nonce manual"_test = [] {
            configs_mock::map_type cfg {};
            cfg.emplace("byron-genesis", daedalus_turbo::json::load("./etc/mainnet/byron-genesis.json").as_object());
            {
                auto shelley_genesis = daedalus_turbo::json::load("./etc/mainnet/shelley-genesis.json").as_object();
                shelley_genesis.insert_or_assign("startTime", 1234567890);
                cfg.emplace("shelley-genesis", std::move(shelley_genesis));
            }
            cfg.emplace("alonzo-genesis", daedalus_turbo::json::load("./etc/mainnet/alonzo-genesis.json").as_object());
            cfg.emplace("conway-genesis", daedalus_turbo::json::load("./etc/mainnet/conway-genesis.json").as_object());
            cfg.emplace("config", daedalus_turbo::json::object {
                { "ByronGenesisFile", "byron-genesis" },
                { "ByronGenesisHash", fmt::format("{}", blake2b<cardano::block_hash>(daedalus_turbo::json::serialize_canon(cfg.at("byron-genesis").json()))) },
                { "ShelleyGenesisFile", "shelley-genesis" },
                { "ShelleyGenesisHash", fmt::format("{}", blake2b<cardano::block_hash>(cfg.at("shelley-genesis").bytes())) },
                { "AlonzoGenesisFile", "alonzo-genesis" },
                { "AlonzoGenesisHash", fmt::format("{}", blake2b<cardano::block_hash>(cfg.at("alonzo-genesis").bytes())) },
                { "ConwayGenesisFile", "conway-genesis" },
                { "ConwayGenesisHash", fmt::format("{}", blake2b<cardano::block_hash>(cfg.at("conway-genesis").bytes())) }
            });
            cardano::config c_cfg { configs_mock { std::move(cfg) } };
            const ledger::shelley::vrf_state vrf_state { c_cfg };
            test_same(vrf_state.nonce_epoch(), vrf_nonce::from_hex("5403C5AA8CB9B076BB54809BF7E44333EE1B8B662C80D8EEB2C9414E631CD006"));
        };
    };
};