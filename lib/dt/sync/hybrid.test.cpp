/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/sync/mocks.hpp>
#include <dt/sync/hybrid.hpp>
#include <dt/test.hpp>

namespace {
    using namespace daedalus_turbo;
    using namespace daedalus_turbo::sync;
}

suite sync_hybrid_suite = [] {
    "sync::hybrid"_test = [] {
        const auto [turbo_sk, turbo_vk] = ed25519::create_from_seed(blake2b<ed25519::seed>(std::string_view { "turbo-test" }));
        mock_chain_config mock_cfg {};
        mock_cfg.cfg.emplace("turbo", json::object {
            { "hosts", json::array { "turbo1.daedalusturbo.org", "turbo2.daedalusturbo.org" } },
            { "vkey", fmt::format("{}", turbo_vk) }
        });
        mock_cfg.height = 19;
        const auto good_chain = gen_chain(mock_cfg);
        const std::string data_dir { "./tmp/test-sync-hybrid/data" };
        const std::string turbo_dir { "./tmp/test-sync-hybrid/turbo" };
        "success"_test = [&] {
            std::filesystem::remove_all(data_dir);
            write_turbo_metadata(turbo_dir, good_chain, turbo_sk);
            chunk_registry cr { data_dir, chunk_registry::mode::validate, good_chain.cfg };
            download_queue_mock dq { turbo_dir, {} };
            cardano_client_manager_mock ccm { good_chain.data };
            hybrid::syncer syncer { cr, peer_selection_simple::get(), dq, ccm };
            test_same(cr.num_blocks(), 0);
            syncer.sync(syncer.find_peer());
            test_same(cr.num_blocks(), 19);
        };
        "turbo progress despite failure"_test = [&] {
            for (const auto failure: { failure_type::prev_hash, failure_type::slot_no }) {
                std::filesystem::remove_all(data_dir);
                mock_chain_config test_mock_cfg { mock_cfg };
                test_mock_cfg.failure_height = 7;
                test_mock_cfg.failure_type = failure;
                const auto bad_chain = gen_chain(test_mock_cfg);
                write_turbo_metadata(turbo_dir, bad_chain, turbo_sk);
                download_queue_mock dq { turbo_dir, {} };
                chunk_registry cr { data_dir, chunk_registry::mode::validate, bad_chain.cfg };
                cardano_client_manager_mock ccm { bad_chain.data };
                hybrid::syncer syncer { cr, peer_selection_simple::get(), dq, ccm };
                test_same(cr.num_blocks(), 0);
                expect(nothrow([&] { syncer.sync(syncer.find_peer()); }));
                test_same(cr.num_blocks(), 7);
            }
        };

        "turbo failure but p2p continues"_test = [&] {
            std::filesystem::remove_all(data_dir);
            mock_chain_config test_mock_cfg { mock_cfg };
            test_mock_cfg.failure_height = 7;
            const auto bad_chain = gen_chain(test_mock_cfg);
            write_turbo_metadata(turbo_dir, bad_chain, turbo_sk);
            download_queue_mock dq { turbo_dir, {} };
            chunk_registry cr { data_dir, chunk_registry::mode::validate, bad_chain.cfg };
            cardano_client_manager_mock ccm { good_chain.data };
            hybrid::syncer syncer { cr, peer_selection_simple::get(), dq, ccm };
            test_same(cr.num_blocks(), 0);
            expect(nothrow([&] { syncer.sync(syncer.find_peer()); }));
            test_same(cr.num_blocks(), 19);
        };
    };
};