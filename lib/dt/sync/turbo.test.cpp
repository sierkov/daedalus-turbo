/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/sync/mocks.hpp>
#include <dt/sync/turbo.hpp>
#include <dt/test.hpp>

namespace {
    using namespace daedalus_turbo;
    using namespace daedalus_turbo::sync;
}

suite sync_turbo_suite = [] {
    "sync::turbo"_test = [] {
        const auto [turbo_sk, turbo_vk] = ed25519::create_from_seed(blake2b<ed25519::seed>(std::string_view { "turbo-test" }));
        mock_chain_config mock_cfg {};
        mock_cfg.cfg.emplace("turbo", json::object {
            { "hosts", json::array { "turbo1.daedalusturbo.org", "turbo2.daedalusturbo.org" } },
            { "vkey", fmt::format("{}", turbo_vk) }
        });
        mock_cfg.height = 19;
        const std::string data_dir { "./tmp/test-sync-turbo/data" };
        const std::string turbo_dir { "./tmp/test-sync-turbo/turbo" };
        "success"_test = [&] {
            std::filesystem::remove_all(data_dir);
            const auto chain = gen_chain(mock_cfg);
            write_turbo_metadata(turbo_dir, chain, turbo_sk);
            download_queue_mock dq { turbo_dir, {} };
            chunk_registry cr { data_dir, chunk_registry::mode::validate, chain.cfg };
            turbo::syncer syncer { cr, peer_selection_simple::get(), dq };
            test_same(cr.num_blocks(), 0);
            syncer.sync(syncer.find_peer());
            test_same(cr.num_blocks(), 19);
            expect(cr.valid_end_offset() == cr.num_bytes()) << cr.valid_end_offset() << cr.num_bytes();
        };
        "progress despite failure"_test = [&] {
            mock_chain_config test_mock_cfg { mock_cfg };
            test_mock_cfg.failure_height = 9;
            std::filesystem::remove_all(data_dir);
            const auto chain = gen_chain(test_mock_cfg);
            write_turbo_metadata(turbo_dir, chain, turbo_sk);
            download_queue_mock dq { turbo_dir, {} };
            chunk_registry cr { data_dir, chunk_registry::mode::validate, chain.cfg };
            turbo::syncer syncer { cr, peer_selection_simple::get(), dq };
            test_same(cr.num_blocks(), 0);
            expect(nothrow([&] { syncer.sync(syncer.find_peer()); }));
            test_same(cr.num_blocks(), 9);
            expect(cr.valid_end_offset() == cr.num_bytes()) << cr.valid_end_offset() << cr.num_bytes();
        };
    };
};