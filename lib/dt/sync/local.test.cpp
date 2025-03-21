/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/test.hpp>
#include <dt/sync/local.hpp>

using namespace daedalus_turbo;

suite sync_local_suite = [] {
    // keep an own instance to prevent the sharing of shelley_start_slot with other tests
    const configs &cfg = configs_dir::get();
    "sync::local"_test = [&] {
        const std::filesystem::path node_dir { "./data"s };
        const std::string data_dir { "./tmp/sync-local" };
        std::filesystem::remove_all(data_dir);
        std::filesystem::remove_all(node_dir / "volatile-dt");
        file_remover my_fr {};
        chunk_registry idxr { data_dir, chunk_registry::mode::index, cfg, scheduler::get(), my_fr };
        "from scratch"_test = [&] {
            sync::local::syncer syncr { idxr };
            expect(syncr.sync(syncr.find_peer(node_dir), {}, sync::validation_mode_t::none));
            test_same(idxr.max_slot(), 93147517);
            test_same(333'649'716, idxr.num_bytes());
        };
        "truncate manual"_test = [&] {
            const auto before_slot = idxr.max_slot();
            const auto before_fr = my_fr.size();
            // keep just the first immutable chunk
            idxr.truncate(idxr.find_block_by_offset(52'958'358 - 1).point());
            // 29 (30 - 1) chunks + 4 index slices
            test_same(my_fr.size(), before_fr + 33);
            expect(idxr.max_slot() < before_slot) << idxr.max_slot() << before_slot;
            test_same(idxr.num_chunks(), 1);
        };
        "incremental"_test = [&] {
            sync::local::syncer syncr { idxr };
            expect(syncr.sync(syncr.find_peer(node_dir), {}, sync::validation_mode_t::none));
            test_same(333'649'716, idxr.num_bytes());
            test_same(idxr.max_slot(), 93147517);
        };
        "nothing to do"_test = [&] {
            sync::local::syncer syncr { idxr };
            expect(!syncr.sync(syncr.find_peer(node_dir), {}, sync::validation_mode_t::none));
            test_same(333'649'716, idxr.num_bytes());
            test_same(idxr.max_slot(), 93147517);
        };
        "shorter source"_test = [&] {
            const std::string empty_dir { "./tmp/empty" };
            std::filesystem::remove_all(empty_dir);
            std::filesystem::create_directories(empty_dir + "/immutable");
            std::filesystem::create_directories(empty_dir + "/volatile");
            sync::local::syncer syncr { idxr, 3, std::chrono::seconds { 0 } };
            const auto before_fr = my_fr.size();
            expect(!syncr.sync(syncr.find_peer(empty_dir), {}, sync::validation_mode_t::none));
            test_same(idxr.max_slot(), 93147517);
            test_same(333'649'716, idxr.num_bytes());
            test_same(my_fr.size(), before_fr);
        };
    };
};