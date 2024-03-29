/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/indexer.hpp>
#include <dt/sync/local.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite sync_local_suite = [] {
    "sync::local"_test = [] {
        std::string node_dir { "./data"s };
        std::string data_dir { "./tmp/sync-local" };
        std::filesystem::remove_all(data_dir);
        indexer::incremental idxr { indexer::default_list(data_dir), data_dir, false };
        auto &fr = file_remover::get();
        "from scratch"_test = [&] {
            sync::local::syncer syncr { idxr, node_dir };
            auto res = syncr.sync();
            expect(res.errors.size() == 0_u);
            expect(res.updated.size() == 29_u);
            expect(res.last_slot == 93147517_u);
        };
        "truncate manual"_test = [&] {
            auto before_slot = idxr.max_slot();
            idxr.truncate(52958359);
            idxr.save_state();
            expect(fr.size() == 28_u);
            expect(idxr.max_slot() < before_slot) << idxr.max_slot() << before_slot;
        };
        "incremental"_test = [&] {
            sync::local::syncer syncr { idxr, node_dir };
            auto res = syncr.sync();
            expect(res.errors.size() == 0_u);
            expect(res.updated.size() == 28_u);
            expect(res.last_slot == 93147517_u);
        };
        "nothing to do"_test = [&] {
            sync::local::syncer syncr { idxr, node_dir };
            auto res = syncr.sync();
            expect(res.errors.size() == 0_u);
            expect(res.updated.size() == 0_u);
            expect(res.last_slot == 93147517_u);
        };
        "shorter source"_test = [&] {
            std::string empty_dir { "./tmp/empty" };
            std::filesystem::remove_all(empty_dir);
            std::filesystem::create_directories(empty_dir + "/immutable");
            std::filesystem::create_directories(empty_dir + "/volatile");
            sync::local::syncer syncr { idxr, empty_dir, 3, std::chrono::seconds { 0 } };
            auto res = syncr.sync();
            expect(res.errors.size() == 0_u);
            expect(res.updated.size() == 0_u);
            expect(res.last_slot == 0_u);
        };
    };
};