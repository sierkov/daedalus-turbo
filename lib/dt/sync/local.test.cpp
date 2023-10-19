/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/indexer.hpp>
#include <dt/sync/local.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite sync_local_suite = [] {
    "sync::local"_test = [] {
        std::string node_dir { "./data"s };
        std::string db_dir { "./tmp/compressed" };
        std::string idx_dir { "./tmp/index" };
        for (const auto &path: { db_dir, idx_dir })
            std::filesystem::remove_all(path);
        scheduler sched {};
        auto indexers = indexer::default_list(sched, idx_dir);
        indexer::incremental idxr { sched, db_dir, indexers };
        "from scratch"_test = [&] {
            sync::local::syncer syncr { sched, idxr, node_dir, true };
            auto res = syncr.sync();
            expect(res.errors.size() == 0_u);
            expect(res.deleted.size() == 0_u);
            expect(res.updated.size() == 6_u);
            expect(res.last_slot == 93147517_u);
        };
        "truncate manual"_test = [&] {
            auto before_slot = idxr.max_slot();
            auto del_1 = idxr.truncate(52958359);
            idxr.save_state();
            expect(del_1.size() == 5_u);
            expect(idxr.max_slot() < before_slot);
        };
        "incremental"_test = [&] {
            sync::local::syncer syncr { sched, idxr, node_dir, true };
            auto res = syncr.sync();
            expect(res.errors.size() == 0_u);
            expect(res.deleted.size() == 0_u);
            expect(res.updated.size() == 5_u);
            expect(res.last_slot == 93147517_u);
        };
        "nothing to do"_test = [&] {
            sync::local::syncer syncr { sched, idxr, node_dir, true };
            auto res = syncr.sync();
            expect(res.errors.size() == 0_u);
            expect(res.deleted.size() == 0_u);
            expect(res.updated.size() == 0_u);
            expect(res.last_slot == 93147517_u);
        };
        "shorter source"_test = [&] {
            std::string empty_dir { "./tmp/empty" };
            std::filesystem::remove_all(empty_dir);
            std::filesystem::create_directories(empty_dir + "/immutable");
            std::filesystem::create_directories(empty_dir + "/volatile");
            sync::local::syncer syncr { sched, idxr, empty_dir, true, 3, std::chrono::seconds { 0 } };
            auto res = syncr.sync();
            expect(res.errors.size() == 0_u);
            expect(res.deleted.size() == 6_u);
            expect(res.updated.size() == 0_u);
            expect(res.last_slot == 0_u);
        };
    };
};