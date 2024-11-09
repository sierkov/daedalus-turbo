/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/config.hpp>
#include <dt/cardano/ledger/subchain.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano::ledger;

suite cardano_ledger_subchain_suite = [] {
    "cardano::ledger::subchain"_test = [] {
        "subchain"_test = [&] {
            subchain sc1 { 100, 200, 2, 0 };
            expect(!sc1);
            expect(sc1.end_offset() == 300_ull);
            subchain sc2 { 300, 200, 1, 1 };
            expect(!!sc2);
            expect(sc1 < sc2);
            sc1.merge(sc2);
            expect(sc1.offset == 100_ull);
            expect(sc1.num_bytes == 400_ull);
            expect(sc1.end_offset() == 500_ull);
            expect(sc1.num_blocks == 3);
            expect(sc1.valid_blocks == 1);
            expect(!sc1);
        };

        "subchain_list"_test = []
        {
            // keep an own instance to prevent the sharing of shelley_start_epoch with other tests
            const cardano::config cfg { configs_dir::get() };
            const auto hash1 = blake2b<cardano::block_hash>(std::string_view { "1" });
            const auto hash2 = blake2b<cardano::block_hash>(std::string_view { "2" });
            const auto hash3 = blake2b<cardano::block_hash>(std::string_view { "3" });
            const auto hash4 = blake2b<cardano::block_hash>(std::string_view { "4" });
            const auto hash5 = blake2b<cardano::block_hash>(std::string_view { "5" });
            const auto hash6 = blake2b<cardano::block_hash>(std::string_view { "6" });
            "merge_valid"_test = [&] {
                subchain_list sl {};
                subchain sc1 { 200, 200, 1, 1, 1'000, hash2, 1'500, hash3 };
                sl.add(sc1);
                sl.add(subchain { 1000, 200, 1, 1, 10'000, hash3, 10'500, hash4 });
                test_same(sl.valid_size(), 0);
                test_same(sl.max_valid_point(), cardano::optional_point {});
                sl.add(subchain { 0, 200, 2, 2, 0, hash1, 900, hash2 });
                test_same(sl.valid_size(), 400);
                test_same(sl.max_valid_point(), cardano::point { hash3, 1'500 });
                expect(sl.size() == 2_ull);
            };
            "merge_same_epoch"_test = [&] {
                subchain_list sl {};
                sl.add(subchain { 200, 200, 1, 1, 21600 * 2, hash1, 21600 * 3 - 1, hash2 });
                sl.add(subchain { 1000, 200, 1, 0, 21600 * 3, hash2, 21600 * 3 + 100, hash3 });
                sl.add(subchain { 1200, 200, 1, 0, 21600 * 3 + 101, hash3, 21600 * 3 + 1000, hash4 });
                sl.add(subchain { 1400, 200, 1, 0, 21600 * 3 + 1001, hash4, 21600 * 3 + 2000, hash5 });
                sl.add(subchain { 1600, 200, 1, 0, 21600 * 4, hash5, 21600 * 5 - 1, hash6 });
                test_same(sl.valid_size(), 0);
                test_same(sl.size(), 5);
                sl.merge_same_epoch(cfg);
                test_same(sl.valid_size(), 0);
                test_same(sl.size(), 3);
            };
        };
    };
};