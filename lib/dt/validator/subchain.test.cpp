/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/validator/subchain.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::validator;

suite validator_subchain_suite = [] {
    "validator::subchain"_test = [] {
        "kes_interval"_test = [] {
            expect(throws([] { kes_interval { 6, 5 }; }));
            kes_interval i1 { 5, 7 };
            expect(i1.can_merge(kes_interval { 7, 9 }));
            expect(i1.can_merge(kes_interval { 7, 7 }));
            expect(i1.can_merge(kes_interval { 15, 20 }));
            expect(!i1.can_merge(kes_interval { 3, 4 }));
            expect(!i1.can_merge(kes_interval { 5, 7 }));
            expect(!i1.can_merge(kes_interval { 6, 7 }));
        };

        auto ph0 = cardano::pool_hash::from_hex("00000000000000000000000000000000000000000000000000000000");
        auto ph1 = cardano::pool_hash::from_hex("11111111111111111111111111111111111111111111111111111111");
        auto ph2 = cardano::pool_hash::from_hex("22222222222222222222222222222222222222222222222222222222");
        "kes_interval_map"_test = [&] {
            kes_interval_map m1 {};
            m1.emplace(ph0, kes_interval { 2, 5 });
            m1.emplace(ph1, kes_interval { 1, 2 });
            kes_interval_map m2 {};
            m2.emplace(ph0, kes_interval { 6, 11 });
            m2.emplace(ph2, kes_interval { 7, 9 });
            m1.merge(m2, 0);
            expect(m1.size() == 3_ull);
            expect(m1.at(ph0) == kes_interval { 2, 11 });
            expect(m1.at(ph1) == kes_interval { 1, 2 });
            expect(m1.at(ph2) == kes_interval { 7, 9 });
            kes_interval_map m3 {};
            m3.emplace(ph0, kes_interval { 0, 0 });
            expect(throws([&] { m1.merge(m3, 0); }));
        };

        "subchain"_test = [&] {
            kes_interval_map m1 {};
            m1.emplace(ph0, kes_interval { 2, 5 });
            m1.emplace(ph1, kes_interval { 1, 2 });
            subchain sc1 { 100, 200, 2, 0, m1 };
            expect(!sc1);
            expect(sc1.kes_intervals.size() == 2_ull);
            expect(sc1.end_offset() == 300_ull);
            kes_interval_map m2 {};
            m2.emplace(ph0, kes_interval { 6, 11 });
            m2.emplace(ph2, kes_interval { 7, 9 });
            subchain sc2 { 300, 200, 1, 1, m2 };
            expect(sc2);
            expect(sc1 < sc2);
            sc1.merge(sc2);
            expect(sc1.offset == 100_ull);
            expect(sc1.num_bytes == 400_ull);
            expect(sc1.end_offset() == 500_ull);
            expect(sc1.num_blocks == 3);
            expect(sc1.ok_eligibility == 1);
            expect(sc1.kes_intervals.size() == 3_ull);
            expect(!sc1);
        };

        "subchain_list"_test = []
        {
            "merge_valid"_test = [] {
                std::vector<subchain> saved {};
                subchain_list sl { [&] (const auto &sc) { saved.emplace_back(sc); } };
                subchain sc1 { 200, 200, 1, 1 };
                sc1.snapshot = true;
                sl.add(sc1);
                sl.add(subchain { 1000, 200, 1, 1 });
                expect(sl.valid_size() == 0_ull);
                expect(saved.empty());
                sl.add(subchain { 0, 200, 2, 2 });
                expect(sl.valid_size() == 400_ull);
                expect(sl.size() == 2_ull);
                expect(!saved.empty());
            };
            "merge_same_epoch"_test = [] {
                std::vector<subchain> saved {};
                subchain_list sl { [&] (const auto &sc) { saved.emplace_back(sc); } };
                sl.add(subchain { 200, 200, 1, 1, {}, 2 });
                sl.add(subchain { 1000, 200, 1, 0, {}, 3 });
                sl.add(subchain { 1200, 200, 1, 0, {}, 3 });
                sl.add(subchain { 1400, 200, 1, 0, {}, 3 });
                sl.add(subchain { 1600, 200, 1, 0, {}, 4 });
                expect(sl.valid_size() == 0_ull);
                expect(sl.size() == 5_ull);
                expect(saved.empty());
                sl.merge_same_epoch();
                expect(sl.valid_size() == 0_ull);
                expect(sl.size() == 3_ull);
                expect(saved.empty());
            };
        };
    };
};