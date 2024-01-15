/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/indexer/merger.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;
using namespace daedalus_turbo::indexer;
using namespace daedalus_turbo::indexer::merger;

suite indexer_merger_suite = [] {
    "indexer::merger"_test = [] {
        "main operations"_test = [] {
            merger::tree m {};
            m.add(merger::slice { 10, 2 });
            m.add(merger::slice { 12, 2 });
            m.add(merger::slice { 15, 5 });
            m.add(merger::slice { 21, 1 });
            m.add(merger::slice { 22, 1 });
            m.add(merger::slice { 25, 5 });
            m.add(merger::slice { 40, 11 });
            m.add(merger::slice { 51, 9 });
            std::vector<proposal> proposals {};
            m.find_mergeable([&](auto &&p) {
                proposals.emplace_back(std::move(p));
            });
            expect(proposals.size() == 3_u);
            if (proposals.size() >= 1) {
                expect(proposals[0].new_slice.offset == 10_u);
                expect(proposals[0].new_slice.size == 4_u);
                expect(proposals[0].input_slices.size() == 2_u);
                expect(proposals[0].input_slices[0] == 10_u);
                expect(proposals[0].input_slices[1] == 12_u);
            }
            if (proposals.size() >= 2) {
                expect(proposals[1].new_slice.offset == 21_u);
                expect(proposals[1].new_slice.size == 2_u);
                expect(proposals[1].input_slices.size() == 2_u);
                expect(proposals[1].input_slices[0] == 21_u);
                expect(proposals[1].input_slices[1] == 22_u);
            }
            if (proposals.size() >= 3) {
                expect(proposals[2].new_slice.offset == 40_u);
                expect(proposals[2].new_slice.size == 20_u);
                expect(proposals[2].input_slices.size() == 2_u);
                expect(proposals[2].input_slices[0] == 40_u);
                expect(proposals[2].input_slices[1] == 51_u);
            }
        };
        "test set - final merge"_test = [] {
            merger::tree m {};
            m.add(merger::slice { 100007772522, 830467559 });
            m.add(merger::slice { 100838240081, 766620564 });
            m.add(merger::slice { 101604860645, 735679059 });
            std::vector<proposal> proposals {};
            m.find_mergeable([&](auto &&p) {
                proposals.emplace_back(std::move(p));
            });
            expect(proposals.size() == 1_u);
            if (proposals.size() >= 1) {
                expect(proposals[0].new_slice.offset == 100007772522_ull);
                expect(proposals[0].new_slice.size == 2332767182_ull);
                expect(proposals[0].input_slices.size() == 3_ull);
            }
        };
    };
};