/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <boost/ut.hpp>
#include <dt/index.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

const string TMP_DIR = "/tmp";

struct indexed_type {
    uint8_t val[8];
};
static_assert(sizeof(indexed_type) == 8_u);

suite index_writer_suite = [] {
    "index_writer sorts outputs on flush"_test = [] {
        const string idx_path = TMP_DIR + "/index-test.tmp";
        constexpr size_t item_size = 8;
        indexed_type item1 { { 0x93, 0xF9, 0x03, 0x01, 0x3F, 0x01, 0xD1, 0xAE } };
        indexed_type item2 { { 0x6F, 0x2D, 0x0F, 0x07, 0xC0, 0x00, 0x70, 0x02 } };
        indexed_type item3 { { 0x7B, 0x28, 0x01, 0x80, 0xDE, 0x00, 0x55, 0x6B } };
        indexed_type item4 { { 0x2B, 0x33, 0x01, 0x00, 0xB8, 0x00, 0x1E, 0xAE } };
        constexpr size_t item_cnt = 4;
        const indexed_type items[item_cnt] = { item1, item2, item3, item4 };
        const indexed_type expected[item_cnt] = { item4, item2, item3, item1 };

        index_writer<indexed_type> idx(idx_path);
        for (size_t i = 0; i < item_cnt; ++i) {
            indexed_type &it = idx.writable();
            it = items[i];
            idx.next();
        }
        idx.flush();

        ifstream is(idx_path, ios::binary);
        char buf[item_size];
        for (size_t i = 0; i < item_cnt; ++i) {
            is.read(buf, item_size);
            expect(is.fail() == false);
            expect(memcmp(buf, &expected[i], sizeof(indexed_type)) == 0) << buffer(reinterpret_cast<const uint8_t *>(buf), item_size);
        }
        expect(is.eof() == false);
        is.read(buf, item_size);
        expect(is.eof() == true);
    };
    "index_radix_writer sorts outputs on flush"_test = [] {
        vector<string> paths;
        paths.emplace_back(TMP_DIR + "/index_radix_writer-test-1.tmp");
        paths.emplace_back(TMP_DIR + "/index_radix_writer-test-2.tmp");
        indexed_type item1 { { 0xAA, 0xF9, 0x03, 0x01, 0x3F, 0x01, 0xD1, 0xAE } };
        indexed_type item2 { { 0x6F, 0x2D, 0x0F, 0x07, 0xC0, 0x00, 0x70, 0x02 } };
        indexed_type item3 { { 0x93, 0x28, 0x01, 0x80, 0xDE, 0x00, 0x55, 0x6B } };
        indexed_type item4 { { 0x2C, 0x33, 0x01, 0x00, 0xB8, 0x00, 0x1E, 0xAE } };
        constexpr size_t item_cnt = 4;
        const indexed_type items[item_cnt] { item1, item2, item3, item4 };
        const size_t item_cnt_stream = item_cnt / paths.size();
        const indexed_type expected_1[item_cnt_stream] { item4, item2 };
        const indexed_type expected_2[item_cnt_stream] { item3, item1 };
        const indexed_type *expected[paths.size()] { expected_1, expected_2 };

        index_radix_writer<indexed_type> idx(paths);
        for (size_t i = 0; i < item_cnt; ++i) {
            indexed_type &it = idx.writable(items[i].val[0]);
            it = items[i];
            idx.next();
        }
        idx.flush();

        for (size_t i = 0; i < paths.size(); ++i) {
            const auto &path = paths[i];
            ifstream is(path, ios::binary);
            indexed_type buf;
            for (size_t j = 0; j < item_cnt_stream; ++j) {
                is.read(reinterpret_cast<char *>(&buf), sizeof(buf));
                expect(is.fail() == false);
                expect(memcmp(&buf, &expected[i][j], sizeof(indexed_type)) == 0)
                    << "stream: " << i << " position: " << j
                    << " read: " << buffer(reinterpret_cast<const uint8_t *>(&buf), sizeof(buf))
                    << " expected: " << buffer(reinterpret_cast<const uint8_t *>(&expected[i][j]), sizeof(buf));
            }
            expect(is.eof() == false);
            is.read(reinterpret_cast<char *>(&buf), sizeof(buf));
            expect(is.eof() == true);
        }
        
    };
};
