/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <string_view>
#include <boost/ut.hpp>
#include <dt/zstd.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

suite zstd_suite = [] {
    "zstd"_test = [] {
        const string_view test_data = "some text\0\x11\xFE"sv;
        uint8_vector orig, compressed;
        orig.resize(test_data.size());
        memcpy(orig.data(), test_data.data(), test_data.size());

        "compress"_test = [&] {
            zstd_compress(compressed, orig);
            expect(compressed.size() > 8_u);
        };

        "decompress"_test = [&] {
            uint8_vector out;
            zstd_decompress(out, compressed);
            expect(out == orig);
        };
    };
    
};
