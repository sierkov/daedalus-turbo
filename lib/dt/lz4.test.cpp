/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <string_view>
#include <boost/ut.hpp>
#include <dt/lz4.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

suite lz4_suite = [] {
    const string_view test_data = "some text\0\x11\xFE"sv;
    bin_string orig, compressed;
    orig.resize(test_data.size());
    memcpy(orig.data(), test_data.data(), test_data.size());

    "compress"_test = [&] {
        lz4_compress(compressed, orig);
        expect(compressed.size() > 8_u);
    };

    "decompress"_test = [&] {
        bin_string out;
        lz4_decompress(out, compressed);
        expect(out == orig);
    };
};
