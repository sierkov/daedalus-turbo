/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <string_view>

#include <boost/ut.hpp>

#include <dt/lz4.hpp>

using namespace std::literals;
using namespace boost::ut;
using namespace daedalus_turbo;

suite lz4_suite = [] {
    "lz4"_test = [] {
        const std::string_view test_data = "some text\0\x11\xFE"sv;
        uint8_vector orig, compressed;
        orig.resize(test_data.size());
        memcpy(orig.data(), test_data.data(), test_data.size());

        "compress"_test = [&] {
            lz4_compress(compressed, orig);
            expect(compressed.size() > 8_u);
        };

        "decompress"_test = [&] {
            uint8_vector out;
            lz4_decompress(out, compressed);
            expect(out == orig);
        };
    };
    
};
