/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/narrow-cast.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite narrow_cast_suite = [] {
    "narrow_cast"_test = [] {
        test_same(uint8_t { 24 }, narrow_cast<uint8_t>(uint64_t { 24 }));
        test_same(int8_t { 24 }, narrow_cast<int8_t>(int64_t { 24 }));
        test_same(int8_t { -24 }, narrow_cast<int8_t>(int64_t { -24 }));
        test_same(uint8_t { 255 }, narrow_cast<uint8_t>(int16_t { 255 }));
        test_same(int64_t { 205665 }, narrow_cast<int64_t>(uint64_t { 205665 }));
        test_same(uint64_t { std::numeric_limits<int64_t>::max() },
            narrow_cast<uint64_t>(std::numeric_limits<int64_t>::max()));
        expect(throws([&] { narrow_cast<uint8_t>(256); }));
        expect(throws([&] { narrow_cast<uint8_t>(256); }));
        expect(throws([&] { narrow_cast<int8_t>(-129); }));
        expect(throws([&] { narrow_cast<uint64_t>(int64_t { -250 }); }));
        expect(throws([&] { narrow_cast<int8_t>(int64_t { -250 }); }));
        expect(throws([&] { narrow_cast<int8_t>(int64_t { 250 }); }));
        expect(throws([&] { narrow_cast<int64_t>(std::numeric_limits<uint64_t>::max()); }));
    };
};