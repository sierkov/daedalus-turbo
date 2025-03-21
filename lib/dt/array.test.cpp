/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/test.hpp>
#include <dt/array.hpp>

using namespace daedalus_turbo;

suite array_suite = [] {
    using daedalus_turbo::array;
    "array"_test = [] {
        "initialize empty"_test = [] {
            byte_array<4> a {};
            expect(a.size() == 4);
            for (auto v: a)
                expect(v == 0) << v;
        };

        "initialize"_test = [] {
            byte_array<4> a { 1, 2, 3, 4 };
            expect(a.size() == 4);
            expect(a[0] == 1);
            expect(a[1] == 2);
            expect(a[2] == 3);
            expect(a[3] == 4);
        };

        "construct_span"_test = [] {
            byte_array<4> a { 1, 2, 3, 4 };
            byte_array<4> b { 9, 8, 7, 6 };
            byte_array<4> c { std::span(b) };
            expect(c.size() == 4);
            expect(c[0] == 9);
            expect(c[1] == 8);
            expect(c[2] == 7);
            expect(c[3] == 6);
        };

        "construct_string_view"_test = [] {
            using namespace std::literals;
            byte_array<4> a { "\x01\x02\x03\x04"sv };
            expect(a.size() == 4);
            expect(a[0] == 1);
            expect(a[1] == 2);
            expect(a[2] == 3);
            expect(a[3] == 4);
        };

        "assign_span"_test = [] {
            byte_array<4> a { 1, 2, 3, 4 };
            byte_array<4> b { 9, 8, 7, 6 };
            expect(a.size() == 4);
            expect(a[0] == 1);
            expect(a[1] == 2);
            expect(a[2] == 3);
            expect(a[3] == 4);
            a = std::span(b);
            expect(a[0] == 9);
            expect(a[1] == 8);
            expect(a[2] == 7);
            expect(a[3] == 6);
        };

        "assign_string_view"_test = [] {
            using namespace std::literals;
            byte_array<4> a {};
            expect(a.size() == 4);
            for (const auto v: a) expect(v == 0);
            a = "\x01\x02\x03\x04"sv;
            expect(a[0] == 1);
            expect(a[1] == 2);
            expect(a[2] == 3);
            expect(a[3] == 4);
        };

        "uint8_t array can be formatted"_test = [] {
            auto data = byte_array<4>::from_hex("f0e1d2c3");
            expect(fmt::format("{}", data) == "F0E1D2C3");
        };

        "secure_array"_test = [] {
            const auto empty = byte_array<4>::from_hex("00000000");
            const auto filled = byte_array<4>::from_hex("DEADBEAF");
            byte_array<4> data {};
            {
                const secure_store sec { data };
                data = filled;
                test_same(true, memcmp(data.data(), filled.data(), filled.size()) == 0);
            }
            test_same(false, memcmp(data.data(), filled.data(), filled.size()) == 0);
            test_same(true, memcmp(data.data(), empty.data(), empty.size()) == 0);
        };
    };  
};