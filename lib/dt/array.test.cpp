/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/array.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite array_suite = [] {
    "array"_test = [] {
        
        "initialize empty"_test = [] {
            array<uint8_t, 4> a {};
            expect(a.size() == 4);
            for (auto v: a)
                expect(v == 0) << v;
        };

        "initialize"_test = [] {
            array<uint8_t, 4> a { 1, 2, 3, 4 };
            expect(a.size() == 4);
            expect(a[0] == 1);
            expect(a[1] == 2);
            expect(a[2] == 3);
            expect(a[3] == 4);
        };

        "initialize size_t"_test = [] {
            array<size_t, 10> a { 1, 5, 1, 1, 1, 3, 1, 1, 4, 0 };
            expect(a.size() == 10);
            expect(a[0] == 1);
            expect(a[1] == 5);
            expect(a[2] == 1);
            expect(a[3] == 1);
            expect(a[4] == 1);
            expect(a[5] == 3);
            expect(a[6] == 1);
            expect(a[7] == 1);
            expect(a[8] == 4);
            expect(a[9] == 0);
        };

        "construct_span"_test = [] {
            array<uint8_t, 4> a { 1, 2, 3, 4 };
            array<uint8_t, 4> b { 9, 8, 7, 6 };
            array<uint8_t, 4> c { std::span(b) };
            expect(c.size() == 4);
            expect(c[0] == 9);
            expect(c[1] == 8);
            expect(c[2] == 7);
            expect(c[3] == 6);
        };

        "construct size_t span"_test = [] {
            std::array<size_t, 10> tmp { 1, 5, 1, 1, 1, 3, 1, 1, 4, 0 };
            array<size_t, 10> a { std::span(tmp) };
            expect(a.size() == 10);
            expect(a[0] == 1);
            expect(a[1] == 5);
            expect(a[2] == 1);
            expect(a[3] == 1);
            expect(a[4] == 1);
            expect(a[5] == 3);
            expect(a[6] == 1);
            expect(a[7] == 1);
            expect(a[8] == 4);
            expect(a[9] == 0);
        };

        "construct_string_view"_test = [] {
            using namespace std::literals;
            array<uint8_t, 4> a { "\x01\x02\x03\x04"sv };
            expect(a.size() == 4);
            expect(a[0] == 1);
            expect(a[1] == 2);
            expect(a[2] == 3);
            expect(a[3] == 4);
        };

        "assign_span"_test = [] {
            array<uint8_t, 4> a { 1, 2, 3, 4 };
            array<uint8_t, 4> b { 9, 8, 7, 6 };
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

        "assign size_t span"_test = [] {
            std::array<size_t, 10> tmp { 1, 5, 1, 1, 1, 3, 1, 1, 4, 0 };
            array<size_t, 10> a {};
            expect(a.size() == 10);
            for (size_t i = 0; i < a.size(); ++i)
                expect(a[i] == 0);
            a = std::span(tmp);
            expect(a[0] == 1);
            expect(a[1] == 5);
            expect(a[2] == 1);
            expect(a[3] == 1);
            expect(a[4] == 1);
            expect(a[5] == 3);
            expect(a[6] == 1);
            expect(a[7] == 1);
            expect(a[8] == 4);
            expect(a[9] == 0);
        };

        "assign_string_view"_test = [] {
            using namespace std::literals;
            array<uint8_t, 4> a {};
            expect(a.size() == 4);
            for (const auto v: a) expect(v == 0);
            a = "\x01\x02\x03\x04"sv;
            expect(a[0] == 1);
            expect(a[1] == 2);
            expect(a[2] == 3);
            expect(a[3] == 4);
        };

        "uint8_t array can be formatted"_test = [] {
            auto data = array<uint8_t, 4>::from_hex("f0e1d2c3");
            expect(fmt::format("{}", data) == "F0E1D2C3");
        };
    };  
};