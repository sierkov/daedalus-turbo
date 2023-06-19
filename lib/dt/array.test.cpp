/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <boost/ut.hpp>

#include <dt/array.hpp>

using namespace boost::ut;
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
    };  
};
