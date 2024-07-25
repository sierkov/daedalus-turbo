/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cbor/zero.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cbor;
using namespace daedalus_turbo::cbor::zero;

suite cbor_turbo_test = [] {
    "cbor::turbo"_test = [] {
        "uint"_test = [] {
            {
                const auto data = uint8_vector::from_hex("18FF");
                const auto v = parse(data);
                test_same(v.uint(), 0xFFULL);
            }
            {
                const auto data = uint8_vector::from_hex("19FFFF");
                const auto v = parse(data);
                test_same(v.uint(), 0xFFFFULL);
            }
            {
                const auto data = uint8_vector::from_hex("1AFFFFFFFF");
                const auto v = parse(data);
                test_same(v.uint(), 0xFFFFFFFFULL);
            }
            {
                const auto data = uint8_vector::from_hex("1B000000FFFFFFFFFF");
                const auto v = parse(data);
                test_same(v.uint(), 0xFFFFFFFFFFULL);
            }
        };
        "bytes"_test = [] {
            const auto data = uint8_vector::from_hex("43000102");
            const auto v = parse(data);
            test_same(v.bytes(),  uint8_vector::from_hex("000102").span());
        };
        "text"_test = [] {
            const auto data = uint8_vector::from_hex("63000102");
            const auto v = parse(data);
            test_same(v.text(), uint8_vector::from_hex("000102").str());
        };
        "float32"_test = [] {
            {
                const auto data = uint8_vector::from_hex("FA21B62E17");
                const auto v = parse(data);
                test_same(v.float32(), 123.45e-20F);
            }
            {
                const auto data = uint8_vector::from_hex("FAF7F37868");
                const auto v = parse(data);
                test_same(v.float32(), -9876.33e30F);
            }
        };
        "array indefinite"_test = [] {
            const auto data = uint8_vector::from_hex("9f0001ff");
            const auto v = parse(data);
            test_same(v.type(), major_type::array);
            test_same(v.size(), 2);
            auto it = v.array();
            expect(!it.done());
            test_same(it.next().uint(), 0ULL);
            test_same(it.next().uint(), 1ULL);
            expect(it.done());
            expect(throws([&]{ it.next(); }));
            test_same(v.at(0).uint(), 0ULL);
            test_same(v.at(1).uint(), 1ULL);
        };
        "array"_test = [] {
            const auto data = uint8_vector::from_hex("820001");
            const auto v = parse(data);
            test_same(v.type(), major_type::array);
            test_same(v.size(), 2ULL);
            auto it = v.array();
            expect(!it.done());
            test_same(it.next().uint(), 0ULL);
            test_same(it.next().uint(), 1ULL);
            expect(it.done());
            expect(throws([&]{ it.next(); }));
            test_same(v.at(0).uint(), 0ULL);
            test_same(v.at(1).uint(), 1ULL);
        };
        "map"_test = [] {
            const auto data = uint8_vector::from_hex("A10001");
            const auto v = parse(data);
            test_same(v.type(), major_type::map);
            test_same(v.size(), 1ULL);
            auto it = v.map();
            expect(!it.done());
            const auto [key, val] = it.next();
            test_same(key.uint(), 0ULL);
            test_same(val.uint(), 1ULL);
            expect(it.done());
            expect(throws([&]{ it.next(); }));
        };
        "map indefinite"_test = [] {
            const auto data = uint8_vector::from_hex("BF0001FF");
            const auto v = parse(data);
            test_same(v.type(), major_type::map);
            test_same(v.size(), 1ULL);
            auto it = v.map();
            expect(!it.done());
            const auto [key, val] = it.next();
            test_same(key.uint(), 0ULL);
            test_same(val.uint(), 1ULL);
            expect(it.done());
            expect(throws([&]{ it.next(); }));
        };
        "tag"_test = [] {
            {
                const auto data = uint8_vector::from_hex("C102");
                const auto v1 = parse(data);
                test_same(v1.type(), major_type::tag);
                const auto kv1 = v1.tag();
                test_same(kv1.first, 1ULL);
                test_same(kv1.second.uint(), 2ULL);
            }
            {
                const auto data = uint8_vector::from_hex("C29f0001ff");
                const auto v1 = parse(data);
                test_same(v1.type(), major_type::tag);
                const auto kv1 = v1.tag();
                test_same(kv1.first, 2ULL);
                test_same(kv1.second.type(), major_type::array);
                auto it = kv1.second.array();
                expect(!it.done());
                test_same(it.next().uint(), 0ULL);
                test_same(it.next().uint(), 1ULL);
                expect(it.done());
            }
        };
        "simple"_test = [] {
            const auto data = uint8_vector::from_hex("FF");
            decoder dec { data };
            test_same(dec.read().simple(), special_val::s_break);
        };
        "ordering"_test = [] {
            const auto k1 = uint8_vector::from_hex("42534E");
            const auto v1 = uint8_vector::from_hex("00");
            const auto k2 = uint8_vector::from_hex("424554");
            const auto v2 = uint8_vector::from_hex("01");
            map<value, value> m {};
            m.emplace(parse(k1), parse(v1));
            m.emplace(parse(k2), parse(v2));
            expect(m.begin()->first.raw_span() == k2);
            expect(m.rbegin()->first.raw_span() == k1);
        };
        "stringify"_test = [] {
            for (const auto &[hex, exp]: std::initializer_list<std::pair<std::string_view, std::string_view>> {
                { "BF0001FF", "{(items: 1, indefinite)\n    I 0: I 1\n}" },
                { "C29f0001ff" , "TAG 2 [(items: 2, indefinite)\n    #0: I 0\n    #1: I 1\n]" }
            }) {
                const auto data = uint8_vector::from_hex(hex);
                test_same(parse(data).stringify(), exp);
            }
        };
    };
};