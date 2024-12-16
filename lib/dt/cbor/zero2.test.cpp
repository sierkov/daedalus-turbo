/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cbor/encoder.hpp>
#include <dt/cbor/zero2.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cbor;
using namespace daedalus_turbo::cbor::zero2;

suite cbor_zero2_test = [] {
    "cbor::zero2"_test = [] {
        "data_raw"_test = [] {
            const auto data = uint8_vector::from_hex("18FFFFFFFFFFFF");
            const auto v = parse(data);
            test_same(uint8_vector::from_hex("18FF"), v.data_raw());
        };
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
            {
                const auto data = uint8_vector::from_hex("1B000000FFFFFFFFFF");
                const auto v = parse(data);
                expect(throws([&] { v.text(); }));
                expect(throws([&] { v.bytes(); }));
                expect(throws([&] { v.array(); }));
                expect(throws([&] { v.map(); }));
                expect(throws([&] { v.tag(); }));
                expect(throws([&] { v.simple(); }));
            }
        };
        "bytes"_test = [] {
            const auto data = uint8_vector::from_hex("43000102");
            {
                const auto v = parse(data);
                test_same(uint8_vector::from_hex("000102"), v.bytes());
            }
            {
                auto v = parse(data);
                uint8_vector res {};
                v.to_bytes(res);
                test_same(uint8_vector::from_hex("000102"), res);
            }
            {
                const auto v = parse(data);
                expect(throws([&] { v.uint(); }));
                expect(throws([&] { v.bigint(); }));
                expect(throws([&] { v.text(); }));
                expect(throws([&] { v.array(); }));
                expect(throws([&] { v.map(); }));
                expect(throws([&] { v.tag(); }));
                expect(throws([&] { v.simple(); }));
            }
        };
        "text"_test = [] {
            const auto data = uint8_vector::from_hex("63494A4B");
            {
                const auto v = parse(data);
                test_same(std::string { "IJK" }, v.text());
            }
            {
                auto v = parse(data);
                std::string res {};
                v.to_text(res);
                test_same(std::string { "IJK" }, res);
            }
            {
                const auto v = parse(data);
                expect(throws([&] { v.uint(); }));
                expect(throws([&] { v.bigint(); }));
                expect(throws([&] { v.bytes(); }));
                expect(throws([&] { v.array(); }));
                expect(throws([&] { v.map(); }));
                expect(throws([&] { v.tag(); }));
                expect(throws([&] { v.simple(); }));
            }
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
            {
                const auto data = uint8_vector::from_hex("FAF7F37868");
                const auto v = parse(data);
                expect(throws([&] { v.uint(); }));
                expect(throws([&] { v.bigint(); }));
                expect(throws([&] { v.text(); }));
                expect(throws([&] { v.bytes(); }));
                expect(throws([&] { v.array(); }));
                expect(throws([&] { v.map(); }));
                expect(throws([&] { v.tag(); }));
            }
        };
        "array indefinite"_test = [] {
            const auto data = uint8_vector::from_hex("9f0001ff");
            {
                const auto v = parse(data);
                test_same(v.type(), major_type::array);
                auto &it = v.array();
                expect(!it.done());
                {
                    auto v = it.read();
                    test_same(v.uint(), 0ULL);
                }
                {
                    auto v = it.read();
                    test_same(v.uint(), 1ULL);
                }
                expect(it.done());
                expect(throws([&]{ it.read(); }));
            }
            {
                const auto v = parse(data);
                expect(throws([&] { v.uint(); }));
                expect(throws([&] { v.bigint(); }));
                expect(throws([&] { v.text(); }));
                expect(throws([&] { v.bytes(); }));
                expect(throws([&] { v.float32(); }));
                expect(throws([&] { v.map(); }));
                expect(throws([&] { v.tag(); }));
                expect(throws([&] { v.simple(); }));
            }
        };
        "array"_test = [] {
            const auto data = uint8_vector::from_hex("820001");
            {
                const auto v = parse(data);
                test_same(v.type(), major_type::array);
                auto &it = v.array();
                test_same(v.special_uint(), 2ULL);
                expect(!it.done());
                {
                    auto v = it.read();
                    test_same(v.uint(), 0ULL);
                }
                {
                    auto v = it.read();
                    test_same(v.uint(), 1ULL);
                }
                expect(it.done());
                expect(throws([&]{ it.read(); }));
                expect(it.done());
            }
            {
                const auto v = parse(data);
                auto &it = v.array();
                it.skip(1);
                expect(!it.done());
                {
                    auto v = it.read();
                    test_same(v.uint(), 1ULL);
                }
            }
            // implicit consume
            {
                auto v = parse(data);
                test_same(3, v.data_raw().size());
            }
        };
        "map"_test = [] {
            const auto data = uint8_vector::from_hex("A10001");
            {
                const auto v = parse(data);
                test_same(v.type(), major_type::map);
                auto &it = v.map();
                test_same(v.special_uint(), 1ULL);
                expect(!it.done());
                {
                    auto key = it.read_key();
                    test_same(key.uint(), 0ULL);
                    auto val = it.read_val(key);
                    test_same(val.uint(), 1ULL);
                }
                expect(it.done());
                expect(throws([&]{ it.read_key(); }));
                expect(it.done());
            }
            {
                const auto v = parse(data);
                auto &it = v.map();
                expect(!it.done());
                it.skip(1);
                expect(it.done());
            }
            {
                const auto v = parse(data);
                expect(throws([&] { v.uint(); }));
                expect(throws([&] { v.bigint(); }));
                expect(throws([&] { v.text(); }));
                expect(throws([&] { v.bytes(); }));
                expect(throws([&] { v.float32(); }));
                expect(throws([&] { v.array(); }));
                expect(throws([&] { v.tag(); }));
                expect(throws([&] { v.simple(); }));
            }
            // implicit consume
            {
                auto v = parse(data);
                test_same(3, v.data_raw().size());
            }
        };
        "map indefinite"_test = [] {
            const auto data = uint8_vector::from_hex("BF0001FF");
            const auto v = parse(data);
            test_same(v.type(), major_type::map);
            auto &it = v.map();
            expect(!it.done());
            {
                auto key = it.read_key();
                test_same(key.uint(), 0ULL);
                auto val = it.read_val(key);
                test_same(val.uint(), 1ULL);
            }
            expect(it.done());
            expect(throws([&]{ it.read_key(); }));
        };
        "tag"_test = [] {
            {
                const auto data = uint8_vector::from_hex("C102");
                auto v1 = parse(data);
                test_same(v1.type(), major_type::tag);
                auto &kv1 = v1.tag();
                test_same(kv1.id(), 1ULL);
                test_same(kv1.read().uint(), 2ULL);
            }
            {
                const auto data = uint8_vector::from_hex("9fC200C201ff");
                auto v = parse(data);
                auto &it = v.array();
                test_same(0, it.read().tag().read().uint());
                test_same(1, it.read().tag().read().uint());
                expect(it.done());
            }
            const auto data = uint8_vector::from_hex("C29f0001ff");
            {
                auto v1 = parse(data);
                test_same(v1.type(), major_type::tag);
                auto &kv1 = v1.tag();
                test_same(kv1.id(), 2ULL);
                auto vv = kv1.read();
                test_same(vv.type(), major_type::array);
                auto &it = vv.array();
                expect(!it.done());
                {
                    auto v = it.read();
                    test_same(v.uint(), 0ULL);
                }
                {
                    auto v = it.read();
                    test_same(v.uint(), 1ULL);
                }
                expect(it.done());
            }
            // implicit consume
            {
                auto v1 = parse(data);
                test_same(5, v1.data_raw().size());
            }
            {
                const auto v = parse(data);
                expect(throws([&] { v.uint(); }));
                expect(throws([&] { v.bigint(); }));
                expect(throws([&] { v.text(); }));
                expect(throws([&] { v.bytes(); }));
                expect(throws([&] { v.float32(); }));
                expect(throws([&] { v.map(); }));
                expect(throws([&] { v.array(); }));
                expect(throws([&] { v.simple(); }));
            }
        };
        "simple"_test = [] {
            const auto data = uint8_vector::from_hex("FF");
            {
                decoder dec { data };
                expect(!dec.done());
                auto v = dec.read();
                test_same(v.simple(), special_val::s_break);
                dec.step(v);
                expect(dec.done());
            }
            {
                const auto v = parse(data);
                expect(throws([&] { v.uint(); }));
                expect(throws([&] { v.bigint(); }));
                expect(throws([&] { v.text(); }));
                expect(throws([&] { v.bytes(); }));
                expect(throws([&] { v.float32(); }));
                expect(throws([&] { v.tag(); }));
                expect(throws([&] { v.map(); }));
                expect(throws([&] { v.array(); }));
            }
        };
        "chunked_text"_test = [] {
            {
                cbor::encoder enc {};
                enc.text();
                enc.text("AB");
                enc.text("CD");
                enc.s_break();
                {
                    auto v = parse(enc.cbor());
                    std::string res {};
                    v.to_text(res);
                    test_same(std::string { "ABCD" }, res);
                    test_same(8, v.data_raw().size());
                }
                {
                    auto v = parse(enc.cbor());
                    expect(throws([&] { v.text(); }));
                }
                {
                    auto v = parse(enc.cbor());
                    uint8_vector res {};
                    expect(throws([&] { v.to_bytes(res); }));
                }
                // test the implicit consumption
                {
                    auto v = parse(enc.cbor());
                    test_same(8, v.data_raw().size());
                }
            }
            // to many chunks
            {
                cbor::encoder enc {};
                enc.text();
                for (size_t i = 0; i < 1025; ++i)
                    enc.text("A");
                enc.s_break();
                test_same(1025 * 2 + 2, enc.cbor().size());
                expect(throws([&] {
                    auto v = parse(enc.cbor());
                    std::string res {};
                    v.to_text(res);
                }));
            }
        };
        "chunked_bytes"_test = [] {
            {
                cbor::encoder enc {};
                enc.bytes();
                enc.bytes(uint8_vector::from_hex("0011"));
                enc.bytes(uint8_vector::from_hex("2233"));
                enc.s_break();
                {
                    auto v = parse(enc.cbor());
                    uint8_vector res {};
                    v.to_bytes(res);
                    test_same(uint8_vector::from_hex("00112233"), res);
                    test_same(8, v.data_raw().size());
                }
                {
                    auto v = parse(enc.cbor());
                    expect(throws([&] { v.bytes(); }));
                }
                {
                    auto v = parse(enc.cbor());
                    std::string res {};
                    expect(throws([&] { v.to_text(res); }));
                }
                // test the implicit consumption
                {
                    auto v = parse(enc.cbor());
                    test_same(8, v.data_raw().size());
                }
            }
            // to many chunks
            {
                cbor::encoder enc {};
                enc.bytes();
                for (size_t i = 0; i < 1025; ++i)
                    enc.bytes(uint8_vector::from_hex("00"));
                enc.s_break();
                test_same(1025 * 2 + 2, enc.cbor().size());
                expect(throws([&] {
                    auto v = parse(enc.cbor());
                    uint8_vector res {};
                    v.to_bytes(res);
                }));
            }
        };
        "bigint"_test = [] {
            {
                encoder enc {};
                cpp_int i = 1;
                i <<= 32;
                enc.bigint(i);
                auto v = parse(enc.cbor());
                test_same(i, v.bigint());
            }
            {
                encoder enc {};
                cpp_int i = 1;
                i <<= 32;
                i *= -1;
                enc.bigint(i);
                auto v = parse(enc.cbor());
                test_same(i, v.bigint());
            }
            {
                encoder enc {};
                cpp_int i = 1;
                i <<= 128;
                enc.bigint(i);
                auto v = parse(enc.cbor());
                test_same(i, v.bigint());
            }
            {
                encoder enc {};
                cpp_int i = 1;
                i <<= 128;
                i *= -1;
                enc.bigint(i);
                auto v = parse(enc.cbor());
                test_same(i, v.bigint());
            }
            {
                encoder enc {};
                enc.tag(259);
                enc.array(0);
                auto v = parse(enc.cbor());
                expect(throws([&] { v.bigint(); }));
            }
        };
        "extract"_test = [] {
            encoder enc {};
            enc.array(2)
                .array(2)
                    .uint(0)
                    .uint(1)
                .array(2)
                    .uint(2)
                    .uint(3);
            {
                auto v = parse(enc.cbor());
                test_same(3, extract(v, std::initializer_list<size_t> { 1, 1 }).uint());
            }
            {
                auto v = parse(enc.cbor());
                expect(throws([&] { extract(v, std::initializer_list<size_t> { 2, 1 }); }));
            }
            {
                auto v = parse(enc.cbor());
                expect(throws([&] { extract(v, std::initializer_list<size_t> { 1, 2 }); }));
            }
            {
                auto v = parse(enc.cbor());
                expect(throws([&] { extract(v, std::initializer_list<size_t> { 1, 1, 1 }); }));
            }
        };
        "indefinite"_test = [] {
            for (const auto &[hex, exp]: std::initializer_list<std::pair<std::string_view, bool>> {
                { "64494A4B4C", false },
                { "7F6149614AFF", true },
                { "420011", false },
                { "5F4149414AFF", true },
                { "A10001", false },
                { "BF0001FF", true },
                { "9f0001ff" , true },
                { "820001" , false }
            }) {
                const auto data = uint8_vector::from_hex(hex);
                test_same(exp, parse(data).indefinite());
            }
            for (const auto hex: std::initializer_list<std::string_view> {
                { "00" },
                { "FF" }
            }) {
                const auto data = uint8_vector::from_hex(hex);
                expect(throws([&]{ parse(data).indefinite(); }));
            }
        };
        "equality"_test = [] {
            auto a = uint8_vector::from_hex("00");
            auto b = uint8_vector::from_hex("00");
            auto c = uint8_vector::from_hex("01");
            expect(parse(a) == parse(b));
            expect(parse(a) != parse(c));
            expect(parse(b) != parse(c));
        };
        "order"_test = [] {
            auto a = uint8_vector::from_hex("00FF");
            auto b = uint8_vector::from_hex("0102");
            expect(parse(a) < parse(b));
            expect(!(parse(a) < parse(a)));
            expect(!(parse(b) < parse(a)));
            expect(!(parse(b) < parse(b)));
        };
        "stringify"_test = [] {
            for (const auto &[hex, exp]: std::initializer_list<std::pair<std::string_view, std::string_view>> {
                { "3903e7", "I -1000" },
                { "64494A4B4C", "T 'IJKL'" },
                { "7F6149614AFF", "T indefinite 'IJ'" },
                { "420011", "B #0011" },
                { "5F4149414AFF", "B indefinite #494A ('IJ')" },
                { "A10001", "{(items: 1)\n    I 0: I 1\n}" },
                { "A3000102030405", "{(items: 3)}" },
                { "BF0001FF", "{(items: indefinite)\n    I 0: I 1\n}" },
                { "C29f0001ff" , "TAG 2 [(items: indefinite)\n    #0: I 0\n    #1: I 1\n]" },
                { "C2820001" , "TAG 2 [(items: 2)\n    #0: I 0\n    #1: I 1\n]" },
                { "C283000102" , "TAG 2 [(items: 3)]" }
            }) {
                const auto data = uint8_vector::from_hex(hex);
                test_same(parse(data).stringify(2), exp);
            }
        };
    };
};