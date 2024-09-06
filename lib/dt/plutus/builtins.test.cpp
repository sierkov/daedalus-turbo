/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/plutus/builtins.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::plutus;

suite plutus_builtins_suite = [] {
    "plutus::builtins"_test = [] {
        "add_integer"_test = [] {
            expect(builtins::add_integer(term::make_int(2), term::make_int(3)) == term::make_int(5));
        };
        "subtract_integer"_test = [] {
            expect(builtins::subtract_integer(term::make_int(-5), term::make_int(-15)) == term::make_int(10));
        };
        "multiply_integer"_test = [] {
            expect(builtins::multiply_integer(term::make_int(-5), term::make_int(-5)) == term::make_int(25));
        };
        "divide_integer"_test = [] {
            expect(builtins::divide_integer(term::make_int(5), term::make_int(3)) == term::make_int(1));
            {
                const auto res = builtins::divide_integer(term::make_int(-5), term::make_int(3));
                expect(res == term::make_int(-2)) << fmt::format("{}", res);
            }
            {
                const auto res = builtins::divide_integer(term::make_int(-5), term::make_int(-3));
                expect(res == term::make_int(1)) << fmt::format("{}", res);
            }
            expect(builtins::divide_integer(term::make_int(5), term::make_int(-3)) == term::make_int(-2));
            expect(throws([] { builtins::divide_integer(term::make_int(3), term::make_int(0)); }));
        };
        "quotient_integer"_test = [] {
            expect(builtins::quotient_integer(term::make_int(5), term::make_int(3)) == term::make_int(1));
            expect(builtins::quotient_integer(term::make_int(-5), term::make_int(3)) == term::make_int(-1));
            expect(builtins::quotient_integer(term::make_int(-5), term::make_int(-3)) == term::make_int(1));
            expect(builtins::quotient_integer(term::make_int(5), term::make_int(-3)) == term::make_int(-1));
            expect(throws([] { builtins::quotient_integer(term::make_int(3), term::make_int(0)); }));
        };
        "mod_integer"_test = [] {
            expect(builtins::mod_integer(term::make_int(5), term::make_int(3)) == term::make_int(2));
            expect(builtins::mod_integer(term::make_int(-5), term::make_int(3)) == term::make_int(1));
            expect(builtins::mod_integer(term::make_int(-5), term::make_int(-3)) == term::make_int(-2));
            expect(builtins::mod_integer(term::make_int(5), term::make_int(-3)) == term::make_int(-1));
            expect(throws([] { builtins::mod_integer(term::make_int(3), term::make_int(0)); }));
        };
        "remainder_integer"_test = [] {
            expect(builtins::remainder_integer(term::make_int(5), term::make_int(3)) == term::make_int(2));
            expect(builtins::remainder_integer(term::make_int(-5), term::make_int(3)) == term::make_int(-2));
            expect(builtins::remainder_integer(term::make_int(-5), term::make_int(-3)) == term::make_int(-2));
            expect(builtins::remainder_integer(term::make_int(5), term::make_int(-3)) == term::make_int(2));
            expect(throws([] { builtins::remainder_integer(term::make_int(3), term::make_int(0)); }));
        };
        "equals_integer"_test = [] {
            expect(builtins::equals_integer(term::make_int(5), term::make_int(5)).as_bool());
            expect(!builtins::equals_integer(term::make_int(5), term::make_int(-5)).as_bool());
            expect(builtins::equals_integer(term::make_int(-5), term::make_int(-5)).as_bool());
            expect(!builtins::equals_integer(term::make_int(-5), term::make_int(5)).as_bool());
        };
        "less_than_integer"_test = [] {
            expect(builtins::less_than_integer(term::make_int(-5), term::make_int(5)).as_bool());
            expect(!builtins::less_than_integer(term::make_int(5), term::make_int(-5)).as_bool());
            expect(!builtins::less_than_integer(term::make_int(5), term::make_int(5)).as_bool());
        };
        "less_than_equals_integer"_test = [] {
            expect(builtins::less_than_equals_integer(term::make_int(-5), term::make_int(5)).as_bool());
            expect(!builtins::less_than_equals_integer(term::make_int(5), term::make_int(-5)).as_bool());
            expect(builtins::less_than_equals_integer(term::make_int(5), term::make_int(5)).as_bool());
        };
        "less_than_equals_byte_string"_test = [] {
            expect(builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("")), term::make_bstr(uint8_vector::from_hex(""))).as_bool());
            expect(builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("")), term::make_bstr(uint8_vector::from_hex("AA"))).as_bool());
            expect(!builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("AA")), term::make_bstr(uint8_vector::from_hex(""))).as_bool());
            expect(builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("AA")), term::make_bstr(uint8_vector::from_hex("AA"))).as_bool());
            expect(builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("AABB")), term::make_bstr(uint8_vector::from_hex("BBAA"))).as_bool());
            expect(!builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("BBAA")), term::make_bstr(uint8_vector::from_hex("AABB"))).as_bool());
            expect(builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("AABB")), term::make_bstr(uint8_vector::from_hex("AABBCC"))).as_bool());
        };
        "append_byte_string"_test = [] {
            expect(builtins::append_byte_string(term::make_bstr(uint8_vector::from_hex("")),
                    term::make_bstr(uint8_vector::from_hex("AA"))).as_bstr() == uint8_vector::from_hex("AA"));
            expect(builtins::append_byte_string(term::make_bstr(uint8_vector::from_hex("AA")),
                    term::make_bstr(uint8_vector::from_hex(""))).as_bstr() == uint8_vector::from_hex("AA"));
            expect(builtins::append_byte_string(term::make_bstr(uint8_vector::from_hex("11")),
                    term::make_bstr(uint8_vector::from_hex("2233"))).as_bstr() == uint8_vector::from_hex("112233"));
        };
        "cons_byte_string"_test = [] {
            expect(builtins::cons_byte_string(term::make_int(0x41),
                    term::make_bstr(uint8_vector::from_hex("42"))).as_bstr() == uint8_vector::from_hex("4142"));
            expect(builtins::cons_byte_string(term::make_int(0x42),
                    term::make_bstr(uint8_vector::from_hex(""))).as_bstr() == uint8_vector::from_hex("42"));
            expect(throws([] { builtins::cons_byte_string(term::make_int(-1), term::make_bstr(uint8_vector::from_hex(""))); }));
        };
        "slice_byte_string"_test = [] {
            expect(builtins::slice_byte_string(term::make_int(-10), term::make_int(2),
                term::make_bstr(uint8_vector::from_hex("0011223344"))).as_bstr() == uint8_vector::from_hex("0011"));
            expect(builtins::slice_byte_string(term::make_int(2), term::make_int(-1),
                term::make_bstr(uint8_vector::from_hex("0011223344"))).as_bstr() == uint8_vector::from_hex(""));
            expect(builtins::slice_byte_string(term::make_int(2), term::make_int(10),
                term::make_bstr(uint8_vector::from_hex("0011223344"))).as_bstr() == uint8_vector::from_hex("223344"));
            expect(builtins::slice_byte_string(term::make_int(20), term::make_int(10),
                                               term::make_bstr(uint8_vector::from_hex("0011223344"))).as_bstr() == uint8_vector::from_hex(""));
        };
        "length_of_byte_string"_test = [] {
            expect(builtins::length_of_byte_string(term::make_bstr(uint8_vector::from_hex(""))).as_int() == 0);
            expect(builtins::length_of_byte_string(term::make_bstr(uint8_vector::from_hex("0011223344"))).as_int() == 5);
        };
        "index_byte_string"_test = [] {
            expect(builtins::index_byte_string(term::make_bstr(uint8_vector::from_hex("0011223344")), term::make_int(0)).as_int() == 0x00);
            expect(builtins::index_byte_string(term::make_bstr(uint8_vector::from_hex("0011223344")), term::make_int(2)).as_int() == 0x22);
            expect(builtins::index_byte_string(term::make_bstr(uint8_vector::from_hex("0011223344")), term::make_int(4)).as_int() == 0x44);
            expect(throws([] { builtins::index_byte_string(term::make_bstr(uint8_vector::from_hex("0011223344")), term::make_int(-1)); }));
            expect(throws([] { builtins::index_byte_string(term::make_bstr(uint8_vector::from_hex("0011223344")), term::make_int(5)); }));
            expect(throws([] { builtins::index_byte_string(term::make_bstr(uint8_vector::from_hex("0011223344")), term::make_int(cpp_int { std::numeric_limits<size_t>::max() } + 1)); }));
        };
        "equals_byte_string"_test = [] {
            expect(builtins::equals_byte_string(term::make_bstr(uint8_vector::from_hex("")), term::make_bstr(uint8_vector::from_hex(""))).as_bool());
            expect(!builtins::equals_byte_string(term::make_bstr(uint8_vector::from_hex("")), term::make_bstr(uint8_vector::from_hex("AA"))).as_bool());
            expect(!builtins::equals_byte_string(term::make_bstr(uint8_vector::from_hex("BB")), term::make_bstr(uint8_vector::from_hex(""))).as_bool());
            expect(builtins::equals_byte_string(term::make_bstr(uint8_vector::from_hex("AABB")), term::make_bstr(uint8_vector::from_hex("AABB"))).as_bool());
            expect(!builtins::equals_byte_string(term::make_bstr(uint8_vector::from_hex("AABB")), term::make_bstr(uint8_vector::from_hex("AABBCC"))).as_bool());
        };
        "less_than_byte_string"_test = [] {
            expect(builtins::less_than_byte_string(term::make_bstr(uint8_vector::from_hex("")), term::make_bstr(uint8_vector::from_hex("AA"))).as_bool());
            expect(!builtins::less_than_byte_string(term::make_bstr(uint8_vector::from_hex("")), term::make_bstr(uint8_vector::from_hex(""))).as_bool());
            expect(!builtins::less_than_byte_string(term::make_bstr(uint8_vector::from_hex("AA")), term::make_bstr(uint8_vector::from_hex("AA"))).as_bool());
            expect(builtins::less_than_byte_string(term::make_bstr(uint8_vector::from_hex("AA")), term::make_bstr(uint8_vector::from_hex("AABB"))).as_bool());
        };
        "less_than_equals_byte_string"_test = [] {
            expect(builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("")), term::make_bstr(uint8_vector::from_hex("AA"))).as_bool());
            expect(!builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("AA")), term::make_bstr(uint8_vector::from_hex(""))).as_bool());
            expect(builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("")), term::make_bstr(uint8_vector::from_hex(""))).as_bool());
            expect(builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("AA")), term::make_bstr(uint8_vector::from_hex("AA"))).as_bool());
            expect(builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("AA")), term::make_bstr(uint8_vector::from_hex("AABB"))).as_bool());
            expect(!builtins::less_than_equals_byte_string(term::make_bstr(uint8_vector::from_hex("AABB")), term::make_bstr(uint8_vector::from_hex("AA"))).as_bool());
        };
        "sha2_256"_test = [] {
            {
                const auto exp = term::make_bstr(sha2::hash_256::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
                const auto act = builtins::sha2_256(term::make_bstr(uint8_vector::from_hex("")));
                expect(exp == act) <<fmt::format("{}", act);
            }
            {
                const auto exp = term::make_bstr(sha2::hash_256::from_hex("038051e9c324393bd1ca1978dd0952c2aa3742ca4f1bd5cd4611cea83892d382"));
                const auto act = builtins::sha2_256(term::make_bstr(uint8_vector::from_hex("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e")));
                expect(exp == act) <<fmt::format("{}", act);
            }
        };
        "sha3_256"_test = [] {
            {
                const auto exp = term::make_bstr(sha3::hash_256::from_hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"));
                const auto act = builtins::sha3_256(term::make_bstr(uint8_vector::from_hex("")));
                expect(exp == act) <<fmt::format("{}", act);
            }
            {
                const auto exp = term::make_bstr(sha3::hash_256::from_hex("33BE80DD552BB39D0AC8212313AE729C26EDE50613491E5ABFB57686ECF037F5"));
                const auto act = builtins::sha3_256(term::make_bstr(uint8_vector::from_hex("de188941a3375d3a8a061e67576e926dc71a7fa3f0cceb97452b4d3227965f9ea8cc75076d9fb9c5417aa5cb30fc22198b34982dbb629e")));
                expect(exp == act) <<fmt::format("{}", act);
            }
        };
        "blake2b_256"_test = [] {
            {
                const auto exp = term::make_bstr(blake2b_256_hash::from_hex("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"));
                const auto act = builtins::blake2b_256(term::make_bstr(uint8_vector::from_hex("")));
                expect(exp == act) <<fmt::format("{}", act);
            }
            {
                const auto exp = term::make_bstr(blake2b_256_hash::from_hex("E1EAE5A8ADAE652EC9AF9677346A9D60ECED61E3A0A69BFACF518DB31F86E36B"));
                const auto act = builtins::blake2b_256(term::make_bstr(uint8_vector::from_hex("00010203")));
                expect(exp == act) <<fmt::format("{}", act);
            }
        };
        "verify_ed25519_signature"_test = [] {
            static const ed25519::vkey vk {
                    0xe5, 0x2e, 0x09, 0xb2, 0xd3, 0x76, 0x3c, 0x57, 0x00, 0xd5, 0x41, 0xed, 0x9b, 0x88, 0xbe, 0xbd,
                    0xf8, 0x5b, 0x4a, 0x41, 0xd5, 0x42, 0x1a, 0xf1, 0x88, 0x85, 0x46, 0x98, 0x10, 0xf3, 0x17, 0xf7 };
            static const ed25519::signature sig {
                    0xa0, 0xdb, 0x79, 0x88, 0x7b, 0xcb, 0xb9, 0x2e, 0xe9, 0xcf, 0xe9, 0x0e, 0x83, 0x2c, 0x75, 0xab,
                    0xdb, 0xcb, 0xe7, 0x10, 0xb6, 0x29, 0x76, 0x55, 0x35, 0x59, 0x11, 0x33, 0xb4, 0xf2, 0xb6, 0xe6,
                    0xad, 0xfa, 0xb9, 0x33, 0xa8, 0x96, 0xda, 0x75, 0xf2, 0xcd, 0x5d, 0xb3, 0xa3, 0x35, 0x4a, 0x27,
                    0x3d, 0x3e, 0x37, 0xc7, 0x28, 0xca, 0x98, 0x07, 0x53, 0x8d, 0x83, 0x8f, 0xef, 0xbb, 0x2f, 0x00 };
            static const std::array<uint8_t, 84> msg {
                    0xa3, 0x00, 0x81, 0x82, 0x58, 0x20, 0xc1, 0xa1, 0xff, 0x8e, 0x54, 0x99, 0xc3, 0x9f, 0xfa, 0x4c,
                    0x70, 0x67, 0x43, 0x78, 0x5e, 0x62, 0x17, 0xa3, 0x3d, 0xf4, 0x8c, 0xef, 0x73, 0x42, 0xd0, 0xc4,
                    0x52, 0x60, 0x51, 0x58, 0x50, 0xa1, 0x00, 0x01, 0x81, 0x82, 0x58, 0x1d, 0x61, 0xc2, 0x6a, 0xc0,
                    0x99, 0x31, 0xf2, 0xff, 0x67, 0x58, 0x57, 0x30, 0x9b, 0xe6, 0xea, 0xf2, 0xd4, 0xbc, 0x18, 0xd2,
                    0xdd, 0x33, 0xf5, 0x29, 0x0f, 0xc3, 0xa2, 0xad, 0xd1, 0x1a, 0x01, 0x54, 0x45, 0x60, 0x02, 0x1a,
                    0x00, 0x0a, 0xae, 0x60 };
            const auto hash = blake2b<blake2b_256_hash>(std::span<const uint8_t>(msg));
            expect(builtins::verify_ed25519_signature(term::make_bstr(sig), term::make_bstr(hash), term::make_bstr(vk)).as_bool());
            expect(!builtins::verify_ed25519_signature(term::make_bstr(sig), term::make_bstr(msg), term::make_bstr(vk)).as_bool());
        };
        "trace"_test = [] {
            const auto main_term = term::make_int(22);
            expect(builtins::trace(term::make_str("trace msg"), main_term) == main_term);
        };
        "if_then_else"_test = [] {
            const auto val1 = term::make_int(12);
            const auto val2 = term::make_str("Hello");
            {
                const auto &res = builtins::if_then_else(term::make_bool(true), val1, val2);
                expect(&val1 == &res) << fmt::format("{}", res);
            }
            {
                const auto &res = builtins::if_then_else(term::make_bool(false), val1, val2);
                expect(&val2 == &res) << fmt::format("{}", res);
            }
            {
                expect(throws([&] { builtins::if_then_else(term { term_tag::error }, val1, val2); }));
            }
            {
                expect(throws([&] { builtins::if_then_else(term::make_int(22), val1, val2); }));
            }
        };
        "append_string"_test = [] {
            expect(builtins::append_string(term::make_str("Hello"), term::make_str(" world!")).as_str() == "Hello world!");
            expect(builtins::append_string(term::make_str(""), term::make_str("AAA")).as_str() == "AAA");
            expect(builtins::append_string(term::make_str("AAA"), term::make_str("")).as_str() == "AAA");
        };
        "equals_string"_test = [] {
            expect(builtins::equals_string(term::make_str("hello"), term::make_str("hello")).as_bool());
            expect(!builtins::equals_string(term::make_str("hello"), term::make_str("Hello")).as_bool());
            expect(builtins::equals_string(term::make_str(""), term::make_str("")).as_bool());
            expect(!builtins::equals_string(term::make_str(""), term::make_str("A")).as_bool());
        };
        "encode_utf8"_test = [] {
            const auto s = term::make_str("Some UTF8 string: ÖÜ ЯЯ");
            const auto b = builtins::encode_utf8(s);
            expect(b.as_bstr().str() == s.as_str());
        };
        "encode_utf8"_test = [] {
            const auto b = term::make_bstr(std::string_view { "Some UTF8 string: ÖÜ ЯЯ" });
            const auto s = builtins::decode_utf8(b);
            expect(b.as_bstr().str() == s.as_str());
        };
        "choose_unit"_test = [] {
            expect(builtins::choose_unit(term::make_unit(), term::make_str("AAA")).as_str() == "AAA");
            expect(builtins::choose_unit(term::make_unit(), term::make_int(22)).as_int() == 22);
            expect(throws([] { builtins::choose_unit(term::make_bool(true), term::make_bool(false)); }));
            expect(throws([] { builtins::choose_unit(term::make_bool(true), term::make_unit()); }));
        };
        "fst_pair"_test = [] {
            expect(builtins::fst_pair(term::make_pair(constant::make_int(22), constant::make_int(33))).as_int() == 22);
            expect(builtins::fst_pair(term::make_pair(constant::make_int(33), constant::make_int(0))).as_int() == 33);
        };
        "snd_pair"_test = [] {
            expect(builtins::snd_pair(term::make_pair(constant::make_int(22), constant::make_int(33))).as_int() == 33);
            expect(builtins::snd_pair(term::make_pair(constant::make_int(33), constant::make_int(0))).as_int() == 0);
        };
        "choose_list"_test = [] {
            {
                expect(builtins::choose_list(term::make_list(constant_type { type_tag::integer }), term::make_int(11), term::make_int(22)).as_int() == 11);
            }
            {
                constant_list vals {};
                vals.emplace_back(constant::make_int(0));
                expect(builtins::choose_list(term::make_list(std::move(vals)), term::make_int(11), term::make_int(22)).as_int() == 22);
            }
        };
        "mk_cons"_test = [] {
            {
                expect(builtins::mk_cons(term::make_int(22), term::make_list(constant_type { type_tag::integer })).as_list().size() == 1_u);
            }
            {
                constant_list vals {};
                vals.emplace_back(constant::make_int(0));
                const auto res = builtins::mk_cons(term::make_int(22), term::make_list(std::move(vals)));
                const auto &res_vals = res.as_list();
                expect(res_vals.size() == 2_u);
                expect(res_vals.at(0).as_int() == 22);
                expect(res_vals.at(1).as_int() == 0);
            }
        };
        "head_list"_test = [] {
            {
                expect(throws([&] { builtins::head_list(term::make_list(constant_type { type_tag::integer })); }));
            }
            {
                constant_list vals {};
                vals.emplace_back(constant::make_int(22));
                expect(builtins::head_list(term::make_list(std::move(vals))).as_int() == 22);
            }
            {
                constant_list vals {};
                vals.emplace_back(constant::make_int(22));
                vals.emplace_back(constant::make_int(33));
                vals.emplace_back(constant::make_int(44));
                expect(builtins::head_list(term::make_list(std::move(vals))).as_int() == 22);
            }
            expect(throws([] { builtins::head_list(term::make_list(constant_type { type_tag::integer })); }));
        };
        "tail_list"_test = [] {
            {
                expect(throws([&] { builtins::tail_list(term::make_list(constant_type { type_tag::integer })); }));
            }
            {
                constant_list vals {};
                vals.emplace_back(constant::make_int(22));
                expect(builtins::tail_list(term::make_list(std::move(vals))).as_list().empty());
            }
            {
                constant_list vals {};
                vals.emplace_back(constant::make_int(22));
                vals.emplace_back(constant::make_int(33));
                vals.emplace_back(constant::make_int(44));
                const auto res = builtins::tail_list(term::make_list(std::move(vals)));
                const auto &res_vals = res.as_list();
                expect(res_vals.size() == 2_u);
                expect(res_vals.at(0).as_int() == 33_u);
                expect(res_vals.at(1).as_int() == 44_u);
            }
            expect(throws([] { builtins::tail_list(term::make_list(constant_type { type_tag::integer })); }));
        };
        "null_list"_test = [] {
            {
                expect(builtins::null_list(term::make_list(constant_type { type_tag::integer })).as_bool());
            }
            {
                constant_list vals {};
                vals.emplace_back(constant::make_int(22));
                expect(!builtins::null_list(term::make_list(std::move(vals))).as_bool());
            }
            {
                constant_list vals {};
                vals.emplace_back(constant::make_int(22));
                vals.emplace_back(constant::make_int(33));
                vals.emplace_back(constant::make_int(44));
                expect(!builtins::null_list(term::make_list(std::move(vals))).as_bool());
            }
        };
        "choose_data"_test = [] {
            const auto map = builtins::map_data(term::make_list(constant_type { type_tag::data }));
            const auto list = builtins::list_data(term::make_list(constant_type { type_tag::data }));
            const auto bstr = builtins::b_data(term::make_bstr(uint8_vector::from_hex("112233")));
            const auto r1 = term::make_int(1);
            const auto r2 = term::make_int(2);
            const auto r3 = term::make_int(3);
            const auto r4 = term::make_int(4);
            const auto r5 = term::make_int(5);
            expect(builtins::choose_data(builtins::constr_data(term::make_int(5), term::make_list(constant_type { type_tag::data })), r1, r2, r3, r4, r5) == r1);
            expect(builtins::choose_data(builtins::constr_data(term::make_int(22), term::make_list(constant_type { type_tag::data })), r1, r2, r3, r4, r5) == r1);
            expect(builtins::choose_data(builtins::constr_data(term::make_int(1000), term::make_list(constant_type { type_tag::data })), r1, r2, r3, r4, r5) == r1);
            expect(builtins::choose_data(map, r1, r2, r3, r4, r5) == r2);
            expect(builtins::choose_data(list, r1, r2, r3, r4, r5) == r3);
            expect(builtins::choose_data(builtins::i_data(term::make_int(22)), r1, r2, r3, r4, r5) == r4);
            expect(builtins::choose_data(builtins::i_data(term::make_int(-22)), r1, r2, r3, r4, r5) == r4);
            expect(builtins::choose_data(builtins::i_data(term::make_int(cpp_int { 1 } << 80)), r1, r2, r3, r4, r5) == r4);
            expect(builtins::choose_data(builtins::i_data(term::make_int((cpp_int { 1 } << 80) * -1)), r1, r2, r3, r4, r5) == r4);
            expect(builtins::choose_data(bstr, r1, r2, r3, r4, r5) == r5);
        };
        "constr_data/un_consr_data"_test = [] {
            {
                const auto id = term::make_int(5);
                const auto val = term::make_list(constant::make_int(-5));
                const auto res = builtins::constr_data(id, val);
                const auto act = builtins::un_constr_data(res);
                const auto &act_vals = act.as_pair();
                expect(act_vals.at(0) == id.as_constant());
                expect(act_vals.at(1) == val.as_constant());
            }
            {
                const auto id = term::make_int(25);
                const auto val = term::make_list(constant::make_int(1), constant::make_int(15));
                const auto res = builtins::constr_data(id, val);
                const auto act = builtins::un_constr_data(res);
                const auto &act_vals = act.as_pair();
                expect(act_vals.at(0) == id.as_constant());
                expect(act_vals.at(1) == val.as_constant());
            }
            {
                const auto id = term::make_int(1025);
                const auto val = term::make_list(constant::make_bstr(uint8_vector::from_hex("AABBCC")), constant::make_bstr(uint8_vector::from_hex("CCBBAA")));
                const auto res = builtins::constr_data(id, val);
                const auto act = builtins::un_constr_data(res);
                const auto &act_vals = act.as_pair();
                expect(act_vals.at(0) == id.as_constant());
                expect(act_vals.at(1) == val.as_constant());
            }
        };
        "map_data/un_map_data"_test = [] {
            {
                const auto val = term::make_list(constant_type::make_pair(constant_type { type_tag::data }, constant_type { type_tag::data }));
                const auto res = builtins::map_data(val);
                const auto act = builtins::un_map_data(res);
                expect(val == act) << fmt::format("exp: {} act: {}", val, act);
            }
            {
                const auto val = term::make_list(
                    constant::make_pair(
                        plutus::constant { builtins::i_data(term::make_int(-5)).as_constant() },
                        plutus::constant { builtins::i_data(term::make_int(66)).as_constant() }
                    )
                );
                const auto res = builtins::map_data(val);
                const auto act = builtins::un_map_data(res);
                expect(val == act) << fmt::format("exp: {} act: {}", val, act);
            }
            {
                const auto val = term::make_list(
                    constant::make_pair(
                        plutus::constant { builtins::i_data(term::make_int(-5)).as_constant() },
                        plutus::constant { builtins::b_data(term::make_bstr(uint8_vector::from_hex("112233"))).as_constant() }
                    ),
                    constant::make_pair(
                        plutus::constant { builtins::i_data(term::make_int(17)).as_constant() },
                        plutus::constant { builtins::b_data(term::make_bstr(uint8_vector::from_hex("AABBCC"))).as_constant() }
                    )
                );
                const auto res = builtins::map_data(val);
                const auto act = builtins::un_map_data(res);
                expect(val == act) << fmt::format("exp: {} act: {}", val, act);
            }
            expect(throws([] { builtins::map_data(term::make_list(constant::make_int(22))); }));
        };
        "list_data/un_list_data"_test = [] {
            {
                const auto val = term::make_list(constant_type { type_tag::data });
                const auto res = builtins::list_data(val);
                const auto act = builtins::un_list_data(res);
                expect(val == act);
            }
            {
                const auto val = term::make_list(
                    plutus::constant { builtins::i_data(term::make_int(-5)).as_constant() },
                    plutus::constant { builtins::i_data(term::make_int(88)).as_constant() }
                );
                const auto res = builtins::list_data(val);
                const auto act = builtins::un_list_data(res);
                expect(val == act) << fmt::format("exp: {} act: {}", val, act);
            }
            {
                const auto val = term::make_list(
                    plutus::constant { builtins::b_data(term::make_bstr(uint8_vector::from_hex("112233"))).as_constant() },
                    plutus::constant { builtins::b_data(term::make_bstr(uint8_vector::from_hex("556677"))).as_constant() }
                );
                const auto res = builtins::list_data(val);
                const auto act = builtins::un_list_data(res);
                expect(val == act) << fmt::format("exp: {} act: {}", val, act);
            }
            expect(throws([] { builtins::map_data(term::make_list(constant::make_int(22))); }));
        };
        "i_data/un_i_data"_test = [] {
            {
                const auto res = builtins::i_data(term::make_int(-1));
                expect(res.as_data() == uint8_vector::from_hex("20"));
                expect(builtins::un_i_data(res).as_int() == -1);
            }
            {
                const auto res = builtins::i_data(term::make_int(-24));
                expect(res.as_data() == uint8_vector::from_hex("37"));
                expect(builtins::un_i_data(res).as_int() == -24);
            }
            {
                const auto res = builtins::i_data(term::make_int(-25));
                expect(res.as_data() == uint8_vector::from_hex("3818"));
                expect(builtins::un_i_data(res).as_int() == -25);
            }
            {
                const cpp_int val { (cpp_int { 1 } << 64) * -1 };
                const auto res = builtins::i_data(term::make_int(val));
                expect(res.as_data() == uint8_vector::from_hex("3BFFFFFFFFFFFFFFFF")) << fmt::format("{}", res.as_data());
                expect(builtins::un_i_data(res).as_int() == val);
            }
            {
                const cpp_int val { (cpp_int { 1 } << (64 * 7)) * -1 };
                const auto res = builtins::i_data(term::make_int(val));
                expect(res.as_data() == uint8_vector::from_hex("C35840FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F")) << fmt::format("{}", res.as_data());
            }
            expect(throws([] { builtins::i_data(term::make_int((cpp_int { 1 } << (64 * 7 + 1)) * -1)); }));
            {
                const cpp_int val { 0 };
                const auto res = builtins::i_data(term::make_int(val));
                expect(res.as_data() == uint8_vector::from_hex("00"));
                expect(builtins::un_i_data(res).as_int() == val);
            }
            {
                const cpp_int val { 23 };
                const auto res = builtins::i_data(term::make_int(val));
                expect(res.as_data() == uint8_vector::from_hex("17"));
                expect(builtins::un_i_data(res).as_int() == val);
            }
            {
                const cpp_int val { 24 };
                const auto res = builtins::i_data(term::make_int(val));
                expect(res.as_data() == uint8_vector::from_hex("1818"));
                expect(builtins::un_i_data(res).as_int() == val);
            }
            {
                const cpp_int val { std::numeric_limits<uint64_t>::max() };
                const auto res = builtins::i_data(term::make_int(val));
                expect(res.as_data() == uint8_vector::from_hex("1BFFFFFFFFFFFFFFFF")) << fmt::format("{}", res.as_data());
                expect(builtins::un_i_data(res).as_int() == val);
            }
            {
                const cpp_int val { cpp_int { 1 } << 80 };
                const auto res = builtins::i_data(term::make_int(val));
                expect(res.as_data() == uint8_vector::from_hex("C24C808080808080808080808008")) << fmt::format("{}", res.as_data());
                expect(builtins::un_i_data(res).as_int() == val) << fmt::format("{}", builtins::un_i_data(res).as_int());
            }
            expect(throws([] { builtins::i_data(term::make_int(cpp_int { 1 } << (64 * 7 + 1))); }));
            expect(throws([] {
                const auto data = uint8_vector::from_hex("C35841FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F");
                builtins::un_i_data(term::make_data(data));
            }));
        };
        "b_data/un_b_data"_test = [] {
            {
                uint8_vector data(65);
                expect(throws([&] { builtins::b_data(term::make_bstr(std::move(data))); }));
            }
            {
                const auto val = term::make_bstr(uint8_vector::from_hex("001122"));
                const auto res = builtins::b_data(val);
                const auto act = builtins::un_b_data(res);
                expect(val == act) << fmt::format("exp: {} act: {}", val, act);
            }
        };
        "equals_data"_test = [] {
            expect(builtins::equals_data(term::make_data(uint8_vector::from_hex("")), term::make_data(uint8_vector::from_hex(""))).as_bool());
            expect(!builtins::equals_data(term::make_data(uint8_vector::from_hex("")), term::make_data(uint8_vector::from_hex("AA"))).as_bool());
            expect(builtins::equals_data(term::make_data(uint8_vector::from_hex("AA")), term::make_data(uint8_vector::from_hex("AA"))).as_bool());
            expect(!builtins::equals_data(term::make_data(uint8_vector::from_hex("AA")), term::make_data(uint8_vector::from_hex("BB"))).as_bool());
        };
        "mk_pair_data"_test = [] {
            const auto res = builtins::mk_pair_data(builtins::i_data(term::make_int(1)), builtins::i_data(term::make_int(2)));
            const auto &res_vals = res.as_pair();
            expect(res_vals.size() == 2_ull);
            expect(res_vals.at(0).as_data() == uint8_vector::from_hex("01"));
            expect(res_vals.at(1).as_data() == uint8_vector::from_hex("02"));
        };
        "mk_nil_data"_test = [] {
            expect(builtins::mk_nil_data(term::make_unit()) == term::make_list(constant_type { type_tag::data }));
        };
        "mk_nil_pair_data"_test = [] {
            constant_type_list nested {};
            nested.emplace_back(type_tag::data);
            nested.emplace_back(type_tag::data);
            expect(builtins::mk_nil_pair_data(term::make_unit()) == term::make_list(constant_type { type_tag::pair, std::move(nested) }));
        };
        "serialize"_test = [] {
            const auto val = term::make_list(
                constant::make_pair(
                    plutus::constant { builtins::i_data(term::make_int(-5)).as_constant() },
                    plutus::constant { builtins::b_data(term::make_bstr(uint8_vector::from_hex("112233"))).as_constant() }
                ),
                constant::make_pair(
                    plutus::constant { builtins::i_data(term::make_int(17)).as_constant() },
                    plutus::constant { builtins::b_data(term::make_bstr(uint8_vector::from_hex("AABBCC"))).as_constant() }
                )
            );
            const auto act = builtins::serialize_data(builtins::map_data(val)).as_bstr();
            const auto exp = uint8_vector::from_hex("a224431122331143aabbcc");
            expect(act == exp) << fmt::format("exp: {} act: {}", exp, act);
        };
    };
};