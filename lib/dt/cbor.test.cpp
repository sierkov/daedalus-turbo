/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cbor.hpp>
#include <dt/test.hpp>

using namespace std::literals;
using namespace daedalus_turbo;

inline cbor_value parse_cbor(const uint8_t *data, size_t size)
{
    cbor_parser parser(buffer { data, size });
    cbor_value val;
    parser.read(val);
    return val;
}

inline cbor_value parse_cbor(const std::string_view &bytes)
{
    cbor_value val {};
    cbor_parser parser { bytes };
    parser.read(val);
    return val;
}

suite cbor_parser_suite = [] {
    "cbor"_test = [] {
        "parse_uint"_test = [] {
            {
                const uint8_t bytes[] = { 0x00 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_UINT);
                expect(val.uint() == 0);
            }
            {
                const uint8_t bytes[] = { 0x17 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_UINT);
                expect(val.uint() == 23);
            }
            {
                const uint8_t bytes[] = { 0x18, 0x18 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_UINT);
                expect(val.uint() == 24);
            }
            {
                const uint8_t bytes[] = { 0x1b, 0x00, 0x00, 0x00, 0xe8, 0xd4, 0xa5, 0x10, 0x00 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_UINT);
                expect(val.uint() == 1000000000000);
            }
        };

        "parse_nint"_test = [] {
            {
                const uint8_t bytes[] = { 0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_NINT);
                expect(val.nint() == 18446744073709551615ULL) << val.nint();
            }
            {
                const uint8_t bytes[] = { 0x20 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_NINT);
                expect(val.nint() == 1) << val.nint();
            }
            {
                const uint8_t bytes[] = { 0x38, 0x63 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_NINT);
                expect(val.nint() == 100) << val.nint();
            }
            {
                const uint8_t bytes[] = { 0x39, 0x03, 0xe7 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_NINT);
                expect(val.nint() == 1000) << val.nint();
            }
        };

        "parse_float32"_test = [] {
            {
                const uint8_t bytes[] = { 0xfa, 0x47, 0xc3, 0x50, 0x00 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_FLOAT32);
                expect(val.float32() == 100000.0) << val.float32();
            }
            {
                const uint8_t bytes[] = { 0xfa, 0x7f, 0x7f, 0xff, 0xff };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_FLOAT32);
                expect(val.float32() == 3.4028234663852886e+38) << val.float32();
            }
        };

        "parse_special"_test = [] {
            {
                const uint8_t bytes[] = { 0xf4 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_SIMPLE_FALSE);
            }
            {
                const uint8_t bytes[] = { 0xf5 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_SIMPLE_TRUE);
            }
            {
                const uint8_t bytes[] = { 0xf6 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_SIMPLE_NULL);
            }
            {
                const uint8_t bytes[] = { 0xf7 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_SIMPLE_UNDEFINED);
            }
        };

        "parse_tag"_test = [] {
            {
                const uint8_t bytes[] = { 0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0 };
                cbor_value val = parse_cbor(bytes, sizeof(bytes));
                expect(val.type == CBOR_TAG);
                const cbor_tag &tag = val.tag();
                expect(tag.first == 1);
                expect(tag.second->type == CBOR_UINT);
                expect(tag.second->uint() == 1363896240);
            }
        };

        "parse_text"_test = [] {
            {
                cbor_value val = parse_cbor("\x61\x61"sv);
                expect(val.type == CBOR_TEXT);
                expect(val.buf() == "a"sv);
            }
            {
                cbor_value val = parse_cbor("\x64\x49\x45\x54\x46"sv);
                expect(val.type == CBOR_TEXT);
                expect(val.buf() == "IETF"sv);
            }
        };

        "parse bytes indef"_test = [] {
            {
                cbor_value val = parse_cbor("\x5F\x44\xAA\xBB\xCC\xDD\x43\xEE\xFF\x99\xFF"sv);
                expect(val.type == CBOR_BYTES);
                expect(val.buf() == "\xAA\xBB\xCC\xDD\xEE\xFF\x99"sv);
                expect(val.storage != nullptr);
            }
        };

        "parse_array"_test = [] {
            {
                cbor_value val = parse_cbor("\x83\x01\x02\x03"sv);
                expect(val.type == CBOR_ARRAY);
                const cbor_array &items = val.array();
                expect(items.size() == 3);
                expect(items[0].type == CBOR_UINT);
                expect(items[0].uint() == 1);
                expect(items[1].type == CBOR_UINT);
                expect(items[1].uint() == 2);
                expect(items[2].type == CBOR_UINT);
                expect(items[2].uint() == 3);
            }
        };

        "parse_map"_test = [] {
            {
                cbor_value val = parse_cbor("\xa2\x61\x61\x01\x61\x62\x82\x02\x03"sv);
                expect(val.type == CBOR_MAP);
                const cbor_map &items = val.map();
                expect(items.size() == 2);
                expect(items[0].first.type == CBOR_TEXT);
                expect(items[0].first.buf() == "a"sv);
                expect(items[0].second.type == CBOR_UINT);
                expect(items[0].second.uint() == 1);
                expect(items[1].first.type == CBOR_TEXT);
                expect(items[1].first.buf() == "b"sv);
                expect(items[1].second.type == CBOR_ARRAY) << items[1].first.type;
                const cbor_array &item2 = items[1].second.array();
                expect(item2.size() == 2);
                expect(item2[0].type == CBOR_UINT);
                expect(item2[0].uint() == 2);
                expect(item2[1].type == CBOR_UINT);
                expect(item2[1].uint() == 3);
            }
        };

        "array_checked_at"_test = [] {
            cbor_value val = parse_cbor("\x83\x01\x02\x03"sv);
            expect(val.type == CBOR_ARRAY);
            const cbor_array &items = val.array();
            expect(items.size() == 3);
            expect(boost::ut::nothrow([&] { items.at(2); }));
            expect(throws<cbor_error>([&] { items.at(3); }));
        };
    };

};