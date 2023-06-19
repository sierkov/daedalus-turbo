/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <iostream>

#include <boost/ut.hpp>

#include <dt/chunk-registry.hpp>

using namespace std::literals;
using namespace boost::ut;
using namespace daedalus_turbo;

static const std::string DATA_DIR = "./data";

suite chunk_registry_suite = [] {
    "chunk_registry"_test = [] {
        "create chunk registry"_test = [] {
            chunk_registry cr(DATA_DIR);
            expect(cr.begin() != cr.end()) << cr.num_chunks();
            expect(cr.num_chunks() == 8_u) << cr.num_chunks();
            expect(cr.num_bytes() == 162'960'922_u) << cr.num_bytes();
        };

        "find chunk"_test = [] {
            chunk_registry cr(DATA_DIR);
            const std::string chunk_name = cr.find_chunk_name(100'000'000);
            expect(chunk_name == "./data/03306.chunk"s) << chunk_name;
        };

        "read"_test = [] {
            chunk_registry cr(DATA_DIR);
            cbor_value block_tuple;
            cr.read(28'762'567, block_tuple);
            expect(block_tuple.type == CBOR_ARRAY) << block_tuple.type;
            expect(block_tuple.array().size() == 2_u);
        };

        "read_automatic_resizing"_test = [] {
            chunk_registry cr(DATA_DIR);
            cbor_value block_tuple;
            size_t read_attempts = cr.read(28'762'567, block_tuple, 0x10, 4);
            expect(block_tuple.size > 0x10) << block_tuple.size;
            expect(read_attempts == 7_u) << read_attempts;
        };
    };
};
