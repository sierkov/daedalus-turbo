/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/file.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite cardano_sheley_suite = [] {
    "cardano::shelley"_test = [] {
        "body_hash_ok"_test = [] {
            auto chunk = file::read("./data/chunk-registry/compressed/immutable/DF597E3FA352A7BD2F021733804C33729EBAA3DCAA9C0643BD263EFA09497B03.zstd");
            cbor_parser parser { chunk };
            cbor_value block_tuple {};
            while (!parser.eof()) {
                parser.read(block_tuple);
                auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
                expect(blk->era() == 2_ull);
                expect(blk->body_hash_ok());
            }
        };
    };
};