/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/file.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite cardano_mary_suite = [] {
    "cardano::mary"_test = [] {
        "body_hash_ok"_test = [] {
            auto chunk = file::read("./data/chunk-registry/compressed/chunk/1A6CC809A5297CFC502B229B4CD31A9B00B71638CEAEDE45409D4F0EBC534356.zstd");
            cbor_parser parser { chunk };
            cbor_value block_tuple {};
            while (!parser.eof()) {
                parser.read(block_tuple);
                const auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
                expect(blk->era() == 5_ull);
                expect(blk->body_hash_ok());
            }
        };
    };
};