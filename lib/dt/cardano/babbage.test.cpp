/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/file.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite cardano_babbage_suite = [] {
    "cardano::babbage"_test = [] {
        "body_hash_ok"_test = [] {
            auto chunk = file::read("./data/chunk-registry/compressed/chunk/9C5C0267DCA941851D0330E19B91712618EB6DB4BF17E458BCF00829F84CF3CF.zstd");
            cbor_parser parser { chunk };
            cbor_value block_tuple {};
            while (!parser.eof()) {
                parser.read(block_tuple);
                auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
                expect(blk->era() == 6_ull);
                expect(blk->body_hash_ok());
            }
        };
    };
};