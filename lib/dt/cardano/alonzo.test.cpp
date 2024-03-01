/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/file.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite cardano_alonzo_suite = [] {
    "cardano::alonzo"_test = [] {
        "body_hash_ok"_test = [] {
            for (const auto &chunk_hash: { "1A6CC809A5297CFC502B229B4CD31A9B00B71638CEAEDE45409D4F0EBC534356",
                                                          "471C013F34D419FFA96A8FCD8E0D12EAC3DED4414982F5F055D2FD0AD52D035C" }) {
                auto chunk = file::read(fmt::format("./data/chunk-registry/compressed/immutable/{}.zstd", chunk_hash));
                cbor_parser parser { chunk };
                cbor_value block_tuple {};
                while (!parser.eof()) {
                    parser.read(block_tuple);
                    auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
                    expect(blk->era() == 5_ull);
                    expect(blk->body_hash_ok());
                }
            }
        };
    };
};