/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/benchmark.hpp>
#include <dt/cardano.hpp>
#include <dt/cbor.hpp>
#include <dt/file.hpp>

using namespace daedalus_turbo;

suite cardano_common_bench_suite = [] {
    "cardano::common"_test = [] {
        "block method vs direct CBOR access"_test = [] {
            auto extract_slot = [&](const cbor_value &bt) { return bt.array().at(1).array().at(0).array().at(0).array().at(1).uint(); };
            auto chunk = file::read("./data/chunk-registry/compressed/chunk/9C5C0267DCA941851D0330E19B91712618EB6DB4BF17E458BCF00829F84CF3CF.zstd");
            cbor_parser parser { chunk };
            expect(!parser.eof());
            cbor_value block_tuple;
            parser.read(block_tuple);
            auto blk = cardano::make_block(block_tuple, 0);
            const auto &blk_ref = *blk;
            expect(blk_ref.slot() == extract_slot(block_tuple));
            size_t num_iter = 100'000'000;
            auto struct_r = benchmark_rate("extract slot structured", 3, [&] {
                for (size_t i = 0; i < num_iter; ++i) {
                    blk_ref.slot();
                }
                return num_iter;
            });
            auto raw_r = benchmark_rate("extract slot direct", 3, [&] {
                for (size_t i = 0; i < num_iter; ++i) {
                    extract_slot(block_tuple);
                }
                return num_iter;
            });
            expect(struct_r >= 10e6);
            expect(raw_r >= 10e6);
        };
    };    
};