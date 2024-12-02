/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/plutus/context.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite cardano_babbage_suite = [] {
    "cardano::babbage"_test = [] {
        "example scripts"_test = [] {
            configs_dir cfg { configs_dir::default_path() };
            cardano::config ccfg { cfg };
            ccfg.shelley_start_epoch(208);
            "validate plutus"_test = [&] {
                for (const auto &entry: std::filesystem::directory_iterator { install_path("data/babbage") }) {
                    if (entry.is_regular_file() && entry.path().extension() == ".zpp") {
                        const auto path = entry.path().string();
                        logger::info("evaluating script context from {}", path);
                        logger::debug("testing script context: {}", path);
                        {
                            const plutus::context ctx { path, ccfg };
                            expect(nothrow([&] {
                                try {
                                    for (const auto &[rid, rinfo]: ctx.redeemers()) {
                                        auto ps = ctx.prepare_script(rinfo);
                                        ctx.eval_script(ps);
                                    }
                                } catch (const error &ex) {
                                    logger::warn("context {} failed with {}", path, ex.what());
                                    throw;
                                }
                            })) << path;
                        }
                    }
                }
            };
        };
        "body_hash_ok"_test = [] {
            auto chunk = file::read("./data/chunk-registry/compressed/chunk/977E9BB3D15A5CFF5C5E48617288C5A731DB654C0B42D63627C690CEADC9E1F3.zstd");
            cbor_parser parser { chunk };
            cbor_value block_tuple {};
            while (!parser.eof()) {
                parser.read(block_tuple);
                const auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
                expect(blk->era() == 6_ull);
                expect(blk->body_hash_ok());
            }
        };
    };
};