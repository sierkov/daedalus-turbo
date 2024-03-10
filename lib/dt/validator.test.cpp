/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/test.hpp>
#include <dt/validator.hpp>

using namespace daedalus_turbo;

suite validator_suite = [] {
    "validator"_test = [] {
        /*"header hashes"_test = [] {
            auto genesis_hash;
            auto chunk1 = random_chunk_from_epoch(422);
            auto chunk2 = random_chunk_from_epoch(422, block1);
            auto chunk3 = random_chunk_from_epoch(422, block2);
            "chunk-level"_test = [] {
                "all good"_test = [] {
                    auto c1 = chunk1.block(0).prev_hash(genesis_hash);
                    cr.add(c1);
                    auto c2 = chunk2.block(0).prev_hash(c1.last_block().hash());
                    cr.add(c2);
                    auto c3 = chunk3.block(0).prev_hash(c2.last_block().hash());
                    cr.add(c3);
                    expect(cr.num_chunks() == 3_ull);
                    expect(cr.num_unmerged() == 0_ull);
                };
                "gap at the beginning"_test = [] {
                };
                "gap in the middle"_test = [] {
                };
                "gap at the end"_test = [] {
                };
            };
            "block-level"_test = [] {
                "all good"_test = [] {
                    auto c1 = chunk1.block(0).prev_hash(genesis_hash);
                    expect(c1.num_blocks() > 10_uz);
                    cr.add(c1);
                    expect(cr.num_blocks() == 1_uz);
                    expect(cr.num_umberged() == 0_uz);
                };
                "gap at the beginning"_test = [] {
                    // add chunk without updating the prev hash of its first block
                    auto c1 = chunk1;
                    expect(c1.num_blocks() > 10_uz);
                    cr.add(c1);
                    expect(cr.num_blocks() == 0_uz);
                    expect(cr.num_umberged() == 1_uz);
                };
                "gap in the middle"_test = [] {
                    auto c1 = chunk1.clone();
                    c1.block(0).prev_hash(genesis_hash);
                    c1.block(chunk1.num_blocks() / 2).prev_hash(cardano::block_hash {});
                    cr.add(c1);
                    expect(cr.num_blocks() == 0_uz);
                    expect(cr.num_umberged() == 1_uz);
                };
                "gap at the end"_test = [] {
                    auto c1 = chunk1.clone();
                    c1.block(0).prev_hash(genesis_hash);
                    chunk1.block_last().prev_hash(cardano::block_hash {});
                    cr.add(c1);
                    expect(cr.num_blocks() == 0_uz);
                    expect(cr.num_umberged() == 1_uz);
                };
            };
        };
        "body hashes"_test = [] {
            "ok"_test = [] {
            };
            "override tx data"_test = [] {
            };
            "override tx witness data"_test = [] {
            };
            "override auxiliary data"_test = [] {
            };
            "override invlid tx data"_test = [] {
            };
        };
        "slot numbers"_test = [] {
            "chunk-level"_test = [] {
            };
            "block-level"_test = [] {
            };
        };
        "KES signatures"_test = [] {
            "within-chunks"_test = [] {
            };
            "across-chunks"_test = [] {
            };
        };
        "leadership-eligibility"_test = [] {
            "ok"_test = [] {
            };
            "override relative stake"_test = [] {
            };
            "override vrf result"_test = [] {
            };
        };*/
    };
};