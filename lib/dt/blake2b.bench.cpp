/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <chrono>
#include <cstring>
#include <iostream>
#include <string_view>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/blake2b.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

suite blake2b_bench_suite = [] {
    for (size_t hash_size_bits : { 224, 256 }) {
        test("blake2b" + to_string(hash_size_bits)) = [=] {
            const char *in = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
            size_t in_len = strlen(in);
            size_t num_evals = 1000000;
            size_t out_len = hash_size_bits / 8;
            uint8_t blake2_sse_out[out_len];
            double throughput = benchmark_throughput("blake2b/" + to_string(hash_size_bits), 5,
                [=, &blake2_sse_out] {
                    for (size_t i = 0; i < num_evals; ++i)
                        blake2b_best(blake2_sse_out, out_len, in, in_len);
                    return in_len * num_evals;
                }
            );
            expect(throughput >= 200'000'000.0_d);
        };
    }
};
