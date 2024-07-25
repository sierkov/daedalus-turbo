/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <chrono>
#include <dt/benchmark.hpp>
#include <dt/sha3.hpp>

using namespace daedalus_turbo;

suite sha3_bench_suite = [] {
    "sha3"_test = [&] {
        const auto in = file::read("./data/chunk-registry/compressed/chunk/47F62675C9B0161211B9261B7BB1CF801EDD4B9C0728D9A6C7A910A1581EED41.zstd");
        benchmark("sha3", 400'000'000.0, 3, [&] {
            sha3::hash_256 out {};
            const size_t num_evals = (1 << 30) / in.size();
            for (size_t i = 0; i < num_evals; ++i)
                sha3::digest(out, in);
            return in.size() * num_evals;
        });
    };
};