/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <chrono>
#include <cstring>
#include <iostream>
#include <string_view>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/blake2b.hpp>
#include <dt/file.hpp>
#include <dt/scheduler.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite blake2b_bench_suite = [] {
    "blake2b"_test = [&] {
        auto in = file::read("./data/chunk-registry/compressed/immutable/47F62675C9B0161211B9261B7BB1CF801EDD4B9C0728D9A6C7A910A1581EED41.zstd");
        scheduler sched {};
        for (const auto &[name, func]: { std::make_pair("blake2b-sodium", blake2b_sodium) }) {
            size_t num_evals = (1 << 30) / in.size();
            for (size_t hash_size_bits : { 224, 256 }) {
                size_t out_len = hash_size_bits / 8;
                uint8_vector out {};
                out.resize(out_len);
                benchmark(std::string { name } + "/" + std::to_string(hash_size_bits), 500'000'000.0, 5,
                    [&] {
                        for (size_t i = 0; i < num_evals; ++i)
                            func(out.data(), out.size(), in.data(), in.size());
                        return in.size() * num_evals;
                    }
                );
            }
            size_t num_evals_par = num_evals * 32;
            benchmark(name + std::string { "-parallel" }, 500'000'000.0, 3,
                [&] {
                    for (size_t i = 0; i < num_evals_par; ++i)
                        sched.submit("hash", 100, [&]() {
                            blake2b_256_hash out;
                            func(out.data(), out.size(), in.data(), in.size());
                            return true;
                        });
                    sched.process(false);
                    return in.size() * num_evals_par;
                }
            );
        }
    };
};