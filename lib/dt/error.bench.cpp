/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/benchmark.hpp>

using namespace daedalus_turbo;

suite error_bench_suite = [] {
    "error"_test = [] {
        benchmark_r("construct one-param", 2.0, 10,
            [] {
                error("Hello {}!", "world");
            }
        );
        benchmark_r("construct, throw, and catch", 2.0, 10,
            [] {
                try {
                    throw error("Hello {}!", "world");
                } catch (error &ex) {
                }
            }
        );
    };
};