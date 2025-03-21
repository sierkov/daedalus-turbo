/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/benchmark.hpp>

using namespace daedalus_turbo;

suite error_bench_suite = [] {
    "error"_test = [] {
        benchmark_r("construct one-param", 2.0, 10,
            [] {
                error(fmt::format("Hello {}!", "world"));
            }
        );
        benchmark_r("construct, throw, and catch", 2.0, 10,
            [] {
                try {
                    throw error(fmt::format("Hello {}!", "world"));
                } catch (error &) {
                }
            }
        );
    };
};