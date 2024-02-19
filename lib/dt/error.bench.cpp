/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <chrono>
#include <cstring>
#include <iostream>
#include <source_location>
#include <string_view>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/error.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

inline void create_error(const std::source_location &loc=std::source_location::current())
{
    error_src_loc(loc, "Hello {}!", "world");
}

suite error_bench_suite = [] {
    "error"_test = [] {
        benchmark_r("construct one-param", 1'000'000.0, 1'000'000,
            [] {
                error("Hello {}!", "world");
            }
        );
        benchmark_r("construct, throw, and catch", 100'000.0, 100'000,
            [] {
                try {
                    throw error("Hello {}!", "world");
                } catch (error &ex) {
                }
            }
        );
        benchmark_r("extract source-location by value", 1'000'000.0, 100'0000,
            [] {
                const auto loc = std::source_location::current();
                return loc;
            }
        );
        benchmark_r("extract source-location by ref", 1'000'000.0, 100'0000,
            [] {
                const auto &loc = std::source_location::current();
                return loc;
            }
        );
        benchmark_r("construct source-location", 100'000.0, 100'000,
            [] {
                create_error();
            }
        );
    };
};