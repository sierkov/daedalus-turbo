/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <algorithm>
#include <cstring>
#include <string_view>
#include <boost/ut.hpp>
#include <dt/array.hpp>
#include <dt/benchmark.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite array_bench_suite = [] {
    "array"_test = [] {
        daedalus_turbo::array<size_t, 16> data { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
        daedalus_turbo::array<size_t, 16> tmp {};

        auto copy_rate = benchmark_throughput("std::copy", 1'000'000'000, [&] {
            std::copy(data.begin(), data.end(), tmp.begin());
            return data.size();
        });
        auto memcpy_rate = benchmark_throughput("memcpy", 1'000'000'000, [&] {
            std::memcpy(tmp.data(), data.data(), data.size());
            return data.size();
        });
        expect(memcpy_rate >= copy_rate * 1.2) << memcpy_rate << copy_rate;
    };
};