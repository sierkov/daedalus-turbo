/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_BENCHMARK_HPP
#define DAEDALUS_TURBO_BENCHMARK_HPP

#include <chrono>
#include <iostream>
#include <string_view>

namespace daedalus_turbo {
    using namespace std;

    template<typename T>
    concept Countable = requires(T a) {
        { a() + 1 };
    };

    template<Countable T>
    static double benchmark_throughput(const string_view &name, size_t num_iter, T &&action) {
        const auto start = std::chrono::high_resolution_clock::now();
        uint64_t total_bytes = 0;
        for (size_t i = 0; i < num_iter; ++i) {
            total_bytes += action();
        }
        const auto stop = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> sec = stop - start;
        double rate = (double)total_bytes / sec.count();
        string prefix = "";
        size_t rate_view = rate;
        if (rate > 10'000'000'000) {
            prefix = "G";
            rate_view /= 1'000'000'000;
        } else if (rate > 10'000'000) {
            prefix = "M";
            rate_view /= 1'000'000;
        } else if (rate > 10'000) {
            prefix = "K";
            rate_view /= 1'000;
        }
        std::clog << "[" << name << "] " << rate_view << " " << prefix << "bytes/sec"
            << ", total bytes: " << total_bytes
            << endl;
        return rate;
    };

}

#endif // !DAEDALUS_TURBO_BENCHMARK_HPP