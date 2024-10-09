/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <algorithm>
#include <cstring>
#include <dt/array.hpp>
#include <dt/benchmark.hpp>
#include <dt/scheduler.hpp>

using namespace daedalus_turbo;

suite array_bench_suite = [] {
    "array"_test = [] {
        std::vector<size_t> data(1 << 26);
        for (size_t i = 0; i < data.size(); ++i)
            data[i] = i;
        volatile const size_t *data_ptr = data.data();
        volatile const size_t *data_end = data.data() + data.size();
        volatile size_t res = 0;
        std::vector<size_t> tmp(data.size());

        benchmark_throughput("std::copy", 5, [&] {
            std::copy(data_ptr, data_end, tmp.begin());
            return data.size() * sizeof(data[0]);
        });
        benchmark_throughput("loop volatile assign", 5, [&] {
            volatile auto *dp = tmp.data();
            for (volatile const auto *p = data_ptr; p < data_end; ++p)
                *dp++ = *p;
            return data.size() * sizeof(data[0]);
        });
        auto &sched = scheduler::get();
        benchmark_throughput("loop volatile assign - parallel", 3, [&] {
            const size_t num_jobs = sched.num_workers() * 2;
            for (size_t j = 0; j < num_jobs; ++j) {
                sched.submit_void("copy", 100, [&] {
                    volatile auto *dp = tmp.data();
                    for (volatile const auto *p = data_ptr; p < data_end; ++p)
                        *dp++ = *p;
                });
            }
            sched.process();
            return data.size() * sizeof(data[0]) * num_jobs;
        });
        benchmark_throughput("loop volatile read", 5, [&] {
            size_t sum = 0;
            for (volatile const auto *p = data_ptr; p < data_end; ++p)
                sum += *p;
            res = sum;
            return data.size() * sizeof(data[0]);
        });
        benchmark_throughput("loop volatile write", 5, [&] {
            volatile auto *p = tmp.data();
            for (size_t i = 0; i < tmp.size(); ++i)
                *p++ = i;
            return tmp.size() * sizeof(tmp[0]);
        });
    };
};