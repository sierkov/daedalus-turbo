/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/benchmark.hpp>
#include <dt/scheduler.hpp>
#include <dt/zstd-stream.hpp>

using namespace daedalus_turbo;

suite zstd_stream_bench_suite = [] {
    "zstd::stream"_test = [] {
        const auto test_path = install_path("data/chunk-registry/compressed/chunk/977E9BB3D15A5CFF5C5E48617288C5A731DB654C0B42D63627C690CEADC9E1F3.zstd");
        benchmark("zstd::read_stream", 500e6, 3, [&] {
            zstd::read_stream s { test_path };
            uint8_vector data(54206949);
            const auto num_read = s.try_read(data);
            return num_read;
        });
        auto &sched = scheduler::get();
        benchmark("zstd::read_stream parallel", sched.num_workers() * 500e6, 3, [&] {
            const auto num_tasks = sched.num_workers() * 2;
            std::atomic_size_t num_read { 0 };
            for (size_t i = 0; i < num_tasks; i++) {
                sched.submit_void("zstd::read_stream", 100, [&] {
                    zstd::read_stream s { test_path };
                    uint8_vector data(54206949);
                    num_read.fetch_add(s.try_read(data), std::memory_order_relaxed);
                });
            }
            sched.process();
            return num_read.load(std::memory_order_relaxed);
        });
    };
};