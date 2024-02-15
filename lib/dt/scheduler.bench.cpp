/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <cmath>
#include <filesystem>
#include <dt/benchmark.hpp>
#include <dt/file.hpp>
#include <dt/logger.hpp>
#include <dt/scheduler.hpp>
#include <dt/zstd.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite scheduler_bench_suite = [] {
    "scheduler"_test = [] {
        static const std::string DATA_DIR { "./data/immutable"s };
        size_t num_iter = 3;
        size_t data_multiple = 20;
        "micro_tasks_default"_test = [num_iter, data_multiple] {
            std::vector<uint8_vector> chunks;
            uint8_vector buf;
            for (const auto &entry: std::filesystem::directory_iterator(DATA_DIR)) {
                if (entry.path().extension() != ".chunk") continue;
                file::read(entry.path().string(), buf);
                chunks.push_back(buf);
            }
            benchmark("scheduler/default progress update", 200'000'000.0, num_iter, [data_multiple, &chunks]() {
                size_t total_size = 0;
                scheduler s;
                for (size_t i = 0; i < data_multiple; ++i) {
                    for (const auto &chunk: chunks) {
                        s.submit(
                            "compress", 0,
                            [&chunk]() {
                                uint8_vector tmp;
                                zstd::compress(tmp, chunk, 3);
                                return true;
                            }
                        );
                        total_size += chunk.size();
                    }
                }    
                s.process();
                return total_size;
            });
        };
        "nano tasks"_test = [] {
            std::vector<double> tasks {};
            for (size_t i = 0; i < 10'000'000; ++i)
                tasks.emplace_back(static_cast<double>(i));
            scheduler s {};
            for (size_t batch_size: { 100, 1000, 10'000, 100'000, 1'000'000 }) {
                benchmark_r(fmt::format("nano tasks - batch {}", batch_size), 100'000.0, 1, [&]() {
                    double total_time = 0.0;
                    size_t num_batches = 0;
                    s.on_result("math", [&](const auto &res) {
                        total_time += std::any_cast<double>(res);
                        num_batches++;
                    });
                    for (size_t start = 0; start < tasks.size(); start += batch_size) {
                        auto end = std::min(start + batch_size, tasks.size());
                        s.submit("math", 0, [&tasks, start, end]() {
                            auto start_time = std::chrono::system_clock::now();
                            double sum = 0.0;
                            for (size_t i = start; i < end; ++i) {
                                auto &val = tasks[i];
                                sum += std::sqrt(val * val);
                            }
                            logger::trace("start: {} end: {} sum: {}", start, end, sum);
                            return std::chrono::duration<double> { std::chrono::system_clock::now() - start_time }.count() * 1000;
                        });
                    }
                    expect(s.process_ok());
                    //std::cerr << fmt::format("nano tasks batch {} total compute time {:3f} ms average task time {:.3f} ms\n", batch_size, total_time, total_time / num_batches);
                    return tasks.size();
                });
            }
        };
    };
};