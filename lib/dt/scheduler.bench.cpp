/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <filesystem>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/lz4.hpp>
#include <dt/scheduler.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

const string DATA_DIR = "./data"s;

suite scheduler_bench_suite = [] {
    "scheduler"_test = [] {
        size_t num_iter = 3;
        size_t data_multiple = 20;
        "micro_tasks_default"_test = [num_iter, data_multiple] {
            vector<uint8_vector> chunks;
            uint8_vector buf;
            for (const auto &entry: filesystem::directory_iterator(DATA_DIR)) {
                if (entry.path().extension() != ".chunk") continue;
                read_whole_file(entry.path().string(), buf);
                chunks.push_back(buf);
            }
            double throughput = benchmark_throughput("scheduler/default progress update", num_iter, [data_multiple, &chunks]() {
                size_t total_size = 0;
                scheduler s;
                for (size_t i = 0; i < data_multiple; ++i) {
                    for (const auto &chunk: chunks) {
                        s.submit(
                            "lz4_compress", 0,
                            [&chunk]() {
                                uint8_vector tmp;
                                lz4_compress(tmp, chunk);
                                return true;
                            }
                        );
                        total_size += chunk.size();
                    }
                }    
                s.process();
                return total_size;
            });
            expect(throughput >= 200'000'000.0_d);
        };
    };
};
