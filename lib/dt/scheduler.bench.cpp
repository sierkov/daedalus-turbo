/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <filesystem>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/file.hpp>
#include <dt/zstd.hpp>
#include <dt/scheduler.hpp>

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
    };
};