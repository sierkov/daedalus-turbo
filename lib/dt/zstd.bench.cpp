/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/benchmark.hpp>
#include <dt/file.hpp>
#include <dt/zstd.hpp>

using namespace daedalus_turbo;

namespace {
    struct perf_exp {
        size_t zstd_level;
        double throughput;
    };
}

suite zstd_bench_suite = [] {
    "zstd"_test = [] {
        auto data = file::read("./data/chunk-registry/compressed/chunk/977E9BB3D15A5CFF5C5E48617288C5A731DB654C0B42D63627C690CEADC9E1F3.zstd");
        if (data.size() > (1 << 22))
            data.resize(1 << 24);
        for (const auto &[zstd_level, exp_throughput]: {
            perf_exp { 1, 300e6 },
            perf_exp { 3, 200e6 },
            perf_exp { 9, 50e6 },
            perf_exp { 22, 2e6 }
        }) {
            uint8_vector compressed {};
            benchmark("zstd::compress level " + std::to_string(zstd_level), exp_throughput, 3, [&] {
                zstd::compress(compressed, data, zstd_level);
                return data.size();
            });
            benchmark("zstd::decompress level " + std::to_string(zstd_level), 1000e6, 3, [&] {
                uint8_vector out_data {};
                zstd::decompress(out_data, compressed);
                return out_data.size();
            });
        }
    };
};