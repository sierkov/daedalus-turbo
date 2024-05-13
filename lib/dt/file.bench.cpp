/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/benchmark.hpp>
#include <dt/file.hpp>

using namespace daedalus_turbo;

suite file_bench_suite = [] {
    "file"_test = [] {
        benchmark("file::read", 1e9, 5, [] {
            auto buf = file::read("./data/chunk-registry/compressed/chunk/977E9BB3D15A5CFF5C5E48617288C5A731DB654C0B42D63627C690CEADC9E1F3.zstd");
            return buf.size();
        });
        benchmark("file::read_raw", 1e9, 5, [] {
            auto buf = file::read_raw("./data/chunk-registry/compressed/chunk/977E9BB3D15A5CFF5C5E48617288C5A731DB654C0B42D63627C690CEADC9E1F3.zstd");
            return buf.size();
        });
        file::tmp tmp_f { "file-write.tmp" };
        auto buf = file::read("./data/chunk-registry/compressed/chunk/977E9BB3D15A5CFF5C5E48617288C5A731DB654C0B42D63627C690CEADC9E1F3.zstd");
        benchmark("file::write", 1e9, 5, [&] {
            file::write(tmp_f.path(), buf);
            return buf.size();
        });
    };
};