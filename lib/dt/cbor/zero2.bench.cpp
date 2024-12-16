/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/benchmark.hpp>
#include <dt/cbor/zero2.hpp>
#include <dt/file.hpp>

using namespace daedalus_turbo;

suite cbor_zero2_bench_suite = [] {
    "cbor::zero2"_test = [&] {
        uint8_vector data {};
        for (const auto &path: file::files_with_ext_str(install_path("data/chunk-registry/compressed/chunk"), ".zstd"))
            data << file::read(path);
        benchmark("decoder", 1e9, 10, [&data] {
            cbor::zero2::decoder dec { data };
            while (!dec.done()) {
                dec.read();
            }
            return data.size();
        });
    };
};