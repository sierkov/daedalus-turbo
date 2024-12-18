/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <string>
#include <dt/benchmark.hpp>
#include <dt/cbor.hpp>
#include <dt/file.hpp>
#include <dt/util.hpp>

using namespace daedalus_turbo;

suite cbor_bench_suite = [] {
    "cbor::default"_test = [] {
        uint8_vector data {};
        for (const auto &path: file::files_with_ext_str(install_path("data/chunk-registry/compressed/chunk"), ".zstd"))
            data << file::read(path);
        benchmark("decoder", 200e6, 10, [&data] {
            cbor_parser parser { data };
            cbor_value block_tuple;
            while (!parser.eof()) {
                parser.read(block_tuple);
            }
            return data.size();
        });
    };
};
