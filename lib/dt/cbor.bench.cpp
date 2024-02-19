/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <vector>
#include <string>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/cbor.hpp>
#include <dt/file.hpp>
#include <dt/util.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

static size_t parse_all_chunks(const std::string &db_path, void processor(const uint8_vector &), size_t skip_factor = 1) {
    uint8_vector buf;
    size_t i = 0;
    size_t total_size = 0;
    for (const auto &entry: std::filesystem::directory_iterator(db_path)) {
        if (entry.path().extension() != ".chunk") continue;
        if (i++ % skip_factor != 0) continue;
        string path = entry.path().string();
        try {
            file::read(path, buf);
            total_size += buf.size();
            processor(buf);
        } catch (std::exception &ex) {
            throw error("error parsing chunk {}: {}", path, ex.what());
        }    
    }
    return total_size;
}

static void parse_own(const uint8_vector &buf)
{
    cbor_value block_tuple;
    cbor_parser parser { buf };
    while (!parser.eof()) {
        parser.read(block_tuple);
    }
}

suite cbor_bench_suite = [] {
    "cbor"_test = [] {
        static const std::string DATA_DIR { "./data/immutable"s };
        benchmark("cbor/parse cardano", 100'000'000.0, 3, [] {
            return parse_all_chunks(DATA_DIR, parse_own);
        });
    };
};