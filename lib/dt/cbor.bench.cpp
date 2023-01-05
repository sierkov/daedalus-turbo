/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <fstream>
#include <vector>
#include <string>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/cbor.hpp>
#include <dt/util.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

static const string DATA_DIR = "./data"s;

static size_t parse_all_chunks(const string &db_path, void processor(const bin_string &), size_t skip_factor = 1) {
    bin_string buf;
    size_t i = 0;
    size_t total_size = 0;
    for (const auto &entry : filesystem::directory_iterator(db_path)) {
        if (entry.path().extension() != ".chunk") continue;
        if (i++ % skip_factor != 0) continue;
        string path = entry.path().string();
        try {
            read_whole_file(path, buf);
            total_size += buf.size();
            processor(buf);
        } catch (exception &ex) {
            throw runtime_error("error parsing chunk " + path + ": " + ex.what());
        }    
    }
    return total_size;
}

static void parse_own(const bin_string &buf)
{
    cbor_value block_tuple;
    cbor_parser parser(buf.data(), buf.size());
    while (!parser.eof()) {
        parser.readValue(block_tuple);
    }
}

suite cbor_bench_suite = [] {
    "parse cardano"_test = [] {
        double throughput = benchmark_throughput("cbor/parse cardano", 3,
            [] {
                return parse_all_chunks(DATA_DIR, parse_own);
            }
        );
        expect(throughput >= 200'000'000.0_d);
    };
};
