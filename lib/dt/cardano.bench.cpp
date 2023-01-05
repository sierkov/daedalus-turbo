/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <string_view>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/cardano.hpp>
#include <dt/util.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

const string DATA_DIR = "./data"s;

class MyProcessor: public cardano_processor {
public:
    size_t tx_count = 0;
    size_t block_count = 0;

    void every_block(const cardano_block_context &/*block_ctx*/, const cbor_value &/*block_tuple*/) {
        block_count++;
    }

    void every_tx(const cardano_tx_context &/*tx_ctx*/, const cbor_value &/*tx*/, uint64_t) {
        tx_count++;
    }
};

static uint64_t process_all_chunks(const string_view &db_path, size_t skip_factor = 1)
{
    MyProcessor proc;
    cardano_parser parser(proc);
    cardano_chunk_context chunk_ctx(0);
    bin_string chunk;
    size_t total_size = 0;
    size_t i = 0;
    for (const auto &entry : filesystem::directory_iterator(db_path)) {
        if (entry.path().extension() != ".chunk") continue;
        if (i++ % skip_factor != 0) continue;
        string path = entry.path().string();
        read_whole_file(path, chunk);
        total_size += chunk.size();
        parser.parse_chunk(chunk_ctx, chunk);
        chunk_ctx.offset += chunk.size();
    }
    return total_size;
}

suite cardano_bench_suite = [] {
    "cardano"_test = [] {
        "tx counting"_test = [] {
            double throughput = benchmark_throughput("cardano/count transactions", 3, [] { return process_all_chunks(DATA_DIR, 50); } );
            expect(throughput >= 200'000'000.0_d);
        };
    };
};
