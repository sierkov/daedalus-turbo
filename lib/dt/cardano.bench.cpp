/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/benchmark.hpp>
#include <dt/cardano.hpp>
#include <dt/file.hpp>
#include <dt/util.hpp>

using namespace std::literals;
using namespace daedalus_turbo;

namespace {
    static uint64_t lazy_process_chunks(const std::string_view &db_path, size_t skip_factor = 1)
    {
        size_t total_size = 0;
        size_t i = 0;
        uint8_vector chunk {};
        cbor_value block_tuple {};
        for (const auto &entry : std::filesystem::directory_iterator(db_path)) {
            if (entry.path().extension() != ".chunk") continue;
            if (i++ % skip_factor != 0) continue;
            file::read(entry.path().string(), chunk);
            cbor_parser parser { chunk };
            while (!parser.eof()) {
                parser.read(block_tuple);
                auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
            }
            total_size += chunk.size();
        }
        return total_size;
    }
}

suite cardano_bench_suite = [] {
    "cardano"_test = [] {
        static const std::string DATA_DIR { "./data/immutable"s };
        benchmark("cardano/lazy parse tx count"sv, 100'000'000.0, 3, [] { return lazy_process_chunks(DATA_DIR, 50); } );
    };
};