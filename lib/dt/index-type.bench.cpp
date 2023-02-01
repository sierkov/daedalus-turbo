/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/index-type.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

suite index_type_bench_suite = [] {
    "index_type"_test = [] {
        size_t num_evals = 10'000'000'000;
        size_t num_iter = 5;
        double min_throughput = 100'000'000'000.0;
        benchmark("pack_offset", min_throughput, num_iter,
            [=] {
                uint8_t tx_offset[5];
                for (size_t i = 0; i < num_evals; ++i)
                    pack_offset(tx_offset, sizeof(tx_offset), 55'123'456'789);
                return sizeof(tx_offset) * num_evals;
            }
        );
        benchmark("unpack_offset", min_throughput, num_iter,
            [=] {
                uint8_t tx_offset[5] = { 0xDE, 0xAD, 0xBE, 0xAF, 0x00 };
                for (size_t i = 0; i < num_evals; ++i)
                    unpack_offset(tx_offset, sizeof(tx_offset));
                return sizeof(tx_offset) * num_evals;
            }
        );
        benchmark("pack_tx_size", min_throughput, num_iter,
            [=] {
                for (size_t i = 0; i < num_evals; ++i) pack_tx_size(7777);
                return 1 * num_evals;
            }
        );
        benchmark("unpack_tx_size", min_throughput, num_iter,
            [=] {
                for (size_t i = 0; i < num_evals; ++i) unpack_tx_size(31);
                return 1 * num_evals;
            }
        );
    };
};
