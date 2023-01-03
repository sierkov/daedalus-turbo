/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <iostream>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/index.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

struct indexed_type {
    uint64_t offset;
    uint16_t size;
    bool has_x;
    bool special_y;
};

suite index_bench_suite = [] {
    "index_writer"_test = [] {
        double throughput = benchmark_throughput("index_writer", 5, [] {
            index_writer<indexed_type> index("/workspace/tmp/index-bench.tmp"s);
            size_t num_ops = 10'000'000;
            
            for (size_t i = 0; i < num_ops; ++i) {
                indexed_type &it = index.writable();
                it.offset = i;
                it.size = sizeof(it);
                it.has_x = false;
                it.special_y = true;
                index.next();
            }
            return num_ops * sizeof(indexed_type);
        });
        expect(throughput >= 50'000'000.0_d);
    };
    
    "index_radix_writer"_test = [] {
        double throughput = benchmark_throughput("index_radix_writer", 5, [] {
            vector<string> paths;
            paths.emplace_back("/workspace/tmp/index-bench-radix-1.tmp");
            paths.emplace_back("/workspace/tmp/index-bench-radix-2.tmp");
            paths.emplace_back("/workspace/tmp/index-bench-radix-3.tmp");
            paths.emplace_back("/workspace/tmp/index-bench-radix-4.tmp");
            index_radix_writer<indexed_type> index(paths);
            size_t num_ops = 5'000'000;
            
            for (size_t i = 0; i < num_ops; ++i) {
                indexed_type &it = index.writable(i % 256);
                it.offset = i;
                it.size = sizeof(it);
                it.has_x = false;
                it.special_y = true;
                index.next();
            }
            return num_ops * sizeof(indexed_type);
        });
        expect(throughput >= 50'000'000.0_d);
    };
    
};
