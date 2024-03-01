/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <map>
#include <set>
#include <zpp_bits.h>
#include <dt/benchmark.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite zpp_bits_bench_suite = [] {
    "zpp::bits"_test = [] {
        "map of sets"_test = [] {
            using test_item = std::map<std::string, std::set<uint64_t>>;
            test_item items {};
            {
                auto &set = items["item1"];
                set.emplace(1234);
                set.emplace(12);
            }
            {
                auto &set = items["item2"];
                set.emplace(0);
            }
            test_item out_items {};
            size_t num_iters = 1'000;
            auto [data, in, out] = zpp::bits::data_in_out();
            benchmark("serialize map of sets", 1e8, 5, [&] {
                for (size_t i = 0; i < num_iters; ++i)
                    out(items).or_throw();
                return data.size();
            });
            benchmark("deserialize", 5e8, 5, [&] {
                for (size_t i = 0; i < num_iters; ++i)
                    in(items).or_throw();
                return data.size();
            });
        };
    };
};