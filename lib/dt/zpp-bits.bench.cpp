/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/benchmark.hpp>
#include <dt/container.hpp>
#include <dt/zpp.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;
namespace dt = daedalus_turbo;

suite zpp_bits_bench_suite = [] {
    "zpp::bits"_test = [] {
        "map of sets"_test = [] {
            using test_item = dt::map<std::string, dt::set<uint64_t>>;
            test_item items {};
            for (size_t i = 0; i < 1024; ++i) {
                auto &set = items[fmt::format("item{}", i)];
                if (i % 2) {
                    set.emplace(1234);
                    set.emplace(12);
                } else {
                    set.emplace(0);
                }
            }
            uint8_vector data {};
            benchmark("serialize map of sets", 1e8, 5, [&] {
                auto out = ::zpp::bits::out(data);
                out(items).or_throw();
                return data.size();
            });
            test_item out_items {};
            volatile size_t do_not_optimize;
            benchmark("deserialize", 5e8, 5, [&] {
                auto in = ::zpp::bits::in(data);
                in(out_items).or_throw();
                do_not_optimize = out_items.size();
                return data.size();
            });
        };
    };
};
