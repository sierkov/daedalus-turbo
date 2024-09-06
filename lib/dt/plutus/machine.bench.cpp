/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/plutus/machine.hpp>
#include <dt/benchmark.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::plutus;

suite plutus_machine_bench_suite = [] {
    "plutus::machine"_test = [] {
        benchmark_rate("term create", 1'000'000, [&] {
            const term t { term_tag::error };
            return 1;
        });
        {
            const term t { term_tag::error };
            benchmark_rate("term copy", 1'000'000, [&] {
                const auto t2 = t;
                return 1;
            });
        }
        {
            const term t { term_tag::error };
            benchmark_rate("term return-value optimization", 1'000'000, [&] {
                const auto t2 = [&t] { auto tl = t; return tl; }();
                return 1;
            });
        }
        benchmark_rate("term shared_ptr create", 1'000'000, [&] {
            const auto t = std::make_shared<term>(term_tag::error);
            return 1;
        });
        {
            const auto t = std::make_shared<term>(term_tag::error);
            benchmark_rate("term shared_ptr copy", 1'000'000, [&] {
                const auto t2 = t;
                return 1;
            });
        }
        benchmark_rate("term unique_ptr create", 1'000'000, [&] {
            const auto t = std::make_unique<term>(term_tag::error);
            return 1;
        });
        {
            const auto t = std::make_unique<term>(term_tag::error);
            benchmark_rate("const ptr copy", 1'000'000, [&] {
                const auto *t2 = t.get();
                return 1;
            });
        }
    };
};