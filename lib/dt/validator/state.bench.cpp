/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <set>
#include <map>
#include <unordered_map>
#include <ranges>
#include <boost/container/flat_map.hpp>
#include <boost/container/flat_set.hpp>
#include <dt/benchmark.hpp>
#include <dt/file.hpp>
#include <dt/scheduler.hpp>
#include <dt/validator/state.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;
using namespace daedalus_turbo::validator;

namespace {
    template<typename T>
    static void bench_create(const std::string &name, size_t sz)
    {
        benchmark_r(fmt::format("{} create and destroy {} items", name, sz), 1'000'000.0, 3, [&] {
            T m {};
            cardano::stake_ident stake_id {};
            for (size_t i = 0; i < sz; ++i) {
                span_memcpy(std::span(stake_id.hash.begin(), stake_id.hash.begin() + 8), buffer::from<size_t>(i));
                m[stake_id] = i;
            }
            return sz;
        });
    }
}

suite validator_state_bench_suite = [] {
    using test_map = std::map<cardano::stake_ident, uint64_t>;
    using test_umap = std::unordered_map<cardano::stake_ident, uint64_t>;
    using test_fmap = boost::container::flat_map<cardano::stake_ident, uint64_t>;
    using test_vec = std::vector<std::pair<cardano::stake_ident, uint64_t>>;
    scheduler sched {};
    "validator::state"_test = [&] {
        "create and destroy"_test = [] {
            for (size_t sz: { 10, 1000, 100'000 }) {
                bench_create<test_map>("std::map", sz);
                bench_create<test_umap>("std::unordered_map", sz);
                bench_create<test_fmap>("boost::container::flat_map", sz);
            }
        };
        "copy ordered"_test = [] {
            for (size_t sz: { 1000, 1'000'000 }) {
                test_map src {};
                cardano::stake_ident stake_id {};
                for (size_t i = 0; i < sz; ++i) {
                    span_memcpy(std::span(stake_id.hash.begin(), stake_id.hash.begin() + 8), buffer::from<size_t>(i));
                    src[stake_id] = i;
                }
                benchmark_r(fmt::format("fmap copy {} items", sz), 1'000'000.0, 3, [&] {
                    test_fmap dst {};
                    dst.reserve(src.size());
                    for (const auto &[stake_id, amount]: src)
                        dst.emplace(stake_id, amount);
                    return sz;
                });
                benchmark_r(fmt::format("umap copy {} items", sz), 1'000'000.0, 3, [&] {
                    test_umap dst {};
                    dst.reserve(src.size());
                    for (const auto &[stake_id, amount]: src)
                        dst.emplace(stake_id, amount);
                    return sz;
                });
                benchmark_r(fmt::format("map copy {} items", sz), 1'000'000.0, 3, [&] {
                    test_map dst {};
                    for (const auto &[stake_id, amount]: src)
                        dst.emplace(stake_id, amount);
                    return sz;
                });
                benchmark_r(fmt::format("vector copy {} items", sz), 1'000'000.0, 3, [&] {
                    test_vec dst {};
                    dst.reserve(src.size());
                    for (const auto &[stake_id, amount]: src)
                        dst.emplace_back(stake_id, amount);
                    return sz;
                });
                benchmark_r(fmt::format("vector copy & sort {} items", sz), 1'000'000.0, 3, [&] {
                    test_vec dst {};
                    dst.reserve(src.size());
                    for (const auto &[stake_id, amount]: src | std::views::reverse)
                        dst.emplace_back(stake_id, amount);
                    std::sort(dst.begin(), dst.end());
                    return sz;
                });
            }
        };
        "iterate over"_test = [] {
            for (size_t sz: { 1000, 1'000'000 }) {
                test_map src {};
                cardano::stake_ident stake_id {};
                for (size_t i = 0; i < sz; ++i) {
                    span_memcpy(std::span(stake_id.hash.begin(), stake_id.hash.begin() + 8), buffer::from<size_t>(i));
                    src[stake_id] = i;
                }
                benchmark_r(fmt::format("map iterate over {} items", sz), 1'000'000.0, 3, [&] {
                    uint64_t total = 0;
                    for (const auto &[stake_id, amount]: src)
                        total += amount;
                    logger::trace("total: {}", total);
                    return sz;
                });

                test_umap umap {};
                umap.reserve(src.size());
                for (const auto &[stake_id, amount]: src)
                    umap.emplace(stake_id, amount);
                benchmark_r(fmt::format("umap iterate over {} items", sz), 1'000'000.0, 3, [&] {
                    uint64_t total = 0;
                    for (const auto &[stake_id, amount]: umap)
                        total += amount;
                    logger::trace("total: {}", total);
                    return sz;
                });

                test_vec vec {};
                vec.reserve(src.size());
                for (const auto &[stake_id, amount]: src)
                    vec.emplace_back(stake_id, amount);
                benchmark_r(fmt::format("vec iterate over {} items", sz), 1'000'000.0, 3, [&] {
                    uint64_t total = 0;
                    for (const auto &[stake_id, amount]: vec)
                        total += amount;
                    logger::trace("total: {}", total);
                    return sz;
                });
            }
        };
        "set copy"_test = [] {
            for (size_t sz: { 10, 100, 1000, 10'000 }) {
                {
                    std::set<cardano::stake_ident> stakes {};
                    cardano::stake_ident stake_id {};
                    for (size_t i = 0; i < sz; ++i) {
                        span_memcpy(std::span(stake_id.hash.begin(), stake_id.hash.begin() + 8), buffer::from<size_t>(i));
                        stakes.emplace(stake_id);
                    }
                    benchmark_r(fmt::format("std::set copy {} items", sz), 1'000'000.0, 3, [&] {
                        std::set<cardano::stake_ident> copy { stakes };
                        return sz;
                    });
                }
                {
                    boost::container::flat_set<cardano::stake_ident> stakes {};
                    cardano::stake_ident stake_id {};
                    for (size_t i = 0; i < sz; ++i) {
                        span_memcpy(std::span(stake_id.hash.begin(), stake_id.hash.begin() + 8), buffer::from<size_t>(i));
                        stakes.emplace(stake_id);
                    }
                    benchmark_r(fmt::format("flast_set copy {} items", sz), 1'000'000.0, 3, [&] {
                        boost::container::flat_set<cardano::stake_ident> copy { stakes };
                        return sz;
                    });
                }
            }
        };
        "finish_epoch"_test = [&] {
            state s { sched };
            auto zpp_data = file::read("./data/validator-state/state-460.bin");
            zpp::bits::in in { zpp_data };
            in(s).or_throw();
            benchmark_r("finish_epoch", 1.0, 1, [&] {
                s.finish_epoch();
                return 3;
            });
        };
    };
};