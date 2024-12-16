/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/benchmark.hpp>
#include <dt/cardano.hpp>
#include <dt/cbor.hpp>
#include <dt/file.hpp>

using namespace daedalus_turbo;

namespace {
    struct static_a {
        uint64_t m1() const
        {
            return 213;
        }
    };

    struct static_b {
        uint64_t m1() const
        {
            return 222;
        }
    };

    struct static_c {
        uint64_t m1() const
        {
            return 999;
        }
    };

    using static_any = std::variant<static_a, static_b, static_c>;

    struct dynamic_base {
        virtual ~dynamic_base() =default;
        virtual uint64_t m1() const =0;
    };

    struct dynamic_a: dynamic_base {
        uint64_t m1() const override
        {
            return 213;
        }
    };

    struct dynamic_b: dynamic_base {
        uint64_t m1() const override
        {
            return 222;
        }
    };

    struct dynamic_c: dynamic_base {
        uint64_t m1() const override
        {
            return 999;
        }
    };
}

suite cardano_common_bench_suite = [] {
    "cardano::common"_test = [] {
        "block method vs direct CBOR access"_test = [] {
            auto extract_slot = [&](const cbor_value &bt) { return bt.array().at(1).array().at(0).array().at(0).array().at(1).uint(); };
            auto chunk = file::read("./data/chunk-registry/compressed/chunk/977E9BB3D15A5CFF5C5E48617288C5A731DB654C0B42D63627C690CEADC9E1F3.zstd");
            cbor_parser parser { chunk };
            expect(!parser.eof());
            cbor_value block_tuple;
            parser.read(block_tuple);
            auto blk = cardano::make_block(block_tuple, 0);
            const auto &blk_ref = *blk;
            expect(blk_ref.slot() == extract_slot(block_tuple));
            size_t num_iter = 100'000'000;
            auto struct_r = benchmark_rate("extract slot structured", 3, [&] {
                for (size_t i = 0; i < num_iter; ++i) {
                    blk_ref.slot();
                }
                return num_iter;
            });
            auto raw_r = benchmark_rate("extract slot direct", 3, [&] {
                for (size_t i = 0; i < num_iter; ++i) {
                    extract_slot(block_tuple);
                }
                return num_iter;
            });
            expect(struct_r >= 10e6);
            expect(raw_r >= 10e6);
        };
        "static vs dynamic polymorphism"_test = [] {
            static constexpr size_t num_iter = 10e7;
            daedalus_turbo::vector<static_any> s_objs { static_a {}, static_b {}, static_c {} };
            const auto stat = benchmark_rate("static polymorphism", 3, [&s_objs] {
                uint64_t sum = 0;
                for (size_t i = 0; i < num_iter; ++i) {
                    for (const auto &obj : s_objs)
                        std::visit([&sum](const auto &obj) {
                            sum += obj.m1();
                        }, obj);
                }
                if (sum == 1434 * num_iter) [[likely]]
                    return num_iter * s_objs.size();
                throw error(fmt::format("invalid sum: {}", sum));
            });
            daedalus_turbo::vector<std::unique_ptr<dynamic_base>> d_objs {};
            d_objs.emplace_back(std::make_unique<dynamic_a>());
            d_objs.emplace_back(std::make_unique<dynamic_b>());
            d_objs.emplace_back(std::make_unique<dynamic_c>());
            const auto dyn = benchmark_rate("dynamic polymorphism", 3, [&d_objs] {
                uint64_t sum = 0;
                for (size_t i = 0; i < num_iter; ++i) {
                    for (const auto &obj : d_objs)
                        sum += obj->m1();
                }
                if (sum == 1434 * num_iter) [[likely]]
                    return num_iter * d_objs.size();
                throw error(fmt::format("invalid sum: {}", sum));
            });
            expect(stat > dyn) << stat << dyn;
        };
    };    
};