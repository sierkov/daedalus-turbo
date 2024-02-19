/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <random>
#include <dt/benchmark.hpp>
#include <dt/index/common.hpp>
#include <dt/file.hpp>

namespace {
    using namespace boost::ut;
    using namespace daedalus_turbo;
    using namespace daedalus_turbo::index;

    struct index_item {
        uint64_t offset = 0;
        uint16_t out_idx = 0;

        bool index_less(const index_item &b) const
        {
            return offset < b.offset;
        }

        bool operator<(const index_item &b) const
        {
            if (offset != b.offset) return offset < b.offset;
            return out_idx < b.out_idx;
        }

        bool operator==(const index_item &b) const
        {
            return offset == b.offset;
        }
    };
}      

suite index_common_bench_suite = [] {
    "index::common"_test = [] {
        {
            file::tmp idx_path { "index-writer-bench" }, data_path { "index-writer-bench.data" }, meta_path { "index-writer-bench.meta" };
            size_t num_items = 10'000'000;
            benchmark("writer", 50'000'000.0, 3, [&] {
                writer<index_item> idx { idx_path };
                for (size_t i = 0; i < num_items; ++i) {
                    idx.emplace(i * 2, (uint16_t)12);
                }
                return num_items * sizeof(index_item);
            });
            benchmark("reader", 50'000'000.0, 3, [&] {
                reader<index_item> idx { idx_path };
                size_t read_items = 0;
                index_item item {};
                while (idx.read(item)) {
                    ++read_items;
                }
                return read_items * sizeof(index_item);
            });
        }

        {
            file::tmp idx_path { "index-writer-test" }, data_path { "index-writer-test.data" }, meta_path { "index-writer-test.meta" };
            size_t num_parts = 4;
            size_t num_items = 10'000'000 / num_parts;
            benchmark("writer partitioned", 50'000'000.0, 3, [&] {
                writer<index_item> idx { idx_path, num_parts };
                for (size_t i = 0; i < num_items; ++i) {
                    for (size_t p = 0; p < num_parts; ++p)
                        idx.emplace_part(p, p * num_items + i, (uint16_t)(i % 12));
                }
                return num_items * num_parts * sizeof(index_item);
            });
            benchmark("reader partitioned", 50'000'000.0, 3, [&] {
                reader<index_item> idx { idx_path };
                index_item item {};
                size_t read_items = 0;
                for (size_t p = 0; p < num_parts; p++) {
                    while (idx.read_part(p, item)) {
                        ++read_items;
                    }
                }
                return read_items * sizeof(index_item);
            });
        }

        {
            file::tmp idx_path { "index-writer-test" }, data_path { "index-writer-test.data" }, meta_path { "index-writer-test.meta" };
            size_t num_items = 0x98765; // more than the default cache sparsity to test both branches of index search
            size_t chunk_size = writer<index_item>::default_chunk_size;
            size_t part_size = chunk_size * 3;
            size_t num_parts = (num_items + part_size - 1) / part_size;
            {
                writer<index_item> idx { idx_path, num_parts };
                for (size_t i = 0; i < num_items; i += 2)
                    idx.emplace_part(i / part_size, i, static_cast<uint16_t>(i % 13));
            }
            {
                reader<index_item> reader { idx_path };
                benchmark_r("partitioned sequential search", 5'000'000.0, 10, [&] {
                    index_item item {};
                    for (size_t i = 0; i < num_items; i += 2) {
                        item.offset = i;
                        reader.find(item);
                    }
                    return num_items / 2;
                });
                benchmark_r("partitioned sequential search for missing item", 5'000'000.0, 10, [&] {
                    index_item item {};
                    for (size_t i = 1; i < num_items; i += 2) {
                        item.offset = i;
                        reader.find(item);
                    }
                    return num_items / 2;
                });
                std::seed_seq seed { 0, 1, 2, 3, 4, 5 };
                std::default_random_engine rnd(seed);
                std::uniform_int_distribution<size_t> dist(0, num_items);
                size_t sample_size = 10'000;
                benchmark_r("partitioned random search", 1'000.0, 3, [&] {
                    index_item item {};
                    for (size_t i = 1; i < sample_size; ++i) {
                        item.offset = dist(rnd);
                        reader.find(item);
                    }
                    return sample_size;
                });
            }
        }

        "multi-part indices"_test = [] {
            size_t num_parts = 8;
            size_t num_items = 0x39873;
            std::vector<std::string> paths {};
            for (size_t pi = 0; pi < num_parts; ++pi) {
                auto path = fmt::format("./tmp/index-writer-{}-multi-index-bench", pi);
                paths.emplace_back(path);
                writer<index_item> idx { path };
                for (size_t j = 0; j < num_items; j++)
                    idx.emplace(j * (pi + 1));
            }
            {
                reader_multi<index_item> reader { paths };
                expect(reader.size() == num_items * num_parts);
                std::seed_seq seed { 0, 1, 2, 3, 4, 5 };
                std::default_random_engine rnd(seed);
                std::uniform_int_distribution<size_t> dist(0, num_items * num_parts);
                size_t sample_size = 10'000;
                benchmark_r("multi-part index random search", 1'000.0, 3, [&] {
                    index_item item {};
                    for (size_t i = 1; i < sample_size; ++i) {
                        item.offset = dist(rnd);
                        reader.find(item);
                    }
                    return sample_size;
                });
            }
            for (const auto &path: paths)
                writer<index_item>::remove(path);
        };
    };    
};