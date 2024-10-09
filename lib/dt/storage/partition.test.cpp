/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/storage/partition.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::storage;

suite storage_partition_suite = [] {
    "storage::partition"_test = [] {
        static std::string data_dir = install_path("./data/chunk-registry");
        const chunk_registry cr { data_dir, chunk_registry::mode::store };
        "partition_map"_test = [&] {
            {
                const partition_map pm { cr };
                test_same(cr.num_chunks(), pm.size());
            }
            {
                const partition_map pm { cr, 4 };
                test_same(4, pm.size());
                expect(nothrow([&] { pm.find(0); }));
                expect(nothrow([&] { pm.find(cr.num_bytes() - 1); }));
                expect(throws([&] { pm.find(cr.num_bytes()); }));
                test_same(0, pm.find_no(0));
                test_same(3, pm.find_no(cr.num_bytes() - 1));
                for (const auto off: { uint64_t { 0 }, cr.num_bytes() / 2, cr.num_bytes() - 1 }) {
                    const auto &p = pm.find(off);
                    expect(p.offset() <= off) << p.offset() << off;
                    expect(p.end_offset() > off) << p.end_offset() << off;
                }
            }
        };
        "parse_parallel"_test = [&] {
            std::atomic_uint64_t num_parsed { 0 };
            parse_parallel(cr, 4,
                [&](const auto &blk, std::any &tmp) {
                    tmp = std::any_cast<uint64_t>(tmp) + blk.size();
                },
                [&](const size_t) {
                    return uint64_t { 0 };
                },
                [&](const size_t, std::any &&tmp) {
                    num_parsed.fetch_add(std::any_cast<uint64_t>(std::move(tmp)), std::memory_order_relaxed);
                }
            );
            test_same(cr.num_bytes(), num_parsed.load(std::memory_order_relaxed));
        };
    };
};