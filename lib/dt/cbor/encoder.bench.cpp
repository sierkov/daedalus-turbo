/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cbor/encoder.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/benchmark.hpp>
#include <dt/container.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;
namespace dt = daedalus_turbo;

suite cbor_encoder_bench_suite = [] {
    "cbor::encoder"_test = [] {
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
                cbor::encoder enc {};
                enc.map(items.size());
                for (const auto &[k, vals]: items) {
                    enc.text(k);
                    enc.array(vals.size());
                    for (const auto v: vals)
                        enc.uint(v);
                }
                data = std::move(enc.cbor());
                return data.size();
            });
            volatile size_t do_not_optimize;
            benchmark("deserialize", 5e8, 5, [&] {
                const auto v = cbor::zero::parse(data);
                test_item out_items {};
                auto m_it = v.map();
                while (!m_it.done()) {
                    const auto [k, c_vals] = m_it.next();
                    dt::set<uint64_t> vals {};
                    auto v_it = c_vals.array();
                    while (!v_it.done()) {
                        vals.emplace(v_it.next().uint());
                    }
                    out_items.try_emplace(std::string { k.text() }, std::move(vals));
                }
                do_not_optimize = out_items.size();
                return data.size();
            });
        };
    };
};
