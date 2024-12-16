/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/zpp-stream.hpp>
#include <dt/benchmark.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite zpp_stream_bench_suite = [] {
    "zpp_stream"_test = [] {
        static constexpr size_t num_items = 1e5;
        benchmark("write and read cycle", 200e6, 3, [] {
            using data_type = std::array<size_t, 10>;
            file::tmp tmp { "bench-zpp-1.bin" };
            {
                zpp_stream::write_stream ws { tmp };
                data_type data {};
                for (size_t i = 0; i < num_items; ++i) {
                    std::ranges::fill(data, i);
                    ws.write(data);
                }
            }
            {
                zpp_stream::read_stream rs { tmp };
                for (size_t i = 0; i < num_items; ++i) {
                    const auto data = rs.read<data_type>();
                    for (const auto act_i: data)
                        if (act_i != i) [[unlikely]]
                            throw error(fmt::format("unexpected value: {} when waiting for {}", act_i, i));
                }
            }
            return num_items * sizeof(data_type) * 2;
        });
    };
};
