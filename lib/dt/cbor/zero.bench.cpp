/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/benchmark.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/file.hpp>

using namespace daedalus_turbo;

namespace {
    template<size_t BATCH>
    size_t byte_scan_unroll(const buffer data)
    {
        if (reinterpret_cast<std::uintptr_t>(data.data()) % BATCH != 0)
            throw error("unaligned data!");
        if (data.size() % BATCH != 0)
            throw error("unpadded data!");
        size_t cnt = 0;
        for (const auto *ptr = data.data(), *end = data.data() + data.size(); ptr < end; ptr += BATCH) {
            for (size_t i = 0; i < BATCH; ++i) {
                if (ptr[i] == 0x80) [[unlikely]]
                    ++cnt;
            }
        }
        return cnt;
    }

    template<size_t BATCH>
    size_t byte_scan_unroll_dec_table(const buffer data, const std::array<uint8_t, 256> &dec_table)
    {
        if (reinterpret_cast<std::uintptr_t>(data.data()) % BATCH != 0)
            throw error("unaligned data!");
        if (data.size() % BATCH != 0)
            throw error("unpadded data!");
        size_t cnt = 0;
        for (const auto *ptr = data.data(), *end = data.data() + data.size(); ptr < end; ptr += BATCH) {
            for (size_t i = 0; i < BATCH; ++i)
                cnt += dec_table[ptr[i]];
        }
        return cnt;
    }
}

suite cbor_zero_bench_suite = [] {
    "cbor::zero"_test = [&] {
        static const std::string test_path { "./data/chunk-registry/compressed/chunk/977E9BB3D15A5CFF5C5E48617288C5A731DB654C0B42D63627C690CEADC9E1F3.zstd" };
        const auto chunk_data = file::read(test_path);
        benchmark("decoder", 1e9, 3, [&chunk_data] {
            cbor::zero::decoder dec { chunk_data };
            size_t parsed = 0;
            while (!dec.done()) {
                const auto val = dec.read();
                parsed += val.raw_span().size();
            }
            return parsed;
        });
        uint8_vector data {};
        static constexpr size_t max_batch = 64;
        data.reserve((1ULL << 30) + chunk_data.size() + max_batch);
        while (data.size() < 1ULL << 30)
            data << chunk_data;
        while (data.size() % max_batch != 0)
            data.emplace_back(0);
        benchmark_throughput("byte scanning: range", 3, [&data] {
            size_t cnt = 0;
            for (const auto b: data) {
                if (b == 0x80) [[unlikely]]
                    ++cnt;
            }
            // needed so that the compilier does not optimize the computation of cnt
            logger::trace("byte scan: {}", cnt);
            return data.size();
        });
        benchmark_throughput("byte scanning: iterator", 3, [&data] {
            size_t cnt = 0;
            for (auto it = data.begin(), end = data.end(); it != end; ++it) {
                if (*it == 0x80) [[unlikely]]
                    ++cnt;
            }
            // needed so that the compilier does not optimize the computation of cnt
            logger::trace("byte scan: {}", cnt);
            return data.size();
        });
        benchmark_throughput("byte scanning: index", 3, [&data] {
            size_t cnt = 0;
            for (size_t i = 0, end = data.size(); i < end; ++i) {
                if (data[i] == 0x80) [[unlikely]]
                    ++cnt;
            }
            // needed so that the compilier does not optimize the computation of cnt
            logger::trace("byte scan: {}", cnt);
            return data.size();
        });
        benchmark_throughput("byte scanning: pointer", 3, [&data] {
            size_t cnt = 0;
            for (const auto *ptr = data.data(), *end = data.data() + data.size(); ptr < end; ++ptr) {
                if (*ptr == 0x80) [[unlikely]]
                    ++cnt;
            }
            // needed so that the compilier does not optimize the computation of cnt
            logger::trace("byte scan: {}", cnt);
            return data.size();
        });
        benchmark_throughput(fmt::format("byte scanning: unrolled loop batch of 8"), 3, [&data] {
           // needed so that the compilier does not optimize the computation of cnt
           logger::trace("byte scan: {}", byte_scan_unroll<8>(data));
           return data.size();
        });
        benchmark_throughput(fmt::format("byte scanning: unrolled loop batch of 16"), 3, [&data] {
           // needed so that the compilier does not optimize the computation of cnt
           logger::trace("byte scan: {}", byte_scan_unroll<16>(data));
           return data.size();
        });
        benchmark_throughput(fmt::format("byte scanning: unrolled loop batch of 64"), 3, [&data] {
           // needed so that the compilier does not optimize the computation of cnt
           logger::trace("byte scan: {}", byte_scan_unroll<64>(data));
           return data.size();
        });
        {
            std::array<uint8_t, 256> decision_table {};
            decision_table[0x80] = 1;
            benchmark_throughput("byte scanning: decision table", 3, [&] {
                size_t cnt = 0;
                for (const auto b: data)
                    cnt += decision_table[b];
                // needed so that the compilier does not optimize the computation of cnt
                logger::trace("byte scan: {}", cnt);
                return data.size();
            });
            benchmark_throughput(fmt::format("byte scanning: unrolled loop batch of 64"), 3, [&] {
               // needed so that the compilier does not optimize the computation of cnt
               logger::trace("byte scan: {}", byte_scan_unroll_dec_table<64>(data, decision_table));
               return data.size();
            });
        }
    };
};