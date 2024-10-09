/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/container.hpp>
#include <dt/plutus/machine.hpp>
#include <dt/plutus/uplc.hpp>
#include <dt/benchmark.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::plutus;

suite plutus_machine_bench_suite = [] {
    "plutus::machine"_test = [] {
        "unique_ptr vs shared_ptr vs allocator"_test = [] {
            plutus::allocator alloc {};
            const auto sptr_rate = benchmark_rate("std::shared_ptr", 1'000'000, [&] {
                const auto p = std::make_shared<value::value_type>(plutus::constant { alloc, cpp_int { 22 } });
                const volatile auto p2 = p;
                return 1;
            });
            const auto uptr_rate = benchmark_rate("std::unique_ptr", 1'000'000, [&] {
                const auto p = std::make_unique<value::value_type>(plutus::constant { alloc, cpp_int { 22 } });
                const volatile auto p2 = std::make_unique<value::value_type>(*p);
                return 1;
            });
            const auto mbr_rate = benchmark_rate("allocator", 1'000'000, [&] {
                const auto p = alloc.make<value::value_type>(plutus::constant { alloc, cpp_int { 22 } });
                const volatile auto p2 = p;
                return 1;
            });
            expect(sptr_rate > uptr_rate) << uptr_rate << sptr_rate;
            expect(uptr_rate > mbr_rate) << uptr_rate << mbr_rate;
        };
        "switch variant.index() vs std::visit"_test = [] {
            using val_type = std::variant<uint64_t, std::string, uint8_vector>;
            std::vector<val_type> vals { { uint8_vector::from_hex("00112233") }, { "abc" }, { 123ULL } };
            const auto switch_rate = benchmark_rate("switch", 1'000'000, [&] {
                uint64_t res = 0;
                for (const auto &val: vals) {
                    switch (val.index()) {
                        case 0: res += sizeof(uint64_t); break;
                        case 1: res += std::get<std::string>(val).size(); break;
                        case 2: res += std::get<uint8_vector>(val).size(); break;
                        default: throw error("unsupported variant index: {}", val.index());
                    }
                }
                return std::min(static_cast<uint64_t>(vals.size()), res); // make the optimizer keep the res calculation
            });
            const auto visit_rate = benchmark_rate("visit", 1'000'000, [&] {
                uint64_t res = 0;
                for (const auto &val: vals) {
                    res += std::visit([](const auto &v) {
                        using T = std::decay_t<decltype(v)>;
                        if constexpr (std::is_same_v<T, uint64_t>)
                            return sizeof(v);
                        else
                            return v.size();
                    }, val);
                }
                return std::min(static_cast<uint64_t>(vals.size()), res);
            });
            expect(static_cast<double>(visit_rate) / switch_rate > 0.95) << visit_rate << switch_rate;
        };
        {
            plutus::allocator s_alloc {};
            daedalus_turbo::vector<uplc::script> scripts {};
            for (const auto &path: file::files_with_ext(install_path("./data/plutus/conformance/example"), ".uplc")) {
                if (!path.stem().string().starts_with("DivideByZero"))
                    scripts.emplace_back(s_alloc, file::read(path.string()));
            }
            benchmark_r("conformance examples", 1e9, 5, [&] {
                uint64_t total_steps = 0;
                for (const auto &s: scripts) {
                    plutus::allocator m_alloc {};
                    machine m { m_alloc };
                    const auto res = m.evaluate(s.program());
                    total_steps += res.cost.steps;
                }
                return std::max(total_steps, static_cast<uint64_t>(1));
            });
        }
    };
};