/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/test.hpp>
#include <dt/container.hpp>

using namespace daedalus_turbo;

namespace {
    using std::string_literals::operator""s;
}

suite container_suite = [] {
    "container"_test = [] {
        "flat_map"_test = [] {
            "implicit_sort"_test = [] {
                flat_map<std::string, uint64_t> m {};
                m.emplace("b"s, 2);
                m.emplace("a"s, 3);
                m.emplace("c"s, 1);
                test_same(3, m.size());
                test_same("a"s, m.begin()->first);
                test_same("b"s, std::next(m.begin())->first);
                test_same("c"s, std::prev(m.end())->first);
            };
            "implicit_sort_2"_test = [] {
                flat_map<std::string, uint64_t> m {};
                m.emplace_hint(m.end(), "b"s, 2);
                m.emplace_hint(m.end(), "a"s, 3);
                m.emplace_hint(m.end(), "c"s, 1);
                test_same(3, m.size());
                test_same("a"s, m.begin()->first);
                test_same("b"s, std::next(m.begin())->first);
                test_same("c"s, std::prev(m.end())->first);
            };
        };
    };
};