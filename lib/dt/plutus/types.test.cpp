/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/test.hpp>
#include <dt/plutus/types.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::plutus;

suite plutus_types_suite = [] {
    using namespace std::string_literals;
    "plutus::types"_test = [] {
        "version"_test = [&] {
            {
                const version v { "0.1.2" };
                test_same(0, v.major);
                test_same(1, v.minor);
                test_same(2, v.patch);
                test_same("0.1.2"s, static_cast<std::string>(v));
                expect(throws([]{ version { "0.2" }; }));
                expect(throws([]{ version { ".0.2.3" }; }));
                expect(throws([]{ version { "0.b.3" }; }));
                expect(throws([]{ version { "0.1.." }; }));
                expect(throws([]{ version { "0.1.3." }; }));
                expect(throws([]{ version { "0.1.3c" }; }));
                expect(throws([]{ version { " 0.1.3" }; }));
                expect(throws([]{ version { "0.1.3 " }; }));
            }
            {
                test_same(true, version { "1.1.0" } >= "1.0.0");
                test_same(true, version { "1.1.0" } >= "1.1.0");
                test_same(true, version { "2.0.0" } >= "1.9.10");
                test_same(true, version { "1.2.0" } >= "1.1.10");
                test_same(true, version { "1.2.1" } >= "1.2.0");
                test_same(false, version { "1.1.0" } >= "1.1.1");
                test_same(false, version { "1.1.9" } >= "1.2.3");
                test_same(false, version { "1.2.3" } >= "2.0.7");
            }
        };
    };
};