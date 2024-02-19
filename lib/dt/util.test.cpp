/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/array.hpp>
#include <dt/util.hpp>

using namespace std::literals;
using namespace boost::ut;
using namespace daedalus_turbo;

suite util_suite = [] {
    "util"_test = [] {
        "binary_search"_test = [] {
            array<int, 8> data { 0, 10, 20, 30, 40, 50, 60, 70 };
            std::vector<std::pair<int, bool>> test_vector {
                { -1, false }, { 0, true }, { 5, false }, { 30, true },
                { 50, true }, { 65, false }, { 70, true }, { 75, false }
            };
            for (const auto &[val, exp]: test_vector) {
                auto it = binary_search(data.begin(), data.end(), val, [&](const auto &el, const auto &val) { return el < val; });
                expect((it != data.end()) == exp);
                if (it != data.end()) expect(*it == val);
            }
        };

        "net_to_host"_test = [] {
            static int x = 1;
            uint64_t val = 0x00000000DEADBEAF;
            expect(net_to_host(host_to_net(val)) == val);
            if (*reinterpret_cast<char *>(&x) == 1) {
                expect(host_to_net(val) == 0xAFBEADDE00000000);
                expect(net_to_host(0xAFBEADDE00000000) == val);
            }
        };

        "buffer_readable"_test = [] {
            {
                auto bytes = bytes_from_hex("2389d40886678db816de5ff85d81c12aaec51b11dcb0187aed73a815838cc5a7");
                auto text = fmt::format("{}", buffer_readable { bytes });
                expect(text == "2389D40886678DB816DE5FF85D81C12AAEC51B11DCB0187AED73A815838CC5A7") << text;
            }
            {
                auto bytes = bytes_from_hex("534f554c");
                auto text = fmt::format("{}", buffer_readable { bytes });
                expect(text == "SOUL") << text;
            }
        };
    };
};