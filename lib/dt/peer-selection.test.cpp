/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/peer-selection.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite peer_selection_suite = [] {
    using namespace std::literals::string_literals;
    "peer_selection"_test = [] {
        auto &ps = peer_selection_simple::get();
        {
            static size_t num_rolls = 20;
            std::map<std::string, size_t> host_dist {};
            for (size_t i = 0; i < num_rolls; ++i) {
                auto host = ps.next_turbo();
                expect(host.starts_with("turbo"));
                ++host_dist[host];
            }
            expect(host_dist.size() >= 2);
            for (const auto &[host, freq]: host_dist)
                expect(static_cast<double>(freq) / num_rolls >= 0.25 * static_cast<double>(host_dist.size()) / num_rolls) << host << freq << num_rolls;
        }
        test_same("backbone.cardano.iog.io"s, ps.next_cardano().host);
    };
};