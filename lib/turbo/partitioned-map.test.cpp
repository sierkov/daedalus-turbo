/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/ledger/types.hpp>
#include <turbo/common/test.hpp>
#include <turbo/partitioned-map.hpp>
#include <turbo/zpp.hpp>
#include <boost/container/flat_map.hpp>

using namespace turbo;
using namespace cardano::ledger;

suite partitioned_map_suite = [] {
    "partitioned_map"_test = [] {
        "credential groups preserve global order"_test = [] {
            const auto check = []<typename Map>() {
                using credential = cardano::credential_t;
                Map actual;
                std::map<credential, int> expected;
                expect(actual.begin() == actual.end());
                for (const uint8_t prefix: { uint8_t { 0 }, uint8_t { 255 } }) {
                    for (const bool script: { false, true }) {
                        credential id { {}, script };
                        id.hash[0] = prefix;
                        actual.try_emplace(id, prefix);
                        expected.try_emplace(id, prefix);
                    }
                }
                // Exercise advancement within a group in the same partition.
                credential local_successor { {}, true };
                local_successor.hash.back() = 1;
                actual.try_emplace(local_successor, 1);
                expected.try_emplace(local_successor, 1);
                expect(actual.size() == 5_ul);
                const auto check_order = [&] {
                    const auto &view = actual;
                    auto it = view.begin();
                    for (const auto &[id, value]: expected) {
                        expect(fatal(it != view.end()));
                        expect(it->first == id);
                        expect(it->second == value);
                        expect(view.find(id) == it);
                        typename Map::const_iterator found = actual.find(id);
                        expect(found == it);
                        ++it;
                    }
                    expect(it == view.end());
                };
                check_order();
                auto mutable_it = actual.begin();
                for (const auto &[id, value]: expected) {
                    expect(fatal(mutable_it != actual.end()));
                    expect(mutable_it->first == id);
                    expect(mutable_it->second == value);
                    ++mutable_it;
                }
                expect(mutable_it == actual.end());
                static_map<credential, int> snapshot;
                snapshot = actual;
                for (const auto &[id, value]: expected)
                    expect(snapshot.at(id) == value);
                const auto restored = turbo::zpp::deserialize<Map>(turbo::zpp::serialize(actual));
                expect(restored == actual);
                expect(std::is_sorted(restored.begin(), restored.end(), [](const auto &a, const auto &b) {
                    return a.first < b.first;
                }));
                while (!expected.empty()) {
                    // The successor of a script can be in another partition,
                    // even when a key follows it in its local map.
                    const auto id = expected.begin()->first;
                    typename Map::const_iterator found = actual.find(id);
                    auto next = actual.erase(found);
                    expected.erase(expected.begin());
                    expect(next == actual.begin());
                    check_order();
                }
            };
            check.template operator()<partitioned_map<cardano::credential_t, int>>();
            check.template operator()<partitioned_map<cardano::credential_t, int,
                boost::container::flat_map<cardano::credential_t, int>>>();
        };
        "partition selection depends only on the hash prefix"_test = [] {
            using map_type = partitioned_map<cardano::credential_t, int>;
            for (size_t prefix = 0; prefix < map_type::num_parts; ++prefix) {
                for (const bool script: { false, true }) {
                    cardano::credential_t id { {}, script };
                    id.hash.fill(0xff);
                    id.hash[0] = static_cast<uint8_t>(prefix);
                    expect(map_type::partition_idx(id) == prefix);
                }
            }
        };
        using my_pmap = partitioned_map<cardano::stake_ident, reward_update_list>;
        using std_partition = std::map<cardano::stake_ident, reward_update_list>;
        using std_pmap = partitioned_map<cardano::stake_ident, reward_update_list, std_partition>;
        using flat_partition = boost::container::flat_map<cardano::stake_ident, reward_update_list>;
        using flat_pmap = partitioned_map<cardano::stake_ident, reward_update_list, flat_partition>;
        static_assert(std::forward_iterator<my_pmap::iterator>);
        static_assert(std::forward_iterator<my_pmap::const_iterator>);
        static_assert(std::ranges::forward_range<my_pmap>);
        static_assert(std::ranges::forward_range<const my_pmap>);
        my_pmap pm {};
        expect(pm.empty());
        my_pmap::partition_type part {};
        cardano::stake_ident stake1 { cardano::key_hash::from_hex("42FBE3C7DE5853FC74DA3C27DC583E7A660CCFF4042FBF12F223E53A"), false };
        cardano::stake_ident stake2 { cardano::key_hash::from_hex("00000000000000000000000000000000000000000000000000000000"), false };
        cardano::stake_ident stake3 { cardano::key_hash::from_hex("22222222222222222222222222222222222222222222222222222222"), false };
        cardano::stake_ident stake_missing { cardano::key_hash::from_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), false };
        auto pool1 = cardano::pool_hash::from_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        auto &rl = part[stake1];
        rl.emplace(reward_type::member, pool1, 12345);
        pm.partition(pm.partition_idx(stake1), std::move(part));
        expect(!pm.empty());
        expect(pm.size() == 1_ul);
        expect(pm.contains(stake1));
        expect(pm.at(stake1).size() == 1_ul);
        expect(pm[stake2].size() == 0_ul);
        expect(pm.size() == 2_ul);
        expect(pm.contains(stake2));
        expect(pm.at(stake2).size() == 0_ul);
        expect(pm.partition(pm.partition_idx(stake1)).get_allocator()
            != pm.partition(pm.partition_idx(stake2)).get_allocator());
        "iterate"_test = [&] {
            auto it = pm.begin();
            expect(it != pm.end());
            expect(it->first == stake2);
            expect(it->second.size() == 0_ul);
            ++it;
            expect(it->first == stake1);
            expect(it->second.size() == 1_ul);
            ++it;
            expect(it == pm.end());
        };
        "try_emplace"_test = [&] {
            {
                auto [it, created] = pm.try_emplace(stake3);
                expect(it->first == stake3);
                expect(it->second.size() == 0_ul);
                expect(created);
            }
            {
                auto [it, created] = pm.try_emplace(stake3);
                expect(it->first == stake3);
                expect(it->second.size() == 0_ul);
                expect(!created);
            }
            expect(pm.size() == 3_ul);
        };
        "range"_test = [&] {
            size_t cnt = 0;
            for (auto it = pm.begin(); it != pm.end(); ++it)
                cnt++;
            expect(cnt == 3_ul);
        };
        "erase"_test = [&] {
            {
                expect(pm.erase(stake_missing) == 0);
                expect(pm.size() == 3_ul);
            }
            {
                auto it = pm.find(stake3);
                it = pm.erase(it);
                expect(it != pm.end());
                expect(it == pm.find(stake1));
                expect(pm.size() == 2_ul);
            }
        };
        "find"_test = [&] {
            expect(pm.find(stake_missing) == pm.end());
            auto it = pm.find(stake1);
            expect(pm.find(stake1) != pm.end());
            expect(it->first == stake1);
            expect(it->second.size() == 1_ul);
        };
        "clear and reuse"_test = [&] {
            const auto old_alloc = pm.partition(pm.partition_idx(stake1)).get_allocator();
            pm.clear();
            expect(pm.empty());
            expect(pm.partition(pm.partition_idx(stake1)).get_allocator() != old_alloc);
            auto [it, created] = pm.try_emplace(stake1);
            expect(created);
            expect(it == pm.find(stake1));
        };
        "partition container policy"_test = [&] {
            std::map<cardano::stake_ident, reward_update_list> source {};
            source.try_emplace(stake1);
            std_pmap std_pm { source };
            my_pmap pooled { source };
            const auto encoded = turbo::zpp::serialize(std_pm);
            expect(encoded == turbo::zpp::serialize(pooled));
            expect(turbo::zpp::deserialize<my_pmap>(encoded) == pooled);
            auto std_it = std_pm.find(stake1);
            expect(std_it != std_pm.end());
            expect(std_it == std_pm.find(stake1));
            std_pm.clear();
            expect(std_pm.empty());

            flat_pmap flat_pm { source };
            auto flat_it = flat_pm.find(stake1);
            expect(flat_it != flat_pm.end());
            expect(flat_it == flat_pm.find(stake1));
            flat_pm.clear();
            expect(flat_pm.empty());
        };
    };
};
