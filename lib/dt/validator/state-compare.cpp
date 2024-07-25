/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/blake2b.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/compare.hpp>
#include <dt/scheduler.hpp>
#include <dt/timer.hpp>
#include <dt/validator/state-compare.hpp>

namespace daedalus_turbo::validator {
    using namespace cbor::zero;

    static bool compare(const std::string_view name, const value v1, const value v2, const bool print_values=false)
    {
        const auto v1_data = v1.raw_span();
        const auto v2_data = v2.raw_span();
        const bool res = v1 == v2;
        if (res) {
            logger::info("{} values match", name);
        } else {
            const auto typ = v1.type();
            if ((typ != major_type::array && typ != major_type::map) || print_values)
                logger::warn("{} values do not match: size1: {} size2: {}\nval1: {} val2: {}",
                    name, v1_data.size(), v2_data.size(), v1, v2);
            else
                logger::warn("{} values do not match: size1: {} size2: {} type1: {} type2: {}",
                    name, v1_data.size(), v2_data.size(), v1.type(), v2.type());
        }
        return res;
    }

    static bool compare_sizes(const std::string_view name, const value s1, const value s2, const size_t sz_exp)
    {
        const bool res = s1.size() == s2.size() && s1.size() == sz_exp;
        if (res)
            logger::info("{}.size values match", name);
        else
            logger::warn("{}.size values do not match sz1: {} sz2: {} sz_exp: {}", name, s1.size(), s2.size(), sz_exp);
        return res;
    }

    static void compare_maps(const std::string_view name, const value m1, const value m2)
    {
        size_t diffs = 0;
        auto it1 = m1.map();
        auto it2 = m2.map();
        if (compare_values(fmt::format("{}.size", name), m1.size(), m2.size())) {
            for (size_t i = 0; i < m1.size(); ++i) {
                const auto [k1, v1] = it1.next();
                const auto [k2, v2] = it2.next();
                if (k1 == k2) {
                    if (v1 != v2) {
                        ++diffs;
                        logger::debug("item {}: values do not match: size1: {} size2: {} \nval1: {} val2: {}",
                           k1, v1.raw_span().size(), v2.raw_span().size(), v1, v2);
                    }
                } else {
                    logger::debug("different keys at index: {}: {} != {}", i, k1, k2);
                    ++diffs;
                }
            }

        } else {
            map<value, value> m1_fast {};
            while (!it1.done()) {
                auto kv = it1.next();
                m1_fast.try_emplace(kv.first, kv.second);
            }
            map<value, value> m2_fast {};
            while (!it2.done()) {
                auto kv = it2.next();
                m2_fast.try_emplace(kv.first, kv.second);
            }
            for (const auto &[k1, v1]: m1_fast) {
                if (const auto m2_it = m2_fast.find(k1); m2_it != m2_fast.end()) {
                    if (v1 != m2_it->second) {
                        ++diffs;
                        logger::debug("changed item: {} orig: {} new: {}", k1, v1, m2_it->second);
                    }
                } else {
                    ++diffs;
                    logger::debug("missing item: {} val: {}", k1, v1);
                }
            }
            for (const auto &[k2, v2]: m2_fast) {
                if (!m1_fast.contains(k2)) {
                    ++diffs;
                    logger::debug("extra item: {} val: {}", k2, v2);
                }
            }
        }
        if (diffs)
            logger::warn("{} {} values do not match", name, diffs);
    }

    static void compare_arrays(const std::string_view name, const value a1, const value a2)
    {
        if (compare_values(fmt::format("{}.size", name), a1.size(), a2.size())) {
            size_t diffs = 0;
            auto it1 = a1.array();
            auto it2 = a2.array();
            for (size_t i = 0; i < a1.size(); ++i) {
                const auto v1 = it1.next();
                const auto v2 = it2.next();
                if (v1.raw_span() != v2.raw_span()) {
                    ++diffs;
                    logger::debug("{}#{}: values do not match: size1: {} size2: {}\nval1: {} val2: {}",
                       name, i, v1.raw_span().size(), v2.raw_span().size(), v1, v2);
                }
            }
            if (diffs)
                logger::warn("{} {} values do not match", name, diffs);
        }
    }

    static void compare_delegation_state(const value d1, const value d2)
    {
        if (!compare_sizes("stateBefore.delegation", d1, d2, 3)) {
            auto it1 = d1.array();
            auto it2 = d2.array();
            compare("stateBefore.delegation.unknown", it1.next(), it2.next());
            const auto pstate1 = it1.next();
            const auto pstate2 = it2.next();
            compare_arrays("stateBefore.delegation.pstate", pstate1, pstate2);
            /*compare("stateBefore.delegation.pstate.poolParams", d1.at(1).at(0), d2.at(1).at(0), false);
            compare("stateBefore.delegation.pstate.futurePoolParams", d1.at(1).at(1), d2.at(1).at(1), false);
            compare("stateBefore.delegation.pstate.poolsRetiring", d1.at(1).at(2), d2.at(1).at(2), false);
            compare("stateBefore.delegation.pstate.poolDeposits", d1.at(1).at(3), d2.at(1).at(3), false);*/
            const auto dstate1 = it1.next();
            const auto dstate2 = it2.next();
            if (!compare_sizes("stateBefore.delegation.dstate", dstate1, dstate2, 4)) {
                auto dstate1_it = dstate1.array();
                auto dstate2_it = dstate2.array();
                {
                    auto unified1_it = dstate1_it.next().array();
                    auto unified2_it = dstate2_it.next().array();
                    compare_maps("stateBefore.delegation.dstate.unified.credentials", unified1_it.next(), unified2_it.next());
                    compare_maps("stateBefore.delegation.dstate.unified.pointers", unified1_it.next(), unified2_it.next());
                }
                compare_maps("stateBefore.delegation.dstate.fGenDelegs", dstate1_it.next(), dstate2_it.next());
                compare_maps("stateBefore.delegation.dstate.genDelegs", dstate1_it.next(), dstate2_it.next());
                compare_arrays("stateBefore.delegation.dstate.irwd", dstate1_it.next(), dstate2_it.next());
                /*
                    compare("stateBefore.delegation.dstate.irwd.IRReserves", d1.at(2).at(3).at(0), d2.at(2).at(3).at(0), false);
                    compare("stateBefore.delegation.dstate.irwd.IRTreasury", d1.at(2).at(3).at(1), d2.at(2).at(3).at(1), false);
                    compare("stateBefore.delegation.dstate.irwd.deltaReserves", d1.at(2).at(3).at(2), d2.at(2).at(3).at(2));
                    compare("stateBefore.delegation.dstate.irwd.deltaTreasury", d1.at(2).at(3).at(3), d2.at(2).at(3).at(3));*/
            }
        }
    }

    static void compare_utxo_state_stake(const value s1, const value s2)
    {
        if (compare_sizes("stateBefore.utxoState.stake", s1, s2, 2)) {
            auto it1 = s1.array();
            auto it2 = s2.array();
            compare_maps("stateBefore.utxoState.stake.credentials", it1.next(), it2.next());
            compare_maps("stateBefore.utxoState.stake.pointers", it1.next(), it2.next());
        }
    }

    static void compare_utxo_pp(const value s1, const value s2)
    {
        compare_arrays("stateBefore.utxoState.pp", s1, s2);
    }

    static void compare_utxo_state(const value s1, const value s2)
    {
        if (compare_sizes("stateBefore.utxoState", s1, s2, 6)) {
            auto it1 = s1.array();
            auto it2 = s2.array();
            compare_maps("stateBefore.utxoState.utxos", it1.next(), it2.next());
            compare("stateBefore.utxoState.deposited", it1.next(), it2.next());
            compare("stateBefore.utxoState.fees", it1.next(), it2.next());
            compare_utxo_pp(it1.next(), it2.next());
            compare_utxo_state_stake(it1.next(), it2.next());
            compare("stateBefore.utxoState.version", it1.next(), it2.next());
        }
    }

    static void compare_ledger_state(const value s1, const value s2)
    {
        if (compare_sizes("stateBefore.lstate", s1, s2, 2)) {
            auto it1 = s1.array();
            auto it2 = s2.array();
            compare_delegation_state(it1.next(), it2.next());
            compare_utxo_state(it1.next(), it2.next());
        }
    }

    static void compare_snapshots(const value s1, const value s2)
    {
        if (compare_sizes("stateBefore.snapshots", s1, s2, 4)) {
            auto it1 = s1.array();
            auto it2 = s2.array();
            for (size_t i = 0; i < 3; ++i) {
                const auto name = fmt::format("stateBefore.snapshots.#{}", i);
                const auto snap1 = it1.next();
                const auto snap2 = it2.next();
                if (compare_sizes(name, snap1, snap2, 3)) {
                    auto snap1_it = snap1.array();
                    auto snap2_it = snap2.array();
                    compare_maps(fmt::format("{}.stake", name), snap1_it.next(), snap2_it.next());
                    compare_maps(fmt::format("{}.delegs", name), snap1_it.next(), snap2_it.next());
                    compare_maps(fmt::format("{}.params", name), snap1_it.next(), snap2_it.next());
                }
            }
            compare("stateBefore.snapshots.feeSS", it1.next(), it2.next());
        }
    }

    static void compare_likelihoods(const std::string_view name, const value s1, const value s2)
    {
        if (compare_values(fmt::format("{}.size", name), s1.size(), s2.size())) {
            size_t diffs = 0;
            auto it1 = s1.map();
            auto it2 = s2.map();
            for (size_t i = 0; !it1.done(); ++i) {
                const auto [pool1, lks1] = it1.next();
                const auto [pool2, lks2] = it2.next();
                if (pool1 == pool2) [[likely]] {
                    auto l1_it = lks1.array();
                    auto l2_it = lks2.array();
                    for (size_t li = 0; li < lks1.size(); ++li) {
                        const auto lh1 = l1_it.next().float32();
                        const auto lh2 = l2_it.next().float32();
                        if (lh1 != lh2) {
                            if (lh1 != 0.0) {
                                if (const auto eps = std::fabs(lh2 - lh1) / lh1; eps > 1e-4) {
                                    ++diffs;
                                    logger::debug("pool: {} likelihood #{} eps: {} orig: {} own: {}", pool1, li, eps, lh1, lh2);
                                }
                            } else if (const auto delta = std::fabs(lh2 - lh1); delta > 1e-4) {
                                ++diffs;
                                logger::debug("pool: {} likelihood #{} delta: {} orig: {} own: {}", pool1, li, delta, lh1, lh2);
                            }
                        }
                    }
                } else {
                    logger::debug("mismatching keys at #{}: {} vs {}", i, pool1, pool2);
                }
            }
            if (diffs)
                logger::warn("{} {} items mismatch", name, diffs);
            else
                logger::info("{} all items are within 1-e4 epsilon", name);
        }
    }

    static void compare_nonmyopic(const std::string_view name, const value v1, const value v2)
    {
        if (compare_sizes(name, v1, v2, 2)) {
            auto it1 = v1.array();
            auto it2 = v2.array();
            compare_likelihoods(fmt::format("{}.likelihoods", name), it1.next(), it2.next());
            compare(fmt::format("{}.rewardPot", name), it1.next(), it2.next());
        }
    }

    static void compare_state_before(const value s1, const value s2)
    {
        if (compare_sizes("stateBefore", s1, s2, 4)) {
            auto it1 = s1.array();
            auto it2 = s2.array();
            compare("stateBefore.esAccountState", it1.next(), it2.next(), true);
            compare_ledger_state(it1.next(), it2.next());
            compare_snapshots(it1.next(), it2.next());
            compare_nonmyopic("stateBefore.esNonMyopic", it1.next(), it2.next());
        }
    }

    static void compare_possible_update(const value s1, const value s2)
    {
        if (compare_sizes("update", s1, s2, 1)) {
            const auto ser1 = s1.at(0);
            const auto ser2 = s2.at(0);
            if (compare_sizes("update.ser", ser1, ser2, 2)) {
                auto ser1_it = ser1.array();
                auto ser2_it = ser2.array();
                const auto format1 = ser1_it.next();
                if (compare("update.ser.format", format1, ser2_it.next())) {
                    switch (format1.uint()) {
                        case 0: { // an intermediate reward snapshot
                            compare("update.rewardSnapshot", ser1_it.next(), ser2_it.next());
                            compare("update.rewardPulserData", ser1_it.next(), ser2_it.next());
                            break;
                        }
                        case 1: { // a final potential update
                            auto it1 = ser1_it.next().array();
                            auto it2 = ser2_it.next().array();
                            compare("update.deltaT", it1.next(), it2.next());
                            compare("update.deltaR", it1.next(), it2.next());
                            compare_maps("update.rs", it1.next(), it2.next());
                            compare("update.deltaF", it1.next(), it2.next());
                            compare_nonmyopic("update.nonMyopic", it1.next(), it2.next());
                            break;
                        }
                        default:
                            throw error("unsupported update format");
                    }
                }
            }
        }
    }

    static void compare_states(const value s1, const value s2)
    {
        if (compare_sizes("era-state", s1, s2, 3)) {
            auto it1 = s1.array();
            auto it2 = s2.array();
            compare("tip", it1.next(), it2.next());
            {
                auto st1_it = it1.next().array();
                auto st2_it = it2.next().array();
                const auto epoch1 = st1_it.next();
                const auto epoch2 = st2_it.next();
                compare("epoch", epoch1, epoch2);
                logger::info("epoch {} {}", epoch1, epoch2);
                compare("blocksBefore", st1_it.next(), st2_it.next());
                compare("blocksCurrent", st1_it.next(), st2_it.next());
                compare_state_before(st1_it.next(), st2_it.next());
                compare_possible_update(st1_it.next(), st2_it.next());
                compare_maps("stakeDistrib", st1_it.next(), st2_it.next());
                compare("shelleyDeprecated", st1_it.next(), st2_it.next());
            }
            compare("blockPastVotingDeadline", it1.next(), it2.next());
        }
    }

    static void compare_eras(const value list1, const value list2)
    {
        if (compare_values("eras.size", list1.size(), list2.size())) {
             auto it1 = list1.array();
             auto it2 = list2.array();
             for (size_t i = 0; i < list1.size(); ++i) {
                 const auto left = it1.next();
                 const auto right = it2.next();
                 if (i < list1.size() - 1) {
                     compare_arrays(fmt::format("eras#{}", i), left, right);
                 } else {
                     auto left_it = left.array();
                     auto right_it = right.array();
                     compare("last era start", left_it.next(), right_it.next());
                     compare_states(left_it.next().at(1), right_it.next().at(1));
                 }
             }
         }
    }

    bool compare_node_state(const buffer buf1, const buffer buf2)
    {
        vector<value> st1 {}, st2 {};
        {
            timer t { "parse", logger::level::info };
            auto &sched = scheduler::get();
            sched.submit_void("load-st1", 100, [&] {
                st1 = parse_all(buf1);
            });
            sched.submit_void("load-st2", 100, [&] {
                st2 = parse_all(buf2);
            });
            sched.process();
        }

        timer t2 { "compare", logger::level::info };
        const bool res = compare_values("file-hash", blake2b<blake2b_256_hash>(buf1), blake2b<blake2b_256_hash>(buf2));
        if (!res) {
            if (compare_values("stream items", st1.size(), st2.size())) {
                for (size_t i = 0; i < st1.size(); ++i) {
                    if (compare_values(fmt::format("stream #{} size", i), st1.at(i).size(), st2.at(i).size())) {
                        auto it1 = st1.at(i).array();
                        auto it2 = st2.at(i).array();
                        compare(fmt::format("stream #{} format version", i), it1.next(), it2.next());
                        auto data1_it = it1.next().array();
                        auto data2_it = it2.next().array();
                        compare_eras(data1_it.next(), data2_it.next());
                        compare("headerValidationState", data1_it.next(), data2_it.next(), true);
                    }
                }
            }
        }
        return res;
    }
}