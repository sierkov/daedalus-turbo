/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/file.hpp>
#include <dt/json.hpp>
#include <dt/validator.hpp>

namespace {
    using namespace daedalus_turbo;
    using namespace daedalus_turbo::validator;

    struct epoch_state {
        stake_distribution stakes {};
        delegation_map delegs {};
    };

    struct node_ledger_state {
        uint64_t epoch = 0;
        pool_stake_distribution pool_dist {};
        reward_update_distribution reward_updates {};
        epoch_state pstake_mark {}, pstake_set {}, pstake_go {};
        stake_distribution instant_rewards_r {};
        stake_distribution instant_rewards_t {};
        reward_distribution rewards {};
        ptr_to_stake_map pointers {};
        uint64_t reserves = 0;
        uint64_t treasury = 0;
    };

    cardano::stake_ident extract_stake_id(const json::value &j)
    {
        bool is_script = j.as_object().contains("script hash");
        return cardano::stake_ident {
            is_script
                ? cardano::key_hash::from_hex(j.at("script hash").as_string())
                : cardano::key_hash::from_hex(j.at("key hash").as_string()),
            is_script
        };
    }

    const node_ledger_state load_node_state(const std::string &state_path)
    {
        node_ledger_state st {};
        auto json_data = file::read(state_path);
        auto j_state = json::parse(json_data);

        st.epoch = json::value_to<uint64_t>(j_state.at("lastEpoch"));
        st.reserves = json::value_to<uint64_t>(j_state.at("stateBefore").at("esAccountState").at("reserves"));
        st.treasury = json::value_to<uint64_t>(j_state.at("stateBefore").at("esAccountState").at("treasury"));

        for (const auto &j_reward: j_state.at("possibleRewardUpdate").at("rs").as_array()) {
            auto stake_id = extract_stake_id(j_reward.at(0));
            for (const auto &j_ru: j_reward.at(1).as_array()) {
                validator::reward_update upd {
                    j_ru.at("rewardType").as_string() == "LeaderReward" ? reward_type::leader : reward_type::member,
                    cardano::pool_hash::from_hex(j_ru.at("rewardPool").as_string()),
                    json::value_to<uint64_t>(j_ru.at("rewardAmount"))
                };
                if (upd.amount > 0) {
                    st.reward_updates.add(stake_id, upd);
                }
            }
        }
        {
            const auto &j_stake_distrib = j_state.at("stakeDistrib");
            uint64_t max_active_stake = 0;
            for (const auto &[j_pool_id, j_stake_info]: j_stake_distrib.as_object()) {
                auto denom = json::value_to<uint64_t>(j_stake_info.at("individualPoolStake").at("denominator"));
                if (denom > max_active_stake)
                    max_active_stake = denom;
            }
            for (const auto &[j_pool_id, j_stake_info]: j_stake_distrib.as_object()) {
                auto pool_id = cardano::pool_hash::from_hex(static_cast<std::string_view>(j_pool_id));
                auto num = json::value_to<uint64_t>(j_stake_info.at("individualPoolStake").at("numerator"));
                auto denom = json::value_to<uint64_t>(j_stake_info.at("individualPoolStake").at("denominator"));
                auto coeff = max_active_stake / denom;
                st.pool_dist.create(pool_id);
                st.pool_dist.add(pool_id, num * coeff);
            }
        }
        {
            const auto &j_rewards = j_state.at("stateBefore").at("esLState").at("delegationState").at("dstate").at("irwd").at("iRReserves").as_array();
            for (const auto &j_reward: j_rewards) {
                auto stake_id = extract_stake_id(j_reward.at(0));
                auto reward = json::value_to<uint64_t>(j_reward.at(1));
                st.instant_rewards_r.add(stake_id, reward);
            }
        }
        {
            const auto &j_rewards = j_state.at("stateBefore").at("esLState").at("delegationState").at("dstate").at("irwd").at("iRTreasury").as_array();
            for (const auto &j_reward: j_rewards) {
                auto stake_id = extract_stake_id(j_reward.at(0));
                auto reward = json::value_to<uint64_t>(j_reward.at(1));
                st.instant_rewards_t.add(stake_id, reward);
            }
        }
        {
            const auto &j_rewards = j_state.at("stateBefore").at("esLState").at("delegationState").at("dstate").at("unified").at("credentials").as_array();
            for (const auto &j_reward: j_rewards) {
                auto reward = json::value_to<uint64_t>(j_reward.at(1).at("reward"));
                auto stake_id = extract_stake_id(j_reward.at(0));
                st.rewards.create(stake_id);
                st.rewards.add(stake_id, reward);
            }
        }
        {
            for (const auto &j_ptr: j_state.at("stateBefore").at("esLState").at("delegationState").at("dstate").at("unified").at("pointers").as_array()) {
                cardano::stake_pointer ptr {
                    json::value_to<uint64_t>(j_ptr.at(0).at("slot")),
                    json::value_to<size_t>(j_ptr.at(0).at("txIndex")),
                    json::value_to<size_t>(j_ptr.at(0).at("certIndex"))
                };
                auto stake_id = extract_stake_id(j_ptr.at(1));
                st.pointers[ptr] = stake_id;
            }
        }
        {
            const auto &j_stake_dist = j_state.at("stateBefore").at("esSnapshots").at("pstakeMark").at("stake").as_array();
            for (const auto &j_stake: j_stake_dist) {
                auto stake_id = extract_stake_id(j_stake.at(0));
                st.pstake_mark.stakes.add(stake_id, json::value_to<uint64_t>(j_stake.at(1)));
            }
        }
        {
            const auto &j_delegs = j_state.at("stateBefore").at("esSnapshots").at("pstakeMark").at("delegations").as_array();
            for (const auto &j_deleg: j_delegs) {
                auto stake_id = extract_stake_id(j_deleg.at(0));
                auto pool_id = cardano::pool_hash::from_hex(j_deleg.at(1).as_string());
                st.pstake_mark.delegs.try_emplace(stake_id, pool_id);
            }
        }
        {
            const auto &j_stake_dist = j_state.at("stateBefore").at("esSnapshots").at("pstakeSet").at("stake").as_array();
            for (const auto &j_stake: j_stake_dist) {
                auto stake_id = extract_stake_id(j_stake.at(0));
                st.pstake_set.stakes.add(stake_id, json::value_to<uint64_t>(j_stake.at(1)));
            }
        }
        {
            const auto &j_delegs = j_state.at("stateBefore").at("esSnapshots").at("pstakeSet").at("delegations").as_array();
            for (const auto &j_deleg: j_delegs) {
                auto stake_id = extract_stake_id(j_deleg.at(0));
                auto pool_id = cardano::pool_hash::from_hex(j_deleg.at(1).as_string());
                st.pstake_set.delegs.try_emplace(stake_id, pool_id);
            }
        }
        {
            const auto &j_stake_dist = j_state.at("stateBefore").at("esSnapshots").at("pstakeGo").at("stake").as_array();
            for (const auto &j_stake: j_stake_dist) {
                auto stake_id = extract_stake_id(j_stake.at(0));
                st.pstake_go.stakes.add(stake_id, json::value_to<uint64_t>(j_stake.at(1)));
            }
        }
        {
            const auto &j_delegs = j_state.at("stateBefore").at("esSnapshots").at("pstakeGo").at("delegations").as_array();
            for (const auto &j_deleg: j_delegs) {
                auto stake_id = extract_stake_id(j_deleg.at(0));
                auto pool_id = cardano::pool_hash::from_hex(j_deleg.at(1).as_string());
                st.pstake_go.delegs.try_emplace(stake_id, pool_id);
            }
        }
        return st;
    }

    template<typename ExpDist, typename ActDist>
    void compare_dists(const std::string &name, const ExpDist &expected, const ActDist &actual)
    {
        logger::debug("{} expected items: {} actual items: {} diff: {}",
            name, expected.size(), actual.size(), static_cast<int64_t>(actual.size()) - static_cast<int64_t>(expected.size()));
        size_t diffs = 0;
        for (const auto &[id, exp_val]: expected) {
            if (!actual.contains(id)) {
                logger::debug("{} missing item: {} val: {}", name, id, exp_val);
                ++diffs;
                continue;
            }
            const auto &act_val = actual.at(id);
            if (exp_val != act_val) {
                logger::debug("{} item: {} expected: {} actual: {}", name, id, exp_val, act_val);
                ++diffs;
            }
        }
        // do an inverse check to detect extra elements
        for (const auto &[id, act_val]: actual) {
            if (!expected.contains(id)) {
                logger::debug("{} extra item: {} val: {}", name, id, act_val);
                if constexpr (std::convertible_to<decltype(act_val), uint64_t>) {
                    if (static_cast<uint64_t>(act_val) != 0)
                        ++diffs;
                } else {
                    ++diffs;
                }
            }
        }
        if (diffs == 0)
            logger::info("{} {} items match", name, expected.size());
        else
            logger::warn("{} has {} differences - see the details in the log file", name, diffs);
    }

    template<typename T>
    void compare_values(const std::string &name, const T &expected, const T &actual)
    {
        if (expected != actual)
            logger::warn("{} mismatch node: {} dt: {} diff: {}", name, expected, actual,
                static_cast<int64_t>(actual) - static_cast<int64_t>(expected));
        else
            logger::info("{} match", name);
    }
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        std::cerr << "Usage: validate-state <node-state.json> <dt-state.bin>\n";
        return 1;
    }
    scheduler sched {};
    validator::state dt_state { sched };
    {
        auto zpp_data = file::read(argv[2]);
        zpp::bits::in in { zpp_data };
        in(dt_state).or_throw();
    }
    auto node_state = load_node_state(argv[1]);
    
    compare_values("epoch", node_state.epoch, dt_state.epoch());
    // blocksBefore
    // blocksCurrent
    compare_values("reserves", node_state.reserves, dt_state.reserves());
    compare_values("treasury", node_state.treasury, dt_state.treasury());
    compare_dists("stake_dist_mark", node_state.pstake_mark.stakes, dt_state.stake_dist_mark());
    compare_dists("delegs_mark", node_state.pstake_mark.delegs, dt_state.delegs_mark());
    // pstakeMark.poolParams
    compare_dists("stake_dist_set", node_state.pstake_set.stakes, dt_state.stake_dist_set());
    compare_dists("delegs_set", node_state.pstake_set.delegs, dt_state.delegs_set());
    // pstakeSet.poolParams
    compare_dists("stake_dist_go", node_state.pstake_go.stakes, dt_state.stake_dist_go());
    compare_dists("delegs_go", node_state.pstake_go.delegs, dt_state.delegs_go());
    // pstakeGo.poolParams
    // feeSS
    // esLState.utxoState.stake.credentials
    compare_dists("reward_dist", node_state.rewards, dt_state.reward_dist());
    compare_dists("pointers", node_state.pointers, dt_state.pointers());
    // delegationState
    // fGenDelegs
    // genDelegs
    compare_dists("instant_rewards_r", node_state.instant_rewards_r, dt_state.instant_rewards_reserves());
    compare_dists("instant_rewards_t", node_state.instant_rewards_t, dt_state.instant_rewards_treasury());
    // stakePoolParams
    // futureStakePoolParams
    // retiring
    // esPrevPp
    // esPp
    compare_dists("potential_rewards", node_state.reward_updates, dt_state.potential_rewards());
    compare_dists("pool_dist_set", node_state.pool_dist, dt_state.pool_dist_set());
}