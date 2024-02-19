/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/validator/state.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

namespace {
    /*void expect_diff(const std::string &name, uint64_t act, uint64_t exp, const std::source_location &loc=std::source_location::current())
    {
        expect(act == exp, loc)
            << name << "diff:" << static_cast<int64_t>(act) - static_cast<int64_t>(exp);
    }*/

    /*void load_dist_reward(validator::state &st, const std::string &path_prefix)
    {
        // for set_last_epoch_blocks to work pools must be registered
        {
            auto json_data = file::read(path_prefix + "-pools.json");
            auto j_pools = json::parse(json_data).as_object();
            for (const auto &[j_pool_id, j_info]: j_pools) {
                auto pool_id = cardano::pool_hash::from_hex(j_pool_id);
                std::vector<cardano::stake_ident> owners {};
                for (const auto &j_stake_id: j_info.at("owners").as_array()) {
                    cardano::stake_ident owner_id { cardano::key_hash::from_hex(j_stake_id.as_string()) };
                    //if (!_stake_dist_go.has(owner_id))
                    //    throw error("pool {} owner {} has no registered stake!", pool_id, owner_id);
                    owners.emplace_back(owner_id);
                }
                cardano::stake_ident reward_id {
                    cardano::key_hash::from_hex(j_info.at("rewardAccount").at("credential").at("key hash").as_string())
                };
                auto pledge = json::value_to<uint64_t>(j_info.at("pledge"));
                auto cost = json::value_to<uint64_t>(j_info.at("cost"));
                auto margin = json::value_to<double>(j_info.at("margin"));
                st.register_pool(pool_id, reward_id, owners, pledge, cost, margin);
            }
        }
        // set_last_epoch_blocks need to be set one epoch beforehand
        {
            auto json_data = file::read(path_prefix + "-blocks-before.json");
            auto j_blocks = json::parse(json_data).as_object();
            for (const auto &[j_pool_id, j_block_count]: j_blocks) {
                auto pool_id = cardano::pool_hash::from_hex(j_pool_id);
                st.set_last_epoch_blocks(pool_id, json::value_to<uint64_t>(j_block_count));
            }
        }
        st.transition_epoch();
        {
            auto json_data = file::read(path_prefix + "-pools-retiring.json");
            auto j_rpools = json::parse(json_data).as_object();
            for (const auto &[j_pool_id, j_epoch]: j_rpools) {
                auto pool_id = cardano::pool_hash::from_hex(j_pool_id);
                if (st.has_pool(pool_id))
                    st.retire_pool(pool_id, json::value_to<uint64_t>(j_epoch));
            }
        }
        {
            auto json_data = file::read("./data/validator-state/212-stake-reg.json");
            auto j_regs = json::parse(json_data).as_array();
            for (const auto &j_reg: j_regs) {
                cardano::stake_ident stake_id { cardano::key_hash::from_hex(j_reg.as_string()) };
                st.register_stake(0, stake_id);
            }
        }
        {
            auto json_data = file::read("./data/validator-state/212-stake-unreg.json");
            auto j_unregs = json::parse(json_data).as_array();
            for (const auto &j_unreg: j_unregs) {
                cardano::stake_ident stake_id { cardano::key_hash::from_hex(j_unreg.as_string()) };
                st.retire_stake(0, stake_id);
            }
        }
        {
            auto json_data = file::read(path_prefix + "-delegs.json");
            auto j_delegs = json::parse(json_data).as_array();
            for (const auto &j_deleg: j_delegs) {
                stake_ident stake_id {
                    cardano::key_hash::from_hex(j_deleg.at(0).at("key hash").as_string())
                };
                auto pool_id = cardano::pool_hash::from_hex(j_deleg.at(1).as_string());
                st.delegate_stake(stake_id, pool_id);
            }
        }
        {
            auto json_data = file::read(path_prefix + "-stake.json");
            auto j_stake_dist = json::parse(json_data).as_array();
            for (const auto &j_stake: j_stake_dist) {
                stake_ident stake_id {
                    cardano::key_hash::from_hex(j_stake.at(0).at("key hash").as_string())
                };
                auto stake = json::value_to<uint64_t>(j_stake.at(1));
                st.update_stake(stake_id, stake);
            }
        }

        st.rotate_snapshots(); // active -> mark
        st.rotate_snapshots(); // mark -> set
        st.rotate_snapshots(); // set -> go
        st.rotate_snapshots(); // go -> reward
    }*/
}

suite validator_state_suite = [] {
    scheduler sched {};
    "validator::state"_test = [&] {
        "re-delegation of a stake"_test = [&] {
            validator::state st { sched };
            st.start_epoch(208);
            auto pool1 = cardano::pool_hash::from_hex("96840EBA5A4D0FF0D42F7AD5AC83343A0C6A87B1C71BF106CC544855");
            stake_ident owner1 { cardano::key_hash::from_hex("93C1A867A514A5270B6524419AFC6699ED4B013972CF8AA2DFC1A9AF") };
            array<stake_ident, 1> owners1 { owner1 };
            st.register_pool(pool1, owner1, owners1);
            st.register_stake(0, owner1);
            st.update_stake(owner1, 17'421'833);
            stake_ident delegator1 { cardano::key_hash::from_hex("E56445828E8F8B9DC138A1048BDA59E69B71262328FC06B9A2EBDC06") };
            st.register_stake(0, delegator1);
            st.update_stake(delegator1, 13'901'584'886);
            st.delegate_stake(delegator1, pool1);
            st.delegate_stake(delegator1, pool1);
            auto pool2 = cardano::pool_hash::from_hex("B6AD3E6E873A7654E68BDFE5922C86D506CD5E9299FBC3AAAB3E84BD");
            std::vector<stake_ident> owners2 {};
            st.register_pool(pool2, owner1, owners2);
            stake_ident delegator2 { cardano::key_hash::from_hex("4B83DD277D38A24C5E0586EDF3529B42E6C6FE63F03E7E265159AF6E") };
            st.register_stake(0, delegator2);
            st.delegate_stake(delegator2, pool1);
            st.update_stake(delegator2, 1'326'167'913);
            st.delegate_stake(delegator2, pool2);
            expect(st.pool_dist_go().size() == 0);
            st.transition_epoch(); // 209
            expect(st.pool_dist_go().size() == 0);
            st.transition_epoch(); // 210
            st.finish_epoch();
            const auto &dist = st.pool_dist_go();
            expect(dist.size() == 2);
            expect(dist.get(pool1) == 13'901'584'886) << dist.get(pool1);
            expect(dist.get(pool2) == 1'326'167'913) << dist.get(pool2);
        };
        "re-delegation of a stake 2"_test = [&] {
            validator::state st { sched };
            st.start_epoch(208);
            auto pool1 = cardano::pool_hash::from_hex("FB2EF0B6933E23890AE8CA4A4D3137F61991AAB76B33A2426E0F6AA2");
            stake_ident reward1 { cardano::key_hash::from_hex("93C1A867A514A5270B6524419AFC6699ED4B013972CF8AA2DFC1A9AF") };
            std::vector<stake_ident> owners {};
            st.register_pool(pool1, reward1, owners);
            stake_ident deleg1 { cardano::key_hash::from_hex("3D4B6A709D9B84A3DBFAAAFC3F4B5EB04C812DA1080FF0019B5285A9") };
            st.register_stake(0, deleg1);
            st.update_stake(deleg1, 29'808'800'311);
            st.delegate_stake(deleg1, pool1);
            st.register_pool(pool1, reward1, owners);
            st.delegate_stake(deleg1, pool1);
            auto pool2 = cardano::pool_hash::from_hex("00000000000000000000000000000000000000000000000000000000");
            stake_ident reward2 { cardano::key_hash::from_hex("00000000000000000000000000000000000000000000000000000000") };
            std::vector<stake_ident> owners2 {};
            st.register_pool(pool2, reward2, owners2);
            st.delegate_stake(deleg1, pool2);
            st.register_pool(pool1, reward1, owners);
            st.delegate_stake(deleg1, pool1);
            expect(st.pool_dist_go().size() == 0);
            st.transition_epoch(); // 209
            expect(st.pool_dist_go().size() == 0);
            st.transition_epoch(); // 210
            st.finish_epoch();
            const auto &dist = st.pool_dist_go();
            expect(dist.size() == 1);
            expect(dist.get(pool1) == 29'808'800'311) << dist.get(pool1);
        };
        "unregistered pool"_test = [&] {
            validator::state st { sched };
            auto pool = cardano::pool_hash::from_hex("B6AD3E6E873A7654E68BDFE5922C86D506CD5E9299FBC3AAAB3E84BD");
            stake_ident deleg { cardano::key_hash::from_hex("4B83DD277D38A24C5E0586EDF3529B42E6C6FE63F03E7E265159AF6E") };
            st.register_stake(0, deleg);
            expect(throws([&]{ st.delegate_stake(deleg, pool); }));
        };
        /*"pool retirement"_test = [&] {
            validator::state st { sched };
            st.start_epoch(208);
            auto pool1 = cardano::pool_hash::from_hex("0649226025CA5ED18C5D0478527DD8F83B4D0BF49D48DF5166715588");
            stake_ident reward1 { cardano::key_hash::from_hex("4DB35B41611FFB2D1F8C04E7BBA37498262482C4B9AE4830F52DBC62") };
            std::vector<stake_ident> owners {};
            st.register_stake(0, reward1);
            st.register_pool(pool1, reward1, owners);
            stake_ident deleg1 { cardano::key_hash::from_hex("1D349FAA7693149F61D1EBAD8F8D18E9FF4604DE584C2E1B5660EEEF") };
            st.register_stake(0, deleg1);
            st.update_stake(deleg1, 17'647'968);
            st.delegate_stake(deleg1, pool1);
            st.delegate_stake(deleg1, pool1); // duplicate delegation
            st.retire_pool(pool1, 210);
            st.retire_pool(pool1, 209); // duplicate retirement
            expect(st.has_pool(pool1));
            {
                const auto &stake_dist = st.stake_dist();
                auto reward1_stake_it = stake_dist.find(reward1);
                expect(reward1_stake_it == stake_dist.end());
            }
            st.transition_epoch(); // 209
            expect(!st.has_pool(pool1));
            {
                const auto &stake_dist = st.stake_dist();
                auto reward1_stake_it = stake_dist.find(reward1);
                expect(reward1_stake_it != stake_dist.end());
                expect(reward1_stake_it->second == 500'000'000) << reward1_stake_it->second;
            }
            st.transition_epoch(); // 210
            st.transition_epoch(); // 211
            {
                auto dist = st.pool_dist();
                expect(dist.size() == 1);
                expect(dist.at(0).pool_id == pool1);
                expect(dist.at(0).stake == 17'647'968) << dist.at(0).stake;
            }
            st.transition_epoch(); // 211
            expect(st.pool_dist().size() == 0);
        };
        "treasury and reserves epoch 210 to 211"_test = [&] {
            uint64_t reserves_before = 13'278'197'552'770'393;
            uint64_t treasury_before = 16'306'644'182'013;
            validator::state st { sched };
            st.start_epoch(210);
            st.reserves(reserves_before);
            st.treasury(treasury_before);
            expect_diff("treasury", st.treasury(), treasury_before);
            expect_diff("reserves", st.reserves(), reserves_before);
            st.fees(209, 7'666'346'424);
            st.finish_epoch();
            expect_diff("treasury", st.treasury(), treasury_before + 7'968'451'800'947);
            expect_diff("reserves", st.reserves(), reserves_before - 7'960'785'454'523);
        };*/
        /*"rewards for epoch 212"_test = [] {
            validator::state st {};
            std::set<cardano::pool_hash> traced_pools {};
            traced_pools.emplace(cardano::pool_hash::from_hex("000001B844F4E4C900AE0DFDC84A8845F71090B82FB473E6C70A31EE"));
            traced_pools.emplace(cardano::pool_hash::from_hex("20B95F87C93F3BE9E5094C8FBDB924F9AB8B5E1C7BFB542D3A8BC7FC"));
            st.traced_pools(traced_pools);
            std::set<cardano::stake_ident> traced_stakes {};
            traced_stakes.emplace(cardano::key_hash::from_hex("001EC42376196DF0B85B6AD660E7419E77B51B16FDA8B931D559562E"));
            traced_stakes.emplace(cardano::key_hash::from_hex("221E1B60EBA6413800A63F912B998331EE1FD6F04C00D3FA8C63481B"));
            st.traced_stakes(traced_stakes);
            st.start_epoch(211);
            st.fees(211, 6'517'886'228);
            // st.reserves(13'270'236'767'315'870);
            // loads data and transition to epoch 212
            load_dist_reward(st, "./data/validator-state/212");
            st.reserves(13'262'280'841'681'299);
            st.treasury(32239292149804);
            st.fees(212, 5'578'218'279);
            st.transition_epoch();
            expect_diff("reserves", st.reserves(), 13'247'093'198'353'459);
            expect_diff("treasury", st.treasury(), 40'198'464'232'058);

            auto json_data = file::read("./data/validator-state/212-rewards.json");
            auto j_rewards = json::parse(json_data).as_object();
            const auto &own_rewards = st.potential_rewards(212);
            uint64_t own_rewards_nonzero = 0;
            for (const auto &[stake_id, reward]: own_rewards)
                if (reward != 0)
                    own_rewards_nonzero++;
            validator::reward_distribution ledger_rewards {};
            for (const auto &j_reward: j_rewards.at("rs").as_array()) {
                cardano::stake_ident stake_id { cardano::key_hash::from_hex(j_reward.at(0).at("key hash").as_string()) };
                ledger_rewards.create(stake_id);
                for (const auto &j_ru: j_reward.at(1).as_array()) {
                    ledger_rewards.replace_if_greater(stake_id, json::value_to<uint64_t>(j_ru.at("rewardAmount")));
                }
                if (traced_stakes.contains(stake_id))
                    logger::trace("search id: {} ledger reward: {}", stake_id, ledger_rewards.get(stake_id));
            }
            uint64_t ledger_rewards_nonzero = 0;
            for (const auto &[stake_id, reward]: ledger_rewards)
                if (reward != 0)
                    ledger_rewards_nonzero++;
            expect(ledger_rewards.size() == 17'988_ul);
            expect_diff("num rewards", own_rewards_nonzero, ledger_rewards_nonzero);
            expect(ledger_rewards.total_stake() + ledger_rewards.filtered_stake() == 7'235'499'325'914_ul);
            expect_diff("total rewards", own_rewards.total_stake(), ledger_rewards.total_stake());
            expect_diff("filtered rewards", own_rewards.filtered_stake(), ledger_rewards.filtered_stake());
            for (const auto &[stake_id, reward]: ledger_rewards) {
                expect(own_rewards.get(stake_id) == reward)
                    << fmt::format("{} ledger reward delta: {} ADA",
                        stake_id, cardano::balance_change { static_cast<int64_t>(own_rewards.get(stake_id)) - static_cast<int64_t>(reward) });
            }
            // do an inverse check to detect extra elements
            for (const auto &[stake_id, reward]: own_rewards) {
                if (reward == 0)
                    continue;
                if (traced_stakes.contains(stake_id))
                    logger::trace("search id: {} own reward: {}", stake_id, reward);
                expect(ledger_rewards.contains(stake_id))
                    << fmt::format("{} extra own reward: {}", stake_id, cardano::amount { reward });
            }
        };*/
    };
};