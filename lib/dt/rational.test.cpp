/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/rational.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

namespace {
    uint64_t member_reward_f64(uint64_t max_reward, uint64_t pool_stake, uint64_t deleg_stake, uint64_t cost, const rational &margin)
    {
        return static_cast<uint64_t>((max_reward - cost) * (1 - static_cast<double>(margin)) * deleg_stake / pool_stake);
    }

    uint64_t member_reward_rat(uint64_t max_reward, uint64_t pool_stake, uint64_t deleg_stake, uint64_t cost, const rational & margin)
    {
        rational reward = max_reward - cost;
        reward *= (1 - static_cast<rational>(margin));
        reward *= deleg_stake;
        reward /= pool_stake;
        return static_cast<uint64_t>(reward);
    }

    uint64_t leader_reward_f64(uint64_t max_reward, uint64_t pool_stake, uint64_t owner_stake, uint64_t cost, const rational &margin)
    {
        return static_cast<uint64_t>(cost + (max_reward - cost) * (static_cast<double>(margin) + (1.0 - static_cast<double>(margin)) * owner_stake / pool_stake));
    }

    uint64_t leader_reward_rat(uint64_t max_reward, uint64_t pool_stake, uint64_t owner_stake, uint64_t cost, const rational &margin)
    {
        rational ratio = 1 - static_cast<rational>(margin);
        ratio *= owner_stake;
        ratio /= pool_stake;
        rational reward = (max_reward - cost) * (static_cast<rational>(margin) + ratio) + cost;
        return static_cast<uint64_t>(reward);
    }

    uint64_t reward_pot_f64(uint64_t reserves, uint64_t fees, uint64_t num_blocks, const rational &expansion_rate,
        const rational &treasury_growth_rate, const rational &decentralization)
    {
        uint64_t expansion = static_cast<double>(expansion_rate) * reserves
            * std::min(1.0, static_cast<double>(num_blocks) / ((1.0 - static_cast<double>(decentralization)) * 21600));
        uint64_t total_reward_pool = expansion + fees;
        uint64_t treasury_rewards = static_cast<double>(treasury_growth_rate) * total_reward_pool;
        return total_reward_pool - treasury_rewards;
    }

    uint64_t reward_pot_rat(uint64_t reserves, uint64_t fees, uint64_t num_blocks, const rational &expansion_rate,
        const rational &treasury_growth_rate, const rational &decentralization)
    {
        rational expansion = static_cast<rational>(expansion_rate);
        expansion *= reserves;
        rational perf = num_blocks;
        perf /= (1.0 - static_cast<rational>(decentralization)) * 21600;
        perf = std::min(rational { 1 }, perf);
        expansion *= perf;
        uint64_t total_reward_pool = static_cast<uint64_t>(expansion) + fees;
        uint64_t treasury_rewards = static_cast<uint64_t>(static_cast<rational>(treasury_growth_rate) * total_reward_pool);
        return total_reward_pool - treasury_rewards;
    }
}

suite rational_suite = [] {
    "rational"_test = [] {
        uint64_t reward_pot = 31834688329017;
        uint64_t total_stake = 31737719158318701;
        "max_pool_reward"_test = [&] {
            rational a0 = 3;
            a0 /= 10;
            uint64_t pledge = 10000000000;
            uint64_t pool_stake = 94511860029536;
            rational z0 = 1;
            z0 /= 150;
            rational pool_s = pool_stake;
            pool_s /= total_stake;
            pool_s = std::min(pool_s, z0);
            rational pledge_s = pledge;
            pledge_s /= total_stake;
            pledge_s = std::min(pledge_s, z0);
            rational reward_s = reward_pot;
            reward_s /= (1 + a0);
            rational y = (z0 - pool_s) / z0;
            rational x = (pool_s - pledge_s * y) / z0;
            rational max_reward = reward_s * (pool_s + pledge_s * a0 * x);
            auto max_reward_u = static_cast<uint64_t>(max_reward);
            expect(max_reward_u == 72924591476_ull);
        };
        "leader reward #1"_test = [&] {
            uint64_t cost = 340000000;
            uint64_t owner_stake = 1304513815286;
            uint64_t pool_stake = 1304513815286;
            uint64_t pool_reward_pot = 1620341316;
            rational margin { 1, 40 };
            expect(pool_stake == owner_stake);
            expect(leader_reward_f64(pool_reward_pot, pool_stake, owner_stake, cost, margin) == 1620341315_ull);
            expect(leader_reward_rat(pool_reward_pot, pool_stake, owner_stake, cost, margin) == 1620341316_ull);
        };

        "member reward #1"_test = [&] {
            uint64_t cost = 340000000;
            uint64_t deleg_stake = 1304513815286;
            uint64_t pool_stake = 122064488772828;
            uint64_t pool_reward_pot = 70564577986;
            rational margin { 3, 100 };
            uint64_t reward_f64 = member_reward_f64(pool_reward_pot, pool_stake, deleg_stake, cost, margin);
            uint64_t reward_rat = member_reward_rat(pool_reward_pot, pool_stake, deleg_stake, cost, margin);
            expect(reward_f64 == reward_rat) << reward_f64 << reward_rat;
        };

        "member reward #2"_test = [&] {
            uint64_t cost = 340000000;
            uint64_t deleg_stake = 8642660310954;
            uint64_t pool_stake = 61139181786687;
            uint64_t pool_reward_pot = 43128231125;
            rational margin { 1, 100 };
            expect(member_reward_f64(pool_reward_pot, pool_stake, deleg_stake, cost, margin) == 5988076627_ull);
            expect(member_reward_rat(pool_reward_pot, pool_stake, deleg_stake, cost, margin) == 5988076626_ull);
        };

        "member reward #3"_test = [&] {
            uint64_t cost = 345000000;
            uint64_t deleg_stake = 150103776586505;
            uint64_t pool_stake = 150103776586505;
            uint64_t pool_reward_pot = 87679113050;
            rational margin { 6, 100 };
            expect(member_reward_f64(pool_reward_pot, pool_stake, deleg_stake, cost, margin) == 82094066267_ull);
            expect(member_reward_rat(pool_reward_pot, pool_stake, deleg_stake, cost, margin) == 82094066267_ull);
        };

        "pool reward pot"_test = [&] {
            uint64_t reserves = 12963125292915959;
            uint64_t fees = 4962718967;
            rational expansion_rate { 3, 1000 };
            rational treasury_growth_rate { 1, 5 };
            rational decentralization { 1, 2 };
            uint64_t num_blocks = 10375;
            expect(reward_pot_f64(reserves, fees, num_blocks, expansion_rate, treasury_growth_rate, decentralization) == 29891175711619_ull);
            expect(reward_pot_rat(reserves, fees, num_blocks, expansion_rate, treasury_growth_rate, decentralization) == 29891175711619_ull);
        };

        "comparison"_test = [] {
            rational v { 4, 5 };
            expect(v >= rational { 8, 10 });
            expect(!(v < rational { 8, 10 }));
        };
    };
};