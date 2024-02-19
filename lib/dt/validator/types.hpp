/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_VALIDATOR_TYPES_HPP
#define DAEDALUS_TURBO_VALIDATOR_TYPES_HPP

#include <unordered_set>
#include <zpp_bits.h>
#include <dt/cardano/common.hpp>
#include <dt/partitioned-map.hpp>
#include <dt/static-map.hpp>

namespace daedalus_turbo::validator {
    template<typename C>
    struct map_with_get: C
    {
        using C::C;

        const C::mapped_type get(const C::key_type &id) const
        {
            auto it = C::find(id);
            if (it != C::end())
                return it->second;
            return typename C::mapped_type {};
        }
    };

    template<typename C>
    struct restricted_map: map_with_get<C> {
        
    };

    template<typename C>
    struct distribution: map_with_get<C>
    {
        using map_with_get<C>::map_with_get;

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self._total_stake, const_cast<map_with_get<C> &>(dynamic_cast<const map_with_get<C> &>(self)));
        }

        void add(map_with_get<C>::iterator it, C::mapped_type stake)
        {
            if (stake > 0) {
                it->second += stake;
                _total_stake += static_cast<uint64_t>(stake);
            }
        }

        void add(const C::key_type &id, C::mapped_type stake)
        {
            if (stake > 0) {
                auto [it, created] = map_with_get<C>::try_emplace(id, 0);
                add(it, stake);
            }
        }

        void sub(const C::key_type &id, C::mapped_type stake, bool remove_zero=true)
        {
            if (stake > 0) {
                auto it = map_with_get<C>::find(id);
                if (it == map_with_get<C>::end()) 
                    throw error("request to remove stake from an unknown id: {}", id);
                if (it->second < stake)
                    throw error("request to delete more stake ({}) than id {} has: {}", stake, id, it->second);
                it->second -= stake;
                if (it->second == 0 && remove_zero)
                    map_with_get<C>::erase(it);
                _total_stake -= static_cast<uint64_t>(stake);
            }
        }

        void clear()
        {
            map_with_get<C>::clear();
            _total_stake = 0;
        }

        uint64_t total_stake() const
        {
            return _total_stake;
        }
    protected:
        uint64_t _total_stake = 0;
    };

    template<typename C>
    struct restricted_distribution: distribution<C>
    {
        using distribution<C>::distribution;

        bool create(const C::key_type &id)
        {
            auto [it, created] = distribution<C>::try_emplace(id);
            return created;
        }

        void retire(const C::key_type &id)
        {
            auto it = distribution<C>::find(id);
            if (it == distribution<C>::end())
                throw error("retiring an unknown id {}", id);
            distribution<C>::_total_stake -= static_cast<uint64_t>(it->second);
            distribution<C>::erase(it);
        }

        void add(distribution<C>::iterator it, C::mapped_type stake)
        {
            if (it == distribution<C>::end())
                throw error("request to increase an unregistered id {} by {}", it->first, stake);
            distribution<C>::add(it, stake);
        }

        void add(const C::key_type &id, C::mapped_type stake)
        {
            add(distribution<C>::find(id), stake);
        }

        void sub(const C::key_type &id, C::mapped_type stake)
        {
            distribution<C>::sub(id, stake, false);
        }
    };

    enum class reward_type {
        leader,
        member
    };
    struct reward_update {
        using serialize = zpp::bits::members<4>;
        reward_type type {};
        cardano::pool_hash pool_id {};
        uint64_t amount {};
        std::optional<cardano::pool_hash> delegated_pool_id {};

        bool operator<(const auto &b) const
        {
            if (type != b.type)
                return type < b.type;
            return pool_id < b.pool_id;
        }

        bool operator==(const auto &b) const
        {
            return type == b.type && pool_id == b.pool_id && amount == b.amount;
        }
    };
    using reward_update_list = std::set<reward_update>;

    struct reward_update_distribution: std::unordered_map<cardano::stake_ident, reward_update_list> {
        using std::unordered_map<cardano::stake_ident, reward_update_list>::unordered_map;

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self._total_stake, dynamic_cast<std::unordered_map<cardano::stake_ident, reward_update_list> &>(self));
        }

        void add(const cardano::stake_ident &id, const reward_update &reward)
        {
            auto [it, created] = try_emplace(id);
            it->second.emplace(reward);
            _total_stake += reward.amount;
        }

        uint64_t get(const cardano::stake_ident &id) const
        {
            uint64_t sum = 0;
            auto it = find(id);
            if (it != end()) {
                for (const auto &upd: it->second)
                    sum += upd.amount;
            }
            return sum;
        }

        void clear()
        {
            std::unordered_map<cardano::stake_ident, reward_update_list>::clear();
            _total_stake = 0;
        }

        uint64_t total_stake()
        {
            return _total_stake;
        }
    protected:
        uint64_t _total_stake = 0;
    };

    struct reward_distribution: partitioned_map<stake_ident, uint64_t> {
        using C = partitioned_map<stake_ident, uint64_t>;

        bool create(const C::key_type &id)
        {
            auto [it, created] = C::try_emplace(id);
            return created;
        }

        void retire(const C::key_type &id)
        {
            auto it = C::find(id);
            if (it == C::end())
                throw error("retiring an unknown id {}", id);
            C::erase(it);
        }

        void add(map_with_get<C>::iterator it, C::mapped_type stake)
        {
            if (it == C::end())
                throw error("request to increase an unregistered id {} by {}", it->first, stake);
            it->second += stake;
        }

        void add(const C::key_type &id, C::mapped_type stake)
        {
            add(C::find(id), stake);
        }

        void sub(const C::key_type &id, C::mapped_type stake)
        {
            auto it = C::find(id);
            if (it == C::end())
                throw error("request to increase an unregistered id {} by {}", it->first, stake);
            if (it->second < stake)
                throw error("request to delete more stake ({}) than id {} has: {}", stake, id, it->second);
            it->second -= stake;
        }
    };

    using partitioned_reward_update_dist = partitioned_map<cardano::stake_ident, reward_update_list>;
    using pool_stake_distribution = restricted_distribution<std::map<cardano::pool_hash, uint64_t>>;
    using pool_stake_distribution_copy = static_map<cardano::pool_hash, uint64_t>;
    using pool_update_distribution = distribution<std::map<cardano::pool_hash, size_t>>;
    using stake_distribution = distribution<std::map<cardano::stake_ident, uint64_t>>;
    using stake_distribution_copy = static_map<cardano::stake_ident, uint64_t>;
    //using reward_distribution = restricted_distribution<std::map<stake_ident, uint64_t>>;
    using reward_distribution_copy = static_map<stake_ident, uint64_t>;
    using delegation_map = std::map<cardano::stake_ident, cardano::pool_hash>;
    using delegation_map_copy = static_map<cardano::stake_ident, cardano::pool_hash>;
    using inv_delegation_map = std::map<cardano::pool_hash, std::unordered_set<cardano::stake_ident>>;
    using inv_delegation_map_copy = static_map<cardano::pool_hash, std::unordered_set<cardano::stake_ident>>;

    using ptr_to_stake_map = std::map<cardano::stake_pointer, cardano::stake_ident>;
    using stake_to_ptr_map = std::map<cardano::stake_ident, cardano::stake_pointer>;

    struct epoch_info {
        uint64_t fees = 0;
        uint64_t ir_reserves = 0;
        uint64_t ir_treasury = 0;
        uint64_t withdrawals = 0;
        uint64_t unclaimed_rewards = 0;
    };

    struct protocol_params {
        using serialize = zpp::bits::members<21>;

        double f = 0.05;
        uint64_t k = 2160;
        uint64_t epoch_blocks = 21'600;
        uint64_t max_lovelace_supply = 45'000'000'000'000'000;
        uint64_t min_fee_a {};
        uint64_t min_fee_b {};
        uint64_t max_block_body_size {};
        uint64_t max_transaction_size {};
        uint64_t max_block_header_size {};
        uint64_t key_deposit = 2'000'000;
        uint64_t pool_deposit = 500'000'000;
        uint64_t max_epoch {};
        uint64_t n_opt = 150;
        rational_u64 pool_pledge_influence { 3, 10 };
        rational_u64 expansion_rate { 3, 1000 };
        rational_u64 treasury_growth_rate { 1, 5 };
        rational_u64 decentralization { 1, 1 };
        rational_u64 decentralizationThreshold { 4, 5 };
        cardano::nonce extra_entropy {};
        cardano::protocol_version protocol_ver {};
        uint64_t min_utxo_value {};

        uint64_t stability_window()
        {
            return std::ceil(3 * k / f);
        }

        uint64_t randomness_stabilization_window()
        {
            return std::ceil(4 * k / f);
        }
    };
}

#endif // !DAEDALUS_TURBO_VALIDATOR_STATE_TYPES_HPP