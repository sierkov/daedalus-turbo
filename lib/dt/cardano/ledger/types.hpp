/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_LEDGER_TYPES_HPP
#define DAEDALUS_TURBO_CARDANO_LEDGER_TYPES_HPP

#include <unordered_set>
#include <dt/cardano/common.hpp>
#include <dt/cardano/ledger/pool-rank.hpp>
#include <dt/partitioned-map.hpp>
#include <dt/scheduler.hpp>
#include <dt/static-map.hpp>

namespace daedalus_turbo::cardano::ledger {
    template<typename C>
    struct map_with_get: C
    {
        using C::C;

        const typename C::mapped_type get(const typename C::key_type &id) const
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

        void add(map_with_get<C>::iterator it, typename C::mapped_type stake)
        {
            if (stake > 0) {
                it->second += stake;
                _total_stake += static_cast<uint64_t>(stake);
            }
        }

        void add(const typename C::key_type &id, typename C::mapped_type stake)
        {
            if (stake > 0) {
                auto [it, created] = map_with_get<C>::try_emplace(id, 0);
                add(it, stake);
            }
        }

        void sub(const typename C::key_type &id, typename C::mapped_type stake, bool remove_zero=true)
        {
            if (stake > 0) {
                auto it = map_with_get<C>::find(id);
                if (it == map_with_get<C>::end()) 
                    throw error(fmt::format("request to remove stake from an unknown id: {}", id));
                if (it->second < stake)
                    throw error(fmt::format("request to delete more stake ({}) than id {} has: {}", stake, id, it->second));
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

        bool create(const typename C::key_type &id)
        {
            auto [it, created] = distribution<C>::try_emplace(id);
            return created;
        }

        void retire(const typename C::key_type &id)
        {
            auto it = distribution<C>::find(id);
            if (it == distribution<C>::end())
                throw error(fmt::format("retiring an unknown id {}", id));
            distribution<C>::_total_stake -= static_cast<uint64_t>(it->second);
            distribution<C>::erase(it);
        }

        void add(distribution<C>::iterator it, typename C::mapped_type stake)
        {
            if (it == distribution<C>::end())
                throw error(fmt::format("request to increase an unregistered id {} by {}", it->first, stake));
            distribution<C>::add(it, stake);
        }

        void add(const typename C::key_type &id, typename C::mapped_type stake)
        {
            add(distribution<C>::find(id), stake);
        }

        void sub(const typename C::key_type &id, typename C::mapped_type stake)
        {
            distribution<C>::sub(id, stake, false);
        }
    };

    enum class reward_type {
        leader,
        member
    };
    struct reward_update {
        reward_type type {};
        pool_hash pool_id {};
        uint64_t amount {};
        std::optional<pool_hash> delegated_pool_id {};

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.type, self.pool_id, self.amount, self.delegated_pool_id);
        }

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

    struct reward_distribution: partitioned_map<cardano::stake_ident, uint64_t> {
        using C = partitioned_map<cardano::stake_ident, uint64_t>;

        bool operator==(const auto &o) const
        {
            return C::operator==(o);
        }

        bool create(const C::key_type &id)
        {
            auto [it, created] = C::try_emplace(id);
            return created;
        }

        void retire(const C::key_type &id)
        {
            auto it = C::find(id);
            if (it == C::end())
                throw error(fmt::format("retiring an unknown id {}", id));
            C::erase(it);
        }

        void add(map_with_get<C>::iterator it, C::mapped_type stake)
        {
            if (it == C::end())
                throw error(fmt::format("request to increase an unregistered id {} by {}", it->first, stake));
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
                throw error(fmt::format("request to increase an unregistered id {} by {}", it->first, stake));
            if (it->second < stake)
                throw error(fmt::format("request to delete more stake ({}) than id {} has: {}", stake, id, it->second));
            it->second -= stake;
        }
    };

    using partitioned_reward_update_dist = partitioned_map<cardano::stake_ident, reward_update_list>;
    using pool_stake_distribution = restricted_distribution<map<cardano::pool_hash, uint64_t>>;
    using pool_stake_distribution_copy = static_map<cardano::pool_hash, uint64_t>;
    using pool_update_distribution = distribution<map<cardano::pool_hash, size_t>>;
    using stake_distribution = distribution<map<cardano::stake_ident, uint64_t>>;
    using stake_pointer_distribution = distribution<map<cardano::stake_pointer, uint64_t>>;
    using stake_distribution_copy = static_map<cardano::stake_ident, uint64_t>;
    //using reward_distribution = restricted_distribution<std::map<stake_ident, uint64_t>>;
    using reward_distribution_copy = static_map<cardano::stake_ident, uint64_t>;
    using delegation_map = map<cardano::stake_ident, cardano::pool_hash>;
    using delegation_map_copy = static_map<cardano::stake_ident, cardano::pool_hash>;
    using inv_delegation_map = map<cardano::pool_hash, std::unordered_set<cardano::stake_ident>>;
    using inv_delegation_map_copy = static_map<cardano::pool_hash, std::unordered_set<cardano::stake_ident>>;

    using ptr_to_stake_map = map<cardano::stake_pointer, cardano::stake_ident>;
    using stake_to_ptr_map = map<cardano::stake_ident, cardano::stake_pointer>;

    struct pool_reward_item {
        cardano::stake_ident stake_id {};
        reward_type type {};
        uint64_t amount = 0;
        std::optional<cardano::pool_hash> delegated_pool_id {};

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.stake_id, self.type, self.amount, self.delegated_pool_id);
        }
    };

    using pool_set = std::set<cardano::pool_hash>;
    using pool_block_dist = distribution<std::map<cardano::pool_hash, uint64_t>>;
    using pool_reward_list = std::vector<pool_reward_item>;
    using pool_rewards_result = std::tuple<cardano::pool_hash, pool_reward_list, uint64_t>;
    using pool_reward_map = std::map<cardano::pool_hash, pool_reward_list>;
    using pool_retiring_map = std::map<cardano::pool_hash, uint64_t>;

    struct operating_pool_info {
        rational_u64 rel_stake {};
        cardano::vrf_vkey vrf_vkey {};

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.rel_stake, self.vrf_vkey);
        }

        bool operator==(const operating_pool_info &o) const
        {
            return rel_stake == o.rel_stake && vrf_vkey == o.vrf_vkey;
        }
    };
    using operating_pool_map = map<pool_hash, operating_pool_info>;

    struct pool_info {
        pool_params params {};
        rational member_reward_base {};

        static constexpr auto serialize(auto &archive, auto &self)
        {
            return archive(self.params);
        }

        bool operator==(const pool_info &o) const
        {
            return params == o.params;
        }
    };

    using pool_info_map = map<pool_hash, pool_info>;
    using pool_deposit_map = map<pool_hash, uint64_t>;
    using nonmyopic_likelihood_map = map<pool_hash, pool_rank::likelihood_list>;

    using era_list = std::vector<uint64_t>;
    using stake_update_map = std::unordered_map<stake_ident, int64_t>;
    using pointer_update_map = std::unordered_map<stake_pointer, int64_t>;

    struct account_info {
        uint64_t stake = 0;
        uint64_t reward = 0;
        uint64_t deposit = 0;
        uint64_t mark_stake = 0;
        uint64_t set_stake = 0;
        uint64_t go_stake = 0;
        // the presence of a stake pointer means that the account's stake address is registered currently
        std::optional<stake_pointer> ptr {};
        std::optional<pool_hash> deleg {};
        std::optional<pool_hash> mark_deleg {};
        std::optional<pool_hash> set_deleg {};
        std::optional<pool_hash> go_deleg {};
        std::optional<drep_t> vote_deleg {};

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.stake, self.reward, self.deposit, self.mark_stake, self.set_stake, self.go_stake,
                self.ptr, self.deleg, self.mark_deleg, self.set_deleg, self.go_deleg, self.vote_deleg);
        }

        bool operator==(const account_info &o) const
        {
            return stake == o.stake && reward == o.reward && deposit == o.deposit
                && mark_stake == o.mark_stake && set_stake == o.set_stake && go_stake == o.go_stake
                && deleg == o.deleg && mark_deleg == o.mark_deleg && set_deleg == o.set_deleg && go_deleg == o.go_deleg
                && ptr == o.ptr;
        }

        const std::optional<pool_hash> &deleg_copy(const size_t idx) const
        {
            switch (idx) {
                case 0: return mark_deleg;
                case 1: return set_deleg;
                case 2: return go_deleg;
                default: throw error(fmt::format("unsupported deleg_copy index: {}", idx));
            }
        }

        std::optional<pool_hash> &deleg_copy(const size_t idx)
        {
            return const_cast<std::optional<pool_hash> &>(const_cast<const account_info &>(*this).deleg_copy(idx));
        }

        const uint64_t &stake_copy(const size_t idx) const
        {
            switch (idx) {
                case 0: return mark_stake;
                case 1: return set_stake;
                case 2: return go_stake;
                default: throw error(fmt::format("unsupported stake_copy index: {}", idx));
            }
        }

        uint64_t &stake_copy(const size_t idx)
        {
            return const_cast<uint64_t &>(const_cast<const account_info &>(*this).stake_copy(idx));
        }
    };

    struct ledger_copy {
        pool_stake_distribution pool_dist {};
        inv_delegation_map_copy inv_delegs {};
        pool_info_map pool_params {};

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.pool_dist, self.inv_delegs, self.pool_params);
        }

        bool operator==(const ledger_copy &o) const
        {
            return pool_dist == o.pool_dist
                && inv_delegs == o.inv_delegs
                && pool_params == o.pool_params;
        }

        size_t size() const
        {
            return pool_dist.size() + inv_delegs.size() + pool_params.size();
        }

        void clear()
        {
            pool_dist.clear();
            inv_delegs.clear();
            pool_params.clear();
        }
    };

    struct block_update_list;
    struct timed_update_t;
    struct timed_update_list;
    struct utxo_update_list;
    struct updates_t;
    struct state;

    struct parallel_decoder {
        using decode_func = std::function<void(buffer)>;
        using done_func = std::function<void()>;

        explicit parallel_decoder(const std::string &path);
        [[nodiscard]] size_t size() const;
        void add(const decode_func &t);
        buffer at(size_t idx) const;
        void on_done(const done_func &);
        void run(scheduler &sched, const std::string &task_group, int prio=1000, bool report_progress=false);
    private:
        const uint8_vector _data;
        vector<buffer> _buffers {};
        vector<decode_func> _tasks {};
        vector<done_func> _on_done {};
    };

    struct parallel_serializer {
        using encode_func = std::function<uint8_vector()>;

        [[nodiscard]] size_t size() const;
        void add(const encode_func &t);
        void run(scheduler &sched, const std::string &task_group, int prio=1000, bool report_progress=false);
        void save(const std::string &path, bool headers=false) const;
        [[nodiscard]] uint8_vector flat() const;
    private:
        vector<encode_func> _tasks {};
        vector<uint8_vector> _buffers {};
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_LEDGER_STATE_TYPES_HPP