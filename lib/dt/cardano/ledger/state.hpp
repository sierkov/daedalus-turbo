/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_LEDGER_STATE_HPP
#define DAEDALUS_TURBO_CARDANO_LEDGER_STATE_HPP

#include <ranges>
#include <dt/atomic.hpp>
#include <dt/cardano/ledger/babbage.hpp>
#include <dt/cardano/ledger/shelley.hpp>
#include <dt/cardano/ledger/subchain.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/format.hpp>
#include <dt/mutex.hpp>
#include <dt/scheduler.hpp>
#include <dt/static-map.hpp>

namespace daedalus_turbo::cardano::ledger {
    struct state {
        explicit state(const cardano::config &cfg=cardano::config::get(), scheduler &sched=scheduler::get());

        bool operator==(const state &o) const;
        void clear();

        void load_zpp(const std::string &path);
        void save_zpp(const std::string &path);
        parallel_serializer serialize_node(const point &tip, int prio=1000) const;
        point deserialize_node(buffer data);
        point load_node(const std::string &path);
        void save_node(const std::string &path, const point &tip, int prio=1000) const;

        void track_era(uint64_t era, uint64_t slot);
        void process_updates(updates_t &&);

        optional_point add_subchain(subchain &&sc)
        {
            mutex::scoped_lock sc_lk { _subchains_mutex };
            _subchains.add(std::move(sc));
            return _subchains.max_valid_point();
        }

        optional_point mark_subchain_valid(const uint64_t epoch, const uint64_t epoch_min_offset, const size_t num_valid_blocks)
        {
            mutex::scoped_lock sc_lk { _subchains_mutex };
            auto sc_it = _subchains.find(epoch_min_offset);
            sc_it->second.valid_blocks += num_valid_blocks;
            if (sc_it->second) {
                logger::debug("subchain became valid epoch: {} start_offset: {} end_offset: {}",
                    epoch, sc_it->second.offset, sc_it->second.end_offset());
                _subchains.merge_valid();
                return _subchains.max_valid_point();
            }
            return {};
        }

        uint64_t valid_end_offset() const
        {
            mutex::scoped_lock lk { _subchains_mutex };
            return std::min(_subchains.valid_size(), _state->_end_offset);
        }

        void merge_same_epoch_subchains()
        {
            mutex::scoped_lock sc_lk { _subchains_mutex };
            _subchains.merge_same_epoch(_cfg);
        }

        void proposal_vote(const uint64_t slot, const param_update_vote &vote)
        {
            _state->proposal_vote(slot, vote);
        }

        void propose_update(const uint64_t slot, const param_update_proposal &prop)
        {
            _state->propose_update(slot, prop);
        }

        void register_pool(const shelley::pool_reg_cert &reg)
        {
            _state->register_pool(reg);
        }

        void vrf_process_updates(const vector<index::vrf::item> &updates)
        {
            _vrf_state->process_updates(updates);
        }

        void process_block(const uint64_t end_offset, const uint64_t era, const uint64_t slot, const uint64_t fees)
        {
            track_era(era, slot);
            add_fees(fees);
            _state->process_block(end_offset, slot);
        }

        void reserves(const uint64_t r)
        {
            _state->reserves(r);
        }

        void start_epoch(std::optional<uint64_t> new_epoch={});

        // Accessors

        const shelley::vrf_state &vrf_state() const
        {
            return *_vrf_state;
        }

        const txo_map &utxos() const
        {
            return _state->_utxo;
        }

        const ptr_to_stake_map &pointers() const
        {
            return _state->_ptr_to_stake;
        }

        cardano::amount unspent_reward(const cardano::stake_ident &id) const
        {
            const auto acc_it = _state->_accounts.find(id);
            if (acc_it != _state->_accounts.end() && acc_it->second.ptr)
                return { acc_it->second.reward };
            return { 0 };
        }

        const era_list eras() const
        {
            era_list copy {};
            std::copy(_eras.begin(), _eras.end(), std::back_inserter(copy));
            return copy;
        }

        reward_distribution reward_dist() const
        {
            reward_distribution rewards {};
            for (const auto &[stake_id, acc]: _state->_accounts) {
                if (acc.ptr && acc.reward) {
                    rewards.create(stake_id);
                    rewards.add(stake_id, acc.reward);
                }
            }
            return rewards;
        }

        const stake_distribution &instant_rewards_reserves() const
        {
            return _state->_instant_rewards_reserves;
        }

        const stake_distribution &instant_rewards_treasury() const
        {
            return _state->_instant_rewards_treasury;
        }

        delegation_map_copy delegs_mark() const
        {
            return _filtered_delegs(0);
        }

        delegation_map_copy delegs_set() const
        {
            return _filtered_delegs(1);
        }

        delegation_map_copy delegs_go() const
        {
            return _filtered_delegs(2);
        }

        const stake_distribution stake_dist_mark() const
        {
            return _filtered_stake_dist(0);
        }

        const stake_distribution stake_dist_set() const
        {
            return _filtered_stake_dist(1);
        }

        const stake_distribution stake_dist_go() const
        {
            return _filtered_stake_dist(2);
        }

        const pool_deposit_map &pool_deposits() const
        {
            return _state->_pool_deposits;
        }

        const pool_stake_distribution &pool_dist_go() const
        {
            return _state->_go.pool_dist;
        }

        const pool_stake_distribution &pool_dist_mark() const
        {
            return _state->_mark.pool_dist;
        }

        const pool_stake_distribution &pool_dist_set() const
        {
            return _state->_set.pool_dist;
        }

        const operating_pool_map &pool_stake_dist() const
        {
            return _state->_operating_stake_dist;
        }

        const pool_info_map &pool_params_mark() const
        {
            return _state->_mark.pool_params;
        }

        const pool_info_map &pool_params_set() const
        {
            return _state->_set.pool_params;
        }

        const pool_info_map &pool_params_go() const
        {
            return _state->_go.pool_params;
        }

        const pool_info_map &pool_params() const
        {
            return _state->_active_pool_params;
        }

        const pool_info_map &pool_params_future() const
        {
            return _state->_future_pool_params;
        }

        const pool_block_dist &blocks_before() const
        {
            return _state->_blocks_before;
        }

        const pool_block_dist &blocks_current() const
        {
            return _state->_blocks_current;
        }

        const pool_retiring_map &pools_retiring() const
        {
            return _state->_pools_retiring;
        }

        uint64_t deposited() const
        {
            return _state->_deposited;
        }

        uint64_t fees_reward_snapshot() const
        {
            return _state->_fees_next_reward;
        }

        void sub_fees(const uint64_t refund)
        {
            _state->sub_fees(refund);
        }

        void add_fees(const uint64_t amount)
        {
            _state->add_fees(amount);
        }

        uint64_t reserves() const
        {
            return _state->_reserves;
        }

        uint64_t treasury() const
        {
            return _state->_treasury;
        }

        const protocol_params &params() const
        {
            return _state->_params;
        }

        const protocol_params &prev_params() const
        {
            return _state->_params_prev;
        }

        const partitioned_reward_update_dist &potential_rewards() const
        {
            return _state->_potential_rewards;
        }

        const nonmyopic_likelihood_map &nonmyopic() const
        {
            return _state->_nonmyopic;
        }

        uint64_t nonmyopic_reward_pot() const
        {
            return _state->_nonmyopic_reward_pot;
        }

        const nonmyopic_likelihood_map &potential_nonmyopic() const
        {
            return _state->_nonmyopic_next;
        }

        cardano::slot last_slot() const
        {
            return cardano::slot::from_epoch(_state->_epoch, _state->_epoch_slot, _cfg);
        }

        uint64_t end_offset() const
        {
            return _state->_end_offset;
        }

        uint64_t delta_reserves() const
        {
            return _state->_delta_reserves;
        }

        uint64_t delta_treasury() const
        {
            return _state->_delta_treasury;
        }

        uint64_t delta_fees() const
        {
            return _state->_delta_fees;
        }

        uint64_t reward_pot() const
        {
            return _state->_reward_pot;
        }

        const shelley_delegate_map &future_shelley_delegates() const
        {
            return _state->_future_shelley_delegs;
        }

        const shelley_delegate_map &shelley_delegates() const
        {
            return _state->_shelley_delegs;
        }

        const set<pool_hash> &pbft_pools() const
        {
            return _state->_pbft_pools;
        }

        uint64_t utxo_balance() const
        {
            return _state->utxo_balance();
        }

        void compute_rewards_if_ready()
        {
            _state->compute_rewards_if_ready();
        }

        bool exportable() const
        {
            if (_state->_params.protocol_ver.major >= 3 && (_state->_rewards_ready || _state->_epoch_slot < _cfg.shelley_randomness_stabilization_window))
                return true;
            return false;
        }

        const stake_pointer_distribution stake_pointers() const
        {
            return _state->_stake_pointers;
        }

        uint64_t epoch() const
        {
            return _state->_epoch;
        }
    private:
        // non-serializable members:
        const cardano::config &_cfg;
        scheduler &_sched;

        alignas(mutex::padding) mutable mutex::unique_lock::mutex_type _subchains_mutex {};
        subchain_list _subchains{};
        /// implementation-specific fields
        era_list _eras {};
        std::unique_ptr<shelley::state> _state;
        std::unique_ptr<shelley::vrf_state> _vrf_state;

        void _serialize_node_state(parallel_serializer &ser, const point &tip) const;
        void _serialize_node_vrf_state(parallel_serializer &ser, const point &tip) const;
        void _transition_era(uint64_t from_era, uint64_t to_era);

        delegation_map_copy _filtered_delegs(const size_t idx) const
        {
            delegation_map_copy delegs {};
            for (const auto &[stake_id, acc]: _state->_accounts) {
                if (const auto &deleg = acc.deleg_copy(idx); deleg)
                    delegs.emplace_back(stake_id, *deleg);
            }
            return delegs;
        }

        stake_distribution _filtered_stake_dist(const size_t idx) const
        {
            stake_distribution sd {};
            for (const auto &[stake_id, acc]: _state->_accounts) {
                if (const auto stake = acc.stake_copy(idx); stake > 0 && acc.deleg_copy(idx))
                    sd.try_emplace(stake_id, stake);
            }
            return sd;
        }
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::cardano::ledger::reward_type>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            switch (v) {
                case daedalus_turbo::cardano::ledger::reward_type::leader:
                    return fmt::format_to(ctx.out(), "reward_type::leader");

                case daedalus_turbo::cardano::ledger::reward_type::member:
                    return fmt::format_to(ctx.out(), "reward_type::member");

                default:
                    return fmt::format_to(ctx.out(), "reward_type::unsupported");
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::ledger::reward_update>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "reward_update(type: {} pool_id: {} amount: {})", v.type, v.pool_id, v.amount);
        }
    };

    template<>
    struct formatter<daedalus_turbo::cardano::ledger::operating_pool_info>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "rel_stake: {} vrf: {}", v.rel_stake, v.vrf_vkey);
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_LEDGER_STATE_HPP