/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_VALIDATOR_STATE_HPP
#define DAEDALUS_TURBO_VALIDATOR_STATE_HPP

#include <ranges>
#include <unordered_map>
#include <dt/atomic.hpp>
#include <dt/cardano/state/vrf.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/format.hpp>
#include <dt/scheduler.hpp>
#include <dt/static-map.hpp>
#include <dt/timer.hpp>
#include <dt/validator/pool-rank.hpp>
#include <dt/validator/types.hpp>
#include <dt/validator/subchain.hpp>

namespace daedalus_turbo::validator {
    struct state_encoder;

    struct parallel_serializer {
        using task = std::function<uint8_vector()>;
        using task_cbor = std::function<void(state_encoder &)>;

        size_t size() const;
        void add(const task &t);
        void add(const task_cbor &);
        void run(scheduler &sched, const std::string &task_group, int prio=1000, bool report_progress=false);
        void save(const std::string &path, bool headers=false) const;
        uint8_vector flat() const;
    private:
        vector<task> _tasks {};
        vector<uint8_vector> _buffers {};
    };

    struct pool_info {
        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.reward_id, self.owners, self.pledge, self.cost, self.margin, self.vrf_vkey,
                self.relays, self.metadata, self.reward_network);
        }

        bool operator==(const auto &o) const
        {
            return reward_id == o.reward_id && owners == o.owners && pledge == o.pledge
                && cost == o.cost && margin == o.margin
                && vrf_vkey == o.vrf_vkey && relays == o.relays
                && metadata == o.metadata && reward_network == o.reward_network;
        }

        pool_info() =default;

        pool_info(const cardano::pool_reg &reg)
            : reward_id { reg.reward_id }, owners { reg.owners }, pledge { reg.pledge }, cost { reg.cost },
                margin { reg.margin }, vrf_vkey { reg.vrf_vkey }, relays { reg.relays },
                metadata { reg.metadata }, reward_network { reg.reward_network }
        {
        }

        cardano::stake_ident reward_id {};
        set<cardano::stake_ident> owners {};
        uint64_t pledge = 0;
        uint64_t cost = 0;
        rational_u64 margin = { 0, 1 };
        cardano::vrf_vkey vrf_vkey {};
        cardano::relay_list relays {};
        std::optional<cardano::pool_metadata> metadata {};
        uint8_t reward_network = 1;
        // not serializable and not comparable:
        rational member_reward_base {};
    };

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
    using operating_pool_map = map<cardano::pool_hash, operating_pool_info>;

    using pool_info_map = map<cardano::pool_hash, pool_info>;
    using pool_deposit_map = map<cardano::pool_hash, uint64_t>;
    using nonmyopic_likelihood_map = map<cardano::pool_hash, pool_rank::likelihood_list>;

    using era_list = std::vector<uint64_t>;
    using stake_update_map = std::unordered_map<cardano::stake_ident, int64_t>;
    using pointer_update_map = std::unordered_map<cardano::stake_pointer, int64_t>;

    struct state {
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

        explicit state(const cardano::config &cfg=cardano::config::get(), scheduler &sched=scheduler::get())
            : _cfg { cfg }, _sched { sched }, _utxo { _cfg.byron_utxos }
        {
        }

        bool operator==(const auto &o) const
        {
            return _subchains == o._subchains
                && _end_offset == o._end_offset
                && _epoch_slot == o._epoch_slot
                && _eras == o._eras
                && _vrf_state == o._vrf_state
                && _reward_pulsing_snapshot_slot == o._reward_pulsing_snapshot_slot
                && _reward_pulsing_snapshot == o._reward_pulsing_snapshot
                && _active_pool_dist == o._active_pool_dist
                && _active_inv_delegs == o._active_inv_delegs
                && _accounts == o._accounts

                && _epoch == o._epoch
                && _blocks_current == o._blocks_current
                && _blocks_before == o._blocks_before

                && _reserves == o._reserves
                && _treasury == o._treasury

                && _mark == o._mark
                && _set == o._set
                && _go == o._go
                && _fees_next_reward == o._fees_next_reward

                && _utxo == o._utxo
                && _deposited == o._deposited
                && _delta_fees == o._delta_fees
                && _fees_utxo == o._fees_utxo
                && _ppups == o._ppups
                && _ppups_future == o._ppups_future

                && _ptr_to_stake == o._ptr_to_stake
                && _future_shelley_delegs == o._future_shelley_delegs
                && _shelley_delegs == o._shelley_delegs
                && _stake_pointers == o._stake_pointers

                && _instant_rewards_reserves == o._instant_rewards_reserves
                && _instant_rewards_treasury == o._instant_rewards_treasury

                && _active_pool_params == o._active_pool_params
                && _future_pool_params == o._future_pool_params
                && _pools_retiring == o._pools_retiring
                && _pool_deposits == o._pool_deposits

                && _params == o._params
                && _params_prev == o._params_prev
                && _nonmyopic == o._nonmyopic
                && _nonmyopic_reward_pot == o._nonmyopic_reward_pot

                && _delta_treasury == o._delta_treasury
                && _delta_reserves == o._delta_reserves
                && _reward_pot == o._reward_pot
                && _potential_rewards == o._potential_rewards
                && _rewards_ready == o._rewards_ready
                && _nonmyopic_next == o._nonmyopic_next

                && _operating_stake_dist == o._operating_stake_dist
                && _blocks_past_voting_deadline == o._blocks_past_voting_deadline;
        }

        void clear();
        void load(const std::string &path);
        cardano::point deserialize_node(const buffer &data);
        cardano::point load_node(const std::string &path);
        void save(const std::string &path);
        void save_node(const std::string &path, const cardano::point &tip, int prio=1000) const;
        parallel_serializer serialize_node(const cardano::point &tip, int prio=1000) const;

        cardano::optional_point add_subchain(subchain &&sc)
        {
            mutex::scoped_lock sc_lk { _subchains_mutex() };
            _subchains.add(std::move(sc));
            return _subchains.max_valid_point();
        }

        cardano::optional_point mark_subchain_valid(const uint64_t epoch, const uint64_t epoch_min_offset, const size_t num_valid_blocks)
        {
            mutex::scoped_lock sc_lk { _subchains_mutex() };
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
            mutex::scoped_lock lk { _subchains_mutex() };
            return std::min(_subchains.valid_size(), _end_offset);
        }

        void merge_same_epoch_subchains()
        {
            mutex::scoped_lock sc_lk { _subchains_mutex() };
            _subchains.merge_same_epoch(_cfg);
        }

        void register_pool(const cardano::pool_reg &reg)
        {
            pool_info pool_params { reg };
            auto [it, created] = _active_pool_params.try_emplace(reg.pool_id, std::move(pool_params));
            if (created) {
                _pool_deposits[reg.pool_id] = _params.pool_deposit;
                _deposited += _params.pool_deposit;
            } else {
                auto [f_it, f_created] = _future_pool_params.try_emplace(reg.pool_id, std::move(pool_params));
                if (!f_created)
                    f_it->second = std::move(pool_params);
            }
            // search for already delegated stake ids - needed for the case of re-registration of a retired pool
            if (_active_pool_dist.create(reg.pool_id)) {
                auto [inv_delegs_it, inv_delegs_created] = _active_inv_delegs.try_emplace(reg.pool_id);
                if (!inv_delegs_created) {
                    for (const auto &stake_id: inv_delegs_it->second) {
                        const auto &acc = _accounts.at(stake_id);
                        _active_pool_dist.add(reg.pool_id, acc.stake + acc.reward);
                    }
                }
            }
            // delete a planned retirement if present
            _pools_retiring.erase(reg.pool_id);
        }

        void retire_pool(const cardano::pool_hash &pool_id, uint64_t epoch)
        {
            if (_active_pool_params.contains(pool_id)) {
                _pools_retiring[pool_id] = epoch;
            } else {
                logger::warn("retirement of an unknown pool: {}", pool_id);
            }
        }

        bool has_pool(const cardano::pool_hash &pool_id)
        {
            return _active_pool_params.contains(pool_id);
        }

        void instant_reward_reserves(const uint64_t, const cardano::stake_ident &stake_id, const uint64_t reward)
        {
            if (const auto prev_amount = _instant_rewards_reserves.get(stake_id); prev_amount > 0)
                _instant_rewards_reserves.sub(stake_id, prev_amount);
            _instant_rewards_reserves.add(stake_id, reward);
        }

        void instant_reward_treasury(const uint64_t, const cardano::stake_ident &stake_id, const uint64_t reward)
        {

            if (const auto prev_amount = _instant_rewards_treasury.get(stake_id); prev_amount > 0)
                _instant_rewards_treasury.sub(stake_id, prev_amount);
            _instant_rewards_treasury.add(stake_id, reward);
        }

        const utxo_map &utxos() const
        {
            return _utxo;
        }

        void vrf_process_updates(const vector<index::vrf::item> &updates)
        {
            _vrf_state.process_updates(updates, _cfg);
        }

        const cardano::state::vrf &vrf_state() const
        {
            return _vrf_state;
        }

        static void _update_stake_delta(stake_update_map &deltas, const cardano::stake_ident &stake_id, const int64_t delta)
        {
            if (delta) {
                const auto [it, created] = deltas.try_emplace(stake_id, delta);
                if (!created) {
                    it->second += delta;
                    if (!it->second)
                        deltas.erase(it);
                }
            }
        }

        const cardano::tx_out_data *utxo_find(const cardano::tx_out_ref &txo_id)
        {
            if (const auto it = _utxo.find(txo_id);it != _utxo.end()) [[likely]]
                return &it->second;
            return nullptr;
        }

        void utxo_add(const cardano::tx_out_ref &txo_id, cardano::tx_out_data &&txo_data)
        {
            if (!txo_data.empty()) [[likely]] {
                auto [it, created] = _utxo.try_emplace(txo_id, std::move(txo_data));
                if (!created)
                    logger::warn("a non-unique TXO {}!", it->first);
            }
        }

        void utxo_del(const cardano::tx_out_ref &txo_id)
        {
            if (const size_t num_del = _utxo.erase(txo_id); num_del != 1)
                throw error("request to remove an unknown TXO {}!", txo_id);
        }

        void utxo_apply_updates(vector<utxo_map> &updates)
        {
            const std::string task_group = fmt::format("ledger-state:apply-utxo-updates:epoch-{}", _epoch);
            alignas(mutex::padding) mutex::unique_lock::mutex_type all_mutex {};
            stake_update_map all_deltas {};
            pointer_update_map all_pointer_deltas {};
            _sched.wait_all_done(task_group, utxo_map::num_parts,
                [&] {
                    for (size_t part_idx = 0; part_idx < utxo_map::num_parts; ++part_idx) {
                        _sched.submit_void(task_group, 1000, [this, part_idx, &updates, &all_mutex, &all_deltas, &all_pointer_deltas] {
                            stake_update_map deltas {};
                            pointer_update_map pointer_deltas {};
                            for (auto &&update_batch: updates) {
                                auto &upd_part = update_batch.partition(part_idx);
                                auto &utxo_part = _utxo.partition(part_idx);
                                for (auto &&[txo_id, txo_data]: upd_part) {
                                    if (!txo_data.address.empty()) {
                                        const cardano::address addr { txo_data.address };
                                        if (addr.has_stake_id()) [[likely]]
                                            _update_stake_delta(deltas, addr.stake_id(), static_cast<int64_t>(txo_data.coin));
                                        else if (addr.has_pointer()) [[unlikely]]
                                            pointer_deltas[addr.pointer()] += static_cast<int64_t>(txo_data.coin);
                                        if (!txo_data.empty()) [[likely]] {
                                            if (auto [it, created] = utxo_part.try_emplace(txo_id, std::move(txo_data)); !created) [[unlikely]]
                                                logger::warn("a non-unique TXO {}!", it->first);
                                        }
                                    } else {
                                        if (auto it = utxo_part.find(txo_id); it != utxo_part.end()) [[likely]] {
                                            const cardano::address addr { it->second.address };
                                            if (addr.has_stake_id()) [[likely]]
                                                _update_stake_delta(deltas, addr.stake_id(), -static_cast<int64_t>(it->second.coin));
                                            else if (addr.has_pointer()) [[unlikely]]
                                                pointer_deltas[addr.pointer()] -= static_cast<int64_t>(it->second.coin);
                                            utxo_part.erase(it);
                                        } else {
                                            throw error("request to remove an unknown TXO {}!", txo_id);
                                        }
                                    }
                                }
                            }
                            mutex::scoped_lock lk { all_mutex };
                            for (const auto &[stake_id, delta]: deltas) {
                                const auto [it, created] = all_deltas.try_emplace(stake_id, delta);
                                if (!created) {
                                    it->second += delta;
                                    if (!it->second)
                                        all_deltas.erase(it);
                                }
                            }
                            for (const auto &[stake_ptr, delta]: pointer_deltas)
                                all_pointer_deltas[stake_ptr] += delta;
                        });
                    }
                }
            );
            for (const auto &[stake_id, delta]: all_deltas)
                update_stake(stake_id, delta);
            for (const auto &[stake_ptr, delta]: all_pointer_deltas)
                update_pointer(stake_ptr, delta);
        }

        void withdraw_reward(const uint64_t, const cardano::stake_ident &stake_id, const uint64_t amount)
        {
            auto &acc = _accounts.at(stake_id);
            if (acc.reward < amount)
                throw error("trying to withdraw from account {} more stake {} than it has: {}", stake_id, amount, acc.reward);
            acc.reward -= amount;
            if (acc.deleg)
                _active_pool_dist.sub(*acc.deleg, amount);
        }

        void register_stake(const uint64_t slot, const cardano::stake_ident &stake_id, size_t tx_idx=0, size_t cert_idx=0)
        {
            _tick(slot);
            auto [acc_it, acc_created] = _accounts.try_emplace(stake_id);
            if (acc_created || !acc_it->second.ptr) {
                _deposited += _params.key_deposit;
                acc_it->second.deposit += _params.key_deposit;
            }
            cardano::stake_pointer ptr { slot, tx_idx, cert_idx };
            _ptr_to_stake[ptr] = stake_id;
            acc_it->second.ptr = ptr;
        }

        void retire_stake(const uint64_t slot, const cardano::stake_ident &stake_id)
        {
            _tick(slot);
            auto &acc = _accounts.at(stake_id);
            if (acc.deleg) {
                const auto stake = acc.stake + acc.reward;
                //logger::trace("epoch: {} retirement of {} - removing {} from pool {}", _epoch, stake_id, cardano::amount { stake }, deleg_it->second);
                _active_pool_dist.sub(*acc.deleg, stake);
                _active_inv_delegs.at(*acc.deleg).erase(stake_id);
            }
            if (acc.ptr) {
                _ptr_to_stake.erase(*acc.ptr);
                acc.ptr.reset();
            } else {
                logger::trace("slot: {}/{} can't find the retiring stake's pointer");
            }
            if (_deposited < acc.deposit)
                throw error("trying to remove a deposit while having insufficient deposits");
            _deposited -= acc.deposit;
            _treasury += acc.reward;
            acc.reward = 0;
            acc.deposit = 0;
            acc.deleg.reset();
        }

        void delegate_stake(const cardano::stake_ident &stake_id, const cardano_hash_28 &pool_id)
        {
            if (!_active_pool_params.contains(pool_id))
                throw error("trying to delegate {} to an unknown pool: {}", stake_id, pool_id);
            auto &acc = _accounts.at(stake_id);
            const auto stake = acc.stake + acc.reward;
            const bool deleg_created = !acc.deleg;
            if (!acc.deleg)
                acc.deleg = pool_id;
            if (deleg_created || *acc.deleg != pool_id) {
                _active_inv_delegs[pool_id].emplace(stake_id);
                _active_pool_dist.add(pool_id, stake);
            }
            if (*acc.deleg != pool_id) {
                _active_inv_delegs[*acc.deleg].erase(stake_id);
                // ignore retired pools
                if (_active_pool_params.contains(*acc.deleg)) {
                    _active_pool_dist.sub(*acc.deleg, stake);
                }
                *acc.deleg = pool_id;
            }
        }

        void update_stake(const cardano::stake_ident &stake_id, const int64_t delta)
        {
            auto &acc = _accounts[stake_id];
            if (delta >= 0) {
                acc.stake += static_cast<uint64_t>(delta);
                if (acc.deleg && _active_pool_params.contains(*acc.deleg))
                    _active_pool_dist.add(*acc.deleg, static_cast<uint64_t>(delta));
            } else {
                const uint64_t dec = static_cast<uint64_t>(-delta);
                if (acc.stake < dec)
                    throw error("trying to remove from account {} more stake {} than it has: {}", stake_id, dec, acc.stake);
                acc.stake -= dec;
                if (acc.deleg && _active_pool_params.contains(*acc.deleg))
                    _active_pool_dist.sub(*acc.deleg, static_cast<uint64_t>(-delta));
            }
        }

        void update_pointer(const cardano::stake_pointer &ptr, const int64_t delta)
        {
            /*if (const auto ptr_it = _ptr_to_stake.find(ptr); ptr_it != _ptr_to_stake.end()) {
                logger::trace("epoch: {} stake update via pointer: {} {} delta: {}", _epoch, ptr, ptr_it->second, cardano::balance_change { delta });
                update_stake(ptr_it->second, delta);
            } else { */
            if (delta) {
                if (delta >= 0)
                    _stake_pointers.add(ptr, delta);
                else if (_stake_pointers.contains(ptr))
                    _stake_pointers.sub(ptr, static_cast<uint64_t>(-delta));
                else
                    logger::warn("epoch: {} skipping an unknown stake pointer: {} delta: {}", _epoch, ptr, cardano::balance_change { delta });
            }
        }

        void update_stake_id_hybrid(const cardano::stake_ident_hybrid &stake_id, const int64_t delta)
        {
            if (delta) {
                if (std::holds_alternative<cardano::stake_ident>(stake_id))
                    update_stake(std::get<cardano::stake_ident>(stake_id), delta);
                else if (std::holds_alternative<cardano::stake_pointer>(stake_id))
                    update_pointer(std::get<cardano::stake_pointer>(stake_id), delta);
                else
                    throw error("internal error: an unexpected value for a stake_indent!");
            }
        }

        void proposal_vote(const uint64_t slot, const cardano::param_update_vote &vote)
        {
            // needed only for Byron-era voting, and all updates are in the current epoch
            logger::debug("slot: {}: proposal_vote: {}", slot, vote);
            for (const auto &[pool_id, prop]: _ppups) {
                if (prop.hash == vote.proposal_id) {
                    _ppups[vote.pool_id] = prop;
                    break;
                }
            }
            logger::debug("ppups: {}", _ppups);
        }

        void propose_update(const uint64_t slot, const cardano::param_update_proposal &prop)
        {
            logger::debug("slot: {} proposal: {}", slot, prop);
            if (_params.protocol_ver.major >= 2) {
                if (!_cfg.shelley_delegates.contains(prop.pool_id))
                    throw error("protocol update proposal from a key not in the shelley genesis delegate list: {}!", prop.pool_id);
                if (!prop.epoch || *prop.epoch == _epoch) {
                    const auto too_late = cardano::slot::from_epoch(_epoch + 1, _cfg) - 2 * _cfg.shelley_stability_window;
                    if (slot < too_late) {
                        _ppups[prop.pool_id] = prop.update;
                    } else {
                        logger::warn("epoch: {} slot: {} ignoring an update proposal since its too late in the epoch", _epoch, slot);
                    }
                } else if (*prop.epoch == _epoch + 1) {
                    _ppups_future[prop.pool_id] = prop.update;
                } else {
                    logger::warn("epoch: {} slot: {} ignoring an update proposal for an unexpected epoch: {}", _epoch, slot, *prop.epoch);
                }
            } else {
                _ppups[prop.pool_id] = prop.update;
            }
            logger::debug("ppups: {}", _ppups);
        }

        const ptr_to_stake_map &pointers() const
        {
            return _ptr_to_stake;
        }

        cardano::amount unspent_reward(const cardano::stake_ident &id) const
        {
            const auto acc_it = _accounts.find(id);
            if (acc_it != _accounts.end() && acc_it->second.ptr)
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
            for (const auto &[stake_id, acc]: _accounts) {
                if (acc.ptr && acc.reward) {
                    rewards.create(stake_id);
                    rewards.add(stake_id, acc.reward);
                }
            }
            return rewards;
        }

        const stake_distribution &instant_rewards_reserves() const
        {
            return _instant_rewards_reserves;
        }

        const stake_distribution &instant_rewards_treasury() const
        {
            return _instant_rewards_treasury;
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
            return _pool_deposits;
        }

        const pool_stake_distribution &pool_dist_go() const
        {
            return _go.pool_dist;
        }

        const pool_stake_distribution &pool_dist_mark() const
        {
            return _mark.pool_dist;
        }

        const pool_stake_distribution &pool_dist_set() const
        {
            return _set.pool_dist;
        }

        const operating_pool_map &pool_stake_dist() const
        {
            return _operating_stake_dist;
        }

        const pool_info_map &pool_params_mark() const
        {
            return _mark.pool_params;
        }

        const pool_info_map &pool_params_set() const
        {
            return _set.pool_params;
        }

        const pool_info_map &pool_params_go() const
        {
            return _go.pool_params;
        }

        const pool_info_map &pool_params() const
        {
            return _active_pool_params;
        }

        const pool_info_map &pool_params_future() const
        {
            return _future_pool_params;
        }

        const pool_block_dist &blocks_before() const
        {
            return _blocks_before;
        }

        const pool_block_dist &blocks_current() const
        {
            return _blocks_current;
        }

        const pool_retiring_map &pools_retiring() const
        {
            return _pools_retiring;
        }

        uint64_t deposited() const
        {
            return _deposited;
        }

        void add_pool_blocks(const cardano::pool_hash &pool_id, uint64_t num_blocks)
        {
            if (!_pbft_pools.contains(pool_id)) {
                if (_operating_stake_dist.contains(pool_id)) {
                    _blocks_current.add(pool_id, num_blocks);
                } else {
                    logger::warn("trying to provide the number of generated blocks in epoch {} for an unknown pool {} num_blocks: {}!", _epoch, pool_id, num_blocks);
                }
            }
        }

        uint64_t fees_reward_snapshot() const
        {
            return _fees_next_reward;
        }

        void track_era(const uint64_t era, const uint64_t slot)
        {
            if (era > 0) {
                if (!_eras.empty() && slot < _eras.back())
                    throw error("era blocks have reported out of order slot {} came after {}", slot, _eras.back());
                if (era > _eras.size()) {
                    const auto era_start_slot = !_eras.empty() && era > 2 ? slot - (slot - _eras.back()) % _cfg.shelley_epoch_length : slot;
                    while (era > _eras.size()) {
                        _eras.emplace_back(era_start_slot);
                    }
                } else if (era < _eras.size()) {
                    throw error("a block of era {} came in era {}", era, _eras.size());
                }
            }
        }

        void sub_fees(const uint64_t refund)
        {
            if (_fees_next_reward >= refund) [[likely]]
                _fees_next_reward -= refund;
            else
                throw error("insufficient fees_next_reward: {} to refund {}", _fees_next_reward, refund);
            if (_fees_utxo >= refund) [[likely]]
                _fees_utxo -= refund;
            else
                throw error("insufficient fees_utxo: {} to refund {}", _fees_utxo, refund);
        }

        void add_fees(const uint64_t amount)
        {
            _fees_next_reward += amount;
            _fees_utxo += amount;
        }

        void process_block(const uint64_t end_offset, const uint64_t era, const uint64_t slot, const uint64_t fees)
        {
            track_era(era, slot);
            add_fees(fees);
            if (end_offset > _end_offset)
                _end_offset = end_offset;
            if (_params.protocol_ver.major >= 2) {
                const auto epoch_slot = cardano::slot { slot, _cfg }.epoch_slot();
                if (epoch_slot >= _cfg.shelley_voting_deadline)
                    ++_blocks_past_voting_deadline;
                if (epoch_slot > _epoch_slot)
                    _epoch_slot = epoch_slot;
            }
        }

        void reserves(const uint64_t r)
        {
            logger::trace("epoch: {} override reserves with {} while {} currently, diff: {}",
                _epoch, r, _reserves, static_cast<int64_t>(_reserves) - static_cast<int64_t>(r));
            _reserves = r;
        }

        uint64_t reserves() const
        {
            return _reserves;
        }

        void treasury(uint64_t t)
        {
            logger::trace("epoch: {} override treasury with {} while {} currently, diff: {}",
                _epoch, t, _treasury, static_cast<int64_t>(_treasury) - static_cast<int64_t>(t));
            _treasury = t;
        }

        uint64_t treasury() const
        {
            return _treasury;
        }

        const cardano::protocol_params &params() const
        {
            return _params;
        }

        const cardano::protocol_params &prev_params() const
        {
            return _params_prev;
        }

        const partitioned_reward_update_dist &potential_rewards() const
        {
            return _potential_rewards;
        }

        const nonmyopic_likelihood_map &nonmyopic() const
        {
            return _nonmyopic;
        }

        uint64_t nonmyopic_reward_pot() const
        {
            return _nonmyopic_reward_pot;
        }

        const nonmyopic_likelihood_map &potential_nonmyopic() const
        {
            return _nonmyopic_next;
        }

        /*void end_offset(uint64_t offset)
        {
        }*/

        cardano::slot last_slot() const
        {
            return cardano::slot::from_epoch(_epoch, _epoch_slot, _cfg);
        }

        uint64_t end_offset() const
        {
            return _end_offset;
        }

        uint64_t delta_reserves() const
        {
            return _delta_reserves;
        }

        uint64_t delta_treasury() const
        {
            return _delta_treasury;
        }

        uint64_t delta_fees() const
        {
            return _delta_fees;
        }

        uint64_t reward_pot() const
        {
            return _reward_pot;
        }

        void genesis_deleg_update(const cardano::key_hash &hash, const cardano::pool_hash &pool_id, const cardano::vrf_vkey &vrf_vkey)
        {
            if (auto it = _shelley_delegs.find(hash); it != _shelley_delegs.end()) [[likely]] {
                const auto [f_it, f_created] = _future_shelley_delegs.try_emplace(hash, pool_id, vrf_vkey);
                if (!f_created) {
                    f_it->second.delegate = pool_id;
                    f_it->second.vrf = vrf_vkey;
                }
            } else {
                throw error("atterm to redelegate an unknown shelley genesis delegate {}", hash);
            }
        }

        const cardano::shelley_delegate_map &future_shelley_delegates() const
        {
            return _future_shelley_delegs;
        }

        const cardano::shelley_delegate_map &shelley_delegates() const
        {
            return _shelley_delegs;
        }

        const std::set<cardano::pool_hash> &pbft_pools() const
        {
            return _pbft_pools;
        }

        void rotate_snapshots()
        {
            timer t { fmt::format("validator::state epoch: {} rotate_snapshots", _epoch), logger::level::trace };
            {
                timer ts { fmt::format("validator::state epoch: {} move set snapshot to go", _epoch), logger::level::trace };
                _go = std::move(_set);
            }
            {
                timer ts { fmt::format("validator::state epoch: {} move mark snapshot to set", _epoch), logger::level::trace };
                _set = std::move(_mark);
            }
            timer ts { fmt::format("validator::state epoch: {} copy active snapshot to mark", _epoch), logger::level::trace };
            const std::string task_group = fmt::format("ledger-state:rotate-snapshots:epoch-{}", _epoch);
            _sched.wait_all_done(task_group, 3 + _accounts.num_parts, [&] {
                _sched.submit_void(task_group, 1000, [this] {
                    timer tsi { fmt::format("validator::state epoch: {} copy pool_dist to mark", _epoch), logger::level::trace };
                    _mark.pool_dist = _active_pool_dist;
                });
                _sched.submit_void(task_group, 1000, [this] {
                    timer tsi { fmt::format("validator::state epoch: {} copy pool_params to mark", _epoch), logger::level::trace };
                    _mark.pool_params = _active_pool_params;
                });
                _sched.submit_void(task_group, 1000, [this] {
                    timer tsi { fmt::format("validator::state epoch: {} copy inv_delegs to mark", _epoch), logger::level::trace };
                    _mark.inv_delegs = _active_inv_delegs;
                });
                for (size_t pi = 0; pi < _accounts.num_parts; ++pi) {
                    _sched.submit_void(task_group, 1000, [this, pi] {
                        auto &part = _accounts.partition(pi);
                        set<cardano::stake_ident> retired {};
                        for (auto &[stake_id, acc]: part) {
                            if (acc.ptr || acc.stake || acc.go_deleg || acc.set_deleg || acc.mark_deleg || acc.deleg) {
                                acc.go_deleg = acc.set_deleg;
                                acc.go_stake = acc.set_stake;
                                acc.set_deleg = acc.mark_deleg;
                                acc.set_stake = acc.mark_stake;
                                acc.mark_deleg = acc.deleg;
                                acc.mark_stake = acc.stake + acc.reward;
                            } else {
                                retired.emplace(stake_id);
                            }
                        }
                        for (const auto &stake_id: retired)
                            part.erase(stake_id);
                    });
                }
            });
            for (const auto &[stake_ptr, coin]: _stake_pointers) {
                if (const auto ptr_it = _ptr_to_stake.find(stake_ptr); ptr_it != _ptr_to_stake.end()) {
                    auto &acc = _accounts.at(ptr_it->second);
                    acc.mark_stake += coin;
                    if (acc.mark_deleg)
                        _mark.pool_dist.add(*acc.mark_deleg, coin);
                }
            }
        }

        void start_epoch(std::optional<uint64_t> new_epoch={}) {
            if (!new_epoch) {
                // increment the epoch only if seen some data
                if (_end_offset)
                    new_epoch = _epoch + 1;
                else
                    new_epoch = 0;
            }
            if (*new_epoch < _epoch || *new_epoch > _epoch + 1)
                throw error("unexpected new epoch value: {} the current epoch: {}", *new_epoch, _epoch);;
            _epoch = *new_epoch;
            _epoch_slot = 0;
            const auto prev_params = _apply_param_updates();
            if (_params.protocol_ver.major >= 2) {
                {
                    const auto delta_ireserves = _transfer_instant_rewards(_instant_rewards_reserves);
                    _reserves -= delta_ireserves;
                    const auto delta_itreasury = _transfer_instant_rewards(_instant_rewards_treasury);
                    _treasury -= delta_itreasury;
                    logger::debug("delta_ireserves: {} delta_itreasury: {}", delta_ireserves, delta_itreasury);
                }
                _transfer_potential_rewards(prev_params);
                rotate_snapshots();
                _prep_op_stake_dist();
                _apply_future_pool_params();
                {
                    for (auto &[id, info]: _future_shelley_delegs)
                        _shelley_delegs.at(id) = info;
                    _future_shelley_delegs.clear();
                }
                if (!_vrf_state.kes_counters().empty())
                    _vrf_state.finish_epoch(_params.extra_entropy);
                _nonmyopic = std::move(_nonmyopic_next);
                _nonmyopic_reward_pot = _reward_pot;
                _reserves -= _delta_reserves;
                _delta_reserves = 0;
                _treasury += _delta_treasury;
                _delta_treasury = 0;
                _reward_pot = 0;
                _rewards_ready = false;
                _blocks_past_voting_deadline = 0;
                _clean_old_epoch_data();
                _fees_utxo -= _delta_fees;
                _delta_fees = _fees_next_reward;
                _fees_next_reward = 0;
                _reward_pulsing_snapshot_slot = cardano::slot::from_epoch(_epoch, _cfg) + _cfg.shelley_randomness_stabilization_window;

                const auto [ refunds_user, refunds_treasury ] = _retire_pools();

                logger::debug("epoch {} start: treasury: {} reserves: {} user refunds: {} treasury refunds: {}",
                    _epoch, cardano::amount { _treasury }, cardano::amount { _reserves },
                    cardano::amount { refunds_user }, cardano::amount { refunds_treasury });
            }
        }

        uint64_t utxo_balance() const
        {
            std::atomic_uint64_t total_balance = 0;
            static const std::string task_group { "validator::state::utxo_balance" };
            _sched.wait_all_done(task_group, _utxo.num_parts, [&] {
                for (size_t pi = 0; pi < _utxo.num_parts; ++pi) {
                    _sched.submit_void(task_group, 1000, [&, pi] {
                        uint64_t part_balance = 0;
                        const auto &part = _utxo.partition(pi);
                        for (const auto &[txo_id, txo_data]: part) {
                            part_balance += txo_data.coin;
                        }
                        atomic_add(total_balance, part_balance);
                    });
                }
            });
            return total_balance.load();
        }

        void compute_rewards_if_ready()
        {
            if (_params.protocol_ver.major >= 2 && _epoch_slot >= _cfg.shelley_rewards_ready_slot && !_rewards_ready)
                _compute_rewards();
        }

        bool exportable() const
        {
            if (_params.protocol_ver.major >= 3 && (_rewards_ready || _epoch_slot < _cfg.shelley_randomness_stabilization_window))
                return true;
            return false;
        }

        uint64_t epoch() const
        {
            return _epoch;
        }
    private:
        struct account_info {
            uint64_t stake = 0;
            uint64_t reward = 0;
            uint64_t deposit = 0;
            uint64_t mark_stake = 0;
            uint64_t set_stake = 0;
            uint64_t go_stake = 0;
            // the presence of a stake pointer means that the account's stake address is registered currently
            std::optional<cardano::stake_pointer> ptr {};
            std::optional<cardano::pool_hash> deleg {};
            std::optional<cardano::pool_hash> mark_deleg {};
            std::optional<cardano::pool_hash> set_deleg {};
            std::optional<cardano::pool_hash> go_deleg {};

            constexpr static auto serialize(auto &archive, auto &self)
            {
                return archive(self.stake, self.reward, self.deposit, self.mark_stake, self.set_stake, self.go_stake,
                    self.ptr, self.deleg, self.mark_deleg, self.set_deleg, self.go_deleg);
            }

            bool operator==(const account_info &o) const
            {
                return stake == o.stake && reward == o.reward && deposit == o.deposit
                    && mark_stake == o.mark_stake && set_stake == o.set_stake && go_stake == o.go_stake
                    && deleg == o.deleg && mark_deleg == o.mark_deleg && set_deleg == o.set_deleg && go_deleg == o.go_deleg
                    && ptr == o.ptr;
            }

            const std::optional<cardano::pool_hash> &deleg_copy(const size_t idx) const
            {
                switch (idx) {
                    case 0: return mark_deleg;
                    case 1: return set_deleg;
                    case 2: return go_deleg;
                    default: throw error("unsupported deleg_copy index: {}", idx);
                }
            }

            std::optional<cardano::pool_hash> &deleg_copy(const size_t idx)
            {
                return const_cast<std::optional<cardano::pool_hash> &>(const_cast<const account_info &>(*this).deleg_copy(idx));
            }

            const uint64_t &stake_copy(const size_t idx) const
            {
                switch (idx) {
                    case 0: return mark_stake;
                    case 1: return set_stake;
                    case 2: return go_stake;
                    default: throw error("unsupported stake_copy index: {}", idx);
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

        // non-serializable members:
        const cardano::config &_cfg;
        scheduler &_sched;

        // serializable members
        // tracks parallel leader-eligibility verification and thus needs a mutex to protect its access
        subchain_list _subchains{};
        /// implementation-specific fields
        uint64_t _end_offset = 0;
        uint64_t _epoch_slot = 0;
        era_list _eras {};
        cardano::state::vrf _vrf_state {};
        uint64_t _reward_pulsing_snapshot_slot = 0;
        reward_distribution_copy _reward_pulsing_snapshot {};
        pool_stake_distribution _active_pool_dist {};
        inv_delegation_map _active_inv_delegs {};

        /// fields that correspond to Cardano Node's binary state
        partitioned_map<cardano::stake_ident, account_info> _accounts {};

        uint64_t _epoch = 0;
        pool_block_dist _blocks_current {};
        pool_block_dist _blocks_before {};

        //// stateBefore.esAccountState
        uint64_t _reserves = 0;
        uint64_t _treasury = 0;

        //// stateBefore.esSnapshots
        ledger_copy _mark {}, _set {}, _go {};
        uint64_t _fees_next_reward = 0;

        //// stateBefore.utxoState
        utxo_map _utxo {};
        uint64_t _deposited = 0;
        uint64_t _delta_fees = 0;
        uint64_t _fees_utxo = 0;
        map<cardano::pool_hash, cardano::param_update> _ppups {};
        map<cardano::pool_hash, cardano::param_update> _ppups_future {};

        // stateBefore.esLState.delegationState
        ptr_to_stake_map _ptr_to_stake {};
        cardano::shelley_delegate_map _future_shelley_delegs {};
        cardano::shelley_delegate_map _shelley_delegs { _cfg.shelley_delegates };
        stake_pointer_distribution _stake_pointers {};

        // stateBefore.esLState.delegationState.irwd
        stake_distribution _instant_rewards_reserves {};
        stake_distribution _instant_rewards_treasury {};

        // stateBefore.esLState.pstate
        pool_info_map _active_pool_params {};
        pool_info_map _future_pool_params {};
        pool_retiring_map _pools_retiring {};
        pool_deposit_map _pool_deposits {};

        // protocol params
        cardano::protocol_params _params = _default_params(_cfg);
        cardano::protocol_params _params_prev = _default_params(_cfg);
        nonmyopic_likelihood_map _nonmyopic {};
        uint64_t _nonmyopic_reward_pot = 0;

        // possibleRewardUpdate.rs
        uint64_t _delta_treasury = 0;
        uint64_t _delta_reserves = 0;
        uint64_t _reward_pot = 0;
        partitioned_reward_update_dist _potential_rewards {};
        bool _rewards_ready = false;
        nonmyopic_likelihood_map _nonmyopic_next {};

        // stakeDistrib
        operating_pool_map _operating_stake_dist {};
        uint64_t _blocks_past_voting_deadline = 0;

        // non-serializable cache entries
        mutable std::set<cardano::pool_hash> _pbft_pools = _make_pbft_pools(_shelley_delegs);

        void _parse_protocol_params(cardano::protocol_params &params, uint64_t era, const cbor_value &values);

        // needed to keep the mutex out of the normal state and make the state object copy-constructible
        static mutex::unique_lock::mutex_type &_subchains_mutex()
        {
            alignas(mutex::padding) static mutex::unique_lock::mutex_type m {};
            return m;
        }

        static std::set<cardano::pool_hash> _make_pbft_pools(const cardano::shelley_delegate_map &delegs)
        {
            std::set<cardano::pool_hash> pools {};
            for (const auto &[id, meta]: delegs)
                pools.emplace(meta.delegate);
            return pools;
        }

        static void _apply_byron_params(cardano::protocol_params &p, const cardano::config &)
        {
            p.protocol_ver = { 0, 0 };
        }

        static void _apply_shelley_params(cardano::protocol_params &p, const cardano::config &cfg)
        {
            const auto &shelley_params = cfg.shelley_genesis.at("protocolParams").as_object();
            p.min_fee_a = json::value_to<uint64_t>(shelley_params.at("minFeeA"));
            p.min_fee_b = json::value_to<uint64_t>(shelley_params.at("minFeeB"));
            p.max_block_body_size = json::value_to<uint64_t>(shelley_params.at("maxBlockBodySize"));
            p.max_transaction_size = json::value_to<uint64_t>(shelley_params.at("maxTxSize"));
            p.max_block_header_size = json::value_to<uint64_t>(shelley_params.at("maxBlockHeaderSize"));
            p.key_deposit = json::value_to<uint64_t>(shelley_params.at("keyDeposit"));
            p.pool_deposit = json::value_to<uint64_t>(shelley_params.at("poolDeposit"));
            p.e_max = json::value_to<uint64_t>(shelley_params.at("eMax"));
            p.n_opt = json::value_to<uint64_t>(shelley_params.at("nOpt"));
            p.expansion_rate = rational_u64::from_double(json::value_to<double>(shelley_params.at("rho")));
            p.treasury_growth_rate = rational_u64::from_double(json::value_to<double>(shelley_params.at("tau")));
            p.pool_pledge_influence = rational_u64::from_double(json::value_to<double>(shelley_params.at("a0")));
            p.decentralization = rational_u64::from_double(json::value_to<double>(shelley_params.at("decentralisationParam")));
            p.min_utxo_value = json::value_to<uint64_t>(shelley_params.at("minUTxOValue"));
            p.min_pool_cost = json::value_to<uint64_t>(shelley_params.at("minPoolCost"));
        }

        static rational_u64 _decode_rational(const json::value &v)
        {
            if (v.is_object())
                return rational_u64 { json::value_to<uint64_t>(v.at("numerator")), json::value_to<uint64_t>(v.at("denominator")) };
            return rational_u64::from_double(json::value_to<double>(v));
        }

        static void _apply_alonzo_params(cardano::protocol_params &p, const cardano::config &cfg)
        {
            const auto &al_cfg = cfg.alonzo_genesis;
            p.lovelace_per_utxo_byte = json::value_to<uint64_t>(al_cfg.at("lovelacePerUTxOWord"));
            p.ex_unit_prices = {
                _decode_rational(al_cfg.at("executionPrices").at("prMem")),
                _decode_rational(al_cfg.at("executionPrices").at("prSteps"))
            };
            p.max_tx_ex_units = {
                json::value_to<uint64_t>(al_cfg.at("maxTxExUnits").at("exUnitsMem")),
                json::value_to<uint64_t>(al_cfg.at("maxTxExUnits").at("exUnitsSteps"))
            };
            p.max_block_ex_units = {
                json::value_to<uint64_t>(al_cfg.at("maxBlockExUnits").at("exUnitsMem")),
                json::value_to<uint64_t>(al_cfg.at("maxBlockExUnits").at("exUnitsSteps"))
            };
            p.max_value_size = json::value_to<uint64_t>(al_cfg.at("maxValueSize"));
            p.max_collateral_pct = json::value_to<uint64_t>(al_cfg.at("collateralPercentage"));
            p.max_collateral_inputs = json::value_to<uint64_t>(al_cfg.at("maxCollateralInputs"));
            p.plutus_cost_models.v1.emplace(cardano::plutus_cost_model::from_json(cfg.plutus_v1_cost_model, al_cfg.at("costModels").at("PlutusV1")));
        }

        static void _apply_babbage_params(cardano::protocol_params &p, const cardano::config &/*cfg*/)
        {
            p.decentralization = rational_u64 { 0, 1 };
            p.lovelace_per_utxo_byte = 4310;
        }

        static cardano::protocol_params _default_params(const cardano::config &cfg)
        {
            cardano::protocol_params p {};
            _apply_byron_params(p, cfg);
            return p;
        }

        template<typename VISITOR>
        void _visit(const VISITOR &v);

        void _node_load_delegation_state(const cbor::value &);
        void _node_load_utxo_state(const cbor::value &);
        void _node_load_vrf_state_shelley(const cbor::value &);
        void _node_load_vrf_state_babbage(const cbor::value &);
        void _node_load_vrf_state(const cbor::value &);

        void _node_save_params(state_encoder &enc, const cardano::protocol_params &params) const;
        void _node_save_params_shelley(state_encoder &enc, const cardano::protocol_params &params) const;
        void _node_save_params_alonzo(state_encoder &enc, const cardano::protocol_params &params) const;
        void _node_save_params_babbage(state_encoder &enc, const cardano::protocol_params &params) const;
        void _node_save_eras(parallel_serializer &ser, const cardano::point &tip) const;
        void _node_save_ledger(parallel_serializer &ser) const;
        void _node_save_ledger_delegation(parallel_serializer &ser) const;
        void _node_save_ledger_utxo(parallel_serializer &ser) const;
        void _node_save_state(parallel_serializer &ser) const;
        void _node_save_snapshots(parallel_serializer &ser) const;
        void _node_save_state_before(parallel_serializer &ser) const;
        void _node_save_vrf_state_shelley(state_encoder &, const cardano::point &) const;
        void _node_save_vrf_state_babbage(state_encoder &, const cardano::point &) const;
        void _node_save_vrf_state(parallel_serializer &ser, const cardano::point &) const;

        uint64_t _retire_avvm_balance()
        {
            std::atomic_uint64_t total_balance = 0;
            static const std::string task_group { "validator::state::retire_avvm_balance" };
            _sched.wait_all_done(task_group, _utxo.num_parts, [&] {
                for (size_t pi = 0; pi < _utxo.num_parts; ++pi) {
                    _sched.submit_void(task_group, 1000, [&, pi] {
                        uint64_t part_balance = 0;
                        auto &part = _utxo.partition(pi);
                        for (auto it = part.begin(), end = part.end(); it != end; ) {
                            const auto &txo_data = it->second;
                            if (txo_data.address.at(0) == 0x82) {
                                const auto crc_v = cbor::zero::parse(txo_data.address);
                                const auto addr_v = cbor::zero::parse(crc_v.at(0).tag().second.bytes());
                                if (addr_v.at(2).uint() == 2) {
                                    part_balance += txo_data.coin;
                                    it = part.erase(it);
                                    continue;
                                }
                            }
                            ++it;
                        }
                        atomic_add(total_balance, part_balance);
                    });
                }
            });
            return total_balance.load();
        }

        std::optional<cardano::stake_ident> _extract_stake_id(const cardano::address &addr) const
        {
            if (addr.has_stake_id()) [[likely]]
                return addr.stake_id();
            if (addr.has_pointer()) [[unlikely]] {
                const auto stake_ptr = addr.pointer();
                if (const auto ptr_it = _ptr_to_stake.find(stake_ptr); ptr_it != _ptr_to_stake.end())
                    return ptr_it->second;
                logger::warn("epoch: {} an unrecognized stake pointer has been referenced {} - ignoring it", _epoch, stake_ptr);
            }
            return {};
        }

        void _prep_op_stake_dist()
        {
            _operating_stake_dist.clear();
            for (const auto &[pool_id, coin]: _set.pool_dist) {
                if (!_set.inv_delegs.at(pool_id).empty()) {
                    const auto &params = _set.pool_params.at(pool_id);
                    rational_u64 rel_stake { coin, _set.pool_dist.total_stake() };
                    rel_stake.normalize();
                    _operating_stake_dist.try_emplace(pool_id, std::move(rel_stake), params.vrf_vkey);
                }
            }
        }

        void _apply_future_pool_params()
        {
            for (auto &&[pool_id, params]: _future_pool_params) {
                _active_pool_params.at(pool_id) = std::move(params);
            }
            _future_pool_params.clear();
        }

        void _recompute_caches() const
        {
            _pbft_pools = _make_pbft_pools(_shelley_delegs);
        }

        uint64_t _total_stake(uint64_t reserves) const
        {
            return _cfg.shelley_max_lovelace_supply - reserves;
        }

        void _compute_rewards()
        {
            timer t { fmt::format("compute rewards for epoch {}", _epoch), logger::level::debug };
            _rewards_ready = true;
            uint64_t expansion = 0;
            if (_params_prev.decentralization.as_r() < _params_prev.decentralizationThreshold.as_r() && _epoch > 0) {
                rational perf = std::min(rational { 1 }, rational { _blocks_before.total_stake() } / ((1 - _params_prev.decentralization.as_r()) * _cfg.shelley_epoch_blocks));
                expansion = static_cast<uint64_t>(_params_prev.expansion_rate.as_r() * _reserves * perf);
                logger::trace("epoch: {} performance-adjusted expansion: {} perf: {} d: {} blocks: {}",
                    _epoch, expansion, perf, _params_prev.decentralization, _blocks_before.total_stake());
            } else {
                expansion = static_cast<uint64_t>(_params_prev.expansion_rate.as_r() * _reserves);
                logger::trace("epoch: {} simple expansion: {}", _epoch, expansion);
            }
            const uint64_t total_reward_pool = expansion + _delta_fees;
            const uint64_t treasury_rewards = static_cast<uint64_t>(_params_prev.treasury_growth_rate.as_r() * total_reward_pool);
            _reward_pot = total_reward_pool - treasury_rewards;
            uint64_t pool_rewards_filtered = 0;
            const uint64_t total_stake = _total_stake(_reserves);
            if (!_blocks_before.empty()) {
                const auto &pools_active = _blocks_before;
                {
                    timer t2 { fmt::format("compute per-pool rewards for epoch {}", _epoch), logger::level::trace };
                    pool_rewards_filtered = _compute_pool_rewards_parallel(pools_active, _reward_pot, total_stake);
                }
                logger::trace("epoch {} total stake {} treasury: {} reserves: {} rewards pot: {} block-producing pools: {} reward pools: {} rewards attributed: {}",
                    _epoch, total_stake, _treasury, _reserves, _reward_pot, pools_active.size(), _go.pool_params.size(), pool_rewards_filtered);
            }
            _delta_treasury = treasury_rewards;
            _delta_reserves = treasury_rewards + pool_rewards_filtered - _delta_fees;
            logger::debug("epoch {} deltaR ({}) = deltaT ({}) + poolRewards ({}) - deltaF {}",
                _epoch, cardano::amount { _delta_reserves }, cardano::amount { _delta_treasury },
                cardano::amount { pool_rewards_filtered }, cardano::amount { _delta_fees });
        }

        void _rewards_prepare_pool_params(uint64_t &total, uint64_t &filtered, const double z0,
            uint64_t staking_reward_pot, uint64_t total_stake, const cardano::pool_hash &pool_id, pool_info &info, uint64_t pool_blocks)
        {
            const uint64_t pool_stake = _go.pool_dist.get(pool_id);
            uint64_t pool_reward_pot = 0;
            if (pool_stake > 0) {
                uint64_t leader_reward = 0;
                uint64_t owner_stake = 0;
                for (const auto &stake_id: info.owners) {
                    if (const auto acc_it = _accounts.find(stake_id); acc_it != _accounts.end() && acc_it->second.go_deleg && *acc_it->second.go_deleg == pool_id)
                        owner_stake += acc_it->second.go_stake;
                }
                if (owner_stake >= info.pledge) {
                    double pool_rel_total_stake = static_cast<double>(pool_stake) / std::max(static_cast<uint64_t>(1), total_stake);
                    double sigma_mark = std::min(pool_rel_total_stake, z0);
                    double pool_rel_active_stake = static_cast<double>(pool_stake) / std::max(static_cast<uint64_t>(1), _go.pool_dist.total_stake());
                    double pledge_rel_total_stake = static_cast<double>(info.pledge) / std::max(static_cast<uint64_t>(1), total_stake);
                    if (pool_rel_total_stake < pledge_rel_total_stake)
                        throw error("internal error: pledged stake: {} of pool {} is larger than the pool's total stake: {}", info.pledge, pool_id, pool_stake);
                    double s_mark = std::min(pledge_rel_total_stake, z0);
                    uint64_t optimal_reward = static_cast<uint64_t>(staking_reward_pot / (1 + _params_prev.pool_pledge_influence.as_r()) *
                        (sigma_mark + s_mark * _params_prev.pool_pledge_influence.as_r() * (sigma_mark - s_mark * (z0 - sigma_mark) / (z0)) / z0));
                    pool_reward_pot = optimal_reward;
                    double beta = static_cast<double>(pool_blocks) / std::max(static_cast<uint64_t>(1), _blocks_before.total_stake());
                    double pool_performance = pool_rel_active_stake != 0 ? beta / pool_rel_active_stake : 0;
                    if (_params_prev.decentralization.as_r() < _params_prev.decentralizationThreshold.as_r())
                        pool_reward_pot = optimal_reward * pool_performance;
                    if (pool_reward_pot > info.cost && owner_stake < pool_stake) {
                        auto pool_margin = info.margin.as_r();
                        info.member_reward_base = (pool_reward_pot - info.cost) * (1 - pool_margin) / pool_stake;
                        leader_reward = static_cast<uint64_t>(info.cost + (pool_reward_pot - info.cost) * (pool_margin + (1 - pool_margin) * owner_stake / pool_stake));
                    } else {
                        leader_reward = pool_reward_pot;
                    }
                }
                const bool leader_active = _params_prev.protocol_ver.forgo_reward_prefilter() || _reward_pulsing_snapshot.contains(info.reward_id);
                if (leader_active) {
                    auto &reward_list = _potential_rewards[info.reward_id];
                    total += leader_reward;
                    if (!reward_list.empty())
                        filtered -= reward_list.begin()->amount;
                    if (const auto acc_it = _accounts.find(info.reward_id); acc_it != _accounts.end() && acc_it->second.deleg)
                        reward_list.emplace(reward_type::leader, pool_id, leader_reward, *acc_it->second.deleg);
                    else
                        reward_list.emplace(reward_type::leader, pool_id, leader_reward);
                    filtered += reward_list.begin()->amount;
                }
            }
        }

        std::pair<uint64_t, uint64_t> _rewards_prepare_pools(const pool_block_dist &pools_active, const uint64_t staking_reward_pot, const uint64_t total_stake)
        {
            uint64_t total = 0;
            uint64_t filtered = 0;
            const rational z0 { 1, _params_prev.n_opt };
            const auto z0_d = static_cast<double>(z0);
            _nonmyopic_next.clear();
            for (auto &[pool_id, pool_info]: _go.pool_params) {
                if (!_pbft_pools.contains(pool_id)) {
                    const uint64_t pool_blocks = pools_active.get(pool_id);
                    if (pool_blocks > 0)
                        _rewards_prepare_pool_params(total, filtered, z0_d, staking_reward_pot, total_stake, pool_id, pool_info, pool_blocks);
                    const rational rel_stake { _go.pool_dist.get(pool_id), total_stake };
                    const auto rel_stake_bounded = std::min(z0, rel_stake);
                    //logger::debug("estimating hit-rate likelihood epoch: {} pool: {} blocks: {} d: {} rel_stake: {} rel_stake_bounded: {}", _epoch, pool_id, pool_blocks, _params_prev.decentralization, rel_stake, rel_stake_bounded);
                    pool_rank::likelihood_prior prior {};
                    if (const auto prior_it = _nonmyopic.find(pool_id); prior_it != _nonmyopic.end())
                        prior.emplace(prior_it->second);
                    _nonmyopic_next.try_emplace(pool_id, pool_rank::likelihoods(pool_blocks, _cfg.shelley_epoch_length,
                        static_cast<double>(rel_stake), _cfg.shelley_active_slots, _params_prev.decentralization, prior));
                }
            }
            return std::make_pair(total, filtered);
        }

        std::pair<uint64_t, uint64_t> _rewards_compute_part(const size_t part_idx)
        {
            uint64_t total = 0;
            uint64_t filtered = 0;
            auto &part = _potential_rewards.partition(part_idx);
            const auto &acc_part = _accounts.partition(part_idx);
            for (const auto &[stake_id, acc]: acc_part) {
                if (acc.go_deleg) {
                    const auto &pool_info = _go.pool_params.at(*acc.go_deleg);
                    if (std::find(pool_info.owners.begin(), pool_info.owners.end(), stake_id) == pool_info.owners.end()) {
                        const uint64_t deleg_stake = acc.go_stake;
                        const uint64_t member_reward = static_cast<uint64_t>(pool_info.member_reward_base * deleg_stake);
                        if (member_reward > 0) {
                            const bool active = _params_prev.protocol_ver.forgo_reward_prefilter() || _reward_pulsing_snapshot.contains(stake_id);
                            if (active) {
                                auto &reward_list = part[stake_id];
                                total += member_reward;
                                if (!reward_list.empty())
                                    filtered -= reward_list.begin()->amount;
                                if (acc.deleg)
                                    reward_list.emplace(reward_type::member, *acc.go_deleg, member_reward, *acc.deleg);
                                else
                                    reward_list.emplace(reward_type::member, *acc.go_deleg, member_reward);
                                filtered += reward_list.begin()->amount;
                            }
                        }
                    }
                }
            }
            return std::make_pair(total, filtered);
        }

        uint64_t _compute_pool_rewards_parallel(const pool_block_dist &pools_active, const uint64_t staking_reward_pot, const uint64_t total_stake)
        {
            const std::string task_group = fmt::format("ledger-state:compute-rewards:epoch-{}", _epoch);
            const auto [init_total, init_filtered] = _rewards_prepare_pools(pools_active, staking_reward_pot, total_stake);
            std::atomic_uint64_t total = init_total;
            std::atomic_uint64_t filtered = init_filtered;
            _sched.wait_all_done(task_group, _potential_rewards.num_parts,
                [&] {
                    for (size_t part_idx = 0; part_idx < _potential_rewards.num_parts; ++part_idx) {
                        _sched.submit(task_group, 1000, [this, part_idx] {
                            return _rewards_compute_part(part_idx);
                        });
                    }
                },
                [&](auto &&res, auto, auto) {
                    const auto [part_total, part_filtered] = std::any_cast<std::pair<uint64_t, uint64_t>>(std::move(res));
                    atomic_add(total, part_total);
                    atomic_add(filtered, part_filtered);
                }
            );
            logger::trace("epoch: {} staking_rewards total: {} filtered: {} diff: {}",
                _epoch, cardano::amount { total.load() }, cardano::amount { filtered.load() },
                cardano::balance_change { static_cast<int64_t>(filtered) - static_cast<int64_t>(total) });
            if (_params_prev.protocol_ver.aggregated_rewards())
                return total;
            return filtered;
        }

        void _clean_old_epoch_data()
        {
            timer t { fmt::format("validator::state epoch: {} clean_old_epoch_data", _epoch), logger::level::trace };
            _blocks_before = std::move(_blocks_current);
            _blocks_current.clear();
            _reward_pulsing_snapshot.clear();
            const std::string task_group = fmt::format("ledger-state:clean-potential-rewards:epoch-{}", _epoch);
            _sched.wait_all_done(task_group, _potential_rewards.num_parts,
                [&] {
                    for (size_t part_idx = 0; part_idx < _potential_rewards.num_parts; ++part_idx) {
                        _sched.submit_void(task_group, 1000, [this, part_idx] () {
                            _potential_rewards.partition(part_idx).clear();
                        });
                    }
                }
            );
        }

        template<typename T>
        void _apply_one_param_update(T &tgt, std::string &desc, const std::optional<T> &upd, const std::string_view name)
        {
            if (upd) {
                tgt = *upd;
                desc += fmt::format("{}: {} ", name, tgt);
            }
        }

        cardano::protocol_params _apply_param_updates()
        {
            auto orig_params_prev = std::move(_params_prev);
            _params_prev = _params;
            std::optional<cardano::param_update> update {};
            {
                std::unordered_map<cardano::param_update, size_t> votes {};
                for (const auto &[pool_id, proposal]: _ppups) {
                    ++votes[proposal];
                }
                for (const auto &[prop, num_votes]: votes) {
                    if (num_votes >= _cfg.shelley_update_quorum) {
                        if (update)
                            throw error("more than one protocol parameter update has a quorum!");
                        update.emplace(prop);
                    } else {
                        logger::warn("update proposal with insufficient votes: {}: {}", num_votes, prop);
                    }
                }
            }
            if (update) {
                std::string update_desc {};
                if (update->protocol_ver) {
                    if (update->protocol_ver->major >= 2 && _params.protocol_ver.major < 2) {
                        {
                            const auto utxo_bal = utxo_balance();
                            if (utxo_bal > _cfg.shelley_max_lovelace_supply)
                                throw error("utxo balance: {} is larger than the total ADA supply: {}",
                                    cardano::amount { utxo_bal }, cardano::amount { _cfg.shelley_max_lovelace_supply });
                            _reserves = _cfg.shelley_max_lovelace_supply - utxo_bal;
                        }
                        _apply_shelley_params(_params, _cfg);
                        _apply_shelley_params(_params_prev, _cfg);
                        // protocol_ver immediately propagates to _params_prev
                        _params_prev.protocol_ver = *update->protocol_ver;
                    }
                    if (update->protocol_ver->major >= 3 &&  _params.protocol_ver.major < 3) {
                        const auto unspent_avvm = _retire_avvm_balance();
                        _reserves += unspent_avvm;
                        logger::info("retired {} in unclaimed AVVM vouchers", cardano::amount { unspent_avvm });
                    }
                    if (update->protocol_ver->major >= 5 &&  _params.protocol_ver.major < 5) {
                        _apply_alonzo_params(_params, _cfg);
                        _apply_alonzo_params(_params_prev, _cfg);
                    }
                    if (update->protocol_ver->major >= 7 &&  _params.protocol_ver.major < 7) {
                        _apply_babbage_params(_params, _cfg);
                        _apply_babbage_params(_params_prev, _cfg);
                    }
                }
                _apply_one_param_update(_params.protocol_ver, update_desc, update->protocol_ver, "protocol_ver");
                _apply_one_param_update(_params.min_fee_a, update_desc, update->min_fee_a, "min_fee_a");
                _apply_one_param_update(_params.min_fee_b, update_desc, update->min_fee_b, "min_fee_b");
                _apply_one_param_update(_params.max_block_body_size, update_desc, update->max_block_body_size, "max_block_body_size");
                _apply_one_param_update(_params.max_transaction_size, update_desc, update->max_transaction_size, "max_transaction_size");
                _apply_one_param_update(_params.max_block_header_size, update_desc, update->max_block_header_size, "max_block_header_size");
                _apply_one_param_update(_params.key_deposit, update_desc, update->key_deposit, "key_deposit");
                _apply_one_param_update(_params.pool_deposit, update_desc, update->pool_deposit, "pool_deposit");
                _apply_one_param_update(_params.e_max, update_desc, update->e_max, "e_max");
                _apply_one_param_update(_params.n_opt, update_desc, update->n_opt, "n_opt");
                _apply_one_param_update(_params.pool_pledge_influence, update_desc, update->pool_pledge_influence, "pool_pledge_influence");
                _apply_one_param_update(_params.expansion_rate, update_desc, update->expansion_rate, "expansion_rate");
                _apply_one_param_update(_params.treasury_growth_rate, update_desc, update->treasury_growth_rate, "treasury_growth_rate");
                _apply_one_param_update(_params.decentralization, update_desc, update->decentralization, "decentralization");
                _apply_one_param_update(_params.extra_entropy, update_desc, update->extra_entropy, "extra_entropy");
                _apply_one_param_update(_params.min_utxo_value, update_desc, update->min_utxo_value, "min_utxo_value");
                _apply_one_param_update(_params.min_pool_cost, update_desc, update->min_pool_cost, "min_pool_cost");
                _apply_one_param_update(_params.lovelace_per_utxo_byte, update_desc, update->lovelace_per_utxo_byte, "lovelace_per_utxo_byte");
                _apply_one_param_update(_params.ex_unit_prices, update_desc, update->ex_unit_prices, "ex_unit_prices");
                _apply_one_param_update(_params.max_tx_ex_units, update_desc, update->max_tx_ex_units, "max_tx_ex_units");
                _apply_one_param_update(_params.max_block_ex_units, update_desc, update->max_block_ex_units, "max_block_ex_units");
                _apply_one_param_update(_params.max_value_size, update_desc, update->max_value_size, "max_value_size");
                _apply_one_param_update(_params.max_collateral_pct, update_desc, update->max_collateral_pct, "max_collateral_pct");
                _apply_one_param_update(_params.max_collateral_inputs, update_desc, update->max_collateral_inputs, "max_collateral_inputs");
                _apply_one_param_update(_params.plutus_cost_models, update_desc, update->plutus_cost_models, "plutus_cost_models");
                logger::info("epoch: {} protocol params update: [ {}]", _epoch, update_desc);
            }
            _ppups = std::move(_ppups_future);
            _ppups_future.clear();
            return orig_params_prev;
        }

        void _tick(const uint64_t slot)
        {
            if (_params.protocol_ver.major >= 2) {
                if (!_params_prev.protocol_ver.forgo_reward_prefilter() && slot > _reward_pulsing_snapshot_slot) {
                    if (_reward_pulsing_snapshot.empty() && !_accounts.empty()) {
                        timer t { fmt::format("epoch: {} create a pulsing snapshot of reward accounts", _epoch), logger::level::debug };
                        _reward_pulsing_snapshot.clear();
                        for (const auto &[stake_id, acc]: _accounts) {
                            if (acc.ptr)
                                _reward_pulsing_snapshot.emplace_back(stake_id, acc.reward);
                        }
                    }
                }
            }
        }

        void _transfer_potential_rewards(const cardano::protocol_params &params_prev)
        {
            const auto aggregated = params_prev.protocol_ver.aggregated_rewards();
            const auto forgo_prefilter = params_prev.protocol_ver.forgo_reward_prefilter();
            const bool force_active = !aggregated || forgo_prefilter;
            timer t { fmt::format("validator::state epoch: {} transfer_potential_rewards aggregated forgo_prefilter: {}", _epoch, forgo_prefilter), logger::level::debug };
            using pool_update_map = std::unordered_map<cardano::pool_hash, uint64_t>;
            const std::string task_group = fmt::format("ledger-state:transfer-rewards:epoch-{}", _epoch);
            std::atomic_uint64_t treasury_update = 0;
            std::vector<pool_update_map> part_updates(_potential_rewards.num_parts);
            // all rewards must be already created to ensure no allocation is necessary
            _sched.wait_all_done(task_group, _potential_rewards.num_parts,
                [&] {
                    for (size_t part_idx = 0; part_idx < _potential_rewards.num_parts; ++part_idx) {
                        _sched.submit_void(task_group, 1000, [this, &part_updates, &treasury_update, part_idx, aggregated, force_active] () {
                            // relies on _rewards, _potential_rewards, _pulsing_snapshot being ordered containers!
                            auto acc_it = _accounts.partition(part_idx).begin();
                            const auto acc_end = _accounts.partition(part_idx).end();
                            pool_update_map pool_dist_updates {};
                            pool_dist_updates.reserve(_go.pool_params.size());
                            uint64_t part_treasury_update = 0;
                            for (const auto &[stake_id, reward_list]: _potential_rewards.partition(part_idx)) {
                                if (force_active || _reward_pulsing_snapshot.contains(stake_id)) {
                                    while (acc_it != acc_end && acc_it->first < stake_id)
                                        ++acc_it;
                                    for (auto &&ri: reward_list) {
                                        if (ri.amount) {
                                            if (acc_it != acc_end && acc_it->first == stake_id && acc_it->second.ptr) {
                                                acc_it->second.reward += ri.amount;
                                                if (ri.delegated_pool_id) {
                                                    pool_dist_updates[*ri.delegated_pool_id] += ri.amount;
                                                }
                                            } else {
                                                part_treasury_update += ri.amount;
                                            }
                                            if (!aggregated)
                                                break;
                                        }
                                    }
                                }
                            }
                            part_updates[part_idx] = std::move(pool_dist_updates);
                            atomic_add(treasury_update, part_treasury_update);
                        });
                    }
                }
            );
            logger::debug("epoch {} transfer_potential_rewards treasury_update: {}", _epoch, treasury_update.load());
            _treasury += treasury_update;
            {
                timer t2 { fmt::format("epoch: {} transfer_potential_rewards sequential application of updates", _epoch), logger::level::trace };
                // updates are applied in the same order as if they were computed sequentially
                for (const auto &pool_dist_updates: part_updates) {
                    for (const auto &[pool_id, amount]: pool_dist_updates)
                        _active_pool_dist.add(pool_id, amount);
                }
            }
        }

        uint64_t _transfer_instant_rewards(stake_distribution &rewards)
        {
            timer t { fmt::format("validator::state epoch: {} transfer_instant_rewards", _epoch) };
            uint64_t sum = 0;
            for (const auto &[stake_id, reward]: rewards) {
                if (auto acc_it = _accounts.find(stake_id); acc_it != _accounts.end() && acc_it->second.ptr) {
                    sum += reward;
                    acc_it->second.reward += reward;
                    if (acc_it->second.deleg)
                        _active_pool_dist.add(*acc_it->second.deleg, reward);
                }
            }
            rewards.clear();
            return sum;
        }

        std::pair<uint64_t, uint64_t> _retire_pools()
        {
            uint64_t refunds_user = 0;
            uint64_t refunds_treasury = 0;
            for (auto it = _pools_retiring.begin(); it != _pools_retiring.end(); ) {
                if (_epoch >= it->second) {
                    const auto &pool_id = it->first;
                    const auto &pool_info = _active_pool_params.at(pool_id);
                    const auto pd_it = _pool_deposits.find(pool_id);
                    if (pd_it == _pool_deposits.end())
                        throw error("retiring pool {} does not have a deposit record!");
                    const auto pool_deposit = pd_it->second;
                    _pool_deposits.erase(pd_it);
                    //logger::trace("epoch: {} returning the deposit of a retiring pool {} to {}", _epoch, it->first, pool_info.reward_id);
                    for (const auto &stake_id: _active_inv_delegs.at(pool_id))
                        _accounts.at(stake_id).deleg.reset();
                    _active_inv_delegs.erase(pool_id);
                    if (auto acc_it = _accounts.find(pool_info.reward_id); acc_it != _accounts.end() && acc_it->second.ptr) {
                        acc_it->second.reward += pool_deposit;
                        if (const auto rew_acc_it = _accounts.find(pool_info.reward_id); rew_acc_it != _accounts.end() && rew_acc_it->second.deleg) {
                            if (_active_pool_params.contains(*rew_acc_it->second.deleg)) {
                                _active_pool_dist.add(*rew_acc_it->second.deleg, pool_deposit);
                                refunds_user += pool_deposit;
                            }
                        }
                    } else {
                        logger::trace("epoch: {} can't return the deposit of a retiring pool {}, so it goes to the treasury", _epoch, it->first);
                        _treasury += pool_deposit;
                        refunds_treasury += pool_deposit;
                    }

                    if (_deposited < pool_deposit)
                        throw error("trying to remove a deposit while having insufficient deposits");
                    _deposited -= pool_deposit;
                    _active_pool_dist.retire(it->first);
                    _active_pool_params.erase(pool_id);
                    it = _pools_retiring.erase(it);
                } else {
                    ++it;
                }
            }
            return std::make_pair(refunds_user, refunds_treasury);
        }

        delegation_map_copy _filtered_delegs(const size_t idx) const
        {
            delegation_map_copy delegs {};
            for (const auto &[stake_id, acc]: _accounts) {
                if (const auto &deleg = acc.deleg_copy(idx); deleg)
                    delegs.emplace_back(stake_id, *deleg);
            }
            return delegs;
        }

        stake_distribution _filtered_stake_dist(const size_t idx) const
        {
            stake_distribution sd {};
            for (const auto &[stake_id, acc]: _accounts) {
                if (const auto stake = acc.stake_copy(idx); stake > 0 && acc.deleg_copy(idx))
                    sd.try_emplace(stake_id, stake);
            }
            return sd;
        }
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::validator::reward_type>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            switch (v) {
                case daedalus_turbo::validator::reward_type::leader:
                    return fmt::format_to(ctx.out(), "reward_type::leader");

                case daedalus_turbo::validator::reward_type::member:
                    return fmt::format_to(ctx.out(), "reward_type::member");

                default:
                    return fmt::format_to(ctx.out(), "reward_type::unsupported");
            }
        }
    };

    template<>
    struct formatter<daedalus_turbo::validator::reward_update>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "reward_update(type: {} pool_id: {} amount: {})", v.type, v.pool_id, v.amount);
        }
    };

    template<>
    struct formatter<daedalus_turbo::validator::pool_info>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "pledge: {} cost: {} margin: {} reward: {} owners: {} vrf: {} relays: {} metadata: {}",
                v.pledge, v.cost, v.margin, v.reward_id, v.owners, v.vrf_vkey, v.relays, v.metadata);
        }
    };

    template<>
    struct formatter<daedalus_turbo::validator::operating_pool_info>: formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "rel_stake: {} vrf: {}", v.rel_stake, v.vrf_vkey);
        }
    };
}

#endif // !DAEDALUS_TURBO_VALIDATOR_STATE_HPP