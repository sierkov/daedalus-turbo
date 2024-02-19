/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_VALIDATOR_STATE_HPP
#define DAEDALUS_TURBO_VALIDATOR_STATE_HPP

#include <unordered_map>
#include <unordered_set>
#include <zpp_bits.h>
#include <dt/atomic.hpp>
#include <dt/format.hpp>
#include <dt/index/stake-delta.hpp>
#include <dt/static-map.hpp>
#include <dt/timer.hpp>
#include <dt/validator/types.hpp>

namespace daedalus_turbo::validator {
    struct state {
        constexpr static auto serialize(auto &archive, auto &self)
        {
            auto res = archive(
                self._epoch,
                self._end_offset,
                self._mark,
                self._set,
                self._go,
                self._pools_retiring,
                self._active_stake_dist,
                self._active_pool_dist,
                self._active_pool_params,
                self._active_delegs,
                self._active_inv_delegs,
                self._params,
                self._params_prev,
                self._ppups,
                self._ppups_future,
                self._epoch_infos,
                self._rewards,
                self._ptr_to_stake,
                self._stake_to_ptr,
                self._instant_rewards_reserves,
                self._instant_rewards_treasury,
                self._reward_pool_params,
                self._blocks_current,
                self._blocks_before,
                self._potential_rewards,
                self._reward_pulsing_start,
                self._reward_pulsing_snapshot,
                self._reserves,
                self._treasury
            );
#ifndef NDEBUG
            logger::trace("validator::state::serialize epoch: {} reserves: {} treasury: {}", self._epoch, self._reserves, self._treasury);
            for (const auto &stake_id: self._traced_stakes) {
                logger::trace("validator::state::serialize {} rewards: {}", stake_id, self._rewards.get(stake_id));
            }
#endif
            return res;
        }

        state(scheduler &sched): _sched { sched }
        {
            //_traced_stakes.emplace(cardano::stake_ident { cardano::key_hash::from_hex("42FBE3C7DE5853FC74DA3C27DC583E7A660CCFF4042FBF12F223E53A") });
        }

        template<std::ranges::input_range T>
        void register_pool(const cardano::pool_hash &pool_id, const stake_ident &reward_id, const T &owners,
            uint64_t pledge=0, uint64_t cost=340'000'000, rational_u64 margin=rational_u64 { 0, 1 })
        {
#ifndef NDEBUG
            if (_traced_pools.contains(pool_id))
                logger::trace("epoch: {} register_pool: {} pledge: {} cost: {} margin: {}",
                    _epoch, pool_id, cardano::amount { pledge }, cardano::amount { cost }, margin);
#endif
            pool_info pool_params {
                .reward_id = reward_id,
                .pledge = pledge,
                .cost = cost,
                .margin = margin
            };
            for (const auto &stake_id: owners)
                pool_params.owners.emplace_back(stake_id);
            
            auto [it, created] = _active_pool_params.try_emplace(pool_id, pool_params);
            if (created) {
                // propagate through the snapshots - immediate registration works only for the first time
                _mark.pool_params.try_emplace(pool_id, pool_params);
                _set.pool_params.try_emplace(pool_id, pool_params);
                _go.pool_params.try_emplace(pool_id, pool_params);
                _reward_pool_params.try_emplace(pool_id, pool_params);
            } else {
                it->second = std::move(pool_params);
            }
            // search for already delegated stake ids - needed for the case of re-registration of a retired pool
            if (_active_pool_dist.create(pool_id)) {
                auto [inv_delegs_it, inv_delegs_created] = _active_inv_delegs.try_emplace(pool_id);
                if (!inv_delegs_created) {
                    for (const auto &stake_id: inv_delegs_it->second)
                        _active_pool_dist.add(pool_id, _active_stake_dist.get(stake_id) + _rewards.get(stake_id));
                }
#ifndef NDEBUG
                if (_traced_pools.contains(pool_id))
                    logger::trace("epoch: {} register_pool: {} => stake: {}",
                        _epoch, pool_id, cardano::amount { _active_pool_dist.get(pool_id) });
#endif
            }
            // delete planned retirement if present
            _pools_retiring.erase(pool_id);
        }

        void retire_pool(const cardano::pool_hash &pool_id, uint64_t epoch)
        {
#ifndef NDEBUG
            if (_traced_pools.contains(pool_id))
                logger::trace("epoch: {} retire_pool: {} from_epoch: {}", _epoch, pool_id, epoch);
#endif
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

        void instant_reward_reserves(const cardano::slot &, const stake_ident &stake_id, uint64_t reward)
        {
            auto prev_amount = _instant_rewards_reserves.get(stake_id);
            if (prev_amount > 0)
                _instant_rewards_reserves.sub(stake_id, prev_amount);
            _instant_rewards_reserves.add(stake_id, reward);
        }

        void instant_reward_treasury(const cardano::slot &, const stake_ident &stake_id, uint64_t reward)
        {
            auto prev_amount = _instant_rewards_treasury.get(stake_id);
            if (prev_amount > 0)
                _instant_rewards_treasury.sub(stake_id, prev_amount);
            _instant_rewards_treasury.add(stake_id, reward);
        }

        void withdraw_reward(const cardano::slot &
#ifndef NDEBUG
            slot
#endif
            ,
            const stake_ident &stake_id, uint64_t amount)
        {
#ifndef NDEBUG
            if (_traced_stakes.contains(stake_id))
                logger::trace("epoch: {} slot: {} withdraw {} from {}",
                    _epoch, slot, stake_id, cardano::amount { amount }, stake_id);
#endif
            _rewards.sub(stake_id, amount);
            auto deleg_it = _active_delegs.find(stake_id);
            if (deleg_it != _active_delegs.end())
                _active_pool_dist.sub(deleg_it->second, amount);
            _epoch_infos[_epoch].withdrawals += amount;
        }

        void register_stake(const cardano::slot &slot, const stake_ident &stake_id, size_t tx_idx=0, size_t cert_idx=0)
        {
            _tick(slot);
#ifndef NDEBUG
            if (_traced_stakes.contains(stake_id))
                logger::trace("epoch: {} register_stake: {}", _epoch, stake_id);
#endif
            _rewards.create(stake_id);
            cardano::stake_pointer ptr { slot, tx_idx, cert_idx };
            _ptr_to_stake[ptr] = stake_id;
            _stake_to_ptr[stake_id] = ptr;
        }

        void retire_stake(const cardano::slot &slot, const stake_ident &stake_id)
        {
            _tick(slot);
            auto reward = _rewards.get(stake_id);
#ifndef NDEBUG
            if (_traced_stakes.contains(stake_id))
                logger::trace("epoch: {} epoch slot: {} retire stake: {} unclaimed reward: {} stake: {} delegated: {}",
                    _epoch, slot.epoch_slot(), stake_id, reward, _active_stake_dist.get(stake_id), _active_delegs.contains(stake_id));
#endif
            _epoch_infos[_epoch].unclaimed_rewards += reward;
            auto deleg_it = _active_delegs.find(stake_id);
            if (deleg_it != _active_delegs.end()) {
                auto stake = _active_stake_dist.get(stake_id) + _rewards.get(stake_id);
                //logger::trace("epoch: {} retirement of {} - removing {} from pool {}", _epoch, stake_id, cardano::amount { stake }, deleg_it->second);
                _active_pool_dist.sub(deleg_it->second, stake);
                _active_inv_delegs.at(deleg_it->second).erase(stake_id);
                _active_delegs.erase(deleg_it);
            }
            _rewards.retire(stake_id);
            auto ptr_it = _stake_to_ptr.find(stake_id);
            if (ptr_it != _stake_to_ptr.end()) {
                _ptr_to_stake.erase(ptr_it->second);
                _stake_to_ptr.erase(ptr_it);
            } else {
                logger::trace("slot: {}/{} can't find the retiring stake's pointer");
            }
            _treasury += reward;
        }

        void delegate_stake(const stake_ident &stake_id, const cardano_hash_28 &pool_id)
        {
#ifndef NDEBUG
            if (_traced_stakes.contains(stake_id))
                logger::trace("epoch: {} delegate_stake: {} to pool: {}", _epoch, stake_id, pool_id);
#endif
            if (!_active_pool_params.contains(pool_id))
                throw error("trying to delegate {} to an unknown pool: {}", stake_id, pool_id);
            auto stake = _active_stake_dist.get(stake_id) + _rewards.get(stake_id);
            auto [deleg_it, deleg_created] = _active_delegs.try_emplace(stake_id, pool_id);
            if (deleg_created || deleg_it->second != pool_id) {
                _active_inv_delegs[pool_id].emplace(stake_id);
                _active_pool_dist.add(pool_id, stake);
            }
            if (deleg_it->second != pool_id) {
                _active_inv_delegs[deleg_it->second].erase(stake_id);
                // ignore retired pools
                if (_active_pool_params.contains(deleg_it->second)) {
                    _active_pool_dist.sub(deleg_it->second, stake);
                }
                deleg_it->second = pool_id;
            }
#ifndef NDEBUG
            if (_traced_stakes.contains(stake_id))
                logger::trace("epoch: {} delegate_stake: {} to pool: {} => pool's stake: {}", _epoch, stake_id, pool_id, _active_pool_dist.get(pool_id));
#endif
        }

        void update_stake(const stake_ident &stake_id, int64_t delta)
        {
#ifndef NDEBUG
            if (_traced_stakes.contains(stake_id))
                logger::trace("epoch: {} update_stake: {} by {}", _epoch, stake_id, delta);
#endif
            auto deleg_it = _active_delegs.find(stake_id);
            if (delta >= 0) {
                _active_stake_dist.add(stake_id, static_cast<uint64_t>(delta));
                if (deleg_it != _active_delegs.end()) {
                    if (_active_pool_params.contains(deleg_it->second))
                        _active_pool_dist.add(deleg_it->second, static_cast<uint64_t>(delta));
                }
                    
            } else {
                _active_stake_dist.sub(stake_id, static_cast<uint64_t>(-delta));
                if (deleg_it != _active_delegs.end()) {
                    if (_active_pool_params.contains(deleg_it->second))
                        _active_pool_dist.sub(deleg_it->second, static_cast<uint64_t>(-delta));
                }
            }
#ifndef NDEBUG
            if (_traced_stakes.contains(stake_id)) {
                logger::trace("epoch: {} update_stake: {} by {} => {}", _epoch, stake_id, delta, cardano::amount { _active_stake_dist.get(stake_id) });
                if (deleg_it != _active_delegs.end())
                    logger::trace("epoch: {} update_stake: {} => pool {}: {}", _epoch, stake_id, deleg_it->second, cardano::amount { _active_pool_dist.get(deleg_it->second) });
            }
#endif
        }

        void update_pointer(const cardano::stake_pointer &ptr, int64_t delta)
        {
            auto ptr_it = _ptr_to_stake.find(ptr);
            if (ptr_it != _ptr_to_stake.end() && _rewards.contains(ptr_it->second)) {
                logger::trace("epoch: {} stake update via pointer: {} {} delta: {}", _epoch, ptr, ptr_it->second, cardano::balance_change { delta });
                update_stake(ptr_it->second, delta);
            } else {
                logger::trace("epoch: {} skipping an unknown stake pointer: {} delta: {}", _epoch, ptr, cardano::balance_change { delta });
            }
        }

        void propose_update(const cardano::slot &slot, const cardano::param_update &pupd)
        {
            logger::trace("slot: {}/{} proposal: {}", slot.epoch(), slot, pupd);
            if (pupd.epoch == _epoch) {
                auto too_late = cardano::slot::from_epoch(_epoch + 1) - 2 * _params.stability_window();
                if (slot < too_late) {
                    _ppups[pupd.pool_id] = pupd;
                } else {
                    logger::warn("slot: {}/{} ignoring an update proposal since its too late in the epoch", slot.epoch(), slot);    
                }
            } else if (pupd.epoch == _epoch + 1) {
                _ppups_future[pupd.pool_id] = pupd;
            } else {
                logger::warn("slot: {}/{} ignoring an update proposal for an unexpected epoch {}", slot.epoch(), slot, pupd.epoch);
            }
        }

        const ptr_to_stake_map &pointers() const
        {
            return _ptr_to_stake;
        }

        const reward_distribution &reward_dist() const
        {
            return _rewards;
        }

        const stake_distribution &stake_dist() const
        {
            return _active_stake_dist;
        }

        const stake_distribution &instant_rewards_reserves() const
        {
            return _instant_rewards_reserves;
        }

        const stake_distribution &instant_rewards_treasury() const
        {
            return _instant_rewards_treasury;
        }

        const delegation_map_copy &delegs_mark() const
        {
            return _mark.delegs;
        }

        const delegation_map_copy &delegs_set() const
        {
            return _set.delegs;
        }

        const delegation_map_copy &delegs_go() const
        {
            return _go.delegs;
        }

        const stake_distribution stake_dist_mark() const
        {
            return _filtered_stake_dist(_mark);
        }

        const stake_distribution stake_dist_set() const
        {
            return _filtered_stake_dist(_set);
        }

        const stake_distribution stake_dist_go() const
        {
            return _filtered_stake_dist(_go);
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

        void add_pool_blocks(const cardano::pool_hash &pool_id, uint64_t num_blocks)
        {
            if (_genesis_pools().contains(pool_id))
                return;
#ifndef NDEBUG
            if (_traced_pools.contains(pool_id))
                logger::trace("epoch: {} set_last_epoch_blocks for pool {}: {}", _epoch, pool_id, num_blocks);
#endif
            if (_go.pool_params.contains(pool_id)) {
                _blocks_current.add(pool_id, num_blocks);
            } else {
                logger::warn("trying to provide the number of generated blocks in epoch {} for an unknown pool {} num_blocks: {}!", _epoch, pool_id, num_blocks);
            }
        }

        void fees(uint64_t epoch, uint64_t amount)
        {
            if (epoch < _epoch)
                throw error("fees can be set only for the coming epochs!");
            auto &epoch_info = _epoch_infos[epoch];
            logger::trace("epoch: {} set fees: {} prev value: {} diff: {}",
                epoch, amount, epoch_info.fees, static_cast<int64_t>(amount) - static_cast<int64_t>(epoch_info.fees));
            epoch_info.fees = amount;
        }

        void add_fees(uint64_t amount)
        {
            _epoch_infos[_epoch + 1].fees += amount;
        }

        void fees(uint64_t amount)
        {
            fees(_epoch + 1, amount);
        }

        void reserves(uint64_t r)
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

        const protocol_params &params() const
        {
            return _params;
        }

        const partitioned_reward_update_dist &potential_rewards()
        {
            return _potential_rewards;
        }

        void end_offset(uint64_t offset)
        {
            if (offset > _end_offset)
                _end_offset = offset;
        }

        uint64_t end_offset() const
        {
            return _end_offset;
        }

#ifndef NDEBUG
        void traced_pools(const std::set<cardano::pool_hash> &pools)
        {
            _traced_pools = pools;
        }

        void traced_stakes(const std::set<cardano::stake_ident> &stakes)
        {
            _traced_stakes = stakes;
        }
#endif

        void rotate_snapshots()
        {
            timer t { fmt::format("validator::state epoch: {} rotate_snapshots", _epoch), logger::level::trace };
            {
                timer ts { fmt::format("validator::state epoch: {} move reward_pool_params", _epoch), logger::level::trace };
                _reward_pool_params = std::move(_go.pool_params);
            }
            {
                timer ts { fmt::format("validator::state epoch: {} move set snapshot to go", _epoch), logger::level::trace };
                _go = std::move(_set);
            }
            {
                timer ts { fmt::format("validator::state epoch: {} move mark snapshot to set", _epoch), logger::level::trace };
                _set = std::move(_mark);
            }
            timer ts { fmt::format("validator::state epoch: {} copy active snapshot to mark", _epoch), logger::level::trace };
            static const std::string task_group { "rotate-snapshot" };
            _sched.wait_for_count(task_group, 6,
                [&] {
                    _sched.submit("rotate-snapshot", 1000, [this] {
                        timer ts { fmt::format("validator::state epoch: {} copy pool_dist to mark", _epoch), logger::level::trace };
                        _mark.pool_dist = _active_pool_dist;
                        return true;
                    });
                    _sched.submit("rotate-snapshot", 1000, [this] {
                        timer ts { fmt::format("validator::state epoch: {} copy pool_params to mark", _epoch), logger::level::trace };
                        _mark.pool_params = _active_pool_params;
                        return true;
                    });
                    _sched.submit("rotate-snapshot", 1000, [this] {
                        timer ts { fmt::format("validator::state epoch: {} copy delegs to mark", _epoch), logger::level::trace };
                        _mark.delegs = _active_delegs;
                        return true;
                    });
                    _sched.submit("rotate-snapshot", 1000, [this] {
                        timer ts { fmt::format("validator::state epoch: {} copy inv_delegs to mark", _epoch), logger::level::trace };
                        _mark.inv_delegs = _active_inv_delegs;
                        return true;
                    });
                    _sched.submit("rotate-snapshot", 1000, [this] {
                        timer ts { fmt::format("validator::state epoch: {} copy stake_dist to mark", _epoch), logger::level::trace };
                        _mark.stake_dist = _active_stake_dist;
                        return true;
                    });
                    _sched.submit("rotate-snapshot", 1000, [this] {
                        timer ts { fmt::format("validator::state epoch: {} copy rewards to mark", _epoch), logger::level::trace };
                        _mark.reward_dist = _rewards;
                        return true;
                    });
                }
            );
        }

        void start_epoch(uint64_t new_epoch=0)
        {
            timer ts { fmt::format("validator::state::start_epoch {}", new_epoch), logger::level::trace };
            if (new_epoch == 0)
                new_epoch = _epoch + 1;

            _transfer_instant_rewards();
            _transfer_potential_rewards();
            rotate_snapshots();
            _apply_param_updates();
            _reserves -= _delta_reserves;
            _treasury += _delta_treasury;

            logger::trace("epoch {} before refunds and epoch rewards: treasury: {} reserves: {}",
                _epoch, cardano::amount { _treasury }, cardano::amount { _reserves });

            _epoch = new_epoch;
            _clean_old_epoch_data();
            
#ifndef NDEBUG
            for (const auto &pool_id: _traced_pools) {
                using dist_info = std::tuple<const char *, const ledger_copy &>;
                for (const auto &[name, ledg]: { dist_info { "mark", _mark }, dist_info { "set", _set }, dist_info { "go", _go } }) {
                    logger::trace("epoch start: {} pool {} present in {}: pstake: {} % {}", _epoch, pool_id, name,
                        ledg.pool_dist.get(pool_id), ledg.pool_dist.total_stake());
                }
            }
            for (const auto &stake_id: _traced_stakes) {
                using dist_info = std::pair<const char *, const stake_distribution_copy &>;
                for (const auto &[name, dist]: { dist_info { "dist_mark", _mark.stake_dist }, dist_info { "dist_set", _set.stake_dist },
                                                 dist_info { "dist_go", _go.stake_dist } }) {
                    logger::trace("epoch start: {} {} present in {}: {}", _epoch, stake_id, name, dist.get(stake_id));
                }
                logger::trace("epoch start: {} {} rewards: {}", _epoch, stake_id, _rewards.get(stake_id));
            }
#endif
            
            // retire pools and return pool deposits
            auto [ refunds_user, refunds_treasury ] = _retire_pools();
            _prepare_reward_pulsing_schedule();

            logger::debug("epoch {} start: treasury: {} reserves: {} user refunds: {} treasury refunds: {}",
                _epoch, cardano::amount { _treasury }, cardano::amount { _reserves },
                cardano::amount { refunds_user }, cardano::amount { refunds_treasury });
        }

        void finish_epoch()
        {
            timer ts { fmt::format("validator::state::finish_epoch {}", _epoch), logger::level::trace };
            _tick(cardano::slot::from_epoch(_epoch + 1));
            _accumulate_instant_rewards();
            _compute_rewards();
        }

        void transition_epoch()
        {
            finish_epoch();
            start_epoch();
        }

        uint64_t epoch() const
        {
            return _epoch;
        }
    private:
        struct pool_info {
            constexpr static auto serialize(auto &archive, auto &self)
            {
                return archive(self.reward_id, self.owners, self.pledge, self.cost, self.margin);
            }

            stake_ident reward_id {};
            std::vector<stake_ident> owners {};
            uint64_t pledge = 0;
            uint64_t cost = 0;
            rational_u64 margin = { 0, 1 };
            rational member_reward_base {}; // not serializable
        };
        using pool_info_map = std::map<cardano::pool_hash, pool_info>;

        struct ledger_copy {
            stake_distribution_copy stake_dist {};
            reward_distribution_copy reward_dist {};
            pool_stake_distribution pool_dist {};
            delegation_map_copy delegs {};
            inv_delegation_map_copy inv_delegs {};
            pool_info_map pool_params {};
        };

        struct pool_reward_item {
            using serialize = zpp::bits::members<4>;
            cardano::stake_ident stake_id {};
            reward_type type {};
            uint64_t amount = 0;
            std::optional<cardano::pool_hash> delegated_pool_id {};
        };

        using pool_block_dist = distribution<std::map<cardano::pool_hash, uint64_t>>;
        using pool_reward_list = std::vector<pool_reward_item>;
        using pool_rewards_result = std::tuple<cardano::pool_hash, pool_reward_list, uint64_t>;
        using pool_reward_map = std::map<cardano::pool_hash, pool_reward_list>;

        scheduler &_sched;
        uint64_t _epoch = 0;
        uint64_t _end_offset = 0;
        // stateBefore.esSnapshots
        ledger_copy _mark {}, _set {}, _go {};
        // delegationState.pstate.retiring
        std::map<cardano::pool_hash, uint64_t> _pools_retiring {};

        // active state
        stake_distribution _active_stake_dist {};
        pool_stake_distribution _active_pool_dist {};
        pool_info_map _active_pool_params {};
        delegation_map _active_delegs {};
        inv_delegation_map _active_inv_delegs {};

        // protocol params
        protocol_params _params {};
        protocol_params _params_prev {};
        std::map<cardano::pool_hash, cardano::param_update> _ppups {};
        std::map<cardano::pool_hash, cardano::param_update> _ppups_future {};

        // rewards-related data
        std::map<uint64_t, epoch_info> _epoch_infos {};
        reward_distribution _rewards {};
        ptr_to_stake_map _ptr_to_stake {};
        stake_to_ptr_map _stake_to_ptr {};
        stake_distribution _instant_rewards_reserves {};
        stake_distribution _instant_rewards_treasury {};
        pool_info_map _reward_pool_params {};
        pool_block_dist _blocks_current {};
        pool_block_dist _blocks_before {};
        // possibleRewardUpdate.rs
        uint64_t _delta_treasury = 0;
        uint64_t _delta_reserves = 0;
        partitioned_reward_update_dist _potential_rewards {};
        //pool_reward_map _pool_potential_rewards {};
        cardano::slot _reward_pulsing_start {};
        reward_distribution_copy _reward_pulsing_snapshot {};

        // stateBefore.esAccountState
        uint64_t _reserves = 0;
        uint64_t _treasury = 0;

#ifndef NDEBUG
        std::set<cardano::pool_hash> _traced_pools {};
        std::set<stake_ident> _traced_stakes {};
#endif

        uint64_t _total_stake(uint64_t reserves) const
        {
            return _params_prev.max_lovelace_supply - reserves;
        }

        void _compute_rewards()
        {
            timer t { fmt::format("compute rewards for epoch {}", _epoch), logger::level::trace };
            uint64_t fees = _epoch_infos[_epoch].fees;
            uint64_t ir_reserves = _epoch_infos[_epoch].ir_reserves;
            uint64_t ir_treasury = _epoch_infos[_epoch].ir_treasury;
            uint64_t expansion = 0;
            if (_params_prev.decentralization.as_r() < _params_prev.decentralizationThreshold.as_r() && _epoch > 0) {
                rational perf = std::min(rational { 1 }, rational { _blocks_before.total_stake() } / ((1 - _params_prev.decentralization.as_r()) * _params_prev.epoch_blocks));
                expansion = static_cast<uint64_t>(_params_prev.expansion_rate.as_r() * _reserves * perf);
                logger::trace("epoch: {} performance-adjusted expansion: {} perf: {} d: {} blocks: {}",
                    _epoch, expansion, perf, _params_prev.decentralization, _blocks_before.total_stake());
            } else {
                expansion = static_cast<uint64_t>(_params_prev.expansion_rate.as_r() * _reserves);
                logger::trace("epoch: {} simple expansion: {}", _epoch, expansion);
            }
            logger::trace("epoch: {} reserves: {} fees: {} expansion_rate: {} treasury_growth_rate: {}",
                _epoch, _reserves, fees, _params_prev.expansion_rate, _params_prev.treasury_growth_rate);
            uint64_t total_reward_pool = expansion + fees;
            uint64_t treasury_rewards = static_cast<uint64_t>(_params_prev.treasury_growth_rate.as_r() * total_reward_pool);
            uint64_t rewards_pot = total_reward_pool - treasury_rewards;
            logger::trace("epoch: {} deltaT: {} rewardsPot: {}", _epoch, treasury_rewards, rewards_pot);
            uint64_t pool_rewards_filtered = 0;
            uint64_t total_stake = _total_stake(_reserves);
            logger::trace("epoch: {} total stake: {} pre-computed active stake: {} re-computed active stake: {}",
                _epoch, total_stake,  _go.pool_dist.total_stake(), _go.pool_dist.total_stake());
            if (!_blocks_before.empty()) {
                const auto &pools_active = _blocks_before;
                logger::trace("epoch {} begin reward allocation: total stake {} treasury: {} reserves: {} rewards pot: {} block-producing pools: {} reward pools: {}",
                    _epoch, total_stake, _treasury, _reserves, rewards_pot, pools_active.size(), _reward_pool_params.size());
                {
                    timer t2 { fmt::format("compute per-pool rewards for epoch {}", _epoch), logger::level::trace };
                    pool_rewards_filtered = _compute_pool_rewards_parallel(pools_active, rewards_pot, total_stake);
                }
                logger::trace("epoch {} allocated rewards: total stake: {} treasury: {} reserves: {} rewards attributed: {}",
                    _epoch, total_stake, _treasury, _reserves, pool_rewards_filtered);
            }
            logger::trace("epoch {} before accounts update: total stake {} treasury: {} reserves: {} fees: {} ir_reserves: {} ir_treasury: {}",
                 _epoch, total_stake, _treasury, _reserves, fees, ir_reserves, ir_treasury);
            _delta_treasury = treasury_rewards - ir_treasury;
            _delta_reserves = treasury_rewards + ir_reserves + pool_rewards_filtered - fees;
            logger::trace("epoch {} rewards allocated: {} unclaimed: {} mir: {} withdrawals: {}",
                _epoch, cardano::amount { pool_rewards_filtered }, cardano::amount { _epoch_infos[_epoch].unclaimed_rewards },
                cardano::amount { ir_reserves }, cardano::amount { _epoch_infos[_epoch].withdrawals });
            logger::debug("epoch {} accounts update: deltaF -{} deltaT: {} deltaR: -{}",
                 _epoch, cardano::amount { fees }, cardano::amount { _delta_treasury }, cardano::amount { _delta_reserves });
        }

        void _rewards_prepare_pool_params(uint64_t &total, uint64_t &filtered,
            uint64_t staking_reward_pot, uint64_t total_stake, const cardano::pool_hash &pool_id, pool_info &info, uint64_t pool_blocks)
        {
            uint64_t pool_reward_pot = 0;
            uint64_t pool_stake = _go.pool_dist.get(pool_id);
            if (pool_stake > 0) {
                uint64_t owner_stake = 0;
                for (const auto &stake_id: info.owners) {
                    auto deleg_it = _go.delegs.find(stake_id);
                    if (deleg_it != _go.delegs.end() && deleg_it->second == pool_id) {
                        owner_stake += _go.stake_dist.get(stake_id) + _go.reward_dist.get(stake_id);
                    }
                }
                if (owner_stake >= info.pledge) {
                    double z0 = 1.0 / _params_prev.n_opt;
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
                    uint64_t leader_reward = 0;
                    if (_params_prev.decentralization.as_r() < _params_prev.decentralizationThreshold.as_r())
                        pool_reward_pot = optimal_reward * pool_performance;
                    if (pool_reward_pot > info.cost && owner_stake < pool_stake) {
                        auto pool_margin = info.margin.as_r();
                        info.member_reward_base = (pool_reward_pot - info.cost) * (1 - pool_margin) / pool_stake;
                        leader_reward = static_cast<uint64_t>(info.cost + (pool_reward_pot - info.cost) * (pool_margin + (1 - pool_margin) * owner_stake / pool_stake));
                    } else {
                        leader_reward = pool_reward_pot;
                    }
                    bool leader_active = _params_prev.protocol_ver.forgo_reward_prefilter() || _reward_pulsing_snapshot.contains(info.reward_id);
                    if (leader_active && leader_reward > 0) {
                        auto &reward_list = _potential_rewards[info.reward_id];
                        total += leader_reward;
                        if (!reward_list.empty())
                            filtered -= reward_list.begin()->amount;
                        auto deleg_it = _active_delegs.find(info.reward_id);
                        if (deleg_it != _active_delegs.end())
                            reward_list.emplace(reward_type::leader, pool_id, leader_reward, deleg_it->second);
                        else
                            reward_list.emplace(reward_type::leader, pool_id, leader_reward);
                        filtered += reward_list.begin()->amount;
                    }
                }
            }
        }

        std::pair<uint64_t, uint64_t> _rewards_prepare_pools(const pool_block_dist &pools_active, const uint64_t staking_reward_pot, const uint64_t total_stake)
        {
            uint64_t total = 0;
            uint64_t filtered = 0;
            for (auto &[pool_id, pool_info]: _reward_pool_params) {
                uint64_t pool_blocks = pools_active.get(pool_id);
                if (pool_blocks > 0 && !_genesis_pools().contains(pool_id)) {
                    _rewards_prepare_pool_params(total, filtered, staking_reward_pot, total_stake, pool_id, pool_info, pool_blocks);
                }
            }
            return std::make_pair(total, filtered);
        }

        std::pair<uint64_t, uint64_t> _rewards_compute_part(size_t part_idx)
        {
            uint64_t total = 0;
            uint64_t filtered = 0;
            auto &part = _potential_rewards.partition(part_idx);
            for (const auto &[stake_id, pool_id]: _go.delegs) {
                if (_potential_rewards.partition_idx(stake_id) != part_idx)
                    continue;
                const auto &pool_info = _reward_pool_params.at(pool_id);
                if (std::find(pool_info.owners.begin(), pool_info.owners.end(), stake_id) == pool_info.owners.end()) {
                    uint64_t deleg_stake = _go.stake_dist.get(stake_id) + _go.reward_dist.get(stake_id);
                    uint64_t member_reward = static_cast<uint64_t>(pool_info.member_reward_base * deleg_stake);
                    if (member_reward > 0) {
                        bool active = _params_prev.protocol_ver.forgo_reward_prefilter() || _reward_pulsing_snapshot.contains(stake_id);
                        if (active) {
                            auto deleg_it = _active_delegs.find(stake_id);
                            auto &reward_list = part[stake_id];
                            total += member_reward;
                            if (!reward_list.empty())
                                filtered -= reward_list.begin()->amount;
                            if (deleg_it != _active_delegs.end())
                                reward_list.emplace(reward_type::member, pool_id, member_reward, deleg_it->second);
                            else
                                reward_list.emplace(reward_type::member, pool_id, member_reward);
                            filtered += reward_list.begin()->amount;
                        }
                    }
                }
            }
            return std::make_pair(total, filtered);
        }

        uint64_t _compute_pool_rewards_parallel(const pool_block_dist &pools_active, const uint64_t staking_reward_pot, const uint64_t total_stake)
        {
            const std::string task_group { "staking-rewards-part" };
            auto [total, filtered] = _rewards_prepare_pools(pools_active, staking_reward_pot, total_stake);
            _sched.wait_for_count(task_group, _potential_rewards.num_parts,
                [&] {
                    for (size_t part_idx = 0; part_idx < _potential_rewards.num_parts; ++part_idx) {
                        _sched.submit(task_group, 1000, [this, part_idx] {
                            return _rewards_compute_part(part_idx);
                        });
                    }
                },
                [&](auto &&res) {
                    auto [part_total, part_filtered] = std::any_cast<std::pair<uint64_t, uint64_t>>(std::move(res));
                    total += part_total;
                    filtered += part_filtered;
                }
            );
            logger::trace("epoch: {} staking_rewards total: {} filtered: {} diff: {}",
                _epoch, cardano::amount { total }, cardano::amount { filtered },
                cardano::balance_change { static_cast<int64_t>(filtered) - static_cast<int64_t>(total) });
            if (!_params_prev.protocol_ver.aggregated_rewards())
                return filtered;
            else
                return total;
        }

        void _clean_old_epoch_data()
        {
            timer t { fmt::format("validator::state epoch: {} clean_old_epoch_data", _epoch), logger::level::trace };
            for (auto it = _epoch_infos.begin(); it != _epoch_infos.end(); ) {
                if (it->first < _epoch - 1)
                    it = _epoch_infos.erase(it);
                else
                    it++;
            }
            _blocks_before = std::move(_blocks_current);
            _blocks_current.clear();
            _reward_pulsing_snapshot.clear();
            static const std::string task_group { "clean-potential-rewards" };
            _sched.wait_for_count(task_group, _potential_rewards.num_parts,
                [&] {
                    for (size_t part_idx = 0; part_idx < _potential_rewards.num_parts; ++part_idx) {
                        _sched.submit_void(task_group, 1000, [this, part_idx] () {
                            _potential_rewards.partition(part_idx).clear();
                        });
                    }
                }
            );
        }

        void _prepare_reward_pulsing_schedule()
        {
            timer t { fmt::format("validator::state epoch: {} prepare_reward_pulsing_schedule", _epoch), logger::level::trace };
            _reward_pulsing_start = cardano::slot::from_epoch(_epoch) + _params.randomness_stabilization_window();
        }

        void _apply_param_updates()
        {
            timer t { fmt::format("validator::state epoch: {} apply_param_updates", _epoch), logger::level::trace };
            _params_prev = _params;
            std::optional<cardano::param_update> update {};
            for (const auto &[pool_id, proposal]: _ppups) {
                if (!update) {
                    update = proposal;
                } else if (*update != proposal) {
                    logger::warn("proposal from {} is in disagreement - cancelling the update");
                    return;
                }
            }
            std::string update_desc {};
            if (update) {
                if (update->min_fee_a) {
                    _params.min_fee_a = *update->min_fee_a;
                    update_desc += fmt::format("min_fee_a: {} ", _params.min_fee_a);
                }
                if (update->min_fee_b) {
                    _params.min_fee_b = *update->min_fee_b;
                    update_desc += fmt::format("min_fee_b: {} ", _params.min_fee_b);
                }
                if (update->max_block_body_size) {
                    _params.max_block_body_size = *update->max_block_body_size;
                    update_desc += fmt::format("max_block_body_size: {} ", _params.max_block_body_size);
                }
                if (update->max_transaction_size) {
                    _params.max_transaction_size = *update->max_transaction_size;
                    update_desc += fmt::format("max_transaction_size: {} ", _params.max_transaction_size);
                }
                if (update->max_block_header_size) {
                    _params.max_block_header_size = *update->max_block_header_size;
                    update_desc += fmt::format("max_block_header_size: {} ", _params.max_block_header_size);
                }
                if (update->key_deposit) {
                    _params.key_deposit = *update->key_deposit;
                    update_desc += fmt::format("key_deposit: {} ", _params.key_deposit);
                }
                if (update->pool_deposit) {
                    _params.pool_deposit = *update->pool_deposit;
                    update_desc += fmt::format("pool_deposit: {} ", _params.pool_deposit);
                }
                if (update->max_epoch) {
                    _params.max_epoch = *update->max_epoch;
                    update_desc += fmt::format("max_epoch: {} ", _params.max_epoch);
                }
                if (update->n_opt) {
                    _params.n_opt = *update->n_opt;
                    update_desc += fmt::format("n_opt: {} ", _params.n_opt);
                }
                if (update->pool_pledge_influence) {
                    _params.pool_pledge_influence = *update->pool_pledge_influence;
                    update_desc += fmt::format("pool_pledge_influence: {} ", _params.pool_pledge_influence);
                }
                if (update->expansion_rate) {
                    _params.expansion_rate = *update->expansion_rate;
                    update_desc += fmt::format("expansion_rate: {} ", _params.expansion_rate);
                }
                if (update->treasury_growth_rate) {
                    _params.treasury_growth_rate = *update->treasury_growth_rate;
                    update_desc += fmt::format("treasury_growth_rate: {} ", _params.treasury_growth_rate);
                }
                if (update->decentralization) {
                    _params.decentralization = *update->decentralization;
                    update_desc += fmt::format("decentralization: {} ", _params.decentralization);
                }
                if (update->extra_entropy) {
                    _params.extra_entropy = *update->extra_entropy;
                    update_desc += fmt::format("extra_entropy: {} ", _params.extra_entropy);
                }
                if (update->protocol_ver) {
                    _params.protocol_ver = *update->protocol_ver;
                    update_desc += fmt::format("protocol_ver: {} ", _params.protocol_ver);
                }
                if (update->min_utxo_value) {
                    _params.min_utxo_value = *update->min_utxo_value;
                    update_desc += fmt::format("min_utxo_value: {} ", _params.min_utxo_value);
                }
            }
            _ppups = std::move(_ppups_future);
            _ppups_future.clear();
            if (!update_desc.empty())
                logger::info("epoch: {} protocol params update: [{}]", _epoch, update_desc);
        }

        void _tick (const cardano::slot &slot)
        {
            if (!_params_prev.protocol_ver.forgo_reward_prefilter() && slot > _reward_pulsing_start) {
                if (_reward_pulsing_snapshot.empty() && !_rewards.empty()) {
                    timer t { fmt::format("validator::state epoch: {} rewards pulsing - take a snapshot of reward accounts", _epoch), logger::level::trace };
                    _reward_pulsing_snapshot = _rewards;
                }
            }
        }

        void _transfer_potential_rewards()
        {
            const auto aggregated = _params_prev.protocol_ver.aggregated_rewards();
            const auto forgo_prefilter = _params_prev.protocol_ver.forgo_reward_prefilter();
            const bool force_active = !aggregated || forgo_prefilter;
            timer t { fmt::format("validator::state epoch: {} transfer_potential_rewards aggregated forgo_prefilter: {}", _epoch, forgo_prefilter), logger::level::trace };
            using pool_update_map = std::unordered_map<cardano::pool_hash, uint64_t>;
            static const std::string task_group { "transfer-rewards-part" };
            std::atomic_uint64_t treasury_after { _treasury };
            std::vector<pool_update_map> part_updates(_potential_rewards.num_parts);
            // all rewards must be already created to ensure no allocation is necessary
            _sched.wait_for_count(task_group, _potential_rewards.num_parts,
                [&] {
                    for (size_t part_idx = 0; part_idx < _potential_rewards.num_parts; ++part_idx) {
                        _sched.submit_void("transfer-rewards-part", 1000, [this, &part_updates, &treasury_after, part_idx, aggregated, force_active] () {
                            // relies on _rewards, _potential_rewards, _pulsing_snapshot being ordered containers!
                            auto reward_it = _rewards.partition(part_idx).begin();
                            const auto reward_end = _rewards.partition(part_idx).end();
                            pool_update_map pool_dist_updates {};
                            pool_dist_updates.reserve(_reward_pool_params.size());
                            uint64_t treasury_update = 0;
                            for (const auto &[stake_id, reward_list]: _potential_rewards.partition(part_idx)) {
                                if (force_active || _reward_pulsing_snapshot.contains(stake_id)) {
                                    while (reward_it != reward_end && reward_it->first < stake_id)
                                        ++reward_it;
                                    for (auto &&ri: reward_list) {
                                        if (reward_it != reward_end && reward_it->first == stake_id) {
                                            reward_it->second += ri.amount;
                                            if (ri.delegated_pool_id) {
                                                pool_dist_updates[*ri.delegated_pool_id] += ri.amount;
                                            }
                                        } else {
                                            treasury_update += ri.amount;
                                        }
                                        if (!aggregated)
                                            break;
                                    }
                                }
                            }
                            part_updates[part_idx] = std::move(pool_dist_updates);
                            atomic_add(treasury_after, treasury_update);
                        });
                    }
                }
            );
            _treasury = treasury_after.load();
            // updates are applied in the same order as if they were computed sequentially
            for (const auto &pool_dist_updates: part_updates) {
                for (const auto &[pool_id, amount]: pool_dist_updates)
                    _active_pool_dist.add(pool_id, amount);
            }
        }

        void _accumulate_instant_rewards()
        {
            timer t { fmt::format("validator::state epoch: {} accumulate_instant_rewards", _epoch), logger::level::trace };
            for (const auto &[stake_id, reward]: _instant_rewards_reserves) {
                if (_rewards.contains(stake_id)) {
                    _epoch_infos[_epoch].ir_reserves += reward;
                } else {
                    logger::trace("epoch: {} instant reward: {} from reserves to a retired stake_id: {} - ignoring", _epoch, reward, stake_id);
                }
            }
            for (const auto &[stake_id, reward]: _instant_rewards_treasury) {
                if (_rewards.contains(stake_id)) {
                    _epoch_infos[_epoch].ir_treasury += reward;
                } else {
                    logger::trace("epoch: {} instant reward: {} from treasury to a retired stake_id: {} - ignoring", _epoch, reward, stake_id);
                }
            }
        }

        void _transfer_instant_rewards()
        {
            timer t { fmt::format("validator::state epoch: {} transfer_instant_rewards", _epoch) };
            for (const auto &[stake_id, reward]: _instant_rewards_reserves) {
                if (_rewards.contains(stake_id)) {
                    _rewards.add(stake_id, reward);
                    auto deleg_it = _active_delegs.find(stake_id);
                    if (deleg_it != _active_delegs.end())
                        _active_pool_dist.add(deleg_it->second, reward);
                }
            }
            _instant_rewards_reserves.clear();
            for (const auto &[stake_id, reward]: _instant_rewards_treasury) {
                if (_rewards.contains(stake_id)) {
                    _rewards.add(stake_id, reward);
                    auto deleg_it = _active_delegs.find(stake_id);
                    if (deleg_it != _active_delegs.end())
                        _active_pool_dist.add(deleg_it->second, reward);
                }
            }
            _instant_rewards_treasury.clear();
        }

        std::pair<uint64_t, uint64_t> _retire_pools()
        {
            timer t { fmt::format("validator::state epoch: {} retire_pools", _epoch), logger::level::trace };
            uint64_t refunds_user = 0;
            uint64_t refunds_treasury = 0;
            for (auto it = _pools_retiring.begin(); it != _pools_retiring.end(); ) {
                if (_epoch >= it->second) {
                    const auto &pool_id = it->first;
                    const auto &pool_info = _active_pool_params.at(pool_id);
                    //logger::trace("epoch: {} returning the deposit of a retiring pool {} to {}", _epoch, it->first, pool_info.reward_id);
                    static constexpr int64_t pool_deposit = 500'000'000;
                    for (const auto &stake_id: _active_inv_delegs.at(pool_id))
                        _active_delegs.erase(stake_id);
                    _active_inv_delegs.erase(pool_id);
                    if (_rewards.contains(pool_info.reward_id)) {
                        _rewards.add(pool_info.reward_id, pool_deposit);
                        auto deleg_it = _active_delegs.find(pool_info.reward_id);
                        if (deleg_it != _active_delegs.end()) {
                            if (_active_pool_params.contains(deleg_it->second)) {
                                _active_pool_dist.add(deleg_it->second, pool_deposit);
                                refunds_user += pool_deposit;
                            }
                        }
                    } else {
                        logger::trace("epoch: {} can't return the deposit of a retiring pool {}, so it goes to the treasury", _epoch, it->first);
                        _treasury += pool_deposit;
                        refunds_treasury += pool_deposit;
                    }
                    _active_pool_dist.retire(it->first);
                    _active_pool_params.erase(pool_id);
                    it = _pools_retiring.erase(it);
                } else {
                    it++;
                }
            }
            return std::make_pair(refunds_user, refunds_treasury);
        }

        stake_distribution _filtered_stake_dist(const ledger_copy &ledg) const
        {
            stake_distribution sd {};
            for (const auto &[stake_id, pool_id]: ledg.delegs) {
                auto stake = ledg.stake_dist.get(stake_id) + ledg.reward_dist.get(stake_id);
                if (stake > 0)
                    sd.try_emplace(stake_id, stake);
            }
            return sd;
        }

        static const std::span<const std::pair<cardano::stake_ident, cardano::pool_hash>> _genesis_delegates()
        {
            static const array<std::pair<cardano::stake_ident, cardano::pool_hash>, 7> delegates {
                {
                    cardano::stake_ident { cardano::key_hash::from_hex("ad5463153dc3d24b9ff133e46136028bdc1edbb897f5a7cf1b37950c") },
                    cardano::pool_hash::from_hex("d9e5c76ad5ee778960804094a389f0b546b5c2b140a62f8ec43ea54d")
                },
                {
                    cardano::stake_ident { cardano::key_hash::from_hex("b9547b8a57656539a8d9bc42c008e38d9c8bd9c8adbb1e73ad529497") },
                    cardano::pool_hash::from_hex("855d6fc1e54274e331e34478eeac8d060b0b90c1f9e8a2b01167c048")
                },
                {
                    cardano::stake_ident { cardano::key_hash::from_hex("60baee25cbc90047e83fd01e1e57dc0b06d3d0cb150d0ab40bbfead1") },
                    cardano::pool_hash::from_hex("7f72a1826ae3b279782ab2bc582d0d2958de65bd86b2c4f82d8ba956")
                },
                {
                    cardano::stake_ident { cardano::key_hash::from_hex("f7b341c14cd58fca4195a9b278cce1ef402dc0e06deb77e543cd1757") },
                    cardano::pool_hash::from_hex("69ae12f9e45c0c9122356c8e624b1fbbed6c22a2e3b4358cf0cb5011")
                },
                {
                    cardano::stake_ident { cardano::key_hash::from_hex("162f94554ac8c225383a2248c245659eda870eaa82d0ef25fc7dcd82") },
                    cardano::pool_hash::from_hex("4485708022839a7b9b8b639a939c85ec0ed6999b5b6dc651b03c43f6")
                },
                {
                    cardano::stake_ident { cardano::key_hash::from_hex("2075a095b3c844a29c24317a94a643ab8e22d54a3a3a72a420260af6") },
                    cardano::pool_hash::from_hex("6535db26347283990a252313a7903a45e3526ec25ddba381c071b25b")
                },
                {
                    cardano::stake_ident { cardano::key_hash::from_hex("268cfc0b89e910ead22e0ade91493d8212f53f3e2164b2e4bef0819b") },
                    cardano::pool_hash::from_hex("1d4f2e1fda43070d71bb22a5522f86943c7c18aeb4fa47a362c27e23")
                }
            };
            return delegates;
        }

        static const std::set<cardano::pool_hash> &_genesis_pools()
        {
            static std::set<cardano::pool_hash> pools {};
            if (pools.empty()) {
                for (const auto &it: _genesis_delegates())
                    pools.emplace(it.second);
            }
            return pools;
        }
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::validator::reward_type>: public formatter<uint64_t> {
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
    struct formatter<daedalus_turbo::validator::reward_update>: public formatter<uint64_t> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            return fmt::format_to(ctx.out(), "reward_update(type: {} pool_id: {} amount: {})", v.type, v.pool_id, v.amount);
        }
    };
}

#endif // !DAEDALUS_TURBO_VALIDATOR_STATE_HPP