/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/atomic.hpp>
#include <dt/cardano/ledger/shelley.hpp>
#include <dt/cardano/ledger/updates.hpp>
#include <dt/cardano/shelley.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/timer.hpp>
#include <dt/zpp.hpp>

namespace daedalus_turbo::cardano::ledger::shelley {
    template<typename T>
        concept Clearable = requires(T a)
    {
        a.clear();
    };

    template<typename T>
    concept Sizable = requires(T a)
    {
        a.size();
    };

    vrf_state::vrf_state(const config &cfg):
        _cfg { cfg },
        _nonce_genesis { _cfg.shelley_genesis_hash },
        _max_epoch_slot { _cfg.shelley_epoch_length - _cfg.shelley_stability_window }
    {
        logger::debug("sheley::vrf_state created nonce_genesis: {} max_epoch_slot: {}", _nonce_genesis, _max_epoch_slot);
    }

    void vrf_state::from_cbor(const cbor::value &v)
    {
        const auto &raw = v.at(1);
        _slot_last = raw.at(0).at(1).uint();
        _kes_counters.clear();
        for (const auto &[pool_id, ctr]: raw.at(1).at(0).at(0).map()) {
            const auto [it, created] = _kes_counters.try_emplace(pool_id.buf(), ctr.uint());
            if (!created) [[unlikely]]
                throw error(fmt::format("duplicate kes counter reported for pool: {}", pool_id));
        }
        _nonce_evolving = raw.at(1).at(0).at(1).at(1).buf();
        _nonce_candidate = raw.at(1).at(0).at(2).at(1).buf();
        _nonce_epoch = raw.at(1).at(1).at(0).at(1).buf();
        _prev_epoch_lab_prev_hash.reset();
        if (raw.at(1).at(1).at(1).at(0).uint() == 1)
            _prev_epoch_lab_prev_hash = raw.at(1).at(1).at(1).at(1).buf();
        _lab_prev_hash = raw.at(1).at(2).at(1).buf();
    }

    void vrf_state::from_zpp(parallel_decoder &dec)
    {
        dec.add([&](const auto b) {
            zpp::deserialize(*this, b);
        });
    }

    void vrf_state::to_zpp(parallel_serializer &ser) const
    {
        ser.add([&] {
            return zpp::serialize(*this);
        });
    }

    void vrf_state::process_updates(const vector<index::vrf::item> &updates)
    {
        blake2b_256_hash nonce_block {};
        for (const auto &item: updates) {
            if (item.slot < _slot_last)
                throw error(fmt::format("got block with a slot number {} when last seed slot is : {}", item.slot, _slot_last));
            if (item.era < 6) {
                blake2b(nonce_block, item.nonce_result);
            } else {
                nonce_block = vrf_nonce_value(item.leader_result);
            }
            //logger::debug("VRF update slot: {} prev_evolving_nonce: {} prev_candidate_nonce: {} epoch_nonce: {} prev_lab_nonce: {}",
            //    item.slot, _nonce_evolving, _nonce_candidate, _nonce_epoch, _lab_prev_hash);
            const auto item_slot = cardano::slot { item.slot, _cfg };
            _nonce_evolving = vrf_nonce_accumulate(_nonce_evolving, nonce_block);
            if (item_slot.epoch_slot() < _max_epoch_slot)
                _nonce_candidate = _nonce_evolving;
            _lab_prev_hash = item.prev_hash;
            _slot_last = item.slot;
            //logger::debug("VRF update slot: {} eta: {} new nonce_evolving_nonce: {} new_lab_nonce: {} nonce_candidate: {}", item_slot, nonce_block, _nonce_evolving, _lab_prev_hash, _nonce_candidate);
            auto [kes_it, kes_created] = _kes_counters.try_emplace(item.pool_id, item.kes_counter);
            if (!kes_created) {
                if (item.kes_counter > kes_it->second)
                    kes_it->second = item.kes_counter;
                else if (item.kes_counter < kes_it->second)
                    throw error(fmt::format("slot: {} out of order KES counter {} < {} for pool: {}", item_slot, item.kes_counter, kes_it->second, item.pool_id));
            }
        }
    }

    void vrf_state::finish_epoch(const nonce &extra_entropy)
    {
        //logger::debug("vrf::state::finish_epoch: {}", extra_entropy);
        const auto prev_epoch_nonce = _nonce_epoch;
        if (_prev_epoch_lab_prev_hash) {
            if (extra_entropy) {
                _nonce_epoch = vrf_nonce_accumulate(vrf_nonce_accumulate(_nonce_candidate, *_prev_epoch_lab_prev_hash), extra_entropy.value());
            } else {
                _nonce_epoch = vrf_nonce_accumulate(_nonce_candidate, *_prev_epoch_lab_prev_hash);
            }
        } else {
            _nonce_epoch = _nonce_candidate;
        }
        logger::debug("VRF finish_epoch last_slot: {} prev nonce_epoch: {} new nonce_epoch: {} prev_lab_prev_hash: {} extra_entropy: {}",
            _slot_last, prev_epoch_nonce, _nonce_epoch, _prev_epoch_lab_prev_hash, extra_entropy);
        _nonce_candidate = _nonce_evolving;
        _prev_epoch_lab_prev_hash = _lab_prev_hash;
    }

    void vrf_state::to_cbor(parallel_serializer &ser) const
    {
        ser.add([&] {
            cbor::encoder enc {};
            enc.array(2)
                .uint(1)
                .array(2)
                    .array(2)
                        .uint(1)
                        .uint(_slot_last)
                    .array(3)
                        .array(3)
                            .custom([this] (auto &enc) {
                                enc.map(_kes_counters.size());
                                for (const auto &[pool_id, cnt]: _kes_counters) {
                                    enc.bytes(pool_id);
                                    enc.uint(cnt);
                                }
                            })
                            .array(2)
                                .uint(1)
                                .bytes(_nonce_evolving)
                            .array(2)
                                .uint(1)
                                .bytes(_nonce_candidate)
                        .array(2)
                            .array(2)
                                .uint(1)
                                .bytes(_nonce_epoch)
                            .custom([this](auto &enc) {
                                if (_prev_epoch_lab_prev_hash) {
                                    enc.array(2)
                                        .uint(1)
                                        .bytes(*_prev_epoch_lab_prev_hash);
                                } else {
                                    enc.array(1).uint(0);
                                }
                            })
                        .array(2)
                            .uint(1)
                            .bytes(_lab_prev_hash);
            return std::move(enc.cbor());
        });
    }

    uint8_vector vrf_state::cbor() const
    {
        parallel_serializer ser {};
        to_cbor(ser);
        ser.run(scheduler::get(), "vrf_state::to_cbor");
        return ser.flat();
    }

    state::state(const cardano::config &cfg, scheduler &sched):
        _cfg { cfg }, _sched { sched }, _utxo { _cfg.byron_utxos }
    {
    }

    void state::_add_encode_task(parallel_serializer &ser, const encode_cbor_func &t) const
    {
        ser.add([t] {
            cbor::encoder enc {};
            t(enc);
            return enc.cbor();
        });
    }

    void state::from_cbor(const cbor::value &v)
    {
        const auto &snap = v.at(1);
        _epoch = snap.at(0).uint();
        for (const auto &[pool_hash, block_count]: snap.at(1).map()) {
            _blocks_before.add(pool_hash.buf(), block_count.uint());
        }
        for (const auto &[pool_hash, block_count]: snap.at(2).map()) {
            _blocks_current.add(pool_hash.buf(), block_count.uint());
        }
        {
            const auto &state_before = snap.at(3);
            {
                const auto &accounts = state_before.at(0).array();
                _treasury = accounts.at(0).uint();
                _reserves = accounts.at(1).uint();
            }
            {
                const auto &lstate = state_before.at(1);
                _node_load_delegation_state(lstate.at(0));
                _node_load_utxo_state(lstate.at(1));
            }
            {
                const auto &snapshots = state_before.at(2).array();
                struct snapshot_copy {
                    size_t idx;
                    ledger_copy &dst_copy;
                };
                for (const auto &[idx, dst]: { snapshot_copy { 0, _mark }, snapshot_copy { 1, _set }, snapshot_copy { 2, _go } }) {
                    const auto &src = snapshots.at(idx).array();
                    const auto &stake = src.at(0).map();
                    for (const auto &[stake_id, coin]: stake) {
                        auto &acc = _accounts[cardano::stake_ident {stake_id.array().at(1).buf(), stake_id.array().at(0).uint() == 1 }];
                        acc.stake_copy(idx) = coin.uint();
                    }
                    for (const auto &[stake_id, pool_id]: src.at(1).map()) {
                        auto &acc = _accounts[cardano::stake_ident {stake_id.array().at(1).buf(), stake_id.array().at(0).uint() == 1 }];
                        acc.deleg_copy(idx) = pool_id.buf();
                    }
                    for (const auto &[id, params]: src.at(2).map()) {
                        dst.pool_params.try_emplace(id.buf(), params);
                    }
                }
                //_fees_next_reward = snapshots.at(3).uint();
            }
            for (const auto &[pool_id, c_likelihoods]: state_before.at(3).at(0).map()) {
                pool_rank::likelihood_list likelihoods {};
                likelihoods.reserve(c_likelihoods.array().size());
                for (const auto &c_like: c_likelihoods.array())
                    likelihoods.emplace_back(c_like.float32());
                _nonmyopic.try_emplace(pool_id.buf(), std::move(likelihoods));
            }
            _nonmyopic_reward_pot = state_before.at(3).at(1).uint();
        }
        if (const auto &possible_update_raw = snap.at(4).array(); !possible_update_raw.empty()) {
            if (possible_update_raw.at(0).at(0).uint() == 1) {
                const auto &possible_update = possible_update_raw.at(0).at(1).array();
                _delta_treasury = possible_update.at(0).uint();
                _delta_reserves = possible_update.at(1).uint();
                _delta_fees = possible_update.at(3).uint();
                for (const auto &[id, reward_list]: possible_update.at(2).map()) {
                    reward_update_list rl {};
                    for (const auto &reward: reward_list.array()) {
                        rl.emplace(reward.at(0).uint() == 0 ? reward_type::member : reward_type::leader, reward.at(1).buf(),  reward.at(2).uint());
                    }
                    _potential_rewards.try_emplace(cardano::stake_ident { id.array().at(1).buf(), id.array().at(0).uint() == 1 }, std::move(rl));
                }
                for (const auto &[pool_id, c_likelihoods]: possible_update.at(4).at(0).map()) {
                    pool_rank::likelihood_list likelihoods {};
                    likelihoods.reserve(c_likelihoods.array().size());
                    for (const auto &c_like: c_likelihoods.array())
                        likelihoods.emplace_back(c_like.float32());
                    _nonmyopic_next.try_emplace(pool_id.buf(), std::move(likelihoods));
                }
                _reward_pot = possible_update.at(4).at(1).uint();
            }
        }
        {
            for (const auto &[pool_id, info]: snap.at(5).at(0).map()) {
                _operating_stake_dist.try_emplace(pool_id.buf(), info.at(0).array(), info.at(1).buf());
            }
        }
        {
            // const auto &tbd = snap.at(6); NULL
        }
        _blocks_past_voting_deadline = v.at(2).uint();
        _pulsing_snapshot_slot = slot::from_epoch(_epoch, _cfg) + _cfg.shelley_randomness_stabilization_window;
        _recompute_caches();
    }

    bool state::operator==(const state &o) const
    {
        return typeid(*this) == typeid(o)
            && _end_offset == o._end_offset
            && _epoch_slot == o._epoch_slot
            && _pulsing_snapshot_slot == o._pulsing_snapshot_slot
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

    const set<key_hash> &state::genesis_signers() const
    {
        return _cfg.byron_delegate_hashes;
    }

    void state::register_pool(const pool_reg_cert &reg)
    {
        auto [it, created] = _active_pool_params.try_emplace(reg.pool_id, reg.params);
        if (created) {
            _pool_deposits[reg.pool_id] = _params.pool_deposit;
            _deposited += _params.pool_deposit;
        } else {
            auto [f_it, f_created] = _future_pool_params.try_emplace(reg.pool_id, reg.params);
            if (!f_created)
                f_it->second.params = reg.params;
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

    void state::retire_pool(const pool_hash &pool_id, uint64_t epoch)
    {
        if (_active_pool_params.contains(pool_id)) {
            _pools_retiring[pool_id] = epoch;
        } else {
            logger::warn("retirement of an unknown pool: {}", pool_id);
        }
    }

    bool state::has_pool(const pool_hash &id) const
    {
        return _active_pool_params.contains(id);
    }

    bool state::has_stake(const stake_ident &id) const
    {
        const auto acc_it = _accounts.find(id);
        return acc_it != _accounts.end() && acc_it->second.ptr;
    }

    bool state::has_drep(const credential_t &) const
    {
        return false;
    }

    void state::instant_reward_reserves(const stake_ident &stake_id, const uint64_t reward)
    {
        if (const auto prev_amount = _instant_rewards_reserves.get(stake_id); prev_amount > 0)
            _instant_rewards_reserves.sub(stake_id, prev_amount);
        _instant_rewards_reserves.add(stake_id, reward);
    }

    void state::instant_reward_treasury(const stake_ident &stake_id, const uint64_t reward)
    {

        if (const auto prev_amount = _instant_rewards_treasury.get(stake_id); prev_amount > 0)
            _instant_rewards_treasury.sub(stake_id, prev_amount);
        _instant_rewards_treasury.add(stake_id, reward);
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

    const tx_out_data *state::utxo_find(const tx_out_ref &txo_id)
    {
        if (const auto it = _utxo.find(txo_id);it != _utxo.end()) [[likely]]
            return &it->second;
        return nullptr;
    }

    void state::utxo_add(const cardano::tx_out_ref &txo_id, cardano::tx_out_data &&txo_data)
    {
        if (!txo_data.empty()) [[likely]] {
            auto [it, created] = _utxo.try_emplace(txo_id, std::move(txo_data));
            if (!created)
                logger::warn("a non-unique TXO {}!", it->first);
        }
    }

    void state::utxo_del(const cardano::tx_out_ref &txo_id)
    {
        if (const size_t num_del = _utxo.erase(txo_id); num_del != 1)
            throw error(fmt::format("request to remove an unknown TXO {}!", txo_id));
    }

    void state::_process_block_updates(block_update_list &&block_updates)
    {
        map<pool_hash, size_t> pool_blocks {};
        for (const auto &bu: block_updates) {
            add_fees(bu.fees);
            process_block(bu.end_offset, bu.slot);
            if (bu.era > 1)
                ++pool_blocks[bu.issuer_id];
        }
        for (const auto &[pool_id, num_blocks]: pool_blocks)
            add_pool_blocks(pool_id, num_blocks);
    }

    void state::process_cert(const cert_any_t &cert, const cert_loc_t &loc)
    {
        _tick(loc.slot);
        std::visit([&](const auto &c) {
            using T = std::decay_t<decltype(c)>;
            if constexpr (std::is_same_v<T, stake_reg_cert>
                    || std::is_same_v<T, stake_dereg_cert>
                    || std::is_same_v<T, stake_deleg_cert>
                    || std::is_same_v<T, pool_reg_cert>
                    || std::is_same_v<T, pool_retire_cert>
                    || std::is_same_v<T, genesis_deleg_cert>
                    || std::is_same_v<T, instant_reward_cert>) {
                process_cert(c, loc);
            } else {
                throw error(fmt::format("certificate type is not supported in shelley era: {}", typeid(T).name()));
            }
        }, cert.val);
    }

    void state::process_cert(const stake_reg_cert &c, const cert_loc_t &loc)
    {
        register_stake(loc.slot, c.stake_id, {}, loc.tx_idx, loc.cert_idx);
    }

    void state::process_cert(const stake_dereg_cert &c, const cert_loc_t &loc)
    {
        retire_stake(loc.slot, c.stake_id, {});
    }

    void state::process_cert(const stake_deleg_cert &c, const cert_loc_t &)
    {
        delegate_stake(c.stake_id, c.pool_id);
    }

    void state::process_cert(const pool_reg_cert &c, const cert_loc_t &)
    {
        register_pool(c);
    }

    void state::process_cert(const pool_retire_cert &c, const cert_loc_t &)
    {
        retire_pool(c.pool_id, c.epoch);
    }

    void state::process_cert(const genesis_deleg_cert &c, const cert_loc_t &)
    {
        genesis_deleg_update(c.hash, c.pool_id, c.vrf_vkey);
    }

    void state::process_cert(const instant_reward_cert &c, const cert_loc_t &)
    {
        for (const auto &[stake_id, coin]: c.rewards) {
            if (c.source == reward_source::reserves)
                instant_reward_reserves(stake_id, coin);
            else if (c.source == reward_source::treasury)
                instant_reward_treasury(stake_id, coin);
            else
                throw error(fmt::format("unsupported reward source: {}", static_cast<int>(c.source)));
        }
    }

    void state::_process_timed_update(tx_out_ref_list &collected_collateral, timed_update_t &&upd)
    {
        std::visit([&](const auto &u) {
            using T = std::decay_t<decltype(u)>;
            if constexpr (std::is_same_v<T, index::timed_update::stake_withdraw>) {
                withdraw_reward(u.stake_id, u.amount);
            } else if constexpr (std::is_same_v<T, param_update_proposal>) {
                propose_update(upd.loc.slot, u);
            } else if constexpr (std::is_same_v<T, param_update_vote>) {
                proposal_vote(upd.loc.slot, u);
            } else if constexpr (std::is_same_v<T, index::timed_update::collected_collateral_input>) {
                collected_collateral.emplace_back(u.tx_hash, u.txo_idx);
            } else if constexpr (std::is_same_v<T, index::timed_update::collected_collateral_refund>) {
                logger::debug("refunded fees from refunded collateral {}", u.refund);
                sub_fees(u.refund);
            } else if constexpr (std::is_same_v<T, stake_reg_cert>
                || std::is_same_v<T, stake_dereg_cert>
                || std::is_same_v<T, stake_deleg_cert>
                || std::is_same_v<T, pool_reg_cert>
                || std::is_same_v<T, pool_retire_cert>
                || std::is_same_v<T, genesis_deleg_cert>
                || std::is_same_v<T, instant_reward_cert>) {
                process_cert(cert_any_t { u }, upd.loc);
            } else {
                throw error(fmt::format("unsupported timed update: {}", typeid(u).name()));
            }
        }, upd.update);
    }

    tx_out_ref_list state::_process_timed_updates(timed_update_list &&timed_updates)
    {
        timer tp { fmt::format("validator epoch: {} process {} timed updates", _epoch, timed_updates.size()) };
        vector<tx_out_ref> collected_collateral {};
        for (auto &&upd: timed_updates) {
            _process_timed_update(collected_collateral, std::move(upd));
        }
        return collected_collateral;
    }

    void state::_process_utxo_updates(utxo_update_list &&utxo_updates)
    {
        const std::string task_group = fmt::format("ledger-state:apply-utxo-updates:epoch-{}", _epoch);
        alignas(mutex::padding) mutex::unique_lock::mutex_type all_mutex {};
        stake_update_map all_deltas {};
        pointer_update_map all_pointer_deltas {};
        _sched.wait_all_done(task_group, txo_map::num_parts,
            [&] {
                for (size_t part_idx = 0; part_idx < txo_map::num_parts; ++part_idx) {
                    _sched.submit_void(task_group, 1000, [this, part_idx, &utxo_updates, &all_mutex, &all_deltas, &all_pointer_deltas] {
                        stake_update_map deltas {};
                        pointer_update_map pointer_deltas {};
                        for (auto &&update_batch: utxo_updates) {
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
                                        throw error(fmt::format("request to remove an unknown TXO {}!", txo_id));
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

    void state::_process_collateral_use(tx_out_ref_list &&collected_collateral)
    {
        for (const auto &txo_id: collected_collateral) {
            const auto txo_data = utxo_find(txo_id);
            if (!txo_data) [[unlikely]]
                throw error(fmt::format("epoch {}: cannot find data about a TXO used as a collateral input: {}", _epoch, txo_id));
            logger::debug("fees from used collateral {}: {}", txo_id, txo_data->coin);
            add_fees(txo_data->coin);
            if (const address addr { txo_data->address }; addr.has_stake_id_hybrid()) [[likely]]
                update_stake_id_hybrid(addr.stake_id_hybrid(), -static_cast<int64_t>(txo_data->coin));
            utxo_del(txo_id);
        }
    }

    void state::process_updates(updates_t &&updates)
    {
        _process_block_updates(std::move(updates.blocks));
        auto collected_collateral = _process_timed_updates(std::move(updates.timed));
        _process_utxo_updates(std::move(updates.utxos));
        _process_collateral_use(std::move(collected_collateral));
        compute_rewards_if_ready();
    }

    void state::compute_rewards_if_ready()
    {
        if (_params.protocol_ver.major >= 2 && _epoch_slot >= _cfg.shelley_rewards_ready_slot && !_rewards_ready)
            _compute_rewards();
    }

    uint64_t state::utxo_balance() const
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

    void state::withdraw_reward(const stake_ident &stake_id, const uint64_t amount)
    {
        auto &acc = _accounts.at(stake_id);
        if (acc.reward < amount)
            throw error(fmt::format("trying to withdraw from account {} more stake {} than it has: {}", stake_id, amount, acc.reward));
        acc.reward -= amount;
        if (acc.deleg)
            _active_pool_dist.sub(*acc.deleg, amount);
    }

    void state::register_stake(const uint64_t slot, const stake_ident &stake_id, const std::optional<uint64_t> deposit, const size_t tx_idx, const size_t cert_idx)
    {
        const auto deposit_size = deposit ? *deposit : _params.key_deposit;
        auto [acc_it, acc_created] = _accounts.try_emplace(stake_id);
        if (acc_created || !acc_it->second.ptr) {
            _deposited += deposit_size;
            acc_it->second.deposit += deposit_size;
        }
        stake_pointer ptr { slot, tx_idx, cert_idx };
        _ptr_to_stake[ptr] = stake_id;
        acc_it->second.ptr = ptr;
    }

    void state::retire_stake(const uint64_t slot, const stake_ident &stake_id, const std::optional<uint64_t> deposit)
    {
        const auto deposit_size = deposit ? *deposit : _params.key_deposit;
        auto &acc = _accounts.at(stake_id);
        if (acc.ptr) {
            if (acc.deposit >= deposit_size) [[likely]]
                acc.deposit -= deposit_size;
            else
                throw error(fmt::format("expected stake deposit: {} is more than the actual one: {}", deposit_size, acc.deposit));
            if (_deposited >= deposit_size) [[likely]]
                _deposited -= deposit_size;
            else
                throw error("trying to remove a deposit while having insufficient deposits");
            _ptr_to_stake.erase(*acc.ptr);
            acc.ptr.reset();
        } else {
            logger::trace("slot: {}/{} can't find the retiring stake's pointer", _epoch, slot);
        }
        if (acc.deleg) {
            const auto stake = acc.stake + acc.reward;
            //logger::trace("epoch: {} retirement of {} - removing {} from pool {}", _epoch, stake_id, cardano::amount { stake }, deleg_it->second);
            _active_pool_dist.sub(*acc.deleg, stake);
            _active_inv_delegs.at(*acc.deleg).erase(stake_id);
        }
        _treasury += acc.reward;
        acc.reward = 0;
        acc.deleg.reset();
    }

    void state::delegate_stake(const stake_ident &stake_id, const pool_hash &pool_id)
    {
        if (!_active_pool_params.contains(pool_id))
            throw error(fmt::format("trying to delegate {} to an unknown pool: {}", stake_id, pool_id));
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

    void state::update_stake(const stake_ident &stake_id, const int64_t delta)
    {
        auto &acc = _accounts[stake_id];
        if (delta >= 0) {
            acc.stake += static_cast<uint64_t>(delta);
            if (acc.deleg && _active_pool_params.contains(*acc.deleg))
                _active_pool_dist.add(*acc.deleg, static_cast<uint64_t>(delta));
        } else {
            const uint64_t dec = static_cast<uint64_t>(-delta);
            if (acc.stake < dec)
                throw error(fmt::format("trying to remove from account {} more stake {} than it has: {}", stake_id, dec, acc.stake));
            acc.stake -= dec;
            if (acc.deleg && _active_pool_params.contains(*acc.deleg))
                _active_pool_dist.sub(*acc.deleg, static_cast<uint64_t>(-delta));
        }
    }

    void state::update_pointer(const cardano::stake_pointer &ptr, const int64_t delta)
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

    void state::update_stake_id_hybrid(const cardano::stake_ident_hybrid &stake_id, const int64_t delta)
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

    void state::proposal_vote(const uint64_t slot, const cardano::param_update_vote &vote)
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

    void state::propose_update(const uint64_t slot, const cardano::param_update_proposal &prop)
    {
        logger::debug("slot: {} proposal: {}", slot, prop);
        if (_params.protocol_ver.major >= 2) {
            if (!_cfg.shelley_delegates.contains(prop.pool_id))
                throw error(fmt::format("protocol update proposal from a key not in the shelley genesis delegate list: {}!", prop.pool_id));
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

    void state::add_pool_blocks(const cardano::pool_hash &pool_id, uint64_t num_blocks)
    {
        if (!_pbft_pools.contains(pool_id)) {
            if (_operating_stake_dist.contains(pool_id)) {
                _blocks_current.add(pool_id, num_blocks);
            } else {
                logger::warn("trying to provide the number of generated blocks in epoch {} for an unknown pool {} num_blocks: {}!", _epoch, pool_id, num_blocks);
            }
        }
    }

    void state::sub_fees(const uint64_t refund)
    {
        if (_fees_next_reward >= refund) [[likely]]
            _fees_next_reward -= refund;
        else
            throw error(fmt::format("insufficient fees_next_reward: {} to refund {}", _fees_next_reward, refund));
        if (_fees_utxo >= refund) [[likely]]
            _fees_utxo -= refund;
        else
            throw error(fmt::format("insufficient fees_utxo: {} to refund {}", _fees_utxo, refund));
    }

    void state::add_fees(const uint64_t amount)
    {
        _fees_next_reward += amount;
        _fees_utxo += amount;
    }

    const shelley_delegate_map &state::shelley_delegs() const
    {
        return _shelley_delegs;
    }

    void state::genesis_deleg_update(const cardano::key_hash &hash, const cardano::pool_hash &pool_id, const cardano::vrf_vkey &vrf_vkey)
    {
        if (auto it = _shelley_delegs.find(hash); it != _shelley_delegs.end()) [[likely]] {
            const auto [f_it, f_created] = _future_shelley_delegs.try_emplace(hash, pool_id, vrf_vkey);
            if (!f_created) {
                f_it->second.delegate = pool_id;
                f_it->second.vrf = vrf_vkey;
            }
        } else {
            throw error(fmt::format("an attempt to redelegate an unknown shelley genesis delegate {}", hash));
        }
    }

    void state::rotate_snapshots()
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
        if (_params.protocol_ver.keep_pointers()) {
            for (const auto &[stake_ptr, coin]: _stake_pointers) {
                if (const auto ptr_it = _ptr_to_stake.find(stake_ptr); ptr_it != _ptr_to_stake.end()) {
                    logger::debug("rotate_snapshots epoch: {} pointer {} adds: {} to stake_id: {}",
                        _epoch, stake_ptr, cardano::amount { coin }, ptr_it->second);
                    auto &acc = _accounts.at(ptr_it->second);
                    acc.mark_stake += coin;
                    if (acc.mark_deleg)
                        _mark.pool_dist.add(*acc.mark_deleg, coin);
                }
            }
        }
    }

    void state::start_epoch(std::optional<uint64_t> new_epoch)
    {
        if (!new_epoch) {
            // increment the epoch only if seen some data
            if (_end_offset)
                new_epoch = _epoch + 1;
            else
                new_epoch = 0;
        }
        if (*new_epoch < _epoch || *new_epoch > _epoch + 1)
            throw error(fmt::format("unexpected new epoch value: {} the current epoch: {}", *new_epoch, _epoch));;
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
            _pulsing_snapshot_slot = cardano::slot::from_epoch(_epoch, _cfg) + _cfg.shelley_randomness_stabilization_window;

            const auto [ refunds_user, refunds_treasury ] = _retire_pools();

            logger::debug("epoch {} start: treasury: {} reserves: {} user refunds: {} treasury refunds: {}",
                _epoch, cardano::amount { _treasury }, cardano::amount { _reserves },
                cardano::amount { refunds_user }, cardano::amount { refunds_treasury });
        }
    }

    void state::reserves(const uint64_t r)
    {
        logger::trace("epoch: {} override reserves with {} while {} currently, diff: {}",
            _epoch, r, _reserves, static_cast<int64_t>(_reserves) - static_cast<int64_t>(r));
        _reserves = r;
    }

    void state::treasury(uint64_t t)
    {
        logger::trace("epoch: {} override treasury with {} while {} currently, diff: {}",
            _epoch, t, _treasury, static_cast<int64_t>(_treasury) - static_cast<int64_t>(t));
        _treasury = t;
    }

    void state::process_block(const uint64_t end_offset, const uint64_t slot)
    {
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

    static void _apply_byron_params(cardano::protocol_params &p, const cardano::config &)
    {
        p.protocol_ver = { 0, 0 };
    }

    void state::_apply_shelley_params(protocol_params &p) const
    {
        const auto &shelley_params = _cfg.shelley_genesis.at("protocolParams").as_object();
        p.min_fee_a = json::value_to<uint64_t>(shelley_params.at("minFeeA"));
        p.min_fee_b = json::value_to<uint64_t>(shelley_params.at("minFeeB"));
        p.max_block_body_size = json::value_to<uint64_t>(shelley_params.at("maxBlockBodySize"));
        p.max_transaction_size = json::value_to<uint64_t>(shelley_params.at("maxTxSize"));
        p.max_block_header_size = json::value_to<uint64_t>(shelley_params.at("maxBlockHeaderSize"));
        p.key_deposit = json::value_to<uint64_t>(shelley_params.at("keyDeposit"));
        p.pool_deposit = json::value_to<uint64_t>(shelley_params.at("poolDeposit"));
        p.e_max = json::value_to<uint64_t>(shelley_params.at("eMax"));
        p.n_opt = json::value_to<uint64_t>(shelley_params.at("nOpt"));
        p.expansion_rate = rational_u64 { json::value_to<double>(shelley_params.at("rho")) };
        p.treasury_growth_rate = rational_u64 { json::value_to<double>(shelley_params.at("tau")) };
        p.pool_pledge_influence = rational_u64 { json::value_to<double>(shelley_params.at("a0")) };
        p.decentralization = rational_u64 { json::value_to<double>(shelley_params.at("decentralisationParam")) };
        p.min_utxo_value = json::value_to<uint64_t>(shelley_params.at("minUTxOValue"));
        p.min_pool_cost = json::value_to<uint64_t>(shelley_params.at("minPoolCost"));
    }

    protocol_params state::_default_params(const cardano::config &cfg)
    {
        protocol_params p {};
        _apply_byron_params(p, cfg);
        return p;
    }

    set<pool_hash> state::_make_pbft_pools(const shelley_delegate_map &delegs)
    {
        set<pool_hash> pools {};
        for (const auto &[id, meta]: delegs)
            pools.emplace(meta.delegate);
        return pools;
    }

    uint8_vector state::_parse_address(const buffer buf)
    {
        address addr { buf };
        if (addr.bytes()[0] == 0x82)
            return cbor::parse(addr.bytes()).at(0).tag().second->buf();
        return buf;
    }

    void state::_parse_protocol_params(protocol_params &params, const cbor_value &val) const
    {
        _apply_shelley_params(params);
        params.min_fee_a = val.at(0).uint();
        params.min_fee_b = val.at(1).uint();
        params.max_block_body_size = val.at(2).uint();
        params.max_transaction_size = val.at(3).uint();
        params.max_block_header_size = val.at(4).uint();
        params.key_deposit = val.at(5).uint();
        params.pool_deposit = val.at(6).uint();
        params.e_max = val.at(7).uint();
        params.n_opt = val.at(8).uint();
        params.pool_pledge_influence = rational_u64 { val.at(9) };
        params.expansion_rate = rational_u64 { val.at(10) };
        params.treasury_growth_rate = rational_u64 { val.at(11) };
        params.decentralization = rational_u64 { val.at(12) };
        switch (val.at(13).at(0).uint()) {
            case 0: params.extra_entropy.reset(); break;
            case 1: params.extra_entropy.emplace(val.at(13).at(1).buf()); break;
            default: throw error(fmt::format("unexpected value for extra_entropy: {}", val.at(13)));
        }
        params.protocol_ver.major = val.at(14).uint();
        params.protocol_ver.minor = val.at(15).uint();
        params.min_utxo_value = val.at(16).uint();
    }

    static void _parse_assets(cardano::tx_out_data &data, const cardano::tx_out_ref &id, const cbor_value &val)
    {
        switch (val.type) {
            case CBOR_UINT:
                data.coin = val.uint();
            break;
            case CBOR_ARRAY:
                data.coin = val.at(0).uint();
            data.assets.emplace(val.at(1).raw_span());
            break;
            default:
                throw error(fmt::format("unexpected type of txo_data amount: {} in {}", val, id));
        }
    }

    static cardano::stake_ident _parse_stake_ident(const cbor_value &id)
    {
        return { id.at(1).buf(), id.at(0).uint() == 1 };
    }

    uint64_t state::_retire_avvm_balance()
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

    std::optional<cardano::stake_ident> state::_extract_stake_id(const cardano::address &addr) const
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

    void state::_prep_op_stake_dist()
    {
        _operating_stake_dist.clear();
        for (const auto &[pool_id, coin]: _set.pool_dist) {
            if (!_set.inv_delegs.at(pool_id).empty()) {
                const auto &params = _set.pool_params.at(pool_id).params;
                rational_u64 rel_stake { coin, _set.pool_dist.total_stake() };
                rel_stake.normalize();
                _operating_stake_dist.try_emplace(pool_id, std::move(rel_stake), params.vrf_vkey);
            }
        }
    }

    void state::_apply_future_pool_params()
    {
        for (auto &&[pool_id, params]: _future_pool_params) {
            _active_pool_params.at(pool_id) = std::move(params);
        }
        _future_pool_params.clear();
    }

    void state::_recompute_caches() const
    {
        _pbft_pools = _make_pbft_pools(_shelley_delegs);
    }

    uint64_t state::_total_stake(uint64_t reserves) const
    {
        return _cfg.shelley_max_lovelace_supply - reserves;
    }

    void state::_compute_rewards()
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

    void state::_rewards_prepare_pool_params(uint64_t &total, uint64_t &filtered, const double z0,
        const uint64_t staking_reward_pot, const uint64_t total_stake, const pool_hash &pool_id,
        pool_info &info, const uint64_t pool_blocks)
    {
        const uint64_t pool_stake = _go.pool_dist.get(pool_id);
        uint64_t pool_reward_pot = 0;
        if (pool_stake > 0) {
            uint64_t leader_reward = 0;
            uint64_t owner_stake = 0;
            for (const auto &stake_id: info.params.owners) {
                if (const auto acc_it = _accounts.find(stake_id); acc_it != _accounts.end() && acc_it->second.go_deleg && *acc_it->second.go_deleg == pool_id)
                    owner_stake += acc_it->second.go_stake;
            }
            if (owner_stake >= info.params.pledge) {
                double pool_rel_total_stake = static_cast<double>(pool_stake) / std::max(static_cast<uint64_t>(1), total_stake);
                double sigma_mark = std::min(pool_rel_total_stake, z0);
                double pool_rel_active_stake = static_cast<double>(pool_stake) / std::max(static_cast<uint64_t>(1), _go.pool_dist.total_stake());
                double pledge_rel_total_stake = static_cast<double>(info.params.pledge) / std::max(static_cast<uint64_t>(1), total_stake);
                if (pool_rel_total_stake < pledge_rel_total_stake)
                    throw error(fmt::format("internal error: pledged stake: {} of pool {} is larger than the pool's total stake: {}", info.params.pledge, pool_id, pool_stake));
                double s_mark = std::min(pledge_rel_total_stake, z0);
                uint64_t optimal_reward = static_cast<uint64_t>(staking_reward_pot / (1 + _params_prev.pool_pledge_influence.as_r()) *
                    (sigma_mark + s_mark * _params_prev.pool_pledge_influence.as_r() * (sigma_mark - s_mark * (z0 - sigma_mark) / (z0)) / z0));
                pool_reward_pot = optimal_reward;
                double beta = static_cast<double>(pool_blocks) / std::max(static_cast<uint64_t>(1), _blocks_before.total_stake());
                double pool_performance = pool_rel_active_stake != 0 ? beta / pool_rel_active_stake : 0;
                if (_params_prev.decentralization.as_r() < _params_prev.decentralizationThreshold.as_r())
                    pool_reward_pot = optimal_reward * pool_performance;
                if (pool_reward_pot > info.params.cost && owner_stake < pool_stake) {
                    auto pool_margin = info.params.margin.as_r();
                    info.member_reward_base = (pool_reward_pot - info.params.cost) * (1 - pool_margin) / pool_stake;
                    leader_reward = static_cast<uint64_t>(info.params.cost + (pool_reward_pot - info.params.cost) * (pool_margin + (1 - pool_margin) * owner_stake / pool_stake));
                } else {
                    leader_reward = pool_reward_pot;
                }
            }
            const bool leader_active = _params_prev.protocol_ver.forgo_reward_prefilter() || _reward_pulsing_snapshot.contains(info.params.reward_id);
            if (leader_active) {
                auto &reward_list = _potential_rewards[info.params.reward_id];
                total += leader_reward;
                if (!reward_list.empty())
                    filtered -= reward_list.begin()->amount;
                if (const auto acc_it = _accounts.find(info.params.reward_id); acc_it != _accounts.end() && acc_it->second.deleg)
                    reward_list.emplace(reward_type::leader, pool_id, leader_reward, *acc_it->second.deleg);
                else
                    reward_list.emplace(reward_type::leader, pool_id, leader_reward);
                filtered += reward_list.begin()->amount;
            }
        }
    }

    std::pair<uint64_t, uint64_t> state::_rewards_prepare_pools(const pool_block_dist &pools_active, const uint64_t staking_reward_pot, const uint64_t total_stake)
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

    std::pair<uint64_t, uint64_t> state::_rewards_compute_part(const size_t part_idx)
    {
        uint64_t total = 0;
        uint64_t filtered = 0;
        auto &part = _potential_rewards.partition(part_idx);
        const auto &acc_part = _accounts.partition(part_idx);
        for (const auto &[stake_id, acc]: acc_part) {
            if (acc.go_deleg) {
                const auto &pool_info = _go.pool_params.at(*acc.go_deleg);
                if (std::find(pool_info.params.owners.begin(), pool_info.params.owners.end(), stake_id) == pool_info.params.owners.end()) {
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

    uint64_t state::_compute_pool_rewards_parallel(const pool_block_dist &pools_active, const uint64_t staking_reward_pot, const uint64_t total_stake)
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

    void state::_clean_old_epoch_data()
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

    void state::_apply_param_update(const param_update &update)
    {
        if (update.protocol_ver) {
            if (update.protocol_ver->major >= 2 && _params.protocol_ver.major < 2) {
                {
                    const auto utxo_bal = utxo_balance();
                    if (utxo_bal > _cfg.shelley_max_lovelace_supply)
                        throw error(fmt::format("utxo balance: {} is larger than the total ADA supply: {}",
                            cardano::amount { utxo_bal }, cardano::amount { _cfg.shelley_max_lovelace_supply }));
                    _reserves = _cfg.shelley_max_lovelace_supply - utxo_bal;
                }
                // remove empty UTXO entries
                static const std::string task_name { "shelley-remove-empty-utxos" };
                _sched.wait_all_done(task_name, txo_map::num_parts,
                    [&] {
                        for (size_t part_idx = 0; part_idx < txo_map::num_parts; ++part_idx) {
                            _sched.submit_void(task_name, 1000, [this, part_idx] {
                                auto &utxo_part = _utxo.partition(part_idx);
                                for (auto it = utxo_part.begin(); it != utxo_part.end();) {
                                    if (it->second.coin) [[likely]] {
                                        ++it;
                                    } else {
                                        logger::debug("removed empty UTXO {}", it->first);
                                        it = utxo_part.erase(it);
                                    }
                                }
                            });
                        }
                    }
                );
                _apply_shelley_params(_params);
                _apply_shelley_params(_params_prev);
                _params_prev.protocol_ver = *update.protocol_ver;
            }
            if (update.protocol_ver->major >= 3 &&  _params.protocol_ver.major < 3) {
                const auto unspent_avvm = _retire_avvm_balance();
                _reserves += unspent_avvm;
                logger::info("retired {} in unclaimed AVVM vouchers", cardano::amount { unspent_avvm });
            }
        }
        const auto update_desc = _params.apply(update);
        logger::info("epoch: {} protocol params update: [ {}]", _epoch, update_desc);
    }

    std::optional<param_update> state::_prep_param_update() const
    {
        std::optional<param_update> update {};
        {
            std::unordered_map<param_update, size_t> votes {};
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
        return update;
    }

    protocol_params state::_apply_param_updates()
    {
        auto orig_params_prev = std::move(_params_prev);
        _params_prev = _params;
        if (const auto update = _prep_param_update(); update)
            _apply_param_update(*update);
        _ppups = std::move(_ppups_future);
        _ppups_future.clear();
        return orig_params_prev;
    }

    void state::_tick(const uint64_t slot)
    {
        if (_params.protocol_ver.major >= 2) {
            if (!_params_prev.protocol_ver.forgo_reward_prefilter() && slot > _pulsing_snapshot_slot) {
                if (_reward_pulsing_snapshot.empty() && !_accounts.empty()) {
                    timer t { fmt::format("epoch: {} create a pulsing snapshot of reward accounts", _epoch), logger::level::debug };
                    _reward_pulsing_snapshot.reserve(_accounts.size());
                    for (const auto &[stake_id, acc]: _accounts) {
                        if (acc.ptr)
                            _reward_pulsing_snapshot.emplace_back(stake_id, acc.reward);
                    }
                }
            }
        }
    }

    void state::_transfer_potential_rewards(const cardano::protocol_params &params_prev)
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

    uint64_t state::_transfer_instant_rewards(stake_distribution &rewards)
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

    std::pair<uint64_t, uint64_t> state::_retire_pools()
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
                if (auto acc_it = _accounts.find(pool_info.params.reward_id); acc_it != _accounts.end() && acc_it->second.ptr) {
                    acc_it->second.reward += pool_deposit;
                    if (const auto rew_acc_it = _accounts.find(pool_info.params.reward_id); rew_acc_it != _accounts.end() && rew_acc_it->second.deleg) {
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

    void state::_node_load_delegation_state(const cbor::value &s)
    {
        {
            const auto &dstate = s.at(2).array();
            for (const auto &[id, cred]: dstate.at(0).at(0).map()) {
                const cardano::stake_ident stake_id = _parse_stake_ident(id);
                // credential.deposit 0.1
                auto &acc = _accounts[stake_id];
                acc.reward = cred.at(0).at(0).at(0).uint();
                acc.deposit = cred.at(0).at(0).at(1).uint();
                const auto &cred_ptr = cred.at(1).at(0).array();
                cardano::stake_pointer stake_ptr { cred_ptr.at(0).uint(), cred_ptr.at(1).uint(), cred_ptr.at(2).uint() };
                acc.ptr = stake_ptr;
                _ptr_to_stake.try_emplace(stake_ptr, stake_id);
                const auto &deleg_ptr = cred.at(2).array();
                if (!deleg_ptr.empty())
                    _accounts[stake_id].deleg = deleg_ptr.at(0).buf();
            }
            // pointers - contains a reverse map already read
            for (const auto &[id, meta]: dstate.at(1).map()) {
                _future_shelley_delegs[id.buf()] = cardano::shelley_delegate {
                    meta.at(0).buf(),
                    meta.at(1).buf()
                };
            }
            for (const auto &[id, meta]: dstate.at(2).map()) {
                _shelley_delegs[id.buf()] = cardano::shelley_delegate {
                    meta.at(0).buf(),
                    meta.at(1).buf()
                };
            }
            for (const auto &[id, coin]: dstate.at(3).at(0).map()) {
                _instant_rewards_reserves.try_emplace(_parse_stake_ident(id), coin.uint());
            }
            for (const auto &[id, coin]: dstate.at(3).at(1).map()) {
                _instant_rewards_treasury.try_emplace(_parse_stake_ident(id), coin.uint());
            }
        }
        {
            const auto &pstate = s.at(1).array();
            for (const auto &[id, params]: pstate.at(0).map()) {
                _active_pool_params.try_emplace(id.buf(), params);
            }
            for (const auto &[id, params]: pstate.at(1).map()) {
                _future_pool_params[id.buf()] = pool_info { params };
            }
            for (const auto &[id, epoch]: pstate.at(2).map()) {
                _pools_retiring.try_emplace(id.buf(), epoch.uint());
            }
            for (const auto &[id, deposit]: pstate.at(3).map()) {
                const cardano::pool_hash pool_id = id.buf();
                _pool_deposits[pool_id] = deposit.uint();
            }
        }
    }

    param_update state::_parse_param_update(const cbor::value &proposal) const
    {
        param_update upd = cardano::shelley::parse_shelley_param_update(proposal);
        upd.rehash();
        return upd;
    }

    void state::_node_load_utxo_state(const cbor::value &utxo_state)
    {
        _utxo.clear();
        for (const auto &[txo_id, txo_data]: utxo_state.at(0).map()) {
            tx_out_ref id { txo_id.at(0).buf(), txo_id.at(1).uint() };
            tx_out_data data {};
            switch (txo_data.type) {
                case CBOR_ARRAY:
                    data.address = _parse_address(txo_data.at(0).buf());
                    _parse_assets(data, id, txo_data.at(1));
                    if (txo_data.array().size() > 2)
                        data.datum.emplace(datum_hash { txo_data.at(2).buf() });
                    break;
                case CBOR_MAP:
                    for (const auto &[val_id, val]: txo_data.map()) {
                        switch (val_id.uint()) {
                            case 0:
                                data.address = _parse_address(val.buf());
                                break;
                            case 1:
                                _parse_assets(data, id, val);
                                break;
                            case 2:
                                switch (val.at(0).uint()) {
                                    case 0:
                                        data.datum.emplace(datum_hash { val.at(1).buf() });
                                        break;
                                    case 1:
                                        data.datum.emplace(uint8_vector { val.at(1).tag().second->buf() });
                                        break;
                                    default:
                                        throw error(fmt::format("unexpected format of datum_option in {}: {}", id, val));
                                }
                                break;
                            case 3:
                                data.script_ref.emplace(val.tag().second->buf());
                                break;
                            default:
                                throw error(fmt::format("unexpected value of txo_data map {} in {} {}", val_id, id, txo_data));
                        }
                    }
                    break;
                default:
                    throw error(fmt::format("unexpected txo_data value: {}", txo_data));
            }
            utxo_add(id, std::move(data));
        }
        _deposited = utxo_state.at(1).uint();
        _fees_utxo = utxo_state.at(2).uint();
        for (const auto &[gen_deleg_id, proposal]: utxo_state.at(3).at(0).map()) {
            _ppups[gen_deleg_id.buf()] = _parse_param_update(proposal);
        }
        for (const auto &[gen_deleg_id, proposal]: utxo_state.at(3).at(1).map()) {
            _ppups_future[gen_deleg_id.buf()] = _parse_param_update(proposal);
        }
        _parse_protocol_params(_params, utxo_state.at(3).at(2));
        _parse_protocol_params(_params_prev, utxo_state.at(3).at(3));
        for (const auto &[id_raw, coin]: utxo_state.at(4).at(0).map()) {
            _accounts[_parse_stake_ident(id_raw)].stake = coin.uint();
        }
        for (const auto &[ptr_raw, coin]: utxo_state.at(4).at(1).map()) {
            _stake_pointers.try_emplace(ptr_raw, coin.uint());
        }
    }

    void state::_params_to_cbor(cbor::encoder &enc, const protocol_params &params) const
    {
        enc.array(18);
        enc.uint(params.min_fee_a);
        enc.uint(params.min_fee_b);
        enc.uint(params.max_block_body_size);
        enc.uint(params.max_transaction_size);
        enc.uint(params.max_block_header_size);
        enc.uint(params.key_deposit);
        enc.uint(params.pool_deposit);
        enc.uint(params.e_max);
        enc.uint(params.n_opt);
        enc.rational(params.pool_pledge_influence);
        enc.rational(params.expansion_rate);
        enc.rational(params.treasury_growth_rate);
        enc.rational(params.decentralization);
        if (!params.extra_entropy)
            enc.array(1).uint(0);
        else
            enc.array(2).uint(1).bytes(*params.extra_entropy);
        enc.uint(params.protocol_ver.major);
        enc.uint(params.protocol_ver.minor);
        enc.uint(params.min_utxo_value);
        enc.uint(params.min_pool_cost);
    }

    size_t state::_param_to_cbor(cbor::encoder &enc, const size_t idx, const std::optional<rational_u64> &val)
    {
        if (val) {
            enc.uint(idx);
            enc.rational(*val);
            return 1;
        }
        return 0;
    }

    size_t state::_param_update_common_to_cbor(cbor::encoder &enc, const param_update &upd)
    {
        size_t cnt = 0;
        cnt += _param_to_cbor(enc, 0, upd.min_fee_a);
        cnt += _param_to_cbor(enc, 1, upd.min_fee_b);
        cnt += _param_to_cbor(enc, 2, upd.max_block_body_size);
        cnt += _param_to_cbor(enc, 3, upd.max_transaction_size);
        cnt += _param_to_cbor(enc, 4, upd.max_block_header_size);
        cnt += _param_to_cbor(enc, 5, upd.key_deposit);
        cnt += _param_to_cbor(enc, 6, upd.pool_deposit);
        cnt += _param_to_cbor(enc, 7, upd.e_max);
        cnt += _param_to_cbor(enc, 8, upd.n_opt);
        cnt += _param_to_cbor(enc, 9, upd.pool_pledge_influence);
        cnt += _param_to_cbor(enc, 10, upd.expansion_rate);
        cnt += _param_to_cbor(enc, 11, upd.treasury_growth_rate);
        cnt += _param_to_cbor(enc, 12, upd.decentralization);
        if (upd.extra_entropy) {
            ++cnt;
            enc.uint(13);
            if (*upd.extra_entropy) {
                enc.array(2);
                enc.uint(1);
                enc.bytes(*(*upd.extra_entropy));
            } else {
                enc.array(1);
                enc.uint(0);
            }
        }
        if (upd.protocol_ver) {
            ++cnt;
            enc.uint(14);
            enc.array(2).uint(upd.protocol_ver->major).uint(upd.protocol_ver->minor);
        }
        return cnt;
    }

    void state::_param_update_to_cbor(cbor::encoder &enc, const param_update &upd) const
    {
        cbor::encoder my_enc {};
        size_t cnt = _param_update_common_to_cbor(my_enc, upd);
        cnt += _param_to_cbor(my_enc, 15, upd.min_utxo_value);
        enc.map(cnt);
        enc << my_enc;
    }

    void state::_node_save_snapshots(parallel_serializer &ser) const
    {
        const vector<std::reference_wrapper<const ledger_copy>> snaps { _mark, _set, _go };
        _add_encode_task(ser, [snaps] (auto &enc) {
            enc.array(snaps.size() + 1);
        });
        for (size_t idx = 0; idx < snaps.size(); ++idx) {
            const auto &snap = snaps.at(idx).get();
            _add_encode_task(ser, [this, snap, idx] (auto &enc) {
                enc.array(3);
                // Only the stake of delegated stake_ids is of interest
                size_t num_delegs = 0;
                cbor::encoder enc_deleg_s {}, enc_deleg_k {}, enc_stake_s {}, enc_stake_k {};
                for (const auto &[stake_id, acc]: _accounts) {
                    const auto &deleg = acc.deleg_copy(idx);
                    if (deleg) {
                        ++num_delegs;
                        {
                            auto &i_enc = stake_id.script ? enc_stake_s : enc_stake_k;
                            stake_id.to_cbor(i_enc);
                            i_enc.uint(acc.stake_copy(idx));
                        }
                        {
                            auto &i_enc = stake_id.script ? enc_deleg_s : enc_deleg_k;
                            stake_id.to_cbor(i_enc);
                            i_enc.bytes(*deleg);
                        }
                    }
                }
                enc.map_compact(num_delegs, [&] {
                    enc << enc_stake_s << enc_stake_k;
                });
                enc.map_compact(num_delegs, [&] {
                    enc << enc_deleg_s << enc_deleg_k;
                });
                enc.map_compact(snap.pool_params.size(), [&] {
                    for (const auto &[pool_id, params]: snap.pool_params) {
                        enc.bytes(pool_id);
                        params.params.to_cbor(enc, pool_id);
                    }
                });
            });
        }
        _add_encode_task(ser, [this] (auto &enc) {
            enc.uint(_delta_fees);
        });
    }

    void state::_node_save_ledger_delegation(parallel_serializer &ser) const
    {
        _add_encode_task(ser, [this] (auto &enc) {
            enc.array(3);
            // unidentified - always empty??
            enc.array(3).map(0).map(0).uint(0);
            // poolState
            enc.array(4);
            enc.map_compact(_active_pool_params.size(), [&] {
                for (const auto &[pool_id, info]: _active_pool_params) {
                    enc.bytes(pool_id);
                    info.params.to_cbor(enc, pool_id);
                }
            });
            enc.map_compact(_future_pool_params.size(), [&] {
                for (const auto &[pool_id, info]: _future_pool_params) {
                    enc.bytes(pool_id);
                    info.params.to_cbor(enc, pool_id);
                }
            });
            enc.map_compact(_pools_retiring.size(), [&] {
                for (const auto &[pool_id, epoch]: _pools_retiring) {
                    enc.bytes(pool_id);
                    enc.uint(epoch);
                }
            });
            enc.map_compact(_pool_deposits.size(), [&] {
                for (const auto &[pool_id, coin]: _pool_deposits) {
                    enc.bytes(pool_id);
                    enc.uint(coin);
                }
            });

        });
        _add_encode_task(ser, [this] (auto &enc) {
            // delegationState
            enc.array(4);
            enc.array(2);
            cbor::encoder s_enc {}, k_enc {};
            size_t num_creds = 0;
            for (const auto &[stake_id, acc]: _accounts) {
                if (acc.ptr) {
                    ++num_creds;
                    auto &i_enc = stake_id.script ? s_enc : k_enc;
                    stake_id.to_cbor(i_enc);
                    i_enc.array(4);
                    i_enc.array(1).array(2).uint(acc.reward).uint(acc.deposit);
                    i_enc.array(1);
                    acc.ptr->to_cbor(i_enc);
                    if (acc.deleg) {
                        i_enc.array(1).bytes(*acc.deleg);
                    } else {
                        i_enc.array(0);
                    }
                    // DRep
                    i_enc.array(0);
                }
            }
            enc.map_compact(num_creds, [&] {
                enc << s_enc << k_enc;
            });
        });
        _add_encode_task(ser, [this] (auto &enc) {
            enc.map_compact(_ptr_to_stake.size(), [&] {
                for (const auto &[ptr, stake_id]: _ptr_to_stake) {
                    ptr.to_cbor(enc);
                    stake_id.to_cbor(enc);
                }
            });
        });
        _add_encode_task(ser, [this] (auto &enc) {
            enc.map_compact(_future_shelley_delegs.size(), [&] {
                for (const auto &[key_hash, info]: _future_shelley_delegs) {
                    enc.bytes(key_hash);
                    enc.array(2).bytes(info.delegate).bytes(info.vrf);
                }
            });
            enc.map_compact(_shelley_delegs.size(), [&] {
                for (const auto &[key_hash, info]: _shelley_delegs) {
                    enc.bytes(key_hash);
                    enc.array(2).bytes(info.delegate).bytes(info.vrf);
                }
            });
            // irwd
            enc.array(4);
            enc.map_compact(_instant_rewards_reserves.size(), [&] {
                for (const auto &[stake_id, coin]: _instant_rewards_reserves) {
                    stake_id.to_cbor(enc);
                    enc.uint(coin);
                }
            });
            enc.map_compact(_instant_rewards_treasury.size(), [&] {
                for (const auto &[stake_id, coin]: _instant_rewards_treasury) {
                    stake_id.to_cbor(enc);
                    enc.uint(coin);
                }
            });
            enc.uint(0);
            enc.uint(0);
        });
    }

    void state::_protocol_state_to_cbor(cbor::encoder &enc) const
    {
        enc.array(5);
        enc.map(_ppups.size());
        for (const auto &[gen_deleg_id, proposal]: _ppups) {
            enc.bytes(gen_deleg_id);
            _param_update_to_cbor(enc, proposal);
        }
        enc.map(_ppups_future.size());
        for (const auto &[gen_deleg_id, proposal]: _ppups_future) {
            enc.bytes(gen_deleg_id);
            _param_update_to_cbor(enc, proposal);
        }
        _params_to_cbor(enc, _params);
        _params_to_cbor(enc, _params_prev);
        // new in node 9+ - expected update next epoch?
        {
            const auto update = _prep_param_update();
            if (update) {
                enc.array(2);
                enc.uint(1);
                auto new_params = _params;
                new_params.apply(*update);
                _params_to_cbor(enc, new_params);
            } else {
                enc.array(0);
            }
        }
    }

    void state::_stake_pointers_to_cbor(cbor::encoder &enc) const
    {
        enc.map_compact(_stake_pointers.size(), [&] {
            for (const auto &[ptr, coin]: _stake_pointers) {
                ptr.to_cbor(enc);
                enc.uint(coin);
            }
        });
    }

    void state::_donations_to_cbor(cbor::encoder &enc) const
    {
        enc.uint(0);
    }

    void state::_node_save_ledger_utxo(parallel_serializer &ser) const
    {
        _add_encode_task(ser, [](auto &enc) {
            enc.array(6);
            enc.map();
        });
        for (size_t pi = 0; pi < _utxo.num_parts; ++pi) {
            _add_encode_task(ser, [this, pi](auto &enc) {
                const auto &part = _utxo.partition(pi);
                for (const auto &[txo_id, txo_data]: part) {
                    enc.array(2)
                        .bytes(txo_id.hash)
                        .uint(txo_id.idx);
                    txo_data.to_cbor(enc);
                }
            });
        }
        _add_encode_task(ser, [this] (auto &enc) {
            enc.s_break();
            enc.uint(_deposited);
            enc.uint(_fees_utxo);
            _protocol_state_to_cbor(enc);
        });
        _add_encode_task(ser, [this] (auto &enc) {
            enc.array(2);
            // Cardano Node puts script keys first, so mimic that
            cbor::encoder s_enc {};
            cbor::encoder k_enc {};
            size_t num_accounts = 0;
            for (const auto &[stake_id, acc]: _accounts) {
                if (acc.stake) {
                    ++num_accounts;
                    auto &i_enc = stake_id.script ? s_enc : k_enc;
                    stake_id.to_cbor(i_enc);
                    i_enc.uint(acc.stake);
                }
            }
            enc.map_compact(num_accounts, [&] {
                enc << s_enc << k_enc;
            });
        });
        _add_encode_task(ser, [this] (auto &enc) {
            _stake_pointers_to_cbor(enc);
            _donations_to_cbor(enc);
        });
    }

    void state::_node_save_ledger(parallel_serializer &ser) const
    {
        _add_encode_task(ser, [](auto &enc) {
            enc.array(2);
        });
        _node_save_ledger_delegation(ser);
        _node_save_ledger_utxo(ser);
    }

    void state::_node_save_state_before(parallel_serializer &ser) const
    {
        _add_encode_task(ser, [this] (auto &enc) {
            enc.array(4);
            // esAccountState
            enc.array(2).uint(_treasury).uint(_reserves);
        });
        // esLState
        _node_save_ledger(ser);
        // esSnapshots
        _node_save_snapshots(ser);
        // esNonmyopic
        _add_encode_task(ser, [this] (auto &enc) {
            enc.array(2);
            enc.map_compact(_nonmyopic.size(), [&] {
                for (const auto &[pool_id, lks]: _nonmyopic) {
                    enc.bytes(pool_id);
                    enc.array_compact(lks.size(), [&] {
                        for (const auto l: lks)
                            enc.float32(l);
                    });
                }
            });
            enc.uint(_nonmyopic_reward_pot);
        });
    }

    uint8_vector state::cbor() const
    {
        parallel_serializer ser {};
        to_cbor(ser);
        ser.run(scheduler::get(), "state::to_cbor");
        return ser.flat();
    }

    void state::_stake_distrib_to_cbor(cbor::encoder &enc) const
    {
        enc.array(2);
        enc.map_compact(_operating_stake_dist.size(), [&] {
            for (const auto &[pool_id, op_info]: _operating_stake_dist) {
                enc.bytes(pool_id);
                enc.array(3)
                    .array(2)
                        .uint(op_info.rel_stake.numerator)
                        .uint(op_info.rel_stake.denominator)
                    .uint(_set.pool_dist.get(pool_id))
                    .bytes(op_info.vrf_vkey);
            }
        });
        enc.uint(_set.pool_dist.total_stake());
    }

    void state::to_cbor(parallel_serializer &ser) const
    {
        _add_encode_task(ser, [this](auto &enc) {
            enc.array(7);
            enc.uint(_epoch);
            for (const auto &blocks: { _blocks_before, _blocks_current }) {
                enc.map_compact(blocks.size(), [&] {
                    for (const auto &[pool_id, num_blocks]: blocks) {
                        enc.bytes(pool_id);
                        enc.uint(num_blocks);
                    }
                });
            }
        });

        // stateBefore
        _node_save_state_before(ser);
        // possibleUpdate
        if (_rewards_ready) {
            _add_encode_task(ser, [this](auto &enc) {
                enc.array(1).array(2).uint(1).array(5);
                enc.uint(_delta_treasury);
                enc.uint(_delta_reserves);
            });
            _add_encode_task(ser, [this](auto &enc) {
                enc.map_compact(_potential_rewards.size(), [&] {
                    auto s_enc = enc.make_sibling();
                    auto k_enc = enc.make_sibling();
                    for (const auto &[stake_id, rewards]: _potential_rewards) {
                        auto &i_enc = stake_id.script ? *s_enc : *k_enc;
                        stake_id.to_cbor(i_enc);
                        i_enc.set(rewards.size(), [&] {
                            for (const auto &ru: rewards) {
                                i_enc.array(3).uint(ru.type == reward_type::leader ? 1 : 0).bytes(ru.pool_id).uint(ru.amount);
                            }
                        });
                    }
                    enc << *s_enc << *k_enc;
                });
            });
            _add_encode_task(ser, [this](auto &enc) {
                enc.uint(_delta_fees);
                enc.array(2);
                enc.map_compact(_nonmyopic_next.size(), [&] {
                    for (const auto &[pool_id, lks]: _nonmyopic_next) {
                        enc.bytes(pool_id);
                        enc.array_compact(lks.size(), [&] {
                            for (const auto l: lks)
                                enc.float32(l);
                        });
                    }
                });
                enc.uint(_reward_pot);
            });
        } else if (!_reward_pulsing_snapshot.empty()) {
            _add_encode_task(ser, [](auto &enc) {
                enc.array(1).array(3).uint(0);
            });
            // reward snapshot
            _add_encode_task(ser, [](auto &enc) {
                enc.array(0);
            });
            // reward pulser
            _add_encode_task(ser, [](auto &enc) {
                enc.array(0);
            });
        } else {
            _add_encode_task(ser, [](auto &enc) {
                enc.array(0);
            });
        }
        _add_encode_task(ser, [this](auto &enc) {
            _stake_distrib_to_cbor(enc);
        });
        _add_encode_task(ser, [](auto &enc) {
            enc.s_null();
        });
        _add_encode_task(ser, [this](auto &enc) {
           enc.uint(_blocks_past_voting_deadline);
        });
    }

    template<typename VISITOR>
    void state::_visit(const VISITOR &v) const
    {
        v(_end_offset);
        v(_epoch_slot);

        v(_pulsing_snapshot_slot);
        v(_reward_pulsing_snapshot);
        v(_active_pool_dist);
        v(_active_inv_delegs);

        v(_accounts);

        v(_epoch);
        v(_blocks_current);
        v(_blocks_before);

        v(_reserves);
        v(_treasury);

        v(_mark);
        v(_set);
        v(_go);
        v(_fees_next_reward);

        for (size_t pi = 0; pi < _utxo.num_parts; ++pi)
            v(_utxo.partition(pi));

        v(_deposited);
        v(_delta_fees);
        v(_fees_utxo);
        v(_ppups);
        v(_ppups_future);

        v(_ptr_to_stake);
        v(_future_shelley_delegs);
        v(_shelley_delegs);
        v(_stake_pointers);

        v(_instant_rewards_reserves);
        v(_instant_rewards_treasury);

        v(_active_pool_params);
        v(_future_pool_params);
        v(_pools_retiring);
        v(_pool_deposits);

        v(_params);
        v(_params_prev);
        v(_nonmyopic);
        v(_nonmyopic_reward_pot);

        v(_delta_treasury);
        v(_delta_reserves);
        v(_reward_pot);
        v(_potential_rewards);
        v(_rewards_ready);
        v(_nonmyopic_next);

        v(_operating_stake_dist);
        v(_blocks_past_voting_deadline);
    }

    void state::to_zpp(parallel_serializer &sec) const
    {
        _visit([&](const auto &obj) {
           sec.add([&] {
               return zpp::serialize(obj);
           });
        });
    }

    void state::from_zpp(parallel_decoder &dec)
    {
        _visit([&](auto &obj) {
            using T = std::decay_t<decltype(obj)>;
            dec.add([&](const auto b) {
                zpp::deserialize(const_cast<T &>(obj), b);
            });
        });
        dec.on_done([&] {
            _recompute_caches();
        });
    }

    void state::clear()
    {
        _visit([&](const auto &obj) {
            using T = std::decay_t<decltype(obj)>;
            auto &o = const_cast<T &>(obj);
            if constexpr (Clearable<decltype(o)>) {
                o.clear();
            } else if constexpr (std::is_same_v<decltype(o), bool>) {
                o = false;
            } else {
                o = 0;
            }
        });
    }

    const protocol_params &state::params() const
    {
        return _params;
    }
}