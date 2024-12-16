/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <boost/beast/http/status.hpp>
#include <dt/cardano/ledger/conway.hpp>
#include <dt/cardano/ledger/updates.hpp>

namespace daedalus_turbo::cardano::ledger::conway {
    struct cbor_encoder: cbor::encoder {
        encoder &set(const size_t sz, const prepare_data_func &prepare_data) override
        {
            tag(258);
            return array_compact(sz, prepare_data);
        }

        std::unique_ptr<encoder> make_sibling() const override
        {
            return std::make_unique<cbor_encoder>();
        }
    };

    vrf_state::vrf_state(babbage::vrf_state &&o): babbage::vrf_state { std::move(o) }
    {
        _max_epoch_slot = _cfg.shelley_epoch_length - _cfg.shelley_randomness_stabilization_window;
        logger::debug("conway::vrf_state created max_epoch_slot: {}", _max_epoch_slot);
    }

    uint64_t drep_info_t::compute_expire_epoch(const protocol_params &pp, const uint64_t current_epoch)
    {
        //if (pp.protocol_ver.bootstrap_phase())
        //    return current_epoch + pp.drep_activity;
        return current_epoch + pp.drep_activity;
    }

    void drep_info_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(4);
        enc.uint(expire_epoch);
        anchor.to_cbor(enc);
        enc.uint(deposited);
        delegs.to_cbor(enc);
    }

    committee_t committee_t::from_json(const json::value &j)
    {
        member_map members {};
        for (const auto &[cred, epoch]: j.at("members").as_object()) {
            members.try_emplace(credential_t::from_json(cred), json::value_to<uint64_t>(epoch));
        }
        return {
            std::move(members),
            rational_u64 { j.at("threshold") }
        };
    }

    void committee_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(2);
        enc.map_compact(members.size(), [&] {
            for (const auto &[cred, epoch]: members) {
                cred.to_cbor(enc);
                enc.uint(epoch);
            }
        });
        threshold.to_cbor(enc);
    }

    void gov_action_state_t::to_cbor(cbor::encoder &enc, const gov_action_id_t &id) const
    {
        enc.array(7);
        id.to_cbor(enc);
        // committee votes
        {
            cbor::encoder k_enc {}, s_enc {};
            size_t k_cnt = 0, s_cnt = 0;
            for (const auto &[cred, vote]: committee_votes) {
                auto &my_enc = cred.script ? s_enc : k_enc;
                auto &my_cnt = cred.script ? s_cnt : k_cnt;
                cred.to_cbor(my_enc);
                vote.to_cbor(my_enc);
                ++my_cnt;
            }
            enc.map_compact(k_cnt + s_cnt, [&] {
                enc << s_enc;
                enc << k_enc;
            });
        }
        {
            cbor::encoder k_enc {}, s_enc {};
            size_t k_cnt = 0, s_cnt = 0;
            for (const auto &[cred, vote]: drep_votes) {
                auto &my_enc = cred.script ? s_enc : k_enc;
                auto &my_cnt = cred.script ? s_cnt : k_cnt;
                cred.to_cbor(my_enc);
                vote.to_cbor(my_enc);
                ++my_cnt;
            }
            enc.map_compact(k_cnt + s_cnt, [&] {
                enc << s_enc;
                enc << k_enc;
            });
        }
        {
            enc.map_compact(pool_votes.size(), [&] {
                for (const auto &[id, vote]: pool_votes) {
                    enc.bytes(id);
                    vote.to_cbor(enc);
                }
            });
        }
        proposal.to_cbor(enc);
        enc.uint(proposed_in);
        enc.uint(expires_after);
    }

    void pulsing_data_t::from_zpp(parallel_decoder &dec)
    {
        dec.add([&](const auto b) {
            zpp::deserialize(proposals, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(drep_state, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(drep_voting_power, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(pool_voting_power, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(drep_state_updated, b);
        });
    }

    void pulsing_data_t::to_zpp(parallel_serializer &enc) const
    {
        enc.add([&] {
            return zpp::serialize(proposals);
        });
        enc.add([&] {
            return zpp::serialize(drep_state);
        });
        enc.add([&] {
            return zpp::serialize(drep_voting_power);
        });
        enc.add([&] {
            return zpp::serialize(pool_voting_power);
        });
        enc.add([&] {
            return zpp::serialize(drep_state_updated);
        });
    }

    state::state(): state { babbage::state { shelley::state { cardano::config::get(), scheduler::get() } } }
    {
    }

    state::state(babbage::state &&o):
        babbage::state { std::move(o) },
        _enact_state {
            committee_t::from_json(_cfg.conway_genesis.at("committee")),
            constitution_t::from_json(_cfg.conway_genesis.at("constitution"))
        }
    {
        _apply_conway_params(_params);
        _params_prev = _params;
        static const std::string task_name { "conway-update-utxos" };
        _sched.wait_all_done(task_name, txo_map::num_parts,
            [&] {
                for (size_t part_idx = 0; part_idx < txo_map::num_parts; ++part_idx) {
                    _sched.submit_void(task_name, 1000, [this, part_idx] {
                        auto &utxo_part = _utxo.partition(part_idx);
                        for (auto &&[txo_id, txo_data]: utxo_part) {
                            if (const address addr { txo_data.address }; addr.has_pointer()) {
                                const auto ptr = addr.pointer();
                                if (ptr.slot > slot::from_epoch(_epoch, _cfg)
                                        || ptr.tx_idx >= std::numeric_limits<uint16_t>::max()
                                        || ptr.cert_idx >= std::numeric_limits<uint16_t>::max()) {
                                    const auto old_addr = txo_data.address;
                                    txo_data.address.resize(29);
                                    txo_data.address << uint8_t { 0 } << uint8_t { 0 } << uint8_t { 0 };
                                    logger::debug("conway-start: txo_id: {} updated address {} => {}", txo_id, old_addr, txo_data.address);
                                }
                            }
                        }
                    });
                }
            }
        );

        _enact_state.params = _params;
        _enact_state.prev_params = _params_prev;
        _enact_state.treasury = _treasury;

        _ratify_state.new_state = _enact_state;
    }

    void state::process_cert(const cert_any_t &cert, const cert_loc_t &loc)
    {
        _tick(loc.slot);
        std::visit([&](const auto &c) {
            process_cert(c, loc);
        }, cert.val);
    }

    bool state::has_drep(const credential_t &id) const
    {
        return _drep_state.contains(id);
    }

    void state::_tick(const uint64_t slot)
    {
        babbage::state::_tick(slot);
        if (!_pulsing_data.drep_state_updated && slot > _pulsing_snapshot_slot) {
            logger::debug("slot: {} creating drep pulser snapshots", cardano::slot { slot, _cfg });
            _pulsing_data.drep_state_updated = true;
        }
    }

    void state::_add_encode_task(parallel_serializer &ser, const encode_cbor_func &t) const
    {
        ser.add([t] {
            cbor_encoder enc {};
            t(enc);
            return enc.cbor();
        });
    }

    void state::_apply_conway_params(protocol_params &p) const
    {
        const auto &co_cfg = _cfg.conway_genesis;
        p.plutus_cost_models.v3.emplace(plutus_cost_model::from_json(_cfg.plutus_all_cost_models.v3.value(), co_cfg.at("plutusV3CostModel")));
        p.pool_voting_thresholds = _cfg.conway_pool_voting_thresholds;
        p.drep_voting_thresholds = _cfg.conway_drep_voting_thresholds;
        p.committee_min_size = json::value_to<uint64_t>(co_cfg.at("committeeMinSize"));
        p.committee_max_term_length = json::value_to<uint64_t>(co_cfg.at("committeeMaxTermLength"));
        p.gov_action_lifetime = json::value_to<uint64_t>(co_cfg.at("govActionLifetime"));
        p.gov_action_deposit = json::value_to<uint64_t>(co_cfg.at("govActionDeposit"));
        p.drep_deposit = json::value_to<uint64_t>(co_cfg.at("dRepDeposit"));
        p.drep_activity = json::value_to<uint64_t>(co_cfg.at("dRepActivity"));
        p.min_fee_ref_script_cost_per_byte = rational_u64 { json::value_to<double>(co_cfg.at("minFeeRefScriptCostPerByte")) };
    }

    void state::_donations_to_cbor(cbor::encoder &enc) const
    {
        enc.uint(_donations);
    }

    void state::_params_to_cbor(cbor::encoder &enc, const protocol_params &params) const
    {
        enc.array(31);
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
        enc.array(2)
            .uint(params.protocol_ver.major)
            .uint(params.protocol_ver.minor);
        enc.uint(params.min_pool_cost);
        enc.uint(params.lovelace_per_utxo_byte);
        params.plutus_cost_models.to_cbor(enc);
        enc.array(2)
            .rational(params.ex_unit_prices.mem)
            .rational(params.ex_unit_prices.steps);
        enc.array(2)
            .uint(params.max_tx_ex_units.mem)
            .uint(params.max_tx_ex_units.steps);
        enc.array(2)
            .uint(params.max_block_ex_units.mem)
            .uint(params.max_block_ex_units.steps);
        enc.uint(params.max_value_size);
        enc.uint(params.max_collateral_pct);
        enc.uint(params.max_collateral_inputs);
        params.pool_voting_thresholds.to_cbor(enc);
        params.drep_voting_thresholds.to_cbor(enc);
        enc.uint(params.committee_min_size);
        enc.uint(params.committee_max_term_length);
        enc.uint(params.gov_action_lifetime);
        enc.uint(params.gov_action_deposit);
        enc.uint(params.drep_deposit);
        enc.uint(params.drep_activity);
        params.min_fee_ref_script_cost_per_byte.to_cbor(enc);
    }

    void state::_protocol_state_to_cbor(cbor::encoder &enc) const
    {
        enc.array(7);
        // gov_action_state
        {
            enc.array(2);
            // retired government actions
            enc.array(4)
                .array(0)
                .array(0)
                .array(0)
                .array(0);
            enc.array_compact(_proposals.size(), [&] {
                for (const auto &[id, action]: _proposals) {
                    action.to_cbor(enc, id);
                }
            });
        }
        _enact_state.committee.to_cbor(enc);
        _enact_state.constitution.to_cbor(enc);
        _params_to_cbor(enc, _params);
        _params_to_cbor(enc, _params_prev);
        // treasury?
        enc.array(1).uint(0);
        // voting stats?
        {
            enc.array(2);
            {
                // DRep pulser state
                enc.array(4);
                enc.array_compact(_pulsing_data.proposals.size(), [&] {
                    for (const auto &[id, action]: _pulsing_data.proposals) {
                        if (_epoch > action.proposed_in)
                            action.to_cbor(enc, id);
                    }
                });
                enc.map_compact(_pulsing_data.drep_voting_power.size(), [&] {
                    for (const auto &[drep, power]: _pulsing_data.drep_voting_power) {
                        drep.to_cbor(enc);
                        enc.uint(power);
                    }
                });
                {
                    cbor::encoder k_enc {}, s_enc {};
                    size_t k_cnt = 0, s_cnt = 0;
                    for (auto &[drep_id, info]: _pulsing_data.drep_state) {
                        auto &my_enc = drep_id.script ? s_enc : k_enc;
                        auto &my_cnt = drep_id.script ? s_cnt : k_cnt;
                        drep_id.to_cbor(my_enc);
                        info.to_cbor(my_enc);
                        ++my_cnt;
                    }
                    enc.map_compact(k_cnt + s_cnt, [&] {
                        enc << s_enc;
                        enc << k_enc;
                    });
                }
                // spo voting power
                enc.map_compact( _pulsing_data.pool_voting_power.size(), [&] {
                    for (const auto &[pool_id, stake]: _pulsing_data.pool_voting_power) {
                        enc.bytes(pool_id);
                        enc.uint(stake);
                    }
                });
            }
            {
                enc.array(4);
                enc.array(7);
                {
                    _enact_state.committee.to_cbor(enc);
                    _enact_state.constitution.to_cbor(enc);
                    _params_to_cbor(enc, _params);
                    _params_to_cbor(enc, _params_prev);
                    enc.uint(0);
                    enc.map(0);
                    // ratifyState
                    enc.array(4);
                    // nextEnactState?
                    enc.array(0);
                    // enactedGovActions?
                    enc.array(0);
                    // expiredGovActions?
                    enc.array(0);
                    // ratificationDelayed?
                    enc.array(0);
                }
                enc.array(0);
                // prev gov action ids
                enc.tag(258).array(0);
                enc.s_false();
            }
        }
    }

    void state::_stake_distrib_to_cbor(cbor::encoder &enc) const
    {
        enc.array(2);
        enc.map_compact(_operating_stake_dist.size(), [&] {
            for (const auto &[pool_id, op_info]: _operating_stake_dist) {
                enc.bytes(pool_id);
                enc.array(3)
                    .tag(30).array(2)
                        .uint(op_info.rel_stake.numerator)
                        .uint(op_info.rel_stake.denominator)
                    .uint(_set.pool_dist.get(pool_id))
                    .bytes(op_info.vrf_vkey);
            }
        });
        enc.uint(_set.pool_dist.total_stake());
    }

    void state::_stake_pointers_to_cbor(cbor::encoder &enc) const
    {
        enc.map(0);
    }

    void state::delegate_vote(const stake_ident &stake_id, const drep_t &drep, const cert_loc_t &)
    {
        // logger::debug("slot: {} delegate vote stake_id: {} drep: {}", slot { loc.slot, _cfg }, stake_id, drep);
        auto &acc = _accounts.at(stake_id);
        if (acc.vote_deleg && acc.vote_deleg->typ == drep_t::credential && _params.protocol_ver.major >= 10) {
            if (auto d_it = _drep_state.find(*acc.vote_deleg->cred); d_it != _drep_state.end())
                d_it->second.delegs.erase(stake_id);
        }
        if (drep.cred) {
            if (auto d_it = _drep_state.find(*drep.cred); d_it != _drep_state.end()) [[likely]] {
                d_it->second.delegs.emplace(stake_id);
            } else {
                logger::debug("delegate_vote: {} delegating to an unknown drep credential: {}", stake_id, *drep.cred);
            }
        }
        acc.vote_deleg = drep;
    }

    void state::process_cert(const reg_cert &c, const cert_loc_t &loc)
    {
        register_stake(loc.slot, c.stake_id, c.deposit, loc.tx_idx, loc.cert_idx);
    }

    void state::process_cert(const unreg_cert &c, const cert_loc_t &loc)
    {
        retire_stake(loc.slot, c.stake_id, c.deposit);
    }

    void state::process_cert(const vote_deleg_cert &c, const cert_loc_t &loc)
    {
        delegate_vote(c.stake_id, c.drep, loc);
    }

    void state::process_cert(const stake_vote_deleg_cert &c, const cert_loc_t &loc)
    {
        delegate_stake(c.stake_id, c.pool_id);
        delegate_vote(c.stake_id, c.drep, loc);
    }

    void state::process_cert(const stake_reg_deleg_cert &c, const cert_loc_t &loc)
    {
        register_stake(loc.slot, c.stake_id, c.deposit, loc.tx_idx, loc.cert_idx);
        delegate_stake(c.stake_id, c.pool_id);
    }

    void state::process_cert(const vote_reg_deleg_cert &c, const cert_loc_t &loc)
    {
        register_stake(loc.slot, c.stake_id, c.deposit, loc.tx_idx, loc.cert_idx);
        delegate_vote(c.stake_id, c.drep, loc);
    }

    void state::process_cert(const stake_vote_reg_deleg_cert &c, const cert_loc_t &loc)
    {
        register_stake(loc.slot, c.stake_id, c.deposit, loc.tx_idx, loc.cert_idx);
        delegate_stake(c.stake_id, c.pool_id);
        delegate_vote(c.stake_id, c.drep, loc);
    }

    void state::process_cert(const auth_committee_hot_cert &c, const cert_loc_t &)
    {
        logger::debug("epoch: {} cert auth_enact_state.committee_hot_cert cold_id: {} hot_id: {}", _epoch, c.cold_id, c.hot_id);
        if (_enact_state.committee) {
            // Do not check for the presence in the committee to allow new members to immediately update their certs
            const auto [it, created] = _committee_hot_keys.try_emplace(c.cold_id, c.hot_id);
            if (!created) {
                if (std::holds_alternative<committee_t::resigned_t>(it->second)) [[unlikely]]
                    throw error(fmt::format("an attempt to provide a hot certificate to a resigned committee member: {}", c.cold_id));
                it->second = c.hot_id;
            }
        }
    }

    void state::process_cert(const resign_committee_cold_cert &c, const cert_loc_t &)
    {
        if (_enact_state.committee) {
            if (auto it = _committee_hot_keys.find(c.cold_id); it != _committee_hot_keys.end()) [[likely]] {
                it->second = committee_t::resigned_t {};
            } else {
                throw error(fmt::format("an unknown resigning committee cold_id: {}", c.cold_id));
            }
        }
    }

    void state::process_cert(const reg_drep_cert &c, const cert_loc_t &loc)
    {
        logger::debug("slot: {} reg_drep id: {}", slot { loc.slot, _cfg }, c.drep_id);
        const auto [it, created] = _drep_state.try_emplace(c.drep_id, c.deposit, c.anchor, _epoch + _params_prev.drep_activity);
        if (created) {
            _deposited += c.deposit;
        } else {
            if (c.deposit != it->second.deposited) [[unlikely]]
                throw error(fmt::format("the recorded deposit does not match the claimed when re-registering a drep: {}", c.drep_id));
            it->second.anchor = c.anchor;
            it->second.expire_epoch = drep_info_t::compute_expire_epoch(_params, _epoch);
        }
    }

    void state::process_cert(const unreg_drep_cert &c, const cert_loc_t &loc)
    {
        logger::debug("slot: {} unreg_drep id: {}", slot { loc.slot, _cfg }, c.drep_id);
        const auto it = _drep_state.find(c.drep_id);
        if (it ==_drep_state.end()) [[unlikely]]
            throw error(fmt::format("unreg_drep_cert: an unknown drep_id: {}", c.drep_id));
        if (it->second.deposited != c.deposit) [[unlikely]]
            throw error(fmt::format("the registered drep deposit: {} does not match the requested withdrawal: {}", it->second.deposited, c.deposit));
        if (_deposited < c.deposit) [[unlikely]]
            throw error(fmt::format("unable to withdraw the old drep deposit: {}", it->second.deposited));
        for (auto &[id, ga_st]: _proposals) {
            ga_st.drep_votes.erase(c.drep_id);
        }
        _deposited -= c.deposit;
        _drep_state.erase(it);
    }

    void state::process_cert(const update_drep_cert &c, const cert_loc_t &loc)
    {
        logger::debug("slot: {} update_drep id: {}", slot { loc.slot, _cfg }, c.drep_id);
        const auto drep_it = _drep_state.find(c.drep_id);
        if (drep_it ==_drep_state.end()) [[unlikely]]
            throw error(fmt::format("unreg_drep_cert: an unknown drep_id: {}", c.drep_id));
        drep_it->second.anchor = c.anchor;
        drep_it->second.expire_epoch = drep_info_t::compute_expire_epoch(_params, _epoch);
    }

    void state::process_proposal(const proposal_t &p, const cert_loc_t &)
    {
        _proposals.try_emplace(p.id, p.procedure, _epoch, _epoch + _params_prev.gov_action_lifetime);
        _deposited += p.procedure.deposit;
    }

    void state::process_vote(const vote_info_t &v, const cert_loc_t &loc)
    {
        logger::debug("slot: {} voter: {} gid: {} vote: {}", slot { loc.slot, _cfg }, v.voter, v.action_id, v.voting_procedure);
        if (auto gov_it = _proposals.find(v.action_id); gov_it != _proposals.end()) [[unlikely]] {
            switch (v.voter.type) {
                case voter_t::type_t::const_comm_key:
                case voter_t::type_t::const_comm_script: {
                    if (_enact_state.committee) {
                        const credential_t hot_id { v.voter.hash, v.voter.type == voter_t::type_t::const_comm_script };
                        const auto it = std::find_if(_committee_hot_keys.begin(), _committee_hot_keys.end(), [&](const auto &item) {
                            return std::holds_alternative<credential_t>(item.second) && std::get<credential_t>(item.second) == hot_id &&_enact_state.committee->members.contains(item.first);
                        });
                        if (it == _committee_hot_keys.end()) [[unlikely]]
                            throw error(fmt::format("a vote from an unknown committee member with a hot_id: {}", hot_id));
                        // convert the vote from the hot_id to the cold_id
                        const auto &cold_id = it->first;
                        gov_it->second.committee_votes[cold_id] = v.voting_procedure;
                    } else {
                        logger::warn("an attempted committee vote with no active committee: {}", v);
                    }
                    break;
                }
                case voter_t::type_t::drep_key:
                case voter_t::type_t::drep_script: {
                    const credential_t drep_id { v.voter.hash, v.voter.type == voter_t::type_t::drep_script };
                    auto it = _drep_state.find(drep_id);
                    if (it == _drep_state.end()) [[unlikely]]
                        throw error(fmt::format("a vote from an unknown drep: {}", drep_id));
                    gov_it->second.drep_votes[drep_id] = v.voting_procedure;
                    break;
                }
                case voter_t::type_t::pool_key: {
                    if (!_mark.pool_params.contains(v.voter.hash)) [[unlikely]]
                        throw error(fmt::format("a vote from an unknown pool: {}", v.voter.hash));
                    gov_it->second.pool_votes[v.voter.hash] = v.voting_procedure;
                    break;
                }
                default: throw error(fmt::format("an unsupported voter type: {}", v.voter.type));
            }
        } else {
            logger::warn("a vote for an unknown gov_action_id: {}", v.action_id);
        }
    }

    void state::_process_block_updates(block_update_list &&block_updates)
    {
        for (const auto &bu: block_updates)
            _donations += bu.donations;
        babbage::state::_process_block_updates(std::move(block_updates));
    }

    void state::_process_timed_update(tx_out_ref_list &collected_collateral, timed_update_t &&upd)
    {
        std::visit([&](const auto &u) {
            using T = std::decay_t<decltype(u)>;
            if constexpr (std::is_same_v<T, reg_cert>
                || std::is_same_v<T, stake_reg_deleg_cert>
                || std::is_same_v<T, vote_reg_deleg_cert>
                || std::is_same_v<T, stake_vote_reg_deleg_cert>
                || std::is_same_v<T, reg_drep_cert>
                || std::is_same_v<T, vote_deleg_cert>
                || std::is_same_v<T, stake_vote_deleg_cert>
                || std::is_same_v<T, auth_committee_hot_cert>
                || std::is_same_v<T, resign_committee_cold_cert>
                || std::is_same_v<T, update_drep_cert>
                || std::is_same_v<T, unreg_cert>
                || std::is_same_v<T, unreg_drep_cert>) {
                process_cert(u, upd.loc);
            } else if constexpr (std::is_same_v<T, proposal_t>) {
                process_proposal(u, upd.loc);
            } else if constexpr (std::is_same_v<T, vote_info_t>) {
                process_vote(u, upd.loc);
            } else {
                babbage::state::_process_timed_update(collected_collateral, std::move(upd));
            }
        }, upd.update);
    }

    void state::to_zpp(parallel_serializer &ser) const
    {
        ser.add([&] {
            return zpp::serialize(_enact_state);
        });
        ser.add([&] {
            return zpp::serialize(_ratify_state);
        });
        _pulsing_data.to_zpp(ser);
        ser.add([&] {
            return zpp::serialize(_committee_hot_keys);
        });
        ser.add([&] {
            return zpp::serialize(_drep_state);
        });
        ser.add([&] {
            return zpp::serialize(_num_dormant_epochs);
        });
        ser.add([&] {
            return zpp::serialize(_proposals);
        });
        ser.add([&] {
            return zpp::serialize(_donations);
        });
        ser.add([&] {
            return zpp::serialize(_conway_start_epoch);
        });
        babbage::state::to_zpp(ser);
    }

    void state::from_zpp(parallel_decoder &dec)
    {
        dec.add([&](const auto b) {
            zpp::deserialize(_enact_state, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_ratify_state, b);
        });
        _pulsing_data.from_zpp(dec);
        dec.add([&](const auto b) {
            zpp::deserialize(_committee_hot_keys, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_drep_state, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_num_dormant_epochs, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_proposals, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_donations, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_conway_start_epoch, b);
        });
        babbage::state::from_zpp(dec);
    }

    bool state::_committee_accepted(const enact_state_t &st, const gov_action_state_t &ga) const
    {
        if (st.committee) {
            size_t yes = 0;
            size_t total = 0;
            // starting with the list of committee key allows to discard votes
            // of those members who first votes but then resigned
            for (const auto &[cold_id, expire_epoch]: st.committee->members) {
                const auto v_it = ga.committee_votes.find(cold_id);
                if (v_it != ga.committee_votes.end()) {
                    if (v_it->second.vote != vote_t::abstain) {
                        ++total;
                        if (v_it->second.vote == vote_t::yes)
                            ++yes;
                    }
                } else {
                    // No vote is counted as a "no"
                    ++total;
                }
            }
            const rational_u64 r { yes, total };
            return r >= st.committee->threshold;
        }
        return false;
    }

    state::default_vote_t state::_pool_default_vote(const pool_hash &id) const
    {
        const auto &params = _active_pool_params.at(id);
        const auto acc_it = _accounts.find(params.params.reward_id);
        if (acc_it->second.vote_deleg) {
            switch (acc_it->second.vote_deleg->typ) {
                case drep_t::abstain: return default_vote_t::abstain;
                case drep_t::no_confidence: return default_vote_t::no_confidence;
                default: break;
            }
        }
        return default_vote_t::no;
    }

    state::voting_threshold_t state::_pool_voting_threshold(const gov_action_t &ga) const
    {
        const auto &params = _ratify_state.new_state.params;
        const auto has_committee = _ratify_state.new_state.committee.has_value();
        const auto vt = params.pool_voting_thresholds;
        return std::visit<voting_threshold_t>([&](const auto &av) {
            using T = std::decay_t<decltype(av)>;
            if constexpr (std::is_same_v<T, gov_action_t::no_confidence_t>)
                return voting_threshold_t { voting_threshold_t::threshold, vt.motion_of_no_confidence };
            if constexpr (std::is_same_v<T, gov_action_t::update_committee_t>) {
                if (has_committee)
                    return voting_threshold_t { voting_threshold_t::threshold, vt.committee_normal };
                return voting_threshold_t { voting_threshold_t::threshold, vt.committee_no_confidence };
            }
            if constexpr (std::is_same_v<T, gov_action_t::new_constitution_t>)
                return voting_threshold_t { voting_threshold_t::no_voting_allowed };
            if constexpr (std::is_same_v<T, gov_action_t::hard_fork_init_t>)
                return voting_threshold_t { voting_threshold_t::threshold, vt.hard_fork_initiation };
            if constexpr (std::is_same_v<T, gov_action_t::parameter_change_t>) {
                if (av.update.security_group())
                    return voting_threshold_t { voting_threshold_t::threshold, vt.security_voting_threshold };
                return voting_threshold_t { voting_threshold_t::no_voting_allowed };
            }
            if constexpr (std::is_same_v<T, gov_action_t::treasury_withdrawals_t>)
                return voting_threshold_t { voting_threshold_t::no_voting_allowed };
            if constexpr (std::is_same_v<T, gov_action_t::info_action_t>)
                return voting_threshold_t { voting_threshold_t::no_voting_threshold };
            throw error(fmt::format("unsupported gov action type: {}", typeid(T).name()));
            return voting_threshold_t { voting_threshold_t::no_voting_allowed };
        }, ga.val);
    }

    bool state::_check_threshold(const voting_threshold_t &t, const rational_u64 &r)
    {
        switch (t.typ) {
            case voting_threshold_t::threshold: return r >= t.val;
            case voting_threshold_t::no_voting_threshold: return true;
            case voting_threshold_t::no_voting_allowed: return false;
            default: throw error(fmt::format("unsupported voting_threshold type: {}", static_cast<int>(t.typ)));
        }
    }

    bool state::_pools_accepted(const gov_action_state_t &ga) const
    {
        uint64_t yes = 0;
        uint64_t abstain = 0;
        // starting with the list of pools allows to handle the cases of no vote differently
        for (const auto &[pool_id, stake]: _pulsing_data.pool_voting_power) {
            const auto v_it = ga.pool_votes.find(pool_id);
            if (v_it != ga.pool_votes.end()) {
                switch (v_it->second.vote) {
                    case vote_t::abstain: abstain += stake; break;
                    case vote_t::no: break;
                    case vote_t::yes: yes += stake; break;
                    default: throw error(fmt::format("unsupported vote value: {}", static_cast<int>(v_it->second.vote)));
                }
            } else {
                if (std::holds_alternative<gov_action_t::hard_fork_init_t>(ga.proposal.action.val)) {
                    // match first and ignore
                } else if (_params.protocol_ver.bootstrap_phase()) {
                    abstain += stake;
                } else {
                    switch (const auto default_vote = _pool_default_vote(pool_id); default_vote) {
                        case default_vote_t::no_confidence:
                            if (std::holds_alternative<gov_action_t::no_confidence_t>(ga.proposal.action.val))
                                yes += stake;
                            break;
                        case default_vote_t::abstain:
                            abstain += stake;
                            break;
                        default:
                            break;
                    }
                }
            }
        }
        const rational_u64 r { yes, _pulsing_data.pool_voting_power.total_stake() - abstain };
        if ((_pulsing_data.pool_voting_power.total_stake() == 0) + (_pulsing_data.pool_voting_power.total_stake() == abstain)) [[unlikely]]
            return false;
        return _check_threshold(_pool_voting_threshold(ga.proposal.action), r);
    }

    rational_u64 state::_param_update_threshold(const param_update_t &upd, const drep_voting_thresholds_t &t) const
    {
        rational_u64 r { 0, 1 };
        if (upd.network_group() && r < t.pp_network_group)
            r = t.pp_network_group;
        if (upd.governance_group() && r < t.pp_governance_group)
            r = t.pp_governance_group;
        if (upd.technical_group() && r < t.pp_technical_group)
            r = t.pp_technical_group;
        if (upd.economic_group() && r < t.pp_economic_group)
            r = t.pp_economic_group;
        return r;
    }

    state::voting_threshold_t state::_drep_voting_threshold(const gov_action_t &ga) const
    {
        const auto &params = _ratify_state.new_state.params;
        const auto has_committee = _ratify_state.new_state.committee.has_value();
        const auto &t = _params.protocol_ver.bootstrap_phase()
            ? drep_voting_thresholds_t::zero()
            : params.drep_voting_thresholds;
        return std::visit<voting_threshold_t>([&](const auto &a) {
            using T = std::decay_t<decltype(a)>;
            if constexpr (std::is_same_v<T, gov_action_t::no_confidence_t>)
                return voting_threshold_t { voting_threshold_t::threshold, t.motion_no_confidence };
            if constexpr (std::is_same_v<T, gov_action_t::update_committee_t>) {
                if (has_committee)
                    return voting_threshold_t { voting_threshold_t::threshold, t.committee_normal };
                return voting_threshold_t { voting_threshold_t::threshold, t.committee_no_confidence };
            }
            if constexpr (std::is_same_v<T, gov_action_t::new_constitution_t>)
                return voting_threshold_t { voting_threshold_t::threshold, t.update_constitution };
            if constexpr (std::is_same_v<T, gov_action_t::hard_fork_init_t>)
                return voting_threshold_t { voting_threshold_t::threshold, t.hard_fork_initiation };
            if constexpr (std::is_same_v<T, gov_action_t::parameter_change_t>)
                return voting_threshold_t { voting_threshold_t::threshold, _param_update_threshold(a.update, t) };
            if constexpr (std::is_same_v<T, gov_action_t::treasury_withdrawals_t>)
                return voting_threshold_t { voting_threshold_t::threshold, t.treasury_withdrawal };
            if constexpr (std::is_same_v<T, gov_action_t::info_action_t>)
                return voting_threshold_t { voting_threshold_t::no_voting_threshold };
            throw error(fmt::format("unsupported governance action type: {}", typeid(T).name()));
            return voting_threshold_t { voting_threshold_t::no_voting_allowed };
        }, ga.val);
    }

    bool state::_dreps_accepted(const gov_action_state_t &ga) const
    {
        uint64_t yes = 0;
        uint64_t total_wo_abstain = 0;
        for (const auto &[drep, stake]: _pulsing_data.drep_voting_power) {
            switch (drep.typ) {
                case drep_t::abstain: break;
                case drep_t::no_confidence:
                    total_wo_abstain += stake;
                    if (std::holds_alternative<gov_action_t::no_confidence_t>(ga.proposal.action.val))
                        yes += stake;
                    break;
                case drep_t::credential: {
                    const auto d_it = _drep_state.find(*drep.cred);
                    if (d_it != _drep_state.end() && _epoch <= d_it->second.expire_epoch) {
                        const auto v_it = ga.drep_votes.find(*drep.cred);
                        if (v_it != ga.drep_votes.end()) {
                            switch (v_it->second.vote) {
                                case vote_t::no:
                                    total_wo_abstain += stake;
                                    break;
                                case vote_t::yes:
                                    yes += stake;
                                    total_wo_abstain += stake;
                                    break;
                                case vote_t::abstain:
                                    break;
                                default:
                                    throw error(fmt::format("unsupported vote value: {}", static_cast<int>(v_it->second.vote)));
                            }
                        } else {
                            total_wo_abstain += stake;
                        }
                    }
                    break;
                }
                default:
                    throw error(fmt::format("unsupported drep type: {}", static_cast<int>(drep.typ)));
            }
        }
        const rational_u64 r { yes, total_wo_abstain };
        if (!r.numerator)
            return false;
        return _check_threshold(_drep_voting_threshold(ga.proposal.action), r);
    }

    bool state::_accepted_by_everyone(const enact_state_t &st, const gov_action_state_t &gas) const
    {
        return _committee_accepted(st, gas) && _pools_accepted(gas) && _dreps_accepted(gas);
    }

    // Why it's checked here not at the time of proposal parsing?
    static bool _valid_committee_term(const gov_action_t &ga, const protocol_params &pp, const uint64_t epoch)
    {
        if (std::holds_alternative<gov_action_t::update_committee_t>(ga.val)) {
            const auto max_expire_epoch = epoch + pp.committee_max_term_length;
            const auto &new_c = std::get<gov_action_t::update_committee_t>(ga.val);
            for (const auto &[cred, expire_epoch]: new_c.members_to_add) {
                if (expire_epoch > max_expire_epoch)
                    return false;
            }
            return true;
        }
        return true;
    }

    static bool _withdrawals_can_withdraw(const gov_action_t &ga, const uint64_t treasury)
    {
        if (std::holds_alternative<gov_action_t::treasury_withdrawals_t>(ga.val)) {
            uint64_t withdrawals = 0;
            const auto &w = std::get<gov_action_t::treasury_withdrawals_t>(ga.val);
            for (const auto &[cred, coin]: w.withdrawals)
                withdrawals += coin;
            return withdrawals <= treasury;
        }
        return true;
    }

    static bool _prev_action_as_expected(const gov_action_t &ga, const enact_state_t &st)
    {
        return std::visit<bool>([&](const auto &a) {
            using T = std::decay_t<decltype(a)>;
            if constexpr (std::is_same_v<T, gov_action_t::parameter_change_t>)
                return !a.prev_action_id || (!st.prev_param_update_gids.empty() && *a.prev_action_id == st.prev_param_update_gids.back());
            if constexpr (std::is_same_v<T, gov_action_t::hard_fork_init_t>)
                return !a.prev_action_id || (!st.prev_hard_fork_gids.empty() && *a.prev_action_id == st.prev_hard_fork_gids.back());
            if constexpr (std::is_same_v<T, gov_action_t::update_committee_t>)
                return !a.prev_action_id || (!st.prev_committee_gids.empty() && *a.prev_action_id == st.prev_committee_gids.back());
            if constexpr (std::is_same_v<T, gov_action_t::new_constitution_t>)
                return !a.prev_action_id || (!st.prev_constitution_gids.empty() && *a.prev_action_id == st.prev_constitution_gids.back());
            return true;
        }, ga.val);
    }

    void state::_enact(enact_state_t &st, const gov_action_id_t &gid, const gov_action_t &ga)
    {
        std::visit([&](const auto &a) {
            using T = std::decay_t<decltype(a)>;
            if constexpr (std::is_same_v<T, gov_action_t::parameter_change_t>) {
                st.params.apply(a.update);
                st.prev_param_update_gids.emplace_back(gid);
            } else if constexpr (std::is_same_v<T, gov_action_t::hard_fork_init_t>) {
                st.params.protocol_ver = a.protocol_ver;
                st.prev_hard_fork_gids.emplace_back(gid);
            } else if constexpr (std::is_same_v<T, gov_action_t::treasury_withdrawals_t>) {
                for (const auto &[cred, coin]: a.withdrawals) {
                    st.withdrawals[cred] += coin;
                    st.treasury -= coin;
                }
            } else if constexpr (std::is_same_v<T, gov_action_t::no_confidence_t>) {
                st.committee.reset();
                st.prev_committee_gids.emplace_back(gid);
            } else if constexpr (std::is_same_v<T, gov_action_t::update_committee_t>) {
                if (!st.committee)
                    st.committee.emplace();
                for (const auto &cred: a.members_to_remove)
                    st.committee->members.erase(cred);
                for (const auto &[cred, expire_epoch]: a.members_to_add)
                    st.committee->members[cred] = expire_epoch;
                st.committee->threshold = a.new_threshold;
                st.prev_committee_gids.emplace_back(gid);
            } else if constexpr (std::is_same_v<T, gov_action_t::new_constitution_t>) {
                st.constitution = a.new_constitution;
                st.prev_constitution_gids.emplace_back(gid);
            } else if constexpr (std::is_same_v<T, gov_action_t::info_action_t>) {
                // do nothing
            } else {
                throw error(fmt::format("unsupported gov action type: {}", typeid(T).name()));
            }
        }, ga.val);
    }

    void state::_transfer_treasury_withdrawals(const stake_distribution &rewards)
    {
        for (const auto &[stake_id, reward]: rewards) {
            if (auto acc_it = _accounts.find(stake_id); acc_it != _accounts.end() && acc_it->second.ptr) {
                _treasury -= reward;
                acc_it->second.reward += reward;
                if (acc_it->second.deleg)
                    _active_pool_dist.add(*acc_it->second.deleg, reward);
            } else {
                logger::warn("treasury withdrawal ignored - no such reward account: {}", stake_id);
            }
        }
    }

    void state::_finalize_gov_actions()
    {
        if (!_proposals.empty()) {
            if (_num_dormant_epochs) {
                for (auto &[id, state]: _drep_state) {
                    state.expire_epoch += _num_dormant_epochs;
                }
                _num_dormant_epochs = 0;
            }

            vector<gov_action_id_t> retired_actions {};
            for (const auto &[gid, gas]: _proposals) {
                const auto new_expire_epoch = drep_info_t::compute_expire_epoch(_params, _epoch);;
                for (auto &[id, vote]: gas.drep_votes) {
                    _drep_state.at(id).expire_epoch = new_expire_epoch;
                }

                if (_prev_action_as_expected(gas.proposal.action, _ratify_state.new_state)
                        && _valid_committee_term(gas.proposal.action, _ratify_state.new_state.params, _epoch)
                        && !_ratify_state.delayed
                        && _withdrawals_can_withdraw(gas.proposal.action, _ratify_state.new_state.treasury)
                        && _accepted_by_everyone(_ratify_state.new_state, gas)) {
                     _enact(_ratify_state.new_state, gid, gas.proposal.action);
                    _ratify_state.enacted.emplace_back(gid, gas);
                } else if (_epoch > gas.expires_after) {
                    _ratify_state.expired.emplace(gid);
                    auto [acc_it, created] = _accounts.try_emplace(gas.proposal.return_addr);
                    if (created)
                        logger::warn("gov_action {} deposit is returned to an unregistered stake_id: {}", gid, gas.proposal.return_addr);
                    acc_it->second.reward += gas.proposal.deposit;
                    _deposited -= gas.proposal.deposit;
                }
            }
            for (const auto &[gid, gas]: _ratify_state.enacted)
                _proposals.erase(gid);
            for (const auto &gid: _ratify_state.expired)
                _proposals.erase(gid);

            // move the ratified state to enact
            _enact_state = std::move(_ratify_state.new_state);
            _params = _enact_state.params;
            _params_prev = _enact_state.prev_params;
            _transfer_treasury_withdrawals(_enact_state.withdrawals);

            // prepare the ratification state for the next round
            _ratify_state.new_state = _enact_state;
            _ratify_state.enacted.clear();
            _ratify_state.delayed = false;
            _ratify_state.new_state.prev_params = _ratify_state.new_state.params;
            _ratify_state.new_state.withdrawals.clear();
        } else {
            ++_num_dormant_epochs;
        }
    }

    drep_distr_t state::_compute_drep_voting_power() const
    {
        drep_distr_t power {};
        if (!_drep_state.empty()) {
            static const std::string task_id { "drep-voting-power" };
            mutex::unique_lock::mutex_type drep_mutex alignas(mutex::padding) {};
            _sched.wait_all_done(task_id, _accounts.num_parts, [&] {
                for (size_t part_no = 0; part_no < _accounts.num_parts; ++part_no) {
                    _sched.submit_void(task_id, 1000, [&, part_no] {
                        drep_distr_t part_stake {};
                        const auto &acc_part = _accounts.partition(part_no);
                        for (const auto &[stake_id, info]: acc_part) {
                            if (info.vote_deleg && (info.vote_deleg->typ != drep_t::credential || _drep_state.contains(info.vote_deleg->cred.value()))) {
                                if (info.mark_stake)
                                    part_stake[*info.vote_deleg] += info.mark_stake;
                            }
                        }
                        mutex::scoped_lock lk { drep_mutex };
                        for (const auto &[drep, stake]: part_stake)
                            power[drep] += stake;
                    });
                }
            });
        }
        return power;
    }

    pool_stake_distribution state::_compute_pool_voting_power() const
    {
        pool_stake_distribution power {};
        for (const auto &[pool_id, stake]: _mark.pool_dist) {
            if (const auto num_delegs = _mark.inv_delegs.at(pool_id).size(); num_delegs) {
                power.create(pool_id);
                power.add(pool_id, stake);
            }
        }
        for (const auto &[gid, ga]: _proposals) {
            const auto acc_it = _accounts.find(ga.proposal.return_addr);
            if (acc_it != _accounts.end() && acc_it->second.deleg)
                power.add(*acc_it->second.deleg, ga.proposal.deposit);
        }
        return power;
    }

    void state::start_epoch(const std::optional<uint64_t> new_epoch)
    {
        babbage::state::start_epoch(new_epoch);
        if (!_conway_start_epoch)
            _conway_start_epoch.emplace(_epoch);
        if (!_stake_pointers.empty() && _epoch > *_conway_start_epoch)
            _stake_pointers.clear();

        if (_params.protocol_ver.major >= 10 && _params_prev.protocol_ver.major < 10) {
            // Recreate drep delegation state as Cardano Ledger PV 9 had a bug
            for (auto &[drep, state]: _drep_state)
                state.delegs.clear();
            for (const auto &[id, info]: _accounts) {
                if (info.vote_deleg && info.vote_deleg->typ == drep_t::credential)
                    _drep_state.at(*info.vote_deleg->cred).delegs.emplace(id);
            }
        }

        _treasury += _donations;
        _donations = 0;

        _finalize_gov_actions();

        if (_proposals.empty())
            ++_num_dormant_epochs;
        else
            _num_dormant_epochs = 0;
        _pulsing_data.drep_state_updated = false;
        _pulsing_data.drep_state = _drep_state;
        _pulsing_data.proposals = _proposals;
        _pulsing_data.pool_voting_power = _compute_pool_voting_power();
        _pulsing_data.drep_voting_power = _compute_drep_voting_power();
    }

    bool state::has_gov_action(const gov_action_id_t &gid) const
    {
        return _proposals.contains(gid);
    }

    const gov_action_state_t &state::gov_action(const gov_action_id_t &gid) const
    {
        return _proposals.at(gid);
    }

    const optional_t<committee_t> &state::committee() const
    {
        return _enact_state.committee;
    }
}