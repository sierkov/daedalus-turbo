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

    void drep_info_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(3);
        enc.uint(epoch_inactive);
        anchor.to_cbor(enc);
        enc.uint(deposited);
    }

    state::constitution_t::constitution_t(const json::value &j):
        anchor { j.at("anchor") }, script { script_hash::from_hex(j.at("script").as_string()) }
    {
    }

    void state::constitution_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(2);
        anchor.to_cbor(enc);
        enc.bytes(script);
    }

    state::committee_t::committee_t(const json::value &j):
        threshold { j.at("threshold") }
    {
        for (const auto &[cred, epoch]: j.at("members").as_object()) {
            members.try_emplace(credential_t { cred }, json::value_to<uint64_t>(epoch));
        }
    }

    void state::committee_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(1);
        enc.array(2);
        enc.map_compact(members.size(), [&] {
            for (const auto &[cred, epoch]: members) {
                cred.to_cbor(enc);
                enc.uint(epoch);
            }
        });
        threshold.to_cbor(enc);
    }

    void state::gov_action_state_t::to_cbor(cbor::encoder &enc, const gov_action_id_t &id) const
    {
        enc.array(7);
        id.to_cbor(enc);
        // committee votes?
        size_t ck_cnt = 0, cs_cnt = 0, dk_cnt = 0, ds_cnt = 0, p_cnt = 0;
        cbor::encoder ck_enc {}, cs_enc {}, dk_enc {}, ds_enc {}, p_enc {};
        for (const auto &[voter, vote]: votes) {
            switch (voter.type) {
                case voter_t::const_comm_key: {
                    const credential_t comm_id { voter.hash, false };
                    comm_id.to_cbor(ck_enc);;
                    vote.to_cbor(ck_enc);
                    ++ck_cnt;
                    break;
                }
                case voter_t::const_comm_script: {
                    const credential_t comm_id { voter.hash, true };
                    comm_id.to_cbor(cs_enc);;
                    vote.to_cbor(cs_enc);
                    ++cs_cnt;
                    break;
                }
                case voter_t::drep_key: {
                    const credential_t drep_id { voter.hash, false };
                    drep_id.to_cbor(dk_enc);;
                    vote.to_cbor(dk_enc);
                    ++dk_cnt;
                    break;
                }
                case voter_t::drep_script: {
                    const credential_t drep_id { voter.hash, true };
                    drep_id.to_cbor(ds_enc);;
                    vote.to_cbor(ds_enc);
                    ++ds_cnt;
                    break;
                }
                case voter_t::pool_key: {
                    p_enc.bytes(voter.hash);
                    vote.to_cbor(p_enc);
                    ++p_cnt;
                    break;
                }
                default: throw error("unsupported voter type: {}", static_cast<int>(voter.type));
            }
        }
        enc.map_compact(ck_cnt + cs_cnt, [&] {
            enc << cs_enc;
            enc << ck_enc;
        });
        enc.map_compact(dk_cnt + ds_cnt, [&] {
            enc << ds_enc;
            enc << dk_enc;
        });
        enc.map_compact(p_cnt, [&] {
            enc << p_enc;
        });
        // action info
        enc.array(4);
        {
            enc.uint(deposit);
            array<uint8_t, sizeof(stake_id.hash) + 1> stake_addr;
            stake_addr[0] = stake_id.script ? 0xF1 : 0xE1;
            memcpy(stake_addr.data() + 1, stake_id.hash.data(), stake_id.hash.size());
            enc.bytes(stake_addr);
            action.to_cbor(enc);
            anchor.to_cbor(enc);
        }
        enc.uint(epoch_created);
        enc.uint(epoch_expires);
    }

    state::state(babbage::state &&o):
        babbage::state { std::move(o) },
        _constitution { _cfg.conway_genesis.at("constitution") },
        _committee { _cfg.conway_genesis.at("committee") }
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
        p.comittee_min_size = json::value_to<uint64_t>(co_cfg.at("committeeMinSize"));
        p.committee_max_term_length = json::value_to<uint64_t>(co_cfg.at("committeeMaxTermLength"));
        p.gov_action_lifetime = json::value_to<uint64_t>(co_cfg.at("govActionLifetime"));
        p.gov_action_deposit = json::value_to<uint64_t>(co_cfg.at("govActionDeposit"));
        p.drep_deposit = json::value_to<uint64_t>(co_cfg.at("dRepDeposit"));
        p.drep_activity = json::value_to<uint64_t>(co_cfg.at("dRepActivity"));
        p.min_fee_ref_script_cost_per_byte = rational_u64 { json::value_to<double>(co_cfg.at("minFeeRefScriptCostPerByte")) };
    }

    void state::_apply_param_update(const cardano::param_update &update)
    {
        std::string update_desc {};
        _apply_one_param_update(_params.protocol_ver, update_desc, update.protocol_ver, "protocol_ver");
        _apply_one_param_update(_params.min_fee_a, update_desc, update.min_fee_a, "min_fee_a");
        _apply_one_param_update(_params.min_fee_b, update_desc, update.min_fee_b, "min_fee_b");
        _apply_one_param_update(_params.max_block_body_size, update_desc, update.max_block_body_size, "max_block_body_size");
        _apply_one_param_update(_params.max_transaction_size, update_desc, update.max_transaction_size, "max_transaction_size");
        _apply_one_param_update(_params.max_block_header_size, update_desc, update.max_block_header_size, "max_block_header_size");
        _apply_one_param_update(_params.key_deposit, update_desc, update.key_deposit, "key_deposit");
        _apply_one_param_update(_params.pool_deposit, update_desc, update.pool_deposit, "pool_deposit");
        _apply_one_param_update(_params.e_max, update_desc, update.e_max, "e_max");
        _apply_one_param_update(_params.n_opt, update_desc, update.n_opt, "n_opt");
        _apply_one_param_update(_params.pool_pledge_influence, update_desc, update.pool_pledge_influence, "pool_pledge_influence");
        _apply_one_param_update(_params.expansion_rate, update_desc, update.expansion_rate, "expansion_rate");
        _apply_one_param_update(_params.treasury_growth_rate, update_desc, update.treasury_growth_rate, "treasury_growth_rate");
        _apply_one_param_update(_params.decentralization, update_desc, update.decentralization, "decentralization");
        _apply_one_param_update(_params.extra_entropy, update_desc, update.extra_entropy, "extra_entropy");
        _apply_one_param_update(_params.min_utxo_value, update_desc, update.min_utxo_value, "min_utxo_value");
        _apply_one_param_update(_params.min_pool_cost, update_desc, update.min_pool_cost, "min_pool_cost");
        _apply_one_param_update(_params.lovelace_per_utxo_byte, update_desc, update.lovelace_per_utxo_byte, "lovelace_per_utxo_byte");
        _apply_one_param_update(_params.ex_unit_prices, update_desc, update.ex_unit_prices, "ex_unit_prices");
        _apply_one_param_update(_params.max_tx_ex_units, update_desc, update.max_tx_ex_units, "max_tx_ex_units");
        _apply_one_param_update(_params.max_block_ex_units, update_desc, update.max_block_ex_units, "max_block_ex_units");
        _apply_one_param_update(_params.max_value_size, update_desc, update.max_value_size, "max_value_size");
        _apply_one_param_update(_params.max_collateral_pct, update_desc, update.max_collateral_pct, "max_collateral_pct");
        _apply_one_param_update(_params.max_collateral_inputs, update_desc, update.max_collateral_inputs, "max_collateral_inputs");
        _apply_one_param_update(_params.plutus_cost_models, update_desc, update.plutus_cost_models, "plutus_cost_models");
        logger::debug("epoch: {} protocol params update: [ {}]", _epoch, update_desc);
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
        enc.uint(params.comittee_min_size);
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
        size_t seasoned_actions = 0;
        {
            enc.array(2);
            // retired government actions
            enc.array(4)
                .array(0)
                .array(0)
                .array(0)
                .array(0);
            enc.array_compact(_gov_actions.size(), [&] {
                for (const auto &[id, action]: _gov_actions) {
                    if (_epoch > action.epoch_created)
                        ++seasoned_actions;
                    action.to_cbor(enc, id);
                }
            });
        }
        // const comittee
        _committee.to_cbor(enc);
        _constitution.to_cbor(enc);
        _params_to_cbor(enc, _params);
        _params_to_cbor(enc, _params_prev);
        // treasury?
        enc.array(1).uint(0);
        // voting stats?
        {
            enc.array(2);
            {
                enc.array(4);
                // seasoned actions
                enc.array_compact(seasoned_actions, [&] {
                    for (const auto &[id, action]: _gov_actions) {
                        if (_epoch > action.epoch_created)
                            action.to_cbor(enc, id);
                    }
                });
                {
                    enc.map_compact(_drep_stake.size(), [&] {
                        for (const auto &[drep, power]: _drep_stake) {
                            drep.to_cbor(enc);
                            enc.uint(power);
                        }
                    });
                }
                {
                    enc.map_compact(_dreps.size(), [&] {
                        for (const auto &[drep_id, info]: _dreps) {
                            drep_id.to_cbor(enc);
                            info.to_cbor(enc);
                        }
                    });
                }
                // spo voting power
                pool_stake_distribution spo_dist {};
                for (const auto &[pool_id, stake]: _mark.pool_dist) {
                    if (const auto num_delegs = _mark.inv_delegs.at(pool_id).size(); num_delegs)
                        spo_dist.try_emplace(pool_id, stake);
                }
                enc.map_compact( spo_dist.size(), [&] {
                    for (const auto &[pool_id, stake]: spo_dist) {
                        enc.bytes(pool_id);
                        enc.uint(stake);
                    }
                });
            }
            {
                enc.array(4);
                enc.array(7);
                {
                    _committee.to_cbor(enc);
                    _constitution.to_cbor(enc);
                    _params_to_cbor(enc, _params);
                    _params_to_cbor(enc, _params_prev);
                    enc.uint(0);
                    enc.map(0);
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

    void state::delegate_vote(const stake_ident &stake_id, const drep_t &drep)
    {
        if (drep.cred) {
            if (const auto drep_it = _dreps.find(*drep.cred); drep_it == _dreps.end()) [[unlikely]]
                logger::debug("delegate_vote: {} delegating to an unknown drep credential: {}", stake_id, *drep.cred);
        }
        auto &acc = _accounts.at(stake_id);
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

    void state::process_cert(const vote_deleg_cert &c, const cert_loc_t &)
    {
        delegate_vote(c.stake_id, c.drep);
    }

    void state::process_cert(const stake_vote_deleg_cert &c, const cert_loc_t &)
    {
        delegate_stake(c.stake_id, c.pool_id);
        delegate_vote(c.stake_id, c.drep);
    }

    void state::process_cert(const stake_reg_deleg_cert &c, const cert_loc_t &loc)
    {
        register_stake(loc.slot, c.stake_id, c.deposit, loc.tx_idx, loc.cert_idx);
        delegate_stake(c.stake_id, c.pool_id);
    }

    void state::process_cert(const vote_reg_deleg_cert &c, const cert_loc_t &loc)
    {
        register_stake(loc.slot, c.stake_id, c.deposit, loc.tx_idx, loc.cert_idx);
        delegate_vote(c.stake_id, c.drep);
    }

    void state::process_cert(const stake_vote_reg_deleg_cert &c, const cert_loc_t &loc)
    {
        register_stake(loc.slot, c.stake_id, c.deposit, loc.tx_idx, loc.cert_idx);
        delegate_stake(c.stake_id, c.pool_id);
        delegate_vote(c.stake_id, c.drep);
    }

    void state::process_cert(const auth_committee_hot_cert &c, const cert_loc_t &)
    {
        logger::debug("auth_committee_hot_cert cold: {} hot: {}", c.cold_id, c.hot_id);
        // Do not check for the presence in the committee to allow new members to immediately update their certs
        const auto [it, created] = _committee.hot_keys.try_emplace(c.cold_id, c.hot_id);
        if (!created) {
            if (std::holds_alternative<committee_t::resigned_t>(it->second)) [[unlikely]]
                throw error("an attempt to provide a hot certificate to a resigned committee member: {}", c.cold_id);
            it->second = c.hot_id;
        }
    }

    void state::process_cert(const resign_committee_cold_cert &c, const cert_loc_t &)
    {
        logger::debug("resign_committee_cold_cert cold: {}", c.cold_id);
        if (auto it = _committee.hot_keys.find(c.cold_id); it != _committee.hot_keys.end()) [[likely]] {
            it->second = committee_t::resigned_t {};
        } else {
            throw error("an unknown resigning committee cold_id: {}", c.cold_id);
        }
    }

    void state::process_cert(const reg_drep_cert &c, const cert_loc_t &)
    {
        const auto [it, created] = _dreps.try_emplace(c.drep_id, c.deposit, c.anchor, _epoch + _params_prev.drep_activity);
        logger::debug("reg_drep_cert: {} deposit: {} anchor: {}", c.drep_id, c.deposit, c.anchor);
        if (created) {
            _deposited += c.deposit;
        } else {
            if (c.deposit != it->second.deposited) [[unlikely]]
                throw error("the recorded deposit does not match the claimed when re-registering a drep: {}", c.drep_id);
            it->second.anchor = c.anchor;
            it->second.epoch_inactive = _epoch + _params_prev.drep_activity;
        }
    }

    void state::process_cert(const unreg_drep_cert &c, const cert_loc_t &)
    {
        logger::debug("unreg_drep_cert: {} deposit: {}", c.drep_id, c.deposit);
        const auto it = _dreps.find(c.drep_id);
        if (it ==_dreps.end()) [[unlikely]]
            throw error("unreg_drep_cert: an unknown drep_id: {}", c.drep_id);
        if (it->second.deposited != c.deposit) [[unlikely]]
            throw error("the registered drep deposit: {} does not match the requested withdrawal: {}", it->second.deposited, c.deposit);
        if (_deposited < c.deposit) [[unlikely]]
            throw error("unable to withdraw the old drep deposit: {}", it->second.deposited);
        const voter_t voter_id { c.drep_id.script ? voter_t::type_t::drep_script : voter_t::type_t::drep_key, c.drep_id.hash };
        for (auto &[id, action]: _gov_actions) {
            action.votes.erase(voter_id);
        }
        _deposited -= c.deposit;
        _dreps.erase(it);
    }

    void state::process_cert(const update_drep_cert &c, const cert_loc_t &)
    {
        const auto drep_it = _dreps.find(c.drep_id);
        if (drep_it ==_dreps.end()) [[unlikely]]
            throw error("unreg_drep_cert: an unknown drep_id: {}", c.drep_id);
        drep_it->second.anchor = c.anchor;
    }

    void state::process_proposal(const proposal_t &p, const cert_loc_t &loc)
    {
        logger::debug("a proposal {} at slot: {} deposit: {} stake_id: {}", p.action_id, loc.slot, p.deposit, p.stake_id);
        _gov_actions.try_emplace(p.action_id, p.deposit, p.stake_id, p.action, p.anchor,
            _epoch, _epoch + _params_prev.gov_action_lifetime);
        _deposited += p.deposit;
    }

    void state::process_vote(const vote_info_t &v, const cert_loc_t &)
    {
        logger::debug("vote for {} from {}: {}", v.action_id, v.voter, v.voting_procedure);
        if (auto gov_it = _gov_actions.find(v.action_id); gov_it != _gov_actions.end()) [[unlikely]] {
            switch (v.voter.type) {
                case voter_t::type_t::const_comm_key:
                case voter_t::type_t::const_comm_script: {
                    const credential_t hot_id { v.voter.hash, v.voter.type == voter_t::type_t::const_comm_script };
                    const auto it = std::find_if(_committee.hot_keys.begin(), _committee.hot_keys.end(), [&](const auto &item) {
                        return std::holds_alternative<credential_t>(item.second) && std::get<credential_t>(item.second) == hot_id && _committee.members.contains(item.first);
                    });
                    if (it == _committee.hot_keys.end()) [[unlikely]]
                        throw error("a vote from an unknown committee member with a git hot_id: {}", hot_id);
                    // convert the vote from the hot_id to the cold_id
                    const auto &cold_id = it->first;
                    const voter_t c_voter { cold_id.script ? voter_t::type_t::const_comm_script : voter_t::type_t::const_comm_key, cold_id.hash };
                    gov_it->second.votes[c_voter] = v.voting_procedure;
                    break;
                }
                case voter_t::type_t::drep_key:
                case voter_t::type_t::drep_script: {
                    const credential_t drep_id { v.voter.hash, v.voter.type == voter_t::type_t::drep_script };
                    auto it = _dreps.find(drep_id);
                    if (it == _dreps.end()) [[unlikely]]
                        throw error("a vote from an unknown drep: {}", drep_id);
                    it->second.epoch_inactive = _epoch + _params_prev.drep_activity;
                    gov_it->second.votes[v.voter] = v.voting_procedure;
                    break;
                }
                case voter_t::type_t::pool_key: {
                    if (!_mark.pool_params.contains(v.voter.hash)) [[unlikely]]
                        throw error("a vote from an unknown pool: {}", v.voter.hash);
                    gov_it->second.votes[v.voter] = v.voting_procedure;
                    break;
                }
                default: throw error("an unsupported voter type: {}", v.voter.type);
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
           return zpp::serialize(_constitution);
        });
        ser.add([&] {
           return zpp::serialize(_committee);
        });
        ser.add([&] {
            return zpp::serialize(_dreps);
        });
        ser.add([&] {
            return zpp::serialize(_drep_stake);
        });
        ser.add([&] {
            return zpp::serialize(_gov_actions);
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
            zpp::deserialize(_constitution, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_committee, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_dreps, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_drep_stake, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_gov_actions, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_donations, b);
        });
        dec.add([&](const auto b) {
            zpp::deserialize(_conway_start_epoch, b);
        });
        babbage::state::from_zpp(dec);
    }

    void state::_finalize_gov_actions()
    {
        vector<gov_action_id_t> retired_actions {};
        for (const auto &[id, action]: _gov_actions) {
            if (_epoch > action.epoch_expires) {
                retired_actions.emplace_back(id);
                auto [acc_it, created] = _accounts.try_emplace(action.stake_id);
                if (created)
                    logger::warn("gov_action {} deposit is returned to an unregistered stake_id: {}", id, action.stake_id);
                acc_it->second.reward += action.deposit;
                _deposited -= action.deposit;
            }
        }
        for (const auto &id: retired_actions)
            _gov_actions.erase(id);
    }

    void state::_calc_gov_action_votes()
    {
        alignas(mutex::padding) mutex::unique_lock::mutex_type drep_mutex {};
        drep_t drep_abstain { drep_t::abstain };
        _drep_stake.clear();
        static const std::string task_id { "drep-stake" };
        _sched.wait_all_done(task_id, _accounts.num_parts, [&] {
            for (size_t part_no = 0; part_no < _accounts.num_parts; ++part_no) {
                _sched.submit_void(task_id, 1000, [&, part_no] {
                    map<drep_t, uint64_t> part_stake {};
                    const auto &acc_part = _accounts.partition(part_no);
                    for (const auto &[stake_id, info]: acc_part) {
                        if (info.vote_deleg && (info.vote_deleg->typ != drep_t::credential || _dreps.contains(info.vote_deleg->cred.value()))) {
                            part_stake[*info.vote_deleg] += info.stake + info.reward;
                        } else {
                            part_stake[drep_abstain] += info.stake + info.reward;
                        }
                    }
                    mutex::scoped_lock lk { drep_mutex };
                    for (const auto &[drep, stake]: part_stake)
                        _drep_stake[drep] += stake;
                });
            }
        });
    }

    void state::start_epoch(const std::optional<uint64_t> new_epoch)
    {
        babbage::state::start_epoch(new_epoch);
        if (!_conway_start_epoch)
            _conway_start_epoch.emplace(_epoch);
        if (!_stake_pointers.empty() && _epoch > *_conway_start_epoch)
            _stake_pointers.clear();
        _treasury += _donations;
        _donations = 0;
        _calc_gov_action_votes();
        _finalize_gov_actions();
    }
}