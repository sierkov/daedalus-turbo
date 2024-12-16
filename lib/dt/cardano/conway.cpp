/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <boost/url/url.hpp>
#include <boost/url/urls.hpp>
#include <dt/cardano/cert.hpp>
#include <dt/cardano/conway.hpp>
#include <dt/narrow-cast.hpp>
#include <dt/plutus/context.hpp>
#include <dt/plutus/flat.hpp>
#include <dt/plutus/machine.hpp>
#include <dt/plutus/types.hpp>

namespace daedalus_turbo::cardano::conway {
    using namespace plutus;

    anchor_t anchor_t::from_cbor(const cbor::value &v)
    {
        return { std::string { v.at(0).buf().string_view() }, v.at(1).buf() };
    }

    anchor_t anchor_t::from_json(const json::value &j)
    {
        return { json::value_to<std::string>(j.at("url")), datum_hash::from_hex(j.at("dataHash").as_string()) };
    }

    void anchor_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(2).text(url).bytes(hash);
    }

    param_update_t param_update_t::from_cbor(const cbor::value &v)
    {
        param_update_t upd {};
        for (const auto &[u_typ, u]: v.map()) {
            switch (const auto typ = u_typ.uint(); typ) {
                case 0: upd.min_fee_a.emplace(u.uint()); break;
                case 1: upd.min_fee_b.emplace(u.uint()); break;
                case 2: upd.max_block_body_size.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 3: upd.max_transaction_size.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 4: upd.max_block_header_size.emplace(narrow_cast<uint16_t>(u.uint())); break;
                case 5: upd.key_deposit.emplace(u.uint()); break;
                case 6: upd.pool_deposit.emplace(u.uint()); break;
                case 7: upd.e_max.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 8: upd.n_opt.emplace(u.uint()); break;
                case 9: upd.pool_pledge_influence.emplace(u); break;
                case 10: upd.expansion_rate.emplace(u); break;
                case 11: upd.treasury_growth_rate.emplace(u); break;
                case 16: upd.min_pool_cost.emplace(u.uint()); break;
                case 17: upd.lovelace_per_utxo_byte.emplace(u.uint()); break;
                case 18: upd.plutus_cost_models.emplace(u); break;
                case 19: upd.ex_unit_prices.emplace(u); break;
                case 20: upd.max_tx_ex_units.emplace(u); break;
                case 21: upd.max_block_ex_units.emplace(u); break;
                case 22: upd.max_value_size.emplace(u.uint()); break;
                case 23: upd.max_collateral_pct.emplace(u.uint()); break;
                case 24: upd.max_collateral_inputs.emplace(u.uint()); break;
                case 25: upd.pool_voting_thresholds.emplace(u); break;
                case 26: upd.drep_voting_thresholds.emplace(u); break;
                case 27: upd.committee_min_size.emplace(narrow_cast<uint16_t>(u.uint())); break;
                case 28: upd.committee_max_term_length.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 29: upd.gov_action_lifetime.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 30: upd.gov_action_deposit.emplace(u.uint()); break;
                case 31: upd.drep_deposit.emplace(u.uint()); break;
                case 32: upd.drep_activity.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 33: upd.min_fee_ref_script_cost_per_byte.emplace(u); break;
                default: throw error(fmt::format("unsupported conway param update: {}", u));
            }
        }
        return upd;
    }

    bool param_update_t::security_group() const
    {
        bool res = false;
        res |= min_fee_a.has_value();
        res |= min_fee_b.has_value();
        res |= max_block_body_size.has_value();
        res |= max_transaction_size.has_value();
        res |= max_block_header_size.has_value();
        res |= lovelace_per_utxo_byte.has_value();
        res |= max_block_ex_units.has_value();
        res |= max_value_size.has_value();
        res |= gov_action_deposit.has_value();
        res |= min_fee_ref_script_cost_per_byte.has_value();
        return res;
    }

    bool param_update_t::network_group() const
    {
        bool res = false;
        res |= max_block_body_size.has_value();
        res |= max_transaction_size.has_value();
        res |= max_block_header_size.has_value();
        res |= max_tx_ex_units.has_value();
        res |= max_block_ex_units.has_value();
        res |= max_value_size.has_value();
        res |= max_collateral_inputs.has_value();
        return res;
    }

    bool param_update_t::economic_group() const
    {
        bool res = false;
        res |= min_fee_a.has_value();
        res |= min_fee_b.has_value();
        res |= key_deposit.has_value();
        res |= pool_deposit.has_value();
        res |= lovelace_per_utxo_byte.has_value();
        res |= ex_unit_prices.has_value();
        res |= min_fee_ref_script_cost_per_byte.has_value();
        // res |= min_ref_script_size_per_tx.has_value();
        // res |= min_ref_script_size_per_block.has_value();
        // res |= ref_script_cost_stride.has_value();
        // res |= ref_script_cost_multiplier.has_value();
        return res;
    }

    bool param_update_t::technical_group() const
    {
        bool res = false;
        res |= e_max.has_value();
        res |= n_opt.has_value();
        res |= expansion_rate.has_value();
        res |= max_collateral_pct.has_value();
        res |= plutus_cost_models.has_value();
        return res;
    }

    bool param_update_t::governance_group() const
    {
        bool res = false;
        res |= pool_voting_thresholds.has_value();
        res |= drep_voting_thresholds.has_value();
        res |= committee_min_size.has_value();
        res |= committee_max_term_length.has_value();
        res |= gov_action_lifetime.has_value();
        res |= gov_action_deposit.has_value();
        res |= drep_deposit.has_value();
        res |= drep_activity.has_value();
        return res;
    }

    gov_action_id_t gov_action_id_t::from_cbor(const cbor::value &v)
    {
        return { v.at(0).buf(), narrow_cast<uint16_t>(v.at(1).uint()) };
    }

    void gov_action_id_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(2)
            .bytes(tx_id)
            .uint(idx);
    }

    voter_t::type_t voter_type_from_cbor(const cbor::value &v)
    {
        switch (const auto typ = v.uint(); typ) {
            case 0: return voter_t::const_comm_key;
            case 1: return voter_t::const_comm_script;
            case 2: return voter_t::drep_key;
            case 3: return voter_t::drep_script;
            case 4: return voter_t::pool_key;
            default: throw error(fmt::format("unsupported voter type: {}", typ));
        }
    }

    voter_t voter_t::from_cbor(const cbor::value &v)
    {
        return { voter_type_from_cbor(v.at(0)), v.at(1).buf() };
    }

    proposal_procedure_t proposal_procedure_t::from_cbor(const cbor::value &v)
    {
        return {
            v.at(0).uint(),
            address { v.at(1).buf() }.stake_id(),
            gov_action_t::from_cbor(v.at(2)),
            anchor_t::from_cbor(v.at(3))
        };
    }

    void proposal_procedure_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(4);
        enc.uint(deposit);
        array<uint8_t, sizeof(return_addr.hash) + 1> stake_addr;
        stake_addr[0] = return_addr.script ? 0xF1 : 0xE1;
        memcpy(stake_addr.data() + 1, return_addr.hash.data(), return_addr.hash.size());
        enc.bytes(stake_addr);
        action.to_cbor(enc);
        anchor.to_cbor(enc);
    }

    proposal_t proposal_t::from_cbor(const gov_action_id_t &id_, const cbor::value &v)
    {
        return { id_, proposal_procedure_t::from_cbor(v) };
    }

    vote_t vote_from_cbor(const cbor::value &v)
    {
        switch (const auto vote = v.uint(); vote) {
            case 0: return vote_t::no;
            case 1: return vote_t::yes;
            case 2: return vote_t::abstain;
            default: throw error(fmt::format("unsupported vote: {}", vote));
        }
    }

    voting_procedure_t voting_procedure_t::from_cbor(const cbor::value &v)
    {
        return { vote_from_cbor(v.at(0)), optional_anchor_t::from_cbor(v.at(1)) };
    }

    void voting_procedure_t::to_cbor(cbor::encoder &enc) const
    {
        switch (vote) {
            case vote_t::no: enc.uint(0); break;
            case vote_t::yes: enc.uint(1); break;
            case vote_t::abstain: enc.uint(2); break;
            default: throw error(fmt::format("unsupported vote: {}", static_cast<int>(vote)));
        }
    }

    constitution_t constitution_t::from_cbor(const cbor::value &v)
    {
        return { anchor_t::from_cbor(v.at(0)), optional_t<script_hash>::from_cbor(v.at(1)) };
    }

    constitution_t constitution_t::from_json(const json::value &j)
    {
        return {
            anchor_t::from_json(j.at("anchor")),
            script_hash::from_hex(j.at("script").as_string())
        };
    }

    void constitution_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(2);
        anchor.to_cbor(enc);
        policy_id.to_cbor(enc);
    }

    gov_action_t::parameter_change_t gov_action_t::parameter_change_t::from_cbor(const cbor::value &v)
    {
        return {
            optional_gov_action_id_t::from_cbor(v.at(1)),
            param_update_t::from_cbor(v.at(2)),
            optional_script_t::from_cbor(v.at(3))
        };
    }

    gov_action_t::hard_fork_init_t gov_action_t::hard_fork_init_t::from_cbor(const cbor::value &v)
    {
        return {
            optional_gov_action_id_t::from_cbor(v.at(1)),
            protocol_version { v.at(2) }
        };
    }

    gov_action_t::treasury_withdrawals_t gov_action_t::treasury_withdrawals_t::from_cbor(const cbor::value &v)
    {
        ledger::stake_distribution withdrawals {};
        for (const auto &[addr, coin]: v.at(1).map())
            withdrawals.add(address { addr.buf() }.stake_id(), coin.uint());
        return {
            std::move(withdrawals),
            optional_script_t::from_cbor(v.at(2))
        };
    }

    gov_action_t::no_confidence_t gov_action_t::no_confidence_t::from_cbor(const cbor::value &v)
    {
        return { optional_gov_action_id_t::from_cbor(v.at(1)) };
    }

    gov_action_t::update_committee_t gov_action_t::update_committee_t::from_cbor(const cbor::value &v)
    {
        map<credential_t, uint64_t> members_to_add {};
        for (const auto &[addr, expires_after]: v.at(3).map()) {
            // ensure that in the case of multiple CBOR entries the last value take precedence
            members_to_add[credential_t::from_cbor(addr)] = expires_after.uint();
        }
        return {
            optional_gov_action_id_t::from_cbor(v.at(1)),
            set_t<credential_t>::from_cbor(v.at(2)),
            std::move(members_to_add),
            v.at(4)
        };
    }

    gov_action_t::new_constitution_t gov_action_t::new_constitution_t::from_cbor(const cbor::value &v)
    {
        return {
            optional_gov_action_id_t::from_cbor(v.at(1)),
            constitution_t::from_cbor(v.at(2))
        };
    }

    gov_action_t::info_action_t gov_action_t::info_action_t::from_cbor(const cbor::value &)
    {
        return {};
    }

    static gov_action_t::value_type gov_action_t_from_cbor(const cbor::value &v)
    {
        switch (const auto typ = v.at(0).uint(); typ) {
            case 0: return gov_action_t::parameter_change_t::from_cbor(v);
            case 1: return gov_action_t::hard_fork_init_t::from_cbor(v);
            case 2: return gov_action_t::treasury_withdrawals_t::from_cbor(v);
            case 3: return gov_action_t::no_confidence_t::from_cbor(v);
            case 4: return gov_action_t::update_committee_t::from_cbor(v);
            case 5: return gov_action_t::new_constitution_t::from_cbor(v);
            case 6: return gov_action_t::info_action_t::from_cbor(v);
            default: throw error(fmt::format("unsupported gov action type: {}", typ));
        }
    }

    gov_action_t gov_action_t::from_cbor(const cbor::value &v)
    {
        return { gov_action_t_from_cbor(v) };
    }

    void gov_action_t::to_cbor(cbor::encoder &enc) const
    {
        std::visit([&](const auto &v) {
            using T = std::decay_t<decltype(v)>;
            enc.array(1);
            if constexpr (std::is_same_v<T, parameter_change_t>) {
                enc.uint(0);
            } else if constexpr (std::is_same_v<T, hard_fork_init_t>) {
                enc.uint(1);
            } else if constexpr (std::is_same_v<T, treasury_withdrawals_t>) {
                enc.uint(2);
            } else if constexpr (std::is_same_v<T, no_confidence_t>) {
                enc.uint(3);
            } else if constexpr (std::is_same_v<T, update_committee_t>) {
                enc.uint(4);
            } else if constexpr (std::is_same_v<T, new_constitution_t>) {
                enc.uint(5);
            } else if constexpr (std::is_same_v<T, info_action_t>) {
                enc.uint(6);
            } else {
                throw error(fmt::format("unsupported gov_action: {}", typeid(T).name()));
            }
        }, val);
    }

    static cert_t::value_type cert_from_cbor(const cbor::value &v)
    {
        const cert_any_t cert_any { cert_any_t::from_cbor(v) };
        return std::visit<cert_t::value_type>([&](auto &&vv) {
            using T = std::decay_t<decltype(vv)>;
            if constexpr (std::is_same_v<T, stake_reg_cert>
                    || std::is_same_v<T, stake_dereg_cert>
                    || std::is_same_v<T, stake_deleg_cert>
                    || std::is_same_v<T, pool_reg_cert>
                    || std::is_same_v<T, pool_retire_cert>
                    || std::is_same_v<T, reg_cert>
                    || std::is_same_v<T, unreg_cert>
                    || std::is_same_v<T, vote_deleg_cert>
                    || std::is_same_v<T, stake_vote_deleg_cert>
                    || std::is_same_v<T, stake_reg_deleg_cert>
                    || std::is_same_v<T, vote_reg_deleg_cert>
                    || std::is_same_v<T, stake_vote_reg_deleg_cert>
                    || std::is_same_v<T, auth_committee_hot_cert>
                    || std::is_same_v<T, resign_committee_cold_cert>
                    || std::is_same_v<T, reg_drep_cert>
                    || std::is_same_v<T, unreg_drep_cert>
                    || std::is_same_v<T, update_drep_cert>)
                return cert_t::value_type { std::move(vv) };
            throw error("certificate types 5 and 6 are not supported in conway era!");
            // Make Visual C++ happy
            return cert_t::value_type { stake_reg_cert {} };
        }, std::move(cert_any.val));
    }

    cert_t::cert_t(const cbor::value &v): val { cert_from_cbor(v) }
    {
    }

    const credential_t &cert_t::cred() const
    {
        static credential_t empty {};
        return std::visit([&](const auto &c)-> auto const & {
            using T = std::decay_t<decltype(c)>;
            if constexpr (std::is_same_v<T, auth_committee_hot_cert>
                    || std::is_same_v<T, resign_committee_cold_cert>) {
                return c.cold_id;
            } else if constexpr (std::is_same_v<T, reg_drep_cert>
                   || std::is_same_v<T, unreg_drep_cert>
                   || std::is_same_v<T, update_drep_cert>) {
                return c.drep_id;
            } else if constexpr (std::is_same_v<T, pool_reg_cert>
                   || std::is_same_v<T, pool_retire_cert>) {
                throw error(fmt::format("unsupported certificate type: {}", typeid(T).name()));
                return empty;
            } else {
                return c.stake_id;
            }
        }, val);
    }

    void tx::foreach_set(const cbor_value &set_raw, const std::function<void(const cbor_value &, size_t)> &observer) const
    {
        set<buffer> unique {};
        const auto &set = (set_raw.type == CBOR_TAG ? *set_raw.tag().second : set_raw).array();
        for (const auto &v: set) {
            const auto prev_size = unique.size();
            if (const auto [it, created] = unique.emplace(v.raw_span()); created)
                observer(v, prev_size);
        }
    }

    void tx::foreach_redeemer(const std::function<void(const tx_redeemer &)> &observer) const
    {
        foreach_witness([&](const auto typ, const auto &w_val) {
            if (typ != 5)
                return;
            switch (w_val.type) {
                case CBOR_ARRAY: {
                    const auto &redeemers = w_val.array();
                    for (size_t ri = 0; ri < redeemers.size(); ++ri) {
                        const auto &r = redeemers[ri];
                        observer(tx_redeemer {
                            redeemer_tag_from_cbor(r.at(0)),
                            narrow_cast<uint16_t>(ri),
                            narrow_cast<uint16_t>(r.at(1).uint()),
                            r.at(2).raw_span(),
                            r.at(3)
                        });
                    }
                    break;
                }
                case CBOR_MAP: {
                    const auto &redeemers = w_val.map();
                    for (size_t ri = 0; ri < redeemers.size(); ++ri) {
                        const auto &[k, v] = redeemers[ri];
                        observer(tx_redeemer {
                            redeemer_tag_from_cbor(k.at(0)),
                            narrow_cast<uint16_t>(ri),
                            narrow_cast<uint16_t>(k.at(1).uint()),
                            v.at(0).raw_span(),
                            v.at(1)
                        });
                    }
                    break;
                }
                default: throw error(fmt::format("unsupported redeemer CBOR: {}", w_val));
            }
        });
    }

    void tx::foreach_vote(const vote_observer_t &observer) const
    {
        for (const auto &[entry_type, entry]: _tx.map()) {
            if (entry_type.uint() == 19) {
                for (const auto &[voter, actions]: entry.map()) {
                    for (const auto &[action_id, vote]: actions.map()) {
                        observer({
                            voter_t::from_cbor(voter),
                            gov_action_id_t::from_cbor(action_id),
                            voting_procedure_t::from_cbor(vote)
                        });
                    }
                }
                break;
            }
        }
    }

    void tx::foreach_proposal(const proposal_observer_t &observer) const
    {
        for (const auto &[entry_type, entry]: _tx.map()) {
            if (entry_type.uint() == 20) {
                foreach_set(entry, [&](const cbor::value &v, const size_t idx) {
                    observer(proposal_t {
                        gov_action_id_t { hash(), narrow_cast<uint16_t>(idx) },
                        proposal_procedure_t::from_cbor(v)
                    });
                });
                break;
            }
        }
    }

    std::optional<uint64_t> tx::current_treasury() const
    {
        std::optional<uint64_t> res {};
        for (const auto &[entry_type, entry]: _tx.map()) {
            if (entry_type.uint() == 21) {
                res.emplace(entry.uint());
                break;
            }
        }
        return res;
    }

    uint64_t tx::donation() const
    {
        for (const auto &[entry_type, entry]: _tx.map()) {
            if (entry_type.uint() == 22)
                return entry.uint();
        }
        return 0;
    }

    void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        std::set<size_t> invalid_tx_idxs {};
        for (const auto &tx_idx: invalid_transactions())
            invalid_tx_idxs.emplace(tx_idx.uint());
        for (size_t i = 0; i < txs.size(); ++i)
            if (!invalid_tx_idxs.contains(i))
                observer(tx { txs.at(i), *this, i, &wits.at(i), auxiliary_at(i), false });
    }

    void block::foreach_invalid_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        if (const auto &inv_txs = invalid_transactions(); !inv_txs.empty()) [[unlikely]] {
            for (const auto &tx_idx: inv_txs)
                observer(tx { txs.at(tx_idx.uint()), *this, tx_idx.uint(), &wits.at(tx_idx.uint()), auxiliary_at(tx_idx.uint()), true });
        }
    }
}
