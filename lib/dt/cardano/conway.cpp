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

    anchor_t::anchor_t(const cbor::value &v):
        url { v.at(0).buf().string_view() }, hash { v.at(1).buf() }
    {
    }

    anchor_t::anchor_t(const json::value &j):
        url { j.at("url").as_string() }, hash { datum_hash::from_hex(j.at("dataHash").as_string()) }
    {
    }

    void anchor_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(2).text(url).bytes(hash);
    }

    param_update_t::param_update_t(const cbor::value &v)
    {
        for (const auto &[u_typ, u]: v.map()) {
            switch (const auto typ = u_typ.uint(); typ) {
                case 0: min_fee_a.emplace(u.uint()); break;
                case 1: min_fee_b.emplace(u.uint()); break;
                case 2: max_block_body_size.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 3: max_transaction_size.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 4: max_block_header_size.emplace(narrow_cast<uint16_t>(u.uint())); break;
                case 5: key_deposit.emplace(u.uint()); break;
                case 6: pool_deposit.emplace(u.uint()); break;
                case 7: e_max.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 8: n_opt.emplace(u.uint()); break;
                case 9: pool_pledge_influence.emplace(u); break;
                case 10: expansion_rate.emplace(u); break;
                case 11: treasury_growth_rate.emplace(u); break;
                case 16: min_pool_cost.emplace(u.uint()); break;
                case 17: lovelace_per_utxo_byte.emplace(u.uint()); break;
                case 18: plutus_cost_models.emplace(u); break;
                case 19: ex_unit_prices.emplace(u); break;
                case 20: max_tx_ex_units.emplace(u); break;
                case 21: max_block_ex_units.emplace(u); break;
                case 22: max_value_size.emplace(u.uint()); break;
                case 23: max_collateral_pct.emplace(u.uint()); break;
                case 24: max_collateral_inputs.emplace(u.uint()); break;
                case 25: pool_voting_thresholds.emplace(u); break;
                case 26: drep_voting_thresholds.emplace(u); break;
                case 27: comittee_min_size.emplace(narrow_cast<uint16_t>(u.uint())); break;
                case 28: comittee_max_term_length.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 29: gov_action_lifetime.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 30: gov_action_deposit.emplace(u.uint()); break;
                case 31: drep_deposit.emplace(u.uint()); break;
                case 32: drep_activity.emplace(narrow_cast<uint32_t>(u.uint())); break;
                case 33: min_fee_ref_script_cost_per_byte.emplace(u.uint()); break;
                default: throw error("unsupported conway param update: {}", u);
            }
        }
    }

    gov_action_id_t::gov_action_id_t(const buffer tx_id_, const uint64_t idx_):
        tx_id {  tx_id_ }, idx { narrow_cast<uint16_t>(idx_) }
    {
    }

    gov_action_id_t::gov_action_id_t(const cbor::value &v):
        tx_id {  v.at(0).buf() }, idx { narrow_cast<uint16_t>(v.at(1).uint()) }
    {
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
            default: throw error("unsupported voter type: {}", typ);
        }
    }

    voter_t::voter_t(const cbor::value &v):
        type { voter_type_from_cbor(v.at(0)) }, hash { v.at(1).buf() }
    {
    }

    proposal_t::proposal_t(const gov_action_id_t &id, const cbor::value &v):
        stake_id { address { v.at(1).buf() }.stake_id() }, deposit { v.at(0).uint() },
        action_id { id }, action { v.at(2) }, anchor { v.at(3) }
    {
    }

    vote_t vote_from_cbor(const cbor::value &v)
    {
        switch (const auto vote = v.uint(); vote) {
            case 0: return vote_t::no;
            case 1: return vote_t::yes;
            case 2: return vote_t::abstain;
            default: throw error("unsupported vote: {}", vote);
        }
    }

    voting_procedure_t::voting_procedure_t(const cbor::value &v):
        vote { vote_from_cbor(v.at(0)) }
    {
        if (v.at(1).type == CBOR_ARRAY)
            anchor.emplace(v.at(1));
    }

    void voting_procedure_t::to_cbor(cbor::encoder &enc) const
    {
        switch (vote) {
            case vote_t::no: enc.uint(0); break;
            case vote_t::yes: enc.uint(1); break;
            case vote_t::abstain: enc.uint(2); break;
            default: throw error("unsupported vote: {}", static_cast<int>(vote));
        }
    }

    gov_action_t::parameter_change_t::parameter_change_t(const cbor::value &v):
        prev_action_id { v.at(1) }, update { v.at(2) }, policy_id { v.at(3) }
    {
        if (const auto typ = v.at(0).uint(); typ != 0) [[unlikely]]
            throw error("parameter_change action must have type 0 but got: {}", typ);
    }

    static gov_action_t::value_type gov_action_t_from_cbor(const cbor::value &v)
    {
        switch (const auto typ = v.at(0).uint(); typ) {
            case 0: return gov_action_t::parameter_change_t { v };
            case 1: return gov_action_t::hard_fork_init_t {};
            case 2: return gov_action_t::treasury_withdrawals_t {};
            case 3: return gov_action_t::no_confidence_t {};
            case 4: return gov_action_t::update_committee_t {};
            case 5: return gov_action_t::new_constitution_t {};
            case 6: return gov_action_t::info_action_t {};
            default: throw error("unsupported gov action type: {}", typ);
        }
    }

    gov_action_t::gov_action_t(const cbor::value &v):
        val { gov_action_t_from_cbor(v) }
    {
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
                throw error("unsupported gov_action: {}", typeid(T).name());
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
                throw error("unsupported certificate type: {}", typeid(T).name());
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
                default: throw error("unsupported redeemer CBOR: {}", w_val);
            }
        });
    }

    void tx::foreach_vote(const vote_observer_t &observer) const
    {
        for (const auto &[entry_type, entry]: _tx.map()) {
            if (entry_type.uint() == 19) {
                for (const auto &[voter, actions]: entry.map()) {
                    for (const auto &[action_id, vote]: actions.map()) {
                        observer({ voter_t { voter }, gov_action_id_t { action_id }, voting_procedure_t { vote } });
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
                    observer(proposal_t { gov_action_id_t { hash(), idx }, v });
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
