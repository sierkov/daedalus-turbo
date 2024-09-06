/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/alonzo.hpp>
#include <dt/plutus/parser.hpp>
#include <dt/plutus/machine.hpp>

namespace daedalus_turbo::cardano::alonzo {
    static plutus::term _make_tx_context(const tx &/*tx*/)
    {
        /*plutus::constant_list ctx {};
        {
            plutus::constant_list inputs {};
            tx.foreach_input([&](const auto &txin) {
                inputs.emplace_back(plutus::constant::make_constant(
                    ))
            });
            ctx.emplace_back(plutus::constant::make_list(std::move(inputs)));
        }
        return plutus::term::make_list(std::move(ctx));*/
        return plutus::term::make_unit();
    }

    static void _evaluate_script(const script_info &script, const cbor::value &datum, const cbor::value &redeemer, const plutus::term &context)
    {
        plutus::script s { script.script() };
        logger::info("script hash: {}", s.hash());
        logger::info("datum: {}", datum);
        logger::info("redeemer: {}", redeemer);
        logger::info("program: {}", s.program());
        plutus::term_list args {};
        if (datum.type == CBOR_BYTES)
            args.emplace_back(plutus::term::make_constant(plutus::constant::make_bstr(datum.buf())));
        else
            args.emplace_back(plutus::term::make_unit());
        args.emplace_back(plutus::builtins::un_constr_data(plutus::term::make_data(redeemer.raw_span())));
        args.emplace_back(context);
        plutus::machine m {};
        m.evaluate(s, args);
        // - returns a true value
        // - new datum matches the transaction output's datum
        // - script evaluation resources are within the budget
        // - script evaluation costs and match the fee
    }

    void tx::_validate_witness_plutus_v1(wit_ok &ok, const cbor::array &redeemers, const script_info_map &scripts, const cbor::array *data,
        const vector<tx_out_data> &input_data, const vector<script_hash> &policies) const
    {
        if (!data || data->size() != redeemers.size())
            throw error("invalid number of scripts, data and redeemer items!");
        const auto context = _make_tx_context(*this);
        for (size_t ri = 0; ri < redeemers.size(); ++ri) {
            ++ok.script_total;
            const auto &r = redeemers[ri];
            const auto r_type = r.at(0).uint();
            const auto r_idx = r.at(1).uint();
            switch (r_type) {
                case 0: {
                    const address addr { input_data.at(r_idx).address };
                    if (const auto pay_id = addr.pay_id(); pay_id.type == pay_ident::ident_type::SHELLEY_SCRIPT) [[likely]]
                        _evaluate_script(scripts.at(pay_id.hash), data->at(ri), r.at(2), context);
                    else
                        throw error("txin txo address references from tx {} redeemer #{} is not a payment script!", hash(), ri);
                    break;
                }
                case 1:
                    if (r_idx < policies.size()) [[likely]]
                        _evaluate_script(scripts.at(policies[r_idx]), data->at(ri), r.at(2), context);
                    else
                        throw error("tx: {} mint redeemer references a too big mint policy index: {}", hash(), r_idx);
                    break;
                default:
                    throw error("tx: {} unsupported redeemer_tag: {}", hash(), r_type);
            }
            ++ok.script_ok;
        }
    }

    tx::wit_ok tx::witnesses_ok(const tx_out_data_list *input_data) const
    {
        if (!_wit) [[unlikely]]
            throw cardano_error("vkey_witness_ok called on a transaction without witness data!");
        const cbor::array *plutus_data = nullptr;
        wit_ok ok {};
        // validate vkey witnesses and create a vkeys set for the potential native script validation
        set<key_hash> vkeys {};
        script_info_map scripts {};
        for (const auto &[w_type, w_val]: _wit->map()) {
            switch (w_type.uint()) {
                case 0: _validate_witness_vkey(ok, vkeys, w_val); break;
                case 3: {
                    for (const auto &script_raw: w_val.array()) {
                        script_info si { script_type::plutus_v1, script_raw.buf() };
                        const auto script_hash = si.hash();
                        scripts.try_emplace(script_hash, std::move(si));
                    }
                    break;
                }
                case 4: plutus_data = &w_val.array(); break;
                default: break;
            }
        }
        if (!scripts.empty() && !input_data) [[unlikely]]
            throw error("input_data must be prepared for witness validation of Alonzo+ transaction witnesses");
        // prepare data structures to resolve redeemers
        vector<tx_out_ref> inputs {};
        foreach_input([&](const auto &txin) {
            inputs.emplace_back(txin.tx_hash, txin.txo_idx);
        });
        vector<script_hash> mint_policies {};
        foreach_mint([&](const auto &policy_id, const auto &) {
            mint_policies.emplace_back(policy_id);
        });
        // validate native scripts and bootstrap witnesses
        for (const auto &[w_type, w_val]: _wit->map()) {
            switch (w_type.uint()) {
                case 0:
                case 3:
                case 4:
                    break; // ignore - has been processed above
                case 1: _validate_witness_native_script(ok, w_val, vkeys); break;
                case 2: _validate_witness_bootstrap(ok, w_val); break;
                case 5: _validate_witness_plutus_v1(ok, w_val.array(), scripts, plutus_data, *input_data, mint_policies); break;
                default: throw cardano_error("unsupported witness type {} at tx {}: {}", w_type.uint(), hash(), w_val);
            }
        }
        return ok;
    }
}
