/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/alonzo.hpp>
#include <dt/plutus/builtins.hpp>
#include <dt/plutus/flat.hpp>
#include <dt/plutus/machine.hpp>
#include <dt/plutus/context.hpp>

namespace daedalus_turbo::cardano::alonzo {
    using namespace daedalus_turbo::plutus;

    static void _evaluate_plutus(const script_info &script, const cbor::value &datum, const cbor::value &redeemer, const term_ptr &t_ctx)
    {
        using namespace plutus;
        flat::script s { script.script() };
        auto t_datum = term::make_ptr(constant { data { datum.buf() } });
        auto t_redeemer = term::make_ptr(constant { data { buffer { redeemer.raw_span() } } });
        // Todo: force maximum evaluation budget
        machine m {};
        const auto [expr, cost] = m.evaluate(s.program(), { t_datum, t_redeemer, t_ctx });
    }

    static void _validate_plutus(tx::wit_ok &ok, const tx &tx, const cbor::array &redeemers, const script_info_map &scripts, const cbor::array *data,
        const resolved_input_list &inputs, const mint_info_list &mints, const set<key_hash> &signatories)
    {
        if (!data || data->size() != redeemers.size())
            throw error("invalid number of scripts, data and redeemer items!");
        context ctx { tx, inputs, mints, signatories };
        for (size_t ri = 0; ri < redeemers.size(); ++ri) {
            ++ok.script_total;
            const auto &r = redeemers[ri];
            const auto r_type = r.at(0).uint();
            const auto r_idx = r.at(1).uint();
            switch (r_type) {
                case 0: {
                    const auto &in = inputs.at(r_idx);
                    const address addr { in.data.address };
                    if (const auto pay_id = addr.pay_id(); pay_id.type == pay_ident::ident_type::SHELLEY_SCRIPT) [[likely]]
                        _evaluate_plutus(scripts.at(pay_id.hash), data->at(ri), r.at(2), ctx.v1(purpose { in }));
                    else
                        throw error("txin txo address references from tx {} redeemer #{} is not a payment script!", tx.hash(), ri);
                    break;
                }
                case 1:
                    if (r_idx < mints.size()) [[likely]] {
                        const auto &m = mints[r_idx];
                        _evaluate_plutus(scripts.at(m.policy_id), data->at(ri), r.at(2), ctx.v1(purpose { m }));
                    } else {
                        throw error("tx: {} mint redeemer references a too big mint policy index: {}", tx.hash(), r_idx);
                    }
                    break;
                default:
                    throw error("tx: {} unsupported redeemer_tag: {}", tx.hash(), r_type);
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

        for (const auto &[w_type, w_val]: _wit->map()) {
            switch (w_type.uint()) {
                case 0:
                case 3:
                case 4:
                    break; // ignore - has been processed above
                case 1: _validate_witness_native_script(ok, w_val, vkeys); break;
                case 2: _validate_witness_bootstrap(ok, w_val); break;
                case 5: break; // validated later
                default: throw cardano_error("unsupported witness type {} at tx {}: {}", w_type.uint(), hash(), w_val);
            }
        }

        if (!scripts.empty()) {
            if (!input_data) [[unlikely]]
                throw error("input_data must be prepared for witness validation of Alonzo+ transaction witnesses");

            // prepare resolved inputs
            tx_out_ref_list input_refs {};
            resolved_input_list inputs {};
            foreach_input([&input_refs](const tx_input &txin) {
                input_refs.emplace_back(tx_out_ref::from_input(txin));
            });
            if (input_refs.size() != input_data->size())
                throw error("invalid number of resolved tx inputs: {} while expected: {}", input_data->size(), input_refs.size());
            for (size_t ri = 0; ri < input_refs.size(); ++ri)
                inputs.emplace_back(input_refs[ri], (*input_data)[ri]);

            // prepare mints
            vector<mint_info> mints {};
            foreach_mint([&mints](const auto &policy_id, const auto &assets) {
                mints.emplace_back(policy_id, assets);
            });

            for (const auto &[w_type, w_val]: _wit->map()) {
                switch (w_type.uint()) {
                    case 5: _validate_plutus(ok, *this, w_val.array(), scripts, plutus_data, inputs, mints, vkeys); break;
                    default: break;
                }
            }
        }
        return ok;
    }
}
