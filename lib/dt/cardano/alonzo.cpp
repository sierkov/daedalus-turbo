/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/alonzo.hpp>
#include <dt/narrow-cast.hpp>
#include <dt/plutus/flat.hpp>
#include <dt/plutus/machine.hpp>
#include <dt/plutus/context.hpp>

namespace daedalus_turbo::cardano::alonzo {
    using namespace daedalus_turbo::plutus;

    void tx::evaluate_plutus(const context &ctx, const script_info &script, const term_list &args, const ex_units &max_cost) const
    {
        try {
            flat::script s { ctx.alloc(), script.script() };
            machine m { ctx.alloc(), ctx.cost_models().for_script(script), builtins::semantics_v1(), max_cost };
            const auto t = m.apply_args(s.program(), args);
            //file::write(install_path("tmp/error.uplc"), fmt::format("(program 0.0.0 {})", t));
            m.evaluate_no_res(t);
        } catch (const std::exception &ex) {
            throw error("script {} {}: {}", script.type(), script.hash(), ex.what());
        }
    }

    static term term_from_datum(allocator &alloc, const context &ctx, const datum_hash &hash)
    {
        return { alloc, constant { alloc, ctx.datums().at(hash) } };
    }

    static term term_from_datum(allocator &alloc, const context &, const uint8_vector &datum)
    {
        return { alloc, constant { alloc, data::from_cbor(alloc, datum) } };
    }

    static tx::wit_cnt _validate_plutus(const tx &tx, const script_info_map &scripts, const context &ctx)
    {
        auto &alloc = ctx.alloc();
        tx::wit_cnt cnt {};
        tx.foreach_redeemer([&](const auto &r) {
            auto t_redeemer = term { alloc, constant { alloc, data::from_cbor(alloc, r.data) } };
            switch (r.tag) {
                case redeemer_tag::spend: {
                    const auto &in = ctx.input_at(r.ref_idx);
                    const address addr { in.data.address };
                    if (const auto pay_id = addr.pay_id(); pay_id.type == pay_ident::ident_type::SHELLEY_SCRIPT) [[likely]] {
                        const auto &script = scripts.at(pay_id.hash);
                        auto t_datum = std::visit([&](const auto &v) { return term_from_datum(ctx.alloc(), ctx, v); }, in.data.datum.value());
                        term_list args { alloc, { std::move(t_datum), std::move(t_redeemer), ctx.data(script.type(), r) } };
                        tx.evaluate_plutus(ctx, script, args, r.budget);
                        cnt += script;
                    } else
                        throw error("tx {} redeemer #{} (spend) input #{}: the output address is not a payment script: {}!", tx.hash(), r.idx, r.ref_idx, in);
                    break;
                }
                case redeemer_tag::mint: {
                    const auto policy_id = ctx.mint_at(r.ref_idx);
                    const auto &script = scripts.at(policy_id);
                    const term_list args { alloc, { t_redeemer, ctx.data(script.type(), r) } };
                    tx.evaluate_plutus(ctx, script, args, r.budget);
                    cnt += script;
                    break;
                }
                case redeemer_tag::reward: {
                    const auto &script = scripts.at(std::get<stake_ident>(ctx.withdraw_at(r.ref_idx)).hash);
                    const term_list args { alloc, { t_redeemer, ctx.data(script.type(), r) } };
                    tx.evaluate_plutus(ctx, script, args, r.budget);
                    cnt += script;
                    break;
                }
                default:
                    throw error("tx: {} unsupported redeemer_tag: {}", tx.hash(), static_cast<int>(r.tag));
            };
        });
        return cnt;
    }

    void tx::foreach_redeemer(const std::function<void(const tx_redeemer &)> &observer) const
    {
        foreach_witness([&](const auto typ, const auto &w_val) {
            if (typ != 5)
                return;
            const auto &redeemers = w_val.array();
            for (size_t ri = 0; ri < redeemers.size(); ++ri) {
                const auto &r = redeemers[ri];
                observer(tx_redeemer {
                    redeemer_tag_from_cbor(r.at(0)),
                    narrow_cast<uint16_t>(ri),
                    narrow_cast<uint16_t>(r.at(1).uint()),
                    r.at(2).raw_span(),
                    ex_units::from_cbor(r.at(3))
                });
            }
        });
    }

    void tx::foreach_script(const std::function<void(const script_info &)> &observer) const
    {
        foreach_witness([&](const auto typ, const auto &w_val) {
            switch (typ) {
                case 3: {
                    foreach_set(w_val, [&](const auto &script_raw, const auto) {
                        observer({ script_type::plutus_v1, script_raw.buf() });
                    });
                    break;
                }
                case 6: {
                    foreach_set(w_val, [&](const auto &script_raw, const auto) {
                        observer({ script_type::plutus_v2, script_raw.buf() });
                    });
                    break;
                }
                case 7: {
                    foreach_set(w_val, [&](const auto &script_raw, const auto) {
                        observer({ script_type::plutus_v3, script_raw.buf() });
                    });
                    break;
                }
                default: break;
            }
        });
    }

    tx::wit_cnt tx::witnesses_ok_other(const context *ctx) const
    {
        script_info_map scripts {};
        foreach_script([&](const auto &si) {
            scripts.try_emplace(si.hash(), si);
        });
        if (!scripts.empty()) {
            if (!ctx)
                throw error("plutus::context must be defined for transactions with script witnesses");
            for (const auto &txo: ctx->ref_inputs()) {
                if (txo.data.script_ref) {
                    auto si = script_info::from_cbor(*txo.data.script_ref);
                    scripts.try_emplace(si.hash(), std::move(si));
                }
            }
            return _validate_plutus(*this, scripts, *ctx);
        }
        return {};
    }

    void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        std::set<size_t> invalid_tx_idxs {};
        if (protocol_ver().major >= 6) {
            for (const auto &tx_idx: invalid_transactions())
                invalid_tx_idxs.emplace(tx_idx.uint());
        }
        for (size_t i = 0; i < txs.size(); ++i)
            if (!invalid_tx_idxs.contains(i))
                observer(tx { txs.at(i), *this, i, &wits.at(i), auxiliary_at(i), false });
    }

    void block::foreach_invalid_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        if (protocol_ver().major >= 6) {
            const auto &txs = transactions();
            const auto &wits = witnesses();
            for (const auto &tx_idx: invalid_transactions())
                observer(tx { txs.at(tx_idx.uint()), *this, tx_idx.uint(), &wits.at(tx_idx.uint()), auxiliary_at(tx_idx.uint()), true });
        }
    }
}
