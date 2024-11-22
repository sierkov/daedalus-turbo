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

    static tx::wit_cnt _validate_plutus(const context &ctx)
    {

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
                    r.at(3)
                });
            }
        });
    }

    void tx::foreach_script(const std::function<void(script_info &&)> &observer, const context *ctx) const
    {
        foreach_witness([&](const auto typ, const auto &w_val) {
            switch (typ) {
                case 1: {
                    foreach_set(w_val, [&](const auto &script_raw, const auto) {
                        observer({ script_type::native, script_raw.raw_span() });
                    });
                    break;
                }
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
        if (ctx) {
            for (const auto &txo: ctx->inputs()) {
                if (txo.data.script_ref)
                    observer(script_info::from_cbor(*txo.data.script_ref))
                ;
            }
            for (const auto &txo: ctx->ref_inputs()) {
                if (txo.data.script_ref)
                    observer(script_info::from_cbor(*txo.data.script_ref));
            }
        }
    }

    tx::wit_cnt tx::witnesses_ok_plutus(const context &ctx) const
    {
        wit_cnt cnt {};
        for (const auto &[rid, rinfo]: ctx.redeemers()) {
            const auto ps = ctx.prepare_script(rinfo);
            ctx.eval_script(ps);
            cnt += ps.script;
        }
        return cnt;
    }

    tx::wit_cnt tx::witnesses_ok_other(const context *ctx) const
    {
        if (ctx)
            return witnesses_ok_plutus(*ctx);
        foreach_redeemer([&](const auto &) {
            throw error("the validation of transactions with plutus witnesses requires a plutus::context instance!");
        });
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
