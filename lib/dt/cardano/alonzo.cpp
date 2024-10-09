/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/alonzo.hpp>
#include <dt/plutus/flat.hpp>
#include <dt/plutus/machine.hpp>
#include <dt/plutus/context.hpp>
#include <dt/timer.hpp>

namespace daedalus_turbo::cardano::alonzo {
    using namespace daedalus_turbo::plutus;

    static void _evaluate_plutus(allocator &alloc, const script_info &script, const term_list &args)
    {
        //timer ts { "plutus script parsing", logger::level::debug };
        flat::script s { alloc, script.script() };
        //ts.stop_and_print();
        //try {
        //timer tm { "a plutus::machine creation and the script execution", logger::level::debug };
            // Todo: force maximum evaluation budget
            machine m { alloc, s.version() };
            m.evaluate(s.program(), args);
        //} catch (const std::exception &ex) {
        //    throw error("script {} failed with error: {} when called with args: {}", script.hash(), ex.what(), args);
        //}
    }

    static term_ptr term_from_datum(allocator &alloc, const context &ctx, const datum_hash &hash)
    {
        return term::make_ptr(alloc, constant { alloc, ctx.datums().at(hash) });
    }

    static term_ptr term_from_datum(allocator &alloc, const context &, const uint8_vector &datum)
    {
        return term::make_ptr(alloc, constant { alloc, datum });
    }

    static tx::wit_cnt _validate_plutus(const tx &tx, const cbor::array &redeemers, const script_info_map &scripts, const context &ctx)
    {
        allocator alloc {};
        tx::wit_cnt cnt {};
        for (size_t ri = 0; ri < redeemers.size(); ++ri) {
            const auto &r = redeemers[ri];
            const auto r_type = r.at(0).uint();
            const auto r_idx = r.at(1).uint();
            switch (r_type) {
                case 0: {
                    const auto &in = ctx.input_at(r_idx);
                    const address addr { in.data.address };
                    if (const auto pay_id = addr.pay_id(); pay_id.type == pay_ident::ident_type::SHELLEY_SCRIPT) [[likely]] {
                        auto t_datum = std::visit([&](const auto &v) { return term_from_datum(alloc, ctx, v); }, in.data.datum.value());
                        auto t_redeemer = term::make_ptr(alloc, constant { alloc, data::from_cbor(r.at(2).raw_span()) });
                        const auto &script = scripts.at(pay_id.hash);
                        _evaluate_plutus(alloc, script, { std::move(t_datum), std::move(t_redeemer), ctx.data(alloc, script.type(), purpose { purpose::type::spend, r_idx }) });
                        cnt += script;
                    } else
                        throw error("tx {} redeemer #{} (spend) input #{}: the output address is not a payment script: {}!", tx.hash(), ri, r_idx, in);
                    break;
                }
                case 1: {
                    auto t_redeemer = term::make_ptr(alloc, constant { alloc, data::from_cbor(r.at(2).raw_span()) });
                    const auto &script = scripts.at(ctx.mint_at(r_idx));
                    _evaluate_plutus(alloc, script, { std::move(t_redeemer), ctx.data(alloc, script.type(), purpose { purpose::type::mint, r_idx }) });
                    cnt += script;
                    break;
                }
                default:
                    throw error("tx: {} unsupported redeemer_tag: {}", tx.hash(), r_type);
            };
        }
        return cnt;
    }

    tx::wit_cnt tx::witnesses_ok_other(const context *ctx) const
    {
        wit_cnt cnt {};
        script_info_map scripts {};
        foreach_witness([&](const auto typ, const auto &w_val) {
            switch (typ) {
                case 3: {
                    foreach_set(w_val, [&](const auto &script_raw, const auto) {
                        script_info si { script_type::plutus_v1, script_raw.buf() };
                        const auto script_hash = si.hash();
                        scripts.try_emplace(script_hash, std::move(si));
                    });
                    break;
                }
                case 6: {
                    foreach_set(w_val, [&](const auto &script_raw, const auto) {
                        script_info si { script_type::plutus_v2, script_raw.buf() };
                        const auto script_hash = si.hash();
                        scripts.try_emplace(script_hash, std::move(si));
                    });
                    break;
                }
                case 7: {
                    foreach_set(w_val, [&](const auto &script_raw, const auto) {
                        script_info si { script_type::plutus_v3, script_raw.buf() };
                        const auto script_hash = si.hash();
                        scripts.try_emplace(script_hash, std::move(si));
                    });
                    break;
                }
                default: break;
            }
        });

        foreach_witness([&](const auto typ, const auto &w_val) {
            if (typ == 5) {
                if (!ctx) [[unlikely]]
                    throw error("a prepared plutus::context is required for witness validation of Alonzo+ transactions");
                cnt += _validate_plutus(*this, w_val.array(), scripts, *ctx);
            }
        });
        return cnt;
    }
}
