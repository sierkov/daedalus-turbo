/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/history.hpp>
#include <dt/plutus/context.hpp>
#include <dt/zpp-stream.hpp>

namespace daedalus_turbo::plutus {
    using namespace cardano;

    static data to_data(const tx_out_ref &ref)
    {
        return data::constr(0, {
            data::constr(0, { data::bstr(ref.hash) }),
            data::bint(static_cast<uint16_t>(ref.idx))
        });
    }

    static data to_data(const pay_ident &pay_id)
    {
        switch (pay_id.type) {
            case pay_ident::ident_type::SHELLEY_KEY: return data::constr(0, { data::bstr(pay_id.hash) });
            case pay_ident::ident_type::SHELLEY_SCRIPT: return data::constr(1, { data::bstr(pay_id.hash) });
            default: throw error("an unsupported pay_id type within a script context: {}", static_cast<int>(pay_id.type));
        }
    }

    static data to_data(const stake_ident &stake_id)
    {
        if (stake_id.script)
            return data::constr(1, { data::bstr(stake_id.hash) });
        return data::constr(0, { data::bstr(stake_id.hash) });
    }

    static data to_data(const stake_ident_hybrid &stake_id)
    {
        return std::visit([](const auto &id) {
            using T = std::decay_t<decltype(id)>;
            if constexpr (std::is_same_v<T, stake_ident>)
                return data::constr(0, { to_data(id) });
            if constexpr (std::is_same_v<T, stake_pointer>)
                return data::constr(1, { data::bint(id.slot), data::bint(id.tx_idx), data::bint(id.cert_idx) });
            throw error("unsupported stake_id type: {}", typeid(T).name());
            // A noop, to make Visual C++ happy
            return data::bint(0);
        }, stake_id);
    }

    static data to_data(const address &addr)
    {
        auto pay_cred = to_data(addr.pay_id());
        auto stake_cred = addr.has_stake_id_hybrid() ? data::constr(0, { to_data(addr.stake_id_hybrid()) }) : data::constr(1, {});
        return data::constr(0, { std::move(pay_cred), std::move(stake_cred) });
    }

    static data to_data(const uint64_t coin, const std::optional<uint8_vector> &assets)
    {
        data::map_type m {};
        m.emplace_back(
            data::bstr(uint8_vector {}),
            data::map({ data_pair { data::bstr(uint8_vector {}), data::bint(coin) } })
        );
        if (assets) {
            auto it = cbor::zero::parse(*assets).map();
            while (!it.done()) {
                const auto [policy_id, p_assets] = it.next();
                data::map_type pm {};
                auto p_it = p_assets.map();
                while (!p_it.done()) {
                    const auto [name, value] = p_it.next();
                    pm.emplace_back(data::bstr(name.bytes_alloc()), data::bint(value.big_int()));
                }
                m.emplace_back(data::bstr(policy_id.bytes_alloc()), data::map(std::move(pm)));
            }
        }
        return data::map(std::move(m));
    }

    static data to_data(const std::optional<tx_out_data::datum_option_type> &datum)
    {
        if (datum) {
            return std::visit([](const auto &d) {
                using T = std::decay_t<decltype(d)>;
                if constexpr (std::is_same_v<T, datum_hash>) {
                    return data::constr(0, { data::bstr(d) });
                } else if constexpr (std::is_same_v<T, uint8_vector>) {
                    return data::constr(2, { data::bstr(d) });
                } else {
                    throw error("unsupported datum type: {}", typeid(T).name());
                    //return data::unit();
                }
            }, *datum);
        }
        return data::constr(1, {});
    }

    static data to_data(const tx_out_data &txo)
    {
        return data::constr(0, {
            to_data(address { txo.address }),
            to_data(txo.coin, txo.assets),
            to_data(txo.datum)
        });
    }

    static data datums_to_data(const context::datum_map &datums)
    {
        data::list_type l {};
        for (const auto &[hash, d]: datums) {
            l.emplace_back(data::constr(0, { data::bstr(hash), d }));
        }
        return data::list(std::move(l));
    }

    static data redeemers_to_data(const tx &)
    {
        return data::list({});
    }

    static data inputs_to_data(const stored_txo_list &inputs)
    {
        data::list_type l {};
        for (const auto &in: inputs) {
            auto d_ref = to_data(in.id);
            auto d_data = to_data(in.data);
            l.emplace_back(data::constr(0, { std::move(d_ref), std::move(d_data) }));
        }
        return data::list(std::move(l));
    }

    static data outputs_to_data(const tx &tx)
    {
        data::list_type l {};
        tx.foreach_output([&](const tx_output &txout) {
            l.emplace_back(to_data(tx_out_data::from_output(txout)));
        });
        return data::list(std::move(l));
    }

    static data fee_to_data(const tx &tx)
    {
        return data::map({
            data_pair {
                data::bstr(uint8_vector {}),
                data::map({
                    data_pair { data::bstr(uint8_vector {}), data::bint(static_cast<uint64_t>(tx.fee())) }
                })
            }
        });
    }

    static data mints_to_data(const tx &tx)
    {
        data::map_type m {
            data_pair { data::bstr(uint8_vector {}), data::map({ data_pair { data::bstr(uint8_vector {}), data::bint(0) } }) }
        };
        tx.foreach_mint([&](const buffer &policy_id, const cbor_map &assets) {
            data::map_type a_m {};
            for (const auto &[name, value]: assets) {
                a_m.emplace_back(data::bstr(name.buf()), data::bint(value.bigint()));
            }
            m.emplace_back(data::bstr(policy_id), data::map(std::move(a_m)));
        });
        return data::map(std::move(m));
    }

    static data certs_to_data(const tx &tx)
    {
        data::list_type l {};
        tx.foreach_cert([&](const auto &cert, const auto) {
            switch (const auto typ = cert.at(0).uint(); typ) {
                case 0: {
                    const auto &cred = cert.at(1).array();
                    return data::constr(0, { to_data(stake_ident { cred.at(1).buf(), cred.at(0).uint() == 1 }) });
                }
                case 1: {
                    const auto &cred = cert.at(1).array();
                    return data::constr(1, { to_data(stake_ident { cred.at(1).buf(), cred.at(0).uint() == 1 }) });
                }
                case 2: {
                    const auto &cred = cert.at(1).array();
                    return data::constr(1, {
                        to_data(stake_ident { cred.at(1).buf(), cred.at(0).uint() == 1 }),
                        data::bstr(cert.at(2).buf())
                    });
                }
                case 4: {
                    return data::constr(1, {
                        data::bstr(cert.at(1).buf()),
                        data::bint(cert.at(2).uint()),
                    });
                }
                default: throw error("unsupported certificate type: {}", typ);
            }
        });
        return data::list(std::move(l));
    }

    static data withdrawals_to_data(const tx &tx)
    {
        vector<data> withdrawals {};
        tx.foreach_withdrawal([&](const tx_withdrawal &w) {
            withdrawals.emplace_back(data::list({
                data::bstr(uint8_vector { w.address.stake_id().hash }),
                data::bint(static_cast<uint64_t>(w.amount))
            }));
        });
        return data::list(std::move(withdrawals));
    }

    static data slot_to_data(const context &ctx, uint64_t slot)
    {
        return data::bint(cardano::slot { slot, ctx.config() }.unixtime() * 1000);
    }

    static data validity_start_to_data(const context &ctx, const std::optional<uint64_t> start)
    {
        if (start)
            return data::constr(1, { slot_to_data(ctx, *start) });
        return data::constr(0, {});
    }

    static data validity_end_to_data(const context &ctx, const std::optional<uint64_t> end)
    {
        if (end)
            return data::constr(1, { slot_to_data(ctx, *end) });
        return data::constr(2, {});
    }

    static data validity_range_to_data(const context &ctx)
    {
        const auto end = ctx.tx().validity_end();
        const auto start = ctx.tx().validity_start();
        return data::constr(0, {
            data::constr(0, { validity_start_to_data(ctx, start), data::constr(1, {}) }),
            data::constr(0, { validity_end_to_data(ctx, end), data::constr(1, {}) })
        });
    }

    static data signatories_to_data(const tx &tx)
    {
        vector<data> signatories {};
        tx.foreach_required_signer([&](const buffer vkey_hash) {
            signatories.emplace_back(data::bstr(vkey_hash));
        });
        /*for (const auto &[w_type, w_val]: tx.raw_witness().map()) {
            if (w_type.uint() == 0) {
                for (const auto &w: w_val.array()) {
                    signatories.emplace_back(data::bstr(blake2b<key_hash>(w.array().at(0).buf())));
                }
            }
        }*/
        return data::list(std::move(signatories));
    }

    static data purpose_to_data(const context &ctx, const purpose &p)
    {
        switch (p.typ) {
            case purpose::type::mint:
                return data::constr(0, { data::bstr(ctx.mint_at(p.idx)) });
            case purpose::type::spend:
                return data::constr(1, { to_data(ctx.input_at(p.idx).id) });
            /*case purpose::type::reward:
                return data::constr(1, { to_data(ctx.reward_at(p.idx).stake_id) });
            case purpose::type::certify:
                return data::constr(1, { to_data(ctx.cert_at(p.idx).ref) });*/
            default: throw error("unsupported purpose: {}", static_cast<int>(p.typ));
        }
    }

    context::context(uint8_vector &&tx_body_data, uint8_vector &&tx_wits_data, storage::block_info &&block,
        stored_txo_list &&inputs, stored_txo_list &&ref_inputs, const cardano::config &c_cfg):
            _cfg { c_cfg },
            _tx_body_bytes { std::move(tx_body_data) },
            _tx_body_cbor { cbor::parse(_tx_body_bytes) },
            _tx_wits_bytes { std::move(tx_wits_data) },
            _tx_wits_cbor { cbor::parse(_tx_wits_bytes) },
            _block_info { std::move(block) },
            _block { _block_info, _tx_body_cbor, _block_info.offset, _cfg },
            _tx { make_tx(_tx_body_cbor, _block, &_tx_wits_cbor) },
            _inputs { std::move(inputs) },
            _ref_inputs { std::move(ref_inputs) }
    {
        _tx->foreach_witness([this](const auto typ, const auto &val) {
            switch (typ) {
                case 4: {
                    for (const auto &d_raw: val.array()) {
                        _datums.try_emplace(blake2b<datum_hash>(d_raw.raw_span()), data::from_cbor(d_raw.raw_span()));
                    }
                }
                default: break;
            }
        });
    }

    context::context(stored_tx_context &&ctx, const cardano::config &c_cfg):
        context { std::move(ctx.body), std::move(ctx.wits), std::move(ctx.block),
                  std::move(ctx.inputs), std::move(ctx.ref_inputs), c_cfg }
    {
    }

    static stored_tx_context context_load(const std::string &path)
    {
        zpp_stream::read_stream s { path };
        return s.read<stored_tx_context>();
    }

    context::context(const std::string &path, const cardano::config &c_cfg):
        context { context_load(path), c_cfg }
    {
    }

    const tx &context::tx() const
    {
        return *_tx;
    }

    buffer context::mint_at(const uint64_t r_idx) const
    {
        size_t mi = 0;
        std::optional<buffer> policy_id {};
        _tx->foreach_mint([&](const buffer &p_id, const cbor_map &) {
            if (mi++ == r_idx)
                policy_id.emplace(p_id);
        });
        if (policy_id) [[likely]]
            return *policy_id;
        throw error("a redeemer referenced an unknown mint instruction: {}", r_idx);
    }

    const stored_txo &context::input_at(const uint64_t r_idx) const
    {
        return _inputs.at(r_idx);
    }

    term_ptr context::data(allocator &alloc, const script_type typ, const purpose &p) const
    {
        switch (typ) {
            case script_type::plutus_v1: {
                auto context = data::constr(0, {
                    data::constr(0, {
                        inputs_to_data(_inputs),
                        outputs_to_data(*_tx),
                        fee_to_data(*_tx),
                        mints_to_data(*_tx),
                        certs_to_data(*_tx),
                        withdrawals_to_data(*_tx),
                        validity_range_to_data(*this),
                        signatories_to_data(*_tx),
                        datums_to_data(_datums),
                        data::constr(0, { data::bstr(_tx->hash()) })
                    }),
                    purpose_to_data(*this, p)
                });
                return term::make_ptr(alloc, constant { alloc, std::move(context) });
            }
            case script_type::plutus_v2: {
                auto context = data::constr(0, {
                    data::constr(0, {
                        inputs_to_data(_inputs),
                        inputs_to_data(_ref_inputs),
                        outputs_to_data(*_tx),
                        fee_to_data(*_tx),
                        mints_to_data(*_tx),
                        certs_to_data(*_tx),
                        withdrawals_to_data(*_tx),
                        validity_range_to_data(*this),
                        signatories_to_data(*_tx),
                        redeemers_to_data(*_tx),
                        datums_to_data(_datums),
                        data::constr(0, { data::bstr(_tx->hash()) })
                    }),
                    purpose_to_data(*this, p)
                });
                return term::make_ptr(alloc, constant { alloc, std::move(context) });
            }
            default: throw error("unsupported script_type: {}", static_cast<int>(typ));
        }
    }
}
