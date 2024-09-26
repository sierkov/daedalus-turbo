/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/plutus/context.hpp>

namespace daedalus_turbo::plutus {
    using namespace cardano;

    static data to_data(const tx_out_ref &ref)
    {
        return data::constr(0, {
            data::constr(0, { data::bstr(ref.hash) }),
            data::bint(static_cast<uint16_t>(ref.idx))
        });
    }

    static data to_data(const address &addr)
    {
        data::list_type l {};
        if (addr.has_pay_id()) {
            const auto pay_id = addr.pay_id();
            l.emplace_back(data::constr(pay_id.type == pay_ident::ident_type::SHELLEY_SCRIPT ? 1 : 0, { data::bstr(pay_id.hash) }));
        } else {
            l.emplace_back(data::constr(1, {}));
        }
        if (addr.has_stake_id()) {
            const auto stake_id = addr.stake_id();
            l.emplace_back(data::constr(stake_id.script ? 1 : 0, { data::bstr(stake_id.hash) }));
        } else {
            l.emplace_back(data::constr(1, {}));
        }
        return data::constr(0, std::move(l));
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
                    pm.emplace_back(data::bstr(name.bytes()), data::bint(value.big_int()));
                }
                m.emplace_back(data::bstr(policy_id.bytes()), data::map(std::move(pm)));
            }
        }
        return data::map(std::move(m));
    }

    static data to_data(const std::optional<tx_out_data::datum_option_type> &datum)
    {
        if (datum)
            return data::constr(0, { data::bstr(std::get<datum_hash>(*datum)) });
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

    static data to_data(const resolved_input &in)
    {
        return data::constr(0, {
            to_data(in.ref),
            to_data(in.data)
        });
    }

    static data datums_to_data(const tx &tx)
    {
        data::list_type l {};
        for (const auto &[w_type, w_val]: tx.raw_witness().map()) {
            if (w_type.uint() == 4) {
                for (const auto &d: w_val.array()) {
                    l.emplace_back(data::constr(0, {
                        data::bstr(blake2b<blake2b_256_hash>(data::bstr(d.buf()).as_cbor())),
                        data::bstr(d.buf())
                    }));
                }
            }
        }
        return data::list(std::move(l));
    }

    static data inputs_to_data(const resolved_input_list &inputs)
    {
        data::list_type l {};
        for (const auto &in: inputs) {
            auto d_ref = to_data(in.ref);
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
                a_m.emplace_back(data::bstr(name.buf()), data::bint(value.uint()));
            }
            m.emplace_back(data::bstr(policy_id), data::map(std::move(a_m)));
        });
        return data::map(std::move(m));
    }

    context::context(const tx &tx, const resolved_input_list &i, const mint_info_list &m, const set<key_hash> &s):
        _tx { tx }, _inputs { i }, _mints { m }, _signatories { s }
    {
    }

    term_ptr context::v1(const purpose &p) const
    {
        // DCerts: stake_reg, stake_unreg, stake_deleg, pool_reg, pool_retire, genesis_deleg, mir
        vector<data> dcerts {};

        // Withdrawals: List (stake_cred, coin)
        vector<data> withdrawals {};
        _tx.foreach_withdrawal([&](const tx_withdrawal &w) {
            withdrawals.emplace_back(data::list({
                data::bstr(uint8_vector { w.address.stake_id().hash }),
                data::bint(static_cast<uint64_t>(w.amount))
            }));
        });

        data valid_range = data::constr(0, {
            data::constr(0, {
                data::constr(0, {}), data::constr(1, {})
            }),
            data::constr(0, {
                data::constr(2, {}), data::constr(1, {})
            })
        });

        vector<data> signatories {};
        for (const auto &s: _signatories)
            signatories.emplace_back(data::bstr(s));

        // Valid range: posix_time_range - validity interval start + ttl tx fields?
        // Signatories: List (pub key hash) - hashes of from tx vkey witnesses like in native script?
        // Datums: List (datum hash => datum) - plutus data from tx data witnesses?
        auto d_purpose = std::visit([&](const auto &v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, purpose::spend>)
                return data::constr(0, { to_data(v.ref) });
            if constexpr (std::is_same_v<T, purpose::mint>)
                return data::constr(1, { data::bstr(v.policy_id) });
            throw error("unsupported purpose: {}", typeid(T).name());
            // A noop to make Visual C++ happy
            return data::bint(0);
        }, p.val);

        auto d_info = data::constr(0, {
            inputs_to_data(_inputs),
            outputs_to_data(_tx),
            fee_to_data(_tx),
            mints_to_data(_tx),
            data::list(std::move(dcerts)),
            data::list(std::move(withdrawals)),
            std::move(valid_range),
            data::list(std::move(signatories)),
            datums_to_data(_tx),
            data::bstr(_tx.hash())
        });

        auto context = data::constr(0, {
            std::move(d_info),
            std::move(d_purpose)
        });
        return term::make_ptr(constant { std::move(context) });
    }
}
