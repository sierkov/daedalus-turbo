/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/history.hpp>
#include <dt/plutus/context.hpp>
#include <dt/zpp-stream.hpp>

namespace daedalus_turbo::plutus {
    using namespace cardano;

    struct data_encoder {
        data_encoder(allocator &alloc, script_type typ): _alloc { alloc }, _typ { typ }
        {
        }

        data constr(uint64_t tag, std::initializer_list<data> il)
        {
            return data::constr(_alloc, tag, il);
        }

        // a specific name to no allow collisions with int
        data boolean(bool v)
        {
            return constr(v ? 1 : 0, {});
        }

        data encode(const cpp_int &v)
        {
            return data::bint(_alloc, v);
        }

        data encode(buffer b)
        {
            return data::bstr(_alloc, b);
        }

        data encode(uint64_t u)
        {
            return data::bint(_alloc, u);
        }

        data encode(const tx_out_ref &ref)
        {
            return constr(0, {
                constr(0, { encode(ref.hash) }),
                encode(ref.idx)
            });
        }

        data encode(const pay_ident &pay_id)
        {
            switch (pay_id.type) {
                case pay_ident::ident_type::SHELLEY_KEY: return constr(0, { encode(pay_id.hash) });
                case pay_ident::ident_type::SHELLEY_SCRIPT: return constr(1, { encode(pay_id.hash) });
                default: throw error("an unsupported pay_id type within a script context: {}", static_cast<int>(pay_id.type));
            }
        }

        data encode(const stake_ident &stake_id)
        {
            if (stake_id.script)
                return constr(1, { encode(stake_id.hash) });
            return constr(0, { encode(stake_id.hash) });
        }

        data encode(const stake_ident_hybrid &stake_id)
        {
            return std::visit([&](const auto &id) {
                using T = std::decay_t<decltype(id)>;
                if constexpr (std::is_same_v<T, stake_ident>)
                    return constr(0, { encode(id) });
                if constexpr (std::is_same_v<T, stake_pointer>)
                    return constr(1, { encode(id.slot), encode(id.tx_idx), encode(id.cert_idx) });
                throw error("unsupported stake_id type: {}", typeid(T).name());
                // A noop, to make Visual C++ happy
                return data::bint(_alloc, 0);
            }, stake_id);
        }

        data encode(const address &addr)
        {
            auto pay_cred = encode(addr.pay_id());
            auto stake_cred = addr.has_stake_id_hybrid()
                ? constr(0, { encode(addr.stake_id_hybrid()) })
                : constr(1, {});
            return constr(0, { std::move(pay_cred), std::move(stake_cred) });
        }

        data value(const uint64_t coin, const std::optional<uint8_vector> &assets)
        {
            data::map_type m { _alloc };
            m.emplace_back(_alloc,
                encode(uint8_vector {}),
                data::map(_alloc, { data_pair { _alloc, encode(uint8_vector {}), encode(coin) } })
            );
            if (assets) {
                auto it = cbor::zero::parse(*assets).map();
                while (!it.done()) {
                    const auto [policy_id, p_assets] = it.next();
                    data::map_type pm { _alloc };
                    auto p_it = p_assets.map();
                    while (!p_it.done()) {
                        const auto [name, value] = p_it.next();
                        bstr_type::value_type bytes { _alloc };
                        name.bytes_alloc(bytes);
                        pm.emplace_back(_alloc, encode(std::move(bytes)), data::bint(_alloc, value.big_int()));
                    }
                    bstr_type::value_type bytes { _alloc };
                    policy_id.bytes_alloc(bytes);
                    m.emplace_back(_alloc, encode(bytes), data::map(_alloc, std::move(pm)));
                }
            }
            return data::map(_alloc, std::move(m));
        }

        data datum(const std::optional<tx_out_data::datum_option_type> &datum)
        {
            if (datum) {
                return std::visit([&](const auto &d) {
                    using T = std::decay_t<decltype(d)>;
                    if constexpr (std::is_same_v<T, datum_hash>)
                        return constr(0, { encode(d) });
                    throw error("unsupported datum type: {}", typeid(T).name());
                    // Make Visual C++ happy
                    return data::bint(_alloc, 0);
                }, *datum);
            }
            return constr(1, {});
        }

        data datum_option(const std::optional<tx_out_data::datum_option_type> &datum)
        {
            if (datum) {
                return std::visit([&](const auto &d) {
                    using T = std::decay_t<decltype(d)>;
                    if constexpr (std::is_same_v<T, datum_hash>) {
                        return constr(1, { encode(d) });
                    } else if constexpr (std::is_same_v<T, uint8_vector>) {
                        return constr(2, { data::from_cbor(_alloc, d) });
                    } else {
                        throw error("unsupported datum type: {}", typeid(T).name());
                    }
                }, *datum);
            }
            return constr(0, {});
        }

        data script_ref(const std::optional<uint8_vector> &script_ref)
        {
            if (script_ref) {
                auto si = script_info::from_cbor(*script_ref);
                return constr(0, { encode(si.hash()) });
            }
            return constr(1, {});
        }

        data txo(const tx_out_data &txo)
        {
            switch (_typ) {
                case script_type::plutus_v1:
                    return constr(0, {
                        encode(address { txo.address }),
                        value(txo.coin, txo.assets),
                        datum(txo.datum)
                    });
                case script_type::plutus_v2:
                case script_type::plutus_v3:
                    return constr(0, {
                        encode(address { txo.address }),
                        value(txo.coin, txo.assets),
                        datum_option(txo.datum),
                        script_ref(txo.script_ref)
                    });
                default: throw error("unsupported script type: {}", static_cast<int>(_typ));
            }
        }

        data datums(const context::datum_map &datums)
        {
            switch (_typ) {
                case script_type::plutus_v1: {
                    data::list_type l { _alloc };
                    for (const auto &[hash, d]: datums) {
                        l.emplace_back(constr(0, { encode(hash), d }));
                    }
                    return data::list(_alloc, std::move(l));
                }
                case script_type::plutus_v2: {
                    data::map_type m { _alloc };
                    for (const auto &[hash, d]: datums) {
                        m.emplace_back(data_pair { _alloc, encode(hash), d });
                    }
                    return data::map(_alloc, std::move(m));
                }
                default: throw error("unsupported script type: {}", static_cast<int>(_typ));
            }
        }

        data redeemers(const context &ctx)
        {
            data::map_type m { _alloc };
            ctx.tx().foreach_redeemer([&](const auto &r) {
                m.emplace_back(data_pair { _alloc, purpose(ctx, r), data::from_cbor(_alloc, r.data) });
            });
            return data::map(_alloc, std::move(m));
        }

        data inputs(const stored_txo_list &inputs)
        {
            data::list_type l { _alloc };
            for (const auto &in: inputs) {
                auto d_ref = encode(in.id);
                auto d_data = txo(in.data);
                l.emplace_back(constr(0, { std::move(d_ref), std::move(d_data) }));
            }
            return data::list(_alloc, std::move(l));
        }

        data outputs(const tx &tx)
        {
            data::list_type l { _alloc };
            tx.foreach_output([&](const tx_output &txout) {
                l.emplace_back(txo(tx_out_data::from_output(txout)));
            });
            return data::list(_alloc, std::move(l));
        }

        data fee(const tx &tx)
        {
            return data::map(_alloc, {
                data_pair {_alloc,
                    encode(uint8_vector {}),
                    data::map(_alloc, {
                        data_pair { _alloc, encode(uint8_vector {}), encode(tx.fee()) }
                    })
                }
            });
        }

        data mints(const tx &tx)
        {
            data::map_type m { _alloc,
                { data_pair { _alloc,
                        encode(uint8_vector {}),
                        data::map(_alloc, { data_pair { _alloc, encode(uint8_vector {}), encode(0) } }) }
                }
            };
            tx.foreach_mint([&](const buffer &policy_id, const cbor_map &assets) {
                data::map_type a_m { _alloc };
                for (const auto &[name, value]: assets) {
                    a_m.emplace_back(_alloc, encode(name.buf()), encode(value.bigint()));
                }
                m.emplace_back(_alloc, encode(policy_id), data::map(_alloc, std::move(a_m)));
            });
            return data::map(_alloc, std::move(m));
        }

        data certs(const tx &tx)
        {
            data::list_type l { _alloc };
            tx.foreach_cert([&](const auto &cert, const auto) {
                switch (const auto typ = cert.at(0).uint(); typ) {
                    case 0: {
                        const auto &cred = cert.at(1).array();
                        return constr(0, { encode(stake_ident { cred.at(1).buf(), cred.at(0).uint() == 1 }) });
                    }
                    case 1: {
                        const auto &cred = cert.at(1).array();
                        return constr(1, { encode(stake_ident { cred.at(1).buf(), cred.at(0).uint() == 1 }) });
                    }
                    case 2: {
                        const auto &cred = cert.at(1).array();
                        return constr(1, {
                            encode(stake_ident { cred.at(1).buf(), cred.at(0).uint() == 1 }),
                            encode(cert.at(2).buf())
                        });
                    }
                    case 4: {
                        return constr(1, {
                            data::bstr(_alloc, cert.at(1).buf()),
                            data::bint(_alloc, cert.at(2).uint()),
                        });
                    }
                    default: throw error("unsupported certificate type: {}", typ);
                }
            });
            return data::list(_alloc, std::move(l));
        }

        data withdrawals(const tx &tx)
        {
            switch (_typ) {
                case script_type::plutus_v1: {
                    data::list_type l { _alloc };
                    tx.foreach_withdrawal([&](const tx_withdrawal &w) {
                        l.emplace_back(data::list(_alloc, {
                            encode(w.address.stake_id().hash),
                            encode(static_cast<uint64_t>(w.amount))
                        }));
                    });
                    return data::list(_alloc, std::move(l));
                }
                case script_type::plutus_v2: {
                    data::map_type m { _alloc };
                    tx.foreach_withdrawal([&](const tx_withdrawal &w) {
                        m.emplace_back(data_pair { _alloc,
                            encode(w.address.stake_id_hybrid()),
                            encode(static_cast<uint64_t>(w.amount))
                        });
                    });
                    return data::map(_alloc, std::move(m));
                }
                default: throw error("unsupported script type: {}", static_cast<int>(_typ));
            }
        }

        data slot(const context &ctx, const uint64_t slot)
        {
            return data::bint(_alloc, cardano::slot { slot, ctx.config() }.unixtime() * 1000);
        }

        data validity_start(const context &ctx, const std::optional<uint64_t> start)
        {
            if (start)
                return constr(0, { constr(1, { slot(ctx, *start) }), constr(1, {}) });
            return constr(0, { constr(0, {}), constr(1, {}) });;
        }

        data validity_end(const context &ctx, const std::optional<uint64_t> end, const std::optional<uint64_t> start)
        {
            if (end)
                return constr(0, { constr(1, { slot(ctx, *end) }), constr(start ? 0 : 1, {}) });
            return constr(0, { constr(2, {}), constr(1, {}) });
        }

        data validity_range(const context &ctx)
        {
            const auto end = ctx.tx().validity_end();
            const auto start = ctx.tx().validity_start();
            return constr(0, {
                validity_start(ctx, start),
                validity_end(ctx, end, start)
            });
        }

        data signatories(const tx &tx)
        {
            // ensure the sorted order
            set<key_hash> vkeys {};
            tx.foreach_required_signer([&](const buffer vkey_hash) {
                vkeys.emplace(vkey_hash);
            });
            data::list_type l { _alloc };
            for (const auto &vkey : vkeys) {
                l.emplace_back(encode(vkey));
            }
            return data::list(_alloc, std::move(l));
        }

        data purpose(const context &ctx, const tx_redeemer &r)
        {
            switch (r.tag) {
                case redeemer_tag::mint:
                    return constr(0, { encode(ctx.mint_at(r.ref_idx)) });
                case redeemer_tag::spend:
                    return constr(1, { encode(ctx.input_at(r.ref_idx).id) });
                case redeemer_tag::reward:
                    return constr(2, { encode(ctx.withdraw_at(r.ref_idx)) });
                /*case purpose::type::certify:
                    return data::constr(3, { to_data(ctx.cert_at(p.idx).ref) });*/
                default: throw error("unsupported purpose: {}", static_cast<int>(r.tag));
            }
        }

        data context_v1(const context &ctx, const tx_redeemer &r)
        {
            return constr(0, {
                constr(0, {
                    inputs(ctx.inputs()),
                    outputs(ctx.tx()),
                    fee(ctx.tx()),
                    mints(ctx.tx()),
                    certs(ctx.tx()),
                    withdrawals(ctx.tx()),
                    validity_range(ctx),
                    signatories(ctx.tx()),
                    datums(ctx.datums()),
                    constr(0, { encode(ctx.tx().hash()) })
                }),
                purpose(ctx, r)
            });
        }

        data context_v2(const context &ctx, const tx_redeemer &r)
        {
            return constr(0, {
                constr(0, {
                    inputs(ctx.inputs()),
                    inputs(ctx.ref_inputs()),
                    outputs(ctx.tx()),
                    fee(ctx.tx()),
                    mints(ctx.tx()),
                    certs(ctx.tx()),
                    withdrawals(ctx.tx()),
                    validity_range(ctx),
                    signatories(ctx.tx()),
                    redeemers(ctx),
                    datums(ctx.datums()),
                    constr(0, { encode(ctx.tx().hash()) })
                }),
                purpose(ctx, r)
            });
        }

        data context_v3(const context &, const tx_redeemer &)
        {
            throw error("not implemented");
        }

        data context(const context &ctx, const tx_redeemer &r)
        {
            switch (_typ) {
                case script_type::plutus_v1: return context_v1(ctx, r);
                case script_type::plutus_v2: return context_v2(ctx, r);
                case script_type::plutus_v3: return context_v3(ctx, r);
                default: throw error("unsupported script_type: {}", static_cast<int>(_typ));
            }
        }
    private:
        allocator &_alloc;
        script_type _typ;
    };

    context::context(uint8_vector &&tx_body_data, uint8_vector &&tx_wits_data, uint8_vector &&tx_aux_data, storage::block_info &&block,
        stored_txo_list &&inputs, stored_txo_list &&ref_inputs, const cardano::config &c_cfg):
            _cfg { c_cfg },
            _cost_models { costs::defaults() },
            _tx_body_bytes { std::move(tx_body_data) },
            _tx_body_cbor { cbor::parse(_tx_body_bytes) },
            _tx_wits_bytes { std::move(tx_wits_data) },
            _tx_wits_cbor { cbor::parse(_tx_wits_bytes) },
            _tx_aux_bytes { std::move(tx_aux_data) },
            _tx_aux_cbor { _tx_aux_bytes.empty() ? nullptr : std::make_unique<cbor::value>(cbor::parse(_tx_aux_bytes)) },
            _block_info { std::move(block) },
            _block { _block_info, _tx_body_cbor, _block_info.offset, _cfg },
            _tx { make_tx(_tx_body_cbor, _block, 0, &_tx_wits_cbor, _tx_aux_cbor.get()) },
            _inputs { std::move(inputs) },
            _ref_inputs { std::move(ref_inputs) }
    {
        _tx->foreach_witness([this](const auto typ, const auto &val) {
            if (typ == 4) {
                _tx->foreach_set(val, [&](const auto &d_raw, const auto) {
                    _datums.try_emplace(blake2b<datum_hash>(d_raw.raw_span()), data::from_cbor(_alloc, d_raw.raw_span()));
                });
            }
        });
    }

    context::context(stored_tx_context &&ctx, const cardano::config &c_cfg):
        context { std::move(ctx.body), std::move(ctx.wits), std::move(ctx.aux), std::move(ctx.block),
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

    stake_ident_hybrid context::withdraw_at(uint64_t r_idx) const
    {
        std::optional<stake_ident_hybrid> stake_id {};
        _tx->foreach_withdrawal([&](const tx_withdrawal &w) {
            if (w.idx == r_idx)
                stake_id.emplace(w.address.stake_id_hybrid());
        });
        if (stake_id) [[likely]]
            return *stake_id;
        throw error("a redeemer referenced an unknown withdrawal instruction: {}", r_idx);
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

    term context::data(const script_type typ, const tx_redeemer &r) const
    {
        data_encoder enc { _alloc, typ };
        return { _alloc, constant { _alloc, enc.context(*this, r) } };
    }
}
