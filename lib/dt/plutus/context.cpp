/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/history.hpp>
#include <dt/plutus/context.hpp>
#include <dt/plutus/flat.hpp>
#include <dt/plutus/machine.hpp>
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

        data constr(uint64_t tag, data::list_type &&l)
        {
            return data::constr(_alloc, tag, std::move(l));
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
            switch (_typ) {
                case script_type::plutus_v1:
                case script_type::plutus_v2:
                    return constr(0, {
                        constr(0, { encode(ref.hash) }),
                        encode(ref.idx)
                    });
                case script_type::plutus_v3:
                    return constr(0, {
                        encode(ref.hash),
                        encode(ref.idx)
                    });
                default: throw error("unsupported script_type: {}", static_cast<int>(_typ));
            }
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

        data stake_cred(const stake_ident &stake_id)
        {
            switch (_typ) {
                case script_type::plutus_v1:
                case script_type::plutus_v2:
                    return constr(0, { encode(stake_id) });
                case script_type::plutus_v3:
                    return encode(stake_id);
                default:
                    throw error("unsupported script type: {}", _typ);
            }
        }

        data encode(const drep_t &drep)
        {
            switch (drep.typ) {
                case drep_t::credential: return constr(0, { encode(*drep.cred) });
                case drep_t::abstain: return constr(1, {});
                case drep_t::no_confidence: return constr(2, {});
                default: throw error("unsupported drep type: {}", static_cast<int>(drep.typ));
            }
        }

        data encode(const conway::voter_t &voter)
        {
            switch (voter.type) {
                case conway::voter_t::const_comm_key:
                    return constr(0, { stake_cred(stake_ident { voter.hash, false } )});
                case conway::voter_t::const_comm_script:
                    return constr(0, { stake_cred(stake_ident { voter.hash, true } )});
                case conway::voter_t::drep_key:
                    return constr(1, { stake_cred(stake_ident { voter.hash, false } )});
                case conway::voter_t::drep_script:
                    return constr(1, { stake_cred(stake_ident { voter.hash, true } )});
                case conway::voter_t::pool_key:
                    return constr(2, { encode(voter.hash) });
                default:
                    throw error("unsuported voter type: {}", static_cast<int>(voter.type));
            }
        }

        data encode(const conway::gov_action_id_t &ga_id)
        {
            return constr(0, { encode(ga_id.tx_id), data::bint(_alloc, ga_id.idx) });
        }

        data encode(const conway::vote_t &vote)
        {
            switch (vote) {
                case conway::vote_t::no: return constr(0, {});
                case conway::vote_t::yes: return constr(1, {});
                case conway::vote_t::abstain: return constr(2, {});
                default: throw error("unsupported vote: {}", static_cast<int>(vote));
            }
        }

        data encode(const conway::voting_procedure_t &vote)
        {
            return encode(vote.vote);
        }

        data encode(const redeemer_id &r, const context &ctx)
        {
            switch (r.tag) {
                case redeemer_tag::mint:
                    return constr(0, { encode(ctx.mint_at(r.ref_idx)) });
                case redeemer_tag::spend: {
                    const auto &in = ctx.input_at(r.ref_idx);
                    return constr(1, { encode(in.id) });
                }
                case redeemer_tag::reward:
                    return constr(2, { encode(ctx.withdraw_at(r.ref_idx)) });
                case redeemer_tag::cert: {
                    const auto &cert = ctx.cert_at(r.ref_idx);
                    switch (_typ) {
                        case script_type::plutus_v1:
                        case script_type::plutus_v2:
                            return constr(3, { encode(cert) });
                        case script_type::plutus_v3:
                            return constr(3, { data::bint(_alloc, r.ref_idx), encode(cert) });
                        default: throw error("unsupported script type: {}", _typ);
                    }
                }
                case redeemer_tag::vote: {
                    return constr(4, { encode(ctx.voter_at(r.ref_idx)) });
                }
                case redeemer_tag::propose: {
                    return constr(5, { data::bint(_alloc, r.ref_idx), encode(ctx.proposal_at(r.ref_idx)) });
                }
                default: throw error("unsupported redeemer_tag: {}", static_cast<int>(r.tag));
            }
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

        data encode(const conway::anchor_t &a)
        {
            return constr(0, { encode(a.url), encode(a.hash) });
        }

        template<typename T>
        data encode(const conway::optional_t<T> &o)
        {
            if (o)
                return constr(0, { encode(*o) });
            return constr(1, {});
        }

        data encode(const shelley::stake_reg_cert &c)
        {
            switch (_typ) {
                case script_type::plutus_v1:
                case script_type::plutus_v2:
                    return constr(0, { stake_cred(c.stake_id) });
                case script_type::plutus_v3:
                    return constr(0, { stake_cred(c.stake_id), constr(1, {}) });
                default:
                    throw error("unsupported script type: {}", _typ);
            }
        }

        data encode(const conway::reg_cert &c)
        {
            //return constr(0, { stake_cred(c.stake_id), data::bint(_alloc, c.deposit) });
            return constr(0, { stake_cred(c.stake_id), constr(1, {}) });
        }

        data encode(const shelley::stake_dereg_cert &c)
        {
            switch (_typ) {
                case script_type::plutus_v1:
                case script_type::plutus_v2:
                    return constr(1, { stake_cred(c.stake_id) });
                case script_type::plutus_v3:
                    return constr(1, { stake_cred(c.stake_id), constr(1, {}) });
                default:
                    throw error("unsupported script type: {}", _typ);
            }
        }

        data encode(const conway::unreg_cert &c)
        {
            switch (_typ) {
                case script_type::plutus_v1:
                case script_type::plutus_v2:
                    return constr(1, { stake_cred(c.stake_id) });
                case script_type::plutus_v3:
                    //return constr(1, { stake_cred(c.stake_id), data::bint(_alloc, c.deposit) });
                    return constr(1, { stake_cred(c.stake_id), constr(1, {}) });
                default:
                    throw error("unsupported script type: {}", _typ);
            }
        }

        data encode(const shelley::stake_deleg_cert &c)
        {
            switch (_typ) {
                case script_type::plutus_v1:
                case script_type::plutus_v2:
                    return constr(2, { stake_cred(c.stake_id), encode(c.pool_id) });
                case script_type::plutus_v3:
                    return constr(2, { stake_cred(c.stake_id), constr(0, { encode(c.pool_id) }) });
                default: throw error("unsupported script type: {}", static_cast<int>(_typ));
            }
        }

        data encode(const conway::vote_deleg_cert &c)
        {
            return constr(2, { encode(c.stake_id), constr(1, { encode(c.drep) }) });
        }

        data encode(const conway::stake_vote_deleg_cert &c)
        {
            return constr(2, { encode(c.stake_id), constr(2, { encode(c.pool_id), encode(c.drep) }) });
        }

        data encode(const conway::stake_reg_deleg_cert &c)
        {
            return constr(3, { encode(c.stake_id), constr(0, { encode(c.pool_id) }), data::bint(_alloc, c.deposit) });
        }

        data encode(const conway::vote_reg_deleg_cert &c)
        {
            return constr(3, { encode(c.stake_id), constr(1, { encode(c.drep) }), data::bint(_alloc, c.deposit) });
        }

        data encode(const conway::stake_vote_reg_deleg_cert &c)
        {
            return constr(3, { encode(c.stake_id), constr(2, { encode(c.pool_id), encode(c.drep) }), data::bint(_alloc, c.deposit) });
        }

        data encode(const conway::reg_drep_cert &c)
        {
            return constr(4, { encode(c.drep_id), data::bint(_alloc, c.deposit) });
        }

        data encode(const conway::update_drep_cert &c)
        {
            return constr(5, { encode(c.drep_id) });
        }

        data encode(const conway::unreg_drep_cert &c)
        {
            return constr(6, { encode(c.drep_id), data::bint(_alloc, c.deposit) });
        }

        data encode(const shelley::pool_reg_cert &)
        {
            throw error("pool_reg_cert script witnesses not supported!");
        }

        data encode(const shelley::pool_retire_cert &)
        {
            throw error("pool_retire_cert script witnesses not supported!");
        }

        data encode(const conway::auth_committee_hot_cert &c)
        {
            return constr(9, { encode(c.cold_id), encode(c.hot_id) });
        }

        data encode(const conway::resign_committee_cold_cert &c)
        {
            return constr(10, { encode(c.cold_id) });
        }

        data encode(const conway::cert_t &cert)
        {
            return std::visit<data>([&](const auto &c) {
                return encode(c);
            }, cert.val);
        }

        data encode(const plutus_cost_model &m)
        {
            data::list_type l { _alloc };
            for (const auto &[name, value] : m) {
                l.emplace_back(data::bint(_alloc, cpp_int { value }));
            }
            return data::list(_alloc, std::move(l));
        }

        data encode(const plutus_cost_models &mdls)
        {
            data::map_type m { _alloc };
            if (mdls.v1)
                m.emplace_back(_alloc, data::bint(_alloc, 0), encode(*mdls.v1));
            if (mdls.v2)
                m.emplace_back(_alloc, data::bint(_alloc, 1), encode(*mdls.v2));
            if (mdls.v3)
                m.emplace_back(_alloc, data::bint(_alloc, 2), encode(*mdls.v3));
            return data::map(_alloc, std::move(m));
        }

        data encode(const conway::param_update_t &u)
        {
            data::map_type m { _alloc };
            if (u.plutus_cost_models)
                m.emplace_back(_alloc, data::bint(_alloc, 18), encode(*u.plutus_cost_models));
            return data::map(_alloc, std::move(m));
        }

        data encode(const conway::gov_action_t::parameter_change_t &p)
        {
            return constr(0, {
                encode(p.prev_action_id),
                encode(p.update),
                encode(p.policy_id)
            });
        }

        data encode(const conway::gov_action_t::hard_fork_init_t &)
        {
            return constr(1, {});
        }

        data encode(const conway::gov_action_t::treasury_withdrawals_t &)
        {
            return constr(2, {});
        }

        data encode(const conway::gov_action_t::no_confidence_t &)
        {
            return constr(3, {});
        }

        data encode(const conway::gov_action_t::update_committee_t &)
        {
            return constr(4, {});
        }

        data encode(const conway::gov_action_t::new_constitution_t &)
        {
            return constr(5, {});
        }

        data encode(const conway::gov_action_t::info_action_t &)
        {
            return constr(6, {});
        }

        data encode(const conway::gov_action_t &ga)
        {
            return std::visit<data>([&](const auto &a) {
                return encode(a);
            }, ga.val);
        }

        data encode(const conway::proposal_t &p)
        {
            return constr(0, {
                data::bint(_alloc, p.deposit),
                constr(0, { encode(p.stake_id.hash) }),
                encode(p.action)
            });
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

        data datum_value(const context &ctx, const std::optional<tx_out_data::datum_option_type> &datum)
        {
            if (datum) {
                return std::visit([&](const auto &d) {
                    using T = std::decay_t<decltype(d)>;
                    if constexpr (std::is_same_v<T, datum_hash>) {
                        return constr(0, { ctx.datums().at(d) });
                    } else if constexpr (std::is_same_v<T, uint8_vector>) {
                        return constr(0, { data::from_cbor(_alloc, d) });
                    } else {
                        throw error("unsupported datum type: {}", typeid(T).name());
                    }
                }, *datum);
            }
            return constr(1, {});
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
                case script_type::plutus_v2:
                case script_type::plutus_v3: {
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
            for (const auto &[rid, rinfo]: ctx.redeemers()) {
                m.emplace_back(data_pair { _alloc, encode(rid, ctx), data::from_cbor(_alloc, rinfo.data) });
            }
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
            switch (_typ) {
                case script_type::plutus_v1:
                case script_type::plutus_v2:
                    return data::map(_alloc, {
                        data_pair {_alloc,
                            encode(uint8_vector {}),
                            data::map(_alloc, {
                                data_pair { _alloc, encode(uint8_vector {}), encode(tx.fee()) }
                            })
                        }
                    });
                case script_type::plutus_v3:
                    return encode(tx.fee());
                default: throw error("unsupported script type: {}", static_cast<int>(_typ));
            }
        }

        data mints(const tx &tx)
        {
            data::map_type m { _alloc };
            switch (_typ) {
                case script_type::plutus_v1:
                case script_type::plutus_v2:
                        m.emplace_back(_alloc,
                            encode(uint8_vector {}),
                            data::map(_alloc, { data_pair { _alloc, encode(uint8_vector {}), encode(0) } }));
                    break;
                case script_type::plutus_v3:
                    // do nothing
                    break;
                default: throw error("unsupported script type: {}", static_cast<int>(_typ));
            }
            tx.foreach_mint([&](const buffer &policy_id, const cbor_map &assets) {
                data::map_type a_m { _alloc };
                for (const auto &[name, value]: assets) {
                    a_m.emplace_back(_alloc, encode(name.buf()), encode(value.bigint()));
                }
                std::sort(a_m.begin(), a_m.end(), [](const auto &a, const auto &b) {
                    return *std::get<data::bstr_type>(*a->first) < *std::get<data::bstr_type>(*b->first);
                });
                m.emplace_back(_alloc, encode(policy_id), data::map(_alloc, std::move(a_m)));
            });
            std::sort(m.begin(), m.end(), [](const auto &a, const auto &b) {
                return *std::get<data::bstr_type>(*a->first) < *std::get<data::bstr_type>(*b->first);
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
                        l.emplace_back(constr(0, { stake_cred(stake_ident { cred.at(1).buf(), cred.at(0).uint() == 1 }) }));
                        break;
                    }
                    case 1: {
                        const auto &cred = cert.at(1).array();
                        l.emplace_back(constr(1, { stake_cred(stake_ident { cred.at(1).buf(), cred.at(0).uint() == 1 }) }));
                        break;
                    }
                    case 2: {
                        const auto &cred = cert.at(1).array();
                        l.emplace_back(constr(2, {
                            stake_cred(stake_ident { cred.at(1).buf(), cred.at(0).uint() == 1 }),
                            encode(cert.at(2).buf())
                        }));
                        break;
                    }
                    case 4: {
                        l.emplace_back(constr(4, {
                            data::bstr(_alloc, cert.at(1).buf()),
                            data::bint(_alloc, cert.at(2).uint()),
                        }));
                        break;
                    }
                    default:
                        l.emplace_back(encode(conway::cert_t { cert }));
                        break;
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
                case script_type::plutus_v3: {
                    data::map_type m { _alloc };
                    tx.foreach_withdrawal([&](const tx_withdrawal &w) {
                        m.emplace_back(data_pair { _alloc,
                            stake_cred(w.address.stake_id()),
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

        data purpose(const context &ctx, const redeemer_id &r)
        {
            switch (r.tag) {
                case redeemer_tag::spend: {
                    const auto &in = ctx.input_at(r.ref_idx);
                    switch (_typ) {
                        case script_type::plutus_v1:
                        case script_type::plutus_v2:
                            return constr(1, { encode(in.id) });
                        case script_type::plutus_v3:
                            return constr(1, { encode(in.id), datum_value(ctx, in.data.datum) });
                        default: throw error("unsupported script type: {}", static_cast<int>(_typ));
                    }
                }
                case redeemer_tag::cert: {
                    const auto &cert = ctx.cert_at(r.ref_idx);
                    switch (_typ) {
                        case script_type::plutus_v1:
                        case script_type::plutus_v2:
                            return constr(3, { encode(cert) });
                        case script_type::plutus_v3:
                            return constr(3, { data::bint(_alloc, r.ref_idx), encode(cert) });
                        default: throw error("unsupported script type: {}", static_cast<int>(_typ));
                    }
                }
                default: return encode(r, ctx);
            }
        }

        data proposals(const context &ctx)
        {
            data::list_type l { _alloc };
            for (const auto &p: ctx.proposals()) {
                l.emplace_back(encode(p));
            }
            return data::list(_alloc, std::move(l));
        }

        data votes(const context &ctx)
        {
            data::map_type m { _alloc };
            for (const auto &[voter, votes]: ctx.votes()) {
                data::map_type vm { _alloc };
                for (const auto &[action_id, vote]: votes) {
                    vm.emplace_back(_alloc, encode(action_id), encode(vote));
                }
                m.emplace_back(_alloc, encode(voter), data::map(_alloc, std::move(vm)));
            }
            return data::map(_alloc, std::move(m));
        }

        data current_treasury(const tx &)
        {
            return constr(1, {});
        }

        data donation(const tx &)
        {
            return constr(1, {});
        }

        data redeemer(const tx_redeemer &r)
        {
            return data::from_cbor(_alloc, r.data);
        }

        data context_shared_v1(const context &ctx)
        {
            return constr(0, {
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
            });
        }

        data context_shared_v2(const context &ctx)
        {
            return constr(0, {
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
            });
        }

        data context_shared_v3(const context &ctx)
        {
            return constr(0, {
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
                encode(ctx.tx().hash()),
                votes(ctx),
                proposals(ctx),
                current_treasury(ctx.tx()),
                donation(ctx.tx())
            });
        }

        data context_v1(const context &ctx, const data &ctx_shared, const tx_redeemer &r)
        {
            return constr(0, { ctx_shared, purpose(ctx, r.id()) });
        }

        data context_v2(const context &ctx, const data &ctx_shared, const tx_redeemer &r)
        {
            return constr(0, { ctx_shared, purpose(ctx, r.id()) });
        }

        data context_v3(const context &ctx, const data &ctx_shared, const tx_redeemer &r)
        {
            return constr(0, { ctx_shared, redeemer(r), purpose(ctx, r.id()) });
        }

        data context_shared(const context &ctx)
        {
            switch (_typ) {
                case script_type::plutus_v1: return context_shared_v1(ctx);
                case script_type::plutus_v2: return context_shared_v2(ctx);
                case script_type::plutus_v3: return context_shared_v3(ctx);
                default: throw error("unsupported script_type: {}", static_cast<int>(_typ));
            }
        }

        data context(const context &ctx, const data &ctx_shared, const tx_redeemer &r)
        {
            switch (_typ) {
                case script_type::plutus_v1: return context_v1(ctx, ctx_shared, r);
                case script_type::plutus_v2: return context_v2(ctx, ctx_shared, r);
                case script_type::plutus_v3: return context_v3(ctx, ctx_shared, r);
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
        _tx->foreach_cert([&](const auto &v_raw, const auto) {
            _certs.emplace_back(v_raw);
        });
        _tx->foreach_mint([&](const buffer &p_id, const cbor_map &) {
            _mints.emplace_back(p_id);
        });
        std::sort(_mints.begin(), _mints.end());
        _tx->foreach_redeemer([&](const auto &r) {
            const auto [it, created] = _redeemers.try_emplace(redeemer_id { r.tag, r.ref_idx }, r);
            // There are in fact transactions with duplicate redeemers, such as E8D403D9D2AD5F1CD4D3327F48E34E717B66AC4E4764765BA3A5843758B696E4
            if (!created)
                it->second = r;
        });
        _tx->foreach_script([&](auto &&s) {
            _scripts.try_emplace(s.hash(), std::move(s));
        }, this);
        if (const auto *c_tx = dynamic_cast<const conway::tx *>(_tx.get()); c_tx) {
            c_tx->foreach_proposal([&](const auto &p) {
                _proposals.emplace_back(p);
            });
            c_tx->foreach_vote([&](const auto &v) {
                _votes[v.voter][v.action_id] = v.voting_procedure;
            });
        }
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

    prepared_script context::apply_script(const script_info &script, const std::initializer_list<term> args, const std::optional<ex_units> &budget) const
    {
        auto s_it = _scripts_parsed.find(script.hash());
        if (s_it == _scripts_parsed.end()) {
            flat::script s { _alloc, script.script() };
            auto [new_it, created] = _scripts_parsed.try_emplace(script.hash(), s.program(), s.version());
            s_it = new_it;
        }

        term t = s_it->second.expr;
        for (auto it = args.begin(); it != args.end(); ++it) {
#ifndef NDEBUG
            file::write(install_path(fmt::format("tmp/script-args-my-{}.txt", it - args.begin())), fmt::format("{}\n", *it));
#endif
            if (std::next(it) != args.end()) {
                if (script.type() == script_type::plutus_v1 || script.type() == script_type::plutus_v2)
                    t = term { _alloc, apply { t, *it } };
            } else {
                t = term { _alloc, apply { t, *it } };
            }
        }
        return { script, t, s_it->second.ver, budget };
    }

    static term term_from_datum(allocator &alloc, const context &ctx, const datum_hash &hash)
    {
        return { alloc, constant { alloc, ctx.datums().at(hash) } };
    }

    static term term_from_datum(allocator &alloc, const context &, const uint8_vector &datum)
    {
        return { alloc, constant { alloc, data::from_cbor(alloc, datum) } };
    }

    prepared_script context::prepare_script(const tx_redeemer &r) const
    {
        auto t_redeemer = term { _alloc, constant { _alloc, data::from_cbor(_alloc, r.data) } };
        switch (r.tag) {
            case redeemer_tag::spend: {
                const auto &in = input_at(r.ref_idx);
                const address addr { in.data.address };
                if (const auto pay_id = addr.pay_id(); pay_id.type == pay_ident::ident_type::SHELLEY_SCRIPT) [[likely]] {
                    const auto &script = _scripts.at(pay_id.hash);
                    std::optional<term> t_datum {};
                    if (in.data.datum)
                        t_datum = std::visit([&](const auto &v) { return term_from_datum(_alloc, *this, v); }, *in.data.datum);
                    if (!t_datum && !r.data.empty())
                        t_datum.emplace(_alloc, constant { _alloc, data::from_cbor(_alloc, r.data) });
                    if (!t_datum)
                        throw error("couldn't find datum for tx {} redeemer {}", _tx->hash(), r.ref_idx);
                    return apply_script(script, { *t_datum, t_redeemer, data(script.type(), r) }, r.budget);
                }
                throw error("tx {} redeemer #{} (spend) input #{}: the output address is not a payment script: {}!", _tx->hash(), r.idx, r.ref_idx, in);
                break;
            }
            case redeemer_tag::mint: {
                const auto policy_id = mint_at(r.ref_idx);
                const auto &script = scripts().at(policy_id);
                return apply_script(script, { t_redeemer, data(script.type(), r) }, r.budget);
            }
            case redeemer_tag::cert: {
                const auto &script = scripts().at(cert_cred_at(r.ref_idx).hash);
                return apply_script(script, { t_redeemer, data(script.type(), r) }, r.budget);
            }
            case redeemer_tag::reward: {
                const auto &script = scripts().at(std::get<stake_ident>(withdraw_at(r.ref_idx)).hash);
                return apply_script(script, { t_redeemer, data(script.type(), r) }, r.budget);
            }
            case redeemer_tag::vote: {
                const auto &script = scripts().at(voter_at(r.ref_idx).hash);
                return apply_script(script, { t_redeemer, data(script.type(), r) }, r.budget);
            }
            case redeemer_tag::propose: {
                const auto &p = proposal_at(r.ref_idx);
                return std::visit<prepared_script>([&](const auto &a) {
                    using T = std::decay_t<decltype(a)>;
                    if constexpr (std::is_same_v<T, conway::gov_action_t::parameter_change_t>) {
                        const auto &script = scripts().at(a.policy_id.value());
                        return apply_script(script, { t_redeemer, data(script.type(), r) }, r.budget);
                    }
                    throw error("unsupported gov_action type: {}", typeid(T).name());
                    // Unreachable and needed only to Make Visual C++ happy
                    return prepared_script {
                        scripts().begin()->second,
                        term { _alloc, failure {} }
                    };
                }, p.action.val);
            }
            default:
                throw error("tx: {} unsupported redeemer_tag: {}", _tx->hash(), static_cast<int>(r.tag));
        };
    }

    void context::eval_script(const prepared_script &ps) const
    {
        try {
            const auto &semantics = ps.script.type() == script_type::plutus_v3 ? builtins::semantics_v2() : builtins::semantics_v1();
            machine m { _alloc, cost_models().for_script(ps.script), semantics };
            m.evaluate_no_res(ps.expr);
        } catch (const std::exception &ex) {
            throw error("script {} {}: {}", ps.script.type(), ps.script.hash(), ex.what());
        }
    };

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

    const conway::cert_t &context::cert_at(const uint64_t r_idx) const
    {
        return _certs.at(r_idx);
    }

    const credential_t &context::cert_cred_at(const uint64_t r_idx) const
    {
        return _certs.at(r_idx).cred();
    }

    buffer context::mint_at(const uint64_t r_idx) const
    {
        return _mints.at(r_idx);
    }

    const stored_txo &context::input_at(const uint64_t r_idx) const
    {
        return _inputs.at(r_idx);
    }

    const context::proposal_list &context::proposals() const
    {
        return _proposals;
    }

    const conway::proposal_t &context::proposal_at(const uint64_t r_idx) const
    {
        return _proposals.at(r_idx);
    }

    const conway::voter_t &context::voter_at(const uint64_t r_idx) const
    {
        uint64_t idx = 0;
        for (const auto &[v, votes]: _votes) {
            if (idx++ == r_idx)
                return v;
        }
        throw error("unable to find a vote at index {}!", r_idx);
    }

    const context::voter_map &context::votes() const
    {
        return _votes;
    }

    term context::data(const script_type typ, const tx_redeemer &r) const
    {
        data_encoder enc { _alloc, typ };
        auto shared_it = _shared.find(typ);
        if (shared_it == _shared.end()) {
            auto [new_it, created] = _shared.try_emplace(typ, enc.context_shared(*this));
            shared_it = new_it;
        }
        return { _alloc, constant { _alloc, enc.context(*this, shared_it->second, r) } };
    }
}
