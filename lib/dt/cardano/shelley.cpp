/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/shelley.hpp>

namespace daedalus_turbo::cardano::shelley {
    genesis_deleg_cert::genesis_deleg_cert(const cbor::value &v):
        hash { v.at(1).buf() }, pool_id { v.at(2).buf() }, vrf_vkey { v.at(3).buf() }
    {
    }

    instant_reward_cert::instant_reward_cert(const cbor::value &v)
    {
        const auto &reward = v.at(1).array();
        switch (const auto source_raw = reward.at(0).uint(); source_raw) {
            case 0: source = reward_source::reserves; break;
            case 1: source = reward_source::treasury; break;
            default: throw error("unexpected value of reward source: {}!", source_raw);
        }
        for (const auto &[stake_cred, coin]: reward.at(1).map()) {
            rewards.try_emplace(stake_ident { stake_cred.array().at(1).buf(), stake_cred.array().at(0).uint() == 1 }, coin.uint());
        }
    }

    pool_reg_cert pool_reg_cert::from_cbor(const cbor::value &v)
    {
        const auto &cert = v.array();
        return { cert.at(1).buf(), pool_params::from_cbor(cert, 1) };
    }

    pool_retire_cert pool_retire_cert::from_cbor(const cbor::value &v)
    {
        const auto &cert = v.array();
        return { cert.at(1).buf(), cert.at(2).uint() };
    }

    static cert_t::value_type cert_from_cbor(const cbor::value &v)
    {
        const auto &cert = v.array();
        switch (const auto typ = cert.at(0).uint(); typ) {
            case 0: return stake_reg_cert { cert.at(1) };
            case 1: return stake_dereg_cert { cert.at(1) };
            case 2: return stake_deleg_cert { cert.at(1), cert.at(2).buf() };
            case 3: return pool_reg_cert::from_cbor(v);
            case 4: return pool_retire_cert::from_cbor(v);
            case 5: return genesis_deleg_cert { v };
            case 6: return instant_reward_cert { v };
            default:
                throw error("unsupported cert type: {}", typ);
        }
    }

    cert_t::cert_t(const cbor::value &v): val { cert_from_cbor(v) }
    {
    }

    tx::wit_cnt tx::witnesses_ok_vkey(set<key_hash> &valid_vkeys) const
    {
        wit_cnt cnts {};
        foreach_witness([&](const auto typ, const auto &w_list) {
            switch (typ) {
                case 0:
                    foreach_set(w_list, [&](const auto &w, const auto) {
                        const auto &vkey = w.array().at(0).buf();
                        const auto &sig = w.array().at(1).buf();
                        if (!ed25519::verify(sig, vkey, hash())) [[unlikely]]
                            throw error("tx vkey witness failed at slot {}: vkey: {}, sig: {} tx_hash: {}", block().slot(), vkey, sig, hash());
                        valid_vkeys.emplace(blake2b<key_hash>(vkey));
                        ++cnts.vkey;
                    });
                    break;
                case 2:
                    foreach_set(w_list, [&](const auto &w, const auto) {
                        const auto &vkey = w.at(0).buf();
                        const auto &sig = w.at(1).buf();
                        if (!ed25519::verify(sig, vkey, hash())) [[unlikely]]
                            throw cardano_error("tx bootstrap witness failed at slot {}: vkey: {}, sig: {} tx_hash: {}", block().slot(), vkey, sig, hash());
                        valid_vkeys.emplace(blake2b<key_hash>(vkey));
                        ++cnts.vkey;
                    });
                default: break;
            }
        });
        return cnts;
    }

    tx::wit_cnt tx::witnesses_ok_native(const set<key_hash> &valid_vkeys) const
    {
        wit_cnt cnts {};
        foreach_witness([&](const auto typ, const auto &w_list) {
            switch (typ) {
                case 1:
                    foreach_set(w_list, [&](const auto &w, const auto) {
                        if (const auto err = _validate_native_script_single(w, valid_vkeys); err) [[unlikely]]
                            throw cardano_error("native script for tx {} failed: {} script: {}", hash(), *err, w);
                        ++cnts.native_script;
                    });
                    break;
                default: break;
            }
        });
        return cnts;
    }

    tx::wit_cnt tx::_witnesses_ok_other(uint64_t typ, const cbor::value &w_val, const plutus::context *) const
    {
        throw cardano_error("unsupported witness type {} at tx {}: {}", typ, hash(), w_val);
    }

    cardano::tx::wit_cnt tx::witnesses_ok_other(const plutus::context *ctx) const
    {
        wit_cnt cnt {};
        foreach_witness([&](const auto typ, const auto &w_val) {
            if (typ > 2)
                cnt += _witnesses_ok_other(typ, w_val, ctx);
        });
        return cnt;
    }

    cardano::tx::wit_cnt tx::witnesses_ok(const plutus::context *ctx) const
    {
        if (!_wit)[[unlikely]]
            throw cardano_error("vkey_witness_ok called on a transaction without witness data!");
        wit_cnt cnt {};
        set<key_hash> valid_vkeys {};
        cnt += witnesses_ok_vkey(valid_vkeys);
        cnt += witnesses_ok_native(valid_vkeys);
        cnt += witnesses_ok_other(ctx);
        return cnt;
    }

    void tx::foreach_input(const std::function<void(const tx_input &)> &observer) const
    {
        if (!_unique_inputs) {
            _unique_inputs.emplace();
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 0) {
                    foreach_set(entry, [&](const auto &txin, size_t) {
                        const auto in_idx = txin.at(1).uint();
                        _unique_inputs->emplace(txin.at(0).buf(), in_idx);
                    });
                }
            }
        }
        size_t unique_idx = 0;
        for (const auto &unique_txin: *_unique_inputs) {
            observer(tx_input { unique_txin.hash, unique_txin.idx, unique_idx++ });
        }
    }

    void tx::foreach_script(const std::function<void(script_info &&)> &observer, const plutus::context *) const
    {
        foreach_witness([&](const auto typ, const auto &w_val) {
            switch (typ) {
                case 1: {
                    foreach_set(w_val, [&](const auto &script_raw, const auto) {
                        observer({ script_type::native, script_raw.raw_span() });
                    });
                    break;
                }
                default: break;
            }
        });
    }

    void tx::foreach_witness(const witness_observer_t &observer) const
    {
        for (const auto &[w_type, w_val]: _wit->map()) {
            observer(w_type.uint(), w_val);
        }
    }

    void tx::foreach_witness_item(const witness_observer_t &observer) const
    {
        foreach_witness([&](const auto wtyp, const auto &w_val) {
            foreach_set(w_val, [&](const auto &w_data, const auto) {
                observer(wtyp, w_data);
            });
        });
    }

    void tx::foreach_witness_vkey(const vkey_observer_t &observer) const
    {
        foreach_witness([&](const auto wtyp, const auto &w_val) {
            switch (wtyp) {
                case 0:
                    foreach_set(w_val, [&](const auto &w_data, const auto) {
                        observer({ vkey_witness_t::vkey, w_data.at(0).buf() });
                    });
                    break;
                case 2:
                    foreach_set(w_val, [&](const auto &w_data, const auto) {
                        observer({ vkey_witness_t::bootstrap, w_data.raw_span() });
                    });
                    break;
                default: break;
            }
        });
    }

    std::optional<uint64_t> tx::validity_end() const
    {
        for (const auto &[entry_type, entry]: _tx.map()) {
            if (entry_type.uint() == 3)
                return entry.uint();
        }
        return {};
    }

    void tx::foreach_cert(const std::function<void(const cbor::value &cert, size_t cert_idx)> &observer) const
    {
        for (const auto &[entry_type, entry]: _tx.map()) {
            if (entry_type.uint() == 4) {
                foreach_set(entry, [&](const auto &cert_raw, const size_t cert_idx) {
                    observer(cert_raw, cert_idx);
                });
            }
        }
    }

    void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        for (size_t i = 0; i < txs.size(); ++i) {
            observer(tx { txs.at(i), *this, i, &wits.at(i), auxiliary_at(i) });
        }
    }
}