/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/shelley.hpp>

namespace daedalus_turbo::cardano::shelley {
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
            case 5: return genesis_deleg_cert { cert.at(1).buf(), cert.at(2).buf(), cert.at(3).buf() };
            case 6: return instant_reward_cert { v };
            default:
                throw error("unsupported cert type: {}", typ);
        }
    }

    cert_t::cert_t(const cbor::value &v): val { cert_from_cbor(v) }
    {
    }

    static std::optional<std::string> _validate_native_script_single(const cbor_value &script, const tx &tx, const set<key_hash> &vkeys)
    {
        switch (const auto typ = script.at(0).uint(); typ) {
            case 0:
                if (const auto &req_vkey = script.at(1).buf(); !vkeys.contains(req_vkey)) [[unlikely]]
                    return fmt::format("required key {} didn't sign the transaction", req_vkey);
                break;
            case 1:
                for (const auto &sub_script: script.at(1).array()) {
                    if (const auto err = _validate_native_script_single(sub_script, tx, vkeys); err)
                        return err;
                }
                break;
            case 2: {
                bool any_ok = false;
                for (const auto &sub_script: script.at(1).array()) {
                    if (!_validate_native_script_single(sub_script, tx, vkeys))
                        any_ok = true;
                }
                if (!any_ok) [[unlikely]]
                    return fmt::format("no child script was successful while require at least one!");
                break;
            }
            case 3: {
                const auto min_ok = script.at(1).uint();
                uint64_t num_ok = 0;
                for (const auto &sub_script: script.at(2).array()) {
                    if (!_validate_native_script_single(sub_script, tx, vkeys))
                        ++num_ok;
                }
                if (num_ok < min_ok) [[unlikely]]
                    return fmt::format("only {} child scripts succeed while {} are required!", num_ok, min_ok);
                break;
            }
            case 4:
                if (const auto invalid_before = script.at(1).uint(); tx.block().slot() < invalid_before)
                    return fmt::format("invalid before {} while the current slot is {}!", invalid_before, tx.block().slot());
                break;
            case 5:
                if (const auto invalid_after = script.at(1).uint(); tx.block().slot() >= invalid_after)
                    return fmt::format("invalid after {} while the current slot is {}!", invalid_after, tx.block().slot());
                break;
            default:
                return fmt::format("unsupported native script type {}", typ);
        }
        return {};
    }

    set<key_hash> tx::_witnesses_ok_vkey(const cbor::value &w_val) const
    {
        set<key_hash> vkeys {};
        foreach_set(w_val, [&](const auto &w, const auto) {
            const auto &vkey = w.array().at(0).buf();
            const auto &sig = w.array().at(1).buf();
            if (!ed25519::verify(sig, vkey, hash())) [[unlikely]]
                throw error("tx vkey witness failed at slot {}: vkey: {}, sig: {} tx_hash: {}", block().slot(), vkey, sig, hash());
            vkeys.emplace(blake2b<key_hash>(vkey));
        });
        return vkeys;
    }

    size_t tx::_witnesses_ok_native_script(const cbor::value &w_val, const set<key_hash> &vkeys) const
    {
        size_t cnt = 0;
        foreach_set(w_val, [&](const auto &w, const auto) {
            if (const auto err = _validate_native_script_single(w, *this, vkeys); err) [[unlikely]]
                throw cardano_error("native script for tx {} failed: {} script: {}", hash(), *err, w_val);
            ++cnt;
        });
        return cnt;
    }

    size_t tx::_witnesses_ok_bootstrap(const cbor::value &w_val) const
    {
        size_t cnt = 0;
        foreach_set(w_val, [&](const auto &w, const auto) {
            const auto &vkey = w.at(0).buf();
            const auto &sig = w.at(1).buf();
            if (!ed25519::verify(sig, vkey, hash())) [[unlikely]]
                throw cardano_error("tx bootstrap witness failed at slot {}: vkey: {}, sig: {} tx_hash: {}", block().slot(), vkey, sig, hash());
            ++cnt;
        });
        return cnt;
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
        // validate vkey witnesses and create a vkeys set for the potential native script validation
        set<key_hash> vkeys {};
        foreach_witness([&](const auto typ, const auto &w_val) {
            switch (typ) {
                case 0:
                    vkeys = _witnesses_ok_vkey(w_val);
                    cnt.vkey += vkeys.size();
                    break;
                case 2:
                    cnt.vkey += _witnesses_ok_bootstrap(w_val);
                    break;
                default:
                    // ignore, will be processed later
                    break;
            }
        });
        foreach_witness([&](const auto typ, const auto &w_val) {
            if (typ == 1)
                cnt.native_script += _witnesses_ok_native_script(w_val, vkeys);
        });
        cnt += witnesses_ok_other(ctx);
        return cnt;
    }

    void tx::foreach_input(const std::function<void(const tx_input &)> &observer) const
    {
        for (const auto &[entry_type, entry]: _tx.map()) {
            if (entry_type.uint() == 0) {
                set<tx_out_ref> unique_inputs {};
                foreach_set(entry, [&](const auto &txin, size_t) {
                    const auto in_idx = txin.at(1).uint();
                    unique_inputs.emplace(tx_out_ref { txin.at(0).buf(), in_idx });
                });
                size_t unique_idx = 0;
                for (const auto &unique_txin: unique_inputs) {
                    observer(tx_input { unique_txin.hash, unique_txin.idx, unique_idx++ });
                }
            }
        }
    }

    void tx::foreach_witness(const std::function<void(uint64_t, const cbor::value &)> &observer) const
    {
        for (const auto &[w_type, w_val]: _wit->map()) {
            observer(w_type.uint(), w_val);
        }
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