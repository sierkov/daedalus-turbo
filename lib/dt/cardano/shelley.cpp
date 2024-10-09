/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/shelley.hpp>

namespace daedalus_turbo::cardano::shelley {
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
        for (const auto &w: w_val.array()) {
            const auto &vkey = w.array().at(0).buf();
            const auto &sig = w.array().at(1).buf();
            if (!ed25519::verify(sig, vkey, hash())) [[unlikely]]
                throw error("tx vkey witness failed at slot {}: vkey: {}, sig: {} tx_hash: {}", block().slot(), vkey, sig, hash());
            vkeys.emplace(blake2b<key_hash>(vkey));
        }
        return vkeys;
    }

    size_t tx::_witnesses_ok_native_script(const cbor::value &w_val, const set<key_hash> &vkeys) const
    {
        size_t cnt = 0;
        for (const auto &w: w_val.array()) {
            if (const auto err = _validate_native_script_single(w, *this, vkeys); err) [[unlikely]]
                throw cardano_error("native script for tx {} failed: {} script: {}", hash(), *err, w_val);
            ++cnt;
        }
        return cnt;
    }

    size_t tx::_witnesses_ok_bootstrap(const cbor::value &w_val) const
    {
        size_t cnt = 0;
        for (const auto &w: w_val.array()) {
            const auto &vkey = w.at(0).buf();
            const auto &sig = w.at(1).buf();
            if (!ed25519::verify(sig, vkey, hash())) [[unlikely]]
                throw cardano_error("tx bootstrap witness failed at slot {}: vkey: {}, sig: {} tx_hash: {}", block().slot(), vkey, sig, hash());
            ++cnt;
        }
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
}