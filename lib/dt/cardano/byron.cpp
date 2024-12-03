/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/byron.hpp>
#include <dt/cardano/native-script.hpp>
#include <dt/container.hpp>

namespace daedalus_turbo::cardano::byron {
    static blake2b_256_hash merkle_leaf_hash(const buffer tx_raw)
    {
        uint8_vector data {};
        data << 0 << tx_raw;
        return blake2b<blake2b_256_hash>(data);
    }

    static blake2b_256_hash merkle_node_hash(const blake2b_256_hash &l, const blake2b_256_hash &r)
    {
        uint8_vector data {};
        data << 1 << l << r;
        return blake2b<blake2b_256_hash>(data);
    }

    static tx_hash make_merkle_tree_root(const cbor_array &txs)
    {
        using merkle_level = vector<tx_hash>;
        using merkle_tree = vector<merkle_level>;

        if (!txs.empty()) {
            merkle_tree mt {};
            mt.emplace_back();
            {
                auto &level0 = mt.back();
                for (const auto &tx: txs)
                    level0.emplace_back(merkle_leaf_hash(tx.at(0).raw_span()));
            }

            while (mt.back().size() > 1) {
                mt.emplace_back();
                auto &next_level = mt.back();
                auto &prev_level = mt.at(mt.size() - 2);
                for (size_t i = 0; i < prev_level.size(); i += 2) {
                    if (i + 1 < prev_level.size()) [[likely]] {
                        next_level.emplace_back(merkle_node_hash(prev_level[i], prev_level[i + 1]));
                    } else {
                        next_level.emplace_back(prev_level[i]);
                    }
                }
            }

            return mt.back().at(0);
        }

        return blake2b<tx_hash>(uint8_vector {});
    }

    bool block::body_hash_ok() const
    {
        const auto &proofs = body_proof_raw().array();
        cbor::encoder tx_wits_enc {};
        tx_wits_enc.array();
        for (const auto &tx_raw: transactions())
            tx_wits_enc << tx_raw.at(1).raw_span();
        tx_wits_enc.s_break();
        const auto tx_merkle_root = make_merkle_tree_root(transactions());
        const auto tx_wits_hash = blake2b<blake2b_256_hash>(tx_wits_enc.cbor());
        const bool tx_ok = transactions().size() == proofs.at(0).at(0).uint()
                && tx_merkle_root == proofs.at(0).at(1).buf()
                && tx_wits_hash == proofs.at(0).at(2).buf();
        const auto dlg_hash = blake2b<blake2b_256_hash>(body().at(2).raw_span());
        const auto dlg_ok = dlg_hash == proofs.at(2).buf();
        const auto upd_hash = blake2b<blake2b_256_hash>(body().at(3).raw_span());
        const auto upd_ok = upd_hash == proofs.at(3).buf();
        return tx_ok && dlg_ok && upd_ok;
    }

    void block::foreach_update_proposal(const std::function<void(const param_update_proposal &)> &observer) const
    {
        const auto &updates = update_proposals();
        for (const auto &r_prop: updates.at(0).array()) {
            param_update upd { .protocol_ver=protocol_version { r_prop.at(0).at(0).uint(), r_prop.at(0).at(1).uint() } };
            const auto &bvermod = r_prop.at(1).array();
            if (const auto &v = bvermod.at(2).array(); !v.empty())
                upd.max_block_body_size = v.at(0).uint();
            if (const auto &v = bvermod.at(3).array(); !v.empty())
                upd.max_block_header_size = v.at(0).uint();
            if (const auto &v = bvermod.at(4).array(); !v.empty())
                upd.max_transaction_size = v.at(0).uint();
            param_update_proposal prop { .pool_id=issuer_hash(), .update=std::move(upd) };
            prop.update.hash_from_cbor(r_prop);
            observer(prop);
        }
    }

    void tx::foreach_witness(const witness_observer_t &observer) const
    {
        for (const auto &w_raw: _wit->array()) {
            observer(w_raw.at(0).uint(), *w_raw.at(1).tag().second);
        }
    }

    void tx::foreach_witness_item(const witness_observer_t &observer) const
    {
        foreach_witness(observer);
    }

    void tx::foreach_witness_vkey(const vkey_observer_t &observer) const
    {
        foreach_witness([&](const auto wtyp, const auto &w_val) {
            switch (wtyp) {
                case 0: {
                    const auto w_data = cbor::parse(w_val.buf());
                    observer({ vkey_witness_t::byron_vkey, w_data.array().at(0).buf() });
                    break;
                }
                case 2: {
                    const auto w_data = cbor::parse(w_val.buf());
                    observer({ vkey_witness_t::byron_redeem, w_data.array().at(0).buf() });
                    break;
                }
                default: break;
            }
        });
    }

    void tx::foreach_script(const std::function<void(script_info &&)> &observer, const plutus::context *) const
    {
        foreach_witness([&](const auto typ, const auto &w_val) {
            switch (typ) {
                case 1: {
                    observer({ script_type::native, w_val.raw_span() });
                    break;
                }
                default: break;
            }
        });
    }

    tx::wit_cnt tx::witnesses_ok_vkey(set<key_hash> &valid_vkeys) const {
        const auto &tx_hash = hash();
        const auto pm = dynamic_cast<const byron::block &>(block()).protocol_magic_raw().raw_span();
        wit_cnt cnts {};
        foreach_witness([&](const auto w_typ, const auto &w_val) {
            const auto w_data = cbor::parse(w_val.buf());
            switch (w_typ) {
                // Normal VKWitness
                case 0: {
                    const auto &vkey = w_data.array().at(0).buf();
                    const auto &sig = w_data.array().at(1).buf();
                    uint8_vector msg {};
                    msg.reserve(64);
                    msg << 0x01; // signing tag
                    msg << pm;   // protocol magic
                    msg << 0x58; // CBOR bytestring
                    msg << 0x20; // hash size
                    msg << tx_hash;
                    const auto vkey_short = vkey.subspan(0, 32);
                    if (!ed25519::verify(sig, vkey_short, msg)) [[unlikely]]
                        throw error("byron tx witness type 0 failed for tx {}: {}", tx_hash, w_data);
                    valid_vkeys.emplace(blake2b<key_hash>(vkey_short));
                    ++cnts.vkey;
                    break;
                }
                // BootstrapWitness
                case 2: {
                    const auto &vkey = w_data.array().at(0).buf();
                    const auto &sig = w_data.array().at(1).buf();
                    uint8_vector msg {};
                    msg.reserve(64);
                    msg << 0x02; // signing tag
                    msg << pm;   // protocol magic
                    msg << 0x58; // CBOR bytestring
                    msg << 0x20; // hash size
                    msg << tx_hash;
                    const auto vkey_short = vkey.subspan(0, 32);
                    if (!ed25519::verify(sig, vkey_short, msg)) [[unlikely]]
                        throw error("byron tx witness type 2 failed for tx {}: {}", tx_hash, w_data);
                    valid_vkeys.emplace(blake2b<key_hash>(vkey_short));
                    ++cnts.vkey;
                    break;
                }
                default: // do nothing
                    break;
            }
        });
        return cnts;
    }

    tx::wit_cnt tx::witnesses_ok_native(const set<key_hash> &vkeys) const
    {
        wit_cnt cnts {};
        foreach_witness([&](const auto w_typ, const auto &w_val) {
            const auto w_data = cbor::parse(w_val.buf());
            switch (w_typ) {
                case 1:
                    if (const auto err = native_script::validate(w_data, block().slot(), vkeys); err) [[unlikely]]
                        throw cardano_error("native script for tx {} failed: {} script: {}", hash(), *err, w_val);
                    ++cnts.native_script;
                    break;
                default:
                    break;
            }
        });
        return cnts;
    }

    tx::wit_cnt tx::witnesses_ok(const plutus::context */*input_data*/) const
    {
        if (!_wit) [[unlikely]]
            throw cardano_error("vkey_witness_ok called on a transaction without witness data!");
        wit_cnt cnt {};
        set<key_hash> valid_vkeys {};
        cnt += witnesses_ok_vkey(valid_vkeys);
        cnt += witnesses_ok_native(valid_vkeys);
        return cnt;
    }
}