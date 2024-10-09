/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/byron.hpp>
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

    tx::wit_cnt tx::witnesses_ok(const plutus::context */*input_data*/) const
    {
        if (!_wit) [[unlikely]]
            throw cardano_error("vkey_witness_ok called on a transaction without witness data!");
        wit_cnt cnt {};
        const auto &tx_hash = hash();
        for (const auto &w_raw: _wit->array()) {
            const auto &w_items = w_raw.array();
            switch (const auto w_type = w_items.at(0).uint(); w_type) {
                // Normal VKWitness
                case 0: {
                    cbor_value w_data;
                    _parse_cbor_tag(w_data, w_items.at(1).tag());
                    const auto &vkey = w_data.array().at(0).buf();
                    const auto &sig = w_data.array().at(1).buf();
                    //const auto &msg = tx_hash;
                    array<uint8_t, 34> msg;
                    msg[0] = 0x82;
                    msg[1] = 0x01;
                    span_memcpy(std::span(msg.data() + 2, 32), tx_hash);
                    if (!ed25519::verify(sig, vkey.subspan(0, 32), msg)) [[unlikely]]
                        throw error("byron tx witness type 0 failed for tx {}: {}", tx_hash, w_data);
                    ++cnt.vkey;
                    break;
                }
                // RedeemWitness
                /*case 2: {
                    cbor_value w_data;
                    _parse_cbor_tag(w_data, w_items.at(1).tag());
                    const auto &vkey = w_data.array().at(0).buf();
                    const auto &sig = w_data.array().at(1).buf();
                    array<uint8_t, 34> msg;
                    msg[0] = 0x82;
                    msg[1] = 0x01;
                    span_memcpy(std::span(msg.data() + 2, 32), tx_hash);
                    if (!ed25519::verify(sig, vkey.subspan(0, 32), msg)) [[unlikely]]
                        throw error("byron tx witness type 2 failed for tx {}: {}", tx_hash, w_data);
                    ++ok.vkey_ok;
                    break;
                }*/
                default:
                    throw cardano_error("slot: {}, tx: {} - unsupported witness type: {}", (uint64_t)_blk.slot(), hash().span(), w_type);
            }
        }
        return cnt;
    }
}