/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_SHELLEY_HPP
#define DAEDALUS_TURBO_CARDANO_SHELLEY_HPP

#include <dt/cardano/common.hpp>
#include <dt/cbor.hpp>
#include <dt/ed25519.hpp>

namespace daedalus_turbo::cardano::shelley {
    struct tx;

    struct block: public block_base {
        using block_base::block_base;

        cardano_hash_32 hash() const override
        {
            return blake2b<cardano_hash_32>(header_cbor().raw_span());
        }

        const cbor_buffer &prev_hash() const override
        {
            return header_body().at(2).buf();
        }

        uint64_t height() const override
        {
            return header_body().at(0).uint();
        }

        size_t tx_count() const override
        {
            return transactions().size();
        }

        void foreach_tx(const std::function<void(const cardano::tx &)> &observer) const override;

        inline const cardano::slot slot() const override
        {
            return cardano::slot { header_body().at(1).uint() };
        }

        inline const cbor_value &header_cbor() const
        {
            return _block.array().at(0);
        }

        inline const cbor_array &header() const
        {
            return header_cbor().array();
        }

        inline const buffer header_body_raw() const
        {
            return header().at(0).raw_span();
        }

        inline const cbor_array &header_body() const
        {
            return header().at(0).array();
        }

        inline const cbor_array &transactions() const
        {
            return _block.array().at(1).array();
        }

        inline const cbor_array &witnesses() const
        {
            return _block.array().at(2).array();
        }

        const buffer issuer_vkey() const override
        {
            return header_body().at(3).buf();
        }

        const kes_signature kes() const override
        {
            const auto &op_cert = header_body();
            size_t op_start_idx = 9;
            return kes_signature {
                op_cert.at(op_start_idx + 0).buf(),
                op_cert.at(op_start_idx + 3).buf(),
                issuer_vkey(),
                header().at(1).buf(),
                header_body_raw(),
                op_cert.at(op_start_idx + 1).uint(),
                op_cert.at(op_start_idx + 2).uint(),
                slot()
            };
        }

        const block_vrf vrf() const override
        {
            const auto &vkey = header_body().at(4).span();
            const auto &leader_vrf = header_body().at(6).array();
            const auto &nonce_vrf = header_body().at(5).array();
            return block_vrf {
                vkey,
                leader_vrf.at(0).span(),
                leader_vrf.at(1).span(),
                nonce_vrf.at(0).span(),
                nonce_vrf.at(1).span()
            };
        }
    };

    struct tx: public cardano::tx {
        using cardano::tx::tx;

        void foreach_input(const std::function<void(const tx_input &)> &observer) const override
        {
            const cbor_array *inputs = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 0) inputs = &entry.array();
            }
            if (inputs == nullptr) return;
            for (size_t i = 0; i < inputs->size(); i++) {
                const auto &in = inputs->at(i).array();
                auto in_idx = in.at(1).uint();
                if (i >= 0x10000) throw cardano_error("transaction input number is too high {}!", i);
                if (in_idx >= 0x10000) throw cardano_error("referenced transaction output number is too high {}!", in_idx);
                observer(tx_input { in.at(0).buf(), (uint16_t)in_idx, (uint16_t)i });
            }
        }

        void foreach_output(const std::function<void(const tx_output &)> &observer) const override
        {
            const cbor_array *outputs = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 1) outputs = &entry.array();
            }
            if (outputs == nullptr) return;
            for (size_t i = 0; i < outputs->size(); i++) {
                if (outputs->at(i).type != CBOR_ARRAY) throw cardano_error("slot: {}, era: {}, unsupported tx output format!", _blk.slot(), _blk.era());
                const auto &out = outputs->at(i).array();
                if (i >= 0x10000) throw cardano_error("transaction output number is too high {}!", i);
                observer(tx_output { out.at(0).buf(), out.at(1).uint(), (uint16_t)i });
            }
        }

        void foreach_withdrawal(const std::function<void(const tx_withdrawal &)> &observer) const override
        {
            const cbor_map *withdrawals = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 5) withdrawals = &entry.map();
            }
            if (withdrawals == nullptr) return;
            for (size_t i = 0; i < withdrawals->size(); i++) {
                const auto &[address, amount] = withdrawals->at(i);
                if (i >= 0x10000) throw cardano_error("transaction withdrawal number is too high {}!", i);
                observer(tx_withdrawal { address.buf(), amount.uint(), (uint16_t)i });
            }
        }

        const cardano::amount fee() const override
        {
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 2)
                    return cardano::amount { entry.uint() };
            }
            throw error("a shelley+ transaction has no fee information: {} at offset {}!", hash(), offset());
        }

        void foreach_stake_reg(const std::function<void(const stake_ident &)> &observer) const override
        {
            _foreach_cert(0, [&observer](const auto &cert) {
                const auto &stake_cred = cert.at(1).array();
                observer(stake_ident { stake_cred.at(1).buf(), stake_cred.at(0).uint() == 1 });
            });
        }

        void foreach_stake_unreg(const std::function<void(const stake_ident &)> &observer) const override
        {
            _foreach_cert(1, [&observer](const auto &cert) {
                const auto &stake_cred = cert.at(1).array();
                observer(stake_ident { stake_cred.at(1).buf(), stake_cred.at(0).uint() == 1 });
            });
        }

        void foreach_stake_deleg(const std::function<void(const stake_deleg &)> &observer) const override
        {
            _foreach_cert(2, [&observer](const auto &cert) {
                const auto &stake_cred = cert.at(1).array();
                observer(stake_deleg { stake_ident { stake_cred.at(1).buf(), stake_cred.at(0).uint() == 1 }, cert.at(2).buf() });
            });
        }

        void foreach_pool_reg(const std::function<void(const pool_reg &)> &observer) const override
        {
            _foreach_cert(3, [&observer](const auto &cert) {
                pool_reg params {
                    cert.at(1).buf(),
                    cert.at(3).uint(),
                    cert.at(4).uint(),
                    cert.at(5).tag().second->array().at(0).uint(),
                    cert.at(5).tag().second->array().at(1).uint(),
                    cardano::address { cert.at(6).buf() }.stake_id()
                };
                const auto &owners = cert.at(7).array();
                for (const auto &addr: owners)
                    params.owners.emplace(stake_ident { addr.buf(), false });
                observer(params);
            });
        }

        void foreach_pool_unreg(const std::function<void(const pool_unreg &)> &observer) const override
        {
            _foreach_cert(4, [&observer](const auto &cert) {
                observer(pool_unreg { cert.at(1).buf(), cert.at(2).uint() });
            });
        }

        void foreach_instant_reward(const std::function<void(const instant_reward &)> &observer) const override
        {
            _foreach_cert(6, [&observer](const auto &cert) {
                const auto &reward = cert.at(1).array();
                auto source_raw = reward.at(0).uint();
                if (source_raw > 1)
                    throw error("unexpected value of reward source: {}!", source_raw);
                auto source = reward.at(0).uint() == 0 ? reward_source::reserves : reward_source::treasury;
                std::map<stake_ident, cardano::amount> rewards {};
                for (const auto &[stake_cred, coin]: reward.at(1).map()) {
                    rewards.try_emplace(stake_ident { stake_cred.array().at(1).buf(), stake_cred.array().at(0).uint() == 1 }, coin.uint());
                }
                observer(instant_reward { source, std::move(rewards) });
            });
        }

        vkey_wit_ok vkey_witness_ok() const override
        {
            if (!_wit) throw cardano_error("vkey_witness_ok called on a transaction without witness data!");
            vkey_wit_ok ok {};
            auto tx_hash = hash();
            for (const auto &[w_type, w_val]: _wit->map()) {
                switch (w_type.uint()) {
                    // vkey witness
                    case 0: {
                        for (const auto &w: w_val.array()) {
                            ok.total++;
                            const auto &vkey = w.array().at(0).buf();
                            const auto &sig = w.array().at(1).buf();
                            if (ed25519::verify(sig, vkey, tx_hash)) ok.ok++;
                        }
                        break;
                    }

                    case 1: // native_script
                    case 2: // bootstrap witness
                    case 3: // plutus_v1_script
                    case 6: // plutus_v2_script
                    case 7: // plutus_v3_script
                    case 4: // plutus_data
                    case 5: // redeemer
                        break;

                    default:
                        throw cardano_error("unsupported witness type: {}!", w_type.uint());
                }
            }
            return ok;
        }
    protected:
        void _foreach_cert(uint64_t cert_type, const std::function<void(const cbor_array &)> &observer) const
        {
            const cbor_array *certs = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 4)
                    certs = &entry.array();
            }
            if (certs != nullptr) {
                for (const auto &cert_raw: *certs) {
                    const auto &cert = cert_raw.array();
                    if (cert.at(0).uint() == cert_type)
                        observer(cert);
                }
            }
        }
    };

    inline void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        if (txs.size() != wits.size())
            throw error("slot: {} the number of transactions {} does not match the number of witnesses {}", (uint64_t)slot(), txs.size(), wits.size());
        for (size_t i = 0; i < txs.size(); ++i) {
            observer(tx { txs.at(i), *this, &wits.at(i) });
        }
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_SHELLEY_HPP