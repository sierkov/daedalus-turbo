/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_BYRON_HPP
#define DAEDALUS_TURBO_CARDANO_BYRON_HPP

#include <dt/cardano/common.hpp>
#include <dt/cbor.hpp>
#include <dt/ed25519.hpp>

namespace daedalus_turbo::cardano::byron {
    struct block_signature {
        block_signature(const cbor_array &sig): _sig { sig }
        {
        }

        uint64_t epoch() const
        {
            return _sig.at(0).array().at(0).uint();
        }

        const cbor_buffer &issuer_vkey_full() const
        {
            return _sig.at(0).array().at(1).buf();
        }

        const cbor_buffer issuer_vkey() const
        {
            return _sig.at(0).array().at(1).buf().subspan(0, 32);;
        }

        const cbor_buffer delegate_vkey() const
        {
            return _sig.at(0).array().at(2).buf().subspan(0, 32);
        }

        const cbor_buffer &certificate() const
        {
            return _sig.at(0).array().at(3).buf();
        }

        const cbor_buffer &signature() const
        {
            return _sig.at(1).buf();
        }
    private:
        const cbor_array &_sig;
    };

    struct boundary_block: block_base {
        using block_base::block_base;

        static cardano::block_hash padded_hash(uint8_t magic, const buffer &data)
        {
            uint8_vector padded(data.size() + 2);
            padded[0] = 0x82;
            padded[1] = magic;
            memcpy(padded.data() + 2, data.data(), data.size());
            return blake2b<cardano::block_hash>(padded);
        }

        uint64_t height() const override
        {
            return slot();
        }

        cardano_hash_32 hash() const override
        {
            return padded_hash(0x00, _block.array().at(0).raw_span());
        }

        const buffer issuer_vkey() const override
        {
            static auto dummy = cardano::vkey::from_hex("0000000000000000000000000000000000000000000000000000000000000000");
            return dummy.span();
        }

        const cbor_buffer &prev_hash() const override
        {
            return header().at(1).buf();
        }

        const cardano::slot slot() const override
        {
            return cardano::slot { epoch() * 21600 };
        }

        inline const cbor_array &header() const
        {
            return _block.array().at(0).array();
        }

        inline const cbor_array &consensus() const
        {
            return header().at(3).array();
        }

        inline uint64_t epoch() const
        {
            return consensus().at(0).uint();
        }

        bool signature_ok() const override
        {
            return true;
        }
    };

    struct tx;

    struct block: boundary_block {
        using boundary_block::boundary_block;

        cardano_hash_32 hash() const override
        {
            return padded_hash(0x01, _block.array().at(0).raw_span());
        }

        size_t tx_count() const override
        {
            return body().at(0).array().size();
        }

        inline void foreach_tx(const std::function<void(const cardano::tx &)> &observer) const override;

        inline const cbor_array &header() const
        {
            return _block.array().at(0).array();
        }

        inline const cbor_array &body() const
        {
            return _block.array().at(1).array();
        }

        inline const cbor_array &update_proposals() const
        {
            return body().at(3).array();
        }

        const cbor_value &protocol_magic_raw() const
        {
            return header().at(0);
        }

        uint64_t protocol_magic() const
        {
            return protocol_magic_raw().uint();
        }

        const cbor_value &prev_hash_raw() const
        {
            return header().at(1);
        }

        const cardano::slot slot() const override
        {
            auto epoch = header().at(3).array().at(0).array().at(0).uint();
            auto epoch_slot = header().at(3).array().at(0).array().at(1).uint();
            return cardano::slot { epoch * 21600 + epoch_slot };
        }

        const cbor_buffer issuer_vkey_full() const
        {
            return header().at(3).array().at(1).buf();
        }

        const buffer issuer_vkey() const override
        {
            return buffer { issuer_vkey_full().data(), 32 };
        }

        uint64_t signature_type() const
        {
            const auto &sig = header().at(3).array().at(3).array();
            return sig.at(0).uint();
        }

        const cbor_value &body_proof_raw() const
        {
            return header().at(2);
        }

        const cbor_array &consensus() const
        {
            return header().at(3).array();
        }

        const cbor_value &slot_id_raw() const
        {
            return consensus().at(0);
        }

        const cbor_value &difficulty_raw() const
        {
            return consensus().at(2);
        }

        const cbor_value &extra_raw() const
        {
            return header().at(4);
        }

        const cbor_array &transactions() const
        {
            return body().at(0).array();
        }

        block_signature signature() const
        {
            const auto &sig = consensus().at(3).array();
            const auto sig_type = sig.at(0).uint();
            if (sig_type != 2)
                throw cardano_error("Byron block signature must have type 2 but got {}!", sig_type);
            return block_signature { sig.at(1).array() };
        }

        uint8_vector make_signed_data() const
        {
            using namespace std::literals;
            uint8_vector data;
            data.reserve(512);
            data << "01"sv;
            data << signature().issuer_vkey_full();
            data << "\x09"sv;
            data << protocol_magic_raw().data_buf();
            data << "\x85"sv; // CBOR Array of length 5
            data << prev_hash_raw().data_buf();
            data << body_proof_raw().data_buf();
            data << slot_id_raw().data_buf();
            data << difficulty_raw().data_buf();
            data << extra_raw().data_buf();
            return data;
        }

        bool signature_ok() const override
        {
            const auto s = signature();
            return ed25519::verify(s.signature(), s.delegate_vkey(), make_signed_data());
        }
    };

    struct tx: cardano::tx {
        using cardano::tx::tx;

        void foreach_input(const std::function<void(const tx_input &)> &observer) const override
        {
            const auto &inputs = _tx.array().at(0).array();
            for (size_t i = 0; i < inputs.size(); i++) {
                const auto &in = inputs.at(i).array();
                if (in.at(0).uint() != 0) throw cardano_error("unsupported byron tx input encoding {}!", in.at(0).uint());
                cbor_value in_data;
                _parse_cbor_tag(in_data, in.at(1).tag());
                observer(tx_input { in_data.array().at(0).buf(), in_data.array().at(1).uint(), i });
            }
        }

        void foreach_output(const std::function<void(const tx_output &)> &observer) const override
        {
            const auto &outputs = _tx.array().at(1).array();
            for (size_t i = 0; i < outputs.size(); i++) {
                const auto &out = outputs.at(i).array();
                observer(tx_output { out.at(0).array().at(0).tag().second->buf(), cardano::amount { out.at(1).uint() }, i });
            }
        }

        vkey_wit_cnt witness_count() const override
        {
            if (!_wit)
                throw cardano_error("vkey_witness_ok called on a transaction without witness data!");
            return vkey_wit_cnt { _wit->array().size() };
        }

        vkey_wit_ok vkey_witness_ok() const override
        {
            if (!_wit) throw cardano_error("vkey_witness_ok called on a transaction without witness data!");
            vkey_wit_ok ok {};
            auto tx_hash = hash();
            for (const auto &w_raw: _wit->array()) {
                const auto &w_items = w_raw.array();
                auto w_type = w_items.at(0).uint();
                switch (w_type) {
                case 0:
                case 2: {
                    ok.total++;
                    cbor_value w_data;
                    _parse_cbor_tag(w_data, w_items.at(1).tag());
                    const auto &vkey = w_data.array().at(0).buf();
                    const auto &sig = w_data.array().at(1).buf();
                    array<uint8_t, 34> msg;
                    msg[0] = 0x82;
                    msg[1] = 0x01;
                    span_memcpy(std::span(msg.data() + 2, 32), tx_hash);
                    if (ed25519::verify(sig, vkey.subspan(0, 32), msg)) ok.ok++;
                    break;
                }

                default:
                    throw cardano_error("slot: {}, tx: {} - unsupported witness type: {}", (uint64_t)_blk.slot(), hash().span(), w_type);
                }
            }
            return ok;
        }
    private:
        void _parse_cbor_tag(cbor_value &val, const cbor_tag &tag) const
        {
            if (tag.first != 24)
                throw cardano_error("slot: {}, tx: {} - byron encoded cbor tag has a mark != 24: {}!", (uint64_t)_blk.slot(), hash().span(), tag.first);
            cbor_parser parser { tag.second->buf() };
            parser.read(val);
        }
    };

    inline void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        for (const auto &tx_raw: transactions()) {
            if (tx_raw.array().size() == 1) {
                observer(tx { tx_raw.array().at(0), *this });
            } else if (tx_raw.array().size() == 2) {
                observer(tx { tx_raw.array().at(0), *this, &tx_raw.array().at(1) });
            } else {
                throw cardano_error("unexpected number of transaction entries: {}", tx_raw.array().size());
            }
        }
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_BYRON_HPP