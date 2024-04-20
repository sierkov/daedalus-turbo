/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_BLOCK_PRODUCER_HPP
#define DAEDALUS_TURBO_CARDANO_BLOCK_PRODUCER_HPP

#include <dt/cardano/common.hpp>
#include <dt/cardano/shelley.hpp>
#include <dt/cbor-encoder.hpp>
#include <dt/kes.hpp>
#include <dt/vrf.hpp>

namespace daedalus_turbo::cardano {
    struct block_producer {
        uint64_t height {};
        cardano::slot slot {};
        block_hash prev_hash {};
        uint64_t op_seq_no {};
        cardano::vrf_nonce vrf_nonce = cardano::vrf_nonce::from_hex("1a3be38bcbb7911969283716ad7aa550250226b76a61fc51cc9a9a35d9276d81");

        explicit block_producer(const write_buffer &cold_key, const write_buffer &kes_seed, const buffer &vrf_sk)
            : _cold_sk { cold_key }, _kes_sk { kes_seed }, _vrf_sk { vrf_sk }
        {
            ed25519::extract_vk(_cold_vk, _cold_sk);
            vrf03_extract_vk(_vrf_vk, _vrf_sk);
        }

        uint8_vector cbor()
        {
            const auto txs = _gen_transactions();
            const auto wits = _gen_witnesses();
            const auto data = _gen_data();
            const auto inval = _gen_invalid();
            cbor::encoder enc {};
            enc.array(2);
            enc.uint(6);
            enc.array(5);
            _gen_header(enc, txs, wits, data, inval);
            enc.cbor() << txs << wits << data << inval;
            return enc.cbor();
        }
    private:
        ed25519::skey _cold_sk;
        ed25519::vkey _cold_vk;
        kes::secret<6> _kes_sk;
        vrf_skey _vrf_sk;
        vrf_vkey _vrf_vk;

        void _gen_op_cert(cbor::encoder &enc) const
        {
            const auto &op_vkey = _kes_sk.vkey();
            std::array<uint8_t, sizeof(cardano_vkey) + 2 * sizeof(uint64_t)> ocert_data {};
            memcpy(ocert_data.data(), op_vkey.data(), op_vkey.size());
            const auto ctr = host_to_net<uint64_t>(op_seq_no);
            memcpy(ocert_data.data() + op_vkey.size(), &ctr, sizeof(uint64_t));
            const auto kp = host_to_net<uint64_t>(op_seq_no);
            memcpy(ocert_data.data() + op_vkey.size() + sizeof(uint64_t), &kp, sizeof(uint64_t));
            ed25519::signature op_signature {};
            ed25519::sign(op_signature, ocert_data, _cold_sk);
            const auto op_period = static_cast<uint64_t>(slot) / cardano::shelley::kes_period_slots;
            enc.array(4);
            enc.bytes(op_vkey);
            enc.uint(op_seq_no);
            enc.uint(op_period);
            enc.bytes(op_signature);
        }

        void _gen_protocol_ver(cbor::encoder &enc) const
        {
            enc.array(2);
            enc.uint(8);
            enc.uint(0);
        }

        void _gen_body_hash(cbor::encoder &enc, const buffer &txs, const buffer &wits, const buffer &data, const buffer &inval) const
        {
            std::array<block_hash, 4> hashes {};
            blake2b(hashes[0], txs);
            blake2b(hashes[1], wits);
            blake2b(hashes[2], data);
            blake2b(hashes[3], inval);
            enc.bytes(blake2b<block_hash>(buffer { reinterpret_cast<uint8_t*>(hashes.data()), hashes.size() * sizeof(hashes[0]) }));
        }

        void _gen_vrf_result(cbor::encoder &enc) const
        {
            const auto input = vrf_make_input(slot, vrf_nonce);
            vrf_result res {};
            vrf_proof proof {};
            vrf03_prove(proof, res, _vrf_sk, input);
            enc.array(2);
            enc.bytes(res);
            enc.bytes(proof);
        }

        void _gen_header_body(cbor::encoder &enc, const buffer &txs, const buffer &wits, const buffer &data, const buffer &inval) const
        {
            enc.array(10);
            enc.uint(height);
            enc.uint(slot);
            enc.bytes(prev_hash);
            enc.bytes(_cold_vk);
            enc.bytes(_vrf_vk);
            _gen_vrf_result(enc);
            enc.uint(txs.size() + wits.size() + data.size() + inval.size());
            _gen_body_hash(enc, txs, wits, data, inval);
            _gen_op_cert(enc);
            _gen_protocol_ver(enc);
        }

        void _gen_kes_signature(cbor::encoder &enc, const buffer &header_body_cbor) const
        {
            cardano_kes_signature_data sigma {};
            _kes_sk.sign(sigma, header_body_cbor);
            enc.bytes(sigma);
        }

        void _gen_header(cbor::encoder &enc, const buffer &txs, const buffer &wits, const buffer &data, const buffer &inval) const
        {
            enc.array(2);
            cbor::encoder hb_enc {};
            _gen_header_body(hb_enc, txs, wits, data, inval);
            enc << hb_enc;
            _gen_kes_signature(enc, hb_enc.cbor());
        }

        uint8_vector _gen_transactions() const
        {
            cbor::encoder enc {};
            enc.array(0);
            return enc.cbor();
        }

        uint8_vector _gen_witnesses() const
        {
            cbor::encoder enc {};
            enc.array(0);
            return enc.cbor();
        }

        uint8_vector _gen_data() const
        {
            cbor::encoder enc {};
            enc.map(0);
            return enc.cbor();
        }

        uint8_vector _gen_invalid() const
        {
            cbor::encoder enc {};
            enc.array(0);
            return enc.cbor();
        }
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_BLOCK_PRODUCER_HPP