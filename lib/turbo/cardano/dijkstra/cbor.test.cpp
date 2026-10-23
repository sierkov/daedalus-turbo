/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/dijkstra/block.hpp>
#include <turbo/cbor/normalize.hpp>
#include <turbo/common/test.hpp>

namespace {
    using namespace turbo;
    using namespace cardano;

    template<typename T>
    T decode(const buffer bytes) {
        cbor::zero2::decoder dec { bytes, cbor::zero2::decoder::create_chunk_storage() };
        auto value = T::from_cbor(dec.read());
        expect(dec.done());
        return value;
    }

    template<typename T>
    void check_preserved(const std::string_view hex) {
        const auto bytes = uint8_vector::from_hex(hex);
        const auto value = decode<T>(bytes);
        // Both the decoder and its concatenated chunk storage have been destroyed.
        expect(value.original_cbor().data() == bytes.data());
        era_encoder enc { era_t::dijkstra };
        value.to_cbor(enc);
        expect_equal(enc.cbor(), bytes);
    }
}

suite cardano_dijkstra_cbor_suite = [] {
    "cardano::dijkstra::cbor"_test = [] {
        const auto native = "9F005F581C" + std::string(56, '0') + "FFFF";
        const std::string data = "5F41004101FF";
        const std::string redeemers = "BF820000829F00FF820102FF";
        const auto witnesses = "BF0181" + native + "0481" + data + "05" + redeemers + "FF";
        const std::string auxiliary = "BF0000FF";
        const std::string sub_body = "BF00800180FF";
        const auto sub_tx = "83" + sub_body + witnesses + auxiliary;
        const auto body = "BF008001800218001781" + sub_tx + "FF";
        const auto transaction = "83" + body + witnesses + auxiliary;

        "validated wire values borrow their original bytes"_test = [&] {
            check_preserved<decoded_cbor_t<dijkstra::native_script_t>>(native);
            check_preserved<decoded_cbor_t<dijkstra::native_script_t>>(
                "9F068201581C" + std::string(56, '0') + "FF");
            check_preserved<dijkstra::plutus_data_t>(data);
            check_preserved<decoded_cbor_t<dijkstra::auxiliary_data_t>>(auxiliary);
            check_preserved<decoded_cbor_t<dijkstra::redeemers_t>>(redeemers);
            check_preserved<decoded_cbor_t<dijkstra::transaction_witness_set_t>>(witnesses);
            check_preserved<decoded_cbor_t<dijkstra::transaction_body_t>>(body);
            check_preserved<decoded_cbor_t<dijkstra::sub_transaction_body_t>>(sub_body);
            expect(throws([] {
                const auto invalid = uint8_vector::from_hex("A0");
                decode<decoded_cbor_t<dijkstra::transaction_body_t>>(invalid);
            }));
        };

        "transactions preserve nested components while rebuilding their envelope"_test = [&] {
            const auto bytes = uint8_vector::from_hex("84" + body + witnesses + "F5" + auxiliary);
            const auto tx = decode<dijkstra::transaction_t>(bytes);
            era_encoder enc { era_t::dijkstra };
            tx.to_cbor(enc);
            expect_equal(enc.cbor(), uint8_vector::from_hex(transaction));
            expect(tx.body.original_cbor().data() == bytes.data() + 1);
            expect_equal(tx.body.value().sub_transactions.size(), 1);

            // Editing a semantic copy still preserves its decoded sub-transactions.
            auto edited_body = tx.body.value();
            edited_body.fee = 1;
            era_encoder edited { era_t::dijkstra };
            edited_body.to_cbor(edited);
            const auto result = decode<dijkstra::transaction_body_t>(edited.cbor());
            expect_equal(result.fee, 1);
            era_encoder nested { era_t::dijkstra };
            result.sub_transactions.at(0).to_cbor(nested);
            expect_equal(nested.cbor(), uint8_vector::from_hex(sub_tx));

            const auto sub_bytes = uint8_vector::from_hex(sub_body);
            const auto decoded_sub = decode<decoded_cbor_t<dijkstra::sub_transaction_body_t>>(sub_bytes);
            era_encoder sub_enc { era_t::dijkstra };
            decoded_sub.to_cbor(sub_enc);
            // The corpus compares this rule after normalization, unlike transaction_body.
            expect_equal(cbor::normalize(sub_enc.cbor()), uint8_vector::from_hex("A200800180"));
            expect(throws([&] {
                const auto invalid = uint8_vector::from_hex("84" + body + witnesses + "F4" + auxiliary);
                decode<dijkstra::transaction_t>(invalid);
            }));
        };

        "semantic encoders retain validated payloads without reparsing"_test = [&] {
            const auto script = [&] {
                const auto bytes = uint8_vector::from_hex("9F00" + native + "FF");
                return decode<dijkstra::script_t>(bytes);
            }();
            era_encoder script_enc { era_t::dijkstra };
            script.to_cbor(script_enc);
            expect_equal(script_enc.cbor(), uint8_vector::from_hex("8200" + native));

            const auto wits = [&] {
                const auto bytes = uint8_vector::from_hex(witnesses);
                return decode<dijkstra::transaction_witness_set_t>(bytes);
            }();
            era_encoder wits_enc { era_t::dijkstra };
            wits.to_cbor(wits_enc);
            expect_equal(wits_enc.cbor(), uint8_vector::from_hex(
                "A301D9010281" + native + "04D9010281" + data + "05A1820000829F00FF820102"));

            const auto aux_bytes = uint8_vector::from_hex("D90103A10181" + native);
            const auto aux = decode<dijkstra::auxiliary_data_t>(aux_bytes);
            era_encoder aux_enc { era_t::dijkstra };
            aux.to_cbor(aux_enc);
            expect_equal(aux_enc.cbor(), aux_bytes);

            // The embedded decoder must support chunked key bytes. The output owns
            // its script after both the source and the decoder's storage are gone.
            const auto reference = uint8_vector::from_hex("8200" + native);
            era_encoder output_enc { era_t::dijkstra };
            output_enc.map(3).uint(0).bytes(uint8_vector::from_hex("60" + std::string(56, '0')))
                .uint(1).uint(0).uint(3).tag(24).bytes(reference);
            const auto output = [&] {
                const auto bytes = output_enc.cbor();
                return decode<dijkstra::transaction_output_t>(bytes);
            }();
            era_encoder encoded { era_t::dijkstra };
            output.to_cbor(encoded);
            expect_equal(encoded.cbor(), output_enc.cbor());

            const auto guarded_bytes = uint8_vector::from_hex(
                "A400D9010280018002001818A18200581C" + std::string(56, '0') + data);
            const auto guarded = decode<dijkstra::transaction_body_t>(guarded_bytes);
            era_encoder guarded_enc { era_t::dijkstra };
            guarded.to_cbor(guarded_enc);
            expect_equal(guarded_enc.cbor(), guarded_bytes);
        };

        "standalone block body preserves bytes while the block rebuilds its fields"_test = [&] {
            cbor::encoder header_enc {};
            header_enc.array().array(12).uint(0).uint(0).s_null().bytes(vkey {}).bytes(vrf_vkey {})
                .array(2).bytes(vrf_result {}).bytes(vrf_proof {}).uint(0).bytes(block_hash {})
                .array(4).bytes(kes_vkey {}).uint(0).uint(0).bytes(signature {})
                .array(2).uint(13).uint(0).s_false().s_null()
                .bytes(cardano_kes_signature_data {}).s_break();
            const auto tx_bytes = uint8_vector::from_hex(transaction);
            cbor::encoder body_enc {};
            body_enc.array().array().uint(1).uint(0).s_break()
                .array(2).raw_cbor(tx_bytes).raw_cbor(tx_bytes).s_null().s_null().s_break();
            era_encoder input { era_t::dijkstra };
            input.array(2).raw_cbor(header_enc.cbor()).raw_cbor(body_enc.cbor());
            cbor::zero2::decoder dec { input.cbor(), cbor::zero2::decoder::create_chunk_storage() };
            const dijkstra::block block { 8, 0, 0, dec.read(), cardano::config::get() };
            expect(dec.done());
            era_encoder encoded_body { era_t::dijkstra };
            block.body_to_cbor(encoded_body);
            expect_equal(encoded_body.cbor(), body_enc.cbor());
            era_encoder encoded { era_t::dijkstra };
            block.to_cbor(encoded);
            era_encoder expected { era_t::dijkstra };
            expected.array(2).raw_cbor(header_enc.cbor()).array(4).tag(258).array(2).uint(0).uint(1)
                .array(2).raw_cbor(tx_bytes).raw_cbor(tx_bytes).s_null().s_null();
            expect_equal(encoded.cbor(), expected.cbor());
        };
    };
};
