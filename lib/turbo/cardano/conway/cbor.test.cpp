/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/conway/block.hpp>
#include <turbo/common/test.hpp>

namespace {
    using namespace turbo;
    using namespace cardano;

    static_assert(!std::is_default_constructible_v<decoded_cbor_t<conway::transaction_body_t>>);
    static_assert(!std::is_constructible_v<decoded_cbor_t<conway::transaction_body_t>, conway::transaction_body_t>);

    template<typename T>
    void check_borrowed_roundtrip(const std::string_view hex)
    {
        const auto bytes = uint8_vector::from_hex(hex);
        const auto decoded = [&] {
            auto parsed = cbor::zero2::parse(bytes);
            return T::from_cbor(parsed.get());
        }();
        // The decoder is gone, but the input remains alive. Copies borrow it too.
        const auto copy = decoded;
        expect(copy.original_cbor().data() == bytes.data());
        expect_equal(copy.original_cbor().size(), bytes.size());
        era_encoder enc { era_t::conway };
        copy.to_cbor(enc);
        expect_equal(enc.cbor(), bytes);
    }

    constexpr auto body_hex = "BF00800180021800FF";
    constexpr auto witness_hex = "BF01819F041801FF04819F00FF05818400009F00FF820102FF";
    constexpr auto auxiliary_hex = "BF0000FF";
}

suite cardano_conway_cbor_suite = [] {
    "cardano::conway::cbor"_test = [] {
        "memoized values borrow validated original bytes"_test = [] {
            check_borrowed_roundtrip<decoded_cbor_t<allegra::native_script_t>>("9F041801FF");
            check_borrowed_roundtrip<conway::plutus_data_t>("9F00FF");
            // Chunk headers remain in the original item; no concatenation is needed.
            check_borrowed_roundtrip<conway::plutus_data_t>("5F41004101FF");
            check_borrowed_roundtrip<decoded_cbor_t<conway::auxiliary_data_t>>(auxiliary_hex);
            check_borrowed_roundtrip<decoded_cbor_t<conway::redeemers_t>>("818400009F00FF820102");
            check_borrowed_roundtrip<decoded_cbor_t<conway::transaction_body_t>>(body_hex);
            check_borrowed_roundtrip<decoded_cbor_t<conway::transaction_witness_set_t>>(witness_hex);
            expect(throws([] {
                const auto bytes = uint8_vector::from_hex("A0");
                auto parsed = cbor::zero2::parse(bytes);
                decoded_cbor_t<conway::transaction_body_t>::from_cbor(parsed.get());
            }));
            expect(throws([] {
                const auto bytes = uint8_vector::from_hex("F5");
                auto parsed = cbor::zero2::parse(bytes);
                conway::plutus_data_t::from_cbor(parsed.get());
            }));
        };

        "transaction preserves children while semantic copies can be edited"_test = [] {
            const auto bytes = uint8_vector::from_hex(
                std::string { "84" } + body_hex + witness_hex + "F5" + auxiliary_hex);
            auto parsed = cbor::zero2::parse(bytes);
            const auto tx = conway::transaction_t::from_cbor(parsed.get());
            expect(tx.body.original_cbor().data() == bytes.data() + 1);
            era_encoder enc { era_t::conway };
            tx.to_cbor(enc);
            expect_equal(enc.cbor(), bytes);

            auto body = tx.body.value();
            body.fee = 1;
            era_encoder edited { era_t::conway };
            body.to_cbor(edited);
            auto reparsed = cbor::zero2::parse(edited.cbor());
            const auto result = conway::transaction_body_t::from_cbor(reparsed.get());
            expect_equal(result.fee, 1);
            expect_equal(tx.body.value().fee, 0);
            era_encoder original { era_t::conway };
            tx.to_cbor(original);
            expect_equal(original.cbor(), bytes);
        };

        "rebuilt wrappers retain owned script and datum payloads"_test = [] {
            // These payloads must also survive destruction of their input storage.
            const auto script = [] {
                const auto bytes = uint8_vector::from_hex("9F009F041801FFFF");
                auto parsed = cbor::zero2::parse(bytes);
                return conway::script_t::from_cbor(parsed.get());
            }();
            era_encoder script_enc { era_t::conway };
            script.to_cbor(script_enc);
            expect_equal(script_enc.cbor(), uint8_vector::from_hex("82009F041801FF"));

            const auto redeemer = [] {
                const auto bytes = uint8_vector::from_hex("9F00009F00FF820102FF");
                auto parsed = cbor::zero2::parse(bytes);
                return conway::redeemer_t::from_cbor(parsed.get());
            }();
            era_encoder redeemer_enc { era_t::conway };
            redeemer.to_cbor(redeemer_enc);
            expect_equal(redeemer_enc.cbor(), uint8_vector::from_hex("8400009F00FF820102"));

            const auto witnesses = [] {
                const auto bytes = uint8_vector::from_hex(witness_hex);
                auto parsed = cbor::zero2::parse(bytes);
                return conway::transaction_witness_set_t::from_cbor(parsed.get());
            }();
            era_encoder witnesses_enc { era_t::conway };
            witnesses.to_cbor(witnesses_enc);
            expect_equal(witnesses_enc.cbor(), uint8_vector::from_hex(
                "A301D90102819F041801FF04D90102819F00FF05A1820000829F00FF820102"));

            era_encoder output_enc { era_t::conway };
            const auto address = uint8_vector::from_hex("60" + std::string(56, '0'));
            output_enc.map(4).uint(0).bytes(address).uint(1).uint(1)
                .uint(2).array(2).uint(1).tag(24).bytes(uint8_vector::from_hex("9F00FF"))
                .uint(3).tag(24).bytes(script_enc.cbor());
            const auto output = [&] {
                const auto input = output_enc.cbor();
                auto parsed = cbor::zero2::parse(input);
                return conway::transaction_output_t::from_cbor(parsed.get());
            }();
            era_encoder encoded { era_t::conway };
            output.to_cbor(encoded);
            expect_equal(encoded.cbor(), output_enc.cbor());
        };

        "block preserves header and transaction components"_test = [] {
            const auto sample = file::read(install_path("data/conway/block-0.cbor"));
            auto parsed_sample = cbor::zero2::parse(sample);
            auto &tuple = parsed_sample.get().array();
            const auto era = tuple.read().uint();
            const auto header = tuple.read().array().read().data_raw();
            expect(fatal(header[0] == 0x82));
            // A legal nonminimal array header makes replay observable.
            cbor::encoder header_enc {};
            header_enc.raw_cbor(uint8_vector::from_hex("9802")).raw_cbor(header.subbuf(1));
            era_encoder input { era_t::conway };
            input.array(5).raw_cbor(header_enc.cbor())
                .array(1).raw_cbor(uint8_vector::from_hex(body_hex))
                .array(1).raw_cbor(uint8_vector::from_hex(witness_hex))
                .map(1).uint(0).raw_cbor(uint8_vector::from_hex(auxiliary_hex))
                .tag(258).array(0);
            auto parsed = cbor::zero2::parse(input.cbor());
            const conway::block block { era, 0, 0, parsed.get(), cardano::config::get() };
            era_encoder encoded { era_t::conway };
            block.to_cbor(encoded);
            expect_equal(encoded.cbor(), input.cbor());
        };
    };
};
