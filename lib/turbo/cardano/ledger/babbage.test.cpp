/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/cardano/ledger/babbage.hpp>
#include <turbo/common/test.hpp>

using namespace turbo;
using namespace cardano;
using namespace ledger;

suite cardano_ledger_babbage_vrf_state_suite = [] {
    "cardano::ledger::babbage::vrf_state"_test = [] {
        "max_epoch_slot"_test = [] {
            ledger::babbage::vrf_state st { ledger::shelley::vrf_state {} };
            expect_equal(432000 - 129600, st.max_epoch_slot());
        };
        "cbor load/save"_test = [] {
            ledger::babbage::vrf_state st { ledger::shelley::vrf_state {} };
            const auto exp_cbor = file::read(install_path("data/ledger/babbage-vrf-state.cbor"));
            st.from_cbor(cbor::zero2::parse(exp_cbor).get());
            cbor_encoder enc { []{ return era_encoder { era_t::babbage }; } };
            st.to_cbor(enc);
            enc.run(scheduler::get(), "vrf_state::to_cbor");
            const auto act_cbor = enc.flat();
            expect_equal(exp_cbor.size(), act_cbor.size());
            expect_equal(static_cast<buffer>(exp_cbor), act_cbor);
        };
        "Node 11 retains the previous epoch nonce across replay and reload"_test = [] {
            ledger::babbage::vrf_state st { ledger::shelley::vrf_state {} };
            const auto old_cbor = file::read(install_path("data/ledger/babbage-vrf-state.cbor"));
            st.from_cbor(cbor::zero2::parse(old_cbor).get());
            const auto encode = [](const auto &state, const node_format format) {
                cbor_encoder enc { [] { return era_encoder { era_t::babbage }; } };
                state.to_cbor(enc, format);
                enc.run(scheduler::get(), "encode-praos-header");
                return enc.flat();
            };
            expect(!st.nonce_previous_epoch());
            expect(throws([&] { encode(st, node_format::v11_1_3); }));
            expect_equal(encode(st, node_format::legacy), old_cbor);

            // Emulate an existing local snapshot with no appended nonce metadata.
            const file::tmp old_path { "praos-old-snapshot" };
            zpp_encoder old_enc {};
            old_enc.add([&](auto) { return turbo::zpp::serialize(st); });
            old_enc.run(scheduler::get(), "encode-old-praos");
            old_enc.save(old_path.path(), true);
            ledger::babbage::vrf_state replayed { ledger::shelley::vrf_state {} };
            parallel_decoder old_dec { old_path.path() };
            replayed.from_zpp(old_dec);
            old_dec.run(scheduler::get(), "decode-old-praos");
            expect(!replayed.nonce_previous_epoch());
            const auto previous = replayed.nonce_epoch();
            replayed.finish_epoch({});
            expect(replayed.nonce_previous_epoch() == std::optional<vrf_nonce> { previous });

            const auto modern = encode(replayed, node_format::v11_1_3);
            auto parsed = cbor::zero2::parse(modern);
            auto &header = parsed.get().at(1);
            expect_equal(header.special_uint(), 8);
            auto &fields = header.array();
            auto &last_slot = fields.read();
            expect_equal(last_slot.special_uint(), 2);
            auto &slot_fields = last_slot.array();
            expect_equal(slot_fields.read().uint(), 1);
            expect_equal(slot_fields.read().uint(), cbor::zero2::parse(old_cbor).get().at(1).at(0).at(1).uint());
            expect_equal(fields.skip(4).read().at(1).bytes(), buffer { previous });

            const file::tmp path { "praos-new-snapshot" };
            zpp_encoder enc {};
            replayed.to_zpp(enc);
            enc.run(scheduler::get(), "encode-new-praos");
            enc.save(path.path(), true);
            ledger::babbage::vrf_state restored { ledger::shelley::vrf_state {} };
            parallel_decoder dec { path.path() };
            restored.from_zpp(dec);
            dec.run(scheduler::get(), "decode-new-praos");
            expect_equal(encode(restored, node_format::v11_1_3), modern);
            restored.from_cbor(cbor::zero2::parse(modern).get());
            expect_equal(encode(restored, node_format::v11_1_3), modern);
            const auto next_previous = restored.nonce_epoch();
            restored.finish_epoch({});
            expect(restored.nonce_previous_epoch() == std::optional<vrf_nonce> { next_previous });
        };
    };
};
