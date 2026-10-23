/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <atomic>
#include <turbo/common/test.hpp>
#include <turbo/cardano/ledger/state.hpp>
#include <turbo/cardano/common/block-producer.hpp>
#include <turbo/storage/test.hpp>
#include "validator.hpp"
#include "turbo/chunk-registry.hpp"

namespace {
    using namespace turbo;
}

suite txwit_validator_suite = [] {
    "txwit::validator"_test = [] {
        static const std::string src_dir { turbo::storage::sample_registry_path() };
        const chunk_registry cr { src_dir, chunk_registry_settings_t { .mode=chunk_registry::mode::store } };
        const cardano::optional_point target { cr.find_block_by_slot(7167).point() };
        expect_equal(txwit::validate(cr, {}, target), target);

        "direct and queued batches reject invalid signatures before ledger application"_test = [] {
            const auto seed = crypto::blake2b::digest<crypto::ed25519::seed>(std::string_view { "signature-worker" });
            const auto sk = crypto::ed25519::create_sk_from_seed(seed);
            const auto other_seed = crypto::blake2b::digest<crypto::ed25519::seed>(std::string_view { "wrong-key" });
            const auto wrong_vk = crypto::ed25519::extract_vk(crypto::ed25519::create_sk_from_seed(other_seed));
            for (const size_t num_chunks: { 1, 2 }) {
                const file::tmp_directory dir { "txwit-parallel-signatures" };
                storage::chunk_fixture_t fixture { dir.path() };
                cardano::block_producer block { sk, seed, cardano::vrf03_create_sk_from_seed(seed) };
                block.prev_hash = cardano::config::get().byron_genesis_hash;
                // The signature is made with sk but advertises another key.
                block.txs.push_back({ { { {}, 0, sk, wrong_vk } }, {} });
                size_t offset = 0;
                for (size_t i = 0; i < num_chunks; ++i) {
                    uint8_vector chunk_bytes;
                    for (size_t j = 0; j < 8; ++j) {
                        block.height = i * 8 + j;
                        block.slot = block.height * 2;
                        block.txs.front().inputs.front().txo_idx = cardano::tx_out_idx { block.height };
                        const auto bytes = block.cbor();
                        cbor::zero2::decoder dec { bytes };
                        const cardano::block_container parsed { offset + chunk_bytes.size(), dec.read() };
                        block.prev_hash = parsed->hash();
                        chunk_bytes << bytes;
                    }
                    expect(fatal(chunk_bytes.size() < (1U << 20)));
                    fixture.add(offset, chunk_bytes);
                    offset += chunk_bytes.size();
                }
                fixture.save();
                scheduler sched { 4 };
                const chunk_registry source { dir.path(), chunk_registry_settings_t {
                    .mode=chunk_registry::mode::store, .sched=sched
                } };
                storage::chunk_cptr_list chunks;
                for (const auto &[id, chunk]: source.chunks())
                    chunks.push_back(&chunk);
                cardano::ledger::state st { source.config(), sched };
                st.start_epoch(0);
                std::atomic_size_t signature_errors { 0 };
                txwit::processor proc { source, st, [&](const auto &message) {
                    if (message.find("shelley vkey witness failed") != std::string::npos)
                        ++signature_errors;
                    throw error(message);
                } };
                // One small chunk uses the direct path; two use compressed,
                // queued batches whose raw block views outlive preparation.
                expect(throws([&] { proc.apply(chunks); }));
                expect(signature_errors.load() > 0);
                expect_equal(st.end_offset(), 0);
                expect_equal(proc.end_offset(), 0);
                expect(!sched.process_ok(false));
            }
        };

        "epoch setup gates ledger application"_test = [&] {
            cardano::ledger::state st { cr.config(), cr.sched() };
            txwit::processor proc { cr, st };
            storage::chunk_cptr_list chunks;
            for (const auto &[id, chunk]: cr.chunks()) {
                if (chunk.offset >= target->end_offset)
                    break;
                chunks.push_back(&chunk);
            }
            size_t setup_calls = 0;
            proc.apply({}, {}, target, txwit::witness_type::all, [&] {
                ++setup_calls;
                return false;
            });
            expect_equal(setup_calls, 1);
            proc.apply(chunks, {}, target, txwit::witness_type::all, [&] {
                ++setup_calls;
                return false;
            });
            expect_equal(setup_calls, 2);
            expect_equal(st.end_offset(), 0);
            expect(throws([&] {
                proc.apply(chunks, {}, target, txwit::witness_type::all, [&]() -> bool {
                    throw error("epoch setup failed");
                });
            }));
            expect_equal(st.end_offset(), 0);
            proc.apply(chunks, {}, target, txwit::witness_type::all, [&] {
                ++setup_calls;
                expect_equal(st.end_offset(), 0);
                st.start_epoch(0);
                return true;
            });
            expect_equal(setup_calls, 3);
            expect_equal(proc.end_offset(), target->end_offset);
            expect_equal(st.end_offset(), target->end_offset);
        };
    };
};
