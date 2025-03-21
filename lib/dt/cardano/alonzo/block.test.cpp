/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/test.hpp>
#include <dt/cardano/alonzo/block.hpp>
#include <dt/plutus/context.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano;

suite cardano_alonzo_suite = [] {
    "cardano::alonzo"_test = [] {

        "parse block header"_test = [] {
            const auto data = file::read(install_path("data/alonzo/block-0.cbor"));
            auto block_tuple = cbor::zero2::parse(data);
            auto &it = block_tuple.get().array();
            const alonzo::block blk { it.read().uint(), 0, 2, it.read(), cardano::config::get() };
            test_same(block_hash::from_hex("F988EF7D3C1E32096AE3767F5B0C4AAC598FA17BE0F40FEA77FBCE44B85E8721"), blk.hash());
            test_same(block_hash::from_hex("D9CE7CAFF5B7A6178AEB7F2A240480AD67BE572805087BBFF6788E2B4BE576C1"), blk.prev_hash());
            test_same(44215215, blk.slot());
            test_same(5, blk.era());
            test_same(protocol_version { 6, 0 }, blk.protocol_ver());
            expect(blk.body_hash_ok());
            expect(blk.signature_ok());
        };

        "invalid transactions"_test = [] {
            const auto data = file::read(install_path("data/alonzo/block-1.cbor"));
            auto block_tuple = cbor::zero2::parse(data);
            auto &it = block_tuple.get().array();
            const alonzo::block blk { it.read().uint(), 0, 2, it.read(), cardano::config::get() };
            test_same(block_hash::from_hex("FAAEDA2A014E0AD176E06837978C2F663AB0FAB5F5874B079B886398099B97BE"), blk.hash());
            test_same(block_hash::from_hex("1ED872535807D009468CFDB8A165875A9D27F049AF4BCC0E4A036E8D12B82B37"), blk.prev_hash());
            test_same(49503576, blk.slot());
            test_same(5, blk.era());
            test_same(protocol_version { 6, 0 }, blk.protocol_ver());
            expect(blk.body_hash_ok());
            expect(blk.signature_ok());
            // check that txs reports all transactions including invalid
            test_same(70, blk.txs().size());
            expect(blk.txs().at(3)->invalid());
            test_same(1, blk.invalid_txs().size());
            // check that foreach_tx does not report invalid transactions
            {
                size_t num_invalid = 0;
                blk.foreach_tx([&](const auto &tx) {
                    if (tx.invalid())
                        ++num_invalid;
                });
                test_same(0, num_invalid);
            }
            // check that foreach_invalid_tx reports invalid transactions
            {
                size_t num_invalid = 0;
                blk.foreach_invalid_tx([&](const auto &) {
                    ++num_invalid;
                });
                test_same(1, num_invalid);
            }
        };

        "validate plutus"_test = [&] {
            const configs_dir cfg { configs_dir::default_path() };
            const cardano::config ccfg { cfg };
            ccfg.shelley_start_epoch(208);
            for (const auto &path: file::files_with_ext_str(install_path("data/alonzo"), ".zpp")) {
                try {
                    const plutus::context ctx { path, ccfg };
                    expect(ctx.tx().witnesses_ok(&ctx)) << path;
                } catch (const error &err) {
                    expect(false) << fmt::format("validation of tx witnesses for tx {} failed with: {}", path, err.what());
                }
            }
        };

        "body_hash_ok"_test = [] {
            for (const auto &chunk_hash: { "1A6CC809A5297CFC502B229B4CD31A9B00B71638CEAEDE45409D4F0EBC534356",
                                                          "471C013F34D419FFA96A8FCD8E0D12EAC3DED4414982F5F055D2FD0AD52D035C" }) {
                const auto chunk = zstd::read(fmt::format("./data/chunk-registry/compressed/chunk/{}.zstd", chunk_hash));
                cbor::zero2::decoder dec { chunk };
                while (!dec.done()) {
                    auto &block_tuple = dec.read();
                    auto &it = block_tuple.array();
                    const alonzo::block blk { it.read().uint(), 0, 2, it.read(), cardano::config::get() };
                    test_same(5, blk.era());
                    expect(blk.body_hash_ok());
                    expect(blk.signature_ok());
                }
            }
        };
    };
};