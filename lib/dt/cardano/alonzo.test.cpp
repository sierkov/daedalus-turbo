/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/history.hpp>
#include <dt/file.hpp>
#include <dt/storage/chunk_info.hpp>
#include <dt/test.hpp>
#include <dt/zpp.hpp>

using namespace daedalus_turbo;

suite cardano_alonzo_suite = [] {
    "cardano::alonzo"_test = [] {
        configs_dir cfg { configs_dir::default_path() };
        cardano::config ccfg { cfg };
        ccfg.shelley_start_slot(208 * ccfg.byron_epoch_length);
        "validate plutus v1"_test = [&] {
            // a95d16e891e51f98a3b1d3fe862ed355ebc8abffb7a7269d86f775553d9e653f
            for (const char *tx_hex: { "C8EE18A7965CC8BEA4986F7F2573CF094BE20F4E58137EC46356BB73BBC6774F" }) {
                const auto tx_data = file::read(fmt::format("./data/alonzo/tx-{}.bin", tx_hex));
                const auto tx_wit_data = file::read(fmt::format("./data/alonzo/tx-{}-wit.bin", tx_hex));
                const auto block_info = daedalus_turbo::zpp::load<storage::block_info>(fmt::format("./data/alonzo/tx-{}-block.bin", tx_hex));
                const auto input_data = daedalus_turbo::zpp::load<cardano::tx_out_data_list>(fmt::format("./data/alonzo/tx-{}-inputs.bin", tx_hex));
                const auto tx_raw = cbor::parse(tx_data);
                const auto tx_wit_raw = cbor::parse(tx_wit_data);
                history_mock_block block { block_info, tx_raw, block_info.offset, ccfg };
                const auto tx = make_tx(tx_raw, block, &tx_wit_raw);
                const auto wit_ok = tx->witnesses_ok(&input_data);
                expect(!!wit_ok);
                expect(wit_ok.script_total > 0) << wit_ok.script_total;
            }
        };
        "body_hash_ok"_test = [] {
            for (const auto &chunk_hash: { "1A6CC809A5297CFC502B229B4CD31A9B00B71638CEAEDE45409D4F0EBC534356",
                                                          "471C013F34D419FFA96A8FCD8E0D12EAC3DED4414982F5F055D2FD0AD52D035C" }) {
                const auto chunk = file::read(fmt::format("./data/chunk-registry/compressed/chunk/{}.zstd", chunk_hash));
                cbor_parser parser { chunk };
                cbor_value block_tuple {};
                while (!parser.eof()) {
                    parser.read(block_tuple);
                    const auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
                    expect(blk->era() == 5_ull);
                    expect(blk->body_hash_ok());
                }
            }
        };
    };
};