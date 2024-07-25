/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/config.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::cardano;

suite cardano_config_suite = [] {
    "cardano::config"_test = [] {
        const cardano::config cfg {};
        "mainnet genesis hashes"_test = [&] {
            expect(cfg.byron_genesis_hash == block_hash::from_hex("5f20df933584822601f9e3f8c024eb5eb252fe8cefb24d1317dc3d432e940ebb"));
            expect(cfg.shelley_genesis_hash == block_hash::from_hex("1a3be38bcbb7911969283716ad7aa550250226b76a61fc51cc9a9a35d9276d81"));
            expect(cfg.alonzo_genesis_hash == block_hash::from_hex("7e94a15f55d1e82d10f09203fa1d40f8eede58fd8066542cf6566008068ed874"));
            expect(cfg.conway_genesis_hash == block_hash::from_hex("f28f1c1280ea0d32f8cd3143e268650d6c1a8e221522ce4a7d20d62fc09783e1"));
        };
        "mainnet utxo balances"_test = [&] {
            const auto &utxos = cfg.byron_utxos;
            test_same(14505, utxos.size());
            expect(utxos.contains(tx_out_ref { tx_hash::from_hex("000F09675EF28CD358039CDAD71CF1FBDB35BE5B80EED98E296B6DC8F0718D7D"), 0 }));
            expect(utxos.contains(tx_out_ref { tx_hash::from_hex("62F199A14F352004239E1F96302C15ABE38554D53E8F0088508AC9CDE9C10EC9"), 0 }));
            expect(utxos.contains(tx_out_ref { tx_hash::from_hex("8E624C6A36DC1C84B8CD85D12585EF0DA565FA7166CB5F41BE9C5F183B07F95A"), 0 }));
            expect(utxos.contains(tx_out_ref { tx_hash::from_hex("DCE0CA2A40603CC2395CD7E348FBBF91A9D5A83E54597D1095486A2307B4CAB2"), 0 }));
        };
        "plutus cost models"_test = [&] {
            expect(cfg.plutus_v1_cost_model.size() == 166);
        };
    };
};