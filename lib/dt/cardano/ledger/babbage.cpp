/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/ledger/babbage.hpp>

namespace daedalus_turbo::cardano::ledger::babbage {
    vrf_state::vrf_state(alonzo::vrf_state &&o): alonzo::vrf_state { std::move(o) }
    {
        logger::debug("babbage::vrf_state created max_epoch_slot: {}", _max_epoch_slot);
    }

    void vrf_state::from_cbor(const cbor::value &v)
    {
        const auto &raw = v.at(1);
        _slot_last = raw.at(0).at(1).uint();
        _kes_counters.clear();
        for (const auto &[pool_id, ctr]: raw.at(1).map()) {
            const auto [it, created] = _kes_counters.try_emplace(pool_id.buf(), ctr.uint());
            if (!created) [[unlikely]]
                throw error("duplicate kes counter reported for pool: {}", pool_id);
        }
        _nonce_evolving = raw.at(2).at(1).buf();
        _nonce_candidate = raw.at(3).at(1).buf();
        _nonce_epoch = raw.at(4).at(1).buf();
        _lab_prev_hash = raw.at(5).at(1).buf();
        _prev_epoch_lab_prev_hash.reset();
        if (raw.at(6).at(0).uint() == 1)
            _prev_epoch_lab_prev_hash = raw.at(6).at(1).buf();
    }

    void vrf_state::to_cbor(parallel_serializer &ser) const
    {
        ser.add([&] {
            cbor::encoder enc {};
            enc.array(2)
                .uint(0)
                .array(7)
                    .array(2)
                        .uint(1)
                        .uint(_slot_last)
                    .custom([this] (auto &enc) {
                        enc.map(_kes_counters.size());
                        for (const auto &[pool_id, cnt]: _kes_counters) {
                            enc.bytes(pool_id);
                            enc.uint(cnt);
                        }
                    })
                    .array(2)
                        .uint(1)
                        .bytes(_nonce_evolving)
                    .array(2)
                        .uint(1)
                        .bytes(_nonce_candidate)
                    .array(2)
                        .uint(1)
                        .bytes(_nonce_epoch)
                    .array(2)
                        .uint(1)
                        .bytes(_lab_prev_hash)
                    .custom([this](auto &enc) {
                        if (_prev_epoch_lab_prev_hash) {
                            enc.array(2)
                                .uint(1)
                                .bytes(*_prev_epoch_lab_prev_hash);
                        } else {
                            enc.array(1).uint(0);
                        }
                    });
            return enc.cbor();
        });
    }

    state::state(alonzo::state &&o): alonzo::state { std::move(o) }
    {
        _apply_babbage_params(_params);
        _apply_babbage_params(_params_prev);
    }

    void state::_apply_babbage_params(protocol_params &p) const
    {
        p.decentralization = rational_u64 { 0, 1 };
        p.lovelace_per_utxo_byte = 4310;
    }

    void state::_apply_param_update(const param_update &update)
    {
        std::string update_desc {};
        _apply_one_param_update(_params.protocol_ver, update_desc, update.protocol_ver, "protocol_ver");
        _apply_one_param_update(_params.min_fee_a, update_desc, update.min_fee_a, "min_fee_a");
        _apply_one_param_update(_params.min_fee_b, update_desc, update.min_fee_b, "min_fee_b");
        _apply_one_param_update(_params.max_block_body_size, update_desc, update.max_block_body_size, "max_block_body_size");
        _apply_one_param_update(_params.max_transaction_size, update_desc, update.max_transaction_size, "max_transaction_size");
        _apply_one_param_update(_params.max_block_header_size, update_desc, update.max_block_header_size, "max_block_header_size");
        _apply_one_param_update(_params.key_deposit, update_desc, update.key_deposit, "key_deposit");
        _apply_one_param_update(_params.pool_deposit, update_desc, update.pool_deposit, "pool_deposit");
        _apply_one_param_update(_params.e_max, update_desc, update.e_max, "e_max");
        _apply_one_param_update(_params.n_opt, update_desc, update.n_opt, "n_opt");
        _apply_one_param_update(_params.pool_pledge_influence, update_desc, update.pool_pledge_influence, "pool_pledge_influence");
        _apply_one_param_update(_params.expansion_rate, update_desc, update.expansion_rate, "expansion_rate");
        _apply_one_param_update(_params.treasury_growth_rate, update_desc, update.treasury_growth_rate, "treasury_growth_rate");
        _apply_one_param_update(_params.decentralization, update_desc, update.decentralization, "decentralization");
        _apply_one_param_update(_params.extra_entropy, update_desc, update.extra_entropy, "extra_entropy");
        _apply_one_param_update(_params.min_utxo_value, update_desc, update.min_utxo_value, "min_utxo_value");
        _apply_one_param_update(_params.min_pool_cost, update_desc, update.min_pool_cost, "min_pool_cost");
        _apply_one_param_update(_params.lovelace_per_utxo_byte, update_desc, update.lovelace_per_utxo_byte, "lovelace_per_utxo_byte");
        _apply_one_param_update(_params.ex_unit_prices, update_desc, update.ex_unit_prices, "ex_unit_prices");
        _apply_one_param_update(_params.max_tx_ex_units, update_desc, update.max_tx_ex_units, "max_tx_ex_units");
        _apply_one_param_update(_params.max_block_ex_units, update_desc, update.max_block_ex_units, "max_block_ex_units");
        _apply_one_param_update(_params.max_value_size, update_desc, update.max_value_size, "max_value_size");
        _apply_one_param_update(_params.max_collateral_pct, update_desc, update.max_collateral_pct, "max_collateral_pct");
        _apply_one_param_update(_params.max_collateral_inputs, update_desc, update.max_collateral_inputs, "max_collateral_inputs");
        _apply_one_param_update(_params.plutus_cost_models, update_desc, update.plutus_cost_models, "plutus_cost_models");
        logger::info("epoch: {} protocol params update: [ {}]", _epoch, update_desc);
    }

    void state::_parse_protocol_params(protocol_params &params, const cbor_value &val) const
    {
        _apply_shelley_params(params);
        _apply_alonzo_params(params);
        _apply_babbage_params(params);
        params.min_fee_a = val.at(0).uint();
        params.min_fee_b = val.at(1).uint();
        params.max_block_body_size = val.at(2).uint();
        params.max_transaction_size = val.at(3).uint();
        params.max_block_header_size = val.at(4).uint();
        params.key_deposit = val.at(5).uint();
        params.pool_deposit = val.at(6).uint();
        params.e_max = val.at(7).uint();
        params.n_opt = val.at(8).uint();
        params.pool_pledge_influence = rational_u64 { val.at(9) };
        params.expansion_rate = rational_u64 { val.at(10) };
        params.treasury_growth_rate = rational_u64 { val.at(11) };
        params.protocol_ver.major = val.at(12).uint();
        params.protocol_ver.minor = val.at(13).uint();
        params.min_pool_cost = val.at(14).uint();
        params.lovelace_per_utxo_byte = val.at(15).uint();
        for (const auto &[model_id, values]: val.at(16).map()) {
            switch (model_id.uint()) {
                case 0:
                    params.plutus_cost_models.v1 = cardano::plutus_cost_model::from_cbor(_cfg.plutus_all_cost_models.v1.value(), values.array());
                break;
                case 1:
                    params.plutus_cost_models.v2 = cardano::plutus_cost_model::from_cbor(_cfg.plutus_all_cost_models.v1.value(), values.array());
                break;
                default:
                    throw error("unsupported cost model id: {}", model_id);
            }
        }
        params.ex_unit_prices = {
            rational_u64 { val.at(17).at(0) },
            rational_u64 { val.at(17).at(1) }
        };
        params.max_tx_ex_units = {
            val.at(18).at(0).uint(),
            val.at(18).at(1).uint()
        };
        params.max_block_ex_units = {
            val.at(19).at(0).uint(),
            val.at(19).at(1).uint()
        };
        params.max_value_size = val.at(20).uint();
        params.max_collateral_pct = val.at(21).uint();
        params.max_collateral_inputs = val.at(22).uint();
    }

    void state::_params_to_cbor(cbor::encoder &enc, const protocol_params &params) const
    {
        enc.array(23);
        enc.uint(params.min_fee_a);
        enc.uint(params.min_fee_b);
        enc.uint(params.max_block_body_size);
        enc.uint(params.max_transaction_size);
        enc.uint(params.max_block_header_size);
        enc.uint(params.key_deposit);
        enc.uint(params.pool_deposit);
        enc.uint(params.e_max);
        enc.uint(params.n_opt);
        enc.rational(params.pool_pledge_influence);
        enc.rational(params.expansion_rate);
        enc.rational(params.treasury_growth_rate);
        enc.uint(params.protocol_ver.major);
        enc.uint(params.protocol_ver.minor);
        enc.uint(params.min_pool_cost);
        enc.uint(params.lovelace_per_utxo_byte);
        params.plutus_cost_models.to_cbor(enc);
        enc.array(2)
            .rational(params.ex_unit_prices.mem)
            .rational(params.ex_unit_prices.steps);
        enc.array(2).uint(params.max_tx_ex_units.mem).uint(params.max_tx_ex_units.steps);
        enc.array(2).uint(params.max_block_ex_units.mem).uint(params.max_block_ex_units.steps);
        enc.uint(params.max_value_size);
        enc.uint(params.max_collateral_pct);
        enc.uint(params.max_collateral_inputs);
    }
}
