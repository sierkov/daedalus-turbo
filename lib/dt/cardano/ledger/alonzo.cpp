/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/alonzo.hpp>
#include <dt/cardano/ledger/alonzo.hpp>

namespace daedalus_turbo::cardano::ledger::alonzo {
    vrf_state::vrf_state(shelley::vrf_state &&o): shelley::vrf_state { std::move(o) }
    {
        logger::debug("alonzo::vrf_state created max_epoch_slot: {}", _max_epoch_slot);
    }

    state::state(shelley::state &&o): shelley::state { std::move(o) }
    {
        _apply_alonzo_params(_params);
        _apply_alonzo_params(_params_prev);
    }

    param_update state::_parse_param_update(const cbor::value &proposal) const
    {
        param_update upd = cardano::alonzo::parse_alonzo_param_update(proposal, _cfg);
        upd.rehash();
        return upd;
    }

    void state::_params_to_cbor(cbor::encoder &enc, const protocol_params &params) const
    {
        enc.array(25);
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
        enc.rational(params.decentralization);
        if (!params.extra_entropy)
            enc.array(1).uint(0);
        else
            enc.array(2).uint(1).bytes(*params.extra_entropy);
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

    void state::_apply_alonzo_params(protocol_params &p) const
    {
        const auto &al_cfg = _cfg.alonzo_genesis;
        p.lovelace_per_utxo_byte = json::value_to<uint64_t>(al_cfg.at("lovelacePerUTxOWord"));
        p.ex_unit_prices = {
            al_cfg.at("executionPrices").at("prMem"),
            al_cfg.at("executionPrices").at("prSteps")
        };
        p.max_tx_ex_units = {
            json::value_to<uint64_t>(al_cfg.at("maxTxExUnits").at("exUnitsMem")),
            json::value_to<uint64_t>(al_cfg.at("maxTxExUnits").at("exUnitsSteps"))
        };
        p.max_block_ex_units = {
            json::value_to<uint64_t>(al_cfg.at("maxBlockExUnits").at("exUnitsMem")),
            json::value_to<uint64_t>(al_cfg.at("maxBlockExUnits").at("exUnitsSteps"))
        };
        p.max_value_size = json::value_to<uint64_t>(al_cfg.at("maxValueSize"));
        p.max_collateral_pct = json::value_to<uint64_t>(al_cfg.at("collateralPercentage"));
        p.max_collateral_inputs = json::value_to<uint64_t>(al_cfg.at("maxCollateralInputs"));
        p.plutus_cost_models.v1.emplace(plutus_cost_model::from_json(_cfg.plutus_all_cost_models.v1.value(), al_cfg.at("costModels").at("PlutusV1")));
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
        params.decentralization = rational_u64 { val.at(12) };
        switch (val.at(13).at(0).uint()) {
            case 0: params.extra_entropy.reset(); break;
            case 1: params.extra_entropy.emplace(val.at(13).at(1).buf()); break;
            default: throw error("unexpected value for extra_entropy: {}", val.at(13));
        }
        params.protocol_ver.major = val.at(14).uint();
        params.protocol_ver.minor = val.at(15).uint();
        params.min_pool_cost = val.at(16).uint();
        params.lovelace_per_utxo_byte = val.at(17).uint();
        for (const auto &[model_id, values]: val.at(18).map()) {
            switch (model_id.uint()) {
                case 0:
                    params.plutus_cost_models.v1 = plutus_cost_model::from_cbor(_cfg.plutus_all_cost_models.v1.value(), values.array());
                    break;
                break;
                default:
                    throw error("unsupported cost model id: {}", model_id);
            }
        }
        params.ex_unit_prices = {
            rational_u64 { val.at(19).at(0) },
            rational_u64 { val.at(19).at(1) }
        };
        params.max_tx_ex_units = {
            val.at(20).at(0).uint(),
            val.at(20).at(1).uint()
        };
        params.max_block_ex_units = {
            val.at(21).at(0).uint(),
            val.at(21).at(1).uint()
        };
        params.max_value_size = val.at(22).uint();
        params.max_collateral_pct = val.at(23).uint();
        params.max_collateral_inputs = val.at(24).uint();
    }

    void state::_param_update_to_cbor(cbor::encoder &enc, const param_update &upd) const
    {
        cbor::encoder my_enc {};
        size_t cnt = _param_update_common_to_cbor(my_enc, upd);
        cnt += _param_to_cbor(enc, 16, upd.min_pool_cost);
        cnt += _param_to_cbor(enc, 17, upd.lovelace_per_utxo_byte);
        if (upd.plutus_cost_models) {
            ++cnt;
            enc.uint(18);
            upd.plutus_cost_models->to_cbor(enc);
        }
        if (upd.ex_unit_prices) {
            ++cnt;
            enc.uint(19);
            enc.array(2).rational(upd.ex_unit_prices->mem).rational(upd.ex_unit_prices->steps);
        }
        if (upd.max_tx_ex_units) {
            ++cnt;
            enc.uint(20);
            enc.array(2).uint(upd.max_tx_ex_units->mem).uint(upd.max_tx_ex_units->steps);
        }
        if (upd.max_block_ex_units) {
            ++cnt;
            enc.uint(21);
            enc.array(2).uint(upd.max_block_ex_units->mem).uint(upd.max_block_ex_units->steps);
        }
        cnt += _param_to_cbor(enc, 22, upd.max_value_size);
        cnt += _param_to_cbor(enc, 23, upd.max_collateral_pct);
        cnt += _param_to_cbor(enc, 24, upd.max_collateral_inputs);
        enc.map(cnt);
        enc << my_enc;
    }
}