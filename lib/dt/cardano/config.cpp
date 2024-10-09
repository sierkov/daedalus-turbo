/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/base64.hpp>
#include <dt/cardano/config.hpp>

namespace daedalus_turbo::cardano {
    const config &config::get()
    {
        static config c { configs_dir::get() };
        return c;
    }

    shelley_delegate_map config::_shelley_prep_delegates(const daedalus_turbo::config &shelley_genesis)
    {
        shelley_delegate_map delegs {};
        for (const auto &[id, meta]: shelley_genesis.at("genDelegs").as_object()) {
            delegs[key_hash::from_hex(id)] = shelley_delegate {
                pool_hash::from_hex(meta.at("delegate").as_string()),
                vrf_vkey::from_hex(meta.at("vrf").as_string())
            };
        }
        return delegs;
    }

    txo_map config::_byron_prep_utxos(const daedalus_turbo::config &byron_genesis)
    {
        txo_map txos {};
        for (const auto &[redeem_key, lovelace]: byron_genesis.at("avvmDistr").as_object()) {
            const auto txo_addr = byron_avvm_addr(redeem_key);
            tx_out_ref txo_id { blake2b<tx_hash>(txo_addr), 0 };
            tx_out_data txo_data { std::stoull(json::value_to<std::string>(lovelace)), std::move(txo_addr) };
            if (const auto [it, created] = txos.try_emplace(txo_id, std::move(txo_data)); !created) [[unlikely]]
                throw error("duplicate TXO {} in the byron genesis config", txo_id);
        }
        return txos;
    }

    set<vkey> config::_byron_prep_issuers(const daedalus_turbo::config &genesis)
    {
        set<vkey> issuers {};
        for (const auto &[deleg_id, deleg_info]: genesis.at("heavyDelegation").as_object()) {
            issuers.emplace(base64::decode(json::value_to<std::string_view>(deleg_info.at("issuerPk"))).span().subbuf(0, 32));
        }
        return issuers;
    }

    block_hash config::_verify_hash_byron(const std::string_view &hash_hex, const daedalus_turbo::config &genesis)
    {
        const auto cfg_hash = block_hash::from_hex(hash_hex);
        const auto cfg_canon = json::serialize_canon(genesis.json());
        auto act_hash = blake2b<block_hash>(cfg_canon);
        if (act_hash != cfg_hash)
            throw error("The actual hash of ByronGenesisFile does not match ByronGenesisHash!");
        return act_hash;
    }

    block_hash config::_verify_hash(const std::string_view &hash_hex, const daedalus_turbo::config &genesis)
    {
        const auto cfg_hash = block_hash::from_hex(hash_hex);
        auto act_hash = blake2b<block_hash>(genesis.bytes());
        if (act_hash != cfg_hash)
            throw error("The actual hash of genesis file does not match {}!", hash_hex);
        return act_hash;
    }

    static plutus_cost_model _make_plutus_v1_default_cost_model()
    {
        plutus_cost_model costs {};
        static vector<std::string> names {
            "addInteger-cpu-arguments-intercept",
            "addInteger-cpu-arguments-slope",
            "addInteger-memory-arguments-intercept",
            "addInteger-memory-arguments-slope",
            "appendByteString-cpu-arguments-intercept",
            "appendByteString-cpu-arguments-slope",
            "appendByteString-memory-arguments-intercept",
            "appendByteString-memory-arguments-slope",
            "appendString-cpu-arguments-intercept",
            "appendString-cpu-arguments-slope",
            "appendString-memory-arguments-intercept",
            "appendString-memory-arguments-slope",
            "bData-cpu-arguments",
            "bData-memory-arguments",
            "blake2b-cpu-arguments-intercept",
            "blake2b-cpu-arguments-slope",
            "blake2b-memory-arguments",
            "cekApplyCost-exBudgetCPU",
            "cekApplyCost-exBudgetMemory",
            "cekBuiltinCost-exBudgetCPU",
            "cekBuiltinCost-exBudgetMemory",
            "cekConstCost-exBudgetCPU",
            "cekConstCost-exBudgetMemory",
            "cekDelayCost-exBudgetCPU",
            "cekDelayCost-exBudgetMemory",
            "cekForceCost-exBudgetCPU",
            "cekForceCost-exBudgetMemory",
            "cekLamCost-exBudgetCPU",
            "cekLamCost-exBudgetMemory",
            "cekStartupCost-exBudgetCPU",
            "cekStartupCost-exBudgetMemory",
            "cekVarCost-exBudgetCPU",
            "cekVarCost-exBudgetMemory",
            "chooseData-cpu-arguments",
            "chooseData-memory-arguments",
            "chooseList-cpu-arguments",
            "chooseList-memory-arguments",
            "chooseUnit-cpu-arguments",
            "chooseUnit-memory-arguments",
            "consByteString-cpu-arguments-intercept",
            "consByteString-cpu-arguments-slope",
            "consByteString-memory-arguments-intercept",
            "consByteString-memory-arguments-slope",
            "constrData-cpu-arguments",
            "constrData-memory-arguments",
            "decodeUtf8-cpu-arguments-intercept",
            "decodeUtf8-cpu-arguments-slope",
            "decodeUtf8-memory-arguments-intercept",
            "decodeUtf8-memory-arguments-slope",
            "divideInteger-cpu-arguments-constant",
            "divideInteger-cpu-arguments-model-arguments-intercept",
            "divideInteger-cpu-arguments-model-arguments-slope",
            "divideInteger-memory-arguments-intercept",
            "divideInteger-memory-arguments-minimum",
            "divideInteger-memory-arguments-slope",
            "encodeUtf8-cpu-arguments-intercept",
            "encodeUtf8-cpu-arguments-slope",
            "encodeUtf8-memory-arguments-intercept",
            "encodeUtf8-memory-arguments-slope",
            "equalsByteString-cpu-arguments-constant",
            "equalsByteString-cpu-arguments-intercept",
            "equalsByteString-cpu-arguments-slope",
            "equalsByteString-memory-arguments",
            "equalsData-cpu-arguments-intercept",
            "equalsData-cpu-arguments-slope",
            "equalsData-memory-arguments",
            "equalsInteger-cpu-arguments-intercept",
            "equalsInteger-cpu-arguments-slope",
            "equalsInteger-memory-arguments",
            "equalsString-cpu-arguments-constant",
            "equalsString-cpu-arguments-intercept",
            "equalsString-cpu-arguments-slope",
            "equalsString-memory-arguments",
            "fstPair-cpu-arguments",
            "fstPair-memory-arguments",
            "headList-cpu-arguments",
            "headList-memory-arguments",
            "iData-cpu-arguments",
            "iData-memory-arguments",
            "ifThenElse-cpu-arguments",
            "ifThenElse-memory-arguments",
            "indexByteString-cpu-arguments",
            "indexByteString-memory-arguments",
            "lengthOfByteString-cpu-arguments",
            "lengthOfByteString-memory-arguments",
            "lessThanByteString-cpu-arguments-intercept",
            "lessThanByteString-cpu-arguments-slope",
            "lessThanByteString-memory-arguments",
            "lessThanEqualsByteString-cpu-arguments-intercept",
            "lessThanEqualsByteString-cpu-arguments-slope",
            "lessThanEqualsByteString-memory-arguments",
            "lessThanEqualsInteger-cpu-arguments-intercept",
            "lessThanEqualsInteger-cpu-arguments-slope",
            "lessThanEqualsInteger-memory-arguments",
            "lessThanInteger-cpu-arguments-intercept",
            "lessThanInteger-cpu-arguments-slope",
            "lessThanInteger-memory-arguments",
            "listData-cpu-arguments",
            "listData-memory-arguments",
            "mapData-cpu-arguments",
            "mapData-memory-arguments",
            "mkCons-cpu-arguments",
            "mkCons-memory-arguments",
            "mkNilData-cpu-arguments",
            "mkNilData-memory-arguments",
            "mkNilPairData-cpu-arguments",
            "mkNilPairData-memory-arguments",
            "mkPairData-cpu-arguments",
            "mkPairData-memory-arguments",
            "modInteger-cpu-arguments-constant",
            "modInteger-cpu-arguments-model-arguments-intercept",
            "modInteger-cpu-arguments-model-arguments-slope",
            "modInteger-memory-arguments-intercept",
            "modInteger-memory-arguments-minimum",
            "modInteger-memory-arguments-slope",
            "multiplyInteger-cpu-arguments-intercept",
            "multiplyInteger-cpu-arguments-slope",
            "multiplyInteger-memory-arguments-intercept",
            "multiplyInteger-memory-arguments-slope",
            "nullList-cpu-arguments",
            "nullList-memory-arguments",
            "quotientInteger-cpu-arguments-constant",
            "quotientInteger-cpu-arguments-model-arguments-intercept",
            "quotientInteger-cpu-arguments-model-arguments-slope",
            "quotientInteger-memory-arguments-intercept",
            "quotientInteger-memory-arguments-minimum",
            "quotientInteger-memory-arguments-slope",
            "remainderInteger-cpu-arguments-constant",
            "remainderInteger-cpu-arguments-model-arguments-intercept",
            "remainderInteger-cpu-arguments-model-arguments-slope",
            "remainderInteger-memory-arguments-intercept",
            "remainderInteger-memory-arguments-minimum",
            "remainderInteger-memory-arguments-slope",
            "sha2_256-cpu-arguments-intercept",
            "sha2_256-cpu-arguments-slope",
            "sha2_256-memory-arguments",
            "sha3_256-cpu-arguments-intercept",
            "sha3_256-cpu-arguments-slope",
            "sha3_256-memory-arguments",
            "sliceByteString-cpu-arguments-intercept",
            "sliceByteString-cpu-arguments-slope",
            "sliceByteString-memory-arguments-intercept",
            "sliceByteString-memory-arguments-slope",
            "sndPair-cpu-arguments",
            "sndPair-memory-arguments",
            "subtractInteger-cpu-arguments-intercept",
            "subtractInteger-cpu-arguments-slope",
            "subtractInteger-memory-arguments-intercept",
            "subtractInteger-memory-arguments-slope",
            "tailList-cpu-arguments",
            "tailList-memory-arguments",
            "trace-cpu-arguments",
            "trace-memory-arguments",
            "unBData-cpu-arguments",
            "unBData-memory-arguments",
            "unConstrData-cpu-arguments",
            "unConstrData-memory-arguments",
            "unIData-cpu-arguments",
            "unIData-memory-arguments",
            "unListData-cpu-arguments",
            "unListData-memory-arguments",
            "unMapData-cpu-arguments",
            "unMapData-memory-arguments",
            "verifySignature-cpu-arguments-intercept",
            "verifySignature-cpu-arguments-slope",
            "verifySignature-memory-arguments"
        };
        for (const auto &name: names)
            costs.emplace_back(name, 0);
        costs.sort();
        return costs;
    }

    static plutus_cost_model _make_plutus_v2_default_cost_model(const plutus_cost_model &v1_costs)
    {
        plutus_cost_model costs = v1_costs;
        costs.emplace_back("serialiseData-cpu-arguments-intercept", 1159724);
        costs.emplace_back("serialiseData-cpu-arguments-slope", 392670);
        costs.emplace_back("serialiseData-memory-arguments-intercept", 0);
        costs.emplace_back("serialiseData-memory-arguments-slope", 2);
        costs.emplace_back("verifyEcdsaSecp256k1Signature-cpu-arguments", 35892428);
        costs.emplace_back("verifyEcdsaSecp256k1Signature-memory-arguments", 10);
        costs.emplace_back("verifySchnorrSecp256k1Signature-cpu-arguments-intercept", 38887044);
        costs.emplace_back("verifySchnorrSecp256k1Signature-cpu-arguments-slope", 32947);
        costs.emplace_back("verifySchnorrSecp256k1Signature-memory-arguments", 10);
        costs.sort();
        return costs;
    }

    static plutus_cost_model _make_plutus_v3_default_cost_model(const plutus_cost_model &v2_costs)
    {
        plutus_cost_model costs = v2_costs;
        // todo: add the defaults
        costs.sort();
        return costs;
    }

    plutus_cost_models config::_prep_plutus_cost_models(const daedalus_turbo::config &genesis)
    {
        static plutus_cost_model v1_defaults = _make_plutus_v1_default_cost_model();
        static plutus_cost_model v2_defaults = _make_plutus_v2_default_cost_model(v1_defaults);
        static plutus_cost_model v3_defaults = _make_plutus_v3_default_cost_model(v2_defaults);
        plutus_cost_models res {};
        const auto &cfg_models = genesis.at("costModels").as_object();
        const auto import = [&](const std::string &param, const plutus_cost_model &defaults) {
            const auto it = cfg_models.find(param);
            return it != cfg_models.end() ? plutus_cost_model::from_json(defaults, it->value()) : defaults;
        };
        res.v1.emplace(import("PlutusV1", v1_defaults));
        res.v2.emplace(import("PlutusV2", v2_defaults));
        res.v3.emplace(import("PlutusV3", v3_defaults));
        return res;
    }

    config::config(const configs &cfg)
        : byron_genesis { cfg.at(std::filesystem::path { json::value_to<std::string>(cfg.at("config").at("ByronGenesisFile")) }.stem().string()) },
        byron_genesis_hash { _verify_hash_byron(cfg.at("config").at("ByronGenesisHash").as_string(), byron_genesis) },
        byron_protocol_magic { json::value_to<uint64_t>(byron_genesis.at("protocolConsts").at("protocolMagic")) },
        byron_start_time { json::value_to<uint64_t>(byron_genesis.at("startTime")) },
        byron_epoch_length { 21600 },
        byron_slot_duration { std::stoull(json::value_to<std::string>(byron_genesis.at("blockVersionData").as_object().at("slotDuration"))) / 1000 },
        byron_utxos { _byron_prep_utxos(byron_genesis) },
        byron_issuers { _byron_prep_issuers(byron_genesis) },
        shelley_genesis { cfg.at(std::filesystem::path { json::value_to<std::string>(cfg.at("config").at("ShelleyGenesisFile")) }.stem().string()) },
        shelley_genesis_hash { _verify_hash(cfg.at("config").at("ShelleyGenesisHash").as_string(), shelley_genesis) },
        shelley_epoch_length { json::value_to<uint64_t>(shelley_genesis.at("epochLength")) },
        shelley_update_quorum { json::value_to<uint64_t>(shelley_genesis.at("updateQuorum")) },
        shelley_max_lovelace_supply { json::value_to<uint64_t>(shelley_genesis.at("maxLovelaceSupply")) },
        shelley_active_slots { json::value_to<double>(shelley_genesis.at("activeSlotsCoeff")) },
        shelley_security_param { json::value_to<uint64_t>(shelley_genesis.at("securityParam")) },
        shelley_epoch_blocks { static_cast<uint64_t>(shelley_active_slots * shelley_epoch_length) },
        shelley_rewards_ready_slot { shelley_epoch_length - static_cast<uint64_t>(std::ceil(2 * shelley_security_param / shelley_active_slots)) },
        shelley_stability_window { static_cast<uint64_t>(std::ceil(3 * shelley_security_param / shelley_active_slots)) },
        shelley_randomness_stabilization_window { static_cast<uint64_t>(std::ceil(4 * shelley_security_param / shelley_active_slots)) },
        shelley_voting_deadline { static_cast<uint64_t>(std::ceil(4 * shelley_security_param / shelley_active_slots)) },
        shelley_delegates { _shelley_prep_delegates(shelley_genesis) },
        alonzo_genesis { cfg.at(std::filesystem::path { json::value_to<std::string>(cfg.at("config").at("AlonzoGenesisFile")) }.stem().string()) },
        alonzo_genesis_hash { _verify_hash(cfg.at("config").at("AlonzoGenesisHash").as_string(), alonzo_genesis) },
        conway_genesis { cfg.at(std::filesystem::path { json::value_to<std::string>(cfg.at("config").at("ConwayGenesisFile")) }.stem().string()) },
        conway_genesis_hash { _verify_hash(cfg.at("config").at("ConwayGenesisHash").as_string(), conway_genesis) },
        plutus_all_cost_models { _prep_plutus_cost_models(alonzo_genesis) }
    {
        static const auto mainnet_hash = uint8_vector::from_hex("15a199f895e461ec0ffc6dd4e4028af28a492ab4e806d39cb674c88f7643ef62");
        if (conway_genesis_hash == mainnet_hash)
            shelley_start_epoch(208);
    }
}