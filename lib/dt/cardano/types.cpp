/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/base64.hpp>
#include <dt/cardano/types.hpp>
#include <dt/cardano/config.hpp>
#include <dt/crypto/crc32.hpp>
#include <dt/crypto/sha3.hpp>
#include <dt/cbor/zero.hpp>
#include <dt/mutex.hpp>
#include <dt/plutus/costs.hpp>

namespace daedalus_turbo::cardano {
    using namespace crypto;

    void address::to_cbor(cbor::encoder &enc) const
    {
        if (is_byron() && _bytes[0] == 0x83) {
            enc.bytes(byron_crc_protected(bytes()));
        } else {
            enc.bytes(bytes());
        }
    }

    byron_addr address::byron() const
    {
        if (is_byron())
            return { bytes() };
        throw error("address {} is not a byron one!", *this);
    }

    const pay_ident address::pay_id() const
    {
        switch (type()) {
            case 0b0110: // enterprise key
            case 0b0111: // enterprise script
            case 0b0000: // base address: keyhash28,keyhash28
            case 0b0001: // base address: scripthash28,keyhash28
            case 0b0010: // base address: keyhash28,scripthash28
            case 0b0011: // base address: scripthash28,scripthash28
            case 0b0100: // pointer key
            case 0b0101: // pointer script
                return pay_ident { data().subbuf(0, 28), (type() & 0x1) > 0 ? pay_ident::ident_type::SHELLEY_SCRIPT : pay_ident::ident_type::SHELLEY_KEY };

            case 0b1000: { // byron
                const auto w_data = cbor::parse(data());
                switch (const auto n_items = w_data.array().size(); n_items) {
                    case 3: return pay_ident { w_data.at(0).buf(), pay_ident::ident_type::BYRON_KEY };
                    case 2: {
                        const auto nested_data = cbor::parse(w_data.at(0).tag().second->buf());
                        return pay_ident { nested_data.at(0).buf(), pay_ident::ident_type::BYRON_KEY };
                    }
                    default: throw error("unsupported format of a byron address: {} items", n_items);
                }
            }

            default:
                throw cardano_error("unsupported address for type: {}!", type());
        }
    }

    cert_loc_t::cert_loc_t(const uint64_t s, const uint64_t t, const uint64_t c):
        slot { s }, tx_idx { narrow_cast<uint32_t>(t) }, cert_idx { narrow_cast<uint32_t>(c) }
    {
    }

    stake_pointer::stake_pointer(const cbor::value &v):
        cert_loc_t { v.at(0).uint(), v.at(1).uint(), v.at(2).uint() }
    {
    }

    void stake_pointer::to_cbor(cbor::encoder &enc) const
    {
        enc.array(3).uint(slot).uint(tx_idx).uint(cert_idx);
    }

    credential_t::credential_t(const key_hash &hash_, const bool script_):
        hash { hash_ }, script { script_ }
    {
    }

    credential_t::credential_t(const cbor::value &v):
        hash { v.at(1).buf() }, script { v.at(0).uint() == 1 }
    {
    }

    credential_t::credential_t(const std::string_view s)
    {
        const auto pos = s.find('-');
        if (pos == std::string::npos) [[unlikely]]
            throw error("invalid credential format: {}", s);
        const auto typ = s.substr(0, pos);
        const auto hex = s.substr(pos + 1);
        if (typ == "keyHash") {
            script = false;
        } else if (typ == "scriptHash") {
            script = true;
        } else {
            throw error("invalid credential format: {}", s);
        }
        hash = key_hash::from_hex(hex);
    }

    void credential_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(2).uint(script ? 1 : 0).bytes(hash);
    }

    pool_voting_thresholds_t::pool_voting_thresholds_t(const cbor::value &v):
        motion_of_no_confidence { v.at(0) },
        committee_normal { v.at(1) },
        committee_no_confidence { v.at(2) },
        hard_fork_initiation { v.at(3) },
        security_voting_threshold { v.at(4) }
    {
    }

    pool_voting_thresholds_t::pool_voting_thresholds_t(const json::value &j):
        motion_of_no_confidence { j.at("motionNoConfidence") },
        committee_normal { j.at("committeeNormal") },
        committee_no_confidence { j.at("committeeNoConfidence") },
        hard_fork_initiation { j.at("hardForkInitiation") },
        security_voting_threshold { j.at("ppSecurityGroup") }
    {
    }

    void pool_voting_thresholds_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(5)
            .rational(motion_of_no_confidence)
            .rational(committee_normal)
            .rational(committee_no_confidence)
            .rational(hard_fork_initiation)
            .rational(security_voting_threshold);
    }

    drep_voting_thresholds_t::drep_voting_thresholds_t(const cbor::value &v):
        motion_no_confidence { v.at(0) },
        committee_normal { v.at(1) },
        committee_no_confidence { v.at(2) },
        update_constitution { v.at(3) },
        hard_fork_initiation { v.at(4) },
        pp_network_group { v.at(5) },
        pp_economic_group { v.at(6) },
        pp_technical_group { v.at(7) },
        pp_governance_group { v.at(8) },
        treasury_withdrawal { v.at(9) }
    {
    }

    drep_voting_thresholds_t::drep_voting_thresholds_t(const json::value &j):
        motion_no_confidence { j.at("motionNoConfidence") },
        committee_normal { j.at("committeeNormal") },
        committee_no_confidence { j.at("committeeNoConfidence") },
        update_constitution { j.at("updateToConstitution") },
        hard_fork_initiation { j.at("hardForkInitiation") },
        pp_network_group { j.at("ppNetworkGroup") },
        pp_economic_group { j.at("ppEconomicGroup") },
        pp_technical_group { j.at("ppTechnicalGroup") },
        pp_governance_group { j.at("ppGovGroup") },
        treasury_withdrawal { j.at("treasuryWithdrawal") }
    {
    }

    void drep_voting_thresholds_t::to_cbor(cbor::encoder &enc) const
    {
        enc.array(10)
            .rational(motion_no_confidence)
            .rational(committee_normal)
            .rational(committee_no_confidence)
            .rational(update_constitution)
            .rational(hard_fork_initiation)
            .rational(pp_network_group)
            .rational(pp_economic_group)
            .rational(pp_technical_group)
            .rational(pp_governance_group)
            .rational(treasury_withdrawal);
    }

    void plutus_cost_models::to_cbor(cbor::encoder &enc) const
    {
        size_t cnt = 1;
        if (!v1) [[unlikely]]
            throw error("v1 plutus cost model must be defined!");
        if (v2)
            ++cnt;
        if (v3)
            ++cnt;
        enc.map(cnt);
        enc.uint(0);
        enc.array_compact(v1->size(), [&] {
            for (const auto &[name, cost]: *v1)
                enc.uint(cost);
        });
        if (v2) {
            enc.uint(1);
            enc.array_compact(v2->size(), [&] {
                for (const auto &[name, cost]: *v2)
                    enc.uint(cost);
            });
        }
        if (v3) {
            enc.uint(2);
            enc.array_compact(v3->size(), [&] {
                for (const auto &[name, cost]: *v3) {
                    if (cost >= 0)
                        enc.uint(cost);
                    else
                        enc.nint(-(cost + 1));
                }
            });
        }
    }

    void slot::to_cbor(cbor::encoder &enc) const
    {
        enc.array(3)
            .bigint(cpp_int { unixtime() - _cfg.byron_start_time } * 1'000'000'000'000)
            .uint(_slot)
            .uint(epoch());
    }

    static void assets_to_cbor(cbor::encoder &enc, const tx_out_data &data)
    {
        if (data.assets) {
            enc.array(2);
            enc.uint(data.coin);
            enc.raw_cbor(*data.assets);
        } else {
            enc.uint(data.coin);
        }
    }

    void tx_out_data::to_cbor(cbor::encoder &enc) const
    {
        if (script_ref || (datum && datum->index() != 0)) {
            enc.map(2 + (datum ? 1 : 0) + (script_ref ? 1 : 0));
            enc.uint(0);
            cardano::address { address }.to_cbor(enc);
            enc.uint(1);
            assets_to_cbor(enc, *this);
            if (datum) {
                enc.uint(2);
                enc.array(2);
                switch (datum->index()) {
                    case 0: {
                        enc.uint(0);
                        enc.bytes(std::get<datum_hash>(*datum));
                        break;
                    }
                    case 1: {
                        enc.uint(1);
                        enc.tag(24);
                        enc.bytes(std::get<uint8_vector>(*datum));
                        break;
                    }
                    default:
                        throw error("unsupported tx_out_data::datum_option_type index: {}", datum->index());
                }
            }
            if (script_ref) {
                enc.uint(3);
                enc.tag(24);
                enc.bytes(*script_ref);
            }
        } else {
            enc.array(2 + (datum ? 1 : 0));
            cardano::address { address }.to_cbor(enc);
            assets_to_cbor(enc, *this);
            if (datum)
                enc.bytes(std::get<datum_hash>(*datum));
        }
    }

    plutus_cost_model plutus_cost_model::from_cbor(const vector<std::string> &names, const cbor_array &data)
    {
        if (names.size() != data.size()) [[unlikely]]
            throw error("plutus_cost_model: was expecting an array with {} elements but got {}", names.size(), data.size());
        plutus_cost_model res {};
        res.reserve(names.size());
        for (size_t i = 0; i < names.size(); ++i) {
            const auto &v = data[i];
            if (v.type == CBOR_UINT)
                res.emplace_back(names[i], narrow_cast<int64_t>(v.uint()));
            else
                res.emplace_back(names[i], -narrow_cast<int64_t>(v.nint()));
        }
        return res;
    }

    plutus_cost_model plutus_cost_model::from_json(const plutus_cost_model &orig, const json::value &data)
    {
        plutus_cost_model res {};
        res.reserve(orig.size());
        if (data.is_object()) {
            const auto &data_obj = data.as_object();
            if (orig.size() != data_obj.size())
                throw error("was expecting an array with {} elements but got {}", orig.size(), data_obj.size());
            for (size_t i = 0; i < orig.size(); ++i) {
                const auto &key = orig.storage().at(i).first;
                auto it = data_obj.find(key);
                if (it == data_obj.end())
                    it = data_obj.find(plutus::costs::v1_arg_name(key));
                if (it == data_obj.end())
                    throw error("missing required cost model key: {}", key);
                res.emplace_back(key, json::value_to<int64_t>(it->value()));
            }
        } else if (data.is_array()) {
            const auto &data_arr = data.as_array();
            if (orig.size() != data_arr.size())
                throw error("was expecting an array with {} elements but got {}", orig.size(), data_arr.size());
            for (size_t i = 0; i < orig.size(); ++i) {
                const auto &key = orig.storage().at(i).first;
                res.emplace_back(key, json::value_to<int64_t>(data_arr[i]));
            }
        } else {
            throw error("an unsupported json value representing a cost model: {}", json::serialize_pretty(data));
        }
        return res;
    }

    void plutus_cost_model::update(const plutus_cost_model &src)
    {
        for (auto &item: _data) {
            if (const auto it = src.find(item.first); it != src.end())
                item.second = it->second;
        }
    }

    plutus_cost_model::diff_type plutus_cost_model::diff(const plutus_cost_model &o) const
    {
        diff_type m {};
        for (const auto &[k, v]: *this) {
            const auto it = o.find(k);
            if (it == o.end()) {
                m.try_emplace(k, v, std::optional<int64_t> {});
            } else if (it->second != v) {
                m.try_emplace(k, v, it->second);
            }
        }
        for (const auto &[k, v]: o) {
            const auto it = find(k);
            if (it == end())
                m.try_emplace(k, std::optional<int64_t> {}, v);
        }
        return m;
    }

    slot slot::from_time(const std::chrono::time_point<std::chrono::system_clock> &tp, const cardano::config &cfg)
    {
        const uint64_t secs = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
        if (secs >= cfg.byron_start_time) [[likely]] {
            if (secs >= cfg.shelley_start_time()) [[likely]]
                return { secs - cfg.shelley_start_time() + cfg.shelley_start_slot(), cfg };
            return { (secs - cfg.byron_start_time) / cfg.byron_slot_duration, cfg };
        }
        throw error("cannot create a slot from a time point before the byron start time: {}", cfg.byron_start_time);
    }

    slot slot::from_epoch(const uint64_t epoch, const uint64_t epoch_slot, const cardano::config &cfg)
    {
        if (epoch >= cfg.shelley_start_epoch()) [[likely]]
            return { (epoch - cfg.shelley_start_epoch()) * cfg.shelley_epoch_length + cfg.shelley_start_slot() + epoch_slot, cfg };
        return { epoch * cfg.byron_epoch_length + epoch_slot, cfg };
    }

    slot slot::from_chunk(const uint64_t chunk, const cardano::config &cfg)
    {
        return { chunk * cfg.byron_epoch_length, cfg };
    }

    slot slot::from_epoch(const uint64_t epoch, const cardano::config &cfg)
    {
        return from_epoch(epoch, 0, cfg);
    }

    slot slot::from_future(const cardano::config &cfg)
    {
        return from_time(std::chrono::system_clock::now() + std::chrono::seconds { 5 }, cfg);
    }

    uint64_t slot::epoch() const
    {
        if (_slot > _cfg.shelley_start_slot())
            return _cfg.shelley_start_epoch() + (_slot - _cfg.shelley_start_slot()) / _cfg.shelley_epoch_length;
        return _slot / _cfg.byron_epoch_length;
    }

    uint64_t slot::epoch_slot() const
    {
        if (_slot > _cfg.shelley_start_slot())
            return (_slot - _cfg.shelley_start_slot()) % _cfg.shelley_epoch_length;
        return _slot % _cfg.byron_epoch_length;
    }

    uint64_t slot::chunk_id() const
    {
        return _slot / _cfg.byron_epoch_length;
    }

    uint64_t slot::unixtime() const
    {
        if (_slot >= _cfg.shelley_start_slot())
            return _cfg.shelley_start_time() + (_slot - _cfg.shelley_start_slot());
        return _cfg.shelley_start_time() - (_cfg.shelley_start_slot() - _slot) * 20;
    }

    std::string slot::timestamp() const
    {
        alignas(mutex::padding) static mutex::unique_lock::mutex_type gmtime_mutex {};
        std::stringstream ss {};
        std::time_t t = unixtime();
        {
            mutex::scoped_lock lk { gmtime_mutex };
            std::tm* tm = std::gmtime(&t);
            ss << std::put_time(tm, "%Y-%m-%d %H:%M:%S");
        }
        return ss.str();
    }

    std::string slot::utc_month() const
    {
        return timestamp().substr(0, 7);
    }

    void param_update::rehash()
    {
        memset(hash.data(), 0, hash.size());
        blake2b(hash, zpp::serialize(*this));
    }

    plutus_cost_models::plutus_cost_models(const cbor::value &v)
    {
        for (const auto &[model_id, values]: v.map()) {
            switch (model_id.uint()) {
                case 0:
                    v1.emplace(plutus_cost_model::from_cbor(plutus::costs::cost_arg_names_v1(), values.array()));
                    break;
                case 1:
                    v2.emplace(plutus_cost_model::from_cbor(plutus::costs::cost_arg_names_v2(), values.array()));
                    break;
                case 2:
                    switch (const auto sz = values.array().size(); sz) {
                        case 251:
                            v3.emplace(plutus_cost_model::from_cbor(plutus::costs::cost_arg_names_v3(), values.array()));
                            break;
                        case 297:
                            v3.emplace(plutus_cost_model::from_cbor(plutus::costs::cost_arg_names_v3b(), values.array()));
                            break;
                        default:
                            throw error("an unsupported number of arguments in plutus v2 cost model: {}", sz);
                    }
                    break;
                default:
                    throw error("unsupported cost model id: {}", model_id);
            }
        }
    }

    static std::optional<uint8_vector> _normalize_assets(const buffer policies_buf)
    {
        std::optional<uint8_vector> res {};
        const cbor::zero::value policies = cbor::zero::parse(policies_buf);
        if (policies.size()) [[likely]] {
            map<buffer, uint8_vector> ok_policies {};
            auto p_it = policies.map();
            while (!p_it.done()) [[likely]] {
                const auto [policy_id, assets] = p_it.next();
                if (assets.size()) [[likely]] {
                    // create a map to sort the assets
                    map<buffer, cbor::zero::value> ok_assets {};
                    auto a_it = assets.map();
                    while (!a_it.done()) [[likely]] {
                        const auto [asset_id, coin] = a_it.next();
                        if (coin.uint())
                            ok_assets.emplace(asset_id.bytes(), coin);
                    }
                    if (!ok_assets.empty()) [[likely]] {
                        cbor::encoder p_enc {};
                        p_enc.map_compact(ok_assets.size(), [&] {
                            for (const auto &[asset_id, coin]: ok_assets)
                                p_enc.bytes(asset_id).raw_cbor(coin.raw_span());
                        });
                        ok_policies.emplace(policy_id.bytes(), std::move(p_enc.cbor()));
                    }
                }
            }
            if (!ok_policies.empty()) [[likely]] {
                cbor::encoder final_enc {};
                final_enc.map_compact(ok_policies.size(), [&] {
                    for (const auto &[policy_id, assets]: ok_policies)
                        final_enc.bytes(policy_id).raw_cbor(assets);
                });
                res.emplace(std::move(final_enc.cbor()));
            }
        }
        return res;
    }

    static tx_output _extract_assets(const cbor_value &addr, const cbor_value &value, const size_t idx, const cbor::value &out_raw)
    {
        if (value.type == CBOR_UINT)
            return { address { addr.buf() }, amount { value.uint() }, idx, out_raw };
        const auto &multi_val = value.array();
        return { address { addr.buf() }, amount { multi_val.at(0).uint() }, idx, out_raw, &multi_val.at(1) };
    }

    tx_output tx_output::from_cbor(const uint64_t era, const uint64_t idx, const cbor::value &out_raw)
    {
        if (idx >= 0x10000) [[unlikely]]
            throw cardano_error("transaction output number is too high {}!", idx);
        switch (era) {
            case 1: {
                const auto &out = out_raw.array();
                return { cardano::address { out.at(0).array().at(0).tag().second->buf() }, cardano::amount { out.at(1).uint() }, idx, out_raw };
            }
            case 2: {
                if (out_raw.type != CBOR_ARRAY) [[unlikely]]
                    throw cardano_error("era: {} unsupported tx output format: {}!", era, out_raw);
                const auto &out = out_raw.array();
                return { cardano::address { out.at(0).buf() }, cardano::amount { out.at(1).uint() }, idx, out_raw };
            }
            case 3: {
                if (out_raw.type != CBOR_ARRAY)
                    throw cardano_error("era: {} unsupported tx output format: {}!", era, out_raw);
                const auto &out = out_raw.array();
                return _extract_assets(out.at(0), out.at(1), idx, out_raw);
            }
            case 4:
            case 5:
            case 6:
            case 7:  {
                const cbor_value *address = nullptr;
                const cbor_value *amount = nullptr;
                const cbor_value *datum = nullptr;
                const cbor_value *script_ref = nullptr;
                switch (out_raw.type) {
                    case CBOR_ARRAY: {
                        const auto &out = out_raw.array();
                        address = &out.at(0);
                        amount = &out.at(1);
                        if (out.size() > 2)
                            datum = &out.at(2);
                        break;
                    }
                    case CBOR_MAP:
                        if (era < 6) [[unlikely]]
                            throw error("map-based transaction outputs are not supported in eras below 6");
                        for (const auto &[o_type, o_entry]: out_raw.map()) {
                            switch (const auto typ = o_type.uint(); typ) {
                                case 0: address = &o_entry; break;
                                case 1: amount = &o_entry; break;
                                case 2: datum = &o_entry; break;
                                case 3: script_ref = &o_entry; break;
                                default: throw error("unsupported output_type: {}", typ);
                            }
                        }
                        break;
                    default: throw cardano_error("era: {} unsupported tx output format: {}!", era, out_raw);
                }
                if (address == nullptr)
                    throw cardano_error("transaction output misses address field!");
                if (amount == nullptr)
                    throw cardano_error("transaction output misses amount field!");
                auto res = _extract_assets(*address, *amount, idx, out_raw);
                res.datum = datum;
                res.script_ref = script_ref;
                return res;
            }
            default: throw error("tx_output::from_cbor: unsupported era: {}", era);
        }
    }

    tx_out_data tx_out_data::from_output(const tx_output &txo)
    {
        tx_out_data res { txo.amount, txo.address.bytes() };
        if (txo.assets)
            res.assets = _normalize_assets(txo.assets->raw_span());
        if (txo.datum) {
            switch (txo.datum->type) {
                case CBOR_BYTES:
                    res.datum.emplace(cardano::datum_hash { txo.datum->buf() });
                    break;
                case CBOR_ARRAY: {
                    switch (txo.datum->at(0).uint()) {
                        case 0:
                            res.datum.emplace(cardano::datum_hash { txo.datum->at(1).buf() });
                            break;
                        case 1:
                            res.datum.emplace(uint8_vector { txo.datum->at(1).tag().second->buf() });
                            break;
                        default:
                            throw error("unexpected datum value: {}", *txo.datum);
                    }
                    break;
                }
                default:
                    throw error("unexpected datum value: {}", *txo.datum);
            }
        }
        if (txo.script_ref)
            res.script_ref.emplace(txo.script_ref->tag().second->buf());
        return res;
    }

    script_info script_info::from_cbor(const buffer bytes)
    {
        auto it = cbor::zero::parse(bytes).array();
        const auto id = it.next();
        const auto data = it.next();
        switch (const auto s_typ = id.uint(); s_typ) {
            case 0: return { script_type::native, data.raw_span() };
            case 1: return { script_type::plutus_v1, data.bytes() };
            case 2: return { script_type::plutus_v2, data.bytes() };
            case 3: return { script_type::plutus_v3, data.bytes() };
            default: throw error("unsupported script_type in script_ref: {}", s_typ);
        }
    }

    ex_units::ex_units(const cbor::value &v):
        mem { v.at(0).uint() }, steps { v.at(1).uint() }
    {
    }

    ex_units::ex_units(const json::value &j):
        mem { json::value_to<uint64_t>(j.at("exUnitsMem")) },
        steps { json::value_to<uint64_t>(j.at("exUnitsSteps")) }
    {
    }

    drep_t::drep_t(const type_t &t): typ { t }
    {
        if (typ == credential) [[unlikely]]
            throw error("credential-based drep must be initialized only with a defined credential!");
    }

    drep_t::drep_t(const credential_t &c): typ { credential }, cred { c }
    {
    }

    drep_t::drep_t(const cbor::value &v)
    {
        switch (const auto dtyp = v.at(0).uint(); dtyp) {
            case 0:
                typ = credential;
                cred.emplace(v.at(1).buf(), false);
                break;
            case 1:
                typ = credential;
                cred.emplace(v.at(1).buf(), true);
                break;
            case 2: typ = abstain; break;
            case 3: typ = no_confidence; break;
            default: throw error("unsupported drep type: {}", dtyp);
        }
    }

    void drep_t::to_cbor(cbor::encoder &enc) const
    {
        switch (typ) {
            case abstain: enc.array(1).uint(2); break;
            case no_confidence: enc.array(1).uint(3); break;
            case credential: {
                const auto &c = cred.value();
                enc.array(2).uint(c.script ? 1 : 0);
                enc.bytes(c.hash);
                break;
            }
            default: throw error("unsupported drep type: {}", static_cast<int>(typ));
        }
    }

    std::tuple<uint8_t, size_t> from_haskell_char(const std::string_view sv)
    {
        static std::map<uint8_t, uint8_t> one_char_codes {
            { '0', 0x00 }, { 'a', 0x07 }, { 'b', 0x08 }, { 'f', 0x0C },
            { 'n', 0x0A }, { 'r', 0x0D }, { 't', 0x09 }, { 'v', 0x0B },
            { '"', 0x22 }, { '\'', 0x27 }, { '\\', 0x5C }
        };
        static std::map<std::string, uint8_t> multichar_codes {
            { "BS"s, 0x08 }, { "HT"s, 0x09 }, { "LF"s, 0x0A }, { "VT"s, 0x0B },
            { "FF"s, 0x0C }, { "CR"s, 0x0D }, { "SO"s, 0x0E }, { "SI"s, 0x0F },
            { "EM"s, 0x19 }, { "FS"s, 0x1C }, { "GS"s, 0x1D }, { "RS"s, 0x1E },
            { "US"s, 0x1F }, { "SP"s, 0x20 },
            
            // SO and SOH share the same prefix, so the resolution should go from longest to shortest matches!
            { "NUL"s, 0x00 }, { "SOH"s, 0x01 }, { "STX"s, 0x02 }, { "ETX"s, 0x03 },
            { "EOT"s, 0x04 }, { "ENQ"s, 0x05 }, { "ACK"s, 0x06 }, { "BEL"s, 0x07 },            
            { "DLE"s, 0x10 }, { "DC1"s, 0x11 }, { "DC2"s, 0x12 }, { "DC3"s, 0x13 },
            { "DC4"s, 0x14 }, { "NAK"s, 0x15 }, { "SYN"s, 0x16 }, { "ETB"s, 0x17 },
            { "CAN"s, 0x18 }, { "SUB"s, 0x1A }, { "ESC"s, 0x1B }, { "DEL"s, 0x7F }
        };
        if (sv[0] >= '1' && sv[0] <= '9') {
            auto end = sv.find_first_not_of("0123456789"sv);
            if (end == std::string_view::npos) end = sv.size();
            std::string text { sv.substr(0, end) };
            uint8_t byte = std::stoul(text);
            return std::make_tuple(byte, end);
        } else if (sv[0] >= 'A' && sv[0] <= 'Z') {
            for (size_t n_chars = sv.size() > 3 ? 3 : sv.size(); n_chars >= 1; --n_chars) {
                std::string text { sv.substr(0, n_chars) };
                auto it = multichar_codes.find(text);
                if (it != multichar_codes.end()) {
                    return std::make_tuple(it->second, n_chars);
                }
            }
            throw error("Unsupported escape sequence starting with {}!", sv);
        } else {
            auto it = one_char_codes.find(sv[0]);
            if (it != one_char_codes.end()) {
                return std::make_tuple(it->second, 1);
            }
            throw error("Escape sequence starts from an unsupported character: '{}' code {}!", sv[0], (int)sv[0]);
        }
    }

    uint8_vector from_haskell(const std::string_view sv)
    {
        uint8_vector bytes;
        for (size_t i = 0; i < sv.size(); ++i) {
            if (sv[i] != '\\') {
                bytes.push_back(sv[i]);
            } else if (i + 1 < sv.size()) {
                if (sv[i + 1] != '&') {
                    const auto [byte, extra_size] = from_haskell_char(sv.substr(i + 1));
                    bytes.push_back(byte);
                    i += extra_size;
                } else {
                    // empty string, just skip it
                    i += 1;
                }
            }
        }
        return bytes;
    }

    byron_addr::byron_addr(const buffer bytes):
        _bytes { bytes },
        _addr { cbor::parse(_bytes) }
    {
        if (_addr.array().size() == 2) {
            _bytes = uint8_vector { _addr.at(0).tag().second->buf() };
            _addr = cbor::parse(_bytes);
        }
    }

    bool byron_addr::vkey_ok(const buffer vk, const uint8_t typ) const
    {
        const auto root_hash = byron_addr_root_hash(type(), vk, attrs());
        return root_hash == root() && typ == type();
    }

    key_hash byron_addr::bootstrap_root(const cbor::value &w_data) const
    {
        uint8_vector vk_full {};
        vk_full << w_data.at(0).buf() << w_data.at(2).buf();
        return byron_addr_root_hash(0, vk_full, w_data.at(3).buf());
    }

    bool byron_addr::bootstrap_ok(const cbor::value &w_data) const
    {
        const auto root_hash = bootstrap_root(w_data);
        return root_hash == root() && 0 == type();
    }

    key_hash byron_addr_root_hash(const size_t typ, const buffer vk, const buffer attrs_cbor) {
        cbor::encoder enc {};
        enc.array(3);
        enc.uint(typ);
        enc.array(2);
        enc.uint(typ);
        enc.bytes(vk);
        enc.raw_cbor(attrs_cbor);
        return blake2b<key_hash>(sha3::digest(enc.cbor()));
    }

    inline uint8_vector byron_encode_redeem_root(const buffer redeem_vk)
    {
        cbor::encoder enc {};
        enc.array(3)
            .uint(2)
            .array(2).uint(2).bytes(redeem_vk)
            .map(0);
        return enc.cbor();
    }

    inline key_hash byron_address_hash(const buffer data)
    {
        return blake2b<key_hash>(sha3::digest(data));
    }

    inline uint8_vector byron_encode_address(const buffer root_hash)
    {
        cbor::encoder enc {};
        enc.array(3)
            .bytes(root_hash)
            .map(0)
            .uint(2);
        return enc.cbor();
    }

    uint8_vector byron_crc_protected(const buffer &encoded_addr)
    {
        cbor::encoder enc {};
        enc.array(2);
        enc.tag(24).bytes(encoded_addr);
        enc.uint(crc32::digest(encoded_addr));
        return enc.cbor();
    }

    uint8_vector byron_avvm_addr(std::string_view redeem_vk_base64u)
    {
        const auto redeem_vk = base64::decode_url(redeem_vk_base64u);
        const auto encoded_root = byron_encode_redeem_root(redeem_vk);
        const auto root_hash = byron_address_hash(encoded_root);
        const auto encoded_addr = byron_encode_address(root_hash);
        return byron_crc_protected(encoded_addr);
    }

    tx_hash byron_avvm_tx_hash(std::string_view redeem_vk)
    {
        return blake2b<tx_hash>(byron_avvm_addr(redeem_vk));
    }
}