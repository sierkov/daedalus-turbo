/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cardano/alonzo.hpp>
#include <dt/cardano/shelley.hpp>
#include <dt/cbor-encoder.hpp>
#include <dt/progress.hpp>
#include <dt/util.hpp>
#include <dt/validator/state.hpp>
#include <dt/zpp.hpp>

// Disable a windows macro
#ifdef small
#   undef small
#endif

namespace daedalus_turbo::validator {

    template<typename T>
    concept Clearable = requires(T a)
    {
        a.clear();
    };

    template<typename T>
    concept Sizable = requires(T a)
    {
        a.size();
    };

    static pool_info pool_params_from_cbor(const cbor_value &params)
    {
        return pool_info { cardano::shelley::pool_params_from_cbor(params.array(), 0) };
    }

    static cardano::param_update parse_param_update(const uint64_t era, const cbor::value &proposal, const cardano::config &cfg)
    {
        cardano::param_update upd {};
        if (era >= 5)
            upd = cardano::alonzo::parse_alonzo_param_update(proposal, cfg);
        else
            upd = cardano::shelley::parse_shelley_param_update(proposal);
        upd.rehash();
        return upd;
    }

    static cardano::stake_pointer _parse_stake_pointer(const cbor::value &v)
    {
        return { v.at(0).uint(), v.at(1).uint(), v.at(2).uint() };
    }

    struct state_encoder: cbor::encoder {
        void assets(const cardano::tx_out_data &data)
        {
            if (data.assets) {
                array(2);
                uint(data.coin);
                _encode_data(*data.assets);
            } else {
                uint(data.coin);
            }
        }

        void address(const buffer &addr)
        {
            if (!addr.empty() && addr[0] == 0x83) {
                bytes(cardano::byron_crc_protected(addr));
            } else {
                bytes(addr);
            }
        }

        void encode(const cardano::slot &slot)
        {
            array(3)
                .bigint(cpp_int { slot.unixtime() - slot.config().byron_start_time } * 1'000'000'000'000)
                .uint(slot)
                .uint(slot.epoch());
        }

        void encode(const cardano::stake_ident &stake_id)
        {
            array(2).uint(stake_id.script ? 1 : 0).bytes(stake_id.hash);
        }

        void encode(const cardano::stake_pointer &ptr)
        {
            array(3).uint(ptr.slot).uint(ptr.tx_idx).uint(ptr.cert_idx);
        }

        static void encode_param_uint(size_t &num_items, state_encoder &enc, const size_t idx, const std::optional<uint64_t> &val)
        {
            if (val) {
                ++num_items;
                enc.uint(idx);
                enc.uint(*val);
            }
        }

        static void encode_param_rational(size_t &num_items, state_encoder &enc, const size_t idx, const std::optional<rational_u64> &val)
        {
            if (val) {
                ++num_items;
                enc.uint(idx);
                enc.rational(*val);
            }
        }

        static void encode_common(size_t &cnt, state_encoder &enc, const cardano::param_update &upd)
        {
            encode_param_uint(cnt, enc, 0, upd.min_fee_a);
            encode_param_uint(cnt, enc, 1, upd.min_fee_b);
            encode_param_uint(cnt, enc, 2, upd.max_block_body_size);
            encode_param_uint(cnt, enc, 3, upd.max_transaction_size);
            encode_param_uint(cnt, enc, 4, upd.max_block_header_size);
            encode_param_uint(cnt, enc, 5, upd.key_deposit);
            encode_param_uint(cnt, enc, 6, upd.pool_deposit);
            encode_param_uint(cnt, enc, 7, upd.e_max);
            encode_param_uint(cnt, enc, 8, upd.n_opt);
            encode_param_rational(cnt, enc, 9, upd.pool_pledge_influence);
            encode_param_rational(cnt, enc, 10, upd.expansion_rate);
            encode_param_rational(cnt, enc, 11, upd.treasury_growth_rate);
            encode_param_rational(cnt, enc, 12, upd.decentralization);
            if (upd.extra_entropy) {
                ++cnt;
                enc.uint(13);
                if (*upd.extra_entropy) {
                    enc.array(2);
                    enc.uint(1);
                    enc.bytes(*(*upd.extra_entropy));
                } else {
                    enc.array(1);
                    enc.uint(0);
                }
            }
            if (upd.protocol_ver) {
                ++cnt;
                enc.uint(14);
                enc.array(2).uint(upd.protocol_ver->major).uint(upd.protocol_ver->minor);
            }
        }

        void encode_shelley(const cardano::param_update &upd)
        {
            size_t cnt = 0;
            state_encoder enc {};
            encode_common(cnt, enc, upd);
            encode_param_uint(cnt, enc, 15, upd.min_utxo_value);
            map(cnt);
            *this << enc;
        }

        void encode_alonzo(const cardano::param_update &upd)
        {
            size_t cnt = 0;
            state_encoder enc {};
            encode_common(cnt, enc, upd);
            encode_param_uint(cnt, enc, 16, upd.min_pool_cost);
            encode_param_uint(cnt, enc, 17, upd.lovelace_per_utxo_byte);
            if (upd.plutus_cost_models) {
                ++cnt;
                enc.uint(18);
                enc.encode(*upd.plutus_cost_models);
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
            encode_param_uint(cnt, enc, 22, upd.max_value_size);
            encode_param_uint(cnt, enc, 23, upd.max_collateral_pct);
            encode_param_uint(cnt, enc, 24, upd.max_collateral_inputs);
            map(cnt);
            *this << enc;
        }

        void encode(const cardano::param_update &upd, const uint64_t era)
        {
            if (era >= 5)
                encode_alonzo(upd);
            else
                encode_shelley(upd);
        }

        void encode(const cardano::tx_out_data &txo_data, const uint64_t /*era*/)
        {
            if (txo_data.script_ref || (txo_data.datum && txo_data.datum->index() != 0)) {
                map(2 + (txo_data.datum ? 1 : 0) + (txo_data.script_ref ? 1 : 0));
                uint(0);
                address(txo_data.address);
                uint(1);
                assets(txo_data);
                if (txo_data.datum) {
                    uint(2);
                    array(2);
                    switch (txo_data.datum->index()) {
                        case 0: {
                            uint(0);
                            bytes(std::get<cardano::datum_hash>(*txo_data.datum));
                            break;
                        }
                        case 1: {
                            uint(1);
                            tag(24);
                            bytes(std::get<uint8_vector>(*txo_data.datum));
                            break;
                        }
                        default:
                            throw error("unsupported tx_out_data::datum_option_type index: {}", txo_data.datum->index());
                    }
                }
                if (txo_data.script_ref) {
                    uint(3);
                    tag(24);
                    bytes(*txo_data.script_ref);
                }
            } else {
                array(2 + (txo_data.datum ? 1 : 0));
                address(txo_data.address);
                assets(txo_data);
                if (txo_data.datum)
                    bytes(std::get<cardano::datum_hash>(*txo_data.datum));
            }
        }

        void encode(const cardano::plutus_cost_models &cost_mdls)
        {
            size_t cnt = 1;
            if (!cost_mdls.v1)
                throw error("v1 plutus cost model must be defined!");
            if (cost_mdls.v2)
                ++cnt;
            if (cost_mdls.v3)
                ++cnt;
            map(cnt);
            uint(0);
            array_compact(cost_mdls.v1->size(), [&] {
                for (const auto &[name, cost]: *cost_mdls.v1)
                    uint(cost);
            });
            if (cost_mdls.v2) {
                uint(1);
                array_compact(cost_mdls.v2->size(), [&] {
                    for (const auto &[name, cost]: *cost_mdls.v2)
                        uint(cost);
                });
            }
            if (cost_mdls.v3) {
                uint(2);
                array_compact(cost_mdls.v3->size(), [&] {
                    for (const auto &[name, cost]: *cost_mdls.v3)
                        uint(cost);
                });
            }
        }

        void encode(const cardano::pool_hash &pool_id, const pool_info &params)
        {
            array(9);
            bytes(pool_id);
            bytes(params.vrf_vkey);
            uint(params.pledge);
            uint(params.cost);
            rational(params.margin);
            uint8_vector reward_addr {};
            reward_addr << ((params.reward_id.script ? 0xF0 : 0xE0) | (params.reward_network & 0xF)) << params.reward_id.hash;
            bytes(reward_addr);
            if (params.owners.size() < 24) {
                array(params.owners.size());
                for (const auto &stake_id: params.owners)
                    bytes(stake_id.hash);
            } else {
                array();
                for (const auto &stake_id: params.owners)
                    bytes(stake_id.hash);
                s_break();
            }
            array_compact(params.relays.size(), [&] {
                for (const auto &relay: params.relays) {
                    switch (relay.index()) {
                        case 0: {
                            const auto &ra = std::get<cardano::relay_addr>(relay);
                            array(4).uint(0);
                            if (ra.port)
                                uint(*ra.port);
                            else
                                s_null();
                            if (ra.ipv4)
                                bytes(*ra.ipv4);
                            else
                                s_null();
                            if (ra.ipv6)
                                bytes(*ra.ipv6);
                            else
                                s_null();
                            break;
                        }
                        case 1: {
                            const auto &rh = std::get<cardano::relay_host>(relay);
                            array(3).uint(1);
                            if (rh.port)
                                uint(*rh.port);
                            else
                                s_null();
                            text(rh.host);
                            break;
                        }
                        case 2: {
                            const auto &rd = std::get<cardano::relay_dns>(relay);
                            array(2).uint(2).text(rd.name);
                            break;
                        }
                        default:
                            throw error("unsupported relay variant index: {}", relay.index());
                    }
                }
            });
            if (params.metadata)
                array(2).text(params.metadata->url).bytes(params.metadata->hash);
            else
                s_null();
        }
    };

    size_t parallel_serializer::size() const
    {
        return _tasks.size();
    }

    void parallel_serializer::add(const task &t)
    {
        _tasks.emplace_back(t);
        _buffers.emplace_back();
    }

    void parallel_serializer::add(const task_cbor &t)
    {
        add([t] {
            state_encoder enc {};
            t(enc);
            return enc.cbor();
        });
    }

    void parallel_serializer::run(scheduler &sched, const std::string &task_group, const int prio, const bool report_progress)
    {
        sched.wait_all_done(task_group, _tasks.size(),
            [&] {
                for (size_t i = 0; i < _tasks.size(); ++i) {
                    sched.submit_void(task_group, prio, [this, i] {
                        _buffers[i] = _tasks[i]();
                    });
                }
            },
            [this, &task_group, report_progress](auto &&, auto done, auto errs) {
                if (report_progress)
                    progress::get().update(task_group, done - errs, _tasks.size() + 1);
            }
        );
    }

    void parallel_serializer::save(const std::string &path, const bool headers) const
    {
        const auto tmp_path = fmt::format("{}.tmp", path);
        timer t { fmt::format("writing serialized data to {}", path), logger::level::debug };
        {
            file::write_stream ws { tmp_path };
            // first write the block sizes to allow parallel load
            if (headers) {
                ws.write(buffer::from<size_t>(_buffers.size()));
                for (const auto &buf: _buffers)
                    ws.write(buffer::from<size_t>(buf.size()));
            }
            // then write the actual data
            for (const auto &buf: _buffers)
                ws.write(buf);
        }
        // ensures the correct file exists only if the whole saving procedure is successful
        std::filesystem::rename(tmp_path, path);
    }

    uint8_vector parallel_serializer::flat() const
    {
        uint8_vector res {};
        for (const auto &buf: _buffers)
            res << buf;
        return res;
    }

    static uint8_vector _parse_address(const buffer buf)
    {
        cardano::address addr { buf };
        if (addr.bytes()[0] == 0x82)
            return cbor::parse(addr.bytes()).at(0).tag().second->buf();
        return buf;
    }

    static rational_u64 _parse_rational(const cbor_array &r)
    {
        return { r.at(0).uint(), r.at(1).uint() };
    }

    static rational_u64 _parse_rational(const cbor_value &val)
    {
        return _parse_rational(val.tag().second->array());
    }

    static void _parse_assets(cardano::tx_out_data &data, const cardano::tx_out_ref &id, const cbor_value &val)
    {
        switch (val.type) {
            case CBOR_UINT:
                data.coin = val.uint();
                break;
            case CBOR_ARRAY:
                data.coin = val.at(0).uint();
                data.assets.emplace(val.at(1).raw_span());
                break;
            default:
                throw error("unexpected type of txo_data amount: {} in {}", val, id);
        }
    }

    static void _parse_shelley_params(cardano::protocol_params &params, const cbor_value &val)
    {
        params.min_fee_a = val.at(0).uint();
        params.min_fee_b = val.at(1).uint();
        params.max_block_body_size = val.at(2).uint();
        params.max_transaction_size = val.at(3).uint();
        params.max_block_header_size = val.at(4).uint();
        params.key_deposit = val.at(5).uint();
        params.pool_deposit = val.at(6).uint();
        params.e_max = val.at(7).uint();
        params.n_opt = val.at(8).uint();
        params.pool_pledge_influence = _parse_rational(val.at(9));
        params.expansion_rate = _parse_rational(val.at(10));
        params.treasury_growth_rate = _parse_rational(val.at(11));
        params.decentralization = _parse_rational(val.at(12));
        switch (val.at(13).at(0).uint()) {
            case 0: params.extra_entropy.reset(); break;
            case 1: params.extra_entropy.emplace(val.at(13).at(1).buf()); break;
            default: throw error("unexpected value for extra_entropy: {}", val.at(13));
        }
        params.protocol_ver.major = val.at(14).uint();
        params.protocol_ver.minor = val.at(15).uint();
        params.min_utxo_value = val.at(16).uint();
    }

    static void _parse_alonzo_params(cardano::protocol_params &params, const cardano::config &cfg, const cbor_value &val)
    {
        params.min_fee_a = val.at(0).uint();
        params.min_fee_b = val.at(1).uint();
        params.max_block_body_size = val.at(2).uint();
        params.max_transaction_size = val.at(3).uint();
        params.max_block_header_size = val.at(4).uint();
        params.key_deposit = val.at(5).uint();
        params.pool_deposit = val.at(6).uint();
        params.e_max = val.at(7).uint();
        params.n_opt = val.at(8).uint();
        params.pool_pledge_influence = _parse_rational(val.at(9));
        params.expansion_rate = _parse_rational(val.at(10));
        params.treasury_growth_rate = _parse_rational(val.at(11));
        params.decentralization = _parse_rational(val.at(12));
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
                    params.plutus_cost_models.v1 = cardano::plutus_cost_model::from_cbor(cfg.plutus_v1_cost_model, values.array());
                    break;
                break;
                default:
                    throw error("unsupported cost model id: {}", model_id);
            }
        }
        params.ex_unit_prices = {
            _parse_rational(val.at(19).at(0)),
            _parse_rational(val.at(19).at(1))
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

    static void _parse_babbage_params(cardano::protocol_params &params, const cardano::config &cfg, const cbor_value &val)
    {
        params.min_fee_a = val.at(0).uint();
        params.min_fee_b = val.at(1).uint();
        params.max_block_body_size = val.at(2).uint();
        params.max_transaction_size = val.at(3).uint();
        params.max_block_header_size = val.at(4).uint();
        params.key_deposit = val.at(5).uint();
        params.pool_deposit = val.at(6).uint();
        params.e_max = val.at(7).uint();
        params.n_opt = val.at(8).uint();
        params.pool_pledge_influence = _parse_rational(val.at(9));
        params.expansion_rate = _parse_rational(val.at(10));
        params.treasury_growth_rate = _parse_rational(val.at(11));
        params.protocol_ver.major = val.at(12).uint();
        params.protocol_ver.minor = val.at(13).uint();
        params.min_pool_cost = val.at(14).uint();
        params.lovelace_per_utxo_byte = val.at(15).uint();
        for (const auto &[model_id, values]: val.at(16).map()) {
            switch (model_id.uint()) {
                case 0:
                    params.plutus_cost_models.v1 = cardano::plutus_cost_model::from_cbor(cfg.plutus_v1_cost_model, values.array());
                    break;
                case 1:
                    params.plutus_cost_models.v2 = cardano::plutus_cost_model::from_cbor(cfg.plutus_v2_cost_model, values.array());
                break;
                default:
                    throw error("unsupported cost model id: {}", model_id);
            }
        }
        params.ex_unit_prices = {
            _parse_rational(val.at(17).at(0)),
            _parse_rational(val.at(17).at(1))
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

    static cardano::stake_ident _parse_stake_ident(const cbor_value &id)
    {
        return { id.at(1).buf(), id.at(0).uint() == 1 };
    }

    void state::_parse_protocol_params(cardano::protocol_params &params, const uint64_t era, const cbor_value &values)
    {
        if (era >= 2)
            _apply_shelley_params(params, _cfg);
        if (era >= 5)
            _apply_alonzo_params(params, _cfg);
        if (era >= 6)
            _apply_babbage_params(params, _cfg);
        switch (era) {
            case 2:
            case 3:
            case 4:
                return _parse_shelley_params(params, values);
            case 5:
                return _parse_alonzo_params(params, _cfg, values);
            case 6:
                return _parse_babbage_params(params, _cfg, values);
            default:
                throw error("unsupported era: {}", era);
        }
    }

    void state::_node_load_delegation_state(const cbor::value &s)
    {
        {
            const auto &dstate = s.at(2).array();
            for (const auto &[id, cred]: dstate.at(0).at(0).map()) {
                const cardano::stake_ident stake_id = _parse_stake_ident(id);
                // credential.deposit 0.1
                auto &acc = _accounts[stake_id];
                acc.reward = cred.at(0).at(0).at(0).uint();
                acc.deposit = cred.at(0).at(0).at(1).uint();
                const auto &cred_ptr = cred.at(1).at(0).array();
                cardano::stake_pointer stake_ptr { cred_ptr.at(0).uint(), cred_ptr.at(1).uint(), cred_ptr.at(2).uint() };
                acc.ptr = stake_ptr;
                _ptr_to_stake.try_emplace(stake_ptr, stake_id);
                const auto &deleg_ptr = cred.at(2).array();
                if (!deleg_ptr.empty())
                    _accounts[stake_id].deleg = deleg_ptr.at(0).buf();
            }
            // pointers - contains a reverse map already read
            for (const auto &[id, meta]: dstate.at(1).map()) {
                _future_shelley_delegs[id.buf()] = cardano::shelley_delegate {
                    meta.at(0).buf(),
                    meta.at(1).buf()
                };
            }
            for (const auto &[id, meta]: dstate.at(2).map()) {
                _shelley_delegs[id.buf()] = cardano::shelley_delegate {
                    meta.at(0).buf(),
                    meta.at(1).buf()
                };
            }
            for (const auto &[id, coin]: dstate.at(3).at(0).map()) {
                _instant_rewards_reserves.try_emplace(_parse_stake_ident(id), coin.uint());
            }
            for (const auto &[id, coin]: dstate.at(3).at(1).map()) {
                _instant_rewards_treasury.try_emplace(_parse_stake_ident(id), coin.uint());
            }
        }
        {
            const auto &pstate = s.at(1).array();
            for (const auto &[id, params]: pstate.at(0).map()) {
                _active_pool_params.try_emplace(id.buf(), pool_params_from_cbor(params));
            }
            for (const auto &[id, params]: pstate.at(1).map()) {
                _future_pool_params[id.buf()] = pool_params_from_cbor(params);
            }
            for (const auto &[id, epoch]: pstate.at(2).map()) {
                _pools_retiring.try_emplace(id.buf(), epoch.uint());
            }
            for (const auto &[id, deposit]: pstate.at(3).map()) {
                const cardano::pool_hash pool_id = id.buf();
                _pool_deposits[pool_id] = deposit.uint();
            }
        }
    }

    void state::_node_load_utxo_state(const cbor::value &utxo_state)
    {
        for (const auto &[txo_id, txo_data]: utxo_state.at(0).map()) {
            cardano::tx_out_ref id { txo_id.at(0).buf(), txo_id.at(1).uint() };
            cardano::tx_out_data data {};
            switch (txo_data.type) {
                case CBOR_ARRAY:
                    data.address = _parse_address(txo_data.at(0).buf());
                    _parse_assets(data, id, txo_data.at(1));
                    if (txo_data.array().size() > 2)
                        data.datum.emplace(cardano::datum_hash { txo_data.at(2).buf() });
                    break;
                case CBOR_MAP:
                    for (const auto &[val_id, val]: txo_data.map()) {
                        switch (val_id.uint()) {
                            case 0:
                                data.address = _parse_address(val.buf());
                                break;
                            case 1:
                                _parse_assets(data, id, val);
                                break;
                            case 2:
                                switch (val.at(0).uint()) {
                                    case 0:
                                        data.datum.emplace(cardano::datum_hash { val.at(1).buf() });
                                        break;
                                    case 1:
                                        data.datum.emplace(uint8_vector { val.at(1).tag().second->buf() });
                                        break;
                                    default:
                                        throw error("unexpected format of datum_option in {}: {}", id, val);
                                }
                                break;
                            case 3:
                                data.script_ref.emplace(val.tag().second->buf());
                                break;
                            default:
                                throw error("unexpected value of txo_data map {} in {} {}", val_id, id, txo_data);
                        }
                    }
                    break;
                default:
                    throw error("unexpected txo_data value: {}", txo_data);
            }
            utxo_add(id, std::move(data));
        }
        _deposited = utxo_state.at(1).uint();
        _fees_utxo = utxo_state.at(2).uint();
        for (const auto &[gen_deleg_id, proposal]: utxo_state.at(3).at(0).map()) {
            _ppups[gen_deleg_id.buf()] = parse_param_update(_eras.size(), proposal, _cfg);
        }
        for (const auto &[gen_deleg_id, proposal]: utxo_state.at(3).at(1).map()) {
            _ppups_future[gen_deleg_id.buf()] = parse_param_update(_eras.size(), proposal, _cfg);
        }
        _parse_protocol_params(_params, _eras.size(), utxo_state.at(3).at(2));
        _parse_protocol_params(_params_prev, _eras.size(), utxo_state.at(3).at(3));
        for (const auto &[id_raw, coin]: utxo_state.at(4).at(0).map()) {
            _accounts[_parse_stake_ident(id_raw)].stake = coin.uint();
        }
        for (const auto &[ptr_raw, coin]: utxo_state.at(4).at(1).map()) {
            _stake_pointers.try_emplace(_parse_stake_pointer(ptr_raw), coin.uint());
        }
    }

    void state::_node_load_vrf_state_shelley(const cbor::value &hst)
    {
        const auto &raw = hst.at(1).array().back().at(1).at(1);
        const auto last_slot = raw.at(0).at(1).uint();
        cardano::state::vrf::pool_update_map kes_counters {};
        for (const auto &[pool_id, ctr]: raw.at(1).at(0).at(0).map()) {
            const auto [it, created] = kes_counters.try_emplace(pool_id.buf(), ctr.uint());
            if (!created)
                throw error("duplicate kes counter reported for pool: {}", pool_id);
        }
        const auto nonce_lab = raw.at(1).at(0).at(1).at(1).buf();
        const auto nonce_next_epoch = raw.at(1).at(0).at(2).at(1).buf();
        const auto nonce_epoch = raw.at(1).at(1).at(0).at(1).buf();
        std::optional<vrf_nonce> prev_lab_prev_hash {};
        if (raw.at(1).at(1).at(1).at(0).uint() == 1)
            prev_lab_prev_hash = raw.at(1).at(1).at(1).at(1).buf();
        const auto lab_prev_hash = raw.at(1).at(2).at(1).buf();
        _vrf_state.set(nonce_epoch, nonce_lab, nonce_next_epoch, lab_prev_hash, prev_lab_prev_hash,
            last_slot, std::move(kes_counters));
    }

    void state::_node_load_vrf_state_babbage(const cbor::value &hst)
    {
        const auto &raw = hst.at(1).array().back().at(1).at(1);
        const auto last_slot = raw.at(0).at(1).uint();
        cardano::state::vrf::pool_update_map kes_counters {};
        for (const auto &[pool_id, ctr]: raw.at(1).map()) {
            const auto [it, created] = kes_counters.try_emplace(pool_id.buf(), ctr.uint());
            if (!created)
                throw error("duplicate kes counter reported for pool: {}", pool_id);
        }
        const auto nonce_lab = raw.at(2).at(1).buf();
        const auto nonce_next_epoch = raw.at(3).at(1).buf();
        const auto nonce_epoch = raw.at(4).at(1).buf();
        const auto lab_prev_hash = raw.at(5).at(1).buf();
        std::optional<vrf_nonce> prev_lab_prev_hash {};
        if (raw.at(6).at(0).uint() == 1)
            prev_lab_prev_hash = raw.at(6).at(1).buf();
        _vrf_state.set(nonce_epoch, nonce_lab, nonce_next_epoch, lab_prev_hash, prev_lab_prev_hash,
            last_slot, std::move(kes_counters));
    }

    void state::_node_load_vrf_state(const cbor::value &hst)
    {
        if (_eras.size() >= 6)
            _node_load_vrf_state_babbage(hst);
        else
            _node_load_vrf_state_shelley(hst);
    }

    cardano::point state::deserialize_node(const buffer &data)
    {
        cbor_parser_large p { data };
        cbor_value item {};
        p.read(item);
        const auto &eras = item.at(1).at(0).array();
        for (const auto &era: eras) {
            _eras.emplace_back(era.at(0).at(1).uint());
        }
        if (_eras.empty())
            throw error("eras cannot be empty!");
        cardano::point tip {
            eras.back().at(1).at(1).at(0).at(0).at(2).buf(),
            eras.back().at(1).at(1).at(0).at(0).at(0).uint(),
            eras.back().at(1).at(1).at(0).at(0).at(1).uint()
        };
        const auto &snap = eras.back().at(1).at(1).at(1);
        _epoch = snap.at(0).uint();
        for (const auto &[pool_hash, block_count]: snap.at(1).map()) {
            _blocks_before.add(pool_hash.buf(), block_count.uint());
        }
        for (const auto &[pool_hash, block_count]: snap.at(2).map()) {
            _blocks_current.add(pool_hash.buf(), block_count.uint());
        }
        {
            const auto &state_before = snap.at(3);
            {
                const auto &accounts = state_before.at(0).array();
                _treasury = accounts.at(0).uint();
                _reserves = accounts.at(1).uint();
            }
            {
                const auto &lstate = state_before.at(1);
                _node_load_delegation_state(lstate.at(0));
                _node_load_utxo_state(lstate.at(1));
            }
            {
                const auto &snapshots = state_before.at(2).array();
                struct snapshot_copy {
                    size_t idx;
                    ledger_copy &dst_copy;
                };
                for (const auto &[idx, dst]: { snapshot_copy { 0, _mark }, snapshot_copy { 1, _set }, snapshot_copy { 2, _go } }) {
                    const auto &src = snapshots.at(idx).array();
                    const auto &stake = src.at(0).map();
                    for (const auto &[stake_id, coin]: stake) {
                        auto &acc = _accounts[cardano::stake_ident {stake_id.array().at(1).buf(), stake_id.array().at(0).uint() == 1 }];
                        acc.stake_copy(idx) = coin.uint();
                    }
                    for (const auto &[stake_id, pool_id]: src.at(1).map()) {
                        auto &acc = _accounts[cardano::stake_ident {stake_id.array().at(1).buf(), stake_id.array().at(0).uint() == 1 }];
                        acc.deleg_copy(idx) = pool_id.buf();
                    }
                    for (const auto &[id, params]: src.at(2).map()) {
                        dst.pool_params.try_emplace(id.buf(), pool_params_from_cbor(params));
                    }
                }
                //_fees_next_reward = snapshots.at(3).uint();
            }
            for (const auto &[pool_id, c_likelihoods]: state_before.at(3).at(0).map()) {
                pool_rank::likelihood_list likelihoods {};
                likelihoods.reserve(c_likelihoods.array().size());
                for (const auto &c_like: c_likelihoods.array())
                    likelihoods.emplace_back(c_like.float32());
                _nonmyopic.try_emplace(pool_id.buf(), std::move(likelihoods));
            }
            _nonmyopic_reward_pot = state_before.at(3).at(1).uint();
        }
        if (const auto &possible_update_raw = snap.at(4).array(); !possible_update_raw.empty()) {
            if (possible_update_raw.at(0).at(0).uint() == 1) {
                const auto &possible_update = possible_update_raw.at(0).at(1).array();
                _delta_treasury = possible_update.at(0).uint();
                _delta_reserves = possible_update.at(1).uint();
                _delta_fees = possible_update.at(3).uint();
                for (const auto &[id, reward_list]: possible_update.at(2).map()) {
                    reward_update_list rl {};
                    for (const auto &reward: reward_list.array()) {
                        rl.emplace(reward.at(0).uint() == 0 ? reward_type::member : reward_type::leader, reward.at(1).buf(),  reward.at(2).uint());
                    }
                    _potential_rewards.try_emplace(cardano::stake_ident { id.array().at(1).buf(), id.array().at(0).uint() == 1 }, std::move(rl));
                }
                for (const auto &[pool_id, c_likelihoods]: possible_update.at(4).at(0).map()) {
                    pool_rank::likelihood_list likelihoods {};
                    likelihoods.reserve(c_likelihoods.array().size());
                    for (const auto &c_like: c_likelihoods.array())
                        likelihoods.emplace_back(c_like.float32());
                    _nonmyopic_next.try_emplace(pool_id.buf(), std::move(likelihoods));
                }
                _reward_pot = possible_update.at(4).at(1).uint();
            }
        }
        {
            for (const auto &[pool_id, info]: snap.at(5).map()) {
                _operating_stake_dist.try_emplace(pool_id.buf(), _parse_rational(info.at(0).array()), info.at(1).buf());
            }
        }
        {
            // const auto &tbd = snap.at(6); NULL
        }
        _blocks_past_voting_deadline = eras.back().at(1).at(1).at(2).uint();
        _node_load_vrf_state(item.at(1).at(1));
        _recompute_caches();
        return tip;
    }

    cardano::point state::load_node(const std::string &path)
    {
        _utxo.clear(); // drop the default values
        const auto buf = file::read(path);
        return deserialize_node(buf);
    }

    void state::_node_save_params_shelley(state_encoder &enc, const cardano::protocol_params &params) const
    {
        enc.array(18);
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
        enc.uint(params.min_utxo_value);
        enc.uint(params.min_pool_cost);
    }

    void state::_node_save_params_alonzo(state_encoder &enc, const cardano::protocol_params &params) const
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
        enc.encode(params.plutus_cost_models);
        enc.array(2)
            .rational(params.ex_unit_prices.mem)
            .rational(params.ex_unit_prices.steps);
        enc.array(2).uint(params.max_tx_ex_units.mem).uint(params.max_tx_ex_units.steps);
        enc.array(2).uint(params.max_block_ex_units.mem).uint(params.max_block_ex_units.steps);
        enc.uint(params.max_value_size);
        enc.uint(params.max_collateral_pct);
        enc.uint(params.max_collateral_inputs);
    }

    void state::_node_save_params_babbage(state_encoder &enc, const cardano::protocol_params &params) const
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
        enc.encode(params.plutus_cost_models);
        enc.array(2)
            .rational(params.ex_unit_prices.mem)
            .rational(params.ex_unit_prices.steps);
        enc.array(2).uint(params.max_tx_ex_units.mem).uint(params.max_tx_ex_units.steps);
        enc.array(2).uint(params.max_block_ex_units.mem).uint(params.max_block_ex_units.steps);
        enc.uint(params.max_value_size);
        enc.uint(params.max_collateral_pct);
        enc.uint(params.max_collateral_inputs);
    }

    void state::_node_save_params(state_encoder &enc, const cardano::protocol_params &params) const
    {
        switch (_eras.size()) {
            case 2:
            case 3:
            case 4:
                return _node_save_params_shelley(enc, params);
            case 5:
                return _node_save_params_alonzo(enc, params);
            case 6:
                return _node_save_params_babbage(enc, params);
            default:
                throw error("unsupported era: {}", _eras.size());
        }
    }

    void state::_node_save_snapshots(parallel_serializer &ser) const
    {
        const vector<std::reference_wrapper<const ledger_copy>> snaps { _mark, _set, _go };
        ser.add([snaps] (auto &enc) {
            enc.array(snaps.size() + 1);
        });
        for (size_t idx = 0; idx < snaps.size(); ++idx) {
            const auto &snap = snaps.at(idx).get();
            ser.add([this, snap, idx] (auto &enc) {
                enc.array(3);
                // Only the stake of delegated stake_ids is of interest
                size_t num_delegs = 0;
                state_encoder enc_deleg_s {}, enc_deleg_k {}, enc_stake_s {}, enc_stake_k {};
                for (const auto &[stake_id, acc]: _accounts) {
                    const auto &deleg = acc.deleg_copy(idx);
                    if (deleg) {
                        ++num_delegs;
                        {
                            auto &i_enc = stake_id.script ? enc_stake_s : enc_stake_k;
                            i_enc.encode(stake_id);
                            i_enc.uint(acc.stake_copy(idx));
                        }
                        {
                            auto &i_enc = stake_id.script ? enc_deleg_s : enc_deleg_k;
                            i_enc.encode(stake_id);
                            i_enc.bytes(*deleg);
                        }
                    }
                }
                enc.map_compact(num_delegs, [&] {
                    enc << enc_stake_s << enc_stake_k;
                });
                enc.map_compact(num_delegs, [&] {
                    enc << enc_deleg_s << enc_deleg_k;
                });
                enc.map_compact(snap.pool_params.size(), [&] {
                    for (const auto &[pool_id, params]: snap.pool_params) {
                        enc.bytes(pool_id);
                        enc.encode(pool_id, params);
                    }
                });
            });
        }
        ser.add([this] (auto &enc) {
            enc.uint(_delta_fees);
        });
    }

    void state::_node_save_ledger_delegation(parallel_serializer &ser) const
    {
        ser.add([this] (auto &enc) {
            enc.array(3);
            // unidentified - always empty??
            enc.array(3).map(0).map(0).uint(0);
            // poolState
            enc.array(4);
            enc.map_compact(_active_pool_params.size(), [&] {
                for (const auto &[pool_id, params]: _active_pool_params) {
                    enc.bytes(pool_id);
                    enc.encode(pool_id, params);
                }
            });
            enc.map_compact(_future_pool_params.size(), [&] {
                for (const auto &[pool_id, params]: _future_pool_params) {
                    enc.bytes(pool_id);
                    enc.encode(pool_id, params);
                }
            });
            enc.map_compact(_pools_retiring.size(), [&] {
                for (const auto &[pool_id, epoch]: _pools_retiring) {
                    enc.bytes(pool_id);
                    enc.uint(epoch);
                }
            });
            enc.map_compact(_pool_deposits.size(), [&] {
                for (const auto &[pool_id, coin]: _pool_deposits) {
                    enc.bytes(pool_id);
                    enc.uint(coin);
                }
            });

        });
        ser.add([this] (auto &enc) {
            // delegationState
            enc.array(4);
            enc.array(2);
            state_encoder s_enc {}, k_enc {};
            size_t num_creds = 0;
            for (const auto &[stake_id, acc]: _accounts) {
                if (acc.ptr) {
                    ++num_creds;
                    auto &i_enc = stake_id.script ? s_enc : k_enc;
                    i_enc.encode(stake_id);
                    i_enc.array(4);
                    i_enc.array(1).array(2).uint(acc.reward).uint(acc.deposit);
                    i_enc.array(1);
                    i_enc.encode(*acc.ptr);
                    if (acc.deleg) {
                        i_enc.array(1).bytes(*acc.deleg);
                    } else {
                        i_enc.array(0);
                    }
                    // DRep
                    i_enc.array(0);
                }
            }
            enc.map_compact(num_creds, [&] {
                enc << s_enc << k_enc;
            });
        });
        ser.add([this] (auto &enc) {
            enc.map_compact(_ptr_to_stake.size(), [&] {
                for (const auto &[ptr, stake_id]: _ptr_to_stake) {
                    enc.encode(ptr);
                    enc.encode(stake_id);
                }
            });
        });
        ser.add([this] (auto &enc) {
            enc.map_compact(_future_shelley_delegs.size(), [&] {
                for (const auto &[key_hash, info]: _future_shelley_delegs) {
                    enc.bytes(key_hash);
                    enc.array(2).bytes(info.delegate).bytes(info.vrf);
                }
            });
            enc.map_compact(_shelley_delegs.size(), [&] {
                for (const auto &[key_hash, info]: _shelley_delegs) {
                    enc.bytes(key_hash);
                    enc.array(2).bytes(info.delegate).bytes(info.vrf);
                }
            });
            // irwd
            enc.array(4);
            enc.map_compact(_instant_rewards_reserves.size(), [&] {
                for (const auto &[stake_id, coin]: _instant_rewards_reserves) {
                    enc.encode(stake_id);
                    enc.uint(coin);
                }
            });
            enc.map_compact(_instant_rewards_treasury.size(), [&] {
                for (const auto &[stake_id, coin]: _instant_rewards_treasury) {
                    enc.encode(stake_id);
                    enc.uint(coin);
                }
            });
            enc.uint(0);
            enc.uint(0);
        });
    }

    void state::_node_save_ledger_utxo(parallel_serializer &ser) const
    {
        ser.add([](auto &enc) {
            enc.array(6);
            enc.map();
        });
        for (size_t pi = 0; pi < _utxo.num_parts; ++pi) {
            ser.add([this, pi](auto &enc) {
                const auto &part = _utxo.partition(pi);
                for (const auto &[txo_id, txo_data]: part) {
                    enc.array(2)
                        .bytes(txo_id.hash)
                        .uint(txo_id.idx);
                    enc.encode(txo_data, _eras.size());
                }
            });

        }
        ser.add([this] (auto &enc) {
            enc.s_break();
            enc.uint(_deposited);
            enc.uint(_fees_utxo);
            // ppups + pparams
            enc.array(4);
            enc.map(_ppups.size());
            for (const auto &[gen_deleg_id, proposal]: _ppups) {
                enc.bytes(gen_deleg_id);
                enc.encode(proposal, _eras.size());
            }
            enc.map(_ppups_future.size());
            for (const auto &[gen_deleg_id, proposal]: _ppups_future) {
                enc.bytes(gen_deleg_id);
                enc.encode(proposal, _eras.size());
            }
            // esParams
            _node_save_params(enc, _params);
            // esParamsPrev
            _node_save_params(enc, _params_prev);
        });
        ser.add([this] (auto &enc) {
            enc.array(2);
            // Cardano Node puts script keys first, so mimic that
            state_encoder s_enc {};
            state_encoder k_enc {};
            size_t num_accounts = 0;
            for (const auto &[stake_id, acc]: _accounts) {
                if (acc.stake) {
                    ++num_accounts;
                    auto &i_enc = stake_id.script ? s_enc : k_enc;
                    i_enc.encode(stake_id);
                    i_enc.uint(acc.stake);
                }
            }
            enc.map_compact(num_accounts, [&] {
                enc << s_enc << k_enc;
            });
        });
        ser.add([this] (auto &enc) {
            enc.map_compact(_stake_pointers.size(), [&] {
                for (const auto &[ptr, coin]: _stake_pointers) {
                    enc.encode(ptr);
                    enc.uint(coin);
                }
            });
            // unidentified - always zero?
            enc.uint(0);
        });
    }

    void state::_node_save_ledger(parallel_serializer &ser) const
    {
        ser.add([](auto &enc) {
            enc.array(2);
        });
        _node_save_ledger_delegation(ser);
        _node_save_ledger_utxo(ser);
    }

    void state::_node_save_state_before(parallel_serializer &ser) const
    {
        ser.add([this] (auto &enc) {
            enc.array(4);
            // esAccountState
            enc.array(2).uint(_treasury).uint(_reserves);
        });
        // esLState
        _node_save_ledger(ser);
        // esSnapshots
        _node_save_snapshots(ser);
        // esNonmyopic
        ser.add([this] (auto &enc) {
            enc.array(2);
            enc.map_compact(_nonmyopic.size(), [&] {
                for (const auto &[pool_id, lks]: _nonmyopic) {
                    enc.bytes(pool_id);
                    enc.array_compact(lks.size(), [&] {
                        for (const auto l: lks)
                            enc.float32(l);
                    });
                }
            });
            enc.uint(_nonmyopic_reward_pot);
        });
    }

    void state::_node_save_state(parallel_serializer &ser) const
    {
        ser.add([this](auto &enc) {
            enc.array(7);
            enc.uint(_epoch);
            for (const auto &blocks: { _blocks_before, _blocks_current }) {
                enc.map_compact(blocks.size(), [&] {
                    for (const auto &[pool_id, num_blocks]: blocks) {
                        enc.bytes(pool_id);
                        enc.uint(num_blocks);
                    }
                });
            }
        });

        // stateBefore
        _node_save_state_before(ser);
        // possibleUpdate
        if (_rewards_ready) {
            ser.add([this](auto &enc) {
                enc.array(1).array(2).uint(1).array(5);
                enc.uint(_delta_treasury);
                enc.uint(_delta_reserves);
            });
            ser.add([this](auto &enc) {
                enc.map_compact(_potential_rewards.size(), [&] {
                    state_encoder s_enc {}, k_enc {};
                    for (const auto &[stake_id, rewards]: _potential_rewards) {
                        auto &i_enc = stake_id.script ? s_enc : k_enc;
                        i_enc.encode(stake_id);
                        i_enc.array_compact(rewards.size(), [&] {
                            for (const auto &ru: rewards) {
                                i_enc.array(3).uint(ru.type == reward_type::leader ? 1 : 0).bytes(ru.pool_id).uint(ru.amount);
                            }
                        });
                    }
                    enc << s_enc << k_enc;
                });
            });
            ser.add([this](auto &enc) {
                enc.uint(_delta_fees);
                enc.array(2);
                enc.map_compact(_nonmyopic_next.size(), [&] {
                    for (const auto &[pool_id, lks]: _nonmyopic_next) {
                        enc.bytes(pool_id);
                        enc.array_compact(lks.size(), [&] {
                            for (const auto l: lks)
                                enc.float32(l);
                        });
                    }
                });
                enc.uint(_reward_pot);
            });
        } else if (!_reward_pulsing_snapshot.empty()) {
            ser.add([](auto &enc) {
                enc.array(1).array(3).uint(0);
            });
            // reward snapshot
            ser.add([](auto &enc) {
                enc.array(0);
            });
            // reward pulser
            ser.add([](auto &enc) {
                enc.array(0);
            });
        } else {
            ser.add([](auto &enc) {
                enc.array(0);
            });
        }
        // stakeDistrib
        ser.add([this](auto &enc) {
            enc.map_compact(_operating_stake_dist.size(), [&] {
                for (const auto &[pool_id, op_info]: _operating_stake_dist) {
                    enc.bytes(pool_id);
                    enc.array(2)
                        .array(2)
                            .uint(op_info.rel_stake.numerator)
                            .uint(op_info.rel_stake.denominator)
                        .bytes(op_info.vrf_vkey);
                }
            });
            enc.s_null();
        });
    }

    void state::_node_save_eras(parallel_serializer &ser, const cardano::point &tip) const
    {
        ser.add([this, tip](auto &enc) {
            enc.array(_eras.size());
            for (size_t era = 0; era < _eras.size(); ++era) {
                enc.array(2);
                enc.encode(cardano::slot { _eras[era], _cfg });
                if (era + 1 < _eras.size()) {
                    enc.encode(cardano::slot { _eras[era + 1], _cfg });
                } else {
                    enc.array(2)
                        .uint(2)
                        .array(3)
                            .array(1).array(3).uint(tip.slot).uint(tip.height).bytes(tip.hash);
                }
            }
        });
        _node_save_state(ser);
        ser.add([this] (auto &enc) {
            enc.uint(_blocks_past_voting_deadline);
        });
    }

    void state::_node_save_vrf_state_shelley(state_encoder &enc, const cardano::point &/*tip*/) const
    {
        enc.array(2)
            .uint(1)
            .array(2)
                .array(2)
                    .uint(1)
                    .uint(_vrf_state.last_slot())
                .array(3)
                    .array(3)
                        .custom([this] (auto &enc) {
                            enc.map(_vrf_state.kes_counters().size());
                            for (const auto &[pool_id, cnt]: _vrf_state.kes_counters()) {
                                enc.bytes(pool_id);
                                enc.uint(cnt);
                            }
                        })
                        .array(2)
                            .uint(1)
                            .bytes(_vrf_state.nonce_lab())
                        .array(2)
                            .uint(1)
                            .bytes(_vrf_state.nonce_next_epoch())
                    .array(2)
                        .array(2)
                            .uint(1)
                            .bytes(_vrf_state.nonce_epoch())
                        .custom([this](auto &enc) {
                            if (_vrf_state.prev_epoch_lab_prev_hash()) {
                                enc.array(2)
                                    .uint(1)
                                    .bytes(*_vrf_state.prev_epoch_lab_prev_hash());
                            } else {
                                enc.array(1).uint(0);
                            }
                        })
                    .array(2)
                        .uint(1)
                        .bytes(_vrf_state.lab_prev_hash());
    }

    void state::_node_save_vrf_state_babbage(state_encoder &enc, const cardano::point &/*tip*/) const
    {
        enc.array(2)
            .uint(0)
            .array(7)
                .array(2)
                    .uint(1)
                    .uint(_vrf_state.last_slot())
                .custom([this] (auto &enc) {
                    enc.map(_vrf_state.kes_counters().size());
                    for (const auto &[pool_id, cnt]: _vrf_state.kes_counters()) {
                        enc.bytes(pool_id);
                        enc.uint(cnt);
                    }
                })
                .array(2)
                    .uint(1)
                    .bytes(_vrf_state.nonce_lab())
                .array(2)
                    .uint(1)
                    .bytes(_vrf_state.nonce_next_epoch())
                .array(2)
                    .uint(1)
                    .bytes(_vrf_state.nonce_epoch())
                .array(2)
                    .uint(1)
                    .bytes(_vrf_state.lab_prev_hash())
                .custom([this](auto &enc) {
                    if (_vrf_state.prev_epoch_lab_prev_hash()) {
                        enc.array(2)
                            .uint(1)
                            .bytes(*_vrf_state.prev_epoch_lab_prev_hash());
                    } else {
                        enc.array(1).uint(0);
                    }
                });
    }

    void state::_node_save_vrf_state(parallel_serializer &ser, const cardano::point &tip) const
    {
        ser.add([this, tip] (auto &enc) {
            enc.array(2);
            if (!_eras.empty()) {
                enc.array(1)
                    .array(2)
                        .uint(_eras.size() - 1)
                        .array(3)
                            .uint(tip.slot)
                            .bytes(tip.hash)
                            .uint(tip.height);
            } else {
                enc.array(0);
            }
            enc.array(_eras.size());
            for (size_t era = 0; era < _eras.size(); ++era) {
                enc.array(2);
                enc.encode(cardano::slot { _eras[era], _cfg });
                if (era + 1 < _eras.size()) {
                    enc.encode(cardano::slot { _eras[era + 1], _cfg });
                } else {
                    if (_eras.size() >= 6)
                        _node_save_vrf_state_babbage(enc, tip);
                    else
                        _node_save_vrf_state_shelley(enc, tip);
                }
            }
        });
    }

    parallel_serializer state::serialize_node(const cardano::point &tip, const int prio) const
    {
        timer t { "serialize the state into the Cardano Node format", logger::level::info };
        parallel_serializer ser {};
        ser.add([] (auto &enc) {
            enc.array(2); // versioned encoding tuple
            enc.uint(1); // version number
            enc.array(2);
        });
        _node_save_eras(ser, tip);
        _node_save_vrf_state(ser, tip);
        ser.run(_sched, "ledger-export", prio, true);
        return ser;
    }

    void state::save_node(const std::string &path, const cardano::point &tip, const int prio) const
    {
        const auto ser = serialize_node(tip, prio);
        timer t { "write the serialized node state to a file", logger::level::info };
        ser.save(path, false);
        progress::get().update("ledger-export", 1, 1);
    }

    template<typename VISITOR>
    void state::_visit(const VISITOR &v)
    {
        v(_subchains);
        v(_end_offset);
        v(_epoch_slot);
        v(_eras);
        v(_vrf_state);
        v(_reward_pulsing_snapshot_slot);
        v(_reward_pulsing_snapshot);
        v(_active_pool_dist);
        v(_active_inv_delegs);

        v(_accounts);

        v(_epoch);
        v(_blocks_current);
        v(_blocks_before);

        v(_reserves);
        v(_treasury);

        v(_mark);
        v(_set);
        v(_go);
        v(_fees_next_reward);

        for (size_t pi = 0; pi < _utxo.num_parts; ++pi)
            v(_utxo.partition(pi));

        v(_deposited);
        v(_delta_fees);
        v(_fees_utxo);
        v(_ppups);
        v(_ppups_future);

        v(_ptr_to_stake);
        v(_future_shelley_delegs);
        v(_shelley_delegs);
        v(_stake_pointers);

        v(_instant_rewards_reserves);
        v(_instant_rewards_treasury);

        v(_active_pool_params);
        v(_future_pool_params);
        v(_pools_retiring);
        v(_pool_deposits);

        v(_params);
        v(_params_prev);
        v(_nonmyopic);
        v(_nonmyopic_reward_pot);

        v(_delta_treasury);
        v(_delta_reserves);
        v(_reward_pot);
        v(_potential_rewards);
        v(_rewards_ready);
        v(_nonmyopic_next);

        v(_operating_stake_dist);
        v(_blocks_past_voting_deadline);
    }

    void state::load(const std::string &path)
    {
        const auto data = file::read_raw(path);
        const auto num_bufs = data.span().subbuf(0, sizeof(size_t)).to<size_t>();
        size_t next_offset = (num_bufs + 1) * sizeof(size_t);
        vector<buffer> bufs {};
        for (size_t i = 0; i < num_bufs; ++i) {
            const auto buf_size = data.span().subbuf((i + 1) * sizeof(size_t), sizeof(size_t)).to<size_t>();
            bufs.emplace_back(data.span().subbuf(next_offset, buf_size));
            next_offset += buf_size;
        }

        using decoder_type = std::function<void(buffer)>;
        vector<decoder_type> decoders {};
        _visit([&](auto &obj) {
            decoders.emplace_back([&](const auto b) {
                zpp::deserialize(obj, b);
            });
        });
        if (decoders.size() != bufs.size())
            throw error("was expecting {} items in the serialized data but got {}!", decoders.size(), bufs.size());

        static const std::string task_group { "ledger-state:load-state-snapshot" };
        _sched.wait_all_done(task_group, bufs.size(), [&] {
            for (size_t i = 0; i < bufs.size(); ++i) {
                _sched.submit_void(task_group, bufs.at(i).size() * 100 / data.size(), [&, i] { decoders[i](bufs.at(i)); } );
            }
        });
        _recompute_caches();
    }

    void state::save(const std::string &path)
    {
        parallel_serializer ser {};
        _visit([&](auto &obj) {
            ser.add([&] {
                return zpp::serialize(obj);
            });
        });
        ser.run(_sched, "ledger-state:save-state-snapshot");
        ser.save(path, true);
    }

    void state::clear()
    {
        _visit([&](auto &o) {
            if constexpr (Clearable<decltype(o)>) {
                o.clear();
            } else if constexpr (std::is_same_v<decltype(o), bool>) {
                o = false;
            } else {
                o = 0;
            }
        });

        // set the defaults
        _utxo = _cfg.byron_utxos;
        _params = _default_params(_cfg);
        _params_prev = _default_params(_cfg);
        _shelley_delegs = _cfg.shelley_delegates;
        _recompute_caches();
    }
}