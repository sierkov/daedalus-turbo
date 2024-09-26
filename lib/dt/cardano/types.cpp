/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/base64.hpp>
#include <dt/cardano/types.hpp>
#include <dt/cardano/config.hpp>
#include <dt/cbor/zero.hpp>

namespace daedalus_turbo::cardano {
    using namespace crypto;

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