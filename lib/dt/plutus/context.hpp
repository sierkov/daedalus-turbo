/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_CONTEXT_HPP
#define DAEDALUS_TURBO_PLUTUS_CONTEXT_HPP

#include <dt/cardano/mocks.hpp>
#include <dt/plutus/types.hpp>

namespace daedalus_turbo::plutus {
    struct purpose {
        enum class type: uint8_t { spend, mint, certify, reward, propose, vote };
        type typ;
        uint8_t idx = 0;

        purpose(const purpose &) = default;

        purpose(const type typ_, const uint64_t idx_): typ { typ_ }, idx { _to_uint8(idx_) }
        {
        }
    private:
        static uint8_t _to_uint8(const uint64_t u)
        {
            if (u < 256) [[likely]]
                return static_cast<uint8_t>(u);
            throw error("reference index is too big: {}", u);
        }
    };

    struct resolved_input {
        const cardano::tx_out_ref &ref;
        const cardano::tx_out_data &data;
    };

    struct stored_tx_id {
        cardano::tx_hash hash {};
        uint64_t slot = 0;

        bool operator<(const stored_tx_id &o) const
        {
            return memcmp(hash.data(), o.hash.data(), hash.size()) < 0;
        }

        bool operator==(const stored_tx_id &o) const
        {
            return memcmp(hash.data(), o.hash.data(), hash.size()) == 0 && slot == o.slot;
        }
    };

    struct stored_txo {
        cardano::tx_out_ref id {};
        cardano::tx_out_data data {};
    };
    using stored_txo_list = vector<stored_txo>;

    struct stored_tx_context {
        stored_tx_id id {};
        uint8_vector body {};
        uint8_vector wits {};
        storage::block_info block {};
        stored_txo_list inputs {};
    };

    struct context {
        static context load(const std::string &path, const cardano::config &c_cfg=cardano::config::get());
        static context deserialize(buffer, const cardano::config &c_cfg=cardano::config::get());
        context(uint8_vector &&tx_body_data, uint8_vector &&tx_wits_data, storage::block_info &&block,
            stored_txo_list &&inputs, const cardano::config &c_cfg=cardano::config::get());
        const cardano::tx &tx() const;
        buffer mint_at(uint64_t r_idx) const;
        resolved_input input_at(uint64_t r_idx) const;
        term_ptr v1(const purpose &) const;
        term_ptr v2(const purpose &) const;
        term_ptr v3(const purpose &) const;

        const cardano::config &config() const
        {
            return _cfg;
        }
    private:
        const cardano::config &_cfg;
        uint8_vector _tx_body_bytes;
        cbor::value _tx_body_cbor;
        uint8_vector _tx_wits_bytes;
        cbor::value _tx_wits_cbor;
        storage::block_info _block_info;
        cardano::mocks::block _block;
        std::unique_ptr<cardano::tx> _tx;
        stored_txo_list _inputs;
    };
}

namespace std {
    template<>
    struct hash<daedalus_turbo::plutus::stored_tx_id> {
        size_t operator()(const auto &o) const noexcept
        {
            return *reinterpret_cast<const size_t *>(o.hash.data());
        }
    };
}

#endif //DAEDALUS_TURBO_PLUTUS_CONTEXT_HPP