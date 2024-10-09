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

    struct stored_txo {
        cardano::tx_out_ref id {};
        cardano::tx_out_data data {};
    };
    using stored_txo_list = vector<stored_txo>;

    struct stored_tx_context {
        cardano::tx_hash tx_id {};
        uint8_vector body {};
        uint8_vector wits {};
        storage::block_info block {};
        stored_txo_list inputs {};
        stored_txo_list ref_inputs {};

        bool operator<(const stored_tx_context &o) const
        {
            return tx_id < o.tx_id;
        }
    };

    struct context {
        using datum_map = map<cardano::datum_hash, data>;

        context(const std::string &, const cardano::config &c_cfg=cardano::config::get());
        context(stored_tx_context &&, const cardano::config &c_cfg=cardano::config::get());
        context(uint8_vector &&tx_body_data, uint8_vector &&tx_wits_data, storage::block_info &&block,
            stored_txo_list &&inputs, stored_txo_list &&ref_inputs, const cardano::config &c_cfg=cardano::config::get());
        const cardano::tx &tx() const;
        buffer mint_at(uint64_t r_idx) const;
        const stored_txo &input_at(uint64_t r_idx) const;
        term_ptr data(allocator &alloc, cardano::script_type typ, const purpose &) const;

        const cardano::config &config() const
        {
            return _cfg;
        }

        const datum_map &datums() const
        {
            return _datums;
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
        stored_txo_list _ref_inputs;
        datum_map _datums {};
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::plutus::stored_txo>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out())
        {
            return fmt::format_to(ctx.out(), "txo-id: {} txo-data: {}", v.id, v.data);
        }
    };

    template<>
    struct formatter<daedalus_turbo::plutus::stored_tx_context>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out())
        {
            using namespace daedalus_turbo;
            return fmt::format_to(ctx.out(), "txo-id: {} body: {} wits: {} block at slot: {} inputs: {} ref_inputs: {}",
                v.tx_id, blake2b<blake2b_256_hash>(v.body), blake2b<blake2b_256_hash>(v.wits), v.block.slot, v.inputs, v.ref_inputs);
        }
    };
}

#endif //DAEDALUS_TURBO_PLUTUS_CONTEXT_HPP