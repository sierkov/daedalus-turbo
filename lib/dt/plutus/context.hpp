/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PLUTUS_CONTEXT_HPP
#define DAEDALUS_TURBO_PLUTUS_CONTEXT_HPP

#include <dt/cardano/mocks.hpp>
#include <dt/plutus/types.hpp>
#include <dt/plutus/costs.hpp>

namespace daedalus_turbo::plutus {
    struct stored_txo {
        cardano::tx_out_ref id {};
        cardano::tx_out_data data {};
    };
    using stored_txo_list = vector<stored_txo>;

    struct stored_tx_context {
        cardano::tx_hash tx_id {};
        uint8_vector body {};
        uint8_vector wits {};
        uint8_vector aux {};
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
        context(uint8_vector &&tx_body_data, uint8_vector &&tx_wits_data, uint8_vector &&tx_aux_data, storage::block_info &&block,
            stored_txo_list &&inputs, stored_txo_list &&ref_inputs, const cardano::config &c_cfg=cardano::config::get());
        const cardano::tx &tx() const;
        buffer mint_at(uint64_t r_idx) const;
        cardano::stake_ident_hybrid withdraw_at(uint64_t r_idx) const;
        const stored_txo &input_at(uint64_t r_idx) const;
        term data(cardano::script_type typ, const cardano::tx_redeemer &) const;

        const cardano::config &config() const
        {
            return _cfg;
        }

        void cost_models(const costs::parsed_models &models) {
            _cost_models = models;
        }

        const costs::parsed_models &cost_models() const
        {
            return _cost_models;
        }

        const datum_map &datums() const
        {
            return _datums;
        }

        allocator &alloc() const
        {
            return _alloc;
        }

        cardano::slot slot() const
        {
            return { _block_info.slot, _cfg };
        }

        const stored_txo_list &inputs() const
        {
            return _inputs;
        }

        const stored_txo_list &ref_inputs() const
        {
            return _ref_inputs;
        }
    private:
        mutable allocator _alloc {};
        const cardano::config &_cfg;
        std::reference_wrapper<const costs::parsed_models> _cost_models;
        uint8_vector _tx_body_bytes;
        cbor::value _tx_body_cbor;
        uint8_vector _tx_wits_bytes;
        cbor::value _tx_wits_cbor;
        uint8_vector _tx_aux_bytes;
        std::unique_ptr<cbor::value> _tx_aux_cbor {};
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