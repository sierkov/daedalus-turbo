/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_MARY_HPP
#define DAEDALUS_TURBO_CARDANO_MARY_HPP

#include <dt/cardano/common.hpp>
#include <dt/cardano/shelley.hpp>
#include <dt/cbor.hpp>

namespace daedalus_turbo::cardano::mary {
    struct tx;

    struct block: shelley::block {
        using shelley::block::block;

        void foreach_tx(const std::function<void(const cardano::tx &)> &observer) const override;

        bool body_hash_ok() const override
        {
            const auto &exp_hash = header_body().at(8).buf();
            auto act_hash = _calc_body_hash(_block.array(), 1, _block.array().size());
            return exp_hash == act_hash;
        }
    };

    struct tx: shelley::tx {
        using shelley::tx::tx;

        void foreach_output(const std::function<void(const cardano::tx_output &)> &observer) const override
        {
            const cbor_array *outputs = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 1)
                    outputs = &entry.array();
            }
            if (outputs == nullptr) [[unlikely]]
                return;
            for (size_t i = 0; i < outputs->size(); i++) {
                observer(tx_output::from_cbor(_blk.era(), i, outputs->at(i)));
            }
        }

        size_t foreach_mint(const std::function<void(const buffer &, const cbor::map &)> &observer) const override
        {
            const cbor_map *mint = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 9)
                    mint = &entry.map();
            }
            size_t num_mints = 0;
            if (mint) {
                for (const auto &[policy_id, assets]: *mint) {
                    ++num_mints;
                    observer(policy_id.buf(), assets.map());
                }
            }
            return num_mints;
        }

        std::optional<uint64_t> validity_start() const override;
    };

    inline void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        if (txs.size() != wits.size())
            throw error("slot: {}, the number of transactions {} does not match the number of witnesses {}", (uint64_t)slot(), txs.size(), wits.size());
        for (size_t i = 0; i < txs.size(); ++i) {
            observer(tx { txs.at(i), *this, &wits.at(i), i });
        }
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_MARY_HPP