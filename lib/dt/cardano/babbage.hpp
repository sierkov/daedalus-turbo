/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_BABBAGE_HPP
#define DAEDALUS_TURBO_CARDANO_BABBAGE_HPP

#include <dt/cardano/common.hpp>
#include <dt/cardano/alonzo.hpp>
#include <dt/cbor.hpp>
#include <dt/ed25519.hpp>

namespace daedalus_turbo::cardano::babbage {
    struct tx;

    struct block: public alonzo::block {
        using alonzo::block::block;

        void foreach_tx(const std::function<void(const cardano::tx &)> &observer) const override;
        void foreach_invalid_tx(const std::function<void(const cardano::tx &)> &observer) const override;

        const protocol_version protocol_ver() const override
        {
            const auto &pv = header_body().at(9).array();
            return protocol_version { pv.at(0).uint(), pv.at(1).uint() };
        }
    };

    struct tx: public alonzo::tx {
        using alonzo::tx::tx;
    };

    inline void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        if (txs.size() != wits.size())
            throw error("slot: {}, the number of transactions {} does not match the number of witnesses {}", (uint64_t)slot(), txs.size(), wits.size());
        std::set<size_t> invalid_tx_idxs {};
        for (const auto &tx_idx: invalid_transactions())
            invalid_tx_idxs.emplace(tx_idx.uint());
        for (size_t i = 0; i < txs.size(); ++i)
            if (!invalid_tx_idxs.contains(i))
                observer(tx { txs.at(i), *this, &wits.at(i), i });
    }

    inline void block::foreach_invalid_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        if (txs.size() != wits.size())
            throw error("slot: {}, the number of transactions {} does not match the number of witnesses {}", (uint64_t)slot(), txs.size(), wits.size());
        for (const auto &tx_idx: invalid_transactions())
            observer(tx { txs.at(tx_idx.uint()), *this, &wits.at(tx_idx.uint()), tx_idx.uint() });
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_BABBAGE_HPP