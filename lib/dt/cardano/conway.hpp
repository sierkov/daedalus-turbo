/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_CONWAY_HPP
#define DAEDALUS_TURBO_CARDANO_CONWAY_HPP

#include <dt/cardano/babbage.hpp>

namespace daedalus_turbo::cardano::conway {
    struct block: babbage::block {
        using babbage::block::block;

        void foreach_tx(const std::function<void(const cardano::tx &)> &observer) const override;
        void foreach_invalid_tx(const std::function<void(const cardano::tx &)> &observer) const override;
    };

    struct tx: babbage::tx {
        using babbage::tx::tx;
    };

    inline void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
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
        if (const auto &inv_txs = invalid_transactions(); !inv_txs.empty()) [[unlikely]] {
            for (const auto &tx_idx: inv_txs)
                observer(tx { txs.at(tx_idx.uint()), *this, &wits.at(tx_idx.uint()), tx_idx.uint() });
        }
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_CONWAY_HPP