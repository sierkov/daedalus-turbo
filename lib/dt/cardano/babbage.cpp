/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/babbage.hpp>

namespace daedalus_turbo::cardano::babbage {
    void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        std::set<size_t> invalid_tx_idxs {};
        for (const auto &tx_idx: invalid_transactions())
            invalid_tx_idxs.emplace(tx_idx.uint());
        for (size_t i = 0; i < txs.size(); ++i)
            if (!invalid_tx_idxs.contains(i))
                observer(tx { txs.at(i), *this, i, &wits.at(i), auxiliary_at(i), false });
    }

    void block::foreach_invalid_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        std::set<size_t> invalid_tx_idxs {};
        for (const auto &tx_idx: invalid_transactions())
            invalid_tx_idxs.emplace(tx_idx.uint());
        for (size_t i = 0; i < txs.size(); ++i)
            if (invalid_tx_idxs.contains(i))
                observer(tx { txs.at(i), *this, i, &wits.at(i), auxiliary_at(i), true });
    }
}
