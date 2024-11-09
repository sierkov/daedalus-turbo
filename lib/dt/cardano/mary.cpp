/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/mary.hpp>

namespace daedalus_turbo::cardano::mary {
    std::optional<uint64_t> tx::validity_start() const
    {
        for (const auto &[entry_type, entry]: _tx.map()) {
            if (entry_type.uint() == 8)
                return entry.uint();
        }
        return {};
    }

    void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        for (size_t i = 0; i < txs.size(); ++i) {
            observer(tx { txs.at(i), *this, i, &wits.at(i), auxiliary_at(i) });
        }
    }
}