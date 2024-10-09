/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano/conway.hpp>

namespace daedalus_turbo::cardano::conway {
    void tx::foreach_set(const cbor_value &set_raw, const std::function<void(const cbor_value &, size_t)> &observer) const
    {
        const auto &set = (set_raw.type == CBOR_TAG ? *set_raw.tag().second : set_raw).array();
        for (size_t i = 0; i < set.size(); ++i)
            observer(set[i], i);
    }

    void tx::foreach_genesis_deleg(const std::function<void(const genesis_deleg &, size_t)> &) const
    {
        // this feature is no more available in Conway blocks
    }

    void tx::foreach_instant_reward(const std::function<void(const instant_reward &)> &) const
    {
        // this feature is no more available in Conway blocks
    }

    void tx::foreach_stake_reg(const stake_reg_observer &observer) const
    {
        _foreach_cert(0, [&observer](const auto &cert, size_t cert_idx) {
            const auto &stake_cred = cert.at(1).array();
            observer(stake_ident { stake_cred.at(1).buf(), stake_cred.at(0).uint() == 1 }, cert_idx, {});
        });
        _foreach_cert(7, [&observer](const auto &cert, size_t cert_idx) {
            const auto &stake_cred = cert.at(1).array();
            observer(stake_ident { stake_cred.at(1).buf(), stake_cred.at(0).uint() == 1 }, cert_idx, cert.at(2).uint());
        });
    }

    void tx::foreach_stake_unreg(const stake_unreg_observer &observer) const
    {
        _foreach_cert(1, [&observer](const auto &cert, size_t cert_idx) {
            const auto &stake_cred = cert.at(1).array();
            observer(stake_ident { stake_cred.at(1).buf(), stake_cred.at(0).uint() == 1 }, cert_idx, {});
        });
        _foreach_cert(8, [&observer](const auto &cert, size_t cert_idx) {
            const auto &stake_cred = cert.at(1).array();
            observer(stake_ident { stake_cred.at(1).buf(), stake_cred.at(0).uint() == 1 }, cert_idx, cert.at(2).uint());
        });
    }

    void block::foreach_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        set<size_t> invalid_tx_idxs {};
        for (const auto &tx_idx: invalid_transactions())
            invalid_tx_idxs.emplace(tx_idx.uint());
        for (size_t i = 0; i < txs.size(); ++i)
            if (!invalid_tx_idxs.contains(i))
                observer(tx { txs.at(i), *this, &wits.at(i), i });
    }

    void block::foreach_invalid_tx(const std::function<void(const cardano::tx &)> &observer) const
    {
        const auto &txs = transactions();
        const auto &wits = witnesses();
        if (const auto &inv_txs = invalid_transactions(); !inv_txs.empty()) [[unlikely]] {
            for (const auto &tx_idx: inv_txs)
                observer(tx { txs.at(tx_idx.uint()), *this, &wits.at(tx_idx.uint()), tx_idx.uint() });
        }
    }
}
