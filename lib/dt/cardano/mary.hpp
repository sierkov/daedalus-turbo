/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_MARY_HPP
#define DAEDALUS_TURBO_CARDANO_MARY_HPP

#include <dt/cardano/common.hpp>
#include <dt/cardano/shelley.hpp>
#include <dt/cbor.hpp>
#include <dt/ed25519.hpp>

namespace daedalus_turbo::cardano::mary {
    struct tx;

    struct block: public shelley::block {
        using shelley::block::block;

        void foreach_tx(const std::function<void(const cardano::tx &)> &observer) const override;
    };

    struct tx: public shelley::tx {
        using shelley::tx::tx;

        void foreach_output(const std::function<void(const cardano::tx_output &)> &observer) const override
        {
            const cbor_array *outputs = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 1) outputs = &entry.array();
            }
            if (outputs == nullptr) return;
            for (size_t i = 0; i < outputs->size(); i++) {
                if (outputs->at(i).type != CBOR_ARRAY) throw cardano_error("slot: {}, era: {}, unsupported tx output format!", _blk.slot(), _blk.era());
                const auto &out = outputs->at(i).array();
                _extract_assets(out.at(0), out.at(1), i, observer);
            }
        }

        virtual void foreach_mint(const std::function<void(const cbor_buffer &, const cbor_map &)> &observer) const
        {
            const cbor_map *mint = nullptr;
            for (const auto &[entry_type, entry]: _tx.map()) {
                if (entry_type.uint() == 9) mint = &entry.map();
            }
            if (mint == nullptr) return;
            for (const auto &[policy_id, assets]: *mint) {
                observer(policy_id.buf(), assets.map());
            }
        }
    protected:
        static void _extract_assets(const cbor_value &address, const cbor_value &value, size_t idx, const std::function<void(const cardano::tx_output &)> &observer)
        {
            if (value.type == CBOR_UINT) {
                observer(tx_output { address.buf(), cardano::amount { value.uint() }, idx });
            } else {
                observer(tx_output { address.buf(), cardano::amount { value.array().at(0).uint() }, idx, &value.array().at(1).map() });
            }
        }
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