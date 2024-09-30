/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_MOCKS_HPP
#define DAEDALUS_TURBO_CARDANO_MOCKS_HPP

#include <dt/cardano/common.hpp>
#include <dt/storage/chunk-info.hpp>

namespace daedalus_turbo::cardano::mocks {
    struct block: block_base {
        block(const storage::block_info &block_meta, const cbor_value &tx, const uint64_t tx_offset, const cardano::config &cfg):
            block_base { tx, block_meta.offset, block_meta.era, tx, cfg }, _block_meta { block_meta }, _tx { tx }, _tx_offset { tx_offset }
        {
        }

        cardano_hash_32 hash() const override
        {
            throw cardano_error("internal error: hash() unsupported for failure blocks!");
        }

        buffer prev_hash() const override
        {
            throw cardano_error("internal error: prev_hash() unsupported for failure blocks!");
        }

        uint64_t height() const override
        {
            throw cardano_error("internal error: height() unsupported for failure blocks!");
        }

        uint64_t slot() const override
        {
            return _block_meta.slot;
        }

        uint64_t value_offset(const cbor_value &v) const override
        {
            if (&v != &_tx)
                throw cardano_error("internal error: value_offset can be computed only for the referenced tx value!");
            return _tx_offset;
        }
    private:
        const storage::block_info &_block_meta;
        const cbor_value &_tx;
        uint64_t _tx_offset;
    };
}

#endif // !DAEDALUS_TURBO_CARDANO_MOCKS_HPP