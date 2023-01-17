/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_INDEX_TYPE_HPP
#define DAEDALUS_TURBO_INDEX_TYPE_HPP

#include <cstring>
#include "util.hpp"

namespace daedalus_turbo {

    struct __attribute__((packed)) addr_use_item {
        uint8_t stake_addr[28];
        uint8_t tx_offset[5];

        bool operator<(const addr_use_item &b) const {
            return memcmp(this, &b, sizeof(*this)) < 0;
        }
    };
    static_assert(sizeof(addr_use_item) == 33);

    struct __attribute__((packed)) tx_use_item {
        uint8_t tx_hash[32];
        uint16_t tx_out_idx;
        uint8_t tx_offset[5];

        bool operator<(const tx_use_item &b) const {
            return memcmp(this, &b, sizeof(*this)) < 0;
        }
    };
    static_assert(sizeof(tx_use_item) == 39);

    struct __attribute__((packed)) block_item {
        uint64_t offset = 0;
        uint64_t fees = 0;
        uint32_t slot = 0;
        uint32_t block_number = 0;
        uint32_t size = 0;
        uint8_t era = 0;
        uint8_t pool_hash[28];

        block_item()
        {
            memset(this, 0, sizeof(*this));
        }

        block_item(uint64_t off)
            : offset(off)
        {
        }

        block_item(const uint8_t *data, size_t size)
        {
            if (size != sizeof(*this)) throw error("invalid size of the binary data: %zu bytes!", size);
            memcpy(this, data, size);
        }

        bool operator<(const block_item &bi) const {
            return offset < bi.offset;
        }

    };
    static_assert(sizeof(block_item) == 57);

    inline ostream &operator<<(ostream &os, const block_item &bi)
    {
        os << "block at slot: " << bi.slot << " chain offset: " << bi.offset << " size: " << bi.size << endl;
        return os;
    }

    inline uint64_t unpack_offset(const uint8_t *data, size_t size)
    {
        uint64_t offset = 0;
        memcpy(&offset, data, size);
        return offset;
    }
}

#endif // !DAEDALUS_TURBO_INDEX_TYPE_HPP
