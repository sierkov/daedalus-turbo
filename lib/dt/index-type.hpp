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

#include <dt/cardano.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {

    struct __attribute__((packed)) index_tx_ptr {
        uint64_t offset:40;
        uint8_t size;
    };
    static_assert(sizeof(index_tx_ptr) == 6);

    struct __attribute__((packed)) stake_ident {
        cardano_hash_28 hash;
        bool script;

        bool operator<(const auto &b) const {
            static_assert(sizeof(*this) == 29);
            return memcmp(this, &b, sizeof(*this)) < 0;
        }
    };

    inline std::ostream &operator<<(std::ostream &os, const stake_ident &v)
    {
        os << "stake_ident(hash: " << buffer(v.hash) << ", script: " << v.script << ')';
        return os;
    }

    struct __attribute__((packed)) addr_use_item {
        uint8_t stake_addr[28];
        uint8_t tx_offset[5];
        uint8_t tx_size;

        bool operator<(const auto &b) const {
            static_assert(sizeof(*this) == 34);
            return memcmp(this, &b, sizeof(*this)) < 0;
        }
    };

    struct __attribute__((packed)) tx_use_item {
        uint8_t tx_hash[32];
        uint16_t tx_out_idx;
        uint8_t tx_offset[5];
        uint8_t tx_size;

        bool operator<(const auto &b) const {
            static_assert(sizeof(*this) == 40);
            return memcmp(this, &b, sizeof(*this)) < 0;
        }
    };

    struct __attribute__((packed)) delta_item {
        stake_ident stake_id;
        int64_t delta;

        bool operator<(const auto &b) const {
            static_assert(sizeof(*this) == 37);
            return memcmp(this, &b, sizeof(*this)) < 0;
        }
    };

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
            if (size != sizeof(*this)) throw error_fmt("invalid size of the binary data: {} bytes!", size);
            memcpy(this, data, size);
        }

        bool operator<(const auto &bi) const {
            static_assert(sizeof(*this) == 57);
            return offset < bi.offset;
        }

    };

    inline std::ostream &operator<<(std::ostream &os, const block_item &bi)
    {
        os << "block(slot: " << bi.slot << ", epoch: " << slot_to_epoch(bi.slot) << ", chain offset: " << bi.offset << ", size: " << bi.size << ')';
        return os;
    }

    inline uint8_t pack_tx_size(size_t sz)
    {
        size_t packed_sz = sz >> 8;
        if (sz & 0xFF) ++packed_sz;
        return (uint8_t)(packed_sz < 255 ? packed_sz : 255);
    }

    inline size_t unpack_tx_size(uint8_t packed_sz)
    {
        return ((size_t)packed_sz << 8);
    }

    inline void pack_offset(uint8_t *packed, size_t packed_size, uint64_t offset)
    {
        if (packed_size > sizeof(offset)) throw error_fmt("target buffer is too large: {} but must be up to {} bytes!", packed_size, sizeof(offset));
        const uint8_t *src_ptr = reinterpret_cast<const uint8_t *>(&offset);
        for (size_t i = 0; i < packed_size; ++i) {
            packed[i] = *(src_ptr + packed_size - 1 - i);
        }
    }

    inline uint64_t unpack_offset(const uint8_t *packed, size_t packed_size)
    {
        uint64_t offset = 0;
        if (packed_size > sizeof(offset)) throw error_fmt("target buffer is too large: {} but must be up to {} bytes!", packed_size, sizeof(offset));
        uint8_t *ptr = reinterpret_cast<uint8_t *>(&offset);
        for (size_t i = 0; i < packed_size; ++i) {
            *(ptr + packed_size - 1 - i) = packed[i];
        }
        return offset;
    }
}

#endif // !DAEDALUS_TURBO_INDEX_TYPE_HPP
