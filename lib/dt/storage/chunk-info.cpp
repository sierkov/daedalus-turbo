/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/crypto/crc32.hpp>
#include <dt/storage/chunk-info.hpp>

namespace daedalus_turbo::storage {
    block_info block_info::from_block(const cardano::block_base &blk)
    {
        return {
            blk.hash(), blk.offset(), blk.size(),
            narrow_cast<uint32_t>(blk.slot()),
            narrow_cast<uint32_t>(blk.height ()),
            crypto::crc32::digest(blk.raw_data()),
            blk.issuer_hash(),
            narrow_cast<uint16_t>(blk.header_raw_data().size()),
            narrow_cast<uint8_t>(blk.header_raw_data().data() - blk.raw_data().data()),
            narrow_cast<uint8_t>(blk.era())
        };
    }
}
