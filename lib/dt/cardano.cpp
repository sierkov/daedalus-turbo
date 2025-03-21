/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>

namespace daedalus_turbo::cardano {
    header_container make_header(cbor::zero2::value &block_tuple, const config &cfg)
    {
        return { block_tuple, cfg };
    }

    block_container make_block(cbor::zero2::value &block_tuple, uint64_t offset, const config &cfg)
    {
        return { offset, block_tuple, cfg };
    }
}