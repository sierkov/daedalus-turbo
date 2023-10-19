/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_HPP
#define DAEDALUS_TURBO_CARDANO_HPP

#include <cstdint>
#include <array>
#include <functional>
#include <span>
#include <unordered_map>
#include <variant>
#include "bech32.hpp"
#include "blake2b.hpp"
#include "cbor.hpp"
#include "ed25519.hpp"
#include "file.hpp"
#include "kes.hpp"
#include "vrf.hpp"
#include "util.hpp"
#include "cardano/common.hpp"
#include "cardano/byron.hpp"
#include "cardano/mary.hpp"
#include "cardano/shelley.hpp"
#include "cardano/babbage.hpp"

namespace daedalus_turbo::cardano {
    inline std::unique_ptr<tx> make_tx(const cbor_value &tx, const cardano::block_base &blk)
    {
        switch (blk.era()) {
        case 1:
            return std::make_unique<byron::tx>(tx, blk);

        case 2:
        case 3:
            return std::make_unique<shelley::tx>(tx, blk);
        case 4:
        case 5:
            return std::make_unique<mary::tx>(tx, blk);

        case 6:
        case 7:
            return std::make_unique<babbage::tx>(tx, blk);

        default:
            throw cardano_error("unsupported era {}!", blk.era());
        }
    }

    inline std::unique_ptr<block_base> make_block(const cbor_value &block_tuple, uint64_t offset)
    {
        uint64_t era = block_tuple.array().at(0).uint();
        const cbor_value &block = block_tuple.array().at(1);
        switch (era) {
        case 0:
            return std::make_unique<byron::boundary_block>(block_tuple, offset, era, block);

        case 1:
            return std::make_unique<byron::block>(block_tuple, offset, era, block);

        case 2:
        case 3:
            return std::make_unique<cardano::shelley::block>(block_tuple, offset, era, block);

        case 4:
        case 5:
            return std::make_unique<cardano::mary::block>(block_tuple, offset, era, block);

        case 6:
        case 7:
            return std::make_unique<cardano::babbage::block>(block_tuple, offset, era, block);

        default:
            throw cardano_error("unsupported era {}!", era);
        }
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_HPP