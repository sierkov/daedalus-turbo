/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CARDANO_HPP
#define DAEDALUS_TURBO_CARDANO_HPP

#include <cstdint>
#include <dt/cbor.hpp>
#include <dt/cardano/byron.hpp>
#include <dt/cardano/shelley.hpp>
#include <dt/cardano/alonzo.hpp>
#include <dt/cardano/babbage.hpp>
#include <dt/cardano/conway.hpp>

namespace daedalus_turbo::cardano {


    inline std::unique_ptr<tx> make_tx(const cbor_value &tx, const block_base &blk, const size_t idx=0, const cbor::value *wit=nullptr, const cbor::value *aux=nullptr)
    {
        switch (blk.era()) {
        case 1:
            return std::make_unique<byron::tx>(tx, blk, idx, wit, aux);
        case 2:
        case 3:
            return std::make_unique<shelley::tx>(tx, blk, idx, wit, aux);
        case 4:
        case 5:
            return std::make_unique<alonzo::tx>(tx, blk, idx, wit, aux);
        case 6:
            return std::make_unique<babbage::tx>(tx, blk, idx, wit, aux);
        case 7:
            return std::make_unique<conway::tx>(tx, blk, idx, wit, aux);
        default:
            throw cardano_error(fmt::format("unsupported era {}!", blk.era()));
        }
    }

    inline std::unique_ptr<block_base> make_block(const cbor_value &block_tuple, uint64_t offset, const config &cfg=cardano::config::get())
    {
        uint64_t era = block_tuple.array().at(0).uint();
        const cbor_value &block = block_tuple.array().at(1);
        switch (era) {
        case 0:
            return std::make_unique<byron::boundary_block>(block_tuple, offset, era, block, cfg);
        case 1:
            return std::make_unique<byron::block>(block_tuple, offset, era, block, cfg);
        case 2:
        case 3:
            return std::make_unique<shelley::block>(block_tuple, offset, era, block, cfg);
        case 4:
        case 5:
            return std::make_unique<alonzo::block>(block_tuple, offset, era, block, cfg);
        case 6:
            return std::make_unique<babbage::block>(block_tuple, offset, era, block, cfg);
        case 7:
            return std::make_unique<conway::block>(block_tuple, offset, era, block, cfg);
        default:
            throw cardano_error(fmt::format("unsupported era {}!", era));
        }
    }
}

#endif // !DAEDALUS_TURBO_CARDANO_HPP