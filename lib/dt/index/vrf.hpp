/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_VRF_HPP
#define DAEDALUS_TURBO_INDEX_VRF_HPP

#include <dt/cardano/common.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::vrf {
    struct item {
        cardano::slot slot {};
        uint64_t era = 0;
        cardano::pool_hash pool_id {};
        cardano::block_hash prev_hash {};
        cardano_vrf_vkey vkey {};
        cardano_vrf_result leader_result {};
        cardano_vrf_proof leader_proof {};
        cardano_vrf_result nonce_result {};
        cardano_vrf_proof nonce_proof {};

        bool operator<(const auto &b) const
        {
            return slot < b.slot;
        }
    };

    struct chunk_indexer: public chunk_indexer_multi_epoch_zpp<item> {
        using chunk_indexer_multi_epoch_zpp<item>::chunk_indexer_multi_epoch_zpp;
    protected:
        void _index_epoch(const cardano::block_base &blk, std::vector<item> &idx) override
        {
            if (blk.era() >= 2) {
                auto vrf = blk.vrf();
                idx.emplace_back(blk.slot(), blk.era(), blk.issuer_hash(), blk.prev_hash(),
                    vrf.vkey, vrf.leader_result, vrf.leader_proof, vrf.nonce_result, vrf.nonce_proof);
            }
        }
    };
    using indexer = indexer_multi_epoch<item, chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_VRF_HPP