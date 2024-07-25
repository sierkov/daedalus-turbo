/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEX_VRF_HPP
#define DAEDALUS_TURBO_INDEX_VRF_HPP

#include <dt/cardano/type.hpp>
#include <dt/index/common.hpp>

namespace daedalus_turbo::index::vrf {
    struct item {
        uint64_t slot = 0;
        uint64_t era = 0;
        uint64_t kes_counter = 0;
        cardano::protocol_version protocol_ver {};
        cardano::pool_hash pool_id {};
        cardano::block_hash prev_hash {};
        cardano::vrf_vkey vkey {};
        cardano::vrf_result leader_result {};
        cardano::vrf_proof leader_proof {};
        cardano::vrf_result nonce_result {};
        cardano::vrf_proof nonce_proof {};

        constexpr static auto serialize(auto &archive, auto &self)
        {
            return archive(self.slot, self.era, self.kes_counter, self.protocol_ver, self.pool_id, self.prev_hash,
                self.vkey, self.leader_result, self.leader_proof, self.nonce_result, self.nonce_proof);
        }

        bool operator<(const item &b) const
        {
            return slot < b.slot;
        }
    };

    struct chunk_indexer: chunk_indexer_one_epoch<item> {
        using chunk_indexer_one_epoch::chunk_indexer_one_epoch;
    protected:
        void _index_epoch(const cardano::block_base &blk, data_type &idx) override
        {
            if (blk.era() >= 2) {
                const auto vrf = blk.vrf();
                const auto kes = blk.kes();
                idx.emplace_back(blk.slot(), blk.era(), kes.counter, blk.protocol_ver(), blk.issuer_hash(), blk.prev_hash(),
                    vrf.vkey, vrf.leader_result, vrf.leader_proof, vrf.nonce_result, vrf.nonce_proof);
            }
        }
    };
    using indexer = indexer_one_epoch<chunk_indexer>;
}

#endif //!DAEDALUS_TURBO_INDEX_VRF_HPP