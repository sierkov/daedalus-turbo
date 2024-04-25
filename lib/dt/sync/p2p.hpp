/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_P2P_HPP
#define DAEDALUS_TURBO_SYNC_P2P_HPP

#include <dt/indexer.hpp>
#include <dt/file-remover.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/peer-selection.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::sync::p2p {
    struct peer_info {
        cardano::network::address addr {};
        cardano::network::blockchain_point tip {};
        std::optional<cardano::network::blockchain_point> isect {};
    };

    struct syncer {
        explicit syncer(indexer::incremental &cr, cardano::network::client &cnc=cardano::network::client_async::get(),
            peer_selection &ps=peer_selection_simple::get());
        [[nodiscard]] peer_info find_peer() const;
        ~syncer();
        void sync(std::optional<peer_info> peer={}, std::optional<cardano::slot> max_slot={});
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_SYNC_P2P_HPP