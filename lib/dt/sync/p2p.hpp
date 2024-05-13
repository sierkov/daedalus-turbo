/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_P2P_HPP
#define DAEDALUS_TURBO_SYNC_P2P_HPP

#include <dt/cardano/common.hpp>
#include <dt/indexer.hpp>
#include <dt/file-remover.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/peer-selection.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::sync::p2p {
    struct peer_info {
        std::unique_ptr<cardano::network::client> client;
        cardano::point tip {};
        std::optional<cardano::point> isect {};

        const cardano::network::address &addr() const
        {
            return client->addr();
        }
    };

    struct syncer {
        explicit syncer(indexer::incremental &cr, cardano::network::client_manager &cnc=cardano::network::client_manager_async::get(),
            peer_selection &ps=peer_selection_simple::get());
        [[nodiscard]] peer_info find_peer(std::optional<cardano::network::address> addr={}) const;
        ~syncer();
        bool sync(std::optional<peer_info> peer={}, std::optional<cardano::slot> max_slot={});
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::sync::p2p::peer_info>: public formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out())
        {
            return fmt::format_to(ctx.out(), "(addr: {}, tip: {})", v.client->addr(), v.tip);
        }
    };
}

#endif // !DAEDALUS_TURBO_SYNC_P2P_HPP