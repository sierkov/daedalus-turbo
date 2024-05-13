/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_HTTP_HPP
#define DAEDALUS_TURBO_SYNC_HTTP_HPP

#include <dt/indexer.hpp>
#include <dt/file-remover.hpp>
#include <dt/http/download-queue.hpp>
#include <dt/json.hpp>
#include <dt/peer-selection.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::sync::http {
    struct peer_info {
        std::string host {};
        json::object chain {};

        [[nodiscard]] cardano::slot last_slot() const
        {
            const auto &j_epochs = chain.at("epochs").as_array();
            if (j_epochs.empty())
                return 0;
            return json::value_to<uint64_t>(j_epochs.back().at("lastSlot"));
        }
    };

    struct syncer {
        syncer(indexer::incremental &cr, daedalus_turbo::http::download_queue &dq=daedalus_turbo::http::download_queue_async::get(),
            cardano::network::client_manager &ccm=cardano::network::client_manager_async::get(),
            peer_selection &ps=peer_selection_simple::get(),
            scheduler &sched=scheduler::get(), file_remover &fr=file_remover::get());
        ~syncer();
        [[nodiscard]] peer_info find_peer() const;
        void sync(std::optional<peer_info> peer=std::optional<peer_info> {},
            const std::optional<uint64_t> max_epoch=std::optional<uint64_t> {});
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_SYNC_HTTP_HPP