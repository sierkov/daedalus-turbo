/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_HYBRID_HPP
#define DAEDALUS_TURBO_SYNC_HYBRID_HPP

#include <dt/sync/turbo.hpp>

namespace daedalus_turbo::sync::hybrid {
    struct syncer: turbo::syncer {
        syncer(chunk_registry &cr, peer_selection &ps=peer_selection_simple::get(),
            daedalus_turbo::http::download_queue &dq=daedalus_turbo::http::download_queue_async::get(),
            cardano::network::client_manager &ccm=cardano::network::client_manager_async::get()
        );
        ~syncer() override;
        bool sync(const std::shared_ptr<sync::peer_info> &peer, cardano::optional_slot max_slot={}) override;
    protected:
        void cancel_tasks(uint64_t max_valid_offset) override;
        void sync_attempt(sync::peer_info &peer, cardano::optional_slot max_slot) override;
        void on_progress(std::string_view name, uint64_t rel_pos, uint64_t rel_target) override;
    private:
        struct impl;
        friend impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_SYNC_HYBRID_HPP