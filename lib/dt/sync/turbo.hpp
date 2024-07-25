/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_TURBO_HPP
#define DAEDALUS_TURBO_SYNC_TURBO_HPP

#include <dt/http/download-queue.hpp>
#include <dt/json.hpp>
#include <dt/sync/base.hpp>

namespace daedalus_turbo::sync::turbo {
    struct peer_info: sync::peer_info {
        peer_info(const std::string &host, json::object &&chain, const cardano::optional_point &tip, const cardano::optional_point &isect);

        ~peer_info() override =default;

        std::string id() const override
        {
            return _host;
        }

        const cardano::optional_point &tip() const override
        {
            return _tip;
        }

        const cardano::optional_point &intersection() const override
        {
            return _isect;
        }

        const json::object &chain() const
        {
            return _chain;
        }

        const std::string &host() const
        {
            return _host;
        }
    private:
        std::string _host {};
        json::object _chain {};
        cardano::optional_point _tip {};
        cardano::optional_point _isect {};
    };

    struct syncer: sync::syncer {
        syncer(chunk_registry &cr, peer_selection &ps=peer_selection_simple::get(),
            daedalus_turbo::http::download_queue &dq=daedalus_turbo::http::download_queue_async::get());
        ~syncer() override;
        [[nodiscard]] std::shared_ptr<sync::peer_info> find_peer(const std::optional<std::string> &host={}) const;
        void cancel_tasks(uint64_t max_valid_offset) override;
        void sync_attempt(sync::peer_info &peer, cardano::optional_slot max_slot) override;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_SYNC_TURBO_HPP