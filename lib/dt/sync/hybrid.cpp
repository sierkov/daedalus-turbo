/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/sync/hybrid.hpp>
#include <dt/sync/p2p.hpp>

namespace daedalus_turbo::sync::hybrid {
    struct syncer::impl {
        impl(syncer &parent, daedalus_turbo::http::download_queue &dq, cardano::network::client_manager &ccm)
            : _parent { parent },
              _turbo { _parent.local_chain(), _parent.peer_list(), dq },
              _p2p { _parent.local_chain(), _parent.peer_list(), ccm }
        {
        }

        bool sync(const std::shared_ptr<sync::peer_info> &turbo_peer, const cardano::optional_slot max_slot, const validation_mode_t mode)
        {
            const auto &cr = _parent.local_chain();
            bool turbo_progress = false;
            progress_guard pg { "download", "parse", "merge", "validate", "verify" };
            // Use Turbo only when more than several chunks of data need to be synchronized
            const auto future_slot = cardano::slot::from_future(cr.config());
            if (!cr.config().shelley_started() || cr.max_slot() + cr.config().shelley_randomness_stabilization_window <= future_slot) {
                logger::info("turbo sync stage from {}", turbo_peer->intersection());
                _progress_stage = stage::turbo;
                turbo_progress = _turbo.sync(turbo_peer, max_slot, mode);
            }
            /*for (const auto &name: pg.names()) {
                if (name != "verify")
                    progress::get().update(name, 1, 1);
            }*/
            const auto p2p_peer = _p2p.find_peer({});
            logger::info("P2P sync stage continues from {}", p2p_peer->intersection());
            _progress_stage = stage::p2p;
            const auto p2p_progress = _p2p.sync(p2p_peer, max_slot, mode);
            //progress::get().update("verify", 1, 1);
            return turbo_progress || p2p_progress;
        }

        void on_progress(const std::string name, const uint64_t rel_pos, const uint64_t rel_target)
        {
            if (_progress_stage == stage::turbo || name == "verify")
                progress::get().update(name, rel_pos, rel_target);
        }
    private:
        enum class stage { turbo, p2p };

        syncer &_parent;
        turbo::syncer _turbo;
        p2p::syncer _p2p;
        std::atomic<stage> _progress_stage = stage::turbo;
    };

    syncer::syncer(chunk_registry &cr, peer_selection &ps,
        daedalus_turbo::http::download_queue &dq, cardano::network::client_manager &ccm)
        : turbo::syncer { cr, ps, dq }, _impl { std::make_unique<impl>(*this, dq, ccm) }
    {
    }

    syncer::~syncer() =default;

    bool syncer::sync(const std::shared_ptr<sync::peer_info> &peer, cardano::optional_slot max_slot, const validation_mode_t mode)
    {
        if (!peer)
            throw error("peer must be initialized!");
        return _impl->sync(peer, max_slot, mode);
    }

    void syncer::cancel_tasks(const uint64_t /*min_invalid_offset*/)
    {
        throw error("not implemented");
    }

    void syncer::sync_attempt(sync::peer_info &/*peer*/, const cardano::optional_slot /*max_slot*/)
    {
        throw error("not implemented");
    }

    void syncer::on_progress(const std::string_view name, const uint64_t rel_pos, const uint64_t rel_target)
    {
        _impl->on_progress(std::string { name }, rel_pos, rel_target);
    }
}