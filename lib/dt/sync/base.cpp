/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/sync/base.hpp>

namespace daedalus_turbo::sync {
    struct syncer::impl {
        impl(syncer &parent, chunk_registry &cr, peer_selection &ps)
            : _parent { parent }, _cr { cr }, _ps { ps }
        {
            _cr.register_processor(_proc);
        }

        ~impl()
        {
            _cr.remove_processor(_proc);
        }

        bool sync(peer_info &peer, cardano::optional_slot max_slot)
        {
            /*static const auto mainnet_hash = uint8_vector::from_hex("15a199f895e461ec0ffc6dd4e4028af28a492ab4e806d39cb674c88f7643ef62");
            if (cardano::config::get().conway_genesis_hash == mainnet_hash) {
                cardano::config::get().shelley_start_epoch(208);
                static const auto babbage_max_slot = cardano::slot::from_epoch(507, cardano::config::get()) - 1;
                if (!max_slot || max_slot > babbage_max_slot) {
                    logger::warn("Limiting the sync the Babbage era last slot: {}; Chang support comes soon!", babbage_max_slot);
                    max_slot = babbage_max_slot;
                }
            }*/
            logger::info("attempting to sync with {} with the tip {}", peer.id(), peer.tip());
            const auto start_tip = _cr.tip();
            static constexpr size_t max_retries = 1;
            auto start_point = peer.intersection();
            optional_progress_point target { peer.tip() };
            if (max_slot && max_slot < target) {
                logger::info("user override of the target: up to {}", *max_slot);
                target = max_slot;
            }
            if (peer.intersection() < target && peer.intersection() < peer.tip()) {
                for (size_t num_retries = max_retries; num_retries; --num_retries) {
                    logger::info("syncing from {} to {}", start_point, target);
                    const auto ex_ptr = _cr.accept_progress(start_point, target, [&] {
                        _cr.validation_failure_handler([this](auto max_valid_offset) {
                            _parent.cancel_tasks(max_valid_offset);
                        });
                        _parent.sync_attempt(peer, max_slot);
                    });
                    if (!ex_ptr) {
                        _cr.remover().remove();
                        break;
                    }
                    // reset the retry count if made progress
                    if (const auto end_tip = _cr.tip(); end_tip && start_point < end_tip) {
                        num_retries = max_retries;
                        start_point = end_tip;
                    }
                    logger::info("retrying after a failure, number of planned attempts: {}", num_retries);
                }
            }
            logger::info("the new tip: {}", _cr.tip());
            // the new chain's tip can be smaller but have a better chain, so compare for equality here
            return start_tip != _cr.tip();
        }

        chunk_registry &local_chain() noexcept
        {
            return _cr;
        }

        peer_selection &peer_list() noexcept
        {
            return _ps;
        }

        void on_progress(const std::string &name, uint64_t rel_pos, const uint64_t rel_target)
        {
            progress::get().update(name, rel_pos, rel_target);
        }
    private:
        syncer &_parent;
        chunk_registry &_cr;
        peer_selection &_ps;
        chunk_processor _proc {
            .on_progress = [this](const auto name, const auto rel_pos, const auto rel_target) {
                _parent.on_progress(name, rel_pos, rel_target);
            }
        };
    };

    syncer::syncer(chunk_registry &cr, peer_selection &ps)
        : _impl { std::make_unique<impl>(*this, cr, ps) }
    {
    }

    syncer::~syncer() =default;

    bool syncer::sync(const std::shared_ptr<peer_info> &peer, const cardano::optional_slot max_slot)
    {
        if (!peer)
            throw error("peer must be initialized!");
        return _impl->sync(*peer, max_slot);
    }

    chunk_registry &syncer::local_chain() noexcept
    {
        return _impl->local_chain();
    }

    peer_selection &syncer::peer_list() noexcept
    {
        return _impl->peer_list();
    }

    void syncer::on_progress(const std::string_view name, const uint64_t rel_pos, const uint64_t rel_target)
    {
        _impl->on_progress(std::string { name }, rel_pos, rel_target);
    }
}