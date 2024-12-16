/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_BASE_HPP
#define DAEDALUS_TURBO_SYNC_BASE_HPP

#include <dt/cardano/types.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/peer-selection.hpp>

namespace daedalus_turbo::sync {
    enum class validation_mode_t { turbo, full, none };
    extern validation_mode_t validation_mode_from_text(std::string_view);

    struct peer_info {
        virtual ~peer_info() =default;
        virtual std::string id() const =0;
        virtual const cardano::optional_point &tip() const =0;
        virtual const cardano::optional_point &intersection() const =0;
    };

    struct syncer {
        syncer(chunk_registry &cr, peer_selection &pr=peer_selection_simple::get());
        virtual ~syncer();
        virtual bool sync(const std::shared_ptr<peer_info> &peer, cardano::optional_slot max_slot={}, validation_mode_t mode=validation_mode_t::turbo);
        chunk_registry &local_chain() noexcept;
        peer_selection &peer_list() noexcept;
    protected:
        virtual void cancel_tasks(uint64_t max_valid_offset) =0;
        virtual void sync_attempt(peer_info &peer, cardano::optional_slot max_slot) =0;
        virtual void on_progress(std::string_view name, uint64_t rel_pos, uint64_t rel_target);
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::sync::validation_mode_t>: formatter<int32_t> {
        template<typename FormatContext>
        auto format(const daedalus_turbo::sync::validation_mode_t &v, FormatContext &ctx) const -> decltype(ctx.out()) {
            using daedalus_turbo::sync::validation_mode_t;
            switch (v) {
                case validation_mode_t::full: return fmt::format_to(ctx.out(), "full");
                case validation_mode_t::turbo: return fmt::format_to(ctx.out(), "turbo");
                default: throw daedalus_turbo::error(fmt::format("unsupported validation_mode_t value: {}", static_cast<int>(v)));
            }
        }
    };
}

#endif // !DAEDALUS_TURBO_SYNC_BASE_HPP