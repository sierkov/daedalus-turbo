/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_LOCAL_HPP
#define DAEDALUS_TURBO_SYNC_LOCAL_HPP

#include <dt/sync/base.hpp>

namespace daedalus_turbo::sync::local {
    struct chunk_update {
        std::string path {};
        std::time_t update_time {};
        uint64_t data_size = 0;
        uint64_t offset = 0;

        bool operator<(const chunk_update &b) const
        {
            return path < b.path;
        }

        cardano::point last_point(const cardano::config &cfg) const;
    };
    using updated_chunk_list = vector<chunk_update>;

    struct peer_info: sync::peer_info {
        peer_info(const std::filesystem::path &node_dir, updated_chunk_list &&updated_chunks, const uint64_t num_bytes,
            const cardano::optional_point &tip, const cardano::optional_point &isect)
            : _node_dir { std::move(node_dir) }, _updated_chunks { std::move(updated_chunks) }, _num_bytes { num_bytes }, _tip { tip }, _isect { isect }
        {
        }

        ~peer_info() override =default;

        std::string id() const override
        {
            return fmt::format("{}", _node_dir.string());
        }

        const cardano::optional_point &tip() const override
        {
            return _tip;
        }

        const cardano::optional_point &intersection() const override
        {
            return _isect;
        }

        const std::filesystem::path &node_dir() const
        {
            return _node_dir;
        }

        const updated_chunk_list &updated_chunks() const
        {
            return _updated_chunks;
        }

        uint64_t num_bytes() const
        {
            return _num_bytes;
        }
    private:
        std::filesystem::path _node_dir;
        updated_chunk_list _updated_chunks;
        uint64_t _num_bytes;
        std::optional<cardano::point> _tip;
        std::optional<cardano::point> _isect;
    };

    struct syncer: sync::syncer {
        explicit syncer(chunk_registry &cr, size_t zstd_max_level=3, std::chrono::seconds del_delay=std::chrono::seconds { 3600 });
        ~syncer() override;
        [[nodiscard]] std::shared_ptr<sync::peer_info> find_peer(const std::filesystem::path &node_dir) const;
        void cancel_tasks(uint64_t max_valid_offset) override;
        void sync_attempt(sync::peer_info &peer, cardano::optional_slot max_slot) override;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

namespace fmt {
    template<>
    struct formatter<daedalus_turbo::sync::local::peer_info>: formatter<int> {
        template<typename FormatContext>
        auto format(const auto &v, FormatContext &ctx) const -> decltype(ctx.out())
        {
            return fmt::format_to(ctx.out(), "(node_dir: {})", v.node_dir());
        }
    };
}

#endif // !DAEDALUS_TURBO_SYNC_LOCAL_HPP
