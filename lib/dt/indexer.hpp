/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_INDEXER_HPP
#define DAEDALUS_TURBO_INDEXER_HPP

#ifndef _WIN32
#   include <sys/resource.h>
#endif
#include <dt/container.hpp>
#include <dt/index/common.hpp>
#include <dt/indexer/merger.hpp>
#include <dt/logger.hpp>
#include <dt/progress.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo {
    struct chunk_registry;
}

namespace daedalus_turbo::indexer {
    using chunk_indexer_list = vector<std::shared_ptr<index::chunk_indexer_base>>;
    using slice_list = vector<merger::slice>;
    using slice_path_list = vector<std::string>;

    struct indexer_map: std::map<std::string, std::shared_ptr<index::indexer_base>> {
        using std::map<std::string, std::shared_ptr<index::indexer_base>>::map;

        void emplace(std::shared_ptr<index::indexer_base> &&idxr) {
            auto [ it, created ] = try_emplace(idxr->name(), std::move(idxr));
            if (!created) [[unlikely]]
                throw error(fmt::format("duplicate index: {}", it->first));
        }
    };

    extern slice_path_list multi_reader_paths(const std::string &idx_dir, const std::string &name, const slice_list &slices);
    extern indexer_map default_list(const std::string &data_dir, scheduler &sched=scheduler::get());

    struct incremental {
        static std::string storage_dir(const std::string &data_dir);

        incremental(chunk_registry &cr, indexer_map &&indexers);
        ~incremental();
        chunk_indexer_list make_chunk_indexers(uint64_t chunk_offset);
        slice_list slices(std::optional<uint64_t> end_offset={}) const;
        slice_path_list reader_paths(const std::string &name, const slice_list &slcs) const;
        slice_path_list reader_paths(const std::string &name) const;
        const indexer_map &indexers() const;
        const std::filesystem::path &idx_dir() const;
    protected:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_INDEXER_HPP