/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_SYNC_HTTP_HPP
#define DAEDALUS_TURBO_SYNC_HTTP_HPP

#include <dt/http/download-queue.hpp>
#include <dt/indexer.hpp>
#include <dt/progress.hpp>

namespace daedalus_turbo::sync::http {
    struct syncer {
        syncer(scheduler &sched, indexer::incremental &cr, const std::string &src_host, bool report_progress=true);
        void sync(std::optional<uint64_t> max_epoch = std::optional<uint64_t> {});
    private:
        using download_queue = daedalus_turbo::http::download_queue;
        using download_task_list = std::vector<chunk_registry::chunk_info>;
        struct sync_task {
            uint64_t start_epoch = 0;
            uint64_t start_offset = 0;
        };

        scheduler &_sched;
        indexer::incremental &_cr;
        std::string _host;
        const bool _report_progress;
        download_queue _dlq;
        chunk_registry::file_set _deletable_chunks {};
        alignas(mutex::padding) std::mutex _epoch_json_cache_mutex {};
        std::map<uint64_t, std::string> _epoch_json_cache {};

        std::string _get_sync(const std::string &target);
        template<typename T>
        T _get_json(const std::string &target);
        std::tuple<std::optional<syncer::sync_task>, json::array, uint64_t> _find_sync_start_position();
        std::string _parse_local_chunk(const chunk_registry::chunk_info &chunk, const std::string &save_path);
        void _download_chunks(const download_task_list &download_tasks, uint64_t max_offset, chunk_registry::file_set &updated_chunks);
        chunk_registry::file_set _download_data(const json::array &epoch_groups, size_t first_synced_epoch);
    };
}

#endif // !DAEDALUS_TURBO_SYNC_HTTP_HPP