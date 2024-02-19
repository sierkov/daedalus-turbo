/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_PUBLISHER_HPP
#define DAEDALUS_TURBO_PUBLISHER_HPP

#include <dt/sync/local.hpp>

namespace daedalus_turbo {
    struct  publisher {
        publisher(scheduler &sched, chunk_registry &cr, const std::string &node_path, bool strict=true, size_t zstd_max_level=22);
        size_t size() const;
        void publish();
        void run(std::chrono::milliseconds update_interval=std::chrono::milliseconds { 2000 });
    private:
        sync::local::syncer _syncer;
        chunk_registry &_cr;

        void _write_index_html(uint64_t total_size, uint64_t total_compressed_size) const;
        void _write_meta() const;
    };
}

#endif // !DAEDALUS_TURBO_PUBLISHER_HPP