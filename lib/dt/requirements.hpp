/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_REQUIREMENTS_HPP
#define DAEDALUS_TURBO_REQUIREMENTS_HPP

#include <filesystem>
#include <dt/memory.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::requirements {
    inline void check(const std::string &data_dir)
    {
        auto avail_cores = scheduler::default_worker_count();
        logger::debug("detected CPU cores: {}", avail_cores);
        if (avail_cores < 8)
            logger::warn("8+ CPU cores are expected but only {} available - expect degraded performance!", avail_cores);
        auto avail_ram = memory::physical_mb();
        logger::debug("detected physical RAM: {} MiB", avail_ram);
        if (avail_ram < 8192)
            logger::warn("8192+ MiB of physical RAM are expected but only {} MiB available - expect degraded performance!", avail_ram);
        // filesystem::space requires the directory to exist
        std::filesystem::create_directories(data_dir);
        auto storage = std::filesystem::space(data_dir);
        auto avail_storage = storage.available >> 30;
        logger::debug("storage capacity: {} free: {} available: {} checked: {} GiB", storage.capacity, storage.free, storage.available, avail_storage);
        if (avail_storage < 60)
            logger::warn("60+ GiB of available storage is recommended but only {} GiB available - the operation may fail!", avail_storage);
    }
}

#endif //DAEDALUS_TURBO_REQUIREMENTS_HPP