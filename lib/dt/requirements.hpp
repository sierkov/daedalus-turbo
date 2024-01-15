/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_REQUIREMENTS_HPP
#define DAEDALUS_TURBO_REQUIREMENTS_HPP

#include <filesystem>
#include <dt/json.hpp>
#include <dt/memory.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::requirements {
    static constexpr size_t ram_recommended_mb = 8192;
    static constexpr size_t ram_min_mb = 4096;
    static constexpr size_t cores_recommended = 8;
    static constexpr size_t storage_min_gb = 60;

    struct issue {
        std::string descr {};
        bool can_proceed = false;
    };

    struct check_status {
        std::vector<issue> issues {};

        operator bool() const
        {
            return issues.empty();
        }

        json::object to_json() const
        {
            json::array j_issues {};
            for (const auto &issue: issues)
                j_issues.emplace_back(json::object {
                    { "description", issue.descr },
                    { "canProceed", issue.can_proceed }
                });
            return json::object {
                { "issues", std::move(j_issues) },
                { "ok", static_cast<bool>(*this) }
            };
        }
    };

    inline check_status check(const std::string &data_dir)
    {
        check_status status {};
        auto avail_cores = scheduler::default_worker_count();
        logger::debug("detected CPU cores: {}", avail_cores);
        if (avail_cores < cores_recommended) {
            auto descr = fmt::format("{}+ CPU cores are required but only {} are available!", cores_recommended, avail_cores);
            logger::warn(descr);
            status.issues.emplace_back(std::move(descr), true);
        }
        auto avail_ram = memory::physical_mb();
        logger::debug("detected physical RAM: {} MiB", avail_ram);
        if (avail_ram < ram_recommended_mb) {
            auto descr = fmt::format("{}+ MiB of physical RAM are required but only {} MiB are available!", ram_recommended_mb, avail_ram);
            logger::warn(descr);
            status.issues.emplace_back(std::move(descr), avail_ram >= ram_min_mb);
        }
        // filesystem::space requires the directory to exist
        std::filesystem::create_directories(data_dir);
        auto storage = std::filesystem::space(data_dir);
        auto avail_storage = storage.available >> 30;
        logger::debug("storage capacity: {} free: {} available: {} checked: {} GiB", storage.capacity, storage.free, storage.available, avail_storage);
        if (avail_storage < storage_min_gb) {
            auto descr = fmt::format("{}+ GiB of available storage are required but only {} GiB are available!", storage_min_gb, avail_storage);
            logger::warn(descr);
            status.issues.emplace_back(std::move(descr), false);
        }
        return status;
    }
}

#endif //DAEDALUS_TURBO_REQUIREMENTS_HPP