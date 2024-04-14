/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_REQUIREMENTS_HPP
#define DAEDALUS_TURBO_REQUIREMENTS_HPP

#include <filesystem>
#include <dt/json.hpp>
#include <dt/memory.hpp>
#include <dt/scheduler.hpp>

namespace daedalus_turbo::requirements {
    static constexpr size_t ram_min_mb = 15000;
    static constexpr size_t cores_min = 8;
    static constexpr size_t storage_min_gb = 80;

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

    inline bool cpu_speed_ok()
    {
        auto vkey = bytes_from_hex("5ca0ed2b774adf3bae5e3e7da2f8ec877d9f063cc3d7050a6c49dfbbe2641dec");
        auto proof = bytes_from_hex("02180c447320b66012420971b70b448d11fead6d6e334c398f4daf01ccd92bfbcc4a8730a296ab33241f72da3c3a1fd53f1206a2b9f27ff6a5d9b8860fd955c39f55f9293ab58d1a2c18d555d2686101");
        auto result = bytes_from_hex("deb23fdc1267fa447fb087796544ce02b0580df8f1927450bed0df134ddc3548075ed48ffd72ae2a9ea65f79429cfbe2e15b625cb239ad0ec3910003765a8eb3");
        auto msg = bytes_from_hex("fc9f719740f900ee2809f6fdcf31bb6f096f0af133c604a27aaf85379c");
        static constexpr size_t batch_size = 40;
        static constexpr size_t num_batches = 40;
        static constexpr size_t task_size = num_batches * batch_size;
        auto &sched = scheduler::get();
        timer t { "vrf_speed_bench" };
        for (size_t i = 0; i < num_batches; ++i) {
            sched.submit_void("signature_ok", 100, [&]() {
                for (size_t i = 0; i < batch_size; ++i)
                    vrf03_verify(result, vkey, proof, msg);
            });
        }
        sched.process(false);
        double rate = task_size / t.stop(false);
        logger::debug("VRF verification speed: {:.1f} results/sec", rate);
        return rate >= 8000;
    }

    inline check_status check(const std::string &data_dir)
    {
        check_status status {};
        auto avail_ram = memory::physical_mb();
        logger::debug("detected physical RAM: {} MiB", avail_ram);
        if (avail_ram < ram_min_mb) {
            auto descr = fmt::format("{}+ MiB of physical RAM are required but only {} MiB are available!", ram_min_mb, avail_ram);
            logger::warn(descr);
            status.issues.emplace_back(std::move(descr), false);
        }
        auto avail_cores = scheduler::default_worker_count();
        logger::debug("detected CPU cores: {}", avail_cores);
        if (avail_cores < cores_min) {
            auto descr = fmt::format("{}+ CPU cores are required but only {} are available!", cores_min, avail_cores);
            logger::warn(descr);
            status.issues.emplace_back(std::move(descr), false);
        }
        if (!cpu_speed_ok()) {
            auto descr = fmt::format("CPU compute performance is too low!");
            logger::warn(descr);
            status.issues.emplace_back(std::move(descr), false);
        }
        // filesystem::space requires the directory to exist
        std::filesystem::create_directories(data_dir);
        auto storage = std::filesystem::space(data_dir);
        // the storage currently used by the app's data
        auto recoverable_storage = file::disk_used(data_dir);
        logger::debug("storage capacity: {} free: {} available: {} recoverable: {} bytes", storage.capacity, storage.free, storage.available, recoverable_storage);
        auto avail_storage = (storage.available + recoverable_storage) >> 30;
        if (avail_storage < storage_min_gb) {
            auto descr = fmt::format("{}+ GiB of available storage are required but only {} GiB are available!", storage_min_gb, avail_storage);
            logger::warn(descr);
            status.issues.emplace_back(std::move(descr), false);
        }
        return status;
    }
}

#endif //DAEDALUS_TURBO_REQUIREMENTS_HPP