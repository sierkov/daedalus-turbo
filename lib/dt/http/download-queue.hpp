/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_HPP
#define DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_HPP

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <dt/json.hpp>

namespace daedalus_turbo {
    struct scheduler;
}

namespace daedalus_turbo::http {
    struct internet_speed {
        double current = 0.0;
        double max = 0.0;
    };

    extern internet_speed internet_speed_mbps(std::optional<double> new_current_speed={});
    extern std::string fetch(const std::string &url);
    extern json::value fetch_json(const std::string &url);

    struct download_queue {
        struct result {
            std::string url {};
            std::string save_path {};
            std::optional<std::string> error {};
            size_t size = 0;

            operator bool() const
            {
                return !static_cast<bool>(error);
            }
        };

        download_queue();
        ~download_queue();
        void download(const std::string &url, const std::string &save_path, uint64_t priority, const std::function<void(result &&)> &handler);
        bool process_ok(bool report_progress=false, scheduler *sched = nullptr);
        void process(bool report_progress=false, scheduler *sched = nullptr);
    private:
        struct impl;
        std::unique_ptr<impl> _impl;
    };
}

#endif // !DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_HPP