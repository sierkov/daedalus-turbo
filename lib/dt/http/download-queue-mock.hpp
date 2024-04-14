/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_MOCK_HPP
#define DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_MOCK_HPP

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <dt/http/download-queue.hpp>
#include <dt/json.hpp>

namespace daedalus_turbo::http {
    struct download_queue_mock: download_queue {
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

#endif // !DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_MOCK_HPP