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
#include <dt/mutex.hpp>

namespace daedalus_turbo {
    struct scheduler;
}

namespace daedalus_turbo::http {
    struct download_queue {
        struct result {
            std::string url {};
            std::string save_path {};
            std::optional<std::string> error {};
            size_t size = 0;

            explicit operator bool() const
            {
                return !static_cast<bool>(error);
            }
        };

        struct speed_mbps {
            double current = 0.0;
            double max = 0.0;
        };

        virtual ~download_queue() =default;

        void download(const std::string &url, const std::string &save_path, uint64_t priority, const std::function<void(result &&)> &handler)
        {
            return _download_impl(url, save_path, priority, handler);
        }

        bool process_ok(bool report_progress=false, scheduler *sched = nullptr)
        {
            return _process_ok_impl(report_progress, sched);
        }

        speed_mbps internet_speed()
        {
            return _internet_speed_impl();
        }

        void process(bool report_progress=false, scheduler *sched = nullptr)
        {
            if (!process_ok(report_progress, sched))
                throw error("some download requests have failed, please check the logs");
        }

        std::string fetch(const std::string &url)
        {
            alignas(mutex::padding) mutex::unique_lock::mutex_type m {};
            alignas(mutex::padding) std::condition_variable_any cv {};
            const auto url_hash = blake2b<blake2b_256_hash>(url);
            const file::tmp tmp { fmt::format("http-fetch-sync-{}.tmp", url_hash) };
            std::atomic_bool ready { false };
            std::optional<std::string> err {};
            download(url, tmp.path(), 0, [&](const auto &res) {
                err = std::move(res.error);
                ready = true;
                cv.notify_one();
            });;
            {
                mutex::unique_lock lk { m };
                cv.wait(lk, [&] { return ready.load(); });
            }
            if (err)
                throw error("download of {} failed: {}", url, *err);
            return std::string { file::read(tmp.path()).span().string_view() };
        }

        json::value fetch_json(const std::string &url)
        {
            try {
                return json::parse(fetch(url));
            } catch (std::exception &ex) {
                throw error("fetch {} failed with error: {}", url, ex.what());
            }
        }

        json::value fetch_json_signed(const std::string &url, const buffer &vk)
        {
            try {
                return json::parse_signed(fetch(url), vk);
            } catch (std::exception &ex) {
                throw error("fetch {} failed with error: {}", url, ex.what());
            }
        }
    private:
        virtual void _download_impl(const std::string &url, const std::string &save_path, uint64_t priority, const std::function<void(result &&)> &handler) =0;
        virtual bool _process_ok_impl(bool report_progress, scheduler *sched) =0;
        virtual speed_mbps _internet_speed_impl() =0;
    };

    struct download_queue_async: download_queue {
        static download_queue_async &get()
        {
            static download_queue_async ps {};
            return ps;
        }

        download_queue_async();
        ~download_queue_async() override;
    private:
        struct impl;
        std::unique_ptr<impl> _impl;

        void _download_impl(const std::string &url, const std::string &save_path, uint64_t priority, const std::function<void(result &&)> &handler) override;
        bool _process_ok_impl(bool report_progress, scheduler *sched) override;
        speed_mbps _internet_speed_impl() override;
    };
}

#endif // !DAEDALUS_TURBO_HTTP_DOWNLOAD_QUEUE_HPP