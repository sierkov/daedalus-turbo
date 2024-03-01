/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <atomic>
#include <optional>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <dt/logger.hpp>

namespace daedalus_turbo::logger {
    static std::atomic_bool initializing { false };
    static std::atomic_bool initialized { false };
    static std::optional<spdlog::logger> logger {};

    spdlog::logger &get()
    {
        if (!initialized) {
            bool exp = false;
            if (initializing.compare_exchange_strong(exp, true)) {
                auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
                console_sink->set_level(spdlog::level::info);
                console_sink->set_pattern("[%^%l%$] %v");
                auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_path());
                file_sink->set_level(spdlog::level::trace);
                file_sink->set_pattern("[%Y-%m-%d %T %z] [%P:%t] [%n] [%l] %v");
                logger = spdlog::logger("dt", { console_sink, file_sink });
                logger->set_level(spdlog::level::trace);
                logger->flush_on(spdlog::level::debug);
                spdlog::flush_every(std::chrono::seconds(1));
                initialized = true;
            } else {
                while (!initialized) {
                    std::this_thread::sleep_for(std::chrono::milliseconds { 10 });
                }
            }
        }
        return *logger;
    }
}