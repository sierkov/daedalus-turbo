/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/logger.hpp>
#include <dt/mutex.hpp>

namespace daedalus_turbo::logger {
    alignas(mutex::padding) static std::mutex m {};
    static std::optional<spdlog::logger> logger {};

    spdlog::logger &get()
    {
        if (!logger) {
            std::scoped_lock lk { m };
            // checking again since another thread could have already started initializing the logger
            if (!logger) {
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
            }
        }
        return *logger;
    }
}