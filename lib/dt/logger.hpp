/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_LOGGER_HPP
#define DAEDALUS_TURBO_LOGGER_HPP

#include <optional>
#define SPDLOG_FMT_EXTERNAL 1
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <dt/error.hpp>
#include <dt/format.hpp>
#include <dt/mutex.hpp>

namespace daedalus_turbo::logger {

    enum class level {
        trace, debug, info, warn, error
    };

    inline spdlog::logger &get()
    {
        static std::optional<spdlog::logger> logger {};
        if (!logger) {
            alignas(mutex::padding) static std::mutex m {};
            std::scoped_lock lk { m };
            // checking again since another thread could have already started initializing the logger
            if (!logger) {
                auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
                console_sink->set_level(spdlog::level::info);
                console_sink->set_pattern("[%^%l%$] %v");
                const char *log_path = "./log/dt.log";
                const char *env_log_path = std::getenv("DT_LOG");
                if (env_log_path != nullptr)
                    log_path = env_log_path;
                auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_path);
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

    template<typename... Args>
    inline void log(const level &lev, const std::string_view &fmt, Args&&... a)
    {
        auto msg = format(fmt::runtime(fmt), std::forward<Args>(a)...);
        switch (lev) {
            case level::trace:
                get().trace(msg);
                break;

            case level::debug:
                get().debug(msg);
                break;

            case level::info:
                get().info(msg);
                break;

            case level::warn:
                get().warn(msg);
                break;

            case level::error:
                get().error(msg);
                break;

            default:
                throw error("unsupported log level: {}", (int)lev);
        }
    }

    template<typename... Args>
    inline void trace(const std::string_view &fmt, Args&&... a)
    {
        get().trace(format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }

    template<typename... Args>
    inline void debug(const std::string_view &fmt, Args&&... a)
    {
        get().debug(format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }

    template<typename... Args>
    inline void info(const std::string_view &fmt, Args&&... a)
    {
        get().info(format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }

    template<typename... Args>
    inline void warn(const std::string_view &fmt, Args&&... a)
    {
        get().warn(format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }

    template<typename... Args>
    inline void error(const std::string_view &fmt, Args&&... a)
    {
        get().error(format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }
}

#endif // !DAEDALUS_TURBO_LOGGER_HPP