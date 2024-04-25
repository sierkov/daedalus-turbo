/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <format>
#ifndef SPDLOG_FMT_EXTERNAL
#   define SPDLOG_FMT_EXTERNAL 1
#endif
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <dt/debug.hpp>
#include <dt/file.hpp>
#include <dt/logger.hpp>
#include <dt/mutex.hpp>

namespace daedalus_turbo::logger {
    static const char *log_path()
    {
        const char *log_path = "./log/dt.log";
        const char *env_log_path = std::getenv("DT_LOG");
        if (env_log_path != nullptr)
            log_path = env_log_path;
        return log_path;
    }

    static spdlog::logger create(const std::string &path)
    {
        auto console_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
        console_sink->set_level(spdlog::level::info);
        console_sink->set_pattern("[%^%l%$] %v");
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(path);
        file_sink->set_level(spdlog::level::trace);
        file_sink->set_pattern("[%Y-%m-%d %T %z] [%P:%t] [%n] [%l] %v");
        auto logger = spdlog::logger("dt", { console_sink, file_sink });
        if (debug::tracing_enabled())
            logger.set_level(spdlog::level::trace);
        else
            logger.set_level(spdlog::level::debug);
        logger.flush_on(spdlog::level::trace);
        return logger;
    }

    static spdlog::logger &get()
    {
        static spdlog::logger logger = create(log_path());
        return logger;
    }

    void log(level lev, const std::string &msg)
    {
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
                throw daedalus_turbo::error("unsupported log level: {}", static_cast<int>(lev));
        }
    }
}
