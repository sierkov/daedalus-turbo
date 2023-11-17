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

    struct progress {
        using state_map = std::map<std::string, std::string>;

        static progress &get()
        {
            static std::optional<progress> p {};
            if (!p) {
                alignas(mutex::padding) static std::mutex m {};
                std::scoped_lock lk { m };
                // checking again since another thread could have already started initializing the logger
                if (!p)
                    p.emplace();
            }
            return *p;
        }

        void update(const std::string &name, const std::string &value)
        {
            std::scoped_lock lk { _state_mutex };
            _state[name] = value;
        }

        void update(const state_map &updates)
        {
            std::scoped_lock lk { _state_mutex };
            for (const auto &[name, value]: updates)
                _state[name] = value;
        }

        void update(const state_map &updates, const state_map &retiring)
        {
            std::scoped_lock lk { _state_mutex };
            for (const auto &[name, value]: retiring)
                _state.erase(name);
            for (const auto &[name, value]: updates)
                _state[name] = value;
        }

        void retire(const std::string &name)
        {
            std::scoped_lock lk { _state_mutex };
            _state.erase(name);
        }

        void retire(const state_map &retiring)
        {
            std::scoped_lock lk { _state_mutex };
            for (const auto &[name, value]: retiring)
                _state.erase(name);
        }

        void inform(std::ostream &stream=std::cerr)
        {
            std::string str {};
            {
                std::scoped_lock lk { _state_mutex };
                for (const auto &[name, val]: _state)
                    str += fmt::format("{}: [{}] ", name, val);
            }
            // adjust for the invisible \r
            if (str.size() > _max_str)
                _max_str = str.size();
            stream << fmt::format("{:<{}}\r", str, _max_str);
        }
    private:
        alignas(mutex::padding) std::mutex _state_mutex {};
        state_map _state {};
        size_t _max_str = 0;
    };

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