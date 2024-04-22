/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_LOGGER_HPP
#define DAEDALUS_TURBO_LOGGER_HPP

#ifndef SPDLOG_FMT_EXTERNAL
#   define SPDLOG_FMT_EXTERNAL 1
#endif
#include <functional>
#include <source_location>
#include <spdlog/spdlog.h>
#include <dt/error.hpp>
#include <dt/format.hpp>

namespace daedalus_turbo::logger {
    enum class level {
        trace, debug, info, warn, error
    };

    inline const char *log_path()
    {
        const char *log_path = "./log/dt.log";
        const char *env_log_path = std::getenv("DT_LOG");
        if (env_log_path != nullptr)
            log_path = env_log_path;
        return log_path;
    }

    extern spdlog::logger &get();

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

    inline void trace(const std::string_view &msg)
    {
        get().trace(msg);
    }

    template<typename... Args>
    inline void trace(const std::string_view &fmt, Args&&... a)
    {
        trace(format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }

    inline void debug(const std::string_view &msg)
    {
        get().debug(msg);
    }

    template<typename... Args>
    inline void debug(const std::string_view &fmt, Args&&... a)
    {
        debug(format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }

    inline void info(const std::string_view &msg)
    {
        get().info(msg);
    }

    template<typename... Args>
    inline void info(const std::string_view &fmt, Args&&... a)
    {
        info(format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }

    inline void warn(const std::string_view &msg)
    {
        get().warn(msg);
    }

    template<typename... Args>
    inline void warn(const std::string_view &fmt, Args&&... a)
    {
        warn(format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }

    inline void error(const std::string_view &msg)
    {
        get().error(msg);
    }

    template<typename... Args>
    inline void error(const std::string_view &fmt, Args&&... a)
    {
        error(format(fmt::runtime(fmt), std::forward<Args>(a)...));
    }

    inline void flush()
    {
        get().flush();
    }

    using action = std::function<void()>;
    using optional_action = std::optional<action>;

    inline void run_and_log_errors(const action &main, const optional_action &cleanup={}, const bool rethrow=true,
            const std::source_location &loc=std::source_location::current())
    {
        try {
            main();
            if (cleanup)
                (*cleanup)();
        } catch (const daedalus_turbo::error &err) {
            logger::error("block at {}:{} failed with {}", loc.file_name(), loc.line(), err);
            if (cleanup)
                (*cleanup)();
            if (rethrow)
                throw;
        } catch (const std::exception &ex) {
            logger::error("block at {}:{} failed with std::exception: {}", loc.file_name(), loc.line(), ex.what());
            if (cleanup)
                (*cleanup)();
            if (rethrow)
                throw;
        } catch (...) {
            logger::error("block at {}:{} failed with an unknown error", loc.file_name(), loc.line());
            if (cleanup)
                (*cleanup)();
            if (rethrow)
                throw;
        }
    }
}

#endif // !DAEDALUS_TURBO_LOGGER_HPP