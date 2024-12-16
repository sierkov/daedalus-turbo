/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_MUTEX_HPP
#define DAEDALUS_TURBO_MUTEX_HPP

#define DT_MUTEX_WITH_STACKTRACE 0

#include <chrono>
#include <mutex>
#include <source_location>
#include <stack>
#include <dt/error.hpp>
#include <dt/logger.hpp>

namespace daedalus_turbo::mutex {
#ifndef _MSC_VER
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Wpragmas"
#   ifndef __clang__
#       pragma GCC diagnostic ignored "-Winterference-size"
#   endif
#endif
#   ifdef __cpp_lib_hardware_interference_size
        static const size_t padding = std::hardware_destructive_interference_size;
#   else
        static const size_t padding = 64;
#   endif
#ifndef _MSC_VER
#   pragma GCC diagnostic pop
#endif

    struct tracing_lock {
        using mutex_type = std::timed_mutex;
        static constexpr size_t max_retries_default = 60;

        explicit tracing_lock(std::timed_mutex &m, const size_t max_retries=max_retries_default, const std::source_location &src_loc=std::source_location::current())
            : _ulock { m, std::try_to_lock }, _max_retries { max_retries }, _src_loc { src_loc }, _lock_time { std::chrono::system_clock::now() }
        {
            lock();
        }

        tracing_lock(tracing_lock &&lk) noexcept
            : _ulock { std::move(lk._ulock) }, _max_retries { lk._max_retries }, _src_loc { std::move(lk._src_loc) }, _lock_time { lk._lock_time }
        {
        }

        ~tracing_lock()
        {
            unlock();
        }

        void lock()
        {
            static constexpr size_t wait_duration_sec = 1;
            static constexpr std::chrono::seconds wait_duration { wait_duration_sec };
            if (!_ulock) {
                for (size_t retry = 1; retry <= _max_retries; ++retry) {
                    if (_ulock.try_lock_for(wait_duration)) {
                        _lock_time = std::chrono::system_clock::now();
                        return;
                    }
                    logger::warn("waiting for lock at {}:{} for longer than {} sec;",
                        _src_loc.file_name(), _src_loc.line(), retry * wait_duration_sec);
                }
                throw error(fmt::format("couldn't acquire lock at {}:{} for longer than {} sec",
                    _src_loc.file_name(), _src_loc.line(), _max_retries * wait_duration_sec));
            }
        }

        void unlock()
        {
            if (_ulock) {
                _ulock.unlock();
                auto duration = std::chrono::duration<double> { std::chrono::system_clock::now() - _lock_time }.count();
                if (duration >= 1.0)
                    logger::warn("kept lock at {}:{} for {} sec", _src_loc.file_name(), _src_loc.line(), duration);
            }
        }

        explicit operator bool() const
        {
            return static_cast<bool>(_ulock);
        }

        std::unique_lock<std::timed_mutex> &unique_lock()
        {
            return _ulock;
        }
    private:
        std::unique_lock<std::timed_mutex> _ulock;
        const size_t _max_retries;
        std::source_location _src_loc;
        std::chrono::time_point<std::chrono::system_clock> _lock_time;
    };

    using scoped_lock = std::scoped_lock<std::mutex>;
    using unique_lock = std::unique_lock<std::mutex>;
    //using scoped_lock = tracing_lock;
    //using unique_lock = tracing_lock;
}

#endif // !DAEDALUS_TURBO_MUTEX_HPP