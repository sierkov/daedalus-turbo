/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <cerrno>
#include <cstring>
#include <boost/interprocess/streams/bufferstream.hpp>
#include <boost/stacktrace.hpp>
#include "error.hpp"
#include "format.hpp"
#include <dt/logger.hpp>

namespace daedalus_turbo {
    base_error::base_error(const std::string_view msg):
        _msg { msg }
    {
        // skips top 3 frames: safe_dump, base_error, and error
        boost::stacktrace::safe_dump_to(3, _trace.data(), _trace.size());
    }

    const char *base_error::what() const noexcept
    {
        thread_local std::array<char, 0x2000> buf {};
        boost::interprocess::obufferstream os { buf.data(), buf.size() - 1 };
        os << _msg << '\n';
        os << boost::stacktrace::stacktrace::from_dump(_trace.data(), _trace.size()) << '\n';
        // the bufferstream's constructor arguments ensure that there is always at least one byte available.
        buf[os.buffer().second] = 0;
        logger::debug("stacktrace for a user visible exception: {}", buf.data());
        return _msg.c_str();
    }

    error::error(const std::string_view msg)
        : base_error { msg }
    {
    }

    error::error(const std::string_view msg, const std::exception &ex)
        : error { fmt::format("{} caused by {}: {}", msg, typeid(ex).name(), ex.what()) }
    {
    }

    error_sys::error_sys(const std::string_view msg)
        : error { fmt::format("{} errno: {} strerror: {}", msg, errno, std::strerror(errno)) }
    {
    }
}
