/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#ifdef __APPLE__
#   define _GNU_SOURCE 1
#endif
#include <boost/stacktrace.hpp>
#include <dt/error.hpp>

namespace daedalus_turbo {
    std::string error_stacktrace()
    {
        //Boost's stacktrace generation is _VERY_ slow, so it's enabled only for rare debugging sessions
        //std::stringstream ss {};
        //ss << boost::stacktrace::stacktrace();
        //return ss.str();
        static std::string s { "none" };
        return s;
    }

    const std::string &error_trace(const std::string &msg, const std::string &stack)
    {
        logger::debug("error created: {}, stacktrace: {}", msg, stack);
        return msg;
    }
}