/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_MUTEX_HPP
#define DAEDALUS_TURBO_MUTEX_HPP

#include <mutex>

namespace daedalus_turbo::mutex {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#ifndef __clang__
#   pragma GCC diagnostic ignored "-Winterference-size"
#endif
#   ifdef __cpp_lib_hardware_interference_size
        static const size_t padding = std::hardware_destructive_interference_size;
#   else
        static const size_t padding = 64;
#   endif
#pragma GCC diagnostic pop
}

#endif // !DAEDALUS_TURBO_MUTEX_HPP