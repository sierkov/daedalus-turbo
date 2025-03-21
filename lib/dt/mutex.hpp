#pragma once
/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <mutex>
#include <new>

namespace daedalus_turbo::mutex {
#ifndef _MSC_VER
#   pragma GCC diagnostic push
#   pragma GCC diagnostic ignored "-Wpragmas"
#   ifndef __clang__
#       pragma GCC diagnostic ignored "-Winterference-size"
#   endif
#endif
#   ifdef __cpp_lib_hardware_interference_size
        static const size_t alignment = std::hardware_destructive_interference_size;
#   else
        static const size_t alignment = 64;
#   endif
#ifndef _MSC_VER
#   pragma GCC diagnostic pop
#endif

    using scoped_lock = std::scoped_lock<std::mutex>;
    using unique_lock = std::unique_lock<std::mutex>;
}
