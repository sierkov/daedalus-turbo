/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_MEMORY_HPP
#define DAEDALUS_TURBO_MEMORY_HPP

#include <cstddef>

namespace daedalus_turbo::memory {
    extern size_t max_usage_mb();
    extern size_t physical_mb();
    extern size_t my_usage_mb();
}

#endif // !DAEDALUS_TURBO_MEMORY_HPP