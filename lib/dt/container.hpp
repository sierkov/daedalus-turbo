/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CONTAINER_HPP
#define DAEDALUS_TURBO_CONTAINER_HPP

#include <map>
#include <set>
#include <vector>
#if DT_USE_MIMALLOC
#   include <mimalloc.h>
#endif

namespace daedalus_turbo {
    // Standard containers with the default allocator performs perform poorly in multi-threaded scenarios on Windows.
#if DT_USE_MIMALLOC
    template<typename T>
    using container_allocator = mi_stl_allocator<T>;
#else
    template<typename T>
    using container_allocator = std::allocator<T>;
#endif
    template<typename T>
    using vector = std::vector<T, container_allocator<T>>;

    template<typename K, typename V>
    using map = std::map<K, V, std::less<K>, container_allocator<std::pair<const K, V>>>;

    template<typename T>
    using set = std::set<T, std::less<T>, container_allocator<T>>;
}

#endif //!DAEDALUS_TURBO_CONTAINER_HPP