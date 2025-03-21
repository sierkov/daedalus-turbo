/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_ATOMIC_HPP
#define DAEDALUS_TURBO_ATOMIC_HPP

#include <atomic>
#include <dt/logger.hpp>

namespace daedalus_turbo {
    // in some configurations operator+= of std::atomic was failing
    // to update uint64_t values correctly
    template<typename T>
    T atomic_add(std::atomic<T> &val, const T addend)
    {
        for (;;) {
            auto old_val = val.load();
            auto new_val = old_val + addend;
            if (val.compare_exchange_strong(old_val, new_val))
                return new_val;
            logger::trace("atomic add for {} failed, retrying", static_cast<void *>(&val));
        }
    }
}

#endif // !DAEDALUS_TURBO_ATOMIC_HPP