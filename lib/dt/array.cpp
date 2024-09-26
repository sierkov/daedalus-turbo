/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <algorithm>
#include <dt/array.hpp>

namespace daedalus_turbo {
    void secure_clear(const std::span<uint8_t> store)
    {
        std::fill_n<volatile uint8_t *>(store.data(), store.size(), 0);
    }
}
