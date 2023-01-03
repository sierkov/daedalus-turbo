/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#ifndef DAEDALUS_TURBO_BLAKE2B_HPP
#define DAEDALUS_TURBO_BLAKE2B_HPP 1

extern "C" {
#   include <blake2/blake2.h>
};

#include "util.hpp"

namespace daedalus_turbo
{
    inline void blake2b_best(void *out, size_t out_len, const void *in, size_t in_len)
    {
        if (blake2b(out, out_len, in, in_len, nullptr, 0) != 0) throw error("blake2b hashing failed!");
    }
}

#endif // !DAEDALUS_TURBO_BLAKE2B_HPP
