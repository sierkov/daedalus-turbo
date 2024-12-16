/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CBOR_COMPARE_HPP
#define DAEDALUS_TURBO_CBOR_COMPARE_HPP

#include <dt/util.hpp>

namespace daedalus_turbo::cbor {
    extern bool compare(const buffer &buf1, const buffer &buf2);
}

#endif // !DAEDALUS_TURBO_CBOR_COMPARE_HPP