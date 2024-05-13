/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <dt/cbor.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, const size_t size)
{
    using namespace daedalus_turbo;
    try {
        const auto val = cbor::parse(buffer { data, size });
    } catch (const error &err) {
        // ignore the library's exceptions
    }
    return 0;
}