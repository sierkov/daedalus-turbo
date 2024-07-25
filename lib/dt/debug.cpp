/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/debug.hpp>

namespace daedalus_turbo::debug {
    bool &tracing_enabled()
    {
        static bool enabled = std::getenv("DT_DEBUG") != nullptr;
        return enabled;
    }
}