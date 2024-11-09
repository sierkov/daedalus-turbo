/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#ifndef DAEDALUS_TURBO_CLI_COMMON_HPP
#define DAEDALUS_TURBO_CLI_COMMON_HPP

#include <dt/chunk-registry.hpp>
#include <dt/cli.hpp>

namespace daedalus_turbo::cli::common {
    extern void add_opts(config &cmd);
    extern chunk_registry::mode cr_mode(const options &opts);
}

#endif // !DAEDALUS_TURBO_CLI_COMMON_HPP
