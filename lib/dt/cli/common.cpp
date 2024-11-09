/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cli/common.hpp>

namespace daedalus_turbo::cli::common {
    void add_opts(config &cmd)
    {
        cmd.opts.try_emplace("mode", "<store|index|validate> the activities to performed during synchronization", "validate");
    }

    chunk_registry::mode cr_mode(const options &opts)
    {
        const auto &mode_s = opts.at("mode").value();
        if (mode_s == "store")
            return chunk_registry::mode::store;
        if (mode_s == "index")
            return chunk_registry::mode::index;
        if (mode_s == "validate")
            return chunk_registry::mode::validate;
        throw error("unsupported mode: '{}'", mode_s);
    }
}
