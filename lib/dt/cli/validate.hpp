/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_CLI_VALIDATE_HPP
#define DAEDALUS_TURBO_CLI_VALIDATE_HPP

#include <dt/cli.hpp>
#include <dt/validator.hpp>

namespace daedalus_turbo::cli::validate {
    struct cmd: command {
        const command_info &info() const override;
        void run(const arguments &args) const override;
    private:
        using chunk_registry = daedalus_turbo::chunk_registry;
        using chunk_info = chunk_registry::chunk_info;
        using chunk_list = chunk_registry::chunk_list;

        mutable progress::info _parse_progress {};

        void _validate_chunks(scheduler &sched, chunk_registry &cr, chunk_list &&chunks) const;
    };
}

#endif // !DAEDALUS_TURBO_CLI_VALIDATE_HPP