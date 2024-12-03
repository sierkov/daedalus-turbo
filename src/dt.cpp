/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cli.hpp>

int main(const int argc, const char **argv)
{
    using namespace daedalus_turbo;
    consider_bin_dir(argv[0]);
    return cli::run(argc, argv);
}