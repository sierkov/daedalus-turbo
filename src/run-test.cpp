/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <iostream>
#include <dt/test.hpp>

int main(const int argc, const char **argv)
{
    using namespace daedalus_turbo;
    consider_install_dir(argv[0]);
    if (argc >= 2) {
        std::cerr << "using test-filter mask: " << argv[1] << '\n';
        boost::ut::cfg<boost::ut::override> = { .filter = argv[1] };
    }
    const bool res = boost::ut::cfg<boost::ut::override>.run();
    logger::info("run-test finished with {}", res ? "failures" : "success");
    return 0;
}
