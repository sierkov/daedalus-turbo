/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <iostream>
#include <boost/ut.hpp>

using namespace boost::ut;

int main(int argc, char **argv)
{
    std::ios_base::sync_with_stdio(false);
    if (argc >= 2) {
        std::cerr << "using test-filter mask: " << argv[1] << '\n';
        cfg<override> = { .filter = argv[1] };
    }
}