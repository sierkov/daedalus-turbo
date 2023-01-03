/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <iostream>
#include <boost/ut.hpp>

using namespace std;
using namespace boost::ut;

int main(int argc, char **argv)
{
    if (argc >= 2) {
        cerr << "using test-filter mask: " << argv[1] << endl;
        cfg<override> = {.filter = argv[1] };
    }
}
