/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <iostream>
#include <boost/ut.hpp>
#include <dt/chunk-registry.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

suite chunk_registry_suite = [] {
    "create chunk registry"_test = [] {
        chunk_registry cr("./data");
        expect(cr.begin() != cr.end()) << cr.numChunks();
    };
};
