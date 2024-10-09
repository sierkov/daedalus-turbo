/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/container.hpp>
#include <dt/test.hpp>
#include <dt/zpp-stream.hpp>

namespace {
    using namespace daedalus_turbo;
}

suite zpp_suite = [] {
    "zpp_stream"_test = [] {
        vector<int> exp { 1, 2, 3 };
        file::tmp tmp { "test-zpp-1.bin" };
        {
            zpp_stream::write_stream ws { tmp };
            for (const auto &i: exp)
                ws.write(i);
        }
        vector<int> act {};
        {
            zpp_stream::read_stream rs { tmp };
            while (!rs.eof())
                act.emplace_back(rs.read<int>());
        }
        test_same(tmp.path(), exp, act);
    };
};
