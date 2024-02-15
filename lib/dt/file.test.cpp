/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/file.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite file_suite = [] {
    "file"_test = [] {
        "read"_test = [] {
            auto buf = file::read("./data/immutable/04307.chunk");
            expect(buf.size() == 52'958'359) << buf.size();
        };
        "read_zstd"_test = [] {
            auto buf = file::read("./data/chunk-registry/compressed/immutable/9C5C0267DCA941851D0330E19B91712618EB6DB4BF17E458BCF00829F84CF3CF.zstd");
            expect(buf.size() == 42'052'372) << buf.size();
        };
        "tmp"_test = [] {
            std::string tmp_path {};
            {
                file::tmp tmp1 { "hello.txt" };
                tmp_path = tmp1.path();
                expect(!std::filesystem::exists(tmp1.path()));
                file::write(tmp1.path(), std::string_view { "Hello\n" });
                expect(std::filesystem::exists(tmp1.path()));
                expect(std::filesystem::file_size(tmp1.path()));
            }
            expect(!std::filesystem::exists(tmp_path));
        };
        "64-bit seek and tell"_test = [] {
            file::tmp tmp_f { "file-seek-test.bin" };
            file::write_stream ws { tmp_f };
            auto exp_pos = 1ULL << 33;
            std::string data { "hello, write!" };
            ws.seek(exp_pos);
            expect(ws.tellp() == exp_pos) << ws.tellp();
            ws.write(data.data(), data.size());
            expect(ws.tellp() == exp_pos + data.size()) << ws.tellp();
            ws.close();

            expect(std::filesystem::file_size(tmp_f.path()) == exp_pos + data.size());
            file::read_stream rs { tmp_f };
            rs.seek(exp_pos);
            std::string read_data {};
            read_data.resize(data.size());
            rs.read(read_data.data(), data.size());
            expect(read_data == data) << read_data;
        };
    };
};