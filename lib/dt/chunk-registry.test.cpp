/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/chunk-registry.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite chunk_registry_suite = [] {
    "chunk-registry"_test = [] {
        static std::string data_dir { "./data/chunk-registry"s };
        scheduler sched {};
        "strict creation"_test = [&] {
            expect(throws([&] { chunk_registry cr { sched, data_dir }; cr.init_state(true, true, false); }));
            expect(nothrow([&] { chunk_registry cr { sched, data_dir }; cr.init_state(false, false, false); }));
        };
        {
            chunk_registry cr { sched, data_dir };
            cr.init_state(false, true, false);
            "create chunk registry"_test = [&cr] {
                expect(cr.chunks().size()) << cr.num_chunks();
                expect(cr.num_chunks() == 8_u) << cr.num_chunks();
                expect(cr.num_bytes() == 162'960'922_u) << cr.num_bytes();
            };
            "find chunk"_test = [&cr] {
                const auto &orig_rel_path = cr.find(100'000'000).orig_rel_path;
                expect(orig_rel_path == "immutable/03306.chunk") << orig_rel_path;
            };
            "read"_test = [&cr] {
                cbor_value block_tuple {};
                cr.read(28'762'567, block_tuple);
                expect(block_tuple.type == CBOR_ARRAY) << block_tuple.type;
                expect(block_tuple.array().size() == 2_u);
            };
            "full_path"_test = [&] {
                auto exp = std::filesystem::weakly_canonical(std::filesystem::absolute(data_dir) / "some-dir/some-file.ext");
                auto act = cr.full_path("some-dir/some-file.ext");
                expect(exp == act) << act;
                expect(throws([&] { cr.full_path("../../../../../etc/passwd"); }));
            };
            "rel_path"_test = [&] {
                auto full_path = std::filesystem::weakly_canonical(std::filesystem::absolute(data_dir) / "some-dir/some-file.ext");
                auto exp = std::filesystem::path { "some-dir/some-file.ext" }.make_preferred().string();
                auto act = cr.rel_path(full_path);
                expect(exp == act) << act;
                expect(throws([&] { cr.rel_path(std::filesystem::weakly_canonical("./data2/another-file.txt")); }));
            };
        }
        
        {
            static std::string tmp_data_dir { "./tmp/chunk-registry"s };
            std::filesystem::remove_all(tmp_data_dir);
            std::filesystem::create_directories(tmp_data_dir);
            std::filesystem::copy(data_dir, tmp_data_dir, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing);
            chunk_registry cr { sched, tmp_data_dir };
            cr.init_state(false, true, false);
            "truncate"_test = [&] {
                auto before_size = cr.num_bytes();
                auto before_slot = cr.max_slot();
                auto before_chunks = cr.num_chunks();
                auto del_1 = cr.truncate(before_size);
                expect(del_1.size() == 0);
                expect(before_size == cr.num_bytes());
                auto del_2 = cr.truncate(before_size / 2);
                expect(del_2.size() > 0);
                expect(cr.num_bytes() < before_size / 2);
                expect(cr.max_slot() < before_slot);
                expect(cr.num_chunks() < before_chunks);
                auto del_3 = cr.truncate(0);
                expect(del_3.size() > 0);
                expect(del_2.size() + del_3.size() == before_chunks);
                expect(cr.num_bytes() == 0_u);
                expect(cr.max_slot() == 0_u);
                expect(cr.num_chunks() == 0_u);
            };
        }
    };
};