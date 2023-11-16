/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/index/txo-use.hpp>
#include <dt/indexer.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;
using namespace daedalus_turbo::indexer;

suite indexer_suite = [] {
    "indexer"_test = [] {
        static const std::string db_dir { "./data/chunk-registry" };
        static const std::string idx_dir { "./tmp/index" };
        "incremental"_test = [=] {
            static const std::string tmp_db_dir { "./tmp/compressed" };
            std::filesystem::remove_all(tmp_db_dir);
            std::filesystem::remove_all(idx_dir + "/txo-use");
            {
                scheduler sched {};
                chunk_registry src_cr { sched, db_dir };
                src_cr.init_state(false, true, false);
                indexer_map indexers {};
                indexers.emplace(std::make_unique<index::txo_use::indexer>(sched, idx_dir, "txo-use"));
                incremental idxr { sched, tmp_db_dir, indexers };
                idxr.import(src_cr);
            }
            {
                index::reader_multi<index::txo_use::item> reader { indexer::multi_reader_paths(idx_dir, "txo-use") };
                index::txo_use::item i {};
                size_t read_count = 0;
                while (reader.read(i)) {
                    ++read_count;
                }
                expect(read_count == 226251_u) << read_count;
                expect(read_count == reader.size());
            }
        };
    };    
};