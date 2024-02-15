/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/validator.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;
using namespace daedalus_turbo::validator;

suite validator_suite = [] {
    "validator"_test = [] {
        static const std::string db_dir { "./data/chunk-registry" };
        static const std::string tmp_idx_dir { "./tmp/index" };
        static const std::string tmp_db_dir { "./tmp/compressed" };
        /*"incremental"_test = [=] {    
            std::filesystem::remove_all(tmp_db_dir);
            std::filesystem::remove_all(tmp_idx_dir);
            {
                scheduler sched {};
                chunk_registry src_cr { sched, db_dir };
                src_cr.init_state(false, true, false);
                incremental idxr { sched, tmp_db_dir, tmp_idx_dir };
                idxr.import(src_cr);
            }
            for (uint64_t epoch: { 0, 222, 247, 267, 297, 362, 368 }) {
                auto delta_path = index::indexer_base::reader_path(tmp_idx_dir, "epoch-delta", std::to_string(epoch));
                expect(index::writer<int>::disk_size(delta_path) > 0) << delta_path;
                auto dist_path = index::indexer_base::reader_path(tmp_idx_dir, "epoch-dist", std::to_string(epoch)) + ".bin";
                if (epoch <= 247)
                    expect(!std::filesystem::exists(dist_path)) << dist_path;
                else
                    expect(std::filesystem::file_size(dist_path) > 0) << dist_path;
            }
        };*/
    };
};