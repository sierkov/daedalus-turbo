/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/index/txo-use.hpp>
#include <dt/indexer.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::indexer;

suite indexer_suite = [] {
    "indexer"_test = [] {
        static const std::string src_dir { "./data/chunk-registry" };
        static const std::string data_dir { "./tmp/indexer" };
        static const auto idx_dir = indexer::incremental::storage_dir(data_dir);
        "incremental"_test = [&] {
            std::filesystem::remove_all(data_dir);
            {
                chunk_registry src_cr { src_dir, false };
                indexer_map indexers {};
                indexers.emplace(std::make_unique<index::txo_use::indexer>(idx_dir, "txo-use"));
                incremental idxr { std::move(indexers), data_dir, false };
                idxr.import(src_cr);
            }
            {
                indexer_map indexers {};
                indexers.emplace(std::make_unique<index::txo_use::indexer>(idx_dir, "txo-use"));
                incremental idxr { std::move(indexers), data_dir, false };
                index::reader_multi<index::txo_use::item> reader { idxr.reader_paths("txo-use") };
                index::txo_use::item i {};
                size_t read_count = 0;
                while (reader.read(i)) {
                    ++read_count;
                }
                expect(read_count == 244'802_ull) << read_count;
                expect(read_count == reader.size());
            }
        };
    };    
};