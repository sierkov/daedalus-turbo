/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/file.hpp>
#include <dt/index/block-meta.hpp>

namespace {
    using namespace boost::ut;
    using namespace daedalus_turbo;
    using namespace daedalus_turbo::index;
}

suite index_block_meta_suite = [] {
    "index::block_meta"_test = [] {
        "index and read"_test = [] {
            std::string idx_dir { "./tmp/index" };
            std::filesystem::remove_all(idx_dir);
            scheduler sched {};
            index::block_meta::indexer idxr { sched, idx_dir, "block-meta" };
            size_t blk_count = 0;
            {
                auto chunk_idxr = idxr.make_chunk_indexer("update", 0);
                auto chunk = file::read("./data/chunk-registry/immutable/DF597E3FA352A7BD2F021733804C33729EBAA3DCAA9C0643BD263EFA09497B03.zstd");
                cbor_parser parser { chunk };
                cbor_value block_tuple {};
                while (!parser.eof()) {
                    parser.read(block_tuple);
                    auto blk = cardano::make_block(block_tuple, block_tuple.data - chunk.data());
                    blk_count++;
                    chunk_idxr->index(*blk);
                }
            }
            expect(std::filesystem::exists(idx_dir + "/block-meta/index-update-0.data"));
            reader<index::block_meta::item> rdr { idx_dir + "/block-meta/index-update-0" };
            expect(rdr.size() == blk_count);
        };
    };
};