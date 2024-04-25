/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/chunk-registry.hpp>
#include <dt/json.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite chunk_registry_suite = [] {
    "chunk_registry"_test = [] {
        static std::string data_dir { "./data/chunk-registry"s };
        static std::string tmp_data_dir { "./tmp/chunk-registry"s };
        "strict creation"_test = [&] {
            expect(throws([&] { chunk_registry cr { data_dir, true }; }));
            expect(nothrow([&] { chunk_registry cr { data_dir, false }; }));
        };
        {
            chunk_registry cr { data_dir, false };
            "create chunk registry"_test = [&cr] {
                expect(cr.chunks().size()) << cr.num_chunks();
                expect(cr.num_chunks() == 8_u) << cr.num_chunks();
                expect(cr.num_bytes() == 175'115'499_u) << cr.num_bytes();
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
        }
        {
            chunk_registry cr { tmp_data_dir, false };
            "full_path"_test = [&] {
                auto exp = std::filesystem::weakly_canonical(std::filesystem::absolute(tmp_data_dir) / "compressed/some-dir/some-file.ext");
                auto act = cr.full_path("some-dir/some-file.ext");
                expect(exp == act) << act;
                auto dir_path = cr.full_path("some-dir");
                expect(std::filesystem::exists(dir_path));
                std::filesystem::remove_all(dir_path);
                expect(throws([&] { cr.full_path("../../../../../etc/passwd"); }));
            };
            "rel_path"_test = [&] {
                auto full_path = std::filesystem::weakly_canonical(std::filesystem::absolute(tmp_data_dir) / "compressed/some-dir/some-file.ext");
                auto exp = std::filesystem::path { "some-dir/some-file.ext" }.make_preferred().string();
                auto act = cr.rel_path(full_path);
                expect(exp == act) << act;
                expect(throws([&] { cr.rel_path(std::filesystem::weakly_canonical("./data2/another-file.txt")); }));
            };
        }
        
        {
            std::filesystem::remove_all(tmp_data_dir);
            std::filesystem::create_directories(tmp_data_dir);
            std::filesystem::copy(data_dir, tmp_data_dir, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing);
            chunk_registry cr { tmp_data_dir, false };
            "truncate"_test = [&] {
                auto before_size = cr.num_bytes();
                auto before_slot = cr.max_slot();
                auto before_chunks = cr.num_chunks();
                cr.start_tx(before_size, before_size);
                cr.prepare_tx();
                cr.commit_tx();
                expect(before_size == cr.num_bytes());
                auto mid_offset = cr.find(before_size / 2).end_offset();
                expect(mid_offset < before_size);
                cr.start_tx(mid_offset, mid_offset);
                cr.prepare_tx();
                cr.commit_tx();
                expect(cr.num_bytes() == mid_offset);
                expect(cr.max_slot() < before_slot);
                expect(cr.num_chunks() < before_chunks);
                cr.start_tx(0, 0);
                cr.prepare_tx();
                cr.commit_tx();
                expect(cr.num_bytes() == 0_u);
                expect(cr.max_slot() == 0_u);
                expect(cr.num_chunks() == 0_u);
            };
        }

        "count_blocks_in_window"_test = [&] {
            chunk_registry src_cr { data_dir, false };
            expect(src_cr.count_blocks_in_window(0) == 9601_ull);
            expect(src_cr.count_blocks_in_window(21'500) == 100_ull);
            expect(throws([&]{ src_cr.count_blocks_in_window(71'405'000); }));
            expect(src_cr.count_blocks_in_window(71'415'000) == 475_ull);
            expect(src_cr.count_blocks_in_window(74'030'000) == 492_ull);
            expect(throws([&]{ src_cr.count_blocks_in_window(100'000'000); }));
        };

        "epoch-level auto-merge"_test = [&] {
            struct test_chunk_registry: chunk_registry
            {
                using chunk_registry::chunk_registry;

                std::set<uint64_t> epochs {};
                size_t num_chunks = 0;
            protected:
                // a new epoch is registered when all blocks of are added:
                // - there is a block from a later epoch that refers in its prev_block_hash to the last block of this one
                // - save_state is called and this epoch's blocks are the last ones
                void _on_epoch_merge(uint64_t epoch, const chunk_registry::epoch_info &info) override
                {
                    epochs.emplace(epoch);
                    num_chunks += info.chunks.size();
                }
            };

            std::filesystem::remove_all(tmp_data_dir);
            // 0, 1, 2, 1, 0, 2, 3
            static const std::string src_dir { "./data/chunk-registry-new" };
            auto j_chunks = json::load(src_dir + "/epoch-merge.json").as_array();
            test_chunk_registry cr { tmp_data_dir, false };
            expect(cr.epochs.empty());
            uint64_t target_offset = 0;
            for (const auto &j_chunk: j_chunks) {
                auto src_path = fmt::format("{}/{}", src_dir, static_cast<std::string_view>(j_chunk.at("relPath").as_string()));
                target_offset += std::filesystem::file_size(src_path);
            }
            cr.start_tx(0, target_offset);
            for (const auto &j_chunk: j_chunks) {
                std::string orig_rel_path { static_cast<std::string_view>(j_chunk.at("relPath").as_string()) };
                auto src_path = fmt::format("{}/{}", src_dir, orig_rel_path);
                auto offset = json::value_to<uint64_t>(j_chunk.at("offset"));
                auto data_hash = blake2b<cardano::block_hash>(file::read(src_path));
                auto local_path = cr.full_path(storage::chunk_info::rel_path_from_hash(data_hash));
                auto raw_data = file::read(src_path);
                auto compressed = zstd::compress(raw_data, 3);
                file::write(local_path, compressed);
                cr.add(offset, local_path, data_hash, orig_rel_path);
                auto exp_max_epoch = json::value_to<uint64_t>(j_chunk.at("expMaxEpoch"));
                auto act_max_epoch = cr.epochs.empty() ? 0 : *cr.epochs.rbegin();
                expect(act_max_epoch == exp_max_epoch) << orig_rel_path << exp_max_epoch << act_max_epoch;
            }
            cr.prepare_tx();
            cr.commit_tx();
            expect(cr.num_chunks == j_chunks.size()) << cr.num_chunks;
            if (!cr.epochs.empty())
                expect(3 == *cr.epochs.rbegin()) << fmt::format("{}", cr.epochs);
        };
        "parse_parallel"_test = [&] {
            struct res_t {
                size_t num_txs = 0;
                res_t &operator+=(const res_t &v)
                {
                    num_txs += v.num_txs;
                    return *this;
                }
            };
            chunk_registry cr { data_dir, false };
            res_t agg_res {};
            auto ok = cr.parse_parallel<res_t>(
                [&](auto &res, const auto &, auto &blk) {
                    res.num_txs += blk.tx_count();
                },
                [&](auto &&, auto &&res) {
                    agg_res += res;
                }
            );
            expect(ok);
            expect(agg_res.num_txs == 90'455_ull);
        };
    };
};