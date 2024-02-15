/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#include <boost/ut.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/json.hpp>

using namespace boost::ut;
using namespace daedalus_turbo;

suite chunk_registry_suite = [] {
    "chunk_registry"_test = [] {
        static std::string data_dir { "./data/chunk-registry"s };
        static std::string tmp_data_dir { "./tmp/chunk-registry"s };
        scheduler sched {};
        "strict creation"_test = [&] {
            expect(throws([&] { chunk_registry cr { sched, data_dir }; cr.init_state(true, true); }));
            expect(nothrow([&] { chunk_registry cr { sched, data_dir }; cr.init_state(false, false); }));
        };
        {
            chunk_registry cr { sched, data_dir };
            cr.init_state(false, true);
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
                auto exp = std::filesystem::weakly_canonical(std::filesystem::absolute(data_dir) / "compressed/some-dir/some-file.ext");
                auto act = cr.full_path("some-dir/some-file.ext");
                expect(exp == act) << act;
                expect(throws([&] { cr.full_path("../../../../../etc/passwd"); }));
            };
            "rel_path"_test = [&] {
                auto full_path = std::filesystem::weakly_canonical(std::filesystem::absolute(data_dir) / "compressed/some-dir/some-file.ext");
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
            chunk_registry cr { sched, tmp_data_dir };
            cr.init_state(false, true);
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
                    num_chunks += info.chunk_ids.size();
                }
            };

            std::filesystem::remove_all(tmp_data_dir);
            // 0, 1, 2, 1, 0, 2, 3
            auto j_chunks = json::load("./data/chunk-registry-new/epoch-merge.json").as_array();
            test_chunk_registry cr { sched, tmp_data_dir };
            expect(cr.epochs.empty());
            std::optional<uint64_t> max_epoch {};
            for (const auto &j_chunk: j_chunks) {
                auto chunk = chunk_registry::chunk_info::from_json(j_chunk.as_object());
                if (!max_epoch || chunk.last_slot.epoch() > *max_epoch)
                    max_epoch = chunk.last_slot.epoch();
                cr.add(std::move(chunk));
                auto exp_epochs = json::value_to<uint64_t>(j_chunk.at("expNumEpochs"));
                expect(cr.epochs.size() == exp_epochs) << exp_epochs << cr.epochs.size();
            }
            cr.save_state();
            expect(cr.num_chunks == j_chunks.size()) << cr.num_chunks;
            expect(static_cast<bool>(max_epoch));
            if (max_epoch && !cr.epochs.empty())
                expect(*max_epoch == *cr.epochs.rbegin()) << fmt::format("{}", cr.epochs);
        };
    };
};