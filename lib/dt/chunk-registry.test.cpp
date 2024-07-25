/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/chunk-registry.hpp>
#include <dt/json.hpp>
#include <dt/test.hpp>

namespace {
    using namespace daedalus_turbo;

    static void copy_chunk(chunk_registry &dst_cr, const chunk_registry &src_cr, const storage::chunk_info &chunk)
    {
        const auto dst_path = dst_cr.full_path(chunk.rel_path());
        const auto src_path = src_cr.full_path(chunk.rel_path());
        std::filesystem::remove(dst_path);
        std::filesystem::copy(src_path, dst_path);
        dst_cr.add(dst_cr.num_bytes(), dst_path);
    }
}

suite chunk_registry_suite = [] {
    "chunk_registry"_test = [] {
        static std::string data_dir { "./data/chunk-registry"s };
        static std::string tmp_data_dir { "./tmp/chunk-registry"s };

        const auto recreate_tmp_data_dir = [&] {
            std::filesystem::remove_all(tmp_data_dir);
            std::filesystem::create_directories(tmp_data_dir);
            std::filesystem::copy(data_dir, tmp_data_dir, std::filesystem::copy_options::recursive | std::filesystem::copy_options::overwrite_existing);
        };

        "strict creation"_test = [&] {
            expect(throws([&] { chunk_registry cr { data_dir, chunk_registry::mode::validate }; }));
            expect(nothrow([&] { chunk_registry cr { data_dir, chunk_registry::mode::store }; }));
        };

        "empty"_test = [&] {
            std::filesystem::remove_all(tmp_data_dir);
            chunk_registry cr { tmp_data_dir, chunk_registry::mode::validate };
            expect(cr.num_chunks() == 0_ull);
            expect(cr.num_bytes() == 0_ull);
            expect(cr.num_compressed_bytes() == 0_ull);
            expect(cr.max_slot() == 0_ull);
            expect(!cr.last_block());
            expect(!cr.last_chunk());
            expect(!cr.has_epoch(0));
            expect(cr.epochs().empty());
            expect(cr.chunks().empty());
            expect(&cr.sched() == &scheduler::get());
            expect(&cr.remover() == &file_remover::get());
            expect(cr.data_dir() == tmp_data_dir);
            expect(!cr.tx());
        };

        // access
        {
            chunk_registry cr { data_dir, chunk_registry::mode::store };
            "create chunk registry"_test = [&cr] {
                expect(cr.chunks().size()) << cr.num_chunks();
                expect(cr.num_chunks() == 8_u) << cr.num_chunks();
                expect(cr.num_bytes() == 175'115'499_u) << cr.num_bytes();
            };
            "find"_test = [&cr] {
                expect(static_cast<bool>(cr.last_chunk()));
                expect(static_cast<bool>(cr.last_block()));
                const auto rel_path = cr.find_offset(100'000'000).rel_path();
                test_same(rel_path, "chunk/47F62675C9B0161211B9261B7BB1CF801EDD4B9C0728D9A6C7A910A1581EED41.zstd");
                expect(throws([&cr] { cr.find_offset(200'000'000); }));
                expect(cr.find_block_by_offset(100'000'000).offset == 99'936'542_ull);
                expect(throws([&cr] { cr.find_block_by_offset(200'000'000); }));
                expect(cr.find_last_block_hash(cardano::block_hash::from_hex("EF282E85A8EF8A9C31D255C736F52AA0D52BEA260276BF2FB4AF3ADB700D0F1B")).offset == 84'430'954_ull);
                expect(throws([&cr] { cr.find_last_block_hash(cardano::block_hash {}); }));
                expect(cr.find_block_by_offset(100'000'000).slot == 71420546ULL) << fmt::format("{}", cr.find_block_by_offset(100'000'000).slot);
                expect(throws([&cr] { cr.find_block_by_offset(200'000'000); }));
                expect(cr.find_block_by_slot(71431152).offset == 120'772'796_ull);
                expect(throws([&cr] { cr.find_block_by_slot(72'000'000); }));
                expect(cr.find_offset_it(100'000'000)->second.offset == 84'430'954_ull);
                expect(throws([&cr] { cr.find_offset_it(200'000'000); }));
                expect(cr.find_data_hash_it(cardano::block_hash::from_hex("47F62675C9B0161211B9261B7BB1CF801EDD4B9C0728D9A6C7A910A1581EED41"))->second.offset == 84'430'954_ull);
                expect(cr.find_data_hash_it(cardano::block_hash {}) == cr.chunks().end());
            };
            "read"_test = [&cr] {
                cbor_value block_tuple {};
                cr.read(28'762'567, block_tuple);
                expect(block_tuple.type == CBOR_ARRAY) << block_tuple.type;
                expect(block_tuple.array().size() == 2_u);
            };
        }
        {
            chunk_registry cr { tmp_data_dir, chunk_registry::mode::store };
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

        "truncate chunk boundary"_test = [&] {
            recreate_tmp_data_dir();
            chunk_registry cr { tmp_data_dir, chunk_registry::mode::store };
            const auto before_tip = cr.tip();
            const auto before_size = cr.num_bytes();
            const auto before_slot = cr.max_slot();
            const auto before_chunks = cr.num_chunks();
            cr.truncate(before_tip);
            expect(before_size == cr.num_bytes());
            const auto mid_point = cr.find_block_by_offset(before_size / 2).point();
            expect(mid_point < before_tip);
            cr.truncate(mid_point);
            expect(cr.tip() == mid_point);
            expect(cr.max_slot() < before_slot);
            expect(cr.num_chunks() < before_chunks);
            cr.truncate({});
            test_same(cr.num_bytes(), 0);
            test_same(cr.max_slot(), 0);
            test_same(cr.num_chunks(), 0);
        };

        "truncate block boundary"_test = [&] {
            recreate_tmp_data_dir();
            chunk_registry cr { tmp_data_dir, chunk_registry::mode::store };
            const auto before_size = cr.num_bytes();
            const auto before_slot = cr.max_slot();
            const auto before_chunks = cr.num_chunks();
            const auto before_blocks = cr.num_blocks();
            expect(before_size == 175115499_ull);
            const auto last_chunk = cr.last_chunk();
            expect(!!last_chunk);
            if (last_chunk) {
                const auto &blocks = last_chunk->blocks;
                const auto new_tip = blocks.at(blocks.size() - 2).point();
                cr.truncate(new_tip);
                test_same(cr.tip(), new_tip);
                expect(cr.num_blocks() == before_blocks - 1);
                expect(cr.num_chunks() == before_chunks);
                expect(cr.max_slot() == 74044763_ull);
                expect(cr.max_slot() != before_slot);
            }
        };

        "count_blocks_in_window"_test = [&] {
            chunk_registry src_cr { data_dir, chunk_registry::mode::store };
            expect(src_cr.count_blocks_in_window() == 9601_ull);
            expect(src_cr.count_blocks_in_window(cardano::point { cardano::block_hash::from_hex("89D9B5A5B8DDC8D7E5A6795E9774D97FAF1EFEA59B2CAF7EAF9F8C5B32059DF4"), 0 }) == 9601_ull);
            expect(src_cr.count_blocks_in_window(cardano::point { cardano::block_hash::from_hex("67A3718CE1F14DBC20D156D619CB027E0F234F6D3BB570FE79DFFB62C4F82FF7"), 21'500 }) == 100_ull);
            expect(src_cr.count_blocks_in_window(cardano::point { {}, 71'405'000 }) == 254_ull);
            expect(src_cr.count_blocks_in_window(cardano::point { {}, 71'415'000 }) == 475_ull);
            expect(src_cr.count_blocks_in_window(cardano::point { {}, 74'030'000 }) == 492_ull);
            expect(src_cr.count_blocks_in_window(cardano::point { {}, 100'000'000 }) == 0_ull);
        };

        "epoch-level auto-merge"_test = [&] {
            std::filesystem::remove_all(tmp_data_dir);
            // 0, 1, 2, 1, 0, 2, 3
            std::set<uint64_t> epochs {};
            size_t num_bytes = 0;
            static const std::string src_dir { "./data/chunk-registry-new" };
            auto j_chunks = json::load(src_dir + "/epoch-merge.json").as_array();
            chunk_processor proc {
                .on_epoch_update = [&](const auto epoch, const auto &info) {
                    epochs.emplace(epoch);
                    num_bytes += info.size();
                }
            };
            chunk_registry cr { tmp_data_dir, chunk_registry::mode::store };
            cr.register_processor(proc);
            expect(epochs.empty());

            cardano::point target_tip {
                cardano::block_hash::from_hex("CB7B006C985635E9197FE7D005E1598391AA2CA1DD507543743E416E84B2F1B9"),
                79999, 79999
            };
            {
                uint64_t target_offset = 0;
                for (const auto &j_chunk: j_chunks) {
                    auto src_path = fmt::format("{}/{}", src_dir, static_cast<std::string_view>(j_chunk.at("relPath").as_string()));
                    target_offset += std::filesystem::file_size(src_path);
                }
                target_tip.end_offset = target_offset;
            }

            const auto ex_ptr = cr.accept_progress({}, target_tip, [&]{
                for (const auto &j_chunk: j_chunks) {
                    std::string orig_rel_path { static_cast<std::string_view>(j_chunk.at("relPath").as_string()) };
                    const auto src_path = fmt::format("{}/{}", src_dir, orig_rel_path);
                    const auto offset = json::value_to<uint64_t>(j_chunk.at("offset"));
                    const auto local_path = cr.full_path(orig_rel_path);
                    const auto data = file::read(src_path);
                    const auto compressed = zstd::compress(data);
                    file::write(local_path, compressed);
                    cr.add(offset, local_path);
                    auto exp_max_epoch = json::value_to<uint64_t>(j_chunk.at("expMaxEpoch"));
                    auto act_max_epoch = epochs.empty() ? 0 : *epochs.rbegin();
                    test_same(act_max_epoch, exp_max_epoch);
                }
            });
            expect(!cr.tx());
            expect(!ex_ptr);
            test_same(2602139, num_bytes);
            if (!epochs.empty())
                expect(3 == *epochs.rbegin()) << fmt::format("{}", epochs);
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
            chunk_registry cr { data_dir, chunk_registry::mode::store };
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
        "epoch info"_test = [&] {
            expect(throws([]{
                epoch_info::chunk_list no_chunks {};
                epoch_info { std::move(no_chunks) };
            }));
            chunk_registry cr { data_dir, chunk_registry::mode::store };
            uint64_t total_size = 0;
            uint64_t total_compressed_size = 0;
            std::optional<cardano::block_hash> last_block_hash {};
            std::optional<uint64_t> last_slot {};
            for (const auto &[epoch, einfo]: cr.epochs()) {
                // need a strict test data set to re-enable the following check
                // if (last_block_hash)
                //    expect(*last_block_hash == einfo.prev_block_hash()) << epoch;
                last_block_hash = einfo.last_block_hash();
                if (last_slot)
                    expect(einfo.last_slot() >= *last_slot);
                last_slot = einfo.last_slot();
                expect(einfo.start_offset() == total_size);
                total_size += einfo.size();
                expect(einfo.end_offset() == total_size);
                expect(einfo.size() == einfo.end_offset() - einfo.start_offset());
                total_compressed_size += einfo.compressed_size();
            }
            expect(cr.num_bytes() == total_size);
            expect(cr.num_compressed_bytes() == total_compressed_size);
            expect(static_cast<bool>(last_block_hash));
            expect(static_cast<bool>(cr.last_block()));
            if (last_block_hash && cr.last_block())
                expect(*last_block_hash == cr.last_block()->hash);
            if (last_slot)
                expect(*last_slot == cr.max_slot());
        };
        "progress despite errors and rollback"_test = [&] {
            chunk_registry src_cr { data_dir, chunk_registry::mode::store };
            std::filesystem::remove_all(tmp_data_dir);
            chunk_registry dst_cr { tmp_data_dir, chunk_registry::mode::store };
            expect(dst_cr.num_chunks() == 0_ull);
            expect(!!dst_cr.accept_progress({}, src_cr.tip(), [&] {
                throw error("something went wrong");
                copy_chunk(dst_cr, src_cr, src_cr.chunks().begin()->second);
            }));
            expect(dst_cr.num_chunks() == 0_ull) << dst_cr.num_chunks();
            expect(!dst_cr.tx());
            expect(!dst_cr.accept_progress({}, src_cr.tip(), [&] {
                copy_chunk(dst_cr, src_cr, src_cr.chunks().begin()->second);
            }));
            expect(!dst_cr.tx());
            test_same(dst_cr.num_chunks(), 1);
            expect(!!dst_cr.accept_progress({}, src_cr.tip(), [&] {
                copy_chunk(dst_cr, src_cr, src_cr.chunks().begin()->second);
                throw error("something went wrong");
                copy_chunk(dst_cr, src_cr, (++src_cr.chunks().begin())->second);
            }));
            expect(!dst_cr.tx());
            test_same(dst_cr.num_chunks(), 1);
        };
    };
};