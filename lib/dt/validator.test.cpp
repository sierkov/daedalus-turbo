/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cardano.hpp>
#include <dt/sync/mocks.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/test.hpp>

namespace {
    using namespace daedalus_turbo;
    using namespace daedalus_turbo::sync;
}

suite validator_suite = [] {
    "validator"_test = [] {
        static std::string data_dir { "tmp/validator" };
        "success"_test = [&] {
            std::filesystem::remove_all(data_dir);
            const std::string chunk1_name { "chunk1.chunk" };
            const auto chunk1_path = fmt::format("{}/{}", data_dir, chunk1_name);
            const auto chain1 = gen_chain();
            file::write_zstd(chunk1_path, chain1.data);
            chunk_registry cr { data_dir, chunk_registry::mode::validate, chain1.cfg };
            test_same(cr.valid_end_offset(), 0);
            const auto ex_ptr = cr.accept_progress({}, chain1.tip, [&] {
                cr.add(0, chunk1_path);
            });
            expect(!ex_ptr);
            expect(cr.valid_end_offset() == chain1.data.size()) << cr.valid_end_offset();
        };
        "rollback"_test = [&] {
            std::filesystem::remove_all(data_dir);
            const std::string chunk1_name { "chunk1.chunk" };
            const auto chunk1_path = fmt::format("{}/{}", data_dir, chunk1_name);
            const auto chain1 = gen_chain();
            file::write_zstd(chunk1_path, chain1.data);
            chunk_registry cr { data_dir, chunk_registry::mode::validate, chain1.cfg };
            expect(cr.valid_end_offset() == 0_ull);
            const auto ex_ptr = cr.accept_progress({}, chain1.tip, [&] {
                throw error("some failure, rollback now");
                cr.add(0, chunk1_path);
            });
            expect(static_cast<bool>(ex_ptr));
            expect(cr.valid_end_offset() == 0_ull);
        };
        "progress_despite_failure"_test = [&] {
            std::filesystem::remove_all(data_dir);
            const std::string chunk1_name { "chunk1.chunk" };
            const auto chunk1_path = fmt::format("{}/{}", data_dir, chunk1_name);
            const auto chain1 = gen_chain();
            file::write_zstd(chunk1_path, chain1.data);
            chunk_registry cr { data_dir, chunk_registry::mode::validate, chain1.cfg };
            expect(cr.valid_end_offset() == 0_ull);
            const auto ex_ptr = cr.accept_progress({}, chain1.tip, [&] {
                cr.add(0, chunk1_path);
                throw error("some failure, rollback now");
            });
            expect(!ex_ptr);
            expect(cr.valid_end_offset() == chain1.data.size()) << cr.valid_end_offset();
        };
        "failure at block 7"_test = [&] {
            static constexpr uint64_t failure_height = 7;
            std::filesystem::remove_all(data_dir);
            const std::string chunk1_name { "chunk1.chunk" };
            const auto chunk1_path = fmt::format("{}/{}", data_dir, chunk1_name);
            const auto chain1 = gen_chain({ .failure_height=failure_height });
            file::write_zstd(chunk1_path, chain1.data);
            chunk_registry cr { data_dir, chunk_registry::mode::validate, chain1.cfg };
            expect(cr.valid_end_offset() == 0_ull);
            const auto ex_ptr = cr.accept_progress({}, chain1.tip, [&] {
                cr.add(0, chunk1_path);
            });
            expect(!ex_ptr);
            expect(cr.num_blocks() == failure_height) << cr.num_blocks();
            expect(cr.valid_end_offset() < chain1.data.size()) << cr.valid_end_offset();
        };
    };
};