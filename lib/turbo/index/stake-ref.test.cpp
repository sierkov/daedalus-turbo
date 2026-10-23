/* This file is part of TurboCardano project: https://github.com/r2rationality/turbocardano
 * Copyright (c) 2024-2026 R2 Rationality OÜ (info at r2rationality dot com)
 * License: https://github.com/r2rationality/turbocardano/blob/main/LICENSE */

#include <turbo/common/test.hpp>
#include <turbo/file.hpp>
#include <turbo/index/stake-ref.hpp>
#include <turbo/storage/chunk-info.hpp>

namespace {
    using namespace turbo;

    template<bool Script>
    void write_references(const std::string &path, const size_t slice)
    {
        // Small chunks exercise a credential spanning several compressed blocks.
        index::writer<index::stake_ref::item<Script>> writer { path, 256, 2 };
        for (const uint8_t prefix: { uint8_t { 0 }, uint8_t { 255 } }) {
            cardano::key_hash hash {};
            hash[0] = prefix;
            // Equal offsets across slices require the output-index tie-breaker.
            for (size_t i = 0; i < 3; ++i)
                writer.emplace_part(prefix, hash, 100 + i * 2, cardano::tx_size { 256 * (i + 1) }, slice);
        }
        writer.set_meta("max_offset", buffer::from(uint64_t { 110 }));
    }
}

suite stake_ref_suite = [] {
    "index::stake-ref"_test = [] {
        "transaction outputs are routed by stake credential kind"_test = [] {
            const file::tmp_directory dir { "stake-ref-routing" };
            const std::vector<std::string> scripts { fmt::format("{}/scripts.data", dir.path()) };
            const std::vector<std::string> keys { fmt::format("{}/keys.data", dir.path()) };
            // An enterprise output must be skipped without renumbering later outputs.
            cbor::encoder body {};
            body.map(3).uint(0).array(0).uint(1).array(3);
            body.array(2).bytes(uint8_vector::from_hex("60" + std::string(56, '0'))).uint(1);
            for (const auto header: { "00", "20" })
                body.array(2).bytes(uint8_vector::from_hex(header + std::string(56, '0') + std::string(56, 'F'))).uint(1);
            body.uint(2).uint(0);
            auto parsed = cbor::zero2::parse(body.cbor());
            storage::block_info meta {};
            meta.era = 7;
            const cardano::tx_container tx { meta, 100, parsed.get(), 0, cardano::config::get() };
            {
                index::stake_ref::chunk_indexer<true> script_index { scripts.front(), 1 };
                index::stake_ref::chunk_indexer<false> key_index { keys.front(), 1 };
                script_index.index_tx(*tx);
                key_index.index_tx(*tx);
            }
            index::stake_ref::reader reader { scripts, keys };
            expect(reader.size() == 2_ul);
            for (const bool script: { true, false }) {
                cardano::credential_t id { {}, script };
                id.hash.fill(0xff);
                auto [count, record] = reader.find({ id });
                expect(fatal(count == 1_ul));
                expect(record.id == id);
                expect(record.offset == tx->offset());
                expect(record.size == cardano::tx_size { tx->size() });
                expect_equal(static_cast<size_t>(record.out_idx), script ? 2U : 1U);
                expect(!reader.read(record));
            }
        };
        "split streams route queries and merge in credential order"_test = [] {
            const file::tmp_directory dir { "stake-ref-streams" };
            std::vector<std::string> scripts, keys;
            for (size_t slice = 0; slice < 2; ++slice) {
                scripts.emplace_back(fmt::format("{}/scripts-{}.data", dir.path(), slice));
                keys.emplace_back(fmt::format("{}/keys-{}.data", dir.path(), slice));
                write_references<true>(scripts.back(), slice);
                write_references<false>(keys.back(), slice);
            }
            index::stake_ref::reader reader { scripts, keys };
            expect(reader.size() == 24_ul);
            for (const bool script: { true, false, true }) {
                for (const uint8_t prefix: { uint8_t { 0 }, uint8_t { 255 } }) {
                    cardano::credential_t id { {}, script };
                    id.hash[0] = prefix;
                    auto [count, record] = reader.find({ id });
                    expect(fatal(count == 6_ul))
                        << fmt::format("credential {}: expected 6 matches, got {}", id, count);
                    std::set<std::pair<uint64_t, size_t>> outputs;
                    for (size_t i = 0; i < count; ++i) {
                        if (i)
                            expect(fatal(reader.read(record)));
                        expect(record.id == id);
                        outputs.emplace(record.offset, static_cast<size_t>(record.out_idx));
                        expect(static_cast<size_t>(record.size) == 256 * (1 + (record.offset - 100) / 2));
                    }
                    const std::set<std::pair<uint64_t, size_t>> expected {
                        { 100, 0 }, { 100, 1 }, { 102, 0 }, { 102, 1 }, { 104, 0 }, { 104, 1 }
                    };
                    expect(outputs == expected);
                    expect(!reader.read(record));
                    id.hash.back() = 1;
                    expect(reader.find({ id }).first == 0_ul);
                    expect(!reader.read(record));
                }
            }
            std::vector<index::stake_ref::reference> records;
            reader.foreach([&](const auto &record) { records.emplace_back(record); });
            expect(fatal(records.size() == 24_ul));
            for (size_t i = 0; i < records.size(); ++i) {
                const auto &record = records[i];
                cardano::credential_t id { {}, i < 12 };
                id.hash[0] = i % 12 < 6 ? 0 : 255;
                expect(record.id == id);
                expect(record.offset == 100 + i % 6 / 2 * 2);
                expect(static_cast<size_t>(record.size) == 256 * (1 + i % 6 / 2));
                expect(static_cast<size_t>(record.out_idx) == i % 2);
            }
            expect(throws([&] { index::reader<index::stake_ref::item<false>> wrong_kind { scripts.front() }; }));

            // Merging must retain the stream format and its 256 hash partitions.
            const auto merged_path = fmt::format("{}/merged.data", dir.path());
            {
                using item_type = index::stake_ref::item<true>;
                std::vector<std::shared_ptr<index::reader_mt<item_type>>> inputs;
                for (const auto &path: scripts)
                    inputs.emplace_back(std::make_shared<index::reader_mt<item_type>>(path));
                index::writer<item_type> merged { merged_path, 256, 3 };
                for (size_t part = 0; part < 256; ++part)
                    index::merge_index_part(merged, part, inputs);
            }
            index::reader<index::stake_ref::item<true>> merged { merged_path };
            expect(merged.num_parts() == 256_ul);
            expect(merged.size() == 12_ul);
            expect(static_cast<std::string_view>(merged.get_meta("format"))
                == index::stake_ref::item<true>::index_format);
            index::stake_ref::item<true> item {};
            for (size_t i = 0; i < 12; ++i) {
                expect(fatal(merged.read(item)));
                expect(item.hash == records[i].id.hash);
                expect(item.offset == records[i].offset);
                expect(item.size == records[i].size);
                expect(item.out_idx == records[i].out_idx);
            }
            expect(!merged.read(item));

            index::reader<index::stake_ref::item<true>> sparse { scripts.front() };
            expect(!sparse.eof());
            size_t count = 0;
            while (sparse.read(item)) ++count;
            expect(count == 6_ul);
            expect(sparse.eof());
            auto last_part = sparse.mt().init_thread(255);
            expect(!sparse.mt().eof(last_part));
            count = 0;
            while (sparse.mt().read_part(255, item, last_part)) ++count;
            expect(count == 3_ul);
            expect(sparse.mt().eof(last_part));

            index::reader_multi_mt<index::stake_ref::item<true>> multiple { scripts };
            auto all_parts = multiple.init_thread();
            count = 0;
            while (multiple.read_part(255, item, all_parts)) ++count;
            expect(count == 6_ul);
        };

        "empty and legacy streams"_test = [] {
            const file::tmp_directory dir { "stake-ref-empty" };
            const std::vector<std::string> scripts { fmt::format("{}/scripts.data", dir.path()) };
            const std::vector<std::string> keys { fmt::format("{}/keys.data", dir.path()) };
            {
                index::writer<index::stake_ref::item<true>> out { scripts.front(), 256 };
                index::writer<index::stake_ref::item<false>> other { keys.front(), 256 };
            }
            index::stake_ref::reader reader { scripts, keys };
            expect(reader.size() == 0_ul);
            size_t visited = 0;
            reader.foreach([&](const auto &) { ++visited; });
            expect(visited == 0_ul);
            expect(reader.find({ cardano::credential_t { {}, true } }).first == 0_ul);
            const std::vector<std::string> no_paths;
            index::stake_ref::reader no_slices { no_paths, no_paths };
            no_slices.foreach([&](const auto &) { ++visited; });
            expect(visited == 0_ul);
            expect(no_slices.find({ cardano::credential_t {} }).first == 0_ul);

            const auto legacy = fmt::format("{}/legacy.data", dir.path());
            { index::writer<uint64_t> out { legacy, 256 }; }
            expect(throws([&] { index::reader<index::stake_ref::item<true>> old { legacy }; }));
        };
    };
};
