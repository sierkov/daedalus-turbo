/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/cli/validate.hpp>
#include <dt/ed25519.hpp>
#include <dt/requirements.hpp>

namespace daedalus_turbo::cli::validate {
    const command_info &cmd::info() const
    {
        static const command_info i {
            "revalidate", "<data-dir>",
            "revalidate chain in <data-dir> from byte 0"
        };
        return i;
    }

    void cmd::run(const cli::arguments &args) const
    {
        if (args.size() < 1) _throw_usage();
        timer t { "validation", logger::level::trace };
        const auto &data_dir = args.at(0);
        requirements::check(data_dir);
        ed25519::init();        
        progress_guard pg { "parse", "merge", "leaders" };
        uint64_t end_offset = 0;
        chunk_list chunks {};
        scheduler sched {};
        {
            chunk_registry cr { sched, data_dir };
            cr.init_state();
            end_offset = cr.num_bytes();
            for (const auto &[offset, chunk]: cr.chunks()) {
                chunks.emplace_back(chunk);
            }
        }
        auto indexers = validator::default_indexers(sched, data_dir);
        validator::incremental cr { sched, data_dir, indexers, true };
        _parse_progress.total = end_offset;
        cr.target_offset(end_offset);
        _validate_chunks(sched, cr, std::move(chunks));
        cr.save_state();
        if (!cr.chunks().empty()) {
            const auto &last_chunk = cr.chunks().rbegin()->second;
            logger::info("validation complete last_slot: {} last_block: {} took: {:0.1f} secs",
                last_chunk.last_slot, last_chunk.last_block_hash, t.stop(false));
        }
    }

    std::string cmd::_parse_local_chunk(chunk_registry &cr, const chunk_info &chunk, const std::string &save_path) const
    {
        try {
            auto compressed = file::read_raw(save_path);
            uint8_vector data {};
            zstd::decompress(data, compressed);
            auto parsed_chunk = cr.parse(chunk.offset, chunk.orig_rel_path, data, compressed.size());
            if (parsed_chunk.data_hash != chunk.data_hash)
                throw error("data hash does not match for the chunk: {}", save_path);
            cr.add(std::move(parsed_chunk));
            return save_path;
        } catch (std::exception &ex) {
            std::filesystem::path orig_path { save_path };
            auto debug_path = cr.full_path(fmt::format("error/{}", orig_path.filename().string()));
            logger::warn("moving an unparsable chunk {} to {}", save_path, debug_path);
            std::filesystem::copy_file(save_path, debug_path, std::filesystem::copy_options::overwrite_existing);
            throw error("can't parse {}: {}", save_path, ex.what());
        }
    }

    void cmd::_validate_chunks(scheduler &sched, chunk_registry &cr, chunk_list &&chunks) const
    {
        timer t { "validate chunks" };
        for (const auto &chunk: chunks) {
            auto save_path = cr.full_path(chunk.rel_path());
            sched.submit("parse", 0 + 100 * (_parse_progress.total - chunk.offset) / _parse_progress.total, [this, &cr, chunk, save_path]() {
                return _parse_local_chunk(cr, chunk, save_path);
            });
        }
        sched.process(true);
    }
}