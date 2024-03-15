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
            "revalidate the blockchain in <data-dir> from scratch"
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
        progress_guard pg { "parse", "merge", "validate" };
        uint64_t end_offset = 0;
        chunk_list chunks {};
        {
            chunk_registry cr { data_dir };
            end_offset = cr.num_bytes();
            for (const auto &[offset, chunk]: cr.chunks()) {
                chunks.emplace_back(chunk);
            }
        }
        // remove all previously prepared indices and validator snapshots
        std::filesystem::remove_all(std::filesystem::path { data_dir } / "index");
        std::filesystem::remove_all(std::filesystem::path { data_dir } / "validate");
        validator::incremental cr { validator::default_indexers(data_dir), data_dir,  };
        _parse_progress.total = end_offset;
        cr.target_offset(end_offset);
        _validate_chunks(scheduler::get(), cr, std::move(chunks));
        cr.save_state();
        if (!cr.chunks().empty()) {
            const auto &last_chunk = cr.chunks().rbegin()->second;
            logger::info("validation complete last_slot: {} last_block: {} took: {:0.1f} secs",
                last_chunk.last_slot, last_chunk.last_block_hash, t.stop(false));
        }
    }

    void cmd::_validate_chunks(scheduler &sched, chunk_registry &cr, chunk_list &&chunks) const
    {
        timer t { "validate chunks" };
        for (const auto &chunk: chunks) {
            auto save_path = cr.full_path(chunk.rel_path());
            sched.submit_void("parse", 0 + 100 * (_parse_progress.total - chunk.offset) / _parse_progress.total, [&cr, chunk, save_path]() {
                try {
                    cr.add(chunk.offset, save_path, chunk.data_hash, chunk.orig_rel_path);
                } catch (std::exception &ex) {
                    std::filesystem::path orig_path { save_path };
                    auto debug_path = cr.full_path(fmt::format("error/{}", orig_path.filename().string()));
                    logger::warn("moving an unparsable chunk {} to {}", save_path, debug_path);
                    std::filesystem::copy_file(save_path, debug_path, std::filesystem::copy_options::overwrite_existing);
                    throw error("can't parse {}: {}", save_path, ex.what());
                }
            });
        }
        sched.process(true);
    }
}