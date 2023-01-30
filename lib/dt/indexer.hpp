/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */
#ifndef DAEDALUS_TURBO_INDEXER_HPP
#define DAEDALUS_TURBO_INDEXER_HPP

#include <algorithm>
#include <chrono>
#include <ctime>
#include <execution>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <dt/cardano.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/index.hpp>
#include <dt/index-type.hpp>
#include <dt/logger.hpp>
#include <dt/lz4.hpp>
#include <dt/sort.hpp>
#include <dt/scheduler.hpp>
#include <dt/util.hpp>

namespace daedalus_turbo {

    namespace filesystem = std::filesystem;
    using std::string;
    using std::vector;

    struct index_config {
        string base_path;
        string addr_use_path;
        string tx_use_path;
        string block_path;

        index_config(const string &idx_path)
            : base_path(idx_path), addr_use_path(idx_path + "/addruse"), tx_use_path(idx_path + "/txuse"), block_path(idx_path + "/block")
        {
            create_directories();
        }

        void create_directories() {
            if (!filesystem::exists(base_path)) filesystem::create_directory(base_path);
            for (const auto &path : { addr_use_path, tx_use_path, block_path }) {
            if (!filesystem::exists(path)) filesystem::create_directory(path);
            }
        }
    };

    class chain_indexer: public cardano_processor {
        set<cbor_buffer> used_addresses;
        index_radix_writer<tx_use_item> tx_use_idx;
        index_radix_writer<addr_use_item> addr_use_idx;
        vector<block_item> _blocks;
        logger_base &_logger;

        static vector<string> make_radix_paths(const string &path, size_t num_writers)
        {
            vector<string> paths;
            paths.reserve(num_writers);
            for (size_t i = 0; i < num_writers; ++i)
                paths.emplace_back(path + ".radix-" + to_string(i));
            return paths;
        }

    public:

        chain_indexer(const index_config &cfg, const string &path_suffix, size_t num_merge_threads, logger_base &logger)
            : tx_use_idx(make_radix_paths(cfg.tx_use_path + path_suffix, num_merge_threads)),
                addr_use_idx(make_radix_paths(cfg.addr_use_path + path_suffix, num_merge_threads)),
                _blocks(), _logger(logger)
        {
        }

        void every_tx_output(const cardano_tx_output_context &/*ctx*/, const cbor_buffer &address, uint64_t /*amount*/)
        {
            switch ((address.data()[0] >> 4) & 0xF) {
                case 0b0000: // base address: keyhash28,keyhash28
                case 0b0001: // base address: scripthash28,keyhash28
                case 0b0010: // base address: keyhash28,scripthash28
                case 0b0011: // base address: scripthash28,scripthash28
                {
                    if (address.size() != 57) {
                        _logger.log("worker warning: unsupported address size %zu for type %02hhX", address.size(), address.data()[0]);
                        break;
                    }
                    used_addresses.emplace(address.data() + 29, 28 /* address.size - 29 */);
                    break;
                }
            }
        }
        
        void every_tx_input(const cardano_tx_input_context &ctx, const cbor_buffer &tx_in_hash, uint64_t tx_in_out_idx)
        {
            if (tx_in_out_idx > 65535) throw error("tx_out_idx is too large!");
            tx_use_item &item = tx_use_idx.writable(tx_in_hash.data()[0]);
            memcpy(item.tx_hash, tx_in_hash.data(), tx_in_hash.size());
            item.tx_out_idx = tx_in_out_idx;
            pack_offset(item.tx_offset, sizeof(item.tx_offset), ctx.tx_ctx.offset);
            item.tx_size = pack_tx_size(ctx.tx_ctx.size);
            tx_use_idx.next();
        }

        void every_tx_withdrawal(const cardano_tx_context &/*ctx*/, const cbor_buffer &address, uint64_t /*amount*/)
        {
            if (address.size() != 29 || address.data()[0] != 0xE1) return;
            used_addresses.emplace(address.data() + 1, address.size() - 1);
        }

        void every_tx(const cardano_tx_context &ctx, const cbor_value &tx, uint64_t /*fees*/)
        {
            for (const auto &addr : used_addresses) {
                addr_use_item &item = addr_use_idx.writable(addr.data()[0]);
                memcpy(&item.stake_addr, addr.data(), addr.size());
                pack_offset(item.tx_offset, sizeof(item.tx_offset), ctx.offset);
                item.tx_size = pack_tx_size(tx.size);
                addr_use_idx.next();
            }
            used_addresses.clear();
        }

        void every_block(const cardano_block_context &ctx, const cbor_value &block_tuple)
        {
            block_item item;
            memcpy(&item.offset, &ctx.offset, sizeof(item.offset));
            item.size = block_tuple.size;
            item.block_number = ctx.block_number;
            item.slot = ctx.slot;
            memcpy(item.pool_hash, ctx.pool_hash, sizeof(item.pool_hash));
            item.era = ctx.era;
            _blocks.push_back(move(item));
        }

        const vector<block_item> &blocks() const
        {
            return _blocks;
        }

    };

    class indexer
    {
        logger_base &_logger;

        struct task_result {
            string path_suffix;
            vector<block_item> blocks;
        };

    public:

        indexer(logger_base &logger) : _logger(logger)
        {
        }

        vector<block_item> index_chunk(const vector<chunk_map::value_type> &chunks, const index_config &cfg, const string &path_suffix, size_t num_merge_threads) {
            chain_indexer proc(cfg, path_suffix, num_merge_threads, _logger);
            cardano_parser parser(proc);
            uint8_vector buf, compressed;
            for (const auto &chunk: chunks) {
                if (chunk.second.lz4) {
                    read_whole_file(chunk.second.path, compressed);
                    lz4_decompress(buf, compressed);
                } else {
                    read_whole_file(chunk.second.path, buf);
                }
                cardano_chunk_context chunk_ctx(chunk.first);
                parser.parse_chunk(chunk_ctx, buf);
            }
            return proc.blocks();
        }

        template<typename T, typename S>
        static size_t radix_final_merge(shared_ptr<S> out_stream, size_t start_offset, size_t end_offset,
            const vector<string> &paths, bool delete_source)
        {
            using write_stream = item_seeking_write_stream<T, S, 10000>;
            write_stream os(*out_stream, start_offset, end_offset);
            return merge_sort_queue_writer<write_stream, T>(os, paths, delete_source);
        }

        template<typename T, typename S>
        static void schedule_final_radix_merge(scheduler &sched, const string &new_task_group, int new_task_prio, shared_ptr<S> &out_stream, size_t num_radix, vector<string> *radix_paths, size_t *radix_size)
        {
            size_t offset = 0;
            for (size_t ri = 0; ri < num_radix; ++ri) {
                vector<string> &task_paths = radix_paths[ri];
                size_t task_size = radix_size[ri];
                sched.submit(new_task_group, new_task_prio, [=]() {
                    return radix_final_merge<T>(out_stream, offset, offset + task_size, task_paths, true);
                });
                offset += task_size;
            }
        }

        template<typename T>
        static void schedule_final_radix_merge_when_done(scheduler &sched, const string &new_task_group, vector<string> &chunks, const string &final_path, int priority, size_t todo_cnt)
        {
            if (todo_cnt > 1) return;
            if (chunks.size() > 0) {
                size_t num_radix = sched.num_workers();
                vector<string> radix_paths[num_radix];
                size_t radix_size[num_radix];
                for (size_t ri = 0; ri < num_radix; ++ri) {
                    string radix_suffix = ".radix-"s + to_string(ri);
                    transform(chunks.begin(), chunks.end(), back_inserter(radix_paths[ri]),
                        [&radix_suffix](const string &p) { return p + radix_suffix; }
                    );
                    radix_size[ri] = 0;
                    for (const auto &p: radix_paths[ri]) {
                        size_t file_size = filesystem::file_size(p);
                        radix_size[ri] += file_size;
                    }
                }
                shared_ptr<stdio_stream_sync> out_stream = make_shared<stdio_stream_sync>(stdio_stream(final_path.c_str(), "wb", false));
                schedule_final_radix_merge<T>(sched, new_task_group, priority, out_stream, num_radix, radix_paths, radix_size);
            } else {
                throw error("must have some chunks to merge!");
            }
        }

        void index(const string &db_path, const string idx_path, size_t num_threads=scheduler::default_worker_count(), bool sort=true, bool lz4=false)
        {
            index_config cfg(idx_path);
            scheduler sched(num_threads);
            timer t("everything");
            timer t2("preprocesss");
            chunk_registry cr(db_path, lz4);
            size_t num_merge_threads = sched.num_workers();

            vector<string> addr_use_chunks, tx_use_chunks;
            vector<block_item> blocks;

            sched.on_result("preprocess", [&](any &res) {
                size_t todo_cnt = sched.task_count("preprocess");
                if (sort) {
                    task_result tr(any_cast<task_result>(res));
                    tx_use_chunks.push_back(cfg.tx_use_path + tr.path_suffix);
                    schedule_final_radix_merge_when_done<tx_use_item>(sched, "merge_tx_use", tx_use_chunks, cfg.tx_use_path + "/index.bin", 90, todo_cnt);
                    addr_use_chunks.push_back(cfg.addr_use_path + tr.path_suffix);
                    schedule_final_radix_merge_when_done<addr_use_item>(sched, "merge_addr_use", addr_use_chunks, cfg.addr_use_path + "/index.bin", 50, todo_cnt);
                    copy(tr.blocks.begin(), tr.blocks.end(), back_inserter(blocks));
                    if (todo_cnt == 1) {
                        sched.submit("merge_block_metadata", 10, [&blocks, &cfg]() {
                            std::sort(blocks.begin(), blocks.end());
                            string out_path = cfg.block_path + "/index.bin";
                            ofstream os(out_path, ios::binary);
                            if (!os) throw sys_error("can't open %s for writing", out_path.c_str());
                            if (!os.write(reinterpret_cast<const char *>(blocks.data()), blocks.size() * sizeof(block_item))) throw sys_error("write to %s has failed", out_path.c_str());
                            os.close();
                            return out_path;
                        });
                    }
                }
                if (todo_cnt <= 1) t2.stop();
            });

            size_t task_size = 0;
            size_t task_idx = 0;
            vector<chunk_map::value_type> task;
            for (auto it = cr.begin(); it != cr.end(); it++) {
                task_size += it->second.size;
                task.emplace_back(*it);
                if (task_size >= 256'000'000 || next(it) == cr.end()) {
                    string out_path_suffix = "/preprocess-" + to_string(task_idx) + ".tmp";
                    sched.submit("preprocess", 100, [this, task, &cfg, out_path_suffix, num_merge_threads]() {
                        task_result tr;
                        tr.path_suffix = out_path_suffix;
                        tr.blocks = index_chunk(task, cfg, out_path_suffix, num_merge_threads);
                        return tr;
                    });
                    task_size = 0;
                    task.clear();
                    ++task_idx;
                }
            }
            sched.process();
            t2.stop_and_print();
        }

    };

}

#endif // !DAEDALUS_TURBO_INDEXER_HPP
