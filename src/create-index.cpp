/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

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

#include <dt/cardano.hpp>
#include <dt/chunk-registry.hpp>
#include <dt/index.hpp>
#include <dt/index-type.hpp>
#include <dt/lz4.hpp>
#include <dt/sort.hpp>
#include <dt/scheduler.hpp>
#include <dt/util.hpp>

using namespace std;
using namespace daedalus_turbo;

static auto log_stream = ofstream("/workspace/log/create-index.log", ios::app);

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

    static vector<string> make_radix_paths(const string &path, size_t num_writers)
    {
        vector<string> paths;
        paths.reserve(num_writers);
        for (size_t i = 0; i < num_writers; ++i)
            paths.emplace_back(path + ".radix-" + to_string(i));
        return paths;
    }

public:

    chain_indexer(const index_config &cfg, const string &path_suffix, size_t num_merge_threads)
        : tx_use_idx(make_radix_paths(cfg.tx_use_path + path_suffix, num_merge_threads)),
            addr_use_idx(make_radix_paths(cfg.addr_use_path + path_suffix, num_merge_threads)),
            _blocks()
    {
    }

    void every_tx_output(const cardano_tx_output_context &/*ctx*/, const cbor_buffer &address, uint64_t /*amount*/)
    {
        switch ((address.data[0] >> 4) & 0xF) {
            case 0:
            case 1:
            case 2:
            case 3: {
                if (address.size != 57) {
                    log_stream << format("worker warning: unsupported address size %zu for type %02hhX\n", address.size, address.data[0]);
                    break;
                }
                used_addresses.emplace(address.data + 29, 28 /* address.size - 29 */);
                break;
            }
        }
    }
    
    void every_tx_input(const cardano_tx_input_context &ctx, const cbor_buffer &tx_in_hash, uint64_t tx_in_out_idx)
    {
        if (tx_in_out_idx > 65535) throw error("tx_out_idx is too large!");
        tx_use_item &item = tx_use_idx.writable(tx_in_hash.data[0]);
        memcpy(item.tx_hash, tx_in_hash.data, tx_in_hash.size);
        item.tx_out_idx = tx_in_out_idx;
        memcpy(&item.tx_offset, &ctx.tx_ctx.offset, sizeof(item.tx_offset));
        tx_use_idx.next();
    }

    void every_tx_withdrawal(const cardano_tx_context &/*ctx*/, const cbor_buffer &address, uint64_t /*amount*/)
    {
        if (address.size != 29 || address.data[0] != 0xE1) return;
        used_addresses.emplace(address.data + 1, address.size - 1);
    }

    void every_tx(const cardano_tx_context &ctx, const cbor_value &/*tx*/, uint64_t /*fees*/)
    {
        for (const auto &addr : used_addresses) {
            addr_use_item &item = addr_use_idx.writable(addr.data[0]);
            memcpy(&item.stake_addr, addr.data, addr.size);
            memcpy(&item.tx_offset, &ctx.offset, sizeof(item.tx_offset));
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

static vector<block_item> index_chunk(const vector<chunk_map::value_type> &chunks, const index_config &cfg, const string &path_suffix, size_t num_merge_threads) {
    chain_indexer proc(cfg, path_suffix, num_merge_threads);
    cardano_parser parser(proc);
    bin_string buf, compressed;
    for (const auto &chunk: chunks) {
        try {        
            if (chunk.second.lz4) {
                read_whole_file(chunk.second.path, compressed);
                lz4_decompress(buf, compressed);
            } else {
                read_whole_file(chunk.second.path, buf);
            }
            cardano_chunk_context chunk_ctx(chunk.first);
            parser.parse_chunk(chunk_ctx, buf);
        } catch (exception &ex) {
            log_stream << "worker error: "s + ex.what() + "\n";
            log_stream.flush();
        }
    }
    return proc.blocks();
}

template<typename T, typename S>
size_t radix_final_merge(shared_ptr<S> out_stream, size_t start_offset, size_t end_offset,
    const vector<string> &paths, bool delete_source)
{
    using write_stream = item_seeking_write_stream<T, S, 10000>;
    write_stream os(*out_stream, start_offset, end_offset);
    return merge_sort_queue_writer<write_stream, T>(os, paths, delete_source);
}

template<typename T, typename S>
void schedule_final_radix_merge(scheduler &sched, const string &new_task_group, int new_task_prio, shared_ptr<S> &out_stream, size_t num_radix, vector<string> *radix_paths, size_t *radix_size)
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
        size_t total_size = 0;
        for (size_t ri = 0; ri < num_radix; ++ri) {
            string radix_suffix = ".radix-"s + to_string(ri);
            transform(chunks.begin(), chunks.end(), back_inserter(radix_paths[ri]),
                [&radix_suffix](const string &p) { return p + radix_suffix; }
            );
            radix_size[ri] = 0;
            for (const auto &p: radix_paths[ri]) {
                size_t file_size = filesystem::file_size(p);
                radix_size[ri] += file_size;
                total_size += file_size;
            }
        }
        shared_ptr<stdio_stream_sync> out_stream = make_shared<stdio_stream_sync>(stdio_stream(final_path.c_str(), "wb", false));
        schedule_final_radix_merge<T>(sched, new_task_group, priority, out_stream, num_radix, radix_paths, radix_size);
    } else {
        throw error("must have some chunks to merge!");
    }
}

struct task_result {
    string path_suffix;
    vector<block_item> blocks;
};

static void execute_tasks(size_t num_threads, const string &db_path, const index_config &cfg, bool sort=true, bool lz4=false) {
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
            task_result tr(move(any_cast<task_result>(res)));
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
            sched.submit("preprocess", 100, [task, &cfg, out_path_suffix, num_merge_threads]() {
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

static void log_timers()
{
    vector<pair<string, string>> records;
    ostringstream timestamp;
    time_t t = chrono::system_clock::to_time_t(chrono::system_clock::now());
    timestamp << put_time(localtime(&t), "%Y-%m-%d %H:%M:%S");
    records.emplace_back("timestamp", timestamp.str());
    for (const auto &a: timer_registry::instance().attrs()) records.push_back(make_pair(a.first, a.second));
    for (const auto &a: timer_registry::instance().timers()) {
        ostringstream dur;
        dur << setprecision(5) << a.second;
        records.push_back(make_pair("timer_" + a.first, dur.str()));
    }
    string hdrs, vals;
    for (const auto& [hdr, val]: records) {
        if (hdrs.size() > 0) {
            hdrs += ",";
            vals += ",";
        }
        hdrs += hdr;
        vals += val;
    }
    hdrs += "\n";
    vals += "\n";
    const string log_dir = "/workspace/log";
    if (!filesystem::exists(log_dir)) filesystem::create_directories(log_dir);
    ofstream os(log_dir + "/create-index-timers.csv", ios::app);
    if (os.tellp() == 0) os.write(hdrs.data(), hdrs.size());
    os.write(vals.data(), vals.size());
}

int main(int argc, char **argv) {
    if (argc < 3) {
        cerr << "Usage: create-index <chain-dir> <index-dir> [--threads=N] [--no-sort] [--lz4] [--log]" << endl;
        return 1;
    }
    timer t("main");
    const string db_path = argv[1];
    const string idx_path = argv[2];
    bool log = false;
    bool lz4 = false;
    bool sort = true;
    size_t num_threads = thread::hardware_concurrency();
    for (int i = 3; i < argc; ++i) {
        const string_view arg_i(argv[i], strlen(argv[i]));
        if (arg_i.substr(0, 10) == "--threads="sv) {
            string num_threads_str(arg_i.substr(10));
            num_threads = stoi(num_threads_str);
            if (num_threads < 1) num_threads = 1;
            if (num_threads > thread::hardware_concurrency()) num_threads = thread::hardware_concurrency();
        } else if (arg_i == "--log"sv) {
            log = true;
        } else if (arg_i == "--lz4"sv) {
            lz4 = true;
        } else if (arg_i == "--no-sort"sv) {
            sort = false;
        } else {
            cerr << "Error: unsupported command-line argument: " << argv[i] << endl;
            return 1;
        }
    }
    index_config cfg(idx_path);
    execute_tasks(num_threads, db_path, cfg, sort, lz4);
    if (log) {
        timer_registry::instance().set_attr("threads", to_string(num_threads));
        timer_registry::instance().set_attr("lz4", lz4 ? "1" : "0");
        timer_registry::instance().set_attr("chain_dir", db_path);
        timer_registry::instance().set_attr("index_dir", idx_path);
        log_timers();
    }
    return 0;
}
