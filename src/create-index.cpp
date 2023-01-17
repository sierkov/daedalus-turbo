/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <fstream>
#include <iostream>
#include <string>

#include <dt/indexer.hpp>
#include <dt/logger.hpp>
#include <dt/util.hpp>

using namespace std;
using namespace daedalus_turbo;

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
    ofstream log_stream("./log/create-index.log", ios::app);
    logger_file logger(log_stream);
    indexer idxr(logger);
    idxr.index(db_path, idx_path, num_threads, sort, lz4);
    if (log) {
        timer_registry::instance().set_attr("threads", to_string(num_threads));
        timer_registry::instance().set_attr("lz4", lz4 ? "1" : "0");
        timer_registry::instance().set_attr("chain_dir", db_path);
        timer_registry::instance().set_attr("index_dir", idx_path);
        log_timers();
    }
    return 0;
}
