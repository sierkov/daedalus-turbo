/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <filesystem>
#include <iostream>
#include <ranges>
#include <dt/lz4.hpp>
#include <dt/util.hpp>
#include <dt/scheduler.hpp>

using namespace std;
using namespace daedalus_turbo;
namespace rv = std::ranges::views;

static auto &log_stream = cout;

struct compress_result
{
    string path = "";
    string error = "";
    size_t size_orig = 0;
    size_t size_compressed = 0;

    compress_result(const string &path_) : path(path_)
    {
    }
};

static compress_result compress_chunk(const string &path)
{
    compress_result res(path);
    try {
        uint8_vector orig, compressed;
        read_whole_file(path, orig);
        lz4_compress(compressed, orig);
        write_whole_file(path + ".lz4", compressed);
        res.size_orig = orig.size();
        res.size_compressed = compressed.size();
    } catch (exception &ex) {
        res.error = ex.what();
    }
    return res;
}

static compress_result decompress_chunk(const string &path, const string &dst_path)
{
    compress_result res(path);
    try {
        uint8_vector orig, compressed;
        read_whole_file(path, compressed);
        lz4_decompress(orig, compressed);
        write_whole_file(dst_path, orig);
        res.size_orig = orig.size();
        res.size_compressed = compressed.size();
    } catch (exception &ex) {
        res.error = ex.what();
    }
    return res;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        cerr << "Usage: lz4 compress|decompress <chunks-dir>" << endl;
        return 1;
    }
    const string cmd = argv[1];
    const string db_path = argv[2];
    if (cmd != "compress" && cmd != "decompress") {
        cerr << "unsupported command: " << cmd << endl;
        return 1;
    }
    timer t("main", log_stream);
    vector<compress_result> results;
    scheduler sched;
    if (cmd == "compress") {
        vector<string> chunks;
        for (const auto &entry : filesystem::directory_iterator(db_path)) {
            if (entry.path().extension() != ".chunk") continue;
            chunks.push_back(entry.path().string());
        }
        sort(chunks.begin(), chunks.end());
        sched.on_result("compress", [&](any &res) { results.push_back(any_cast<compress_result>(res)); });
        for (const auto &path: chunks) sched.submit("compress", 0, compress_chunk, path);
    } else if (cmd == "decompress") {
        vector<pair<string, string>> chunks;
        for (const auto &entry : filesystem::directory_iterator(db_path)) {
            if (entry.path().extension() != ".lz4") continue;
            const string src_path = entry.path().string();
            const string dst_path = (entry.path().parent_path() / entry.path().stem()).string();
            chunks.push_back(make_pair(src_path, dst_path));
        }
        sort(chunks.begin(), chunks.end());
        sched.on_result("decompress", [&](any &res) { results.push_back(any_cast<compress_result>(res)); });
        for (const auto & [ src_path, dst_path] : chunks) sched.submit("decompress", 0, decompress_chunk, src_path, dst_path);
    } else {
        throw error_fmt("unsupported command: {}", cmd);
    }
    sched.process();
    size_t total_chunks = results.size(), total_errors = 0, total_uncompressed = 0, total_compressed = 0;
    for (const auto &r: results) {
        if (r.error.size() == 0) {
            total_uncompressed += r.size_orig;
            total_compressed += r.size_compressed;
        } else {
            total_errors++;
        }
    }
    t.stop_and_print();
    log_stream
        << "errors: " << total_errors << ", chunks: " << total_chunks 
        << ", uncompressed size: " << (double)total_uncompressed / 1'000'000u << "MB"
        << ", compressed size: " << (double)total_compressed / 1'000'000u << "MB"
        << ", compression ratio: " << (double)total_uncompressed / total_compressed
        << ", processing throughput: " << (double)total_uncompressed / 1'000'000u / t.stop() << "MB/sec"
        << endl;
    if (total_errors > 0) {
        size_t err_idx = 0;
        for (const auto &r: results | rv::filter([&](const auto &r) { return r.error.size() > 0; }) | rv::take(5)) {
            cerr << "error " << ++err_idx << "/" << total_errors << ": " << r.error << "\n";
        }
    }
}
