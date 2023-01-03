/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022 Alex Sierkov (alex at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <filesystem>
#include <iostream>
#include <dt/lz4.hpp>
#include <dt/util.hpp>
#include <dt/scheduler.hpp>

using namespace std;
using namespace daedalus_turbo;

static auto &log_stream = cout;

struct compress_result
{
    string path = ""s;
    string error = ""s;
    size_t size_orig = 0;
    size_t size_compressed = 0;

    compress_result(const string &path_) : path(path_)
    {
    }

    compress_result(const compress_result &) =default;
    compress_result(compress_result &&) =default;

    compress_result &operator=(const compress_result &) =default;

};

static compress_result decompress_chunk(const string &path, const string &dst_path)
{
    compress_result res(path);
    try {
        bin_string orig, compressed;
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
    if (argc < 2) {
        cerr << "Usage: lz4-decompress <chain-dir>" << endl;
        return 1;
    }
    timer t("main");
    const string_view db_path = argv[1];

    vector<pair<string, string>> chunks;
    for (const auto &entry : filesystem::directory_iterator(db_path)) {
        if (entry.path().extension() != ".lz4") continue;
	    const string src_path = entry.path().string();
	    const string dst_path = (entry.path().parent_path() / entry.path().stem()).string();
        chunks.push_back(make_pair(src_path, dst_path));
    }
    sort(chunks.begin(), chunks.end());

    vector<compress_result> results;
    scheduler sched;
    sched.on_result("decompress", [&](any &res) { results.push_back(move(any_cast<compress_result>(res))); });
    for (const auto & [ src_path, dst_path] : chunks) sched.submit("decompress", 0, decompress_chunk, src_path, dst_path);
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
    log_stream << "\rtotal_chunks: " << total_chunks << ", total_errors: " << total_errors
        << ", total_uncompressed: " << (double)total_uncompressed / 1'000'000u << "MB "
        << ", total_compressed: " << (double)total_compressed / 1'000'000u << "MB "
        << ", compression ratio: " << (double)total_uncompressed / total_compressed
        << ", decompression throughput: " << (double)total_uncompressed / 1'000'000u / t.stop() << "MB/sec"
        << endl;
    if (total_errors > 0) {
        for (const auto &r: results)
            if (r.error.size() > 0)
                cerr << "ERROR: " << r.path << ": " << r.error << endl;
    }
}
