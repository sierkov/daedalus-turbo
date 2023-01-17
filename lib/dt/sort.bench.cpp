/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>
#include <boost/ut.hpp>
#include <dt/benchmark.hpp>
#include <dt/sort.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

static const string DATA_DIR = "./data"s;
static const string TMP_DIR = "/tmp"s;
static vector<string> paths;

string sort_file(const string &path, size_t item_size, bool delete_source = true) {
    string src_path = path + ".unsorted";
    filesystem::rename(path, src_path);
    size_t size = filesystem::file_size(src_path);
    if (size % item_size != 0) throw error("the file's size must be a multiple of the item_size!");
    size_t num_items = size / item_size;

    uint8_vector src_buf(size);
    read_whole_file(src_path, src_buf);
    vector<const uint8_t *> items(num_items);
    for (size_t i = 0; i < num_items; ++i) {
        items[i] = src_buf.data() + i * item_size;
    }
    sort(items.begin(), items.end(), item_comparator(item_size));
    uint8_vector dst_buf(size);
    for (size_t i = 0; i < num_items; ++i) {
        memcpy(dst_buf.data() + i * item_size, items[i], item_size);
    }
    ofstream os(path, ios::binary);
    os.write(reinterpret_cast<const char *>(dst_buf.data()), size);
    os.close();
    if (delete_source) filesystem::remove(src_path);
    return path;
}

static void prepare_test_data(const string &src_path, size_t item_size, size_t num_files) {
    sort_file(src_path, item_size);
    size_t src_size = filesystem::file_size(src_path);
    paths.resize(num_files);
    for (size_t i = 0; i < paths.size(); ++i) {
        paths[i] = format("%s/parallel-sort-bench-1-in-%d.tmp", TMP_DIR.c_str(), i);
        if (filesystem::exists(paths[i])) filesystem::remove(paths[i]);
        filesystem::copy_file(src_path, paths[i]);
        if (filesystem::file_size(paths[i]) != src_size) throw runtime_error("copy_file has failed!");
    }
}

static void parallel_sort(merge_sort_func merge_sort, size_t merge_factor) {
    if (merge_factor > paths.size()) throw runtime_error("merge_factor is greater than the preinitialized data collection!");
    vector<string> work_paths(paths.begin(), paths.begin() + merge_factor);
    merge_sort(TMP_DIR + "/parallel-sort-bench-out.tmp", work_paths, false);
}

suite parallel_sort_bench_suite = [] {
    const string sample_path = DATA_DIR + "/parallel-sort-test-1M.dt";
    size_t sample_size = filesystem::file_size(sample_path);
    struct my_val {
        uint8_t data[40];

        bool operator<(const my_val &b) const {
            return memcmp(data, b.data, sizeof(b.data)) < 0;
        }
    };
    size_t max_files = 2048;
    prepare_test_data(sample_path, sizeof(my_val), max_files);

    for (size_t num_files : { 2, 4, 8, 16, 32, 64, 128, 256, 512 }) {
        const auto test_name = "merge_sort_files/" + to_string(num_files);
        test(test_name) = [=] {
            double throughput = benchmark_throughput("merge_sort_files/" + to_string(num_files), 3, [=] {
                parallel_sort(merge_sort_files<my_val>, num_files);
                return num_files * sample_size;
            });
            expect(throughput >= 100'000'000.0_d);
        };
    }
};
