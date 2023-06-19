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

using namespace boost::ut;
using namespace daedalus_turbo;

static const std::string DATA_DIR = "./data"s;
static const std::string TMP_DIR = "/tmp"s;
static std::vector<std::string> paths;

std::string sort_file(const std::string &path, size_t item_size, bool delete_source = true) {
    std::string src_path = path + ".unsorted";
    std::filesystem::rename(path, src_path);
    size_t size = std::filesystem::file_size(src_path);
    if (size % item_size != 0) throw error_fmt("the file's size must be a multiple of the item_size!");
    size_t num_items = size / item_size;

    uint8_vector src_buf(size);
    read_whole_file(src_path, src_buf);
    std::vector<const uint8_t *> items(num_items);
    for (size_t i = 0; i < num_items; ++i) {
        items[i] = src_buf.data() + i * item_size;
    }
    std::sort(items.begin(), items.end(), item_comparator(item_size));
    uint8_vector dst_buf(size);
    for (size_t i = 0; i < num_items; ++i) {
        memcpy(dst_buf.data() + i * item_size, items[i], item_size);
    }
    std::ofstream os(path, std::ios::binary);
    os.write(reinterpret_cast<const char *>(dst_buf.data()), size);
    os.close();
    if (delete_source) std::filesystem::remove(src_path);
    return path;
}

static void prepare_test_data(const std::string &src_path, size_t item_size, size_t num_files) {
    sort_file(src_path, item_size);
    size_t src_size = std::filesystem::file_size(src_path);
    paths.resize(num_files);
    for (size_t i = 0; i < paths.size(); ++i) {
        paths[i] = format("{}/parallel-sort-bench-1-in-{}.tmp", TMP_DIR, i);
        if (std::filesystem::exists(paths[i])) std::filesystem::remove(paths[i]);
        std::filesystem::copy_file(src_path, paths[i]);
        if (std::filesystem::file_size(paths[i]) != src_size) throw error_fmt("copy_file has failed!");
    }
}

static void parallel_sort(merge_sort_func merge_sort, size_t merge_factor) {
    if (merge_factor > paths.size()) throw error_fmt("merge_factor is greater than the preinitialized data collection!");
    vector<string> work_paths(paths.begin(), paths.begin() + merge_factor);
    merge_sort(TMP_DIR + "/parallel-sort-bench-out.tmp", work_paths, false);
}

suite parallel_sort_bench_suite = [] {
    const std::string sample_path = DATA_DIR + "/parallel-sort-test-1M.dt";
    size_t sample_size = std::filesystem::file_size(sample_path);
    struct my_val {
        uint8_t data[40];

        bool operator<(const my_val &b) const {
            return memcmp(data, b.data, sizeof(b.data)) < 0;
        }
    };
    size_t max_files = 2048;
    prepare_test_data(sample_path, sizeof(my_val), max_files);

    for (size_t num_files : { 2, 4, 8, 16, 32, 64, 128, 256, 512 }) {
        const auto test_name = "merge_sort_files/" + std::to_string(num_files);
        test(test_name) = [=] {
            double throughput = benchmark_throughput("merge_sort_files/" + std::to_string(num_files), 3, [=] {
                parallel_sort(merge_sort_files<my_val>, num_files);
                return num_files * sample_size;
            });
            expect(throughput >= 100'000'000.0_d);
        };
    }
};
