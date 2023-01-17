/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <cstring>
#include <cstdio>
#include <string>
#include <string_view>
#include <filesystem>
#include <fstream>
#include <vector>
#include <boost/ut.hpp>
#include <dt/sort.hpp>

using namespace std;
using namespace boost::ut;
using namespace daedalus_turbo;

static const string DATA_DIR = "./data"s;
static const string TMP_DIR = "/tmp"s;

static string create_file(const string &path, const char **bufs, size_t bufs_cnt, size_t buf_size) {
    ofstream of(path, ios::binary);
    for (size_t i = 0; i < bufs_cnt; ++i) of.write(bufs[i], buf_size);
    of.close();
    return path;
}

static void check_expected(const string_view &title, const string &path, const char **expected, size_t expected_cnt, size_t item_size) {
    ifstream is(path, ios::binary);
    char buf[item_size];
    for (size_t i = 0; i < expected_cnt; ++i) {
        is.read(buf, sizeof(buf));
        expect((is.fail() == false) >> fatal);
        expect(memcmp(buf, expected[i], 4) == 0) << title << ": " << string_view(buf, item_size) << "!=" << string_view(expected[i], item_size);
    }
    is.close();
    if (filesystem::exists(path)) filesystem::remove(path);
}

static void test_unsorted(merge_sort_func merge_func) {
    size_t item_size = 4;
    vector<string> paths;
    const char *items1[] = { "CCCC", "BBBB" };
    paths.push_back(create_file(TMP_DIR + "/parallel-sort-test-file-1.txt", items1, 2, item_size));
    const char *items2[] = { "ZZZZ", "AAAA" };
    paths.push_back(create_file(TMP_DIR + "/parallel-sort-test-file-2.txt", items2, 2, item_size));
    string out_path = TMP_DIR + "/parallel-sort-test-file-out.txt";

    merge_func(out_path, paths, true);

    const char *expected[] = { "CCCC", "BBBB", "ZZZZ", "AAAA" };
    check_expected("unsorted", out_path, expected, 4, item_size);
}

static void test_sorted(merge_sort_func merge_func) {
    size_t item_size = 4;
    vector<string> paths;
    const char *items1[] = { "BBBB", "ZZZZ" };
    paths.push_back(create_file(TMP_DIR + "/parallel-sort-test-file-1.txt", items1, 2, item_size));
    const char *items2[] = { "AAAA", "CCCC", "EEEE" };
    paths.push_back(create_file(TMP_DIR + "/parallel-sort-test-file-2.txt", items2, 3, item_size));
    string out_path = TMP_DIR + "/parallel-sort-test-file-out.txt";

    merge_func(out_path, paths, true);

    const char *expected[] = { "AAAA", "BBBB", "CCCC", "EEEE", "ZZZZ" };
    check_expected("sorted", out_path, expected, 5, item_size);
}

static void test_repeating_items(merge_sort_func merge_func) {
    size_t item_size = 4;
    vector<string> paths;
    const char *items1[] = { "AAAA", "BBBB", "ZZZZ" };
    paths.push_back(create_file(TMP_DIR + "/parallel-sort-test-file-1.txt", items1, 3, item_size));
    const char *items2[] = { "AAAA", "CCCC", "EEEE", "ZZZZ" };
    paths.push_back(create_file(TMP_DIR + "/parallel-sort-test-file-2.txt", items2, 4, item_size));
    string out_path = TMP_DIR + "/parallel-sort-test-file-out.txt";

    merge_func(out_path, paths, true);

    const char *expected[] = { "AAAA", "AAAA", "BBBB", "CCCC", "EEEE", "ZZZZ", "ZZZZ" };
    check_expected("repeating", out_path, expected, 7, item_size);
}

static void test_empty_files(merge_sort_func merge_func) {
    vector<string> paths;
    paths.push_back(DATA_DIR + "/parallel-sort-test-2-part1.dt");
    paths.push_back(DATA_DIR + "/parallel-sort-test-2-part2.dt");
    string out_path = TMP_DIR + "/parallel-sort-test-2-output.dt";

    merge_func(out_path, paths, false);
}

static void test_all(merge_sort_func f)
{
    test_unsorted(f);
    test_sorted(f);
    test_repeating_items(f);
    test_empty_files(f);
}


suite parallel_sort_suite = [] {
    "sort"_test = [] {
        "merge_sort_files"_test = [] {
            test_all(merge_sort_files<uint32_t>);
        };
        "merge_sort_radix"_test = [] {
            size_t item_size = 4;
            const char *r1_items1[] = { "ABBB", "AZZZ" };
            create_file(TMP_DIR + "/parallel-sort-test-file1.txt.radix-1", r1_items1, 2, item_size);
            const char *r1_items2[] = { "AAAA", "ACCC", "AEEE" };
            create_file(TMP_DIR + "/parallel-sort-test-file2.txt.radix-1", r1_items2, 3, item_size);
            const char *r2_items1[] = { "BBBB", "BZZZ" };
            create_file(TMP_DIR + "/parallel-sort-test-file1.txt.radix-2", r2_items1, 2, item_size);
            const char *r2_items2[] = { "BAAA", "BCCC", "BEEE" };
            create_file(TMP_DIR + "/parallel-sort-test-file2.txt.radix-2", r2_items2, 3, item_size);
            vector<string> paths;
            paths.push_back(TMP_DIR + "/parallel-sort-test-file1.txt");
            paths.push_back(TMP_DIR + "/parallel-sort-test-file2.txt");
            vector<string> radix_suffixes;
            radix_suffixes.emplace_back(".radix-1");
            radix_suffixes.emplace_back(".radix-2");
            string out_path = merge_sort_radix<uint32_t>(TMP_DIR + "/parallel-sort-radix-output.txt", paths, radix_suffixes, false);
            const char *expected[] = { "AAAA", "ABBB", "ACCC", "AEEE", "AZZZ", "BAAA", "BBBB", "BCCC", "BEEE", "BZZZ" };
            check_expected("radix", out_path, expected, 10, item_size);
        };
    };
    
};
