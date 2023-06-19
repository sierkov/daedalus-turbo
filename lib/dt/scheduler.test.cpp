/*
 * This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 *
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE
 */

#include <iostream>
#include <vector>
#include <sstream>
#include <string>

#include <boost/ut.hpp>

#include <dt/scheduler.hpp>
#include <dt/util.hpp>

using namespace std::literals;
using namespace boost::ut;
using namespace daedalus_turbo;

suite scheduler_suite = [] {
    "scheduler"_test = [] {
        "chained_scheduling"_test = [] {
            scheduler s(16);
            alignas(hardware_destructive_interference_size) std::mutex preproc_mutex;
            size_t preproc_calls = 0;
            std::vector<std::string> preproc_done;

            alignas(hardware_destructive_interference_size) std::mutex merge_1_mutex;
            size_t merge_1_calls = 0;
            std::vector<std::string> merge_1_done;

            alignas(hardware_destructive_interference_size) std::mutex merge_2_mutex;
            size_t merge_2_calls = 0;
            std::vector<std::string> merge_2_done;

            // processed in the manager thread, no locking is needed
            std::vector<std::string> preproc_ready, merge_1_ready;

            s.on_result("pre_process", [&](const std::any &res) {
                std::string path = std::any_cast<std::string>(res);
                preproc_ready.push_back(std::move(path));
                if (preproc_ready.size() >= 4 || s.task_count("pre_process") <= 1) {
                    std::vector<std::string> merge_paths;
                    while (preproc_ready.size() > 0 && merge_paths.size() < 4) {
                        merge_paths.push_back(preproc_ready.back());
                        preproc_ready.pop_back();
                    }
                    auto merge_1 = [&](std::vector<std::string> paths) {
                        std::scoped_lock lock(merge_1_mutex);
                        ++merge_1_calls;
                        std::this_thread::sleep_for(200ms);
                        for (const auto &p: paths) merge_1_done.push_back(p);
                        return paths;
                    };
                    s.submit("merge_1/addr_use", 10, merge_1, std::move(merge_paths));
                }
            });
            s.on_result("merge_1/addr_use", [&](const std::any &res) {
                auto paths = std::any_cast<std::vector<std::string>>(res);
                merge_1_ready.insert(merge_1_ready.end(), paths.begin(), paths.end());
                if (s.task_count("pre_process") + s.task_count("merge_1/addr_use") <= 1) {
                    auto merge_2 = [&](std::vector<std::string> paths) {
                        std::scoped_lock lock(merge_2_mutex);
                        ++merge_2_calls;
                        std::this_thread::sleep_for(400ms);
                        for (const auto &p: paths) merge_2_done.push_back(p);
                        return true;
                    };
                    s.submit("merge_2/addr_use", 1, merge_2, merge_1_ready);
                    merge_1_ready.clear();
                }
            });
            for (size_t i = 0; i < 16; ++i) {
                auto pre_process = [&](const std::string &path) {
                    std::scoped_lock lock(preproc_mutex);
                    ++preproc_calls;
                    std::this_thread::sleep_for(100ms);
                    preproc_done.push_back(path);
                    return path;
                };
                s.submit("pre_process", 100, pre_process, format("chunk-{}.in", i));
            }
            std::ostringstream progress;
            s.process(true, 1000ms, progress);
            expect(preproc_calls == 16_u);
            expect(preproc_done.size() == 16_u);
            expect(merge_1_calls == 4_u);
            expect(merge_1_done.size() == 16_u);
            expect(merge_2_calls == 1_u);
            expect(merge_2_done.size() == 16_u);
            expect(progress.str().size() > 0_u);
            expect(s.num_workers() == 16);
        };
        "exceptions"_test = [] {
            scheduler s;
            size_t num_ok = 0, num_err = 0;
            s.on_result("bad_actor", [&](const std::any &res) {
                if (res.type() == typeid(scheduled_task_error)) ++num_err;
                else ++num_ok;
            });
            s.submit("bad_actor", 100, []() { throw error_fmt("Ha ha! I told ya!"); return true; });
            s.process();
            expect(num_ok == 0_u);
            expect(num_err == 1_u);
        };
        "exceptions_no_observer"_test = [] {
            scheduler s;
            s.submit("bad_actor", 100, []() { throw error_fmt("Ha ha! I told ya!"); return true; });
            expect(throws([&]{ s.process(); }));
        };
    };
};
