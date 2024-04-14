/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
* Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <thread>
#include <dt/mutex.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;

suite mutex_suite = [] {
    "mutex"_test = [] {
        alignas(mutex::padding) std::timed_mutex m {};
        size_t num_ok = 0;
        "success"_test = [&] {
            std::optional<std::string> err {};
            std::thread t1 { [&] {
                mutex::tracing_lock lk { m, 1 };
                ++num_ok;
            } };
            std::thread t2 { [&] {
                try {
                    mutex::tracing_lock lk { m, 2 };
                    ++num_ok;
                } catch (const std::exception &ex) {
                    err = ex.what();
                }
            } };
            t1.join();
            t2.join();
            expect(num_ok == 2);
            expect(!err);
        };
        "detect_deadlock"_test = [&] {
            num_ok = 0;
            std::optional<std::string> err {};
            std::thread t1 { [&] {
                mutex::tracing_lock lk { m, 1 };
                ++num_ok;
                std::this_thread::sleep_for(std::chrono::seconds { 4 });
            } };
            std::thread t2 { [&] {
                try {
                    mutex::tracing_lock lk { m, 2 };
                    ++num_ok;
                } catch (const std::exception &ex) {
                    err = ex.what();
                }
            } };
            t1.join();
            t2.join();
            expect(num_ok == 1);
            expect(static_cast<bool>(err));
        };
    };
};