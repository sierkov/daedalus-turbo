/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/parallel/ordered-queue.hpp>
#include <dt/scheduler.hpp>
#include <dt/test.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::parallel;

suite parallel_ordered_queue_suite = [] {
    "parallel::ordered_queue"_test = [] {
        "out of order put"_test = [] {
            ordered_queue q {};
            q.put(3);
            test_same(false, q.take());
            q.put(1);
            test_same(false, q.take());
            q.put(2);
            test_same(false, q.take());
            q.put(0);
            test_same(ordered_queue::optional_index { 0 }, q.take());
            test_same(ordered_queue::optional_index { 1 }, q.take());
            test_same(ordered_queue::optional_index { 2 }, q.take());
            test_same(ordered_queue::optional_index { 3 }, q.take());
            test_same(false, q.take());
        };
        "index_too_big"_test = [] {
            ordered_queue q {};
            expect(nothrow([&]{ q.put(65536); }));
            test_same(false, q.take());
            expect(nothrow([&]{ q.put(std::numeric_limits<uint64_t>::max() - 1); }));
            test_same(false, q.take());
            expect(throws([&]{ q.put(std::numeric_limits<uint64_t>::max()); }));
            test_same(false, q.take());
        };
        "parallel put and take ordered queue"_test = [] {
            static constexpr size_t items_per_worker = 1024;
            auto &sched = scheduler::get();
            ordered_queue q {};
            for (size_t i = 0; i < sched.num_workers(); ++i) {
                sched.submit_void("parallel-put", 100, [&, i] {
                    size_t idx = i;
                    for (size_t j = 0; j < items_per_worker; ++j) {
                        q.put(idx);
                        idx += sched.num_workers();
                    }
                });
            }
            sched.process();
            const auto total_items = items_per_worker * sched.num_workers();
            std::atomic_size_t ok { 0 };
            std::atomic_size_t err { 0 };
            for (size_t i = 0; i < sched.num_workers(); ++i) {
                sched.submit_void("parallel-take", 100, [&] {
                    for (size_t j = 0; j < items_per_worker; ++j) {
                        const auto v = q.take();
                        if (v)
                            ok.fetch_add(1, std::memory_order_relaxed);
                        else
                            err.fetch_add(1, std::memory_order_relaxed);
                    }
                });
            }
            sched.process();
            test_same(total_items, ok.load(std::memory_order_relaxed));
            test_same(0, err.load(std::memory_order_relaxed));
            test_same(false, q.take());
        };
    };
};