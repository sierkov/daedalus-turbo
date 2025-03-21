/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/container.hpp>
#include <dt/common/test.hpp>
#include <dt/parallel/ordered-consumer.hpp>

using namespace daedalus_turbo;
using namespace daedalus_turbo::parallel;

suite parallel_ordered_consumer_suite = [] {
    using daedalus_turbo::set;
    "parallel::ordered_consumer"_test = [] {
        auto &sched = scheduler::get();
        "progress"_test = [&] {
            set<uint64_t> processed {};
            ordered_consumer c {
                [&](const auto idx) {
                    processed.emplace(idx);
                },
                "my-consumer", 1000, sched
            };
            test_same(false, c.try_push(0));
            test_same(true, c.try_push(1000));
            sched.process();
            test_same(1000, processed.size());
            test_same(false, c.try_push(1000));
            test_same(true, c.try_push(1050));
            sched.process();
            test_same(1050, processed.size());
            test_same(false, c.try_push(1050));
        };
        "one worker at a time"_test = [&] {
            set<uint64_t> processed {};
            ordered_consumer c {
                [&](const auto idx) {
                    processed.emplace(idx);
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                },
                "my-consumer", 1000, sched
            };
            test_same(false, c.try_push(0));
            test_same(true, c.try_push(1));
            test_same(false, c.try_push(2));
            test_same(false, c.try_push(3));
            sched.process();
            test_same(1, processed.size());
            test_same(false, c.try_push(1));
            test_same(true, c.try_push(2));
            test_same(false, c.try_push(3));
            sched.process();
            test_same(2, processed.size());
            test_same(false, c.try_push(2));
        };
        "parallel pushes"_test = [&] {
            set<uint64_t> processed {};
            ordered_consumer c {
                [&](const auto idx) {
                    processed.emplace(idx);
                },
                "my-consumer", 1000, sched
            };
            static constexpr size_t max_idx = 1024;
            if (sched.num_workers() <= 1) [[unlikely]]
                throw error("unit test requires at least two workers!");
            // keep one scheduler worker available for the consumer
            for (size_t i = 0; i < sched.num_workers() - 1; ++i) {
                sched.submit_void("my-pusher", 100, [&] {
                    for (;;) {
                        const auto next_idx = c.next();
                        if (next_idx >= max_idx)
                            break;
                        c.try_push(next_idx + 1);
                    }
                });
            }
            sched.process();
            test_same(max_idx, processed.size());
        };
        "failing consumer"_test = [&] {
            set<uint64_t> processed {};
            ordered_consumer c {
                [&](const auto idx) {
                    if (idx == 10)
                        throw error("unsupported index!");
                    processed.emplace(idx);
                },
                "my-consumer", 1000, sched
            };
            test_same(false, c.try_push(0));
            test_same(true, c.try_push(1));
            sched.process();
            test_same(true, c.try_push(2));
            sched.process();
            test_same(true, c.try_push(10));
            sched.process();
            test_same(10, processed.size());
            test_same(false, c.try_push(10));
            test_same(true, c.try_push(11));
            sched.process();
            test_same(10, processed.size());
            expect(throws([&] { c.try_push(11); }));
            test_same(10, c.next());
        };
    };
};