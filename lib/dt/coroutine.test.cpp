/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <coroutine>
#include <dt/test.hpp>

using namespace daedalus_turbo;

namespace {
    class BasicCoroutine {
    public:
        struct Promise {
            BasicCoroutine get_return_object() { return BasicCoroutine {}; }
            void unhandled_exception() noexcept { }
            void return_void() noexcept { }
            std::suspend_never initial_suspend() noexcept { return {}; }
            std::suspend_never final_suspend() noexcept { return {}; }
        };
        using promise_type = Promise;
    };

    BasicCoroutine coro()
    {
        co_return;
    }
}

suite coroutine_suite = [] {
    "coroutine"_test = [] {
        coro();
    };
};