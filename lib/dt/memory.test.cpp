/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
 * Copyright (c) 2024-2025 R2 Rationality OÜ (info at r2rationality dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */

#include <dt/common/test.hpp>
#include <dt/memory.hpp>

using namespace daedalus_turbo;

suite memory_suite = [] {
    "memory"_test = [] {
        const auto before = memory::my_usage_mb();
        static constexpr size_t alloc_size = 0x4000000;
        size_t after_alloc;
        {
            uint8_vector data(alloc_size);
            // force memory writes so that the memory is really allocated
            for (auto volatile *p = data.data(), *end = data.data() + data.size(); p < end; ++p)
                *p = p - data.data();
            after_alloc = memory::my_usage_mb();
        }
        expect(after_alloc >= before + (alloc_size >> 20)) << after_alloc << before;
        // Some standard libraries do not immediately return the memory to the OS, thus, not checking for the memory release
    };
};