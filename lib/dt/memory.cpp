/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_MEMORY_HPP
#define DAEDALUS_TURBO_MEMORY_HPP

extern "C" {
#ifdef __APPLE__
#   include <mach/mach_init.h>
#   include <mach/task_info.h>
#   include <mach/task.h>
#endif
#ifdef _WIN32
#   define NOMINMAX 1
#   include <windows.h>
#   include <psapi.h>
#else
#   include <unistd.h>
#   include <sys/time.h>
#   include <sys/resource.h>
#endif
};
#include <dt/file.hpp>
#include <dt/memory.hpp>
#include <dt/mutex.hpp>

namespace daedalus_turbo::memory {
    size_t my_usage_mb()
    {
        // Win API is not thread safe by default
        alignas(mutex::padding) static mutex::unique_lock::mutex_type m {};
        mutex::scoped_lock lk { m };
#       ifdef _WIN32
            PROCESS_MEMORY_COUNTERS_EX pmc {};
            GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
            return static_cast<size_t>(pmc.WorkingSetSize >> 20);
#       elif __linux__
            static size_t page_size = sysconf (_SC_PAGESIZE);
            std::string stat { file::read("/proc/self/statm").str() };
            const auto pos = stat.find(' ');
            if (pos == stat.npos) [[unlikely]]
                throw error("invalid statm file format!");
            return (std::stoull(stat.substr(0, pos)) * page_size) >> 20;
#       else
            struct task_basic_info tinfo;
            mach_msg_type_number_t count = TASK_BASIC_INFO_COUNT;
            task_info(
                mach_task_self(), TASK_BASIC_INFO,
                (task_info_t) &tinfo, &count);
            return tinfo.resident_size >> 20;
#       endif
    }

    size_t max_usage_mb()
    {
        // Win API is not thread safe by default
        alignas(mutex::padding) static mutex::unique_lock::mutex_type m {};
        mutex::scoped_lock lk { m };
#       ifdef _WIN32
            PROCESS_MEMORY_COUNTERS_EX pmc {};
            GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
            return static_cast<size_t>(pmc.PeakWorkingSetSize >> 20);
#       else
            struct rusage ru {};
            if (getrusage(RUSAGE_SELF, &ru) != 0)
                throw error_sys("getrusage failed");
#           ifdef __APPLE__
            return static_cast<size_t>(ru.ru_maxrss >> 20);
#           else
            return static_cast<size_t>(ru.ru_maxrss >> 10);
#           endif
#       endif
    }

    size_t physical_mb()
    {
        // Win API is not thread safe by default
        alignas(mutex::padding) static mutex::unique_lock::mutex_type m {};
        mutex::scoped_lock lk { m };
#       ifdef _WIN32
            MEMORYSTATUSEX status;
            status.dwLength = sizeof(status);
            GlobalMemoryStatusEx(&status);
            return static_cast<size_t>(status.ullTotalPhys >> 20);
#       else
            long pages = sysconf(_SC_PHYS_PAGES);
            long page_size = sysconf(_SC_PAGE_SIZE);
            return static_cast<size_t>((pages * page_size) >> 20);
#       endif
    }
}

#endif // !DAEDALUS_TURBO_MEMORY_HPP