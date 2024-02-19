/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2024 Alex Sierkov (alex dot sierkov at gmail dot com)
 * This code is distributed under the license specified in:
 * https://github.com/sierkov/daedalus-turbo/blob/main/LICENSE */
#ifndef DAEDALUS_TURBO_MEMORY_HPP
#define DAEDALUS_TURBO_MEMORY_HPP

extern "C" {
#ifdef _WIN32
#   include <windows.h>
#   include <psapi.h>
#else
#   include <sys/time.h>
#   include <sys/resource.h>
#endif
};

namespace daedalus_turbo::memory {
    inline size_t max_usage_mb()
    {
#       ifdef _WIN32
            PROCESS_MEMORY_COUNTERS_EX pmc {};
            GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc));
            return static_cast<size_t>(pmc.PeakWorkingSetSize >> 20);
#       else
            struct rusage ru {};
            if (getrusage(RUSAGE_SELF, &ru) != 0)
                throw error_sys("getrusage failed");
            return static_cast<size_t>(ru.ru_maxrss >> 10);
#       endif
    }

    inline size_t physical_mb()
    {
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