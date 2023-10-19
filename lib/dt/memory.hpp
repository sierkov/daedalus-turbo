/* This file is part of Daedalus Turbo project: https://github.com/sierkov/daedalus-turbo/
 * Copyright (c) 2022-2023 Alex Sierkov (alex dot sierkov at gmail dot com)
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
            return pmc.PeakWorkingSetSize >> 20;
#       else
            struct rusage ru {};
            if (getrusage(RUSAGE_SELF, &ru) != 0)
                throw error_sys("getrusage failed");
            return (size_t)(ru.ru_maxrss >> 10);
#       endif
    }
}

#endif // !DAEDALUS_TURBO_MEMORY_HPP