/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless native acceptance for processor-group-aware logical CPU count. */
#include "platform/logical_cpu.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(void)
{
    uint32_t observed = platform_logical_cpu_count();
    if (observed == 0)
        return 1;

    /* The oracle has to be taken at the SAME _WIN32_WINNT this translation
     * unit is compiled at, or this program grades a different question than
     * the one the compiler was actually asked. mingw declares
     * GetActiveProcessorCount/ALL_PROCESSOR_GROUPS only at >= 0x0601.
     * ZCL_PLATFORM_CPPFLAGS pins the product's Windows target at 0x0A00
     * (Windows 10), so the shipped build takes the first arm and grades the
     * all-groups count -- but this file is ALSO compiled standalone by
     * strict per-file checks that supply no global _WIN32_WINNT, where
     * mingw's own default decides. That is the exact case
     * lib/platform/src/logical_cpu.c documents when it defines its own
     * baseline, so the branch stays here rather than assuming a define this
     * TU may not receive. lib/platform/src/logical_cpu.c carries the same
     * split -- mirror it rather than assert against an API the compile may
     * not reach. Both arms stay EXACT equality; neither is a bound. */
#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0601
    DWORD expected = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (expected != 0 && observed != (uint32_t)expected)
        return 1;
#else
    /* Below 0x0601 the seam returns the CALLING THREAD's processor group
     * only -- a deliberate undercount, and the only value GetSystemInfo can
     * report. Assert that documented value exactly, so a seam that silently
     * changed strategy at this floor is still caught. The product itself no
     * longer builds here (logical_cpu.c #errors below 0x0601), so this arm
     * exists for the standalone-TU compile above, not for a shipped
     * configuration. */
    SYSTEM_INFO si;
    memset(&si, 0, sizeof si);
    GetSystemInfo(&si);
    DWORD expected = si.dwNumberOfProcessors;
    if (expected != 0 && observed != (uint32_t)expected)
        return 1;
#endif
    puts("logical_cpu_acceptance: PASS");
    return 0;
}
