/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Headless native acceptance for processor-group-aware logical CPU count. */
#include "platform/logical_cpu.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdint.h>
#include <stdio.h>
#include <windows.h>

int main(void)
{
    uint32_t observed = platform_logical_cpu_count();
    /* Kept separate from the equality check below so a seam that returns
     * nothing at all is distinguishable in the source from a seam that
     * returns the wrong count. */
    if (observed == 0)
        return 1;

    /* The oracle has to be taken at the SAME _WIN32_WINNT this translation
     * unit is compiled at, or this program grades a different question than
     * the one the compiler was actually asked. mingw declares
     * GetActiveProcessorCount/ALL_PROCESSOR_GROUPS only at >= 0x0601, and
     * lib/platform/src/logical_cpu.c #errors below that floor, so every
     * configuration this program can link in reaches the all-groups count.
     * The comparison stays EXACT equality; it is not a bound. */
    DWORD expected = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (expected != 0 && observed != (uint32_t)expected)
        return 1;
    puts("logical_cpu_acceptance: PASS");
    return 0;
}
