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
    DWORD expected = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (observed == 0 || (expected != 0 && observed != (uint32_t)expected))
        return 1;
    puts("logical_cpu_acceptance: PASS");
    return 0;
}
