/* Headless native acceptance for processor-group-aware logical CPU count. */
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

    /* The oracle has to be taken at the SAME _WIN32_WINNT the product is
     * built at, or this program grades a different question than the node
     * ships. mingw declares GetActiveProcessorCount/ALL_PROCESSOR_GROUPS
     * only at >= 0x0601; ZCL_PLATFORM_CPPFLAGS pins the Windows target at
     * 0x0600, so calling them unconditionally does not compile for the
     * product's actual target. lib/platform/src/logical_cpu.c carries this
     * exact branch -- mirror it rather than assert against an API the build
     * cannot reach. Both arms stay EXACT equality; neither is a bound. */
#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0601
    DWORD expected = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (expected != 0 && observed != (uint32_t)expected)
        return 1;
#else
    /* At the 0x0600 floor the seam returns the CALLING THREAD's processor
     * group only -- a deliberate undercount. Assert that documented value
     * exactly, so a seam that silently changed strategy at this floor is
     * still caught. */
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
