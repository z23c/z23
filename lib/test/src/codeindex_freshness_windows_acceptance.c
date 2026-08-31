/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Native Windows latency and determinism acceptance for the exact
 * code-index source metadata root used by every warm source-view query. */
#if defined(_WIN32)

#include "codeindex_priv.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

static const char *const lib_modules[] = {
#define LIB_MODULE(name_) name_,
#include "../../../config/lib_module_order.def"
#undef LIB_MODULE
};

static const char *const app_shapes[] = {
    "conditions", "controllers", "jobs", "models",
    "services", "supervisors", "views",
};

const char *const *ci_lib_modules(size_t *count)
{
    if (count) *count = sizeof(lib_modules) / sizeof(lib_modules[0]);
    return lib_modules;
}

const char *const *ci_app_shapes(size_t *count)
{
    if (count) *count = sizeof(app_shapes) / sizeof(app_shapes[0]);
    return app_shapes;
}

static int fail(const char *message)
{
    fprintf(stderr, "codeindex_freshness_windows_acceptance: FAIL: %s\n",
            message);
    return 1;
}

static uint64_t elapsed_us(LARGE_INTEGER start, LARGE_INTEGER end,
                           LARGE_INTEGER frequency)
{
    if (end.QuadPart < start.QuadPart || frequency.QuadPart <= 0) return 0;
    uint64_t ticks = (uint64_t)(end.QuadPart - start.QuadPart);
    uint64_t whole = ticks / (uint64_t)frequency.QuadPart;
    uint64_t remainder = ticks % (uint64_t)frequency.QuadPart;
    if (whole > UINT64_MAX / UINT64_C(1000000)) return UINT64_MAX;
    return whole * UINT64_C(1000000) +
           remainder * UINT64_C(1000000) /
               (uint64_t)frequency.QuadPart;
}

int main(void)
{
    static const uint64_t budget_us = UINT64_C(150000);
    LARGE_INTEGER frequency, start, end;
    uint8_t first[32], second[32];
    if (!QueryPerformanceFrequency(&frequency) ||
        !ci_source_stat_root_sha3(".", first) ||
        !QueryPerformanceCounter(&start) ||
        !ci_source_stat_root_sha3(".", second) ||
        !QueryPerformanceCounter(&end))
        return fail("source metadata root capture");
    if (memcmp(first, second, sizeof(first)) != 0)
        return fail("unchanged source metadata root changed");
    uint64_t microseconds = elapsed_us(start, end, frequency);
    if (microseconds > budget_us) {
        fprintf(stderr,
                "codeindex_freshness_windows_acceptance: FAIL: "
                "elapsed_us=%llu budget_us=%llu\n",
                (unsigned long long)microseconds,
                (unsigned long long)budget_us);
        return 1;
    }
    printf("codeindex_freshness_windows_acceptance: PASS elapsed_us=%llu\n",
           (unsigned long long)microseconds);
    return 0;
}

#else
typedef int codeindex_freshness_windows_acceptance_not_built;
#endif
