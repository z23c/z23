/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the --bench line: first_frame_ms, first_data_ms, rss_kb,
 * private_kb, exe_bytes, idle_cpu_ms. Measured from the OS, not estimated. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "zw.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>

typedef BOOL (WINAPI *mem_info_fn)(HANDLE, PROCESS_MEMORY_COUNTERS_EX *, DWORD);

int64_t zw_process_age_ms(void)
{
    FILETIME c, e, k, u, now;
    if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) return 0;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER a, b;
    a.LowPart = c.dwLowDateTime; a.HighPart = c.dwHighDateTime;
    b.LowPart = now.dwLowDateTime; b.HighPart = now.dwHighDateTime;
    return (int64_t)((b.QuadPart - a.QuadPart) / 10000u);
}

static void memory_kb(long long *rss, long long *priv)
{
    *rss = *priv = -1;
    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    FARPROC p = k ? GetProcAddress(k, "K32GetProcessMemoryInfo") : NULL;
    if (!p) return;
    mem_info_fn f;
    memcpy(&f, &p, sizeof(f));
    PROCESS_MEMORY_COUNTERS_EX c;
    memset(&c, 0, sizeof(c));
    c.cb = sizeof(c);
    if (f(GetCurrentProcess(), &c, sizeof(c))) {
        *rss = (long long)(c.WorkingSetSize / 1024u);
        *priv = (long long)(c.PrivateUsage / 1024u);
    }
}

static long long cpu_ms(void)
{
    FILETIME c, e, k, u;
    if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) return -1;
    ULARGE_INTEGER a, b;
    a.LowPart = k.dwLowDateTime; a.HighPart = k.dwHighDateTime;
    b.LowPart = u.dwLowDateTime; b.HighPart = u.dwHighDateTime;
    return (long long)((a.QuadPart + b.QuadPart) / 10000u);
}

static long long exe_bytes(void)
{
    wchar_t p[1024];
    if (!GetModuleFileNameW(NULL, p, 1024)) return -1;
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExW(p, GetFileExInfoStandard, &d)) return -1;
    return (long long)(((unsigned long long)d.nFileSizeHigh << 32) | d.nFileSizeLow);
}
#else
#include <sys/stat.h>

static struct timespec g_start;
__attribute__((constructor)) static void age_init(void) { clock_gettime(CLOCK_MONOTONIC, &g_start); }

int64_t zw_process_age_ms(void)
{
    struct timespec n;
    clock_gettime(CLOCK_MONOTONIC, &n);
    return (int64_t)(n.tv_sec - g_start.tv_sec) * 1000 + (n.tv_nsec - g_start.tv_nsec) / 1000000;
}

static void memory_kb(long long *rss, long long *priv)
{
    *rss = *priv = -1;
    FILE *f = fopen("/proc/self/status", "r");
    char line[128];
    while (f && fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "VmRSS:", 6)) *rss = strtoll(line + 6, NULL, 10);
        if (!strncmp(line, "RssAnon:", 8)) *priv = strtoll(line + 8, NULL, 10);
    }
    if (f) fclose(f);
}

static long long cpu_ms(void)
{
    struct timespec t;
    return clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t) == 0
        ? (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000 : -1;
}

static long long exe_bytes(void)
{
    struct stat st;
    return stat("/proc/self/exe", &st) == 0 ? (long long)st.st_size : -1;
}
#endif

bool zw_bench_write(const char *path, const struct zw_bench *b)
{
    long long rss, priv;
    memory_kb(&rss, &priv);
#if defined(_WIN32)
    wchar_t wp[1024];
    FILE *out = MultiByteToWideChar(CP_UTF8, 0, path, -1, wp, 1024) > 0 ? _wfopen(wp, L"wb") : NULL;
#else
    FILE *out = fopen(path, "wb");
#endif
    if (!out) return false;
    fprintf(out, "first_frame_ms=%lld first_data_ms=%lld rss_kb=%lld private_kb=%lld exe_bytes=%lld "
            "idle_cpu_ms_total=%lld\n", (long long)b->first_frame_ms, (long long)b->first_data_ms,
            rss, priv, exe_bytes(), cpu_ms());
    return fclose(out) == 0;
}
