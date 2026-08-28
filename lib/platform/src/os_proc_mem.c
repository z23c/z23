/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_proc MEMORY OBSERVATION — how much memory this process and this host
 * are using, and the test override that stands in for it.
 *
 * Split out of os_proc.c along the file-size ceiling seam. This file owns a
 * complete, self-contained group and nothing else: the forced-snapshot flag
 * and its value, the two small text parsers the memory reads need, cgroup v2
 * directory and limit resolution, /proc/meminfo, and os_proc_mem_read()
 * itself. Every function that reads or writes the override pair lives here,
 * so both statics stay file-scope-private exactly as they were before the
 * split — nothing new is exported, and no name crosses the seam in either
 * direction. os_proc.c keeps process identity, liveness, uptime, image paths,
 * argv, fd counts and thread work; it does not reference anything below.
 *
 * The three public entry points here — os_proc_mem_read(),
 * os_proc_cgroup_dir() and os_proc_mem_set_override() — stay declared in
 * platform/os_proc.h, which is the only header any caller needs; there is no
 * private cross-TU header for this split because nothing private is shared.
 *
 * Each arm keeps the platform it had in the combined file: Windows reads the
 * process working set and the global memory status, Darwin reads
 * proc_pid_rusage plus Mach task_info and sysctl hw.memsize, and every other
 * host reads /proc/self/status, cgroup v2 and /proc/meminfo. Nothing here is
 * persisted or a consensus predicate.
 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "platform/os_proc.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <libproc.h>
#include <mach/mach.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#endif

#define OS_PROC_CGROUP_ROOT "/sys/fs/cgroup"

/* ── Test override seam (mirrors platform/clock.h, platform/rng.h) ──── */

static _Atomic bool g_override_active;
static struct os_proc_mem g_override_value;

void os_proc_mem_set_override(const struct os_proc_mem *forced)
{
    if (!forced) {
        atomic_store(&g_override_active, false);
        return;
    }
    g_override_value = *forced;
    atomic_store(&g_override_active, true);
}

/* ── Small parsing helpers ───────────────────────────────────────── */

#if !defined(_WIN32)
static void os_proc_trim_newline(char *s)
{
    if (!s)
        return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[len - 1] = '\0';
        len--;
    }
}

/* Read a single "Label: NNN kB" style line's value (in kB) from a
 * /proc/self/status-shaped file, returned as bytes. -1 if not found. */
#if !defined(__APPLE__) && !defined(_WIN32)
static int64_t os_proc_status_field_bytes(const char *path, const char *label)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[256];
    size_t label_len = strlen(label);
    int64_t result = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, label, label_len) != 0)
            continue;
        long long kb = 0;
        if (sscanf(line + label_len, " %lld", &kb) == 1 && kb >= 0)
            result = (int64_t)kb * 1024;
        break;
    }
    fclose(f);
    return result;
}
#endif

#endif /* !_WIN32 */

/* ── cgroup v2 dir resolution + limit reads ──────────────────────── */

bool os_proc_cgroup_dir(char *out, size_t out_len)
{
    if (!out || out_len == 0)
        return false; // raw-return-ok:optional-cgroup-unavailable

#if defined(_WIN32)
    return false; // raw-return-ok:platform-has-no-cgroups
#else
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f)
        return false; // raw-return-ok:optional-cgroup-unavailable

    char line[512];
    bool ok = false;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::", 3) != 0)
            continue;
        char *rel = line + 3;
        os_proc_trim_newline(rel);
        int n = 0;
        if (rel[0] == '\0' || strcmp(rel, "/") == 0) {
            n = snprintf(out, out_len, "%s", OS_PROC_CGROUP_ROOT);
        } else if (rel[0] == '/') {
            n = snprintf(out, out_len, "%s%s", OS_PROC_CGROUP_ROOT, rel);
        } else {
            n = snprintf(out, out_len, "%s/%s", OS_PROC_CGROUP_ROOT, rel);
        }
        if (n < 0 || (size_t)n >= out_len)
            break;
        ok = true;
        break;
    }

    fclose(f);
    return ok;
#endif
}

#if !defined(__APPLE__) && !defined(_WIN32)
static int64_t os_proc_cgroup_limit_bytes(const char *dir, const char *name)
{
    if (!dir || !name)
        return -1; // raw-return-ok:optional-cgroup-unavailable

    char path[768];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path))
        return -1; // raw-return-ok:optional-cgroup-unavailable

    FILE *f = fopen(path, "r");
    if (!f)
        return -1; // raw-return-ok:optional-cgroup-unavailable

    char buf[64];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -1; // raw-return-ok:optional-cgroup-unavailable
    }
    fclose(f);
    os_proc_trim_newline(buf);
    if (strcmp(buf, "max") == 0)
        return -1; // raw-return-ok:unlimited-cgroup-value

    long long value = -1;
    if (sscanf(buf, "%lld", &value) != 1 || value < 0)
        return -1; // raw-return-ok:optional-cgroup-unavailable
    return (int64_t)value;
}

/* ── /proc/meminfo (system totals) ───────────────────────────────── */

static void os_proc_meminfo(int64_t *total_bytes, int64_t *avail_bytes)
{
    *total_bytes = -1;
    *avail_bytes = -1;

    FILE *f = fopen("/proc/meminfo", "r");
    if (!f)
        return;

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), f) && found < 2) {
        long long kb = 0;
        if (strncmp(line, "MemTotal:", 9) == 0) {
            if (sscanf(line + 9, " %lld", &kb) == 1 && kb >= 0) {
                *total_bytes = (int64_t)kb * 1024;
                found++;
            }
        } else if (strncmp(line, "MemAvailable:", 13) == 0) {
            if (sscanf(line + 13, " %lld", &kb) == 1 && kb >= 0) {
                *avail_bytes = (int64_t)kb * 1024;
                found++;
            }
        }
    }
    fclose(f);
}
#endif

/* ── Public API ───────────────────────────────────────────────────── */

bool os_proc_mem_read(struct os_proc_mem *out)
{
    if (!out)
        return false; // raw-return-ok:null-arg

    if (atomic_load(&g_override_active)) {
        *out = g_override_value;
        return true;
    }

#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS counters;
    memset(&counters, 0, sizeof(counters));
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(GetCurrentProcess(), &counters,
                              sizeof(counters)))
        return false;
    out->rss_bytes = (int64_t)counters.WorkingSetSize;
    out->vsize_bytes = (int64_t)counters.PagefileUsage;
    out->cgroup_current = -1;
    out->cgroup_high = -1;
    out->cgroup_max = -1;
    MEMORYSTATUSEX memory;
    memset(&memory, 0, sizeof(memory));
    memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory)) {
        out->sys_total_bytes = (int64_t)memory.ullTotalPhys;
        out->sys_avail_bytes = (int64_t)memory.ullAvailPhys;
    } else {
        out->sys_total_bytes = -1;
        out->sys_avail_bytes = -1;
    }
    return true;
#elif defined(__APPLE__)
    struct rusage_info_v2 usage;
    memset(&usage, 0, sizeof(usage));
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V2,
                        (rusage_info_t *)&usage) != 0)
        return false;
    out->rss_bytes = (int64_t)usage.ri_resident_size;
    mach_task_basic_info_data_t basic;
    mach_msg_type_number_t basic_count = MACH_TASK_BASIC_INFO_COUNT;
    out->vsize_bytes = task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
        (task_info_t)&basic, &basic_count) == KERN_SUCCESS
        ? (int64_t)basic.virtual_size : -1;
    out->cgroup_current = -1;
    out->cgroup_high = -1;
    out->cgroup_max = -1;
    uint64_t total = 0;
    size_t total_size = sizeof(total);
    out->sys_total_bytes = sysctlbyname("hw.memsize", &total, &total_size,
                                       NULL, 0) == 0 ? (int64_t)total : -1;
    out->sys_avail_bytes = -1;
    return true;
#else
    out->rss_bytes = os_proc_status_field_bytes("/proc/self/status", "VmRSS:");
    out->vsize_bytes = os_proc_status_field_bytes("/proc/self/status", "VmSize:");

    char dir[768];
    if (os_proc_cgroup_dir(dir, sizeof(dir))) {
        out->cgroup_current = os_proc_cgroup_limit_bytes(dir, "memory.current");
        out->cgroup_high = os_proc_cgroup_limit_bytes(dir, "memory.high");
        out->cgroup_max = os_proc_cgroup_limit_bytes(dir, "memory.max");
    } else {
        out->cgroup_current = -1;
        out->cgroup_high = -1;
        out->cgroup_max = -1;
    }

    os_proc_meminfo(&out->sys_total_bytes, &out->sys_avail_bytes);

    return out->rss_bytes >= 0;
#endif
}
