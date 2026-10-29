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
 * The four public entry points here — os_proc_mem_read(),
 * os_proc_cgroup_dir(), os_proc_cgroup_mem_stat_read() and
 * os_proc_mem_set_override() — stay declared in platform/os_proc.h, which is
 * the only header any caller needs; there is no private cross-TU header for
 * this split because nothing private is shared.
 *
 * Each arm keeps the platform it had in the combined file: Windows reads the
 * process working set and the global memory status, Darwin reads
 * proc_pid_rusage plus Mach task_info, sysctl hw.memsize, and reclaimable
 * HOST_VM_INFO64 pages, and every other host reads /proc/self/status, cgroup
 * v2 and /proc/meminfo. Nothing here is persisted or a consensus predicate.
 */
#if !defined(_WIN32) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "platform/os_proc.h"

#include <stdatomic.h>
#include <errno.h>
#include <stdlib.h>
#if defined(__linux__)
#include <sys/stat.h>
#include <sys/vfs.h>
#include <linux/magic.h>
#endif
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
#include <mach/mach_host.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#endif

#define OS_PROC_CGROUP_ROOT "/sys/fs/cgroup"

#if defined(__APPLE__)
static int64_t os_proc_darwin_available_bytes(int64_t total_bytes)
{
    mach_port_t host = mach_host_self();
    vm_statistics64_data_t stats;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    vm_size_t page_size = 0;
    kern_return_t stats_rc = host_statistics64(
        host, HOST_VM_INFO64, (host_info64_t)&stats, &count);
    kern_return_t page_rc = host_page_size(host, &page_size);
    (void)mach_port_deallocate(mach_task_self(), host);
    if (stats_rc != KERN_SUCCESS || page_rc != KERN_SUCCESS ||
        page_size == 0)
        return -1;

    /* XNU accounts speculative pages inside free_count already. Adding
     * speculative_count again would overstate reclaimable memory and delay
     * subordinate-work admission under real unified-memory pressure. */
    uint64_t pages = (uint64_t)stats.free_count +
                     (uint64_t)stats.inactive_count;
    if (pages > (uint64_t)INT64_MAX / (uint64_t)page_size)
        return -1;
    int64_t available = (int64_t)(pages * (uint64_t)page_size);
    if (total_bytes > 0 && available > total_bytes)
        available = total_bytes;
    return available;
}
#endif

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

#if !defined(_WIN32)
/* "<key> <bytes>\n" -> bytes, or -1 when this row is not `key`. The key must
 * be followed by the separating space, so "file" never reads "file_mapped",
 * "file_dirty" or "file_writeback". */
static int64_t cgroup_stat_row_bytes(const char *line, const char *key)
{
    size_t key_len = strlen(key);
    if (strncmp(line, key, key_len) != 0 || line[key_len] != ' ')
        return -1; // raw-return-ok:row-is-a-different-key
    long long value = -1;
    if (sscanf(line + key_len, " %lld", &value) != 1 || value < 0)
        return -1; // raw-return-ok:optional-cgroup-unavailable
    return (int64_t)value;
}

/* Store one memory.stat line into whichever field of `out` it names, if any.
 * Table-driven so the single pass stays one loop over one open however many
 * rows the memory organ later needs. */
static void cgroup_stat_absorb_row(struct os_proc_cgroup_mem_stat *out,
                                   const char *line)
{
    const struct {
        const char *key;
        int64_t *slot;
    } rows[] = {
        { "file", &out->file },
        { "shmem", &out->shmem },
        { "unevictable", &out->unevictable },
        { "file_dirty", &out->file_dirty },
        { "file_writeback", &out->file_writeback },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        int64_t value = cgroup_stat_row_bytes(line, rows[i].key);
        if (value < 0)
            continue;
        *rows[i].slot = value;
        return;
    }
}
#endif

bool os_proc_cgroup_mem_stat_read(const char *dir,
                                  struct os_proc_cgroup_mem_stat *out)
{
    if (!out)
        return false; // raw-return-ok:optional-cgroup-unavailable
    out->file = -1;
    out->shmem = -1;
    out->unevictable = -1;
    out->file_dirty = -1;
    out->file_writeback = -1;
#if defined(_WIN32)
    (void)dir;
    return false; // raw-return-ok:platform-has-no-cgroups
#else
    if (!dir)
        return false; // raw-return-ok:optional-cgroup-unavailable

    char path[768];
    int n = snprintf(path, sizeof(path), "%s/memory.stat", dir);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false; // raw-return-ok:optional-cgroup-unavailable

    FILE *f = fopen(path, "r");
    if (!f)
        return false; // raw-return-ok:optional-cgroup-unavailable

    char line[128];
    while (fgets(line, sizeof(line), f))
        cgroup_stat_absorb_row(out, line);
    fclose(f);
    return true;
#endif
}

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
    os_proc_cgroup_mem_stat_read(NULL, &out->cgroup_stat);
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
    os_proc_cgroup_mem_stat_read(NULL, &out->cgroup_stat);
    uint64_t total = 0;
    size_t total_size = sizeof(total);
    out->sys_total_bytes = sysctlbyname("hw.memsize", &total, &total_size,
                                       NULL, 0) == 0 ? (int64_t)total : -1;
    out->sys_avail_bytes =
        os_proc_darwin_available_bytes(out->sys_total_bytes);
    return true;
#else
    out->rss_bytes = os_proc_status_field_bytes("/proc/self/status", "VmRSS:");
    out->vsize_bytes = os_proc_status_field_bytes("/proc/self/status", "VmSize:");

    char dir[768];
    if (os_proc_cgroup_dir(dir, sizeof(dir))) {
        out->cgroup_current = os_proc_cgroup_limit_bytes(dir, "memory.current");
        out->cgroup_high = os_proc_cgroup_limit_bytes(dir, "memory.high");
        out->cgroup_max = os_proc_cgroup_limit_bytes(dir, "memory.max");
        os_proc_cgroup_mem_stat_read(dir, &out->cgroup_stat);
    } else {
        out->cgroup_current = -1;
        out->cgroup_high = -1;
        out->cgroup_max = -1;
        os_proc_cgroup_mem_stat_read(NULL, &out->cgroup_stat);
    }

    os_proc_meminfo(&out->sys_total_bytes, &out->sys_avail_bytes);

    return out->rss_bytes >= 0;
#endif
}

/* Resident set in KiB. Linux reads field 2 of /proc/self/statm (pages, no
 * cgroup or meminfo work, so cheap enough to call twice around a trim); other
 * hosts fall back to os_proc_mem_read(). -1 on failure. */
int64_t os_proc_resident_kib(void)
{
#if defined(__linux__)
    if (!atomic_load(&g_override_active)) {
        FILE *f = fopen("/proc/self/statm", "r");
        if (f) {
            long long size = 0, res = 0;
            int n = fscanf(f, "%lld %lld", &size, &res);
            fclose(f);
            long ps = sysconf(_SC_PAGESIZE);
            if (n == 2 && res >= 0 && ps > 0)
                return (int64_t)res * ((int64_t)ps / 1024);
        }
        return -1;
    }
#endif
    struct os_proc_mem m;
    if (!os_proc_mem_read(&m) || m.rss_bytes < 0)
        return -1;
    return m.rss_bytes / 1024;
}

#if defined(__linux__)
/* Read one complete control value. Truncation and I/O failures are unknown. */
static bool os_proc_control(const char *dir, const char *name, char *out, size_t cap)
{
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "r");
    if (!f) return false;
    bool ok = fgets(out, (int)cap, f) != NULL && strchr(out, '\n') != NULL &&
              fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0) ok = false;
    if (ok) os_proc_trim_newline(out);
    return ok;
}

static bool os_proc_control_number(const char *dir, const char *name,
                                   bool allow_max, uint64_t *out, bool *unlimited)
{
    char buf[64];
    if (!os_proc_control(dir, name, buf, sizeof(buf))) return false;
    *unlimited = false;
    if (allow_max && strcmp(buf, "max") == 0) { *unlimited = true; return true; }
    if (buf[0] < '0' || buf[0] > '9') return false;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(buf, &end, 10);
    if (errno || !end || *end) return false;
    *out = (uint64_t)value;
    return true;
}

static bool os_proc_cgroup_missing(const char *root, const char *name)
{
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/%s", root, name);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    struct stat st;
    return lstat(path, &st) != 0 && errno == ENOENT;
}

static bool os_proc_cgroup_path_valid(const char *path)
{
    if (!path || path[0] != '/' || strstr(path, "//") ||
        strstr(path, "/../") || strstr(path, "/./")) return false;
    size_t n = strlen(path);
    return !(n >= 3 && strcmp(path + n - 3, "/..") == 0) &&
           !(n >= 2 && strcmp(path + n - 2, "/.") == 0);
}

static bool os_proc_cgroup_leaf(const char *root, char *out, size_t cap)
{
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f) return false;
    char line[4096];
    bool found = false, valid = true;
    while (fgets(line, sizeof(line), f)) {
        if (!strchr(line, '\n')) { valid = false; break; }
        if (strncmp(line, "0::", 3) != 0) continue;
        os_proc_trim_newline(line);
        if (found || !os_proc_cgroup_path_valid(line + 3)) { valid = false; break; }
        int n = snprintf(out, cap, "%s%s", root, line + 3);
        if (n < 0 || (size_t)n >= cap) { valid = false; break; }
        found = true;
    }
    if (ferror(f)) valid = false;
    if (fclose(f) != 0) valid = false;
    return valid && found;
}

static bool os_proc_cgroup_level(const char *dir, uint64_t *headroom)
{
    uint64_t current, high = UINT64_MAX, max = UINT64_MAX;
    bool current_unlimited, high_unlimited, max_unlimited;
    if (!os_proc_control_number(dir, "memory.current", false, &current, &current_unlimited) ||
        !os_proc_control_number(dir, "memory.high", true, &high, &high_unlimited) ||
        !os_proc_control_number(dir, "memory.max", true, &max, &max_unlimited)) return false;
    uint64_t limit = high < max ? high : max;
    if (!high_unlimited || !max_unlimited) {
        uint64_t available = current < limit ? limit - current : 0;
        if (available < *headroom) *headroom = available;
    }
    return true;
}
#endif

/* cgroup.type and cgroup.events are CFTYPE_NOT_ON_ROOT in Linux. A
 * namespace-hidden nonroot still has them; absence must be exact ENOENT.
 * This shape is only meaningful on the separately verified cgroup2 mount. */
bool os_proc_cgroup_root_controls_match(const char *root)
{
#if defined(__linux__)
    char controls[1024];
    if (!root || !os_proc_control(root, "cgroup.controllers", controls, sizeof(controls)) ||
        !os_proc_cgroup_missing(root, "cgroup.type") ||
        !os_proc_cgroup_missing(root, "cgroup.events")) return false;
    char *save = NULL;
    for (char *token = strtok_r(controls, " ", &save); token;
         token = strtok_r(NULL, " ", &save))
        if (strcmp(token, "memory") == 0) return true;
    return false;
#else
    (void)root;
    return false;
#endif
}

#if defined(__linux__)
static bool os_proc_cgroup_pid_line(const char *line, uint64_t *pid)
{
    if (line[0] < '0' || line[0] > '9') return false;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(line, &end, 10);
    if (errno || !end || strcmp(end, "\n") != 0 || value == 0) return false;
    *pid = (uint64_t)value;
    return true;
}
#endif

bool os_proc_cgroup_contains_pid(const char *dir, uint64_t pid)
{
#if defined(__linux__)
    if (!dir || !pid) return false;
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/cgroup.procs", dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[32];
    size_t bytes = 0;
    bool found = false, valid = true;
    while (fgets(line, sizeof(line), f)) {
        bytes += strlen(line);
        uint64_t value;
        if (bytes > 65536u || !os_proc_cgroup_pid_line(line, &value)) {
            valid = false;
            break;
        }
        if (value == pid) found = true;
    }
    if (ferror(f)) valid = false;
    if (fclose(f) != 0) valid = false;
    return valid && found;
#else
    (void)dir; (void)pid;
    return false;
#endif
}

#if defined(__linux__)
static bool os_proc_cgroup_walk_levels(const char *root, char *resolved,
                                        uint64_t *out)
{
    size_t root_len = strlen(root);
    if (strncmp(root, resolved, root_len) != 0 ||
        (resolved[root_len] != '\0' && resolved[root_len] != '/')) return false;
    struct stat root_stat;
    if (stat(root, &root_stat) != 0) return false;
    uint64_t headroom = UINT64_MAX;
    while (strcmp(root, resolved) != 0) {
        struct stat st;
        if (stat(resolved, &st) != 0 || st.st_dev != root_stat.st_dev ||
            !os_proc_cgroup_level(resolved, &headroom)) return false;
        char *slash = strrchr(resolved, '/');
        if (!slash || (size_t)(slash - resolved) < root_len) return false;
        *slash = '\0';
    }
    *out = headroom;
    return true;
}
#endif

bool os_proc_cgroup_memory_levels_read(const char *root_path, const char *leaf,
                                        uint64_t *out)
{
    if (!out) return false;
    *out = 0;
#if defined(__linux__)
    char root[4096], resolved[4096];
    if (!root_path || !leaf || !realpath(root_path, root) ||
        !realpath(leaf, resolved)) return false;
    return os_proc_cgroup_walk_levels(root, resolved, out);
#else
    (void)root_path; (void)leaf;
    return false;
#endif
}

bool os_proc_cgroup_memory_headroom(uint64_t *out)
{
    if (!out) return false;
    *out = 0;
#if defined(__linux__)
    char root[4096], leaf[4096];
    uint64_t headroom;
    struct statfs fs;
    if (!realpath(OS_PROC_CGROUP_ROOT, root) || statfs(root, &fs) != 0 ||
        (unsigned long)fs.f_type != CGROUP2_SUPER_MAGIC ||
        !os_proc_cgroup_root_controls_match(root) ||
        !os_proc_cgroup_leaf(root, leaf, sizeof(leaf)) ||
        !os_proc_cgroup_contains_pid(leaf, (uint64_t)getpid()) ||
        !os_proc_cgroup_memory_levels_read(root, leaf, &headroom) ||
        !os_proc_cgroup_contains_pid(leaf, (uint64_t)getpid())) return false;
    *out = headroom;
    return true;
#else
    return false;
#endif
}
