/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * In-process thread CPU profiler. See util/thread_profile.h.
 *
 * Two thread snapshots `sample_ms` apart (per-thread user+system CPU-tick
 * delta over the window; name + current wchan; a one-line verdict).
 * Bounded, read-only, and robust to a thread that races the sample window.
 */

#include "util/thread_profile.h"

#include "json/json.h"
#include "util/safe_alloc.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <pthread.h>
#include <unistd.h>
#else
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#endif

struct tp_entry {
    long     tid;
    uint64_t ticks1;      /* utime+stime at sample 1 */
    uint64_t ticks2;      /* utime+stime at sample 2 */
    bool     found2;
    char     name[32];    /* thread comm */
    char     wchan[48];   /* current kernel wait channel */
#if defined(_WIN32)
    HANDLE   handle;      /* retained so a recycled tid cannot change identity */
#endif
};

/* Read up to cap-1 bytes of `path` into `buf`, NUL-terminated. Returns bytes
 * read (0 on any failure — a racing thread whose file vanished is not fatal). */
#if !defined(__APPLE__) && !defined(_WIN32)
static size_t tp_read_file(const char *path, char *buf, size_t cap)
{
    if (cap == 0) return 0;
    buf[0] = '\0';
    FILE *f = fopen(path, "re");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n;
}

/* Parse utime(14)+stime(15) from a /proc/.../stat line. The comm field (2) is
 * parenthesised and may itself contain spaces and ')', so we scan from the LAST
 * ')' and count whitespace-separated fields from `state` (field 3). Returns
 * true and fills *out on success. */
static bool tp_parse_stat_ticks(const char *stat, uint64_t *out)
{
    const char *p = strrchr(stat, ')');
    if (!p) return false;
    p++; /* now at the space before `state` */
    /* Field index after ')': 0=state,1=ppid,...,11=utime,12=stime. */
    int idx = 0;
    unsigned long long utime = 0, stime = 0;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *tok = p;
        while (*p && *p != ' ') p++;
        if (idx == 11) utime = strtoull(tok, NULL, 10);
        else if (idx == 12) { stime = strtoull(tok, NULL, 10); break; }
        idx++;
    }
    if (idx < 12) return false;
    *out = (uint64_t)utime + (uint64_t)stime;
    return true;
}
#endif /* !__APPLE__ && !_WIN32 */

/* Windows has no /proc thread tree. Retain an opened thread handle across
 * both samples so a recycled numeric thread id cannot change identity, and
 * read kernel+user CPU time from GetThreadTimes in 100-nanosecond ticks. */
#if defined(_WIN32)
static uint64_t tp_filetime_ticks(const FILETIME *time)
{
    return ((uint64_t)time->dwHighDateTime << 32) | time->dwLowDateTime;
}

static bool tp_read_handle_ticks(HANDLE thread, uint64_t *out)
{
    FILETIME created, exited, kernel, user;
    if (!thread || !GetThreadTimes(thread, &created, &exited, &kernel, &user))
        return false;
    *out = tp_filetime_ticks(&kernel) + tp_filetime_ticks(&user);
    return true;
}

static int tp_collect_sample1(struct tp_entry *e, int cap, int64_t clk_tck)
{
    (void)clk_tck;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return -1;
    THREADENTRY32 entry = { .dwSize = sizeof(entry) };
    DWORD process = GetCurrentProcessId();
    int n = 0;
    if (Thread32First(snapshot, &entry)) {
        do {
            if (entry.th32OwnerProcessID != process || n >= cap) continue;
            HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION,
                                       FALSE, entry.th32ThreadID);
            uint64_t ticks = 0;
            if (!thread || !tp_read_handle_ticks(thread, &ticks)) {
                if (thread) CloseHandle(thread);
                continue;
            }
            e[n].tid = (long)entry.th32ThreadID;
            e[n].ticks1 = ticks;
            e[n].ticks2 = ticks;
            e[n].found2 = false;
            e[n].handle = thread;
            snprintf(e[n].name, sizeof(e[n].name), "tid-%lu",
                     (unsigned long)entry.th32ThreadID);
            snprintf(e[n].wchan, sizeof(e[n].wchan), "-");
            n++;
        } while (Thread32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return n;
}

static void tp_collect_sample2(struct tp_entry *e, int n, int64_t clk_tck)
{
    (void)clk_tck;
    for (int i = 0; i < n; i++) {
        uint64_t ticks = 0;
        e[i].found2 = tp_read_handle_ticks(e[i].handle, &ticks);
        if (e[i].found2) e[i].ticks2 = ticks;
    }
}

static void tp_entries_close(struct tp_entry *e, int n)
{
    for (int i = 0; i < n; i++)
        if (e[i].handle) CloseHandle(e[i].handle);
}
#endif /* _WIN32 */

/* Darwin has no /proc/self/task: the same two snapshots come from Mach. Each
 * entry is keyed by the stable thread identifier (THREAD_IDENTIFIER_INFO), and
 * cpu time (THREAD_BASIC_INFO user+system, seconds+microseconds) is scaled
 * into the same clk_tck tick unit the /proc sampler reports, so the shared
 * delta/verdict math below is identical on both platforms. wchan has no Mach
 * equivalent ("-"); the pthread name (or "?") stands in for comm. */
#if defined(__APPLE__)
static bool tp_mach_ticks(thread_act_t thread, int64_t clk_tck, uint64_t *out)
{
    struct thread_basic_info info;
    mach_msg_type_number_t count = THREAD_BASIC_INFO_COUNT;
    if (thread_info(thread, THREAD_BASIC_INFO, (thread_info_t)&info,
                    &count) != KERN_SUCCESS)
        return false; /* raced out of the task — skip */
    uint64_t us = (uint64_t)info.user_time.seconds * 1000000u +
                  (uint64_t)info.user_time.microseconds +
                  (uint64_t)info.system_time.seconds * 1000000u +
                  (uint64_t)info.system_time.microseconds;
    /* A thread with zero cpu time is real (the /proc sampler reports 0 too);
     * only a failed thread_info means "gone". */
    *out = us * (uint64_t)clk_tck / 1000000u;
    return true;
}

static uint64_t tp_mach_id(thread_act_t thread)
{
    struct thread_identifier_info id;
    mach_msg_type_number_t count = THREAD_IDENTIFIER_INFO_COUNT;
    if (thread_info(thread, THREAD_IDENTIFIER_INFO, (thread_info_t)&id,
                    &count) != KERN_SUCCESS)
        return 0;
    return id.thread_id;
}

static void tp_mach_name(thread_act_t thread, char *out, size_t cap)
{
    pthread_t pthread = pthread_from_mach_thread_np(thread);
    if (pthread && pthread_getname_np(pthread, out, cap) == 0 && out[0])
        return;
    snprintf(out, cap, "?");
}

/* Snapshot every live thread's identifier + cpu ticks (+ name at sample 1).
 * Returns the count, or -1 when the thread list cannot be read. */
static int tp_mach_collect(struct tp_entry *e, int cap, int64_t clk_tck,
                           bool sample1)
{
    thread_act_array_t list = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(mach_task_self(), &list, &count) != KERN_SUCCESS)
        return -1;
    int n = 0;
    bool released = true;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        uint64_t id = tp_mach_id(list[i]);
        uint64_t t = 0;
        bool observed = id != 0 && tp_mach_ticks(list[i], clk_tck, &t);
        if (observed && sample1 && n < cap) {
            e[n].tid = (long)id;
            e[n].ticks1 = t;
            e[n].ticks2 = t;
            e[n].found2 = false;
            tp_mach_name(list[i], e[n].name, sizeof(e[n].name));
            snprintf(e[n].wchan, sizeof(e[n].wchan), "-");
            n++;
        } else if (observed && !sample1) {
            for (int j = 0; j < cap; j++) {
                if ((uint64_t)e[j].tid != id) continue;
                e[j].ticks2 = t;
                e[j].found2 = true;
                tp_mach_name(list[i], e[j].name, sizeof(e[j].name));
                break;
            }
        }
        if (mach_port_deallocate(mach_task_self(), list[i]) != KERN_SUCCESS)
            released = false;
    }
    if (list && vm_deallocate(mach_task_self(), (vm_address_t)list,
                              (vm_size_t)(count * sizeof(*list))) !=
                  KERN_SUCCESS)
        released = false;
    if (!released) n = -1;
    return n;
}

static int tp_collect_sample1(struct tp_entry *e, int cap, int64_t clk_tck)
{
    return tp_mach_collect(e, cap, clk_tck, true);
}

static void tp_collect_sample2(struct tp_entry *e, int n, int64_t clk_tck)
{
    (void)tp_mach_collect(e, n, clk_tck, false);
}

static void tp_entries_close(struct tp_entry *e, int n)
{
    (void)e;
    (void)n;
}
#endif /* __APPLE__ */

/* Read one thread's cpu ticks from /proc/self/task/<tid>/stat. */
#if !defined(__APPLE__) && !defined(_WIN32)
static bool tp_read_ticks(long tid, uint64_t *out)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/stat", tid);
    char buf[512];
    if (tp_read_file(path, buf, sizeof(buf)) == 0) return false;
    return tp_parse_stat_ticks(buf, out);
}

static void tp_read_name(long tid, char *out, size_t cap)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/comm", tid);
    char buf[64];
    size_t n = tp_read_file(path, buf, sizeof(buf));
    if (n == 0) { snprintf(out, cap, "?"); return; }
    /* strip trailing newline */
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
    snprintf(out, cap, "%s", buf[0] ? buf : "?");
}

static void tp_read_wchan(long tid, char *out, size_t cap)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/self/task/%ld/wchan", tid);
    char buf[64];
    size_t n = tp_read_file(path, buf, sizeof(buf));
    if (n == 0) { snprintf(out, cap, "?"); return; }
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
    /* wchan is "0" when the thread is running (not sleeping). */
    if (!buf[0] || strcmp(buf, "0") == 0) snprintf(out, cap, "-");
    else snprintf(out, cap, "%s", buf);
}

/* Collect the numeric tids currently under /proc/self/task into e[].tid,
 * recording sample-1 ticks and the thread name. Returns the count. */
static int tp_collect_sample1(struct tp_entry *e, int cap, int64_t clk_tck)
{
    (void)clk_tck; /* the /proc sampler reads ticks already in clk_tck units */
    DIR *d = opendir("/proc/self/task");
    if (!d) return -1;
    int n = 0;
    struct dirent *de;
    while (n < cap && (de = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        long tid = strtol(de->d_name, NULL, 10);
        if (tid <= 0) continue;
        uint64_t t = 0;
        if (!tp_read_ticks(tid, &t)) continue; /* raced away — skip */
        e[n].tid = tid;
        e[n].ticks1 = t;
        e[n].ticks2 = t;
        e[n].found2 = false;
        tp_read_name(tid, e[n].name, sizeof(e[n].name));
        snprintf(e[n].wchan, sizeof(e[n].wchan), "-");
        n++;
    }
    closedir(d);
    return n;
}

/* Re-read each known tid for sample-2 ticks + current wchan/name. A tid that
 * vanished stays found2=false and is dropped from the report. */
static void tp_collect_sample2(struct tp_entry *e, int n, int64_t clk_tck)
{
    (void)clk_tck;
    for (int i = 0; i < n; i++) {
        uint64_t t = 0;
        if (!tp_read_ticks(e[i].tid, &t)) continue; /* exited mid-window */
        e[i].ticks2 = t;
        e[i].found2 = true;
        tp_read_wchan(e[i].tid, e[i].wchan, sizeof(e[i].wchan));
        tp_read_name(e[i].tid, e[i].name, sizeof(e[i].name));
    }
}

static void tp_entries_close(struct tp_entry *e, int n)
{
    (void)e;
    (void)n;
}
#endif /* !__APPLE__ && !_WIN32 */

static int tp_cmp_desc(const void *a, const void *b)
{
    const struct tp_entry *x = a, *y = b;
    uint64_t dx = x->found2 ? (x->ticks2 - x->ticks1) : 0;
    uint64_t dy = y->found2 ? (y->ticks2 - y->ticks1) : 0;
    if (dx < dy) return 1;
    if (dx > dy) return -1;
    return 0;
}

bool thread_profile_sample(const struct thread_profile_opts *opts,
                           struct json_value *out)
{
    if (!out) return false;
    json_set_object(out);

    int sample_ms = opts ? opts->sample_ms : 1000;
    if (sample_ms < 50) sample_ms = 50;
    if (sample_ms > 60000) sample_ms = 60000;
    int top_n = opts ? opts->top_n : 8;
    if (top_n < 1) top_n = 1;
    if (top_n > THREAD_PROFILE_TOP_MAX) top_n = THREAD_PROFILE_TOP_MAX;

    struct tp_entry *e =
        zcl_malloc(sizeof(*e) * THREAD_PROFILE_MAX, "thread_profile.entries");
    if (!e) return false;

#if defined(_WIN32)
    int64_t clk_tck = INT64_C(10000000);
#else
    int64_t clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0) clk_tck = 100;
#endif

    int64_t t0 = platform_time_monotonic_us();
    int n = tp_collect_sample1(e, THREAD_PROFILE_MAX, clk_tck);
    if (n < 0) { free(e); return false; }

    platform_sleep_ms(sample_ms);

    tp_collect_sample2(e, n, clk_tck);
    int64_t elapsed_us = platform_time_monotonic_us() - t0;
    if (elapsed_us <= 0) elapsed_us = (int64_t)sample_ms * 1000;
    double elapsed_ms = (double)elapsed_us / 1000.0;

    qsort(e, (size_t)n, sizeof(*e), tp_cmp_desc);

    /* Verdict from the busiest thread that survived both samples. */
    char verdict_buf[96];
    const char *verdict = "idle";
    const char *busiest = "-";
    double busiest_fraction = 0.0;
    int reported = 0;

    struct json_value threads;
    json_init(&threads);
    json_set_array(&threads);

    for (int i = 0; i < n && reported < top_n; i++) {
        if (!e[i].found2) continue;
        uint64_t delta = e[i].ticks2 - e[i].ticks1;
        double cpu_ms = (double)delta * 1000.0 / (double)clk_tck;
        double frac = elapsed_ms > 0 ? cpu_ms / elapsed_ms : 0.0;

        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        json_push_kv_int(&item, "tid", (int64_t)e[i].tid);
        json_push_kv_str(&item, "name", e[i].name);
        json_push_kv_int(&item, "cpu_ms", (int64_t)(cpu_ms + 0.5));
        json_push_kv_int(&item, "cpu_pct", (int64_t)(frac * 100.0 + 0.5));
        json_push_kv_str(&item, "wchan", e[i].wchan);
        json_push_back(&threads, &item);
        json_free(&item);

        if (reported == 0) {
            busiest = e[i].name;
            busiest_fraction = frac;
        }
        reported++;
    }

    /* Classify: a clearly cpu-bound top thread, an io/journal wait, else idle.
     * jbd2 is the ext4 journal daemon; our threads block on it via a wchan that
     * contains "jbd2" (e.g. jbd2_log_wait_commit). */
    if (busiest_fraction >= 0.50) {
        snprintf(verdict_buf, sizeof(verdict_buf), "cpu-bound in %s", busiest);
        verdict = verdict_buf;
    } else {
        const char *io_wchan = NULL;
        for (int i = 0; i < n; i++) {
            if (!e[i].found2) continue;
            const char *w = e[i].wchan;
            if (strstr(w, "jbd2") || strstr(w, "io_schedule") ||
                strstr(w, "wait_on_page") || strstr(w, "balance_dirty") ||
                strstr(w, "blk_") || strstr(w, "wbt_")) {
                io_wchan = w;
                break;
            }
        }
        if (io_wchan) {
            snprintf(verdict_buf, sizeof(verdict_buf), "io-wait in %s",
                     io_wchan);
            verdict = verdict_buf;
        } else if (busiest_fraction >= 0.05) {
            snprintf(verdict_buf, sizeof(verdict_buf), "light load, busiest %s",
                     busiest);
            verdict = verdict_buf;
        } else {
            verdict = "idle";
        }
    }

    json_push_kv_int(out, "sample_ms", (int64_t)sample_ms);
    json_push_kv_int(out, "sampled_threads", (int64_t)n);
    json_push_kv_int(out, "reported_threads", (int64_t)reported);
    json_push_kv_int(out, "clk_tck", clk_tck);
    json_push_kv_str(out, "busiest_thread", busiest);
    json_push_kv_str(out, "verdict", verdict);
    json_push_kv(out, "threads", &threads);
    json_free(&threads);

    tp_entries_close(e, n);
    free(e);
    return true;
}
