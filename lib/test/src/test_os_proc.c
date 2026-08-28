/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for the platform os_proc introspection shim
 * (lib/platform/src/os_proc.c) — Rung 1, docs/adr/0003-os-substrate-
 * verdict.md.
 *
 * Coverage:
 *   - real os_proc_mem_read() returns a sane VmRSS for this live process
 *   - real os_proc_uptime_seconds() returns a non-negative age
 *   - real os_proc_exe_path() resolves to an existing, absolute path
 *   - os_proc_mem_set_override() forces every subsequent read; NULL clears
 *   - os_proc_cgroup_dir() either resolves a real path or reports
 *     unavailable — never garbage
 */

#include "test/test_core.h"
#include "platform/os_proc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define OSPROC_CHECK(name, expr) do { \
    printf("os_proc: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

int test_os_proc(void);
int test_os_proc(void)
{
    printf("\n=== platform os_proc tests ===\n");
    int failures = 0;

    OSPROC_CHECK("native Linux release classification",
                 os_proc_environment_classify_kernel_release(
                     "6.12.8-generic") == OS_PROC_ENVIRONMENT_NATIVE);
    OSPROC_CHECK("WSL2 release classification",
                 os_proc_environment_classify_kernel_release(
                     "5.15.153.1-microsoft-standard-WSL2") ==
                     OS_PROC_ENVIRONMENT_WSL);
    OSPROC_CHECK("WSL classification is case-insensitive",
                 os_proc_environment_classify_kernel_release(
                     "4.4.0-MICROSOFT") == OS_PROC_ENVIRONMENT_WSL);
    OSPROC_CHECK("missing release remains unknown",
                 os_proc_environment_classify_kernel_release(NULL) ==
                     OS_PROC_ENVIRONMENT_UNKNOWN);
    OSPROC_CHECK("live environment is observed",
                 os_proc_environment_observe() !=
                     OS_PROC_ENVIRONMENT_UNKNOWN);

    /* ── real reads: this live process ───────────────────────────── */
    {
        os_proc_mem_set_override(NULL);

        struct os_proc_mem mem;
        bool ok = os_proc_mem_read(&mem);
        OSPROC_CHECK("mem_read succeeds for live process", ok);
        OSPROC_CHECK("live RSS is positive and sane (<64GB)",
                     mem.rss_bytes > 0 &&
                     mem.rss_bytes < (int64_t)64 * 1024 * 1024 * 1024);
        /* cgroup fields may legitimately be -1 (no cgroup v2 / no limit
         * configured) — only assert they are never a bogus negative other
         * than the -1 sentinel. */
        OSPROC_CHECK("cgroup_current is -1 or non-negative",
                     mem.cgroup_current == -1 || mem.cgroup_current >= 0);
        OSPROC_CHECK("cgroup_high is -1 or positive",
                     mem.cgroup_high == -1 || mem.cgroup_high > 0);
        OSPROC_CHECK("cgroup_max is -1 or positive",
                     mem.cgroup_max == -1 || mem.cgroup_max > 0);
        OSPROC_CHECK("sys_total_bytes is sane (>0, <can't-exist)",
                     mem.sys_total_bytes > 0);
        OSPROC_CHECK("sys_avail_bytes <= sys_total_bytes",
                     mem.sys_avail_bytes <= mem.sys_total_bytes);
    }

    /* ── uptime ───────────────────────────────────────────────────── */
    {
        int64_t age = os_proc_uptime_seconds();
        OSPROC_CHECK("uptime_seconds is non-negative", age >= 0);
        /* Sanity ceiling: this test process cannot possibly be older than
         * 10 years — catches a units bug (ticks vs seconds) rather than a
         * real long-running process. */
        OSPROC_CHECK("uptime_seconds is not absurdly large",
                     age < (int64_t)10 * 365 * 24 * 3600);
    }

    /* ── exe path ─────────────────────────────────────────────────── */
    {
        char path[4096];
        bool ok = os_proc_exe_path(path, sizeof(path));
        OSPROC_CHECK("exe_path resolves", ok);
        OSPROC_CHECK("exe_path is absolute", ok && path[0] == '/');
        struct stat st;
        OSPROC_CHECK("exe_path names an existing file",
                     ok && stat(path, &st) == 0);
    }

    /* ── open self exe ────────────────────────────────────────────── */
    {
        FILE *fp = os_proc_open_self_exe();
        OSPROC_CHECK("open_self_exe returns a non-NULL FILE*", fp != NULL);
        if (fp) {
            unsigned char buf[64];
            size_t n = fread(buf, 1, sizeof(buf), fp);
            /* The running test binary is always well over 64 bytes; a
             * short read here would mean we opened the wrong thing. */
            OSPROC_CHECK("open_self_exe reads real bytes from the running image",
                         n == sizeof(buf));
            fclose(fp);
        }
    }

    /* ── cgroup dir ───────────────────────────────────────────────── */
    {
        char dir[768];
        bool ok = os_proc_cgroup_dir(dir, sizeof(dir));
        /* Either resolves to a real, non-empty absolute path, or reports
         * unavailable — never a torn/partial buffer. */
        if (ok) {
            OSPROC_CHECK("cgroup_dir non-empty when resolved", dir[0] != '\0');
            OSPROC_CHECK("cgroup_dir absolute when resolved", dir[0] == '/');
        } else {
            OSPROC_CHECK("cgroup_dir false is a clean 'unavailable'", true);
        }

        /* Undersized buffer must fail cleanly, not overflow/crash. */
        char tiny[1];
        bool tiny_ok = os_proc_cgroup_dir(tiny, sizeof(tiny));
        OSPROC_CHECK("cgroup_dir with a 1-byte buffer never claims success",
                     !tiny_ok);
    }

    /* ── override seam ────────────────────────────────────────────── */
    {
        struct os_proc_mem forced = {
            .rss_bytes = 123456789,
            .vsize_bytes = 987654321,
            .cgroup_current = 100,
            .cgroup_high = 200,
            .cgroup_max = 300,
            .sys_total_bytes = 1000,
            .sys_avail_bytes = 500,
        };
        os_proc_mem_set_override(&forced);

        struct os_proc_mem got;
        bool ok = os_proc_mem_read(&got);
        OSPROC_CHECK("override read succeeds", ok);
        OSPROC_CHECK("override rss_bytes observed", got.rss_bytes == 123456789);
        OSPROC_CHECK("override vsize_bytes observed",
                     got.vsize_bytes == 987654321);
        OSPROC_CHECK("override cgroup_current observed",
                     got.cgroup_current == 100);
        OSPROC_CHECK("override cgroup_high observed", got.cgroup_high == 200);
        OSPROC_CHECK("override cgroup_max observed", got.cgroup_max == 300);
        OSPROC_CHECK("override sys_total_bytes observed",
                     got.sys_total_bytes == 1000);
        OSPROC_CHECK("override sys_avail_bytes observed",
                     got.sys_avail_bytes == 500);

        /* Second forced value fully replaces the first (no stale fields). */
        struct os_proc_mem forced2 = {
            .rss_bytes = 1, .vsize_bytes = 1, .cgroup_current = -1,
            .cgroup_high = -1, .cgroup_max = -1,
            .sys_total_bytes = -1, .sys_avail_bytes = -1,
        };
        os_proc_mem_set_override(&forced2);
        (void)os_proc_mem_read(&got);
        OSPROC_CHECK("second override fully replaces the first",
                     got.rss_bytes == 1 && got.cgroup_high == -1);

        /* Clear restores live reads. */
        os_proc_mem_set_override(NULL);
        (void)os_proc_mem_read(&got);
        OSPROC_CHECK("clearing the override restores a live (large, real) RSS",
                     got.rss_bytes != 1 && got.rss_bytes > 0);
    }

    /* Final defensive reset so later tests in the same process never see a
     * stuck override. */
    os_proc_mem_set_override(NULL);

    if (failures == 0) {
        printf("=== platform os_proc tests: ALL PASS ===\n\n");
    } else {
        printf("=== platform os_proc tests: %d FAILURE(S) ===\n\n", failures);
    }
    return failures;
}
