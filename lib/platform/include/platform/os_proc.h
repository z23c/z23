/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_proc — process/host introspection shim (Rung 1,
 * docs/adr/0003-os-substrate-verdict.md + docs/work/os-substrate-plan.md §2).
 *
 * Why:
 *   lib/platform is the one blessed home for direct OS-introspection
 *   syscalls/pseudo-files, mirroring platform/clock.h and platform/rng.h:
 *   production code reads process/host state through this seam; tests
 *   install a forced snapshot instead of faking /proc.
 *
 * Linux implementation:
 *   - rss_bytes / vsize_bytes: VmRSS / VmSize from /proc/self/status.
 *   - cgroup_current/high/max: cgroup v2 memory.current/memory.high/
 *     memory.max under the directory named by /proc/self/cgroup's "0::"
 *     line, -1 if cgroup v2 is unavailable or the value is "max"
 *     (unlimited).
 *   - sys_total_bytes / sys_avail_bytes: MemTotal / MemAvailable from
 *     /proc/meminfo (MemAvailable, not a raw MemFree, already accounts for
 *     reclaimable page cache — the correct denominator for "how much RAM
 *     can this process actually grow into").
 *   - os_proc_uptime_seconds(): system uptime (/proc/uptime) minus process
 *     start time (field 22 of /proc/self/stat, in clock ticks since boot).
 *   - os_proc_exe_path(): readlink("/proc/self/exe", ...).
 *   - os_proc_open_self_exe(): fopen("/proc/self/exe", "rb") — the magic
 *     self-referencing symlink into the kernel's exe_file reference.
 *     Reading through the returned FILE* always yields the exact bytes of
 *     the running image, even after the file at the resolved pathname has
 *     been replaced by a later deploy (the running process keeps its old
 *     inode open). Used by callers that need to hash/verify their own
 *     in-memory image against what currently sits on disk (see
 *     services/binary_staleness_service.h for the concrete consumer).
 *
 * Darwin implementation:
 *   - process memory and start time: proc_pid_rusage/proc_pidinfo; virtual
 *     size: Mach task_info; total RAM: sysctl hw.memsize.
 *   - executable path and argv: dyld and crt_externs APIs. Opening the loaded
 *     image is refused because a pathname cannot prove running-image identity.
 *   - cgroup fields and available-system-memory remain -1 (unavailable).
 *
 * FreeBSD mapping (header comments only — no FreeBSD build in this repo,
 * see docs/work/os-substrate-plan.md §2 "FreeBSD mapping"):
 *   - rss_bytes/vsize_bytes/uptime: kinfo_getproc() (libutil) returns
 *     struct kinfo_proc with ki_rssize (pages; multiply by getpagesize())
 *     and ki_size (vsize, already bytes) and ki_start (struct timeval) —
 *     no /proc parsing needed at all, which is the whole point of this
 *     shim.
 *   - cgroup_current/high/max: FreeBSD has no cgroups; always -1
 *     ("unavailable"), same sentinel this header already uses for "no
 *     limit configured".
 *   - sys_total_bytes/sys_avail_bytes: sysctl hw.physmem (total) and
 *     vm.stats.vm.v_free_count * pagesize (a rough avail analogue; FreeBSD
 *     has no direct MemAvailable equivalent).
 *   - os_proc_exe_path: sysctl({CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME,
 *     -1}, ...) — NOT a readlink, this is a real behavioral fork a FreeBSD
 *     backing must implement, not just a path string swap.
 *
 * Test seam:
 *   os_proc_mem_set_override() mirrors platform_clock_set_source() /
 *   platform_rng_set_source(): install a forced snapshot so tests can walk
 *   os_proc_mem_read() through every threshold without touching the real
 *   /proc filesystem. NULL clears the override and restores live reads.
 *   Thread safety matches the clock/rng seams: the override pointer is an
 *   atomic swap; the pointee must outlive every concurrent reader
 *   (typically static/file-scope storage in the calling test).
 */

#ifndef ZCL_PLATFORM_OS_PROC_H
#define ZCL_PLATFORM_OS_PROC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fields are -1 when unreadable or unavailable on the host. */
struct os_proc_mem {
    int64_t rss_bytes;         /* VmRSS */
    int64_t vsize_bytes;       /* VmSize */
    int64_t cgroup_current;    /* cgroup v2 memory.current, -1 if unavailable */
    int64_t cgroup_high;       /* cgroup v2 memory.high, -1 if unset/unavailable */
    int64_t cgroup_max;        /* cgroup v2 memory.max, -1 if unset/unavailable */
    int64_t sys_total_bytes;   /* /proc/meminfo MemTotal */
    int64_t sys_avail_bytes;   /* /proc/meminfo MemAvailable */
};

enum os_proc_environment {
    OS_PROC_ENVIRONMENT_UNKNOWN = 0,
    OS_PROC_ENVIRONMENT_NATIVE,
    OS_PROC_ENVIRONMENT_WSL,
    OS_PROC_ENVIRONMENT_WINE,
};

/* Classify a Linux kernel release without consulting ambient environment
 * variables. Exposed so fixtures can prove WSL recognition deterministically. */
enum os_proc_environment
os_proc_environment_classify_kernel_release(const char *release);

/* Observe the current runtime environment through the platform authority. */
enum os_proc_environment os_proc_environment_observe(void);
const char *os_proc_environment_string(enum os_proc_environment environment);

/* Fill `out` with a fresh process/host memory snapshot. Returns true if at
 * least the resident set was read; other fields are independently -1 on their own
 * failure without failing the whole call. When a test override is
 * installed, returns a copy of it and always true. */
bool os_proc_mem_read(struct os_proc_mem *out);

/* Process age in seconds: system uptime minus this process's start time.
 * -1 on any read/parse failure. */
int64_t os_proc_uptime_seconds(void);

/* Resolve this process's own executable path into `buf` (NUL-terminated,
 * with failure if it does not fit `n`). Linux: readlink /proc/self/exe. Note this is the
 * PATHNAME only — on Linux a `readlink` result whose original dentry was
 * replaced by a create-new-file-at-same-name deploy gets a trailing
 * " (deleted)" suffix from the kernel; callers that need the real
 * pathname back (e.g. to `stat()`/`fopen()` it) must strip that suffix
 * themselves. */
bool os_proc_exe_path(char *buf, size_t n);

/* Resolve the executable image of a live process. Windows holds a process
 * HANDLE while querying its UTF-16 image path, avoiding PID/path races during
 * the query. POSIX uses the platform's process-image authority. */
bool os_proc_pid_exe_path(uint64_t pid, char *buf, size_t n);

/* Open the exact executable image for reading. Linux holds the running inode
 * via /proc/self/exe. Platforms without an identity-bound running-image
 * primitive fail with ENOTSUP. Caller owns a successful FILE*. */
FILE *os_proc_open_self_exe(void);

/* True iff this process's command line contains `token` as a WHOLE argument
 * (exact match, never a substring). */
bool os_proc_cmdline_has_token(const char *token);

/* Resolve this process's cgroup v2 directory (e.g.
 * "/sys/fs/cgroup/user.slice/...") into `out`. Returns false if cgroup v2
 * is unavailable — callers should treat that as "no cgroup limits to
 * read", not a fatal error. Exposed separately from os_proc_mem_read() for
 * callers that need finer-grained cgroup stats (e.g. memory.stat's
 * anon/file/kernel/slab breakdown) than the three aggregate fields in
 * struct os_proc_mem carry. */
bool os_proc_cgroup_dir(char *out, size_t out_len);

/* Test seam: force every subsequent os_proc_mem_read() call to return a
 * copy of `forced` instead of reading /proc. NULL clears the override.
 * Intended for tests and the simulator only. `forced` is copied at install
 * time, so a stack-local struct is safe to pass. */
void os_proc_mem_set_override(const struct os_proc_mem *forced);

/* Count the descriptors this process currently has open, into `*out`.
 * Returns false when the platform cannot answer, leaving `*out` untouched;
 * a caller that cannot get a count must not treat zero as an answer.
 *
 * Exists for leak assertions: take a census either side of an operation and
 * require the two to agree. The counting descriptor itself is excluded, so
 * two censuses taken the same way are directly comparable. */
bool os_proc_open_fd_count(size_t *out);

/* ── Per-THREAD kernel work counters ─────────────────────────────────────
 *
 * The counters a liveness check needs in order to tell a thread that is
 * merely SLOW from one that is WEDGED. Every field is monotonic within a
 * thread's life; only differences between two reads of the same tid mean
 * anything, never the absolute values.
 *
 * Per-thread and never per-process on purpose: a process-wide counter stays
 * warm off whichever threads are still running, so one deadlocked thread
 * would read as healthy and the wedge detector built on it would be dead
 * code that nobody noticed.
 *
 * Linux: utime+stime, majflt and read_bytes+write_bytes from
 * /proc/self/task/<tid>/{stat,io}. Elsewhere: unavailable, and the caller
 * must treat "cannot see" as "no evidence", never as "healthy". */
struct os_proc_thread_work {
    uint64_t cpu_ticks;     /* utime + stime, clock ticks */
    uint64_t major_faults;  /* faults that needed a disk read */
    uint64_t io_bytes;      /* bytes actually issued to a block device */
};

/* This thread's OS-level thread id, or 0 where the platform has none. */
long os_proc_self_tid(void);

/* Read `tid`'s work counters. `tid` must name a thread of THIS process.
 * Returns false when the platform cannot answer, leaving `*out` zeroed.
 * Reads only kernel-generated pseudo-files: no filesystem lock, no
 * block-device I/O, so it is safe on a thread that must stay responsive
 * while the rest of the process is stuck on storage. */
bool os_proc_thread_work_read(long tid, struct os_proc_thread_work *out);

enum os_proc_liveness {
    OS_PROC_LIVENESS_UNKNOWN = 0,
    OS_PROC_LIVENESS_RUNNING,
    OS_PROC_LIVENESS_DEAD
};

/* Fail-closed process liveness. Access denial or an indeterminate platform
 * error is UNKNOWN, never proof that a process is dead. */
enum os_proc_liveness os_proc_pid_liveness(uint64_t pid);
uint64_t os_proc_current_pid(void);
/* Stable kernel process-birth token. Pair with PID to reject PID reuse. */
bool os_proc_pid_start_token(uint64_t pid, uint64_t *token);

/* Cumulative process filesystem I/O bytes suitable for progress evidence.
 * Windows uses GetProcessIoCounters transfer bytes; POSIX uses getrusage
 * block counts converted from their specified 512-byte units. */
bool os_proc_io_bytes(uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_PLATFORM_OS_PROC_H */
