/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Clean-zygote reflex runner process and its confined candidate child.
 *
 * This translation unit runs only inside the runner: a fresh exec of the
 * resident's own image with an empty environment, stdio on /dev/null and one
 * control socket. It never reads configuration, a datadir, keys or the
 * environment. See devloop_reflex_runner.h for the whole contract.
 *
 * Child ordering is the security argument, so it is spelled out:
 *   1. parent-death signal + parent identity check
 *   2. close every descriptor except the sealed image and the report pipe
 *      (close_range, else a full /proc/self/fd enumeration, else refuse)
 *   3. rlimits (core 0, fsize 0, nofile small, AS/cpu bounded)
 *   4. no_new_privs, open the census directory, Landlock deny-all, seccomp
 *      session deny-list, then the runner/leaf layers (io_uring, pidfd,
 *      userfaultfd, kcmp, process_madvise, kill family, setsid/setpgid) —
 *      no W^X yet; census every remaining descriptor, close the directory
 *   5. re-hash the sealed image and compare
 *   6. write the PRE-LOAD frame; map nothing if any claim in it failed
 *   7. map it through /proc/self/fd/N (constructors run HERE, confined)
 *   8. second seccomp layer: PROT_EXEC mmap/mprotect denied (W^X)
 *   9. run the story / frozen KAT, write the OBSERVATION frame, _exit
 * The runner reads both frames, kills the leaf at its deadline (also when it
 * closed its pipe but will not exit), reads the exited leaf's seccomp layer
 * count, and reaps it.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* pipe2, SO_PEERCRED/struct ucred, MSG_CMSG_CLOEXEC */
#endif

#include "devloop_reflex_runner_wire.h"

#include "base/hex.h"
#include "command/native_dev_hotswap.h"
#include "crypto/sha256.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include "platform/os_proc.h"
#include "platform/os_sandbox.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/* Generic-table numbers (identical on every Linux arch) for libc headers that
 * predate them, so the deny layer can never silently omit io_uring or pidfd
 * and the startup probe always tests the real syscall. */
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif
#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif
#ifndef SYS_io_uring_register
#define SYS_io_uring_register 427
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#endif


/* ── leaf report frames (pure; every host) ─────────────────────────────── */

static enum zcl_reflex_frames_status frames_set(
    struct zcl_reflex_frames *out, enum zcl_reflex_frames_status status)
{
    out->status = (uint32_t)status;
    return status;
}

/* Checks one frame head at `p` (with `left` bytes remaining) for an exact,
 * known, complete frame and returns its kind through *kind. */
static enum zcl_reflex_frames_status frame_check(const uint8_t *p, size_t left,
                                                 uint32_t *kind)
{
    struct zcl_reflex_report_head head;
    if (left < sizeof(head)) return ZCL_REFLEX_FRAMES_TRUNCATED;
    memcpy(&head, p, sizeof(head));
    if (head.magic != ZCL_REFLEX_REPORT_MAGIC) return ZCL_REFLEX_FRAMES_BAD_MAGIC;
    if (head.abi != ZCL_REFLEX_WIRE_ABI) return ZCL_REFLEX_FRAMES_BAD_ABI;
    size_t want = 0;
    if (head.kind == ZCL_REFLEX_REPORT_PRELOAD)
        want = sizeof(struct zcl_reflex_preload_frame);
    else if (head.kind == ZCL_REFLEX_REPORT_OBSERVATION)
        want = sizeof(struct zcl_reflex_observation_frame);
    else
        return ZCL_REFLEX_FRAMES_UNKNOWN_KIND;
    if (head.size != want) return ZCL_REFLEX_FRAMES_WRONG_SIZE;
    if (left < want) return ZCL_REFLEX_FRAMES_TRUNCATED;
    *kind = head.kind;
    return ZCL_REFLEX_FRAMES_OK;
}

/* Bytes after the observation frame: a further well-formed frame head is a
 * duplicate; anything else is trailing garbage. */
static enum zcl_reflex_frames_status frames_tail(const uint8_t *p, size_t left)
{
    struct zcl_reflex_report_head head;
    if (left < sizeof(head)) return ZCL_REFLEX_FRAMES_TRAILING;
    memcpy(&head, p, sizeof(head));
    bool known = head.kind == ZCL_REFLEX_REPORT_PRELOAD ||
        head.kind == ZCL_REFLEX_REPORT_OBSERVATION;
    return head.magic == ZCL_REFLEX_REPORT_MAGIC &&
            head.abi == ZCL_REFLEX_WIRE_ABI && known
        ? ZCL_REFLEX_FRAMES_DUPLICATE : ZCL_REFLEX_FRAMES_TRAILING;
}

enum zcl_reflex_frames_status zcl_reflex_frames_parse(
    const uint8_t *bytes, size_t len, struct zcl_reflex_frames *out)
{
    memset(out, 0, sizeof(*out));
    if (len == 0 || !bytes)
        return frames_set(out, ZCL_REFLEX_FRAMES_PRELOAD_MISSING);
    uint32_t kind = 0;
    enum zcl_reflex_frames_status status = frame_check(bytes, len, &kind);
    if (status != ZCL_REFLEX_FRAMES_OK) return frames_set(out, status);
    if (kind != ZCL_REFLEX_REPORT_PRELOAD)
        return frames_set(out, ZCL_REFLEX_FRAMES_OUT_OF_ORDER);
    memcpy(&out->preload, bytes, sizeof(out->preload));
    out->preload_present = true;
    size_t off = sizeof(out->preload);
    if (off == len)
        return frames_set(out, ZCL_REFLEX_FRAMES_OBSERVATION_MISSING);
    status = frame_check(bytes + off, len - off, &kind);
    if (status != ZCL_REFLEX_FRAMES_OK) return frames_set(out, status);
    if (kind != ZCL_REFLEX_REPORT_OBSERVATION)
        return frames_set(out, ZCL_REFLEX_FRAMES_DUPLICATE);
    memcpy(&out->observation, bytes + off, sizeof(out->observation));
    out->observation_present = true;
    off += sizeof(out->observation);
    if (off == len) return frames_set(out, ZCL_REFLEX_FRAMES_OK);
    return frames_set(out, frames_tail(bytes + off, len - off));
}

const char *zcl_reflex_frames_reason(enum zcl_reflex_frames_status status)
{
    static const char *const reasons[] = {
        [ZCL_REFLEX_FRAMES_OK] = "",
        [ZCL_REFLEX_FRAMES_PRELOAD_MISSING] = "leaf report: pre-load frame missing",
        [ZCL_REFLEX_FRAMES_OBSERVATION_MISSING] =
            "leaf report: observation frame missing",
        [ZCL_REFLEX_FRAMES_TRUNCATED] = "leaf report: frame truncated",
        [ZCL_REFLEX_FRAMES_BAD_MAGIC] = "leaf report: frame magic wrong",
        [ZCL_REFLEX_FRAMES_BAD_ABI] = "leaf report: frame ABI wrong",
        [ZCL_REFLEX_FRAMES_UNKNOWN_KIND] = "leaf report: unknown frame kind",
        [ZCL_REFLEX_FRAMES_WRONG_SIZE] = "leaf report: frame size wrong",
        [ZCL_REFLEX_FRAMES_OUT_OF_ORDER] =
            "leaf report: observation frame before pre-load frame",
        [ZCL_REFLEX_FRAMES_DUPLICATE] = "leaf report: duplicated frame",
        [ZCL_REFLEX_FRAMES_TRAILING] = "leaf report: trailing bytes",
    };
    if ((size_t)status >= sizeof(reasons) / sizeof(reasons[0]))
        return "leaf report: unknown frames status";
    return reasons[status];
}

/* ── report field validation (before any use) ──────────────────────────── */

static bool text_terminated(const char *s, size_t cap)
{
    return memchr(s, '\0', cap) != NULL;
}

static bool lower_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Exactly 64 lowercase hex digits then NUL, or (when allowed) empty. */
static bool digest_field_ok(const char *s, size_t cap, bool allow_empty)
{
    if (cap < 65 || !text_terminated(s, cap)) return false;
    if (s[0] == '\0') return allow_empty;
    for (size_t i = 0; i < 64; i++)
        if (!lower_hex_digit(s[i])) return false;
    return s[64] == '\0';
}

static bool flag_byte_ok(const void *base, size_t offset)
{
    unsigned char byte;
    memcpy(&byte, (const unsigned char *)base + offset, 1);
    return byte <= 1u;
}

const char *zcl_reflex_preload_invalid(const struct zcl_reflex_preload_frame *f)
{
    if (!f) return "pre-load frame absent";
    if (f->hash_verified > 1u) return "pre-load hash_verified flag malformed";
    if (f->sandboxed > 1u) return "pre-load sandboxed flag malformed";
    if (!digest_field_ok(f->runtime_module_sha256,
                         sizeof(f->runtime_module_sha256),
                         f->hash_verified == 0u))
        return "pre-load runtime_module_sha256 is not 64 lowercase hex";
    if (!text_terminated(f->stage, sizeof(f->stage)))
        return "pre-load stage unterminated";
    if (!text_terminated(f->error, sizeof(f->error)))
        return "pre-load error unterminated";
    return NULL;
}

struct reflex_flag_field {
    size_t offset;
    const char *why;
};

#define REFLEX_SERVICE_FLAG(name) \
    {offsetof(struct zcl_hotswap_service_report, name), \
     "observation service." #name " flag malformed"}

static const struct reflex_flag_field g_service_flags[] = {
    REFLEX_SERVICE_FLAG(recognized), REFLEX_SERVICE_FLAG(ok),
    REFLEX_SERVICE_FLAG(verify_only), REFLEX_SERVICE_FLAG(activated),
    REFLEX_SERVICE_FLAG(probed), REFLEX_SERVICE_FLAG(rolled_back),
    REFLEX_SERVICE_FLAG(dev_restart),
};

#undef REFLEX_SERVICE_FLAG

static const char *observation_service_invalid(
    const struct zcl_hotswap_service_report *s)
{
    for (size_t i = 0; i < sizeof(g_service_flags) / sizeof(g_service_flags[0]);
         i++)
        if (!flag_byte_ok(s, g_service_flags[i].offset))
            return g_service_flags[i].why;
    if (!text_terminated(s->service_id, sizeof(s->service_id)))
        return "observation service.service_id unterminated";
    if (!digest_field_ok(s->loaded_image_sha256,
                         sizeof(s->loaded_image_sha256), true))
        return "observation service.loaded_image_sha256 is not 64 lowercase hex";
    if (!digest_field_ok(s->loaded_image_sha3_256,
                         sizeof(s->loaded_image_sha3_256), true))
        return "observation service.loaded_image_sha3_256 is not 64 lowercase "
               "hex";
    if (!text_terminated(s->stage, sizeof(s->stage)))
        return "observation service.stage unterminated";
    if (!text_terminated(s->error, sizeof(s->error)))
        return "observation service.error unterminated";
    return NULL;
}

const char *zcl_reflex_observation_invalid(
    const struct zcl_reflex_observation_frame *f)
{
    if (!f) return "observation frame absent";
    if (f->story_ok > 1u) return "observation story_ok flag malformed";
    if (f->descriptor_valid > 1u)
        return "observation descriptor_valid flag malformed";
    if (f->candidate_executed > 1u)
        return "observation candidate_executed flag malformed";
    if (!text_terminated(f->stage, sizeof(f->stage)))
        return "observation stage unterminated";
    if (!text_terminated(f->error, sizeof(f->error)))
        return "observation error unterminated";
    if (!text_terminated(f->observation.exercised_surface,
                         sizeof(f->observation.exercised_surface)))
        return "observation observation.exercised_surface unterminated";
    if (!text_terminated(f->observation.detail,
                         sizeof(f->observation.detail)))
        return "observation observation.detail unterminated";
    return observation_service_invalid(&f->service);
}

#if defined(__linux__)

extern char **environ;

uint32_t zcl_reflex_env_count(void)
{
    uint32_t count = 0;
    for (char **e = environ; e && *e; e++)
        count++;
    return count;
}

bool zcl_reflex_sha256_fd(int fd, char out[65])
{
    if (fd < 0 || !out || lseek(fd, 0, SEEK_SET) < 0) return false;
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    unsigned char buf[64 * 1024];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) { sha256_write(&ctx, buf, (size_t)n); continue; }
        if (n == 0) break;
        if (errno != EINTR) return false;
    }
    unsigned char digest[SHA256_OUTPUT_SIZE];
    sha256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof(digest), out);
    return lseek(fd, 0, SEEK_SET) == 0;
}

/* ── descriptor hygiene ─────────────────────────────────────────────────── */

/* The fd directory comes from platform/os_proc.h (one open(2), safe between
 * fork and exec); a test may point it elsewhere to make it unavailable. */
#if defined(ZCL_TESTING)
static bool g_close_range_enabled = true;
static const char *g_fd_dir_override;

void zcl_reflex_testing_use_close_range(bool enabled)
{
    g_close_range_enabled = enabled;
}

void zcl_reflex_testing_set_fd_dir(const char *path)
{
    g_fd_dir_override = path;
}

static bool reflex_close_range_enabled(void) { return g_close_range_enabled; }

static int reflex_fd_dir_open(void)
{
    if (g_fd_dir_override)
        return open(g_fd_dir_override, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return os_proc_fd_dir_open();
}
#else
static bool reflex_close_range_enabled(void) { return true; }
static int reflex_fd_dir_open(void) { return os_proc_fd_dir_open(); }
#endif

static bool fd_kept(int fd, const int *keep, size_t keep_count)
{
    for (size_t i = 0; i < keep_count; i++)
        if (keep[i] == fd) return true;
    return false;
}

/* Kernel linux_dirent64 layout (getdents64(2)); glibc's struct is not used
 * so the walk needs no allocation and no libc directory stream. */
struct reflex_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

static bool fd_name_parse(const char *name, int *fd_out)
{
    long value = 0;
    if (!name[0]) return false;
    for (const char *p = name; *p; p++) {
        if (*p < '0' || *p > '9' || value > (INT_MAX - 9) / 10) return false;
        value = value * 10 + (*p - '0');
    }
    *fd_out = (int)value;
    return true;
}

/* Handles one getdents64 batch: each listed descriptor other than `dir_fd`
 * and the kept set is closed (when `close_them`) and counted. */
static long fd_batch(const unsigned char *buf, long len, int dir_fd,
                     const int *keep, size_t keep_count, bool close_them)
{
    long handled = 0;
    for (long off = 0; off < len;) {
        const struct reflex_dirent64 *d =
            (const struct reflex_dirent64 *)(const void *)(buf + off);
        if (d->d_reclen == 0) return -1;
        off += d->d_reclen;
        int fd = -1;
        if (!fd_name_parse(d->d_name, &fd) || fd == dir_fd ||
            fd_kept(fd, keep, keep_count))
            continue;
        if (close_them) (void)close(fd);
        handled++;
    }
    return handled;
}

/* One full pass over an open fd directory from its start. Returns the number
 * of descriptors handled, or -1 when the directory cannot be read. Uses only
 * async-signal-safe syscalls (it runs between fork and exec). */
static long fd_dir_pass(int dir_fd, const int *keep, size_t keep_count,
                        bool close_them)
{
    alignas(8) unsigned char buf[4096];
    long handled = 0;
    if (lseek(dir_fd, 0, SEEK_SET) != 0) return -1;
    for (;;) {
        long n = syscall(SYS_getdents64, dir_fd, buf, sizeof(buf));
        if (n == 0) return handled;
        if (n < 0 && errno == EINTR) continue;
        long batch = n < 0 ? -1
            : fd_batch(buf, n, dir_fd, keep, keep_count, close_them);
        if (batch < 0) return -1;
        handled += batch;
    }
}

uint32_t zcl_reflex_count_fds_in(int dir_fd, const int *keep,
                                 size_t keep_count)
{
    long counted = dir_fd >= 0
        ? fd_dir_pass(dir_fd, keep, keep_count, false) : -1;
    return counted < 0 || counted >= (long)UINT32_MAX ? UINT32_MAX
                                                      : (uint32_t)counted;
}

uint32_t zcl_reflex_count_fds_except(const int *keep, size_t keep_count)
{
    int dir_fd = reflex_fd_dir_open();
    uint32_t counted = zcl_reflex_count_fds_in(dir_fd, keep, keep_count);
    if (dir_fd >= 0) (void)close(dir_fd);
    return counted;
}

/* close_range over every gap between the sorted kept descriptors. False
 * when the kernel (or the test seam) has no close_range. */
static bool close_spans_by_range(const int *sorted, size_t count)
{
#ifdef SYS_close_range
    if (!reflex_close_range_enabled()) return false;
    unsigned lo = 0;
    for (size_t i = 0; i < count; i++) {
        unsigned kept = (unsigned)sorted[i];
        if (kept > lo && syscall(SYS_close_range, lo, kept - 1u, 0) != 0)
            return false;
        lo = kept + 1u;
    }
    return syscall(SYS_close_range, lo, ~0u, 0) == 0;
#else
    (void)sorted;
    (void)count;
    return false;
#endif
}

/* Enumerate the fd directory and close every non-kept descriptor, repeating
 * until a pass finds nothing left. The directory descriptor is skipped while
 * walking and closed last. False when enumeration is impossible. */
static bool close_by_enumeration(const int *keep, size_t keep_count)
{
    int dir_fd = reflex_fd_dir_open();
    if (dir_fd < 0) return false;
    bool clean = false;
    for (int pass = 0; pass < 4 && !clean; pass++) {
        long closed = fd_dir_pass(dir_fd, keep, keep_count, true);
        if (closed < 0) break;
        clean = closed == 0;
    }
    (void)close(dir_fd);
    return clean;
}

/* Sorts `keep` into `sorted` (ascending) for close_spans_by_range and rejects
 * an unusable list. Shared by every close_all_except variant. */
static bool close_keep_sorted(const int *keep, size_t keep_count,
                              int sorted[8])
{
    if (!keep || keep_count == 0 || keep_count > 8) return false;
    memcpy(sorted, keep, keep_count * sizeof(int));
    for (size_t i = 1; i < keep_count; i++)
        for (size_t j = i; j > 0 && sorted[j - 1] > sorted[j]; j--) {
            int t = sorted[j]; sorted[j] = sorted[j - 1]; sorted[j - 1] = t;
        }
    return sorted[0] >= 0;
}

bool zcl_reflex_close_all_except(const int *keep, size_t keep_count)
{
    int sorted[8];
    if (!close_keep_sorted(keep, keep_count, sorted)) return false;
    return close_spans_by_range(sorted, keep_count) ||
        close_by_enumeration(sorted, keep_count);
}

bool zcl_reflex_close_all_except_via(int dir_fd, const int *keep,
                                     size_t keep_count)
{
    int sorted[8];
    if (!close_keep_sorted(keep, keep_count, sorted)) return false;
    if (close_spans_by_range(sorted, keep_count)) return true;
    if (dir_fd < 0) return false;
    bool clean = false;
    for (int pass = 0; pass < 4 && !clean; pass++) {
        long closed = fd_dir_pass(dir_fd, sorted, keep_count, true);
        if (closed < 0) break;
        clean = closed == 0;
    }
    return clean;
}

static bool write_all(int fd, const void *data, size_t len)
{
    const unsigned char *p = data;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n > 0) { p += n; len -= (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

/* ── confined child ─────────────────────────────────────────────────────── */

struct child_ctx {
    const struct zcl_reflex_request *request;
    struct zcl_reflex_observation_frame *obs;
    int64_t load_started_us;
    int64_t story_started_us;
};

/* Both frames carry stage[32] + error[160]; the first error wins. */
static void child_note(char stage[static 32], char error[static 160],
                       const char *at, const char *why)
{
    (void)snprintf(stage, 32, "%s", at);
    if (why && !error[0]) (void)snprintf(error, 160, "%s", why);
}

static bool child_rlimits(uint32_t timeout_ms)
{
    struct os_sandbox_rlimits lim = {
        .as_bytes = UINT64_C(4) << 30,
        .cpu_seconds = (uint64_t)timeout_ms / 1000u + 2u,
        .nproc = OS_SANDBOX_RLIMIT_KEEP,
        .fsize_bytes = 0,
        .nofile = 16,
        .core_bytes = 0,
    };
    return os_sandbox_set_rlimits(&lim).ok;
}

/* Kernel surfaces the shared session deny-set does not name. The runner
 * installs this layer before it serves anything (fail-closed), and every
 * candidate child inherits it across fork. io_uring executes socket, connect
 * and openat as ring operations that never pass through the seccomp syscall
 * filter, so a ring would reopen the network the session set closes.
 * pidfd_open/pidfd_getfd/kcmp/process_madvise and ptrace/process_vm_* reach
 * into other processes; userfaultfd is an exploitation primitive. The runner
 * itself uses none of them. */
static const int g_runner_denied[] = {
#ifdef SYS_io_uring_setup
    SYS_io_uring_setup,
#endif
#ifdef SYS_io_uring_enter
    SYS_io_uring_enter,
#endif
#ifdef SYS_io_uring_register
    SYS_io_uring_register,
#endif
#ifdef SYS_pidfd_open
    SYS_pidfd_open,
#endif
#ifdef SYS_pidfd_getfd
    SYS_pidfd_getfd,
#endif
#ifdef SYS_userfaultfd
    SYS_userfaultfd,
#endif
#ifdef SYS_kcmp
    SYS_kcmp,
#endif
#ifdef SYS_process_madvise
    SYS_process_madvise,
#endif
    SYS_ptrace, SYS_process_vm_readv, SYS_process_vm_writev,
};

/* The candidate leaf additionally signals nothing and never leaves its
 * session: kill/tkill/tgkill would let candidate bytes SIGKILL any same-uid
 * process (the runner, the resident, a node). The runner keeps kill() — it
 * must kill a child at the deadline — so these are leaf-only. */
static const int g_leaf_denied[] = {
#ifdef SYS_pidfd_send_signal
    SYS_pidfd_send_signal,
#endif
    SYS_kill, SYS_tkill, SYS_tgkill, SYS_rt_sigqueueinfo,
    SYS_rt_tgsigqueueinfo, SYS_setsid, SYS_setpgid,
};

/* Every candidate leaf's syscall filters: the shared session deny-set, the
 * runner layer again (already inherited; re-installing keeps the leaf
 * self-sufficient if a future runner variant ever skipped it) and the
 * leaf-only signalling layer — ZCL_REFLEX_LEAF_PRELOAD_FILTERS layers. The
 * runner's startup probes use exactly this. */
static bool child_install_filters(void)
{
    size_t denied_count = 0;
    const int *denied = os_sandbox_session_denied_syscalls(&denied_count);
    return os_sandbox_seccomp_deny(denied, denied_count, false).ok &&
        os_sandbox_seccomp_deny(g_runner_denied, sizeof(g_runner_denied) /
                                sizeof(g_runner_denied[0]), false).ok &&
        os_sandbox_seccomp_deny(g_leaf_denied, sizeof(g_leaf_denied) /
                                sizeof(g_leaf_denied[0]), false).ok;
}

/* Landlock deny-all, then close the ruleset descriptor os_sandbox retains
 * (this single-threaded child never joins threads, so the candidate must not
 * see it), then the syscall layers. `keep` holds the image, the report pipe
 * and the pre-opened census directory.
 *
 * The close walks keep[2] (the census directory), already open before
 * Landlock: close_all_except's plain enumeration fallback opens its own
 * directory, and a fresh open of /proc/self/fd here is exactly what Landlock
 * deny-all just refused, so that path would fail every leaf closed (never
 * reaching the story at all). Walking the descriptor the caller already
 * holds needs no new open. */
static bool child_enter_sandbox(struct zcl_reflex_preload_frame *pre,
                                const int keep[static 3])
{
    if (!os_sandbox_landlock_restrict(NULL, 0).ok)
        return child_note(pre->stage, pre->error, "landlock",
                          "Landlock deny-all unavailable"), false;
    if (!zcl_reflex_close_all_except_via(keep[2], keep, 3))
        return child_note(pre->stage, pre->error, "fds",
                          "ruleset close failed"), false;
    if (!child_install_filters())
        return child_note(pre->stage, pre->error, "seccomp",
                          "seccomp deny-lists unavailable"), false;
    return true;
}

/* Everything the resident may believe about the leaf's environment is
 * established here, before a candidate byte is mapped. The census directory
 * is opened before Landlock (which would refuse it later) and read after the
 * last filter, so the count is a full enumeration of the confined leaf. */
static bool child_confine(struct zcl_reflex_preload_frame *pre,
                          const struct zcl_reflex_request *request,
                          int image_fd, int report_fd, int runner_pid)
{
    const int keep[] = {image_fd, report_fd};
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != runner_pid)
        return child_note(pre->stage, pre->error, "parent",
                          "runner parent identity lost"), false;
    if (!zcl_reflex_close_all_except(keep, 2))
        return child_note(pre->stage, pre->error, "fds",
                          "descriptor close failed"), false;
    if (!child_rlimits(request->timeout_ms))
        return child_note(pre->stage, pre->error, "rlimits",
                          "rlimit lowering failed"), false;
    if (!os_sandbox_no_new_privs())
        return child_note(pre->stage, pre->error, "no_new_privs",
                          "no_new_privs failed"), false;
    int census = reflex_fd_dir_open();
    if (census < 0)
        return child_note(pre->stage, pre->error, "census",
                          "descriptor census unavailable"), false;
    const int keep3[] = {image_fd, report_fd, census};
    bool confined = child_enter_sandbox(pre, keep3);
    if (confined) {
        pre->env_count = zcl_reflex_env_count();
        pre->inherited_fd_count = zcl_reflex_count_fds_in(census, keep3, 3);
        pre->resident_canary_seen = zcl_reflex_resident_canary;
    }
    (void)close(census);
    return confined;
}

/* The leaf's own re-hash of the sealed bytes, before they are mapped. */
static bool child_prehash(struct zcl_reflex_preload_frame *pre,
                          const struct zcl_reflex_request *request,
                          int image_fd)
{
    bool ok = zcl_reflex_sha256_fd(image_fd, pre->runtime_module_sha256) &&
        strcmp(pre->runtime_module_sha256, request->expected_sha256) == 0;
    if (!ok)
        child_note(pre->stage, pre->error, "hash",
                   "sealed image digest mismatch in child");
    return ok;
}

/* Second layer, installed after the mapping exists and before any candidate
 * function runs: no new executable memory for the rest of the child's life.
 * Constructors already ran, so the runner — not this frame — decides whether
 * the layer exists, from the leaf's final seccomp layer count. */
static bool child_install_wx(struct zcl_reflex_observation_frame *obs)
{
    bool installed = os_sandbox_seccomp_deny(NULL, 0, true).ok;
    if (!installed)
        child_note(obs->stage, obs->error, "wx",
                   "W^X seccomp layer unavailable");
    return installed;
}

static bool text_eq(const char *candidate, const char *expected)
{
    return candidate && strcmp(candidate, expected) == 0;
}

static bool child_descriptor_matches(
    const struct zcl_hotfork_capsule_v1 *capsule,
    const struct zcl_reflex_request *request)
{
    return capsule && capsule->abi_version == ZCL_HOTFORK_CAPSULE_ABI_V1 &&
        capsule->descriptor_size == sizeof(*capsule) &&
        text_eq(capsule->owner_id, request->owner_id) &&
        text_eq(capsule->source_tu, request->source_tu) &&
        text_eq(capsule->candidate_object_root,
                request->candidate_object_root) &&
        text_eq(capsule->story_id, request->story_id) &&
        text_eq(capsule->story_root, request->story_root) &&
        text_eq(capsule->story_fixture_root, request->story_fixture_root) &&
        capsule->run_story;
}

static bool child_hotfork_visit(
    const struct zcl_hotfork_capsule_v1 *capsule, void *opaque)
{
    struct child_ctx *ctx = opaque;
    struct zcl_reflex_observation_frame *obs = ctx->obs;
    obs->dlopen_us = platform_time_monotonic_us() - ctx->load_started_us;
    obs->descriptor_valid = child_descriptor_matches(capsule, ctx->request);
    if (!obs->descriptor_valid)
        return child_note(obs->stage, obs->error, "descriptor",
                          "HOT_FORK descriptor binding mismatch"), false;
    if (!child_install_wx(obs)) return false;
    obs->candidate_executed = 1;
    child_note(obs->stage, obs->error, "story", NULL);
    int64_t started = platform_time_monotonic_us();
    bool ok = capsule->run_story(&obs->observation);
    obs->story_us = platform_time_monotonic_us() - started;
    obs->story_ok = ok;
    return ok;
}

static void child_run_hotfork(struct child_ctx *ctx, int image_fd)
{
    struct zcl_reflex_observation_frame *obs = ctx->obs;
    char err[160] = {0};
    char mapped[65] = {0};
    ctx->load_started_us = platform_time_monotonic_us();
    (void)zcl_hotswap_hotfork_visit_fd(
        image_fd, ctx->request->expected_sha256, child_hotfork_visit, ctx,
        mapped, err, sizeof(err));
    if (err[0]) child_note(obs->stage, obs->error, "load", err);
}

static bool child_service_loaded(void *opaque, char *why, size_t why_sz)
{
    struct child_ctx *ctx = opaque;
    struct zcl_reflex_observation_frame *obs = ctx->obs;
    obs->dlopen_us = platform_time_monotonic_us() - ctx->load_started_us;
    obs->descriptor_valid = 1;
    if (!child_install_wx(obs)) {
        (void)snprintf(why, why_sz, "%s", obs->error);
        return false;
    }
    obs->candidate_executed = 1;
    child_note(obs->stage, obs->error, "story", NULL);
    ctx->story_started_us = platform_time_monotonic_us();
    return true;
}

static void child_run_shadow(struct child_ctx *ctx, int image_fd)
{
    struct zcl_reflex_observation_frame *obs = ctx->obs;
    ctx->load_started_us = platform_time_monotonic_us();
    bool ok = zcl_native_hotswap_service_probe_fd(
        image_fd, child_service_loaded, ctx, &obs->service);
    if (ctx->story_started_us)
        obs->story_us = platform_time_monotonic_us() - ctx->story_started_us;
    const struct zcl_hotswap_service_report *svc = &obs->service;
    obs->story_ok = ok && svc->recognized && svc->ok && svc->probed &&
        svc->verify_only && !svc->activated;
    if (!obs->story_ok)
        child_note(obs->stage, obs->error, svc->stage[0] ? svc->stage : "probe",
                   svc->error[0] ? svc->error : "frozen KAT rejected");
}

static bool reflex_mode_known(uint32_t mode)
{
    return mode == ZCL_REFLEX_MODE_HOT_FORK ||
        mode == ZCL_REFLEX_MODE_HOT_SHADOW;
}

/* Frame (a): written before the candidate is mapped. Returns whether every
 * pre-load claim holds; the leaf maps nothing otherwise. */
static bool child_preload(const struct zcl_reflex_request *request,
                          int image_fd, int report_fd, int runner_pid)
{
    struct zcl_reflex_preload_frame pre = {
        .head = {.magic = ZCL_REFLEX_REPORT_MAGIC, .abi = ZCL_REFLEX_WIRE_ABI,
                 .kind = ZCL_REFLEX_REPORT_PRELOAD, .size = sizeof(pre)},
    };
    pre.start_us = platform_time_monotonic_us();
    pre.sandboxed = child_confine(&pre, request, image_fd, report_fd,
                                  runner_pid);
    pre.hash_verified = pre.sandboxed && child_prehash(&pre, request, image_fd);
    bool mode_ok = reflex_mode_known(request->mode);
    if (!mode_ok)
        child_note(pre.stage, pre.error, "mode", "unknown reflex mode");
    else if (pre.hash_verified)
        child_note(pre.stage, pre.error, "preload", NULL);
    pre.confine_us = platform_time_monotonic_us() - pre.start_us;
    if (!write_all(report_fd, &pre, sizeof(pre))) _exit(125);
    return pre.sandboxed && pre.hash_verified && mode_ok;
}

[[noreturn]] void zcl_reflex_runner_child_main(
    const struct zcl_reflex_request *request, int image_fd, int report_fd,
    int runner_pid)
{
    if (!child_preload(request, image_fd, report_fd, runner_pid)) _exit(0);
    struct zcl_reflex_observation_frame obs = {
        .head = {.magic = ZCL_REFLEX_REPORT_MAGIC, .abi = ZCL_REFLEX_WIRE_ABI,
                 .kind = ZCL_REFLEX_REPORT_OBSERVATION, .size = sizeof(obs)},
    };
    struct child_ctx ctx = {.request = request, .obs = &obs};
    if (request->mode == ZCL_REFLEX_MODE_HOT_FORK)
        child_run_hotfork(&ctx, image_fd);
    else
        child_run_shadow(&ctx, image_fd);
    _exit(write_all(report_fd, &obs, sizeof(obs)) ? 0 : 125);
}

/* ── bounded reap + seccomp layer census ────────────────────────────────── */

/* Longest single sleep while waiting for a leaf to exit: SIGCHLD normally
 * wakes the wait at once; the step only bounds a lost wakeup. */
#define REFLEX_REAP_STEP_US 5000

/* True once `child` has exited (it stays a zombie: WNOWAIT). */
static bool reflex_child_exited(pid_t child, bool block, bool *failed)
{
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    int flags = WEXITED | WNOWAIT | (block ? 0 : WNOHANG);
    int rc;
    do { rc = waitid(P_PID, (id_t)child, &info, flags); }
    while (rc < 0 && errno == EINTR);
    if (rc < 0) *failed = true;
    return rc == 0 && info.si_pid == child;
}

static void reflex_wait_sigchld(const sigset_t *chld, int64_t deadline_us)
{
    int64_t remaining = deadline_us - platform_time_monotonic_us();
    if (remaining <= 0) return;
    if (remaining > REFLEX_REAP_STEP_US) remaining = REFLEX_REAP_STEP_US;
    struct timespec ts = {.tv_sec = 0, .tv_nsec = (long)remaining * 1000L};
    (void)sigtimedwait(chld, NULL, &ts);
}

static void reflex_reap_status(pid_t child, struct zcl_reflex_reap *out)
{
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); }
    while (waited < 0 && errno == EINTR);
    out->reaped = waited == child;
    if (out->reaped && WIFEXITED(status)) out->exit_code = WEXITSTATUS(status);
    if (out->reaped && WIFSIGNALED(status)) out->signal = WTERMSIG(status);
}

void zcl_reflex_reap_bounded(pid_t child, int64_t deadline_us,
                             struct zcl_reflex_reap *out)
{
    memset(out, 0, sizeof(*out));
    out->exit_code = -1;
    sigset_t chld, old;
    (void)sigemptyset(&chld);
    (void)sigaddset(&chld, SIGCHLD);
    bool masked = pthread_sigmask(SIG_BLOCK, &chld, &old) == 0;
    bool failed = false;
    while (!reflex_child_exited(child, false, &failed) && !failed) {
        if (platform_time_monotonic_us() < deadline_us) {
            reflex_wait_sigchld(&chld, deadline_us);
            continue;
        }
        /* Past the deadline and still alive: SIGKILL cannot be caught,
         * blocked or ignored, so the blocking wait below ends. */
        (void)kill(child, SIGKILL);
        out->killed_at_deadline = true;
        (void)reflex_child_exited(child, true, &failed);
        break;
    }
    out->filters_read = !failed &&
        os_proc_seccomp_filters((uint64_t)child, &out->seccomp_filters);
    reflex_reap_status(child, out);
    if (masked) (void)pthread_sigmask(SIG_SETMASK, &old, NULL);
}

/* ── runner process ─────────────────────────────────────────────────────── */

/* The runner's own seccomp layer count after runner_enter; every leaf must
 * end with exactly this plus its pre-load layers plus the one W^X layer. */
static uint32_t g_runner_filters;

static void frame_head(struct zcl_reflex_frame_head *head, uint32_t kind,
                       uint32_t size, uint64_t sequence)
{
    head->magic = ZCL_REFLEX_WIRE_MAGIC;
    head->abi = ZCL_REFLEX_WIRE_ABI;
    head->kind = kind;
    head->size = size;
    head->sequence = sequence;
}

static bool runner_send(const void *frame, size_t len)
{
    ssize_t n;
    do {
        n = send(ZCL_REFLEX_RUNNER_CONTROL_FD, frame, len, MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);
    return n == (ssize_t)len;
}

static bool runner_peer_is_parent(void)
{
    struct ucred cred = {0};
    socklen_t cred_len = sizeof(cred);
    int type = 0;
    socklen_t type_len = sizeof(type);
    return getsockopt(ZCL_REFLEX_RUNNER_CONTROL_FD, SOL_SOCKET, SO_PEERCRED,
                      &cred, &cred_len) == 0 &&
        getsockopt(ZCL_REFLEX_RUNNER_CONTROL_FD, SOL_SOCKET, SO_TYPE, &type,
                   &type_len) == 0 &&
        type == SOCK_SEQPACKET && cred.pid > 1 && cred.pid == getppid();
}

/* Receives one datagram and at most one descriptor. Returns 1 with a frame,
 * 0 on orderly EOF, -1 on a malformed datagram (any descriptor closed). */
static int runner_recv(void *frame, size_t len, int *fd_out)
{
    union {
        struct cmsghdr align;
        char buf[CMSG_SPACE(sizeof(int))];
    } control;
    struct iovec iov = {.iov_base = frame, .iov_len = len};
    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1,
                         .msg_control = control.buf,
                         .msg_controllen = sizeof(control.buf)};
    *fd_out = -1;
    ssize_t n;
    do {
        n = recvmsg(ZCL_REFLEX_RUNNER_CONTROL_FD, &msg, MSG_CMSG_CLOEXEC);
    } while (n < 0 && errno == EINTR);
    if (n == 0) return 0;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (c && c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS &&
        c->cmsg_len == CMSG_LEN(sizeof(int)))
        memcpy(fd_out, CMSG_DATA(c), sizeof(int));
    if (n < 0 || (size_t)n != len || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        if (*fd_out >= 0) (void)close(*fd_out);
        *fd_out = -1;
        return -1;
    }
    return 1;
}

static bool request_strings_terminated(const struct zcl_reflex_request *r)
{
    return memchr(r->expected_sha256, 0, sizeof(r->expected_sha256)) &&
        memchr(r->owner_id, 0, sizeof(r->owner_id)) &&
        memchr(r->source_tu, 0, sizeof(r->source_tu)) &&
        memchr(r->candidate_object_root, 0, sizeof(r->candidate_object_root)) &&
        memchr(r->story_id, 0, sizeof(r->story_id)) &&
        memchr(r->story_root, 0, sizeof(r->story_root)) &&
        memchr(r->story_fixture_root, 0, sizeof(r->story_fixture_root));
}

static bool request_valid(const struct zcl_reflex_request *r)
{
    return r->head.magic == ZCL_REFLEX_WIRE_MAGIC &&
        r->head.abi == ZCL_REFLEX_WIRE_ABI &&
        r->head.kind == ZCL_REFLEX_FRAME_REQUEST &&
        r->head.size == sizeof(*r) &&
        reflex_mode_known(r->mode) &&
        r->timeout_ms > 0 && r->timeout_ms <= 60000u &&
        request_strings_terminated(r) && strlen(r->expected_sha256) == 64
#if defined(ZCL_TESTING)
        && (r->testing_flags & ~(uint32_t)ZCL_REFLEX_TESTING_DISABLE_CLOSE_RANGE)
            == 0
#endif
        ;
}

static void reply_error(struct zcl_reflex_reply *reply, const char *error)
{
    if (!reply->error[0])
        (void)snprintf(reply->error, sizeof(reply->error), "%s", error);
}

/* The runner's own proof of what it hands to the child: the seals that make
 * the bytes immutable are present, and the digest is the requested one. */
static bool runner_verify_image(int image_fd,
                                const struct zcl_reflex_request *request,
                                struct zcl_reflex_reply *reply)
{
    const int want = F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW;
    int seals = fcntl(image_fd, F_GET_SEALS);
    reply->seals_verified = seals >= 0 && (seals & want) == want;
    if (!reply->seals_verified)
        return reply_error(reply, "candidate image is not a sealed memfd"),
               false;
    if (!zcl_reflex_sha256_fd(image_fd, reply->runner_sha256) ||
        strcmp(reply->runner_sha256, request->expected_sha256) != 0)
        return reply_error(reply, "sealed image digest mismatch in runner"),
               false;
    return true;
}

/* Room for both frames plus one more frame head, so a duplicate is named as
 * such; anything past that is drained and dropped (the parse already fails). */
#define REFLEX_REPORT_CAP \
    (sizeof(struct zcl_reflex_preload_frame) + \
     sizeof(struct zcl_reflex_observation_frame) + \
     sizeof(struct zcl_reflex_report_head))

struct collect_state {
    int report_fd;
    int64_t deadline_us;
    size_t have;
    bool eof;
    bool control_closed;
    uint8_t bytes[REFLEX_REPORT_CAP];
};

static bool runner_collect_read(struct collect_state *st)
{
    uint8_t drain[256];
    ssize_t n = st->have < sizeof(st->bytes)
        ? read(st->report_fd, st->bytes + st->have,
               sizeof(st->bytes) - st->have)
        : read(st->report_fd, drain, sizeof(drain));
    if (n > 0 && st->have < sizeof(st->bytes)) st->have += (size_t)n;
    if (n == 0) st->eof = true;
    return n > 0 || (n < 0 && errno == EINTR);
}

/* One poll step. Returns false when collection is over. */
static bool runner_collect_step(struct collect_state *st,
                                struct zcl_reflex_reply *reply)
{
    int64_t remaining = st->deadline_us - platform_time_monotonic_us();
    if (remaining <= 0) { reply->timed_out = true; return false; }
    struct pollfd pfd[2] = {
        {.fd = st->report_fd, .events = POLLIN},
        {.fd = ZCL_REFLEX_RUNNER_CONTROL_FD, .events = POLLIN},
    };
    int wait_ms = (int)((remaining + 999) / 1000);
    int ready = poll(pfd, 2, wait_ms);
    if (ready < 0) return errno == EINTR;
    if (pfd[1].revents) {
        struct zcl_reflex_frame_head cancel;
        int fd = -1;
        int got = runner_recv(&cancel, sizeof(cancel), &fd);
        if (fd >= 0) (void)close(fd);
        st->control_closed = got == 0;
        reply->cancelled = true;
        return false;
    }
    return !pfd[0].revents || runner_collect_read(st);
}

/* What the runner itself saw of the leaf's end: exit status or signal, a
 * leaf that outlived its deadline after closing its pipe, and whether it
 * ended with exactly one seccomp layer beyond its pre-load stack (W^X). */
static void runner_record_reap(const struct zcl_reflex_reap *reap, bool eof,
                               struct zcl_reflex_reply *reply)
{
    reply->child_exit_code = reap->exit_code;
    reply->child_signal = reap->signal;
    reply->leaf_seccomp_filters = reap->seccomp_filters;
    reply->runner_seccomp_filters = g_runner_filters;
    reply->wx_observed = reap->filters_read &&
        reap->seccomp_filters == g_runner_filters +
            ZCL_REFLEX_LEAF_PRELOAD_FILTERS + ZCL_REFLEX_LEAF_WX_FILTERS;
    if (eof && reap->killed_at_deadline) {
        reply->timed_out = true;
        reply->reap_timed_out = true;
        reply_error(reply, "leaf outlived its deadline after closing its "
                           "report pipe");
    }
}

/* Fork, collect, kill at deadline, reap. Returns false only when the resident
 * closed the control socket mid-candidate (the runner then exits). */
static bool runner_execute(const struct zcl_reflex_request *request,
                           int image_fd, struct zcl_reflex_reply *reply)
{
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) != 0)
        return reply_error(reply, "report pipe unavailable"), true;
    int64_t started = platform_time_monotonic_us();
    int runner_pid = (int)getpid();
    pid_t child = fork();
    if (child == 0) {
        (void)close(pipefd[0]);
        zcl_reflex_runner_child_main(request, image_fd, pipefd[1], runner_pid);
    }
    (void)close(pipefd[1]);
    if (child < 0) {
        (void)close(pipefd[0]);
        return reply_error(reply, "candidate fork failed"), true;
    }
    struct collect_state st;
    st = (struct collect_state){
        .report_fd = pipefd[0],
        .deadline_us = started + (int64_t)request->timeout_ms * 1000,
    };
    while (!st.eof && runner_collect_step(&st, reply)) {}
    (void)close(pipefd[0]);
    /* The whole leaf lives within one deadline: after EOF it must still exit
     * by it; after a timeout or a cancel it is killed now. */
    struct zcl_reflex_reap reap;
    zcl_reflex_reap_bounded(child, st.eof ? st.deadline_us : 0, &reap);
    runner_record_reap(&reap, st.eof, reply);
    (void)zcl_reflex_frames_parse(st.bytes, st.have, &reply->frames);
    if (reply->frames.preload_present &&
        reply->frames.preload.start_us >= started)
        reply->fork_us = reply->frames.preload.start_us - started;
    reply->total_us = platform_time_monotonic_us() - started;
    return !st.control_closed;
}

/* One request/reply turn. Returns false when the runner should exit. */
static bool runner_serve_one(void)
{
    struct zcl_reflex_request request;
    int image_fd = -1;
    int got = runner_recv(&request, sizeof(request), &image_fd);
    if (got == 0) return false;
    struct zcl_reflex_reply reply;
    reply = (struct zcl_reflex_reply){0};
    frame_head(&reply.head, ZCL_REFLEX_FRAME_REPLY, sizeof(reply),
               got > 0 ? request.head.sequence : 0);
    reply.child_exit_code = -1;
    reply.frames.status = ZCL_REFLEX_FRAMES_PRELOAD_MISSING;
    bool keep_running = true;
    if (got < 0 || image_fd < 0 || !request_valid(&request))
        reply_error(&reply, "malformed reflex request");
    else if (runner_verify_image(image_fd, &request, &reply)) {
#if defined(ZCL_TESTING)
        /* Reset every request: a warm runner serves many candidates, and a
         * flag not carried by THIS request must not linger from the last
         * one. */
        zcl_reflex_testing_use_close_range(
            !(request.testing_flags & ZCL_REFLEX_TESTING_DISABLE_CLOSE_RANGE));
#endif
        keep_running = runner_execute(&request, image_fd, &reply);
    }
    if (image_fd >= 0) (void)close(image_fd);
    return runner_send(&reply, sizeof(reply)) && keep_running;
}

static bool runner_enter(void)
{
    const int keep[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                        ZCL_REFLEX_RUNNER_CONTROL_FD};
    struct sigaction ignore = {.sa_handler = SIG_IGN};
    /* An inherited SIG_IGN on SIGCHLD auto-reaps children (POSIX), which
     * would silently swallow every leaf exit this runner needs to wait for
     * and read the status of. Reset to SIG_DFL before anything forks. */
    struct sigaction dfl = {.sa_handler = SIG_DFL};
    return prctl(PR_SET_PDEATHSIG, SIGKILL) == 0 && runner_peer_is_parent() &&
        os_sandbox_no_new_privs() && zcl_reflex_close_all_except(keep, 4) &&
        chdir("/") == 0 && sigaction(SIGPIPE, &ignore, NULL) == 0 &&
        sigaction(SIGCHLD, &dfl, NULL) == 0 &&
        os_sandbox_seccomp_deny(g_runner_denied, sizeof(g_runner_denied) /
                                sizeof(g_runner_denied[0]), false).ok;
}

/* Before serving, prove the leaf filters bite on THIS kernel: one disposable
 * child per surface enters exactly the candidate filter stack and makes the
 * call. Only death by SIGSYS counts; a runner whose filters let any probe
 * through refuses to say hello, so the resident reports the runner
 * unavailable instead of running candidates behind a hollow filter. */
[[noreturn]] static void runner_probe_child(unsigned which)
{
    unsigned char params[120] = {0}; /* struct io_uring_params, zeroed */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || !child_install_filters())
        _exit(2);
    if (which == 0) (void)syscall(SYS_io_uring_setup, 8u, params);
    else if (which == 1) (void)syscall(SYS_pidfd_open, getppid(), 0u);
    else (void)kill(getppid(), 0);
    _exit(0);
}

static uint32_t runner_deny_probes(void)
{
    uint32_t killed = 0;
    for (unsigned which = 0; which < ZCL_REFLEX_DENY_PROBES; which++) {
        pid_t child = fork();
        if (child == 0) runner_probe_child(which);
        int status = 0;
        pid_t waited = -1;
        if (child > 0)
            do { waited = waitpid(child, &status, 0); }
            while (waited < 0 && errno == EINTR);
        if (waited == child && WIFSIGNALED(status) &&
            WTERMSIG(status) == SIGSYS)
            killed++;
    }
    return killed;
}

static int runner_main(void)
{
    if (!runner_enter()) return 3;
    uint32_t probes_killed = runner_deny_probes();
    if (probes_killed != ZCL_REFLEX_DENY_PROBES) return 5;
    /* Without its own layer count the runner cannot observe a leaf's W^X
     * layer, so every verdict would be unprovable: refuse to serve. */
    if (!os_proc_seccomp_filters(0, &g_runner_filters)) return 6;
    const int keep[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                        ZCL_REFLEX_RUNNER_CONTROL_FD};
    struct zcl_reflex_hello hello = {
        .pid = (int32_t)getpid(),
        .env_count = zcl_reflex_env_count(),
        .fd_count = zcl_reflex_count_fds_except(keep, 4),
        .resident_canary_seen = zcl_reflex_resident_canary,
        .deny_probes_killed = probes_killed,
    };
    frame_head(&hello.head, ZCL_REFLEX_FRAME_HELLO, sizeof(hello), 0);
    if (!runner_send(&hello, sizeof(hello))) return 4;
    while (runner_serve_one()) {}
    return 0;
}

#endif /* __linux__ */

bool zcl_reflex_runner_dispatch(int argc, char **argv, int *rc)
{
    if (argc != 2 || !argv || !argv[1] ||
        strcmp(argv[1], ZCL_REFLEX_RUNNER_ARGV1) != 0 || !rc)
        return false;
#if defined(__linux__)
    *rc = runner_main();
#else
    *rc = 2;
#endif
    return true;
}

void zcl_reflex_runner_exit_if_requested(int argc, char **argv)
{
    int rc = 0;
    if (zcl_reflex_runner_dispatch(argc, argv, &rc))
        exit(rc);
}
