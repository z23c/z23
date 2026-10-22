/* Copyright 2026 Rhett Creighton - Apache 2.0 */
/*
 * Confined native run: a pinned, hash-checked image executed through
 * resident_launch_spawn_confined under the profile the manifest translator
 * builds. Proves (Linux with Landlock+seccomp): a path outside the manifest
 * is EACCES while the unconfined control opens it (red twin), an allowed read
 * and write succeed, exit 7 is observed as 7, a forbidden syscall is a SIGSYS
 * kill, the unavailable-sandbox refusal is named, and a CPU-bound loop pays
 * at most 5% + 20 ms of child CPU time for confinement (median of 3). Without Landlock the named
 * refusal is asserted and the behavioural pairs print a SKIP reason.
 *
 * Hardening pairs (review of the first confined runner): an inherited
 * non-CLOEXEC descriptor is EBADF in the child; a hung pre-exec child returns
 * a typed timeout and is killed and reaped; marker-then-EOF never claims a
 * completed exec; the unconfined handshake keeps its original semantics; the
 * default manifest is finitely limited; bounded threads are allowed, child
 * processes and session detachment are denied, and no detached descendant
 * survives; a symlinked or swapped grant is refused or
 * bound to its exact object; a PT_INTERP image is refused.
 *
 * RCR_LEGACY_BASELINE compiles only the subset that links against the
 * pre-hardening API, so the same pairs can be run against the old source to
 * show them FAIL there.
 */
#include "test/test_core.h"

#include "base/hex.h"
#include "platform/os_sandbox.h"
#include "platform/positioned_file.h"
#include "platform/resident_launch.h"
#include "platform/time_compat.h"
#include "services/package_resident_manifest.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__linux__)
#include <elf.h>
#endif

#if !defined(_WIN32)
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define RCR_CHECK(name, expr) do {                                        \
    printf("resident_confined_run: %s... ", (name));                      \
    fflush(stdout);                                                       \
    if (expr) printf("OK\n");                                             \
    else { printf("FAIL\n"); failures++; }                                \
} while (0)

#define RCR_FIXTURE "build/fixtures/rcc_child"
#define RCR_FIXTURE_DYN "build/fixtures/rcc_child_dyn"

#ifdef RCR_PRE_ROUND4 /* red runs against the previous commit production code */
enum { RESIDENT_EXEC_CONFIRM_UNAVAILABLE = 99 };
#endif

#ifdef RCR_PRE_ROUND2 /* red runs against the previous commit production code */
#define RCR_V2_PROFILE(c) true
#else
#define RCR_V2_PROFILE(c) ((c).profile.seccomp_clone_threads_only && (c).profile.n_enosys == 1)
#endif

#ifdef RCR_LEGACY_BASELINE
enum {
    RESIDENT_EXEC_NONE = 0, RESIDENT_EXEC_ARMED_UNCERTAIN, RESIDENT_EXEC_CONFIRMED,
    RESIDENT_EXEC_FAILED, RESIDENT_EXEC_SANDBOX_FAILED, RESIDENT_EXEC_CHILD_DIED,
    RESIDENT_EXEC_STATUS_ERROR, RESIDENT_EXEC_TIMEOUT
};
#define RCR_SET_DEADLINE(l, ns) ((void)(ns))
#define RCR_SET_FAULTS(l, s, d) ((void)(s), (void)(d))
#define RCR_SET_FAILTRACE(l, v) ((void)(v))
#define RCR_STATE(l) 0
#define RCR_EXECERR(l) 0
#define RCR_RELEASE(c) ((void)0)
#define RCR_BOUND(c, i) true
#define RCR_UNBIND(r) ((void)0)
#else
#define RCR_SET_DEADLINE(l, ns) ((l).spawn_deadline_ns = (ns))
#define RCR_SET_FAULTS(l, s, d) \
    ((l).debug_stall_before_marker_ms = (s), (l).debug_die_after_marker = (d))
#ifdef RCR_PRE_ROUND4
#define RCR_SET_FAILTRACE(l, v) ((void)(v))
#else
#define RCR_SET_FAILTRACE(l, v) ((l).debug_fail_traceme = (v))
#endif
#define RCR_STATE(l) ((int)(l).exec_state)
#define RCR_EXECERR(l) ((l).exec_errno)
#define RCR_RELEASE(c) package_resident_confinement_release(&(c))
#define RCR_BOUND(c, i) ((c).profile.fs_rules[(i)].has_fd)
#define RCR_UNBIND(r) ((r).has_fd = false)
#endif

#if defined(_WIN32)
int test_resident_confined_run(void)
{
    printf("resident_confined_run: SKIP: Windows has no descriptor-bound exec\n");
    return 0;
}
#else

static bool rcr_accept_of(const char *path, struct resident_launch_accepted *a)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot snap;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &snap)) {
        platform_positioned_file_close(&file);
        return false;
    }
    struct sha3_256_ctx ctx;
    unsigned char chunk[4096], digest[32];
    uint64_t offset = 0;
    sha3_256_init(&ctx);
    for (;;) {
        int64_t got = platform_positioned_file_read(&file, chunk, sizeof(chunk), offset);
        if (got < 0) { platform_positioned_file_close(&file); return false; }
        if (got == 0) break;
        sha3_256_write(&ctx, chunk, (size_t)got);
        offset += (uint64_t)got;
    }
    sha3_256_finalize(&ctx, digest);
    platform_positioned_file_close(&file);
    zcl_hex_encode(digest, sizeof(digest), a->image_sha3_hex);
    a->image_volume = snap.volume;
    a->image_low = snap.file_low;
    a->image_high = snap.file_high;
    a->image_size = snap.size;
    return true;
}

struct rcr_outcome {
    bool spawned;
    bool exited;
    int code;
    int signal;
    double wall_ms;
    double cpu_ms; /* child user+sys from wait4: immune to scheduler contention */
    double spawn_ms;
    int state, exec_errno, spawn_errno;
    uint64_t pid;
    char proof[24];
    char error[RESIDENT_LAUNCH_ERROR_MAX];
};

/* Everything a run can vary. manifest == NULL is the unconfined control. */
struct rcr_opts {
    const struct package_resident_manifest *manifest;
    uint32_t stall_ms, deadline_ms, reproof_delay_ms;
    bool die_after_marker, fail_traceme;
    bool fail_reproof_hash, fail_clock, no_close_range;
    void (*tweak)(struct package_resident_confinement *conf, void *ctx);
    void (*pre_spawn)(void *ctx);
    void *ctx;
};

static double rcr_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static double rcr_tv_ms(const struct timeval *tv)
{
    return (double)tv->tv_sec * 1000.0 + (double)tv->tv_usec / 1000.0;
}

static uint64_t rcr_mono_ns(void)
{
    return (uint64_t)platform_time_monotonic_us() * UINT64_C(1000);
}

static bool rcr_spawn(struct resident_launch *launch, const struct rcr_opts *o,
                      char *const argv[], char *const envp[],
                      struct resident_receipt *receipt, struct rcr_outcome *out,
                      const char *image)
{
    struct package_resident_confinement conf;
    if (!o->manifest)
        return resident_launch_spawn(launch, argv, envp, receipt, out->error,
                                     sizeof(out->error));
    struct zcl_result built = package_resident_manifest_profile(o->manifest, image, &conf);
    if (!built.ok) {
        (void)snprintf(out->error, sizeof(out->error), "%s", built.message);
        return false;
    }
    if (o->tweak) o->tweak(&conf, o->ctx);
    if (o->pre_spawn) o->pre_spawn(o->ctx);
    RCR_SET_FAULTS(*launch, o->stall_ms, o->die_after_marker);
    RCR_SET_FAILTRACE(*launch, o->fail_traceme);
    launch->debug_fail_reproof_hash = o->fail_reproof_hash;
    launch->debug_fail_clock = o->fail_clock;
    launch->debug_no_close_range = o->no_close_range;
    launch->debug_reproof_delay_ms = o->reproof_delay_ms;
    if (o->deadline_ms)
        RCR_SET_DEADLINE(*launch, rcr_mono_ns() + (uint64_t)o->deadline_ms * UINT64_C(1000000));
    bool ok = resident_launch_spawn_confined(launch, argv, envp, &conf.profile,
        receipt, out->error, sizeof(out->error));
    RCR_RELEASE(conf);
    return ok;
}

static struct rcr_outcome rcr_run_opts(const char *image, const struct rcr_opts *o,
                                       const char *verb, const char *arg)
{
    struct rcr_outcome out = {0};
    struct resident_launch_accepted accepted;
    struct resident_launch launch;
    struct resident_receipt receipt = {0};
    char *const argv[] = {(char *)image, (char *)verb, (char *)arg, NULL};
    char *const envp[] = {NULL};
    resident_launch_init(&launch);
    if (!rcr_accept_of(image, &accepted) ||
        !resident_launch_prepare(&launch, image, &accepted, out.error, sizeof(out.error)))
        return out;
    double began = rcr_now_ms();
    out.spawned = rcr_spawn(&launch, o, argv, envp, &receipt, &out, image);
    out.spawn_errno = errno;
    out.spawn_ms = rcr_now_ms() - began;
    out.state = RCR_STATE(launch);
    out.exec_errno = RCR_EXECERR(launch);
    out.pid = launch.pid;
    (void)snprintf(out.proof, sizeof(out.proof), "%s", receipt.mapped_proof);
    if (out.spawned) {
        int status = 0;
        /* RUSAGE_CHILDREN grows by exactly this child when it is reaped (the
         * harness reaps one child at a time here). */
        struct rusage before = {0}, after = {0};
        (void)getrusage(RUSAGE_CHILDREN, &before);
        while (waitpid((pid_t)launch.pid, &status, 0) < 0 && errno == EINTR) {}
        (void)getrusage(RUSAGE_CHILDREN, &after);
        out.cpu_ms = rcr_tv_ms(&after.ru_utime) - rcr_tv_ms(&before.ru_utime) +
                     rcr_tv_ms(&after.ru_stime) - rcr_tv_ms(&before.ru_stime);
        out.wall_ms = rcr_now_ms() - began;
        out.exited = WIFEXITED(status);
        out.code = out.exited ? WEXITSTATUS(status) : -1;
        out.signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        launch.spawned = false; /* reaped here */
    }
    resident_launch_close(&launch);
    return out;
}

/* Run the fixture once. `manifest == NULL` is the unconfined control. */
static struct rcr_outcome rcr_run(const char *image,
                                  const struct package_resident_manifest *manifest,
                                  const char *verb, const char *arg)
{
    struct rcr_opts opts = {.manifest = manifest};
    return rcr_run_opts(image, &opts, verb, arg);
}

static int rcr_cmp(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double rcr_median3(double v[3])
{
    qsort(v, 3, sizeof(v[0]), rcr_cmp);
    return v[1];
}

static bool rcr_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

#ifndef RCR_LEGACY_BASELINE
static int rcr_handshake_seam_checks(void);
static int rcr_limit_checks(const char *image);
#endif

/* Refusal and policy checks that hold on every host. */
static int rcr_refusal_checks(const char *image, bool sandbox)
{
    int failures = 0;
    struct package_resident_manifest m;
    package_resident_manifest_init(&m);
    struct package_resident_confinement conf;
    RCR_CHECK("translator refuses a relative path",
        (m.read_paths[0] = "relative/dir", m.n_read = 1,
         !package_resident_manifest_profile(&m, image, &conf).ok));
    RCR_CHECK("translator refuses a '..' segment",
        (m.read_paths[0] = "/etc/../etc", m.n_read = 1,
         !package_resident_manifest_profile(&m, image, &conf).ok));
    RCR_CHECK("translator refuses a missing path",
        (m.read_paths[0] = "/nonexistent-rcr-path", m.n_read = 1,
         !package_resident_manifest_profile(&m, image, &conf).ok));
    m.n_read = 0;
    RCR_CHECK("translator profile enables nnp, landlock, seccomp, core=0",
        package_resident_manifest_profile(&m, image, &conf).ok &&
        conf.profile.no_new_privs && conf.profile.landlock &&
        conf.profile.seccomp && conf.profile.rlimits.core_bytes == 0);
    struct os_sandbox_profile weak = conf.profile;
    weak.landlock = false;
    struct resident_launch launch;
    struct resident_launch_accepted accepted;
    struct resident_receipt receipt;
    char error[RESIDENT_LAUNCH_ERROR_MAX] = {0};
    char *const argv[] = {(char *)image, (char *)"exit", (char *)"0", NULL};
    char *const envp[] = {NULL};
    resident_launch_init(&launch);
    bool ready = rcr_accept_of(image, &accepted) &&
        resident_launch_prepare(&launch, image, &accepted, error, sizeof(error));
    RCR_CHECK("a profile without Landlock is refused, never run unconfined",
        ready && !resident_launch_spawn_confined(&launch, argv, envp, &weak,
            &receipt, error, sizeof(error)) && !launch.spawned);
    if (!sandbox) {
        error[0] = '\0';
        RCR_CHECK("no Landlock/seccomp: named refusal LANDLOCK_UNAVAILABLE",
            ready && !resident_launch_spawn_confined(&launch, argv, envp,
                &conf.profile, &receipt, error, sizeof(error)) &&
            (strstr(error, "LANDLOCK_UNAVAILABLE") ||
             strstr(error, "SECCOMP_UNAVAILABLE")) && !launch.spawned);
    }
    resident_launch_close(&launch);
    RCR_RELEASE(conf);
#ifndef RCR_LEGACY_BASELINE
    failures += rcr_handshake_seam_checks();
    failures += rcr_limit_checks(image);
#endif
    return failures;
}

struct rcr_paths {
    char allowed[PATH_MAX], rw[PATH_MAX], other[PATH_MAX], file[PATH_MAX],
         wfile[PATH_MAX], ofile[PATH_MAX];
};

static int rcr_status_checks(const char *image, const struct rcr_paths *p,
                             const struct package_resident_manifest *m);

#ifndef RCR_LEGACY_BASELINE
/* Status-pipe seam: feed `bytes` (and optionally close the writer) and read
 * the verdict. A closed read end gives POLLNVAL/EBADF, i.e. a read error. */
static struct resident_handshake_result rcr_hs(bool confined,
                                               const unsigned char *bytes, size_t n,
                                               bool close_writer, bool close_reader,
                                               uint32_t deadline_ms)
{
    int fds[2];
    struct resident_handshake_result bad = {RESIDENT_EXEC_STATUS_ERROR, -1, true};
    if (pipe(fds) != 0) return bad;
    if (n && write(fds[1], bytes, n) != (ssize_t)n) return bad;
    if (close_writer) close(fds[1]);
    if (close_reader) close(fds[0]);
    uint64_t deadline = deadline_ms ? rcr_mono_ns() + (uint64_t)deadline_ms * UINT64_C(1000000) : 0;
    struct resident_handshake_result r =
        resident_handshake_interpret(confined, fds[0], deadline);
    if (!close_reader) close(fds[0]);
    if (!close_writer) close(fds[1]);
    return r;
}

static int rcr_handshake_unconfined_checks(void);

static int rcr_handshake_seam_checks(void)
{
    int failures = 0;
    const unsigned char armed[] = {0xA5u}, armed_err[] = {0xA5u, 13u};
    const unsigned char sandbox[] = {0xFEu}, errno_only[] = {13u};
    struct resident_handshake_result r;
    r = rcr_hs(true, armed, 1, true, false, 2000);
    RCR_CHECK("confined marker then EOF is ARMED_EXEC_UNCERTAIN, not a completed exec",
        r.proceed && r.state == RESIDENT_EXEC_ARMED_UNCERTAIN);
    r = rcr_hs(true, armed_err, 2, true, false, 2000);
    RCR_CHECK("confined marker then errno is EXEC_FAILED(errno)",
        !r.proceed && r.state == RESIDENT_EXEC_FAILED && r.err == 13);
    r = rcr_hs(true, sandbox, 1, true, false, 2000);
    RCR_CHECK("confined stage byte is SANDBOX_FAILED",
        !r.proceed && r.state == RESIDENT_EXEC_SANDBOX_FAILED);
    const unsigned char trace_stage[] = {0xFDu};
    r = rcr_hs(true, trace_stage, 1, true, false, 2000);
    RCR_CHECK("confined trace stage byte is CONFIRM_UNAVAILABLE",
        !r.proceed && r.state == RESIDENT_EXEC_CONFIRM_UNAVAILABLE);
    r = rcr_hs(true, NULL, 0, true, false, 2000);
    RCR_CHECK("confined EOF with no marker is CHILD_DIED",
        !r.proceed && r.state == RESIDENT_EXEC_CHILD_DIED);
    r = rcr_hs(true, NULL, 0, false, false, 150);
    RCR_CHECK("confined silence past the deadline is TIMEOUT",
        !r.proceed && r.state == RESIDENT_EXEC_TIMEOUT);
    r = rcr_hs(true, NULL, 0, false, true, 2000);
    RCR_CHECK("confined read error is its own STATUS_ERROR, never success",
        !r.proceed && r.state == RESIDENT_EXEC_STATUS_ERROR && r.err == EBADF);
    r = rcr_hs(true, errno_only, 1, true, false, 2000);
    RCR_CHECK("confined errno byte without the marker is a failure",
        !r.proceed && r.state == RESIDENT_EXEC_FAILED && r.err == 13);
    return failures + rcr_handshake_unconfined_checks();
}

static int rcr_handshake_unconfined_checks(void)
{
    int failures = 0;
    const unsigned char errno_only[] = {13u};
    struct resident_handshake_result r;
    r = rcr_hs(false, NULL, 0, true, false, 0);
    RCR_CHECK("UNCONFINED original semantics: EOF is the exec",
        r.proceed);
    r = rcr_hs(false, errno_only, 1, true, false, 0);
    RCR_CHECK("UNCONFINED original semantics: an errno byte is an exec failure",
        !r.proceed && r.state == RESIDENT_EXEC_FAILED && r.err == 13);
    r = rcr_hs(false, NULL, 0, false, true, 0);
    RCR_CHECK("UNCONFINED original semantics: a read error is an exec failure, not success",
        !r.proceed && r.state == RESIDENT_EXEC_FAILED && r.err == 0);
    return failures;
}

static int rcr_policy_checks(const char *image);

/* The default manifest is finitely limited; KEEP is an explicit opt-out. */
static int rcr_limit_checks(const char *image)
{
    int failures = 0;
    struct package_resident_manifest m;
    struct package_resident_confinement conf;
    package_resident_manifest_init(&m);
    bool built = package_resident_manifest_profile(&m, image, &conf).ok;
    const struct os_sandbox_rlimits *l = &conf.profile.rlimits;
    RCR_CHECK("default manifest yields finite rlimits incl. a uid-task-count thread budget (NPROC >= 256) for AS, CPU, NOFILE, FSIZE, CORE",
        built && l->as_bytes != OS_SANDBOX_RLIMIT_KEEP &&
        l->cpu_seconds != OS_SANDBOX_RLIMIT_KEEP && l->nproc != OS_SANDBOX_RLIMIT_KEEP && l->nproc >= 256u &&
        l->nofile != OS_SANDBOX_RLIMIT_KEEP && l->fsize_bytes != OS_SANDBOX_RLIMIT_KEEP &&
        l->core_bytes == 0 && l->as_bytes == PACKAGE_RESIDENT_DEFAULT_AS_BYTES);
    RCR_RELEASE(conf);
    m.rlimits.cpu_seconds = OS_SANDBOX_RLIMIT_KEEP;
    RCR_CHECK("an unbounded (KEEP) limit is refused without the explicit opt-out",
        !package_resident_manifest_profile(&m, image, &conf).ok);
    m.allow_unbounded_limits = true;
    bool opted = package_resident_manifest_profile(&m, image, &conf).ok &&
        conf.profile.rlimits.cpu_seconds == OS_SANDBOX_RLIMIT_KEEP;
    RCR_CHECK("allow_unbounded_limits is the logged explicit opt-out", opted);
    RCR_RELEASE(conf);
    package_resident_manifest_init(&m);
    m.allow_children = true;
    RCR_CHECK("allow_children is refused: no descendant containment exists",
        !package_resident_manifest_profile(&m, image, &conf).ok);
    RCR_RELEASE(conf);
    return failures + rcr_policy_checks(image);
}

/* Grants and syscall policy of the default profile. */
static int rcr_policy_checks(const char *image)
{
    int failures = 0;
    struct package_resident_manifest m;
    struct package_resident_confinement conf;
    package_resident_manifest_init(&m);
    bool again = package_resident_manifest_profile(&m, image, &conf).ok;
    bool loader = !again;
    for (size_t i = 0; i < conf.profile.n_fs_rules; ++i) {
        const char *p = conf.profile.fs_rules[i].path;
        loader = loader || strncmp(p, "/lib", 4) == 0 || strncmp(p, "/usr/lib", 8) == 0 ||
                 strcmp(p, "/etc/ld.so.cache") == 0;
    }
    RCR_CHECK("no implicit loader directory is granted", !loader);
    bool uring = false, clone_listed = false;
    for (size_t i = 0; i < conf.profile.n_denied; ++i) {
        uring = uring || conf.profile.denied_syscalls[i] == 425 || conf.profile.denied_syscalls[i] == 426 ||
                conf.profile.denied_syscalls[i] == 427;
        clone_listed = clone_listed || conf.profile.denied_syscalls[i] == 56;
    }
    RCR_CHECK("io_uring is denied, clone is thread-only and clone3 answers ENOSYS",
        uring && !clone_listed && RCR_V2_PROFILE(conf));
    RCR_RELEASE(conf);
    return failures;
}
#endif /* RCR_LEGACY_BASELINE */

/* Finding 1: Landlock does not revoke an open fd, so the sweep must. */
static int rcr_fd_checks(const char *image, const struct rcr_paths *p,
                         const struct package_resident_manifest *m)
{
    int failures = 0;
    char leak[PATH_MAX], num[16];
    (void)snprintf(leak, sizeof(leak), "%s/leaked", p->other);
    int first = open(leak, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int fd = first >= 0 ? fcntl(first, F_DUPFD, 20) : -1; /* F_DUPFD: no CLOEXEC */
    if (first >= 0) close(first);
    (void)snprintf(num, sizeof(num), "%d", fd);
    RCR_CHECK("setup: a writable out-of-manifest descriptor without CLOEXEC",
        fd >= 20 && (fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0);
    struct rcr_outcome control = rcr_run(image, NULL, "fdwrite", num);
    RCR_CHECK("red twin: UNCONFINED the child inherits and writes the descriptor",
        control.spawned && control.exited && control.code == 0);
    struct rcr_outcome confined = rcr_run(image, m, "fdwrite", num);
    printf("  [fd leak: spawned=%d exited=%d code=%d sig=%d]\n", confined.spawned,
           confined.exited, confined.code, confined.signal);
    RCR_CHECK("confined: the inherited out-of-manifest descriptor is EBADF in the child",
        confined.spawned && confined.exited && confined.code == EBADF);
    if (fd >= 0) close(fd);
    return failures;
}

/* Findings 2 and 3 at the production boundary (fault injection fields). */
static void rcr_tweak_exec_denied(struct package_resident_confinement *c, void *ctx)
{
    c->rules[0].path = (const char *)ctx; /* the image is no longer granted */
    RCR_UNBIND(c->rules[0]);
    c->rules[0].allow_execute = false;
}

static void rcr_tweak_bad_grant(struct package_resident_confinement *c, void *ctx)
{
    (void)ctx;
    c->rules[1].path = "/nonexistent-rcr-grant";
    RCR_UNBIND(c->rules[1]);
}

static int rcr_hardening_checks(const char *image, const struct rcr_paths *p,
                                  const struct package_resident_manifest *m);
static int rcr_arm_failure_checks(const char *image, const struct rcr_paths *p,
                                  const struct package_resident_manifest *m);

static int rcr_handshake_checks(const char *image, const struct rcr_paths *p,
                                const struct package_resident_manifest *m)
{
    int failures = 0;
    struct rcr_opts hang = {.manifest = m, .stall_ms = 60000, .deadline_ms = 400};
    struct rcr_outcome h = rcr_run_opts(image, &hang, "exit", "0");
    printf("  [hang: spawned=%d state=%d errno=%d spawn_ms=%.0f pid=%llu]\n", h.spawned,
           h.state, h.spawn_errno, h.spawn_ms, (unsigned long long)h.pid);
    RCR_CHECK("a child hung before exec returns a typed timeout within the deadline",
        !h.spawned && h.state == RESIDENT_EXEC_TIMEOUT && h.spawn_errno == ETIMEDOUT &&
        h.spawn_ms < 400.0 + 1500.0);
    RCR_CHECK("the hung child was killed and reaped",
        h.pid > 1 && kill((pid_t)h.pid, 0) != 0 && errno == ESRCH);
    struct rcr_opts die = {.manifest = m, .die_after_marker = true};
    struct rcr_outcome d = rcr_run_opts(image, &die, "exit", "0");
    printf("  [die-after-marker: spawned=%d state=%d proof=%s errno=%d]\n", d.spawned,
           d.state, d.proof, d.spawn_errno);
    RCR_CHECK("marker then death is a typed exec-uncertain result, not spawned plus an exit status",
        !d.spawned && d.state == RESIDENT_EXEC_ARMED_UNCERTAIN && d.spawn_errno == EPROTO &&
        !d.exited && d.pid > 1 && kill((pid_t)d.pid, 0) != 0 && errno == ESRCH);
    return failures + rcr_arm_failure_checks(image, p, m);
}

static int rcr_arm_failure_checks(const char *image, const struct rcr_paths *p,
                                  const struct package_resident_manifest *m)
{
    int failures = 0;
    struct rcr_opts notrace = {.manifest = m, .fail_traceme = true};
    struct rcr_outcome nt = rcr_run_opts(image, &notrace, "exit", "0");
    RCR_CHECK("a refused PTRACE_TRACEME is exec-confirm-unavailable, not a sandbox-arm failure",
        !nt.spawned && nt.state == RESIDENT_EXEC_CONFIRM_UNAVAILABLE &&
        strstr(nt.error, "exec-confirm-unavailable (ptrace_scope)") != NULL);
    struct rcr_opts nox = {.manifest = m, .tweak = rcr_tweak_exec_denied, .ctx = (void *)p->allowed};
    struct rcr_outcome x = rcr_run_opts(image, &nox, "exit", "0");
    RCR_CHECK("a refused exec is EXEC_FAILED with the child's errno",
        !x.spawned && x.state == RESIDENT_EXEC_FAILED && x.exec_errno == EACCES);
    struct rcr_opts badg = {.manifest = m, .tweak = rcr_tweak_bad_grant};
    struct rcr_outcome b = rcr_run_opts(image, &badg, "exit", "0");
    RCR_CHECK("a sandbox that cannot arm is SANDBOX_FAILED, not run unconfined",
        !b.spawned && b.state == RESIDENT_EXEC_SANDBOX_FAILED);
    return failures + rcr_hardening_checks(image, p, m);
}

/* Open descriptors of this process (the directory handle counts the same on
 * every call, so two counts compare directly). */
static int rcr_count_fds(void)
{
    DIR *d = opendir("/proc/self/fd");
    int n = 0;
    if (!d) return -1;
    for (struct dirent *e; (e = readdir(d)) != NULL;)
        if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

/* Review fixes: (c) runs in a forked helper so lowering RLIMIT_NOFILE never
 * touches the harness process. */
static int rcr_high_fd_prepare(void)
{
    struct rlimit saved;
    if (getrlimit(RLIMIT_NOFILE, &saved) != 0) {
        fprintf(stderr, "resident nofile: getrlimit setup: %s\n", strerror(errno));
        return 90;
    }
    if (saved.rlim_max != RLIM_INFINITY && saved.rlim_max <= 70000) {
        fprintf(stderr, "resident nofile: hard limit %llu cannot plant FD 70000\n",
                (unsigned long long)saved.rlim_max);
        return 77;
    }
    if (saved.rlim_cur > 70000) return 0;
    struct rlimit raised = saved;
    raised.rlim_cur = 70001;
    if (setrlimit(RLIMIT_NOFILE, &raised) == 0) return 0;
    fprintf(stderr, "resident nofile: raise soft limit: %s\n", strerror(errno));
    return 90;
}

static int rcr_lowered_limit_child(const char *image,
                                   const struct package_resident_manifest *m)
{
    int setup = rcr_high_fd_prepare();
    if (setup != 0) return setup;
    int low = open("/dev/null", O_WRONLY);
    struct rlimit lim = {.rlim_cur = 64, .rlim_max = 64};
    int high = low >= 0 ? fcntl(low, F_DUPFD, 70000) : -1;
    if (high < 0) {
        fprintf(stderr, "resident nofile: open/duplicate FD 70000: %s\n", strerror(errno));
        if (low >= 0) close(low);
        return 90;
    }
    char fdarg[32];
    int used = snprintf(fdarg, sizeof(fdarg), "%d", high);
    close(low);
    if (used < 0 || (size_t)used >= sizeof(fdarg)) {
        fprintf(stderr, "resident nofile: encode descriptor failed\n");
        close(high);
        return 90;
    }
    if (setrlimit(RLIMIT_NOFILE, &lim) != 0) {
        fprintf(stderr, "resident nofile: lower hard/soft limit: %s\n", strerror(errno));
        close(high);
        return 91;
    } /* high FD remains open above both 65536 and the hard limit */
    struct rcr_opts o = {.manifest = m, .no_close_range = true};
    struct rcr_outcome out = rcr_run_opts(image, &o, "fdwrite", fdarg);
    close(high);
    return out.spawned && out.exited && out.code == EBADF ? 0 : 1;
}

static int rcr_hardening_reproof(const char *image, const struct package_resident_manifest *m)
{
    int failures = 0;
    struct rcr_opts rh = {.manifest = m, .fail_reproof_hash = true};
    struct rcr_outcome h = rcr_run_opts(image, &rh, "exit", "0");
    RCR_CHECK("a failed mapped-image re-hash is a typed refusal and never CONFIRMED",
        !h.spawned && h.state != RESIDENT_EXEC_CONFIRMED && h.pid > 1 &&
        strstr(h.error, "could not be re-proved") != NULL &&
        kill((pid_t)h.pid, 0) != 0 && errno == ESRCH);
    return failures;
}

static int rcr_hardening_clock(const char *image, const struct package_resident_manifest *m)
{
    int failures = 0;
    int before = rcr_count_fds();
    struct rcr_opts ck = {.manifest = m, .fail_clock = true};
    struct rcr_outcome c = rcr_run_opts(image, &ck, "exit", "0");
    int after = rcr_count_fds();
    RCR_CHECK("a clock failure after the channels exist refuses and leaks no descriptor",
        !c.spawned && strstr(c.error, "CLOCK_FAILED") != NULL && before > 0 && before == after);
    return failures;
}

static int rcr_nofile_helper_result(pid_t pid, pid_t waited, int st)
{
    int failures = 0;
    bool reaped = pid > 0 && waited == pid && WIFEXITED(st);
    if (reaped && WEXITSTATUS(st) == 77) {
        printf("resident nofile: high FD closure... UNOBSERVED (descriptor hard limit)\n");
        return failures;
    }
    if (!reaped || WEXITSTATUS(st) != 0)
        fprintf(stderr, "resident nofile: helper pid=%ld waited=%ld status=%d errno=%d\n",
                (long)pid, (long)waited, st, errno);
    RCR_CHECK("without close_range, a descriptor above a lowered hard limit is EBADF in the child",
        reaped && WEXITSTATUS(st) == 0);
    return failures;
}

static int rcr_hardening_nofile(const char *image, const struct package_resident_manifest *m)
{
    int st = 0;
    pid_t pid = fork();
    if (pid == 0) _exit(rcr_lowered_limit_child(image, m));
    pid_t waited = -1;
    if (pid > 0)
        do { waited = waitpid(pid, &st, 0); } while (waited < 0 && errno == EINTR);
    return rcr_nofile_helper_result(pid, waited, st);
}

static int rcr_hardening_grants(const char *image, const struct package_resident_manifest *m)
{
    int failures = 0;
    struct package_resident_confinement conf;
    memset(&conf, 0, sizeof(conf));
    package_resident_manifest_force_unpinned_grants_for_testing(true);
    struct zcl_result r = package_resident_manifest_profile(m, image, &conf);
    package_resident_manifest_force_unpinned_grants_for_testing(false);
    RCR_CHECK("grants that cannot be descriptor-pinned refuse and produce no profile",
        !r.ok && strstr(r.message, "grant-pinning-unavailable") != NULL &&
        conf.profile.n_fs_rules == 0 && conf.n_grant_fds == 0);
    return failures;
}

/* The reproof can spend the budget the wait left: past the deadline the stopped
 * child is killed (typed timeout) and never detached, so it never runs. */
static int rcr_hardening_deadline(const char *image, const struct rcr_paths *p,
                                  const struct package_resident_manifest *m)
{
    int failures = 0;
    unlink(p->wfile);
    struct rcr_opts o = {.manifest = m, .deadline_ms = 400, .reproof_delay_ms = 900};
    struct rcr_outcome t = rcr_run_opts(image, &o, "write", p->wfile);
    RCR_CHECK("a reproof that outlasts the deadline is a typed timeout and the child never ran",
        !t.spawned && t.state == RESIDENT_EXEC_TIMEOUT && t.spawn_errno == ETIMEDOUT &&
        access(p->wfile, F_OK) != 0 && t.pid > 1 &&
        kill((pid_t)t.pid, 0) != 0 && errno == ESRCH);
    return failures;
}

static int rcr_hardening_checks(const char *image, const struct rcr_paths *p,
                                  const struct package_resident_manifest *m)
{
    return rcr_hardening_reproof(image, m) + rcr_hardening_clock(image, m) +
           rcr_hardening_nofile(image, m) + rcr_hardening_grants(image, m) +
           rcr_hardening_deadline(image, p, m);
}

/* Finding 5: no children, no new session or group; nothing survives. */
static pid_t rcr_read_pidfile(const char *path)
{
    FILE *f = fopen(path, "r");
    long pid = 0;
    if (!f) return 0;
    int got = fscanf(f, "%ld", &pid);
    fclose(f);
    return got == 1 && pid > 1 ? (pid_t)pid : 0;
}

static int rcr_thread_checks(const char *image, const struct rcr_paths *p,
                             const struct package_resident_manifest *m);

static int rcr_child_checks(const char *image, const struct rcr_paths *p,
                            const struct package_resident_manifest *m)
{
    int failures = 0;
    static const char *const verbs[] = {"fork", "vfork", "setsid", "setpgid"};
    struct rcr_outcome fork_free = rcr_run(image, NULL, "fork", "");
    RCR_CHECK("red twin: UNCONFINED fork() works", fork_free.spawned && fork_free.exited &&
        fork_free.code == 0);
    for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); ++i) {
        struct rcr_outcome r = rcr_run(image, m, verbs[i], "");
        printf("  [%s: spawned=%d exited=%d code=%d sig=%d]\n", verbs[i], r.spawned, r.exited,
               r.code, r.signal);
        RCR_CHECK("confined fork/vfork/setsid/setpgid is killed by the seccomp policy",
            r.spawned && !r.exited && r.signal == SIGSYS);
    }
    return failures + rcr_thread_checks(image, p, m);
}

static int rcr_thread_checks(const char *image, const struct rcr_paths *p,
                             const struct package_resident_manifest *m)
{
    int failures = 0;
    /* DEFAULT limits: no override of any rlimit. */
    struct rcr_outcome thr = rcr_run(image, m, "thread", "");
    printf("  [thread: spawned=%d exited=%d code=%d sig=%d]\n", thr.spawned, thr.exited, thr.code, thr.signal);
    RCR_CHECK("confined: a pthread starts and joins (clone with CLONE_THREAD, clone3 falls back via ENOSYS)",
        thr.spawned && thr.exited && thr.code == 0);
    char countfile[PATH_MAX];
    (void)snprintf(countfile, sizeof(countfile), "%s/threads.count", p->rw);
    unlink(countfile);
    struct rcr_outcome flood = rcr_run(image, m, "flood", countfile);
    long made = -1;
    FILE *cf = fopen(countfile, "r");
    if (cf) { if (fscanf(cf, "%ld", &made) != 1) made = -1; fclose(cf); }
    printf("  [flood: spawned=%d exited=%d code=%d threads=%ld]\n", flood.spawned, flood.exited, flood.code, made);
    RCR_CHECK("a thread flood stops at the uid-count + 256 budget (not thousands) and exits cleanly",
        flood.spawned && flood.exited && flood.code == 0 && made >= 16 && made <= 256 + 128);
    char pidfile[PATH_MAX];
    (void)snprintf(pidfile, sizeof(pidfile), "%s/daemon.pid", p->rw);
    unlink(pidfile);
    struct rcr_outcome free_daemon = rcr_run(image, NULL, "daemon", pidfile);
    pid_t alive = rcr_read_pidfile(pidfile);
    RCR_CHECK("red twin: UNCONFINED a setsid descendant survives its parent",
        free_daemon.spawned && alive > 1 && kill(alive, 0) == 0);
    if (alive > 1) kill(alive, SIGKILL);
    unlink(pidfile);
    struct rcr_outcome conf_daemon = rcr_run(image, m, "daemon", pidfile);
    pid_t survivor = rcr_read_pidfile(pidfile);
    if (survivor > 1) kill(survivor, SIGKILL); /* clean up before judging */
    RCR_CHECK("confined: no detached descendant exists or survives",
        conf_daemon.spawned && survivor == 0);
    return failures;
}

/* Finding 6: a symlinked grant is refused; a swapped path stays bound. */
struct rcr_swap {
    char dir[PATH_MAX], moved[PATH_MAX], file[PATH_MAX];
};

static void rcr_swap_now(void *ctx)
{
    struct rcr_swap *s = ctx;
    if (rename(s->dir, s->moved) != 0 || mkdir(s->dir, 0700) != 0) return;
    (void)rcr_write_file(s->file, "swapped");
}

/* The grant directory is replaced between validation and spawn. The child must
 * stay confined to the object validated in the parent, not the new path. */
static int rcr_swap_check(const char *image, const char *dir)
{
    int failures = 0;
    struct rcr_swap s;
    (void)snprintf(s.dir, sizeof(s.dir), "%s/swap", dir);
    (void)snprintf(s.moved, sizeof(s.moved), "%s/swap_moved", dir);
    (void)snprintf(s.file, sizeof(s.file), "%s/swap/f", dir);
    bool laid = mkdir(s.dir, 0700) == 0 && rcr_write_file(s.file, "orig");
    RCR_CHECK("setup: a grant directory to swap", laid);
    struct package_resident_manifest m;
    package_resident_manifest_init(&m);
    m.read_paths[0] = s.dir; m.n_read = 1;
    struct rcr_opts opts = {.manifest = &m, .pre_spawn = rcr_swap_now, .ctx = &s};
    struct rcr_outcome r = rcr_run_opts(image, &opts, "open", s.file);
    printf("  [swap: spawned=%d exited=%d code=%d]\n", r.spawned, r.exited, r.code);
    RCR_CHECK("a grant path swapped after validation stays bound to the validated object (EACCES)",
        r.spawned && r.exited && r.code == EACCES);
    return failures;
}


static int rcr_grant_checks(const char *image, const char *dir)
{
    int failures = 0;
    char target[PATH_MAX], link[PATH_MAX], sub[PATH_MAX], viasub[PATH_MAX];
    (void)snprintf(target, sizeof(target), "%s/real", dir);
    (void)snprintf(link, sizeof(link), "%s/link", dir);
    (void)snprintf(sub, sizeof(sub), "%s/real/sub", dir);
    (void)snprintf(viasub, sizeof(viasub), "%s/link/sub", dir);
    bool laid = mkdir(target, 0700) == 0 && mkdir(sub, 0700) == 0 && symlink(target, link) == 0;
    RCR_CHECK("setup: a real directory and a symlink to it", laid);
    struct package_resident_manifest m;
    struct package_resident_confinement conf;
    package_resident_manifest_init(&m);
    m.read_paths[0] = link; m.n_read = 1;
    RCR_CHECK("a grant that is itself a symlink is refused",
        !package_resident_manifest_profile(&m, image, &conf).ok);
    m.read_paths[0] = viasub;
    RCR_CHECK("a grant that crosses a symlinked component is refused",
        !package_resident_manifest_profile(&m, image, &conf).ok);
    m.read_paths[0] = sub;
    bool plain = package_resident_manifest_profile(&m, image, &conf).ok;
    RCR_CHECK("the same object by its real path is accepted and bound by descriptor",
        plain && RCR_BOUND(conf, 1));
    RCR_RELEASE(conf);
    return failures + rcr_swap_check(image, dir);
}

/* Finding 7: a PT_INTERP image needs a loader directory; it is refused. */
static int rcr_dynamic_checks(const char *dyn, const struct package_resident_manifest *m)
{
    int failures = 0;
    struct rcr_outcome control = rcr_run(dyn, NULL, "exit", "0");
    RCR_CHECK("red twin: UNCONFINED the dynamic image itself runs",
        control.spawned && control.exited && control.code == 0);
    struct rcr_outcome r = rcr_run(dyn, m, "exit", "0");
    printf("  [dynamic: spawned=%d err=%s]\n", r.spawned, r.error);
    RCR_CHECK("a dynamic (PT_INTERP) image is refused by default, before any process exists",
        !r.spawned && strstr(r.error, "IMAGE_HAS_INTERPRETER") != NULL && r.pid == 0);
    return failures;
}

#if defined(__linux__)
static void rcr_native_header_change(Elf64_Ehdr *eh, unsigned mode)
{
    if (mode == 0) eh->e_machine = eh->e_machine == EM_X86_64 ? EM_AARCH64 : EM_X86_64;
    if (mode == 1) eh->e_ident[EI_DATA] = eh->e_ident[EI_DATA] == ELFDATA2LSB ? ELFDATA2MSB : ELFDATA2LSB;
    if (mode == 2) eh->e_ident[EI_VERSION] = EV_NONE;
    if (mode == 3) eh->e_version = EV_NONE;
}

/* Copy the real static fixture; each modified copy receives its own accepted
 * digest through rcr_run, so this is compatibility rather than stale bytes. */
static bool rcr_native_copy(const char *image, const char *path, unsigned mode)
{
    FILE *in = fopen(image, "rb");
    if (!in) return false;
    FILE *out = fopen(path, "wb+");
    if (!out) { (void)fclose(in); return false; }
    unsigned char bytes[4096];
    size_t total = 0, n;
    bool ok = true;
    while ((n = fread(bytes, 1, sizeof(bytes), in)) != 0) {
        if (total > 64u * 1024u * 1024u - n ||
            fwrite(bytes, 1, n, out) != n) { ok = false; break; }
        total += n;
    }
    if (ferror(in)) ok = false;
    if (fclose(in) != 0) ok = false;
    Elf64_Ehdr eh;
    if (ok) ok = fflush(out) == 0 && fseek(out, 0, SEEK_SET) == 0 &&
                 fread(&eh, 1, sizeof(eh), out) == sizeof(eh);
    if (ok) {
        rcr_native_header_change(&eh, mode);
        ok = fseek(out, 0, SEEK_SET) == 0 &&
             fwrite(&eh, 1, sizeof(eh), out) == sizeof(eh);
    }
    if (fclose(out) != 0) ok = false;
    return ok && chmod(path, 0700) == 0;
}

static int rcr_native_checks(const char *image, const char *dir)
{
    int failures = 0;
    struct package_resident_manifest plain;
    package_resident_manifest_init(&plain);
    struct rcr_outcome positive = rcr_run(image, &plain, "exit", "0");
    RCR_CHECK("native static fixture still executes under its explicit confinement grant",
        positive.spawned && positive.exited && positive.code == 0);
    for (unsigned mode = 0; mode < 4; ++mode) {
        char path[PATH_MAX];
        int length = snprintf(path, sizeof(path), "%s/native-%u", dir, mode);
        bool copied = length > 0 && (size_t)length < sizeof(path) &&
                      rcr_native_copy(image, path, mode);
        RCR_CHECK("setup: independently accepted incompatible static fixture", copied);
        if (!copied) continue;
        struct rcr_outcome r = rcr_run(path, &plain, "exit", "0");
        printf("  [native mode=%u spawned=%d pid=%llu err=%s]\n",
               mode, r.spawned, (unsigned long long)r.pid, r.error);
        RCR_CHECK("ISA, endian and version mismatch refuse by name before any child",
            !r.spawned && r.pid == 0 && r.spawn_errno == ENOEXEC &&
            strstr(r.error, "IMAGE_NOT_NATIVE_ELF") != NULL);
    }
    return failures;
}
#endif

static int rcr_behaviour_checks(const char *image, const char *dir)
{
    int failures = 0;
    struct rcr_paths p;
    char *allowed = p.allowed, *rw = p.rw, *other = p.other, *file = p.file,
         *wfile = p.wfile, *ofile = p.ofile;
    (void)snprintf(allowed, sizeof(p.allowed), "%s/allowed", dir);
    (void)snprintf(rw, sizeof(p.rw), "%s/rw", dir);
    (void)snprintf(other, sizeof(p.other), "%s/other", dir);
    (void)snprintf(file, sizeof(p.file), "%s/allowed/f", dir);
    (void)snprintf(wfile, sizeof(p.wfile), "%s/rw/out", dir);
    (void)snprintf(ofile, sizeof(p.ofile), "%s/other/f", dir);
    bool laid = mkdir(allowed, 0700) == 0 && mkdir(rw, 0700) == 0 &&
        mkdir(other, 0700) == 0 && rcr_write_file(file, "ok") &&
        rcr_write_file(ofile, "no");
    RCR_CHECK("lay out allowed/rw/other directories", laid);
    struct package_resident_manifest m;
    package_resident_manifest_init(&m);
    m.read_paths[0] = allowed; m.n_read = 1;
    m.write_paths[0] = rw; m.n_write = 1;

    struct rcr_outcome control = rcr_run(image, NULL, "open", "/etc/passwd");
    RCR_CHECK("red twin: UNCONFINED the same open of /etc/passwd succeeds",
        control.spawned && control.exited && control.code == 0);
    struct rcr_outcome red = rcr_run(image, &m, "open", "/etc/passwd");
    printf("  [red: spawned=%d exited=%d code=%d sig=%d err=%s]\n", red.spawned,
           red.exited, red.code, red.signal, red.error);
    RCR_CHECK("red: confined open outside the manifest is EACCES",
        red.spawned && red.exited && red.code == EACCES);
    struct rcr_outcome red2 = rcr_run(image, &m, "open", ofile);
    RCR_CHECK("red: a sibling directory outside the manifest is EACCES",
        red2.spawned && red2.exited && red2.code == EACCES);
    struct rcr_outcome green = rcr_run(image, &m, "open", file);
    RCR_CHECK("green: an allowed path opens",
        green.spawned && green.exited && green.code == 0);
    failures += rcr_status_checks(image, &p, &m);
    failures += rcr_fd_checks(image, &p, &m);
    failures += rcr_handshake_checks(image, &p, &m);
    failures += rcr_child_checks(image, &p, &m);
    failures += rcr_grant_checks(image, dir);
    return failures;
}

static int rcr_status_checks(const char *image, const struct rcr_paths *p,
                             const struct package_resident_manifest *mp)
{
    int failures = 0;
    const struct package_resident_manifest m = *mp;
    struct stat st;
    struct rcr_outcome wgreen = rcr_run(image, &m, "write", p->wfile);
    RCR_CHECK("green: the read-write path accepts a create+write",
        wgreen.spawned && wgreen.exited && wgreen.code == 0 &&
        stat(p->wfile, &st) == 0 && st.st_size == 1);
    struct rcr_outcome wred = rcr_run(image, &m, "write", p->file);
    RCR_CHECK("red: the read-only path refuses a write",
        wred.spawned && wred.exited && wred.code != 0);
    struct rcr_outcome seven = rcr_run(image, &m, "exit", "7");
    RCR_CHECK("exit 7 is observed as 7",
        seven.spawned && seven.exited && seven.code == 7);
    RCR_CHECK("a confined run reports only after the exec is confirmed (proc_exe_triple)",
        seven.spawned && strcmp(seven.proof, "proc_exe_triple") == 0);
    struct rcr_outcome sock = rcr_run(image, &m, "socket", "");
    RCR_CHECK("forbidden socket syscall is killed with SIGSYS",
        sock.spawned && !sock.exited && sock.signal == SIGSYS);
    struct rcr_outcome sock_free = rcr_run(image, NULL, "socket", "");
    RCR_CHECK("red twin: UNCONFINED socket() is not killed",
        sock_free.spawned && sock_free.exited);
    return failures;
}

/* The budget is on the CPU the confined loop burns (child user+sys), not on
 * wall time: a wall measurement also counts every moment the scheduler left
 * the child runnable-but-off-CPU, which under a loaded shared pool dwarfs the
 * 5% + 20 ms budget and made this group fail in 7 of 12 land proofs. */
static int rcr_overhead_checks(const char *image)
{
    int failures = 0;
    struct package_resident_manifest m;
    package_resident_manifest_init(&m);
    struct rcr_outcome probe = rcr_run(image, NULL, "spin", "20000000");
    double per_iter = probe.cpu_ms > 0.5 ? probe.cpu_ms / 20000000.0 : 1e-6;
    char iters[32];
    (void)snprintf(iters, sizeof(iters), "%lu", (unsigned long)(200.0 / per_iter));
    double unc[3], con[3];
    bool ok = probe.spawned;
    for (int i = 0; ok && i < 3; ++i) {
        struct rcr_outcome u = rcr_run(image, NULL, "spin", iters);
        struct rcr_outcome c = rcr_run(image, &m, "spin", iters);
        ok = u.spawned && c.spawned && u.exited && c.exited &&
             u.code == 0 && c.code == 0;
        unc[i] = u.cpu_ms;
        con[i] = c.cpu_ms;
    }
    double mu = ok ? rcr_median3(unc) : 0.0, mc = ok ? rcr_median3(con) : 0.0;
    printf("  [overhead: iters=%s unconfined_median=%.2f ms confined_median=%.2f ms limit=%.2f ms]\n",
           iters, mu, mc, mu * 1.05 + 20.0);
    RCR_CHECK("overhead: loop runs ~200 ms", ok && mu > 50.0);
    RCR_CHECK("overhead: confined <= 1.05 x unconfined + 20 ms (median of 3)",
        ok && mc <= mu * 1.05 + 20.0);
    return failures;
}

int test_resident_confined_run(void)
{
    int failures = 0;
    char image[PATH_MAX], cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)) ||
        snprintf(image, sizeof(image), "%s/%s", cwd, RCR_FIXTURE) >= (int)sizeof(image)) {
        printf("resident_confined_run: fixture missing... FAIL\n");
        return 1;
    }
    bool sandbox = os_sandbox_landlock_abi() >= 1 && os_sandbox_seccomp_supported();
    failures += rcr_refusal_checks(image, sandbox);
    if (!sandbox) {
        printf("resident_confined_run: SKIP: red/green/exit/SIGSYS/overhead "
               "need Landlock ABI >= 1 and seccomp; this host has neither\n");
        return failures;
    }
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "resident_confined_run", "x");
#if defined(__linux__)
    failures += rcr_native_checks(image, dir);
#endif
    failures += rcr_behaviour_checks(image, dir);
    char dyn[PATH_MAX];
    struct package_resident_manifest plain;
    package_resident_manifest_init(&plain);
    if (snprintf(dyn, sizeof(dyn), "%s/%s", cwd, RCR_FIXTURE_DYN) < (int)sizeof(dyn))
        failures += rcr_dynamic_checks(dyn, &plain);
    failures += rcr_overhead_checks(image);
    test_rm_rf(dir);
    return failures;
}
#endif
