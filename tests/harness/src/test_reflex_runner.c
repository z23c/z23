/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Prove the clean-zygote reflex runner with real candidate images.
 *
 * Every case runs a REAL compiled capsule (tests/harness/fixtures/
 * reflex_runner_fixture.c, one image per behavior kind, built as an order-only
 * prerequisite of every test binary) through the production client
 * zcl_reflex_runner_run(): exec of this very binary as the runner, sealed
 * memfd transport, confinement before mapping, W^X before the story.
 *
 * Seeded failures this group catches:
 *   - a fork-of-resident runner: the candidate reads the resident's canary
 *     global, its planted environment variable, or writes the resident's fd;
 *   - dlopen before confinement: the constructor's open() of a readable file
 *     succeeds;
 *   - a regression that is not red, or that replaces the accepted green root;
 *   - a hang or crash that takes the runner down with it;
 *   - a socket or new executable mapping that is permitted;
 *   - io_uring (network past the syscall filter), pidfd_open or kill that the
 *     runner's startup probes see permitted (the runner then refuses hello);
 *   - pidfd_open/kill on the runner, or fork/execve from a constructor or
 *     story, permitted to candidate code;
 *   - any unconfined fallback when the artifact cannot be sealed/verified.
 */

#if !defined(__linux__)

#include <stdio.h>

int test_reflex_runner(void);
int test_reflex_runner(void)
{
    printf("\n=== clean-zygote reflex runner platform contract ===\n");
    printf("reflex_runner: PASS platform=non-linux runner=unavailable "
           "fixture_required=false\n");
    return 0;
}

#else

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "test/test_helpers.h"

#include "devloop_reflex_runner.h"
#include "devloop_reflex_runner_wire.h"
#include "../fixtures/reflex_runner_fixture.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#define RR_DIR "build/fixtures/reflex_runner/zcl_reflex_fixture_"

struct rr_case {
    char path[256];
    char sha[65];
    struct zcl_reflex_runner_spec spec;
    struct zcl_reflex_runner_outcome out;
    int64_t wall_us;
};

static bool rr_prepare(struct rr_case *c, const char *kind,
                       uint32_t timeout_ms)
{
    memset(c, 0, sizeof(*c));
    (void)snprintf(c->path, sizeof(c->path), RR_DIR "%s.so", kind);
    int fd = open(c->path, O_RDONLY | O_CLOEXEC);
    bool hashed = fd >= 0 && zcl_reflex_sha256_fd(fd, c->sha);
    if (fd >= 0) (void)close(fd);
    if (!hashed) {
        printf("reflex_runner: fixture image %s missing (built as a "
               "prerequisite of every test binary)\n", c->path);
        return false;
    }
    c->spec = (struct zcl_reflex_runner_spec){
        .mode = ZCL_REFLEX_MODE_HOT_FORK,
        .artifact_path = c->path,
        .artifact_sha256 = c->sha,
        .owner_id = ZCL_REFLEX_FIXTURE_OWNER,
        .source_tu = ZCL_REFLEX_FIXTURE_SOURCE,
        .candidate_object_root = ZCL_REFLEX_FIXTURE_OBJECT_ROOT,
        .story_id = ZCL_REFLEX_FIXTURE_STORY,
        .story_root = ZCL_REFLEX_FIXTURE_STORY_ROOT,
        .story_fixture_root = ZCL_REFLEX_FIXTURE_FIXTURE_ROOT,
        .timeout_ms = timeout_ms,
    };
    return true;
}

static bool rr_run_with(struct rr_case *c, const char *kind,
                        uint32_t timeout_ms, bool disable_close_range)
{
    if (!rr_prepare(c, kind, timeout_ms)) return false;
    c->spec.testing_disable_close_range = disable_close_range;
    int64_t started = platform_time_monotonic_us();
    bool available = zcl_reflex_runner_run(&c->spec, &c->out);
    c->wall_us = platform_time_monotonic_us() - started;
    printf("[%s available=%d green=%d signal=%d exit=%d timed_out=%d "
           "warm=%d pid=%d checks=%u/%u fork=%lldus confine=%lldus "
           "dlopen=%lldus story=%lldus reason=\"%s\" detail=\"%s\"] ",
           kind, c->out.available, c->out.green, c->out.child_signal,
           c->out.child_exit_code, c->out.timed_out, c->out.runner_warm,
           c->out.runner_pid, c->out.report.observation.checks_passed,
           c->out.report.observation.checks_run,
           (long long)c->out.fork_us, (long long)c->out.confine_us,
           (long long)c->out.dlopen_us, (long long)c->out.story_us,
           c->out.reason, c->out.report.observation.detail);
    return available;
}

static bool rr_run(struct rr_case *c, const char *kind, uint32_t timeout_ms)
{
    return rr_run_with(c, kind, timeout_ms, false);
}

static bool rr_confined(const struct zcl_reflex_runner_outcome *o)
{
    return o->report.sandboxed && o->seals_verified &&
        o->env_inherited_count == 0 && o->inherited_fd_count == 0 &&
        o->address_space_fresh && o->runner_env_count == 0 &&
        o->runner_fd_count == 0;
}

/* (a) The resident plants an environment variable, a nonzero global, a
 * readable file it holds open at a fixed descriptor; the candidate's
 * constructor and story each try all of them and must see none. */
static int t_hostile_candidate_sees_fresh_closed_world(void)
{
    int failures = 0;
    int held = -1;
    TEST("reflex runner: constructor and story observe no resident env, "
         "memory, files or fds") {
        zcl_reflex_runner_shutdown();
        ASSERT_EQ(setenv(ZCL_REFLEX_FIXTURE_CANARY_ENV, "resident-secret", 1),
                  0);
        zcl_reflex_resident_canary = UINT64_C(0x5ec2e7c0ffee0001);
        held = open(ZCL_REFLEX_FIXTURE_CANARY_FILE, O_RDONLY);
        ASSERT(held >= 0);
        ASSERT(dup2(held, ZCL_REFLEX_FIXTURE_PARENT_FD) ==
               ZCL_REFLEX_FIXTURE_PARENT_FD);
        int status_fd = open(ZCL_REFLEX_FIXTURE_CANARY_FILE2, O_RDONLY);
        ASSERT(status_fd >= 0);
        (void)close(status_fd);

        struct rr_case c;
        ASSERT(rr_run(&c, "canary", 2000));
        ASSERT(c.out.green);
        ASSERT(!c.out.runner_warm);
        ASSERT(rr_confined(&c.out));
        ASSERT(c.out.report.wx_installed);
        ASSERT(c.out.report.descriptor_valid);
        ASSERT_EQ(c.out.report.observation.checks_run, 14u);
        ASSERT_EQ(c.out.report.observation.checks_passed, 14u);
        const char *detail = c.out.report.observation.detail;
        ASSERT(strstr(detail, "ctor=7/7 story=7/7") != NULL);
        ASSERT(strstr(detail, "env=0 canary=0 ") != NULL);
        ASSERT(strstr(detail, "open=EACCES/EACCES") != NULL);
        ASSERT(strstr(detail, "fd77=EBADF") != NULL);
        ASSERT(zcl_reflex_resident_canary == UINT64_C(0x5ec2e7c0ffee0001));
        PASS();
    } _test_next:;
    if (held >= 0) (void)close(held);
    (void)close(ZCL_REFLEX_FIXTURE_PARENT_FD);
    (void)unsetenv(ZCL_REFLEX_FIXTURE_CANARY_ENV);
    return failures;
}

/* (e) + (b): a green candidate executes exactly the sealed bytes and becomes
 * the accepted root; a behavior regression is red and never replaces it. */
static int t_green_then_regression_keeps_accepted_root(void)
{
    int failures = 0;
    TEST("reflex runner: green executes exact bytes; regression is red and "
         "keeps the accepted root") {
        struct rr_case green;
        ASSERT(rr_run(&green, "green", 1000));
        ASSERT(green.out.green);
        ASSERT(green.out.runner_warm);
        ASSERT(rr_confined(&green.out));
        ASSERT(green.out.report.candidate_executed);
        ASSERT_STR_EQ(green.out.report.runtime_module_sha256, green.sha);
        ASSERT_STR_EQ(green.out.runner_sha256, green.sha);
        ASSERT(green.out.confine_us > 0 && green.out.dlopen_us > 0);
        char accepted[65] = {0};
        ASSERT(zcl_reflex_runner_last_green(ZCL_REFLEX_FIXTURE_SOURCE,
                                            accepted));
        ASSERT_STR_EQ(accepted, green.sha);

        struct rr_case regress;
        ASSERT(rr_run(&regress, "regress", 1000));
        ASSERT(regress.out.available);
        ASSERT(!regress.out.green);
        ASSERT(!regress.out.report.story_ok);
        ASSERT(regress.out.report.candidate_executed);
        ASSERT_EQ(regress.out.report.observation.checks_run, 5u);
        ASSERT_EQ(regress.out.report.observation.checks_passed, 4u);
        ASSERT(strcmp(regress.sha, green.sha) != 0);
        ASSERT(zcl_reflex_runner_last_green(ZCL_REFLEX_FIXTURE_SOURCE,
                                            accepted));
        ASSERT_STR_EQ(accepted, green.sha);
        PASS();
    } _test_next:;
    return failures;
}

/* (c) + (d): a hang is killed at the deadline and a crash is red; the SAME
 * warm runner then serves the next candidate green. */
static int t_hang_and_crash_do_not_kill_runner(void)
{
    int failures = 0;
    TEST("reflex runner: infinite loop killed at deadline, SIGSEGV red, "
         "runner survives both") {
        struct rr_case warm;
        ASSERT(rr_run(&warm, "green", 1000));
        ASSERT(warm.out.green);
        int runner_pid = warm.out.runner_pid;

        struct rr_case loop;
        ASSERT(rr_run(&loop, "loop", 300));
        ASSERT(loop.out.available);
        ASSERT(!loop.out.green);
        ASSERT(loop.out.timed_out);
        ASSERT_EQ(loop.out.child_signal, SIGKILL);
        ASSERT(loop.wall_us < 3000000);
        ASSERT_EQ(loop.out.runner_pid, runner_pid);

        struct rr_case segv;
        ASSERT(rr_run(&segv, "segv", 1000));
        ASSERT(segv.out.available);
        ASSERT(!segv.out.green);
        ASSERT_EQ(segv.out.child_signal, SIGSEGV);
        ASSERT_EQ(segv.out.runner_pid, runner_pid);

        struct rr_case after;
        ASSERT(rr_run(&after, "green", 1000));
        ASSERT(after.out.green);
        ASSERT(after.out.runner_warm);
        ASSERT_EQ(after.out.runner_pid, runner_pid);
        PASS();
    } _test_next:;
    return failures;
}

/* Confinement is enforced, not advisory: a socket and a new executable
 * mapping after load are both killed (SIGSYS), and the runner survives. */
static int t_socket_and_wx_are_killed(void)
{
    int failures = 0;
    TEST("reflex runner: socket() and post-load PROT_EXEC mapping are "
         "killed by seccomp") {
        struct rr_case sock;
        ASSERT(rr_run(&sock, "socket", 1000));
        ASSERT(sock.out.available);
        ASSERT(!sock.out.green);
        ASSERT(sock.out.report.sandboxed || !sock.out.report_complete);
        ASSERT_EQ(sock.out.child_signal, SIGSYS);

        struct rr_case wx;
        ASSERT(rr_run(&wx, "wx", 1000));
        ASSERT(wx.out.available);
        ASSERT(!wx.out.green);
        ASSERT_EQ(wx.out.child_signal, SIGSYS);

        struct rr_case after;
        ASSERT(rr_run(&after, "green", 1000));
        ASSERT(after.out.green);
        ASSERT_EQ(after.out.runner_pid, sock.out.runner_pid);
        PASS();
    } _test_next:;
    return failures;
}

/* An escape probe is contained when the candidate was killed by the seccomp
 * layers (SIGSYS) or its call merely failed ("refused:"), never "escaped:". */
static bool rr_escape_contained(const struct rr_case *c)
{
    const char *detail = c->out.report.observation.detail;
    bool refused = strncmp(detail, "refused:", 8) == 0;
    return c->out.available && !c->out.green &&
        strncmp(detail, "escaped:", 8) != 0 &&
        (c->out.child_signal == SIGSYS || refused);
}

/* io_uring would carry socket/connect past the syscall filter: the runner
 * proves at startup, under exactly the leaf filter stack, that
 * io_uring_setup, pidfd_open and kill are killed, or it never says hello.
 * Candidate code then tries pidfd and kill on the runner itself, and fork/exec
 * from the constructor (at dlopen) or the story. Every one is contained and
 * the SAME runner serves the next candidate green. */
static int t_kernel_escape_surfaces_are_denied(void)
{
    static const char *const kinds[] = {
        "pidfd", "killparent", "forkctor", "forkstory",
        "execctor", "execstory",
    };
    int failures = 0;
    TEST("reflex runner: io_uring, pidfd, kill(parent), fork and execve from "
         "constructor or story are denied; runner survives") {
        struct rr_case warm;
        ASSERT(rr_run(&warm, "green", 1000));
        ASSERT(warm.out.green);
        ASSERT_EQ(warm.out.runner_deny_probes, ZCL_REFLEX_DENY_PROBES);
        for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
            struct rr_case c;
            ASSERT(rr_run(&c, kinds[i], 1000));
            ASSERT(rr_escape_contained(&c));
            ASSERT_EQ(c.out.runner_pid, warm.out.runner_pid);
        }
        struct rr_case after;
        ASSERT(rr_run(&after, "green", 1000));
        ASSERT(after.out.green);
        ASSERT(after.out.runner_warm);
        ASSERT_EQ(after.out.runner_pid, warm.out.runner_pid);
        PASS();
    } _test_next:;
    return failures;
}

/* Fail closed: an artifact whose sealed bytes are not the requested digest,
 * or that cannot be read, never reaches a runner and is never green. */
static int t_unverifiable_artifact_fails_closed(void)
{
    int failures = 0;
    TEST("reflex runner: digest mismatch or unreadable artifact fails closed") {
        struct rr_case c;
        ASSERT(rr_prepare(&c, "green", 1000));
        char wrong[65];
        (void)snprintf(wrong, sizeof(wrong), "%s", c.sha);
        wrong[0] = wrong[0] == '0' ? '1' : '0';
        c.spec.artifact_sha256 = wrong;
        ASSERT(!zcl_reflex_runner_run(&c.spec, &c.out));
        ASSERT(!c.out.available);
        ASSERT(!c.out.green);
        ASSERT(strstr(c.out.reason, "digest mismatch") != NULL);

        c.spec.artifact_sha256 = c.sha;
        c.spec.artifact_path = RR_DIR "absent.so";
        ASSERT(!zcl_reflex_runner_run(&c.spec, &c.out));
        ASSERT(!c.out.available);
        ASSERT(!c.out.green);
        ASSERT(strstr(c.out.reason, "unreadable") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* Timing census: the runner's own stage timings over RR_BENCH_RUNS warm green
 * runs, printed as p50/p95 so a before/after change is measured, not guessed. */
#define RR_BENCH_RUNS 40

static int rr_cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

static void rr_bench_print(const char *label, int64_t *v, size_t n)
{
    qsort(v, n, sizeof(v[0]), rr_cmp_i64);
    printf("%s p50=%lld p95=%lld ", label, (long long)v[n / 2],
           (long long)v[(n * 95) / 100]);
}

static int t_runner_stage_timings(void)
{
    int failures = 0;
    static int64_t fork_us[RR_BENCH_RUNS], confine_us[RR_BENCH_RUNS],
        dlopen_us[RR_BENCH_RUNS], story_us[RR_BENCH_RUNS],
        total_us[RR_BENCH_RUNS], wall_us[RR_BENCH_RUNS];
    TEST("reflex runner: stage timings over warm green runs") {
        struct rr_case warm;
        ASSERT(rr_prepare(&warm, "green", 1000));
        ASSERT(zcl_reflex_runner_run(&warm.spec, &warm.out));
        ASSERT(warm.out.green);
        for (size_t i = 0; i < RR_BENCH_RUNS; i++) {
            struct rr_case c;
            ASSERT(rr_prepare(&c, "green", 1000));
            int64_t started = platform_time_monotonic_us();
            ASSERT(zcl_reflex_runner_run(&c.spec, &c.out));
            wall_us[i] = platform_time_monotonic_us() - started;
            ASSERT(c.out.green);
            fork_us[i] = c.out.fork_us;
            confine_us[i] = c.out.confine_us;
            dlopen_us[i] = c.out.dlopen_us;
            story_us[i] = c.out.story_us;
            total_us[i] = c.out.runner_total_us;
        }
        printf("[runs=%d ", RR_BENCH_RUNS);
        rr_bench_print("fork_us", fork_us, RR_BENCH_RUNS);
        rr_bench_print("confine_us", confine_us, RR_BENCH_RUNS);
        rr_bench_print("dlopen_us", dlopen_us, RR_BENCH_RUNS);
        rr_bench_print("story_us", story_us, RR_BENCH_RUNS);
        rr_bench_print("total_us", total_us, RR_BENCH_RUNS);
        rr_bench_print("wall_us", wall_us, RR_BENCH_RUNS);
        printf("] ");
        PASS();
    } _test_next:;
    return failures;
}

/* ── unit proofs of the runner's own hygiene and parsing ─────────────────── */

#define RR_HIGH_FD 70000
#define RR_MID_FD 1500

static bool rr_fd_open(int fd) { return fcntl(fd, F_GETFD) >= 0; }

/* Raise RLIMIT_NOFILE so fd 70000 is legal where the hard limit allows it;
 * otherwise report that sub-case as SKIP with the reason. */
static int rr_fd_child_limit(bool *high)
{
    struct rlimit lim;
    if (getrlimit(RLIMIT_NOFILE, &lim) != 0) return 100;
    *high = lim.rlim_max == RLIM_INFINITY || lim.rlim_max > RR_HIGH_FD;
    lim.rlim_cur = *high ? (rlim_t)RR_HIGH_FD + 1 : lim.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &lim) != 0) return 101;
    if (!*high)
        printf("SKIP fd %d sub-case: hard RLIMIT_NOFILE=%llu <= %d; ",
               RR_HIGH_FD, (unsigned long long)lim.rlim_max, RR_HIGH_FD);
    return 0;
}

/* Descriptor proof setup, in the forked child: make 0..2 real, close
 * everything else but `result_fd` with the platform scrub (an independent
 * implementation, the ground truth), then open exactly one descriptor and
 * dup it to 1500 and (when *high) 70000. Returns 0 or a setup error code. */
static int rr_fd_child_setup(int result_fd, bool *high, int *base)
{
    int rc = rr_fd_child_limit(high);
    if (rc != 0) return rc;
    for (int fd = 0; fd < 3; fd++) {
        int null_fd = rr_fd_open(fd) ? fd : open("/dev/null", O_RDWR);
        if (null_fd < 0 || (null_fd != fd && dup2(null_fd, fd) != fd))
            return 106;
    }
    if (!os_proc_close_inherited_fds_except(result_fd)) return 102;
    *base = open("/dev/null", O_RDONLY);
    if (*base < 0 || dup2(*base, RR_MID_FD) != RR_MID_FD) return 103;
    if (*high && dup2(*base, RR_HIGH_FD) != RR_HIGH_FD) return 104;
    return 0;
}

/* close_range disabled: the enumeration fallback must close all three (or
 * two) descriptors, keep the kept ones, and the census must be exact both
 * before (3 or 2) and after (0). Returns the number of failed checks. */
static int rr_fd_child_fallback(const int keep[static 4], int base, bool high)
{
    int bad = 0;
    uint32_t want = high ? 3u : 2u;
    uint32_t counted = zcl_reflex_count_fds_except(keep, 4);
    if (counted != want)
        bad++, printf("count before close=%u want %u; ", counted, want);
    zcl_reflex_testing_use_close_range(false);
    if (!zcl_reflex_close_all_except(keep, 4))
        bad++, printf("fallback close returned false; ");
    if (rr_fd_open(base) || rr_fd_open(RR_MID_FD) ||
        (high && rr_fd_open(RR_HIGH_FD)))
        bad++, printf("fallback left fds open base=%d %d=%d %d=%d; ", base,
                      RR_MID_FD, rr_fd_open(RR_MID_FD), RR_HIGH_FD,
                      rr_fd_open(RR_HIGH_FD));
    for (size_t i = 0; i < 4; i++)
        if (!rr_fd_open(keep[i]))
            bad++, printf("kept fd %d lost; ", keep[i]);
    counted = zcl_reflex_count_fds_except(keep, 4);
    if (counted != 0) bad++, printf("count after close=%u; ", counted);
    return bad;
}

/* Enumeration impossible and close_range off: refuse, never "done". */
static int rr_fd_child_refusal(const int keep[static 4], int result_fd)
{
    int bad = 0;
    zcl_reflex_testing_set_fd_dir("/nonexistent/reflex-fd-dir");
    if (dup2(result_fd, RR_MID_FD) != RR_MID_FD) return 105;
    if (zcl_reflex_close_all_except(keep, 4))
        bad++, printf("close without enumeration returned true; ");
    if (zcl_reflex_count_fds_except(keep, 4) != UINT32_MAX)
        bad++, printf("census without enumeration did not fail closed; ");
    return bad;
}

/* Child body of the descriptor proof. Prints its own verdict lines and
 * returns the number of failed checks (exit status). */
static int rr_fd_child_run(int result_fd)
{
    const int keep[] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO, result_fd};
    bool high = false;
    int base = -1;
    int rc = rr_fd_child_setup(result_fd, &high, &base);
    if (rc != 0) return rc;
    return rr_fd_child_fallback(keep, base, high) +
        rr_fd_child_refusal(keep, result_fd);
}

static int t_fd_hygiene_without_close_range(void)
{
    int failures = 0;
    TEST("reflex runner: close_all_except without close_range closes fds "
         "1500 and 70000; census exact; no enumeration refuses") {
        int pfd[2];
        ASSERT(pipe2(pfd, O_CLOEXEC) == 0);
        (void)fflush(stdout);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            (void)close(pfd[0]);
            int rc = rr_fd_child_run(pfd[1]);
            (void)fflush(stdout);
            _exit(rc > 120 ? 120 : rc);
        }
        (void)close(pfd[1]);
        (void)close(pfd[0]);
        int status = 0;
        ASSERT(waitpid(child, &status, 0) == child);
        ASSERT(WIFEXITED(status));
        ASSERT_EQ(WEXITSTATUS(status), 0);
        PASS();
    } _test_next:;
    return failures;
}

static void rr_hex(char *dst, char c)
{
    memset(dst, c, 64);
    dst[64] = '\0';
}

static void rr_preload_valid(struct zcl_reflex_preload_frame *f)
{
    memset(f, 0, sizeof(*f));
    f->head = (struct zcl_reflex_report_head){
        .magic = ZCL_REFLEX_REPORT_MAGIC, .abi = ZCL_REFLEX_WIRE_ABI,
        .kind = ZCL_REFLEX_REPORT_PRELOAD, .size = sizeof(*f),
    };
    f->hash_verified = 1;
    f->sandboxed = 1;
    rr_hex(f->runtime_module_sha256, 'a');
    (void)snprintf(f->stage, sizeof(f->stage), "preload");
}

static void rr_observation_valid(struct zcl_reflex_observation_frame *f)
{
    memset(f, 0, sizeof(*f));
    f->head = (struct zcl_reflex_report_head){
        .magic = ZCL_REFLEX_REPORT_MAGIC, .abi = ZCL_REFLEX_WIRE_ABI,
        .kind = ZCL_REFLEX_REPORT_OBSERVATION, .size = sizeof(*f),
    };
    f->story_ok = 1;
    f->descriptor_valid = 1;
    f->candidate_executed = 1;
    (void)snprintf(f->observation.detail, sizeof(f->observation.detail), "ok");
    rr_hex(f->service.loaded_image_sha256, 'b');
}

/* One malformed preload: `why` must be non-NULL and name `field`. */
static bool rr_preload_refused(const struct zcl_reflex_preload_frame *f,
                               const char *field)
{
    const char *why = zcl_reflex_preload_invalid(f);
    printf("[%s -> %s] ", field, why ? why : "ACCEPTED");
    return why && strstr(why, field);
}

static bool rr_observation_refused(
    const struct zcl_reflex_observation_frame *f, const char *field)
{
    const char *why = zcl_reflex_observation_invalid(f);
    printf("[%s -> %s] ", field, why ? why : "ACCEPTED");
    return why && strstr(why, field);
}

static int t_report_strings_validated_before_use(void)
{
    int failures = 0;
    TEST("reflex runner: unterminated or malformed report fields are "
         "refused by name before any use") {
        struct zcl_reflex_preload_frame p;
        rr_preload_valid(&p);
        ASSERT(zcl_reflex_preload_invalid(&p) == NULL);
        rr_preload_valid(&p); memset(p.stage, 'x', sizeof(p.stage));
        ASSERT(rr_preload_refused(&p, "stage"));
        rr_preload_valid(&p); memset(p.error, 'x', sizeof(p.error));
        ASSERT(rr_preload_refused(&p, "error"));
        rr_preload_valid(&p);
        memset(p.runtime_module_sha256, 'a', sizeof(p.runtime_module_sha256));
        ASSERT(rr_preload_refused(&p, "runtime_module_sha256"));
        rr_preload_valid(&p); p.runtime_module_sha256[10] = 'A';
        ASSERT(rr_preload_refused(&p, "runtime_module_sha256"));
        rr_preload_valid(&p); p.runtime_module_sha256[63] = '\0';
        ASSERT(rr_preload_refused(&p, "runtime_module_sha256"));
        rr_preload_valid(&p); p.runtime_module_sha256[0] = '\0';
        ASSERT(rr_preload_refused(&p, "runtime_module_sha256"));
        rr_preload_valid(&p); p.sandboxed = 2;
        ASSERT(rr_preload_refused(&p, "sandboxed"));

        struct zcl_reflex_observation_frame o;
        rr_observation_valid(&o);
        ASSERT(zcl_reflex_observation_invalid(&o) == NULL);
        rr_observation_valid(&o);
        memset(o.observation.detail, 'x', sizeof(o.observation.detail));
        ASSERT(rr_observation_refused(&o, "observation.detail"));
        rr_observation_valid(&o);
        memset(o.observation.exercised_surface, 'x',
               sizeof(o.observation.exercised_surface));
        ASSERT(rr_observation_refused(&o, "observation.exercised_surface"));
        rr_observation_valid(&o); memset(o.stage, 'x', sizeof(o.stage));
        ASSERT(rr_observation_refused(&o, "stage"));
        rr_observation_valid(&o); memset(o.error, 'x', sizeof(o.error));
        ASSERT(rr_observation_refused(&o, "error"));
        rr_observation_valid(&o);
        memset(o.service.error, 'x', sizeof(o.service.error));
        ASSERT(rr_observation_refused(&o, "service.error"));
        rr_observation_valid(&o);
        memset(o.service.service_id, 'x', sizeof(o.service.service_id));
        ASSERT(rr_observation_refused(&o, "service.service_id"));
        rr_observation_valid(&o); o.service.loaded_image_sha256[5] = 'g';
        ASSERT(rr_observation_refused(&o, "service.loaded_image_sha256"));
        rr_observation_valid(&o);
        memset(o.service.loaded_image_sha3_256, 'c',
               sizeof(o.service.loaded_image_sha3_256));
        ASSERT(rr_observation_refused(&o, "service.loaded_image_sha3_256"));
        rr_observation_valid(&o); o.story_ok = 0xff;
        ASSERT(rr_observation_refused(&o, "story_ok"));
        rr_observation_valid(&o);
        unsigned char *svc = (unsigned char *)&o.service;
        svc[offsetof(struct zcl_hotswap_service_report, ok)] = 7;
        ASSERT(rr_observation_refused(&o, "service.ok"));
        PASS();
    } _test_next:;
    return failures;
}

struct rr_stream {
    uint8_t bytes[4 * sizeof(struct zcl_reflex_observation_frame)];
    size_t len;
};

static void rr_put(struct rr_stream *s, const void *frame, size_t len)
{
    memcpy(s->bytes + s->len, frame, len);
    s->len += len;
}

static bool rr_parse_is(const struct rr_stream *s, const char *label,
                        enum zcl_reflex_frames_status want,
                        struct zcl_reflex_frames *out)
{
    enum zcl_reflex_frames_status got =
        zcl_reflex_frames_parse(s->bytes, s->len, out);
    printf("[%s: %u \"%s\"] ", label, (unsigned)got,
           zcl_reflex_frames_reason(got));
    return got == want && out->status == (uint32_t)want &&
        (want == ZCL_REFLEX_FRAMES_OK ||
         zcl_reflex_frames_reason(got)[0] != '\0');
}

static int t_report_frames_parse_by_name(void)
{
    int failures = 0;
    TEST("reflex runner: two-frame report; missing, duplicate, out-of-order, "
         "wrong-size, unknown-kind and trailing bytes are named RED") {
        struct zcl_reflex_preload_frame p;
        struct zcl_reflex_observation_frame o;
        rr_preload_valid(&p);
        rr_observation_valid(&o);
        struct zcl_reflex_frames f;
        struct rr_stream s = {0};
        rr_put(&s, &p, sizeof(p)); rr_put(&s, &o, sizeof(o));
        ASSERT(rr_parse_is(&s, "valid", ZCL_REFLEX_FRAMES_OK, &f));
        ASSERT(f.preload_present && f.observation_present);
        ASSERT_STR_EQ(f.preload.runtime_module_sha256, p.runtime_module_sha256);
        ASSERT_STR_EQ(f.observation.observation.detail, "ok");

        s.len = 0;
        ASSERT(rr_parse_is(&s, "empty", ZCL_REFLEX_FRAMES_PRELOAD_MISSING, &f));
        ASSERT(!f.preload_present);
        rr_put(&s, &p, sizeof(p));
        ASSERT(rr_parse_is(&s, "preload-only",
                           ZCL_REFLEX_FRAMES_OBSERVATION_MISSING, &f));
        ASSERT(f.preload_present && !f.observation_present);
        s.len = 0; rr_put(&s, &o, sizeof(o)); rr_put(&s, &p, sizeof(p));
        ASSERT(rr_parse_is(&s, "out-of-order", ZCL_REFLEX_FRAMES_OUT_OF_ORDER,
                           &f));
        ASSERT(!f.preload_present);
        s.len = 0; rr_put(&s, &p, sizeof(p)); rr_put(&s, &p, sizeof(p));
        ASSERT(rr_parse_is(&s, "second-preload", ZCL_REFLEX_FRAMES_DUPLICATE,
                           &f));
        s.len = 0; rr_put(&s, &p, sizeof(p)); rr_put(&s, &o, sizeof(o));
        rr_put(&s, &o, sizeof(o));
        ASSERT(rr_parse_is(&s, "second-observation",
                           ZCL_REFLEX_FRAMES_DUPLICATE, &f));
        ASSERT(!f.observation_present || f.status != ZCL_REFLEX_FRAMES_OK);
        s.len = 0; rr_put(&s, &p, sizeof(p)); rr_put(&s, &o, sizeof(o));
        rr_put(&s, "z", 1);
        ASSERT(rr_parse_is(&s, "trailing", ZCL_REFLEX_FRAMES_TRAILING, &f));
        s.len = 0; rr_put(&s, &p, sizeof(p)); rr_put(&s, &o, sizeof(o) / 2);
        ASSERT(rr_parse_is(&s, "truncated", ZCL_REFLEX_FRAMES_TRUNCATED, &f));

        struct zcl_reflex_preload_frame bad = p;
        bad.head.magic ^= 1u;
        s.len = 0; rr_put(&s, &bad, sizeof(bad)); rr_put(&s, &o, sizeof(o));
        ASSERT(rr_parse_is(&s, "magic", ZCL_REFLEX_FRAMES_BAD_MAGIC, &f));
        bad = p; bad.head.abi = ZCL_REFLEX_WIRE_ABI - 1u;
        s.len = 0; rr_put(&s, &bad, sizeof(bad)); rr_put(&s, &o, sizeof(o));
        ASSERT(rr_parse_is(&s, "abi", ZCL_REFLEX_FRAMES_BAD_ABI, &f));
        bad = p; bad.head.kind = 9u;
        s.len = 0; rr_put(&s, &bad, sizeof(bad)); rr_put(&s, &o, sizeof(o));
        ASSERT(rr_parse_is(&s, "kind", ZCL_REFLEX_FRAMES_UNKNOWN_KIND, &f));
        bad = p; bad.head.size = sizeof(bad) - 8u;
        s.len = 0; rr_put(&s, &bad, sizeof(bad)); rr_put(&s, &o, sizeof(o));
        ASSERT(rr_parse_is(&s, "size", ZCL_REFLEX_FRAMES_WRONG_SIZE, &f));
        struct zcl_reflex_observation_frame obad = o;
        obad.head.kind = 77u;
        s.len = 0; rr_put(&s, &p, sizeof(p)); rr_put(&s, &obad, sizeof(obad));
        ASSERT(rr_parse_is(&s, "observation-kind",
                           ZCL_REFLEX_FRAMES_UNKNOWN_KIND, &f));
        ASSERT(f.preload_present && !f.observation_present);
        PASS();
    } _test_next:;
    return failures;
}

/* The leaf closes its end of the report pipe, then refuses to exit. */
static int t_reap_is_bounded_after_eof(void)
{
    int failures = 0;
    TEST("reflex runner: a leaf that closes its pipe and sleeps is killed "
         "at the deadline and reaped") {
        int pfd[2];
        ASSERT(pipe2(pfd, O_CLOEXEC) == 0);
        (void)fflush(stdout);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            (void)close(pfd[0]);
            (void)close(pfd[1]);
            (void)sleep(3);
            _exit(0);
        }
        (void)close(pfd[1]);
        char byte;
        ssize_t n;
        do { n = read(pfd[0], &byte, 1); } while (n < 0 && errno == EINTR);
        (void)close(pfd[0]);
        ASSERT_EQ(n, 0);
        int64_t started = platform_time_monotonic_us();
        struct zcl_reflex_reap reap;
        zcl_reflex_reap_bounded(child, started + 200000, &reap);
        int64_t waited = platform_time_monotonic_us() - started;
        printf("[waited=%lldus killed=%d signal=%d exit=%d filters_read=%d] ",
               (long long)waited, reap.killed_at_deadline, reap.signal,
               reap.exit_code, reap.filters_read);
        ASSERT(reap.reaped);
        ASSERT(reap.killed_at_deadline);
        ASSERT_EQ(reap.signal, SIGKILL);
        ASSERT(waited >= 150000 && waited < 1500000);

        (void)fflush(stdout);
        pid_t quick = fork();
        ASSERT(quick >= 0);
        if (quick == 0) _exit(7);
        started = platform_time_monotonic_us();
        zcl_reflex_reap_bounded(quick, started + 2000000, &reap);
        waited = platform_time_monotonic_us() - started;
        ASSERT(reap.reaped && !reap.killed_at_deadline);
        ASSERT_EQ(reap.exit_code, 7);
        ASSERT(reap.filters_read);
        ASSERT(waited < 1000000);
        PASS();
    } _test_next:;
    return failures;
}

/* F1 regression: the runner's post-Landlock descriptor close must not
 * reopen /proc/self/fd (Landlock now refuses it) when close_range is
 * unavailable. The only way to drive a REAL leaf down that fallback is the
 * ZCL_TESTING-only wire flag (never an env var: the runner execs with an
 * empty environment and cannot see one). A green candidate must stay green
 * and leave no descriptor behind even on the enumeration path. */
static int t_green_survives_leaf_close_without_close_range(void)
{
    int failures = 0;
    TEST("reflex runner: green candidate confines via the Landlock-safe "
         "enumeration fallback when close_range is disabled") {
        struct rr_case c;
        ASSERT(rr_run_with(&c, "green", 1000, true));
        ASSERT(c.out.green);
        ASSERT(rr_confined(&c.out));
        ASSERT(c.out.report.wx_installed);

        struct rr_case after;
        ASSERT(rr_run(&after, "green", 1000));
        ASSERT(after.out.green);
        ASSERT_EQ(after.out.runner_pid, c.out.runner_pid);
        PASS();
    } _test_next:;
    return failures;
}

/* F4(a): a story that writes a second well-formed pre-load-kind frame
 * after it runs, aimed at every descriptor above 2 since it cannot know the
 * report pipe's number. The runner must name this a duplicated frame and
 * never say green. */
static int t_hostile_story_duplicate_frame_is_red(void)
{
    int failures = 0;
    TEST("reflex runner: a story-injected duplicate pre-load frame is red "
         "by the duplicated-frame name, never green") {
        struct rr_case c;
        ASSERT(rr_run(&c, "dupframe", 1000));
        ASSERT(c.out.available);
        ASSERT(!c.out.green);
        ASSERT(!c.out.report_complete);
        ASSERT_STR_EQ(c.out.reason, "leaf report: duplicated frame");

        struct rr_case after;
        ASSERT(rr_run(&after, "green", 1000));
        ASSERT(after.out.green);
        ASSERT_EQ(after.out.runner_pid, c.out.runner_pid);
        PASS();
    } _test_next:;
    return failures;
}

/* F4(b): a story that closes every descriptor above 2 (the report pipe
 * among them, whatever its number) then never returns. The runner must see
 * EOF, still kill the leaf at the deadline, name it the bounded-reap
 * reason, and survive. */
static int t_leaf_closes_pipe_then_outlives_deadline(void)
{
    int failures = 0;
    TEST("reflex runner: a leaf that closes its own report pipe then spins "
         "past the deadline is killed and named by the bounded-reap "
         "reason; the runner survives") {
        struct rr_case c;
        ASSERT(rr_run(&c, "reapclose", 300));
        ASSERT(c.out.available);
        ASSERT(!c.out.green);
        ASSERT_EQ(c.out.child_signal, SIGKILL);
        ASSERT(c.out.timed_out);
        ASSERT(c.wall_us >= 250000 && c.wall_us < 3000000);
        ASSERT_STR_EQ(c.out.reason, "leaf outlived its deadline after "
                      "closing its report pipe");
        int runner_pid = c.out.runner_pid;

        struct rr_case after;
        ASSERT(rr_run(&after, "green", 1000));
        ASSERT(after.out.green);
        ASSERT_EQ(after.out.runner_pid, runner_pid);
        PASS();
    } _test_next:;
    return failures;
}

/* F2: SIG_IGN on SIGCHLD survives exec, and under it the kernel auto-reaps
 * every exiting child, so a runner that kept it could never waitid() its
 * leaf (nor its startup deny probes). The resident spawns a fresh runner
 * while SIGCHLD is ignored; the runner must reset the disposition itself and
 * still reap, observe the W^X layer and say green. The resident's own
 * disposition is restored before any assert can leave the case. */
static int t_runner_resets_inherited_sigchld_ignore(void)
{
    int failures = 0;
    TEST("reflex runner: a runner exec'd under an inherited SIGCHLD SIG_IGN "
         "still reaps its leaf and says green") {
        struct sigaction ignore = {.sa_handler = SIG_IGN};
        struct sigaction saved;
        zcl_reflex_runner_shutdown();
        ASSERT(sigaction(SIGCHLD, &ignore, &saved) == 0);
        struct rr_case c;
        bool ran = rr_run(&c, "green", 1000);
        bool restored = sigaction(SIGCHLD, &saved, NULL) == 0;
        ASSERT(restored);
        ASSERT(ran);
        ASSERT(!c.out.runner_warm);
        ASSERT(c.out.green);
        ASSERT(rr_confined(&c.out));
        ASSERT(c.out.report.wx_installed);
        ASSERT_EQ(c.out.child_exit_code, 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_reflex_runner(void);
int test_reflex_runner(void)
{
    printf("\n=== clean-zygote reflex runner: real candidate images ===\n");
    int failures = 0;
    failures += t_hostile_candidate_sees_fresh_closed_world();
    failures += t_green_then_regression_keeps_accepted_root();
    failures += t_hang_and_crash_do_not_kill_runner();
    failures += t_socket_and_wx_are_killed();
    failures += t_kernel_escape_surfaces_are_denied();
    failures += t_unverifiable_artifact_fails_closed();
    failures += t_runner_stage_timings();
    failures += t_fd_hygiene_without_close_range();
    failures += t_report_strings_validated_before_use();
    failures += t_report_frames_parse_by_name();
    failures += t_reap_is_bounded_after_eof();
    failures += t_green_survives_leaf_close_without_close_range();
    failures += t_hostile_story_duplicate_frame_is_red();
    failures += t_leaf_closes_pipe_then_outlives_deadline();
    failures += t_runner_resets_inherited_sigchld_ignore();
    zcl_reflex_runner_shutdown();
    printf("=== reflex_runner: %d failures ===\n", failures);
    return failures;
}

#endif /* __linux__ */
