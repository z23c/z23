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
#include "platform/time_compat.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static bool rr_run(struct rr_case *c, const char *kind, uint32_t timeout_ms)
{
    if (!rr_prepare(c, kind, timeout_ms)) return false;
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
        ASSERT(c.out.reason[0] != '\0');

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
    zcl_reflex_runner_shutdown();
    printf("=== reflex_runner: %d failures ===\n", failures);
    return failures;
}

#endif /* __linux__ */
