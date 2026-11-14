/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: base watch, phase mail and digest, producer recovery, evidence and status.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"
#include "command/native_dev_proof_command.h"
#include "zutf8/zutf8.h"

#if !defined(_WIN32)

static bool dlx_proof_fixture_input(int argc, char **argv, struct json_value *input)
{
    json_set_object(input);
    for (int i = 5; i < argc; i++) {
        const char *equal = strchr(argv[i], '='); char key[80];
        if (strncmp(argv[i], "--", 2) || !equal || equal - argv[i] <= 2 ||
            (size_t)(equal - argv[i] - 2) >= sizeof(key)) return false;
        size_t len = (size_t)(equal - argv[i] - 2); memcpy(key, argv[i] + 2, len); key[len] = '\0';
        if (!json_push_kv_str(input, key, equal + 1)) return false;
    }
    return true;
}

static void dlx_proof_fixture_step(int argc, char **argv,
                                   const struct zcl_command_registry *registry)
{
    char wire[32768];
    if (argc < 8 || strcmp(argv[2], "dev") || strcmp(argv[3], "proof") || strcmp(argv[4], "step")) _exit(2);
    const struct zcl_command_spec *original = zcl_command_registry_find(registry, "dev.proof.step", NULL);
    if (!original) _exit(2);
    struct zcl_command_spec spec = *original;
    spec.availability = ZCL_COMMAND_READY; spec.compat_target = "";
    spec.handler = zcl_native_dev_proof_dispatch;
    struct json_value input = {0};
    if (!dlx_proof_fixture_input(argc, argv, &input)) _exit(2);
    struct zcl_command_context context = { .registry = registry, .operator_lane = "dev",
        .granted_capabilities = UINT64_MAX, .authority_ceiling = ZCL_COMMAND_AUTH_OWNER, .dev_build = true };
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(registry, &spec, &context, &input,
        false, spec.path, NULL, 0, 0, NULL, wire, sizeof(wire), &code);
    json_free(&input);
    if (!n || n >= sizeof(wire)) _exit(2);
    if (write(STDOUT_FILENO, wire, n) != (ssize_t)n) _exit(2);
    _exit((int)code);
}

/* The runner re-execs itself only for this exact fixture arm. It restores the
 * one development descriptor's handler; all schema checks remain real. */
void dev_proof_fixture_exit_if_requested(int argc, char **argv)
{
    if (argc < 2 || strcmp(argv[1], "--dev-proof-fixture")) return;
    (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
    const struct zcl_command_registry *registry = zcl_command_catalog();
    if (argc == 5 && !strcmp(argv[2], "discover") && !strcmp(argv[3], "describe") &&
        !strcmp(argv[4], "--input={\"path\":\"dev.proof.step\"}")) {
        char wire[32768]; size_t n = zcl_command_registry_describe_json(registry, "dev.proof.step", wire, sizeof(wire));
        if (!n || n >= sizeof(wire) || write(STDOUT_FILENO, wire, n) != (ssize_t)n) _exit(2);
        _exit(0);
    }
    dlx_proof_fixture_step(argc, argv, registry);
}

void zcl_dev_land_test_first_actionable(const char *text, char *out, size_t cap);

/* CANONICAL_LIFECYCLE.md correctness scenarios, `lifecycle_candidate_race`
 * (two candidates, same base, exactly one accepted): the first candidate
 * lands; the second, built on the same base, is rebased onto the new main
 * and re-proved, is never dispatched on the stale base, and the first landed
 * commit stays an ancestor of remote main.  Publishing the rebuilt pair
 * needs a fresh signed intent. */
int test_dev_land_two_candidates_same_base(void)
{
    int failures = 0;
    TEST("land: a second candidate on the same base never overwrites the first landed commit") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], first[64], second[64], remote[64], wt[1400];
        char marker[1400];
        dlx_isolate("two_candidates");
        ASSERT(dlx_signed_push_lossy(&rig, "two_candidates", base, wt,
                                     marker, NULL));
        (void)snprintf(first, sizeof(first), "%s", rig.tip);
        ASSERT(dlx_dispatch_script(marker, "exec git-receive-pack \"$@\"\n"));
        const char *branch[] = { "checkout", "--quiet", "-B", "second", base,
                                 NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "second.txt", "second\n", second));
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, second);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 2);
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_EQ(dlx_int(&c, "seq"), 1);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, first);
        for (unsigned i = 0; i < 3; i++) {
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            if (i == 0) {
                ASSERT(dlx_ok(&c));
                ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
                ASSERT_EQ(dlx_int(&c, "seq"), 2);
            } else {
                ASSERT(!dlx_ok(&c));
                ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_REQUIRED");
            }
            dlx_end(&c);
            ASSERT(dlx_marker_lines(marker, 1));
            ASSERT(dlx_origin_main(&rig, remote));
            ASSERT(strcmp(remote, second) != 0);
            ASSERT(dlx_is_ancestor(rig.bare, first, "refs/heads/main"));
        }
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

#endif

/* Submit the rig's tip and take the first step to a started proof. */
static bool dlx_started(struct dlx_rig *rig, const char *tag,
                        const char *rig_tag)
{
    struct dlx_call c;
    dlx_isolate(tag);
    if (!dlx_rig_make(rig, rig_tag))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    bool submitted = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_begin(&c, "step");
    bool started = submitted && dlx_run(&c) && dlx_ok(&c) &&
                   strcmp(dlx_str(&c, "state"), "started") == 0;
    dlx_end(&c);
    return started;
}

/* One step under `stub`; true when it answered `state` at `attempt`. */
static bool dlx_step_to(const char *stub, const char *state, int64_t attempt,
                        const char *detail_part)
{
    struct dlx_call c;
    setenv("ZCL_LAND_PROOF_STUB", stub, 1);
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              strcmp(dlx_str(&c, "state"), state) == 0 &&
              (attempt <= 0 || dlx_int(&c, "attempt") == attempt) &&
              (!detail_part || strstr(dlx_str(&c, "detail"), detail_part));
    dlx_end(&c);
    return ok;
}

#if !defined(_WIN32)
/* ── the drive's base watch over a real proof step ───────────────────────
 *
 * The forked worker stands in for the proof worker around ONE real proof
 * step: the production step runner (own session; TERM, then KILL, of its
 * process group on cancel) runs `argv`, under the SIGTERM handler the real
 * worker inherits from its requester (a cancel request). The requester side
 * is the drive's own base probe (dl_base_probe) through the proof's own
 * wait loop, against a real bare origin. Only the step's command is a
 * stand-in for the proof. */
static void dlx_watch_worker_cancel(int signal_number)
{
    (void)signal_number;
    zcl_devloop_process_cancel_request();
}

static void dlx_watch_worker_run(const char *dir, const char *const argv[],
                                 int report_fd)
{
    struct sigaction action = {0};
    action.sa_handler = dlx_watch_worker_cancel;
    sigemptyset(&action.sa_mask);
    zcl_devloop_process_cancel_clear();
    char log[1200];
    struct zcl_dev_proof_step step;
    const struct zcl_dev_proof_budget budget =
        zcl_dev_proof_budget_make(600000, 600000);
    int64_t report[3] = { -1, -1, -1 };
    if (sigaction(SIGTERM, &action, NULL) == 0 &&
        snprintf(log, sizeof(log), "%s.step.log", dir) < (int)sizeof(log) &&
        zcl_dev_proof_step_start(&step, dir, log, argv, &budget)) {
        report[0] = step.child;
        if (write(report_fd, &report[0], sizeof(report[0])) !=
            (ssize_t)sizeof(report[0]))
            _exit(1);
        (void)zcl_dev_proof_steps_wait(&step, 1);
        report[1] = (int64_t)step.report.cause;
        report[2] = (int64_t)step.report.rc;
    } else if (write(report_fd, &report[0], sizeof(report[0])) !=
               (ssize_t)sizeof(report[0])) {
        _exit(1);
    }
    _exit(write(report_fd, &report[1], 2 * sizeof(report[1])) ==
                  (ssize_t)(2 * sizeof(report[1]))
              ? 0 : 1);
}

struct dlx_watched {
    int64_t step_child; /* the proof step's session leader */
    int64_t cause;      /* enum zcl_dev_proof_kill_cause of the step's end */
    int64_t rc;
    int waited;         /* what the drive's watched wait returned */
    bool superseded;
};

/* Start the worker, let `move` (when non-NULL) push a stranger commit to
 * origin main once the step is running, then watch the worker exactly as
 * a proving drive does until it exits. */
static bool dlx_watch_proof(const struct dlx_rig *rig, const char *base,
                            const char *const argv[], const char *move,
                            struct dlx_watched *out)
{
    int fds[2];
    char stranger[64];
    memset(out, 0, sizeof(*out));
    if (pipe(fds) != 0) return false;
    pid_t worker = fork();
    if (worker == 0) {
        (void)close(fds[0]);
        dlx_watch_worker_run(rig->bare, argv, fds[1]);
    }
    (void)close(fds[1]);
    bool ok = worker > 0 &&
        read(fds[0], &out->step_child, sizeof(out->step_child)) ==
            (ssize_t)sizeof(out->step_child) &&
        out->step_child > 0;
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    if (ok && move)
        ok = dlx_commit(rig->clone, move, "elsewhere\n", stranger) &&
             dlx_git(rig->clone, push) == 0;
    if (worker > 0) {
        if (!ok) (void)kill(worker, SIGTERM);
        out->waited = zcl_native_dev_land_test_watch_worker(
            rig->clone, base, (int)worker, 20, &out->superseded);
    }
    int64_t tail[2] = { -1, -1 };
    ok = ok && read(fds[0], tail, sizeof(tail)) == (ssize_t)sizeof(tail);
    (void)close(fds[0]);
    out->cause = tail[0];
    out->rc = tail[1];
    return ok;
}

/* The step's session leader is gone, and nothing is left in its group. */
static bool dlx_step_group_gone(int64_t leader)
{
    errno = 0;
    bool leader_gone = kill((pid_t)leader, 0) != 0 && errno == ESRCH;
    errno = 0;
    bool group_gone = kill(-(pid_t)leader, 0) != 0 && errno == ESRCH;
    return leader_gone && group_gone;
}

struct dlx_external_cancel {
    struct dlx_rig rig; char queue[8192], maker[1400], ready[1400], outcome[1400], root[1400];
    int fds[2]; pid_t child;
};

static bool dlx_external_cancel_start(struct dlx_external_cancel *x, int mode)
{
    char exe[4096], script[1800], land[1200]; size_t n = 0;
    if (!dlx_started(&x->rig, "external_cancel", "external_cancel_rig") ||
        !dlx_queue_bytes(x->queue, sizeof(x->queue), &n) || !os_proc_exe_path(exe, sizeof(exe))) return false;
    dlx_land_wt(x->root, sizeof(x->root));
    (void)snprintf(x->maker, sizeof(x->maker), "%s/fake-make", x->rig.clone);
    (void)snprintf(x->ready, sizeof(x->ready), "%s/held-step.pid", x->rig.clone);
    dlx_landdir(land, sizeof(land)); (void)snprintf(x->outcome, sizeof(x->outcome), "%s/outcomes.jsonl", land);
    (void)snprintf(script, sizeof(script), "#!/bin/sh\nmkdir -p \"$3/build/bin\" || exit 1\nprintf '%%s\\n' '#!/bin/sh' 'exec \"$ZCL_PROOF_FIXTURE_BINARY\" --dev-proof-fixture \"$@\"' > \"$3/build/bin/z23-dev\"\nchmod 700 \"$3/build/bin/z23-dev\"\n");
    if (!dlx_write(x->maker, script) || chmod(x->maker, 0700) || pipe(x->fds)) return false;
    (void)setenv("ZCL_PROOF_FIXTURE_BINARY", exe, 1);
    (void)setenv("ZCL_PROOF_TEST_HELD_STEP", x->ready, 1);
    if (mode == 1) (void)setenv("ZCL_PROOF_TEST_ABNORMAL", "1", 1);
    if (mode == 2) (void)setenv("ZCL_PROOF_TEST_WAIT_ERROR", "1", 1);
    x->child = fork();
    if (x->child == 0) {
        close(x->fds[0]);
        int rc = zcl_native_dev_land_test_boundary_reproof(x->queue, x->root, x->maker);
        if (write(x->fds[1], &rc, sizeof(rc)) != (ssize_t)sizeof(rc)) _exit(2);
        _exit(0);
    }
    close(x->fds[1]);
    if (x->child < 0) { close(x->fds[0]); return false; }
    return true;
}

struct dlx_external_result {
    bool exists, cancelled, captured, joined, unchanged;
    int result; long pid;
};

static void dlx_external_cancel_observe(struct dlx_external_cancel *x,
                                        struct dlx_external_result *out)
{
    struct dlx_call c; char before[8192], after[8192], pidtext[64];
    size_t before_n = 0, after_n = 0; int status = 0;
    for (int i = 0; i < 300 && !out->exists; i++) {
        out->exists = dlx_file_exists(x->ready); if (!out->exists) platform_sleep_ms(20); /* real-clock: external requester and owned OS process coordinate through a readiness file. */
    }
    dlx_begin(&c, "cancel"); (void)json_push_kv_int(&c.input, "seq", 1);
    out->cancelled = dlx_run(&c) && dlx_ok(&c); dlx_end(&c);
    out->captured = dlx_slurp(x->outcome, before, sizeof(before), &before_n);
    out->joined = dlx_wait_child(x->child, &status) == x->child && WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                  read(x->fds[0], &out->result, sizeof(out->result)) == (ssize_t)sizeof(out->result);
    close(x->fds[0]);
    size_t pn = 0; bool read_pid = dlx_slurp(x->ready, pidtext, sizeof(pidtext) - 1, &pn); pidtext[pn] = '\0';
    out->pid = read_pid ? strtol(pidtext, NULL, 10) : -1;
    out->unchanged = dlx_slurp(x->outcome, after, sizeof(after), &after_n) && before_n == after_n &&
                     memcmp(before, after, before_n) == 0;
}

static bool dlx_external_cancel_request(int mode)
{
    struct dlx_external_cancel x; struct dlx_external_result observed = {0};
    if (!dlx_external_cancel_start(&x, mode)) {
        unsetenv("ZCL_PROOF_FIXTURE_BINARY"); unsetenv("ZCL_PROOF_TEST_HELD_STEP");
        unsetenv("ZCL_PROOF_TEST_ABNORMAL"); unsetenv("ZCL_PROOF_TEST_WAIT_ERROR");
        dlx_restore(); return false;
    }
    dlx_external_cancel_observe(&x, &observed);
    unsetenv("ZCL_PROOF_FIXTURE_BINARY"); unsetenv("ZCL_PROOF_TEST_HELD_STEP");
    unsetenv("ZCL_PROOF_TEST_ABNORMAL"); unsetenv("ZCL_PROOF_TEST_WAIT_ERROR"); dlx_restore();
    bool gone = observed.pid > 1 && dlx_step_group_gone(observed.pid);
    if (mode == 1) for (int i = 0; i < 200 && !gone; i++) {
        platform_sleep_ms(20); gone = observed.pid > 1 && dlx_step_group_gone(observed.pid); /* real-clock: observe the separately sessioned OS process group disappear. */
    }
    bool ok = observed.exists && observed.cancelled && observed.captured && observed.joined &&
              (mode ? observed.result != -3 : observed.result == -3) && gone && observed.unchanged;
    if (!ok) fprintf(stderr, "external cancel fixture: ready=%d cancelled=%d outcome=%d joined=%d result=%d pid=%ld gone=%d unchanged=%d\n",
                     observed.exists, observed.cancelled, observed.captured, observed.joined,
                     observed.result, observed.pid, gone, observed.unchanged);
    return ok;
}

static int dlx_external_proof_call(const char *exe, const char *root,
                                   const char *local, const char *base,
                                   const char *binding, char out[8192])
{
    char root_arg[1500], local_arg[128], base_arg[128], binding_arg[128];
    if (snprintf(root_arg, sizeof(root_arg), "--root=%s", root) >= (int)sizeof(root_arg) ||
        snprintf(local_arg, sizeof(local_arg), "--local_commit=%s", local) >= (int)sizeof(local_arg) ||
        snprintf(base_arg, sizeof(base_arg), "--remote_base=%s", base) >= (int)sizeof(base_arg) ||
        snprintf(binding_arg, sizeof(binding_arg), "--land_cancel_binding=%s", binding) >= (int)sizeof(binding_arg)) return -1;
    const char *argv[] = {exe, "--dev-proof-fixture", "dev", "proof", "step",
                          root_arg, local_arg, base_arg, binding_arg, NULL};
    bool timeout = false;
    int rc = zcl_spawn_capture_observed(argv, out, 8192, 10000, &timeout);
    return timeout ? -1 : rc;
}

static bool dlx_external_binding_unknown(const char *exe, const char *root,
    const char *local, const char *base, const char *binding, const char *ready)
{
    char out[8192];
    return dlx_external_proof_call(exe, root, local, base, binding, out) == 1 &&
           strstr(out, "PROOF_BINDING_UNKNOWN") && !dlx_file_exists(ready);
}

static bool dlx_external_cancelled_controls(const char *exe, const char *root,
    const char *local, const char *base, char *binding, const char *outcome,
    const char *saved, size_t len, const char *ready)
{
    char out[8192], altered[8192];
    if (dlx_external_proof_call(exe, root, local, base, binding, out) != 1 ||
        !strstr(out, "PROOF_CANCELLED") || dlx_file_exists(ready)) return false;
    memcpy(altered, saved, len + 1);
    char *field = strstr(altered, "\"local\":\""); if (!field) return false;
    field += strlen("\"local\":\""); if (strlen(field) < 40) return false;
    memmove(field, field + 40, strlen(field + 40) + 1);
    if (!dlx_write(outcome, altered) || !dlx_external_binding_unknown(exe, root, local, base, binding, ready)) return false;
    if (!dlx_write(outcome, "{partial") || !dlx_external_binding_unknown(exe, root, local, base, binding, ready)) return false;
    if (!dlx_write(outcome, saved)) return false;
    binding[strlen(binding) - 1] = binding[strlen(binding) - 1] == '0' ? '1' : '0';
    return dlx_external_binding_unknown(exe, root, local, base, binding, ready);
}

static bool dlx_external_wrong_root(const char *exe, const char *root, const char *local,
                                    const char *base, const char *binding, char *out,
                                    const char *ready)
{
    return dlx_external_proof_call(exe, root, local, base, binding, out) == 1 &&
           strstr(out, "PROOF_BINDING_UNKNOWN") && !dlx_file_exists(ready);
}

static bool dlx_external_prelaunch_controls(void)
{
    struct dlx_rig rig; struct dlx_call c; char queue[8192], exe[4096], binding[96];
    char local[80], base[80], out[8192], land[1200], outcome[1400], saved[8192], ready[1400], root[1400];
    size_t n = 0, len = 0; bool ok = false; struct json_value row = {0};
    if (!dlx_started(&rig, "external_prelaunch", "external_prelaunch_rig") ||
        !dlx_queue_bytes(queue, sizeof(queue), &n) || !json_read(&row, queue, n) ||
        !zcl_native_dev_land_test_cancel_binding(queue, binding) || !os_proc_exe_path(exe, sizeof(exe))) goto done;
    (void)snprintf(local, sizeof(local), "%s", json_get_str(json_get(&row, "local")));
    (void)snprintf(base, sizeof(base), "%s", json_get_str(json_get(&row, "base")));
    dlx_land_wt(root, sizeof(root));
    (void)snprintf(ready, sizeof(ready), "%s/prelaunch.pid", rig.clone);
    (void)setenv("ZCL_PROOF_TEST_HELD_STEP", ready, 1);
    if (!dlx_external_wrong_root(exe, rig.clone, local, base, binding, out, ready)) goto done;
    (void)setenv("ZCL_PROOF_TEST_NORMAL", "1", 1);
    if (dlx_external_proof_call(exe, root, local, base, binding, out) != 3 ||
        !strstr(out, "PROOF_WAIT_TIMEOUT") || !dlx_file_exists(ready)) goto done;
    (void)unsetenv("ZCL_PROOF_TEST_NORMAL");
    if (unlink(ready)) goto done;
    dlx_begin(&c, "cancel"); (void)json_push_kv_int(&c.input, "seq", 1);
    bool cancelled = dlx_run(&c) && dlx_ok(&c); dlx_end(&c);
    dlx_landdir(land, sizeof(land)); (void)snprintf(outcome, sizeof(outcome), "%s/outcomes.jsonl", land);
    if (!cancelled || !dlx_slurp(outcome, saved, sizeof(saved) - 1, &len)) goto done;
    saved[len] = '\0';
    ok = dlx_external_cancelled_controls(exe, root, local, base, binding, outcome, saved, len, ready);
done:
    unsetenv("ZCL_PROOF_TEST_HELD_STEP"); unsetenv("ZCL_PROOF_TEST_NORMAL");
    json_free(&row); dlx_restore(); return ok;
}

int test_dev_land_drive_base_watch(void)
{
    int failures = 0;
    TEST("land drive: candidate capability requires a complete typed descriptor") {
        const char old[] = "{\"path\":\"dev.proof.step\",\"input_schema\":{\"id\":\"zcl.dev_proof_step_input.v1\",\"allowed_keys\":[\"root\",\"local_commit\",\"remote_base\"]}}";
        const char current[] = "{\"path\":\"dev.proof.step\",\"input_schema\":{\"id\":\"zcl.dev_proof_step_input.v1\",\"allowed_keys\":[\"root\",\"local_commit\",\"remote_base\",\"land_cancel_binding\"]}}";
        const char duplicate[] = "{\"path\":\"dev.proof.step\",\"input_schema\":{\"id\":\"zcl.dev_proof_step_input.v1\",\"allowed_keys\":[\"root\",\"local_commit\",\"remote_base\",\"root\"]}}";
        ASSERT_EQ(zcl_native_dev_land_test_cancel_schema(old, strlen(old)), 0);
        ASSERT_EQ(zcl_native_dev_land_test_cancel_schema(current, strlen(current)), 1);
        ASSERT_EQ(zcl_native_dev_land_test_cancel_schema(current, strlen(current) - 1), -1);
        ASSERT_EQ(zcl_native_dev_land_test_cancel_schema(duplicate, strlen(duplicate)), -1);
        PASS();
    }
    TEST("land drive: cancellation acknowledgement needs a complete exact failed envelope") {
        const char good[] = "{\"schema\":\"zcl.result.v1\",\"command\":\"dev.proof.step\",\"status\":\"failed\",\"ok\":false,\"error\":{\"code\":\"PROOF_CANCELLED\"}}";
        const char wrong[] = "{\"schema\":\"zcl.result.v1\",\"command\":\"other\",\"status\":\"failed\",\"ok\":false,\"error\":{\"code\":\"PROOF_CANCELLED\"}}";
        char trailing[sizeof(good) + 2]; memcpy(trailing, good, sizeof(good));
        trailing[sizeof(good)] = 'x'; trailing[sizeof(good) + 1] = '\0';
        ASSERT(zcl_native_dev_land_test_cancel_response(good, strlen(good), true, false, false));
        ASSERT(!zcl_native_dev_land_test_cancel_response(wrong, strlen(wrong), true, false, false));
        ASSERT(!zcl_native_dev_land_test_cancel_response(good, strlen(good), false, false, false));
        ASSERT(!zcl_native_dev_land_test_cancel_response(good, strlen(good), true, true, false));
        ASSERT(!zcl_native_dev_land_test_cancel_response(good, strlen(good), true, false, true));
        ASSERT(!zcl_native_dev_land_test_cancel_response(good, strlen(good) - 1, true, false, false));
        ASSERT(!zcl_native_dev_land_test_cancel_response(trailing, sizeof(good) + 1, true, false, false));
        trailing[sizeof(good) - 1] = 'x';
        ASSERT(!zcl_native_dev_land_test_cancel_response(trailing, sizeof(good), true, false, false));
        PASS();
    }
    TEST("land drive: failed owned waits leave cleanup unconfirmed") {
        struct zcl_dev_proof_step step = { .child = (int64_t)getpid(), .started = true };
        zcl_devloop_process_cleanup_reset();
        ASSERT(zcl_dev_proof_step_poll_deferred(&step));
        ASSERT(zcl_devloop_process_cleanup_uncertain());
        step.finished = false; zcl_devloop_process_cleanup_reset();
        zcl_dev_proof_step_cancel(&step);
        ASSERT(zcl_devloop_process_cleanup_uncertain());
        step.finished = false; zcl_devloop_process_cleanup_reset();
        ASSERT(zcl_dev_proof_step_poll(&step));
        ASSERT(zcl_devloop_process_cleanup_uncertain());
        zcl_devloop_process_cleanup_reset();
        ASSERT(!zcl_dev_proof_test_reap_invalid());
        ASSERT(zcl_devloop_process_cleanup_uncertain());
        zcl_devloop_process_cleanup_reset();
        ASSERT(!zcl_devloop_process_test_reap_invalid());
        ASSERT(zcl_devloop_process_cleanup_uncertain());
        zcl_devloop_process_cleanup_reset();
        PASS();
    }
    TEST("land drive: an external proof requester cooperatively stops its owned session after real cancellation") {
        ASSERT(dlx_external_cancel_request(0));
        PASS();
    }
    TEST("land drive: abnormal worker death never reports confirmed cleanup") {
        ASSERT(dlx_external_cancel_request(1));
        PASS();
    }
    TEST("land drive: an owned wait error never reports confirmed cleanup") {
        ASSERT(dlx_external_cancel_request(2));
        PASS();
    }
    TEST("land drive: external prelaunch validates cancellation and pair binding") {
        ASSERT(dlx_external_prelaunch_controls());
        PASS();
    }
    TEST("land drive: main moving under a running proof cancels it as superseded and leaves no step process") {
        struct dlx_rig rig;
        struct dlx_watched w;
        char base[64];
        const char *never_ends[] = { "sleep", "120", NULL };
        dlx_isolate("watch_moved");
        ASSERT(dlx_rig_make(&rig, "watch_moved_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(dlx_watch_proof(&rig, base, never_ends, "stranger.txt", &w));
        ASSERT_EQ(w.waited, 1);
        ASSERT(w.superseded);
        ASSERT_EQ(w.cause, (int64_t)ZCL_DEV_PROOF_KILL_CANCELLED);
        ASSERT_EQ(w.rc, 130);
        ASSERT(dlx_step_group_gone(w.step_child));
        dlx_restore();
        PASS();
    }
    TEST("land drive: an unreachable origin never cancels a running proof; it runs to its own end") {
        struct dlx_rig rig;
        struct dlx_watched w;
        char base[64], missing[1200];
        const char *short_step[] = { "sleep", "1", NULL };
        dlx_isolate("watch_unknown");
        ASSERT(dlx_rig_make(&rig, "watch_unknown_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        (void)snprintf(missing, sizeof(missing), "%s/absent", rig.bare);
        const char *unreachable[] = { "remote", "set-url", "origin", missing,
                                      NULL };
        ASSERT(dlx_git(rig.clone, unreachable) == 0);
        /* Even a base that is not the (unobservable) tip: only an
         * affirmative answer may cancel. */
        ASSERT(dlx_watch_proof(&rig, rig.tip, short_step, NULL, &w));
        ASSERT_EQ(w.waited, 1);
        ASSERT(!w.superseded);
        ASSERT_EQ(w.cause, (int64_t)ZCL_DEV_PROOF_KILL_NONE);
        ASSERT_EQ(w.rc, 0);
        ASSERT(dlx_step_group_gone(w.step_child));
        dlx_restore();
        PASS();
    }
    TEST("land drive: an unmoved main lets a running proof finish") {
        struct dlx_rig rig;
        struct dlx_watched w;
        char base[64];
        const char *short_step[] = { "sleep", "1", NULL };
        dlx_isolate("watch_current");
        ASSERT(dlx_rig_make(&rig, "watch_current_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT(dlx_watch_proof(&rig, base, short_step, NULL, &w));
        ASSERT_EQ(w.waited, 1);
        ASSERT(!w.superseded);
        ASSERT_EQ(w.cause, (int64_t)ZCL_DEV_PROOF_KILL_NONE);
        ASSERT_EQ(w.rc, 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}
#endif

#if !defined(_WIN32)
/* The producer-recovery counter the proof stub's stand-in rebuild keeps. */
static long dlx_producer_runs(void)
{
    char path[1200];
    struct stat st;
    (void)snprintf(path, sizeof(path), "%s/producer-recovery-count",
                   g_dlx_state);
    return stat(path, &st) == 0 ? (long)st.st_size : 0;
}

/* One step under `stub`; true when it answered `state` with `dimension`. */
static bool dlx_step_dim(const char *stub, const char *state,
                         const char *dimension, const char *detail_part)
{
    struct dlx_call c;
    setenv("ZCL_LAND_PROOF_STUB", stub, 1);
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              strcmp(dlx_str(&c, "state"), state) == 0 &&
              (!dimension || strcmp(dlx_str(&c, "dimension"),
                                    dimension) == 0) &&
              (!detail_part || strstr(dlx_str(&c, "detail"), detail_part));
    dlx_end(&c);
    return ok;
}

/* Stand in for a step that died between phases: rewrite the one row's phase
 * in the rig's queue file. Fails unless `"phase":"<from>"` occurs exactly once. */
static bool dlx_queue_phase(const char *from, const char *to)
{
    char landdir[1100], path[1200], key[64], buf[16384], out[16384];
    size_t len = 0;
    int n = snprintf(key, sizeof(key), "\"phase\":\"%s\"", from);
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", landdir);
    if (n < 0 || (size_t)n >= sizeof(key) ||
        !dlx_slurp(path, buf, sizeof(buf) - 1, &len))
        return false;
    buf[len] = '\0';
    char *hit = strstr(buf, key);
    if (!hit || strstr(hit + n, key))
        return false;
    int w = snprintf(out, sizeof(out), "%.*s\"phase\":\"%s\"%s",
                     (int)(hit - buf), buf, to, hit + n);
    return w > 0 && (size_t)w < sizeof(out) && dlx_write(path, out);
}

/* Stand in for a queued row whose producer recovery was spent: rewrite
 * `from` to `to` inside the one queue.jsonl line that holds `anchor`.
 * Fails unless `anchor` occurs exactly once in the file and `from` occurs
 * exactly once in that line. (Choice: the anchor is the row's tip, since
 * a second row carries the same field.) */
bool dlx_queue_field_once(const char *anchor, const char *from,
                                 const char *to)
{
    char landdir[1100], path[1200], buf[16384], line[16384], out[16384];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", landdir);
    if (!dlx_slurp(path, buf, sizeof(buf) - 1, &len))
        return false;
    buf[len] = '\0';
    char *hit = strstr(buf, anchor);
    if (!hit || strstr(hit + 1, anchor))
        return false;
    char *start = hit;
    while (start > buf && start[-1] != '\n')
        start--;
    char *end = strchr(hit, '\n');
    if (!end)
        end = buf + len;
    if ((size_t)(end - start) >= sizeof(line))
        return false;
    (void)snprintf(line, sizeof(line), "%.*s", (int)(end - start), start);
    char *f = strstr(line, from);
    if (!f || strstr(f + strlen(from), from))
        return false;
    int w = snprintf(out, sizeof(out), "%.*s%.*s%s%s%s",
                     (int)(start - buf), buf, (int)(f - line), line, to,
                     f + strlen(from), end);
    return w > 0 && (size_t)w < sizeof(out) && dlx_write(path, out);
}

/* Move origin/main with a commit from a side clone, as a stranger landing. */
static bool dlx_stranger_lands(const struct dlx_rig *rig)
{
    char stranger[64];
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
    const char *branch[] = { "checkout", "--quiet", "-B", "side",
                             "origin/main", NULL };
    const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
    return dlx_git(rig->clone, branch) == 0 &&
           dlx_commit(rig->clone, "stranger.txt", "elsewhere\n", stranger) &&
           dlx_git(rig->clone, push) == 0 &&
           dlx_git(rig->clone, back) == 0 &&
           dlx_git(rig->clone, fetch) == 0;
}

/* The shared setup of the dead-step cases: recover once, then kill the step. */
static bool dlx_recovered_dead(struct dlx_rig *rig, const char *tag,
                               const char *rig_tag)
{
    return dlx_started(rig, tag, rig_tag) &&
           dlx_step_dim("producer_stale", "proving", "", NULL) &&
           dlx_producer_runs() == 1 &&
           dlx_queue_phase("prove", "prebuild");
}
#endif

#if !defined(_WIN32)
/* Phase mail quieting. The lander posts one phase row per landing step; a
 * row identical to the last one posted for the same landing is not posted
 * again. These cases read the mail leaf's outbox raw and count rows. */
static bool dlx_pm_outbox_path(char *out, size_t cap)
{
    char landdir[1200], mail[1300];
    dlx_landdir(landdir, sizeof(landdir));
    return snprintf(mail, sizeof(mail), "%s/../mail", landdir) <
               (int)sizeof(mail) &&
           dlx_mkdir_p(mail) &&
           snprintf(out, cap, "%s/outbox.jsonl", mail) < (int)cap;
}

static int dlx_pm_count(const char *needle)
{
    char path[1400];
    static char text[1u << 20];
    size_t len = 0;
    int n = 0;
    if (!dlx_pm_outbox_path(path, sizeof(path)) ||
        !dlx_slurp(path, text, sizeof(text) - 1, &len))
        return 0;
    text[len] = '\0';
    for (const char *p = text; (p = strstr(p, needle)) != NULL; p += strlen(needle))
        n++;
    return n;
}

/* Occurrences of `needle` in the land log of the one submission, the same
 * logs/land-1-a1.log that dlx_beat_log_record reads. */
static int dlx_pm_log_count(const char *needle)
{
    char landdir[1200], path[1400];
    static char text[1u << 20];
    size_t len = 0;
    int n = 0;
    dlx_landdir(landdir, sizeof(landdir));
    int w = snprintf(path, sizeof(path), "%s/logs/land-1-a1.log", landdir);
    if (w <= 0 || (size_t)w >= sizeof(path) ||
        !dlx_slurp(path, text, sizeof(text) - 1, &len))
        return 0;
    text[len] = '\0';
    for (const char *p = text; (p = strstr(p, needle)) != NULL; p += strlen(needle))
        n++;
    return n;
}

/* True while queue.jsonl still carries a "phase_mail" member, or cannot be
 * read (the caller then fails rather than passing on an unknown file). */
static bool dlx_pm_queue_has_phase_mail(void)
{
    char landdir[1100], path[1200], buf[16384];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", landdir);
    if (!dlx_slurp(path, buf, sizeof(buf) - 1, &len))
        return true;
    buf[len] = '\0';
    return strstr(buf, "\"phase_mail\":") != NULL;
}

/* Isolated rig, mailbox present, one submission stepped once. */
static bool dlx_pm_start(struct dlx_rig *rig, const char *tag)
{
    struct dlx_call c;
    char path[1400];
    dlx_isolate(tag);
    if (!dlx_rig_make(rig, tag) || !dlx_pm_outbox_path(path, sizeof(path)))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok && dlx_step_dim("running", "started", NULL, NULL);
}

/* One step under the "running" stub that must succeed, whatever the state. */
static bool dlx_pm_step(void)
{
    struct dlx_call c;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

/* Delete the `"phase_mail":N,` member from the queue file: an older row. */
static bool dlx_pm_strip_field(void)
{
    char landdir[1100], path[1200], buf[16384];
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", landdir);
    if (!dlx_slurp(path, buf, sizeof(buf) - 1, &len))
        return false;
    buf[len] = '\0';
    char *key = strstr(buf, "\"phase_mail\":");
    char *comma = key ? strchr(key, ',') : NULL;
    if (!comma)
        return false;
    memmove(key, comma + 1, strlen(comma + 1) + 1);
    return dlx_write(path, buf);
}

int test_dev_land_phase_mail_quiet(void)
{
    int failures = 0;
    TEST("land: steps that change nothing post one phase row; a changed row posts a new one") {
        struct dlx_rig rig;
        int first, beats;
        ASSERT(dlx_pm_start(&rig, "pm_quiet"));
        first = dlx_pm_count("land=phase");
        ASSERT(first >= 1);
        beats = dlx_pm_log_count("beat=proof_status");
        ASSERT(dlx_pm_step());
        ASSERT(dlx_pm_step());
        /* Both steps ran the proof read and their commits succeeded (dlx_pm_step
         * requires an ok reply), so each wrote its proof_status beat. The
         * unchanged post count below is then suppression, not idle steps. */
        ASSERT(dlx_pm_log_count("beat=proof_status") >= beats + 2);
        ASSERT_EQ(dlx_pm_count("land=phase"), first);
        ASSERT(dlx_step_dim("producer_stale", "proving", "", NULL));
        ASSERT(dlx_pm_count("land=phase") > first);
        dlx_restore();
        PASS();
    }
    TEST("land: a terminal row is posted after quiet phase rows") {
        struct dlx_rig rig;
        struct dlx_call c;
        ASSERT(dlx_pm_start(&rig, "pm_terminal"));
        ASSERT(dlx_pm_step());
        ASSERT_EQ(dlx_pm_count("land=outcome"), 0);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        ASSERT_EQ(dlx_pm_count("land=outcome\\nstate=cancelled"), 1);
        dlx_restore();
        PASS();
    }
    TEST("land: a queue row without the phase_mail field loads, steps and posts") {
        struct dlx_rig rig;
        int first;
        ASSERT(dlx_pm_start(&rig, "pm_oldrow"));
        first = dlx_pm_count("land=phase");
        ASSERT(dlx_pm_strip_field());
        ASSERT(!dlx_pm_queue_has_phase_mail());
        ASSERT(dlx_pm_step());
        ASSERT_EQ(dlx_pm_count("land=phase"), first + 1);
        ASSERT(dlx_pm_step());
        ASSERT_EQ(dlx_pm_count("land=phase"), first + 1);
        dlx_restore();
        PASS();
    }
    /* A plain behaviour test: the requeued successor's first phase row posts.
     * It does NOT discriminate the successor.phase_mail reset in
     * dl_requeue_successor; removing that reset leaves this test green. */
    TEST("land: a successor row's first phase row posts") {
        struct dlx_rig rig;
        char base[64], stranger[64];
        int first;
        ASSERT(dlx_started(&rig, "pm_successor", "pm_successor_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        const char *branch[] = { "checkout", "--quiet", "-B", "side", base,
                                 NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_step_to("cancelled", "rebased", 2, "successor queued"));
        first = dlx_pm_count("land=phase");
        ASSERT(dlx_pm_step());
        ASSERT(dlx_pm_count("land=phase") > first);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}
#endif

/* Pure digest judgments through zcl_dev_land_phase_digest, declared in
 * native_dev_land_attestation.h. Each test moves one input and says what
 * that must do to the digest. */
static long long dlx_pd(const char *detail, const char *tip)
{
    return zcl_dev_land_phase_digest("inflight", "prove", 1, "", "n", detail,
                                     "land-1-a1.log", tip);
}

int test_dev_land_phase_digest(void)
{
    int failures = 0;
    static const char idle_901[] =
        "resident_proof_request_queued; proof_request_idle_age_s=901 "
        "(no worker has claimed the queued request)";
    static const char idle_12345[] =
        "resident_proof_request_queued; proof_request_idle_age_s=12345 "
        "(no worker has claimed the queued request)";
    TEST("land phase digest: a tip change moves the digest") {
        ASSERT(dlx_pd(idle_901, "aaaa") != dlx_pd(idle_901, "bbbb"));
        PASS();
    }
    TEST("land phase digest: only the idle-age digits leave it unchanged; other detail moves it") {
        static const char renamed[] =
            "resident_proof_request_queued_x; proof_request_idle_age_s=901 "
            "(no worker has claimed the queued request)";
        static const char reworded[] =
            "resident_proof_request_queued; proof_request_idle_age_s=901 "
            "(no worker has claimed the queued request!)";
        ASSERT(dlx_pd(idle_901, "aaaa") == dlx_pd(idle_12345, "aaaa"));
        ASSERT(dlx_pd(idle_901, "aaaa") != dlx_pd(renamed, "aaaa"));
        ASSERT(dlx_pd(idle_901, "aaaa") != dlx_pd(reworded, "aaaa"));
        PASS();
    }
    TEST("land phase digest: an all-empty row is never 0, NULL reads as empty") {
        long long nulls = zcl_dev_land_phase_digest(NULL, NULL, 0, NULL, NULL,
                                                    NULL, NULL, NULL);
        long long empty = zcl_dev_land_phase_digest("", "", 0, "", "", "", "",
                                                    "");
        ASSERT(nulls != 0);
        ASSERT(empty != 0);
        ASSERT(nulls == empty);
        PASS();
    }
    TEST("land phase digest: adjacent fields keep their borders") {
        ASSERT(zcl_dev_land_phase_digest("ab", "c", 0, NULL, NULL, NULL, NULL,
                                         NULL) !=
               zcl_dev_land_phase_digest("a", "bc", 0, NULL, NULL, NULL, NULL,
                                         NULL));
        PASS();
    }
    TEST("land phase digest: the idle key with no digits, or twice, is stable") {
        static const char bare[] = "x; proof_request_idle_age_s= (none)";
        static const char twice_a[] =
            "proof_request_idle_age_s=1; proof_request_idle_age_s=22";
        static const char twice_b[] =
            "proof_request_idle_age_s=9; proof_request_idle_age_s=3";
        ASSERT(dlx_pd(bare, "t") != 0);
        ASSERT(dlx_pd(bare, "t") == dlx_pd(bare, "t"));
        ASSERT(dlx_pd(twice_a, "t") == dlx_pd(twice_b, "t"));
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_land_step_producer_recovery(void)
{
    int failures = 0;
#if !defined(_WIN32)
    static const char *const stale = "proof_producer_source_mismatch";
    TEST("land step: a spent producer recovery is earned again when a dead step's rebase finds main moved") {
        struct dlx_rig rig;
        ASSERT(dlx_recovered_dead(&rig, "step_producer_moved", "step_producer_moved_rig"));
        ASSERT(dlx_stranger_lands(&rig));
        ASSERT(dlx_step_dim("running", "started", NULL, NULL));
        ASSERT(dlx_step_dim("producer_stale", "proving", "",
                            "producer rebuilt from the candidate"));
        ASSERT_EQ(dlx_producer_runs(), 2);
        dlx_restore();
        PASS();
    }
    TEST("land step: a dead step's rebase on an unmoved main does not hand out a second producer recovery") {
        struct dlx_rig rig;
        ASSERT(dlx_recovered_dead(&rig, "step_producer_still", "step_producer_still_rig"));
        ASSERT(dlx_step_dim("running", "started", NULL, NULL));
        ASSERT(dlx_step_dim("producer_stale", "failed", stale,
                            "producer recovery tried once"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: a producer-stale refusal is recovered once and the re-proved pair lands") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_once", "step_producer_once_rig"));
        ASSERT(dlx_step_dim("producer_stale_once", "proving", "",
                            "producer rebuilt from the candidate"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale_once", "landed", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: a producer refusal that survives the one recovery settles failed and is not recovered again") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_twice", "step_producer_twice_rig"));
        ASSERT(dlx_step_dim("producer_stale", "proving", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale", "failed", stale,
                            "producer recovery tried once"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale", "empty", NULL, NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: any other proof failure settles as before and never recovers the producer") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_other", "step_producer_other_rig"));
        ASSERT(dlx_step_dim("fail", "failed", "lint", "proof stub: fail"));
        ASSERT_EQ(dlx_producer_runs(), 0);
        dlx_restore();
        PASS();
    }
    TEST("land step: a no-verdict producer refusal is recovered once and the re-proved pair lands") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_nv_once", "step_nv_once_rig"));
        ASSERT(dlx_step_dim("producer_stale_nv_once", "proving", "",
                            "producer rebuilt from the candidate"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale_nv_once", "landed", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: a no-verdict producer refusal that survives the one recovery settles failed, never pending") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_nv_twice", "step_nv_twice_rig"));
        ASSERT(dlx_step_dim("producer_stale_nv", "proving", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale_nv", "failed", stale,
                            "producer recovery tried once"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale_nv", "empty", NULL, NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: a no-verdict status with another detail stays pending and never recovers the producer") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_nv_other", "step_nv_other_rig"));
        ASSERT(dlx_step_dim("no_verdict_other", "proving", NULL,
                            "proof_producer_source_id_unavailable"));
        ASSERT(dlx_step_dim("no_verdict_other", "proving", NULL, NULL));
        ASSERT_EQ(dlx_producer_runs(), 0);
        dlx_restore();
        PASS();
    }
    TEST("land step: a host-load retry mark is kept through a producer recovery") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_hl", "step_producer_hl_rig"));
        ASSERT(dlx_step_dim("producer_host_load", "rebased", "host_load",
                            NULL));
        ASSERT(dlx_step_dim("running", "started", "host_load", NULL));
        ASSERT(dlx_step_dim("producer_stale_once", "proving", "host_load",
                            "producer rebuilt from the candidate"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_stale_once", "landed", "host_load",
                            NULL));
        dlx_restore();
        PASS();
    }
    TEST("land step: a host-load retry after the recovery does not earn a second recovery") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_hl2", "step_producer_hl2_rig"));
        ASSERT(dlx_step_dim("producer_stale", "proving", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 1);
        ASSERT(dlx_step_dim("producer_host_load", "rebased", "host_load",
                            NULL));
        ASSERT(dlx_step_dim("running", "started", "host_load", NULL));
        ASSERT(dlx_step_dim("producer_stale", "failed", stale,
                            "producer recovery tried once"));
        ASSERT_EQ(dlx_producer_runs(), 1);
        dlx_restore();
        PASS();
    }
    TEST("land step: a running status whose text mentions the stale producer is not a no-verdict and is left alone") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "step_producer_text", "step_producer_text_rig"));
        ASSERT(dlx_step_dim("producer_stale_text", "proving", "",
                            "background_verification_running"));
        ASSERT(dlx_step_dim("producer_stale_text", "proving", "", NULL));
        ASSERT_EQ(dlx_producer_runs(), 0);
        dlx_restore();
        PASS();
    }
_test_next:;
#endif
    return failures;
}

int test_dev_land_interrupted_proof(void)
{
    int failures = 0;
    TEST("land: an interrupted proof re-runs the same pair instead of failing the candidate") {
        struct dlx_rig rig;
        char before[64], after[64];
        ASSERT(dlx_started(&rig, "interrupt_retry", "interrupt_retry_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        ASSERT(dlx_step_to("cancelled", "proving", 2,
                           "interrupted proof re-queued"));
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, before);
        ASSERT(dlx_step_to("pass", "landed", 0, NULL));
        dlx_restore();
        PASS();
    }
    TEST("land: interruption retries are bounded, then the request settles as failed") {
        struct dlx_rig rig;
        ASSERT(dlx_started(&rig, "interrupt_bound", "interrupt_bound_rig"));
        ASSERT(dlx_step_to("cancelled", "proving", 2, NULL));
        ASSERT(dlx_step_to("cancelled", "proving", 3, NULL));
        ASSERT(dlx_step_to("cancelled", "failed", 3,
                           "child_proof_cancelled_"));
        dlx_restore();
        PASS();
    }
    TEST("land: an interrupted proof whose base moved cuts the successor") {
        struct dlx_rig rig;
        char base[64], stranger[64];
        ASSERT(dlx_started(&rig, "interrupt_moved", "interrupt_moved_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        const char *branch[] = { "checkout", "--quiet", "-B", "side", base,
                                 NULL };
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_step_to("cancelled", "rebased", 2, "successor queued"));
        dlx_restore();
        PASS();
    }
    TEST("land: the base probe answers only from a well-formed remote tip") {
        struct dlx_rig rig;
        char base[64], missing[1200];
        dlx_isolate("base_probe");
        ASSERT(dlx_rig_make(&rig, "base_probe_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        ASSERT_EQ(zcl_native_dev_land_test_base_observe(rig.clone, base),
                  ZCL_DEV_PROOF_BASE_CURRENT);
        ASSERT_EQ(zcl_native_dev_land_test_base_observe(rig.clone, rig.tip),
                  ZCL_DEV_PROOF_BASE_SUPERSEDED);
        (void)snprintf(missing, sizeof(missing), "%s/absent", rig.bare);
        const char *unreachable[] = { "remote", "set-url", "origin", missing,
                                      NULL };
        ASSERT(dlx_git(rig.clone, unreachable) == 0);
        ASSERT_EQ(zcl_native_dev_land_test_base_observe(rig.clone, rig.tip),
                  ZCL_DEV_PROOF_BASE_UNKNOWN);
        ASSERT_EQ(zcl_native_dev_land_test_base_observe(missing, rig.tip),
                  ZCL_DEV_PROOF_BASE_UNKNOWN);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

#if !defined(_WIN32)
/* ── a failed proof keeps what failed ─────────────────────────────────────
 *
 * A real attempt directory, a real stub child run as one proof dimension,
 * and the production failure settle and status reader: the only stand-in
 * is the child itself. Land seqs 163-167 failed with nothing but
 * `child_proof_failed_exit_N`; the first FAIL line has to survive into the
 * `.failed` record, the land outcome, and the attempt's evidence file,
 * while the record's first line stays the exact token every classifier
 * reads. */
struct dlx_evidence_case {
    const char *tag;
    enum zcl_dev_proof_dimension_id dimension;
    const char *script;         /* the stub child: its output and exit */
    const char *token;          /* the settled first line, unchanged */
    const char *land_dimension; /* the outcome's dimension */
    const char *detail;         /* what the outcome detail leads with */
    const char *context;        /* adjacent compiler inline context */
    const char *absent;         /* noise the evidence must not carry */
    const char *file;           /* repo-relative file the cause must name */
    const char *gate;           /* proof gate the cause must name */
    bool frame;
    bool no_frame;
};

static const char k_dlx_evidence_test_script[] =
    "printf '%s\\n' \\\n"
    " '==================== test_dev_land_noise (PASS, 0s) ====================' \\\n"
    " 'assert macros: FAIL names file:line and both values... OK' \\\n"
    " '==================== test_golden_dev_cycle (FAIL, 3s) ====================' \\\n"
    " 'golden dev cycle: a hot swap lands under a second... ' \\\n"
    " 'FAIL at tests/harness/src/test_golden_dev_cycle.c:367 (hotswap_ms < 1000.0)' \\\n"
    " '--- evidence test.c:1 ---' 'FRAME-HEAD'\n"
    "printf '\\033[31munsafe-control\\n'\n"
    "printf 'utf8-\\303\\251\\n'\n"
    "printf 'FRAME-LONG-%09000d-FRAME-LONG-END\\n' 0\n"
    "printf '%s\\n' 'FRAME-TAIL' '--- end evidence ---' \\\n"
    " '  first| L11: --- evidence retry.c:2 ---' \\\n"
    " '  first| L12: RETRY-HEAD' '  first| L13: RETRY-TAIL' \\\n"
    " '  first| L14: --- end evidence ---' \\\n"
    " '  first| L20: --- evidence bad.c:3 ---' \\\n"
    " '  first| L22: BAD-PREFIX-FRAME' '  first| L23: --- end evidence ---' \\\n"
    " 'SOME TESTS FAILED - 1/2 groups failed' \\\n"
    " 'Failed groups:' \\\n"
    " '  - test_golden_dev_cycle: exit code=1 log=./test-tmp/test_parallel_1_822.log'\n"
    "exit 1\n";

static const char k_dlx_evidence_compile_script[] =
    "root=$(pwd -P)\n"
    "echo \"cc -c $root/tools/dev/widget.c\"\n"
    "echo 'inlined from stale_context at tools/dev/stale.c:1:2:'\n"
    "echo 'unrelated diagnostic'\n"
    "echo \"inlined from widget_call at $root/tools/dev/widget.c:10:3:\"\n"
    "echo \"$root/tools/dev/widget.c:12:5: error: unknown type name 'widget_t'\"\n"
    "echo \"$root/tools/dev/widget.c:14:1: error: expected ';' before '}' token\"\n"
    "echo 'make: *** [Makefile:1: build-only] Error 1'\n"
    "exit 2\n";

/* The in-flight pair a `running` stub step left proving. */
static bool dlx_proving_pair(char local[64], char base[64])
{
    struct dlx_call c;
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *f = json_get(&c.reply.data, "in_flight");
    (void)snprintf(local, 64, "%s", f ? dlx_jstr(f, "local") : "");
    (void)snprintf(base, 64, "%s", f ? dlx_jstr(f, "base") : "");
    dlx_end(&c);
    return local[0] != '\0' && base[0] != '\0';
}

/* Submit, start proving, then settle one stub child's failure as the
 * proof of exactly the in-flight pair in the landing worktree. */
static bool dlx_evidence_settle(const struct dlx_evidence_case *k,
                                char real_wt[PATH_MAX], char local[64],
                                char base[64])
{
    struct dlx_rig rig;
    struct dlx_call c;
    char tag[64], landwt[1300], landdir[1200], script[1300], why[256];
    (void)snprintf(tag, sizeof(tag), "%s_rig", k->tag);
    if (!dlx_rig_make(&rig, tag))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, &rig, rig.tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_begin(&c, "step");
    ok = ok && dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_land_wt(landwt, sizeof(landwt));
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(script, sizeof(script), "%s/stub-child.sh", landdir);
    const char *argv[] = { "/bin/sh", script, NULL };
    return ok && dlx_proving_pair(local, base) &&
           realpath(landwt, real_wt) != NULL &&
           dlx_write(script, k->script) &&
           zcl_dev_proof_test_settle_child(real_wt, local, base,
                                           k->dimension, argv, why,
                                           sizeof(why)) &&
           dlx_eq_str(why, k->token);
}

/* The evidence text: present, relative, and free of the named noise. */
static bool dlx_evidence_text_ok(const struct dlx_evidence_case *k,
                                 const char *text, const char *real_wt)
{
    if (!dlx_has(text, k->detail))
        return false;
    if (k->context && !dlx_has(text, k->context)) return false;
    if (k->context && strstr(text, "stale_context")) return false;
    if (strstr(text, k->absent) || strstr(text, real_wt)) {
        printf("FAIL evidence carries '%s' or an absolute path: %s\n",
               k->absent, text);
        return false;
    }
    return true;
}

/* The pair's `.failed` record: the unchanged token, then the evidence. */
static bool dlx_evidence_record_ok(const struct dlx_evidence_case *k,
                                   const char *real_wt, const char *local,
                                   const char *base)
{
    char path[PATH_MAX + 200], record[4096];
    size_t len = 0, token_len = strlen(k->token);
    (void)snprintf(path, sizeof(path), "%s/.cache/zcl-dev-proof/%s-%s.failed",
                   real_wt, local, base);
    if (!dlx_slurp(path, record, sizeof(record) - 1, &len))
        return false;
    record[len] = '\0';
    if (strncmp(record, k->token, token_len) != 0 ||
        record[token_len] != '\n') {
        printf("FAIL record first line is not the bare token: %s\n", record);
        return false;
    }
    char cause[320];
    int wrote = snprintf(cause, sizeof(cause),
                         "cause change=%s file=%s gate=%s",
                         local, k->file, k->gate);
    if (wrote <= 0 || (size_t)wrote >= sizeof(cause) ||
        strstr(record, cause) == NULL) {
        printf("FAIL record does not name change, file, and gate: %s\n",
               record);
        return false;
    }
    return dlx_evidence_text_ok(k, record + token_len, real_wt);
}

static bool dlx_evidence_frame_ok(const char *text)
{
    return strstr(text, "--- evidence test.c:1 ---") && strstr(text, "FRAME-HEAD") &&
           strstr(text, "FRAME-TAIL") && strstr(text, "FRAME-LONG-END") &&
           strstr(text, "utf8-\303\251") && strstr(text, "--- end evidence ---") &&
           strstr(text, "RETRY-HEAD") && strstr(text, "RETRY-TAIL") &&
           !strstr(text, "BAD-PREFIX-FRAME") && !strchr(text, '\033');
}

static bool dlx_evidence_result_ok(const struct dlx_evidence_case *k,
                                   const char *text, const char *real_wt)
{
    return dlx_has(text, k->token) && (!k->no_frame || !strstr(text, "FRAME-HEAD")) &&
           dlx_evidence_text_ok(k, text, real_wt) && (!k->frame || dlx_evidence_frame_ok(text));
}

/* Consume the settled failure through the production status reader and
 * check the outcome row and the attempt's evidence file. */
static bool dlx_evidence_outcome_ok(const struct dlx_evidence_case *k,
                                    const char *real_wt)
{
    struct dlx_call c;
    char landdir[1200], path[1400], text[32768];
    size_t len = 0;
    char steplog[96];
    (void)snprintf(steplog, sizeof(steplog), ".%s.log", k->land_dimension);
    setenv("ZCL_LAND_PROOF_STUB", "status", 1);
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              dlx_eq_str(dlx_str(&c, "state"), "failed") &&
              dlx_eq_str(dlx_str(&c, "dimension"), k->land_dimension) &&
              dlx_has(dlx_str(&c, "detail"), k->detail) &&
              dlx_has(dlx_str(&c, "detail"), "; log: ") &&
              dlx_has(dlx_str(&c, "detail"), steplog) &&
              strncmp(dlx_str(&c, "detail"), k->detail,
                      strlen(k->detail)) == 0;
    if (!ok)
        printf("FAIL outcome dimension='%s' detail='%s'\n",
               dlx_str(&c, "dimension"), dlx_str(&c, "detail"));
    dlx_end(&c);
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/logs/land-1-a1.evidence",
                   landdir);
    if (!ok || !dlx_slurp(path, text, sizeof(text) - 1, &len)) {
        if (ok)
            printf("FAIL no evidence file at %s\n", path);
        return false;
    }
    text[len] = '\0';
    return dlx_evidence_result_ok(k, text, real_wt);
}

static bool dlx_evidence_case_run(const struct dlx_evidence_case *k)
{
    char real_wt[PATH_MAX], local[64], base[64];
    dlx_isolate(k->tag);
    bool ok = dlx_evidence_settle(k, real_wt, local, base) &&
              dlx_evidence_record_ok(k, real_wt, local, base);
    struct zcl_dev_proof_status status = {0};
    ok = ok && zcl_dev_proof_status_read(real_wt, local, base, &status) &&
         status.failure_identity.valid;
    if (ok && k->no_frame) {
        char path[PATH_MAX + 200], record[4096];
        size_t len = 0;
        (void)snprintf(path, sizeof(path), "%s/.cache/zcl-dev-proof/%s-%s.failed",
                       real_wt, local, base);
        ok = dlx_slurp(path, record, sizeof(record) - 1, &len);
        if (ok) {
            record[len] = '\0';
            char *binding = strstr(record, "\nzcl.dev_proof_failure_binding.v1\n");
            if (!binding) ok = false;
            else { *binding = '\0'; ok = dlx_write(path, record); }
        }
    }
    ok = ok && dlx_evidence_outcome_ok(k, real_wt);
    dlx_restore();
    return ok;
}

int test_dev_land_proof_evidence_test(void)
{
    int failures = 0;
    TEST("land: diagnostics stay with their failing groups") {
        const struct dlx_evidence_case k = {
            .tag = "evidence_groups", .dimension = ZCL_DEV_PROOF_TEST,
            .script = "printf '%s\\n' "
                "'==================== test_onion (FAIL, 1s) ====================' "
                "'state_offer_onion_link line 451: arm_landed' "
                "'state_offer_onion_link: FAIL' "
                "'==================== test_lint (FAIL, 2s) ====================' "
                "'FAIL at tests/harness/src/lint_gate_chain_contracts.c:455 (do_from_anchor != NULL)' "
                "'Failed groups:' '  - test_onion: exit code=1' '  - test_lint: exit code=1'\nexit 1\n",
            .token = "child_proof_failed_exit_1",
        };
        char wt[PATH_MAX], local[64], base[64], path[PATH_MAX + 200], record[4096];
        size_t len = 0;
        dlx_isolate(k.tag);
        ASSERT(dlx_evidence_settle(&k, wt, local, base));
        (void)snprintf(path, sizeof(path), "%s/.cache/zcl-dev-proof/%s-%s.failed", wt, local, base);
        ASSERT(dlx_slurp(path, record, sizeof(record) - 1, &len));
        record[len] = '\0';
        ASSERT(strstr(record, "test test_onion: state_offer_onion_link: FAIL") != NULL);
        ASSERT(strstr(record, "test_lint: FAIL at tests/harness/src/lint_gate_chain_contracts.c:455") != NULL);
        ASSERT(strstr(record, "file=state_offer_onion_link") == NULL);
        dlx_restore();
        PASS();
    }
    TEST("land: empty groups and repeated assertions keep their owners") {
        const struct dlx_evidence_case k = {
            .tag = "evidence_duplicate_groups", .dimension = ZCL_DEV_PROOF_TEST,
            .script = "printf '%s\\n' "
                "'==================== test_empty (FAIL, 1s) ====================' "
                "'no diagnostic' "
                "'==================== test_first (FAIL, 1s) ====================' "
                "'FAIL at tests/same.c:12 (broken)' "
                "'==================== test_second (FAIL, 1s) ====================' "
                "'FAIL at tests/same.c:12 (broken)'\nexit 1\n",
            .token = "child_proof_failed_exit_1",
        };
        char wt[PATH_MAX], local[64], base[64], path[PATH_MAX + 200], record[4096];
        size_t len = 0;
        dlx_isolate(k.tag);
        ASSERT(dlx_evidence_settle(&k, wt, local, base));
        (void)snprintf(path, sizeof(path), "%s/.cache/zcl-dev-proof/%s-%s.failed", wt, local, base);
        ASSERT(dlx_slurp(path, record, sizeof(record) - 1, &len));
        record[len] = '\0';
        ASSERT(strstr(record, "test test_first: FAIL at tests/same.c:12 (broken)") != NULL);
        ASSERT(strstr(record, "test_second: FAIL at tests/same.c:12 (broken)") != NULL);
        ASSERT(strstr(record, "file=tests/same.c gate=test") != NULL);
        dlx_restore();
        PASS();
    }
    TEST("land: a failed test group names its FAIL line in the outcome") {
        const struct dlx_evidence_case k = {
            .tag = "evidence_test",
            .dimension = ZCL_DEV_PROOF_TEST,
            .script = k_dlx_evidence_test_script,
            .token = "child_proof_failed_exit_1",
            .land_dimension = "test",
            .detail = "test test_golden_dev_cycle: FAIL at "
                      "tests/harness/src/test_golden_dev_cycle.c:367 "
                      "(hotswap_ms < 1000.0)",
            .absent = "assert macros",
            .file = "tests/harness/src/test_golden_dev_cycle.c",
            .gate = "test",
            .frame = true,
        };
        ASSERT(dlx_evidence_case_run(&k));
        struct dlx_evidence_case unbound = k;
        unbound.tag = "evidence_unbound";
        unbound.frame = false;
        unbound.no_frame = true;
        ASSERT(dlx_evidence_case_run(&unbound));
        PASS();
    }
_test_next:;
    return failures;
}

static bool dlx_lint_refusal_detail(const char *detail)
{
    return strstr(detail, "wrong attempt body") == NULL &&
           strstr(detail, "check-red") != NULL &&
           strstr(detail, "unavailable") != NULL &&
           strstr(detail, "[detail truncated]") != NULL &&
           zutf8_validate(detail);
}

static bool dlx_lint_bad_file(bool fifo)
{
    const struct dlx_evidence_case k = {
        .tag = fifo ? "evidence_lint_fifo" : "evidence_lint_link",
        .dimension = ZCL_DEV_PROOF_LINT,
        .script = "printf 'FAIL check-red '; head -c 150 /dev/zero | tr '\\000' x; printf '€\\n'; exit 1\n",
        .token = "child_proof_failed_exit_1",
    };
    char wt[PATH_MAX], local[64], base[64], path[PATH_MAX + 512], decoy[PATH_MAX + 64];
    dlx_isolate(k.tag);
    bool ok = dlx_evidence_settle(&k, wt, local, base);
    struct zcl_dev_proof_status status = {0};
    ok = ok && zcl_dev_proof_status_read(wt, local, base, &status) && status.failure_identity.valid;
    (void)snprintf(path, sizeof(path), "%s/.cache/zcl-dev-proof/attempts/%s/logs/%s-%s.lint.log",
                   wt, status.failure_identity.attempt, local, base);
    (void)snprintf(decoy, sizeof(decoy), "%s/wrong-attempt.log", wt);
    ok = ok && dlx_write(decoy, "──── FAIL log: check-fake ────────────────────────────\nwrong attempt body\n") &&
         unlink(path) == 0 && (fifo ? mkfifo(path, 0600) == 0 : symlink(decoy, path) == 0);
    setenv("ZCL_LAND_PROOF_STUB", "status", 1);
    struct dlx_call c;
    dlx_begin(&c, "step");
    ok = ok && dlx_run(&c) && dlx_ok(&c) &&
         strcmp(dlx_str(&c, "state"), "failed") == 0 &&
         dlx_lint_refusal_detail(dlx_str(&c, "detail"));
    dlx_end(&c);
    dlx_restore();
    return ok;
}

static bool dlx_lint_utf8_boundary(void)
{
    const struct dlx_evidence_case k = {
        .tag = "evidence_lint_utf8", .dimension = ZCL_DEV_PROOF_LINT,
        .script = "printf '%s\\n' 'FAIL check-red' '──── FAIL log: check-red ────────────────────────────'\n"
                  "head -c 230 /dev/zero | tr '\\000' x; printf '€x\\n'; exit 1\n",
        .token = "child_proof_failed_exit_1",
    };
    char wt[PATH_MAX], local[64], base[64];
    dlx_isolate(k.tag);
    bool ok = dlx_evidence_settle(&k, wt, local, base);
    setenv("ZCL_LAND_PROOF_STUB", "status", 1);
    struct dlx_call c;
    dlx_begin(&c, "step");
    ok = ok && dlx_run(&c) && dlx_ok(&c) &&
         strstr(dlx_str(&c, "detail"), "[detail truncated]") != NULL &&
         zutf8_validate(dlx_str(&c, "detail"));
    dlx_end(&c);
    dlx_restore();
    return ok;
}

static bool dlx_evidence_lint_late(void)
{
    const struct dlx_evidence_case k = {
        .tag = "evidence_lint_late", .dimension = ZCL_DEV_PROOF_LINT,
        .script = "printf '%s\\n' 'widget.c:1: error: expected fixture failure' "
                  "'observed: wrong gate evidence' "
                  "'FAIL check-red' '──── FAIL log: check-red ────────────────────────────'\n"
                  "i=0; while [ \"$i\" -lt 50 ]; do printf 'PASS selftest preamble %s\\n' \"$i\"; i=$((i+1)); done\n"
                  "printf '%s\\n' '[check-other] FAIL wrong gate' '[check-red] FAIL — shell debt changed:' "
                  "'ss tools/scripts/fixture.sh actual=0 baseline=3 (stale row)' "
                  "'──── FAIL log: check-other ────────────────────────────' 'later frame contamination'\nexit 1\n",
        .token = "child_proof_failed_exit_1",
    };
    char wt[PATH_MAX], local[64], base[64];
    dlx_isolate(k.tag);
    bool ok = dlx_evidence_settle(&k, wt, local, base);
    setenv("ZCL_LAND_PROOF_STUB", "status", 1);
    struct dlx_call c; dlx_begin(&c, "step");
    ok = ok && dlx_run(&c) && dlx_ok(&c) && !strcmp(dlx_str(&c, "state"), "failed") &&
        !strcmp(dlx_str(&c, "dimension"), "lint") && strstr(dlx_str(&c, "detail"), "shell debt changed") &&
        strstr(dlx_str(&c, "detail"), "actual=0 baseline=3 (stale row)") &&
        !strstr(dlx_str(&c, "detail"), "wrong gate") && !strstr(dlx_str(&c, "detail"), "PASS selftest") &&
        !strstr(dlx_str(&c, "detail"), "later frame contamination");
    dlx_end(&c); dlx_restore(); return ok;
}

static int dlx_evidence_lint_body(void)
{
    int failures = 0;
    TEST("land: bound failed lint proof names its gate body") {
        const struct dlx_evidence_case k = {
            .tag = "evidence_lint_body", .dimension = ZCL_DEV_PROOF_LINT,
            .script = "printf '%s\\n' 'PASS check-pass' 'FAIL check-red'\n"
                      "printf '%s\\n' '──── FAIL log: check-red ────────────────────────────' 'lint diagnostic body' >&2\nexit 1\n",
            .token = "child_proof_failed_exit_1",
        };
        char wt[PATH_MAX], local[64], base[64];
        dlx_isolate(k.tag);
        ASSERT(dlx_evidence_settle(&k, wt, local, base));
        setenv("ZCL_LAND_PROOF_STUB", "status", 1);
        struct dlx_call c;
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "failed");
        ASSERT_STR_EQ(dlx_str(&c, "dimension"), "lint");
        ASSERT(strstr(dlx_str(&c, "detail"), "lint diagnostic body") != NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "PASS check-pass") == NULL);
        dlx_end(&c);
        dlx_restore();
        ASSERT(dlx_evidence_lint_late());
        ASSERT(dlx_lint_bad_file(false));
        ASSERT(dlx_lint_bad_file(true));
        ASSERT(dlx_lint_utf8_boundary());
        PASS();
    } _test_next:;
    return failures;
}

int test_dev_land_proof_evidence_compile(void)
{
    int failures = dlx_evidence_lint_body();
    TEST("land: generic compiler errors do not name a source file") {
        const struct dlx_evidence_case k = {
            .tag = "evidence_generic_error", .dimension = ZCL_DEV_PROOF_COMPILE,
            .script = "printf '%s\\n' 'error:12 unavailable'\nexit 1\n",
            .token = "child_proof_failed_exit_1",
        };
        char wt[PATH_MAX], local[64], base[64], path[PATH_MAX + 200], record[4096];
        size_t len = 0;
        dlx_isolate(k.tag);
        ASSERT(dlx_evidence_settle(&k, wt, local, base));
        (void)snprintf(path, sizeof(path), "%s/.cache/zcl-dev-proof/%s-%s.failed", wt, local, base);
        ASSERT(dlx_slurp(path, record, sizeof(record) - 1, &len));
        record[len] = '\0';
        ASSERT(strstr(record, "file=error") == NULL);
        dlx_restore();
        PASS();
    }
    TEST("land: system header error retains adjacent inline context") {
        const struct dlx_evidence_case k = {
            .tag = "evidence_inline_system", .dimension = ZCL_DEV_PROOF_COMPILE,
            .script = "printf '%s\\n' 'inlined from stale at tools/dev/stale.c:1:2:' "
                      "'unrelated line' 'inlined from pe_take_str at tools/command/native_pair_epoch.c:330:5:' "
                      "'/usr/include/string_fortified.h:29:3: error: overflow'\nexit 2\n",
            .token = "child_proof_failed_exit_2",
        };
        char wt[PATH_MAX], local[64], base[64], path[PATH_MAX + 200], record[4096];
        size_t len = 0;
        dlx_isolate(k.tag);
        ASSERT(dlx_evidence_settle(&k, wt, local, base));
        (void)snprintf(path, sizeof(path), "%s/.cache/zcl-dev-proof/%s-%s.failed", wt, local, base);
        ASSERT(dlx_slurp(path, record, sizeof(record) - 1, &len));
        record[len] = '\0';
        ASSERT(strstr(record, "compile: /usr/include/string_fortified.h:29:3: error: overflow") != NULL);
        ASSERT(strstr(record, "inlined from pe_take_str at tools/command/native_pair_epoch.c:330:5:") != NULL);
        ASSERT(strstr(record, "inlined from stale") == NULL);
        ASSERT(strstr(record, "cause change=") == NULL);
        dlx_restore();
        PASS();
    }
    TEST("land: compiler commands do not hide a later failing gate") {
        char detail[256];
        zcl_dev_land_test_first_actionable(
            "zcc -c gate_no_wallclock_assertion.c -o gate_no_wallclock_assertion.o\n"
            "FAIL check-kpi-floor\n", detail, sizeof(detail));
        ASSERT_STR_EQ(detail, "FAIL check-kpi-floor");
        zcl_dev_land_test_first_actionable("widget.c:12:5: error: bad type\n",
                                          detail, sizeof(detail));
        ASSERT_STR_EQ(detail, "widget.c:12:5: error: bad type");
        zcl_dev_land_test_first_actionable(
            "PASS check-pipefail-status-pipe\nFAIL first-gate\nFAIL second-gate\n",
            detail, sizeof(detail));
        ASSERT_STR_EQ(detail, "FAIL first-gate");
        zcl_dev_land_test_first_actionable("zcc -c gate_no_wallclock_assertion.o\n",
                                          detail, sizeof(detail));
        ASSERT_STR_EQ(detail, "");
        PASS();
    }
    TEST("land: diagnostic lines preserve spaces and embedded carriage returns") {
        static const struct { const char *input; const char *expected; } cases[] = {
            {"FAIL gate\r\n", "FAIL gate"},
            {"FAIL gate \t\r\n", "FAIL gate  "},
            {"FAIL gate\rcontext\r\n", "FAIL gate context"},
            {"\rFAIL first\nFAIL second\n", " FAIL first"},
            {"\rPASS check-fail\n", ""},
            {"\r\n\r\n", ""},
            {" \t\r\nPASS gate\r\nFAIL gate\r\n", "FAIL gate"},
            {"FAIL gate\r\n  observed: actual=1 \t\r\n",
             "FAIL gate\n  observed: actual=1  "},
        };
        char detail[256];
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            zcl_dev_land_test_first_actionable(cases[i].input, detail, sizeof(detail));
            ASSERT_STR_EQ(detail, cases[i].expected);
        }
        PASS();
    }
    TEST("land: a failed build names its first compiler error, relative") {
        const struct dlx_evidence_case k = {
            .tag = "evidence_compile",
            .dimension = ZCL_DEV_PROOF_COMPILE,
            .script = k_dlx_evidence_compile_script,
            .token = "child_proof_failed_exit_2",
            .land_dimension = "compile",
            .detail = "compile: tools/dev/widget.c:12:5: error: unknown "
                      "type name 'widget_t'",
            .context = "inlined from widget_call at tools/dev/widget.c:10:3:",
            .absent = "expected ';'",
            .file = "tools/dev/widget.c",
            .gate = "compile",
        };
        ASSERT(dlx_evidence_case_run(&k));
        PASS();
    }
_test_next:;
    return failures;
}

/* The newest attempt's archived failure record exists: a retry kept the
 * failed attempt as evidence rather than deleting it. */
static bool dlx_attempt_archive_exists(const char *real_wt, const char *local,
                                       const char *base)
{
    char dir[PATH_MAX + 64], path[PATH_MAX + 512], prefix[160];
    DIR *d;
    struct dirent *e;
    bool found = false;
    (void)snprintf(dir, sizeof(dir), "%s/.cache/zcl-dev-proof/attempts",
                   real_wt);
    (void)snprintf(prefix, sizeof(prefix), "%s-%s.", local, base);
    d = opendir(dir);
    if (!d)
        return false;
    while (!found && (e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, prefix, strlen(prefix)) != 0)
            continue;
        (void)snprintf(path, sizeof(path), "%s/%s/logs/failure.txt", dir,
                       e->d_name);
        found = access(path, R_OK) == 0;
    }
    (void)closedir(d);
    return found;
}

int test_dev_land_resubmit_failed_pair(void)
{
    int failures = 0;
    TEST("land: a new row for a pair whose last proof failed gets a fresh proof") {
        struct dlx_rig rig;
        struct dlx_call c;
        struct zcl_dev_proof_status st = {0};
        char landwt[1300], landdir[1200], script[1300], why[256];
        char real_wt[PATH_MAX], local[64], base[64];
        dlx_isolate("resubmit_failed");
        ASSERT(dlx_rig_make(&rig, "resubmit_failed_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_proving_pair(local, base));
        dlx_land_wt(landwt, sizeof(landwt));
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(realpath(landwt, real_wt) != NULL);
        (void)snprintf(script, sizeof(script), "%s/stub-child.sh", landdir);
        const char *argv[] = { "/bin/sh", script, NULL };
        ASSERT(dlx_write(script, k_dlx_evidence_compile_script));
        ASSERT(zcl_dev_proof_test_settle_child(real_wt, local, base,
                                               ZCL_DEV_PROOF_COMPILE, argv,
                                               why, sizeof(why)));
        /* Row 1 consumes that failure and settles failed. */
        setenv("ZCL_LAND_PROOF_STUB", "status", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "failed");
        dlx_end(&c);
        ASSERT(zcl_dev_proof_status_read(real_wt, local, base, &st));
        ASSERT_EQ((int)st.state, (int)ZCL_DEV_PROOF_STATE_FAILED);
        /* Row 2 resubmits the same commit on the same base. */
        (void)snprintf(script, sizeof(script), "%s/.cache/fixture", real_wt);
        ASSERT(dlx_write(script, "isolated resubmit\n"));
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 2);
        dlx_end(&c);
        for (int i = 0; i < 2; i++) { /* a repeat step must not loop or fail */
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(strcmp(dlx_str(&c, "state"), "failed") != 0);
            dlx_end(&c);
        }
        ASSERT(zcl_dev_proof_status_read(real_wt, local, base, &st));
        ASSERT(st.state != ZCL_DEV_PROOF_STATE_FAILED);
        /* The first attempt's failure is kept, never deleted. */
        ASSERT(dlx_attempt_archive_exists(real_wt, local, base));
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_refusal_names_next_step(void)
{
    int failures = 0;
    TEST("land: refusals name one actionable next step") {
        struct dlx_call c;
        char step[256];
        dlx_isolate("refusal_next");
        /* Table pins: the exact command, with the row's seq filled in. */
        zcl_native_dev_land_test_next_step("PUBLICATION_HELD", "step", 7, step,
                                           sizeof(step));
        ASSERT_STR_EQ(step, "z23 dev land release --seq=7");
        zcl_native_dev_land_test_next_step("DRIVE_BUDGET_EXHAUSTED", "drive",
                                           3, step, sizeof(step));
        ASSERT_STR_EQ(step, "z23 dev land drive --seq=3");
        zcl_native_dev_land_test_next_step("BAD_INPUT", "cancel", 0, step,
                                           sizeof(step));
        ASSERT_STR_EQ(step, "z23 dev land cancel --help");
        zcl_native_dev_land_test_next_step("NOT_A_REAL_CODE", "step", 0, step,
                                           sizeof(step));
        ASSERT_STR_EQ(step, "z23 dev land status");
        /* End to end: a hold with no seq, an unknown verb, an unknown row. */
        dlx_begin(&c, "hold");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "BAD_INPUT");
        ASSERT_STR_EQ(c.reply.error.next_action, "z23 dev land hold --help");
        dlx_end(&c);
        dlx_begin(&c, "bogus");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "UNKNOWN_ACTION");
        ASSERT_STR_EQ(c.reply.error.next_action, "z23 dev land --help");
        dlx_end(&c);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 99);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT(c.reply.error.next_action[0] != '\0');
        ASSERT(strstr(c.reply.error.next_action, "z23 dev land ") != NULL);
        dlx_end(&c);
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}

/* Both fixture lines, a typed next action, and a row that still encodes.
 * A log that is only the token FAIL does not satisfy the same predicate. */
static bool dlx_gate_diag_holds(const struct dlx_call *c)
{
    const char *detail = dlx_str(c, "detail");
    const char *next = dlx_str(c, "next_action");
    return strstr(detail, "FAIL check-kpi-floor") != NULL &&
           strstr(detail, "observed: exit status 1 response body empty") != NULL &&
           strstr(next, "z23 dev land ") != NULL;
}

static bool dlx_gate_diag_step(const char *tag, const char *script,
                               struct dlx_call *c)
{
    const struct dlx_evidence_case k = {
        .tag = tag,
        .dimension = ZCL_DEV_PROOF_LINT,
        .script = script,
        .token = "child_proof_failed_exit_1",
    };
    char wt[PATH_MAX], local[64], base[64];
    dlx_isolate(tag);
    if (!dlx_evidence_settle(&k, wt, local, base))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "status", 1);
    dlx_begin(c, "step");
    if (dlx_run(c) && dlx_ok(c) &&
        strcmp(dlx_str(c, "state"), "failed") == 0)
        return true;
    dlx_end(c);
    return false;
}

int test_dev_land_gate_diagnostic_window(void)
{
    int failures = 0;
    extern bool zcl_native_dev_land_test_encode_detail(const char *, bool,
                                                       char *, size_t);
    TEST("test_dev_land_gate_diagnostic_window: failure line and observed evidence") {
        struct dlx_call c;
        char landdir[1200], path[1400], stored[8192], encoded[8192];
        size_t len = 0;
        const struct json_value *outcomes, *row;
        ASSERT(dlx_gate_diag_step(
            "gate_diag_window",
            "printf '%s\\n' 'FAIL check-kpi-floor' "
            "'observed: exit status 1 response body empty'; exit 1\n",
            &c));
        ASSERT(dlx_gate_diag_holds(&c));
        ASSERT_STR_EQ(dlx_str(&c, "next_action"), "z23 dev land status");
        ASSERT(strstr(dlx_str(&c, "detail"), "; log: ") != NULL);
        ASSERT(zcl_native_dev_land_test_encode_detail(
            dlx_str(&c, "detail"), true, encoded, sizeof(encoded)));
        ASSERT(strstr(encoded, "FAIL check-kpi-floor") != NULL);
        ASSERT(strstr(encoded, "observed: exit status 1 response body empty") != NULL);
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(snprintf(path, sizeof(path), "%s/outcomes.jsonl", landdir) <
               (int)sizeof(path));
        ASSERT(dlx_slurp(path, stored, sizeof(stored) - 1, &len));
        stored[len] = '\0';
        ASSERT(strstr(stored, "FAIL check-kpi-floor") != NULL);
        ASSERT(strstr(stored, "observed: exit status 1 response body empty") != NULL);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes && outcomes->num_children >= 1);
        row = &outcomes->children[0];
        const char *status_detail = json_get_str(json_get(row, "detail"));
        const char *status_next = json_get_str(json_get(row, "next_action"));
        ASSERT(status_detail &&
               strstr(status_detail, "FAIL check-kpi-floor") != NULL);
        ASSERT(status_detail &&
               strstr(status_detail,
                      "observed: exit status 1 response body empty") != NULL);
        ASSERT(status_next != NULL);
        ASSERT_STR_EQ(status_next, "z23 dev land status");
        dlx_end(&c);
        dlx_restore();
        ASSERT(dlx_gate_diag_step(
            "gate_diag_fail_only",
            "printf '%s\\n' 'FAIL'; exit 1\n", &c));
        ASSERT(!dlx_gate_diag_holds(&c));
        dlx_end(&c);
        dlx_restore();
        PASS();
    } _test_next:;
    dlx_restore();
    return failures;
}
#endif

#if !defined(_WIN32)
int test_dev_land_status_observation(void)
{
    int failures = 0;
    char root[4096], land[8192], logs[8300];
    struct stat info;
    struct dlx_call call;
    bool opened = false;
    TEST("land: status observes absent and read-only state without setup") {
        dlx_isolate("observe_only");
        dlx_begin(&call, "status"); opened = true;
        ASSERT(dlx_run(&call));
        ASSERT(!dlx_ok(&call));
        ASSERT(lstat(g_dlx_state, &info) != 0);
        dlx_end(&call); opened = false;
        ASSERT(platform_state_root(root, sizeof(root)));
        ASSERT(snprintf(land, sizeof(land), "%s/land", root) > 0);
        ASSERT(snprintf(logs, sizeof(logs), "%s/logs", land) > 0);
        dlx_begin(&call, "status"); opened = true;
        ASSERT(dlx_run(&call));
        ASSERT(dlx_ok(&call));
        ASSERT(lstat(land, &info) != 0);
        dlx_end(&call); opened = false;
        ASSERT(mkdir(land, 0500) == 0);
        dlx_begin(&call, "status"); opened = true;
        ASSERT(dlx_run(&call));
        ASSERT(dlx_ok(&call));
        ASSERT(stat(land, &info) == 0 && (info.st_mode & 0777) == 0500);
        ASSERT(lstat(logs, &info) != 0);
        dlx_end(&call); opened = false;
        ASSERT(chmod(land, 0700) == 0);
        ASSERT(chmod(root, 0755) == 0);
        dlx_begin(&call, "status"); opened = true;
        ASSERT(dlx_run(&call));
        ASSERT(!dlx_ok(&call));
        ASSERT(stat(root, &info) == 0 && (info.st_mode & 0777) == 0755);
        PASS();
    } _test_next:;
    if (opened) dlx_end(&call);
    dlx_restore();
    return failures;
}
#endif

#if !defined(_WIN32)
/* dev.land.status through the registry executor, the path z23_run takes: the
 * leaf must be READY with a handler in every build (not COMPAT_ONLY), answer
 * ok:true over a fixture state root, and refuse a smuggled mutating verb. */
int test_dev_land_status_registry_run(void)
{
    int failures = 0;
    char root[4096], wire[16384];
    enum zcl_command_exit code;
    struct json_value input, doc;
    bool opened = false;
    const struct zcl_command_spec *spec = NULL;
    TEST("land: dev.land.status runs through the registry executor") {
        dlx_isolate("status_registry");
        ASSERT(platform_state_root(root, sizeof(root)));
        spec = zcl_command_registry_find(zcl_command_catalog(),
                                         "dev.land.status", NULL);
        ASSERT(spec != NULL);
        ASSERT_EQ(spec->availability, ZCL_COMMAND_READY);
        ASSERT(spec->handler != NULL);
        json_init(&input);
        json_set_object(&input);
        json_init(&doc);
        opened = true;
        size_t len = zcl_command_registry_execute_json(
            zcl_command_catalog(), spec, NULL, &input, false,
            "dev.land.status", NULL, 0, 0, NULL, wire, sizeof(wire), &code);
        ASSERT(len > 0 && json_read(&doc, wire, len));
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&doc, "ok")));
        ASSERT(json_get(json_get(&doc, "data"), "queued") != NULL);
        json_free(&doc);
        json_init(&doc);
        ASSERT(json_push_kv_str(&input, "action", "step"));
        len = zcl_command_registry_execute_json(
            zcl_command_catalog(), spec, NULL, &input, false,
            "dev.land.status", NULL, 0, 0, NULL, wire, sizeof(wire), &code);
        ASSERT(len > 0 && json_read(&doc, wire, len));
        ASSERT(!json_get_bool(json_get(&doc, "ok")));
        PASS();
    } _test_next:;
    if (opened) {
        json_free(&doc);
        json_free(&input);
    }
    dlx_restore();
    return failures;
}
#endif

#if !defined(_WIN32)
/* Real local bare receiver and independently signed, same-tree successor.
 * The proof stub hashes each distinct pair: equal trees do not share proof. */
bool dlx_fence_prepare(struct dlx_rig *rig, const char *tag,
                               char base[64], char wt[1400], char successor[64])
{
    char marker[1400], tree[64];
    if (!dlx_signed_push_lossy(rig, tag, base, wt, marker, NULL)) return false;
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && !dlx_ok(&c) &&
        strcmp(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN") == 0;
    dlx_end(&c);
    const char *lookup[] = { "rev-parse", "HEAD^{tree}", NULL };
    const char *restore[] = { "config", "--unset", "remote.origin.receivepack", NULL };
    if (!ok || !dlx_sign_arm(rig->clone, tag) ||
        dlx_git(rig->clone, restore) != 0 ||
        dlx_git_out(rig->clone, lookup, tree, sizeof(tree)) != 0) return false;
    const char *create[] = { "commit-tree", "-S", tree, "-p", base,
                             "-m", "qualified fence successor", NULL };
    if (dlx_git_out(rig->clone, create, successor, 64) != 0) return false;
    const char *checkout[] = { "checkout", "--quiet", "-B", "fence-successor",
                               successor, NULL };
    const char *hooks[] = { "config", "--worktree", "core.hooksPath",
                            g_dlx_hooks_ok, NULL };
    setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
    setenv("ZCL_LAND_TEST_FENCE_POLICY", "monotonic", 1);
    if (dlx_git(rig->clone, checkout) != 0 || dlx_git(rig->clone, hooks) != 0) return false;
    /* A replacement checkout must live inside the land directory (the hook
     * admits main pushes from nowhere else): relocate the clone there. */
    char land[1200], inside[600];
    dlx_landdir(land, sizeof(land));
    if (snprintf(inside, sizeof(inside), "%s/fence-replacement", land) >= (int)sizeof(inside) ||
        rename(rig->clone, inside) != 0) return false;
    (void)snprintf(rig->clone, sizeof(rig->clone), "%s", inside);
    /* The landing worktree is a linked worktree of this clone: re-point it. */
    char landing[1400];
    (void)snprintf(landing, sizeof(landing), "%s/wt", land);
    const char *repair[] = { "worktree", "repair", landing, NULL };
    return dlx_git(rig->clone, repair) == 0;
}

void dlx_fence_call(struct dlx_call *c, const struct dlx_rig *rig,
                           const char *base, const char *head, const char *tip)
{
    dlx_begin(c, "fence_replace");
    (void)json_push_kv_int(&c->input, "seq", 1);
    (void)json_push_kv_str(&c->input, "base", base);
    (void)json_push_kv_str(&c->input, "head", head);
    (void)json_push_kv_str(&c->input, "tip", tip);
    (void)json_push_kv_str(&c->input, "worktree", rig->clone);
}

bool dlx_fence_crash_step(const char *point)
{
    pid_t child = fork();
    if (child == 0) {
        setenv("ZCL_LAND_TEST_FENCE_CRASH", point, 1);
        struct dlx_call call;
        dlx_begin(&call, "step");
        (void)dlx_run(&call);
        dlx_end(&call);
        _exit(88);
    }
    int status = 0;
    return child > 0 && waitpid(child, &status, 0) == child &&
        WIFEXITED(status) && WEXITSTATUS(status) == 87;
}


/* Status deliberately projects selected fields; observation lives in the
 * authoritative outcome. Validate its complete first row with native codec. */
long long dlx_fence_old_recorded(void)
{
    char land[1200], path[1400], raw[32768], canonical[32768]; size_t size;
    dlx_landdir(land, sizeof(land));
    if (snprintf(path, sizeof(path), "%s/outcomes.jsonl", land) >= (int)sizeof(path) ||
        !dlx_slurp(path, raw, sizeof(raw), &size) || memchr(raw, 0, size)) return -1;
    char *lf = memchr(raw, '\n', size);
    if (!lf) return -1;
    *lf = 0;
    if (!zcl_native_dev_land_test_chain_codec(raw, canonical, sizeof(canonical))) return -1;
    struct json_value doc = {0};
    if (!json_read(&doc, canonical, strlen(canonical))) { json_free(&doc); return -1; }
    const struct json_value *clock = json_get(&doc, "terminal_recorded_at");
    bool old = json_get_int(json_get(&doc, "seq")) == 1 &&
        strcmp(json_get_str(json_get(&doc, "state")), "fenced") == 0;
    long long value = old && clock && clock->type == JSON_INT ? json_get_int(clock) : -1;
    json_free(&doc); return value;
}

int dlx_fence_case_admission(struct dlx_fence_case *t)
{
    int failures = 0;
    TEST("land: fenced admission") {
            /* Historical old acceptance/reversion before current protection.
             * The fence must leave that history unknown rather than refused. */
            if (t->scenario == 2) {
                char ref[160];
                (void)snprintf(ref, sizeof(ref), "%s:refs/heads/main", t->rig.tip);
                const char *fetch[] = { "fetch", "--quiet", t->rig.clone, ref, NULL };
                const char *revert[] = { "update-ref", "refs/heads/main", t->base,
                                         t->rig.tip, NULL };
                ASSERT(dlx_git(t->rig.bare, fetch) == 0);
                ASSERT(dlx_git(t->rig.bare, revert) == 0);
            }
            const char *deny_rewinds[] = { "config", "receive.denyNonFastForwards", "true", NULL };
            ASSERT(dlx_git(t->rig.bare, deny_rewinds) == 0);
            /* Missing policy and wrong pins leave original checkpoint exact. */
            setenv("ZCL_LAND_TEST_FENCE_POLICY", "unavailable", 1);
            dlx_fence_call(&t->c, &t->rig, t->base, t->rig.tip, t->successor);
            ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_CONTRACT_UNAVAILABLE");
            dlx_end(&t->c);
            ASSERT(dlx_queue_bytes(t->after, sizeof(t->after), &t->after_len));
            ASSERT(t->before_len == t->after_len && memcmp(t->before, t->after, t->before_len) == 0);
            setenv("ZCL_LAND_TEST_FENCE_POLICY", "monotonic", 1);
            dlx_fence_call(&t->c, &t->rig, t->base, t->base, t->successor);
            ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_OLD_INTENT_CHANGED");
            dlx_end(&t->c);
            dlx_fence_call(&t->c, &t->rig, t->base, t->rig.tip, t->successor);
            ASSERT(dlx_run(&t->c) && dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_str(&t->c, "state"), "fence_armed");
            ASSERT(dlx_int(&t->c, "replacement_seq") == 2);
            dlx_end(&t->c);
            /* Idempotence allocates no second replacement or dispatch. */
            dlx_fence_call(&t->c, &t->rig, t->base, t->rig.tip, t->successor);
            ASSERT(dlx_run(&t->c) && dlx_ok(&t->c));
            ASSERT(dlx_int(&t->c, "replacement_seq") == 2);
            dlx_end(&t->c);
            dlx_begin(&t->c, "cancel"); (void)json_push_kv_int(&t->c.input, "seq", 1);
            ASSERT(dlx_run(&t->c) && !dlx_ok(&t->c));
            ASSERT_STR_EQ(dlx_err_code(&t->c), "FENCE_ACTIVE"); dlx_end(&t->c);
        PASS();
    } _test_next:;
    return failures;
}

#endif /* !defined(_WIN32) */
