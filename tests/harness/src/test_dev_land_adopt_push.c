/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: publisher death, adoption, push checkpoints and attach targets.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)


int test_dev_land_publisher_death(void)
{
    int failures = 0;
    TEST("land: publisher death after remote mutation resumes without another push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], hook[700], wrapper[700], marker[700];
        char received[32];
        size_t received_len;
        int status;
        dlx_isolate("publisher_death");
        ASSERT(dlx_rig_make(&rig, "publisher_death_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        (void)snprintf(hook, sizeof(hook), "%s/hooks/post-receive", rig.bare);
        (void)snprintf(wrapper, sizeof(wrapper), "%s.receive-pack", rig.bare);
        (void)snprintf(marker, sizeof(marker), "%s/hooks/receive-invocations", rig.bare);
        ASSERT(dlx_write(wrapper, "#!/bin/sh\n"
            "printf 'invoked\\n' >> \"$1/hooks/receive-invocations\" || exit 73\n"
            "exec git-receive-pack \"$@\"\n"));
        ASSERT(chmod(wrapper, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.receivepack", wrapper, NULL };
        ASSERT(dlx_git(rig.clone, intercept) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        pid_t publisher = fork();
        ASSERT(publisher >= 0);
        if (publisher == 0) {
            char script[256];
            /* post-receive runs only after the remote ref transaction.
             * Kill this publisher, not the test runner or Git descendants.
             * The hook exits immediately: no FIFO or sleeping orphan. Its
             * own session lets dlx_wait_publisher see its Git descendants
             * out. */
            (void)setsid();
            (void)alarm(30);
            (void)snprintf(script, sizeof(script),
                "#!/bin/sh\nkill -KILL %ld\n", (long)getpid());
            if (!dlx_write(hook, script) || chmod(hook, 0700) != 0)
                _exit(2);
            dlx_begin(&c, "step");
            (void)dlx_run(&c);
            _exit(3);
        }
        pid_t waited = dlx_wait_publisher(publisher, &status);
        ASSERT_EQ(waited, publisher);
        ASSERT(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, rig.tip);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        /* Remove the injector before a new process takes the existing locks. */
        ASSERT(unlink(hook) == 0);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *row = json_get(&c.reply.data, "in_flight");
        ASSERT(row && row->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(row, "tip")), rig.tip);
        ASSERT_STR_EQ(json_get_str(json_get(row, "base")), before);
        const struct json_value *pending_outcomes = dlx_arr(&c, "outcomes");
        ASSERT(pending_outcomes);
        ASSERT_EQ(pending_outcomes->num_children, 0);
        dlx_end(&c);
        char land[1200], queue_path[1400], wire[8192];
        size_t wire_len;
        dlx_landdir(land, sizeof(land));
        (void)snprintf(queue_path, sizeof(queue_path), "%s/queue.jsonl", land);
        ASSERT(dlx_slurp(queue_path, wire, sizeof(wire), &wire_len));
        struct json_value retained;
        json_init(&retained);
        ASSERT(json_read(&retained, wire, wire_len));
        ASSERT_STR_EQ(json_get_str(json_get(&retained, "local")), rig.tip);
        ASSERT_STR_EQ(json_get_str(json_get(&retained, "state")), "inflight");
        ASSERT_STR_EQ(json_get_str(json_get(&retained, "phase")), "push");
        ASSERT_STR_EQ(json_get_str(json_get(&retained, "tip_pushed")), "");
        ASSERT(json_get_int(json_get(&retained, "push_diagnostic_pending")) == 1);
        json_free(&retained);
        pid_t receiver = fork();
        ASSERT(receiver >= 0);
        if (receiver == 0)
            _exit(dlx_resume_after_death() ? 0 : 4);
        waited = dlx_wait_child(receiver, &status);
        ASSERT_EQ(waited, receiver);
        ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 0);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "empty");
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes && outcomes->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&outcomes->children[0], "state")), "landed");
        ASSERT_STR_EQ(json_get_str(json_get(&outcomes->children[0], "tip")), rig.tip);
        ASSERT_STR_EQ(json_get_str(json_get(&outcomes->children[0], "tip_pushed")), rig.tip);
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* Publisher holds the step lock and is killed before it claims. The queued
 * row stays eligible, status names drain_absent, and a different process
 * adopts through dev land step: one claim, one push, refetch matches.
 * Split so each function stays under the cyclomatic cap; the TEST below
 * is the one case. */

bool dlx_eq_str(const char *got, const char *want)
{
    if (!got || !want || strcmp(got, want) != 0) {
        printf("FAIL str got='%s' want='%s'\n",
               got ? got : "(nil)", want ? want : "(nil)");
        return false;
    }
    return true;
}

static bool dlx_eq_i64(int64_t got, int64_t want, const char *what)
{
    if (got != want) {
        printf("FAIL %s got=%lld want=%lld\n", what ? what : "int",
               (long long)got, (long long)want);
        return false;
    }
    return true;
}

bool dlx_has(const char *s, const char *frag)
{
    if (!s || !frag || strstr(s, frag) == NULL) {
        printf("FAIL missing '%s'\n", frag ? frag : "(nil)");
        return false;
    }
    return true;
}

const char *dlx_jstr(const struct json_value *obj, const char *key)
{
    const char *s = json_get_str(json_get(obj, key));
    return s ? s : "";
}

static bool dlx_alls(const bool *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (!v[i])
            return false;
    }
    return true;
}

static void dlx_adopt_hold_child(const char *landdir)
{
    int fd;
    (void)alarm(30);
    fd = dlx_step_lock_take(landdir);
    if (fd < 0)
        _exit(2);
    for (;;)
        pause();
}

static bool dlx_wait_step_held(const char *landdir)
{
    for (int i = 0; i < 100; i++) {
        if (dlx_step_held(landdir) == 1)
            return true;
        struct timespec pause = { 0, 20 * 1000 * 1000L };
        (void)nanosleep(&pause, NULL); /* real-clock: adoption child holds step.lock; no fake-clock seam reaches that flock. */
    }
    return false;
}

static bool dlx_child_ok(pid_t pid, int want)
{
    int status = 0;
    pid_t waited = dlx_wait_child(pid, &status);
    return waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == want;
}

static bool dlx_killed_ok(pid_t pid)
{
    int status = 0;
    if (kill(pid, SIGKILL) != 0)
        return false;
    if (dlx_wait_child(pid, &status) != pid)
        return false;
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
}

static bool dlx_adopt_submit(struct dlx_adopt_fix *fx)
{
    struct dlx_call c;
    memset(fx, 0, sizeof(*fx));
    if (!dlx_rig_make(&fx->rig, "drain_adopt_rig"))
        return false;
    if (!dlx_origin_main(&fx->rig, fx->before))
        return false;
    dlx_submit(&c, &fx->rig, fx->rig.tip);
    if (!dlx_run(&c) || !dlx_ok(&c)) {
        dlx_end(&c);
        return false;
    }
    dlx_end(&c);
    dlx_landdir(fx->landdir, sizeof(fx->landdir));
    if ((size_t)snprintf(fx->qpath, sizeof(fx->qpath), "%s/queue.jsonl",
                         fx->landdir) >= sizeof(fx->qpath))
        return false;
    if (!dlx_slurp(fx->qpath, fx->qsnap, sizeof(fx->qsnap), &fx->qsnap_len))
        return false;
    return fx->qsnap_len > 0;
}

bool dlx_status_json(struct dlx_call *c)
{
    dlx_begin(c, "status");
    (void)json_push_kv_bool(&c->input, "json", true);
    if (!dlx_run(c) || !dlx_ok(c)) {
        dlx_end(c);
        return false;
    }
    return true;
}

static bool dlx_beat_active_status(void)
{
    struct dlx_call c;
    const struct json_value *steer;
    bool ok;
    if (!dlx_status_json(&c))
        return false;
    steer = json_get(&c.reply.data, "steer");
    ok = steer && steer->type == JSON_OBJ &&
         dlx_eq_str(dlx_str(&c, "incident"), "none") &&
         dlx_has(dlx_jstr(steer, "receiver_driver"), "beat_active") &&
         dlx_eq_str(dlx_jstr(steer, "lease"), "step.lock:held");
    dlx_end(&c);
    return ok;
}

static bool dlx_step_is_busy(void)
{
    struct dlx_call c;
    bool busy;
    dlx_begin(&c, "step");
    if (!dlx_run(&c)) {
        dlx_end(&c);
        return false;
    }
    busy = strcmp(dlx_err_code(&c), "STEP_BUSY") == 0;
    dlx_end(&c);
    return busy;
}

static bool dlx_adopt_while_held(struct dlx_adopt_fix *fx)
{
    pid_t pid = fork();
    char after[64];
    bool saw;
    if (pid < 0)
        return false;
    if (pid == 0) {
        dlx_adopt_hold_child(fx->landdir);
        _exit(2);
    }
    saw = dlx_wait_step_held(fx->landdir) && dlx_step_is_busy() &&
          dlx_origin_main(&fx->rig, after) &&
          strcmp(after, fx->before) == 0 && dlx_beat_active_status();
    if (!dlx_killed_ok(pid))
        return false;
    return saw;
}

static bool dlx_queue_unchanged(const struct dlx_adopt_fix *fx)
{
    char after[8192];
    size_t n = 0;
    if (!dlx_slurp(fx->qpath, after, sizeof(after), &n))
        return false;
    return n == fx->qsnap_len && memcmp(after, fx->qsnap, n) == 0;
}

static bool dlx_steer_stalled(const struct dlx_call *c,
                              const struct dlx_adopt_fix *fx)
{
    const struct json_value *steer = json_get(&c->reply.data, "steer");
    const struct json_value *queued = dlx_arr(c, "queued");
    bool v[8];
    if (!steer || steer->type != JSON_OBJ)
        return false;
    v[0] = dlx_eq_str(dlx_str(c, "incident"), "drain_absent");
    v[1] = dlx_eq_str(dlx_jstr(steer, "candidate"), fx->rig.tip);
    v[2] = dlx_eq_i64(json_get_int(json_get(steer, "seq")), 1, "seq");
    v[3] = dlx_eq_str(dlx_jstr(steer, "phase"), "queued");
    v[4] = dlx_eq_str(dlx_jstr(steer, "owner"), "unclaimed");
    v[5] = dlx_eq_str(dlx_jstr(steer, "lease"), "none");
    v[6] = dlx_eq_str(dlx_jstr(steer, "proof_state"), "not_requested");
    v[7] = dlx_has(dlx_jstr(steer, "receiver_driver"), "no_active_drain");
    if (!dlx_alls(v, 8))
        return false;
    v[0] = dlx_eq_str(dlx_jstr(steer, "first_missing_transition"), "claim");
    v[1] = dlx_eq_str(dlx_jstr(steer, "wake_command"), "z23 dev land step");
    v[2] = dlx_has(dlx_jstr(steer, "remote_state"), "cached:");
    v[3] = queued && queued->num_children == 1;
    v[4] = json_get(&c->reply.data, "in_flight") == NULL;
    return dlx_alls(v, 5);
}

static bool dlx_screen_names_incident(void)
{
    struct dlx_call c;
    bool ok;
    dlx_begin(&c, "status");
    if (!dlx_run(&c) || !dlx_ok(&c)) {
        dlx_end(&c);
        return false;
    }
    ok = dlx_has(dlx_str(&c, "screen"), "incident: drain_absent") &&
         dlx_has(dlx_str(&c, "screen"),
                 "steer.wake_command: z23 dev land step");
    dlx_end(&c);
    return ok;
}

static bool dlx_adopt_incident(const struct dlx_adopt_fix *fx)
{
    struct dlx_call c;
    bool stalled;
    if (!dlx_queue_unchanged(fx))
        return false;
    if (!dlx_status_json(&c))
        return false;
    stalled = dlx_steer_stalled(&c, fx);
    dlx_end(&c);
    if (!stalled)
        return false;
    return dlx_screen_names_incident();
}

bool dlx_arm_receive_count(struct dlx_adopt_fix *fx)
{
    char wrapper[700];
    const char *count_push[4];
    if ((size_t)snprintf(wrapper, sizeof(wrapper), "%s.receive-pack",
                         fx->rig.bare) >= sizeof(wrapper))
        return false;
    if ((size_t)snprintf(fx->marker, sizeof(fx->marker),
                         "%s/hooks/receive-invocations", fx->rig.bare) >=
        sizeof(fx->marker))
        return false;
    if (!dlx_write(wrapper,
                   "#!/bin/sh\n"
                   "printf 'invoked\\n' >> \"$1/hooks/receive-invocations\" || exit 73\n"
                   "exec git-receive-pack \"$@\"\n"))
        return false;
    if (chmod(wrapper, 0700) != 0)
        return false;
    count_push[0] = "config";
    count_push[1] = "remote.origin.receivepack";
    count_push[2] = wrapper;
    count_push[3] = NULL;
    return dlx_git(fx->rig.clone, count_push) == 0;
}

static void dlx_adopt_claim_child(void)
{
    struct dlx_call step;
    (void)alarm(60);
    dlx_begin(&step, "step");
    if (!dlx_run(&step) || !dlx_ok(&step) ||
        strcmp(dlx_str(&step, "state"), "started") != 0)
        _exit(4);
    _exit(0);
}

static bool dlx_one_claim_row(const struct dlx_adopt_fix *fx)
{
    char wire[8192];
    size_t n = 0;
    struct json_value row;
    bool ok;
    if (dlx_file_exists(fx->marker))
        return false;
    if (!dlx_slurp(fx->qpath, wire, sizeof(wire), &n))
        return false;
    json_init(&row);
    if (!json_read(&row, wire, n)) {
        json_free(&row);
        return false;
    }
    ok = dlx_eq_str(dlx_jstr(&row, "state"), "inflight") &&
         dlx_eq_str(dlx_jstr(&row, "phase"), "prove") &&
         dlx_eq_i64(json_get_int(json_get(&row, "attempt")), 1, "attempt") &&
         dlx_eq_str(dlx_jstr(&row, "tip"), fx->rig.tip);
    json_free(&row);
    return ok;
}

static bool dlx_inflight_only(const struct dlx_adopt_fix *fx)
{
    struct dlx_call c;
    const struct json_value *flight;
    const struct json_value *queued;
    bool ok;
    if (!dlx_status_json(&c))
        return false;
    flight = json_get(&c.reply.data, "in_flight");
    queued = dlx_arr(&c, "queued");
    ok = flight && flight->type == JSON_OBJ &&
         dlx_eq_str(dlx_jstr(flight, "tip"), fx->rig.tip) &&
         dlx_eq_str(dlx_str(&c, "incident"), "none") &&
         queued && queued->num_children == 0;
    dlx_end(&c);
    return ok;
}

static bool dlx_adopt_claim(struct dlx_adopt_fix *fx)
{
    pid_t pid;
    if (!dlx_arm_receive_count(fx))
        return false;
    pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        dlx_adopt_claim_child();
        _exit(4);
    }
    if (!dlx_child_ok(pid, 0))
        return false;
    if (!dlx_one_claim_row(fx))
        return false;
    return dlx_inflight_only(fx);
}

static void dlx_adopt_push_child(void)
{
    struct dlx_call step;
    (void)alarm(60);
    dlx_begin(&step, "step");
    if (!dlx_run(&step) || !dlx_ok(&step) ||
        strcmp(dlx_str(&step, "state"), "landed") != 0)
        _exit(5);
    dlx_end(&step);
    dlx_begin(&step, "step");
    if (!dlx_run(&step) || !dlx_ok(&step) ||
        strcmp(dlx_str(&step, "state"), "empty") != 0)
        _exit(6);
    _exit(0);
}

bool dlx_receive_once(const struct dlx_adopt_fix *fx)
{
    char wire[64];
    size_t n = 0;
    if (!dlx_slurp(fx->marker, wire, sizeof(wire), &n))
        return false;
    return n == 8 && memcmp(wire, "invoked\n", 8) == 0;
}

static bool dlx_refetch_matches(const struct dlx_adopt_fix *fx)
{
    char after[64], fetched[64];
    const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
    const char *rev[] = { "rev-parse", "origin/main", NULL };
    if (!dlx_origin_main(&fx->rig, after))
        return false;
    if (strcmp(after, fx->rig.tip) != 0)
        return false;
    if (dlx_git(fx->rig.clone, fetch) != 0)
        return false;
    if (dlx_git_out(fx->rig.clone, rev, fetched, sizeof(fetched)) != 0)
        return false;
    return strcmp(fetched, fx->rig.tip) == 0 && strcmp(fetched, after) == 0;
}

static bool dlx_step_empty(void)
{
    struct dlx_call c;
    bool empty;
    dlx_begin(&c, "step");
    if (!dlx_run(&c) || !dlx_ok(&c)) {
        dlx_end(&c);
        return false;
    }
    empty = strcmp(dlx_str(&c, "state"), "empty") == 0;
    dlx_end(&c);
    return empty;
}

static bool dlx_adopt_push(struct dlx_adopt_fix *fx)
{
    pid_t pid;
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0) {
        dlx_adopt_push_child();
        _exit(6);
    }
    if (!dlx_child_ok(pid, 0))
        return false;
    if (!dlx_receive_once(fx) || !dlx_refetch_matches(fx))
        return false;
    if (!dlx_step_empty())
        return false;
    return dlx_receive_once(fx);
}

static bool dlx_live_drive_status(void)
{
    struct dlx_call c;
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *s = json_get(&c.reply.data, "steer");
    bool ok = dlx_eq_str(dlx_str(&c, "incident"), "none") &&
        dlx_eq_str(dlx_jstr(s, "owner"), "unclaimed") &&
        dlx_eq_str(dlx_jstr(s, "lease"), "none") &&
        dlx_has(dlx_jstr(s, "receiver_driver"), "drive_active") &&
        dlx_eq_str(dlx_jstr(s, "wake_command"), "observe: z23 dev land status");
    dlx_end(&c);
    return ok;
}

static bool dlx_live_drive_busy(void)
{
    struct dlx_call c;
    dlx_begin(&c, "drive");
    (void)json_push_kv_int(&c.input, "seq", 1);
    bool ok = dlx_run(&c) && !dlx_ok(&c) &&
        strcmp(dlx_err_code(&c), "DRIVE_BUSY") == 0;
    dlx_end(&c);
    return ok;
}

static void dlx_adopt_drive_child(const char *path, const int ready[2],
                                   const int release[2])
{
    char byte = 0;
    (void)alarm(30);
    close(ready[0]); close(release[1]);
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB) != 0)
        _exit(2);
    if (write(ready[1], "x", 1) != 1 || read(release[0], &byte, 1) != 0)
        _exit(3);
    close(fd);
    _exit(0);
}

static bool dlx_adopt_drive_held(const struct dlx_adopt_fix *fx)
{
    int ready[2], release[2], status;
    char path[1400], byte = 0;
    if (pipe(ready) != 0)
        return false;
    if (pipe(release) != 0) {
        close(ready[0]); close(ready[1]);
        return false;
    }
    (void)snprintf(path, sizeof(path), "%s/drive.lock", fx->landdir);
    pid_t child = fork();
    if (child == 0)
        dlx_adopt_drive_child(path, ready, release);
    close(ready[1]); close(release[0]);
    bool ok = child > 0 && read(ready[0], &byte, 1) == 1;
    if (ok)
        ok = dlx_live_drive_status() && dlx_live_drive_busy() &&
             dlx_queue_unchanged(fx);
    close(ready[0]); close(release[1]);
    if (child <= 0)
        return false;
    bool joined = dlx_wait_child(child, &status) == child;
    return ok && joined && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int test_dev_land_drain_adoption(void)
{
    int failures = 0;
    TEST("land: dead publisher leaves the queued row; one integrator adopts and pushes once") {
        struct dlx_adopt_fix fx;
        dlx_isolate("drain_adopt");
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_DRAIN_IDLE_SEC", "0", 1);
        ASSERT(dlx_adopt_submit(&fx));
        ASSERT(dlx_adopt_while_held(&fx));
        ASSERT(dlx_adopt_drive_held(&fx));
        ASSERT(dlx_adopt_incident(&fx));
        ASSERT(dlx_adopt_claim(&fx));
        ASSERT(dlx_adopt_push(&fx));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_postpush_observation_missing(bool lost_ack)
{
    int failures = 0;
    TEST(lost_ack
        ? "land: final-attempt lost acknowledgement reconciles without duplicate push"
        : "land: successful push awaits independent observation and reconciles once") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[64], after[64], upload_pack[700], hook[700], marker[700];
        char receive_pack[700], invocations[700];
        char received[32];
        size_t received_len;
        dlx_isolate("postpush_observation_missing");
        ASSERT(dlx_rig_make(&rig, "postpush_observation_missing_rig"));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        if (lost_ack) {
            char land[1200], path[1400], wire[8192];
            size_t length;
            dlx_landdir(land, sizeof(land));
            (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
            ASSERT(dlx_slurp(path, wire, sizeof(wire), &length));
            wire[length] = '\0';
            char *attempt = strstr(wire, "\"attempt\":1");
            ASSERT(attempt != NULL);
            attempt[10] = '3';
            ASSERT(dlx_write(path, wire));
        }
        (void)snprintf(hook, sizeof(hook), "%s/hooks/post-receive", rig.bare);
        (void)snprintf(marker, sizeof(marker), "%s/hooks/received", rig.bare);
        ASSERT(dlx_write(hook,
            "#!/bin/sh\n"
            "printf 'received\\n' >> hooks/received || exit 73\n"));
        ASSERT(chmod(hook, 0700) == 0);
        (void)snprintf(upload_pack, sizeof(upload_pack), "%s.upload-pack", rig.bare);
        ASSERT(dlx_write(upload_pack,
            "#!/bin/sh\n"
            "test ! -f \"$1/hooks/received\" || exit 75\n"
            "exec git-upload-pack \"$@\"\n"));
        ASSERT(chmod(upload_pack, 0700) == 0);
        (void)snprintf(receive_pack, sizeof(receive_pack), "%s.receive-pack", rig.bare);
        (void)snprintf(invocations, sizeof(invocations), "%s/hooks/receive-invocations", rig.bare);
        ASSERT(dlx_write(receive_pack, lost_ack ?
            "#!/bin/sh\n"
            "printf 'invoked\\n' >> \"$1/hooks/receive-invocations\" || exit 73\n"
            "git-receive-pack \"$@\" || exit $?\n"
            "exit 75\n" :
            "#!/bin/sh\n"
            "printf 'invoked\\n' >> \"$1/hooks/receive-invocations\" || exit 73\n"
            "exec git-receive-pack \"$@\"\n"));
        ASSERT(chmod(receive_pack, 0700) == 0);
        const char *intercept[] = { "config", "remote.origin.uploadpack",
                                   upload_pack, NULL };
        const char *count_push[] = { "config", "remote.origin.receivepack",
                                    receive_pack, NULL };
        const char *restore[] = { "config", "--unset", "remote.origin.uploadpack", NULL };
        ASSERT(dlx_git(rig.clone, intercept) == 0);
        ASSERT(dlx_git(rig.clone, count_push) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        /* Establish the actual mutation before checking its reported state. */
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT(strcmp(after, before) != 0);
        ASSERT_STR_EQ(after, rig.tip);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 9);
        ASSERT(memcmp(received, "received\n", 9) == 0);
        ASSERT(dlx_slurp(invocations, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "REMOTE_OBSERVATION_UNAVAILABLE");
        ASSERT(c.reply.error.retryable);
        ASSERT(!c.reply.error.human_action_required);
        ASSERT(c.reply.error.mutated);
        dlx_end(&c);
        dlx_begin(&c, "status");
        (void)json_push_kv_bool(&c.input, "json", true);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        const struct json_value *row = json_get(&c.reply.data, "in_flight");
        ASSERT(row && row->type == JSON_OBJ);
        ASSERT_STR_EQ(json_get_str(json_get(row, "phase")), "push");
        ASSERT_STR_EQ(json_get_str(json_get(row, "tip")), rig.tip);
        ASSERT_STR_EQ(json_get_str(json_get(row, "base")), before);
        ASSERT_EQ(json_get_int(json_get(row, "attempt")), lost_ack ? 3 : 1);
        dlx_end(&c);
        ASSERT(dlx_git(rig.clone, restore) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT_EQ(dlx_int(&c, "attempt"), lost_ack ? 3 : 1);
        dlx_end(&c);
        ASSERT(dlx_slurp(marker, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 9);
        ASSERT(memcmp(received, "received\n", 9) == 0);
        ASSERT(dlx_slurp(invocations, received, sizeof(received), &received_len));
        ASSERT_EQ(received_len, 8);
        ASSERT(memcmp(received, "invoked\n", 8) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_land_prepush_checkpoint(void)
{
    int failures = 0;
    TEST("land: push phase and exact pair are durable before pre-push runs") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], hook[1400], script[1800], base[64];
        dlx_isolate("prepush_checkpoint");
        ASSERT(dlx_rig_make(&rig, "prepush_checkpoint_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT((size_t)snprintf(hook, sizeof(hook), "%s/pre-push",
                                g_dlx_hooks_ok) < sizeof(hook));
        ASSERT((size_t)snprintf(script, sizeof(script),
            "#!/bin/sh\n"
            "grep -F '\"phase\":\"push\"' '%s/queue.jsonl' >/dev/null || exit 73\n"
            "grep -F '\"base\":\"%s\"' '%s/queue.jsonl' >/dev/null || exit 74\n"
            "exit 0\n", landdir, base, landdir) < sizeof(script));
        ASSERT(dlx_write(hook, script) && chmod(hook, 0755) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_prepush_persist_refusal(void)
{
    int failures = 0;
    TEST("land: failed pre-push persistence refuses remote mutation") {
        struct dlx_rig rig;
        struct dlx_call c;
        char landdir[1200], base[64], observed[64];
        dlx_isolate("prepush_persist_refusal");
        ASSERT(dlx_rig_make(&rig, "prepush_persist_refusal_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_landdir(landdir, sizeof(landdir));
        ASSERT(chmod(landdir, 0500) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_INTENT_PERSIST_FAILED");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, observed));
        ASSERT_STR_EQ(observed, base);
        ASSERT(chmod(landdir, 0700) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_prepush_sync_refusal(void)
{
    int failures = 0;
    TEST("land: failed directory sync after checkpoint refuses push and retries") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], observed[64];
        dlx_isolate("prepush_sync_refusal");
        ASSERT(dlx_rig_make(&rig, "prepush_sync_refusal_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        setenv("ZCL_LAND_TEST_DIR_SYNC_FAIL", "1", 1);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_INTENT_PERSIST_FAILED");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, observed));
        ASSERT_STR_EQ(observed, base);
        unsetenv("ZCL_LAND_TEST_DIR_SYNC_FAIL");
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    unsetenv("ZCL_LAND_TEST_DIR_SYNC_FAIL");
    dlx_restore();
    return failures;
}

int test_dev_land_missing_publication_intent(void)
{
    int failures = 0;
    TEST("land: a proven pair without canonical intent cannot push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], observed[64];
        dlx_isolate("missing_publication_intent");
        ASSERT(dlx_rig_make(&rig, "missing_publication_intent_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_REQUIRED");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, observed));
        ASSERT_STR_EQ(observed, base);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* ── attach target: the blocked beat names its row; attach never targets
 * nothing ─────────────────────────────────────────────────────────────── */

/* Submit rig.tip and take the first beat under a running proof, then make
 * the proof PASS with unsigned publication forbidden: the row is a live
 * exact proven pair that still needs the operator's signed intent. */
bool dlx_attach_proven_pair(struct dlx_rig *rig, const char *tag,
                                   char base[64])
{
    struct dlx_call c;
    char rig_tag[128];
    (void)snprintf(rig_tag, sizeof(rig_tag), "%s_rig", tag);
    if (!dlx_rig_make(rig, rig_tag) || !dlx_origin_main(rig, base))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    bool ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    dlx_begin(&c, "step");
    ok = ok && dlx_run(&c) && dlx_ok(&c) &&
         strcmp(dlx_str(&c, "state"), "started") == 0;
    dlx_end(&c);
    unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    return ok;
}

bool dlx_queue_bytes(char *out, size_t cap, size_t *len)
{
    char land[1200], path[1400];
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    if (!dlx_slurp(path, out, cap - 1, len))
        return false;
    out[*len] = '\0';
    return true;
}

/* Serialize the captured refusal through the real registry envelope and
 * return the wire error object's next_action and evidence plus the reason
 * of the first next[] entry: a failed envelope omits data, so these are
 * what a shell caller actually sees. */
static bool dlx_blocked_wire(const struct dlx_call *call, char *action,
                             char *evidence, char *reason, size_t cap)
{
    if (!call->request.spec) return false;
    struct zcl_command_spec spec = *call->request.spec;
    spec.handler = dlx_captured_handler;
    char wire[8192];
    enum zcl_command_exit code;
    g_dlx_captured_reply = &call->reply;
    size_t len = zcl_command_registry_execute_json(zcl_command_catalog(),
        &spec, NULL, &call->input, false, DLX_PATH, NULL, 0, 0, NULL,
        wire, sizeof(wire), &code);
    g_dlx_captured_reply = NULL;
    struct json_value doc;
    json_init(&doc);
    bool ok = len > 0 && json_read(&doc, wire, len);
    const struct json_value *error = json_get(&doc, "error");
    const struct json_value *next = json_get(&doc, "next");
    const char *a = json_get_str(json_get(error, "next_action"));
    const char *e = json_get_str(json_get(error, "evidence"));
    const char *r = next && next->type == JSON_ARR && next->num_children > 0
        ? json_get_str(json_get(&next->children[0], "reason")) : NULL;
    ok = ok && a && e && r;
    if (ok) {
        (void)snprintf(action, cap, "%s", a);
        (void)snprintf(evidence, cap, "%s", e);
        (void)snprintf(reason, cap, "%s", r);
    }
    json_free(&doc);
    return ok;
}

/* The witness: after PASS, drive stops at PUBLICATION_INTENT_REQUIRED. The
 * reply must name the row, its exact pair, and the exact attach command, in
 * data and on the wire, so the operator cannot run `attach --seq=`. */
int test_dev_land_blocked_names_attach_target(void)
{
    int failures = 0;
    TEST("land: a proven pair blocked on intent names seq, pair and attach --seq") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], action[256], evidence[256], reason[256];
        dlx_isolate("blocked_attach_target");
        ASSERT(dlx_attach_proven_pair(&rig, "blocked_attach_target", base));
        dlx_begin(&c, "drive");
        ASSERT(dlx_run(&c));
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_REQUIRED");
        ASSERT(!c.reply.error.mutated);
        ASSERT(dlx_int(&c, "seq") == 1);
        ASSERT_STR_EQ(dlx_str(&c, "tip"), rig.tip);
        ASSERT_STR_EQ(dlx_str(&c, "base"), base);
        ASSERT(strlen(dlx_str(&c, "head_commit")) == 40);
        ASSERT_STR_EQ(dlx_str(&c, "next_command"),
                      "z23 dev land attach --seq=1");
        ASSERT_STR_EQ(c.reply.error.next_action,
                      "z23 dev land attach --seq=1");
        ASSERT(strstr(dlx_err_evidence(&c), "seq=1 ") != NULL);
        ASSERT(strstr(dlx_err_evidence(&c), base) != NULL);
        ASSERT(dlx_blocked_wire(&c, action, evidence, reason,
                                sizeof(action)));
        ASSERT_STR_EQ(action, "z23 dev land attach --seq=1");
        ASSERT(strstr(evidence, "seq=1 ") != NULL);
        ASSERT(strstr(evidence, rig.tip) != NULL);
        ASSERT(strstr(reason, "z23 dev land attach --seq=1") != NULL);
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_REQUIRED");
        ASSERT_STR_EQ(c.reply.error.next_action,
                      "z23 dev land attach --seq=1");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        /* The named command, run as named, attaches and the pair lands. */
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "attached");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_attach_resolves_single_row(void)
{
    int failures = 0;
    TEST("land: attach without seq seals the one proven row lacking intent") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_resolves_single");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_resolves_single", base));
        dlx_begin(&c, "attach");
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "attached");
        ASSERT(dlx_int(&c, "seq") == 1);
        ASSERT_STR_EQ(dlx_str(&c, "tip"), rig.tip);
        ASSERT_STR_EQ(dlx_str(&c, "target"), "resolved");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A deliberate signer action should consume the already passed proof and
 * publish under the same queue lock, without a second scheduled step. */
int test_dev_land_attach_publish_one_window(void)
{
    int failures = 0;
    TEST("land: attach_publish seals and lands the exact proven pair in one beat") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_publish_window");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_window", base));
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        ASSERT(dlx_int(&c, "seq") == 1);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_attach_publish_exact_pair(void)
{
    int failures = 0;
    TEST("land: attach_publish refuses a reviewed pair that changed") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_publish_exact_pair");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_exact_pair", base));
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_str(&c.input, "base", base);
        (void)json_push_kv_str(&c.input, "head", base);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PAIR_CHANGED");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_attach_publish_malformed_pair(void)
{
    int failures = 0;
    TEST("land: malformed present pair pins cannot become an unpinned push") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_publish_malformed_pair");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_malformed_pair", base));
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_int(&c.input, "base", 0);
        (void)json_push_kv_int(&c.input, "head", 0);
        /* Exercise the handler too: a wire schema may reject earlier. */
        c.request.spec = NULL;
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "BAD_INPUT");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_attach_publish_wait_expires(void)
{
    int failures = 0;
    TEST("land: reviewed attach wait expires while proof is still pending") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_publish_wait_expires");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_wait_expires", base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_str(&c.input, "base", base);
        (void)json_push_kv_str(&c.input, "head", rig.tip);
        (void)json_push_kv_int(&c.input, "wait_ms", 100);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PROOF_WAIT_EXPIRED");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_attach_publish_wait_failure(void)
{
    int failures = 0;
    TEST("land: reviewed attach wait stops on a failed proof") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("attach_publish_wait_failure");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_wait_failure", base));
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_str(&c.input, "base", base);
        (void)json_push_kv_str(&c.input, "head", rig.tip);
        (void)json_push_kv_int(&c.input, "wait_ms", 100);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PROOF_FAILED");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_attach_publish_wait_busy(void)
{
    int failures = 0;
    int lockfd = -1;
    TEST("land: reviewed attach wait names an occupied step lock") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], land[1200];
        dlx_isolate("attach_publish_wait_busy");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_wait_busy", base));
        dlx_landdir(land, sizeof(land));
        lockfd = dlx_step_lock_take(land);
        ASSERT(lockfd >= 0);
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        (void)json_push_kv_str(&c.input, "base", base);
        (void)json_push_kv_str(&c.input, "head", rig.tip);
        (void)json_push_kv_int(&c.input, "wait_ms", 100);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_STEP_WAIT_EXPIRED");
        dlx_end(&c);
        dlx_step_lock_release(lockfd);
        lockfd = -1;
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    if (lockfd >= 0) dlx_step_lock_release(lockfd);
    dlx_restore();
    return failures;
}

int test_dev_land_attach_publish_moved_base(void)
{
    int failures = 0;
    TEST("land: attach_publish refuses a moved base without signing or pushing") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], stranger[64], remote[64];
        dlx_isolate("attach_publish_moved_base");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_moved_base", base));
        const char *branch[] = {"checkout", "--quiet", "-B", "side", base,
                                NULL};
        const char *push[] = {"push", "--quiet", "origin", "HEAD:main", NULL};
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "other\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "EXPECTED_BASE_MISMATCH");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, stranger);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *flight = json_get(&c.reply.data, "in_flight");
        ASSERT(flight != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(flight, "base")), base);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_attach_publish_push_checkpoint(void)
{
    int failures = 0;
    TEST("land: attach_publish never redispatches a prior push checkpoint") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], land[1200], path[1400], row[8192];
        size_t used = 0;
        dlx_isolate("attach_publish_checkpoint");
        ASSERT(dlx_attach_proven_pair(&rig, "attach_publish_checkpoint", base));
        dlx_landdir(land, sizeof(land));
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_slurp(path, row, sizeof(row) - 1, &used));
        row[used] = '\0';
        char *phase = strstr(row, "\"phase\":\"prove\"");
        ASSERT(phase != NULL);
        memcpy(phase, "\"phase\":\"push\" ", 15);
        ASSERT(dlx_write(path, row));
        dlx_begin(&c, "attach_publish");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_cancel_push_checkpoint(void)
{
    int failures = 0;
    TEST("land: cancel preserves a push checkpoint for reconciliation") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64], land[1200], path[1400], row[8192];
        size_t used = 0;
        dlx_isolate("cancel_push_checkpoint");
        ASSERT(dlx_attach_proven_pair(&rig, "cancel_push_checkpoint", base));
        dlx_landdir(land, sizeof(land));
        (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
        ASSERT(dlx_slurp(path, row, sizeof(row) - 1, &used));
        row[used] = '\0';
        char *phase = strstr(row, "\"phase\":\"prove\"");
        ASSERT(phase != NULL);
        memcpy(phase, "\"phase\":\"push\" ", 15);
        ASSERT(dlx_write(path, row));
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUSH_OUTCOME_UNKNOWN");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT(json_get(&c.reply.data, "in_flight") != NULL);
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_attach_target_none(void)
{
    int failures = 0;
    TEST("land: attach without seq and no proven row refuses and mutates nothing") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        dlx_isolate("attach_target_none");
        ASSERT(dlx_rig_make(&rig, "attach_target_none_rig"));
        /* Empty queue. */
        dlx_begin(&c, "attach");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "ATTACH_TARGET_NONE");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        /* A live row whose exact proof is still running is not a target. */
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        ASSERT(dlx_queue_bytes(before, sizeof(before), &before_len));
        dlx_begin(&c, "attach");
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "ATTACH_TARGET_NONE");
        ASSERT(!c.reply.error.mutated);
        ASSERT(strstr(dlx_err_evidence(&c), "seq=1") != NULL);
        const struct json_value *cands = dlx_arr(&c, "candidates");
        ASSERT(cands && cands->num_children == 0);
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(after, sizeof(after), &after_len));
        ASSERT(before_len == after_len &&
               memcmp(before, after, before_len) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_attach_explicit_unattachable(void)
{
    int failures = 0;
    TEST("land: attach with a seq that is not a proven pair names its state") {
        struct dlx_rig rig;
        struct dlx_call c;
        char before[8192], after[8192];
        size_t before_len = 0, after_len = 0;
        dlx_isolate("attach_explicit_unattachable");
        ASSERT(dlx_rig_make(&rig, "attach_explicit_unattachable_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(before, sizeof(before), &before_len));
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c));
        ASSERT(!dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PAIR_UNAVAILABLE");
        ASSERT(strstr(dlx_err_evidence(&c), "seq=1 state=queued") != NULL);
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT(!c.reply.error.mutated);
        dlx_end(&c);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 9);
        ASSERT(dlx_run(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_PAIR_UNAVAILABLE");
        ASSERT(strstr(dlx_err_evidence(&c), "seq=9 not in the live queue")
               != NULL);
        dlx_end(&c);
        ASSERT(dlx_queue_bytes(after, sizeof(after), &after_len));
        ASSERT(before_len == after_len &&
               memcmp(before, after, before_len) == 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* Model two live proven rows (a damaged or hand-edited queue): duplicate
 * the proven row under the next sequence number. */
bool dlx_duplicate_proven_row(void)
{
    char land[1200], path[1400], wire[8192], twin[4096];
    size_t len = 0;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    if (!dlx_slurp(path, wire, sizeof(wire) - 1, &len)) return false;
    wire[len] = '\0';
    char *eol = strchr(wire, '\n');
    if (!eol || eol[1] != '\0' || (size_t)(eol - wire) >= sizeof(twin))
        return false;
    memcpy(twin, wire, (size_t)(eol - wire));
    twin[eol - wire] = '\0';
    char *seq = strstr(twin, "\"seq\":1");
    if (!seq || (seq[7] >= '0' && seq[7] <= '9')) return false;
    seq[6] = '2';
    size_t used = strlen(wire);
    int n = snprintf(wire + used, sizeof(wire) - used, "%s\n", twin);
    return n > 0 && (size_t)n < sizeof(wire) - used && dlx_write(path, wire);
}

#endif /* !defined(_WIN32) */
