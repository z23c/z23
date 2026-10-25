/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: base watch, phase mail and digest, producer recovery, evidence and status.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)


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

int test_dev_land_drive_base_watch(void)
{
    int failures = 0;
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
    const char *absent;         /* noise the evidence must not carry */
    const char *file;           /* repo-relative file the cause must name */
    const char *gate;           /* proof gate the cause must name */
};

static const char k_dlx_evidence_test_script[] =
    "printf '%s\\n' \\\n"
    " '==================== test_dev_land_noise (PASS, 0s) ====================' \\\n"
    " 'assert macros: FAIL names file:line and both values... OK' \\\n"
    " '==================== test_golden_dev_cycle (FAIL, 3s) ====================' \\\n"
    " 'golden dev cycle: a hot swap lands under a second... ' \\\n"
    " 'FAIL at tests/harness/src/test_golden_dev_cycle.c:367 (hotswap_ms < 1000.0)' \\\n"
    " 'SOME TESTS FAILED - 1/2 groups failed' \\\n"
    " 'Failed groups:' \\\n"
    " '  - test_golden_dev_cycle: exit code=1 log=./test-tmp/test_parallel_1_822.log'\n"
    "exit 1\n";

static const char k_dlx_evidence_compile_script[] =
    "root=$(pwd -P)\n"
    "echo \"cc -c $root/tools/dev/widget.c\"\n"
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

/* Consume the settled failure through the production status reader and
 * check the outcome row and the attempt's evidence file. */
static bool dlx_evidence_outcome_ok(const struct dlx_evidence_case *k,
                                    const char *real_wt)
{
    struct dlx_call c;
    char landdir[1200], path[1400], text[4096];
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
    return dlx_has(text, k->token) &&
           dlx_evidence_text_ok(k, text, real_wt);
}

static bool dlx_evidence_case_run(const struct dlx_evidence_case *k)
{
    char real_wt[PATH_MAX], local[64], base[64];
    dlx_isolate(k->tag);
    bool ok = dlx_evidence_settle(k, real_wt, local, base) &&
              dlx_evidence_record_ok(k, real_wt, local, base) &&
              dlx_evidence_outcome_ok(k, real_wt);
    dlx_restore();
    return ok;
}

int test_dev_land_proof_evidence_test(void)
{
    int failures = 0;
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
        };
        ASSERT(dlx_evidence_case_run(&k));
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_land_proof_evidence_compile(void)
{
    int failures = 0;
    TEST("land: a failed build names its first compiler error, relative") {
        const struct dlx_evidence_case k = {
            .tag = "evidence_compile",
            .dimension = ZCL_DEV_PROOF_COMPILE,
            .script = k_dlx_evidence_compile_script,
            .token = "child_proof_failed_exit_2",
            .land_dimension = "compile",
            .detail = "compile: tools/dev/widget.c:12:5: error: unknown "
                      "type name 'widget_t'",
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
