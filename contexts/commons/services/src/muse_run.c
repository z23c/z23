/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: queue row -> Muse turn -> registered gate -> receipt. See header. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "services/muse_run.h"
#include "services/muse_run_audit.h"
#include "services/muse_run_evidence.h"
#include "services/muse_run_restore.h"
#include "services/muse_session.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "engine/engine_verdict.h"
#include "json/json.h"
#include "platform/clock.h"
#include "sha3/sha3.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MR_TURN_DEFAULT_MS 1500000
#define MR_GATE_DEFAULT_MS 900000
#define MR_TOKEN_DEFAULT 200000u
#define MR_TEXT_DEFAULT (64u * 1024u)
#define MR_GATE_LOG_MAX (256u * 1024u)
#define MR_LINE_MAX (1024u * 1024u)

static const char *mr_verdict_pass = "pass";
static const char *mr_verdict_failed = "failed";
static const char *mr_verdict_timeout = "timeout";
static const char *mr_verdict_cancelled = "cancelled";
static const char *mr_verdict_refused = "refused";

static bool mr_is_terminal_verdict(const char *v)
{
    return v && (strcmp(v, mr_verdict_pass) == 0 ||
        strcmp(v, mr_verdict_failed) == 0 ||
        strcmp(v, mr_verdict_timeout) == 0 ||
        strcmp(v, mr_verdict_cancelled) == 0 ||
        strcmp(v, mr_verdict_refused) == 0);
}

/* --- small utils --------------------------------------------------------- */

static int64_t mr_monotonic_ms(void)
{
    return clock_now_monotonic_ns() / 1000000;
}

static char *mr_read_file(const char *path, size_t cap)
{
    FILE *f = fopen(path, "rb");
    long n;
    char *buf;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    n = ftell(f);
    if (n < 0 || (size_t)n > cap) {
        fclose(f);
        return NULL;
    }
    (void)fseek(f, 0, SEEK_SET);
    buf = zcl_malloc((size_t)n + 1, "muse_run.file");
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static bool mr_append_line(const char *path, const char *line)
{
    FILE *f = fopen(path, "ab");
    bool ok;
    if (!f) return false;
    ok = fprintf(f, "%s\n", line) > 0;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool mr_copy(char *out, size_t cap, const char *v, size_t vn)
{
    if (!out || cap == 0) return false;
    if (vn >= cap) return false;
    memcpy(out, v, vn);
    out[vn] = '\0';
    return true;
}

static bool mr_dir_ok(const char *path)
{
    struct stat st;
    return path && path[0] && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/* One identity character: ASCII alphanumeric plus `_`, `.` and `-`. */
static bool mr_token_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
}

/* Identity token: one path segment, never "." or "..". */
static bool mr_token_ok(const char *s)
{
    size_t n;
    if (!s || s[0] == '\0') return false;
    n = strlen(s);
    if (n >= MUSE_RUN_NAME_MAX) return false;
    if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0) return false;
    for (size_t i = 0; i < n; i++) {
        if (!mr_token_char(s[i])) return false;
    }
    return true;
}

/* --- validation ------------------------------------------------------------ */

/* The queue row's identity: the ref triple plus the optional worker name. */
static int mr_validate_ref(const struct muse_run_task *t,
    char err[MUSE_RUN_ERROR_MAX])
{
    if (t->ref.seq < 0 || t->ref.attempt < 1 ||
        !mr_token_ok(t->ref.name)) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "ref is unusable");
        return -1;
    }
    if (t->worker[0] && !mr_token_ok(t->worker)) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "worker identity is unusable");
        return -1;
    }
    return 0;
}

/* The place the turn edits: an existing workspace and a scope that cannot
 * escape it. */
static int mr_validate_workspace(const struct muse_run_task *t,
    char err[MUSE_RUN_ERROR_MAX])
{
    if (!mr_dir_ok(t->workspace)) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "workspace is not a directory");
        return -1;
    }
    if (!muse_scope_valid(t->scope)) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "scope escapes the workspace");
        return -1;
    }
    return 0;
}

/* The judge and the model's instruction: a named gate and a bounded
 * prompt. */
static int mr_validate_work(const struct muse_run_task *t,
    char err[MUSE_RUN_ERROR_MAX])
{
    size_t prompt_len;
    if (!t->gate[0]) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "no gate names the judge");
        return -1;
    }
    if (!t->prompt || !t->prompt[0]) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "prompt is empty");
        return -1;
    }
    prompt_len = strlen(t->prompt);
    if (prompt_len > MUSE_RUN_PROMPT_MAX) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "prompt exceeds its bound");
        return -1;
    }
    return 0;
}

static int mr_validate(const struct muse_run_task *t,
    char err[MUSE_RUN_ERROR_MAX])
{
    if (!t) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "task is missing");
        return -1;
    }
    if (mr_validate_ref(t, err) != 0) return -1;
    if (mr_validate_workspace(t, err) != 0) return -1;
    if (mr_validate_work(t, err) != 0) return -1;
    if (!mr_dir_ok(t->rundir)) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "rundir is not a directory");
        return -1;
    }
    return 0;
}

/* --- restart pre-check ----------------------------------------------------- */

/* True when the rundir already owns a receipt with a terminal verdict;
 * the run happened, whatever A's queue says. The queue's own locks and
 * outcome rows are A's state machine and are never read here. */
static bool mr_receipt_verdict(const char *rundir, char *out, size_t cap)
{
    char path[8192];
    char *text;
    const char *p;
    if (snprintf(path, sizeof(path), "%s/receipt.json", rundir) >=
        (int)sizeof(path))
        return false;
    text = mr_read_file(path, 65536);
    if (!text) return false;
    p = strstr(text, "\"verdict\":\"");
    if (p) {
        const char *v = p + strlen("\"verdict\":\"");
        const char *q = strchr(v, '"');
        bool ok = false;
        if (q && (size_t)(q - v) < cap) {
            char verb[32];
            size_t n = (size_t)(q - v);
            if (n < sizeof(verb)) {
                memcpy(verb, v, n);
                verb[n] = '\0';
                if (mr_is_terminal_verdict(verb)) {
                    (void)snprintf(out, cap, "%s", verb);
                    ok = true;
                }
            }
        }
        free(text);
        return ok;
    }
    free(text);
    return false;
}

/* 1 = already recorded (do NOT start a turn), 0 = clear. Any verdict
 * receipt counts: either reap saw it or reap is about to. */
static int mr_already_recorded(const struct muse_run_task *t,
    struct muse_run_result *out)
{
    char verb[MUSE_RUN_VERDICT_MAX];
    if (!mr_receipt_verdict(t->rundir, verb, sizeof(verb))) return 0;
    if (out) {
        (void)snprintf(out->verdict, sizeof(out->verdict), "%s", verb);
        out->rc = 0;
    }
    return 1;
}

static void mr_report_short(const struct muse_run_task *t,
    const struct muse_run_result *out)
{
    printf("ref=%lld/%s/%lld already recorded; no turn started\n",
        t->ref.seq, t->ref.name, t->ref.attempt);
    printf("rc=0\n");
    (void)out;
}

/* --- the candidate identity ---------------------------------------------- */

/* SHA-1 over the post-run change set (services/muse_run_restore.h): the
 * tracked diff plus one content hash per untracked path, hashed once more
 * so the token is fixed-width. Empty diffs hash deterministically. On
 * success the fold is also published as <rundir>/candidate-<hex>.diff
 * (atomic): the named artifact a gate checks for existence, and the
 * durable copy the workspace restore verifies before it undoes anything.
 * Every failure leaves candidate "none" and names itself in
 * candidate_note. */
static void mr_candidate(const char *workspace, const char *rundir,
    struct muse_run_result *r)
{
    char art[8192], fname[192];
    char *fold = NULL;
    r->candidate_file[0] = '\0';
    if (!muse_candidate_fold(workspace, rundir, r->candidate,
            sizeof(r->candidate), &fold, r->candidate_note,
            sizeof(r->candidate_note)))
        return;
    if (snprintf(fname, sizeof(fname), "candidate-%s.diff",
            r->candidate) < (int)sizeof(fname) &&
        snprintf(art, sizeof(art), "%s/%s", rundir,
            fname) < (int)sizeof(art) &&
        strlen(fname) < sizeof(r->candidate_file) &&
        muse_run_write_atomic(art, fold)) {
        (void)snprintf(r->candidate_file, sizeof(r->candidate_file), "%s",
            fname);
    } else {
        /* An identity with no artifact is a name for bytes nobody can
         * read back: no restore may verify against it, no pass may rest
         * on it. Name that too. */
        (void)snprintf(r->candidate_note, sizeof(r->candidate_note),
            "the candidate artifact could not be published under the run "
            "dir");
    }
    free(fold);
}

/* Named AND on disk under the run dir: the only shape that counts as a
 * preserved change. */
static bool mr_candidate_named(const struct muse_run_result *r)
{
    return muse_hex40(r->candidate) && r->candidate_file[0] != '\0';
}

/* --- the gate's own process ------------------------------------------------
 * WHAT THE LOG SAYS IS NOT WHAT THE PROCESS DID. A runner that is killed
 * on its deadline, or that exits non-zero, still leaves behind whatever it
 * had already written — and the reader keeps the LAST SUITE VERDICT line
 * it finds, which a half-finished run can easily have printed with
 * groups_failed=0. Discarding the spawn status turns every such death into
 * a pass. So the status is carried, not dropped, and the log is read only
 * for a process that finished normally and successfully.
 *
 * What the capture seam can actually tell apart, and nothing more:
 * a launch that never happened, a deadline this side enforced, a
 * wait status that was never trustworthy, a complete or truncated
 * capture, and one exit number. That number cannot separate a child
 * killed by signal N from a child that called exit(128+N) — both arrive
 * as 128+N — and no distinction is invented here that the seam does not
 * support. Both are non-zero, so both refuse. */
struct mr_spawn_outcome {
    bool attempted;      /* the runner was found and the capture was tried */
    bool launched;       /* the child ran at all */
    bool exit_observed;  /* a trustworthy wait status was obtained */
    bool timed_out;      /* this side killed it on the deadline */
    bool complete;       /* stdout reached EOF without filling the bound */
    int exit_code;       /* normal exit 0..255, or 128+signal; -1 unknown */
};

/* True only for the one outcome whose log may be believed. */
static bool mr_spawn_normal(const struct mr_spawn_outcome *o)
{
    return o->attempted && o->launched && o->exit_observed &&
        !o->timed_out && o->complete && o->exit_code == 0;
}

/* Names the outcome for the evidence, so a refusal says what the process
 * did and never only that the gate "refused". */
static void mr_spawn_outcome_name(const struct mr_spawn_outcome *o,
    char *out, size_t cap)
{
    if (!o->attempted)
        (void)snprintf(out, cap, "runner-unrunnable");
    else if (!o->launched)
        (void)snprintf(out, cap, "launch-failed");
    else if (o->timed_out)
        (void)snprintf(out, cap, "timeout");
    else if (!o->exit_observed)
        (void)snprintf(out, cap, "status-unobserved");
    else if (!o->complete)
        (void)snprintf(out, cap, "log-truncated exit=%d", o->exit_code);
    else
        (void)snprintf(out, cap, "exit=%d", o->exit_code);
}

/* One bounded capture with its outcome preserved. The exact-binary seam is
 * the only capture in the tree that reports the deadline, the wait status
 * and the completeness of the read separately; the plain capture folds all
 * three into one int where a timeout and a clean exit 0 can look alike.
 * It does not terminate the buffer, so that is done here. */
static void mr_gate_capture(const char *const argv[], char *log,
    size_t logcap, int timeout_ms, struct mr_spawn_outcome *o)
{
    struct zcl_spawn_binary_observation obs;
    memset(o, 0, sizeof(*o));
    memset(&obs, 0, sizeof(obs));
    obs.exit_code = -1;
    o->exit_code = -1;
    o->attempted = true;
    log[0] = '\0';
    /* The rolled-up result says only that SOMETHING was wrong; the
     * observation beside it says which thing, and that is the fact the
     * refusal has to name. */
    ZCL_IGNORE_RESULT(
        zcl_spawn_capture_binary(argv, log, logcap - 1, timeout_ms, &obs),
        "the observation below carries every outcome this refuses on");
    log[obs.output_len < logcap ? obs.output_len : logcap - 1] = '\0';
    o->timed_out = obs.timed_out;
    o->exit_observed = obs.exit_observed;
    o->complete = obs.eof && !obs.overflow;
    o->exit_code = obs.exit_code;
    /* A refused launch captures nothing and observes nothing; anything
     * that reached a deadline or a wait status did run. */
    o->launched = obs.timed_out || obs.exit_observed || obs.output_len > 0;
}

/* Runs the named registered group through the workspace's own runner and,
 * ONLY for a normal successful exit, reports the machine verdict line
 * through engine_gate_read. Missing or unrunnable runner, a failed launch,
 * a deadline, an unobserved status, a truncated log and any non-zero exit
 * are all refusal inputs, never a pass — whatever the captured log says. */
static bool mr_run_gate(const char *workspace, const char *group,
    int timeout_ms, char *log, size_t logcap, long long *elapsed_ms,
    struct engine_gate_reading *reading, struct mr_spawn_outcome *o)
{
    char runner[8192];
    const char *argv[8];
    char selector[128];
    int64_t t0;
    memset(o, 0, sizeof(*o));
    o->exit_code = -1;
    if (!workspace || !group || !log || logcap < 2 || !elapsed_ms ||
        !reading || timeout_ms <= 0)
        return false;
    memset(reading, 0, sizeof(*reading));
    if (snprintf(runner, sizeof(runner), "%s/build/bin/test_parallel",
            workspace) >= (int)sizeof(runner))
        return false;
    if (access(runner, X_OK) != 0) return false;
    if (snprintf(selector, sizeof(selector), "--exact=%s", group) >=
        (int)sizeof(selector))
        return false;
    argv[0] = runner;
    argv[1] = selector;
    argv[2] = "--no-cache";
    argv[3] = NULL;
    t0 = mr_monotonic_ms();
    mr_gate_capture(argv, log, logcap, timeout_ms, o);
    *elapsed_ms = (long long)(mr_monotonic_ms() - t0);
    if (!mr_spawn_normal(o)) return false;
    return engine_gate_read(log, strlen(log), reading);
}

/* --- the gate's build ------------------------------------------------------
 * A GATE THAT DOES NOT COMPILE THE CANDIDATE DOES NOT JUDGE IT. The runner
 * in the workspace was built before the turn, so running it as it stands
 * judges the base, not the model's change: a candidate that did not even
 * compile once passed this gate. So the gate target is rebuilt from the
 * candidate tree first, through the workspace's own make target with an
 * argv (no shell), inside the gate's deadline. Anything but a normal,
 * observed exit 0 refuses, and names the build as the reason. */
#define MR_GATE_BUILD_LOG (64u * 1024u)

static bool mr_build_gate(const char *workspace, int timeout_ms,
    struct mr_spawn_outcome *o)
{
    const char *argv[] = {
        "make", "-s", "-C", workspace, MUSE_RUN_GATE_BUILD_TARGET, NULL
    };
    char *log;
    memset(o, 0, sizeof(*o));
    o->exit_code = -1;
    if (!workspace || timeout_ms <= 0) return false;
    log = zcl_malloc(MR_GATE_BUILD_LOG, "muse_run.gate_build");
    if (!log) return false;
    mr_gate_capture(argv, log, MR_GATE_BUILD_LOG, timeout_ms, o);
    free(log);
    return mr_spawn_normal(o);
}

/* SHA3-256 hex of the runner the build left: the binary identity the
 * verdict binds. False (and "none") when it cannot be read in full. */
static bool mr_runner_identity(const char *workspace, char out[65])
{
    char path[8192];
    unsigned char bytes[65536], digest[32];
    struct sha3_256_ctx hash;
    size_t got;
    bool ok;
    FILE *f;
    (void)snprintf(out, 65, "none");
    if (snprintf(path, sizeof(path), "%s/build/bin/test_parallel",
            workspace) >= (int)sizeof(path))
        return false;
    f = fopen(path, "rb");
    if (!f) return false;
    sha3_256_init(&hash);
    while ((got = fread(bytes, 1, sizeof(bytes), f)) > 0)
        sha3_256_write(&hash, bytes, got);
    ok = !ferror(f);
    fclose(f);
    sha3_256_finalize(&hash, digest);
    if (ok) zcl_hex_encode(digest, sizeof(digest), out);
    return ok;
}

/* Last SUITE VERDICT line, verbatim: same keep-last rule as the reader. */
static void mr_last_verdict_line(const char *log, char *out, size_t cap)
{
    const char *cur;
    out[0] = '\0';
    if (!log || cap == 0) return;
    cur = log;
    for (;;) {
        const char *nl = strchr(cur, '\n');
        size_t n = nl ? (size_t)(nl - cur) : strlen(cur);
        if (n >= 13 && n < cap && memcmp(cur, "SUITE VERDICT", 13) == 0) {
            memcpy(out, cur, n);
            out[n] = '\0';
        }
        if (!nl) break;
        cur = nl + 1;
    }
}

/* FAIL(HOLLOW) and FAIL(NO-CHANGE) report the inner name; the verdict
 * stays a lowercase verb and the engine detail rides the evidence. */
static const char *mr_engine_short(const char *name, char *buf, size_t cap)
{
    size_t n;
    if (!name) name = "UNKNOWN";
    n = strlen(name);
    if (n > 6 && strncmp(name, "FAIL(", 5) == 0 && name[n - 1] == ')') {
        size_t inner = n - 6;
        if (inner < cap) {
            memcpy(buf, name + 5, inner);
            buf[inner] = '\0';
            return buf;
        }
    }
    return name;
}

/* --- the run --------------------------------------------------------------- */

struct mr_core {
    const struct muse_run_task *task;
    struct muse_run_result *res;
    int64_t t0;
    int64_t turn_timeout_ms;
    int gate_timeout_ms;
    uint64_t max_tokens;
};

/* What defeated the measurement, for the evidence. A scan can also fail
 * before it reads a single row — a failed allocation, a failed spawn, a
 * non-zero or timed-out git, or a capture that filled its bound — and
 * that case has no row to blame, so it says so rather than leaving the
 * reason blank and reading like a row that was never named. */
static const char *mr_unreadable_why(const struct muse_audit *a)
{
    return a->unreadable_why ? a->unreadable_why
                             : "git did not answer the measurement";
}

/* BEFORE the turn. A workspace that is already dirty can prove nothing,
 * because its pre-existing edits would count toward the non-empty diff a
 * pass requires. So this refuses before a single token is spent: no
 * session, no turn, and the offending paths named in the evidence.
 * `build/` is gitignored, so an already-built workspace is still clean.
 * "refused" is the verb, not "failed": this file already spends "refused"
 * on every breakdown that stops the run BEFORE judgement (no host, no
 * submit, unmeasurable diff), and nothing was judged here either. The
 * detail rides the evidence, never the verdict string. */
static bool mr_prestate_clean(struct mr_core *c)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    struct muse_audit a;
    muse_audit_init(&a, NULL, r->scope_pre, sizeof(r->scope_pre), NULL, 0);
    if (!muse_audit_scan(t->workspace, &a)) {
        /* UNMEASURABLE, which is not clean: the count stays -1 so the
         * evidence can never be read as a measured empty tree. */
        r->scope_pre_measured = false;
        r->scope_pre_count = -1;
        r->scope_pre_clean = false;
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_refused);
        (void)snprintf(r->reason, sizeof(r->reason),
            "workspace pre-state unmeasurable: %lld unreadable row(s): %s",
            a.unreadable, mr_unreadable_why(&a));
        return false;
    }
    r->scope_pre_measured = true;
    r->scope_pre_count = a.total;
    r->scope_pre_clean = a.total == 0;
    if (r->scope_pre_clean) return true;
    (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
        mr_verdict_refused);
    (void)snprintf(r->reason, sizeof(r->reason),
        "workspace dirty before the turn: %lld path(s) [%s]",
        a.total, r->scope_pre);
    return false;
}

/* AFTER the turn. Every measured path must be inside the declared scope.
 * Measured BEFORE the gate is run, so what is judged is the model's own
 * output and never the gate's side effects. The changed list is the proof
 * that the permission was actually respected: that is the whole point.
 * "failed" is the verb here, not "refused": the turn ran, produced output,
 * and that output was judged and rejected. */
static bool mr_scope_clean(struct mr_core *c)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    struct muse_audit a;
    muse_audit_init(&a, t->scope, r->scope_changed, sizeof(r->scope_changed),
        r->scope_outside, sizeof(r->scope_outside));
    if (!muse_audit_scan(t->workspace, &a)) {
        /* UNMEASURABLE, which is not "nothing outside scope": both counts
         * stay -1 and the verdict stays the refused this file already
         * spends on a breakdown before judgement. */
        r->scope_changed_measured = false;
        r->scope_changed_count = -1;
        r->scope_outside_count = -1;
        (void)snprintf(r->reason, sizeof(r->reason),
            "workspace change set unmeasurable: %lld unreadable row(s): %s",
            a.unreadable, mr_unreadable_why(&a));
        return false;
    }
    r->scope_changed_measured = true;
    r->scope_changed_count = a.total;
    r->scope_outside_count = a.outside_total;
    if (a.outside_total == 0) return true;
    (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
        mr_verdict_failed);
    (void)snprintf(r->reason, sizeof(r->reason),
        "%lld path(s) outside scope %s: [%s]", a.outside_total,
        t->scope, r->scope_outside);
    return false;
}

/* Two identities that were both read and DISAGREE. Unreadable is a
 * separate fact with its own refusal: "cannot tell" and "definitely
 * different" are not the same answer, and the evidence must not blur
 * them into one. */
static bool mr_head_moved(const char *pinned, const char *observed)
{
    return muse_hex40(pinned) && muse_hex40(observed) &&
        strcmp(pinned, observed) != 0;
}

/* AFTER the turn, BEFORE the gate. The change set audit proves the scope
 * only while the commit it is measured against holds still: a model that
 * COMMITS its work leaves a porcelain tree with nothing in it, so the
 * audit measures nothing and every count reads as a spotless run. The
 * pinned pre-turn HEAD is the only thing that catches that.
 *
 * Measured beside mr_scope_clean for the same reason that one is: what is
 * judged must be the model's own output and never the gate's side
 * effects. A moved HEAD is "failed" — the turn ran, produced something,
 * and that something was judged and rejected. An identity that could not
 * be read at either end is "refused": nothing was judged, because there
 * was nothing to compare. Either way the run can never reach pass. */
static bool mr_head_pinned(struct mr_core *c)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    r->head_measured = false;
    if (!muse_head_at(t->workspace, r->head_observed,
            sizeof(r->head_observed))) {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_refused);
        (void)snprintf(r->reason, sizeof(r->reason),
            "HEAD unreadable after the turn; pinned %s", r->base);
        return false;
    }
    if (!muse_hex40(r->base)) {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_refused);
        (void)snprintf(r->reason, sizeof(r->reason),
            "HEAD unreadable before the turn; observed %s",
            r->head_observed);
        return false;
    }
    if (mr_head_moved(r->base, r->head_observed)) {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_failed);
        (void)snprintf(r->reason, sizeof(r->reason),
            "HEAD moved during the turn: pinned %s, observed %s",
            r->base, r->head_observed);
        return false;
    }
    r->head_measured = true;
    return true;
}

/* Prior admitted turn without a terminal: a fresh host cannot cancel
 * a dead host's turn (sessionNotLoaded), so the gate still judges
 * the final diff and this note preserves the fact. */
static void mr_note_prior_turn(const struct muse_run_task *t,
    struct muse_run_result *r)
{
    char turns[8192];
    char *old;
    if (snprintf(turns, sizeof(turns), "%s/muse-turn.jsonl", t->rundir) >=
        (int)sizeof(turns))
        return;
    old = mr_read_file(turns, 65536);
    if (!old) return;
    if (strstr(old, "\"turnId\":") && !strstr(old, "\"terminal\":"))
        r->prior_unresolved = true;
    free(old);
}

/* session/start then turn/start. False with the host's reason recorded. */
static bool mr_submit(struct mr_core *c, struct muse_session *s,
    const struct muse_session_policy *policy)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    if (!muse_session_command_id(r->start_command) ||
        muse_session_start(s, r->start_command, t->workspace, policy,
            r->session, r->provider, r->model_resolved) != 0) {
        (void)snprintf(r->reason, sizeof(r->reason), "%s",
            muse_session_last_error(s));
        return false;
    }
    if (!muse_session_command_id(r->turn_command) ||
        muse_session_turn(s, r->turn_command, r->session, t->prompt,
            r->turn) != 0) {
        (void)snprintf(r->reason, sizeof(r->reason), "%s",
            muse_session_last_error(s));
        return false;
    }
    return true;
}

/* Admission is durable before waiting: a restart sees this line and
 * never mistakes the turn for unsubmitted. */
static void mr_record_admission(const struct muse_run_task *t,
    const struct muse_run_result *r)
{
    char line[1024];
    char turns[8192];
    (void)snprintf(line, sizeof(line),
        "{\"sessionId\":\"%s\",\"turnId\":\"%s\",\"commandId\":\"%s\"}",
        r->session, r->turn, r->turn_command);
    if (snprintf(turns, sizeof(turns), "%s/muse-turn.jsonl",
            t->rundir) < (int)sizeof(turns))
        (void)mr_append_line(turns, line);
}

/* A bound trip stops the turn first: the timeout owns its verdict, a
 * token trip keeps "refused" with the budget reason, and anything else
 * reports the host error. */
static void mr_wait_failed(struct mr_core *c, struct muse_session *s)
{
    struct muse_run_result *r = c->res;
    const char *kind = muse_session_last_kind(s);
    if (strcmp(kind, "timeout") == 0 ||
        strcmp(kind, "tokenBudget") == 0) {
        char cc[MUSE_COMMAND_ID_MAX];
        if (muse_session_command_id(cc))
            (void)muse_session_cancel(s, cc, r->session, r->turn);
    }
    if (strcmp(kind, "timeout") == 0) {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_timeout);
        (void)snprintf(r->reason, sizeof(r->reason),
            "turn exceeded its bound");
    } else {
        (void)snprintf(r->reason, sizeof(r->reason), "%s",
            muse_session_last_error(s));
    }
    r->wall_ms = (long long)(mr_monotonic_ms() - c->t0);
}

/* A terminal that is not "completed" settles the verdict without a gate. */
static void mr_settle_terminal(struct mr_core *c)
{
    struct muse_run_result *r = c->res;
    if (strcmp(r->terminal, "cancelled") == 0) {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_cancelled);
        (void)snprintf(r->reason, sizeof(r->reason),
            "turn cancelled");
    } else {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_failed);
        (void)snprintf(r->reason, sizeof(r->reason),
            "turn did not complete");
    }
    r->wall_ms = (long long)(mr_monotonic_ms() - c->t0);
}

/* THE CLOSED PASS PREDICATE. Every fact a pass rests on, measured, in one
 * conjunction: the gate passed over a measured non-empty diff; the
 * workspace was measurably clean before the turn; the change set after it
 * was measured and holds nothing outside the declared scope; the pre-turn
 * HEAD was pinned and had not moved when the change set was measured; and
 * the gate's own process exited normally with status 0, so its log is
 * evidence rather than debris. This is a predicate, not a second decision
 * site: mr_judge below is the only place that acts on it. Nothing here may
 * ever be defaulted — an unmeasured fact is false, never true. */
static bool mr_pass_closed(const struct muse_run_result *r,
    enum engine_verdict v)
{
    return v == ENGINE_VERDICT_PASS && r->scope_pre_measured &&
        r->scope_pre_clean && r->scope_changed_measured &&
        r->scope_outside_count == 0 && r->head_measured &&
        r->gate_normal && mr_candidate_named(r);
}

/* Folds the change set ONCE per run, the first time a caller needs it,
 * and never again: the identity a pass rests on must be the one measured
 * BEFORE the gate build ran, so what it names is the model's own output
 * and never the build's side effects. */
static void mr_fold_once(struct mr_core *c)
{
    if (c->res->candidate[0]) return;
    mr_candidate(c->task->workspace, c->task->rundir, c->res);
}

/* PRESERVED BEFORE IT IS JUDGED. A change that cannot be folded into a
 * durable artifact can never pass (mr_pass_closed) and can never be
 * verified by a restore, so refusing here SAVES the gate build that was
 * about to run and names the blocker in one line. The change itself is
 * untouched either way. */
static bool mr_preserved(struct mr_core *c)
{
    struct muse_run_result *r = c->res;
    mr_fold_once(c);
    if (mr_candidate_named(r)) return true;
    (void)snprintf(r->reason, sizeof(r->reason),
        "change set could not be preserved: %.180s",
        r->candidate_note[0] ? r->candidate_note
                             : "the fold named no reason");
    return false;
}

/* Everything measured before the gate is allowed to run: the diff count,
 * the change set against the declared scope, and the pinned HEAD. Each one
 * writes its own verdict and reason on refusal. */
static bool mr_measured_before_gate(struct mr_core *c)
{
    struct muse_run_result *r = c->res;
    r->files_changed = muse_files_changed(c->task->workspace);
    if (r->files_changed < 0) {
        (void)snprintf(r->reason, sizeof(r->reason),
            "worktree diff unmeasurable");
        return false;
    }
    /* Measured before the gate runs: the change set judged here is the
     * model's output, never the gate's own side effects. */
    if (!mr_scope_clean(c)) return false;
    return mr_head_pinned(c) && mr_preserved(c);
}

/* Builds the gate target from the candidate tree and hands back what is
 * left of the gate deadline for the run. A build that does not finish
 * normally, or that leaves no time to run the group, refuses by name. */
static bool mr_judge_build(struct mr_core *c, int *run_ms)
{
    struct muse_run_result *r = c->res;
    struct mr_spawn_outcome spawn;
    char name[48];
    int64_t t0 = mr_monotonic_ms();
    int64_t spent;
    bool built = mr_build_gate(c->task->workspace, c->gate_timeout_ms,
        &spawn);
    spent = mr_monotonic_ms() - t0;
    r->build_ms = (long long)spent;
    mr_spawn_outcome_name(&spawn, name, sizeof(name));
    (void)snprintf(r->build_spawn, sizeof(r->build_spawn), "%s", name);
    if (!built) {
        (void)snprintf(r->gate_spawn, sizeof(r->gate_spawn), "build %s",
            name);
        r->gate_exit = spawn.exit_code;
        (void)snprintf(r->reason, sizeof(r->reason),
            "gate build failed: %s %s", MUSE_RUN_GATE_BUILD_TARGET, name);
        return false;
    }
    if (!mr_runner_identity(c->task->workspace, r->gate_runner)) {
        (void)snprintf(r->reason, sizeof(r->reason),
            "gate build left no readable runner: %s",
            MUSE_RUN_GATE_BUILD_TARGET);
        return false;
    }
    if (spent >= (int64_t)c->gate_timeout_ms) {
        (void)snprintf(r->gate_spawn, sizeof(r->gate_spawn), "timeout");
        (void)snprintf(r->reason, sizeof(r->reason),
            "gate build spent the gate budget (timeout): %lld ms of %d",
            (long long)spent, c->gate_timeout_ms);
        return false;
    }
    *run_ms = c->gate_timeout_ms - (int)spent;
    return true;
}

/* THE GATE DECIDES. The turn text is evidence, never a verdict input.
 * Returns the rc the run reports and names the engine verdict. */
static int mr_judge(struct mr_core *c, char *gate_log, size_t logcap,
    const char **engine_name, char *engine_buf, size_t engine_cap)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    struct engine_gate_reading gate;
    struct mr_spawn_outcome spawn;
    enum engine_verdict v;
    int run_ms = 0;
    if (!mr_measured_before_gate(c)) return 1;
    /* Built AFTER the scope audit, so what was audited is the model's own
     * output and never the build's side effects (build/ is ignored). */
    if (!mr_judge_build(c, &run_ms)) return 1;
    if (!mr_run_gate(t->workspace, t->gate, run_ms, gate_log,
            logcap, &r->gate_ms, &gate, &spawn)) {
        /* The log may well hold a passing verdict line. It is not read,
         * because the process that wrote it did not finish normally. */
        mr_spawn_outcome_name(&spawn, r->gate_spawn, sizeof(r->gate_spawn));
        r->gate_exit = spawn.exit_code;
        (void)snprintf(r->reason, sizeof(r->reason),
            "gate did not pass a readable verdict: %s", r->gate_spawn);
        return 1;
    }
    mr_spawn_outcome_name(&spawn, r->gate_spawn, sizeof(r->gate_spawn));
    r->gate_exit = spawn.exit_code;
    r->gate_normal = true;
    r->gate_present = gate.saw_verdict_line;
    r->gate_ran = gate.groups_ran;
    r->gate_failed = gate.groups_failed;
    mr_last_verdict_line(gate_log, r->gate_verdict,
        sizeof(r->gate_verdict));
    (void)snprintf(r->gate_evidence, sizeof(r->gate_evidence),
        "%s:%lld/%lld", t->gate, r->gate_ran, r->gate_failed);
    v = engine_verdict_of(&gate, (size_t)r->files_changed, false, true);
    *engine_name = mr_engine_short(engine_verdict_name(v), engine_buf,
        engine_cap);
    if (mr_pass_closed(r, v)) {
        (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
            mr_verdict_pass);
        (void)snprintf(r->reason, sizeof(r->reason), "gate passed");
        return 0;
    }
    (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
        mr_verdict_failed);
    (void)snprintf(r->reason, sizeof(r->reason),
        "gate refused: %s", *engine_name);
    return 1;
}


/* AFTER the verdict and evidence are durable: return the workspace to the
 * pinned base so the next claimed task on it is not refused for this
 * run's own dirt. muse_restore_workspace touches nothing unless the
 * published artifact verifies as a durable copy of exactly the change it
 * would undo; a refusal leaves the change in place and says why. The
 * host is already closed, so no turn can write underneath the restore. */
static void mr_restore(const struct muse_run_task *t,
    struct muse_run_result *r)
{
    struct muse_restore_in in;
    memset(&in, 0, sizeof(in));
    in.workspace = t->workspace;
    in.rundir = t->rundir;
    in.base = r->base;
    in.candidate = r->candidate;
    in.candidate_file = r->candidate_file;
    in.pre_clean = r->scope_pre_measured && r->scope_pre_clean;
    r->workspace_restored = muse_restore_workspace(&in,
        r->workspace_restore, sizeof(r->workspace_restore),
        &r->workspace_blocked);
    if (r->workspace_blocked) muse_run_write_blocked(t, r);
}

/* The receipt, evidence and report every exit path shares. */
static void mr_report(struct mr_core *c, struct muse_session *s,
    const char *engine_name, int rc)
{
    const struct muse_run_task *t = c->task;
    struct muse_run_result *r = c->res;
    (void)snprintf(r->engine, sizeof(r->engine), "%s",
        engine_name);
    r->rc = rc;
    r->workspace_restored = false;
    r->workspace_blocked = false;
    (void)snprintf(r->workspace_restore, sizeof(r->workspace_restore),
        "not attempted yet: evidence first");
    /* A no-op for every run that reached the gate: that fold already
     * happened, before the build. This is the exit path that never got
     * there — a turn that timed out, was cancelled, or broke down after
     * dirtying the workspace — and its change is preserved the same way
     * before anything is restored. */
    mr_fold_once(c);
    /* The claim-holding caller's receipt is canonical: never lay ours
     * beside it. Evidence (muse.json, candidate artifact, admission)
     * is still written — once before the restore, so the verdict is
     * durable whatever the restore does, and once after, with its
     * outcome. */
    if (!t->caller_holds_claim)
        muse_run_write_receipt(t, r);
    muse_run_write_facts(t, r);
    if (s) muse_session_close(s);
    mr_restore(t, r);
    if (!t->caller_holds_claim)
        muse_run_write_receipt(t, r);
    muse_run_write_facts(t, r);
    printf("ref=%lld/%s/%lld verdict=%s tokens=%llu files=%lld wall_ms=%lld\n",
        t->ref.seq, t->ref.name, t->ref.attempt, r->verdict,
        (unsigned long long)r->total_tokens, r->files_changed,
        r->wall_ms);
    printf("rc=%d\n", rc);
}

static int mr_finish(struct mr_core *c, struct muse_session *s,
    const char *open_err, char err[MUSE_RUN_ERROR_MAX])
{
    struct muse_run_task const *t = c->task;
    struct muse_run_result *r = c->res;
    struct muse_session_policy policy;
    struct muse_turn_outcome out;
    char gate_log_stack[MR_GATE_LOG_MAX];
    char *gate_log = gate_log_stack;
    const char *allow[MUSE_SCOPE_MAX_PREFIXES];
    char scope_buf[MUSE_RUN_SCOPE_MAX];
    const char *engine_name = "UNKNOWN";
    char engine_buf[64];
    int rc = 1;
    int wait_rc;
    memset(&policy, 0, sizeof(policy));
    r->duration_ms = -1;
    r->files_changed = -1;
    r->gate_ran = -1;
    r->gate_failed = -1;
    /* -1 until measured: an exit path that never reached an enumeration
     * must not publish a zero that reads as a measured clean tree. */
    r->scope_pre_count = -1;
    r->scope_changed_count = -1;
    r->scope_outside_count = -1;
    /* No trustworthy gate status yet, and -1 is not a measured 0. */
    r->gate_exit = -1;
    (void)snprintf(r->gate_spawn, sizeof(r->gate_spawn), "none");
    r->build_ms = -1;
    (void)snprintf(r->build_spawn, sizeof(r->build_spawn), "none");
    (void)snprintf(r->gate_runner, sizeof(r->gate_runner), "none");
    (void)snprintf(r->head_observed, sizeof(r->head_observed), "none");
    (void)snprintf(r->verdict, sizeof(r->verdict), "%s",
        mr_verdict_refused);
    (void)snprintf(r->reason, sizeof(r->reason),
        "breakdown before judgement");
    r->rc = 1;
    if (!s) {
        (void)snprintf(r->reason, sizeof(r->reason), "%s",
            open_err && open_err[0] ? open_err : "serve host unavailable");
        goto write;
    }
    mr_note_prior_turn(t, r);
    /* Source half of the diff identity, PINNED before the turn lands: the
     * anchor every post-turn measurement is taken against. Recorded here,
     * judged two lines down — a workspace whose porcelain cannot be read
     * usually cannot name a commit either, and that breakdown deserves
     * the more specific diagnosis of the two. */
    (void)muse_head_at(t->workspace, r->base, sizeof(r->base));
    /* The workspace must be measurably clean BEFORE the turn: baseline
     * dirt could otherwise satisfy the non-empty diff a pass requires.
     * No session, no turn, no tokens. */
    if (!mr_prestate_clean(c)) goto write;
    /* An anchor that could not be read can never be compared afterwards,
     * so a run without one stops before a token is spent rather than
     * judging a change set against nothing. */
    if (!muse_hex40(r->base)) {
        (void)snprintf(r->reason, sizeof(r->reason),
            "HEAD unreadable before the turn: base %s", r->base);
        goto write;
    }
    policy.approval_mode = "denyUnmatched";
    policy.model = t->model[0] ? t->model : NULL;
    policy.allow_paths = allow;
    policy.allow_path_count = muse_scope_prefixes(t->scope, scope_buf,
        sizeof(scope_buf), allow);
    if (!mr_submit(c, s, &policy)) goto write;
    mr_record_admission(t, r);
    memset(&out, 0, sizeof(out));
    wait_rc = muse_session_wait(s, r->session, r->turn, &policy, &out);
    /* Usage folded before a failed wait is still spend: a turn cut off by
     * its token cap consumed past the cap, and must never read as 0. */
    r->input_tokens = out.input_tokens;
    r->output_tokens = out.output_tokens;
    r->total_tokens = out.total_tokens;
    r->cached_input_tokens = out.cached_input_tokens;
    r->billed_tokens = out.billed_tokens;
    if (wait_rc != 0) {
        muse_turn_outcome_free(&out);
        mr_wait_failed(c, s);
        goto write;
    }
    (void)snprintf(r->terminal, sizeof(r->terminal), "%s", out.terminal);
    r->duration_ms = out.duration_ms;
    muse_turn_outcome_free(&out);
    if (strcmp(r->terminal, "completed") != 0) {
        mr_settle_terminal(c);
        goto write;
    }
    rc = mr_judge(c, gate_log, sizeof(gate_log_stack), &engine_name,
        engine_buf, sizeof(engine_buf));
    r->wall_ms = (long long)(mr_monotonic_ms() - c->t0);
    goto write;
write:
    mr_report(c, s, engine_name, rc);
    (void)err;
    return rc;
}

static int mr_open_run(struct mr_core *c, char err[MUSE_RUN_ERROR_MAX])
{
    struct muse_session_limits sl;
    struct muse_session *s;
    char serr[MUSE_ERROR_MAX];
    memset(&sl, 0, sizeof(sl));
    sl.turn_timeout_ms = c->turn_timeout_ms;
    sl.max_total_tokens = c->max_tokens;
    sl.max_text_bytes = MR_TEXT_DEFAULT;
    serr[0] = '\0';
    s = muse_session_open("muse", &sl, serr);
    return mr_finish(c, s, serr, err);
}

/* 1 = already recorded (result carries the earlier verdict, rc 0),
 * 0 = clear to run, -1 = fail closed. */
static int mr_prepare(const struct muse_run_task *t,
    struct muse_run_result *out, struct mr_core *c,
    char err[MUSE_RUN_ERROR_MAX])
{
    c->task = t;
    c->res = out;
    c->t0 = mr_monotonic_ms();
    c->turn_timeout_ms = t->budgets.turn_timeout_ms > 0
        ? t->budgets.turn_timeout_ms : MR_TURN_DEFAULT_MS;
    c->gate_timeout_ms = t->budgets.gate_timeout_ms > 0
        ? (int)t->budgets.gate_timeout_ms : MR_GATE_DEFAULT_MS;
    c->max_tokens = t->budgets.max_total_tokens;
    if (c->max_tokens == 0) c->max_tokens = MR_TOKEN_DEFAULT;
    if (mr_validate(t, err) != 0) return -1;
    out->ref = t->ref;
    (void)snprintf(out->worker, sizeof(out->worker), "%s", t->worker);
    (void)snprintf(out->gate, sizeof(out->gate), "%s", t->gate);
    (void)snprintf(out->model_requested, sizeof(out->model_requested),
        "%s", t->model);
    /* The claim-holding caller (A's worker) is the at-most-once
     * guarantee: its claim.json decides submission, never this
     * receipt. Direct callers keep the fail-closed receipt check. */
    if (t->caller_holds_claim) return 0;
    {
        int recorded = mr_already_recorded(t, out);
        if (recorded != 0) {
            if (recorded > 0) {
                mr_report_short(t, out);
                return 1;
            }
            return -1;
        }
    }
    return 0;
}

static int mr_begin(struct mr_core *c, char err[MUSE_RUN_ERROR_MAX])
{
    int prep = mr_prepare(c->task, c->res, c, err);
    if (prep != 0) return prep > 0 ? 0 : 1;
    return mr_open_run(c, err);
}

int muse_run_task(const struct muse_run_task *task,
    struct muse_run_result *out, char err[MUSE_RUN_ERROR_MAX])
{
    struct mr_core c;
    if (!task || !out) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "task/result missing");
        return 1;
    }
    memset(out, 0, sizeof(*out));
    memset(&c, 0, sizeof(c));
    c.task = task;
    c.res = out;
    return mr_begin(&c, err);
}

/* --- composed file --------------------------------------------------------- */

static bool mr_file_header(const char *text, const char *key, char *out,
    size_t cap)
{
    size_t kl = strlen(key);
    const char *p = text;
    for (;;) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        /* Headers end at the titled brief marker the composer emits
         * ("=== BRIEF: <path> ==="); never parse the prompt body. */
        if (len >= 9 && strncmp(p, "=== BRIEF", 9) == 0) return false;
        if (len > kl + 2 && strncmp(p, key, kl) == 0 && p[kl] == ':' &&
            p[kl + 1] == ' ') {
            const char *v = p + kl + 2;
            size_t vn = len - (kl + 2);
            while (vn > 0 &&
                (v[vn - 1] == ' ' || v[vn - 1] == '\t' ||
                    v[vn - 1] == '\r'))
                vn--;
            return mr_copy(out, cap, v, vn);
        }
        if (!eol) return false;
        p = eol + 1;
    }
}

/* The machine headers the composer always emits. The queue: header is
 * accepted and ignored; model is optional and read separately. */
static bool mr_parse_headers(const char *text, struct muse_run_task *t,
    char *seq, size_t seqcap, char *attempt, size_t attcap)
{
    return mr_file_header(text, "seq", seq, seqcap) &&
        mr_file_header(text, "name", t->ref.name,
            sizeof(t->ref.name)) &&
        mr_file_header(text, "attempt", attempt, attcap) &&
        mr_file_header(text, "group", t->gate, sizeof(t->gate)) &&
        mr_file_header(text, "scope", t->scope, sizeof(t->scope)) &&
        mr_file_header(text, "worktree", t->workspace,
            sizeof(t->workspace)) &&
        mr_file_header(text, "rundir", t->rundir,
            sizeof(t->rundir));
}

/* The prompt body: everything past the titled brief marker's own line.
 * NULL with the reason named when the brief is absent or empty. */
static const char *mr_brief_body(const char *text, const char **why)
{
    const char *body = strstr(text, "=== BRIEF");
    if (!body) {
        *why = "task has no brief";
        return NULL;
    }
    body = strchr(body, '\n');
    if (!body) {
        *why = "task brief is empty";
        return NULL;
    }
    body++;
    while (*body == '\n' || *body == '\r') body++;
    if (!*body) {
        *why = "task brief is empty";
        return NULL;
    }
    return body;
}

/* File layout mirrors the queue composer: machine headers, one group
 * line, then the titled brief whose body is the prompt. The queue:
 * header is accepted and ignored; worker defaults to "cli". */
static int mr_parse_file(const char *taskpath, struct muse_run_task *t,
    char **prompt, char err[MUSE_RUN_ERROR_MAX])
{
    char *text = mr_read_file(taskpath, MR_LINE_MAX);
    char kind[32], seq[32], attempt[32];
    const char *body;
    const char *why = NULL;
    if (!text) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "cannot read task file");
        return -1;
    }
    memset(t, 0, sizeof(*t));
    t->ref.seq = -1;
    t->ref.attempt = -1;
    if (!mr_file_header(text, "kind", kind, sizeof(kind)) ||
        strcmp(kind, "muse") != 0) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "task is not kind: muse");
        free(text);
        return -1;
    }
    if (!mr_parse_headers(text, t, seq, sizeof(seq), attempt,
            sizeof(attempt))) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX,
                "task headers incomplete");
        free(text);
        return -1;
    }
    t->ref.seq = strtoll(seq, NULL, 10);
    t->ref.attempt = strtoll(attempt, NULL, 10);
    (void)mr_file_header(text, "model", t->model, sizeof(t->model));
    if (snprintf(t->worker, sizeof(t->worker), "cli") >=
        (int)sizeof(t->worker)) {
        free(text);
        return -1;
    }
    body = mr_brief_body(text, &why);
    if (!body) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "%s", why);
        free(text);
        return -1;
    }
    *prompt = zcl_malloc(strlen(body) + 1, "muse_run.prompt");
    if (!*prompt) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "out of memory");
        free(text);
        return -1;
    }
    memcpy(*prompt, body, strlen(body) + 1);
    free(text);
    return 0;
}

int muse_run_task_file(const char *taskpath,
    const struct muse_run_budgets *budgets, char err[MUSE_RUN_ERROR_MAX])
{
    struct muse_run_task t;
    struct muse_run_result out;
    char *prompt = NULL;
    int rc;
    if (!taskpath) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "task path missing");
        return 1;
    }
    if (mr_parse_file(taskpath, &t, &prompt, err) != 0) {
        free(prompt);
        return 1;
    }
    if (budgets) t.budgets = *budgets;
    t.prompt = prompt;
    memset(&out, 0, sizeof(out));
    rc = muse_run_task(&t, &out, err);
    free(prompt);
    return rc;
}

#ifdef ZCL_TESTING
int muse_run_task_on_transport(const struct muse_run_task *task,
    pid_t child, int to_fd, int from_fd, struct muse_run_result *out,
    char err[MUSE_RUN_ERROR_MAX])
{
    struct mr_core c;
    struct muse_session *s;
    struct muse_session_limits sl;
    if (!task || !out) {
        if (err)
            (void)snprintf(err, MUSE_RUN_ERROR_MAX, "task/result missing");
        return 1;
    }
    memset(out, 0, sizeof(*out));
    memset(&c, 0, sizeof(c));
    c.task = task;
    c.res = out;
    {
        int prep = mr_prepare(task, out, &c, err);
        if (prep != 0) return prep > 0 ? 0 : 1;
    }
    memset(&sl, 0, sizeof(sl));
    sl.turn_timeout_ms = c.turn_timeout_ms;
    sl.max_total_tokens = c.max_tokens;
    sl.max_text_bytes = MR_TEXT_DEFAULT;
    s = muse_session_attach(child, to_fd, from_fd, &sl);
    if (!s && err) {
        (void)snprintf(err, MUSE_RUN_ERROR_MAX, "transport attach failed");
        return 1;
    }
    return mr_finish(&c, s, "", err);
}
#endif
