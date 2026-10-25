/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: stacked-train landing.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)



/* ── land trains (ZCL_LAND_TRAIN_WIDTH) ───────────────────────────────────
 *
 * One exact proof costs about 5,400 CPU-seconds on the shared lander, and
 * rows queued behind it each pay their own. With ZCL_LAND_TRAIN_WIDTH=N the
 * head row's prepared tip carries up to N-1 queued rows stacked onto it, so
 * one proof covers all of them; every row still lands under its own signed
 * intent and its own independent remote receipt. Off by default. */

/* Every tip origin main takes must be a stacked or solo pair that began an
 * exact proof: the watcher records each in_flight.local it sees and checks
 * every main it observes after a beat against that set. */
struct dlx_tr_watch {
    const struct dlx_rig *rig;
    char proven[16][64];
    size_t nproven;
    char main_tip[64];
    int unproven;
};

static void dlx_tr_watch_beat(struct dlx_tr_watch *w)
{
    struct dlx_call c;
    char main_tip[64];
    if (!w || !w->rig)
        return;
    if (dlx_status_json(&c)) {
        const struct json_value *f = json_get(&c.reply.data, "in_flight");
        const char *local = f ? dlx_jstr(f, "local") : "";
        bool known = false;
        for (size_t i = 0; i < w->nproven; i++)
            known = known || strcmp(w->proven[i], local) == 0;
        if (local[0] && !known && w->nproven < 16)
            (void)snprintf(w->proven[w->nproven++], 64, "%s", local);
        dlx_end(&c);
    }
    if (!dlx_origin_main(w->rig, main_tip) ||
        strcmp(main_tip, w->main_tip) == 0)
        return;
    bool known = false;
    for (size_t i = 0; i < w->nproven; i++)
        known = known || strcmp(w->proven[i], main_tip) == 0;
    w->unproven += !known;
    (void)snprintf(w->main_tip, sizeof(w->main_tip), "%s", main_tip);
}

static bool dlx_tr_watch_start(struct dlx_tr_watch *w,
                               const struct dlx_rig *rig)
{
    memset(w, 0, sizeof(*w));
    w->rig = rig;
    return dlx_origin_main(rig, w->main_tip);
}

/* Step until the queue is empty (at most `cap` beats): `started` counts the
 * exact proofs requested, `landed` the rows landed, `states` the beats. The
 * optional watcher sees every beat. */
static bool dlx_tr_drain(int cap, struct dlx_tr_watch *w, int *started,
                         int *landed, char *states, size_t states_cap)
{
    *started = 0;
    *landed = 0;
    states[0] = '\0';
    for (int i = 0; i < cap; i++) {
        struct dlx_call c;
        dlx_begin(&c, "step");
        bool ok = dlx_run(&c) && dlx_ok(&c);
        const char *s = ok ? dlx_str(&c, "state") : dlx_err_code(&c);
        size_t used = strlen(states);
        (void)snprintf(states + used, states_cap - used, "%s%s",
                       used ? "," : "", s);
        bool empty = strcmp(s, "empty") == 0;
        *started += strcmp(s, "started") == 0;
        *landed += strcmp(s, "landed") == 0;
        dlx_end(&c);
        dlx_tr_watch_beat(w);
        if (!ok)
            return false;
        if (empty)
            return true;
    }
    return false;
}

/* A (the rig tip, change.txt), B and C submitted as seqs 1..3 under `stub`;
 * B writes `b_path`, C writes c.txt, each one commit on origin/main. */
static bool dlx_tr_rig(struct dlx_rig *rig, const char *tag, const char *stub,
                       const char *b_path, char b[64], char c[64])
{
    if (!dlx_rig_make(rig, tag) ||
        !dlx_qp_branch(rig, "tr-b", b_path, "b\n", NULL, NULL, b) ||
        !dlx_qp_branch(rig, "tr-c", "c.txt", "c\n", NULL, NULL, c))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", stub, 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    return dlx_qp_submit(rig, rig->tip, 1) && dlx_qp_submit(rig, b, 2) &&
           dlx_qp_submit(rig, c, 3);
}

/* One step that must reply `state`; `members` is the train_members it must
 * report (0: the key is absent). */
static bool dlx_tr_beat(const char *state, int64_t members, int64_t attempt)
{
    struct dlx_call c;
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && dlx_ok(&c) &&
              strcmp(dlx_str(&c, "state"), state) == 0 &&
              dlx_int(&c, "train_members") == (members ? members : -1) &&
              (attempt < 0 || dlx_int(&c, "attempt") == attempt);
    if (!ok)
        printf("[step state=%s train_members=%lld attempt=%lld code=%s "
               "detail=%s] ", dlx_str(&c, "state"),
               (long long)dlx_int(&c, "train_members"),
               (long long)dlx_int(&c, "attempt"), dlx_err_code(&c),
               dlx_str(&c, "detail"));
    dlx_end(&c);
    return ok;
}

/* The queued row `seq`: its attempt and train_intent ("" when unbound). */
static bool dlx_tr_queued(long long seq, int64_t *attempt, char *intent,
                          size_t cap)
{
    struct dlx_call c;
    bool found = false;
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *rows = dlx_arr(&c, "queued");
    for (size_t i = 0; rows && i < rows->num_children; i++) {
        const struct json_value *r = &rows->children[i];
        if (json_get_int(json_get(r, "seq")) != seq)
            continue;
        *attempt = json_get_int(json_get(r, "attempt"));
        (void)snprintf(intent, cap, "%s", dlx_jstr(r, "train_intent"));
        found = true;
    }
    dlx_end(&c);
    return found;
}

static bool dlx_tr_inflight_intent(char *out, size_t cap)
{
    struct dlx_call c;
    if (!dlx_status_json(&c))
        return false;
    const struct json_value *f = json_get(&c.reply.data, "in_flight");
    (void)snprintf(out, cap, "%s", f ? dlx_jstr(f, "proof_intent") : "");
    dlx_end(&c);
    return out[0] != '\0';
}

/* The seqs the in-flight row's train carries, in status order. */
static size_t dlx_tr_members(int64_t out[8])
{
    struct dlx_call c;
    size_t n = 0;
    if (!dlx_status_json(&c))
        return 0;
    const struct json_value *f = json_get(&c.reply.data, "in_flight");
    const struct json_value *m = f ? json_get(f, "train_members") : NULL;
    for (size_t i = 0; m && i < m->num_children && n < 8; i++)
        out[n++] = json_get_int(&m->children[i]);
    dlx_end(&c);
    return n;
}

/* The quoted value of `key` on seq's last line in the land directory's
 * `file` (queue.jsonl or outcomes.jsonl). */
static bool dlx_tr_file_field(const char *file, long long seq, const char *key,
                              char *out, size_t cap)
{
    static char text[262144];
    char land[1200], path[1400], anchor[48], quoted[64];
    size_t len = 0;
    bool found = false;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/%s", land, file);
    if (!dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    (void)snprintf(anchor, sizeof(anchor), "{\"seq\":%lld,", seq);
    (void)snprintf(quoted, sizeof(quoted), "\"%s\":\"", key);
    for (char *line = text; line && *line;) {
        char *end = strchr(line, '\n');
        if (end)
            *end = '\0';
        const char *at = strncmp(line, anchor, strlen(anchor)) == 0
                             ? strstr(line, quoted) : NULL;
        if (at) {
            at += strlen(quoted);
            size_t n = strcspn(at, "\"");
            found = n > 0 && n < cap;
            if (found)
                (void)snprintf(out, cap, "%.*s", (int)n, at);
        }
        line = end ? end + 1 : NULL;
    }
    return found;
}

static bool dlx_tr_outcome_field(long long seq, const char *key, char *out,
                                 size_t cap)
{
    return dlx_tr_file_field("outcomes.jsonl", seq, key, out, cap);
}

/* origin main holds `path`. */
static bool dlx_tr_main_has(const struct dlx_rig *rig, const char *path)
{
    char spec[128];
    (void)snprintf(spec, sizeof(spec), "main:%s", path);
    const char *args[] = { "cat-file", "-e", spec, NULL };
    return dlx_git(rig->bare, args) == 0;
}

/* Every seq in 1..3 landed and origin main holds all three changes. One
 * train (`one_push`) lands them all at one pushed tip, origin main itself. */
static bool dlx_tr_all_landed(const struct dlx_rig *rig, bool one_push)
{
    char main_tip[64], state[32] = "", pushed[64] = "";
    if (!dlx_origin_main(rig, main_tip))
        return false;
    for (long long seq = 1; seq <= 3; seq++) {
        if (!dlx_tr_outcome_field(seq, "state", state, sizeof(state)) ||
            strcmp(state, "landed") != 0 ||
            !dlx_tr_outcome_field(seq, "tip_pushed", pushed, sizeof(pushed)) ||
            (one_push && strcmp(pushed, main_tip) != 0)) {
            printf("[seq=%lld state=%s pushed=%s main=%s] ", seq, state,
                   pushed, main_tip);
            return false;
        }
    }
    return dlx_tr_main_has(rig, "change.txt") &&
           dlx_tr_main_has(rig, "b.txt") && dlx_tr_main_has(rig, "c.txt");
}

/* Proofs and wall time for one three-row queue, train width `width`. A tip
 * origin main took that began no proof is a failure. */
static bool dlx_tr_measure(const char *tag, const char *width, int *proofs,
                           struct dlx_rig *rig)
{
    char b[64], c[64], states[256], rig_tag[64];
    struct dlx_tr_watch w;
    int landed = 0;
    (void)snprintf(rig_tag, sizeof(rig_tag), "%s_rig", tag);
    if (!dlx_tr_rig(rig, rig_tag, "pass", "b.txt", b, c) ||
        !dlx_tr_watch_start(&w, rig))
        return false;
    if (width)
        setenv("ZCL_LAND_TRAIN_WIDTH", width, 1);
    int64_t started = platform_time_monotonic_us();
    bool ok = dlx_tr_drain(12, &w, proofs, &landed, states, sizeof(states));
    long long ms = (long long)((platform_time_monotonic_us() - started) / 1000);
    printf("[measure width=%s rows=3 proofs=%d landed=%d wall_ms=%lld "
           "unproven=%d beats=%s] ", width ? width : "off", *proofs, landed,
           ms, w.unproven, states);
    return ok && landed == 3 && w.unproven == 0 &&
           dlx_tr_all_landed(rig, *proofs == 1);
}

/* Each row's outcome names the one proof pair (local at base) and its own
 * commit in the stacked history, which origin main contains. */
static bool dlx_tr_shared_pair(const struct dlx_rig *rig)
{
    char local[3][64], base[3][64], commit[3][64];
    for (long long seq = 1; seq <= 3; seq++) {
        size_t i = (size_t)seq - 1;
        const char *args[] = { "merge-base", "--is-ancestor", commit[i],
                               "main", NULL };
        if (!dlx_tr_outcome_field(seq, "local", local[i], sizeof(local[i])) ||
            !dlx_tr_outcome_field(seq, "base", base[i], sizeof(base[i])) ||
            !dlx_tr_outcome_field(seq, "train_commit", commit[i],
                                  sizeof(commit[i])) ||
            dlx_git(rig->bare, args) != 0) {
            printf("[seq=%lld local=%s commit=%s] ", seq, local[i],
                   commit[i]);
            return false;
        }
    }
    return strcmp(local[0], local[1]) == 0 && strcmp(local[1], local[2]) == 0 &&
           strcmp(base[0], base[1]) == 0 && strcmp(base[1], base[2]) == 0 &&
           strcmp(commit[0], commit[1]) != 0 &&
           strcmp(commit[1], commit[2]) != 0 &&
           strcmp(commit[0], commit[2]) != 0 &&
           strcmp(commit[2], local[2]) == 0;
}

static int test_dev_land_train_three_rows_one_proof(void)
{
    int failures = 0;
    TEST("land: a train of three rows lands all three from one exact proof") {
        struct dlx_rig rig;
        int proofs = 0;
        dlx_isolate("train_three");
        ASSERT(dlx_tr_measure("train_three", "3", &proofs, &rig));
        ASSERT_EQ(proofs, 1);
        ASSERT(dlx_tr_shared_pair(&rig));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_train_default_off(void)
{
    int failures = 0;
    TEST("land: without ZCL_LAND_TRAIN_WIDTH every row pays its own proof") {
        struct dlx_rig rig;
        char none[64];
        int proofs = 0;
        dlx_isolate("train_off");
        ASSERT(dlx_tr_measure("train_off", NULL, &proofs, &rig));
        for (long long seq = 1; seq <= 3; seq++) {
            ASSERT(!dlx_tr_outcome_field(seq, "train_commit", none,
                                         sizeof(none)));
        }
        ASSERT_EQ(proofs, 3);
        dlx_restore();
        /* Out of range is off, never clamped. */
        dlx_isolate("train_nine");
        ASSERT(dlx_tr_measure("train_nine", "9", &proofs, &rig));
        ASSERT_EQ(proofs, 3);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_train_conflict_skipped(void)
{
    int failures = 0;
    TEST("land: a train skips a row that conflicts with the stacked tip") {
        struct dlx_rig rig;
        struct dlx_tr_watch w;
        char b[64], c[64], intent[200], head[200], detail[512], states[256];
        int64_t attempt = 0, members[8];
        int proofs = 0, landed = 0;
        dlx_isolate("train_conflict");
        /* B adds change.txt too, with other bytes: it cannot stack on A. */
        ASSERT(dlx_tr_rig(&rig, "train_conflict_rig", "running", "change.txt",
                          b, c));
        ASSERT(dlx_tr_watch_start(&w, &rig));
        setenv("ZCL_LAND_TRAIN_WIDTH", "3", 1);
        ASSERT(dlx_tr_beat("started", 1, 1));
        dlx_tr_watch_beat(&w);
        ASSERT(dlx_tr_inflight_intent(head, sizeof(head)));
        ASSERT_EQ((int64_t)dlx_tr_members(members), 1);
        ASSERT_EQ(members[0], 3);
        ASSERT(dlx_tr_queued(2, &attempt, intent, sizeof(intent)));
        ASSERT_EQ(attempt, 1);
        ASSERT_STR_EQ(intent, "");
        ASSERT(dlx_tr_queued(3, &attempt, intent, sizeof(intent)));
        ASSERT_STR_EQ(intent, head);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(dlx_tr_drain(8, &w, &proofs, &landed, states, sizeof(states)));
        ASSERT_EQ(proofs, 0);
        ASSERT_EQ(landed, 2);
        ASSERT_EQ(w.unproven, 0);
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(dlx_tr_main_has(&rig, "c.txt"));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_train_red_falls_back_to_singles(void)
{
    int failures = 0;
    TEST("land: a red train fails nobody; every member proves alone and "
         "fails alone") {
        struct dlx_rig rig;
        char b[64], c[64], intent[200], before[64], after[64];
        int64_t attempt = 0;
        dlx_isolate("train_red");
        ASSERT(dlx_tr_rig(&rig, "train_red_rig", "fail", "b.txt", b, c));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_TRAIN_WIDTH", "3", 1);
        ASSERT(dlx_tr_beat("started", 2, 1));
        /* The stacked proof is red: the head is requeued, not failed. */
        ASSERT(dlx_tr_beat("rebased", 0, 1));
        /* The members are released, unbound and still queued at attempt 1. */
        ASSERT(dlx_tr_queued(2, &attempt, intent, sizeof(intent)));
        ASSERT_EQ(attempt, 1);
        ASSERT_STR_EQ(intent, "");
        ASSERT(dlx_tr_queued(3, &attempt, intent, sizeof(intent)));
        ASSERT_STR_EQ(intent, "");
        /* Marked rows never re-enter a train, even with width 3 and
         * joinable rows behind them: each starts alone, in queue order,
         * and each fails on its own proof. */
        ASSERT(dlx_tr_beat("started", 0, 1));
        ASSERT(dlx_tr_beat("failed", 0, 1));
        ASSERT(dlx_tr_beat("started", 0, 1));
        ASSERT(dlx_tr_beat("failed", 0, 1));
        ASSERT(dlx_tr_beat("started", 0, 1));
        ASSERT(dlx_tr_beat("failed", 0, 1));
        ASSERT(dlx_tr_beat("empty", 0, -1));
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, before);
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_train_red_then_singles_land(void)
{
    int failures = 0;
    TEST("land: after a red train each member lands from its own proof and "
         "no tip is published unproven") {
        struct dlx_rig rig;
        struct dlx_tr_watch w;
        char b[64], c[64], states[256], before[64], after[64];
        int proofs = 0, landed = 0;
        dlx_isolate("train_red_green");
        ASSERT(dlx_tr_rig(&rig, "train_red_green_rig", "fail", "b.txt", b, c));
        ASSERT(dlx_tr_watch_start(&w, &rig));
        ASSERT(dlx_origin_main(&rig, before));
        setenv("ZCL_LAND_TRAIN_WIDTH", "3", 1);
        ASSERT(dlx_tr_beat("started", 2, 1));
        dlx_tr_watch_beat(&w);
        ASSERT(dlx_tr_beat("rebased", 0, 1));
        dlx_tr_watch_beat(&w);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, before);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(dlx_tr_drain(12, &w, &proofs, &landed, states, sizeof(states)));
        printf("[beats=%s unproven=%d] ", states, w.unproven);
        ASSERT_EQ(proofs, 3);
        ASSERT_EQ(landed, 3);
        ASSERT_EQ(w.unproven, 0);
        ASSERT(dlx_tr_all_landed(&rig, false));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_train_held_row_skipped(void)
{
    int failures = 0;
    TEST("land: a held row is never stacked into a train") {
        struct dlx_rig rig;
        struct dlx_call h;
        char b[64], c[64], intent[200], head[200];
        int64_t attempt = 0, members[8];
        dlx_isolate("train_held");
        ASSERT(dlx_tr_rig(&rig, "train_held_rig", "running", "b.txt", b, c));
        dlx_begin(&h, "hold");
        (void)json_push_kv_int(&h.input, "seq", 2);
        ASSERT(dlx_run(&h) && dlx_ok(&h));
        dlx_end(&h);
        setenv("ZCL_LAND_TRAIN_WIDTH", "3", 1);
        ASSERT(dlx_tr_beat("started", 1, 1));
        ASSERT(dlx_tr_inflight_intent(head, sizeof(head)));
        ASSERT_EQ((int64_t)dlx_tr_members(members), 1);
        ASSERT_EQ(members[0], 3);
        ASSERT(dlx_tr_queued(2, &attempt, intent, sizeof(intent)));
        ASSERT_STR_EQ(intent, "");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(dlx_tr_beat("landed", 0, -1));
        /* The head landed; the held row was left queued, unbound and
         * unpublished, and C still rides in the head's pair. */
        ASSERT(dlx_tr_queued(2, &attempt, intent, sizeof(intent)));
        ASSERT_STR_EQ(intent, "");
        ASSERT(dlx_tr_queued(3, &attempt, intent, sizeof(intent)));
        ASSERT_STR_EQ(intent, head);
        ASSERT(dlx_tr_main_has(&rig, "change.txt"));
        ASSERT(!dlx_tr_main_has(&rig, "b.txt"));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_train_cancelled_row_skipped(void)
{
    int failures = 0;
    TEST("land: a cancelled row is never stacked and the train still lands") {
        struct dlx_rig rig;
        struct dlx_call x;
        struct dlx_tr_watch w;
        char b[64], c[64], states[256];
        int proofs = 0, landed = 0;
        dlx_isolate("train_cancelled");
        ASSERT(dlx_tr_rig(&rig, "train_cancelled_rig", "pass", "b.txt", b, c));
        ASSERT(dlx_tr_watch_start(&w, &rig));
        dlx_begin(&x, "cancel");
        (void)json_push_kv_int(&x.input, "seq", 2);
        ASSERT(dlx_run(&x) && dlx_ok(&x));
        dlx_end(&x);
        setenv("ZCL_LAND_TRAIN_WIDTH", "3", 1);
        ASSERT(dlx_tr_drain(12, &w, &proofs, &landed, states, sizeof(states)));
        ASSERT_EQ(proofs, 1);
        ASSERT_EQ(landed, 2);
        ASSERT_EQ(w.unproven, 0);
        ASSERT(dlx_tr_main_has(&rig, "change.txt"));
        ASSERT(dlx_tr_main_has(&rig, "c.txt"));
        ASSERT(!dlx_tr_main_has(&rig, "b.txt"));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static bool dlx_tr_refused(const char *action, long long seq)
{
    struct dlx_call c;
    dlx_begin(&c, action);
    (void)json_push_kv_int(&c.input, "seq", seq);
    bool ok = dlx_run(&c) && !dlx_ok(&c) &&
              strcmp(dlx_err_code(&c), "TRAIN_MEMBER_BOUND") == 0;
    if (!ok)
        printf("[%s seq=%lld code=%s] ", action, seq, dlx_err_code(&c));
    dlx_end(&c);
    return ok;
}

static int test_dev_land_train_member_bound(void)
{
    int failures = 0;
    TEST("land: cancel and hold refuse a bound train member") {
        struct dlx_rig rig;
        char b[64], c[64], intent[200], head[200];
        int64_t attempt = 0;
        dlx_isolate("train_bound");
        ASSERT(dlx_tr_rig(&rig, "train_bound_rig", "running", "b.txt", b, c));
        setenv("ZCL_LAND_TRAIN_WIDTH", "3", 1);
        ASSERT(dlx_tr_beat("started", 2, 1));
        ASSERT(dlx_tr_inflight_intent(head, sizeof(head)));
        ASSERT(dlx_tr_refused("cancel", 2));
        ASSERT(dlx_tr_refused("hold", 3));
        ASSERT(dlx_tr_refused("release", 3));
        ASSERT(dlx_tr_queued(2, &attempt, intent, sizeof(intent)));
        ASSERT_STR_EQ(intent, head);
        /* Landed with its head, a member still refuses until it records
         * its own landing. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(dlx_tr_beat("landed", 0, -1));
        ASSERT(dlx_tr_refused("cancel", 2));
        ASSERT(dlx_tr_beat("landed", 0, -1));
        ASSERT(dlx_tr_beat("landed", 0, -1));
        ASSERT(dlx_tr_all_landed(&rig, true));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_train_signed_drive(void)
{
    int failures = 0;
    TEST("land: drive --seq lands a signed train, each row under its own "
         "intent and remote receipt") {
        struct dlx_rig rig;
        struct dlx_call c;
        char b[64], c_tip[64], sig[3][160], receipt[3][160];
        dlx_isolate("train_signed");
        ASSERT(dlx_tr_rig(&rig, "train_signed_rig", "running", "b.txt", b,
                          c_tip));
        setenv("ZCL_LAND_TRAIN_WIDTH", "3", 1);
        ASSERT(dlx_tr_beat("started", 2, 1));
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        for (int seq = 1; seq <= 3; seq++) {
            ASSERT(dlx_drive_seq(&c, seq) && dlx_ok(&c));
            ASSERT_STR_EQ(dlx_str(&c, "outcome"), "landed");
            ASSERT_EQ(dlx_int(&c, "rounds"), seq == 1 ? 2 : 1);
            dlx_end(&c);
            ASSERT(dlx_tr_outcome_field(seq, "publication_signature",
                                        sig[seq - 1], sizeof(sig[0])));
            ASSERT(dlx_tr_outcome_field(seq, "remote_signature",
                                        receipt[seq - 1],
                                        sizeof(receipt[0])));
        }
        ASSERT(strcmp(sig[0], sig[1]) != 0 && strcmp(sig[0], sig[2]) != 0 &&
               strcmp(sig[1], sig[2]) != 0);
        ASSERT(strcmp(receipt[0], receipt[1]) != 0 &&
               strcmp(receipt[1], receipt[2]) != 0);
        ASSERT(dlx_tr_all_landed(&rig, true));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* ── the gate stays out of the way of plain rows ───────────────────────────
 *
 * Width unset is today's land: one row, one proof, one push. Every row binds
 * a proof_intent, so the publication gate must key on the head's own formed
 * train (a train_commit) and never read the queue or the outcome history
 * for a plain row. */

static bool dlx_tr_has_solo_mark(void)
{
    char land[1200], path[1400];
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    if (dlx_qp_file_has(path, "\"train_solo\":1"))
        return true;
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", land);
    return dlx_qp_file_has(path, "\"train_solo\":1");
}

static int test_dev_land_train_unset_resubmitted_tip(void)
{
    int failures = 0;
    TEST("land: width unset, a resubmitted tip sharing an earlier outcome's "
         "pair lands with no requeue and no train_solo mark") {
        struct dlx_rig rig;
        char b[64], moved[64], rebased[64], states[256], state[32] = "";
        int proofs = 0, landed = 0;
        dlx_isolate("train_unset_resub");
        ASSERT(dlx_rig_make(&rig, "train_unset_resub_rig"));
        ASSERT(dlx_qp_branch(&rig, "re-b", "b.txt", "b\n", NULL, NULL, b));
        setenv("ZCL_LAND_PROOF_STUB", "fail", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        /* Row 1 rebases onto a moved main as B' and fails its proof: its
         * outcome names B' at that main as its pair. */
        ASSERT(dlx_qp_submit(&rig, b, 1));
        ASSERT(dlx_qp_push_main(&rig, "m.txt", "m\n", moved));
        ASSERT(dlx_tr_beat("started", 0, 1));
        ASSERT(dlx_tr_beat("failed", 0, 1));
        ASSERT(dlx_tr_outcome_field(1, "local", rebased, sizeof(rebased)));
        ASSERT(strcmp(rebased, b) != 0);
        /* B' resubmitted: another tip, the same local@base. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(dlx_qp_submit(&rig, rebased, 2));
        ASSERT(dlx_tr_drain(8, NULL, &proofs, &landed, states,
                            sizeof(states)));
        printf("[beats=%s] ", states);
        ASSERT_STR_EQ(states, "started,landed,empty");
        ASSERT_EQ(proofs, 1);
        ASSERT(dlx_tr_outcome_field(2, "state", state, sizeof(state)));
        ASSERT_STR_EQ(state, "landed");
        ASSERT(!dlx_tr_has_solo_mark());
        ASSERT(dlx_tr_main_has(&rig, "b.txt"));
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* The step reads outcomes.jsonl at its slot (terminal replay) before it
 * reaches the push, so an unreadable history is refused there, with the
 * slot's own evidence, whatever the train code does. With width unset the
 * answer must be exactly that: the slot's refusal, never the publication
 * gate's, and no requeue, no train_solo mark, nothing pushed. */
static int test_dev_land_train_unset_unreadable_outcomes(void)
{
    int failures = 0;
    TEST("land: width unset, an unreadable outcomes.jsonl is refused at the "
         "step slot as before trains, with nothing pushed or marked") {
        struct dlx_rig rig;
        struct dlx_call s;
        char b[64], c[64], land[1200], opath[1400], states[256];
        char before[64], after[64];
        int proofs = 0, landed = 0;
        bool slot_refusal = false, gate_refusal = false;
        dlx_isolate("train_unset_unreadable");
        ASSERT(dlx_tr_rig(&rig, "train_unset_unreadable_rig", "pass", "b.txt",
                          b, c));
        ASSERT(dlx_tr_beat("started", 0, 1));
        ASSERT(dlx_tr_beat("landed", 0, -1));
        ASSERT(dlx_tr_beat("started", 0, 1));
        ASSERT(dlx_origin_main(&rig, before));
        dlx_landdir(land, sizeof(land));
        ASSERT(snprintf(opath, sizeof(opath), "%s/outcomes.jsonl", land) <
               (int)sizeof(opath));
        ASSERT(chmod(opath, 0200) == 0);
        {
            FILE *f = fopen(opath, "r");
            ASSERT(f == NULL);
        }
        dlx_begin(&s, "step");
        ASSERT(dlx_run(&s));
        slot_refusal = !dlx_ok(&s) &&
                       strcmp(dlx_err_code(&s), "QUEUE_READ_FAILED") == 0 &&
                       strstr(dlx_err_evidence(&s),
                              "outcomes.jsonl unreadable or malformed") != NULL;
        gate_refusal = strstr(dlx_err_evidence(&s),
                              "queue.jsonl or outcomes.jsonl") != NULL;
        printf("[push beat ok=%d code=%s evidence=%s] ", dlx_ok(&s) ? 1 : 0,
               dlx_err_code(&s), dlx_err_evidence(&s));
        dlx_end(&s);
        ASSERT(chmod(opath, 0600) == 0);
        ASSERT(slot_refusal);
        ASSERT(!gate_refusal);
        ASSERT(dlx_origin_main(&rig, after));
        ASSERT_STR_EQ(after, before);
        ASSERT(!dlx_tr_main_has(&rig, "b.txt"));
        ASSERT(!dlx_tr_has_solo_mark());
        /* Readable again, the same row lands on its own turn. */
        ASSERT(dlx_tr_drain(8, NULL, &proofs, &landed, states,
                            sizeof(states)));
        ASSERT_STR_EQ(states, "landed,started,landed,empty");
        ASSERT(dlx_tr_all_landed(&rig, false));
        ASSERT(!dlx_tr_has_solo_mark());
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int test_dev_land_train_crash_after_bind(void)
{
    int failures = 0;
    TEST("land: a crash between the members' bind and the head's persist "
         "leaves stale members that re-prove alone, never published "
         "unproven") {
        struct dlx_rig rig;
        struct dlx_tr_watch w;
        char b[64], c[64], intent[200], stale[80], states[256], none[64];
        int64_t attempt = 0;
        int proofs = 0, landed = 0, child_status = 0;
        dlx_isolate("train_crash_bind");
        ASSERT(dlx_tr_rig(&rig, "train_crash_bind_rig", "running", "b.txt", b,
                          c));
        ASSERT(dlx_tr_watch_start(&w, &rig));
        setenv("ZCL_LAND_TRAIN_WIDTH", "3", 1);
        pid_t child = fork();
        ASSERT(child >= 0);
        if (child == 0) {
            struct dlx_call cc;
            (void)setenv("ZCL_LAND_TEST_DIE_AFTER_TRAIN_BIND", "1", 1);
            dlx_begin(&cc, "step");
            (void)dlx_run(&cc);
            _exit(90);
        }
        ASSERT(waitpid(child, &child_status, 0) == child);
        ASSERT(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 83);
        /* The members are bound; the head never persisted the pair. */
        ASSERT(!dlx_tr_inflight_intent(intent, sizeof(intent)));
        ASSERT(dlx_tr_queued(2, &attempt, intent, sizeof(intent)));
        ASSERT(intent[0] != '\0');
        ASSERT(dlx_tr_queued(3, &attempt, intent, sizeof(intent)));
        ASSERT(intent[0] != '\0');
        ASSERT(dlx_tr_file_field("queue.jsonl", 3, "local", stale,
                                 sizeof(stale)));
        /* Restart with trains still on: the head and the stale members each
         * prove on their own turn, and every tip main takes began a proof. */
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(dlx_tr_drain(16, &w, &proofs, &landed, states, sizeof(states)));
        printf("[beats=%s unproven=%d] ", states, w.unproven);
        ASSERT_EQ(proofs, 3);
        ASSERT_EQ(landed, 3);
        ASSERT_EQ(w.unproven, 0);
        ASSERT(dlx_tr_all_landed(&rig, false));
        for (long long seq = 1; seq <= 3; seq++) {
            ASSERT(!dlx_tr_outcome_field(seq, "train_commit", none,
                                         sizeof(none)));
        }
        ASSERT(!dlx_tr_has_solo_mark());
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* The queue amends nothing. The rig's Makefile carries the two targets the
 * old regen phase ran after every rebase, each of which would dirty a
 * tracked document and leave a marker; a train of two rows must land with
 * neither run, the document commits it was submitted with, and the pushed
 * tip equal to the stacked commit the proof was bound to. */
static int test_dev_land_train_never_amended(void)
{
    int failures = 0;
    TEST("land: a train of two rows is not amended; the landed commits are "
         "the stacked ones, no generator runs and no document changes") {
        struct dlx_rig rig;
        char b[64], m0[64], scratch[64], main_tip[64], pushed[2][64];
        char commit[2][64], local[2][64], names[128], count[16], range[200];
        char landwt[1300], marks[1400];
        int proofs = 0, landed = 0;
        char states[256];
        const char *names_args[] = { "diff", "--name-only", m0, "main",
                                     NULL };
        const char *count_args[] = { "rev-list", "--count", NULL, "main",
                                     NULL };
        dlx_isolate("train_noamend");
        ASSERT(dlx_rig_make(&rig, "train_noamend_rig"));
        ASSERT(dlx_qp_push_main(&rig, "Makefile",
            "docs-executor-routing:\n"
            "\t@mkdir -p build; echo routing >> build/regen-marks; "
            "echo drift >> docs/agent/EXECUTOR_HEURISTICS.md\n"
            "fix-doc-counts:\n"
            "\t@mkdir -p build; echo counts >> build/regen-marks; "
            "echo drift >> docs/dev/CODEBASE_MAP.md\n"
            "build/dev-loop/restart.env:\n"
            "\t@mkdir -p build/dev-loop; echo plan >> $@\n", scratch));
        ASSERT(dlx_qp_push_main(&rig, "docs/agent/EXECUTOR_HEURISTICS.md",
                                "orig\n", scratch));
        ASSERT(dlx_qp_push_main(&rig, "docs/dev/CODEBASE_MAP.md", "orig\n",
                                m0));
        ASSERT(dlx_qp_branch(&rig, "tr-b", "b.txt", "b\n", NULL, NULL, b));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        ASSERT(dlx_qp_submit(&rig, rig.tip, 1) && dlx_qp_submit(&rig, b, 2));
        setenv("ZCL_LAND_TRAIN_WIDTH", "2", 1);
        ASSERT(dlx_tr_drain(8, NULL, &proofs, &landed, states,
                            sizeof(states)));
        ASSERT_EQ(proofs, 1);
        ASSERT_EQ(landed, 2);
        ASSERT(dlx_origin_main(&rig, main_tip));
        /* Neither generator ran in the landing worktree. */
        dlx_land_wt(landwt, sizeof(landwt));
        /* names is 128 bytes: a long checkout path truncated the mark path
         * to a directory that exists, so the check read the wrong path. */
        ASSERT(snprintf(marks, sizeof(marks), "%s/build/regen-marks",
                        landwt) < (int)sizeof(marks));
        ASSERT(!dlx_file_exists(marks));
        /* Main gained exactly the two submitted changes, as two commits. */
        ASSERT(dlx_git_out(rig.bare, names_args, names, sizeof(names)) == 0);
        ASSERT_STR_EQ(names, "b.txt\nchange.txt");
        (void)snprintf(range, sizeof(range), "%s..main", m0);
        count_args[2] = range;
        ASSERT(dlx_git_out(rig.bare, count_args, count, sizeof(count)) == 0);
        ASSERT_STR_EQ(count, "2");
        /* Each outcome names the stacked commit that was proved; the last
         * member's commit is the pushed tip, unamended. */
        for (long long seq = 1; seq <= 2; seq++) {
            size_t i = (size_t)seq - 1;
            ASSERT(dlx_tr_outcome_field(seq, "tip_pushed", pushed[i],
                                        sizeof(pushed[i])));
            ASSERT(dlx_tr_outcome_field(seq, "train_commit", commit[i],
                                        sizeof(commit[i])));
            ASSERT(dlx_tr_outcome_field(seq, "local", local[i],
                                        sizeof(local[i])));
            ASSERT_STR_EQ(pushed[i], main_tip);
        }
        ASSERT_STR_EQ(commit[1], local[1]);
        ASSERT_STR_EQ(commit[1], main_tip);
        ASSERT(strcmp(commit[0], commit[1]) != 0);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_train_cases(void)
{
    int failures = 0;
    failures += test_dev_land_train_three_rows_one_proof();
    failures += test_dev_land_train_never_amended();
    failures += test_dev_land_train_default_off();
    failures += test_dev_land_train_conflict_skipped();
    failures += test_dev_land_train_red_falls_back_to_singles();
    failures += test_dev_land_train_red_then_singles_land();
    failures += test_dev_land_train_held_row_skipped();
    failures += test_dev_land_train_cancelled_row_skipped();
    failures += test_dev_land_train_member_bound();
    failures += test_dev_land_train_signed_drive();
    failures += test_dev_land_train_unset_resubmitted_tip();
    failures += test_dev_land_train_unset_unreadable_outcomes();
    failures += test_dev_land_train_crash_after_bind();
    return failures;
}

#endif /* !defined(_WIN32) */
