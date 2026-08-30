/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_land_queue — the gate on the landing queue.
 *
 * The queue exists so that N agents cost ONE gate run instead of N, and so
 * that no agent waits for it. That trade is only safe if two things hold
 * absolutely, and this file exists for those two rather than for the happy
 * path:
 *
 *  1. A LANDING CANNOT BE FABRICATED. "The gate did not run" and "the gate
 *     passed" are different facts. Five attempts here try to land work
 *     through the five ways that distinction could be lost — no gate run at
 *     all, a gate run that never contained this submission, a gate run that
 *     was red, a gate run that skipped its groups, and a gate run that
 *     cannot say which tree it proved — and each must be a refusal, by name.
 *
 *  2. A BAD BATCH REFUSES ONLY THE CULPRIT. A batch failure that refused
 *     everyone would be worse than no batching: an agent's work would be
 *     rejected because of a stranger's bug. case_bisect drives the exact
 *     recursion the lander performs — gate three, red; gate the halves; land
 *     the innocent, refuse the guilty — and checks every resulting state.
 *
 * The rest guards the properties the receipts stand on:
 *
 *  3. THE QUEUE IS THE LOG. There is no sidecar state file that could
 *     disagree with the receipts, so a restart is invisible. case_restart
 *     writes, closes, reopens and requires identical state.
 *
 *  4. IDENTICAL CONTENT, IDENTICAL BYTES. Two encodings of the same
 *     submission must be byte-equal, and changing ANY field must change the
 *     bytes. Without that, two honest recorders would chain the same history
 *     differently and the chain would prove nothing about content.
 *
 *  5. FOUR SUBMITTERS DO NOT CORRUPT IT AND DO NOT CONVOY. Four real
 *     processes — one per machine in the fleet this was built for — append
 *     concurrently to one queue file; afterwards the chain must verify and
 *     every submission must be present exactly once, with no gap.
 *
 *  6. SUBMITTING NEVER WAITS FOR A GATE. The property asserted is the
 *     load-independent one — one submit writes exactly ONE frame and its
 *     cost does not grow with queue depth or with a gate run being
 *     outstanding. Deliberately NOT a stopwatch:
 *     tools/lint/check_no_wallclock_assertion.sh forbids grading a test on a
 *     measured interval, and it is right to — this fleet keeps 7200rpm boxes
 *     on purpose, and a millisecond bound would grade the machine rather
 *     than the code. The latency itself is measured and reported by
 *     tools/dev/land_bench.sh, where a number is data instead of a verdict.
 *
 *  7. A VERDICT IS CHECKABLE BY WHOEVER RECEIVES IT. Its content address is
 *     computed from four public facts — submitted commit, integration
 *     commit, gating tree identity, verdict — so a second machine
 *     recomputes it without this queue and without trusting this machine.
 */

#include "test/test_core.h"

#include "land/land_queue.h"

#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

#define LQ_CHECK(name, expr)                                            \
    do {                                                                \
        const bool lq_ok_ = (expr);                                     \
        if (!lq_ok_) failures++;                                        \
        printf("land_queue: %s %s\n", lq_ok_ ? "OK  " : "FAIL", (name)); \
    } while (0)

/* Two distinct 20-byte shas, spelled as hex so the fixtures read like the
 * command lines a person actually types. */
static const char *const k_head_a =
    "1111111111111111111111111111111111111111";
static const char *const k_head_b =
    "2222222222222222222222222222222222222222";
static const char *const k_integ =
    "abcdef0123456789abcdef0123456789abcdef01";

static void fill_submit(struct land_submit *s, const char *branch,
                        const char *head, const char *who, const char *note)
{
    memset(s, 0, sizeof *s);
    snprintf(s->branch, sizeof s->branch, "%s", branch);
    snprintf(s->submitter, sizeof s->submitter, "%s", who);
    snprintf(s->note, sizeof s->note, "%s", note ? note : "");
    (void)land_sha_parse(head, s->head);
}

/* Submit one branch and hand back its seq. */
static uint64_t submit_one(struct land_queue *q, const char *branch,
                           const char *head)
{
    struct land_submit s;
    fill_submit(&s, branch, head, "test-agent", "");
    uint64_t seq = 0;
    if (land_queue_submit(q, &s, &seq) != LAND_OK)
        return 0;
    return seq;
}

/* A gating tree's identity, as source-identity.sh would report one. */
static const char *const k_gate_id =
    "3333333333333333333333333333333333333333333333333333333333333333";

/* Record one gate run over `n` submissions and hand back its seq. */
static uint64_t gate_over(struct land_queue *q, enum land_gate_outcome outcome,
                          bool stress, const uint64_t *seqs, uint32_t n)
{
    struct land_gate_run g;
    memset(&g, 0, sizeof g);
    g.outcome = outcome;
    g.stress = stress;
    (void)land_sha_parse(k_integ, g.integration);
    (void)land_id32_parse(k_gate_id, g.gate_id);
    g.member_count = n;
    for (uint32_t i = 0; i < n; i++)
        g.member_seq[i] = seqs[i];
    uint64_t seq = 0;
    if (land_queue_gate_run(q, &g, &seq) != LAND_OK)
        return 0;
    return seq;
}

static enum land_status settle(struct land_queue *q, uint64_t submit_seq,
                               enum land_state state, uint64_t gate_run_seq)
{
    struct land_verdict v;
    memset(&v, 0, sizeof v);
    v.state = state;
    v.submit_seq = submit_seq;
    v.gate_run_seq = gate_run_seq;
    const struct land_entry *e = land_queue_find_seq(q, submit_seq);
    if (e) {
        memcpy(v.branch, e->submit.branch, sizeof v.branch);
        memcpy(v.head, e->submit.head, sizeof v.head);
    } else {
        snprintf(v.branch, sizeof v.branch, "unknown");
    }
    snprintf(v.reason, sizeof v.reason, "test");
    if (state == LAND_STATE_LANDED)
        (void)land_sha_parse(k_integ, v.integration);
    return land_queue_verdict(q, &v, NULL);
}

static enum land_state state_of(struct land_queue *q, uint64_t seq)
{
    const struct land_entry *e = land_queue_find_seq(q, seq);
    return e ? e->state : LAND_STATE_QUEUED;
}

/* ── 1. submit costs nothing and the queue is the log ──────────────────── */

static int case_submit_and_pending(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "submit");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    LQ_CHECK("a fresh queue opens", q != NULL);
    LQ_CHECK("and is empty", q && land_queue_count(q) == 0);
    if (!q) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t a = submit_one(q, "lane/alpha", k_head_a);
    uint64_t b = submit_one(q, "lane/beta", k_head_b);
    LQ_CHECK("two submissions get dense sequence numbers", a == 1 && b == 2);
    LQ_CHECK("both are QUEUED immediately",
             state_of(q, a) == LAND_STATE_QUEUED &&
                 state_of(q, b) == LAND_STATE_QUEUED);

    const struct land_entry *e = land_queue_find_branch(q, "lane/alpha");
    LQ_CHECK("a branch can be looked up by name", e && e->seq == a);
    uint8_t want_a[LAND_SHA_BYTES];
    (void)land_sha_parse(k_head_a, want_a);
    LQ_CHECK("and carries the exact head that was submitted",
             e && memcmp(e->submit.head, want_a, LAND_SHA_BYTES) == 0);

    /* A resubmitted branch is a NEW entry, and status answers about the
     * live one. A queue that overwrote the first would lose the receipt for
     * work someone was told had been refused. */
    uint64_t again = submit_one(q, "lane/alpha", k_head_b);
    const struct land_entry *live = land_queue_find_branch(q, "lane/alpha");
    LQ_CHECK("a resubmitted branch is a second entry, not an overwrite",
             again == 3 && land_queue_count(q) == 3 && live && live->seq == again);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 2. THE SEAM: a landing cannot be fabricated ───────────────────────── */

static int case_landing_needs_a_real_gate(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "seam");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t a = submit_one(q, "lane/alpha", k_head_a);
    uint64_t b = submit_one(q, "lane/beta", k_head_b);

    /* (i) No gate run at all. This is the one that matters most: an agent
     * that crashed mid-batch, or a lander that lost its log, must never be
     * able to settle work as landed. */
    LQ_CHECK("LANDED with no gate run is refused",
             settle(q, a, LAND_STATE_LANDED, 0) == LAND_ERR_NO_GATE_RUN);
    LQ_CHECK("and the submission is still QUEUED, not landed",
             state_of(q, a) == LAND_STATE_QUEUED);

    /* (ii) A gate run that exists but never contained this submission. */
    uint64_t only_b[] = { b };
    uint64_t gr_b = gate_over(q, LAND_GATE_GREEN, true, only_b, 1);
    LQ_CHECK("a green gate run records", gr_b != 0);
    LQ_CHECK("LANDED against a gate run that did not contain it is refused",
             settle(q, a, LAND_STATE_LANDED, gr_b) == LAND_ERR_NO_GATE_RUN);

    /* (iii) A gate run that DID contain it, and was red. */
    uint64_t both[] = { a, b };
    uint64_t gr_red = gate_over(q, LAND_GATE_RED, true, both, 2);
    LQ_CHECK("LANDED against a red gate run is refused",
             settle(q, a, LAND_STATE_LANDED, gr_red) == LAND_ERR_GATE_NOT_GREEN);

    /* (iv) Green, containing it — but the run skipped its groups. Without
     * ZCL_STRESS_TESTS=1 four groups self-skip and `make pre-push-ci` itself
     * refuses the receipt. A skip-riddled pass is not a pass here either. */
    uint64_t gr_soft = gate_over(q, LAND_GATE_GREEN, false, both, 2);
    LQ_CHECK("LANDED against a gate run that skipped its groups is refused",
             settle(q, a, LAND_STATE_LANDED, gr_soft) ==
                 LAND_ERR_GATE_NOT_STRESSED);

    /* (v) Green, stressed, containing it — but the runner could not say
     * WHICH tree it gated. That is a pass no second machine can check, and a
     * receipt nobody can check is the thing this design exists to remove. */
    struct land_gate_run anon;
    memset(&anon, 0, sizeof anon);
    anon.outcome = LAND_GATE_GREEN;
    anon.stress = true;
    (void)land_sha_parse(k_integ, anon.integration);
    /* gate_id deliberately left all zero */
    anon.member_count = 2;
    anon.member_seq[0] = a;
    anon.member_seq[1] = b;
    uint64_t gr_anon = 0;
    LQ_CHECK("an unidentified gate run still records honestly",
             land_queue_gate_run(q, &anon, &gr_anon) == LAND_OK);
    LQ_CHECK("but LANDED behind an unidentifiable tree is refused",
             settle(q, a, LAND_STATE_LANDED, gr_anon) ==
                 LAND_ERR_GATE_UNIDENTIFIED);

    LQ_CHECK("after five attempts nothing has landed",
             state_of(q, a) != LAND_STATE_LANDED);

    /* Refusing ungated work is always sound, so it needs no backing. */
    LQ_CHECK("REFUSED needs no gate run behind it",
             settle(q, a, LAND_STATE_REFUSED, 0) == LAND_OK);
    LQ_CHECK("and the submission is REFUSED, never LANDED",
             state_of(q, a) == LAND_STATE_REFUSED);
    LQ_CHECK("a second verdict for a settled submission is refused",
             settle(q, a, LAND_STATE_LANDED, 0) == LAND_ERR_ALREADY_FINAL);

    /* And the real thing succeeds, so the four refusals above are not just a
     * function that refuses everything. */
    uint64_t gr_ok = gate_over(q, LAND_GATE_GREEN, true, both, 2);
    LQ_CHECK("a green, stress-enabled run containing it does land",
             settle(q, b, LAND_STATE_LANDED, gr_ok) == LAND_OK);
    LQ_CHECK("and the state is LANDED", state_of(q, b) == LAND_STATE_LANDED);

    struct land_metrics m;
    land_queue_metrics(q, &m);
    LQ_CHECK("every landing in the log is backed", m.unbacked_landings == 0);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 3. a red batch bisects: innocent lands, culprit is refused ─────────
 * This drives the lander's own recursion over the queue: gate all three,
 * red; split; gate the halves; settle from what each smaller run said. */

static int case_bisect(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "bisect");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t a = submit_one(q, "lane/good-a", k_head_a);
    uint64_t b = submit_one(q, "lane/good-b", k_head_b);
    uint64_t c = submit_one(q, "lane/bad-c", k_head_a);

    /* Batch of three: RED. Nothing settles here — a red batch says only
     * "something in this set is bad", which is not a verdict about anyone. */
    uint64_t all[] = { a, b, c };
    uint64_t gr_all = gate_over(q, LAND_GATE_RED, true, all, 3);
    LQ_CHECK("the red batch is recorded", gr_all != 0);
    LQ_CHECK("a red batch settles nobody",
             state_of(q, a) == LAND_STATE_GATING &&
                 state_of(q, b) == LAND_STATE_GATING &&
                 state_of(q, c) == LAND_STATE_GATING);

    /* First half: green. Both land off ONE further gate run. */
    uint64_t half_a[] = { a };
    uint64_t gr_a = gate_over(q, LAND_GATE_GREEN, true, half_a, 1);
    LQ_CHECK("the innocent half lands",
             settle(q, a, LAND_STATE_LANDED, gr_a) == LAND_OK);

    uint64_t half_b[] = { b, c };
    uint64_t gr_bc = gate_over(q, LAND_GATE_RED, true, half_b, 2);
    LQ_CHECK("the half holding the culprit is red", gr_bc != 0);

    uint64_t only_b[] = { b };
    uint64_t gr_b = gate_over(q, LAND_GATE_GREEN, true, only_b, 1);
    LQ_CHECK("the second innocent lands once gated alone",
             settle(q, b, LAND_STATE_LANDED, gr_b) == LAND_OK);

    uint64_t only_c[] = { c };
    uint64_t gr_c = gate_over(q, LAND_GATE_RED, true, only_c, 1);
    LQ_CHECK("the culprit, gated alone, is red", gr_c != 0);
    LQ_CHECK("and is REFUSED, not landed",
             settle(q, c, LAND_STATE_REFUSED, gr_c) == LAND_OK);

    LQ_CHECK("innocent work landed",
             state_of(q, a) == LAND_STATE_LANDED &&
                 state_of(q, b) == LAND_STATE_LANDED);
    LQ_CHECK("guilty work did not",
             state_of(q, c) == LAND_STATE_REFUSED);
    /* The culprit could not have been landed even by mistake: its only green
     * gate runs never contained it. */
    LQ_CHECK("and could not be landed against the innocents' runs",
             land_queue_check_landable(q, c, gr_a) == LAND_ERR_NO_GATE_RUN &&
                 land_queue_check_landable(q, c, gr_b) == LAND_ERR_NO_GATE_RUN);

    struct land_metrics m;
    land_queue_metrics(q, &m);
    LQ_CHECK("two landed, one refused", m.landed == 2 && m.refused == 1);
    LQ_CHECK("five gate runs were spent", m.gate_runs == 5);
    LQ_CHECK("nothing in the log is an unbacked landing",
             m.unbacked_landings == 0);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 4. a timeout is a refusal, never a landing ────────────────────────── */

static int case_timeout(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "timeout");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t a = submit_one(q, "lane/slow", k_head_a);
    uint64_t only_a[] = { a };
    uint64_t gr = gate_over(q, LAND_GATE_TIMEOUT, true, only_a, 1);
    LQ_CHECK("a timed-out gate run is recorded as what it was", gr != 0);
    LQ_CHECK("a timed-out run cannot back a landing",
             land_queue_check_landable(q, a, gr) == LAND_ERR_GATE_NOT_GREEN);
    LQ_CHECK("the submission settles as TIMEOUT",
             settle(q, a, LAND_STATE_TIMEOUT, gr) == LAND_OK);
    LQ_CHECK("and is not landed", state_of(q, a) == LAND_STATE_TIMEOUT);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 5. a restart is invisible ─────────────────────────────────────────── */

static int case_restart(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "restart");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    uint64_t a = submit_one(q, "lane/alpha", k_head_a);
    uint64_t b = submit_one(q, "lane/beta", k_head_b);
    uint64_t both[] = { a, b };
    uint64_t gr = gate_over(q, LAND_GATE_GREEN, true, both, 2);
    (void)settle(q, a, LAND_STATE_LANDED, gr);
    struct land_metrics before;
    land_queue_metrics(q, &before);
    land_queue_close(q);

    /* Nothing was kept in RAM, so nothing can be lost by stopping. */
    struct zcl_chainlog_report rep2;
    struct land_queue *again = land_queue_open(path, &rep2);
    LQ_CHECK("the queue reopens", again != NULL);
    if (!again) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    struct land_metrics after;
    land_queue_metrics(again, &after);
    LQ_CHECK("with nothing torn", rep2.torn_bytes == 0);
    LQ_CHECK("the same submissions", after.submissions == before.submissions);
    LQ_CHECK("the same states",
             after.landed == before.landed && after.queued == before.queued &&
                 after.gating == before.gating);
    LQ_CHECK("the same gate runs", after.gate_runs == before.gate_runs);
    LQ_CHECK("the unsettled submission is still pending after a restart",
             state_of(again, b) == LAND_STATE_GATING);
    LQ_CHECK("the settled one is still landed",
             state_of(again, a) == LAND_STATE_LANDED);
    /* And the seam still holds after a restart: the backing check is
     * recomputed from the log, not remembered. */
    LQ_CHECK("the backing check survives the restart",
             land_queue_check_landable(again, b, gr) == LAND_OK);

    /* Appending after a restart continues the sequence rather than
     * restarting it, so receipts stay totally ordered across restarts. */
    uint64_t c = submit_one(again, "lane/gamma", k_head_a);
    LQ_CHECK("a submission after a restart continues the ordering",
             c > b && c > gr);

    land_queue_close(again);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 6. receipts are ordered and the chain verifies ────────────────────── */

static int case_chain_verifies(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "chain");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    uint64_t a = submit_one(q, "lane/alpha", k_head_a);
    uint64_t b = submit_one(q, "lane/beta", k_head_b);
    uint64_t both[] = { a, b };
    uint64_t gr = gate_over(q, LAND_GATE_GREEN, true, both, 2);
    (void)settle(q, a, LAND_STATE_LANDED, gr);
    (void)settle(q, b, LAND_STATE_LANDED, gr);
    land_queue_close(q);

    uint8_t stream[32];
    land_stream_id(stream);
    struct zcl_chainlog_report vrep;
    LQ_CHECK("the receipt chain verifies from the outside",
             zcl_chainlog_verify(path, stream, &vrep) == ZCL_CHAINLOG_OK);
    LQ_CHECK("with every frame accounted for (2 submits, 1 run, 2 verdicts)",
             vrep.records == 5);
    LQ_CHECK("and receipts are ordered by the log's own dense seq",
             a == 1 && b == 2 && gr == 3);

    /* A queue log is bound to its stream: the frames cannot be lifted into
     * some other chainlog and re-presented as that log's history. */
    uint8_t other[32];
    memset(other, 0x5A, sizeof other);
    struct zcl_chainlog_report orep;
    LQ_CHECK("and cannot be read as a log of something else",
             zcl_chainlog_verify(path, other, &orep) ==
                 ZCL_CHAINLOG_STREAM_MISMATCH);

    /* An edit is named, not merely detected. Flip one payload bit and
     * require the chain to refuse at the frame that was touched. */
    FILE *f = fopen(path, "r+b");
    LQ_CHECK("the log file opens for a tamper test", f != NULL);
    if (f) {
        /* Byte 80 is inside the first frame's payload: past the 64-byte
         * header and the 16-byte frame prefix. */
        (void)fseek(f, 80, SEEK_SET);
        int ch = fgetc(f);
        (void)fseek(f, 80, SEEK_SET);
        (void)fputc(ch ^ 0x01, f);
        (void)fclose(f);
        struct zcl_chainlog_report trep;
        LQ_CHECK("an edited receipt refuses as a broken chain",
                 zcl_chainlog_verify(path, stream, &trep) ==
                     ZCL_CHAINLOG_BROKEN_CHAIN);
        LQ_CHECK("and names the first frame that does not verify",
                 trep.first_bad_seq == 1);
    }

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 7. identical content, identical bytes ─────────────────────────────── */

static int case_canonical_bytes(void)
{
    int failures = 0;
    uint8_t one[1024], two[1024];
    struct land_submit s1, s2;

    fill_submit(&s1, "lane/alpha", k_head_a, "agent-a", "a note");
    fill_submit(&s2, "lane/alpha", k_head_a, "agent-a", "a note");
    /* Poison the buffers differently so a reserved byte the encoder forgets
     * to write shows up as a difference rather than passing by luck. */
    memset(one, 0xAA, sizeof one);
    memset(two, 0x55, sizeof two);
    size_t n1 = land_submit_encode(&s1, one, sizeof one);
    size_t n2 = land_submit_encode(&s2, two, sizeof two);
    LQ_CHECK("a submission encodes", n1 > 0 && n1 == n2);
    LQ_CHECK("identical content gives identical bytes",
             n1 > 0 && memcmp(one, two, n1) == 0);

    /* Every field is load-bearing: changing any one of them must change the
     * bytes. A field that does not is a field an editor could change without
     * the chain noticing. */
    struct land_submit v;
    size_t nv;

    fill_submit(&v, "lane/beta", k_head_a, "agent-a", "a note");
    nv = land_submit_encode(&v, two, sizeof two);
    LQ_CHECK("a different branch gives different bytes",
             nv == 0 || nv != n1 || memcmp(one, two, n1) != 0);

    fill_submit(&v, "lane/alpha", k_head_b, "agent-a", "a note");
    nv = land_submit_encode(&v, two, sizeof two);
    LQ_CHECK("a different head gives different bytes",
             nv == n1 && memcmp(one, two, n1) != 0);

    fill_submit(&v, "lane/alpha", k_head_a, "agent-b", "a note");
    nv = land_submit_encode(&v, two, sizeof two);
    LQ_CHECK("a different submitter gives different bytes",
             nv == n1 && memcmp(one, two, n1) != 0);

    fill_submit(&v, "lane/alpha", k_head_a, "agent-a", "b note");
    nv = land_submit_encode(&v, two, sizeof two);
    LQ_CHECK("a different note gives different bytes",
             nv == n1 && memcmp(one, two, n1) != 0);

    /* Round trip. */
    struct land_submit back;
    LQ_CHECK("a submission decodes back to itself",
             land_submit_decode(one, n1, &back) &&
                 strcmp(back.branch, s1.branch) == 0 &&
                 strcmp(back.submitter, s1.submitter) == 0 &&
                 strcmp(back.note, s1.note) == 0 &&
                 memcmp(back.head, s1.head, LAND_SHA_BYTES) == 0);

    /* Trailing bytes are refused rather than ignored: a decoder that skipped
     * them would let a record carry content nobody hashed a meaning for. */
    LQ_CHECK("a trailing byte is refused, not ignored",
             !land_submit_decode(one, n1 + 1, &back));
    LQ_CHECK("a truncated record is refused",
             !land_submit_decode(one, n1 - 1, &back));

    /* A control character would split a status line in two; a branch that
     * long has no encoding. Both are refusals at the encoder so no such
     * record can reach disk. */
    fill_submit(&v, "lane/a\nb", k_head_a, "agent-a", "");
    LQ_CHECK("a newline in a branch name has no encoding",
             land_submit_encode(&v, two, sizeof two) == 0);
    memset(&v, 0, sizeof v);
    memset(v.branch, 'x', LAND_BRANCH_MAX + 1);
    snprintf(v.submitter, sizeof v.submitter, "agent-a");
    LQ_CHECK("an over-long branch has no encoding",
             land_submit_encode(&v, two, sizeof two) == 0);

    /* The same discipline over the other two kinds. */
    struct land_gate_run g1, g2;
    memset(&g1, 0, sizeof g1);
    g1.outcome = LAND_GATE_GREEN;
    g1.stress = true;
    (void)land_sha_parse(k_integ, g1.integration);
    g1.member_count = 2;
    g1.member_seq[0] = 7;
    g1.member_seq[1] = 9;
    g2 = g1;
    memset(one, 0xAA, sizeof one);
    memset(two, 0x55, sizeof two);
    n1 = land_gate_run_encode(&g1, one, sizeof one);
    n2 = land_gate_run_encode(&g2, two, sizeof two);
    LQ_CHECK("a gate run encodes identically for identical content",
             n1 > 0 && n1 == n2 && memcmp(one, two, n1) == 0);
    g2.stress = false;
    n2 = land_gate_run_encode(&g2, two, sizeof two);
    LQ_CHECK("dropping the stress flag changes the bytes",
             n2 == n1 && memcmp(one, two, n1) != 0);
    g2 = g1;
    g2.member_seq[1] = 10;
    n2 = land_gate_run_encode(&g2, two, sizeof two);
    LQ_CHECK("a different member set changes the bytes",
             n2 == n1 && memcmp(one, two, n1) != 0);
    struct land_gate_run gback;
    LQ_CHECK("a gate run decodes back to itself",
             land_gate_run_decode(one, n1, &gback) &&
                 gback.outcome == g1.outcome && gback.stress == g1.stress &&
                 gback.member_count == 2 && gback.member_seq[0] == 7 &&
                 gback.member_seq[1] == 9);

    struct land_verdict d1, d2;
    memset(&d1, 0, sizeof d1);
    d1.state = LAND_STATE_LANDED;
    d1.submit_seq = 4;
    d1.gate_run_seq = 6;
    snprintf(d1.branch, sizeof d1.branch, "lane/alpha");
    snprintf(d1.reason, sizeof d1.reason, "green in a batch of 3");
    (void)land_sha_parse(k_head_a, d1.head);
    (void)land_sha_parse(k_integ, d1.integration);
    d2 = d1;
    memset(one, 0xAA, sizeof one);
    memset(two, 0x55, sizeof two);
    n1 = land_verdict_encode(&d1, one, sizeof one);
    n2 = land_verdict_encode(&d2, two, sizeof two);
    LQ_CHECK("a verdict encodes identically for identical content",
             n1 > 0 && n1 == n2 && memcmp(one, two, n1) == 0);
    d2.gate_run_seq = 7;
    n2 = land_verdict_encode(&d2, two, sizeof two);
    LQ_CHECK("naming a different gate run changes the bytes",
             n2 == n1 && memcmp(one, two, n1) != 0);
    struct land_verdict dback;
    LQ_CHECK("a verdict decodes back to itself",
             land_verdict_decode(one, n1, &dback) &&
                 dback.state == LAND_STATE_LANDED && dback.submit_seq == 4 &&
                 dback.gate_run_seq == 6 &&
                 strcmp(dback.branch, "lane/alpha") == 0);
    /* QUEUED and GATING are derived by replay. Asserting one as a verdict
     * would be a second, disagreeing source of truth for the same fact. */
    d2 = d1;
    d2.state = LAND_STATE_QUEUED;
    LQ_CHECK("a derived state has no verdict encoding",
             land_verdict_encode(&d2, two, sizeof two) == 0);

    /* A sha is one spelling or it is a refusal. */
    uint8_t sha[LAND_SHA_BYTES];
    char hex[LAND_SHA_HEX + 1];
    LQ_CHECK("a full lowercase sha parses", land_sha_parse(k_head_a, sha));
    land_sha_format(sha, hex);
    LQ_CHECK("and formats back identically", strcmp(hex, k_head_a) == 0);
    LQ_CHECK("an uppercase sha is refused",
             !land_sha_parse("ABCDEF0123456789ABCDEF0123456789ABCDEF01", sha));
    LQ_CHECK("a short sha is refused", !land_sha_parse("abcdef01", sha));
    LQ_CHECK("a non-hex sha is refused",
             !land_sha_parse("zzcdef0123456789abcdef0123456789abcdef01", sha));

    return failures;
}

/* ── 8. four submitters racing, which is the real fleet ────────────────
 * Four real processes, not four threads: the lock that makes this safe is a
 * whole-file lock in lib/platform, and a thread test would never touch it.
 * Four because that is how many machines are actually submitting.
 *
 * Each child appends its own submissions to one queue file; afterwards the
 * chain must verify and every submission must be present exactly once, with
 * dense sequence numbers. A gap would mean one writer's frame landed on top
 * of another's — the convoy's worst failure, silent loss rather than delay. */

#define RACE_EACH 12
#define RACE_WRITERS 4

static int race_child_run(const char *path, const char *prefix)
{
    struct zcl_chainlog_report rep;
    for (int i = 0; i < RACE_EACH; i++) {
        /* Open/append/close per submission — exactly what the CLI does, so
         * the two processes really do interleave at the file lock. */
        struct land_queue *q = land_queue_open(path, &rep);
        if (!q)
            return 2;
        char branch[64];
        snprintf(branch, sizeof branch, "%s/%d", prefix, i);
        if (submit_one(q, branch, k_head_a) == 0) {
            land_queue_close(q);
            return 3;
        }
        land_queue_close(q);
    }
    return 0;
}

#if !defined(_WIN32)
static void race_child(const char *path, const char *prefix)
{
    _exit(race_child_run(path, prefix));
}
#endif

static int case_two_submitters_race(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "race");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    /* Create the log first so neither child races the header write. */
    struct zcl_chainlog_report rep;
    struct land_queue *seed = land_queue_open(path, &rep);
    LQ_CHECK("the queue is created before the race", seed != NULL);
    if (!seed) {
        test_cleanup_tmpdir(dir);
        return failures;
    }
    land_queue_close(seed);

    const char *prefixes[RACE_WRITERS] = { "lane/one", "lane/two",
                                           "lane/three", "lane/four" };
#if defined(_WIN32)
    void *kids[RACE_WRITERS] = {0};
    char logs[RACE_WRITERS][704];
    bool forked = setenv("ZCL_LAND_RACE_PATH", path, 1) == 0;
    for (int k = 0; k < RACE_WRITERS; k++) {
        snprintf(logs[k], sizeof logs[k], "%s/worker-%d.log", dir, k);
        if (setenv("ZCL_LAND_RACE_PREFIX", prefixes[k], 1) != 0) {
            forked = false;
            continue;
        }
        kids[k] = test_spawn_self_with_role("test_land_queue", "race-writer",
                                            logs[k]);
        if (!kids[k])
            forked = false;
    }
    (void)unsetenv("ZCL_LAND_RACE_PATH");
    (void)unsetenv("ZCL_LAND_RACE_PREFIX");
#else
    pid_t kids[RACE_WRITERS];
    bool forked = true;
    for (int k = 0; k < RACE_WRITERS; k++) {
        kids[k] = fork();
        if (kids[k] == 0)
            race_child(path, prefixes[k]);
        if (kids[k] < 0)
            forked = false;
    }
#endif
    LQ_CHECK("four submitter processes start at once", forked);

    int bad = 0;
    for (int k = 0; k < RACE_WRITERS; k++) {
#if defined(_WIN32)
        if (!kids[k])
            continue;
        int child_status = test_self_child_wait(kids[k]);
        if (child_status != 0) {
            printf("land_queue: worker %d exited %d", k, child_status);
            FILE *worker_log = fopen(logs[k], "rb");
            if (worker_log) {
                char diagnostic[512];
                size_t got = fread(diagnostic, 1, sizeof(diagnostic) - 1,
                                   worker_log);
                diagnostic[got] = '\0';
                fclose(worker_log);
                printf(": %s", diagnostic);
            }
            printf("\n");
            bad++;
        }
#else
        if (kids[k] <= 0)
            continue;
        int status = 0;
        (void)waitpid(kids[k], &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            bad++;
#endif
    }
    LQ_CHECK("all four submitters finish cleanly", bad == 0);

    uint8_t stream[32];
    land_stream_id(stream);
    struct zcl_chainlog_report vrep;
    LQ_CHECK("the chain verifies after the race",
             zcl_chainlog_verify(path, stream, &vrep) == ZCL_CHAINLOG_OK);

    struct zcl_chainlog_report rrep;
    struct land_queue *q = land_queue_open(path, &rrep);
    LQ_CHECK("the queue replays after the race", q != NULL);
    if (q) {
        LQ_CHECK("with nothing torn", rrep.torn_bytes == 0);
        LQ_CHECK("every submission is present exactly once",
                 land_queue_count(q) == (size_t)(RACE_WRITERS * RACE_EACH));
        int found = 0;
        for (int k = 0; k < RACE_WRITERS; k++) {
            for (int i = 0; i < RACE_EACH; i++) {
                char branch[64];
                snprintf(branch, sizeof branch, "%s/%d", prefixes[k], i);
                if (land_queue_find_branch(q, branch))
                    found++;
            }
        }
        LQ_CHECK("and each is findable by name", found == RACE_WRITERS * RACE_EACH);

        /* Dense, gap-free sequence numbers across both writers. A gap would
         * mean an interleaved append had overwritten someone else's frame. */
        bool dense = true;
        for (size_t i = 0; i < land_queue_count(q); i++)
            if (land_queue_at(q, i)->seq != (uint64_t)(i + 1))
                dense = false;
        LQ_CHECK("sequence numbers are dense across both writers", dense);
        land_queue_close(q);
    }

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 9. submit costs the same whether the queue is empty or deep ───────
 *
 * WHY THIS IS THE RIGHT ASSERTION AND A STOPWATCH IS NOT. The promise is
 * that submitting never waits for a gate run, and the obvious test — submit,
 * time it, assert under N milliseconds — is exactly what
 * tools/lint/check_no_wallclock_assertion.sh forbids, for this project's own
 * reason: a duration bound grades the MACHINE, and this fleet deliberately
 * includes 7200rpm boxes. A submit that takes 900 ms on an honest slow disk
 * is not a bug, and a test that calls it one teaches everybody to ignore red.
 *
 * The load-independent property underneath the promise is what is asserted
 * instead: ONE submit writes exactly ONE frame, does no gate, and its cost
 * does not grow with how much is already queued or being gated. Latency is
 * measured and reported separately (tools/dev/land_bench.sh), where a number
 * is data rather than a verdict. */

static int case_submit_cost_is_flat(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "flat");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    /* A submit into an empty queue: exactly one frame. */
    uint64_t first = submit_one(q, "lane/first", k_head_a);
    LQ_CHECK("the first submission is frame 1", first == 1);

    /* Fill the queue up, and put some of it inside an outstanding gate run
     * so the deep case is the realistic one: a lander is mid-gate and four
     * more agents want to submit. */
    enum { DEEP = 200 };
    bool all_ok = true;
    uint64_t members[64];
    for (int i = 0; i < DEEP; i++) {
        char branch[64];
        snprintf(branch, sizeof branch, "lane/bulk-%d", i);
        uint64_t s = submit_one(q, branch, k_head_b);
        all_ok = all_ok && s == (uint64_t)(i + 2);
        if (i < 64)
            members[i] = s;
    }
    LQ_CHECK("a deep queue fills with dense sequence numbers", all_ok);
    uint64_t gr = gate_over(q, LAND_GATE_GREEN, true, members, 64);
    LQ_CHECK("a gate run over 64 of them is outstanding", gr != 0);

    /* Now the measurement that matters: a submit while all of that is in
     * flight still writes exactly one frame and lands at the very next
     * sequence number. Nothing about it scales with the 200 entries or waits
     * for the outstanding run. */
    size_t entries_before = land_queue_count(q);
    uint64_t deep = submit_one(q, "lane/deep", k_head_a);
    LQ_CHECK("a submit into a deep queue with a gate run outstanding "
             "succeeds", deep != 0);
    LQ_CHECK("and adds exactly one entry",
             land_queue_count(q) == entries_before + 1);
    LQ_CHECK("and exactly one frame — no fan-out with queue depth",
             deep == (uint64_t)(DEEP + 2 /* submissions */ + 1 /* gate run */));
    LQ_CHECK("and it is QUEUED, not blocked behind the running gate",
             state_of(q, deep) == LAND_STATE_QUEUED);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 10. status says what it is waiting on ────────────────────────────
 * "PENDING" makes the asker think. Every live state has to name the one
 * thing that will end the wait. */

static int case_status_says_what_it_waits_on(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "waiting");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t a = submit_one(q, "lane/a", k_head_a);
    uint64_t b = submit_one(q, "lane/b", k_head_b);
    uint64_t c = submit_one(q, "lane/c", k_head_a);

    LQ_CHECK("the head of the queue has nothing ahead of it",
             land_queue_find_seq(q, a)->ahead == 0);
    LQ_CHECK("and the ones behind it say how many",
             land_queue_find_seq(q, b)->ahead == 1 &&
                 land_queue_find_seq(q, c)->ahead == 2);

    uint64_t two[] = { a, b };
    uint64_t gr = gate_over(q, LAND_GATE_GREEN, true, two, 2);
    LQ_CHECK("a submission inside a batch names the run it is in",
             land_queue_find_seq(q, a)->gate_run_seq == gr &&
                 land_queue_find_seq(q, a)->state == LAND_STATE_GATING);
    LQ_CHECK("and how many submissions that run is proving at once",
             land_queue_find_seq(q, a)->batch_size == 2 &&
                 land_queue_find_seq(q, b)->batch_size == 2);
    LQ_CHECK("the one still queued moved up as the others left the queue",
             land_queue_find_seq(q, c)->ahead == 0 &&
                 land_queue_find_seq(q, c)->state == LAND_STATE_QUEUED);

    (void)settle(q, a, LAND_STATE_LANDED, gr);
    LQ_CHECK("a settled submission is waiting on nothing",
             land_queue_find_seq(q, a)->ahead == 0 &&
                 land_queue_find_seq(q, a)->state == LAND_STATE_LANDED);

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 11. a verdict is checkable by whoever receives it ─────────────────
 *
 * The digest is what stops the queue being a coordinator everyone has to
 * trust: it is computed from four public facts, so a second machine
 * recomputes it without the queue, without the network, and without taking
 * this machine's word for anything. */

static int case_verdict_digest(void)
{
    int failures = 0;
    uint8_t head[LAND_SHA_BYTES], integ[LAND_SHA_BYTES];
    uint8_t gate_id[LAND_GATE_ID_BYTES], other_id[LAND_GATE_ID_BYTES];
    (void)land_sha_parse(k_head_a, head);
    (void)land_sha_parse(k_integ, integ);
    (void)land_id32_parse(k_gate_id, gate_id);
    memset(other_id, 0x7E, sizeof other_id);

    uint8_t d1[LAND_DIGEST_BYTES], d2[LAND_DIGEST_BYTES];
    land_verdict_digest(head, integ, gate_id, LAND_STATE_LANDED, true, d1);
    land_verdict_digest(head, integ, gate_id, LAND_STATE_LANDED, true, d2);
    LQ_CHECK("the same four facts give the same digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) == 0);

    /* Every input is load-bearing. A field that did not change the digest
     * would be a field an attacker could change without the receiver
     * noticing. */
    uint8_t other_head[LAND_SHA_BYTES];
    (void)land_sha_parse(k_head_b, other_head);
    land_verdict_digest(other_head, integ, gate_id, LAND_STATE_LANDED, true, d2);
    LQ_CHECK("a different submitted commit gives a different digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) != 0);

    uint8_t other_integ[LAND_SHA_BYTES];
    memset(other_integ, 0x11, sizeof other_integ);
    land_verdict_digest(head, other_integ, gate_id, LAND_STATE_LANDED, true, d2);
    LQ_CHECK("a different integration commit gives a different digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) != 0);

    land_verdict_digest(head, integ, other_id, LAND_STATE_LANDED, true, d2);
    LQ_CHECK("a different gating tree gives a different digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) != 0);

    land_verdict_digest(head, integ, gate_id, LAND_STATE_REFUSED, true, d2);
    LQ_CHECK("a different verdict gives a different digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) != 0);

    land_verdict_digest(head, integ, gate_id, LAND_STATE_LANDED, false, d2);
    LQ_CHECK("a run that skipped its groups gives a different digest",
             memcmp(d1, d2, LAND_DIGEST_BYTES) != 0);

    /* The digest a queue publishes must be the one an outsider recomputes.
     * If these two ever disagreed, the published receipt would be
     * uncheckable and the whole decentralised half would be decoration. */
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "digest");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);
    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(path, &rep);
    if (!q) {
        LQ_CHECK("the queue opens", false);
        test_cleanup_tmpdir(dir);
        return failures;
    }
    uint64_t a = submit_one(q, "lane/checkable", k_head_a);
    uint64_t only_a[] = { a };
    uint64_t gr = gate_over(q, LAND_GATE_GREEN, true, only_a, 1);
    LQ_CHECK("the submission lands", settle(q, a, LAND_STATE_LANDED, gr) ==
                                         LAND_OK);
    const struct land_entry *e = land_queue_find_seq(q, a);
    LQ_CHECK("a settled submission publishes a digest", e && e->has_digest);
    if (e) {
        LQ_CHECK("and carries the gating tree's identity beside it",
                 memcmp(e->gate_id, gate_id, LAND_GATE_ID_BYTES) == 0 &&
                     e->gate_stress);
        /* Recompute it the way a stranger would: from the four facts only. */
        uint8_t outside[LAND_DIGEST_BYTES];
        land_verdict_digest(e->submit.head, e->verdict.integration,
                            e->gate_id, e->state, e->gate_stress, outside);
        LQ_CHECK("and a receiver recomputes exactly it from the public facts",
                 memcmp(outside, e->digest, LAND_DIGEST_BYTES) == 0);
        /* And a receiver that is told the wrong tree does NOT reproduce it,
         * which is the half that makes the check worth running. */
        land_verdict_digest(e->submit.head, e->verdict.integration, other_id,
                            e->state, e->gate_stress, outside);
        LQ_CHECK("a verdict cannot be replayed onto another tree",
                 memcmp(outside, e->digest, LAND_DIGEST_BYTES) != 0);
    }

    /* A verdict nothing gated still gets a digest — over an all-zero gate
     * identity, so it can never be confused with a gated one. */
    uint64_t b = submit_one(q, "lane/ungated", k_head_b);
    LQ_CHECK("an ungated refusal records", settle(q, b, LAND_STATE_REFUSED, 0) ==
                                               LAND_OK);
    const struct land_entry *eb = land_queue_find_seq(q, b);
    if (eb) {
        uint8_t zero_id[LAND_GATE_ID_BYTES];
        memset(zero_id, 0, sizeof zero_id);
        uint8_t expect[LAND_DIGEST_BYTES];
        land_verdict_digest(eb->submit.head, eb->verdict.integration, zero_id,
                            LAND_STATE_REFUSED, false, expect);
        LQ_CHECK("and its digest names 'nothing gated this'",
                 eb->has_digest &&
                     memcmp(eb->digest, expect, LAND_DIGEST_BYTES) == 0);
    }

    land_queue_close(q);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 12. an unreachable queue refuses; it never looks empty ────────────
 *
 * The failure mode when the queue cannot be reached must be that the agent
 * falls back to gating locally — degraded, never blocked, and never told
 * "there is nothing queued" when the truth is "I could not look". */

static int case_unreachable_queue(void)
{
    int failures = 0;
    struct zcl_chainlog_report rep;
    memset(&rep, 0, sizeof rep);

    /* A path whose parent does not exist. Opening it must fail loudly. */
    struct land_queue *q =
        land_queue_open("/nonexistent-directory-for-land/queue.chainlog", &rep);
    LQ_CHECK("an unreachable queue refuses to open", q == NULL);
    LQ_CHECK("and says why, rather than reporting an empty queue",
             rep.status != ZCL_CHAINLOG_OK);
    if (q)
        land_queue_close(q);

    /* And the refusal is distinguishable from a real, empty queue — the two
     * must never be the same answer. */
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "land", "empty");
    char path[640];
    snprintf(path, sizeof path, "%s/queue.chainlog", dir);
    struct zcl_chainlog_report erep;
    struct land_queue *empty = land_queue_open(path, &erep);
    LQ_CHECK("a real but empty queue opens", empty != NULL);
    LQ_CHECK("with an OK status and no entries",
             empty && erep.status == ZCL_CHAINLOG_OK &&
                 land_queue_count(empty) == 0);
    if (empty)
        land_queue_close(empty);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 13. surface: refusals are named, and nothing crashes on NULL ─────── */

static int case_surface(void)
{
    int failures = 0;

    LQ_CHECK("every status has a label",
             strcmp(land_status_label(LAND_OK), "ok") == 0 &&
                 strcmp(land_status_label(LAND_ERR_NO_GATE_RUN),
                        "no-gate-run") == 0 &&
                 strcmp(land_status_label(LAND_ERR_GATE_NOT_STRESSED),
                        "gate-skipped-groups") == 0);
    LQ_CHECK("every state has a label",
             strcmp(land_state_label(LAND_STATE_QUEUED), "QUEUED") == 0 &&
                 strcmp(land_state_label(LAND_STATE_LANDED), "LANDED") == 0 &&
                 strcmp(land_state_label(LAND_STATE_REFUSED), "REFUSED") == 0);

    enum land_state st;
    LQ_CHECK("a state parses from its command-line spelling",
             land_state_parse("landed", &st) && st == LAND_STATE_LANDED);
    LQ_CHECK("and an unknown spelling is refused",
             !land_state_parse("probably-fine", &st));
    enum land_gate_outcome out;
    LQ_CHECK("an outcome parses",
             land_gate_outcome_parse("red", &out) && out == LAND_GATE_RED);
    LQ_CHECK("and an unknown outcome is refused",
             !land_gate_outcome_parse("amber", &out));

    LQ_CHECK("a NULL queue answers rather than crashes",
             land_queue_count(NULL) == 0 && land_queue_at(NULL, 0) == NULL &&
                 land_queue_find_branch(NULL, "x") == NULL &&
                 land_queue_submit(NULL, NULL, NULL) == LAND_ERR_ARGUMENT);
    LQ_CHECK("and a NULL queue cannot be talked into a landing",
             land_queue_check_landable(NULL, 1, 1) == LAND_ERR_ARGUMENT);

    /* The stream id is a fixed derivation, not a nonce: two calls must agree
     * or two boxes could not read each other's queue. */
    uint8_t s1[32], s2[32];
    land_stream_id(s1);
    land_stream_id(s2);
    LQ_CHECK("the stream id is stable", memcmp(s1, s2, 32) == 0);

    return failures;
}

int test_land_queue(void);
int test_land_queue(void)
{
#if defined(_WIN32)
    const char *role = getenv("ZCL_TEST_FORK_ROLE");
    if (role && strcmp(role, "race-writer") == 0) {
        const char *path = getenv("ZCL_LAND_RACE_PATH");
        const char *prefix = getenv("ZCL_LAND_RACE_PREFIX");
        if (!path || !path[0] || !prefix || !prefix[0])
            return 2;
        return race_child_run(path, prefix);
    }
#endif
    int failures = 0;
    failures += case_submit_and_pending();
    failures += case_landing_needs_a_real_gate();
    failures += case_bisect();
    failures += case_timeout();
    failures += case_restart();
    failures += case_chain_verifies();
    failures += case_canonical_bytes();
    failures += case_two_submitters_race();
    failures += case_submit_cost_is_flat();
    failures += case_status_says_what_it_waits_on();
    failures += case_verdict_digest();
    failures += case_unreachable_queue();
    failures += case_surface();
    printf("land_queue: %d failure(s)\n", failures);
    return failures;
}
