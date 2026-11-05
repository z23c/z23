/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Full-lifecycle SHADOW observer (net/sync_shadow.h). Proves the machinery is
 * sound BEFORE it is trusted to shadow every lifecycle event: the pure
 * comparator agrees when the kernel and reference land on the same phase,
 * classifies the two known structural gaps as allowlisted (not faults), and
 * flags a genuine phase contradiction as a LOUD mismatch that increments the
 * dumpstate-visible counter. The reference FSM stays authoritative throughout —
 * this only observes. */

#include "test/test_core.h"
#include "net/sync_shadow.h"
#include "json/json.h"
#include <string.h>

/* Agreement: a chunk applied in RECEIVING leaves both sides in RECEIVING. */
static int test_shadow_agrees(void)
{
    int failures = 0;
    TEST("sync_shadow: matching phase change is an agreement, not a mismatch") {
        sync_shadow_reset();
        struct sync_shadow_obs o = sync_shadow_compare(
            SYNC_SHADOW_CHUNK_ACCEPTED, /*session=*/7,
            SNAPSYNC_RECEIVING, SNAPSYNC_RECEIVING,
            SYNC_EVENT_CHUNK_RECEIVED, false);
        ASSERT(o.agrees);
        ASSERT(o.expected_disagreement == NULL);
        sync_shadow_record(&o);
        ASSERT(sync_shadow_total_mismatches() == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Allowlisted gap #1: activation containment — kernel stages, reference FAILED. */
static int test_shadow_containment_allowlisted(void)
{
    int failures = 0;
    TEST("sync_shadow: activation-contained divergence is allowlisted (no LOUD)") {
        sync_shadow_reset();
        struct sync_shadow_obs o = sync_shadow_compare(
            SYNC_SHADOW_CONTAINMENT, /*session=*/9,
            SNAPSYNC_VERIFYING, SNAPSYNC_FAILED,
            SYNC_EVENT_PROOF_VERIFIED, /*proof_ok=*/true);
        ASSERT(!o.agrees);
        ASSERT(o.kernel_after == SYNC_PHASE_STAGED);
        ASSERT(o.ref_after == SYNC_PHASE_FAILED);
        ASSERT(o.expected_disagreement != NULL);
        sync_shadow_record(&o);
        ASSERT(sync_shadow_total_mismatches() == 0); /* allowlisted, not counted */
        PASS();
    } _test_next:;
    return failures;
}

/* Allowlisted gap #2: bad chunk — kernel penalizes+holds, reference hard-fails. */
static int test_shadow_chunk_hardfail_allowlisted(void)
{
    int failures = 0;
    TEST("sync_shadow: reference chunk write-path hard-fail is allowlisted") {
        sync_shadow_reset();
        struct sync_shadow_obs o = sync_shadow_compare(
            SYNC_SHADOW_CHUNK_REJECTED, /*session=*/3,
            SNAPSYNC_RECEIVING, SNAPSYNC_FAILED,
            SYNC_EVENT_CHUNK_REJECTED, false);
        ASSERT(!o.agrees);
        ASSERT(o.expected_disagreement != NULL);
        sync_shadow_record(&o);
        ASSERT(sync_shadow_total_mismatches() == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* A genuine, unexplained phase contradiction is a LOUD counted mismatch. */
static int test_shadow_genuine_mismatch_is_loud(void)
{
    int failures = 0;
    TEST("sync_shadow: an unexplained phase contradiction increments the counter") {
        sync_shadow_reset();
        /* Reference claims it moved to RECEIVING on a plain proof-failure — a
         * contradiction the kernel (VERIFYING+PROOF_FAILED → FAILED) cannot
         * explain and no allowlist covers. */
        struct sync_shadow_obs o = sync_shadow_compare(
            SYNC_SHADOW_PROOF_FAILURE, /*session=*/5,
            SNAPSYNC_VERIFYING, SNAPSYNC_RECEIVING,
            SYNC_EVENT_PROOF_FAILED, false);
        ASSERT(!o.agrees);
        ASSERT(o.expected_disagreement == NULL);
        sync_shadow_record(&o);
        ASSERT(sync_shadow_total_mismatches() == 1);
        PASS();
    } _test_next:;
    return failures;
}

/* Proof-failure with a well-behaved reference agrees (both → FAILED). */
static int test_shadow_proof_failure_agrees(void)
{
    int failures = 0;
    TEST("sync_shadow: proof failure lands both sides in FAILED") {
        sync_shadow_reset();
        sync_shadow_observe(SYNC_SHADOW_PROOF_FAILURE, /*session=*/2,
            SNAPSYNC_VERIFYING, SNAPSYNC_FAILED,
            SYNC_EVENT_PROOF_FAILED, false);
        ASSERT(sync_shadow_total_mismatches() == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* The dumper emits a well-formed object with the observability contract. */
static int test_shadow_dump_json(void)
{
    int failures = 0;
    TEST("sync_shadow: dumper is well-formed and reports authoritative:false") {
        sync_shadow_reset();
        sync_shadow_observe(SYNC_SHADOW_CHUNK_ACCEPTED, 1,
            SNAPSYNC_RECEIVING, SNAPSYNC_RECEIVING,
            SYNC_EVENT_CHUNK_RECEIVED, false);

        struct json_value out;
        json_init(&out);
        ASSERT(sync_shadow_dump_state_json(&out, NULL));
        const struct json_value *auth = json_get(&out, "authoritative");
        ASSERT(auth != NULL);
        ASSERT(json_get_bool(auth) == false);
        const struct json_value *tm = json_get(&out, "total_mismatches");
        ASSERT(tm != NULL && json_get_int(tm) == 0);
        const struct json_value *pts = json_get(&out, "points");
        ASSERT(pts != NULL);
        ASSERT(json_get(pts, "chunk_accepted") != NULL);
        json_free(&out);
        sync_shadow_reset();
        PASS();
    } _test_next:;
    return failures;
}


/* ── Mutation-gap tests: names, counters, ring, reset, allowlist edges ─── */

static bool ss_dump(struct json_value *out)
{
    json_init(out);
    return sync_shadow_dump_state_json(out, NULL);
}

/* A hand-built observation: kind 0 agrees, 1 is allowlisted, 2 is a genuine
 * mismatch (kernel FAILED, reference RECEIVING). */
static struct sync_shadow_obs ss_obs(enum sync_shadow_point p, uint64_t sess, int kind)
{
    struct sync_shadow_obs o;
    memset(&o, 0, sizeof(o));
    o.point = p;
    o.session_id = sess;
    o.kernel_before = SYNC_PHASE_VERIFYING;
    o.ref_before = SYNC_PHASE_VERIFYING;
    o.ref_after = SYNC_PHASE_RECEIVING;
    o.kernel_after = kind == 0 ? SYNC_PHASE_RECEIVING : SYNC_PHASE_FAILED;
    o.agrees = (kind == 0);
    o.expected_disagreement = kind == 1 ? "test_gap" : NULL;
    return o;
}

static void ss_rec(enum sync_shadow_point p, uint64_t sess, int kind, int times)
{
    struct sync_shadow_obs o = ss_obs(p, sess, kind);
    for (int i = 0; i < times; i++)
        sync_shadow_record(&o);
}

/* Counter of `field` in the dumped row for `point`, or -1 when absent. */
static int64_t ss_row(const struct json_value *out, const char *point, const char *field)
{
    const struct json_value *row = json_get(json_get(out, "points"), point);
    const struct json_value *v = row ? json_get(row, field) : NULL;
    return v ? json_get_int(v) : -1;
}

static int64_t ss_ring_session(const struct json_value *out, size_t slot)
{
    const struct json_value *ring = json_get(out, "recent_mismatches");
    return json_get_int(json_get(json_at(ring, slot), "session_id"));
}

static int test_shadow_point_names(void)
{
    int failures = 0;
    TEST("sync_shadow: every point has its stable name and the sentinel is '?'") {
        static const char *const want[SYNC_SHADOW_POINT_COUNT] = {
            "offer", "receive_begin", "chunk_accepted", "chunk_rejected",
            "receive_complete", "proof_success", "proof_failure", "peer_loss",
            "timeout", "stop_reset", "containment"};
        for (int i = 0; i < SYNC_SHADOW_POINT_COUNT; i++) {
            const char *got = sync_shadow_point_name((enum sync_shadow_point)i);
            ASSERT(got != NULL && strcmp(got, want[i]) == 0);
        }
        ASSERT(strcmp(sync_shadow_point_name(SYNC_SHADOW_POINT_COUNT), "?") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_shadow_counters_exact(void)
{
    int failures = 0;
    TEST("sync_shadow: per-point counters count each outcome exactly once") {
        sync_shadow_reset();
        ss_rec(SYNC_SHADOW_OFFER, 1, 0, 1);
        ss_rec(SYNC_SHADOW_OFFER, 1, 1, 2);
        ss_rec(SYNC_SHADOW_OFFER, 1, 2, 3);
        /* one past the last point must be ignored, not counted */
        ss_rec(SYNC_SHADOW_POINT_COUNT, 1, 2, 1);
        struct json_value out;
        ASSERT(ss_dump(&out));
        ASSERT(ss_row(&out, "offer", "observed") == 6);
        ASSERT(ss_row(&out, "offer", "agree") == 1);
        ASSERT(ss_row(&out, "offer", "allowlisted") == 2);
        ASSERT(ss_row(&out, "offer", "mismatch") == 3);
        ASSERT(json_get_int(json_get(&out, "total_mismatches")) == 3);
        ASSERT(sync_shadow_total_mismatches() == 3);
        ASSERT(json_size(json_get(&out, "points")) == 1);
        ASSERT(json_get(json_get(&out, "points"), "?") == NULL);
        json_free(&out);
        sync_shadow_reset();
        PASS();
    } _test_next:;
    return failures;
}

static int test_shadow_ring_wraps(void)
{
    int failures = 0;
    TEST("sync_shadow: the mismatch ring keeps the newest eight in slot order") {
        sync_shadow_reset();
        for (uint64_t s = 1; s <= 10; s++)
            ss_rec(SYNC_SHADOW_PROOF_FAILURE, s, 2, 1);
        struct json_value out;
        ASSERT(ss_dump(&out));
        const struct json_value *ring = json_get(&out, "recent_mismatches");
        ASSERT(ring != NULL && ring->type == JSON_ARR && json_size(ring) == 8);
        static const int64_t order[8] = {9, 10, 3, 4, 5, 6, 7, 8};
        for (size_t k = 0; k < 8; k++)
            ASSERT(ss_ring_session(&out, k) == order[k]);
        const struct json_value *e = json_at(ring, 0);
        ASSERT(e->type == JSON_OBJ);
        ASSERT(strcmp(json_get_str(json_get(e, "point")), "proof_failure") == 0);
        ASSERT(strcmp(json_get_str(json_get(e, "kernel_after")),
                      sync_phase_name(SYNC_PHASE_FAILED)) == 0);
        ASSERT(strcmp(json_get_str(json_get(e, "ref_after")),
                      sync_phase_name(SYNC_PHASE_RECEIVING)) == 0);
        ASSERT(ss_row(&out, "proof_failure", "mismatch") == 10);
        json_free(&out);
        sync_shadow_reset();
        PASS();
    } _test_next:;
    return failures;
}

static void ss_fill_every_point(void)
{
    for (int p = 0; p < SYNC_SHADOW_POINT_COUNT; p++)
        for (int kind = 0; kind < 3; kind++)
            ss_rec((enum sync_shadow_point)p, 100 + (uint64_t)p, kind, 1);
}

static int test_shadow_reset_clears_all(void)
{
    int failures = 0;
    TEST("sync_shadow: reset zeroes every counter, the ring and the write head") {
        sync_shadow_reset();
        ss_fill_every_point();
        sync_shadow_reset();
        struct json_value out;
        ASSERT(ss_dump(&out));
        ASSERT(json_size(json_get(&out, "points")) == 0);
        ASSERT(json_get(&out, "points")->type == JSON_OBJ);
        ASSERT(json_get(&out, "recent_mismatches")->type == JSON_ARR);
        ASSERT(json_size(json_get(&out, "recent_mismatches")) == 0);
        ASSERT(json_get_int(json_get(&out, "total_mismatches")) == 0);
        json_free(&out);
        /* fresh counts after reset: one agreeing observation per point */
        for (int p = 0; p < SYNC_SHADOW_POINT_COUNT; p++)
            ss_rec((enum sync_shadow_point)p, 7, 0, 1);
        ASSERT(ss_dump(&out));
        for (int p = 0; p < SYNC_SHADOW_POINT_COUNT; p++) {
            const char *n = sync_shadow_point_name((enum sync_shadow_point)p);
            ASSERT(ss_row(&out, n, "observed") == 1);
            ASSERT(ss_row(&out, n, "agree") == 1);
            ASSERT(ss_row(&out, n, "allowlisted") == 0);
            ASSERT(ss_row(&out, n, "mismatch") == 0);
        }
        json_free(&out);
        sync_shadow_reset();
        PASS();
    } _test_next:;
    return failures;
}

static int test_shadow_reset_rewinds_ring_head(void)
{
    int failures = 0;
    TEST("sync_shadow: after reset the ring fills from slot zero again") {
        sync_shadow_reset();
        ss_fill_every_point();
        sync_shadow_reset();
        for (uint64_t s = 1; s <= 9; s++)
            ss_rec(SYNC_SHADOW_TIMEOUT, s, 2, 1);
        struct json_value out;
        ASSERT(ss_dump(&out));
        static const int64_t order[8] = {9, 2, 3, 4, 5, 6, 7, 8};
        ASSERT(json_size(json_get(&out, "recent_mismatches")) == 8);
        for (size_t k = 0; k < 8; k++)
            ASSERT(ss_ring_session(&out, k) == order[k]);
        json_free(&out);
        sync_shadow_reset();
        PASS();
    } _test_next:;
    return failures;
}

static int test_shadow_allowlist_is_a_conjunction(void)
{
    int failures = 0;
    TEST("sync_shadow: a gap is allowlisted only when BOTH phases match its rule") {
        /* kernel reaches STAGED but the reference is not FAILED */
        struct sync_shadow_obs a = sync_shadow_compare(
            SYNC_SHADOW_CONTAINMENT, 4, SNAPSYNC_VERIFYING, SNAPSYNC_RECEIVING,
            SYNC_EVENT_PROOF_VERIFIED, true);
        ASSERT(a.kernel_after == SYNC_PHASE_STAGED);
        ASSERT(!a.agrees && a.expected_disagreement == NULL);
        /* reference FAILED but the kernel is not at STAGED, not a rejected chunk */
        struct sync_shadow_obs b = sync_shadow_compare(
            SYNC_SHADOW_CHUNK_ACCEPTED, 4, SNAPSYNC_RECEIVING, SNAPSYNC_FAILED,
            SYNC_EVENT_CHUNK_RECEIVED, false);
        ASSERT(b.kernel_after == SYNC_PHASE_RECEIVING);
        ASSERT(!b.agrees && b.expected_disagreement == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_shadow_compare_fields_and_clean_inputs(void)
{
    int failures = 0;
    TEST("sync_shadow: compare reports mapped phases and feeds the kernel clean inputs") {
        /* A completed (STAGED) session asked to take a chunk hits the contained
         * activation door; stale non-zero state would make the chunk inert. */
        struct sync_shadow_obs o = sync_shadow_compare(
            SYNC_SHADOW_CHUNK_ACCEPTED, 42, SNAPSYNC_COMPLETE, SNAPSYNC_COMPLETE,
            SYNC_EVENT_CHUNK_RECEIVED, false);
        ASSERT(o.point == SYNC_SHADOW_CHUNK_ACCEPTED && o.session_id == 42);
        ASSERT(o.kernel_before == SYNC_PHASE_STAGED);
        ASSERT(o.ref_before == SYNC_PHASE_STAGED && o.ref_after == SYNC_PHASE_STAGED);
        ASSERT(o.kernel_after == SYNC_PHASE_ACTIVATION_CONTAINED);
        /* A manifest event with a zeroed verdict is an ACCEPT. */
        struct sync_shadow_obs m = sync_shadow_compare(
            SYNC_SHADOW_RECEIVE_BEGIN, 43, SNAPSYNC_IDLE, SNAPSYNC_NEGOTIATING,
            SYNC_EVENT_MANIFEST_VALIDATED, false);
        ASSERT(m.kernel_before == SYNC_PHASE_IDLE);
        ASSERT(m.kernel_after == SYNC_PHASE_NEGOTIATING);
        ASSERT(m.agrees && m.expected_disagreement == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_shadow_dump_null_and_empty(void)
{
    int failures = 0;
    TEST("sync_shadow: dumper refuses a null output and emits empty containers") {
        ASSERT(!sync_shadow_dump_state_json(NULL, NULL));
        sync_shadow_reset();
        struct json_value out;
        ASSERT(ss_dump(&out));
        ASSERT(out.type == JSON_OBJ);
        ASSERT(json_get(&out, "recent_mismatches")->type == JSON_ARR);
        ASSERT(json_size(json_get(&out, "recent_mismatches")) == 0);
        json_free(&out);
        PASS();
    } _test_next:;
    return failures;
}

int test_sync_shadow(void)
{
    int failures = 0;
    failures += test_shadow_agrees();
    failures += test_shadow_containment_allowlisted();
    failures += test_shadow_chunk_hardfail_allowlisted();
    failures += test_shadow_genuine_mismatch_is_loud();
    failures += test_shadow_proof_failure_agrees();
    failures += test_shadow_dump_json();
    failures += test_shadow_point_names();
    failures += test_shadow_counters_exact();
    failures += test_shadow_ring_wraps();
    failures += test_shadow_reset_clears_all();
    failures += test_shadow_reset_rewinds_ring_head();
    failures += test_shadow_allowlist_is_a_conjunction();
    failures += test_shadow_compare_fields_and_clean_inputs();
    failures += test_shadow_dump_null_and_empty();
    return failures;
}
