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

int test_sync_shadow(void)
{
    int failures = 0;
    failures += test_shadow_agrees();
    failures += test_shadow_containment_allowlisted();
    failures += test_shadow_chunk_hardfail_allowlisted();
    failures += test_shadow_genuine_mismatch_is_loud();
    failures += test_shadow_proof_failure_agrees();
    failures += test_shadow_dump_json();
    return failures;
}
