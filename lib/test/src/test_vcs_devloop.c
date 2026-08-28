/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_vcs_devloop — the dev-loop <-> ZVCS auto-anchor glue
 * (lib/vcs/src/vcs_devloop.c), the function tools/dev/devloop_cycle.c:
 * finish_cycle() calls on every "passed" verdict.
 *
 * Coverage:
 *   1. hex32_decode: valid decode + NULL/short-length/non-hex rejection.
 *   2. a finish_cycle-shaped anchor call (verdict struct + generation hex +
 *      repo root) lands a commit whose verdict fields and generation
 *      binding round-trip exactly, including the "generation unknown"
 *      (e.g. a docs-only "check" cycle) all-zero case.
 *   3. fail-open: a repo whose .zvcs/ cannot be created (a regular file
 *      occupies that path) returns VCS_DEVLOOP_ANCHOR_ERROR with a message,
 *      never crashes.
 *   4. sealed-path refusal: editing a sealed file surfaces
 *      VCS_DEVLOOP_ANCHOR_REFUSED without crashing, and does not advance
 *      HEAD (nothing commits for that cycle).
 *
 * All work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"

#include "command/native_command.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "devloop.h"
#include "json/json.h"
#include "models/database.h"
#include "services/zcode_lane_service.h"
#include "vcs/vcs.h"
#include "vcs/vcs_devloop.h"
#include "vcs/vcs_index.h"
#include "vcs/vcs_object.h"
#include "vcs/package_deps.h"
#include "vcs/package_mapping.h"
#include "vcs/package_recipe.h"
#include "vcs/source_bundle.h"
#include "vcs/zcode_accepted_work.h"
#include "vcs/zcode_accepted_work_bundle.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_lane.h"
#include "vcs/zcode_task_authority.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define VD_CHECK(name, expr) do {                                       \
    if (expr) { printf("  vcs_devloop: %s... OK\n", (name)); }          \
    else { printf("  vcs_devloop: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* Write content to <dir>/<rel>, creating parent dirs. */
static bool vd_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + strlen(dir) + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            /* 0700: the object store verifies its own directories are
             * owner-only, so a fixture that pre-creates .zvcs at the
             * ordinary 0755 makes vcs_open refuse the repo outright. */
            mkdir(full, 0700);
            *p = '/';
        }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    size_t n = content ? strlen(content) : 0;
    if (n) fwrite(content, 1, n, f);
    fclose(f);
    return true;
}

/* Deterministic 64-hex-char string derived from `seed` (avoids hand-counted
 * hex literals). */
static void make_hex64(char out[65], uint8_t seed)
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", (uint8_t)(seed + i));
    out[64] = 0;
}

static void vd_root(uint8_t out[32], uint8_t seed)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(seed + i);
}

struct vd_accepted_fixture {
    struct vcs_zcode_accepted_work_v1 accepted;
    uint8_t signer_secret[32];
    uint8_t signer_pubkey[32];
};

static bool vd_put_object(const char *dir, const uint8_t root[32],
                          const uint8_t *wire, size_t len)
{
    return vcs_object_put_addressed(dir, root, wire, len);
}

static bool vd_put_work_receipt(
    const char *dir, const struct vcs_zcode_task_v1 *task,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    const uint8_t policy_root[32], uint8_t kind, uint8_t seed_byte,
    int64_t now, uint8_t root_out[32])
{
    struct vcs_zcode_work_receipt_v1 receipt = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .work_kind = kind,
        .status = VCS_ZCODE_WORK_PASS,
        .started_unix = now - 20,
        .finished_unix = now - 10,
    };
    memcpy(receipt.task_root, task_root, 32);
    memcpy(receipt.candidate_root, candidate_root, 32);
    memcpy(receipt.proof_policy_root, policy_root, 32);
    memcpy(receipt.toolchain_capsule_root,
           task->toolchain_capsule_root, 32);
    vd_root(receipt.action_root, (uint8_t)(seed_byte + 1));
    vd_root(receipt.input_root, (uint8_t)(seed_byte + 2));
    vd_root(receipt.output_root, 0xa0);
    vd_root(receipt.lease_id, (uint8_t)(seed_byte + 3));
    vd_root(receipt.evidence_root, (uint8_t)(seed_byte + 4));
    vd_root(receipt.confinement_root, (uint8_t)(seed_byte + 5));
    uint8_t seed[32], secret[32], pubkey[32];
    vd_root(seed, seed_byte);
    ed25519_keypair(pubkey, secret, seed);
    uint8_t wire[VCS_ZCODE_WORK_RECEIPT_WIRE_BYTES];
    bool ok = vcs_zcode_work_receipt_seal(
            &receipt, secret, pubkey) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_serialize(&receipt, wire) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_id(&receipt, root_out) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_work_receipt_validate_for_candidate(
            task, candidate, &receipt, now) == VCS_ZCODE_DEV_OK &&
        vd_put_object(dir, root_out, wire, sizeof(wire));
    memset(secret, 0, sizeof(secret));
    return ok;
}

static bool vd_put_lane(
    const char *dir, struct vcs_zcode_lane_receipt_v1 *lane,
    const uint8_t secret[32], const uint8_t pubkey[32], uint8_t root[32])
{
    uint8_t wire[VCS_ZCODE_LANE_WIRE_BYTES];
    memset(lane->signature, 0, sizeof(lane->signature));
    return vcs_zcode_lane_receipt_seal(lane, secret, pubkey) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_serialize(lane, wire) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_lane_receipt_id(lane, root) == VCS_ZCODE_DEV_OK &&
        vd_put_object(dir, root, wire, sizeof(wire));
}

static bool vd_accepted_fixture_create(
    const char *dir, const uint8_t source_root[32], int64_t now,
    uint8_t signer_seed, struct vd_accepted_fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    struct vcs_zcode_proof_policy_v1 *policy = &fixture->accepted.policy;
    *policy = (struct vcs_zcode_proof_policy_v1) {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .required_proofs = VCS_ZCODE_PROOF_COMPILE | VCS_ZCODE_PROOF_TEST,
        .minimum_compile_receipts = 1,
        .minimum_test_receipts = 1,
        .minimum_matching_receipts = 1,
        .maximum_proof_age_seconds = 3600,
    };
    uint8_t policy_wire[VCS_ZCODE_PROOF_POLICY_WIRE_BYTES];
    if (vcs_zcode_proof_policy_serialize(policy, policy_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_policy_root(
            policy, fixture->accepted.proof_policy_root) !=
            VCS_ZCODE_DEV_OK ||
        !vd_put_object(dir, fixture->accepted.proof_policy_root,
                       policy_wire, sizeof(policy_wire)))
        return false;
    struct vcs_zcode_task_v1 *task = &fixture->accepted.task;
    task->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(task->source_root, source_root, 32);
    struct vcs_package_lock lock;
    vcs_package_lock_init(&lock);
    lock.count = 1;
    memcpy(lock.nodes[0].root, source_root, 32);
    (void)snprintf(lock.nodes[0].name, sizeof(lock.nodes[0].name),
                   "test/source");
    (void)snprintf(lock.nodes[0].semver, sizeof(lock.nodes[0].semver),
                   "1.0.0");
    uint8_t *lock_wire = NULL;
    size_t lock_wire_len = 0;
    struct vcs_package_recipe recipe;
    vcs_package_recipe_init(&recipe);
    enum vcs_package_recipe_error recipe_error = VCS_PACKAGE_RECIPE_OK;
    bool task_authority =
        vcs_package_lock_serialize(&lock, &lock_wire, &lock_wire_len) ==
            VCS_PACKAGE_DEPS_OK &&
        vcs_package_recipe_add_source(
            &recipe, "src/main.c", &recipe_error);
    vcs_package_recipe_set_test_limits(
        &recipe, 0, 60, UINT64_C(64) * 1024u * 1024u);
    uint8_t *recipe_wire = NULL;
    size_t recipe_wire_len = 0;
    task_authority = task_authority &&
        vcs_package_recipe_serialize(
            &recipe, &recipe_wire, &recipe_wire_len) ==
            VCS_PACKAGE_RECIPE_OK &&
        vcs_zcode_task_authority_store(
            dir, lock_wire, lock_wire_len, recipe_wire, recipe_wire_len,
            task->dependency_lock_root, task->acceptance_tests_root) ==
            VCS_ZCODE_TASK_AUTHORITY_OK;
    free(recipe_wire);
    vcs_package_recipe_free(&recipe);
    free(lock_wire);
    if (!task_authority) return false;
    vd_root(task->toolchain_capsule_root, 0x21);
    vd_root(task->write_scope_root, 0x31);
    memcpy(task->proof_policy_root,
           fixture->accepted.proof_policy_root, 32);
    vd_root(task->model_policy_root, 0x51);
    vd_root(task->goal_root, signer_seed);
    task->capabilities = VCS_ZCODE_TASK_CAP_V1_MASK;
    task->max_changed_files = 8;
    task->max_patch_bytes = 1024 * 1024;
    task->max_context_bytes = 1024 * 1024;
    task->max_cpu_seconds = 60;
    task->max_memory_bytes = UINT64_C(256) * 1024 * 1024;
    task->max_output_bytes = UINT64_C(16) * 1024 * 1024;
    task->expires_unix = now + 3600;
    uint8_t task_wire[VCS_ZCODE_TASK_WIRE_BYTES];
    if (vcs_zcode_task_serialize(task, task_wire) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_task_root(task, fixture->accepted.task_root) !=
            VCS_ZCODE_DEV_OK ||
        !vd_put_object(dir, fixture->accepted.task_root,
                       task_wire, sizeof(task_wire)))
        return false;
    uint8_t seed[32];
    vd_root(seed, signer_seed);
    ed25519_keypair(fixture->signer_pubkey,
                    fixture->signer_secret, seed);
    struct vcs_zcode_candidate_v1 *candidate = &fixture->accepted.candidate;
    candidate->schema_version = VCS_ZCODE_DEV_VERSION;
    memcpy(candidate->task_root, fixture->accepted.task_root, 32);
    memcpy(candidate->base_source_root, source_root, 32);
    vd_root(candidate->patch_root, 0x71);
    memcpy(candidate->candidate_source_root, source_root, 32);
    vd_root(candidate->adapter_policy_root, 0x81);
    memcpy(candidate->author_pubkey, fixture->signer_pubkey, 32);
    candidate->sequence = 1;
    candidate->created_unix = now - 100;
    uint8_t candidate_wire[VCS_ZCODE_CANDIDATE_WIRE_BYTES];
    if (vcs_zcode_candidate_serialize(candidate, candidate_wire) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(
            candidate, fixture->accepted.candidate_root) !=
            VCS_ZCODE_DEV_OK ||
        !vd_put_object(dir, fixture->accepted.candidate_root,
                       candidate_wire, sizeof(candidate_wire)))
        return false;
    uint8_t receipt_roots[2][32];
    if (!vd_put_work_receipt(
            dir, task, candidate, fixture->accepted.task_root,
            fixture->accepted.candidate_root,
            fixture->accepted.proof_policy_root, VCS_ZCODE_WORK_BUILD,
            0x91, now, receipt_roots[0]) ||
        !vd_put_work_receipt(
            dir, task, candidate, fixture->accepted.task_root,
            fixture->accepted.candidate_root,
            fixture->accepted.proof_policy_root, VCS_ZCODE_WORK_TEST,
            0xb1, now, receipt_roots[1]))
        return false;
    if (memcmp(receipt_roots[0], receipt_roots[1], 32) > 0) {
        uint8_t swap[32];
        memcpy(swap, receipt_roots[0], 32);
        memcpy(receipt_roots[0], receipt_roots[1], 32);
        memcpy(receipt_roots[1], swap, 32);
    }
    uint8_t proof_wire[VCS_ZCODE_PROOF_SET_WIRE_MAX];
    size_t proof_len = 0;
    if (vcs_zcode_proof_set_serialize(
            (const uint8_t (*)[32])receipt_roots, 2,
            proof_wire, sizeof(proof_wire), &proof_len) !=
            VCS_ZCODE_DEV_OK ||
        vcs_zcode_proof_set_root(
            (const uint8_t (*)[32])receipt_roots, 2,
            fixture->accepted.proof_set_root) != VCS_ZCODE_DEV_OK ||
        !vd_put_object(dir, fixture->accepted.proof_set_root,
                       proof_wire, proof_len))
        return false;
    struct vcs_zcode_lane_receipt_v1 lane = {
        .schema_version = VCS_ZCODE_DEV_VERSION,
        .lane = VCS_ZCODE_LANE_FRONTIER,
        .created_unix = now - 50,
    };
    memcpy(lane.source_root, source_root, 32);
    memcpy(lane.task_root, fixture->accepted.task_root, 32);
    memcpy(lane.candidate_root, fixture->accepted.candidate_root, 32);
    memcpy(lane.proof_policy_root,
           fixture->accepted.proof_policy_root, 32);
    if (!vd_put_lane(dir, &lane, fixture->signer_secret,
                     fixture->signer_pubkey,
                     fixture->accepted.frontier_root))
        return false;
    fixture->accepted.frontier = lane;
    lane.lane = VCS_ZCODE_LANE_CANDIDATE;
    lane.created_unix = now - 40;
    memcpy(lane.proof_set_root, fixture->accepted.proof_set_root, 32);
    memcpy(lane.prior_receipt_root,
           fixture->accepted.frontier_root, 32);
    if (!vd_put_lane(dir, &lane, fixture->signer_secret,
                     fixture->signer_pubkey,
                     fixture->accepted.candidate_lane_root))
        return false;
    fixture->accepted.candidate_lane = lane;
    lane.lane = VCS_ZCODE_LANE_PROVEN;
    lane.created_unix = now - 30;
    memcpy(lane.prior_receipt_root,
           fixture->accepted.candidate_lane_root, 32);
    if (!vd_put_lane(dir, &lane, fixture->signer_secret,
                     fixture->signer_pubkey,
                     fixture->accepted.accepted_work_root))
        return false;
    fixture->accepted.proven = lane;
    memcpy(fixture->accepted.expected_signer,
           fixture->signer_pubkey, 32);
    return true;
}

struct captured_commit {
    struct vcs_commit c;
    uint8_t            id[32];
    bool                got;
};

static bool capture_first_commit(const struct vcs_commit *c,
                                 const uint8_t commit_id[32], void *user)
{
    struct captured_commit *cap = user;
    cap->c = *c;
    memcpy(cap->id, commit_id, 32);
    cap->got = true;
    return false; /* newest-first log: stop after the first one */
}

/* ── test: hex32_decode ─────────────────────────────────────────── */
static int t_hex32(void)
{
    int failures = 0;

    char hex[65];
    make_hex64(hex, 0x10);
    uint8_t out[32];
    VD_CHECK("hex32: valid decode", vcs_devloop_hex32_decode(hex, out));
    VD_CHECK("hex32: first byte", out[0] == 0x10);
    VD_CHECK("hex32: last byte", out[31] == (uint8_t)(0x10 + 31));

    uint8_t scratch[32];
    VD_CHECK("hex32: NULL hex rejected",
             !vcs_devloop_hex32_decode(NULL, scratch));
    VD_CHECK("hex32: NULL out rejected",
             !vcs_devloop_hex32_decode(hex, NULL));
    VD_CHECK("hex32: short length rejected",
             !vcs_devloop_hex32_decode("abcd", scratch));

    char bad[65];
    make_hex64(bad, 0);
    bad[10] = 'z';
    VD_CHECK("hex32: non-hex char rejected",
             !vcs_devloop_hex32_decode(bad, scratch));

    return failures;
}

/* ── test: a green cycle lands a correctly-bound commit ───────────── */
static int t_anchor_ok(const char *dir)
{
    int failures = 0;

    vd_write(dir, "readme.txt", "hello\n");
    vd_write(dir, "src/main.c", "int main(void){return 0;}\n");

    char hex[65];
    make_hex64(hex, 0x42);

    struct vcs_devloop_verdict v = {0};
    v.verdict_status = 0;
    v.phase = "resident_commit";
    v.elapsed_ms = 1234;
    v.generation_hex = hex;
    v.agent_id = "agent-fable";
    v.session_id = "sess-abc";
    v.task_ref = "task/zvcs-2.3";

    struct vcs_devloop_anchor_result ar = {0};
    vcs_devloop_anchor_cycle(dir, &v, &ar);
    VD_CHECK("anchor: status OK", ar.status == VCS_DEVLOOP_ANCHOR_OK);

    struct vcs_repo *r = vcs_open(dir);
    VD_CHECK("anchor: reopen", r != NULL);
    if (!r) return failures + 1;

    struct captured_commit cap = {0};
    VD_CHECK("anchor: vcs_log ok",
             vcs_log(r, 1, capture_first_commit, &cap) == VCS_OK);
    VD_CHECK("anchor: commit captured", cap.got);
    VD_CHECK("anchor: commit id matches result",
             cap.got && memcmp(cap.id, ar.commit_id, 32) == 0);
    VD_CHECK("anchor: verdict_status bound",
             cap.got && cap.c.verdict_status == 0);
    VD_CHECK("anchor: phase bound",
             cap.got && strcmp(cap.c.phase, "resident_commit") == 0);
    VD_CHECK("anchor: elapsed_ms bound",
             cap.got && cap.c.elapsed_ms == 1234);
    uint8_t want_gen[32];
    vcs_devloop_hex32_decode(hex, want_gen);
    VD_CHECK("anchor: generation_sha256 bound",
             cap.got && memcmp(cap.c.generation_sha256, want_gen, 32) == 0);
    VD_CHECK("anchor: agent_id bound",
             cap.got && strcmp(cap.c.agent_id, "agent-fable") == 0);
    VD_CHECK("anchor: session_id bound",
             cap.got && strcmp(cap.c.session_id, "sess-abc") == 0);
    VD_CHECK("anchor: task_ref bound",
             cap.got && strcmp(cap.c.task_ref, "task/zvcs-2.3") == 0);
    vcs_close(r);

    /* A cycle with no known generation (e.g. a docs-only "check" cycle, or
     * a reload whose deploy-state file did not parse) still anchors — with
     * an all-zero generation_sha256, never a failure. */
    vd_write(dir, "readme.txt", "hello again\n");
    struct vcs_devloop_verdict v2 = {0};
    v2.verdict_status = 0;
    v2.phase = "check";
    v2.elapsed_ms = 5;
    struct vcs_devloop_anchor_result ar2 = {0};
    vcs_devloop_anchor_cycle(dir, &v2, &ar2);
    VD_CHECK("anchor: generation-absent cycle still OK",
             ar2.status == VCS_DEVLOOP_ANCHOR_OK);

    r = vcs_open(dir);
    struct captured_commit cap2 = {0};
    vcs_log(r, 1, capture_first_commit, &cap2);
    uint8_t zero32[32] = {0};
    VD_CHECK("anchor: absent generation binds all-zero",
             cap2.got && memcmp(cap2.c.generation_sha256, zero32, 32) == 0);
    vcs_close(r);

    return failures;
}

/* lib/vcs never spawns a process to run the initial baseline (ZVCS
 * sovereignty — check-vcs-no-git); the detach mechanics live only in the
 * dev-only tools/dev/devloop_baseline.c, which this test suite does not
 * link. So this test drives both halves in-process and hermetically: (1)
 * the anchor path reports the baseline as REQUIRED without spawning
 * anything, then (2) vcs_devloop_run_initial_baseline() is called directly
 * to run it synchronously, and the next cycle anchors normally. No child
 * process, no polling loop. */
static int t_initial_anchor_deferred(const char *dir)
{
    int failures = 0;
    vd_write(dir, "src/main.c", "int main(void){return 0;}\n");

    struct vcs_devloop_verdict v = {0};
    v.phase = "resident_commit";
    v.defer_initial_snapshot = true;
    struct vcs_devloop_anchor_result first = {0};
    vcs_devloop_anchor_cycle(dir, &v, &first);
    VD_CHECK("deferred: first cycle leaves foreground",
             first.status == VCS_DEVLOOP_ANCHOR_DEFERRED);
    VD_CHECK("deferred: result names unanchored cycle",
             strstr(first.error, "unanchored") != NULL);
    VD_CHECK("deferred: caller told a baseline is required",
             first.baseline_needed);

    /* A second concurrent cycle before anyone has run the baseline still
     * reports baseline_needed — nothing has claimed it yet (no lock is
     * held, since lib/vcs never launches anything on its own). */
    struct vcs_devloop_anchor_result concurrent = {0};
    vcs_devloop_anchor_cycle(dir, &v, &concurrent);
    VD_CHECK("deferred: second cycle also unanchored",
             concurrent.status == VCS_DEVLOOP_ANCHOR_DEFERRED);
    VD_CHECK("deferred: second cycle also told a baseline is required",
             concurrent.baseline_needed);

    /* Run the baseline synchronously, in-process — this is exactly what
     * tools/dev/devloop_baseline.c's grandchild worker calls. */
    struct vcs_devloop_anchor_result baseline = {0};
    vcs_devloop_run_initial_baseline(dir, &baseline);
    VD_CHECK("deferred: synchronous baseline completes",
             baseline.status == VCS_DEVLOOP_ANCHOR_OK);

    /* Once history exists, a defer_initial_snapshot cycle anchors normally
     * rather than deferring again. */
    struct vcs_devloop_anchor_result next = {0};
    vcs_devloop_anchor_cycle(dir, &v, &next);
    VD_CHECK("deferred: next warm cycle anchors synchronously",
             next.status == VCS_DEVLOOP_ANCHOR_OK);

    /* Once durable history exists, re-running the baseline directly is a
     * clean no-op path (lock acquires immediately, snapshot lands — no
     * "already running" collision since nothing else holds the lock). */
    struct vcs_devloop_anchor_result rerun = {0};
    vcs_devloop_run_initial_baseline(dir, &rerun);
    VD_CHECK("deferred: re-running baseline after history exists still OK",
             rerun.status == VCS_DEVLOOP_ANCHOR_OK);

    return failures;
}

/* A complete source-wide proof becomes a small durable publication job. The
 * queue stores only immutable roots; package/network/wallet work is strictly
 * out of the foreground anchor path. */
static int t_publication_enqueue(const char *dir)
{
    int failures = 0;
    vd_write(dir, "src/main.c", "int main(void){return 0;}\n");

    char source_id[65], source_cas[65], generation[65];
    make_hex64(source_id, 0x11);
    make_hex64(source_cas, 0x31);
    make_hex64(generation, 0x51);
    struct vcs_devloop_verdict v = {
        .verdict_status = 0,
        .phase = "verify",
        .elapsed_ms = 17,
        .generation_hex = generation,
        .proof_complete = true,
        .proof_scope = "source_wide_compile_tests_lint_fast",
        .source_identity_hex = source_id,
        .source_cas_hex = source_cas,
    };
    struct vcs_devloop_anchor_result ar = {0};
    vcs_devloop_anchor_cycle(dir, &v, &ar);
    VD_CHECK("publication: source anchor committed",
             ar.status == VCS_DEVLOOP_ANCHOR_OK);
    VD_CHECK("publication: durable job queued",
             ar.publication_status == VCS_DEVLOOP_PUBLICATION_QUEUED);
    VD_CHECK("publication: enqueue latency measured",
             ar.publication_enqueue_us >= 0);

    struct vcs_devloop_publication_job job;
    VD_CHECK("publication: job reloads after writer closes",
             vcs_devloop_publication_job_load(
                 dir, ar.publication_job_root, &job));
    VD_CHECK("publication: job binds ZVCS commit",
             memcmp(job.vcs_commit_root, ar.commit_id, 32) == 0);
    VD_CHECK("publication: job binds proof receipt",
             memcmp(job.proof_receipt_root, ar.proof_receipt_root, 32) == 0);
    uint8_t expected_source[32], expected_cas[32];
    vcs_devloop_hex32_decode(source_id, expected_source);
    vcs_devloop_hex32_decode(source_cas, expected_cas);
    VD_CHECK("publication: job binds exact source identity",
             memcmp(job.source_identity_sha256, expected_source, 32) == 0);
    VD_CHECK("publication: job binds source CAS",
             memcmp(job.source_cas_sha3, expected_cas, 32) == 0);
    VD_CHECK("publication: queue survives reopen",
             vcs_devloop_publication_job_is_queued(
                 dir, ar.publication_job_root));

    bool reused = false;
    VD_CHECK("publication: exact retry succeeds",
             vcs_devloop_publication_job_requeue(
                 dir, ar.publication_job_root, &reused));
    VD_CHECK("publication: exact retry is idempotent", reused);

    struct vcs_devloop_publication_receipt progress;
    uint8_t progress_root[32], loaded_progress_root[32];
    VD_CHECK("publication: no phase receipt before worker advances",
             !vcs_devloop_publication_progress_load(
                 dir, ar.publication_job_root, &progress,
                 loaded_progress_root));
    reused = true;
    VD_CHECK("publication: worker durably records waiting acceptance",
             vcs_devloop_publication_advance_waiting_acceptance(
                 dir, ar.publication_job_root, progress_root, &reused));
    VD_CHECK("publication: first phase receipt is new", !reused);
    VD_CHECK("publication: phase receipt reloads after writer closes",
             vcs_devloop_publication_progress_load(
                 dir, ar.publication_job_root, &progress,
                 loaded_progress_root));
    VD_CHECK("publication: phase root survives restart",
             memcmp(progress_root, loaded_progress_root, 32) == 0);
    VD_CHECK("publication: worker names accepted-lane blocker",
             progress.phase ==
                 VCS_DEVLOOP_PUBLICATION_PHASE_WAITING_ACCEPTANCE);
    VD_CHECK("publication: phase receipt binds immutable job",
             memcmp(progress.job_root, ar.publication_job_root, 32) == 0);
    reused = false;
    uint8_t retried_progress_root[32];
    VD_CHECK("publication: phase retry succeeds",
             vcs_devloop_publication_advance_waiting_acceptance(
                 dir, ar.publication_job_root, retried_progress_root,
                 &reused));
    VD_CHECK("publication: phase retry is idempotent", reused);
    VD_CHECK("publication: phase retry preserves exact receipt root",
             memcmp(progress_root, retried_progress_root, 32) == 0);

    char drive_commit_hex[65], drive_proof_hex[65], drive_job_hex[65];
    zcl_hex_encode(ar.commit_id, 32, drive_commit_hex);
    zcl_hex_encode(ar.proof_receipt_root, 32, drive_proof_hex);
    zcl_hex_encode(ar.publication_job_root, 32, drive_job_hex);
    char drive_cycle[2048], drive_why[160] = {0};
    int drive_cycle_len = snprintf(
        drive_cycle, sizeof(drive_cycle),
        "{\"schema\":\"zcl.dev_cycle.v1\",\"producer\":\"test\","
        "\"status\":\"passed\",\"action\":\"verify\","
        "\"reason\":\"fixture\",\"phase\":\"verify\","
        "\"runtime_published\":false,\"elapsed_ms\":17,"
        "\"proof_complete\":true,"
        "\"proof_scope\":\"source_wide_compile_tests_lint_fast\","
        "\"source_id_sha256\":\"%s\",\"vcs_commit\":\"%s\","
        "\"proof_receipt_root\":\"%s\","
        "\"publication_status\":\"QUEUED\","
        "\"publication_job_root\":\"%s\","
        "\"publication_enqueue_us\":41,\"files\":[]}",
        source_id, drive_commit_hex, drive_proof_hex, drive_job_hex);
    VD_CHECK("drive: exact cycle fixture renders within bound",
             drive_cycle_len > 0 &&
             (size_t)drive_cycle_len < sizeof(drive_cycle));
    VD_CHECK("drive: exact cycle fixture persists",
             drive_cycle_len > 0 &&
             zcl_devloop_cycle_state_write(
                 dir, drive_cycle, (size_t)drive_cycle_len,
                 drive_why, sizeof(drive_why)));
    struct json_value drive_input;
    json_init(&drive_input);
    json_set_object(&drive_input);
    (void)json_push_kv_int(&drive_input, "after_epoch", 0);
    (void)json_push_kv_int(&drive_input, "timeout_ms", 1);
    struct zcl_command_context drive_context = {
        .source_root = dir,
        .authority_ceiling = ZCL_COMMAND_AUTH_OPERATOR,
        .dev_build = true,
    };
    struct zcl_command_request drive_request = {
        .context = &drive_context,
        .input = &drive_input,
    };
    struct zcl_command_reply drive_reply;
    zcl_command_reply_init(&drive_reply, "zcl.dev_drive.v1");
    zcl_native_handle_dev_drive(&drive_request, &drive_reply);
    VD_CHECK("drive: compact warm-service result passes",
             drive_reply.exit_code == ZCL_COMMAND_EXIT_OK);
    VD_CHECK("drive: exact proof is never dropped",
             json_get_bool(json_get(&drive_reply.data, "proof_complete")));
    VD_CHECK("drive: every fallback names why it was not live",
             strcmp(json_get_str(json_get(
                        &drive_reply.data, "why_not_live")),
                    "fixture") == 0);
    VD_CHECK("drive: exact ZVCS root is projected",
             strcmp(json_get_str(json_get(
                        &drive_reply.data, "zvcs_commit_root")),
                    drive_commit_hex) == 0);
    VD_CHECK("drive: job root moves without agent hash handling",
             strcmp(json_get_str(json_get(
                        &drive_reply.data, "publication_job_root")),
                    drive_job_hex) == 0);
    VD_CHECK("drive: restart-safe blocker is verified and compact",
             strcmp(json_get_str(json_get(&drive_reply.data, "blocker")),
                    "human_proven_work_and_offline_publisher_signature_required") == 0);
    VD_CHECK("drive: one exact next action is present",
             json_get_str(json_get(&drive_reply.data, "next_command")) != NULL);
    zcl_command_reply_free(&drive_reply);
    json_free(&drive_input);

    const int64_t accepted_now = 1700000000;
    struct vd_accepted_fixture fixture;
    VD_CHECK("publication: complete accepted-work fixture stores",
             vd_accepted_fixture_create(
                 dir, job.source_tree_root, accepted_now, 0x66, &fixture));
    struct vcs_zcode_accepted_work_v1 resolved;
    VD_CHECK("publication: PROVEN accepted-work chain reconstructs",
             vcs_zcode_accepted_work_resolve(
                 dir, fixture.accepted.accepted_work_root,
                 accepted_now, &resolved));
    uint8_t *accepted_wire = NULL;
    size_t accepted_wire_len = 0;
    struct vcs_zcode_accepted_work_v1 exported;
    VD_CHECK("publication: accepted work exports as closed authority bundle",
             vcs_zcode_accepted_work_bundle_export(
                 dir, fixture.accepted.accepted_work_root, accepted_now,
                 &accepted_wire, &accepted_wire_len, &exported) ==
                 VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK &&
             accepted_wire_len > 0 &&
             memcmp(exported.expected_signer,
                    fixture.signer_pubkey, 32) == 0);
    char accepted_consumer[512];
    test_make_tmpdir(accepted_consumer, sizeof(accepted_consumer),
                     "vcs_devloop", "accepted-authority-consumer");
    struct vcs_source_bundle_sharded accepted_source;
    vcs_source_bundle_sharded_init(&accepted_source);
    VD_CHECK("publication: accepted source stages without Git",
             vcs_source_bundle_sharded_create(
                 dir, job.source_tree_root, &accepted_source) ==
                 VCS_SOURCE_BUNDLE_OK &&
             vcs_source_bundle_sharded_import(
                 &accepted_source, job.source_tree_root, accepted_consumer,
                 NULL) == VCS_SOURCE_BUNDLE_OK);
    struct vcs_zcode_accepted_work_v1 imported;
    uint32_t authority_objects = 0, authority_receipts = 0;
    VD_CHECK("publication: fresh consumer rederives full accepted authority",
             accepted_wire &&
             vcs_zcode_accepted_work_bundle_import(
                 accepted_consumer, fixture.accepted.accepted_work_root,
                 job.source_tree_root, accepted_wire, accepted_wire_len,
                 &imported, &authority_objects, &authority_receipts) ==
                 VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK &&
             authority_objects >= 9 && authority_receipts == 2 &&
             memcmp(imported.expected_signer,
                    fixture.signer_pubkey, 32) == 0);
    uint8_t wrong_accepted_root[32];
    memcpy(wrong_accepted_root, fixture.accepted.accepted_work_root, 32);
    wrong_accepted_root[0] ^= 1u;
    VD_CHECK("publication: caller-selected wrong accepted root is refused",
             vcs_zcode_accepted_work_bundle_import(
                 accepted_consumer, wrong_accepted_root,
                 job.source_tree_root, accepted_wire, accepted_wire_len,
                 NULL, NULL, NULL) ==
                 VCS_ZCODE_ACCEPTED_WORK_BUNDLE_SHAPE);
    if (accepted_wire_len > 0) accepted_wire[accepted_wire_len - 1u] ^= 1u;
    VD_CHECK("publication: corrupt task authority is refused",
             vcs_zcode_accepted_work_bundle_import(
                 accepted_consumer, fixture.accepted.accepted_work_root,
                 job.source_tree_root, accepted_wire, accepted_wire_len,
                 NULL, NULL, NULL) != VCS_ZCODE_ACCEPTED_WORK_BUNDLE_OK);
    free(accepted_wire);
    vcs_source_bundle_sharded_free(&accepted_source);
    uint8_t rejected_progress_root[32];
    reused = true;
    VD_CHECK("publication: valid compile/test CANDIDATE remains waiting",
             !vcs_devloop_publication_advance_proven_work(
                 dir, ar.publication_job_root,
                 fixture.accepted.candidate_lane_root, accepted_now,
                 rejected_progress_root, &reused));
    VD_CHECK("publication: pre-human-accept refusal is not reuse", !reused);

    uint8_t attacker_seed[32], attacker_secret[32], attacker_pubkey[32];
    vd_root(attacker_seed, 0xd1);
    ed25519_keypair(attacker_pubkey, attacker_secret, attacker_seed);
    struct vcs_zcode_lane_receipt_v1 forged = fixture.accepted.candidate_lane;
    uint8_t forged_root[32];
    VD_CHECK("publication: arbitrary self-signed CANDIDATE stores",
             vd_put_lane(dir, &forged, attacker_secret, attacker_pubkey,
                         forged_root));
    reused = true;
    VD_CHECK("publication: arbitrary self-signed CANDIDATE refused",
             !vcs_devloop_publication_advance_proven_work(
                 dir, ar.publication_job_root, forged_root, accepted_now,
                 rejected_progress_root, &reused));
    forged = fixture.accepted.proven;
    VD_CHECK("publication: arbitrary self-signed PROVEN stores",
             vd_put_lane(dir, &forged, attacker_secret, attacker_pubkey,
                         forged_root));
    reused = true;
    VD_CHECK("publication: arbitrary self-signed PROVEN refused",
             !vcs_devloop_publication_advance_proven_work(
                 dir, ar.publication_job_root, forged_root, accepted_now,
                 rejected_progress_root, &reused));
    VD_CHECK("publication: signer rotation inside chain refused",
             !vcs_zcode_accepted_work_resolve(
                 dir, forged_root, accepted_now, &resolved));
    memset(attacker_secret, 0, sizeof(attacker_secret));

    static const char *const context_names[] = {
        "correct source but different task refused",
        "correct source but different candidate refused",
        "changed proof policy refused",
        "changed proof set refused",
        "missing predecessor refused",
        "forged predecessor root refused",
    };
    for (size_t i = 0; i < sizeof(context_names) / sizeof(context_names[0]);
         i++) {
        forged = fixture.accepted.proven;
        if (i == 0) vd_root(forged.task_root, 0xe1);
        if (i == 1) vd_root(forged.candidate_root, 0xe2);
        if (i == 2) vd_root(forged.proof_policy_root, 0xe3);
        if (i == 3) vd_root(forged.proof_set_root, 0xe4);
        if (i == 4) vd_root(forged.prior_receipt_root, 0xe5);
        if (i == 5)
            memcpy(forged.prior_receipt_root,
                   fixture.accepted.frontier_root, 32);
        VD_CHECK("publication: forged-context receipt stores",
                 vd_put_lane(dir, &forged, fixture.signer_secret,
                             fixture.signer_pubkey, forged_root));
        reused = true;
        VD_CHECK(context_names[i],
                 !vcs_devloop_publication_advance_proven_work(
                     dir, ar.publication_job_root, forged_root, accepted_now,
                     rejected_progress_root, &reused));
    }
    VD_CHECK("publication: stale accepted work refused",
             !vcs_devloop_publication_advance_proven_work(
                 dir, ar.publication_job_root,
                 fixture.accepted.accepted_work_root, accepted_now + 4000,
                 rejected_progress_root, &reused));

    uint8_t lane_root[32];
    memcpy(lane_root, fixture.accepted.accepted_work_root, 32);
    uint8_t accepted_progress_root[32];
    reused = true;
    VD_CHECK("publication: worker binds exact human PROVEN accepted work",
             vcs_devloop_publication_advance_proven_work(
                 dir, ar.publication_job_root, lane_root, accepted_now,
                 accepted_progress_root, &reused));
    VD_CHECK("publication: accepted-lane phase is new", !reused);
    VD_CHECK("publication: accepted-lane phase reloads",
             vcs_devloop_publication_progress_load(
                 dir, ar.publication_job_root, &progress,
                 loaded_progress_root));
    VD_CHECK("publication: accepted-lane phase named",
             progress.phase ==
                 VCS_DEVLOOP_PUBLICATION_PHASE_ACCEPTED_LANE_BOUND);
    VD_CHECK("publication: scheduler binds authoritative accepted-work root",
             memcmp(progress.artifact_root, lane_root, 32) == 0);
    VD_CHECK("publication: receipt chain preserves waiting phase",
             memcmp(progress.predecessor_receipt_root,
                    progress_root, 32) == 0);
    reused = false;
    uint8_t accepted_retry_root[32];
    VD_CHECK("publication: accepted-work retry succeeds",
             vcs_devloop_publication_advance_proven_work(
                 dir, ar.publication_job_root, lane_root, accepted_now,
                 accepted_retry_root, &reused));
    VD_CHECK("publication: accepted-lane retry reuses receipt", reused);
    VD_CHECK("publication: accepted-lane retry preserves root",
             memcmp(accepted_progress_root, accepted_retry_root, 32) == 0);

    struct vcs_package_mapping_metrics first_map, warm_map;
    uint8_t mapping_root[32], warm_mapping_root[32];
    VD_CHECK("publication: worker derives content mapping cache",
             vcs_package_mapping_set_build(
                 dir, job.source_tree_root, lane_root,
                 &first_map, mapping_root));
    VD_CHECK("publication: cold mapping scans source bytes",
             first_map.bytes_scanned > 0);
    VD_CHECK("publication: cold mapping creates chunk hashes",
             first_map.new_chunks > 0 && first_map.reused_chunks == 0);
    VD_CHECK("publication: exact mapping retry uses immutable cache",
             vcs_package_mapping_set_build(
                 dir, job.source_tree_root, lane_root,
                 &warm_map, warm_mapping_root));
    VD_CHECK("publication: warm mapping scans zero source bytes",
             warm_map.bytes_scanned == 0 && warm_map.new_chunks == 0);
    VD_CHECK("publication: warm mapping reuses every cold chunk",
             warm_map.reused_chunks == first_map.new_chunks);
    VD_CHECK("publication: warm mapping root is byte-stable",
             memcmp(mapping_root, warm_mapping_root, 32) == 0);
    struct vcs_package_mapping_set loaded_mapping;
    VD_CHECK("publication: mapping set reloads by exact root",
             vcs_package_mapping_set_load(
                 dir, mapping_root, &loaded_mapping));
    VD_CHECK("publication: mapping set binds source tree",
             memcmp(loaded_mapping.source_tree_root,
                    job.source_tree_root, 32) == 0);
    VD_CHECK("publication: mapping set binds accepted lane",
             memcmp(loaded_mapping.lane_receipt_root, lane_root, 32) == 0);
    vcs_package_mapping_set_free(&loaded_mapping);

    uint8_t wrong_mapping_root[32], wrong_lane[32];
    memcpy(wrong_lane, lane_root, 32);
    wrong_lane[0] ^= 0x80u;
    VD_CHECK("publication: wrong-lane mapping set can be represented",
             vcs_package_mapping_set_build(
                 dir, job.source_tree_root, wrong_lane,
                 &warm_map, wrong_mapping_root));
    reused = true;
    VD_CHECK("publication: wrong-lane mapping cannot advance job",
             !vcs_devloop_publication_advance_package_mapping(
                 dir, ar.publication_job_root, wrong_mapping_root,
                 warm_map.bytes_scanned, warm_map.new_chunks,
                 warm_map.reused_chunks, rejected_progress_root, &reused));
    VD_CHECK("publication: wrong mapping refusal is not reuse", !reused);

    uint8_t mapped_progress_root[32];
    reused = true;
    VD_CHECK("publication: worker records mapping-ready phase",
             vcs_devloop_publication_advance_package_mapping(
                 dir, ar.publication_job_root, mapping_root,
                 first_map.bytes_scanned, first_map.new_chunks,
                 first_map.reused_chunks, mapped_progress_root, &reused));
    VD_CHECK("publication: first mapping phase is new", !reused);
    VD_CHECK("publication: mapping phase reloads",
             vcs_devloop_publication_progress_load(
                 dir, ar.publication_job_root, &progress,
                 loaded_progress_root));
    VD_CHECK("publication: mapping-ready phase named",
             progress.phase ==
                 VCS_DEVLOOP_PUBLICATION_PHASE_PACKAGE_MAPPING_READY);
    VD_CHECK("publication: mapping phase binds exact set",
             memcmp(progress.artifact_root, mapping_root, 32) == 0);
    VD_CHECK("publication: mapping phase preserves accepted predecessor",
             memcmp(progress.predecessor_receipt_root,
                    accepted_progress_root, 32) == 0);
    VD_CHECK("publication: mapping receipt reports cold byte scan",
             progress.bytes_scanned == first_map.bytes_scanned);
    reused = false;
    VD_CHECK("publication: mapping phase retry succeeds",
             vcs_devloop_publication_advance_package_mapping(
                 dir, ar.publication_job_root, mapping_root,
                 warm_map.bytes_scanned, warm_map.new_chunks,
                 warm_map.reused_chunks, accepted_retry_root, &reused));
    VD_CHECK("publication: mapping phase retry reuses receipt", reused);
    VD_CHECK("publication: mapping retry preserves receipt root",
             memcmp(mapped_progress_root, accepted_retry_root, 32) == 0);
    char job_hex[65], mapping_hex[65];
    zcl_hex_encode(ar.publication_job_root, 32, job_hex);
    zcl_hex_encode(mapping_root, 32, mapping_hex);
    struct json_value advance_input;
    json_init(&advance_input);
    json_set_object(&advance_input);
    (void)json_push_kv_str(&advance_input, "job_root", job_hex);
    (void)json_push_kv_bool(&advance_input, "details", true);
    struct zcl_command_context command_context = {
        .source_root = dir,
        .authority_ceiling = ZCL_COMMAND_AUTH_OPERATOR,
        .dev_build = true,
    };
    struct zcl_command_request advance_request = {
        .context = &command_context,
        .input = &advance_input,
    };
    struct zcl_command_reply advance_reply;
    zcl_command_reply_init(&advance_reply,
                           "zcl.dev_publication_advance.v1");
    zcl_native_handle_dev_publication_advance(
        &advance_request, &advance_reply);
    VD_CHECK("publication: native worker resumes mapped job",
             advance_reply.exit_code == ZCL_COMMAND_EXIT_OK);
    VD_CHECK("publication: native worker reports mapping phase",
             strcmp(json_get_str(json_get(&advance_reply.data, "status")),
                    "PACKAGE_MAPPING_READY") == 0);
    VD_CHECK("publication: native worker reports exact mapping root",
             strcmp(json_get_str(json_get(
                        &advance_reply.data, "package_mapping_root")),
                    mapping_hex) == 0);
    VD_CHECK("publication: native worker reports durable cold scan",
             (uint64_t)json_get_int(json_get(
                 &advance_reply.data, "bytes_scanned")) ==
                 first_map.bytes_scanned);
    zcl_command_reply_free(&advance_reply);
    json_free(&advance_input);
    uint8_t release_root[32], released_progress_root[32];
    memcpy(release_root, mapping_root, 32);
    release_root[0] ^= 0x5au;
    reused = true;
    VD_CHECK("publication: release refuses the wrong mapping predecessor",
             !vcs_devloop_publication_advance_release(
                 dir, ar.publication_job_root, wrong_mapping_root,
                 release_root, rejected_progress_root, &reused));
    VD_CHECK("publication: wrong release predecessor is not reuse", !reused);
    reused = true;
    VD_CHECK("publication: signed release advances durable job",
             vcs_devloop_publication_advance_release(
                 dir, ar.publication_job_root, mapping_root,
                 release_root, released_progress_root, &reused));
    VD_CHECK("publication: first release phase is new", !reused);
    VD_CHECK("publication: release phase reloads",
             vcs_devloop_publication_progress_load(
                 dir, ar.publication_job_root, &progress,
                 loaded_progress_root));
    VD_CHECK("publication: release phase named",
             progress.phase ==
                 VCS_DEVLOOP_PUBLICATION_PHASE_RELEASE_PUBLISHED);
    VD_CHECK("publication: release phase binds authoritative root",
             memcmp(progress.artifact_root, release_root, 32) == 0);
    VD_CHECK("publication: release phase preserves mapping predecessor",
             memcmp(progress.predecessor_receipt_root,
                    mapped_progress_root, 32) == 0);
    VD_CHECK("publication: release phase preserves scan metrics",
             progress.bytes_scanned == first_map.bytes_scanned &&
             progress.new_chunks == first_map.new_chunks &&
             progress.reused_chunks == first_map.reused_chunks);
    reused = false;
    VD_CHECK("publication: release retry succeeds",
             vcs_devloop_publication_advance_release(
                 dir, ar.publication_job_root, mapping_root,
                 release_root, accepted_retry_root, &reused));
    VD_CHECK("publication: release retry reuses receipt", reused);
    VD_CHECK("publication: release retry preserves receipt root",
             memcmp(released_progress_root,
                    accepted_retry_root, 32) == 0);
    reused = false;
    VD_CHECK("publication: mapping retry cannot regress release phase",
             vcs_devloop_publication_advance_package_mapping(
                 dir, ar.publication_job_root, mapping_root,
                 warm_map.bytes_scanned, warm_map.new_chunks,
                 warm_map.reused_chunks, accepted_retry_root, &reused));
    VD_CHECK("publication: mapping retry returns release receipt", reused);
    VD_CHECK("publication: mapping retry preserves release phase",
             memcmp(released_progress_root,
                    accepted_retry_root, 32) == 0);
    uint8_t passport_root[32], passport_progress_root[32];
    memcpy(passport_root, release_root, 32);
    passport_root[1] ^= 0xa5u;
    reused = true;
    VD_CHECK("publication: Passport refuses the wrong release predecessor",
             !vcs_devloop_publication_advance_passport(
                 dir, ar.publication_job_root, mapping_root,
                 wrong_mapping_root, passport_root,
                 rejected_progress_root, &reused));
    VD_CHECK("publication: wrong Passport predecessor is not reuse", !reused);
    reused = true;
    VD_CHECK("publication: signed Passport advances durable job",
             vcs_devloop_publication_advance_passport(
                 dir, ar.publication_job_root, mapping_root,
                 release_root, passport_root, passport_progress_root,
                 &reused));
    VD_CHECK("publication: first Passport phase is new", !reused);
    VD_CHECK("publication: Passport phase reloads",
             vcs_devloop_publication_progress_load(
                 dir, ar.publication_job_root, &progress,
                 loaded_progress_root));
    VD_CHECK("publication: Passport phase named",
             progress.phase ==
                 VCS_DEVLOOP_PUBLICATION_PHASE_PASSPORT_PUBLISHED);
    VD_CHECK("publication: Passport phase binds authoritative root",
             memcmp(progress.artifact_root, passport_root, 32) == 0);
    VD_CHECK("publication: Passport phase preserves release predecessor",
             memcmp(progress.predecessor_receipt_root,
                    released_progress_root, 32) == 0);
    VD_CHECK("publication: Passport phase preserves scan metrics",
             progress.bytes_scanned == first_map.bytes_scanned &&
             progress.new_chunks == first_map.new_chunks &&
             progress.reused_chunks == first_map.reused_chunks);
    reused = false;
    VD_CHECK("publication: Passport retry succeeds",
             vcs_devloop_publication_advance_passport(
                 dir, ar.publication_job_root, mapping_root,
                 release_root, passport_root, accepted_retry_root,
                 &reused));
    VD_CHECK("publication: Passport retry reuses receipt", reused);
    VD_CHECK("publication: Passport retry preserves receipt root",
             memcmp(passport_progress_root,
                    accepted_retry_root, 32) == 0);
    reused = false;
    VD_CHECK("publication: release retry cannot regress Passport phase",
             vcs_devloop_publication_advance_release(
                 dir, ar.publication_job_root, mapping_root,
                 release_root, accepted_retry_root, &reused));
    VD_CHECK("publication: release retry returns Passport receipt", reused);
    VD_CHECK("publication: release retry preserves Passport phase",
             memcmp(passport_progress_root,
                    accepted_retry_root, 32) == 0);
    uint8_t workspace_root[32], workspace_progress_root[32];
    memcpy(workspace_root, passport_root, 32);
    workspace_root[2] ^= 0x3cu;
    reused = true;
    VD_CHECK("publication: workspace refuses wrong Passport predecessor",
             !vcs_devloop_publication_advance_workspace(
                 dir, ar.publication_job_root, mapping_root,
                 release_root, wrong_mapping_root, workspace_root,
                 rejected_progress_root, &reused));
    VD_CHECK("publication: wrong workspace predecessor is not reuse", !reused);
    reused = true;
    VD_CHECK("publication: signed workspace advances durable job",
             vcs_devloop_publication_advance_workspace(
                 dir, ar.publication_job_root, mapping_root,
                 release_root, passport_root, workspace_root,
                 workspace_progress_root, &reused));
    VD_CHECK("publication: first workspace phase is new", !reused);
    VD_CHECK("publication: workspace phase reloads",
             vcs_devloop_publication_progress_load(
                 dir, ar.publication_job_root, &progress,
                 loaded_progress_root));
    VD_CHECK("publication: workspace phase named",
             progress.phase ==
                 VCS_DEVLOOP_PUBLICATION_PHASE_WORKSPACE_PUBLISHED);
    VD_CHECK("publication: workspace phase binds authoritative root",
             memcmp(progress.artifact_root, workspace_root, 32) == 0);
    VD_CHECK("publication: workspace phase preserves Passport predecessor",
             memcmp(progress.predecessor_receipt_root,
                    passport_progress_root, 32) == 0);
    reused = false;
    VD_CHECK("publication: workspace retry succeeds",
             vcs_devloop_publication_advance_workspace(
                 dir, ar.publication_job_root, mapping_root,
                 release_root, passport_root, workspace_root,
                 accepted_retry_root, &reused));
    VD_CHECK("publication: workspace retry reuses receipt", reused);
    VD_CHECK("publication: workspace retry preserves receipt root",
             memcmp(workspace_progress_root,
                    accepted_retry_root, 32) == 0);
    reused = false;
    VD_CHECK("publication: Passport retry cannot regress workspace phase",
             vcs_devloop_publication_advance_passport(
                 dir, ar.publication_job_root, mapping_root,
                 release_root, passport_root, accepted_retry_root,
                 &reused));
    VD_CHECK("publication: Passport retry returns workspace receipt", reused);
    VD_CHECK("publication: Passport retry preserves workspace phase",
             memcmp(workspace_progress_root,
                    accepted_retry_root, 32) == 0);
    zcl_hex_encode(release_root, 32, mapping_hex);
    json_init(&advance_input);
    json_set_object(&advance_input);
    (void)json_push_kv_str(&advance_input, "job_root", job_hex);
    zcl_command_reply_init(&advance_reply,
                           "zcl.dev_publication_advance.v1");
    zcl_native_handle_dev_publication_advance(
        &advance_request, &advance_reply);
    VD_CHECK("publication: guided advance preserves workspace phase",
             advance_reply.exit_code == ZCL_COMMAND_EXIT_OK &&
             strcmp(json_get_str(json_get(
                        &advance_reply.data, "status")),
                    "WORKSPACE_PUBLISHED") == 0);
    VD_CHECK("publication: guided advance names registered provider step",
             strcmp(json_get_str(json_get(
                        &advance_reply.data, "next_safe_command")),
                    "zcode network publish") == 0);
    VD_CHECK("publication: guided advance keeps workspace root hidden",
             json_get(&advance_reply.data, "workspace_root") == NULL);
    zcl_command_reply_free(&advance_reply);
    json_free(&advance_input);
    json_init(&advance_input);
    json_set_object(&advance_input);
    (void)json_push_kv_str(&advance_input, "job_root", job_hex);
    zcl_command_reply_init(&advance_reply,
                           "zcl.dev_publication_status.v1");
    zcl_native_handle_dev_publication_status(
        &advance_request, &advance_reply);
    VD_CHECK("publication: native status preserves workspace phase",
             advance_reply.exit_code == ZCL_COMMAND_EXIT_OK &&
             strcmp(json_get_str(json_get(
                        &advance_reply.data, "status")),
                    "WORKSPACE_PUBLISHED") == 0);
    VD_CHECK("publication: native status reports exact release root",
             strcmp(json_get_str(json_get(
                        &advance_reply.data, "release_root")),
                    mapping_hex) == 0);
    zcl_hex_encode(passport_root, 32, mapping_hex);
    VD_CHECK("publication: native status reports exact Passport root",
             strcmp(json_get_str(json_get(
                        &advance_reply.data, "passport_root")),
                    mapping_hex) == 0);
    zcl_hex_encode(workspace_root, 32, mapping_hex);
    VD_CHECK("publication: native status reports exact workspace root",
             strcmp(json_get_str(json_get(
                        &advance_reply.data, "workspace_root")),
                    mapping_hex) == 0);
    VD_CHECK("publication: native status names P2P next step",
             strcmp(json_get_str(json_get(
                        &advance_reply.data, "next_command")),
                    "z23 discover search provider") == 0);
    zcl_command_reply_free(&advance_reply);
    json_free(&advance_input);
    memset(fixture.signer_secret, 0, sizeof(fixture.signer_secret));

    vd_write(dir, "src/main.c", "int main(void){return 1;}\n");
    v.proof_complete = false;
    struct vcs_devloop_anchor_result incomplete = {0};
    vcs_devloop_anchor_cycle(dir, &v, &incomplete);
    VD_CHECK("publication: incomplete proof still anchors",
             incomplete.status == VCS_DEVLOOP_ANCHOR_OK);
    VD_CHECK("publication: incomplete proof never queues",
             incomplete.publication_status == VCS_DEVLOOP_PUBLICATION_NONE);

    return failures;
}

/* ── test: fail-open when .zvcs/ cannot be created ─────────────────── */
static int t_fail_open(const char *dir)
{
    int failures = 0;

    vd_write(dir, "readme.txt", "hi\n");

    /* Block .zvcs/ from ever being created: put a regular file where the
     * directory needs to go, so vcs_object_store_init's mkdir() fails with
     * ENOTDIR (not EEXIST) and vcs_open() returns NULL. */
    char blocker[4096];
    snprintf(blocker, sizeof(blocker), "%s/.zvcs", dir);
    FILE *f = fopen(blocker, "wb");
    VD_CHECK("fail-open: blocker file created", f != NULL);
    if (f) fclose(f);

    struct vcs_devloop_verdict v = {0};
    v.verdict_status = 0;
    v.phase = "resident_commit";
    struct vcs_devloop_anchor_result ar = {0};
    vcs_devloop_anchor_cycle(dir, &v, &ar);
    VD_CHECK("fail-open: status ERROR (not a crash)",
             ar.status == VCS_DEVLOOP_ANCHOR_ERROR);
    VD_CHECK("fail-open: error message set", ar.error[0] != '\0');

    unlink(blocker);
    return failures;
}

static int t_accepted_work_ambiguity(const char *dir)
{
    int failures = 0;
    vd_write(dir, "src/main.c", "int main(void){return 0;}\n");
    uint8_t source_root[32];
    VD_CHECK("ambiguity: source tree captures",
             vcs_tree_capture_path(dir, source_root) == VCS_OK);
    struct vd_accepted_fixture first, second;
    const int64_t now = 1700000000;
    VD_CHECK("ambiguity: first accepted work stores",
             vd_accepted_fixture_create(
                 dir, source_root, now, 0x52, &first));
    VD_CHECK("ambiguity: distinct second accepted work stores",
             vd_accepted_fixture_create(
                 dir, source_root, now, 0x72, &second) &&
             memcmp(first.accepted.task_root,
                    second.accepted.task_root, 32) != 0);
    char ledger[4096];
    (void)snprintf(ledger, sizeof(ledger), "%s/ledger", dir);
    VD_CHECK("ambiguity: ledger directory creates",
             mkdir(ledger, 0700) == 0);
    (void)snprintf(ledger, sizeof(ledger), "%s/ledger/node.db", dir);
    struct node_db ndb = {0};
    VD_CHECK("ambiguity: ledger opens", node_db_open(&ndb, ledger));
    char source_hex[65];
    zcl_hex_encode(source_root, 32, source_hex);
    struct zcode_accepted_work_status accepted;
    struct zcl_result result = zcode_accepted_work_find(
        &ndb, dir, source_hex, now, true, &accepted);
    VD_CHECK("ambiguity: two accepted works for one source fail closed",
             !result.ok &&
             strcmp(result.message,
                    "accepted-work-source-ambiguous") == 0);
    node_db_close(&ndb);
    memset(first.signer_secret, 0, sizeof(first.signer_secret));
    memset(second.signer_secret, 0, sizeof(second.signer_secret));
    return failures;
}

/* ── test: sealed-path change is refused, and does not advance HEAD ── */
static int t_sealed_refusal(const char *dir)
{
    int failures = 0;

    vd_write(dir, ".zvcs/sealed_paths", "sealed/\n");
    vd_write(dir, "sealed/consensus.txt", "RULE=1\n");
    vd_write(dir, "readme.txt", "hi\n");

    struct vcs_devloop_verdict v = {0};
    v.verdict_status = 0;
    v.phase = "resident_commit";

    struct vcs_devloop_anchor_result ar1 = {0};
    vcs_devloop_anchor_cycle(dir, &v, &ar1);
    VD_CHECK("sealed: initial anchor pins OK",
             ar1.status == VCS_DEVLOOP_ANCHOR_OK);

    /* Edit the sealed file -> the next anchor is refused, not crashed. */
    vd_write(dir, "sealed/consensus.txt", "RULE=2\n");
    struct vcs_devloop_anchor_result ar2 = {0};
    vcs_devloop_anchor_cycle(dir, &v, &ar2);
    VD_CHECK("sealed: refusal surfaced",
             ar2.status == VCS_DEVLOOP_ANCHOR_REFUSED);
    VD_CHECK("sealed: refusal error set", ar2.error[0] != '\0');

    /* HEAD did not move: the refused cycle recorded nothing. */
    struct vcs_repo *r = vcs_open(dir);
    VD_CHECK("sealed: reopen", r != NULL);
    if (r) {
        uint8_t head[32];
        bool found = false;
        bool got_head = vcs_index_ref_get(vcs_repo_index(r), "HEAD", head,
                                          &found);
        VD_CHECK("sealed: HEAD readable", got_head && found);
        VD_CHECK("sealed: HEAD unchanged (refusal did not commit)",
                 got_head && found &&
                 memcmp(head, ar1.commit_id, 32) == 0);
        vcs_close(r);
    }

    return failures;
}

int test_vcs_devloop(void)
{
    printf("\n=== vcs_devloop: dev-loop auto-anchor glue ===\n");
    int failures = 0;

    failures += t_hex32();

    char dir[512];

    test_make_tmpdir(dir, sizeof(dir), "vcs_devloop", "ok");
    failures += t_anchor_ok(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_devloop", "deferred");
    failures += t_initial_anchor_deferred(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_devloop", "publication");
    failures += t_publication_enqueue(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_devloop", "ambiguity");
    failures += t_accepted_work_ambiguity(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_devloop", "failopen");
    failures += t_fail_open(dir);
    test_rm_rf_recursive(dir);

    test_make_tmpdir(dir, sizeof(dir), "vcs_devloop", "sealed");
    failures += t_sealed_refusal(dir);
    test_rm_rf_recursive(dir);

    printf("=== vcs_devloop complete: %d failure(s) ===\n", failures);
    return failures;
}
