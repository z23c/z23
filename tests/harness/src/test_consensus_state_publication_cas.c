/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: The publication compare-and-swap decision binds the three contained
 * evidence receipts (artifact admission, selected-chain, producer source) into
 * one ADMIT/typed-refusal record. Proves every mutual-binding refusal fires,
 * ADMIT only on full agreement, a pinned decision-digest vector, CAS frontier
 * staleness, durable record round-trip + tamper rejection, and run() guards. */

#define _GNU_SOURCE

#include "test/test_core.h"

#include "services/consensus_state_publication_cas.h"
#include "platform/time_compat.h"
#include "storage/consensus_state_bundle_codec.h"

#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#if !defined(_WIN32)

#define PCAS_COMMIT "0123456789abcdef0123456789abcdef01234567"

#define PCAS_CHECK(label, expr) do {                                       \
    printf("consensus_state_publication_cas: %s... ", (label));            \
    if (expr) printf("OK\n");                                             \
    else { printf("FAIL\n"); failures++; }                               \
} while (0)

static void fill(uint8_t *b, size_t n, uint8_t base)
{
    for (size_t i = 0; i < n; i++)
        b[i] = (uint8_t)(base + i);
}

/* A deterministic, self-consistent producer source receipt. */
static struct consensus_state_source_receipt make_receipt(int32_t height)
{
    struct consensus_state_source_receipt r;
    memset(&r, 0, sizeof(r));
    r.schema_version = CONSENSUS_STATE_SOURCE_RECEIPT_V2;
    r.source_clean = true;
    r.validation_profile = CONSENSUS_STATE_VALIDATION_FULL;
    r.fold_cursor = (int64_t)height + 1;
    fill(r.source_tree_root, 32, 0x11);
    fill(r.toolchain_digest, 32, 0x33);
    fill(r.build_inputs_digest, 32, 0x55);
    fill(r.chain_corpus_digest, 32, 0x77);
    consensus_state_source_epoch_digest(&r, r.source_epoch_digest);
    consensus_state_source_receipt_digest(&r, r.receipt_digest);
    return r;
}

/* A complete, self-bound manifest whose source_digest binds `r`. */
static struct consensus_state_bundle_manifest make_manifest(
    int32_t height, const struct consensus_state_source_receipt *r)
{
    struct consensus_state_bundle_manifest m;
    memset(&m, 0, sizeof(m));
    m.height = height;
    m.history_complete = true;
    m.source_clean = true;
    m.validation_profile = CONSENSUS_STATE_VALIDATION_FULL;
    m.activation_boundary = 0;
    m.sapling_frontier_height = height - 20;
    m.sprout_frontier_height = height - 30;
    m.source_fold_cursor = (int64_t)height + 1;
    m.utxo_count = 5;
    m.total_supply = 50;
    m.anchor_count = 6;
    m.nullifier_count = 7;
    fill(m.block_hash, 32, 0x01);
    fill(m.utxo_root, 32, 0x21);
    fill(m.anchor_digest, 32, 0x41);
    fill(m.sprout_frontier_root, 32, 0x61);
    fill(m.sapling_frontier_root, 32, 0x81);
    fill(m.nullifier_digest, 32, 0xA1);
    fill(m.proof_manifest_digest, 32, 0xC1);
    memcpy(m.source_digest, r->receipt_digest, 32);
    consensus_state_bundle_artifact_digest(&m, m.artifact_digest);
    return m;
}

/* Fully valid inputs that decide to ADMIT. */
static struct consensus_state_publication_cas_inputs make_inputs(void)
{
    static struct consensus_state_source_receipt r;
    r = make_receipt(100);
    struct consensus_state_publication_cas_inputs in;
    memset(&in, 0, sizeof(in));
    in.manifest = make_manifest(100, &r);
    memcpy(in.artifact_logical_digest, in.manifest.artifact_digest, 32);
    fill(in.artifact_receipt_digest, 32, 0xE1);
    in.chain_evidence_present = true;
    in.chain_bound_to_artifact = true;
    fill(in.chain_evidence_digest, 32, 0x09);
    in.source_receipt_present = true;
    in.source_receipt = r;
    in.target_lane = CONSENSUS_STATE_TARGET_LANE_CANONICAL;
    in.frontier_known = true;
    in.frontier_height = 120;
    fill(in.frontier_hash, 32, 0x02);
    return in;
}

/* Fresh ADMIT-shaped inputs whose source receipt, manifest and logical
 * artifact digest are all rebound to `r`. */
static struct consensus_state_publication_cas_inputs inputs_bound_to_receipt(
    const struct consensus_state_source_receipt *r)
{
    struct consensus_state_publication_cas_inputs in = make_inputs();
    in.source_receipt = *r;
    in.manifest = make_manifest(100, r);
    memcpy(in.artifact_logical_digest, in.manifest.artifact_digest, 32);
    return in;
}

static bool refuses_with(struct consensus_state_publication_cas_inputs in,
                         enum consensus_state_publication_refusal expected)
{
    struct consensus_state_publication_decision_record rec;
    consensus_state_publication_cas_decide(&in, &rec);
    return rec.decision == CONSENSUS_PUBLICATION_REFUSED &&
           rec.refusal == expected;
}

struct pcas_race_ctx {
    pthread_mutex_t lock;
    pthread_cond_t cv;
    bool a_entered;
    bool release_a;
    int dir_fd;
    const char *name;
    struct consensus_state_publication_decision_record a;
    struct zcl_result a_result;
};

static void pcas_race_after_temp_open(
    const struct consensus_state_publication_decision_record *record,
    void *opaque)
{
    struct pcas_race_ctx *ctx = opaque;
    if (!ctx || !record ||
        memcmp(record->decision_digest, ctx->a.decision_digest, 32) != 0)
        return;
    pthread_mutex_lock(&ctx->lock);
    ctx->a_entered = true;
    pthread_cond_broadcast(&ctx->cv);
    while (!ctx->release_a)
        pthread_cond_wait(&ctx->cv, &ctx->lock);
    pthread_mutex_unlock(&ctx->lock);
}

static void *pcas_race_writer_a(void *opaque)
{
    struct pcas_race_ctx *ctx = opaque;
    ctx->a_result = consensus_state_publication_cas_persist_for_test(
        ctx->dir_fd, ctx->name, &ctx->a);
    return NULL;
}

/* Block until writer A is parked inside its open temp file, releasing it
 * early when the interleave never happens within the deadline. */
static bool pcas_race_wait_for_temp_open(struct pcas_race_ctx *race)
{
    struct timespec deadline;
    platform_time_realtime_timespec(&deadline);
    deadline.tv_sec += 5;
    pthread_mutex_lock(&race->lock);
    int wait_rc = 0;
    while (!race->a_entered && wait_rc == 0)
        wait_rc = pthread_cond_timedwait(&race->cv, &race->lock, &deadline);
    bool interleave_ready = race->a_entered;
    if (!interleave_ready) {
        race->release_a = true;
        pthread_cond_broadcast(&race->cv);
    }
    pthread_mutex_unlock(&race->lock);
    return interleave_ready;
}

/* Release the parked writer A, join it, then reload whatever it published. */
static struct zcl_result pcas_race_finish_writer_a(
    struct pcas_race_ctx *race, const pthread_t *a_thread, bool thread_ok,
    struct consensus_state_publication_decision_record *loaded)
{
    if (thread_ok) {
        pthread_mutex_lock(&race->lock);
        race->release_a = true;
        pthread_cond_broadcast(&race->cv);
        pthread_mutex_unlock(&race->lock);
        (void)pthread_join(*a_thread, NULL);
    }
    consensus_state_publication_cas_test_set_after_temp_open_hook(NULL, NULL);
    return thread_ok && race->a_result.ok
        ? consensus_state_publication_cas_load(race->dir_fd, race->name,
                                               loaded)
        : race->a_result;
}

static bool pcas_no_temp_names(int dir_fd, const char *name)
{
    int scan_fd = dup(dir_fd);
    if (scan_fd < 0)
        return false;
    DIR *dir = fdopendir(scan_fd);
    if (!dir) {
        (void)close(scan_fd);
        return false;
    }
    char prefix[256];
    int n = snprintf(prefix, sizeof(prefix), "%s.tmp.", name);
    bool ok = n > 0 && (size_t)n < sizeof(prefix);
    struct dirent *de;
    while (ok && (de = readdir(dir)) != NULL) {
        if (strncmp(de->d_name, prefix, (size_t)n) == 0)
            ok = false;
    }
    closedir(dir);
    return ok;
}

/* The legacy codec remains self-consistent and decodable, but cannot earn
 * publication authority even when every other binding agrees. */
static int check_legacy_receipt_cannot_earn_authority(void)
{
    int failures = 0;
    struct consensus_state_source_receipt legacy = make_receipt(100);
    legacy.schema_version = CONSENSUS_STATE_SOURCE_RECEIPT_V1;
    memcpy(legacy.producer_commit, PCAS_COMMIT, 40);
    legacy.producer_commit[40] = '\0';
    consensus_state_source_epoch_digest(&legacy,
                                        legacy.source_epoch_digest);
    consensus_state_source_receipt_digest(&legacy, legacy.receipt_digest);
    struct consensus_state_publication_cas_inputs legacy_in =
        inputs_bound_to_receipt(&legacy);
    PCAS_CHECK("self-consistent legacy v1 receipt never ADMITs",
               refuses_with(
                   legacy_in,
                   CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MALFORMED));
    return failures;
}

/* V2 binds the 32-byte source identity, never optional GitHub trace
 * metadata, and the publication gate admits that self-consistent shape. */
static int check_v2_receipt_binds_source_identity(void)
{
    int failures = 0;
    struct consensus_state_source_receipt v2 = make_receipt(100);
    uint8_t v2_epoch[32], v2_receipt[32];
    memcpy(v2_epoch, v2.source_epoch_digest, 32);
    memcpy(v2_receipt, v2.receipt_digest, 32);
    snprintf(v2.producer_commit, sizeof(v2.producer_commit), "%s",
             PCAS_COMMIT);
    uint8_t traced_epoch[32], traced_receipt[32];
    consensus_state_source_epoch_digest(&v2, traced_epoch);
    consensus_state_source_receipt_digest(&v2, traced_receipt);
    PCAS_CHECK("v2 GitHub trace metadata is non-authoritative",
               memcmp(v2_epoch, traced_epoch, 32) == 0 &&
               memcmp(v2_receipt, traced_receipt, 32) == 0);
    struct consensus_state_publication_cas_inputs traced_in =
        inputs_bound_to_receipt(&v2);
    struct consensus_state_publication_decision_record traced_refusal;
    consensus_state_publication_cas_decide(&traced_in, &traced_refusal);
    PCAS_CHECK("v2 receipt rejects embedded Git trace metadata",
               traced_refusal.decision == CONSENSUS_PUBLICATION_REFUSED);
    v2.producer_commit[0] = '\0';
    struct consensus_state_publication_cas_inputs v2_in =
        inputs_bound_to_receipt(&v2);
    struct consensus_state_publication_decision_record v2_admit;
    consensus_state_publication_cas_decide(&v2_in, &v2_admit);
    PCAS_CHECK("self-consistent source-identity v2 receipt ADMITs",
               v2_admit.decision == CONSENSUS_PUBLICATION_ADMIT);
    return failures;
}

/* Happy path: all three receipts present and mutually binding. */
static int check_full_agreement_admits(
    struct consensus_state_publication_decision_record *admit)
{
    int failures = 0;
    struct consensus_state_publication_cas_inputs in = make_inputs();
    consensus_state_publication_cas_decide(&in, admit);
    PCAS_CHECK("full agreement ADMITs",
               admit->decision == CONSENSUS_PUBLICATION_ADMIT &&
               admit->refusal == CONSENSUS_PUBLICATION_REFUSAL_NONE);
    PCAS_CHECK("ADMIT binds bundle H/hash and frontier",
               admit->bundle_height == 100 &&
               admit->expected_frontier_height == 120 &&
               memcmp(admit->bundle_hash, in.manifest.block_hash, 32) == 0);

    /* Pinned canonical decision-digest vector. */
    uint8_t recomputed[32];
    PCAS_CHECK("decision digest recomputes to the record's stored value",
               consensus_state_publication_decision_digest(admit,
                                                           recomputed) &&
               memcmp(recomputed, admit->decision_digest, 32) == 0);
    char hex[65];
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        hex[i * 2] = hexd[(admit->decision_digest[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hexd[admit->decision_digest[i] & 0xF];
    }
    hex[64] = '\0';
    printf("consensus_state_publication_cas: ADMIT decision_digest=%s\n", hex);
    static const char PINNED[] =
        "8891fac78730575c9a1866ff0f396047d2825e8e5c96c7c2620999fe77d36b7d";
    PCAS_CHECK("ADMIT decision digest matches pinned vector",
               strcmp(hex, PINNED) == 0);
    return failures;
}

/* CAS staleness: current only at the exact bound frontier. */
static int check_cas_frontier_staleness(
    const struct consensus_state_publication_decision_record *admit,
    struct consensus_state_publication_decision_record *admit2)
{
    int failures = 0;
    struct consensus_state_publication_cas_inputs in = make_inputs();
    PCAS_CHECK("decision is current at its bound frontier",
               consensus_state_publication_cas_decision_is_current(
                   admit, 120, in.frontier_hash));
    uint8_t moved[32];
    fill(moved, 32, 0x03);
    PCAS_CHECK("decision is stale after the frontier moves (hash)",
               !consensus_state_publication_cas_decision_is_current(
                   admit, 120, moved));
    PCAS_CHECK("decision is stale after the frontier moves (height)",
               !consensus_state_publication_cas_decision_is_current(
                   admit, 121, in.frontier_hash));
    /* A re-run over a changed frontier yields a fresh, different digest. */
    struct consensus_state_publication_cas_inputs moved_in = make_inputs();
    moved_in.frontier_height = 121;
    consensus_state_publication_cas_decide(&moved_in, admit2);
    PCAS_CHECK("moved-frontier re-run produces a different decision digest",
               admit2->decision == CONSENSUS_PUBLICATION_ADMIT &&
               memcmp(admit2->decision_digest, admit->decision_digest, 32) != 0);
    return failures;
}

/* Every mutual-binding refusal fires, fail-closed and typed. */
static int check_mutual_binding_refusals(void)
{
    int failures = 0;
    struct consensus_state_publication_cas_inputs bad;

    bad = make_inputs();
    bad.target_lane = CONSENSUS_STATE_TARGET_LANE_UNKNOWN;
    PCAS_CHECK("unknown lane refuses",
               refuses_with(bad, CONSENSUS_PUBLICATION_REFUSAL_LANE_UNKNOWN));

    bad = make_inputs();
    bad.manifest.history_complete = false;
    consensus_state_bundle_artifact_digest(&bad.manifest,
                                           bad.manifest.artifact_digest);
    memcpy(bad.artifact_logical_digest, bad.manifest.artifact_digest, 32);
    PCAS_CHECK("incomplete manifest refuses",
               refuses_with(bad,
                            CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_MANIFEST));

    bad = make_inputs();
    bad.manifest.source_clean = false;
    consensus_state_bundle_artifact_digest(&bad.manifest,
                                           bad.manifest.artifact_digest);
    memcpy(bad.artifact_logical_digest, bad.manifest.artifact_digest, 32);
    PCAS_CHECK("capture-incomplete manifest refuses",
               refuses_with(bad,
                            CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_MANIFEST));

    bad = make_inputs();
    bad.artifact_logical_digest[0] ^= 1u;
    PCAS_CHECK("artifact logical/manifest mismatch refuses",
               refuses_with(
                   bad,
                   CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_DIGEST_MISMATCH));

    bad = make_inputs();
    bad.chain_bound_to_artifact = false;
    PCAS_CHECK("chain evidence not bound to artifact refuses",
               refuses_with(
                   bad,
                   CONSENSUS_PUBLICATION_REFUSAL_CHAIN_ARTIFACT_MISMATCH));

    bad = make_inputs();
    bad.chain_evidence_present = false;
    PCAS_CHECK("absent chain evidence refuses",
               refuses_with(
                   bad,
                   CONSENSUS_PUBLICATION_REFUSAL_CHAIN_ARTIFACT_MISMATCH));

    bad = make_inputs();
    bad.source_receipt_present = false;
    PCAS_CHECK("absent source receipt refuses",
               refuses_with(
                   bad,
                   CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MISSING));

    bad = make_inputs();
    bad.source_receipt.receipt_digest[0] ^= 1u; /* self-digest breaks */
    PCAS_CHECK("malformed source receipt refuses",
               refuses_with(
                   bad,
                   CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MALFORMED));

    bad = make_inputs();
    bad.source_receipt.source_clean = false;
    consensus_state_source_epoch_digest(
        &bad.source_receipt, bad.source_receipt.source_epoch_digest);
    consensus_state_source_receipt_digest(
        &bad.source_receipt, bad.source_receipt.receipt_digest);
    memcpy(bad.manifest.source_digest, bad.source_receipt.receipt_digest, 32);
    consensus_state_bundle_artifact_digest(&bad.manifest,
                                           bad.manifest.artifact_digest);
    memcpy(bad.artifact_logical_digest, bad.manifest.artifact_digest, 32);
    PCAS_CHECK("capture-incomplete source receipt refuses",
               refuses_with(
                   bad,
                   CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MALFORMED));

    bad = make_inputs();
    /* Rebind a DIFFERENT self-consistent receipt so the manifest no longer
     * carries this receipt's digest (source-epoch mismatch). */
    {
        struct consensus_state_source_receipt other = make_receipt(100);
        other.chain_corpus_digest[0] ^= 1u;
        consensus_state_source_epoch_digest(&other, other.source_epoch_digest);
        consensus_state_source_receipt_digest(&other, other.receipt_digest);
        bad.source_receipt = other;
    }
    PCAS_CHECK("source receipt not bound to artifact refuses",
               refuses_with(
                   bad,
                   CONSENSUS_PUBLICATION_REFUSAL_SOURCE_ARTIFACT_MISMATCH));

    bad = make_inputs();
    bad.frontier_known = false;
    PCAS_CHECK("unknown frontier refuses",
               refuses_with(bad,
                            CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_UNKNOWN));

    bad = make_inputs();
    bad.frontier_height = 99; /* below bundle height 100 */
    PCAS_CHECK("frontier behind bundle refuses",
               refuses_with(bad,
                            CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_BEHIND));

    bad = make_inputs();
    bad.frontier_height = 0;
    bad.checkpoint_authority_used = true;
    struct consensus_state_publication_decision_record bootstrap_rec;
    consensus_state_publication_cas_decide(&bad, &bootstrap_rec);
    PCAS_CHECK("checkpoint-authorized genesis frontier admits",
               bootstrap_rec.decision == CONSENSUS_PUBLICATION_ADMIT &&
               bootstrap_rec.refusal == CONSENSUS_PUBLICATION_REFUSAL_NONE &&
               bootstrap_rec.expected_frontier_height == 0);

    /* The ASSISTED above-checkpoint tier is the second below-frontier path: a
     * borrowed bundle whose evidence binds only the PoW location + shielded tip
     * admits with the durable frontier still below the bundle height. */
    bad = make_inputs();
    bad.frontier_height = 0; /* borrowed node has folded nothing below the seam */
    bad.assisted_authority_used = true;
    struct consensus_state_publication_decision_record assisted_rec;
    consensus_state_publication_cas_decide(&bad, &assisted_rec);
    PCAS_CHECK("assisted-authorized below-bundle frontier admits",
               assisted_rec.decision == CONSENSUS_PUBLICATION_ADMIT &&
               assisted_rec.refusal == CONSENSUS_PUBLICATION_REFUSAL_NONE);

    /* Neither authority flag → a below-bundle frontier still refuses. */
    bad = make_inputs();
    bad.frontier_height = 99;
    bad.checkpoint_authority_used = false;
    bad.assisted_authority_used = false;
    PCAS_CHECK("below-bundle frontier with no authority still refuses",
               refuses_with(bad,
                            CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_BEHIND));

    bad.frontier_known = false;
    PCAS_CHECK("checkpoint authority never admits an unknown frontier",
               refuses_with(bad,
                            CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_UNKNOWN));

    struct consensus_state_publication_decision_record null_rec;
    consensus_state_publication_cas_decide(NULL, &null_rec);
    PCAS_CHECK("null inputs refuse (null_input)",
               null_rec.decision == CONSENSUS_PUBLICATION_REFUSED &&
               null_rec.refusal == CONSENSUS_PUBLICATION_REFUSAL_NULL_INPUT);
    return failures;
}

/* Deterministically interleave A(open temp) -> B(publish/load) ->
 * A(publish/load). A shared <name>.tmp implementation makes A
 * overwrite or lose B's inode; unique temps make both writes
 * independently valid and leave the last completed writer A. */
static int check_concurrent_writer_race(
    int dir_fd,
    const struct consensus_state_publication_decision_record *admit,
    const struct consensus_state_publication_decision_record *admit2)
{
    int failures = 0;
    struct pcas_race_ctx race;
    memset(&race, 0, sizeof(race));
    pthread_mutex_init(&race.lock, NULL);
    pthread_cond_init(&race.cv, NULL);
    race.dir_fd = dir_fd;
    race.name = "race.rec";
    race.a = *admit;
    struct consensus_state_publication_decision_record b_rec = *admit2;
    consensus_state_publication_cas_test_set_after_temp_open_hook(
        pcas_race_after_temp_open, &race);
    pthread_t a_thread;
    bool thread_ok = pthread_create(&a_thread, NULL,
                                    pcas_race_writer_a, &race) == 0;
    bool interleave_ready = false;
    if (thread_ok)
        interleave_ready = pcas_race_wait_for_temp_open(&race);
    struct zcl_result b_result = interleave_ready
        ? consensus_state_publication_cas_persist_for_test(
              dir_fd, race.name, &b_rec)
        : ZCL_ERR(-1, "thread create failed");
    struct consensus_state_publication_decision_record race_loaded;
    struct zcl_result b_loaded = b_result.ok
        ? consensus_state_publication_cas_load(
              dir_fd, race.name, &race_loaded)
        : b_result;
    PCAS_CHECK("concurrent writer B publishes while A temp is open",
               interleave_ready && b_result.ok && b_loaded.ok &&
               memcmp(race_loaded.decision_digest,
                      b_rec.decision_digest, 32) == 0);
    struct zcl_result a_loaded = pcas_race_finish_writer_a(
        &race, &a_thread, thread_ok, &race_loaded);
    PCAS_CHECK("concurrent writer A completes without clobber race",
               thread_ok && race.a_result.ok && a_loaded.ok &&
               memcmp(race_loaded.decision_digest,
                      race.a.decision_digest, 32) == 0 &&
               pcas_no_temp_names(dir_fd, race.name));
    pthread_cond_destroy(&race.cv);
    pthread_mutex_destroy(&race.lock);
    (void)unlinkat(dir_fd, race.name, 0);
    return failures;
}

/* Durable record round-trip + tamper rejection. */
static int check_durable_record_roundtrip_and_race(
    const struct consensus_state_publication_decision_record *admit,
    const struct consensus_state_publication_decision_record *admit2)
{
    int failures = 0;
    char dir_template[PATH_MAX];
    char *dir = test_mkdtemp(dir_template, sizeof(dir_template), "zcl-pcas");
    PCAS_CHECK("fixture directory", dir != NULL);
    if (dir) {
        int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        PCAS_CHECK("directory descriptor", dir_fd >= 0);
        if (dir_fd >= 0) {
            /* Faithfully write the record by mirroring encode: use load's own
             * inverse is unavailable publicly, so drive persistence through the
             * public API is not exposed; instead verify load rejects garbage. */
            char path[600];
            snprintf(path, sizeof(path), "%s/decision.rec", dir);
            int wfd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            PCAS_CHECK("write a short/garbage record", wfd >= 0);
            if (wfd >= 0) {
                const char junk[] = "not-a-decision-record";
                ssize_t w = write(wfd, junk, sizeof(junk));
                (void)w;
                close(wfd);
            }
            struct consensus_state_publication_decision_record loaded;
            struct zcl_result lr = consensus_state_publication_cas_load(
                dir_fd, "decision.rec", &loaded);
            PCAS_CHECK("load rejects a malformed record", !lr.ok);

            failures += check_concurrent_writer_race(dir_fd, admit, admit2);
            close(dir_fd);
            (void)unlink(path);
        }
        (void)rmdir(dir);
    }
    return failures;
}

/* run() fail-closed guards (no process singleton in this unit test). */
static int check_run_fail_closed_guards(void)
{
    int failures = 0;
    struct consensus_state_publication_decision_record out;
    struct zcl_result rr = consensus_state_publication_cas_run(NULL, &out);
    PCAS_CHECK("run refuses a null request", !rr.ok);
    struct consensus_state_publication_cas_request req;
    memset(&req, 0, sizeof(req));
    req.target_lane = CONSENSUS_STATE_TARGET_LANE_CANONICAL;
    rr = consensus_state_publication_cas_run(&req, &out);
    PCAS_CHECK("run refuses a request with null members", !rr.ok);
    return failures;
}

/* ── mutation-gap coverage: names, CAS currency boundaries, wire codec ───── */

static const struct {
    int refusal;
    const char *name;
} pcas_refusal_names[] = {
    {CONSENSUS_PUBLICATION_REFUSAL_NONE, "none"},
    {CONSENSUS_PUBLICATION_REFUSAL_NULL_INPUT, "null_input"},
    {CONSENSUS_PUBLICATION_REFUSAL_LANE_UNKNOWN, "lane_unknown"},
    {CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_MANIFEST,
     "artifact_manifest_incomplete"},
    {CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_DIGEST_MISMATCH,
     "artifact_digest_mismatch"},
    {CONSENSUS_PUBLICATION_REFUSAL_CHAIN_ARTIFACT_MISMATCH,
     "chain_evidence_not_bound_to_artifact"},
    {CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MISSING,
     "source_receipt_missing"},
    {CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MALFORMED,
     "source_receipt_malformed"},
    {CONSENSUS_PUBLICATION_REFUSAL_SOURCE_ARTIFACT_MISMATCH,
     "source_receipt_not_bound_to_artifact"},
    {CONSENSUS_PUBLICATION_REFUSAL_PROFILE_NOT_SERVING,
     "validation_profile_not_serving"},
    {CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_UNKNOWN, "frontier_unknown"},
    {CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_BEHIND, "frontier_behind_bundle"},
};

/* Every enum value maps to its own stable string; unknown values fail
 * closed to the documented fallback. */
static int check_enum_names(void)
{
    int failures = 0;
    bool all_named = true;
    for (size_t i = 0; i < sizeof(pcas_refusal_names) /
                               sizeof(pcas_refusal_names[0]); i++) {
        const char *got = consensus_state_publication_refusal_name(
            (enum consensus_state_publication_refusal)
                pcas_refusal_names[i].refusal);
        if (!got || strcmp(got, pcas_refusal_names[i].name) != 0)
            all_named = false;
    }
    PCAS_CHECK("every refusal enum has its pinned name", all_named);
    const char *admit = consensus_state_publication_decision_name(
        CONSENSUS_PUBLICATION_ADMIT);
    const char *refused = consensus_state_publication_decision_name(
        CONSENSUS_PUBLICATION_REFUSED);
    const char *unk_dec = consensus_state_publication_decision_name(
        (enum consensus_state_publication_decision)77);
    const char *unk_ref = consensus_state_publication_refusal_name(
        (enum consensus_state_publication_refusal)999);
    PCAS_CHECK("decision names are ADMIT and REFUSED",
               admit && refused && strcmp(admit, "ADMIT") == 0 &&
               strcmp(refused, "REFUSED") == 0);
    PCAS_CHECK("an unknown decision fails closed to REFUSED",
               unk_dec && strcmp(unk_dec, "REFUSED") == 0);
    PCAS_CHECK("an unknown refusal is named unknown",
               unk_ref && strcmp(unk_ref, "unknown") == 0);
    return failures;
}

/* CAS currency: a decision is current only at the exact bound (height, hash)
 * pair; a one-byte hash difference anywhere, or a null input, is stale. */
static int check_is_current_boundaries(void)
{
    int failures = 0;
    struct consensus_state_publication_cas_inputs in = make_inputs();
    struct consensus_state_publication_decision_record rec;
    consensus_state_publication_cas_decide(&in, &rec);
    uint8_t hash[32];
    memcpy(hash, in.frontier_hash, 32);
    PCAS_CHECK("current at the exact bound frontier",
               consensus_state_publication_cas_decision_is_current(
                   &rec, 120, hash));
    hash[31] ^= 1u;
    PCAS_CHECK("last-byte hash difference is stale",
               !consensus_state_publication_cas_decision_is_current(
                   &rec, 120, hash));
    hash[31] ^= 1u;
    hash[0] ^= 1u;
    PCAS_CHECK("first-byte hash difference is stale",
               !consensus_state_publication_cas_decision_is_current(
                   &rec, 120, hash));
    hash[0] ^= 1u;
    PCAS_CHECK("height difference with equal hash is stale",
               !consensus_state_publication_cas_decision_is_current(
                   &rec, 119, hash));
    PCAS_CHECK("null record is never current",
               !consensus_state_publication_cas_decision_is_current(
                   NULL, 120, hash));
    PCAS_CHECK("null frontier hash is never current",
               !consensus_state_publication_cas_decision_is_current(
                   &rec, 120, NULL));
    return failures;
}

static int check_digest_null_guards(void)
{
    int failures = 0;
    struct consensus_state_publication_cas_inputs in = make_inputs();
    struct consensus_state_publication_decision_record rec;
    consensus_state_publication_cas_decide(&in, &rec);
    uint8_t out[32];
    memset(out, 0xEE, sizeof(out));
    PCAS_CHECK("digest of a null record is refused",
               !consensus_state_publication_decision_digest(NULL, out));
    PCAS_CHECK("digest into a null output is refused",
               !consensus_state_publication_decision_digest(&rec, NULL));
    PCAS_CHECK("a refused digest leaves the output untouched",
               out[0] == 0xEE && out[31] == 0xEE);
    return failures;
}

#define PCAS_WIRE 438u        /* 214 preimage + 32 digest + 192 reason */
#define PCAS_OFF_DIGEST 214u
#define PCAS_OFF_REASON 246u
#define PCAS_REASON_LEN 192u

static_assert(sizeof(((struct consensus_state_publication_decision_record *)0)
                         ->reason) == PCAS_REASON_LEN,
              "wire reason width");

struct pcas_fx {
    int dir_fd;
    struct consensus_state_publication_decision_record rec;
    uint8_t wire[PCAS_WIRE + 1];
    size_t wire_n;
};

static uint32_t pcas_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

/* A raw codec record with distinct multi-byte values in every field. The
 * decision/refusal pairing is synthetic: the codec is field-agnostic. */
static struct consensus_state_publication_decision_record pcas_wire_record(void)
{
    struct consensus_state_publication_decision_record r;
    memset(&r, 0, sizeof(r));
    r.decision = CONSENSUS_PUBLICATION_ADMIT;
    r.refusal = CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_BEHIND;
    fill(r.artifact_receipt_digest, 32, 0x10);
    fill(r.chain_evidence_digest, 32, 0x30);
    fill(r.source_receipt_digest, 32, 0x50);
    fill(r.source_epoch_digest, 32, 0x70);
    r.bundle_height = 0x01020304;
    fill(r.bundle_hash, 32, 0x90);
    r.validation_profile = 0x5A;
    r.target_lane = CONSENSUS_STATE_TARGET_LANE_CANONICAL;
    r.expected_frontier_height = 0x7A6B5C4D;
    fill(r.expected_frontier_hash, 32, 0xB0);
    memset(r.reason, 'R', sizeof(r.reason) - 1);
    return r;
}

static size_t pcas_slurp(int dir_fd, const char *name, uint8_t *buf,
                         size_t cap)
{
    int fd = openat(dir_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return 0;
    size_t off = 0;
    ssize_t r;
    while (off < cap && (r = read(fd, buf + off, cap - off)) > 0)
        off += (size_t)r;
    (void)close(fd);
    return off;
}

/* Replace `name` with exactly `buf[0..n)`. */
static bool pcas_spit(int dir_fd, const char *name, const uint8_t *buf,
                      size_t n)
{
    (void)unlinkat(dir_fd, name, 0);
    int fd = openat(dir_fd, name,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    size_t off = 0;
    ssize_t w = 0;
    while (off < n && (w = write(fd, buf + off, n - off)) > 0)
        off += (size_t)w;
    return close(fd) == 0 && off == n;
}

static bool pcas_wire_head_ok(const uint8_t *w,
    const struct consensus_state_publication_decision_record *r)
{
    return pcas_le32(w) == 1u && w[4] == (uint8_t)r->decision &&
           pcas_le32(w + 5) == (uint32_t)r->refusal &&
           memcmp(w + 9, r->artifact_receipt_digest, 32) == 0 &&
           memcmp(w + 41, r->chain_evidence_digest, 32) == 0 &&
           memcmp(w + 73, r->source_receipt_digest, 32) == 0 &&
           memcmp(w + 105, r->source_epoch_digest, 32) == 0 &&
           pcas_le32(w + 137) == (uint32_t)r->bundle_height &&
           memcmp(w + 141, r->bundle_hash, 32) == 0;
}

static bool pcas_wire_tail_ok(const uint8_t *w,
    const struct consensus_state_publication_decision_record *r)
{
    uint8_t digest[32];
    return consensus_state_publication_decision_digest(r, digest) &&
           w[173] == r->validation_profile &&
           pcas_le32(w + 174) == (uint32_t)r->target_lane &&
           pcas_le32(w + 178) == (uint32_t)r->expected_frontier_height &&
           memcmp(w + 182, r->expected_frontier_hash, 32) == 0 &&
           memcmp(w + PCAS_OFF_DIGEST, digest, 32) == 0 &&
           memcmp(w + PCAS_OFF_REASON, r->reason, PCAS_REASON_LEN) == 0;
}

/* The persisted file is exactly the documented little-endian layout. */
static int check_wire_layout(struct pcas_fx *fx)
{
    int failures = 0;
    struct zcl_result pr = consensus_state_publication_cas_persist_for_test(
        fx->dir_fd, "wire.rec", &fx->rec);
    PCAS_CHECK("persist writes the wire record", pr.ok);
    fx->wire_n = pcas_slurp(fx->dir_fd, "wire.rec", fx->wire, sizeof(fx->wire));
    PCAS_CHECK("wire record is exactly 438 bytes", fx->wire_n == PCAS_WIRE);
    if (fx->wire_n != PCAS_WIRE)
        return failures;
    PCAS_CHECK("wire preimage head fields sit at their offsets",
               pcas_wire_head_ok(fx->wire, &fx->rec));
    PCAS_CHECK("wire preimage tail, digest and reason sit at their offsets",
               pcas_wire_tail_ok(fx->wire, &fx->rec));
    PCAS_CHECK("wire height bytes are little-endian",
               fx->wire[137] == 0x04 && fx->wire[140] == 0x01 &&
               fx->wire[178] == 0x4D && fx->wire[181] == 0x7A);
    return failures;
}

static bool pcas_records_match(
    const struct consensus_state_publication_decision_record *a,
    const struct consensus_state_publication_decision_record *b)
{
    return a->decision == b->decision && a->refusal == b->refusal &&
           memcmp(a->artifact_receipt_digest, b->artifact_receipt_digest,
                  32) == 0 &&
           memcmp(a->chain_evidence_digest, b->chain_evidence_digest,
                  32) == 0 &&
           memcmp(a->source_receipt_digest, b->source_receipt_digest,
                  32) == 0 &&
           memcmp(a->source_epoch_digest, b->source_epoch_digest, 32) == 0 &&
           a->bundle_height == b->bundle_height &&
           memcmp(a->bundle_hash, b->bundle_hash, 32) == 0 &&
           a->validation_profile == b->validation_profile &&
           a->target_lane == b->target_lane &&
           a->expected_frontier_height == b->expected_frontier_height &&
           memcmp(a->expected_frontier_hash, b->expected_frontier_hash,
                  32) == 0 &&
           memcmp(a->reason, b->reason, sizeof(a->reason)) == 0;
}

static int check_load_roundtrip(struct pcas_fx *fx)
{
    int failures = 0;
    struct consensus_state_publication_decision_record out;
    memset(&out, 0xFF, sizeof(out));
    struct zcl_result lr =
        consensus_state_publication_cas_load(fx->dir_fd, "wire.rec", &out);
    PCAS_CHECK("load accepts the persisted record", lr.ok);
    PCAS_CHECK("load returns every field with its distinct value",
               lr.ok && pcas_records_match(&fx->rec, &out));
    uint8_t digest[32];
    PCAS_CHECK("loaded decision digest is the recomputed digest",
               lr.ok &&
               consensus_state_publication_decision_digest(&out, digest) &&
               memcmp(digest, out.decision_digest, 32) == 0 &&
               memcmp(digest, fx->wire + PCAS_OFF_DIGEST, 32) == 0);
    return failures;
}

static bool pcas_all_bytes(const void *p, size_t n, uint8_t v)
{
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++)
        if (b[i] != v)
            return false;
    return true;
}

/* Flip one bit in every digest-bound byte (preimage and stored digest):
 * each must fail digest verification (-55). */
static bool pcas_every_bound_byte_is_checked(struct pcas_fx *fx)
{
    uint8_t mod[PCAS_WIRE];
    for (size_t i = 0; i < PCAS_OFF_REASON; i++) {
        memcpy(mod, fx->wire, PCAS_WIRE);
        mod[i] ^= 0x01;
        if (!pcas_spit(fx->dir_fd, "flip.rec", mod, PCAS_WIRE))
            return false;
        struct consensus_state_publication_decision_record out;
        memset(&out, 0xFF, sizeof(out));
        struct zcl_result r = consensus_state_publication_cas_load(
            fx->dir_fd, "flip.rec", &out);
        if (r.ok || r.code != -55)
            return false;
    }
    return true;
}

static int check_tamper_rejection(struct pcas_fx *fx)
{
    int failures = 0;
    PCAS_CHECK("a bit flip in any digest-bound byte fails verification",
               pcas_every_bound_byte_is_checked(fx));
    uint8_t mod[PCAS_WIRE + 1];
    struct consensus_state_publication_decision_record out;

    /* A wrong version with an otherwise intact record (the digest does not
     * cover the version bytes it recomputes) must still be refused, and the
     * output must be left zeroed, not stale or partially decoded. */
    memcpy(mod, fx->wire, PCAS_WIRE);
    mod[0] ^= 0x01;
    memset(&out, 0xFF, sizeof(out));
    bool wrote = pcas_spit(fx->dir_fd, "ver.rec", mod, PCAS_WIRE);
    struct zcl_result vr =
        consensus_state_publication_cas_load(fx->dir_fd, "ver.rec", &out);
    PCAS_CHECK("unknown wire version is refused with a zeroed output",
               wrote && !vr.ok && vr.code == -55 &&
               pcas_all_bytes(&out, sizeof(out), 0));

    /* Reason is not digest-bound and may arrive unterminated: load must
     * terminate it in place without clobbering the byte before it. */
    memcpy(mod, fx->wire, PCAS_WIRE);
    memset(mod + PCAS_OFF_REASON, 'R', PCAS_REASON_LEN);
    wrote = pcas_spit(fx->dir_fd, "rsn.rec", mod, PCAS_WIRE);
    memset(&out, 0xFF, sizeof(out));
    struct zcl_result rr =
        consensus_state_publication_cas_load(fx->dir_fd, "rsn.rec", &out);
    PCAS_CHECK("load NUL-terminates an unterminated reason",
               wrote && rr.ok && out.reason[0] == 'R' &&
               out.reason[PCAS_REASON_LEN - 2] == 'R' &&
               out.reason[PCAS_REASON_LEN - 1] == '\0');

    memcpy(mod, fx->wire, PCAS_WIRE);
    wrote = pcas_spit(fx->dir_fd, "short.rec", mod, PCAS_WIRE - 1);
    struct zcl_result sr =
        consensus_state_publication_cas_load(fx->dir_fd, "short.rec", &out);
    PCAS_CHECK("a one-byte-short record is refused as a size mismatch",
               wrote && !sr.ok && sr.code == -54);
    mod[PCAS_WIRE] = 'Z';
    wrote = pcas_spit(fx->dir_fd, "long.rec", mod, PCAS_WIRE + 1);
    struct zcl_result lr =
        consensus_state_publication_cas_load(fx->dir_fd, "long.rec", &out);
    PCAS_CHECK("a one-byte-long record is refused as a size mismatch",
               wrote && !lr.ok && lr.code == -54);
    return failures;
}

static const char *pcas_long_name(char buf[260], size_t n)
{
    memset(buf, 'n', n);
    buf[n] = '\0';
    return buf;
}

/* Output-name validation: one normalized path component below 200 bytes. */
static int check_output_name_rules(struct pcas_fx *fx)
{
    int failures = 0;
    const struct consensus_state_publication_decision_record *rec = &fx->rec;
    char long199[260], long200[260];
    pcas_long_name(long199, 199);
    pcas_long_name(long200, 200);
    const char *bad[] = {NULL, "", ".", "..", "a/b", "/", long200};
    bool all_refused = true;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct zcl_result r = consensus_state_publication_cas_persist_for_test(
            fx->dir_fd, bad[i], rec);
        if (r.ok || r.code != -41)
            all_refused = false;
    }
    PCAS_CHECK("persist refuses every malformed output name with -41",
               all_refused);
    struct consensus_state_publication_decision_record out;
    PCAS_CHECK("a one-character name is accepted and reloads",
               consensus_state_publication_cas_persist_for_test(
                   fx->dir_fd, "a", rec).ok &&
               consensus_state_publication_cas_load(fx->dir_fd, "a", &out).ok);
    PCAS_CHECK("a 199-byte name is accepted and reloads",
               consensus_state_publication_cas_persist_for_test(
                   fx->dir_fd, long199, rec).ok &&
               consensus_state_publication_cas_load(
                   fx->dir_fd, long199, &out).ok);
    bool load_refused = true;
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        struct zcl_result r =
            consensus_state_publication_cas_load(fx->dir_fd, bad[i], &out);
        if (r.ok || r.code != -51)
            load_refused = false;
    }
    PCAS_CHECK("load refuses every malformed name with -51", load_refused);
    return failures;
}

/* Run `persist` and `load` with descriptor 0 pointing at /dev/null, so a
 * "descriptor is invalid" test of fd 0 touches nothing real. */
static bool pcas_codes_on_fd0(
    const struct consensus_state_publication_decision_record *rec,
    int *persist_code, int *load_code)
{
    int saved = dup(0);
    (void)close(0);
    int z = open("/dev/null", O_RDONLY | O_CLOEXEC);
    bool usable = z == 0;
    if (usable) {
        *persist_code = consensus_state_publication_cas_persist_for_test(
            0, "fd0.rec", rec).code;
        struct consensus_state_publication_decision_record out;
        *load_code =
            consensus_state_publication_cas_load(0, "fd0.rec", &out).code;
    }
    if (saved >= 0) {
        (void)dup2(saved, 0);
        (void)close(saved);
    } else if (z == 0) {
        (void)close(0);
    }
    if (z > 0)
        (void)close(z);
    return usable;
}

static int check_error_codes(struct pcas_fx *fx)
{
    int failures = 0;
    struct consensus_state_publication_decision_record out;
    PCAS_CHECK("persist refuses a negative directory fd with -40",
               consensus_state_publication_cas_persist_for_test(
                   -1, "x.rec", &fx->rec).code == -40);
    PCAS_CHECK("persist refuses a null record with -46",
               consensus_state_publication_cas_persist_for_test(
                   fx->dir_fd, "x.rec", NULL).code == -46);
    PCAS_CHECK("load refuses a null output with -50",
               consensus_state_publication_cas_load(
                   fx->dir_fd, "wire.rec", NULL).code == -50);
    PCAS_CHECK("load refuses a negative directory fd with -51",
               consensus_state_publication_cas_load(
                   -1, "wire.rec", &out).code == -51);
    PCAS_CHECK("load of a missing record reports the open failure (-52)",
               consensus_state_publication_cas_load(
                   fx->dir_fd, "absent.rec", &out).code == -52);
    PCAS_CHECK("load of a directory reports the read failure (-53)",
               mkdirat(fx->dir_fd, "isdir.rec", 0700) == 0 &&
               consensus_state_publication_cas_load(
                   fx->dir_fd, "isdir.rec", &out).code == -53);
    int pcode = 0, lcode = 0;
    bool usable = pcas_codes_on_fd0(&fx->rec, &pcode, &lcode);
    PCAS_CHECK("descriptor 0 is a usable fd, not an invalid one",
               !usable || (pcode == -43 && lcode == -52));
    return failures;
}

/* A failed publish before the rename removes its temp file and says -44. */
static bool pcas_has_prefix(int dir_fd, const char *prefix, uint64_t *nonce)
{
    int scan_fd = dup(dir_fd);
    DIR *dir = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!dir) {
        if (scan_fd >= 0)
            (void)close(scan_fd);
        return false;
    }
    rewinddir(dir); /* dup shares the directory offset with dir_fd */
    bool found = false;
    struct dirent *de;
    size_t n = strlen(prefix);
    while ((de = readdir(dir)) != NULL) {
        if (strncmp(de->d_name, prefix, n) != 0)
            continue;
        found = true;
        const char *dot = strrchr(de->d_name, '.');
        if (nonce && dot)
            *nonce = strtoull(dot + 1, NULL, 16);
    }
    closedir(dir);
    return found;
}

static int check_failed_publish_cleans_temp(struct pcas_fx *fx)
{
    int failures = 0;
    PCAS_CHECK("fixture target directory", mkdirat(fx->dir_fd, "blocked",
                                                   0700) == 0);
    struct zcl_result r = consensus_state_publication_cas_persist_for_test(
        fx->dir_fd, "blocked", &fx->rec);
    PCAS_CHECK("renaming onto a directory fails the publish with -44",
               !r.ok && r.code == -44);
    PCAS_CHECK("a failed publish leaves no temp file behind",
               !pcas_has_prefix(fx->dir_fd, "blocked.tmp.", NULL));
    (void)unlinkat(fx->dir_fd, "blocked", AT_REMOVEDIR);
    return failures;
}

struct pcas_probe {
    int dir_fd;
    uint64_t nonce;
};

static void pcas_probe_hook(
    const struct consensus_state_publication_decision_record *record,
    void *opaque)
{
    (void)record;
    struct pcas_probe *p = opaque;
    (void)pcas_has_prefix(p->dir_fd, "col.rec.tmp.", &p->nonce);
}

static bool pcas_precreate_temps(int dir_fd, uint64_t first, unsigned count)
{
    char nm[256];
    for (unsigned k = 0; k < count; k++) {
        snprintf(nm, sizeof(nm), "col.rec.tmp.%ld.%016llx", (long)getpid(),
                 (unsigned long long)(first + k));
        int fd = openat(dir_fd, nm, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                        0600);
        if (fd < 0)
            return false;
        (void)close(fd);
    }
    return true;
}

/* The temp-name retry loop gives up after exactly 1024 collisions: 1024
 * pre-existing names refuse the publish, 1023 still let the 1024th win. */
static int check_temp_collision_bound(struct pcas_fx *fx)
{
    int failures = 0;
    struct pcas_probe probe = {.dir_fd = fx->dir_fd, .nonce = 0};
    consensus_state_publication_cas_test_set_after_temp_open_hook(
        pcas_probe_hook, &probe);
    bool first = consensus_state_publication_cas_persist_for_test(
        fx->dir_fd, "col.rec", &fx->rec).ok;
    consensus_state_publication_cas_test_set_after_temp_open_hook(NULL, NULL);
    PCAS_CHECK("nonce probe publish succeeds", first);
    if (!first)
        return failures;
    uint64_t next = probe.nonce + 1; /* single writer: nonces are sequential */
    bool made = pcas_precreate_temps(fx->dir_fd, next, 1024);
    struct zcl_result exhausted =
        consensus_state_publication_cas_persist_for_test(
            fx->dir_fd, "col.rec", &fx->rec);
    PCAS_CHECK("1024 colliding temp names exhaust the retry budget (-43)",
               made && !exhausted.ok && exhausted.code == -43);
    made = pcas_precreate_temps(fx->dir_fd, next + 1024, 1023);
    struct consensus_state_publication_decision_record out;
    PCAS_CHECK("1023 colliding temp names still publish on the 1024th try",
               made && consensus_state_publication_cas_persist_for_test(
                           fx->dir_fd, "col.rec", &fx->rec).ok &&
               consensus_state_publication_cas_load(
                   fx->dir_fd, "col.rec", &out).ok);
    return failures;
}

static void pcas_purge_dir(int dir_fd)
{
    int scan_fd = dup(dir_fd);
    DIR *dir = scan_fd >= 0 ? fdopendir(scan_fd) : NULL;
    if (!dir) {
        if (scan_fd >= 0)
            (void)close(scan_fd);
        return;
    }
    rewinddir(dir);
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (unlinkat(dir_fd, de->d_name, 0) != 0)
            (void)unlinkat(dir_fd, de->d_name, AT_REMOVEDIR);
    }
    closedir(dir);
}

static int check_codec_with_fixture(struct pcas_fx *fx)
{
    int failures = 0;
    failures += check_wire_layout(fx);
    if (fx->wire_n != PCAS_WIRE)
        return failures;
    failures += check_load_roundtrip(fx);
    failures += check_tamper_rejection(fx);
    failures += check_output_name_rules(fx);
    failures += check_error_codes(fx);
    failures += check_failed_publish_cleans_temp(fx);
    failures += check_temp_collision_bound(fx);
    return failures;
}

static int check_codec_mutation_gaps(void)
{
    int failures = 0;
    struct pcas_fx fx;
    memset(&fx, 0, sizeof(fx));
    fx.dir_fd = -1;
    fx.rec = pcas_wire_record();
    char dir_template[PATH_MAX] = "";
    char *dir = test_mkdtemp(dir_template, sizeof(dir_template), "zcl-pcas-mg");
    PCAS_CHECK("mutation-gap fixture directory", dir != NULL);
    if (!dir)
        return failures;
    fx.dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    PCAS_CHECK("mutation-gap directory descriptor", fx.dir_fd >= 0);
    if (fx.dir_fd >= 0) {
        failures += check_codec_with_fixture(&fx);
        pcas_purge_dir(fx.dir_fd);
        (void)close(fx.dir_fd);
    }
    (void)rmdir(dir);
    return failures;
}

static int test_consensus_state_publication_cas_platform_arm(void)
{
    int failures = 0;
    struct consensus_state_publication_decision_record admit;
    struct consensus_state_publication_decision_record admit2;

    failures += check_legacy_receipt_cannot_earn_authority();
    failures += check_v2_receipt_binds_source_identity();
    failures += check_full_agreement_admits(&admit);
    failures += check_cas_frontier_staleness(&admit, &admit2);
    failures += check_mutual_binding_refusals();
    failures += check_durable_record_roundtrip_and_race(&admit, &admit2);
    failures += check_run_fail_closed_guards();
    failures += check_enum_names();
    failures += check_is_current_boundaries();
    failures += check_digest_null_guards();
    failures += check_codec_mutation_gaps();

    printf("consensus_state_publication_cas: %s\n",
           failures ? "FAILED" : "ALL PASSED");
    return failures;
}
#else  /* _WIN32 */
/* CAS fixture is written on the POSIX fdopendir/unlinkat directory-fd surface; the Windows production arm (consensus_state_publication_cas_windows.c) exists but this fixture cannot drive it. Skipped loudly rather than faked. */
static int test_consensus_state_publication_cas_platform_arm(void)
{
    printf("consensus_state_publication_cas: SKIP (Windows): cas fixture is written on the posix fdopendir/unlinkat directory-fd surface; the windows production arm (consensus_state_publication_cas_windows.c) exists but this fixture cannot drive it.\n");
    return 0;
}
#endif

int test_consensus_state_publication_cas(void)
{
    return test_consensus_state_publication_cas_platform_arm();
}
