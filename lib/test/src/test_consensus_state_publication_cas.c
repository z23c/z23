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

static int test_consensus_state_publication_cas_platform_arm(void)
{
    int failures = 0;

    /* The legacy codec remains self-consistent and decodable, but cannot earn
     * publication authority even when every other binding agrees. */
    struct consensus_state_source_receipt legacy = make_receipt(100);
    legacy.schema_version = CONSENSUS_STATE_SOURCE_RECEIPT_V1;
    memcpy(legacy.producer_commit, PCAS_COMMIT, 40);
    legacy.producer_commit[40] = '\0';
    consensus_state_source_epoch_digest(&legacy,
                                        legacy.source_epoch_digest);
    consensus_state_source_receipt_digest(&legacy, legacy.receipt_digest);
    struct consensus_state_publication_cas_inputs legacy_in = make_inputs();
    legacy_in.source_receipt = legacy;
    legacy_in.manifest = make_manifest(100, &legacy);
    memcpy(legacy_in.artifact_logical_digest,
           legacy_in.manifest.artifact_digest, 32);
    PCAS_CHECK("self-consistent legacy v1 receipt never ADMITs",
               refuses_with(
                   legacy_in,
                   CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MALFORMED));

    /* V2 binds the 32-byte source identity, never optional GitHub trace
     * metadata, and the publication gate admits that self-consistent shape. */
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
    struct consensus_state_publication_cas_inputs traced_in = make_inputs();
    traced_in.source_receipt = v2;
    traced_in.manifest = make_manifest(100, &v2);
    memcpy(traced_in.artifact_logical_digest,
           traced_in.manifest.artifact_digest, 32);
    struct consensus_state_publication_decision_record traced_refusal;
    consensus_state_publication_cas_decide(&traced_in, &traced_refusal);
    PCAS_CHECK("v2 receipt rejects embedded Git trace metadata",
               traced_refusal.decision == CONSENSUS_PUBLICATION_REFUSED);
    v2.producer_commit[0] = '\0';
    struct consensus_state_publication_cas_inputs v2_in = make_inputs();
    v2_in.source_receipt = v2;
    v2_in.manifest = make_manifest(100, &v2);
    memcpy(v2_in.artifact_logical_digest, v2_in.manifest.artifact_digest, 32);
    struct consensus_state_publication_decision_record v2_admit;
    consensus_state_publication_cas_decide(&v2_in, &v2_admit);
    PCAS_CHECK("self-consistent source-identity v2 receipt ADMITs",
               v2_admit.decision == CONSENSUS_PUBLICATION_ADMIT);

    /* Happy path: all three receipts present and mutually binding. */
    struct consensus_state_publication_cas_inputs in = make_inputs();
    struct consensus_state_publication_decision_record admit;
    consensus_state_publication_cas_decide(&in, &admit);
    PCAS_CHECK("full agreement ADMITs",
               admit.decision == CONSENSUS_PUBLICATION_ADMIT &&
               admit.refusal == CONSENSUS_PUBLICATION_REFUSAL_NONE);
    PCAS_CHECK("ADMIT binds bundle H/hash and frontier",
               admit.bundle_height == 100 &&
               admit.expected_frontier_height == 120 &&
               memcmp(admit.bundle_hash, in.manifest.block_hash, 32) == 0);

    /* Pinned canonical decision-digest vector. */
    uint8_t recomputed[32];
    PCAS_CHECK("decision digest recomputes to the record's stored value",
               consensus_state_publication_decision_digest(&admit,
                                                            recomputed) &&
               memcmp(recomputed, admit.decision_digest, 32) == 0);
    char hex[65];
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        hex[i * 2] = hexd[(admit.decision_digest[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hexd[admit.decision_digest[i] & 0xF];
    }
    hex[64] = '\0';
    printf("consensus_state_publication_cas: ADMIT decision_digest=%s\n", hex);
    static const char PINNED[] =
        "8891fac78730575c9a1866ff0f396047d2825e8e5c96c7c2620999fe77d36b7d";
    PCAS_CHECK("ADMIT decision digest matches pinned vector",
               strcmp(hex, PINNED) == 0);

    /* CAS staleness: current only at the exact bound frontier. */
    PCAS_CHECK("decision is current at its bound frontier",
               consensus_state_publication_cas_decision_is_current(
                   &admit, 120, in.frontier_hash));
    uint8_t moved[32];
    fill(moved, 32, 0x03);
    PCAS_CHECK("decision is stale after the frontier moves (hash)",
               !consensus_state_publication_cas_decision_is_current(
                   &admit, 120, moved));
    PCAS_CHECK("decision is stale after the frontier moves (height)",
               !consensus_state_publication_cas_decision_is_current(
                   &admit, 121, in.frontier_hash));
    /* A re-run over a changed frontier yields a fresh, different digest. */
    struct consensus_state_publication_cas_inputs moved_in = make_inputs();
    moved_in.frontier_height = 121;
    struct consensus_state_publication_decision_record admit2;
    consensus_state_publication_cas_decide(&moved_in, &admit2);
    PCAS_CHECK("moved-frontier re-run produces a different decision digest",
               admit2.decision == CONSENSUS_PUBLICATION_ADMIT &&
               memcmp(admit2.decision_digest, admit.decision_digest, 32) != 0);

    /* Every mutual-binding refusal fires, fail-closed and typed. */
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

    /* Durable record round-trip + tamper rejection. */
    char dir_template[] = "/tmp/zcl-pcas-XXXXXX";
    char *dir = mkdtemp(dir_template);
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

            /* Deterministically interleave A(open temp) -> B(publish/load) ->
             * A(publish/load). A shared <name>.tmp implementation makes A
             * overwrite or lose B's inode; unique temps make both writes
             * independently valid and leave the last completed writer A. */
            struct pcas_race_ctx race;
            memset(&race, 0, sizeof(race));
            pthread_mutex_init(&race.lock, NULL);
            pthread_cond_init(&race.cv, NULL);
            race.dir_fd = dir_fd;
            race.name = "race.rec";
            race.a = admit;
            struct consensus_state_publication_decision_record b_rec = admit2;
            consensus_state_publication_cas_test_set_after_temp_open_hook(
                pcas_race_after_temp_open, &race);
            pthread_t a_thread;
            bool thread_ok = pthread_create(&a_thread, NULL,
                                            pcas_race_writer_a, &race) == 0;
            bool interleave_ready = false;
            if (thread_ok) {
                struct timespec deadline;
                platform_time_realtime_timespec(&deadline);
                deadline.tv_sec += 5;
                pthread_mutex_lock(&race.lock);
                int wait_rc = 0;
                while (!race.a_entered && wait_rc == 0)
                    wait_rc = pthread_cond_timedwait(
                        &race.cv, &race.lock, &deadline);
                interleave_ready = race.a_entered;
                if (!interleave_ready) {
                    race.release_a = true;
                    pthread_cond_broadcast(&race.cv);
                }
                pthread_mutex_unlock(&race.lock);
            }
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
            if (thread_ok) {
                pthread_mutex_lock(&race.lock);
                race.release_a = true;
                pthread_cond_broadcast(&race.cv);
                pthread_mutex_unlock(&race.lock);
                (void)pthread_join(a_thread, NULL);
            }
            consensus_state_publication_cas_test_set_after_temp_open_hook(
                NULL, NULL);
            struct zcl_result a_loaded = thread_ok && race.a_result.ok
                ? consensus_state_publication_cas_load(
                      dir_fd, race.name, &race_loaded)
                : race.a_result;
            PCAS_CHECK("concurrent writer A completes without clobber race",
                       thread_ok && race.a_result.ok && a_loaded.ok &&
                       memcmp(race_loaded.decision_digest,
                              race.a.decision_digest, 32) == 0 &&
                       pcas_no_temp_names(dir_fd, race.name));
            pthread_cond_destroy(&race.cv);
            pthread_mutex_destroy(&race.lock);
            (void)unlinkat(dir_fd, race.name, 0);
            close(dir_fd);
            (void)unlink(path);
        }
        (void)rmdir(dir);
    }

    /* run() fail-closed guards (no process singleton in this unit test). */
    struct consensus_state_publication_decision_record out;
    struct zcl_result rr = consensus_state_publication_cas_run(NULL, &out);
    PCAS_CHECK("run refuses a null request", !rr.ok);
    struct consensus_state_publication_cas_request req;
    memset(&req, 0, sizeof(req));
    req.target_lane = CONSENSUS_STATE_TARGET_LANE_CANONICAL;
    rr = consensus_state_publication_cas_run(&req, &out);
    PCAS_CHECK("run refuses a request with null members", !rr.ok);

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
