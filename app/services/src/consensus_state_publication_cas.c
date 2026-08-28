/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Contained publication compare-and-swap for a consensus-state bundle:
 * bind the artifact-admission, selected-chain, and producer-source receipts into
 * one durable ADMIT/typed-refusal decision record. Never publishes/loads/mutates
 * node state; frontier-bound for CAS staleness. */

// one-result-type-ok:cas-total-decision-plus-durable-record-io — the decision,
// digest, staleness, and codec surfaces are TOTAL predicates over their inputs;
// only the fallible run/load I/O surfaces return struct zcl_result.

#include "services/consensus_state_publication_cas.h"

#include "config/consensus_state_snapshot_install.h"
#include "crypto/sha3.h"
#include "framework/condition.h"
#include "json/json.h"
#include "platform/file_sync.h"
#include "platform/file_compat.h"
#include "platform/fd_path.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/main_state.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CAS_SUBSYS "consensus_publication_cas"

/* Canonical wire layout of the decision record. Fixed-size, little-endian; the
 * decision digest is SHA3-256(domain || preimage). The reason string trails the
 * digest and is NOT digest-bound (human diagnostic only). */
#define CAS_PREIMAGE_SIZE 214u
#define CAS_WIRE_SIZE (CAS_PREIMAGE_SIZE + 32u + sizeof(((struct \
    consensus_state_publication_decision_record *)0)->reason))

/* ── latest-decision snapshot for dumpstate ──────────────────────────── */
static pthread_mutex_t g_latest_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_persist_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_latest_present;
static struct consensus_state_publication_decision_record g_latest;
static _Atomic uint64_t g_temp_nonce;

#ifdef ZCL_TESTING
static consensus_state_publication_cas_after_temp_open_hook
    g_after_temp_open_hook;
static void *g_after_temp_open_hook_ctx;

void consensus_state_publication_cas_test_set_after_temp_open_hook(
    consensus_state_publication_cas_after_temp_open_hook hook, void *ctx)
{
    g_after_temp_open_hook = hook;
    g_after_temp_open_hook_ctx = ctx;
}
#endif

const char *consensus_state_publication_decision_name(
    enum consensus_state_publication_decision decision)
{
    switch (decision) {
    case CONSENSUS_PUBLICATION_ADMIT: return "ADMIT";
    case CONSENSUS_PUBLICATION_REFUSED: return "REFUSED";
    }
    return "REFUSED";
}

const char *consensus_state_publication_refusal_name(
    enum consensus_state_publication_refusal refusal)
{
    switch (refusal) {
    case CONSENSUS_PUBLICATION_REFUSAL_NONE: return "none";
    case CONSENSUS_PUBLICATION_REFUSAL_NULL_INPUT: return "null_input";
    case CONSENSUS_PUBLICATION_REFUSAL_LANE_UNKNOWN: return "lane_unknown";
    case CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_MANIFEST:
        return "artifact_manifest_incomplete";
    case CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_DIGEST_MISMATCH:
        return "artifact_digest_mismatch";
    case CONSENSUS_PUBLICATION_REFUSAL_CHAIN_ARTIFACT_MISMATCH:
        return "chain_evidence_not_bound_to_artifact";
    case CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MISSING:
        return "source_receipt_missing";
    case CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MALFORMED:
        return "source_receipt_malformed";
    case CONSENSUS_PUBLICATION_REFUSAL_SOURCE_ARTIFACT_MISMATCH:
        return "source_receipt_not_bound_to_artifact";
    case CONSENSUS_PUBLICATION_REFUSAL_PROFILE_NOT_SERVING:
        return "validation_profile_not_serving";
    case CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_UNKNOWN:
        return "frontier_unknown";
    case CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_BEHIND:
        return "frontier_behind_bundle";
    }
    return "unknown";
}

static const char *lane_name(enum consensus_state_target_lane lane)
{
    switch (lane) {
    case CONSENSUS_STATE_TARGET_LANE_COPY_PROOF: return "copy-proof";
    case CONSENSUS_STATE_TARGET_LANE_DEV: return "dev";
    case CONSENSUS_STATE_TARGET_LANE_SOAK: return "soak";
    case CONSENSUS_STATE_TARGET_LANE_CANONICAL: return "canonical";
    case CONSENSUS_STATE_TARGET_LANE_UNKNOWN: return NULL;
    }
    return NULL;
}

static bool digest_nonzero(const uint8_t d[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= d[i];
    return any != 0;
}

/* Re-derive the manifest's own artifact digest and assert the complete/self-
 * bound shape the chain binder and exporter both require. Pure. */
static bool manifest_complete_self_bound(
    const struct consensus_state_bundle_manifest *m)
{
    if (!m || m->height < 0 || !m->history_complete || !m->source_clean ||
        m->activation_boundary != 0 || m->sprout_source_cursor != 0 ||
        m->sapling_source_cursor != 0 || m->nullifier_source_cursor != 0 ||
        m->source_fold_cursor != (int64_t)m->height + 1 ||
        m->sapling_frontier_height < 0 ||
        m->sapling_frontier_height > m->height ||
        (m->validation_profile != CONSENSUS_STATE_VALIDATION_FULL &&
         m->validation_profile != CONSENSUS_STATE_VALIDATION_CHECKPOINT_FOLD) ||
        !digest_nonzero(m->block_hash) ||
        !digest_nonzero(m->sapling_frontier_root) ||
        !digest_nonzero(m->proof_manifest_digest) ||
        !digest_nonzero(m->source_digest) ||
        !digest_nonzero(m->artifact_digest))
        return false;
    uint8_t computed[32];
    consensus_state_bundle_artifact_digest(m, computed);
    return memcmp(computed, m->artifact_digest, 32) == 0;
}

/* Publication-safe producer receipt: completed source capture, recomputed
 * epoch + receipt digests, a serving profile, and fold cursor bound to H+1.
 * Pure. */
static bool source_receipt_self_consistent(
    const struct consensus_state_source_receipt *r, int32_t bundle_height)
{
    /* V1 remains decodable for historical inspection, but its Git-SHA-1-
     * derived claim is never publication authority. */
    if (r->schema_version != CONSENSUS_STATE_SOURCE_RECEIPT_V2 ||
        !r->source_clean ||
        !digest_nonzero(r->source_epoch_digest) ||
        !digest_nonzero(r->source_tree_root) ||
        !digest_nonzero(r->toolchain_digest) ||
        !digest_nonzero(r->build_inputs_digest) ||
        !digest_nonzero(r->chain_corpus_digest) ||
        !digest_nonzero(r->receipt_digest) ||
        !consensus_state_source_receipt_commit_valid(
            r->schema_version, r->producer_commit,
            strnlen(r->producer_commit, sizeof(r->producer_commit))) ||
        r->validation_profile != CONSENSUS_STATE_VALIDATION_FULL ||
        r->fold_cursor != (int64_t)bundle_height + 1)
        return false;
    uint8_t epoch[32];
    uint8_t receipt[32];
    consensus_state_source_epoch_digest(r, epoch);
    consensus_state_source_receipt_digest(r, receipt);
    return memcmp(epoch, r->source_epoch_digest, 32) == 0 &&
           memcmp(receipt, r->receipt_digest, 32) == 0;
}

/* ── canonical serialization / digest ─────────────────────────────────── */
static size_t put_u8(uint8_t *b, size_t o, uint8_t v)
{
    b[o] = v;
    return o + 1;
}
static size_t put_u32(uint8_t *b, size_t o, uint32_t v)
{
    for (size_t i = 0; i < 4; i++)
        b[o + i] = (uint8_t)(v >> (8u * i));
    return o + 4;
}
static size_t put_bytes(uint8_t *b, size_t o, const uint8_t *src, size_t n)
{
    memcpy(b + o, src, n);
    return o + n;
}

static void serialize_preimage(
    const struct consensus_state_publication_decision_record *r,
    uint8_t buf[CAS_PREIMAGE_SIZE])
{
    size_t o = 0;
    o = put_u32(buf, o, 1u); /* wire version */
    o = put_u8(buf, o, (uint8_t)r->decision);
    o = put_u32(buf, o, (uint32_t)r->refusal);
    o = put_bytes(buf, o, r->artifact_receipt_digest, 32);
    o = put_bytes(buf, o, r->chain_evidence_digest, 32);
    o = put_bytes(buf, o, r->source_receipt_digest, 32);
    o = put_bytes(buf, o, r->source_epoch_digest, 32);
    o = put_u32(buf, o, (uint32_t)r->bundle_height);
    o = put_bytes(buf, o, r->bundle_hash, 32);
    o = put_u8(buf, o, r->validation_profile);
    o = put_u32(buf, o, (uint32_t)r->target_lane);
    o = put_u32(buf, o, (uint32_t)r->expected_frontier_height);
    o = put_bytes(buf, o, r->expected_frontier_hash, 32);
    /* o must equal CAS_PREIMAGE_SIZE by construction. */
    (void)o;
}

bool consensus_state_publication_decision_digest(
    const struct consensus_state_publication_decision_record *record,
    uint8_t out[32])
{
    if (!record || !out)
        return false; /* raw-return-ok:null-guard-total-predicate */
    uint8_t buf[CAS_PREIMAGE_SIZE];
    serialize_preimage(record, buf);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char domain[] =
        CONSENSUS_STATE_PUBLICATION_DECISION_SCHEMA "/decision";
    sha3_256_write(&ctx, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&ctx, buf, sizeof(buf));
    sha3_256_finalize(&ctx, out);
    return true;
}

bool consensus_state_publication_cas_decision_is_current(
    const struct consensus_state_publication_decision_record *record,
    int32_t current_frontier_height, const uint8_t current_frontier_hash[32])
{
    if (!record || !current_frontier_hash)
        return false; /* raw-return-ok:null-guard-total-predicate */
    return record->expected_frontier_height == current_frontier_height &&
           memcmp(record->expected_frontier_hash, current_frontier_hash,
                  32) == 0;
}

/* ── the pure decision ────────────────────────────────────────────────── */
static void set_reason(struct consensus_state_publication_decision_record *out,
                       const char *msg)
{
    snprintf(out->reason, sizeof(out->reason), "%s", msg);
}

static void finish(struct consensus_state_publication_decision_record *out,
                   enum consensus_state_publication_decision decision,
                   enum consensus_state_publication_refusal refusal,
                   const char *msg)
{
    out->decision = decision;
    out->refusal = refusal;
    set_reason(out, msg);
    (void)consensus_state_publication_decision_digest(out,
                                                      out->decision_digest);
}

void consensus_state_publication_cas_decide(
    const struct consensus_state_publication_cas_inputs *in,
    struct consensus_state_publication_decision_record *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!in) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_NULL_INPUT,
               "no inputs provided");
        return;
    }

    /* Copy every observed identity into the record up front so a refusal still
     * binds what it saw (and the frontier is always bound for staleness). */
    memcpy(out->artifact_receipt_digest, in->artifact_receipt_digest, 32);
    memcpy(out->chain_evidence_digest, in->chain_evidence_digest, 32);
    memcpy(out->source_receipt_digest, in->source_receipt.receipt_digest, 32);
    memcpy(out->source_epoch_digest, in->source_receipt.source_epoch_digest,
           32);
    out->bundle_height = in->manifest.height;
    memcpy(out->bundle_hash, in->manifest.block_hash, 32);
    out->validation_profile = in->manifest.validation_profile;
    out->target_lane = in->target_lane;
    out->expected_frontier_height = in->frontier_known ? in->frontier_height
                                                       : -1;
    if (in->frontier_known)
        memcpy(out->expected_frontier_hash, in->frontier_hash, 32);

    if (!lane_name(in->target_lane)) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_LANE_UNKNOWN,
               "target lane is not a canonical lane tag");
        return;
    }
    if (!manifest_complete_self_bound(&in->manifest)) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_MANIFEST,
               "artifact manifest is not complete/self-bound");
        return;
    }
    /* (a) same artifact logical identity: the opaque artifact's logical digest
     * must equal the manifest it exposed. */
    if (!digest_nonzero(in->artifact_logical_digest) ||
        memcmp(in->artifact_logical_digest, in->manifest.artifact_digest,
               32) != 0) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_ARTIFACT_DIGEST_MISMATCH,
               "artifact logical digest does not match its manifest");
        return;
    }
    /* (b) same artifact file/inode identity + lane: the selected-chain evidence
     * must be bound to THIS artifact receipt digest and target lane. */
    if (!in->chain_evidence_present || !in->chain_bound_to_artifact ||
        !digest_nonzero(in->chain_evidence_digest) ||
        !digest_nonzero(in->artifact_receipt_digest)) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_CHAIN_ARTIFACT_MISMATCH,
               "selected-chain evidence is absent or not bound to this "
               "artifact identity/lane");
        return;
    }
    /* (c) producer source receipt present + self-consistent. */
    if (!in->source_receipt_present) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MISSING,
               "producer source receipt is absent");
        return;
    }
    if (!source_receipt_self_consistent(&in->source_receipt,
                                        in->manifest.height)) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_SOURCE_RECEIPT_MALFORMED,
               "producer source receipt is malformed, capture-incomplete, "
               "non-serving, or its fold cursor is not bound to H+1");
        return;
    }
    /* same source epoch: the receipt embedded in the artifact (manifest
     * source_digest == source receipt digest) must be exactly this receipt. */
    if (memcmp(in->source_receipt.receipt_digest, in->manifest.source_digest,
               32) != 0) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_SOURCE_ARTIFACT_MISMATCH,
               "source receipt digest does not equal the artifact's bound "
               "source digest");
        return;
    }
    /* Canonical publication is FULL-profile only; a checkpoint-fold state is
     * non-serving evidence. Manifest and receipt must agree. */
    if (in->manifest.validation_profile != CONSENSUS_STATE_VALIDATION_FULL ||
        in->source_receipt.validation_profile !=
            CONSENSUS_STATE_VALIDATION_FULL) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_PROFILE_NOT_SERVING,
               "validation profile is not FULL (non-serving state)");
        return;
    }
    /* CAS frontier binding: ordinary state replacement may not move ahead of
     * durable H*. Two headers-first paths are different: their opaque chain-
     * evidence digest already binds the PoW authority and proves the selected
     * header while the current frontier is still below the bundle —
     *   (a) the compiled-checkpoint path (checkpoint_authority_used), and
     *   (b) the ASSISTED above-checkpoint tier (assisted_authority_used): the
     *       bundle LOCATION + shielded TIP root are PoW-bound in the evidence
     *       even though the CONTENT below the seam is borrowed and the install
     *       lands at the non-sovereign RELEASE_ASSISTED tier.
     * Keep unknown frontiers fail-closed; permit a known, stable below-bundle
     * frontier only when one of those evidence flags is present. */
    if (!in->frontier_known) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_UNKNOWN,
               "current durable frontier could not be captured");
        return;
    }
    if (in->frontier_height < in->manifest.height &&
        !in->checkpoint_authority_used && !in->assisted_authority_used) {
        finish(out, CONSENSUS_PUBLICATION_REFUSED,
               CONSENSUS_PUBLICATION_REFUSAL_FRONTIER_BEHIND,
               "bundle height exceeds the durable node frontier");
        return;
    }
    finish(out, CONSENSUS_PUBLICATION_ADMIT,
           CONSENSUS_PUBLICATION_REFUSAL_NONE,
           "all evidence present and mutually binding");
}

/* ── durable record I/O (FULL durability, contained) ──────────────────── */
static bool valid_output_name(const char *name)
{
    if (!name || !name[0])
        return false;
    size_t n = strnlen(name, 256);
    if (n == 0 || n >= 200)
        return false;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return false;
    if (strchr(name, '/'))
        return false;
    return true;
}

static void encode_record(
    const struct consensus_state_publication_decision_record *r,
    uint8_t buf[CAS_WIRE_SIZE])
{
    uint8_t preimage[CAS_PREIMAGE_SIZE];
    serialize_preimage(r, preimage);
    memcpy(buf, preimage, sizeof(preimage));
    uint8_t digest[32];
    (void)consensus_state_publication_decision_digest(r, digest);
    memcpy(buf + CAS_PREIMAGE_SIZE, digest, 32);
    memcpy(buf + CAS_PREIMAGE_SIZE + 32, r->reason, sizeof(r->reason));
}

static size_t get_u32(const uint8_t *b, size_t o, uint32_t *v)
{
    uint32_t x = 0;
    for (size_t i = 0; i < 4; i++)
        x |= (uint32_t)b[o + i] << (8u * i);
    *v = x;
    return o + 4;
}

static bool decode_record(
    const uint8_t buf[CAS_WIRE_SIZE],
    struct consensus_state_publication_decision_record *r)
{
    memset(r, 0, sizeof(*r));
    size_t o = 0;
    uint32_t version = 0;
    o = get_u32(buf, o, &version);
    if (version != 1u)
        return false; /* raw-return-ok:unknown-record-version */
    r->decision = (enum consensus_state_publication_decision)buf[o];
    o += 1;
    uint32_t refusal = 0;
    o = get_u32(buf, o, &refusal);
    r->refusal = (enum consensus_state_publication_refusal)refusal;
    memcpy(r->artifact_receipt_digest, buf + o, 32); o += 32;
    memcpy(r->chain_evidence_digest, buf + o, 32); o += 32;
    memcpy(r->source_receipt_digest, buf + o, 32); o += 32;
    memcpy(r->source_epoch_digest, buf + o, 32); o += 32;
    uint32_t bh = 0;
    o = get_u32(buf, o, &bh);
    r->bundle_height = (int32_t)bh;
    memcpy(r->bundle_hash, buf + o, 32); o += 32;
    r->validation_profile = buf[o]; o += 1;
    uint32_t lane = 0;
    o = get_u32(buf, o, &lane);
    r->target_lane = (enum consensus_state_target_lane)lane;
    uint32_t fh = 0;
    o = get_u32(buf, o, &fh);
    r->expected_frontier_height = (int32_t)fh;
    memcpy(r->expected_frontier_hash, buf + o, 32); o += 32;
    /* o == CAS_PREIMAGE_SIZE now; recompute + verify the stored digest. */
    uint8_t computed[32];
    if (!consensus_state_publication_decision_digest(r, computed) ||
        memcmp(computed, buf + CAS_PREIMAGE_SIZE, 32) != 0)
        return false; /* raw-return-ok:decision-digest-mismatch-tamper */
    memcpy(r->decision_digest, computed, 32);
    memcpy(r->reason, buf + CAS_PREIMAGE_SIZE + 32, sizeof(r->reason));
    r->reason[sizeof(r->reason) - 1] = '\0';
    return true;
}

static bool write_all(int fd, const uint8_t *buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        return false; /* raw-return-ok:short-write-reported-by-caller */
    }
    return true;
}

static bool verify_exact_wire_at(int dir_fd, const char *name,
                                 const uint8_t expected[CAS_WIRE_SIZE])
{
#if defined(_WIN32)
    char path[4096];
    if (!platform_dirfd_child_path(path, sizeof(path), dir_fd, name))
        return false;
    int fd = platform_file_open_nofollow(path, O_RDONLY | O_CLOEXEC, 0);
#else
    int fd = openat(dir_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
#endif
    if (fd < 0)
        return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
              st.st_size == (off_t)CAS_WIRE_SIZE;
    uint8_t actual[CAS_WIRE_SIZE];
    size_t off = 0;
    while (ok && off < sizeof(actual)) {
        ssize_t n = read(fd, actual + off, sizeof(actual) - off);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        ok = false;
    }
    if (close(fd) != 0)
        ok = false;
    return ok && off == sizeof(actual) &&
           memcmp(actual, expected, sizeof(actual)) == 0;
}

static struct zcl_result persist_record(
    int dir_fd, const char *name,
    const struct consensus_state_publication_decision_record *record)
{
    if (dir_fd < 0)
        return ZCL_ERR(-40, "cas persist: invalid output directory fd");
    if (!valid_output_name(name))
        return ZCL_ERR(-41,
                       "cas persist: output_name must be one normalized "
                       "path component");
    uint8_t wire[CAS_WIRE_SIZE];
    encode_record(record, wire);

    /* A shared <name>.tmp lets concurrent writers truncate/write the same
     * inode. Give every attempt an exclusive directory-local temp instead. */
    char tmp[256];
#if defined(_WIN32)
    char tmp_path[4096];
    char destination_path[4096];
    if (!platform_dirfd_child_path(destination_path,
                                   sizeof(destination_path), dir_fd, name))
        return ZCL_ERR(-42, "cas persist: output directory unavailable");
#endif
    int fd = -1;
    for (unsigned attempt = 0; attempt < 1024; attempt++) {
        uint64_t nonce = atomic_fetch_add_explicit(
            &g_temp_nonce, 1, memory_order_relaxed);
        int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld.%016llx", name,
                         (long)getpid(), (unsigned long long)nonce);
        if (n <= 0 || (size_t)n >= sizeof(tmp))
            return ZCL_ERR(-42, "cas persist: temp name overflow");
#if defined(_WIN32)
        if (!platform_dirfd_child_path(tmp_path, sizeof(tmp_path), dir_fd,
                                       tmp))
            break;
        fd = platform_file_open_nofollow(
            tmp_path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0400);
#else
        fd = openat(dir_fd, tmp,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0400);
#endif
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            break;
    }
    if (fd < 0)
        return ZCL_ERR(-43, "cas persist: openat temp failed: %s",
                       strerror(errno));
#ifdef ZCL_TESTING
    if (g_after_temp_open_hook)
        g_after_temp_open_hook(record, g_after_temp_open_hook_ctx);
#endif
    bool ok = write_all(fd, wire, sizeof(wire));
    if (ok && platform_data_sync(fd) != 0) {
        ok = false;
        LOG_WARN(CAS_SUBSYS, "data sync temp failed: %s", strerror(errno));
    }
    if (close(fd) != 0) {
        ok = false;
        LOG_WARN(CAS_SUBSYS, "close temp failed: %s", strerror(errno));
    }
    bool renamed = false;
#if defined(_WIN32)
    if (ok && platform_file_replace_atomic(tmp_path, destination_path) != 0) {
#else
    if (ok && renameat(dir_fd, tmp, dir_fd, name) != 0) {
#endif
        ok = false;
        LOG_WARN(CAS_SUBSYS, "renameat into place failed: %s",
                 strerror(errno));
    } else if (ok) {
        renamed = true;
    }
#if !defined(_WIN32)
    if (ok && fsync(dir_fd) != 0) {
        ok = false;
        LOG_WARN(CAS_SUBSYS, "directory fsync failed: %s", strerror(errno));
    }
#endif
    if (ok && !verify_exact_wire_at(dir_fd, name, wire)) {
        ok = false;
        LOG_WARN(CAS_SUBSYS, "published record verification failed");
    }
    if (!ok) {
        if (!renamed) {
#if defined(_WIN32)
            (void)unlink(tmp_path);
#else
            (void)unlinkat(dir_fd, tmp, 0);
            (void)fsync(dir_fd);
#endif
        }
        /* After rename, durability may be indeterminate. Never unlink by name:
         * a concurrent writer may already own it. Retain the self-verifying
         * record and require the caller to inspect/retry. */
        if (renamed)
            return ZCL_ERR(-45, "cas persist: record may be committed; "
                                "durability/identity verification failed");
        return ZCL_ERR(-44, "cas persist: durable write failed");
    }
    return ZCL_OK;
}

#ifdef ZCL_TESTING
struct zcl_result consensus_state_publication_cas_persist_for_test(
    int dir_fd, const char *name,
    const struct consensus_state_publication_decision_record *record)
{
    if (!record)
        return ZCL_ERR(-46, "cas persist test: null record");
    return persist_record(dir_fd, name, record);
}
#endif

struct zcl_result consensus_state_publication_cas_load(
    int dir_fd, const char *name,
    struct consensus_state_publication_decision_record *out_record)
{
    if (!out_record)
        return ZCL_ERR(-50, "cas load: null out");
    if (dir_fd < 0 || !valid_output_name(name))
        return ZCL_ERR(-51, "cas load: invalid fd/name");
#if defined(_WIN32)
    char path[4096];
    if (!platform_dirfd_child_path(path, sizeof(path), dir_fd, name))
        return ZCL_ERR(-52, "cas load: directory path unavailable");
    int fd = platform_file_open_nofollow(path, O_RDONLY | O_CLOEXEC, 0);
#else
    int fd = openat(dir_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
#endif
    if (fd < 0)
        return ZCL_ERR(-52, "cas load: openat failed: %s", strerror(errno));
    uint8_t wire[CAS_WIRE_SIZE + 1];
    size_t off = 0;
    bool read_ok = true;
    while (off < sizeof(wire)) {
        ssize_t r = read(fd, wire + off, sizeof(wire) - off);
        if (r > 0) {
            off += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            read_ok = false;
        break;
    }
    (void)close(fd);
    if (!read_ok)
        return ZCL_ERR(-53, "cas load: read failed");
    if (off != CAS_WIRE_SIZE)
        return ZCL_ERR(-54, "cas load: record size mismatch (%zu bytes)", off);
    if (!decode_record(wire, out_record))
        return ZCL_ERR(-55, "cas load: record failed digest verification");
    return ZCL_OK;
}

static void store_latest(
    const struct consensus_state_publication_decision_record *record)
{
    pthread_mutex_lock(&g_latest_lock);
    g_latest = *record;
    g_latest_present = true;
    pthread_mutex_unlock(&g_latest_lock);
}

struct zcl_result consensus_state_publication_cas_run(
    const struct consensus_state_publication_cas_request *request,
    struct consensus_state_publication_decision_record *out_record)
{
    struct consensus_state_publication_decision_record local;
    struct consensus_state_publication_decision_record *rec =
        out_record ? out_record : &local;
    memset(rec, 0, sizeof(*rec));

    if (!request || !request->main || !request->artifact ||
        !request->chain_evidence || !request->source_receipt)
        return ZCL_ERR(-60, "cas run: null request member");
    if (!lane_name(request->target_lane))
        return ZCL_ERR(-61, "cas run: target lane is not canonical");
    /* Process-singleton authority, same contract as chain-evidence build: the
     * frontier is read from the open reducer/progress store, not an ad-hoc
     * copy context. */
    if (condition_engine_main_state() != request->main ||
        !progress_store_db())
        return ZCL_ERR(-62, "cas run: request is not the open process "
                            "singleton");

    struct consensus_state_publication_cas_inputs in;
    memset(&in, 0, sizeof(in));
    in.target_lane = request->target_lane;
    in.source_receipt_present = true;
    in.source_receipt = *request->source_receipt;

    /* (a) artifact admission evidence: revalidate the pinned file, then copy
     * its manifest + logical + receipt (file/inode) identities. */
    if (!consensus_state_artifact_evidence_revalidate(request->artifact))
        return ZCL_ERR(-63, "cas run: artifact evidence failed revalidation");
    if (!consensus_state_artifact_evidence_manifest_copy(
            request->artifact, &in.manifest) ||
        !consensus_state_artifact_evidence_digest(
            request->artifact, in.artifact_logical_digest) ||
        !consensus_state_artifact_evidence_receipt_digest(
            request->artifact, in.artifact_receipt_digest))
        return ZCL_ERR(-64, "cas run: artifact evidence is stale");

    /* (b) selected-chain evidence: bind it to THIS artifact + lane and copy
     * its opaque digest. */
    in.chain_evidence_present = true;
    in.chain_bound_to_artifact = consensus_state_chain_evidence_matches_artifact(
        request->chain_evidence, request->artifact, request->target_lane);
    in.checkpoint_authority_used =
        consensus_state_chain_evidence_used_checkpoint_authority(
            request->chain_evidence);
    in.assisted_authority_used =
        consensus_state_chain_evidence_used_assisted_authority(
            request->chain_evidence);
    if (!consensus_state_chain_evidence_digest(request->chain_evidence,
                                               in.chain_evidence_digest))
        return ZCL_ERR(-65, "cas run: chain evidence digest unavailable");

    /* Capture the current durable frontier for the CAS binding. */
    int32_t fh = -1;
    uint8_t fhash[32] = {0};
    if (consensus_state_publication_cas_capture_frontier(&fh, fhash)) {
        in.frontier_known = true;
        in.frontier_height = fh;
        memcpy(in.frontier_hash, fhash, 32);
    }

    consensus_state_publication_cas_decide(&in, rec);

    /* Re-check the pinned artifact was not swapped during the decision. */
    uint8_t final_receipt[32];
    if (!consensus_state_artifact_evidence_receipt_digest(
            request->artifact, final_receipt) ||
        memcmp(final_receipt, in.artifact_receipt_digest, 32) != 0)
        return ZCL_ERR(-66,
                       "cas run: artifact changed during decision capture");

    /* Order persistence and the process-local latest projection together. A
     * slower writer must not publish an older in-memory snapshot after a newer
     * record has reached disk. Cross-process writers remain ordered by their
     * atomic renames and exact reopen verification. */
    pthread_mutex_lock(&g_persist_lock);
    struct zcl_result persisted =
        persist_record(request->output_dir_fd, request->output_name, rec);
    if (persisted.ok)
        store_latest(rec);
    pthread_mutex_unlock(&g_persist_lock);
    if (!persisted.ok)
        return persisted;
    return ZCL_OK;
}

/* ── dumpstate surface ────────────────────────────────────────────────── */
static void push_hex32(struct json_value *out, const char *key,
                       const uint8_t d[32])
{
    static const char hexd[] = "0123456789abcdef";
    char hex[65];
    for (size_t i = 0; i < 32; i++) {
        hex[i * 2] = hexd[(d[i] >> 4) & 0xF];
        hex[i * 2 + 1] = hexd[d[i] & 0xF];
    }
    hex[64] = '\0';
    json_push_kv_str(out, key, hex);
}

bool consensus_state_publication_cas_dump_state_json(struct json_value *out,
                                                     const char *key)
{
    (void)key;
    if (!out)
        return false; /* raw-return-ok:null-guard-total-predicate */
    json_set_object(out);

    struct consensus_state_publication_decision_record snap;
    bool present;
    pthread_mutex_lock(&g_latest_lock);
    present = g_latest_present;
    if (present)
        snap = g_latest;
    pthread_mutex_unlock(&g_latest_lock);

    json_push_kv_bool(out, "has_decision", present);
    if (!present)
        return true;

    json_push_kv_str(out, "decision",
                     consensus_state_publication_decision_name(snap.decision));
    json_push_kv_bool(out, "admit",
                      snap.decision == CONSENSUS_PUBLICATION_ADMIT);
    json_push_kv_str(out, "refusal",
                     consensus_state_publication_refusal_name(snap.refusal));
    json_push_kv_str(out, "reason", snap.reason);
    const char *lane = lane_name(snap.target_lane);
    json_push_kv_str(out, "target_lane", lane ? lane : "unknown");
    json_push_kv_int(out, "bundle_height", (int64_t)snap.bundle_height);
    json_push_kv_int(out, "validation_profile",
                     (int64_t)snap.validation_profile);
    json_push_kv_int(out, "expected_frontier_height",
                     (int64_t)snap.expected_frontier_height);
    push_hex32(out, "bundle_hash", snap.bundle_hash);
    push_hex32(out, "expected_frontier_hash", snap.expected_frontier_hash);
    push_hex32(out, "artifact_receipt_digest", snap.artifact_receipt_digest);
    push_hex32(out, "chain_evidence_digest", snap.chain_evidence_digest);
    push_hex32(out, "source_receipt_digest", snap.source_receipt_digest);
    push_hex32(out, "source_epoch_digest", snap.source_epoch_digest);
    push_hex32(out, "decision_digest", snap.decision_digest);
    return true;
}
