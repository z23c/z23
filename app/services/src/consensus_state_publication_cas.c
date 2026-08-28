/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Contained publication compare-and-swap for a consensus-state bundle:
 * bind the artifact-admission, selected-chain, and producer-source receipts into
 * one durable ADMIT/typed-refusal decision record. Never publishes/loads/mutates
 * node state; frontier-bound for CAS staleness. The pure decision itself lives
 * in consensus_state_publication_decide.c (E1 file-size split). */

// one-result-type-ok:cas-total-decision-plus-durable-record-io — the digest,
// staleness, and codec surfaces are TOTAL predicates over their inputs;
// only the fallible run/load I/O surfaces return struct zcl_result.

#include "services/consensus_state_publication_cas.h"

#include "consensus_state_publication_cas_internal.h"

#include "config/consensus_state_snapshot_install.h"
#include "crypto/sha3.h"
#include "framework/condition.h"
#include "json/json.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include "platform/file_sync.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define CAS_SUBSYS "consensus_publication_cas"

/* Canonical wire layout of the decision record. Fixed-size, little-endian; the
 * decision digest is SHA3-256(domain || preimage). The reason string trails the
 * digest and is NOT digest-bound (human diagnostic only). */
#define CAS_PREIMAGE_SIZE 214u
#define CAS_WIRE_SIZE (CAS_PREIMAGE_SIZE + 32u + sizeof(((struct \
    consensus_state_publication_decision_record *)0)->reason))

/* ── latest-decision snapshot for dumpstate ──────────────────────────── */
static pthread_mutex_t g_latest_lock = PTHREAD_MUTEX_INITIALIZER;
#if !defined(_WIN32)
static pthread_mutex_t g_persist_lock = PTHREAD_MUTEX_INITIALIZER;
#endif
static bool g_latest_present;
static struct consensus_state_publication_decision_record g_latest;
#if !defined(_WIN32)
static _Atomic uint64_t g_temp_nonce;
#endif

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

/* ── durable record I/O (FULL durability, contained) ──────────────────── */
#if !defined(_WIN32)
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
    int fd = openat(dir_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
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
    int fd = -1;
    for (unsigned attempt = 0; attempt < 1024; attempt++) {
        uint64_t nonce = atomic_fetch_add_explicit(
            &g_temp_nonce, 1, memory_order_relaxed);
        int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld.%016llx", name,
                         (long)getpid(), (unsigned long long)nonce);
        if (n <= 0 || (size_t)n >= sizeof(tmp))
            return ZCL_ERR(-42, "cas persist: temp name overflow");
        fd = openat(dir_fd, tmp,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0400);
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
    if (ok && renameat(dir_fd, tmp, dir_fd, name) != 0) {
        ok = false;
        LOG_WARN(CAS_SUBSYS, "renameat into place failed: %s",
                 strerror(errno));
    } else if (ok) {
        renamed = true;
    }
    if (ok && fsync(dir_fd) != 0) {
        ok = false;
        LOG_WARN(CAS_SUBSYS, "directory fsync failed: %s", strerror(errno));
    }
    if (ok && !verify_exact_wire_at(dir_fd, name, wire)) {
        ok = false;
        LOG_WARN(CAS_SUBSYS, "published record verification failed");
    }
    if (!ok) {
        if (!renamed) {
            (void)unlinkat(dir_fd, tmp, 0);
            (void)fsync(dir_fd);
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
    int fd = openat(dir_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
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
#else
/* Windows may not emulate this directory-capability boundary with joined
 * path strings. Refuse until the platform layer can perform relative opens,
 * staging, replacement, and verification beneath one pinned directory
 * HANDLE. These stubs perform no I/O and mutate no caller-owned record. */
#ifdef ZCL_TESTING
struct zcl_result consensus_state_publication_cas_persist_for_test(
    int dir_fd, const char *name,
    const struct consensus_state_publication_decision_record *record)
{
    (void)dir_fd;
    (void)name;
    (void)record;
    return ZCL_ERR(-47, "cas persist: native Windows directory capability "
                        "is unavailable");
}
#endif

struct zcl_result consensus_state_publication_cas_load(
    int dir_fd, const char *name,
    struct consensus_state_publication_decision_record *out_record)
{
    (void)dir_fd;
    (void)name;
    (void)out_record;
    return ZCL_ERR(-56, "cas load: native Windows directory capability "
                        "is unavailable");
}
#endif

#if !defined(_WIN32)
static void store_latest(
    const struct consensus_state_publication_decision_record *record)
{
    pthread_mutex_lock(&g_latest_lock);
    g_latest = *record;
    g_latest_present = true;
    pthread_mutex_unlock(&g_latest_lock);
}
#endif

struct zcl_result consensus_state_publication_cas_run(
    const struct consensus_state_publication_cas_request *request,
    struct consensus_state_publication_decision_record *out_record)
{
#if defined(_WIN32)
    (void)request;
    (void)out_record;
    /* Refuse before validating evidence, capturing the frontier, deciding,
     * touching disk, or updating the process-local latest projection. */
    return ZCL_ERR(-67, "cas run: native Windows directory capability "
                        "is unavailable");
#else
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
#endif
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
