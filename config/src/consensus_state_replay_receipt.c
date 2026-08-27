/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_state_replay_receipt.c — independent replay-derived receipt that
 * lifts the bundle-ACTIVATE production containment. Contract + threat model:
 * config/consensus_state_replay_receipt.h.
 *
 * The derivation reads ONLY the datadir's own folded progress-store tables
 * (coins, sprout_anchors, sapling_anchors, nullifiers). The bundle's tables are
 * opened solely to obtain the manifest values that the derivation is compared
 * AGAINST — they are never fed into the digests. */

#include "config/consensus_state_replay_receipt.h"

#include "config/consensus_state_snapshot_install.h"
#include "consensus_state_producer_receipt_internal.h"
#include "base/serialize_le.h"
#include "coins/utxo_commitment.h"
#include "core/amount.h"
#include "crypto/sha3.h"
#include "script/script.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define RR_SUBSYS "consensus_replay_receipt"

/* Canonical fixed-width receipt payload. Byte offsets are pinned so the writer
 * and the ACTIVATE-time reader agree exactly. */
#define RR_SCHEMA_FIELD    48u
#define RR_OFF_SCHEMA      0u
#define RR_OFF_BUNDLE_FILE 48u
#define RR_OFF_ARTIFACT    80u
#define RR_OFF_BLOCK_HASH  112u
#define RR_OFF_HEIGHT      144u
#define RR_OFF_UTXO_ROOT   152u
#define RR_OFF_UTXO_COUNT  184u
#define RR_OFF_SUPPLY      192u
#define RR_OFF_ANCHOR_DIG  200u
#define RR_OFF_ANCHOR_CNT  232u
#define RR_OFF_NF_DIG      240u
#define RR_OFF_NF_CNT      272u
#define RR_OFF_VERIFIER    280u
#define RR_OFF_RECEIPT_DIG 312u
#define RR_PAYLOAD_BYTES   344u

_Static_assert(RR_OFF_RECEIPT_DIG + 32u == RR_PAYLOAD_BYTES,
               "replay receipt payload layout");

/* One decoded receipt, independent of the on-disk byte order. */
struct rr_receipt {
    uint8_t bundle_file_digest[32];
    uint8_t artifact_digest[32];
    uint8_t block_hash[32];
    int64_t height;
    uint8_t utxo_root[32];
    uint64_t utxo_count;
    int64_t total_supply;
    uint8_t anchor_digest[32];
    uint64_t anchor_count;
    uint8_t nullifier_digest[32];
    uint64_t nullifier_count;
    uint8_t verifier_binary_digest[32];
    uint8_t receipt_digest[32];
};

static bool rr_fail(struct consensus_state_replay_result *out, const char *fmt,
                    ...)
{
    char reason[192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);
    if (out) {
        out->verified = false;
        snprintf(out->reason, sizeof(out->reason), "%s", reason);
    }
    LOG_WARN(RR_SUBSYS, "%s", reason);
    return false;
}

/* Domain-separated binding over every receipt field except receipt_digest. */
static void rr_receipt_digest(const struct rr_receipt *r, uint8_t out[32])
{
    static const char domain[] =
        CONSENSUS_STATE_REPLAY_RECEIPT_SCHEMA "/binding";
    uint8_t le[8];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&ctx, r->bundle_file_digest, 32);
    sha3_256_write(&ctx, r->artifact_digest, 32);
    sha3_256_write(&ctx, r->block_hash, 32);
    zcl_write_u64_le(le, (uint64_t)r->height);
    sha3_256_write(&ctx, le, 8);
    sha3_256_write(&ctx, r->utxo_root, 32);
    zcl_write_u64_le(le, r->utxo_count);
    sha3_256_write(&ctx, le, 8);
    zcl_write_u64_le(le, (uint64_t)r->total_supply);
    sha3_256_write(&ctx, le, 8);
    sha3_256_write(&ctx, r->anchor_digest, 32);
    zcl_write_u64_le(le, r->anchor_count);
    sha3_256_write(&ctx, le, 8);
    sha3_256_write(&ctx, r->nullifier_digest, 32);
    zcl_write_u64_le(le, r->nullifier_count);
    sha3_256_write(&ctx, le, 8);
    sha3_256_write(&ctx, r->verifier_binary_digest, 32);
    sha3_256_finalize(&ctx, out);
}

static void rr_serialize(const struct rr_receipt *r, uint8_t buf[RR_PAYLOAD_BYTES])
{
    memset(buf, 0, RR_PAYLOAD_BYTES);
    memcpy(buf + RR_OFF_SCHEMA, CONSENSUS_STATE_REPLAY_RECEIPT_SCHEMA,
           strlen(CONSENSUS_STATE_REPLAY_RECEIPT_SCHEMA));
    memcpy(buf + RR_OFF_BUNDLE_FILE, r->bundle_file_digest, 32);
    memcpy(buf + RR_OFF_ARTIFACT, r->artifact_digest, 32);
    memcpy(buf + RR_OFF_BLOCK_HASH, r->block_hash, 32);
    zcl_write_u64_le(buf + RR_OFF_HEIGHT, (uint64_t)r->height);
    memcpy(buf + RR_OFF_UTXO_ROOT, r->utxo_root, 32);
    zcl_write_u64_le(buf + RR_OFF_UTXO_COUNT, r->utxo_count);
    zcl_write_u64_le(buf + RR_OFF_SUPPLY, (uint64_t)r->total_supply);
    memcpy(buf + RR_OFF_ANCHOR_DIG, r->anchor_digest, 32);
    zcl_write_u64_le(buf + RR_OFF_ANCHOR_CNT, r->anchor_count);
    memcpy(buf + RR_OFF_NF_DIG, r->nullifier_digest, 32);
    zcl_write_u64_le(buf + RR_OFF_NF_CNT, r->nullifier_count);
    memcpy(buf + RR_OFF_VERIFIER, r->verifier_binary_digest, 32);
    memcpy(buf + RR_OFF_RECEIPT_DIG, r->receipt_digest, 32);
}

/* Parse a fixed payload and verify its self-consistency: schema string and the
 * recomputed receipt_digest. Byte-level tampering fails here. */
static bool rr_deserialize(const uint8_t buf[RR_PAYLOAD_BYTES],
                           struct rr_receipt *r)
{
    size_t schema_len = strlen(CONSENSUS_STATE_REPLAY_RECEIPT_SCHEMA);
    if (schema_len >= RR_SCHEMA_FIELD ||
        memcmp(buf + RR_OFF_SCHEMA, CONSENSUS_STATE_REPLAY_RECEIPT_SCHEMA,
               schema_len) != 0 ||
        buf[RR_OFF_SCHEMA + schema_len] != 0)
        return false;
    memcpy(r->bundle_file_digest, buf + RR_OFF_BUNDLE_FILE, 32);
    memcpy(r->artifact_digest, buf + RR_OFF_ARTIFACT, 32);
    memcpy(r->block_hash, buf + RR_OFF_BLOCK_HASH, 32);
    r->height = (int64_t)zcl_read_u64_le(buf + RR_OFF_HEIGHT);
    memcpy(r->utxo_root, buf + RR_OFF_UTXO_ROOT, 32);
    r->utxo_count = zcl_read_u64_le(buf + RR_OFF_UTXO_COUNT);
    r->total_supply = (int64_t)zcl_read_u64_le(buf + RR_OFF_SUPPLY);
    memcpy(r->anchor_digest, buf + RR_OFF_ANCHOR_DIG, 32);
    r->anchor_count = zcl_read_u64_le(buf + RR_OFF_ANCHOR_CNT);
    memcpy(r->nullifier_digest, buf + RR_OFF_NF_DIG, 32);
    r->nullifier_count = zcl_read_u64_le(buf + RR_OFF_NF_CNT);
    memcpy(r->verifier_binary_digest, buf + RR_OFF_VERIFIER, 32);
    memcpy(r->receipt_digest, buf + RR_OFF_RECEIPT_DIG, 32);
    uint8_t recomputed[32];
    rr_receipt_digest(r, recomputed);
    return memcmp(recomputed, r->receipt_digest, 32) == 0;
}

static bool rr_receipt_path(const char *datadir, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", datadir,
                     CONSENSUS_STATE_REPLAY_RECEIPT_NAME);
    return n > 0 && (size_t)n < cap;
}

/* Atomic keyed-file write: tmp -> fsync(file) -> rename -> fsync(dir). */
static bool rr_write_atomic(const char *datadir,
                            const uint8_t buf[RR_PAYLOAD_BYTES],
                            char *final_out, size_t final_cap)
{
    char final_path[PATH_MAX], tmp_path[PATH_MAX];
    if (!rr_receipt_path(datadir, final_path, sizeof(final_path)))
        return false;
    if (final_out && strlen(final_path) >= final_cap)
        return false;
    int n = snprintf(tmp_path, sizeof(tmp_path), "%s/%s.tmp.%ld", datadir,
                     CONSENSUS_STATE_REPLAY_RECEIPT_NAME, (long)getpid());
    if (n <= 0 || (size_t)n >= sizeof(tmp_path))
        return false;
    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        LOG_WARN(RR_SUBSYS, "receipt tmp open failed: %s", strerror(errno));
        return false;
    }
    bool ok = true;
    size_t written = 0;
    while (written < RR_PAYLOAD_BYTES) {
        ssize_t w = write(fd, buf + written, RR_PAYLOAD_BYTES - written);
        if (w > 0) {
            written += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        ok = false;
        break;
    }
    if (ok && fsync(fd) != 0)
        ok = false;
    if (close(fd) != 0)
        ok = false;
    if (ok && rename(tmp_path, final_path) != 0) {
        LOG_WARN(RR_SUBSYS, "receipt rename failed: %s", strerror(errno));
        ok = false;
    }
    if (!ok) {
        (void)unlink(tmp_path);
        return false;
    }
    int dir_fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd >= 0) {
        (void)fsync(dir_fd);
        (void)close(dir_fd);
    }
    if (final_out)
        memcpy(final_out, final_path, strlen(final_path) + 1u);
    return true;
}

/* Reads through the datadir capability fd, matching ACTIVATE's rule that
 * pathnames are locators, never authority. */
static bool rr_read_file(int datadir_fd, struct rr_receipt *r)
{
    int fd = openat(datadir_fd, CONSENSUS_STATE_REPLAY_RECEIPT_NAME,
                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    uint8_t buf[RR_PAYLOAD_BYTES + 1];
    size_t got = 0;
    bool ok = true;
    while (got < sizeof(buf)) {
        ssize_t n = read(fd, buf + got, sizeof(buf) - got);
        if (n > 0) {
            got += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            ok = false;
        break;
    }
    (void)close(fd);
    /* Exactly RR_PAYLOAD_BYTES — a longer file is not our canonical receipt. */
    if (!ok || got != RR_PAYLOAD_BYTES)
        return false;
    return rr_deserialize(buf, r);
}

/* ── Independent derivation from the datadir's OWN folded tables ───────────── */

static bool rr_column_i64(sqlite3_stmt *st, int col, int64_t *out)
{
    if (sqlite3_column_type(st, col) != SQLITE_INTEGER)
        return false;
    *out = sqlite3_column_int64(st, col);
    return true;
}

static bool derive_utxo(sqlite3 *db, int32_t max_height, uint8_t root[32],
                        uint64_t *count_out, int64_t *supply_out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT txid,vout,value,script,height,is_coinbase "
            "FROM coins ORDER BY txid,vout", -1, &st, NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint64_t count = 0;
    int64_t supply = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        const uint8_t *txid = sqlite3_column_type(st, 0) == SQLITE_BLOB
            ? sqlite3_column_blob(st, 0) : NULL;
        const uint8_t *script = sqlite3_column_type(st, 3) == SQLITE_BLOB
            ? sqlite3_column_blob(st, 3) : NULL;
        int script_len = script ? sqlite3_column_bytes(st, 3) : 0;
        int64_t vout = -1, value = -1, height = -1, coinbase = -1;
        bool numeric = rr_column_i64(st, 1, &vout) &&
                       rr_column_i64(st, 2, &value) &&
                       rr_column_i64(st, 4, &height) &&
                       rr_column_i64(st, 5, &coinbase);
        if (!txid || sqlite3_column_bytes(st, 0) != 32 || !numeric ||
            sqlite3_column_type(st, 3) != SQLITE_BLOB || script_len < 0 ||
            script_len > MAX_SCRIPT_SIZE || vout < 0 || vout > UINT32_MAX ||
            !MoneyRange(value) || supply > MAX_MONEY - value || height < 0 ||
            height > max_height || (coinbase != 0 && coinbase != 1) ||
            count == UINT64_MAX) {
            ok = false;
            break;
        }
        utxo_commitment_sha3_write_record(&ctx, txid, (uint32_t)vout, value,
                                          script_len ? script : NULL,
                                          (uint32_t)script_len,
                                          (uint32_t)height, (uint8_t)coinbase);
        supply += value;
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(st);
    if (!ok || count == 0)
        return false;
    sha3_256_finalize(&ctx, root);
    *count_out = count;
    *supply_out = supply;
    return true;
}

static bool derive_anchors(sqlite3 *db, int32_t max_height, uint8_t digest[32],
                           uint64_t *count_out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT pool,anchor,height,tree FROM ("
            "SELECT 0 AS pool,anchor,height,tree FROM sprout_anchors "
            "UNION ALL "
            "SELECT 1 AS pool,anchor,height,tree FROM sapling_anchors) "
            "ORDER BY pool,anchor", -1, &st, NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx ctx;
    consensus_state_bundle_anchor_digest_begin(&ctx);
    bool have_pool[2] = {false, false};
    uint64_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        const uint8_t *root = sqlite3_column_type(st, 1) == SQLITE_BLOB
            ? sqlite3_column_blob(st, 1) : NULL;
        const uint8_t *tree = sqlite3_column_type(st, 3) == SQLITE_BLOB
            ? sqlite3_column_blob(st, 3) : NULL;
        int tree_len = tree ? sqlite3_column_bytes(st, 3) : 0;
        int64_t pool = -1, height = -1;
        bool numeric = rr_column_i64(st, 0, &pool) &&
                       rr_column_i64(st, 2, &height);
        if (!numeric ||
            (pool != ANCHOR_POOL_SPROUT && pool != ANCHOR_POOL_SAPLING) ||
            !root || sqlite3_column_bytes(st, 1) != 32 || !tree ||
            tree_len <= 0 || height < 0 || height > max_height ||
            count == UINT64_MAX) {
            ok = false;
            break;
        }
        consensus_state_bundle_anchor_digest_row(&ctx, (uint8_t)pool, root,
                                                 (uint64_t)height, tree,
                                                 (uint32_t)tree_len);
        have_pool[pool] = true;
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(st);
    /* A complete shielded history has both pools present. */
    if (!ok || !have_pool[0] || !have_pool[1])
        return false;
    sha3_256_finalize(&ctx, digest);
    *count_out = count;
    return true;
}

static bool derive_nullifiers(sqlite3 *db, int32_t max_height, uint8_t digest[32],
                              uint64_t *count_out)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT pool,nf,height FROM nullifiers ORDER BY pool,nf", -1, &st,
            NULL) != SQLITE_OK)
        return false;
    struct sha3_256_ctx ctx;
    consensus_state_bundle_nullifier_digest_begin(&ctx);
    uint64_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        const uint8_t *nf = sqlite3_column_type(st, 1) == SQLITE_BLOB
            ? sqlite3_column_blob(st, 1) : NULL;
        int64_t pool = -1, height = -1;
        bool numeric = rr_column_i64(st, 0, &pool) &&
                       rr_column_i64(st, 2, &height);
        if (!numeric || (pool != 0 && pool != 1) || !nf ||
            sqlite3_column_bytes(st, 1) != 32 || height < 0 ||
            height > max_height || count == UINT64_MAX) {
            ok = false;
            break;
        }
        consensus_state_bundle_nullifier_digest_row(&ctx, (uint8_t)pool, nf,
                                                    (uint64_t)height);
        count++;
    }
    if (rc != SQLITE_DONE)
        ok = false;
    sqlite3_finalize(st);
    if (!ok)
        return false;
    sha3_256_finalize(&ctx, digest);
    *count_out = count;
    return true;
}

/* Fill `r`'s independently derived components from the datadir progress store
 * and return the derived digests; the caller compares them to the manifest. */
static bool rr_derive_from_datadir(sqlite3 *db,
                                   const struct consensus_state_bundle_manifest *m,
                                   struct rr_receipt *r,
                                   struct consensus_state_replay_result *out)
{
    int32_t applied = -1;
    bool applied_found = false;
    if (!coins_kv_get_applied_height(db, &applied, &applied_found) ||
        !applied_found)
        return rr_fail(out, "datadir has no coins_applied_height; the local "
                            "genesis->anchor fold has not run here");
    if (applied != m->height + 1)
        return rr_fail(out, "datadir is not parked at the bundle anchor "
                            "(coins_applied=%d, want %d); re-derivation must run "
                            "against a store folded EXACTLY to the anchor",
                       applied, m->height + 1);
    if (!derive_utxo(db, m->height, r->utxo_root, &r->utxo_count,
                     &r->total_supply))
        return rr_fail(out, "independent UTXO derivation from the datadir "
                            "failed (empty/malformed coins)");
    if (!derive_anchors(db, m->height, r->anchor_digest, &r->anchor_count))
        return rr_fail(out, "independent anchor derivation from the datadir "
                            "failed (missing/malformed Sprout or Sapling "
                            "anchors)");
    if (!derive_nullifiers(db, m->height, r->nullifier_digest,
                           &r->nullifier_count))
        return rr_fail(out, "independent nullifier derivation from the datadir "
                            "failed");
    return true;
}

/* Compare every independently derived component to the bundle manifest. */
static bool rr_components_match(const struct consensus_state_bundle_manifest *m,
                                const struct rr_receipt *r,
                                struct consensus_state_replay_result *out)
{
    if (r->utxo_count != m->utxo_count ||
        r->total_supply != m->total_supply ||
        memcmp(r->utxo_root, m->utxo_root, 32) != 0)
        return rr_fail(out, "UTXO root/count/supply from the local fold does "
                            "NOT match the bundle (count=%llu want %llu)",
                       (unsigned long long)r->utxo_count,
                       (unsigned long long)m->utxo_count);
    if (r->anchor_count != m->anchor_count ||
        memcmp(r->anchor_digest, m->anchor_digest, 32) != 0)
        return rr_fail(out, "anchor digest/count from the local fold does NOT "
                            "match the bundle");
    if (r->nullifier_count != m->nullifier_count ||
        memcmp(r->nullifier_digest, m->nullifier_digest, 32) != 0)
        return rr_fail(out, "nullifier digest/count from the local fold does "
                            "NOT match the bundle");
    return true;
}

bool consensus_state_replay_verify_and_write_receipt(
    sqlite3 *progress_db, const char *bundle_path, const char *datadir,
    struct consensus_state_replay_result *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!progress_db || !bundle_path || !bundle_path[0] || !datadir ||
        !datadir[0])
        return rr_fail(out, "NULL progress_db/bundle_path/datadir");

    /* (1) Admit + strictly validate the immutable bundle read-only. Best-
     * effort directory capability for the install-verify receipt only; a
     * failed open here just means every replay verify runs the full content
     * scan (fail-soft, same as passing -1). */
    int datadir_fd = open(datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct consensus_state_artifact_evidence *evidence = NULL;
    struct zcl_result admitted =
        consensus_state_artifact_evidence_open(bundle_path, datadir_fd,
                                               &evidence);
    if (datadir_fd >= 0)
        (void)close(datadir_fd);
    if (!admitted.ok)
        return rr_fail(out, "bundle admission/validation failed: %s",
                       admitted.message);

    struct rr_receipt r;
    memset(&r, 0, sizeof(r));
    struct consensus_state_bundle_manifest m;
    bool ok = consensus_state_artifact_evidence_manifest_copy(evidence, &m) &&
              consensus_state_artifact_evidence_file_digest(
                  evidence, r.bundle_file_digest);
    if (!ok) {
        consensus_state_artifact_evidence_free(evidence);
        return rr_fail(out, "artifact evidence became stale after admission");
    }

    /* (2) A complete genesis-derived history bundle — the same anti-mixed-
     *     provenance contract ACTIVATE enforces. */
    if (!m.history_complete || m.activation_boundary != 0 ||
        m.sprout_source_cursor != 0 || m.sapling_source_cursor != 0 ||
        m.nullifier_source_cursor != 0 ||
        m.source_fold_cursor != (int64_t)m.height + 1) {
        consensus_state_artifact_evidence_free(evidence);
        return rr_fail(out, "bundle is not a complete genesis-derived history "
                            "(mixed provenance); replay verification refuses");
    }

    memcpy(r.artifact_digest, m.artifact_digest, 32);
    memcpy(r.block_hash, m.block_hash, 32);
    r.height = m.height;

    /* (3+4) Independently derive from the datadir's own tables and compare. */
    if (!rr_derive_from_datadir(progress_db, &m, &r, out) ||
        !rr_components_match(&m, &r, out)) {
        consensus_state_artifact_evidence_free(evidence);
        return false;
    }
    consensus_state_artifact_evidence_free(evidence);

    /* (5) Bind the verifying binary and persist the receipt. The digest
     * helper is the producer receipt's shared one (byte-identical body; the
     * 344-byte payload and its binding stay behaviorally frozen — see the
     * OS-A1 note in config/consensus_state_replay_receipt.h's contract). */
    if (!producer_running_binary_digest(r.verifier_binary_digest))
        return rr_fail(out, "verifying-binary digest failed");
    rr_receipt_digest(&r, r.receipt_digest);
    uint8_t buf[RR_PAYLOAD_BYTES];
    rr_serialize(&r, buf);
    char final_path[256] = {0};
    if (!rr_write_atomic(datadir, buf, final_path, sizeof(final_path)))
        return rr_fail(out, "receipt persist (fsync'd) failed");

    if (out) {
        out->verified = true;
        out->height = m.height;
        out->utxo_count = r.utxo_count;
        out->total_supply = r.total_supply;
        out->anchor_count = r.anchor_count;
        out->nullifier_count = r.nullifier_count;
        memcpy(out->bundle_file_digest, r.bundle_file_digest, 32);
        memcpy(out->verifier_binary_digest, r.verifier_binary_digest, 32);
        snprintf(out->receipt_path, sizeof(out->receipt_path), "%s",
                 final_path);
        snprintf(out->reason, sizeof(out->reason),
                 "replay-verified height=%d utxo=%llu anchors=%llu "
                 "nullifiers=%llu; receipt at %s", m.height,
                 (unsigned long long)r.utxo_count,
                 (unsigned long long)r.anchor_count,
                 (unsigned long long)r.nullifier_count, final_path);
    }
    LOG_INFO(RR_SUBSYS, "%s", out ? out->reason : "replay-verified");
    return true;
}

bool consensus_state_replay_receipt_authority_available(
    const struct consensus_state_bundle_manifest *manifest,
    const uint8_t bundle_file_digest[32], int datadir_fd)
{
    if (!manifest || !bundle_file_digest || datadir_fd < 0)
        return false;

    struct rr_receipt r;
    memset(&r, 0, sizeof(r));
    /* Reads the keyed file AND re-verifies its self-binding receipt_digest. */
    if (!rr_read_file(datadir_fd, &r)) {
        LOG_WARN(RR_SUBSYS, "no valid replay receipt in the datadir; ACTIVATE "
                            "stays contained");
        return false;
    }

    /* The activating binary must be the exact image that verified. */
    uint8_t running[32];
    if (!producer_running_binary_digest(running) ||
        memcmp(running, r.verifier_binary_digest, 32) != 0) {
        LOG_WARN(RR_SUBSYS, "replay receipt was written by a different binary "
                            "image; ACTIVATE stays contained");
        return false;
    }

    bool bound = memcmp(r.bundle_file_digest, bundle_file_digest, 32) == 0 &&
                 memcmp(r.artifact_digest, manifest->artifact_digest, 32) == 0 &&
                 r.height == manifest->height &&
                 memcmp(r.block_hash, manifest->block_hash, 32) == 0 &&
                 r.utxo_count == manifest->utxo_count &&
                 r.total_supply == manifest->total_supply &&
                 memcmp(r.utxo_root, manifest->utxo_root, 32) == 0 &&
                 r.anchor_count == manifest->anchor_count &&
                 memcmp(r.anchor_digest, manifest->anchor_digest, 32) == 0 &&
                 r.nullifier_count == manifest->nullifier_count &&
                 memcmp(r.nullifier_digest, manifest->nullifier_digest, 32) == 0;
    if (!bound) {
        LOG_WARN(RR_SUBSYS, "replay receipt does not bind THIS bundle/anchor/"
                            "component digests; ACTIVATE stays contained");
        return false;
    }
    return true;
}

/* ── Bundle-binding-only reader (ROM catalog admission) ─────────────────── */

bool consensus_state_replay_receipt_bundle_binding_verified(
    int datadir_fd, const uint8_t bundle_file_digest[32],
    struct consensus_state_replay_receipt_binding *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!bundle_file_digest || datadir_fd < 0) {
        LOG_WARN(RR_SUBSYS, "bundle_binding_verified: NULL digest or bad fd; "
                            "ROM admission refuses (fail-closed)");
        return false;
    }

    struct rr_receipt r;
    memset(&r, 0, sizeof(r));
    /* Reads the keyed file AND re-verifies its self-binding receipt_digest —
     * schema mismatch or any byte tampering fails inside rr_read_file. */
    if (!rr_read_file(datadir_fd, &r)) {
        LOG_WARN(RR_SUBSYS, "no valid replay receipt beside this bundle; ROM "
                            "admission refuses (fail-closed, no receipt no "
                            "serve)");
        return false;
    }

    if (memcmp(r.bundle_file_digest, bundle_file_digest, 32) != 0) {
        LOG_WARN(RR_SUBSYS, "replay receipt does not bind this bundle's "
                            "whole-file digest; ROM admission refuses");
        return false;
    }

    if (out) {
        out->height = (int32_t)r.height;
        out->utxo_count = r.utxo_count;
        out->anchor_count = r.anchor_count;
        out->nullifier_count = r.nullifier_count;
        memcpy(out->verifier_binary_digest, r.verifier_binary_digest, 32);
    }
    return true;
}

#ifdef ZCL_TESTING
bool consensus_state_replay_receipt_write_for_test(
    const char *datadir, const uint8_t bundle_file_digest[32],
    int32_t height, uint64_t utxo_count, uint64_t anchor_count,
    uint64_t nullifier_count, char *out_path, size_t out_cap)
{
    if (!datadir || !datadir[0] || !bundle_file_digest)
        return false;

    struct rr_receipt r;
    memset(&r, 0, sizeof(r));
    memcpy(r.bundle_file_digest, bundle_file_digest, 32);
    r.height = height;
    r.utxo_count = utxo_count;
    r.anchor_count = anchor_count;
    r.nullifier_count = nullifier_count;
    /* artifact_digest / block_hash / utxo_root / anchor_digest /
     * nullifier_digest / total_supply are left zeroed and
     * verifier_binary_digest is a fixed test marker — none of these are
     * compared by the bundle-binding-only reader above; only the ACTIVATE
     * authority path (consensus_state_replay_receipt_authority_available)
     * compares them against a live manifest. */
    memset(r.verifier_binary_digest, 0xAB, sizeof(r.verifier_binary_digest));

    rr_receipt_digest(&r, r.receipt_digest);
    uint8_t buf[RR_PAYLOAD_BYTES];
    rr_serialize(&r, buf);
    return rr_write_atomic(datadir, buf, out_path, out_cap);
}
#endif
