/* boot_mint_anchor_rom_keystone.c — the mint ceremony's SHIELDED keystone
 * hard-assert, the rom_state_checkpoint companion to the coins hard-assert
 * in boot_mint_anchor.c. Kept in its own file so boot_mint_anchor.c stays
 * under the E1 file-size ceiling (800 lines).
 *
 * After the coins SHA3/count assert proves the transparent fold, this
 * recomputes the SHIELDED sections of the compiled ROM state checkpoint
 * (chain/checkpoints.h, struct rom_state_checkpoint) from the just-folded
 * progress.kv tables and HARD-ASSERTS them equal:
 *
 *   anchor_digest / anchor_count        — the combined bundle-canonical
 *       anchors fold: same SQL ordering and codec the full-history bundle
 *       export uses (engine/composition/src/consensus_state_snapshot_export_write.c:
 *       copy_anchors — pool ASC then anchor ASC over
 *       sprout_anchors ∪ sapling_anchors, digest rows via
 *       consensus_state_bundle_anchor_digest_begin/_row), plus each pool's
 *       frontier (the root at the max recorded height).
 *   nullifier_digest / nullifier_count  — the combined nullifiers fold
 *       (copy_nullifiers: ORDER BY pool,nf, rows via
 *       consensus_state_bundle_nullifier_digest_begin/_row).
 *
 * A MISMATCH (or a recompute failure — the shielded state cannot even be
 * read) means our genesis..anchor fold disagrees with the compiled
 * keystone, the h=478544 class: page EV_BOOT_VALIDATION_FAILED, unlink the
 * untrustworthy artifact, and _exit — NEVER retain an unproven artifact.
 * Same fail posture as the coins assert.
 *
 * FOLLOW-UP: cross-check the recomputed sapling_frontier_root against the
 * anchor header's hashFinalSaplingRoot. The ceremony does not hold the
 * block header in scope (only cp->block_hash), and the frontier root is the
 * max-HEIGHT anchor row (height 3,056,742 at the h=3,056,758 keystone —
 * blocks with no shielded activity append no anchor row), so the binding
 * needs a block-index lookup at the frontier height, not the anchor. */

#include "config/boot.h"

#include "chain/checkpoints.h"                  /* get_rom_state_checkpoint */
#include "crypto/sha3.h"                        /* sha3_256_ctx/finalize */
#include "event/event.h"                        /* event_emitf */
#include "storage/anchor_kv.h"                  /* ANCHOR_POOL_* */
#include "storage/consensus_state_bundle_codec.h" /* digest begin/row */
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>                             /* EXIT_FAILURE */
#include <string.h>
#include <unistd.h>                             /* unlink, _exit */

/* The recomputed shielded fold, mirroring the rom_state_checkpoint fields
 * this ceremony can re-derive from progress.kv. */
struct rom_keystone_fold {
    uint8_t  anchor_digest[32];
    uint64_t anchor_count;
    uint8_t  sprout_frontier_root[32];
    int64_t  sprout_frontier_height;
    uint8_t  sapling_frontier_root[32];
    int64_t  sapling_frontier_height;
    uint8_t  nullifier_digest[32];
    uint64_t nullifier_count;
};

static void rom_keystone_hex(const uint8_t b[32], char out[65])
{
    for (int i = 0; i < 32; i++)
        snprintf(out + 2 * i, 3, "%02x", b[i]);
}

/* Fold the combined anchors table exactly as the bundle export does
 * (copy_anchors in consensus_state_snapshot_export_write.c): same SQL, same
 * codec rows, same per-pool frontier (root at the max height), same
 * duplicate-height rejection. `keystone_height` bounds row heights the way
 * the exporter's manifest->height does. Returns false (LOG_WARN context) on
 * any read/validation failure. */
static bool rom_keystone_fold_anchors(sqlite3 *pdb, int32_t keystone_height,
                                      struct rom_keystone_fold *f)
{
    static const char sql[] =
        "SELECT pool,anchor,height,tree FROM ("
        "SELECT 0 AS pool,anchor,height,tree FROM sprout_anchors "
        "UNION ALL "
        "SELECT 1 AS pool,anchor,height,tree FROM sapling_anchors) "
        "ORDER BY pool,anchor";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("mint_anchor", "keystone anchors prepare failed: %s",
                 sqlite3_errmsg(pdb));
        return false;
    }
    struct sha3_256_ctx digest;
    consensus_state_bundle_anchor_digest_begin(&digest);
    int64_t frontier_height[2] = {-1, -1};
    uint8_t frontier_root[2][32] = {{0}, {0}};
    uint64_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        int64_t pool = sqlite3_column_int64(st, 0);
        const void *root = sqlite3_column_blob(st, 1);
        int64_t height = sqlite3_column_int64(st, 2);
        const void *tree = sqlite3_column_blob(st, 3);
        int tree_len = sqlite3_column_bytes(st, 3);
        if ((pool != ANCHOR_POOL_SPROUT && pool != ANCHOR_POOL_SAPLING) ||
            !root || sqlite3_column_bytes(st, 1) != 32 ||
            height < 0 || height > keystone_height ||
            !tree || tree_len <= 0 || count == UINT64_MAX) {
            LOG_WARN("mint_anchor",
                     "keystone anchors row %llu: malformed",
                     (unsigned long long)count);
            ok = false;
            break;
        }
        int pool_index = (int)pool;
        if (height == frontier_height[pool_index]) {
            LOG_WARN("mint_anchor",
                     "keystone anchors: duplicate height %lld in pool %lld",
                     (long long)height, (long long)pool);
            ok = false;
            break;
        }
        if (height > frontier_height[pool_index]) {
            frontier_height[pool_index] = height;
            memcpy(frontier_root[pool_index], root, 32);
        }
        consensus_state_bundle_anchor_digest_row(
            &digest, (uint8_t)pool, root, (uint64_t)height, tree,
            (uint32_t)tree_len);
        count++;
    }
    if (rc != SQLITE_DONE) {
        LOG_WARN("mint_anchor", "keystone anchors step failed: %s",
                 sqlite3_errmsg(pdb));
        ok = false;
    }
    sqlite3_finalize(st);
    if (!ok || frontier_height[ANCHOR_POOL_SPROUT] < 0 ||
        frontier_height[ANCHOR_POOL_SAPLING] < 0) {
        LOG_WARN("mint_anchor",
                 "keystone anchors fold incomplete (ok=%d sprout_h=%lld "
                 "sapling_h=%lld)", ok ? 1 : 0,
                 (long long)frontier_height[ANCHOR_POOL_SPROUT],
                 (long long)frontier_height[ANCHOR_POOL_SAPLING]);
        return false;
    }
    sha3_256_finalize(&digest, f->anchor_digest);
    f->anchor_count = count;
    f->sprout_frontier_height = frontier_height[ANCHOR_POOL_SPROUT];
    f->sapling_frontier_height = frontier_height[ANCHOR_POOL_SAPLING];
    memcpy(f->sprout_frontier_root, frontier_root[ANCHOR_POOL_SPROUT], 32);
    memcpy(f->sapling_frontier_root, frontier_root[ANCHOR_POOL_SAPLING], 32);
    return true;
}

/* Fold the nullifiers table exactly as the bundle export does
 * (copy_nullifiers in consensus_state_snapshot_export_write.c). */
static bool rom_keystone_fold_nullifiers(sqlite3 *pdb, int32_t keystone_height,
                                         struct rom_keystone_fold *f)
{
    static const char sql[] =
        "SELECT pool,nf,height FROM nullifiers ORDER BY pool,nf";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(pdb, sql, -1, &st, NULL) != SQLITE_OK) {
        LOG_WARN("mint_anchor", "keystone nullifiers prepare failed: %s",
                 sqlite3_errmsg(pdb));
        return false;
    }
    struct sha3_256_ctx digest;
    consensus_state_bundle_nullifier_digest_begin(&digest);
    uint64_t count = 0;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:progress-kv-kernel-store
        int64_t pool = sqlite3_column_int64(st, 0);
        const void *nf = sqlite3_column_blob(st, 1);
        int64_t height = sqlite3_column_int64(st, 2);
        if ((pool != 0 && pool != 1) || !nf ||
            sqlite3_column_bytes(st, 1) != 32 ||
            height < 0 || height > keystone_height || count == UINT64_MAX) {
            LOG_WARN("mint_anchor",
                     "keystone nullifiers row %llu: malformed",
                     (unsigned long long)count);
            ok = false;
            break;
        }
        consensus_state_bundle_nullifier_digest_row(
            &digest, (uint8_t)pool, nf, (uint64_t)height);
        count++;
    }
    if (rc != SQLITE_DONE) {
        LOG_WARN("mint_anchor", "keystone nullifiers step failed: %s",
                 sqlite3_errmsg(pdb));
        ok = false;
    }
    sqlite3_finalize(st);
    if (!ok)
        return false;
    sha3_256_finalize(&digest, f->nullifier_digest);
    f->nullifier_count = count;
    return true;
}

/* The fail-closed terminal path, mirroring the coins hard-assert in
 * boot_mint_anchor.c: page, drop the unproven artifact, die. */
static void rom_keystone_fatal(const char *out_path, const char *why)
{
    fprintf(stderr,
            "FATAL: -mint-anchor: minted SHIELDED state FAILED the ROM "
            "keystone check (%s) — our fold disagrees with the compiled "
            "rom_state_checkpoint. Refusing to retain; the artifact at %s "
            "is NOT trustworthy.\n", why, out_path ? out_path : "(null)");
    event_emitf(EV_BOOT_VALIDATION_FAILED, 0,
                "check=mint_anchor_rom_keystone minted shielded state "
                "mismatch (%s) — fold disagrees with the compiled ROM state "
                "checkpoint; do NOT trust the artifact", why);
    if (out_path)
        unlink(out_path);
    _exit(EXIT_FAILURE);
}

void boot_mint_anchor_rom_keystone_assert(sqlite3 *pdb, const char *out_path)
{
    const struct rom_state_checkpoint *rom = get_rom_state_checkpoint();
    if (!rom)
        return;  /* no compiled keystone — nothing to assert */
    if (!pdb)
        rom_keystone_fatal(out_path, "progress store db is NULL");

    struct rom_keystone_fold f;
    memset(&f, 0, sizeof(f));
    if (!rom_keystone_fold_anchors(pdb, rom->height, &f) ||
        !rom_keystone_fold_nullifiers(pdb, rom->height, &f))
        rom_keystone_fatal(out_path, "shielded recompute failed");

    int mismatches = 0;
    char got_hex[65], want_hex[65];
    if (memcmp(f.anchor_digest, rom->anchor_digest, 32) != 0) {
        rom_keystone_hex(f.anchor_digest, got_hex);
        rom_keystone_hex(rom->anchor_digest, want_hex);
        fprintf(stderr, "[mint-anchor] keystone MISMATCH anchor_digest: "
                "got=%s want=%s\n", got_hex, want_hex);
        mismatches++;
    }
    if (f.anchor_count != rom->anchor_count) {
        fprintf(stderr, "[mint-anchor] keystone MISMATCH anchor_count: "
                "got=%llu want=%llu\n", (unsigned long long)f.anchor_count,
                (unsigned long long)rom->anchor_count);
        mismatches++;
    }
    if (memcmp(f.sprout_frontier_root, rom->sprout_frontier_root, 32) != 0) {
        rom_keystone_hex(f.sprout_frontier_root, got_hex);
        rom_keystone_hex(rom->sprout_frontier_root, want_hex);
        fprintf(stderr, "[mint-anchor] keystone MISMATCH "
                "sprout_frontier_root: got=%s want=%s\n", got_hex, want_hex);
        mismatches++;
    }
    if (f.sprout_frontier_height != rom->sprout_frontier_height) {
        fprintf(stderr, "[mint-anchor] keystone MISMATCH "
                "sprout_frontier_height: got=%lld want=%lld\n",
                (long long)f.sprout_frontier_height,
                (long long)rom->sprout_frontier_height);
        mismatches++;
    }
    if (memcmp(f.sapling_frontier_root, rom->sapling_frontier_root, 32) != 0) {
        rom_keystone_hex(f.sapling_frontier_root, got_hex);
        rom_keystone_hex(rom->sapling_frontier_root, want_hex);
        fprintf(stderr, "[mint-anchor] keystone MISMATCH "
                "sapling_frontier_root: got=%s want=%s\n", got_hex, want_hex);
        mismatches++;
    }
    if (f.sapling_frontier_height != rom->sapling_frontier_height) {
        fprintf(stderr, "[mint-anchor] keystone MISMATCH "
                "sapling_frontier_height: got=%lld want=%lld\n",
                (long long)f.sapling_frontier_height,
                (long long)rom->sapling_frontier_height);
        mismatches++;
    }
    if (memcmp(f.nullifier_digest, rom->nullifier_digest, 32) != 0) {
        rom_keystone_hex(f.nullifier_digest, got_hex);
        rom_keystone_hex(rom->nullifier_digest, want_hex);
        fprintf(stderr, "[mint-anchor] keystone MISMATCH nullifier_digest: "
                "got=%s want=%s\n", got_hex, want_hex);
        mismatches++;
    }
    if (f.nullifier_count != rom->nullifier_count) {
        fprintf(stderr, "[mint-anchor] keystone MISMATCH nullifier_count: "
                "got=%llu want=%llu\n",
                (unsigned long long)f.nullifier_count,
                (unsigned long long)rom->nullifier_count);
        mismatches++;
    }
    if (mismatches) {
        char why[64];
        snprintf(why, sizeof(why), "%d field(s) mismatch", mismatches);
        rom_keystone_fatal(out_path, why);
    }

    fprintf(stderr,
            "[mint-anchor] keystone OK: shielded fold matches the compiled "
            "ROM state checkpoint (anchors=%llu nullifiers=%llu "
            "sprout_frontier_h=%lld sapling_frontier_h=%lld)\n",
            (unsigned long long)f.anchor_count,
            (unsigned long long)f.nullifier_count,
            (long long)f.sprout_frontier_height,
            (long long)f.sapling_frontier_height);
}
