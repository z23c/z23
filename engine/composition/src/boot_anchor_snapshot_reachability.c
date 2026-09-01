/* boot_anchor_snapshot_reachability.c — split out of boot_refold_staged.c so
 * each file keeps one focused responsibility (same discipline that file's own
 * header states). This file owns exactly one question: is a SHA3-checkpoint-
 * bound anchor UTXO snapshot (<datadir>/utxo-anchor.snapshot, the artifact the
 * -mint-anchor ceremony or tools/seed_anchor_snapshot.sh produces) reachable
 * and verified RIGHT NOW — never whether/how to load it. Read-only: every path
 * here mmaps the candidate file PROT_READ via uss_open and closes it before
 * returning; no coins_kv mutation, no progress-store transaction.
 *
 * Contract + the full rejection taxonomy are declared in config/boot.h next
 * to boot_refold_from_anchor_artifact_available[_ex]. Path resolution
 * (boot_anchor_snapshot_path_resolve, shared with the two real loaders in
 * boot_refold_staged.c) is declared in config/boot_internal.h. */
#include "config/boot.h"
#include "config/boot_internal.h"

#include "chain/checkpoints.h"           /* get_sha3_utxo_checkpoint */
#include "chain/utxo_snapshot_loader.h"  /* uss_open/uss_close */
#include "config/boot_snapshot_install.h" /* boot_legacy_uss_matches_checkpoint */
#include "models/database.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sqlite3.h>

/* ── B2 anchor-SET SOURCE: the minted snapshot path ─────────────────────────
 *
 * Derive the anchor-snapshot path in this order:
 *   (1) $ZCL_MINT_ANCHOR_OUT verbatim when set — the exact path the
 *       -mint-anchor driver wrote (boot_mint_anchor.c) and the exact override
 *       the test suite uses; honored unconditionally (even if the file turns
 *       out absent) to preserve that producer/test contract byte-for-byte.
 *   (2) $ZCL_ANCHOR_SNAPSHOT_PATH when set AND it names an existing regular
 *       file — a general operator/deploy override (e.g. a shared staging
 *       location distinct from the datadir) for reaching the artifact
 *       without needing any CLI flag. Deliberately falls through to (3)
 *       rather than (1)'s "use it regardless" behavior, so a stale/unset
 *       value never points every caller at a dead path.
 *   (3) <datadir>/utxo-anchor.snapshot (where <datadir> is node.db's
 *       directory) — the default reachable-by-construction location, and the
 *       exact target tools/seed_anchor_snapshot.sh stages into.
 * All three are LOCAL paths only; this never fetches over the network.
 * Shared with boot_refold_staged.c's two real loaders (boot_anchor_seed_
 * from_snapshot, boot_load_verify_snapshot_eligible) via boot_internal.h so
 * "is it reachable" and "load it" can never disagree about which file they
 * mean. */
bool boot_anchor_snapshot_path_resolve(struct node_db *ndb, char *buf,
                                       size_t cap)
{
    const char *env_out = getenv("ZCL_MINT_ANCHOR_OUT");
    if (env_out && env_out[0]) {
        int n = snprintf(buf, cap, "%s", env_out);
        return n > 0 && (size_t)n < cap;
    }
    const char *env_override = getenv("ZCL_ANCHOR_SNAPSHOT_PATH");
    if (env_override && env_override[0]) {
        struct stat st;
        if (stat(env_override, &st) == 0 && S_ISREG(st.st_mode)) {
            int n = snprintf(buf, cap, "%s", env_override);
            return n > 0 && (size_t)n < cap;
        }
    }
    const char *dbpath = sqlite3_db_filename(ndb->db, "main");
    if (!dbpath || !dbpath[0]) return false;
    /* Strip the trailing "/node.db" to get the datadir. */
    char dir[1024];
    int n = snprintf(dir, sizeof(dir), "%s", dbpath);
    if (n <= 0 || (size_t)n >= sizeof(dir)) return false;
    char *slash = strrchr(dir, '/');
    if (slash) *slash = '\0'; else snprintf(dir, sizeof(dir), ".");
    int m = snprintf(buf, cap, "%s/utxo-anchor.snapshot", dir);
    return m > 0 && (size_t)m < cap;
}

const char *anchor_snapshot_reject_reason_str(enum anchor_snapshot_reject_reason r)
{
    switch (r) {
    case ANCHOR_SNAPSHOT_OK:                  return "ok";
    case ANCHOR_SNAPSHOT_NO_CHECKPOINT:       return "no_compiled_checkpoint";
    case ANCHOR_SNAPSHOT_ABSENT:              return "absent";
    case ANCHOR_SNAPSHOT_MALFORMED:           return "malformed_or_self_sha3_mismatch";
    case ANCHOR_SNAPSHOT_CHECKPOINT_MISMATCH: return "checkpoint_mismatch";
    }
    return "unknown";  /* raw-return-ok:exhaustive-enum-switch-default-unreachable */
}

/* Read-only probe: is a fully integrity-checked legacy anchor artifact
 * reachable for THIS transparent checkpoint? True iff the file has an exact,
 * fully body-SHA3-verified layout and its independently recomputed UTXO
 * height/hash/root/count/supply all equal the compiled checkpoint. This exact
 * predicate is shared by boot_anchor_seed_from_snapshot and
 * boot_load_verify_snapshot_eligible (boot_refold_staged.c) before they trust
 * a snapshot, and by boot_refold_from_anchor_arm_if_torn's AUTO-ARM so it can
 * DECLINE (instead of falling into the node.db reseed + FATAL) when no
 * verified snapshot exists. No coins_kv mutation: mmaps read-only, closes
 * immediately.
 *
 * REJECTION TAXONOMY: every "not reachable" path sets *reason_out to a typed
 * enum anchor_snapshot_reject_reason (config/boot.h) and LOG_WARNs it with the
 * exact path tried, instead of collapsing absent/malformed/mismatched into one
 * bare false the caller cannot explain. path_out/reason_out may be NULL. NOTE:
 * this binds ONLY the transparent UTXO component (height/anchor_block_hash/
 * count/total_supply/UTXO-only SHA3) to sha3_utxo_checkpoint — a v2/v3
 * snapshot's embedded Sapling/Sprout/nullifier section (uss_frontier/
 * uss_shielded) is covered by the file's OWN internal self-consistency check
 * (uss_open's verify_full_sha3 over the complete payload) but is NOT compared
 * here to any baked shielded checkpoint; that binding belongs to the separate
 * rom_state_checkpoint / zcl.consensus_state_bundle.v1 path
 * (engine/composition/src/boot_mint_anchor_rom_keystone.c, consensus_state_bundle_validate.c),
 * a different artifact from utxo-anchor.snapshot. */
static bool anchor_snapshot_verified_reachable_ex(
    struct node_db *ndb, const struct sha3_utxo_checkpoint *cp,
    char *path_out, size_t path_cap,
    enum anchor_snapshot_reject_reason *reason_out)
{
    if (path_out && path_cap)
        path_out[0] = '\0';
    if (reason_out)
        *reason_out = ANCHOR_SNAPSHOT_NO_CHECKPOINT;
    if (!ndb || !cp)
        return false;

    char path[1100];
    if (!boot_anchor_snapshot_path_resolve(ndb, path, sizeof(path))) {
        if (reason_out) *reason_out = ANCHOR_SNAPSHOT_ABSENT;
        return false;
    }

    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (reason_out) *reason_out = ANCHOR_SNAPSHOT_ABSENT;
        LOG_WARN("boot", "[boot] anchor snapshot reachability: %s "
                 "(reason=%s)", path, anchor_snapshot_reject_reason_str(
                     ANCHOR_SNAPSHOT_ABSENT));
        return false;
    }

    char err[256] = {0};
    struct uss_header hdr;
    struct uss_handle *h = uss_open(path, /*verify_full_sha3=*/true,
                                    /*expected_sha3=*/NULL,
                                    &hdr, err, sizeof(err));
    if (!h) {
        if (reason_out) *reason_out = ANCHOR_SNAPSHOT_MALFORMED;
        LOG_WARN("boot", "[boot] anchor snapshot reachability: %s "
                 "(reason=%s): %s", path,
                 anchor_snapshot_reject_reason_str(ANCHOR_SNAPSHOT_MALFORMED),
                 err[0] ? err : "(no detail)");
        return false;
    }
    bool ok = boot_legacy_uss_matches_checkpoint(
        h, &hdr, cp, err, sizeof(err));
    uss_close(h);
    if (!ok) {
        if (reason_out) *reason_out = ANCHOR_SNAPSHOT_CHECKPOINT_MISMATCH;
        LOG_WARN("boot", "[boot] anchor snapshot reachability: %s "
                 "(reason=%s): %s", path,
                 anchor_snapshot_reject_reason_str(
                     ANCHOR_SNAPSHOT_CHECKPOINT_MISMATCH),
                 err[0] ? err : "component mismatch");
        return false;
    }

    if (path_out) snprintf(path_out, path_cap, "%s", path);
    if (reason_out) *reason_out = ANCHOR_SNAPSHOT_OK;
    return true;
}

/* Shared with boot_refold_staged.c's AUTO-ARM (boot_refold_from_anchor_arm_
 * if_torn) via config/boot_internal.h — the bare-bool form for a call site
 * that only needs to branch, not explain. */
bool anchor_snapshot_verified_reachable(struct node_db *ndb,
                                        const struct sha3_utxo_checkpoint *cp)
{
    return anchor_snapshot_verified_reachable_ex(ndb, cp, NULL, 0, NULL);
}

/* Public gate for the runtime refold rung (config/boot.h): the compiled
 * checkpoint AND its verified minted snapshot must both be reachable so
 * boot_refold_from_anchor_reset can load a proven anchor set (it FATAL-refuses
 * otherwise). Reports the checkpoint height so the rung can name the anchor. */
bool boot_refold_from_anchor_artifact_available(struct node_db *ndb,
                                                int32_t *anchor_height_out)
{
    return boot_refold_from_anchor_artifact_available_ex(
        ndb, anchor_height_out, NULL, 0, NULL);
}

/* Detail-carrying sibling (config/boot.h): same predicate, plus the typed
 * rejection reason and (on success) the exact resolved path — the form W1-L1
 * (cold-start install), W1-L2 (recovery base), and Workflow-2 (shielded
 * frontier) should call when they want to log or branch on WHY a snapshot
 * isn't usable, not just whether. */
bool boot_refold_from_anchor_artifact_available_ex(
    struct node_db *ndb, int32_t *anchor_height_out,
    char *path_out, size_t path_cap,
    enum anchor_snapshot_reject_reason *reason_out)
{
    if (anchor_height_out)
        *anchor_height_out = -1;
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    if (!cp) {
        if (reason_out) *reason_out = ANCHOR_SNAPSHOT_NO_CHECKPOINT;
        return false;
    }
    if (anchor_height_out)
        *anchor_height_out = cp->height;
    return anchor_snapshot_verified_reachable_ex(ndb, cp, path_out, path_cap,
                                                 reason_out);
}
