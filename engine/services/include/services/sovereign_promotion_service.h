/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sovereign_promotion_service — background re-derivation that EARNS sovereignty
 * back for a borrowed RELEASE_ASSISTED node.
 *
 * An assisted install (engine/composition/src/consensus_state_snapshot_install_activate.c)
 * stamps only the operational migration-complete marker and records a promotion
 * SEAM (bundle height + the three manifest commitments). The node serves + and
 * receives but mining/spending/export/seed stay denied (sync_trust_derive:
 * proven=1, self_folded=0 → RELEASE_ASSISTED_READY).
 *
 * This service closes the gap. On a supervised, duty-cycled background loop it:
 *   1. Detects the assisted tier (proven && !self_folded && seam recorded).
 *   2. Re-derives the state from the compiled trust anchor (the baked SHA3/ROM
 *      checkpoint) UP TO the seam height into an ISOLATED store — never the live
 *      coins_kv frontier (single-writer-per-frontier) — folding real on-disk
 *      bodies with the SAME validators. [the isolated re-fold driver is the
 *      remaining integration — see the .c]
 *   3. Compares the re-derived (utxo_root, count, anchor_digest, nullifier_
 *      digest) against the recorded seam (sovereign_promotion_evaluate).
 *   4. MATCH  → flips the LIVE store to sovereign via the generalized seam
 *      ratifier (boot_ratify_seam_check_and_stamp) — self_folded is stamped and
 *      the node becomes SOVEREIGN.
 *      MISMATCH → raises the PERMANENT named blocker
 *      "sovereign_promotion.seam_mismatch" + pages EV_OPERATOR_NEEDED, keeps
 *      serving, and NEVER promotes (the borrowed state disagreed with an
 *      independent fold from the sovereign anchor).
 *
 * Everything below the flip is fail-closed: an install that never matches stays
 * RELEASE_ASSISTED (usable, not sovereign) forever rather than self-promoting on
 * unverified state. */

#ifndef ZCL_SERVICES_SOVEREIGN_PROMOTION_SERVICE_H
#define ZCL_SERVICES_SOVEREIGN_PROMOTION_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

struct sqlite3;
struct json_value;

/* The named PERMANENT blocker a seam mismatch raises. */
#define SOVEREIGN_PROMOTION_MISMATCH_BLOCKER_ID "sovereign_promotion.seam_mismatch"

/* The recorded assisted-tier seam (mirrors the install-side record). */
struct sovereign_promotion_seam {
    int32_t height;
    uint8_t utxo_root[32];
    uint8_t anchor_digest[32];
    uint8_t nullifier_digest[32];
};

/* The independently re-derived commitments at the seam height. */
struct sovereign_promotion_derived {
    int32_t  height;
    uint8_t  utxo_root[32];
    uint64_t utxo_count;
    uint8_t  anchor_digest[32];
    uint8_t  nullifier_digest[32];
};

enum sovereign_promotion_verdict {
    SOVEREIGN_PROMOTION_MATCH = 0,   /* the re-derivation reproduces the seam */
    SOVEREIGN_PROMOTION_MISMATCH,    /* it disagrees — page the operator */
};

/* True iff `db` is in the borrowed RELEASE_ASSISTED tier: migration-complete
 * stamped, self_folded ABSENT, and an assisted seam recorded. Fills *seam when
 * it returns true. Fail-closed (returns false) on any read error or a sovereign
 * / empty node. `seam` may be NULL. */
bool sovereign_promotion_tier_is_assisted(
    struct sqlite3 *db, struct sovereign_promotion_seam *seam);

/* Pure verdict: does the independently re-derived state reproduce the seam
 * (same height and all three commitments)? Total; a NULL argument is MISMATCH. */
enum sovereign_promotion_verdict sovereign_promotion_evaluate(
    const struct sovereign_promotion_derived *derived,
    const struct sovereign_promotion_seam *seam);

/* Apply the verdict to the LIVE store. MATCH → ratify the seam via
 * boot_ratify_seam_check_and_stamp (the live store already holds exactly this
 * (height, root, count), so this atomically stamps self_folded → SOVEREIGN);
 * returns true iff it flipped. MISMATCH → raise the PERMANENT
 * SOVEREIGN_PROMOTION_MISMATCH_BLOCKER_ID blocker + page EV_OPERATOR_NEEDED and
 * return false (never promote). */
bool sovereign_promotion_apply_verdict(
    struct sqlite3 *db, enum sovereign_promotion_verdict verdict,
    const struct sovereign_promotion_seam *seam,
    const struct sovereign_promotion_derived *derived);

/* Duty-cycle gate (env ZCL_PROMOTION_DUTY_PCT, default 25, clamped 1..100): true
 * on the fraction of ticks the promotion re-fold is allowed to run so it yields
 * to the live reducer (they share the body_persist/script_validate engine). */
bool sovereign_promotion_duty_admits(uint64_t tick);

/* Register + start the supervised background child "sync.sovereign_promotion".
 * MERGE-TIME TODO: call this from engine/composition/src/boot_services.c (owned by another
 * lane this window). Idempotent. */
void sovereign_promotion_service_register(void);
void sovereign_promotion_service_stop(void);

/* CLAUDE.md "Adding state introspection". MERGE-TIME TODO: register in
 * engine/controllers/src/diagnostics_registry.c g_dumpers (owned by another lane
 * this window). `out` is caller-initialized. `key` is unused. */
bool sovereign_promotion_dump_state_json(struct json_value *out,
                                         const char *key);

#endif /* ZCL_SERVICES_SOVEREIGN_PROMOTION_SERVICE_H */
