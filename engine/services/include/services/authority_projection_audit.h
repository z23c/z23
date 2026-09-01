/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * authority_projection_audit — REDUNDANT, BACKGROUND, SAMPLED defense-in-depth
 * cross-check that catches a silently WRONG derived UTXO value the primary
 * reducer path would miss.
 *
 * At an applied height where the coins_kv AUTHORITY (the consensus coin set)
 * and the `utxos` PROJECTION (the read-only mirror) provably reflect the SAME
 * height, their canonical SHA3-256 UTXO commitment roots + UTXO counts MUST be
 * byte-identical — both derive from the one must-never-fork record encoder
 * (utxo_commitment_sha3_write_record). A divergence is a torn-coin / dropped-
 * spend / projection-drift bug that is otherwise SILENT.
 *
 * This module NEVER changes a validity predicate or the primary derivation:
 * consensus is FROZEN. It recomputes the SAME root, independently, over BOTH
 * sources and asserts equality. It runs at a low (hourly) cadence off the fold
 * hot path, reads coins only through coins_kv_commitment()/coins_kv_count()
 * (which honour the RAM read-flip), and NEVER takes the reducer drive lock
 * (LOCK-ORDER LAW) — the applied-height markers are read under the brief
 * progress_store trylock the observational surfaces use. On a confirmed
 * mismatch it raises the PERMANENT blocker `authority_projection_divergence`
 * carrying both roots + counts + the height.
 */

#ifndef ZCL_SERVICES_AUTHORITY_PROJECTION_AUDIT_H
#define ZCL_SERVICES_AUTHORITY_PROJECTION_AUDIT_H

#include <stdbool.h>
#include <stdint.h>

/* ── Pure evaluator (no IO; unit-testable) ──────────────────────────── */

struct ap_audit_inputs {
    bool     comparable;    /* both applied-height markers known AND equal,
                             * unchanged across the whole recompute window */
    int32_t  height;        /* the agreed applied height both sources reflect */
    uint8_t  auth_root[32]; /* coins_kv (authority) SHA3 commitment root */
    uint64_t auth_count;    /* coins_kv live UTXO count */
    uint8_t  proj_root[32]; /* utxos (projection) SHA3 commitment root */
    uint64_t proj_count;    /* utxos live UTXO count */
};

struct ap_audit_verdict {
    bool violated;          /* comparable AND (root or count) diverged */
    bool root_mismatch;
    bool count_mismatch;
    char detail[192];
};

/* Compare the authority and projection commitments. When `comparable` is
 * false the verdict is a clean no-violation (the caller only compares at a
 * proven-equal height). Pure — no globals, no IO. */
void ap_audit_evaluate(const struct ap_audit_inputs *in,
                       struct ap_audit_verdict *out);

/* Fold a verdict into the streak/blocker bookkeeping. A CLEAN verdict resets
 * the streak, bumps the pass counter, and self-clears any latched blocker. A
 * VIOLATED verdict is confirmed across two consecutive samples (to swallow any
 * residual torn-scan race) before it raises the PERMANENT
 * `authority_projection_divergence` blocker carrying both roots. Returns true
 * iff THIS call raised the blocker. Exposed for unit tests (no DB required). */
bool ap_audit_apply_verdict(const struct ap_audit_verdict *v,
                            int32_t height,
                            uint64_t auth_count, uint64_t proj_count,
                            const uint8_t auth_root[32],
                            const uint8_t proj_root[32]);

/* ── Background pass + wiring ────────────────────────────────────────── */

/* One audit pass: read both applied-height markers, and only when they agree
 * (before AND after) recompute the SHA3 root + count over the coins_kv
 * authority and the utxos projection and compare. Read-only. Never takes the
 * reducer drive lock. Returns false only when the node DB / progress store is
 * not wired (early boot / unit tests). */
bool ap_audit_run_once(void);

/* Register the hourly supervisor child in the chain domain. Idempotent. */
void ap_audit_register(void);

/* Reset all counters/streak/latched blocker — test-only fixture reset. */
void ap_audit_reset_for_test(void);

/* `z23 dumpstate authority_projection`. See the "Adding state
 * introspection". Reentrant-safe. */
struct json_value;
bool ap_audit_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_AUTHORITY_PROJECTION_AUDIT_H */
