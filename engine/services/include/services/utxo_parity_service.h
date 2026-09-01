/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_parity_service — STANDING consensus parity vs a co-located zclassicd.
 *
 * Two complementary checks run each tick (60 s cadence via chain.utxo_parity_poll):
 *
 *   1. COARSE BLOCK-HASH (fires at tip): h_check = min(applied,frontier) -
 *      finality_depth. Gets our local block hash from the block index and the
 *      reference's via getblockhash RPC. Match → checks_total++. Mismatch →
 *      LATCHES 'parity_bh_drift_detected' (operator-cleared only) so the
 *      existing Condition pages. Any transport/availability error →
 *      skips_total++ (NEVER pages on unreachability). Advance-only: once a
 *      height is checked it is cached.
 *
 *   2. EXACT UTXO SHA3 (fires only when applied is reorg-safe): recomputes
 *      the local SHA3 UTXO commitment at the live applied height and diffs it
 *      against the pluggable reference, writing 'utxo_drift_detected'.
 *
 * Each check owns a SEPARATE flag; the utxo_drift_detected Condition pages on
 * either — single pager, no new EV_OPERATOR_NEEDED emits live here. They must
 * NOT share a key: the SHA3 path's confirmations clear ITS flag, and with the
 * advance-only cache a BH-mismatched height is never re-examined, so a shared
 * flag would let a later SHA3 confirmation silently un-page a real divergence
 * (wave-3 review finding).
 *
 * Threading: this module creates no background work. The supervised
 * chain.utxo_parity_poll Job owns cadence and calls utxo_parity_tick_once().
 * The tick is event-gated by a finalized-frontier marker maintained from an
 * EV_CHAIN_TIP_COMMIT observer cross-checked against the durable finalized
 * height.
 *
 * Activation: prod turns on automatically when a co-located zclassicd RPC
 * reference resolves at boot (ZCL_PARITY_ORACLE=0 to opt out). Without a
 * reference, the service is a quiet no-op — no health impact, no log spam.
 */

#ifndef ZCL_SERVICES_UTXO_PARITY_SERVICE_H
#define ZCL_SERVICES_UTXO_PARITY_SERVICE_H

#include "services/utxo_audit_service.h"
#include "services/utxo_reference_source.h"
#include "util/result.h"

#include <stdbool.h>
#include <stdint.h>

struct node_db;
struct json_value;

struct utxo_parity_config {
    bool enabled;             /* master gate; default false (dormant) */
    int  finality_depth;      /* stability margin below the frontier; def 100 */
    int  max_checks_per_tick; /* bound full-set SHA3 cost per tick; def 1 */
    struct utxo_parity_rpc_config rpc; /* prod zclassicd reference transport */
};

/* Lifecycle. `ndb` is the runtime node_db (may be NULL in early boot — the
 * tick re-reads app_runtime_node_db() defensively when its handle is NULL). */
struct zcl_result utxo_parity_init(const struct utxo_parity_config *cfg,
                                   struct node_db *ndb);

/* Inject the reference source (test seam + prod wire). `src` is caller-owned
 * and must outlive the service. Passing NULL detaches the source (dormant). */
void utxo_parity_set_reference_source(const struct utxo_reference_source *src);

/* Override the RPC config used by the coarse block-hash check (normally
 * supplied via cfg.rpc at utxo_parity_init; this setter lets boot re-apply
 * after creds are resolved from ~/.zclassic/zclassic.conf). */
void utxo_parity_set_rpc_config(const struct utxo_parity_rpc_config *rpc);

/* Install the EV_CHAIN_TIP_COMMIT observer that maintains the finalized
 * frontier marker. Cheap and always safe; idempotent. */
void utxo_parity_observe_finalization(void);

/* Scheduler-independent Job body. Dormant unless enabled + a reference and a
 * fresh stable frontier target exist. */
void utxo_parity_tick_once(void);

/* Synchronous one-shot check at the live applied `height` against the wired
 * reference (unit test + native escape hatch). Returns the comparator result. */
struct zcl_result utxo_parity_check_height(int32_t height,
                                           struct utxo_audit_result *out);

/* Test seam: force the finalized-frontier marker (mirrors the observer). */
void utxo_parity_set_frontier_for_test(int32_t height);

/* Test seams: inject mock local-block-hash / reference-getblockhash resolvers
 * so unit tests run without a live block index or open sockets.
 * Pass NULL to restore the production paths. */
void utxo_parity_set_local_hash_fn(
    bool (*fn)(void *ctx, int32_t height, char out_hex[65]), void *ctx);

void utxo_parity_set_ref_hash_fn(
    bool (*fn)(void *ctx, int32_t height, char out_hex[65],
               int32_t *ref_height_out, char err[128]),
    void *ctx);

bool utxo_parity_dump_state_json(struct json_value *out, const char *key);
void utxo_parity_reset_for_test(void);

#endif /* ZCL_SERVICES_UTXO_PARITY_SERVICE_H */
