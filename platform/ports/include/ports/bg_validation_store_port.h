/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * bg_validation_store_port — storage interface for the resume cursor the
 * background FULL validation service persists.
 *
 * bg_validation is a read-ONLY, NON-CONSENSUS observer: after fast sync it
 * walks every block from genesis re-verifying Equihash PoW, ECDSA script
 * signatures, Ed25519 JoinSplit signatures, and Groth16/PHGR13 proofs. It
 * never modifies the UTXO set, the block index, or the active chain. The
 * persisted state is a crash-resume cursor, cumulative script-skip count,
 * and a coverage-semantics version. The version prevents a legacy cursor
 * minted by skip-on-missing-body code from authorizing a resumed walk.
 *
 *   load_progress(out)   read the "bg_validation_height" state key; sets
 *                        *out and returns true if present, false (out
 *                        untouched) on a missing key / unavailable store —
 *                        the caller then restarts from genesis.
 *   save_progress(h)     persist the current verified height under the same
 *                        key; returns true on success. Passing -1 clears
 *                        the cursor back to the genesis-restart sentinel
 *                        (used by bg_validation_reset / stop).
 *
 * No sqlite type appears in this header. The adapter under
 * platform/adapters/outbound/persistence/ is the only thing that names the
 * sqlite-backed node DB for this subsystem. It wraps an already-open
 * connection opened by boot and never takes ownership.
 *
 * Threading: load runs once at startup on the dedicated validation thread;
 * save runs periodically on that same thread (and once from the
 * stop/reset path). They go through the node-DB state-kv path, whose own
 * locking serializes them against other writers — the same concurrency
 * contract the inline code had before the seam.
 */

#ifndef ZCL_PORTS_BG_VALIDATION_STORE_PORT_H
#define ZCL_PORTS_BG_VALIDATION_STORE_PORT_H

#include <stdbool.h>
#include <stdint.h>

struct bg_validation_store_port {
    void *self;

    /* Read the persisted resume height into *out. Returns true if the
     * cursor key exists (leaving *out set), false (out untouched) if the
     * store is unavailable or the key has never been written. */
    bool (*load_progress)(void *self, int *out);

    /* Persist `height` as the resume cursor (-1 clears it to the
     * genesis-restart sentinel). Returns true on success, false on a
     * NULL self / unavailable store. */
    bool (*save_progress)(void *self, int height);

    /* Read the persisted cumulative "script-verification skipped, no undo"
     * tally into *out. Same get/set-int semantics as the cursor above but a
     * SEPARATE state key. Returns true if present (leaving *out set), false
     * (out untouched) if unavailable / never written. This counts blocks
     * that advanced verified_height without full script verification (undo
     * missing) so the "verified" claim stays honest across restarts. */
    bool (*load_skips)(void *self, int64_t *out);

    /* Persist the cumulative skip tally. Returns true on success, false on a
     * NULL self / unavailable store. */
    bool (*save_skips)(void *self, int64_t skips);

    /* Missing/zero means the cursor predates fail-closed body coverage and
     * cannot authorize a resumed full-history claim. */
    bool (*load_coverage_version)(void *self, int64_t *out);
    bool (*save_coverage_version)(void *self, int64_t version);
};

#endif /* ZCL_PORTS_BG_VALIDATION_STORE_PORT_H */
