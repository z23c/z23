/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * psc_range_fold — Parallel State Compiler, P0 prototype (fixture-only).
 *
 * PURPOSE: compute the terminal TRANSPARENT UTXO set of a FINALIZED height
 * range [lo,hi] as an order-independent parallel function of the block bodies,
 * instead of the serial per-height utxo_apply walk. This P0 core has two
 * phases: (a) K parallel per-block delta extraction workers over disjoint
 * contiguous height sub-ranges (psc_extract.c), and (b) a sharded outpoint
 * sort-merge join (psc_join.c) that reconstructs the terminal coin set and
 * validates the order-dependent consensus properties (existence, no duplicate
 * outpoint / BIP30, create-before-spend) as an ORDERING property per shard.
 *
 * SCOPE (P0, deliberately narrow): transparent UTXOs only. Shielded commitment
 * trees + the nullifier set stay strictly serial in the production fold and are
 * out of this prototype (the fixture carries no shielded data). No boot / mint
 * wiring — this is the differential-oracle-gated fold core + its proof only.
 *
 * PARITY CONTRACT: PSC changes HOW the terminal transparent set is computed,
 * never WHAT it is. The merge bar (exercised by test_parallel_range_fold) is a
 * BIT-IDENTICAL terminal set vs the serial fold (same SHA3 over the canonical
 * (txid,vout) records — the exact encoder coins_kv_commitment /
 * coins_ram_commitment use), invariant under (K, S).
 *
 * The block source is abstracted behind psc_block_provider_fn so the fold core
 * is decoupled from block storage: in production the provider wraps
 * active_chain_at + stage_read_block (the same lock-free chain-reader + pread
 * pattern bg_validation / pv_lookahead already run concurrently with the fold);
 * in tests it clones from an in-memory fixture array. The provider MUST be
 * safe to call concurrently from K worker threads for distinct heights.
 */
#ifndef ZCL_JOBS_PSC_RANGE_FOLD_H
#define ZCL_JOBS_PSC_RANGE_FOLD_H

#include <stdbool.h>
#include <stdint.h>

struct block;

/* Yield the block at `height` into the caller-owned `blk` (already block_init'd
 * by the caller; the caller block_free's it). Returns true on success, false if
 * the block is unavailable (which aborts the compile with an internal error —
 * PSC only runs over a finalized range whose bodies are all present). Called
 * concurrently from worker threads for DISTINCT heights, so it must be
 * thread-safe. */
typedef bool (*psc_block_provider_fn)(uint32_t height, struct block *blk,
                                      void *user);

/* Result of a range compile. On a clean success `ok` is true and the terminal
 * fields are filled. On a consensus-ordering violation `ok` is false, the
 * terminal fields are undefined, and reject_kind/reject_height name the typed
 * cause the join surfaced. A hard internal/allocation error returns false from
 * psc_compile_range itself (this struct is then only partially filled). */
struct psc_range_result {
    bool ok;                     /* terminal set computed cleanly */

    /* Terminal transparent set — the merge-bar quantities. */
    uint8_t  terminal_sha3[32];  /* SHA3-256 over canonical (txid,vout) records */
    uint64_t terminal_count;     /* number of live coins */
    int64_t  terminal_supply;    /* Σ live coin values */

    /* Typed reject (valid iff !ok). Mirrors compute_block_delta status strings
     * where one exists ("spend_unknown_utxo" / "utxo_collision"). */
    char    reject_kind[48];
    int32_t reject_height;       /* height of the offending event (best-effort) */

    /* Observability / measurement. */
    uint64_t events_total;       /* create + spend events extracted */
    int      k_workers;          /* extraction workers actually used */
    int      s_shards;           /* join shards actually used */
    double   extract_us;         /* wall time of the parallel extraction phase */
    double   join_us;            /* wall time of the sharded join phase */
    double   digest_us;          /* wall time of the terminal digest phase */
    double   total_us;           /* whole compile */
};

/* Compile the terminal transparent UTXO set for the FINALIZED range [lo,hi]
 * (inclusive) from a genesis-empty base, using `k_workers` extraction workers
 * and `s_shards` join shards. `k_workers`/`s_shards` <= 0 auto-size from the
 * CPU topology. Returns true when the compile ran to a definite verdict (check
 * out->ok for accept vs typed reject); returns false only on a hard internal
 * error (out->reject_kind carries a short cause, e.g. "provider_failed").
 *
 * P0 assumes a from-genesis (empty-base) range: every valid transparent spend
 * resolves to a create within [lo,hi]. A partial range with a pre-existing base
 * set (windowed residual propagation) is deferred per the design §4. */
bool psc_compile_range(uint32_t lo, uint32_t hi, int k_workers, int s_shards,
                       psc_block_provider_fn provider, void *provider_user,
                       struct psc_range_result *out);

#endif /* ZCL_JOBS_PSC_RANGE_FOLD_H */
