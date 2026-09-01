/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * psc_audit — opt-in Parallel State Compiler audit + `dumpstate psc`.
 *
 * Runs the ORDER-INDEPENDENT parallel compiler (jobs/psc_range_fold.h) over a
 * finalized height range via the PRODUCTION block source (jobs/psc_block_source.h)
 * and compares its terminal TRANSPARENT UTXO set to the DURABLE coins_kv set the
 * serial utxo_apply stage folded. It is a read-only audit: it NEVER writes
 * consensus state and NEVER replaces the serial fold — it recomputes the same
 * terminal set a different way and reports match/mismatch. Intended use is
 * producer re-mints and full audits, where an operator wants an independent
 * cross-check that the durable coins set equals the order-independent function
 * of the block bodies.
 *
 * The comparison is the merge bar: the coins-only SHA3 commitment
 * (coins_kv_commitment, the SAME utxo_commitment_sha3_write_record encoder the
 * parallel digest uses) plus the coins count. A byte-identical SHA3 proves the
 * whole set — membership, per-coin value/height/script/coinbase — matches.
 */
#ifndef ZCL_JOBS_PSC_AUDIT_H
#define ZCL_JOBS_PSC_AUDIT_H

#include <stdbool.h>
#include <stdint.h>

struct main_state;

/* Outcome of one psc_audit_run (also the shape reported by dumpstate psc). */
struct psc_audit_result {
    bool     ran;                /* the parallel compile reached a clean verdict */
    bool     match;              /* parallel terminal == durable coins_kv */
    uint32_t lo, hi;             /* audited range */

    uint8_t  parallel_sha3[32];  /* coins-only SHA3 from the parallel compile */
    uint8_t  durable_sha3[32];   /* coins_kv_commitment() over the durable set */
    uint64_t parallel_count;     /* live coins the parallel compile produced */
    int64_t  durable_count;      /* coins_kv_count() (-1 if unavailable) */
    int64_t  parallel_supply;    /* Sum of parallel live-coin values */

    char     reject_kind[48];    /* non-empty when the compile did NOT accept */
    int32_t  reject_height;

    int      k_workers, s_shards;
    double   compile_us;         /* whole parallel compile wall time */
    double   us_per_block;       /* compile_us / (hi-lo+1) */
};

/* Compile the FINALIZED, from-genesis range [lo,hi] with the parallel state
 * compiler via the production block source (active_chain_at + pread over
 * ms/datadir) and compare the terminal transparent set to the durable coins_kv
 * commitment over progress_store_db(). `k_workers`/`s_shards` <= 0 auto-size
 * (psc_audit_default_workers / workers*2).
 *
 * VALID only when the durable coins set is exactly the from-genesis fold of
 * [lo,hi] with no snapshot-seeded base (see psc_range_fold.h's empty-base
 * contract) — the producer re-mint / full-audit case. Stores the result for
 * `dumpstate psc` and copies it to *out when non-NULL. Returns out->match
 * (false on any reject / internal error / mismatch / bad args). */
bool psc_audit_run(struct main_state *ms, const char *datadir,
                   uint32_t lo, uint32_t hi, int k_workers, int s_shards,
                   struct psc_audit_result *out);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe. Reports the last
 * psc_audit_run (has_run=false before the first audit): ran, match, range,
 * parallel/durable sha3 (hex) + count, parallel supply, k_workers/s_shards,
 * compile_us, us_per_block, reject_kind. Idle-node-safe. */
struct json_value;
bool psc_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_JOBS_PSC_AUDIT_H */
