/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Checkpoint LADDER verifier — mutual + baked consistency over N rungs.
 *
 * Given the compiled sealed keystone (the ONE baked rung) plus zero or more
 * candidate rung artifacts, the verifier checks, per rung:
 *   - self-consistency  (rom_state_root + self_digest recompute from fields);
 *   - monotonicity      (strictly-increasing height, non-decreasing chainwork
 *                        across the ladder in ascending order);
 *   - baked binding     (a rung AT the compiled keystone height must reproduce
 *                        the compiled keystone byte-for-byte — otherwise it is a
 *                        divergent artifact and MISMATCH);
 *   - header binding    (optional hook: the rung's block hash matches the node's
 *                        header chain at that height);
 *   - root re-derivation(optional hook: where the node holds the state at that
 *                        height, re-derive the roots and compare).
 *
 * Each rung gets a verdict: VERIFIED, UNVERIFIABLE, or MISMATCH. Only the
 * compiled keystone is `bound` (a trust root); every other rung is
 * `candidate_unbaked` — self-attestation that this module NEVER elevates to
 * trusted, even when it verifies clean (lane spec rule 4). A MISMATCH is a
 * divergence the caller escalates to a typed blocker.
 *
 * The verifier is pure (no globals, no IO); the dumpstate wrapper
 * (checkpoint_ladder_dump_state_json) loads the compiled keystone + on-disk
 * candidate artifacts and raises the blocker.
 */

#ifndef ZCL_STORAGE_CHECKPOINT_LADDER_H
#define ZCL_STORAGE_CHECKPOINT_LADDER_H

#include "storage/checkpoint_rung.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;

enum checkpoint_rung_verdict {
    CHECKPOINT_RUNG_VERIFIED = 0,     /* self-consistent + a positive external
                                       * check (baked binding, header, rederive) */
    CHECKPOINT_RUNG_UNVERIFIABLE = 1, /* self-consistent, no external witness */
    CHECKPOINT_RUNG_MISMATCH = 2,     /* a check FAILED — divergent artifact */
};

const char *checkpoint_rung_verdict_name(enum checkpoint_rung_verdict v);

/* Optional live-state hooks. Any member may be NULL; a NULL hook simply
 * contributes no witness (leaving a rung UNVERIFIABLE rather than VERIFIED). */
struct checkpoint_ladder_hooks {
    void *ctx;
    /* Fill out[32] with the header-chain block hash at `height`; return false
     * if the node does not know that height (not a mismatch). */
    bool (*block_hash_at)(void *ctx, int32_t height, uint8_t out[32]);
    /* Fill *out with the node-rederived rung (fields only) at `height` when the
     * node holds the state; return false if it does not (not a mismatch). */
    bool (*rederive_at)(void *ctx, int32_t height, struct checkpoint_rung *out);
};

struct checkpoint_ladder_result {
    int32_t height;
    bool    bound;             /* == the compiled baked keystone at this height */
    bool    candidate_unbaked; /* honesty label: self-attested, not owner-baked */
    enum checkpoint_rung_verdict verdict;
    char    detail[192];
};

/* Verify `n` rungs (ASCENDING height order expected; the verifier flags an
 * out-of-order or duplicate-height rung as MISMATCH). Writes up to `out_cap`
 * results into `out` and returns the number written (min(n, out_cap)). Sets
 * `*any_mismatch` (may be NULL) true iff any rung is MISMATCH. `hooks` may be
 * NULL. */
size_t checkpoint_ladder_verify(const struct checkpoint_rung *rungs, size_t n,
                                const struct checkpoint_ladder_hooks *hooks,
                                struct checkpoint_ladder_result *out,
                                size_t out_cap, bool *any_mismatch);

/* Load candidate rung artifacts (*.rung) from `dir` into `out` (ascending by
 * height), skipping unreadable/foreign/self-inconsistent files (logged, not
 * fatal). Returns the count loaded (<= out_cap). A missing dir returns 0. */
size_t checkpoint_ladder_load_candidates(const char *dir,
                                         struct checkpoint_rung *out,
                                         size_t out_cap);

/* dumpstate provider — subsystem "checkpoint_ladder". Assembles the compiled
 * keystone (as the sole `bound` rung) + on-disk candidate rungs from
 * <datadir>/checkpoint_rungs/, verifies them (no live hooks in this slice, so
 * candidates read UNVERIFIABLE unless self-inconsistent or conflicting with the
 * baked keystone), reports per-rung {height, bound, trust, verdict, detail}, and
 * raises a PERMANENT typed blocker on any MISMATCH. `key` is ignored. */
bool checkpoint_ladder_dump_state_json(struct json_value *out, const char *key);

#endif
