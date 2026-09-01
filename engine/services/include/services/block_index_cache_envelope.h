/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * block_index_cache integrity envelope — split out of block_index_loader.c
 * for the E1 file-size ceiling (same seam pattern as
 * block_index_sidecar_integrity.c splitting off block_index_integrity.c).
 *
 * block_index.bin (the flat cache) carries an embedded whole-file SHA3
 * (services/block_index_integrity.h, bii_verify_embedded); the SQLite
 * block_index_cache table had only a `COUNT(*) > 1000` sanity floor (Wave N
 * hardening backlog, docs/work/FORWARD_PLAN.md item 7.3). This adds the same
 * class of envelope: a single-row digest in block_index_cache_envelope
 * (engine/models/src/database_migrate_features.c v34), folded and verified in
 * the SAME O(rows) passes save_block_index_recent / load_block_index_sqlite
 * already run (block_index_loader.c) — no second scan on either side.
 *
 * The per-row digest is XOR-combined (not a sequential/streaming hash)
 * because the write side iterates block_map in arbitrary hash-bucket order
 * while the read side iterates `ORDER BY height` — XOR is commutative, so
 * both orders fold to the identical accumulator whenever the row CONTENTS
 * are unchanged. It is still a full cryptographic binding: an attacker who
 * wants a colliding accumulator over a DIFFERENT row multiset needs a SHA3
 * preimage/second-preimage, same as any Merkle-style commitment.
 *
 * The SQLite cache is a pure, re-derivable artifact — a mismatch here NEVER
 * refuses boot. bic_demote() discards the cache (so a corrupt cache never
 * keeps re-tripping this check on a future boot) and raises a named,
 * self-clearing TRANSIENT typed blocker
 * ("block_index_cache.integrity_demoted") so the demotion is visible in
 * dumpstate/automation instead of a log line that scrolls off. */

#ifndef ZCL_SERVICES_BLOCK_INDEX_CACHE_ENVELOPE_H
#define ZCL_SERVICES_BLOCK_INDEX_CACHE_ENVELOPE_H

#include <stdbool.h>
#include <stdint.h>

struct node_db;
struct main_state;
struct block_index;

/* XOR one row's SHA3-256 into `acc`, reading every field directly off `p`.
 * Both call sites populate a `struct block_index` before folding it in —
 * save_block_index_recent() iterates block_map entries directly, and
 * load_block_index_sqlite() has just written the SAME fields into a freshly
 * inserted `pindex` — so one function serves both, and a column that failed
 * to decode on the read side (pindex field left at its zero-init default)
 * naturally mismatches a real save-time value instead of needing a separate
 * NULL-sentinel path. `prev_hash` is passed separately: `p->pprev` is not
 * yet linked at the point load_block_index_sqlite folds a row. */
void bic_row_digest_xor(uint8_t acc[32], const struct block_index *p,
                        const uint8_t prev_hash[32]);

/* Best-effort envelope write: call AFTER block_index_cache's own commit
 * succeeds. A failure here only means the NEXT boot's load sees no envelope
 * (falls back to the pre-existing COUNT-only trust) — never worse than
 * before this feature existed, so it is logged, not propagated. */
void bic_write_envelope(struct node_db *ndb, int64_t row_count,
                        const uint8_t digest[32]);

/* Read the (at most one) envelope row. *present=false with no error logged
 * means "no envelope yet" (a cache written before this feature, or the
 * envelope insert failed) — the caller falls back to the pre-existing
 * COUNT-only trust, never a demotion. */
void bic_read_envelope(struct node_db *ndb, bool *present,
                       int64_t *row_count, uint8_t digest[32]);

/* DEMOTE: discard block_index_cache + its envelope and raise the named
 * TRANSIENT blocker. See the file header above. */
void bic_demote(struct node_db *ndb, int64_t row_count,
                int64_t computed_count, const uint8_t stored[32],
                const uint8_t computed[32]);

/* One-call load-time policy: compares the envelope (if present) against the
 * just-computed digest/count; on a mismatch calls bic_demote() AND resets
 * `ms`'s block_index map to empty (a demoted cache must never leave a
 * caller trusting a partially-verified map). Returns true = cache verified
 * (or no envelope present — pre-existing COUNT-only trust), false =
 * demoted. */
bool bic_verify_or_demote(struct node_db *ndb, struct main_state *ms,
                          bool envelope_present, int64_t envelope_row_count,
                          const uint8_t envelope_digest[32],
                          int64_t computed_row_count,
                          const uint8_t computed_digest[32]);

/* Test-only counter of demotions this process has performed. Not gated
 * behind ZCL_TESTING — a cheap atomic read, same convention as
 * blocker_fire_count_for_testing. */
uint64_t block_index_cache_envelope_demotions_for_testing(void);

#endif /* ZCL_SERVICES_BLOCK_INDEX_CACHE_ENVELOPE_H */
