/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * seed_integrity_gate — fail-loud validation pack, check 7 (post-seed
 * linkage gate) + the post-import half of check 5 (commitment gate).
 *
 * Fail at birth: a seed (cold-import, snapshot apply, reducer ingest
 * re-seed) is the moment a poisoned datadir becomes "our" chain. An unchecked
 * seed is caught only dozens of blocks (or one crash-loop) later, if at all.
 * This gate runs BEFORE the cursors are stamped:
 *
 *   step 0 — authority pair: if the blocks projection has a row at the
 *            seed height, its hash must equal the seed hash (subsumes
 *            check 3 at this site).
 *   sweep  — linkage walk: follow prev_hash from the seed tip downward
 *            through PRESENT rows (<= 10,000 steps); every resolved
 *            parent must carry height label child-1. The first broken
 *            link refuses the seed, NAMING (h, parent_h, hashes).
 *   commit — trusted seeds only: when a stored 'utxo_sha3' commitment
 *            exists AT the seed height, recompute over the utxos table
 *            and require an exact hash+count match (the
 *            keyspace-tail truncation detector). Absent/different-height
 *            stamp = skip with a logged note, never a refusal.
 *
 * EXTENDS Invariant A (utxo_recovery_frontier_gate gates RESTORE-family
 * installs via the in-memory index): this gate covers the SEED family
 * via the durable blocks projection — no duplication.
 *
 * Refusal is crash-only: tip_finalize_stage_seed_anchor returns false
 * (all callers already handle it), NO cursor stamp, blocker
 * `seed.linkage_gate` (PERMANENT) + one EV_OPERATOR_NEEDED. Never FATAL.
 * Absent rows below a snapshot base PASS (suffix semantics); an absent
 * tip row is a WARN + counter, not a refusal (projection backfill
 * ordering). A NULL/closed node_db passes with a WARN (unit tests /
 * early boot — tests inject their own handle). */

#ifndef ZCL_SERVICES_SEED_INTEGRITY_GATE_H
#define ZCL_SERVICES_SEED_INTEGRITY_GATE_H

#include <stdbool.h>
#include <stdint.h>

struct node_db;

/* True = seed publishable. False = REFUSE (blocker + page already done).
 * Memoized on (height, hash): the at-tip ingest re-seed calls this every
 * tick; only the first evaluation pays the walk. */
bool seed_integrity_gate_check(int height, const uint8_t hash[32],
                               bool trusted_seed);

/* ARM the commitment half: persist the 'utxo_sha3' stamp at the seed
 * height so gate_commitment_check actually runs for this datadir's
 * trusted seeds. The cold-import path MUST call this with the digest it
 * verified/accepted — a cold-import path that never writes a stamp leaves
 * the gate's commitment half vacuously skipped there, silently missing a
 * keyspace-tail truncation. Trust
 * model: at the compiled SHA3 checkpoint height the stamp is
 * cryptographically grounded; at other heights it pins the ACCEPTED set
 * so any LATER truncation/tear fails the next seed (the same model as
 * the recorded cold_import_seed_anchor_utxo_count key). Callers must NOT
 * stamp a digest computed from a stale SQLite snapshot — a wrong stamp
 * would false-refuse a healthy seed. Returns false on save failure
 * (logged loudly: the gate stays unarmed for this datadir). */
bool seed_integrity_stamp_utxo_sha3(struct node_db *ndb, int height,
                                    const uint8_t root[32], uint64_t count);

#ifdef ZCL_TESTING
void seed_integrity_gate_reset_for_testing(void);
void seed_integrity_gate_set_node_db_for_testing(struct node_db *ndb);
#endif

#endif /* ZCL_SERVICES_SEED_INTEGRITY_GATE_H */
