/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * coins_fault — test-only ALGORITHMIC-regression injection for the UTXO map.
 *
 * Why this exists
 * ---------------
 * The deterministic simulator proves the chain is CORRECT. Nothing proved it
 * was still FAST. A perf detector that only ever prints a number nobody
 * checks is worthless, so the detector (tools/sim/simperf.c,
 * engine/modules/sim/src/simnet_perf.c) needs a real regression it can be pointed at:
 * something that leaves every consensus result bit-identical and only makes
 * the node slower. This is that regression, and it is the only thing in the
 * tree armed by `simperf --inject=coins-hash-collapse`.
 *
 * The injected bug
 * ----------------
 * `struct coins_map` (coins/coins_view.h) is an open-addressed, linear-probe
 * hash map from txid -> cached coins; it is THE UTXO lookup structure every
 * `connect_block` fold walks. Its bucket index comes from
 * `coins_map_hash()` = the first 8 bytes of the txid. Arming
 * `degraded_hash` collapses that index to a single constant bucket, so every
 * key lands on one probe chain: find/insert/erase stay perfectly CORRECT
 * (linear probing over a consistent hash always is) and degrade from O(1) to
 * O(n), making the whole UTXO fold O(n^2).
 *
 * That is a real, recurring bug class, not a strawman: a hash whose entropy
 * silently collapses (a truncation that keeps only a constant prefix, a
 * mixing step dropped in a refactor, a "simplified" key derivation) passes
 * every correctness test in the tree — the map still returns the right coin
 * for every key — and shows up only as a node that got slower. It is exactly
 * the failure the QAP-oracle lesson warns about: a checker that counts
 * results, not costs, reports green while the code is genuinely wrong.
 *
 * Arming contract
 * ---------------
 * Flip it ONLY on an EMPTY map. Every live entry's slot was chosen by
 * whichever hash was in force when it was inserted, so changing the hash
 * under a populated map would strand entries behind an empty slot and break
 * lookups — a correctness fault, not a perf one. `coins_fault_arm_map_hash_
 * collapse()` therefore refuses (and logs) on a non-empty map.
 *
 * Cost when not armed: one already-resident struct-field load per bucket
 * index — no global, no atomic, no call. Default false for every map,
 * because `coins_map_init()` clears it.
 */

#ifndef ZCL_COINS_COINS_FAULT_H
#define ZCL_COINS_COINS_FAULT_H

#include <stdbool.h>

struct coins_map;

/* Arm (or disarm) the single-bucket hash collapse on `m`.
 *
 * Returns false (and logs) if `m` is NULL or already holds entries — see the
 * arming contract above. Disarming an empty map is always allowed. */
bool coins_fault_arm_map_hash_collapse(struct coins_map *m, bool on);

/* True iff the collapse is armed on `m`. NULL reads as false. */
bool coins_fault_map_hash_collapsed(const struct coins_map *m);

#endif /* ZCL_COINS_COINS_FAULT_H */
