/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Oracle policy — turns EV_ORACLE_DISAGREE events from the
 * zclassicd_oracle_service into a state machine that can pause new
 * block acceptance and panic on evidence-prefix violations.
 *
 * State machine:
 *   NORMAL  → on disagree at h ≤ TRUST_PREFIX_END     → PANIC
 *           → on N distinct heights within W seconds  → HALTED
 *   HALTED  → operator clears via oracle_policy_clear()
 *   PANIC   → operator clears via oracle_policy_clear()
 *
 * HALT effect: chain_advance refuses new tip extension. Wallets and
 * RPC stay readable; we just stop committing forward until the
 * disagreement is investigated.
 *
 * PANIC effect: same as HALT, but the evidence prefix is now provably
 * disagreeing with our local data — the coins.db / blk*.dat is
 * corrupted. Refuse all writes; do not write the evidence cache cookie.
 *
 * See CLAUDE.md "Adding state introspection" — dump_state_json
 * follows that convention. */

#ifndef ZCL_SERVICES_ORACLE_POLICY_H
#define ZCL_SERVICES_ORACLE_POLICY_H

#include <stdbool.h>
#include <stdint.h>

struct json_value;

enum oracle_policy_state {
    OP_NORMAL = 0,
    OP_HALTED = 1,
    OP_PANIC  = 2,
};

struct oracle_policy_config {
    int     window_secs;             /* default 300 — sliding observation window */
    int     halt_distinct_heights;   /* default 3 — trigger HALT at this many */
    int     evidence_prefix_end_height; /* heights ≤ this trigger PANIC */
};

/* Initialize once. Idempotent. */
void oracle_policy_init(const struct oracle_policy_config *cfg);

/* Called by the oracle service for each disagreement observation.
 * Thread-safe.  Records into the sliding window and, if thresholds
 * are crossed, transitions state + emits EV_FORK_SUSPECTED /
 * EV_ANCHOR_PANIC / EV_CHAIN_HALTED. */
void oracle_policy_record_disagreement(int height,
                                        const char *our_hash_hex,
                                        const char *their_hash_hex);

/* Query: is chain_advance allowed to extend tip right now? */
bool oracle_policy_chain_extension_allowed(void);

/* Query: current state. */
enum oracle_policy_state oracle_policy_get_state(void);

/* Human-readable state name ("normal"/"halted"/"panic"). Never NULL. */
const char *oracle_policy_state_name(enum oracle_policy_state s);

/* Operator: reset to NORMAL (e.g. via native after investigation). */
void oracle_policy_clear(void);

/* `z23 dumpstate oracle_policy` entry. */
bool oracle_policy_dump_state_json(struct json_value *out, const char *key);

/* Test hook — reset state + counters between unit tests. */
void oracle_policy_reset_for_test(void);

#endif /* ZCL_SERVICES_ORACLE_POLICY_H */
