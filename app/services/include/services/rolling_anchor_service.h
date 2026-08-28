/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Rolling SHA3 anchor extension (T3.1).
 *
 * The compile-time `g_sha3_windows[]` table covers a fixed prefix
 * (genesis..3,110,205 at time of writing). This service extends the
 * evidence prefix at runtime by hashing 1000-block windows of blocks
 * past the prefix and persisting the digests to
 * <datadir>/sha3_windows_runtime.dat.
 *
 * Each runtime window is committed only after every block in the
 * window has reached CONFIRMATION_DEPTH (default 100) confirmations.
 * oracle_policy divergence (HALTED/PANIC) is recorded as evidence
 * (total_oracle_divergence_observed + an EV_SYNC_STATE_CHANGE event) but
 * NEVER gates extension — a co-located zclassicd that is merely wrong or
 * behind must not be able to halt chain-derived state that stands alone;
 * these anchors are self-derived from already-validated local state.
 *
 * Format on disk (binary, little-endian):
 *   [8  bytes] magic "ZCLRAW1\0"
 *   [4  bytes] schema (u32) = 1
 *   [4  bytes] count  (u32)
 *   count * { i32 start_height; u8 hash[32] }   (36 bytes each)
 *   [32 bytes] SHA3-256 over everything above
 *
 * On load: any failure (bad magic / schema / checksum / non-monotonic
 * heights / mismatch with compile-time prefix end) discards the file
 * and falls back to compile-time-only trust.
 *
 * See CLAUDE.md "Adding state introspection" — dump_state_json
 * follows that convention. */

#ifndef ZCL_SERVICES_ROLLING_ANCHOR_SERVICE_H
#define ZCL_SERVICES_ROLLING_ANCHOR_SERVICE_H

#include <stdbool.h>
#include <stdint.h>

#include "util/result.h"

struct main_state;
struct chain_params;
struct json_value;

struct rolling_anchor_config {
    int confirmation_depth;  /* default 100 — depth required to commit anchor */
    int max_extend_per_call; /* default 10 — per-tick extension cap */
};

/* Load persisted runtime anchors from <datadir>/sha3_windows_runtime.dat.
 * Returns ZCL_OK on success or when the file is absent (clean start).
 * Returns non-ok only when the file is present but corrupt — caller
 * may delete it. Idempotent; safe to call multiple times. */
struct zcl_result rolling_anchor_init(const char *datadir,
                          const struct rolling_anchor_config *cfg);

/* Attempt to commit one or more new 1000-block windows past the
 * current effective prefix, up to `cfg.max_extend_per_call`. Reads
 * blocks from disk via the active_chain. No-op when:
 *   - chain tip is below first uncommitted window + confirmation_depth + 999,
 *   - max_extend_per_call already hit.
 * oracle_policy divergence does NOT gate this — see the file doc.
 * Returns number of newly committed windows. */
int rolling_anchor_extend_if_due(struct main_state *ms,
                                  const char *datadir);

/* Boot-time entry: call rolling_anchor_init(datadir) and register a
 * chain-supervisor tick that invokes rolling_anchor_extend_if_due(ms,
 * datadir) every ~60 seconds. Idempotent. Returns ZCL_OK on success. */
struct zcl_result rolling_anchor_start(struct main_state *ms, const char *datadir);

/* Stop the periodic tick. Safe to call when not started. */
void rolling_anchor_stop(void);

/* Effective input-bytes prefix end height (compile-time prefix + committed
 * runtime windows). The seal ratifier requires r.height <= this: the block
 * bytes that produced a sealed state must themselves be sealed (the INPUT
 * prefix must cover G before the OUTPUT seal at G can ratify). Pure read. */
int rolling_anchor_effective_prefix_end(void);

/* SHA3 of the committed window ENDING at end_h (end_h+1 a multiple of 1000),
 * written to out[32]. Returns a non-ok zcl_result if no such window is
 * committed (compile prefix or runtime ring) or the inputs are malformed.
 * Informational input for seal.anchor_window_sha3. Pure read under the
 * rolling_anchor lock. */
struct zcl_result rolling_anchor_window_hash_ending_at(int32_t end_h,
                                                        uint8_t out[32]);

/* `z23 dumpstate rolling_anchor` entry. */
bool rolling_anchor_dump_state_json(struct json_value *out,
                                     const char *key);

/* Test hook — reset state between unit tests. */
void rolling_anchor_reset_for_test(void);

/* Test hooks for the row-8 page path: inject a consecutive read failure (as
 * if a sealed-domain block frame were unreadable) at `failing_height`, then
 * drive the supervisor stall escalation that decides whether to page. Only
 * compiled under ZCL_TESTING. */
#ifdef ZCL_TESTING
struct zcl_result rolling_anchor_test_commit_window(int32_t start_height,
                                                     const uint8_t hash[32]);
void rolling_anchor_test_inject_read_failure(int32_t failing_height);
void rolling_anchor_test_note_window_read_failure(int32_t sealed_end,
                                                  int32_t next_start,
                                                  int32_t failing_height);
int64_t rolling_anchor_test_total_read_failures(void);
int64_t rolling_anchor_test_total_skipped_missing_body(void);
int64_t rolling_anchor_test_consecutive_read_failures(void);
void rolling_anchor_test_reset_read_failures(void);
void rolling_anchor_test_run_stall_escalation(void);
#endif

#endif /* ZCL_SERVICES_ROLLING_ANCHOR_SERVICE_H */
