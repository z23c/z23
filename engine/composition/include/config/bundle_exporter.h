/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * bundle_exporter — the STANDING live consensus-state bundle exporter (lane C1
 * of the Instant-Sync program). On a qualified serving node it holds a producer
 * receipt session open (so the live reducer keeps stamping script_validate /
 * proof_validate rows with THIS binary's source epoch) and runs a supervised
 * periodic job that, every N durable blocks, monotonic-re-finalizes the source
 * receipt at the current durable tip and exports a fresh, fully fail-closed
 * zcl.consensus_state_bundle.v1 into <datadir>/bundles/, keeping K generations.
 *
 * The export runs against a PRIVATE read-only WAL snapshot of progress.kv
 * (consensus_state_snapshot_export_from_progress_snapshot) so the reducer is
 * never stalled for the proof + copy.
 *
 * WHAT THIS PROVES: a bundle from a SELF-FOLDED, single-SOURCE-EPOCH generation
 * — genesis..H* all validated FULL under one source epoch (source tree +
 * toolchain + build inputs), with the receipt finalized and re-checked against
 * the LIVE running executable at export time. The export proof itself is what
 * enforces this: every genesis..H* row of every source-epoch-bound reducer
 * stage must carry the receipt's source_epoch_digest
 * (consensus_export_prove_stage_rows), and the finalized receipt's
 * running_binary_digest must equal SHA3(/proc/self/exe) right then.
 *
 * A BINARY UPGRADE NO LONGER STOPS THE MINT. The durable producer session is
 * bound to the executable IMAGE digest, so every relink makes it foreign and
 * consensus_state_producer_receipt_begin refuses — which used to end minting
 * permanently, since nothing re-ran the gate in-process. The exporter now
 * retries on its own tick with bounded backoff and, when the source epoch
 * already stamped into this datadir is byte-identical to this build's,
 * retires the foreign session row and re-derives one from the running binary.
 * When the epoch actually CHANGED, it does not: those rows carry the old epoch
 * and no bundle could be proven from them, so that case stays fail-closed and
 * is named with its literal cause. It does NOT (yet) produce bundles from a bundle-INSTALLED
 * node: the A3 activate install clears the script/proof validate logs below the
 * install height, so those rows are absent and the genesis..H* stage-row proof
 * cannot be reconstructed without base-evidence composition (a documented
 * follow-up that needs coordination with the A3 install to record the installed
 * bundle's proof digest as base evidence).
 *
 * FAIL-SAFE: nothing here can fail a boot. When provenance does not qualify, the
 * session is not opened and the reason is a dumpstate-visible named degradation
 * (`z23 dumpstate bundle_exporter`). */

#ifndef ZCL_CONFIG_BUNDLE_EXPORTER_H
#define ZCL_CONFIG_BUNDLE_EXPORTER_H

#include <stdbool.h>
#include <stdint.h>

#include <sqlite3.h>

/* Open the producer session if this serving node's provenance qualifies, then
 * register the supervised rolling re-finalize+export job. Idempotent; returns
 * true when the job was registered (whether or not the session opened) and
 * false only on a hard wiring error — the boot caller ignores the result so a
 * degraded exporter never blocks boot. `datadir` must be the live datadir
 * (bundles are written under <datadir>/bundles/). `pdb` is the owned
 * progress.kv handle. */
bool bundle_exporter_start(sqlite3 *pdb, const char *datadir);

/* Stop ticking the supervised job (the durable session in progress.kv is left
 * intact). Safe to call repeatedly and from shutdown. */
void bundle_exporter_stop(void);

/* Register the exporter as an optional maintenance service on `kernel`
 * (ctx = the DATADIR string, like disk_monitor — NOT a DB handle; the
 * exporter writes <datadir>/bundles and reads the owned progress.kv).
 * Fail-safe: the service start records a dumpstate degradation and still
 * arms rather than failing, so a degraded exporter never blocks boot. */
struct zcl_service_kernel;
bool bundle_exporter_register_service(struct zcl_service_kernel *kernel,
                                      const char *datadir);

/* `z23 dumpstate bundle_exporter` (dump-state convention).
 * `out` is json_set_object'd by the caller; this also does it defensively.
 * `key` is unused. */
struct json_value;
bool bundle_exporter_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
/* Pure qualification-rung probe: producer authority is a lowercase 64-hex
 * SHA-256 source identity, never a Git object ID or display trace. */
bool bundle_exporter_source_identity_is_exact_for_test(const char *source_id);

/* GAP-1a at-tip gate (pure): true iff the node is close enough to the network
 * tip to publish a starter bundle (synced, or log_head_gap within max_tip_gap;
 * an unknown gap while unsynced fails closed). */
bool bundle_exporter_at_tip_ok_for_test(bool synced, int log_head_gap,
                                        int64_t max_tip_gap);

/* GAP-1b cadence gate (pure): true iff an export is DUE (block ceiling OR time
 * ceiling, both fenced by the min-secs floor; nothing new is never due). */
bool bundle_exporter_export_due_for_test(int64_t h, int64_t last_h,
                                         int64_t elapsed_secs,
                                         int64_t every_blocks,
                                         int64_t every_secs, int64_t min_secs);

/* GAP-2 rotation seam: run the exporter's generation rotation (keep the `keep`
 * newest bundle heights under `dir`, deregister+unlink the rest) against a
 * fixture. Pair with the skip-validate toggle so lightweight SQLite-shaped
 * fixtures (not full valid bundles) can exercise the deregister+unlink path. */
void bundle_exporter_rotate_for_test(const char *dir, int keep,
                                     const char *datadir);
void bundle_exporter_set_rotate_skip_validate_for_test(bool on);

/* Recovery seams — the retry-with-backoff path that a binary upgrade needs.
 *
 * epoch_adoptable (pure): may a FOREIGN producer session be retired and
 * re-derived? Only when the source epoch already stamped into this datadir's
 * fold rows is byte-identical to this build's. Either side NULL = absent =
 * fails closed. This is the gate that keeps a real source change refused. */
bool bundle_exporter_epoch_adoptable_for_test(const uint8_t *stamped,
                                              const uint8_t *current);

/* Run exactly one recovery attempt — what the worker does per tick while the
 * session is not open — ignoring the backoff window. True iff a producer
 * session is open afterwards. */
bool bundle_exporter_recover_once_for_test(void);

/* The same accounting a successful mint performs (streak reset + blocker
 * cleared), so the clear-on-success contract is testable without a fully
 * folded datadir. */
void bundle_exporter_note_export_ok_for_test(void);

/* Make the recovery step behave as if qualification passed and
 * consensus_state_producer_receipt_begin REFUSED with `err`, so the
 * mismatch -> re-derive -> retry path is reachable from a unit fixture.
 * NULL clears the injection. */
void bundle_exporter_inject_session_failure_for_test(const char *err);

/* Consecutive failed attempts required before bundle_exporter.degraded is
 * raised (BX_DEGRADED_AFTER_FAILURES). */
int bundle_exporter_degraded_after_failures_for_test(void);
#endif

#endif /* ZCL_CONFIG_BUNDLE_EXPORTER_H */
