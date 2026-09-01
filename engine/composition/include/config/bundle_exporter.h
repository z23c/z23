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
 * WHAT THIS PROVES: a bundle from a SELF-FOLDED, single-binary generation —
 * genesis..H* all validated FULL by THIS running binary with the session held
 * open the whole time. It does NOT (yet) produce bundles from a bundle-INSTALLED
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
#endif

#endif /* ZCL_CONFIG_BUNDLE_EXPORTER_H */
