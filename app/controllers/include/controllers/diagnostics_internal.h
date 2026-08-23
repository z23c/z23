/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Internal seam shared across the diagnostics controller family. Focused
 * controller files (registry, nodelog, dbquery, probe) share two things:
 *
 *   - the controller-level state (`main_state` + `datadir`), owned by
 *     diagnostics_registry.c and reachable here via accessors;
 *   - each file's RPC handler prototypes, so the routing table in
 *     diagnostics_controller.c can register them.
 *
 * This header is internal to app/controllers; it is not part of the
 * public diagnostics_controller.h API. */

#ifndef ZCL_DIAGNOSTICS_INTERNAL_H
#define ZCL_DIAGNOSTICS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

#include "util/supervisor.h" /* enum supervisor_stall_reason (debug bundle) */

struct json_value;
struct main_state;
struct node_db;

typedef bool (*diagnostics_dump_fn)(struct json_value *out, const char *key);

/* Complete descriptor shared by dispatch and statecatalog rendering. Keep
 * entries data-only in diagnostics_dumpers.def; do not reintroduce name-based
 * metadata switches in individual controllers. */
struct diagnostics_dump_entry {
    const char *name;
    diagnostics_dump_fn fn;
    const char *desc;
    const char *state_class;
    const char *owner_shape;
    const char *owner_file;
    const char *freshness;
    const char *cost;
    const char *key_hint;
    const char *key_example_1;
    const char *key_example_2;
    const char *primary_test;
    bool include_supervisor_drilldown;
};

/* Independent second derivation of diagnostics_dumpers.def's row count,
 * defined in diagnostics_registry.c right next to g_dumpers[] by
 * re-including the SAME .def file with a dummy 1-byte-struct element type
 * (unrelated to struct diagnostics_dump_entry above). It cannot be the
 * CONDITION_REGISTRY_COUNT-style bare arithmetic enum (conditions/
 * condition_registry.h) because — unlike condition_registry.def's bare
 * macro-call-per-line format — diagnostics_dumpers.def rows are
 * comma-separated array-initializer elements (g_dumpers[] itself is built
 * by including this file inside `= { ... }`), so a top-level `+1` per row
 * would leave stray commas outside any parens. Building a second array with
 * the file's own commas, exactly as g_dumpers[] does, sidesteps that. Test
 * code compares diagnostics_dumper_count() (g_dumpers[]'s real size) against
 * this — a real cross-check between two separately-compiled counts of one
 * source of truth, not count==count. */
size_t diagnostics_dumpers_def_row_count(void);

/* Wired controller-level state, owned by diagnostics_registry.c.
 * `diag_datadir()` returns "" until set_state() runs. */
const char *diag_datadir(void);
struct main_state *diag_main_state(void);

/* ── Fast-sync starter-pack (bundle) freshness — pure read-only helpers ──
 *
 * A fresh install seeds at the published bundle's utxo-seed-<h>.snapshot
 * height then P2P-fetches the gap to the network tip, so a bundle far below
 * the tip turns "seconds to tip" into minutes. These two helpers back the
 * `bundle_staleness` diagnostic (registered in g_dumpers) and are exported so
 * the unit test can exercise the scan + classification directly. They never
 * mint, mutate, or touch the live datadir — read-only signal only. */

/* Scan `datadir` for the highest utxo-seed-<digits>.snapshot (the same naming
 * boot_autodetect_bundle_snapshot selects; highest height wins). Returns the
 * seed height, or -1 if no matching snapshot exists. When non-NULL, *count is
 * set to the number of matching snapshots, and the winning basename is copied
 * into name[name_sz] (or "" if none). */
long long bundle_scan_seed_height(const char *datadir, int *count,
                                  char *name, size_t name_sz);

/* Freshness verdict for the published bundle relative to the network tip. */
enum bundle_freshness {
    BUNDLE_FRESH_UNKNOWN = 0, /* no bundle, or network tip not yet known */
    BUNDLE_FRESH_OK,          /* est. catch-up <= fresh threshold */
    BUNDLE_FRESH_AGING,       /* between fresh and re-mint thresholds */
    BUNDLE_FRESH_STALE,       /* est. catch-up > re-mint threshold */
};

/* Classify staleness. `seed_h` and `header_tip` are heights (>= 0), or < 0 if
 * unknown. Computes the block gap (clamped at 0 when the bundle is at/above our
 * tip) and the estimated fresh-install catch-up seconds, written to *gap_out
 * and *secs_out (each -1 when unknown). Pure arithmetic — no I/O. */
enum bundle_freshness bundle_classify(long long seed_h, long long header_tip,
                                      long long *gap_out, long long *secs_out);

/* The "bundle_staleness" g_dumpers[] entry itself; implementation lives in
 * diagnostics_registry_bundle.c alongside the two helpers above. */
bool bundle_staleness_dump_state_json(struct json_value *out,
                                      const char *key);

/* RPC handlers, one per concern file. Signatures match rpc_handler_fn. */

/* diagnostics_registry.c / diagnostics_dispatch.c.
 *
 * diag_rpc_dumpstate is a hot-swap TRAMPOLINE (resident, in
 * diagnostics_dispatch.c): it acquire-loads an atomic provider and delegates
 * to it when a dev generation .so has installed one, else calls the resident
 * built-in below (which owns g_dumpers[], in the swap-eligible
 * diagnostics_registry.c). See docs/work/HOTSWAP.md. */
bool diag_rpc_dumpstate(const struct json_value *params, bool help,
                        struct json_value *result);
bool diag_rpc_dumpstate_builtin(const struct json_value *params, bool help,
                                struct json_value *result);

/* Matches diag_rpc_dumpstate_builtin — the swap unit for `dumpstate`. */
typedef bool (*diag_dumpstate_fn)(const struct json_value *params, bool help,
                                  struct json_value *result);

#ifdef ZCL_DEV_BUILD
/* DEV-ONLY: atomically re-point the resident `dumpstate` provider at `fn`
 * (release store; the trampoline reads it with an acquire load). Resident in
 * diagnostics_dispatch.c so a generation .so reaches it as an undefined symbol
 * bound to the executable's copy. Returns false on a NULL fn. */
bool diag_dumpstate_replace(diag_dumpstate_fn fn);
#endif
bool diag_rpc_statecatalog(const struct json_value *params, bool help,
                           struct json_value *result);
size_t diagnostics_dumper_count(void);
const struct diagnostics_dump_entry *diagnostics_dumper_at(size_t idx);

/* The native chain-evidence dump, registered in g_dumpers. `out` must be
 * a fresh json_value; the function sets it to an object. */
bool diag_chain_evidence_dump_state_json(struct json_value *out,
                                         const char *key);
bool diag_block_index_dump_state_json(struct json_value *out,
                                      const char *key);
bool diag_header_band_dump_state_json(struct json_value *out,
                                      const char *key);
/* Explorer projection summary used by chain-evidence diagnostics. It opens a
 * private read-only handle so an automatic dump can never serialize wallet
 * reads behind an explorer scan on the shared node_db connection. */
void diag_push_explorer_index_state_json(struct json_value *out,
                                         struct node_db *ndb);
bool sapling_checkpoint_dump_state_json(struct json_value *out,
                                        const char *key);

/* diagnostics_registry_rom.c — the "rom" g_dumpers[] entry: L0-L3 trust
 * machine catalog (compiled checkpoint, header commitment enumeration,
 * per-layer coverage, MMB/utxo_root_ladder projection cursors). See
 * docs/ROM.md. */
bool rom_dump_state_json(struct json_value *out, const char *key);

/* nodelog_controller.c */
bool diag_rpc_getnodelog(const struct json_value *params, bool help,
                         struct json_value *result);

/* dbquery_controller.c */
bool diag_rpc_dbquery(const struct json_value *params, bool help,
                      struct json_value *result);

/* probe_controller.c */
bool diag_rpc_probezclassicd(const struct json_value *params, bool help,
                             struct json_value *result);

/* getmirrorstatus remains as the legacy mirror monitor; the old per-table
 * comparison RPC surfaces are gone. */
bool diag_rpc_getmirrorstatus(const struct json_value *params, bool help,
                              struct json_value *result);

/* selfbacktrace — dump a live backtrace for every registered thread of the
 * RUNNING node into <datadir>/backtrace-<ts>.log and return { path,
 * thread_count }. Backs the ops.debug.backtrace native command. */
bool diag_rpc_selfbacktrace(const struct json_value *params, bool help,
                            struct json_value *result);

/* diagnostics_debug_bundle.c — one-shot diagnostic capture. Writes every
 * registered dumper's state + build identity + supervisor stall summary as
 * ONE JSON document to <datadir>/debug-bundle-<utc>.json. Backs the
 * `debugbundle` RPC (ops.debug.bundle native command) and the
 * supervisor-stall auto-capture. */
bool diag_rpc_debugbundle(const struct json_value *params, bool help,
                          struct json_value *result);

/* Summary of one bundle write; `path` is "" when the write failed. */
struct debug_bundle_result {
    char    path[1200];
    int64_t bytes;
    int     subsystems_captured;
    int     subsystems_failed;
};

/* Build and write one bundle. `trigger` labels the capture ("manual",
 * "supervisor_stall"); trigger_child/trigger_reason identify the stalled
 * child for supervisor-triggered captures (pass NULL/SUPERVISOR_STALL_NONE
 * for manual). Best-effort per dumper: a failing dump degrades to an
 * {"error": ...} entry under its name, never aborts the bundle. Logs and
 * returns false only when the bundle as a whole cannot be produced or
 * written (no datadir, OOM, file I/O). Reentrant-safe. */
bool debug_bundle_write(const char *trigger, const char *trigger_child,
                        int trigger_reason,
                        struct debug_bundle_result *res);

/* supervisor_stall_observer_fn implementation: rate-limited auto-capture.
 * Never blocks the detecting (supervisor) thread — at most one capture per
 * DEBUG_BUNDLE_AUTO_MIN_INTERVAL_SECS and one in flight at a time; the
 * bundle write runs on a detached helper thread. Best-effort: every
 * failure is logged and swallowed. */
void debug_bundle_on_stall(const char *child_name,
                           enum supervisor_stall_reason reason);

/* Idempotently register debug_bundle_on_stall with the supervisor. Called
 * from diagnostics_controller_set_state (the diagnostics-family boot
 * hook). */
void debug_bundle_register_stall_observer(void);

/* Stop accepting automatic and manual captures, join the owned worker, and
 * drain all capture leases. Must run before connman, databases, or main_state
 * are released. Idempotent.
 *
 * BOUNDED: the drain waits at most DEBUG_BUNDLE_DRAIN_BUDGET_MS for the
 * worker to exit and for every in-flight lease to be dropped. A capture
 * blocked inside one dumper is only cancellable at the NEXT dumper boundary
 * (debug_bundle_push_subsystems checks the shutdown flag per entry), so an
 * unbounded wait here hands a single slow dumper the power to stall the whole
 * shutdown past its stage deadline — which is exactly how a healthy node was
 * force-exited before it ever reached its coins flush or WAL checkpoint.
 *
 * false = the drain did NOT complete: a capture is still live and every
 * dumper dependency it reads MUST be retained (never freed, never detached)
 * by the caller, which then continues to its durability stages. It is never a
 * reason to abandon durability. */
bool debug_bundle_shutdown(void);

/* Test seam for the bounded drain above: override the drain budget in
 * milliseconds (<= 0 restores the production default). */
void debug_bundle_set_drain_budget_ms_for_test(int ms);

/* Test seam: take/drop one capture lease exactly as a live bundle walk does,
 * so a test can hold the shutdown drain open without wedging a real dumper.
 * acquire() returns false once the shutdown flag is set, same as a capture. */
bool debug_bundle_capture_lease_acquire_for_test(void);
void debug_bundle_capture_lease_release_for_test(void);

/* profile [seconds] [top_n] — sample this node's threads over `seconds` and
 * return the busiest threads (cpu_ms/name/wchan), a one-line verdict, and the
 * reducer stage step-EWMA snapshot. Backs the ops.profile native command. */
bool diag_rpc_profile(const struct json_value *params, bool help,
                      struct json_value *result);

/* diagnostics_health_rollup.c — unhealthy-only rollup, registered in
 * g_dumpers as subsystem "unhealthy". Walks every OTHER dumper's `_health`
 * key (see the file header for the { ok, reason } convention) and reports
 * only the ones with ok == false. */
bool unhealthy_dump_state_json(struct json_value *out, const char *key);

/* diagnostics_network.c — "network" rollup, registered in g_dumpers.
 * Answers "what does the node know about the ZClassic network": connman
 * counts + addrman size, the net.outbound_floor peer-floor liveness
 * contract, the network_monitor chain view, the (opt-in) network_census
 * whole-network observatory, a derived tip-vs-modal comparison, and
 * peer_lifecycle connect/handshake/timeout counters. Every field is read
 * from an existing owner's dump/snapshot function — this file computes
 * nothing new. */
bool network_dump_state_json(struct json_value *out, const char *key);

/* diagnostics_network.c — the "transport" g_dumpers[] entry: per-peer P2P
 * transport mode (plaintext vs noise_xx), handshake state, and frame counters,
 * with plaintext/noise peer counts. Names AND counts plaintext peers so a
 * default-off (all-plaintext) node is explicit, not silent. */
bool net_transport_dump_state_json(struct json_value *out, const char *key);

/* diagnostics_connman.c — the "connman" g_dumpers[] entry: outbound/inbound
 * counts + diversity, the addnode dial ledger (lifetime + per-index detail),
 * reactor + message-cycle counters, the net.outbound_floor supervisor
 * contract, an addrman size/new/tried pointer, and a peer_lifecycle
 * per-source dial-attempt-outcome rollup. Distinct from the "network"
 * rollup above (which nests a SUMMARY of some of the same data): this is
 * the low-level connman surface itself, for diagnosing "dialer is broken"
 * vs "addrman/peer pool is thin". */
bool connman_diag_dump_state_json(struct json_value *out, const char *key);

/* diagnostics_connman.c — the "addrman" g_dumpers[] entry: new/tried table
 * sizes, bucket occupancy, address-index health, and a live-vs-dead
 * candidate tally (addr_info_is_terrible() over every used entry). */
bool addrman_diag_dump_state_json(struct json_value *out, const char *key);

/* ── MVP v1 scoreboard (diagnostics_mvp.c) ──────────────────────────
 *
 * The "mvp" g_dumpers[] entry (schema zcl.mvp_status.v1): docs/MVP.md's eight
 * operator acceptance criteria as a typed, evidence-derived query surfaced via
 * `ops state --subsystem=mvp`. REPORTER ONLY — it derives met=true|false|
 * unknown strictly from durable/runtime evidence the node already produces
 * (node_health tip-hold, the soak attestation service, the utxo_parity oracle,
 * the replay-canary watch), flips nothing true on its own, and reports any
 * criterion whose runtime evidence source is absent as "unknown" with a NAMED
 * reason (never silently "met"). */

#define MVP_CRITERIA_TOTAL 8
#define MVP_SOAK_WINDOW_HOURS_REQUIRED 168 /* the 7-day (168h) clean window */
#define MVP_RECOVERY_SECS_MAX 120          /* kill-9 recovery budget (2 min) */
#define MVP_SLO_SUCCESS_MIN 0.999          /* SLO floor when a probe is present */

/* Raw evidence inputs, one bundle for all eight criteria. The live dumper
 * fills this from existing sources; the unit test seeds it directly.
 * mvp_build_status_json() is the SINGLE place met/unmet/unknown is decided. */
struct mvp_evidence {
    /* C3 — cold-start sync to tip: live tip-hold + sync-benchmark receipt. */
    bool      c3_health_present;                  /* node_health snapshot taken */
    int       c3_sync_state;                      /* enum sync_state */
    int       c3_log_head_gap;
    bool      c3_sync_benchmark_receipt_present;  /* pending source: false */
    long long c3_cold_sync_secs;                  /* -1 when unknown */

    /* C6 — 7-day soak. */
    bool      c6_soak_present;                    /* soak service initialized */
    bool      c6_soak_last_healthy;
    bool      c6_soak_window_eligible;
    long long c6_soak_window_hours;               /* -1 when not tracked */
    bool      c6_slo_probe_present;               /* external SLO surface? */
    double    c6_slo_success_rate;                /* 0..1, <0 when unknown */

    /* C7 — kill-9 recovery. */
    bool      c7_recovery_drill_present;
    long long c7_recovery_secs;                   /* -1 when unknown */

    /* C8 — consensus parity. */
    bool      c8_parity_present;                  /* standing oracle, checks>0 */
    long long c8_parity_mismatches;               /* -1 when unknown */
    bool      c8_canary_present;
    bool      c8_canary_fail_active;
};

/* Pure classifier: build schema zcl.mvp_status.v1 into `out` (set to a fresh
 * object) from `ev` (NULL treated as all-absent). Deterministic, no I/O — the
 * test seeds `ev` and asserts. Returns false only on a NULL `out`. */
bool mvp_build_status_json(const struct mvp_evidence *ev,
                           struct json_value *out);

/* The "mvp" g_dumpers[] entry. Gathers live evidence from the running node,
 * then calls mvp_build_status_json. Reentrant-safe; NULL-safe on an
 * uninitialized node. */
bool mvp_dump_state_json(struct json_value *out, const char *key);

/* diagnostics_omniscience.c — the "omniscience" g_dumpers[] entry: the
 * capstone one-call verdict on whether the node knows everything it should.
 * Composes the catalog_completeness per-index lag table (against reducer H*),
 * the handshaked-peer count + time-to-first-peer, and the network-census
 * freshness into a single {verdict, per-index array, worst_lag, ...} object.
 * Read-only composition over existing accessors. */
bool omniscience_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_DIAGNOSTICS_INTERNAL_H */
