/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Blocker History — durable firing-history aggregation over
 * EV_OPERATOR_NEEDED pages.
 *
 * Motivation
 * ----------
 * `platform/modules/util/src/blocker.c` is the LIVE typed-blocker registry (what is
 * blocked RIGHT NOW). `engine/services/src/consensus_reject_index.c` answers
 * "why was hash X rejected" from a recent in-memory ring. Neither answers
 * the operational question this service exists for:
 *
 *     "How often has each named blocker/condition paged an operator,
 *      historically, across restarts?"
 *
 * That needs a DURABLE record, because the live registry and the
 * in-memory `engine/modules/event/event.h` bus both reset on every restart. Two
 * pieces:
 *
 *   1. A bridge (this file's `blocker_history_bridge_register()`)
 *      subscribes to the in-memory `EV_OPERATOR_NEEDED` event and
 *      durably appends a copy — `EV_OPERATOR_ALERT` — to the append-only
 *      event log (engine/modules/storage/src/event_log.c), prefixed with the true
 *      fire-time wall clock (`ts=<unix> <original payload>`).
 *   2. A reader/aggregator (`blocker_history_catch_up[_ex]`) streams the
 *      event log forward from a durable cursor, parses each
 *      `EV_OPERATOR_ALERT` payload into a blocker/condition id, and
 *      folds it into a fixed-capacity in-memory table of
 *      {id, fire_count, first_seen_unix, last_seen_unix, last_reason}.
 *
 * The scan is INCREMENTAL: the cursor (durable, in node.db's node_state
 * KV table) advances past every event visited, so a query only walks the
 * bytes appended since the last call — never the whole log.
 *
 * Id extraction
 * -------------
 * Table-driven, in priority order, over the payload with the bridge's
 * own `ts=<unix> ` prefix stripped:
 *   1. `blocker=<id>` token (most authoritative — the literal blocker id
 *      chain_linkage_hold_raise embeds).
 *   2. `check=<id>` token (the literal id most `blocker_init` call sites
 *      pass as their first argument).
 *   3. `condition=<id>` token (the condition-engine's own name).
 *   4. A small table of fixed literal-prefix ids for the handful of
 *      emit sites whose payload carries no `key=` token at all.
 *   5. No rule matches -> counted in `unparsed_count`, dropped from the
 *      per-id aggregate (still counted in `total_events`).
 * `coin_backfill` fires are deliberately coarsened to one aggregate id
 * (the real registry id is `coin_backfill.<h>`, unbounded cardinality by
 * design) rather than let one noisy per-height stage evict every other
 * blocker's history out of the fixed-capacity table.
 *
 * Lifecycle
 * ---------
 * `blocker_history_bridge_register()` — boot wiring, idempotent, call
 * once right after `alerts_init()` so the bridge is live before the
 * condition engine can page.
 * `blocker_history_catch_up()` — zero-arg production entry point,
 * called by the dumper before every read (bounded, incremental).
 * `blocker_history_catch_up_ex(log, ndb)` — explicit-dependency core for
 * testing without the global singletons.
 * `blocker_history_reset_for_test()` — test-only: clears the in-memory
 * table AND the bridge's registration so groups don't leak into each
 * other under test_parallel. Does not touch the event log or the durable
 * cursor (callers own their own fixture log/db).
 *
 * Thread safety
 * -------------
 * The bridge observer fires synchronously on the emitting thread and
 * durably appends (event_log_append fsyncs twice) — accepted because
 * EV_OPERATOR_NEEDED is rate-limited upstream at the blocker-registry
 * layer (BLOCKER_DEFAULT_RATE_LIMIT_MS, <=5/min per id) and durability of
 * an operator page is the entire point of this service. The in-memory
 * aggregate table is guarded by a single mutex; reads/writes are cheap
 * (<=BLOCKER_HISTORY_CAP rows, linear scan). */

#ifndef ZCL_SERVICES_BLOCKER_HISTORY_H
#define ZCL_SERVICES_BLOCKER_HISTORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct event_log event_log_t;
struct node_db;

/* Same bound as BLOCKER_CAP (util/blocker.h) — durable history can never
 * have more distinct ids than the live registry that raises them, modulo
 * the deliberate coarsening above. */
#define BLOCKER_HISTORY_CAP        128
#define BLOCKER_HISTORY_ID_MAX      64
#define BLOCKER_HISTORY_REASON_MAX 200

struct blocker_history_row {
    char    id[BLOCKER_HISTORY_ID_MAX];
    uint64_t fire_count;
    int64_t  first_seen_unix;
    int64_t  last_seen_unix;
    char    last_reason[BLOCKER_HISTORY_REASON_MAX];
};

/* ── Bridge (writer side) ─────────────────────────────────────────── */

/* Register the EV_OPERATOR_NEEDED -> durable EV_OPERATOR_ALERT bridge
 * observer. Idempotent (a static guard makes a second call a no-op).
 * Call once at boot, right after alerts_init(). */
void blocker_history_bridge_register(void);

/* Test-only: drop the observer registration so a fresh test group can
 * re-register without duplicate observers piling up. */
void blocker_history_bridge_unregister_for_test(void);

/* ── Reader / aggregator ──────────────────────────────────────────── */

/* Explicit-dependency core: streams `log` forward from the durable
 * cursor stored in `ndb`, folds every EV_OPERATOR_ALERT event visited
 * into the in-memory aggregate table, and advances the cursor past
 * every event visited (whether or not it parsed). Returns the number of
 * EV_OPERATOR_ALERT events visited THIS call (0 = healthy/idle — the
 * normal case), or -1 if `log` is NULL. `ndb` may be NULL (the scan
 * still runs; the cursor just isn't persisted, so every call rescans
 * from the in-process cursor which resets to 0 on process restart —
 * production always passes a real ndb). */
int blocker_history_catch_up_ex(event_log_t *log, struct node_db *ndb);

/* Production wrapper: sources event_log_singleton() and
 * app_runtime_node_db(). Returns -1 if the event log isn't wired yet
 * (benign — nothing to catch up on before boot finishes). */
int blocker_history_catch_up(void);

/* Total EV_OPERATOR_ALERT events ever visited (lifetime, across all
 * catch_up calls this process). */
uint64_t blocker_history_scan_visits_total(void);

/* Test-only: clears the in-memory aggregate table AND resets the
 * in-process cursor/counters to zero (does not touch any durable
 * cursor already persisted in a caller-owned node_db — tests use a
 * fresh :memory: db per group). */
void blocker_history_reset_for_test(void);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe: calls
 * blocker_history_catch_up() first (bounded, incremental), then reports
 * total_events, unparsed_events, overflow_dropped, distinct_ids,
 * capacity, and a `top` array (id/fire_count/first_seen_unix/
 * last_seen_unix/last_reason) sorted by fire_count descending, capped by
 * `key` (parsed as an integer limit, default 10, max
 * BLOCKER_HISTORY_CAP; NULL/invalid uses the default). */
struct json_value;
bool blocker_history_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_BLOCKER_HISTORY_H */
