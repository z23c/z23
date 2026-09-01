/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_seed_ledger — an append-only, retention-capped record of completed
 * (or aborted) ROM/sync-artifact serve sessions: which peer, which
 * artifact, how many chunks/bytes, when. This is telemetry, not consensus
 * state or a rebuildable projection — it lives in its own tiny SQLite file
 * (<datadir>/rom_seed_ledger.db) opened directly, following the same
 * retention-cap shape as `peer_sessions` in
 * engine/modules/storage/src/peers_projection.c (append, then delete-oldest past the
 * cap) without requiring the full event-log projection machinery that
 * table uses — there is no upstream log to rebuild this FROM, this table
 * IS the append point.
 *
 * Every write goes through the AR lifecycle macros
 * (engine/models/include/models/activerecord.h); this module defines its own
 * minimal `sqlite3 *db` handle so those macros apply directly.
 *
 * OWNERSHIP. The seed engine (sibling lane, dumpstate `rom_seed`) owns the
 * artifact REGISTRY (what artifacts exist, their digests) and the actual
 * chunk-serving path; this module only owns the SERVE LOG the seed engine
 * appends to as sessions complete. artifact_id is an opaque 32-byte digest
 * (the SHA3 root the caller already has — the bundle's checkpoint SHA3, a
 * header-seed segment hash, etc.) so this module never needs to know the
 * seed engine's artifact-metadata shape. */

#ifndef ZCL_NET_ROM_SEED_LEDGER_H
#define ZCL_NET_ROM_SEED_LEDGER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct json_value;

#define ROM_SEED_LEDGER_FILENAME       "rom_seed_ledger.db"
#define ROM_SEED_LEDGER_ARTIFACT_ID_LEN 32   /* SHA3-256 digest, binary */
#define ROM_SEED_LEDGER_RETENTION_CAP   50000

typedef struct rom_seed_ledger rom_seed_ledger_t;

/* Open (creating the schema if needed) the ledger at
 * <datadir>/rom_seed_ledger.db. Returns NULL on a hard open failure (logs
 * context) — callers must tolerate NULL and degrade to "serving proceeds,
 * telemetry is best-effort" rather than fail the serve path. */
rom_seed_ledger_t *rom_seed_ledger_open(const char *datadir);
void rom_seed_ledger_close(rom_seed_ledger_t *l);

/* Append one completed (or aborted) serve session and retention-cap the
 * table to ROM_SEED_LEDGER_RETENTION_CAP rows (delete-oldest past the
 * cap), mirroring peers_projection's peer_sessions ledger. peer_ip is a
 * 16-byte v4-mapped-or-v6 address, matching net/peers' convention.
 * Returns false on a write failure (logs context); never crashes the
 * caller's serve path. */
bool rom_seed_ledger_append(rom_seed_ledger_t *l, const uint8_t peer_ip[16],
                            uint16_t peer_port,
                            const uint8_t artifact_id[ROM_SEED_LEDGER_ARTIFACT_ID_LEN],
                            uint32_t chunks_served, uint64_t bytes_served,
                            int64_t started_unix, int64_t finished_unix);

/* Row count (introspection). */
int64_t rom_seed_ledger_row_count(rom_seed_ledger_t *l);

struct rom_seed_ledger_artifact_stats {
    uint64_t total_bytes_served;
    uint64_t total_chunks_served;
    uint32_t distinct_peers;
    uint32_t sessions;
    int64_t  last_served_unix;
};

/* Per-artifact rollup across every retained ledger row for `artifact_id`.
 * Returns false (all-zero *out) when the ledger has no rows for it. */
bool rom_seed_ledger_artifact_stats(
    rom_seed_ledger_t *l,
    const uint8_t artifact_id[ROM_SEED_LEDGER_ARTIFACT_ID_LEN],
    struct rom_seed_ledger_artifact_stats *out);

/* List every distinct artifact_id the ledger has ever served, most
 * recently served first, up to `max` entries. Returns the number written
 * into out_ids (each ROM_SEED_LEDGER_ARTIFACT_ID_LEN bytes). */
size_t rom_seed_ledger_distinct_artifacts(
    rom_seed_ledger_t *l,
    uint8_t (*out_ids)[ROM_SEED_LEDGER_ARTIFACT_ID_LEN], size_t max);

/* Process-wide lazily-opened singleton against the real datadir
 * (GetDataDir). Returns NULL if opening ever failed; every call after a
 * failure retries (a ledger that could not open at boot due to a
 * transient disk issue can still recover later). */
rom_seed_ledger_t *rom_seed_ledger_global(void);

/* Introspection (see CLAUDE.md "Adding state introspection"). Deliberately
 * never opens/creates the ledger file as a side effect of this bare read —
 * it is reachable from any passive whole-registry sweep (e.g. the
 * `unhealthy` health rollup), so a creating-open here would plant a file
 * (plus SQLite WAL sidecars) in whatever datadir an unrelated caller
 * happens to be pointed at. Reports an accurate row count only once the
 * seed engine (or an explicit operator command) has genuinely opened the
 * global singleton via rom_seed_ledger_global(); before that it reports
 * `open` from a non-creating stat() and `rows: 0`. */
bool rom_seed_ledger_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
void rom_seed_ledger_test_set_retention_cap(uint64_t cap);
void rom_seed_ledger_test_reset_retention_cap(void);
/* Force the next rom_seed_ledger_global() call to re-open (test isolation
 * across processes that share this translation unit's statics). */
void rom_seed_ledger_test_reset_global(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_NET_ROM_SEED_LEDGER_H */
