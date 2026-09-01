/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * rom_seed_policy — the generosity/DoS-safety knobs for free-tier P2P
 * delivery of the ROM/sync artifacts (the consensus-state bundle and
 * header-chain seed data described in docs/ROM_DELIVERY.md).
 *
 * PROBLEM. The owner directive is "generous seeding, ON by default" — a
 * fresh node should be able to pull the checkpoint bundle from any peer,
 * free, unmetered by payment (unlike the priced file_market path,
 * core/modules/net/include/net/file_market.h). Left unbounded that is a bandwidth
 * DoS surface; left off by default it silently defeats the whole point.
 * This module is the single place that answer is decided and observed.
 *
 * SHAPE. This is the POLICY layer only — bounded config plus pure decision
 * helpers plus live counters. It never opens a socket, never reads a chunk
 * off disk, and never speaks the wire protocol; the seed engine (a sibling
 * lane building the artifact registry + the actual chunk-serving path,
 * dumpstate `rom_seed`) is the thing that calls into this header on every
 * admission decision and every completed/refused upload. If the sibling
 * lane's serve path ends up shaped a little differently, wrap these calls
 * in a thin adapter — the surface here is intentionally small.
 *
 * TRUST MODEL. Nothing in this module makes any artifact more or less
 * trustworthy: delivery is untrusted transport (docs/ROM_DELIVERY.md).
 * Policy only decides how MUCH and how FAST to give away for free.
 *
 * CONSENSUS PREEMPTS ARTIFACT TRAFFIC (hard rule, not a knob). Whatever the
 * reducer/sync supervisor judges necessary for consensus progress (headers,
 * bodies, tx relay) always outranks artifact seeding. Call
 * rom_seed_policy_set_consensus_active(true) whenever that pressure is live;
 * rom_seed_policy_admit_upload() then refuses NEW uploads (in-flight ones
 * are left to the caller to throttle/pause) until it is cleared. A caller
 * that never touches this signal gets consensus_active()==false forever —
 * safe by default, no silent seeding disablement.
 *
 * PERSISTENCE. Policy is config-backed: <datadir>/rom_seed_policy.json,
 * written tmp+rename (see boot_status_publish_locked in
 * platform/modules/util/src/boot_status.c for the identical crash-safety pattern) so a
 * reader always sees a complete document, never a torn write. A missing or
 * corrupt file falls back to the compiled defaults below (fail-open on
 * READ, fail-closed on WRITE validation) — this module never refuses to
 * boot and never crashes on a bad file. A bare rom_seed_policy_get() NEVER
 * writes to disk, even when it falls back to compiled defaults — only an
 * explicit owner mutation (_apply/_set_enabled/_reset_to_defaults) persists.
 * This matters beyond tidiness: rom_seed_policy_dump_state_json() is reached
 * by any passive whole-registry sweep (e.g. the `unhealthy` health rollup),
 * so a write-on-read here would plant a file in whatever datadir an
 * unrelated caller happens to be pointed at. */

#ifndef ZCL_NET_ROM_SEED_POLICY_H
#define ZCL_NET_ROM_SEED_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct json_value;

#define ROM_SEED_POLICY_FILENAME "rom_seed_policy.json"
#define ROM_SEED_POLICY_SCHEMA   "zcl.rom_seed_policy.v1"

/* Fail-closed bounds an owner-supplied policy must fall within.
 * rom_seed_policy_apply() rejects anything outside these; the live policy
 * is left unchanged on rejection. */
#define ROM_SEED_POLICY_MIN_GLOBAL_BPS   (256ULL * 1024)                 /* 256 KB/s */
#define ROM_SEED_POLICY_MAX_GLOBAL_BPS   (2ULL * 1024 * 1024 * 1024)     /* 2 GB/s   */
#define ROM_SEED_POLICY_MIN_PER_PEER_BPS (16ULL * 1024)                  /* 16 KB/s  */
#define ROM_SEED_POLICY_MAX_PER_PEER_BPS (256ULL * 1024 * 1024)          /* 256 MB/s */
#define ROM_SEED_POLICY_MIN_CONCURRENCY  1U
#define ROM_SEED_POLICY_MAX_CONCURRENCY  256U
#define ROM_SEED_POLICY_MAX_BOOST_DAYS   90U

/* Compiled defaults: generous but bounded. Seeding is ON by default per the
 * owner directive (the whole point of free-tier ROM delivery is that it
 * just works without operator setup); the caps keep one node from being
 * volunteered as an unbounded free CDN. */
#define ROM_SEED_POLICY_DEFAULT_ENABLED          true
#define ROM_SEED_POLICY_DEFAULT_GLOBAL_BPS       (50ULL * 1024 * 1024)   /* 50 MB/s */
#define ROM_SEED_POLICY_DEFAULT_PER_PEER_BPS     (2ULL * 1024 * 1024)    /* 2 MB/s  */
#define ROM_SEED_POLICY_DEFAULT_MAX_CONCURRENCY  24U
#define ROM_SEED_POLICY_DEFAULT_BOOST_DAYS       7U
/* Effective per-peer cap multiplier while an artifact is inside its
 * generosity-boost window ("the network needs new ROM spread FAST"). Still
 * clamped to the global cap by rom_seed_policy_effective_per_peer_cap(). */
#define ROM_SEED_POLICY_DEFAULT_BOOST_MULTIPLIER 4U

struct rom_seed_policy {
    bool     enabled;
    uint64_t global_up_bytes_per_sec;
    uint64_t per_peer_up_bytes_per_sec;
    uint32_t max_concurrent_uploads;
    uint32_t generosity_boost_days;
};

/* ── read / apply — the minimal adapter surface a serve path consults ─── */

/* Snapshot the current effective policy. Loads from
 * <datadir>/rom_seed_policy.json on first call in the process, falling back
 * to the compiled defaults in memory (never written to disk) if the file
 * does not exist yet; every subsequent call is a cheap in-memory read.
 * Never fails: `out` is always fully populated. Never writes to disk. */
void rom_seed_policy_get(struct rom_seed_policy *out);

/* Owner-mutating: validate `in` against the bounds above (including
 * per_peer_up_bytes_per_sec <= global_up_bytes_per_sec), and on success
 * persist (tmp+rename) then apply in-memory. On a validation failure
 * returns false, writes a bounded reason into `err`, and leaves the live
 * policy untouched — never a partial apply. */
bool rom_seed_policy_apply(const struct rom_seed_policy *in, char *err,
                           size_t errlen);

/* Convenience: flip only `enabled`, leaving every cap untouched. Always
 * succeeds (no bounds to violate). */
bool rom_seed_policy_set_enabled(bool enabled);

/* Reset in-memory + on-disk policy to the compiled defaults above. */
bool rom_seed_policy_reset_to_defaults(void);

/* ── consensus-preempts-artifact-traffic signal (hard rule, not a knob) ── */

void rom_seed_policy_set_consensus_active(bool active);
bool rom_seed_policy_consensus_active(void);

/* ── pure decision helpers the serve path consults on every request ───── */

/* Should a NEW upload be admitted right now? false whenever seeding is
 * disabled, consensus traffic currently preempts it, or `current_active`
 * is already at/over max_concurrent_uploads. Pure w.r.t. the atomically
 * held policy/signal state — safe to call from any thread, on every
 * incoming chunk-serve request. */
bool rom_seed_policy_admit_upload(uint32_t current_active_uploads);

/* True when `artifact_first_seen_unix` is still inside the
 * generosity_boost_days window as of `now_unix` (both Unix seconds). A
 * zero/negative `artifact_first_seen_unix` or a zero boost window always
 * returns false. Pure. */
bool rom_seed_policy_is_boosted(int64_t artifact_first_seen_unix,
                                int64_t now_unix);

/* Effective per-peer byte/s cap for one upload: per_peer_up_bytes_per_sec,
 * times ROM_SEED_POLICY_DEFAULT_BOOST_MULTIPLIER when `boosted`, clamped so
 * it never exceeds global_up_bytes_per_sec (one boosted peer can never
 * itself claim the whole global seat). Pure. */
uint64_t rom_seed_policy_effective_per_peer_cap(bool boosted);

/* ── live counters the serve path reports through ──────────────────────
 * Every counter is monotonic except uploads_active, which tracks started
 * minus finished (floored at 0 against a mismatched call pair). */

void rom_seed_policy_note_upload_started(void);
void rom_seed_policy_note_upload_finished(uint64_t bytes_sent);
void rom_seed_policy_note_upload_refused(void);

struct rom_seed_policy_counters {
    uint64_t uploads_started_total;
    uint64_t uploads_finished_total;
    uint64_t uploads_refused_total;
    uint64_t bytes_served_total;
    uint32_t uploads_active;
};
void rom_seed_policy_get_counters(struct rom_seed_policy_counters *out);

/* ── introspection (see CLAUDE.md "Adding state introspection") ───────── */
/* Backs `dumpstate rom_seed_policy` / `ops debug rom_seed status`. Deliberately a
 * DIFFERENT subsystem name than the seed engine's own `rom_seed` — this
 * dumper only ever describes POLICY + counters, never the artifact
 * registry, so the two can never collide or shadow one another even if
 * both land in the same build. `key` is unused. */
bool rom_seed_policy_dump_state_json(struct json_value *out, const char *key);

#ifdef ZCL_TESTING
/* Reset every in-process static to a fresh unloaded state and point the
 * next rom_seed_policy_get()/apply() at `datadir_override` (an isolated
 * test-tmp directory) instead of the real GetDataDir(). NULL restores the
 * real datadir on the NEXT load. Test-only; never linked into the node. */
void rom_seed_policy_test_reset(const char *datadir_override);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_NET_ROM_SEED_POLICY_H */
