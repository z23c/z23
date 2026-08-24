/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_status — a pre-RPC boot-progress beacon written to the datadir.
 *
 * PROBLEM. Before the RPC/HTTP listener binds, a fresh boot is opaque: an
 * operator (or an agent) can only reach for `ss`/`ps`/`tail node.log` to guess
 * how far the node has climbed. There is no typed, machine-readable answer to
 * "what boot stage are we at, and is it serving yet?" until RPC is up — which
 * is exactly the window you most want to observe (snapshot load, refold,
 * block-index rebuild can each run for minutes).
 *
 * SOLUTION. As boot advances through the `enum boot_stage` state machine
 * (lib/util/src/boot_phase.c), the node atomically rewrites a tiny JSON file at
 * `<datadir>/boot_status.json`:
 *
 *   {
 *     "schema": "zcl.boot_status.v1",
 *     "phase": "starting|loading|chain|network|serving|shutdown",
 *     "stage": "<boot_stage_name>",
 *     "stage_ordinal": <int>,
 *     "height": <int, -1 = unknown>,
 *     "rpc_bound": <bool>,
 *     "serving": <bool>,
 *     "started_unix": <int>,
 *     "updated_unix": <int>,
 *     "elapsed_s": <int>,
 *     "activity": "reindex_chainstate",      // optional
 *     "progress_current": <int>,              // optional with activity
 *     "progress_target": <int>,               // optional with activity
 *     "blocker": "<stable id>",              // optional
 *     "blocker_reason": "<operator remedy>"  // optional with blocker
 *   }
 *
 * The write is tmp+rename (crash-safe: a reader either sees the old complete
 * file or the new complete file, never a torn one). Stage transitions rewrite
 * it; long intra-stage work (block-index top-up, pprev repair) must also
 * heartbeat `updated_unix`/`elapsed_s` or a node-free reader freezes on the
 * last stage name and looks hung. Best-effort: a failed write NEVER fails boot.
 *
 * The reader (`boot_status_read`) needs no running node and no RPC — it parses
 * the file straight off disk. That is what replaces the ss/ps/tail dance; the
 * native `ops node bootstatus` / `ops node bootwait` leaves are thin wrappers
 * over it. */

#ifndef ZCL_BOOT_STATUS_H
#define ZCL_BOOT_STATUS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_BOOT_STATUS_FILENAME "boot_status.json"
#define ZCL_BOOT_STATUS_SCHEMA   "zcl.boot_status.v1"

/* Parsed view of a boot_status.json document. All string fields are
 * NUL-terminated fixed buffers so the reader never allocates. */
struct boot_status_snapshot {
    char    phase[32];       /* coarse category, derived from the stage */
    char    stage[64];       /* boot_stage_name() at last update */
    int32_t stage_ordinal;   /* enum boot_stage value, -1 if absent */
    int64_t height;          /* best chain height, -1 = unknown */
    bool    rpc_bound;       /* RPC/HTTP listener has bound */
    bool    serving;         /* boot reached the serving/ready stage */
    int64_t started_unix;    /* wall-clock boot start */
    int64_t updated_unix;    /* wall-clock of the last update */
    int64_t elapsed_s;       /* updated_unix - started_unix */
    /* A long-running recovery owned by the boot path. Empty/-1 outside an
     * active recovery. Current and target are exact work units (blocks for
     * reindex_chainstate), not a percentage inferred from prose. */
    char    activity[64];
    int64_t progress_current;
    int64_t progress_target;
    /* Why this boot stopped, when it stopped on purpose. Empty on every
     * ordinary boot; the two fields are written only once a caller names a
     * blocker, and they are what turns "phase=loading, stage=db_open, and
     * then nothing, forever" into an answer. A boot that exits without
     * naming one is the silent halt this project says is unreachable. */
    char    blocker[64];         /* blocker id, e.g. wallet_phrase_no_terminal */
    char    blocker_reason[256]; /* plain-English reason + the way out */
};

/* ── Writer (called from the boot path) ──────────────────────────────── */

/* Record the datadir + boot start time and write the initial beacon
 * (phase=starting, stage=init). Idempotent: a second call re-arms the start
 * clock. Passing NULL/empty disarms the writer (subsequent note/set calls
 * no-op) — used by tests and by boot modes that have no datadir. */
void boot_status_init(const char *datadir);

/* Record a boot-stage transition and rewrite the beacon. `stage` is an
 * `enum boot_stage` ordinal (passed as int to keep this header free of the
 * boot_phase.h include cycle). No-op when the writer is not armed. */
void boot_status_note_stage(int stage);

/* Record the best chain height (or -1 for unknown) and rewrite the beacon.
 * No-op when the writer is not armed. */
void boot_status_set_height(int64_t height);

/* Rewrite the beacon with a fresh `updated_unix`/`elapsed_s` without
 * changing stage. Throttled to one publish per wall-clock second. Use
 * from long intra-stage loops so `core.node.bootstatus` does not freeze
 * on `wallet_loaded` for the rest of block-index load. No-op when the
 * writer is not armed. */
void boot_status_heartbeat(void);

/* Publish typed progress for a long-running boot recovery. Calls may be made
 * at fine-grained loop boundaries: durable publication is internally capped
 * to once per second, except for activity changes and completion. Passing an
 * empty activity clears all progress fields and publishes immediately. */
void boot_status_set_progress(const char *activity, int64_t current,
                              int64_t target);

/* Name the blocker this boot is stopping on, and rewrite the beacon, BEFORE
 * exiting. A boot that refuses must leave the reason where a node-free
 * reader can find it: without this the beacon keeps whatever stage the boot
 * had reached (phase=loading, stage=db_open) and an operator staring at a
 * unit that restarts forever has nothing to read. `id` is a stable
 * machine-readable name; `reason` is the plain-English sentence, including
 * what to do about it. Passing NULL/empty for `id` clears both fields.
 * No-op when the writer is not armed. */
void boot_status_set_blocker(const char *id, const char *reason);

/* ── Reader (node-free; used by the native command + tests) ──────────── */

/* Read + parse `<datadir>/boot_status.json` into `out`. Returns true on a
 * successful parse. On any failure (missing file, unreadable, malformed JSON)
 * returns false and, when `err`/`errlen` are given, writes a short reason.
 * Does NOT contact a node and does NOT require RPC. */
bool boot_status_read(const char *datadir, struct boot_status_snapshot *out,
                      char *err, size_t errlen);

/* Serialize `snap` into `buf` as the canonical boot_status.json document.
 * Returns the number of bytes written (excluding the NUL), or 0 on overflow.
 * Exposed so a unit test can prove the writer/reader round-trip without a
 * filesystem. */
size_t boot_status_write_json(const struct boot_status_snapshot *snap,
                              char *buf, size_t buflen);

/* Map an `enum boot_stage` ordinal to its coarse phase label + the derived
 * rpc_bound / serving booleans. Pure; exposed for tests. */
const char *boot_status_phase_for_stage(int stage, bool *rpc_bound,
                                         bool *serving);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_BOOT_STATUS_H */
