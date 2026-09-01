/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the chaos-fault injectors' private cross-TU contract — the
 * result-note/pacing helpers and stage-log fixture builders that the four
 * chaos-fault translation units hand back and forth.
 *
 * simnet_chaos_faults.c owns faults (a)-(f) and (n)-(p): the segment,
 * supervisor, condition and progress.kv fixtures.
 * simnet_chaos_faults_stagelog.c owns the per-stage `*_log` row and
 * stage_cursor seeding those faults damage.
 * simnet_chaos_faults_rom.c owns the ROM-artifact fixture family and faults
 * (g)-(i). simnet_chaos_faults_download.c owns faults (j)-(m), the
 * download/peer-behaviour matrix. The split happened when the combined file
 * passed the 800-line shape ceiling. These declarations are all that
 * crosses those seams, so they live here and nowhere else — nothing outside
 * those four translation units may include this header.
 */

#ifndef ZCL_SIM_SIMNET_CHAOS_FAULTS_INTERNAL_H
#define ZCL_SIM_SIMNET_CHAOS_FAULTS_INTERNAL_H

#include "sim/simnet_chaos_faults.h"

#include <stdbool.h>
#include <stdint.h>

/* The fixture builders below take a live sqlite3 handle. Declared as an
 * incomplete type at FILE scope, not left implicit in each prototype: a bare
 * `struct sqlite3 *` parameter would introduce a fresh prototype-scoped tag
 * that does not match <sqlite3.h>'s typedef, which is a hard error at the
 * definition. A forward declaration keeps this header free of the vendor
 * include. */
struct sqlite3;

/* Format a single-line outcome note into `out->note`. Defined in
 * simnet_chaos_faults.c. */
void chaos_note(struct chaos_fault_result *out, const char *fmt, ...);

/* Zero a sync-fault capsule and stamp its seed / sentinel heights. Defined
 * in simnet_chaos_faults_rom.c. */
void sfm_capsule_init(struct sync_fault_capsule *out, uint64_t seed);

/* chaos_note() for a sync-fault capsule — writes into the embedded
 * base.note. Defined in simnet_chaos_faults_rom.c. */
void sfm_note(struct sync_fault_capsule *out, const char *fmt, ...);

/* ── stage-log fixture builders (simnet_chaos_faults_stagelog.c) ────────
 * The `*_log` row/cursor seeding that a fault body damages. Only these four
 * are reached from outside that file; the per-table row writers behind them
 * stay file-static there. */

/* CREATE TABLE IF NOT EXISTS every per-stage log table the reducer-frontier
 * scan and its hash-agreement cross-check touch. Idempotent against the
 * production DDL. */
bool chaos_ensure_log_tables(struct sqlite3 *db);

/* Deterministic 32-byte hash keyed by height — the value every leg of a
 * consistent fixture row agrees on. */
void chaos_synth_hash(uint8_t out[32], int32_t h);

/* Write one ok=1 validate_headers_log row at height h carrying `hash`. The
 * one per-table writer a fault body seeds on its own, to build a header
 * prefix that runs AHEAD of the body/stage prefix. */
bool chaos_put_validate_headers(struct sqlite3 *db, int32_t h,
                                const uint8_t hash[32]);

/* Stamp a full mutually-consistent prefix [0, n] plus the matching
 * stage_cursor rows. Returns false on the first sqlite error. */
bool chaos_stamp_prefix(struct sqlite3 *db, int32_t n);

#ifdef ZCL_TESTING
/* Sleep `ms` milliseconds. Only the ZCL_TESTING-only fault bodies use it, so
 * it is declared under the same guard as its definition in
 * simnet_chaos_faults.c. */
void chaos_sleep_ms(int ms);
#endif /* ZCL_TESTING */

#endif /* ZCL_SIM_SIMNET_CHAOS_FAULTS_INTERNAL_H */
