/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_scan — dirt-cheap per-step ROW/ITERATION counters for the boot path.
 *
 * The load-bearing law is "boot is O(delta) — no synchronous boot path
 * iterates 0→tip". Nothing MEASURED that until now: a slow rebuild that
 * quietly went O(chain) was only ever caught by a human noticing boot got
 * slow. These counters make boot prove its own complexity — every boot-time
 * data scanner tallies the rows it touches into a named, process-global
 * counter, surfaced via `dumpstate boot` and asserted by the ratchet test
 * `test_boot_odelta_scan` (cold boot vs warm boot + 100 blocks: a step whose
 * counter fails to shrink to the delta on the warm boot names the O(chain)
 * regression).
 *
 * Cost model: one `boot_scan_counter()` find-or-create per scanner (called
 * ONCE, outside the hot loop) plus one relaxed atomic add per counted
 * iteration. Count ONLY loops that scale with data size (rows scanned /
 * block-index entries walked), never fixed-size work.
 *
 * Usage:
 *   atomic_uint_least64_t *ctr =
 *       boot_scan_counter("reducer_frontier.contiguity_rows");
 *   while (sqlite3_step(st) == SQLITE_ROW) {
 *       boot_scan_bump(ctr);
 *       ...
 *   }
 */

#ifndef ZCL_BOOT_SCAN_H
#define ZCL_BOOT_SCAN_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BOOT_SCAN_NAME_MAX     48
#define BOOT_SCAN_MAX_COUNTERS 48

/* Stable pointer to the named counter's atomic cell (find-or-create). Returns
 * NULL only if the fixed table is full (logged once) or `name` is empty. Call
 * ONCE outside the hot loop; bump the returned pointer inside it. The backing
 * store is a fixed static array, so a returned pointer stays valid for the
 * process lifetime. */
atomic_uint_least64_t *boot_scan_counter(const char *name);

/* One relaxed atomic add. NULL-safe (a full-table / empty-name counter is a
 * silent no-op so a scanner never has to branch on registration failure). */
static inline void boot_scan_bump(atomic_uint_least64_t *c)
{
    if (c) atomic_fetch_add_explicit(c, 1u, memory_order_relaxed);
}
static inline void boot_scan_add(atomic_uint_least64_t *c, uint64_t n)
{
    if (c) atomic_fetch_add_explicit(c, n, memory_order_relaxed);
}

/* Read a counter by name (0 if never registered). */
uint64_t boot_scan_value(const char *name);

struct boot_scan_row {
    char     name[BOOT_SCAN_NAME_MAX];
    uint64_t value;
};

/* Emit every counter as a flat JSON object { name: value, ... } into `out`.
 * This function calls json_set_object(out) itself. */
struct json_value;
void boot_scan_dump_json(struct json_value *out);

/* Log one INFO line summarising every counter, prefixed with `tag`. Cheap
 * enough to call at boot completion so the row counts land next to the
 * `[boot] <name> <ms>ms` timing lines in node.log. */
void boot_scan_log_summary(const char *tag);

#ifdef ZCL_TESTING
/* Zero the whole table so a test can measure a single boot in isolation.
 * Production code MUST NOT call this. */
void boot_scan_reset_for_testing(void);
#endif

#endif /* ZCL_BOOT_SCAN_H */
