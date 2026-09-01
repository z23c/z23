/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sysinit — declarative, explicitly-ordered boot-step registration.
 *
 * FreeBSD encodes its kernel boot order in SYSINIT() linker-set entries
 * (a `struct sysinit` per subsystem, sorted by a (subsystem, order) key at
 * boot). This is the same idea WITHOUT the linker set: records are placed in
 * an explicit in-code table and registered via sysinit_register(), so the
 * full boot order is greppable in one place and pinned by a golden lint gate
 * (tools/lint/check_sysinit_ordering.sh) rather than hidden in `.init_array`
 * section magic. Portable (no toolchain-specific SET_ENTRY), and every record
 * is visible to `grep`.
 *
 * The load-bearing win over the previous "literal call order in a 3,950-line
 * boot.c" is that each record names the boot_stage boundary it belongs to.
 * sysinit_run_stage(stage, ctx) runs that stage's records in the deterministic
 * (stage, order, name) sort order, then advances the boot-stage state machine
 * (boot_phase.h) to `stage`. A record whose init fails returns a typed
 * zcl_result and boot does NOT advance — the boundary is fail-closed, not a
 * silent forward-jump WARN.
 *
 * Ordering key (ascending): boot_stage, then `order`, then `name` (strcmp).
 * `order` breaks ties within a stage; `name` makes the sort total so the
 * golden file is stable regardless of registration order.
 *
 * Lifecycle: init() runs at boot in forward order; fini() runs at shutdown in
 * REVERSE of the order records actually ran (LIFO), each with the ctx it ran
 * with. A record with a NULL fini has no teardown.
 *
 * Single-threaded by contract: registration and run happen on the boot thread
 * before the supervisor spawns children (same contract as boot_phase.c). Not
 * safe to call concurrently.
 */

#ifndef ZCL_UTIL_SYSINIT_H
#define ZCL_UTIL_SYSINIT_H

#include "util/boot_phase.h"
#include "util/result.h"

#include <stdbool.h>
#include <stddef.h>

struct sysinit_record {
    const char *subsystem;              /* owning subsystem, e.g. "wallet" */
    enum boot_stage stage;              /* boundary this record establishes */
    int order;                          /* tie-break within the stage (asc) */
    struct zcl_result (*init)(void *ctx);
    void (*fini)(void *ctx);            /* NULL = no teardown */
    const char *name;                   /* unique record name (sort tiebreak) */
};

/* Copy `rec` into the registration table. Returns false if the table is full
 * or the record is malformed (NULL init/name). Idempotence is the caller's
 * responsibility — a duplicate name is accepted but logged. */
bool sysinit_register(const struct sysinit_record *rec);

/* Run every registered record whose stage == `stage`, in (order, name) sort
 * order, passing `ctx` to each init(). On the first init that returns non-ok,
 * stop and return that result WITHOUT advancing the boot stage (fail-closed).
 * If all succeed, advance the boot-stage state machine to `stage` and return
 * ZCL_OK. Records that ran are remembered for reverse fini. */
struct zcl_result sysinit_run_stage(enum boot_stage stage, void *ctx);

/* Run fini() for every record that ran, in reverse execution order, each with
 * the ctx it was run with. Safe to call once at shutdown. */
void sysinit_run_fini_all(void);

/* Number of registered records whose stage == `stage`. */
size_t sysinit_stage_record_count(enum boot_stage stage);

/* Write the full sorted table as one "<stage> <order> <name>" line per record
 * into `buf` (NUL-terminated, truncated if short). Returns the record count.
 * Backs the deterministic-sort unit test and mirrors the golden lint order. */
size_t sysinit_ordering_snapshot(char *buf, size_t buf_sz);

#ifdef ZCL_TESTING
/* Clear the registration + ran tables so a unit test starts from empty
 * without inheriting boot's real records. Test-only. */
void sysinit_reset_for_testing(void);
#endif

#endif /* ZCL_UTIL_SYSINIT_H */
