/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * island_anchor — the durable island-anchor fact of a FlySync node.
 *
 * A FlySync node (-flysync, fresh datadir) holds no header below a compiled
 * ladder rung H except a verified window H-27..H: the row at H-27 is a
 * pprev-less ROOT. Every other part of the node treats a pprev-less non-genesis
 * root as damage (band backfill, evidence freeze, loader work reset). This
 * module holds the one fact that says otherwise, for exactly one (height, hash):
 *
 *   root (height, hash)   the window's lowest row, hash-linked to the rung
 *   root_work             its cumulative chainwork, derived as
 *                         compiled_rung_chainwork - sum(proofs H-26..H)
 *   rung (height, hash)   the compiled rung the window was walked down from
 *
 * The fact is written once (progress_meta) when a verified window seeds the
 * island and registered at boot from that durable row. Every exemption keys on
 * an EXACT root (height, hash) match; a node that never recorded the fact
 * (every node not started with -flysync) sees no registration, and every
 * predicate below answers exactly as the caller's unchanged path expects.
 * Recording a fall-back drops the registration so normal band backfill heals
 * the node from genesis. No consensus predicate reads this module. */

#ifndef ZCL_SERVICES_ISLAND_ANCHOR_H
#define ZCL_SERVICES_ISLAND_ANCHOR_H

#include "base/result.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/arith_uint256.h"
#include "core/uint256.h"

struct block_index;
struct sqlite3;

/* Rows in the window: the rung and the 27 below it. 17 (nPowAveragingWindow)
 * for the retarget average plus 11 (median-time span) for the median time past
 * at the window's far edge: the first header above the rung then gets its full
 * contextual check (process_block_should_skip_contextual_header is false). */
#define ISLAND_ANCHOR_WINDOW 28

struct island_anchor {
    int32_t root_height;
    struct uint256 root_hash;
    struct arith_uint256 root_work;
    int32_t rung_height;
    struct uint256 rung_hash;
};

/* Durable state key values (progress_meta "flysync.island_state"). */
enum island_anchor_state {
    ISLAND_ANCHOR_STATE_NONE = 0,    /* never a FlySync datadir */
    ISLAND_ANCHOR_STATE_SEEDED,      /* window seeded; fact is authoritative */
    ISLAND_ANCHOR_STATE_FELL_BACK,   /* gave up; normal sync owns the node */
    ISLAND_ANCHOR_STATE_INSTALLED,   /* rung bundle installed; never falls back */
};

/* In-process registration. register() refuses a malformed fact. */
bool island_anchor_register(const struct island_anchor *a);
void island_anchor_unregister(void);
bool island_anchor_registered(void);
bool island_anchor_get(struct island_anchor *out);

/* True iff `bi` is exactly the registered root (height AND hash). */
bool island_anchor_is_root(const struct block_index *bi);

/* When `bi` is the registered root, set its nChainWork to the fact's root work
 * and return true; otherwise leave it untouched and return false. */
bool island_anchor_seed_root_work(struct block_index *bi);

/* True iff a registration exists and `fork_height` lies below the rung: a
 * reorg there would disconnect the installed state's base, which no undo data
 * exists for. Unregistered: always false (unchanged path). */
bool island_anchor_refuses_fork_at(int32_t fork_height);

/* Compiled big-endian 32-byte chainwork to arith form. */
void island_anchor_work_from_be(struct arith_uint256 *out,
                                const uint8_t be[32]);

/* Durable fact. save() commits the fact and state SEEDED in one transaction;
 * a fact without a state reads as NONE. After a fall-back the fact stays until
 * its rows rejoin the chain (the boot detach needs the exact root). */
struct zcl_result island_anchor_save(struct sqlite3 *db,
                                     const struct island_anchor *a);
bool island_anchor_load(struct sqlite3 *db, struct island_anchor *out,
                        bool *found);
enum island_anchor_state island_anchor_state_load(struct sqlite3 *db);
/* Record the fall-back durably and drop the in-process registration. Refused
 * (error, registration kept) once the state is INSTALLED: an installed island
 * stands on its state, and a damaged row never turns it back into a fall-back. */
struct zcl_result island_anchor_note_fallback(struct sqlite3 *db,
                                              const char *why);

/* A fallen-back island whose rows rejoined the chain (the root has its real
 * parent): delete the fact; nothing is left to detach. */
struct zcl_result island_anchor_retire(struct sqlite3 *db);

/* Record that the rung bundle installed (SEEDED -> INSTALLED, idempotent). */
struct zcl_result island_anchor_note_installed(struct sqlite3 *db);

/* Count one more boot that held header sync for FlySync (progress_meta
 * "flysync.hold_boots") and return the new total. A crash loop cannot reset
 * it, and time the process is not running never counts.
 * hold_recorded() reads only: true once FlySync ever held this datadir. */
bool island_anchor_hold_recorded(struct sqlite3 *db);
struct zcl_result island_anchor_hold_boot(struct sqlite3 *db, uint64_t *boots);

/* Boot: register the durable fact when the state is SEEDED or INSTALLED.
 * Returns true when
 * a fact was registered. Call after the progress store opens and before the
 * block index loads (the loader's work pass reads the registration). */
bool island_anchor_boot_register(struct sqlite3 *db);

#endif /* ZCL_SERVICES_ISLAND_ANCHOR_H */
