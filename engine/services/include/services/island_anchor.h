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
struct block_header;
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
    ISLAND_ANCHOR_STATE_UNREADABLE,  /* not a stored value: the read failed or
                                      * the value is malformed; never decide */
};

/* Typed failure codes of the fallible exports (zcl_result.code). */
enum island_anchor_err {
    ISLAND_ANCHOR_ERR_UNREADABLE = 1,   /* the progress store read failed */
    ISLAND_ANCHOR_ERR_MALFORMED = 2,    /* a stored value has the wrong shape */
    ISLAND_ANCHOR_ERR_INVALID = 3,      /* a malformed fact or a missing output */
};

/* In-process registration. register() refuses a malformed fact
 * (ISLAND_ANCHOR_ERR_INVALID). The bool exports are total predicates. */
#ifdef ZCL_TESTING
void island_anchor_test_commit_hook(void (*hook)(bool));
#endif

struct zcl_result island_anchor_register(const struct island_anchor *a);
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

/* The window's row hashes, root first: hash[i] is the row at root_height + i,
 * so hash[0] is the root and hash[ISLAND_ANCHOR_WINDOW - 1] the rung. A row's
 * persisted parent link follows its in-memory pprev, so after a fall-back's
 * detach is flushed the rows load parentless; this list finds each one by
 * exact (height, hash). */
struct island_anchor_rows {
    struct uint256 hash[ISLAND_ANCHOR_WINDOW];
};

/* Durable fact. save() commits the fact, its row list and state SEEDED in one
 * transaction (refused unless the list's ends are the fact's root and rung);
 * a fact without a state reads as NONE. After a fall-back the fact and list
 * stay until the rows rejoin the chain (the boot detach needs them). */
struct zcl_result island_anchor_save(struct sqlite3 *db,
                                     const struct island_anchor *a,
                                     const struct island_anchor_rows *rows);
/* Atomically commit exact full-window proof with its anchor and SEEDED state. */
struct zcl_result island_anchor_recovery_fresh(struct sqlite3 *db);
/* Prove only the durable genesis fold; caller separately validates island authority. */
struct zcl_result island_anchor_genesis_fold_proven(struct sqlite3 *db);
struct zcl_result island_anchor_save_window_recover(struct sqlite3 *db, const struct island_anchor *a,
    const struct island_anchor_rows *rows, const struct block_header *window);
struct zcl_result island_anchor_save_window(struct sqlite3 *db,
    const struct island_anchor *a, const struct island_anchor_rows *rows,
    const struct block_header *window);

/* Caller holds progress-store transaction lock and owns an open write transaction
 * on the live progress DB. Caller must validate rung authority and window proof;
 * on failure it must roll back. Writes INSTALLED; this function never commits or registers the fact. */
struct zcl_result island_anchor_install_window_in_tx(struct sqlite3 *db,
    const struct island_anchor *a, const struct island_anchor_rows *rows,
    const struct block_header *window);
/* Missing legacy proof returns OK with found=false; malformed or I/O fails. */
struct zcl_result island_anchor_window_load(struct sqlite3 *db,
    struct block_header *window, bool *found);

/* Loads: OK with *found false when absent; ISLAND_ANCHOR_ERR_UNREADABLE when
 * the read fails (or no store is open), ISLAND_ANCHOR_ERR_MALFORMED when the
 * stored length is wrong. Never decide "absent" on an error. */
struct zcl_result island_anchor_rows_load(struct sqlite3 *db,
                                          struct island_anchor_rows *out,
                                          bool *found);
struct zcl_result island_anchor_load(struct sqlite3 *db,
                                     struct island_anchor *out, bool *found);
/* UNREADABLE when the stored state cannot be read or is malformed; NONE when
 * no state is stored or no progress store is open. Callers never decide a
 * fall-back or a fresh start on UNREADABLE. */
enum island_anchor_state island_anchor_state_load(struct sqlite3 *db);
/* Record the fall-back durably and drop the in-process registration. Refused
 * (error, registration kept) once the state is INSTALLED or UNREADABLE: an
 * installed island stands on its state, and a damaged row never turns it back
 * into a fall-back; an unreadable state may be an installed one. */
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
 * hold_recorded() reads only: *held true once FlySync ever held this datadir
 * (ISLAND_ANCHOR_ERR_UNREADABLE when the read fails or the record is malformed). */
struct zcl_result island_anchor_hold_recorded(struct sqlite3 *db, bool *held);
struct zcl_result island_anchor_hold_boot(struct sqlite3 *db, uint64_t *boots);

/* Boot: register the durable fact when the state is SEEDED or INSTALLED
 * (*registered true). OK with nothing registered for any other readable state;
 * an error (typed code) when the state or the fact cannot be read or used.
 * Call after the progress store opens and before the block index loads (the
 * loader's work pass reads the registration). */
struct zcl_result island_anchor_boot_register(struct sqlite3 *db,
                                              bool *registered);

#endif /* ZCL_SERVICES_ISLAND_ANCHOR_H */
