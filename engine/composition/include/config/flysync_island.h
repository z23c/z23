/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * flysync_island — FlySync island start (-flysync, default off).
 *
 * A fresh node installs a consensus-state bundle at a compiled ladder rung H
 * and syncs only the blocks above it, without downloading any header below
 * H-27. The flow:
 *
 *   WAIT    -flysync on a datadir with no chain state. Normal P2P header sync
 *           is held. The state-offer service fetches a rung bundle into
 *           bundles/ (or an operator stages one by hand).
 *   WALK    A bundle at a baked rung is staged: walk the header window
 *           H-27..H backward from the compiled rung hash
 *           (checkpoint_header_fetch window mode).
 *   SEED    Verify the window (hash links down from the compiled hash, frozen
 *           PoW + Equihash per header, chainwork from the compiled rung
 *           chainwork), insert it as an island, persist it, mint the pass row
 *           at H, record the durable island-anchor fact (services/
 *           island_anchor.h). The unchanged install-ready condition then arms
 *           the install-on-next-boot and respawns.
 *   DONE    The sovereign bundle marker exists: the hold lifts and header sync
 *           continues from H.
 *
 * Fall back to normal sync, with one log line, when no acceptable offer
 * arrives inside the state-offer wait window, the staged bundle is not at a
 * rung, the walk or its verification fails within its bound, or the install
 * has not happened within its bound. Fall-back drops the island registration
 * so the existing band backfill heals the node from genesis.
 *
 * Trust does not widen: the rung's block hash, chainwork and state digests are
 * compiled, and installing its bundle already takes them on trust. Every header
 * above H keeps every zclassicd rule; the window exists so the first header
 * above H gets its full contextual (difficulty + median-time) check. */

#ifndef ZCL_CONFIG_FLYSYNC_ISLAND_H
#define ZCL_CONFIG_FLYSYNC_ISLAND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct block_header;
struct island_anchor;
struct main_state;
struct uint256;

/* Bounds. The offer wait itself is the state-offer store's STATE_OFFER_WAIT_MS. */
#define FLYSYNC_WALK_TIMEOUT_MS     INT64_C(300000)   /* window walk */
#define FLYSYNC_INSTALL_TIMEOUT_MS  INT64_C(1800000)  /* seeded -> installed */
/* The chosen rung offer's download: fall back only when no new verified chunk
 * has landed for FLYSYNC_FETCH_STALL_MS (a slow link that keeps moving, such
 * as a phone on Tor, keeps waiting), or when the download has run
 * FLYSYNC_FETCH_CAP_MS in this process, counted from the first sighting of the
 * chosen offer, not from the offer wait (time switched off never counts; the
 * held-boot count bounds restarts). */
#define FLYSYNC_FETCH_STALL_MS      INT64_C(600000)     /* 10 min, no chunk */
#define FLYSYNC_FETCH_CAP_MS        INT64_C(21600000)   /* 6 h while running */
#define FLYSYNC_WALK_ATTEMPTS       3
/* Boots that may hold header sync (WAIT, WALK, SEEDED), counted durably in
 * "flysync.hold_boots": the boot that fetches, the install respawns and a few
 * ordinary restarts fit; a crash loop cannot hold the node forever. Time the
 * process is not running never counts (a phone killed overnight still waits);
 * each boot keeps its own in-memory wait, walk, fetch and install bounds. */
#define FLYSYNC_HOLD_BOOTS          8

enum flysync_phase {
    FLYSYNC_OFF = 0,
    FLYSYNC_WAIT,
    FLYSYNC_WALK,
    FLYSYNC_SEEDED,
    FLYSYNC_DONE,
    FLYSYNC_FELL_BACK,
};

const char *flysync_phase_name(enum flysync_phase p);

/* Set before boot; auto leaves existing non-island chain state unchanged. */
void flysync_island_set_auto(bool on);
void flysync_island_set_requested(bool on);
bool flysync_island_requested(void);
enum flysync_phase flysync_island_phase(void);

/* Boot gate, after the block index loads. Returns false when -flysync must
 * refuse this datadir: it holds chain state that is not this node's own
 * FlySync island. `why` names the reason. Also starts the phase machine. */
bool flysync_island_boot_gate(const char *datadir, struct main_state *ms,
                              char *why, size_t why_cap);

struct app_context;

/* Boot, right after the progress store opens and before the block index loads:
 * register a durable island-anchor fact (the loader's work pass reads it). */
bool flysync_island_boot_register(const char *datadir);

/* Boot, right after the block index loads: install the header-sync hold, run
 * the boot gate (false = refuse the boot with an explanatory FATAL block),
 * reconcile a registered island, and stop advertising NODE_NETWORK on an
 * island. A node without -flysync and without the fact is unchanged. */
bool flysync_island_boot_rehydrate(struct main_state *ms);
bool flysync_island_boot_loader_allowed(bool publish_tip);
bool flysync_island_boot_materialize(struct main_state *ms);

bool flysync_island_boot_after_index(struct app_context *ctx,
                                     struct main_state *ms);

/* State-offer height filter: until its rung bundle installs (WAIT/WALK/SEEDED)
 * the node takes only an offer at a baked rung; once it is installed (DONE)
 * none; otherwise (off, fallen back) every height. */
bool flysync_island_wants_offer_height(int32_t height);

/* True while FlySync owns this node's state source (WAIT..DONE): boot skips the
 * keystone capture, the weld and the header-seed import. False when off or
 * fallen back, so a fallen-back node boots exactly like a node without it. */
bool flysync_island_owns_state_source(void);
enum flysync_recovery_result { FLYSYNC_RECOVERY_NOT_APPLICABLE, FLYSYNC_RECOVERY_DEFER, FLYSYNC_RECOVERY_WAIT };
enum flysync_recovery_result flysync_island_recover_staged(const char *datadir, struct main_state *ms);

/* True while normal getheaders requests must not go out (WAIT/WALK/SEEDED). */
bool flysync_island_holds_header_sync(void);

/* Advance the phase machine. Cheap; called from a periodic tick. */
void flysync_island_tick(void);

/* Verify a top-first window (w[0] at top_h) against the compiled rung at top_h
 * and fill the island-anchor fact. False with `why` on any refusal. */
bool flysync_island_verify_window(const struct block_header *w, int n,
                                  int32_t top_h, struct island_anchor *out,
                                  char *why, size_t why_cap);

/* Startup-quiescent terminal install only. No selection, persistence or registration.
 * Failure after insertion requires caller termination or discarding the map. */
struct block_index *flysync_island_prepare_terminal_window(
    struct main_state *ms, const struct block_header *w, int n, int32_t top_h);

/* Insert a verified window as the island, persist it, record the fact. */
bool flysync_island_seed(struct main_state *ms, const struct block_header *w,
                         int n, const struct island_anchor *a);

/* After the block index loads on a registered island: the rung row must be in
 * the index, link down to the root, and carry the compiled rung chainwork.
 * Otherwise a SEEDED island falls back; an INSTALLED one never does (it logs
 * the damage and keeps its registration). Returns true when the island stands. */
bool flysync_island_boot_reconcile(struct main_state *ms);

/* Detach a fallen-back island (see flysync_island.c): every listed row still
 * off the chain (by the fact's height range when the list is unreadable) and
 * every entry descending from one loses its parent and keeps only a token work
 * below any real entry's; the best header moves to the best remaining entry.
 * Returns rows detached. */
size_t flysync_island_detach(struct main_state *ms,
                             const struct island_anchor *a);

#ifdef ZCL_TESTING
typedef bool (*flysync_frozen_verify_fn)(const struct uint256 *hash,
                                         const struct block_header *hdr);
void flysync_island_test_set_frozen_verifier(flysync_frozen_verify_fn fn);
void flysync_island_test_reset(void);
void flysync_island_test_set_clock_ms(int64_t now_ms);
/* Hold the tick as if another thread were inside it (single-entry proof). */
void flysync_island_test_hold_tick(bool held);
/* Restarts a fall-back requested (counted instead of shutting down). */
int flysync_island_test_respawns(void);
/* Replace the compiled rung ladder with one rung (NULL restores it). */
struct rom_state_rung;
void flysync_island_test_set_rung(const struct rom_state_rung *rung);
#endif

#endif /* ZCL_CONFIG_FLYSYNC_ISLAND_H */
