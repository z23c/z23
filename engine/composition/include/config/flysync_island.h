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
#define FLYSYNC_WALK_ATTEMPTS       3

enum flysync_phase {
    FLYSYNC_OFF = 0,
    FLYSYNC_WAIT,
    FLYSYNC_WALK,
    FLYSYNC_SEEDED,
    FLYSYNC_DONE,
    FLYSYNC_FELL_BACK,
};

const char *flysync_phase_name(enum flysync_phase p);

/* -flysync. Set once from argv before boot. */
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
void flysync_island_boot_register(void);

/* Boot, right after the block index loads: install the header-sync hold, run
 * the boot gate (false = refuse the boot with an explanatory FATAL block),
 * reconcile a registered island, and stop advertising NODE_NETWORK on an
 * island. A node without -flysync and without the fact is unchanged. */
bool flysync_island_boot_after_index(struct app_context *ctx,
                                     struct main_state *ms);

/* True while normal getheaders requests must not go out (WAIT/WALK/SEEDED). */
bool flysync_island_holds_header_sync(void);

/* Advance the phase machine. Cheap; called from a periodic tick. */
void flysync_island_tick(void);

/* Verify a top-first window (w[0] at top_h) against the compiled rung at top_h
 * and fill the island-anchor fact. False with `why` on any refusal. */
bool flysync_island_verify_window(const struct block_header *w, int n,
                                  int32_t top_h, struct island_anchor *out,
                                  char *why, size_t why_cap);

/* Insert a verified window as the island, persist it, record the fact. */
bool flysync_island_seed(struct main_state *ms, const struct block_header *w,
                         int n, const struct island_anchor *a);

/* After the block index loads on a registered island: the rung row must be in
 * the index, link down to the root, and carry the compiled rung chainwork.
 * Otherwise the island falls back. Returns true when the island stands. */
bool flysync_island_boot_reconcile(struct main_state *ms);

#ifdef ZCL_TESTING
typedef bool (*flysync_frozen_verify_fn)(const struct uint256 *hash,
                                         const struct block_header *hdr);
void flysync_island_test_set_frozen_verifier(flysync_frozen_verify_fn fn);
void flysync_island_test_reset(void);
void flysync_island_test_set_clock_ms(int64_t now_ms);
/* Replace the compiled rung ladder with one rung (NULL restores it). */
struct rom_state_rung;
void flysync_island_test_set_rung(const struct rom_state_rung *rung);
#endif

#endif /* ZCL_CONFIG_FLYSYNC_ISLAND_H */
