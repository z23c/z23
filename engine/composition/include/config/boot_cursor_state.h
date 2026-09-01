/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * OS-S2 — Boot O(delta): persisted cursors that turn the four O(chain) boot
 * passes into O(delta) re-walks. One module owns the node_state keys, the
 * reorg clamp, the block-index fingerprint, and the cursor-gated wrappers for
 * the height-repair (#1) and nChainTx-propagation (#2) passes so no cursor
 * logic is scattered across boot.c.
 *
 * Consensus-parity: these cursors gate boot-derived NAVIGATION indices
 * (block_index.nHeight/pprev/nChainTx/nChainWork) and a wallet projection.
 * NONE touch H* (the reducer_frontier fold over progress.kv), coins_kv, or
 * sapling_anchors/nullifiers. A stale/wrong cursor can only cause a re-scan
 * (slower boot), never a wrong consensus value.
 */

#ifndef ZCL_CONFIG_BOOT_CURSOR_STATE_H
#define ZCL_CONFIG_BOOT_CURSOR_STATE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* node_state keys (see models/database.h node_db_state_get_int/set_int). */
#define BOOT_CUR_HEIGHTS      "heights_repaired_upto"
#define BOOT_CUR_HEIGHTS_CNT  "heights_repaired_count"
#define BOOT_CUR_NCHAINTX     "nchaintx_complete_upto"
/* Wallet cursor + keyset fingerprint (single wallet today; the fingerprint
 * forces a full re-scan whenever the keyset changes — import/remove). */
#define BOOT_CUR_WALLET       "wallet_last_scanned_height"
#define BOOT_CUR_WALLET_KS    "wallet_scanned_keyset_fp"

struct node_db;
struct main_state;
struct active_chain;
struct wallet;

/* Cheap O(n) block-index fingerprint over
 * (phashBlock[0..7] ^ nStatus ^ nChainWork.lo ^ nHeight ^ nChainTx).
 * One tight XOR-accumulate loop, no arith compares, no branches on payload.
 * Used by #3's scan-facts validation and by every A/B equality test. */
uint64_t boot_block_index_fingerprint(const struct main_state *ms);

/* Clamp every boot-derived int cursor to fork_height-1 on a confirmed reorg.
 * Idempotent, min-only: a cursor at/below fork_height-1 is left untouched.
 * The scan-facts binding (#3) needs no clamp (it co-invalidates with the
 * clean-shutdown quick-check). */
void boot_cursor_clamp_on_reorg(struct node_db *ndb, int fork_height);

/* Register boot_cursor_clamp_on_reorg (bound to `ndb`) with the tip_finalize
 * reorg-rewind chokepoint so a live reorg clamps the boot cursors down. */
void boot_cursor_install_reorg_clamp(struct node_db *ndb);

/* #1 — cursor-gated block_index height repair. Reads BOOT_CUR_HEIGHTS +
 * BOOT_CUR_HEIGHTS_CNT, re-scans only above the cursor when the map size is
 * unchanged, re-stamps the high-water. Returns the number of heights repaired
 * (accumulated into index_repaired by the caller, exactly like the un-cursored
 * block_index_repair_heights it replaces). */
int boot_cursor_repair_heights(struct main_state *ms, struct node_db *ndb);

/* #2 — cursor-gated nChainTx propagation. Reads BOOT_CUR_NCHAINTX, restricts
 * the "already computed" pre-scan to entries above the cursor, runs the full
 * forward-fill only on a violation, and stamps the tip height when the index
 * is proven contiguous-complete. Replaces the inline nChainTx block in boot.c
 * (identical derived state; O(delta) pre-scan). */
void boot_cursor_propagate_nchaintx(struct main_state *ms, struct node_db *ndb);

/* #4 (pure decision) — the wallet-scan start height from the persisted cursor +
 * keyset fingerprint. Returns 0 (full scan) when there is no durable cursor (an
 * old wallet datadir → one final full scan) or the keyset changed (a key
 * import/removal makes prior partial scans incomplete); otherwise cursor+1 (the
 * O(delta) re-scan). Returns tip_h+1 (an empty range the scan skips) when the
 * cursor already covers the tip. Separated from the node_db I/O so it is
 * directly unit-testable. */
int boot_cursor_wallet_scan_start(bool have_cursor, int64_t cursor,
                                  bool have_ks, uint64_t stored_fp,
                                  uint64_t cur_fp, int tip_h);

/* #4 — cursor-gated wallet block scan. Reads BOOT_CUR_WALLET + BOOT_CUR_WALLET_KS,
 * calls wallet_scan_blocks over only [start, tip] (start from
 * boot_cursor_wallet_scan_start), and stamps the cursor + keyset fp after a
 * successful scan so each boot re-scans only the new tip delta — turning the
 * unconditional O(chain) boot wallet scan into O(delta). A missing cursor on an
 * existing wallet datadir does one final full scan then persists (no correctness
 * regression). The reorg clamp already rewinds BOOT_CUR_WALLET on a fork.
 * Returns wallet_scan_blocks' result (transactions found, or -1 on error). */
int boot_cursor_scan_wallet(struct node_db *ndb,
                            const struct active_chain *chain,
                            const struct wallet *w,
                            const char *datadir, int tip_h);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONFIG_BOOT_CURSOR_STATE_H */
