# Consensus-gated concurrency hazards (boot-validation blocked)

These are real cross-thread hazards in the consensus/chain-advance path,
documented here with precise fixes. Each fix changes locking on the **live
chain path** and MUST be boot-validated for both correctness AND absence of
deadlock under live reorg before applying — copy-prove first, per the
standing method. Verify the live H\* via `z23 status` /
`z23 dumpstate reducer_frontier`; `docs/agent/HANDOFF.md` holds current
state. NONE of these is the already-fixed `phashBlock` UAF.

## 1 — bg_validation_service.c lock-free `chain_active` read (no UAF on origin/main)

`bg_validation_thread` reads `ms->chain_active` **lock-free** from its background
thread: `active_chain_height(&ms->chain_active)` (bg_validation_service.c:1026,
:1054) reads `c->height`, and `active_chain_at(&ms->chain_active, h)` (:1058, the
catch-up round :793, and the genesis probe :1140-1141) reads `c->height` then
dereferences `c->chain[h]`.

Concurrently the reducer's `active_chain_move_window_tip`
(`core/modules/validation/src/chainstate.c:523`, reached from
`engine/jobs/src/tip_finalize_batch_drain.c:31`) calls `active_chain_fill_window`
(chainstate.c:480), which rewrites `c->height` as the tip advances. The array is
not freed in place: `active_chain_grow_locked` (chainstate.c:435) publishes a
fully populated new array (chainstate.c:452), then moves the old one to the
`retired` list (chainstate.c:458), freed only by `active_chain_free`. Readers
load the height before the array, and writers publish the height last
(chainstate.c:342-346, 478). Writers serialize on `write_lock`
(chainstate.h:146); readers take no lock. On origin/main the bg thread therefore
cannot dereference freed storage, and the realloc UAF this item once described
does not occur.

**Sibling comment:** `bg_hash_verification_service.c` (lines 163-166) takes
`cs_main` around the same snapshot and carries the explicit comment *"Take cs_main
briefly to snapshot block_index fields. Without this lock, active_chain_move_window_tip()
can realloc the chain array or swap entries during reorgs, causing SIGSEGV when
we read stale/freed pointers."* That comment describes a realloc that
`chainstate.c` no longer performs (see above).

**Fix (only if the retired-array discipline changes; mirrors the sibling):** take `ms->cs_main`; call
`active_chain_height` + `active_chain_at` under the lock; snapshot
`pindex->nFile`, `nDataPos`, `(nStatus & BLOCK_HAVE_DATA)`, `*pindex->phashBlock`
and the height bound into locals; release `cs_main`; THEN do
`read_block_from_disk` + `validate_block_proofs` on the snapshot (block_index
nodes are per-node and never freed, so retaining `pindex` across disk I/O is
safe — only the `active_chain` array access must move under `cs_main`). Apply to
the :1026/:1054/:1058 refresh, :793, and the :1140-1141 genesis probe. Cannot be unit-tested
without the live reducer-vs-bg-thread realloc race.

## 2 — chainstate.c `nChainWork` 256-bit torn read (consensus-critical)

`block_index.nChainWork` is a 32-byte `arith_uint256` (8× uint32),
plain/non-atomic (`core/modules/chain/include/chain/chain.h:110`). The header/validation thread updates it
field-by-field via `arith_uint256_add` (accept_block_header.c:196/247/279/362;
msg_headers.c:1635) while `msg_blocks.c:617` (message-handler thread, no lock)
and `header_sync_service.c:597` read it **lock-free** to compare chain work for
tip/locator selection. The chainstate rwlock guards only the bucket array, not
the per-node `nChainWork` bytes. A reader can observe a half-updated 256-bit work
value mid-`arith_uint256_add` → wrong `arith_uint256_compare` → bad tip/header
decision (a consensus fault). Same applies to other plain per-node scalars
(`nStatus`, `nFile`, `nDataPos`) read lock-free by the same walkers.

**Fix:** serialize per-node `block_index` field mutations and the lock-free
consensus walkers under one lock (cs_main, or take the block_map rwlock as a read
lock for a work-comparison walk and a write lock around the `nChainWork` update),
so a 256-bit work value is never read mid-update.

## 3 — node_health_service.c / chain_tip.c lock-free `pindex_best_header` read (low)

`node_health_service.c:658-659` reads `ms->pindex_best_header->nHeight` with no
`cs_main`, while `process_block_tip_publish.c:192` writes `ms->pindex_best_header`. The
pointer field is plain; on mainstream targets an aligned pointer load is atomic
in practice and block_index nodes are never freed, so the worst real outcome is a
slightly stale `nHeight`, not a crash — but it is a documented C-memory-model
data race. Same at `chain_tip.c:64-65`. Other readers (`gap_fill_service.c:421`,
in a function whose caller holds `cs_main`) read it under the lock.

**Fix:** wrap the read in `zcl_mutex_lock(&ms->cs_main)`/unlock, copy `nHeight`
into a local (match `gap_fill_service.c`); apply to `chain_tip.c:64-65` too.
Low value (stale display only) — batch with items 1/2.

## 4 — progress_store.c diagnostic race on `g_path`/`g_opened_at` (low; fixed on origin/main)

`progress_store_dump_state_json` (progress_store.c:884) copies `g_display_path` and
`g_opened_at` under `g_lock` (:896-900), the same lock open and close use to write
them, so the state dump cannot read them mid-write on origin/main. `g_db` is
`_Atomic` so the open/closed flag is race-free.
**Fix:** already applied on origin/main (snapshot under `g_lock`, progress_store.c:896-900).
Diagnostic-only — the `g_lock` acquire interleaves with the open/close init
mutex, so it is a deliberate review, not a drive-by edit. Batch with items 1/2.
