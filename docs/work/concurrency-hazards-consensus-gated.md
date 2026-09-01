# Consensus-gated concurrency hazards (boot-validation blocked)

These are real cross-thread hazards in the consensus/chain-advance path,
documented here with precise fixes. Each fix changes locking on the **live
chain path** and MUST be boot-validated for both correctness AND absence of
deadlock under live reorg before applying — copy-prove first, per the
standing method. Verify the live H\* via `z23 status` /
`z23 dumpstate reducer_frontier`; `docs/HANDOFF.md` holds current
state. NONE of these is the already-fixed `phashBlock` UAF.

## 1 — bg_validation_service.c lock-free `chain_active` read (HIGHEST value — a real UAF)

`bg_validation_thread` reads `ms->chain_active` **lock-free** from its background
thread: `active_chain_height(&ms->chain_active)` (bg_validation_service.c:430,
:454) reads `c->height`, and `active_chain_at(&ms->chain_active, h)` (:458, and
the genesis probe :670-671) reads `c->height` then dereferences `c->chain[h]`.

Concurrently the reducer's `tip_finalize_stage.c:380 →
active_chain_move_window_tip → active_chain_fill_window`
(`core/modules/validation/src/chainstate.c:298`) does `zcl_realloc(c->chain, …)`
(chainstate.c:305) — **freeing the old `c->chain` array** — and rewrites
`c->height` as the tip advances. `struct active_chain` has NO internal lock; the
protecting lock is `ms->cs_main`, which `bg_validation_service.c` **never takes**
(grep `cs_main` in that file = empty). When the realloc fires, the bg thread
reads a freed `c->chain` array → SIGSEGV/UAF. Same class as the fixed phashBlock
UAF, in a different structure.

**Proof it is real, not speculative:** the sibling service
`bg_hash_verification_service.c` (~lines 185-206) does the identical work and
carries the explicit comment *"Take cs_main briefly to snapshot block_index
fields. Without this lock, active_chain_move_window_tip() can realloc the chain
array or swap entries during reorgs, causing SIGSEGV when we read stale/freed
pointers."* bg_validation was simply not given the same guard.

**Fix (mirror the sibling exactly):** take `ms->cs_main`; call
`active_chain_height` + `active_chain_at` under the lock; snapshot
`pindex->nFile`, `nDataPos`, `(nStatus & BLOCK_HAVE_DATA)`, `*pindex->phashBlock`
and the height bound into locals; release `cs_main`; THEN do
`read_block_from_disk` + `validate_block_proofs` on the snapshot (block_index
nodes are per-node and never freed, so retaining `pindex` across disk I/O is
safe — only the `active_chain` array access must move under `cs_main`). Apply to
the :430/:454 refresh and the :670-671 genesis probe. Cannot be unit-tested
without the live reducer-vs-bg-thread realloc race.

## 2 — chainstate.c `nChainWork` 256-bit torn read (consensus-critical)

`block_index.nChainWork` is a 32-byte `arith_uint256` (4× uint64), plain/non-atomic
(`core/modules/chain/include/chain/chain.h:87`). The header/validation thread updates it
field-by-field via `arith_uint256_add` (accept_block_header.c:198/251/283/366;
boot.c:2122) while `msg_headers.c:83-84,125-128` (message-handler thread, no lock)
and `header_sync_service.c:598` read it **lock-free** to compare chain work for
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

`node_health_service.c:254-255` reads `ms->pindex_best_header->nHeight` with no
`cs_main`, while `accept_block_header.c` writes `ms->pindex_best_header`. The
pointer field is plain; on mainstream targets an aligned pointer load is atomic
in practice and block_index nodes are never freed, so the worst real outcome is a
slightly stale `nHeight`, not a crash — but it is a documented C-memory-model
data race. Same at `chain_tip.c:64-65`. Other readers (`gap_fill_service.c:157-166`)
correctly take `cs_main`.

**Fix:** wrap the read in `zcl_mutex_lock(&ms->cs_main)`/unlock, copy `nHeight`
into a local (match `gap_fill_service.c`); apply to `chain_tip.c:64-65` too.
Low value (stale display only) — batch with items 1/2.

## 4 — progress_store.c diagnostic race on `g_path`/`g_opened_at` (low)

`progress_store_dump_state_json` (:352) reads `g_path` (:360) and `g_opened_at`
(:361) without `g_lock`, while open/close write them under `g_lock`. `g_db` is
`_Atomic` so the open/closed flag is race-free; `g_path`/`g_opened_at` are plain
and can be read mid-write → garbled/stale path string in a state dump, no crash.
**Fix (if pursued):** snapshot both into locals under `g_lock` inside the dump.
Diagnostic-only — the `g_lock` acquire interleaves with the open/close init
mutex, so it is a deliberate review, not a drive-by edit. Batch with items 1/2.
