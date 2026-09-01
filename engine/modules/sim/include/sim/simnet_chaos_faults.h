/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * simnet chaos-fault injectors — the always-sync G-TIP harness.
 *
 * MISSION this file serves: the node must ALWAYS fold to the network tip and
 * never silently stall. A stall is always a NAMED, SELF-HEALED blocker at a
 * known height — never a silent halt, never an operator page for a
 * recoverable cause. These six functions each reproduce ONE class of fault
 * against a throwaway fixture (a scratch datadir, a scratch progress.kv, a
 * scratch supervisor/condition/blocker registration) and report whether the
 * subsystem under test named the fault and returned to advancing.
 *
 * This is TEST/SIM SCAFFOLDING, not production code: it builds fixtures with
 * raw sqlite3 INSERTs (the same convention tests/harness/src/test_reducer_frontier.c
 * documents — "does not route through the AR lifecycle... this is TEST
 * scaffolding building the durable image, not production reducer code") and
 * calls real production entry points (block_index_loader_seed_tip_from_
 * finalized, reducer_frontier_compute_hstar, segment_corruption_scan_one/
 * repair, the supervisor + condition-engine + blocker primitives) as pure
 * oracles. No production .c/.h file is touched by this module's existence.
 *
 * Every fault:
 *   (a) chaos_fault_empty_active_chain_window — the block-index map is FULL
 *       (every header admitted, chained, HAVE_DATA+VALID_SCRIPTS) while the
 *       active-chain window is EMPTY (active_chain_tip() == NULL) — the
 *       "Pillar-0" boot wedge. Reproduces it at a caller-chosen gap size so
 *       one call can model both the in-bounds repair (already landed,
 *       BLOCK_INDEX_LOADER_SEED_MAX_GAP) and the live-node wedge scale
 *       (currently refused by design — see docs/HANDOFF.md).
 *   (b) chaos_fault_kill_restart_mid_fold — an abrupt close+reopen of
 *       progress.kv mid-fold (simulates kill -9 before the last stage
 *       committed); asserts H* recomputes identically after the "restart".
 *   (c) chaos_fault_corrupt_sealed_segment — tampers one sealed ROM segment
 *       byte and drives the existing segment_corruption {detect, remedy,
 *       witness} healer to completion.
 *   (d) chaos_fault_freeze_reducer_drive — freezes a supervised child's
 *       heartbeat past its deadline, asserts a NAMED stall (never silent),
 *       then unfreezes it and asserts it resumes ticking.
 *   (e) chaos_fault_stall_single_stage — a typed TRANSIENT blocker + a
 *       synthetic condition model a single reducer stage stalling; asserts
 *       zero EV_OPERATOR_NEEDED pages while the retry budget holds, then
 *       clears and asserts a witnessed self-heal.
 *   (f) chaos_fault_kill_restart_mid_recovery — unlike (b) (kill BEFORE any
 *       repair action started), this kills INSIDE an open recovery window:
 *       after the real stage_rederive_range() primitive (engine/jobs/src/
 *       stage_rederive_range.c) has committed a rewind (stage cursors
 *       lowered, stale suffix rows deleted, coins inverse-rewound) but
 *       before the drive re-folds the range forward. Asserts H* and the
 *       coins-applied frontier are byte-identical across the abrupt
 *       close+reopen, AND that a post-restart call converges (the primitive
 *       resumes idempotently — no duplicate rewind, no lost frontier, no
 *       silent stall).
 *   (n) chaos_fault_torn_progress_wal — checkpoints a base prefix into the
 *       main db, stamps a further suffix into an un-checkpointed WAL, then
 *       truncates a hot copy of that WAL mid-stream (a kill -9 between
 *       commits). Asserts the store reopens clean and H* lands on a
 *       consistent prefix in [base, tip] — never above the last commit,
 *       never below the checkpoint.
 *   (o) chaos_fault_disk_full_pause — caps the store at its current page
 *       count so the next coins write returns SQLite's own SQLITE_FULL,
 *       then lifts the cap. Asserts the real coins write path fails SAFE
 *       (reports failure, never a partial commit, the coin set never
 *       shrinks) and the identical write succeeds once space returns.
 *   (p) chaos_fault_cleared_have_data_hole — models a persisted body that
 *       vanished (HAVE_DATA cleared at height H) as a validated header with
 *       no observed body while the body_fetch cursor stalls at H. Asserts
 *       the production body-fetch-gap predicate NAMES the hole at that exact
 *       height, then clears once the body is re-fetched.
 *
 * Every function is self-contained: it opens/builds its own fixture,
 * exercises the fault, tears down, and never mutates a live datadir (never
 * touches ~/.zclassic-c23 or the mint producer datadirs).
 */

#ifndef ZCL_SIM_SIMNET_CHAOS_FAULTS_H
#define ZCL_SIM_SIMNET_CHAOS_FAULTS_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Common outcome record every fault-injector fills in. */
struct chaos_fault_result {
    bool    ok;              /* the fault was injected and the fixture built
                              * cleanly (a false here is a HARNESS defect,
                              * not a finding about the subsystem). */
    bool    recovered;       /* the subsystem returned to advancing/serving
                              * after the fault (H* climbed again / the tip
                              * resolved / the child resumed ticking / the
                              * blocker cleared). */
    bool    operator_paged;  /* an EV_OPERATOR_NEEDED (or equivalent named
                              * escalation) fired for what should have been
                              * a RECOVERABLE cause. This is the failure mode
                              * the mission forbids — it must be false on
                              * every case this harness asserts (not merely
                              * skips). */
    int32_t hstar_before;    /* -1 when not applicable to this fault */
    int32_t hstar_after;     /* -1 when not applicable to this fault */
    char    note[192];       /* human-readable outcome for the test's printf */
};

/* (a) Pillar-0: full block index, empty active-chain window.
 *
 * Builds a genesis-rooted regtest chain 0..gap_height (every link
 * HAVE_DATA + VALID_SCRIPTS, contiguous pprev — "block index map full"),
 * leaves the active-chain window freshly initialized (NULL tip — "active
 * window empty"), seeds the durable finalized anchor + coins-applied
 * frontier at gap_height, then calls the real
 * block_index_loader_seed_tip_from_finalized() boot-repair path.
 *
 * On a successful install (`out->ok`), also stamps a full consistent ok=1
 * stage-log prefix [0, gap_height] and reads H* back via
 * reducer_frontier_compute_hstar() so `out->hstar_after` proves H* CLIMBED
 * to gap_height, not merely that a pointer became non-NULL.
 *
 * `out->recovered` mirrors `out->ok` here (there is no separate "unfreeze"
 * step for this fault — the repair either installs or it doesn't).
 * Returns false only on a harness-fixture error (disk, sqlite, OOM); check
 * `out->ok` for the actual repair verdict. */
bool chaos_fault_empty_active_chain_window(int gap_height,
                                           struct chaos_fault_result *out);

/* (b) kill/restart mid-fold.
 *
 * Builds a progress.kv fixture with a consistent ok=1 stage-log prefix
 * through a chosen height K, closes the store (simulating kill -9 before
 * any further stage advances), reopens it fresh on the same directory
 * (simulating the restart), and recomputes H*. Asserts nothing was lost or
 * corrupted by the abrupt close/reopen: hstar_after == hstar_before == K. */
bool chaos_fault_kill_restart_mid_fold(struct chaos_fault_result *out);

/* (c) corrupt a sealed chain_segment.
 *
 * Seals two segments into a fixture directory, tampers one byte in the
 * second's block-data region, drives segment_corruption_scan_one (detect)
 * then segment_corruption_repair (remedy), and re-opens the store to
 * witness the corrupt range is no longer covered while the survivor still
 * verifies clean — the "returns to SERVING" proof for this fault (reads
 * fall back to blk*.dat instead of ever serving corrupt bytes). */
bool chaos_fault_corrupt_sealed_segment(struct chaos_fault_result *out);

/* (d) freeze the reducer drive (supervisor liveness layer).
 *
 * Registers a synthetic supervised child modeling the reducer-drive tick
 * loop, freezes its heartbeat past its deadline, asserts the supervisor
 * fires exactly one NAMED stall (SUPERVISOR_STALL_TIME_DEADLINE, never a
 * silent halt), then "unfreezes" it (fresh heartbeat) and asserts it
 * resumes ticking on the next sweep. */
bool chaos_fault_freeze_reducer_drive(struct chaos_fault_result *out);

/* (e) stall a single stage.
 *
 * Registers a synthetic condition modeling one reducer stage stalled
 * behind a typed TRANSIENT blocker. Drives the condition engine while
 * counting EV_OPERATOR_NEEDED fires: asserts zero pages while the retry
 * budget holds, then flips the fixture's witness to simulate the stage's
 * self-heal and asserts the condition clears and the blocker is removed
 * with STILL zero operator pages. */
bool chaos_fault_stall_single_stage(struct chaos_fault_result *out);

/* (f) kill/restart mid-RECOVERY (inside an open rederive/rewind window).
 *
 * Stamps a full consistent prefix [0, N], then calls the real
 * stage_rederive_range() primitive to open a recovery window at a hole
 * height HOLE < N (rewinding the body-dependent stage cursors to HOLE,
 * deleting the stale suffix rows [HOLE, N], and inverse-rewinding the
 * coins-applied frontier to HOLE — exactly what a self-heal rung does
 * before the drive re-folds forward). Records H* and the coins-applied
 * frontier at that point, then simulates kill -9 (abrupt progress.kv
 * close + reopen, no in-RAM state survives) and re-reads both.
 *
 * `out->recovered` is true iff: H* and the coins-applied frontier are
 * IDENTICAL before and after the kill (nothing lost or corrupted inside
 * the window), both name the exact rewound height (HOLE-1 / HOLE — never
 * a silent/undefined value, never a value that would imply the coins
 * frontier was wiped back to "not found"), and a second
 * stage_rederive_range() call over the same range succeeds post-restart
 * (the next boot pass converges — resumes idempotently instead of
 * erroring or stalling). */
bool chaos_fault_kill_restart_mid_recovery(struct chaos_fault_result *out);

/* ══════════════════════════════════════════════════════════════════════
 * (g)-(l): the sync/ROM-artifact fault matrix (lane G3)
 *
 * Six more named injectors extending the always-sync corpus above, this time
 * over the ROM-artifact delivery path (core/modules/net/rom_fetch.c, rom_journal.c,
 * rom_seed.c) and the pure snapshot-sync kernel (core/modules/sync/src/sync_reduce.c).
 * Same law as (a)-(f): every fault DRIVES real production entry points as
 * pure oracles — no production .c/.h logic is edited by this module's
 * existence — and every outcome is either a proven recovery or a NAMED
 * blocker, never a silent stall or an unproven "looks fine".
 *
 * Every function fills a `struct sync_fault_capsule`, which wraps the (a)-(f)
 * `chaos_fault_result` shape (ok/recovered/operator_paged/note) with the
 * "every bug is a 64-bit seed" replay fields the doctrine requires: the seed
 * that drove any per-run variation, the ordinal event that fired the fault,
 * a short phase/fault-point label, and a before/after state snapshot. */

/* Common capsule every (g)-(l) injector fills in — see the header above. */
struct sync_fault_capsule {
    struct chaos_fault_result base;   /* ok / recovered / operator_paged / note */
    uint64_t seed;                    /* deterministic replay seed for this run */
    uint32_t event_number;            /* ordinal of the event that fired the fault */
    char     phase[32];               /* short phase/state name at the fault point */
    char     fault_point[80];         /* exact boundary/action the fault targets */
    char     state_before[160];       /* human-readable snapshot before the fault */
    char     state_after[160];        /* human-readable snapshot after the fault  */
    char     replay_command[192];     /* how an operator reproduces this exact run */
};

/* (g) Two peers serving DIFFERENT bytes for the SAME chunk index.
 *
 * Registers one real artifact on a real fs_server (the GOOD peer, honest
 * content). A second, hand-built TCP listener (the BAD peer — real
 * fs_session_init/fs_handshake/fs_recv_frame/fs_send_chunk_fast, all real
 * production wire primitives, just fed deliberately wrong chunk bytes) claims
 * to serve the SAME chunk_root/index. The transport MAC is self-consistent
 * (fs_send_chunk_fast binds MAC to whatever bytes it is given, exactly as the
 * honest server does — the MAC proves in-flight integrity, never semantic
 * correctness), so the fetch from the BAD peer succeeds at the transport
 * layer; the fault is caught only by the CONTENT check
 * (rom_fetch_verify_chunk against the manifest's committed digest). Asserts:
 * the good peer's chunk is fetched, verified, and durably journaled first;
 * the bad peer's reply for the SAME index fails content verify; the bad peer
 * is named via rom_peer_note_bad_chunk and reads back deprioritized; and the
 * journal + on-disk .part bytes for that chunk are UNCHANGED by the rejected
 * attempt (the good chunk is kept). */
bool chaos_fault_conflicting_chunk_peers(uint64_t seed,
                                         struct sync_fault_capsule *out);

/* (h) ENOSPC (write failure) during a journal bitmap commit.
 *
 * Marks one chunk done normally, then uses setrlimit(RLIMIT_FSIZE) positioned
 * exactly at the journal's bitmap-byte offset (SIGXFSZ ignored for the
 * duration) to force a REAL pwrite() failure (EFBIG — the standard,
 * privilege-free substitute for ENOSPC at this exact syscall boundary; no
 * root/mount-namespace is available in a sandboxed worktree to force a
 * literal full filesystem, and rom_journal_mark's error handling does not
 * distinguish errno) on the NEXT rom_journal_mark() call — the same pwrite
 * the durability contract requires before a bit is considered set. Asserts
 * the failed mark returns false, the in-memory bit is rolled back (never a
 * half-committed bit), count_done is unaffected, and — after the rlimit is
 * restored — the SAME mark call succeeds and a fresh reopen of the journal
 * from disk agrees with the in-memory state exactly (no stray bit either
 * way). */
bool chaos_fault_journal_commit_enospc(uint64_t seed,
                                       struct sync_fault_capsule *out);

/* (i) Kill at the two per-chunk resume boundaries rom_journal.h documents:
 * "pwrite the chunk data -> fdatasync(.part) -> set the chunk's journal bit
 * -> fdatasync(journal)". `after_bitmap_commit=false` kills BETWEEN the data
 * fsync and the bitmap mark (the last chunk's bytes are durably on disk but
 * the journal never learns it — resume must not trust it and must refetch
 * exactly that one chunk). `after_bitmap_commit=true` kills AFTER every
 * chunk's bitmap bit is committed but BEFORE the final whole-file-verify +
 * atomic rename (resume must trust every journaled bit, refetch NOTHING, and
 * still complete the rename). Either way asserts at most one chunk is ever
 * refetched/redone and the resumed run converges to a correctly verified,
 * correctly renamed final file. */
bool chaos_fault_kill_resume_boundary(uint64_t seed, bool after_bitmap_commit,
                                      struct sync_fault_capsule *out);

/* (j) Header reorg during an artifact download — driven directly against the
 * PURE sync_reduce kernel (core/modules/sync/src/sync_reduce.c), no IO. Walks the
 * legitimate START/OFFER_RECEIVED/OFFER_ACCEPTED/CHUNK_RECEIVED sequence into
 * RECEIVING, then fires a PEER_LOST event — the kernel's existing, documented
 * stand-in for "the anchor this session was chasing was reorged out from
 * under it" (there is no separate REORG event in the catalog; PEER_LOST is
 * the typed blocker this class of fault raises). Asserts the decision moves
 * to FAILED with SYNC_BLOCKER_PEER_LOST and SYNC_ACTION_FAIL, and then drives
 * a further CHUNK_RECEIVED / RECEIVE_COMPLETE / PROOF_VERIFIED(proof_ok=true)
 * sequence at the SAME (now-stale) session id, asserting the phase never
 * leaves FAILED and SYNC_ACTION_STAGE_BUNDLE never appears again — the
 * bundle whose anchor was reorged out is never installed. */
bool chaos_fault_reorg_during_artifact_download(uint64_t seed,
                                                struct sync_fault_capsule *out);

/* (k) Slow-loris seeder: a connection that stalls forever instead of
 * refusing or replying. Modeled at the SAME supervisor liveness primitive
 * every bounded-stall class in this codebase ultimately surfaces through
 * (mirrors chaos_fault_freeze_reducer_drive's idiom exactly, scoped to a
 * distinct "chaos.rom_fetch_wait" liveness contract) rather than blocking
 * this gate on rom_fetch.c's REAL multi-second socket timeouts
 * (RF_CONNECT_TIMEOUT_SEC=10 / RF_IO_TIMEOUT_SEC=120 — no test-only override
 * exists, and adding one would be a rom_fetch.c logic edit this lane may not
 * make): a frozen heartbeat proves the SAME "bounded stall -> named stall,
 * never a silent hang" property those real timeouts exist to guarantee, in
 * milliseconds instead of two real minutes. Asserts a named
 * SUPERVISOR_STALL_TIME_DEADLINE fires (never silent) and the child resumes
 * ticking once unfrozen (the stall was bounded, not permanent). */
bool chaos_fault_slow_loris_seeder(uint64_t seed,
                                   struct sync_fault_capsule *out);

/* (l) A valid multi-block "bundle" (a genesis-rooted prefix a checkpoint/
 * artifact install would have left, minted via the real simnet_cluster
 * mint/connect path) immediately followed by one invalid TAIL block — driven
 * through the real Byzantine-fixture connect_block(...,just_check=false)
 * path (sim/simnet_byzantine.h), never a synthetic accept. Asserts the tail
 * block is REJECTED independently of the valid prefix (the tip never
 * advances past the bundle's last height — bundle acceptance never vouches
 * for what comes after it), and that an honest block at the same height
 * connects cleanly right after (the rejected tail did not wedge the chain). */
bool chaos_fault_invalid_tail_block(uint64_t seed,
                                    struct sync_fault_capsule *out);

/* ══════════════════════════════════════════════════════════════════════
 * (m) P2P body-download disruption/resume — the on-disk BLOCK_HAVE_DATA
 * no-refetch contract (lane G4: wf/disruption-resume)
 *
 * Distinct from (i) (rom_journal's chunk-bitmap resume, the SHA3
 * snapshot/artifact path) — this fault exercises the OTHER, older resume
 * surface: ordinary P2P block-BODY download, the real
 * download_manager (core/modules/net/src/download.c) plus the real pure planner
 * engine/services/src/header_sync_service.c implements against
 * sync/sync_planner.h's syncsvc_collect_needed_blocks() — the exact
 * function msg_headers.c calls on every accepted header batch to decide
 * which bodies to queue.
 * ══════════════════════════════════════════════════════════════════════ */

/* Result of chaos_fault_peer_disconnect_mid_body_download. */
struct body_download_resume_result {
    struct chaos_fault_result base;   /* ok / recovered / operator_paged / note */
    int32_t  chain_len;               /* simulated chain height (tip) */
    int32_t  persisted_at_disruption; /* our_height the instant the peer died */
    int32_t  final_height;            /* our_height after the resumed drive */
    uint64_t requested_total;         /* dl_get_stats total_requested, final */
    uint64_t duplicate_persisted_requests; /* count of already-HAVE_DATA
                                            * heights EVER handed back by a
                                            * post-disruption collect/queue
                                            * pass, or ever found in-flight
                                            * again — must be 0 */
    int64_t  reconnect_decision_us;   /* wall-clock: disconnect ->
                                       * reconnected peer's first assigned
                                       * request (collect+queue+assign,
                                       * NO simulated transfer delay) — the
                                       * production decision path's own
                                       * contribution to resume latency */
    int64_t  resume_latency_us;       /* wall-clock: reconnect assignment ->
                                       * first NEW (post-disruption) block
                                       * durably received — includes a
                                       * deliberate per-block simulated
                                       * transfer delay so this number is a
                                       * representative LAN figure, not a
                                       * meaningless sub-microsecond one.
                                       * -1 if no block was ever received. */
};

/* Builds a genesis-rooted synthetic chain [0, chain_len] (chain_len must be
 * >= 8). A durable quarter-chain baseline starts BLOCK_HAVE_DATA (blocks the
 * node already had before this run). A download_manager then plays out a
 * realistic mid-transfer disruption: a peer is assigned a window of the next
 * blocks, roughly a third of that window completes (real forward progress:
 * received + HAVE_DATA set + the active-chain tip pointer genuinely
 * advances) before the peer disconnects — dl_peer_disconnected() re-queues
 * only the still-in-flight remainder of that window, never a
 * received/persisted height (structurally impossible: a received hash is no
 * longer in the in-flight table dl_peer_disconnected scans).
 *
 * The reconnect is modeled by re-running syncsvc_collect_needed_blocks() —
 * literally the production decision msg_headers.c makes on the next accepted
 * header batch — against the block_index as it stands post-disruption, then
 * assigning a NEW peer id and driving the remainder to the tip (re-collecting
 * + re-assigning as needed, exactly the steady-state gap_fill/block_sync_
 * service tick). Every collect pass, and the download manager's own in-
 * flight table, are checked for a height <= persisted_at_disruption ever
 * reappearing — that is duplicate_persisted_requests, and it must be 0 for
 * out->recovered to be true.
 *
 * out->base.ok is false only for a harness-fixture defect (OOM, an
 * assignment the manager unexpectedly refused, chain_len < 8) — check
 * out->base.recovered for the actual property: final_height == chain_len
 * AND duplicate_persisted_requests == 0. This fault never touches the
 * blocker/condition/event escalation surface (a stalled body fetch is
 * body_fetch_missing_have_data's typed blocker, not an operator page), so
 * out->base.operator_paged is always false when out->base.ok is true. */
bool chaos_fault_peer_disconnect_mid_body_download(
    int32_t chain_len, struct body_download_resume_result *out);

/* ══════════════════════════════════════════════════════════════════════
 * (n)-(p): the durability/vanished-state fault trio
 *
 * Same law as (a)-(f): each drives a REAL production entry point as a pure
 * oracle over a throwaway fixture, and reports a proven recovery or a NAMED
 * blocker — never a silent stall.
 * ══════════════════════════════════════════════════════════════════════ */

/* (n) torn progress.kv WAL.
 *
 * Stamps a consistent prefix [0, BASE], forces it into the main db and
 * disables auto-checkpoint, stamps a further [BASE+1, K] suffix that stays
 * resident only in the WAL, then hot-copies db+WAL to a sibling dir and
 * truncates the copied WAL mid-stream (the frames a kill -9 between commits
 * loses). On reopen of the torn copy, asserts the store recovers clean and H*
 * is a consistent value in [BASE, K] — never above the last commit, never
 * below the checkpointed floor. `recovered` is true iff hstar_after is in
 * [BASE, K] and hstar_before == K. */
bool chaos_fault_torn_progress_wal(struct chaos_fault_result *out);

/* (o) disk-full pause.
 *
 * Seeds a coins set, caps the store at its current page count (PRAGMA
 * max_page_count) so the next coins write returns SQLITE_FULL — SQLite's own
 * disk-full signal — attempts the write, then lifts the cap and re-attempts.
 * `recovered` is true iff the capped write REPORTED failure, the coin count
 * did not shrink across it (no wipe, no partial commit), and the identical
 * write succeeds and grows the set once space returns. */
bool chaos_fault_disk_full_pause(struct chaos_fault_result *out);

/* (p) HAVE_DATA cleared at height H (a vanished persisted body).
 *
 * Seeds validated headers [0, V] and observed bodies [0, HOLE-1] (the row at
 * HOLE absent) with the body_fetch cursor stalled at HOLE. Drives the
 * production body-fetch-gap predicate
 * (stage_repair_body_fetch_missing_have_data_candidate): `recovered` is true
 * iff the gap is NAMED at exactly HOLE, then clears once the body is
 * re-fetched and the cursor advances. */
bool chaos_fault_cleared_have_data_hole(struct chaos_fault_result *out);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_SIM_SIMNET_CHAOS_FAULTS_H */
