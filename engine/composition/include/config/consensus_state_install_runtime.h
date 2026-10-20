/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * consensus_state_install_runtime — the NON-TERMINAL core of the sovereign
 * consensus-state install, factored out of the -install-consensus-bundle
 * terminal verb (engine/composition/src/boot_install_consensus_bundle.c) so it can be
 * driven from inside a live boot WITHOUT _exit()ing. The terminal verb is now a
 * thin wrapper around consensus_state_install_from_bundle().
 *
 * Two boot wirings live here:
 *   1b. Zero-flag cold-boot autodetect: on a normal boot with an empty/fresh
 *       datadir, a complete-state bundle under <datadir>/bundles/<name>.sqlite is
 *       installed via the SAME atomic installer BEFORE the transparent-only
 *       from-anchor path (which would leave shielded state empty → the
 *       anchor_backfill_gap wedge).
 *   1c. A durable "install-on-next-boot" request, modeled EXACTLY on the proven
 *       boot_auto_refold_* self-respawn pattern: a bounded, fsync-durable
 *       request that boot consumes and runs through the same installer, then
 *       clears. The shielded-gap self-heal arms it; that self-heal is
 *       not wired here.
 *
 * Every install still routes through consensus_state_snapshot_install_activate
 * (atomic + rollback point); this module adds no new state writer. Fail-closed
 * everywhere: an absent/failed request or bundle leaves boot on its unchanged
 * path, and a durable marker prevents re-installing over sovereign state.
 */

#ifndef ZCL_CONFIG_CONSENSUS_STATE_INSTALL_RUNTIME_H
#define ZCL_CONFIG_CONSENSUS_STATE_INSTALL_RUNTIME_H

#include "config/consensus_state_snapshot_install.h" /* enum consensus_state_install_status */
#include "util/result.h"                             /* struct zcl_result */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct main_state;
struct app_context;

/* Outcome detail for a runtime install. `status` mirrors the terminal verb's
 * activate status. `state_installed` is true once the atomic activate committed
 * the swap (coins/anchors/nullifiers) even if a later best-effort/verify step
 * failed — a landed-but-post-failed install is NOT "not installed" and must
 * never be treated as license to fall through to a transparent-only wipe. */
struct consensus_state_install_runtime_result {
    enum consensus_state_install_status status;
    bool     state_installed; /* the atomic activate committed the swap */
    bool     marker_written;  /* the durable sovereign-install marker was written */
    /* RETRIABLE WAIT, not a rejection: a compiled-checkpoint bundle refused ONLY
     * because this node's validated header chain has not yet reached the
     * checkpoint height (the fresh-boot / mid-header-sync case). The bundle is
     * good — the node simply has not caught up — so the boot seam must NOT
     * permanently .fail it; a later attempt (this session's retry condition OR a
     * future boot) installs it once the checkpoint header arrives on-chain. A
     * genuine byte-mismatch / bad-content refusal leaves this false (→ .fail). */
    bool     retriable_headers_not_ready;
    /* The canonical-lane owner gate refused because the datadir holds chain
     * state and the owner did not authorize the cutover. A verdict on the
     * datadir, not the bundle: the boot seam must not .fail the bundle. */
    bool     owner_gate_refused;
    int32_t  height;          /* installed bundle height (−1 until known) */
    int32_t  hstar;           /* durable H* after install (−1 until known) */
    /* Must retain activate's complete operator-facing success detail,
     * including its independently usable prior-generation path. */
    char     reason[CONSENSUS_STATE_ACTIVATE_REASON_MAX];
};

struct consensus_state_install_recovery_result {
    bool recovered;
    bool advanced;
    int32_t height;
};

/* Before snapshot import or derived-state loading, finish the post-commit
 * tail of an interrupted install. Never activates a bundle or changes coins,
 * trust provenance, generation, or reducer cursors. Missing generation
 * evidence or contradictory identity refuses before any repair. */
struct zcl_result consensus_state_install_recover_committed(
    struct node_db *ndb, const char *datadir,
    struct consensus_state_install_recovery_result *out);

/* True iff this node's validated header chain genuinely OWNS the compiled SHA3
 * UTXO checkpoint block: the header frontier (ms->pindex_best_header) is at or
 * above the checkpoint height AND the header-chain ancestor at the checkpoint
 * height carries exactly the compiled checkpoint block hash. This is the exact
 * precondition the compiled-checkpoint chain-binding gate (-4 header-bootstrap,
 * Gap B/C) needs before a checkpoint bundle can bind — used both to DEFER a
 * premature boot-time install (fail-open wait, not a rejection) and to arm the
 * retry only once the header chain has actually reached the checkpoint. Pure,
 * read-only, no locks taken; false on any NULL / absent / mismatched input. */
bool consensus_state_checkpoint_header_ready(struct main_state *ms);

/* Restore the checkpoint header frontier after a fresh-genesis state reset.
 * The header must already exist in the imported block map and pass the frozen
 * full-header validator before the CSR can publish it. This changes only the
 * header view; it neither seeds state nor moves the served/coins tip. */
bool consensus_state_install_restore_checkpoint_header_frontier(
    struct main_state *ms);

/* NON-TERMINAL install core. Runs the identical fail-closed pipeline as the
 * -install-consensus-bundle verb (containment classify → admit+validate →
 * producer source receipt → publication CAS with the compiled SHA3 +
 * CHECKPOINT_ROM authority → reload durable ADMIT → atomic activate →
 * derived-state invalidation → utxos mirror reset → durable marker) but RETURNS
 * a result instead of _exit()ing. `out` is always populated (reason set on
 * every refusal); pass NULL only if the detail is unwanted. Returns ok iff the
 * state landed AND post-install reconciliation and marker persistence succeeded.
 * A post-commit failure retains state_installed and is recoverable at boot
 * without another activation. */
struct zcl_result consensus_state_install_from_bundle(
    struct node_db *ndb, struct main_state *ms, const char *bundle_path,
    const char *datadir, struct consensus_state_install_runtime_result *out);

/* Zero-flag cold-boot orchestrator (Move 1b + 1c). Consults, in order:
 *   (1) the durable install-on-next-boot request (the Move 2 self-heal), then
 *   (2) an autodetected <datadir>/bundles/<name>.sqlite bundle,
 * and installs the first present UNLESS the sovereign-install marker already
 * exists (never re-install over already-sovereign state). Returns true iff a
 * bundle was FULLY installed this boot — the caller then suppresses the
 * transparent-only from-anchor path (a complete install supersedes it). After
 * a successful install, borrowed HAVE_DATA claims whose blk files are absent
 * on this node are dropped via boot_post_install_drop_borrowed_have_data()
 * (trust_existing_block_files has the same meaning as in the
 * -load-snapshot-at-own-height gate: pass !ctx->no_legacy_auto_import). When a
 * successful install leaves a body gap in the (installed_height, header_tip]
 * fold span, the named blocker refold.body_gap is raised via
 * boot_refold_body_span_contiguous() so the reducer's body-fetch fills it
 * rather than the fold silently stalling. Fail-closed: no request/bundle, or one
 * that fails the authority, returns false and boot proceeds unchanged. */
bool boot_maybe_auto_install_consensus_bundle(struct node_db *ndb,
                                              struct main_state *ms,
                                              const char *datadir,
                                              bool trust_existing_block_files);

/* Autodetect a complete-state bundle under <datadir>/bundles/. Returns a
 * malloc'd absolute path (caller free()s) to the chosen *.sqlite, or NULL when:
 * the sovereign-install marker is already present (never re-install), there is
 * no bundles/ directory, no *.sqlite candidate, or every candidate carries a
 * sibling <name>.failed marker (never-stuck: a prior failed install degrades to
 * a normal boot). With several candidates the lexicographically-greatest name
 * wins (stable, deterministic). Pure discovery — installs nothing. */
char *boot_autodetect_consensus_bundle(const char *datadir);

/* The (height, block_hash) a STAGED bundle's install waits on. For a bundle whose
 * canonical name carries a height with a BAKED commitment (the keystone or a
 * ladder rung, get_baked_rom_state_checkpoint_at_height), that commitment's
 * height + block hash; otherwise the compiled SHA3 checkpoint (the keystone),
 * exactly the pre-ladder behavior. This only decides what to WAIT on (header
 * ownership, checkpoint-header solution); trust still binds at install against
 * the full baked commitment. Returns false when neither exists. */
bool boot_staged_bundle_wait_target(const char *bundle_path, int32_t *height,
                                    uint8_t block_hash[32]);

/* True iff this node's validated header chain has reached `height` and the block
 * there carries `block_hash`. Read-only. */
bool consensus_state_header_chain_owns(struct main_state *ms, int32_t height,
                                       const uint8_t block_hash[32]);

/* Post-install fold-span gate — the call-site wiring around
 * boot_refold_body_span_contiguous() (impl in engine/composition/src/boot_refold_staged.c,
 * contract in config/boot.h), reused here (impl in engine/composition/src/
 * boot_auto_install_bundle.c) after a successful complete-state install (1b/
 * 1c above). When the local header chain already extends above the installed
 * checkpoint height — the Move 2 self-heal case on an already-synced node —
 * every body in (installed_height, local_tip] must already be on disk before
 * the reducer folds over it. On a gap this raises the named blocker
 * refold.body_gap at the first missing height so the reducer's body_fetch
 * stage (primed to resume at installed_height+1 by the forced stage cursors
 * in consensus_state_snapshot_install_activate) fills it. A no-op when the
 * local chain has not advanced past installed_height, or when ms is NULL or
 * installed_height < 0. Never fails the boot — a detected gap only logs and
 * raises the blocker. */
void boot_post_install_fold_span_check(struct main_state *ms,
                                       int32_t installed_height);

/* Post-install borrowed-have-data drop — the call-site wiring around
 * boot_snapshot_drop_bodiless_have_data_above_seed() (impl in
 * engine/composition/src/boot_refold_staged.c, contract in config/boot.h),
 * reused here (impl in engine/composition/src/boot_auto_install_bundle.c)
 * after a successful complete-state install (1b/1c above). The block index
 * loaded from <datadir>/block_index.bin can carry the bundle publisher's
 * HAVE_DATA + (nFile, nDataPos) for bodies this node never wrote, which
 * have-data-gated walkers (pv_lookahead, the have-data window extender,
 * catchup) would read against absent blk files. Drops each claim whose blk
 * file is absent/unreadable, post-install and before the staged pipeline
 * starts (as the -load-snapshot-at-own-height gate does), then retracts the
 * active-chain tip to
 * installed_height so P2P fills the gap bottom-up. trust_existing_block_files
 * selects the cheap stat() keep (a legacy-import datadir's own blk files) vs
 * the strict read-back-and-hash-bind keep. Returns the number of dropped
 * claims; a safe no-op (0) when ms/datadir are NULL or installed_height < 0. */
size_t boot_post_install_drop_borrowed_have_data(
    struct main_state *ms, const char *datadir, int32_t installed_height,
    bool trust_existing_block_files);

/* Clear a stale "<bundle_path>.failed" never-stuck marker after that bundle
 * installed successfully (wired at both install success branches in
 * engine/composition/src/boot_auto_install_bundle.c). Otherwise the marker
 * keeps boot_autodetect_consensus_bundle skipping the now-good bundle.
 * Best-effort: a remove() failure is logged, never fatal; a missing marker
 * (ENOENT) is a silent no-op. Exposed as its own entry point so the wiring
 * is directly unit-testable without a full bundle install. */
void boot_auto_install_clear_failed_marker(const char *bundle_path);

/* ── Durable "install-on-next-boot" request (mirror of boot_auto_refold_*) ──
 * Top-level sentinel <datadir>/install_bundle_request holding
 * "<attempts>\n<bundle_path>\n", NEVER part of any derived-state wipe set.
 * Bounded per request so a persistently-failing bundle PAGES rather than
 * crash-loops; the attempt count increments at CONSUME (boot) time so a FATAL
 * mid-install still burns the budget. fsync-durable. */
#define BOOT_INSTALL_BUNDLE_MAX 3
#define BOOT_INSTALL_BUNDLE_TERMINAL (-1)

/* Arm a request to install `bundle_path` on the next boot. Idempotent while
 * pending (attempts only bump at consume). A TERMINAL marker is a no-op that
 * returns BOOT_INSTALL_BUNDLE_TERMINAL so an exhausted budget is not re-armed.
 * Returns 1 when freshly armed, the current attempt count when already pending,
 * BOOT_INSTALL_BUNDLE_TERMINAL if terminal, or 0 on a write/validation error
 * (empty datadir/path, an embedded newline, or an I/O failure). */
int boot_install_bundle_request(const char *datadir, const char *bundle_path);

/* True iff a request is on disk AND is not the terminal marker. */
bool boot_install_bundle_pending(const char *datadir);

/* Boot-time consume: read the request, and if an install should run THIS boot,
 * copy the bundle path into out_path (out_cap bytes), increment the attempt
 * count (fsync-durable), and return true. Returns false — and rewrites the
 * marker TERMINAL — when the bounded budget is spent (attempts >=
 * BOOT_INSTALL_BUNDLE_MAX). Absent/terminal/malformed request → false, and
 * out_path is set empty. */
bool boot_install_bundle_consume(const char *datadir, char *out_path,
                                 size_t out_cap);

/* Clear the request once a boot consumed it and the install committed. Budget
 * exhaustion does NOT clear (consume rewrites TERMINAL). Idempotent. */
void boot_install_bundle_clear(const char *datadir);

/* ── Boot state-source selection (the app_init seam) ────────────────────────
 * One helper composing the three booleans app_init needs to pick its state
 * source, so that logic lives here rather than bloating app_init:
 *   auto_installed_bundle — a complete-state bundle was installed THIS boot (1b/
 *                           1c) and SUPERSEDES the transparent-only from-anchor
 *                           reset;
 *   consumed_auto_refold  — the sticky escalator's armed refold was consumed
 *                           (A1), bumping its bounded attempt budget;
 *   do_from_anchor        — run the transparent-only from-anchor cutover this
 *                           boot (suppressed whenever a complete install fired).
 */
struct boot_state_source_selection {
    bool auto_installed_bundle;
    bool consumed_auto_refold;
    bool do_from_anchor;
};

void boot_select_state_source(struct node_db *ndb, struct main_state *ms,
                              struct app_context *ctx,
                              struct boot_state_source_selection *out);

#endif /* ZCL_CONFIG_CONSENSUS_STATE_INSTALL_RUNTIME_H */
