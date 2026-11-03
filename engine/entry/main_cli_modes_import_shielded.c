/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The -import-complete-shielded mode (import_complete_shielded_mode and its
 * local helpers). Moved out of engine/entry/main_cli_modes.c unchanged to fit
 * the file-size cap; behaviour is identical. */
#if !defined(ZCL_TESTING) || !defined(ZCL_RPC_COMPOSER_TEST)
#include "main_cli_modes.h"
#include "cli_compare_runtime.h"
#include "main_cli_dispatch.h"
#include "config/boot.h"
#include "config/boot_cold_start.h"     /* -cold-start staged driver */
#include "hotswap/hotswap_module.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "net/file_service.h"
#include "util/thread_registry.h"
#include "util/util.h"
#include "util/hw_profile.h"  /* hw_profile_set_derive_drain_batch (K3 lever) */
#include "util/log_level.h"
#include "util/log_macros.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "util/spawn.h"
#include <sqlite3.h>
#include "json/json.h"
#include "views/wallet_gui.h"
#include "models/database.h"
#include "models/block.h"                 /* db_block_find_by_hash: tip-bind sapling_root */
#include "controllers/agent_controller.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/network_controller.h"
#include "controllers/sync_controller.h"
#include "controllers/snapshot_controller.h"
#include "storage/coins_db.h"
#include "storage/chainstate_legacy_reader.h"
#include "storage/progress_store.h"
#include "services/shielded_history_import_service.h"
#include "services/utxo_recovery_service.h" /* utxo_recovery_copy_chainstate_stable */
#include "jobs/reducer_frontier.h"          /* reducer_frontier_derive_coins_best */
#include "services/block_index_loader.h"    /* block_index_flat_header_at */
#include "jobs/proof_validate_null_hash_rearm.h"
#include "chain/chain.h"                  /* BLOCK_VALID_TRANSACTIONS: connected floor */
#include "chain/chainparams.h"
#include "chain/checkpoints.h"
#include "chain/utxo_snapshot_loader.h"  /* uss_open: post-write checkpoint verify */
#include "coins/utxo_commitment.h"
#include "crypto/sha3.h"
#include "crypto/sha256.h"                /* -bench-crypto-vs-rust: SHA256 */
#include "crypto/blake2b.h"               /* -bench-crypto-vs-rust: BLAKE2b */
#include "crypto/ed25519.h"               /* -bench-crypto-vs-rust: JoinSplit sig verify */
#include "keys/key.h"                     /* -bench-crypto-vs-rust: secp256k1 signing ctx */
#include "keys/pubkey.h"                  /* -bench-crypto-vs-rust: secp256k1 ECDSA verify */
#include "core/uint256.h"
#include "chain/equihash.h"               /* -bench-crypto-verify: PoW verify */
#include "primitives/block.h"
#include "sapling/sapling.h"              /* -bench-crypto-verify: Groth16 verify */
#include "sapling/bls12_381.h"            /* -bench-crypto-vs-rust: BLS12-381 fp_mul + pairing */
#include "sapling/sapling_prover.h"
#include "sapling/params_init.h"
#include "platform/clock.h"               /* clock_now_monotonic_ns (banned: gettimeofday) */
#include "platform/os_proc.h"             /* os_proc_exe_path (banned: raw /proc/self/exe) */
#include "base/utc_tm.h"                  /* zcl_utc_tm: gmtime_s/gmtime_r */
#include "test/verify_bench_fixture.h"    /* baked real (200,9) witness */
#include "services/wallet_backup_service.h"
#include "services/chain_tip_watchdog.h"  /* #8: self-respawn when off-systemd */
#include "util/supervisor_backstop.h"     /* Pillar 7: self-respawn on a frozen
                                            * supervisor sweep, off-systemd */
#include "util/clientversion.h"
#include "util/sd_notify.h"               /* #8: detect NOTIFY_SOCKET */
#include "util/ar_step_readonly.h"
#include "controllers/rpc_client.h"
#include "command/native_command.h"
#include "command/cli_render.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include "base/safe_alloc.h"
#include "platform/socket_compat.h"
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include "config/cli_lane_defaults.h"
#include "config/args.h"                /* print_usage (moved to args.c) */

/* ── -import-complete-shielded=<zclassicd-datadir> mode ─────────────────
 *
 * Owner-gated, copy-prove-gated: import the COMPLETE historical Sprout+Sapling
 * anchor + nullifier set from a zclassicd chainstate into the TARGET datadir's
 * progress.kv, atomically, and flip both activation cursors to 0 — clearing the
 * utxo_apply.anchor_backfill_gap + nullifier_backfill_gap wedge WITHOUT a
 * from-genesis fold (docs/node/shielded-history-importer.md §4).
 *
 * NOT auto-run on any live datadir: this REFUSES the operator's live canonical
 * (~/.zclassic-c23) and mint (~/.zclassic-c23-mint) datadirs by construction;
 * point it at a -datadir=<COPY> (the copy-prove harness flow, §6). The source
 * chainstate is read through the signature-proven point-in-time stable copy
 * (utxo_recovery_copy_chainstate_stable — WAL-inclusive, never the live one);
 * the target header supplies the exact fold-resume block + Sapling root, and
 * the source chainstate best block must equal it. This prevents its unkeyed
 * additive nullifier set from containing future spends. The target must have
 * booted once first so its coins authority and shielded cursors exist.
 *
 * Usage: z23 -datadir=<TARGET-COPY>
 *        -import-complete-shielded=<zclassicd-datadir> */
static bool import_shielded_is_live_datadir(const char *target)
{
    const char *home = getenv("HOME");
    if (!home || !target)
        return false;
    char live[600], mint[600];
    snprintf(live, sizeof(live), "%s/.zclassic-c23", home);
    snprintf(mint, sizeof(mint), "%s/.zclassic-c23-mint", home);
    /* Compare with any single trailing slash normalized away. */
    size_t tl = strlen(target);
    while (tl > 1 && target[tl - 1] == '/') tl--;
    return (strlen(live) == tl && strncmp(target, live, tl) == 0) ||
           (strlen(mint) == tl && strncmp(target, mint, tl) == 0);
}

/* Write $HOME/.zclassic-c23 into target ('.' when HOME is unset). Returns 2 when it does not fit. */
static int import_shielded_default_target(char *target, size_t target_cap)
{
    target[0] = '\0';
    const char *home = getenv("HOME");
    int tn = snprintf(target, target_cap, "%s/.zclassic-c23",
                       home ? home : ".");
    if (tn < 0 || (size_t)tn >= target_cap) {
        fprintf(stderr,
                "-import-complete-shielded: $HOME is too long for the "
                "%zu-byte target datadir buffer — refusing (no silent "
                "truncation); pass -datadir=<short path> explicitly\n",
                target_cap);
        return 2;
    }
    return 0;
}

/* Record -import-complete-shielded= and an optional -datadir= override. Returns 2 on a datadir overflow or a missing source. */
static int import_shielded_parse_invocation(int argc, char **argv,
                                           const char **src_out,
                                           char *target, size_t target_cap)
{
    *src_out = NULL;
    const char *src = NULL;
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-import-complete-shielded=", 26) == 0) {
            src = argv[i] + 26;
        } else if (strncmp(argv[i], "-datadir=", 9) == 0) {
            int n = snprintf(target, target_cap, "%s", argv[i] + 9);
            if (n < 0 || (size_t)n >= target_cap) {
                fprintf(stderr,
                        "-datadir=<...> exceeds the %zu-byte path buffer — "
                        "refusing (no silent truncation)\n", target_cap);
                return 2;
            }
        }
    }
    if (!src || !src[0]) {
        fprintf(stderr,
                "usage: %s -datadir=<TARGET-COPY> "
                "-import-complete-shielded=<zclassicd-datadir>\n", argv[0]);
        return 2;
    }
    *src_out = src;
    return 0;
}

/* Copy the source chainstate to a LOCK-free snapshot under target. Returns 1 on failure. */
static int import_shielded_snapshot_chainstate(const char *src,
                                              const char *target,
                                              char *snap_path, size_t snap_cap)
{
    snap_path[0] = '\0';
    /* Point-in-time snapshot of the source chainstate (never read the live
     * LevelDB directly). MUST be the full WAL-inclusive stable copy — NOT
     * ldb_snapshot_make, which copies only the compacted .ldb SSTs + metadata
     * and drops the .log WAL, so on a live daemon the 'B' best-block / 'z'
     * best-anchor pointers lag every recent record. Uses the same
     * signature-proven point-in-time helper as the legacy UTXO import and the
     * tier1b frontier borrow. */
    char cs_src[700];
    int csn = snprintf(cs_src, sizeof(cs_src), "%s/chainstate", src);
    if (csn < 0 || (size_t)csn >= sizeof(cs_src)) {
        fprintf(stderr,
                "-import-complete-shielded=<path> exceeds the %zu-byte "
                "chainstate path buffer — refusing (no silent truncation)\n",
                sizeof(cs_src));
        return 1;
    }
    struct stat st;
    if (stat(cs_src, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "missing chainstate at %s\n", cs_src);
        return 1;
    }
    int spn = snprintf(snap_path, snap_cap,
                       "%s/shielded_import_cs_snap", target);
    if (spn < 0 || (size_t)spn >= snap_cap) {
        fprintf(stderr,
                "-datadir=<...> exceeds the %zu-byte snapshot path buffer — "
                "refusing (no silent truncation)\n", snap_cap);
        return 1;
    }
    {
        struct zcl_result cpres =
            utxo_recovery_copy_chainstate_stable(cs_src, snap_path);
        if (!cpres.ok) {
            fprintf(stderr, "chainstate snapshot failed: %s\n", cpres.message);
            return 1;
        }
    }
    /* Remove the copied LOCK so the reader can open the snapshot. */
    {
        char tmp_lock[1300];
        snprintf(tmp_lock, sizeof(tmp_lock), "%s/LOCK", snap_path);
        unlink(tmp_lock);
    }
    printf("Chainstate snapshot: %s\n", snap_path);
    return 0;
}

/* Open progress.kv and write the fold-resume height. Returns 1 on failure; the store stays open only on success. */
static int import_shielded_read_resume_anchor(const char *target,
                                             const char *snap_path,
                                             int64_t *tip_height)
{
    *tip_height = 0;
    /* Select the bind anchor from the TARGET's progress.kv. The anchor is the
     * durable seed floor when one is declared (a node that folded PAST its
     * seed already carries roots above the floor in its own anchor table),
     * else the live coins island root. The exact target header at that height
     * is read below and MUST match the source's persisted 'B' best block; a
     * live source that flushed past the resume point is therefore refused.
     * This requires the target to have booted once and landed its UTXO seed,
     * which also initializes the shielded cursors shi_read_boundaries needs. */
    if (!progress_store_open(target)) {
        (void)zcl_tree_remove(snap_path);
        fprintf(stderr, "cannot open progress.kv in %s\n", target);
        return 1;
    }
    int32_t seed_floor = -1;
    bool floor_found = false;
    if (!reducer_seed_floor_height_read(progress_store_db(), &seed_floor,
                                        &floor_found)) {
        progress_store_close();
        (void)zcl_tree_remove(snap_path);
        fprintf(stderr, "cannot read the target's seed floor from "
                        "progress.kv (read error)\n");
        return 1;
    }
    int32_t coins_best = -1;
    uint8_t cb_hash[32];
    bool cb_hash_found = false, cb_found = false;
    if (!reducer_frontier_derive_coins_best(progress_store_db(), &coins_best,
                                            cb_hash, &cb_hash_found,
                                            &cb_found)) {
        progress_store_close();
        (void)zcl_tree_remove(snap_path);
        fprintf(stderr, "cannot derive the target's fold-resume anchor from "
                        "progress.kv (read error)\n");
        return 1;
    }
    if (!floor_found && (!cb_found || coins_best < 0)) {
        progress_store_close();
        (void)zcl_tree_remove(snap_path);
        fprintf(stderr,
                "target datadir has no coins authority yet — boot it once, "
                "let the UTXO seed land, then re-run this import (the "
                "shielded history cursors are also only initialized by that "
                "first boot). Nothing committed.\n");
        return 1;
    }
    *tip_height =
        floor_found ? (int64_t)seed_floor : (int64_t)coins_best;
    return 0;
}

/* Read the fold-resume header's Sapling root and print the tip bind. Returns 1 when the root is all-zero. */
static int import_shielded_read_tip_root(const char *target,
                                        const char *snap_path,
                                        int64_t tip_height,
                                        struct uint256 *tip_block_hash,
                                        struct uint256 *tip_sapling_root)
{
    uint256_set_null(tip_block_hash);
    uint256_set_null(tip_sapling_root);
    /* The chain-committed hashFinalSaplingRoot at the resume anchor comes
     * from the target's own HEADER INDEX flat file (block_index.bin):
     * accept_block_header copies the wire hashFinalSaplingRoot into every
     * persisted index entry (core/modules/validation/src/accept_block_header.c) and
     * the height-sorted flat persists it for EVERY header — including the
     * header-only heights a seeded boot's fold-resume anchor sits at. The
     * node.db blocks.sapling_root column is NOT a valid source (blocks rows
     * are only written on body fold / lean sync / block import — canary
     * FAIL#6), and neither is the event-log block_index projection (a bulk
     * P2P header sync emits no EV_BLOCK_HEADER events — the projection is
     * EMPTY on a fresh cold-import datadir, canary FAIL#7). The reader
     * mmaps the flat, verifies the embedded integrity commitment, and
     * binary-searches the height-sorted rows; a stale-branch sibling at the
     * same height fails CLOSED at the service's by-root source lookup,
     * never a misbind. The flat is freshened by the node's graceful
     * shutdown save, so this read REQUIRES the clean stop the canary /
     * operator flow performs before invoking the verb. */
    {
        struct zcl_result fr = block_index_flat_header_at(
            target, (int32_t)tip_height, tip_block_hash->data,
            tip_sapling_root->data);
        if (!fr.ok) {
            fprintf(stderr, "tip bind root read: %s\n", fr.message);
        }
    }
    if (uint256_is_null(tip_sapling_root)) {
        progress_store_close();
        (void)zcl_tree_remove(snap_path);
        fprintf(stderr,
                "tip bind SOURCE is all-zero: the header index has no "
                "hashFinalSaplingRoot for the fold-resume anchor "
                "(height=%lld) — the node must be stopped GRACEFULLY first "
                "(the shutdown flat save is what freshens block_index.bin "
                "past the header-sync tip), or this header chain was "
                "persisted by a build that did not carry the header's "
                "hashFinalSaplingRoot. Refusing rather than binding the "
                "tip frontier against zeros.\n",
                (long long)tip_height);
        return 1;
    }
    char root_hex[65];
    uint256_get_hex(tip_sapling_root, root_hex);
    printf("Tip bind: height=%lld hashFinalSaplingRoot=%s "
           "(target fold-resume anchor)\n", (long long)tip_height, root_hex);
    return 0;
}

/* Run the bind-height probe. Returns 1 when the probe fails, after closing progress.kv and removing the snapshot. */
static int import_shielded_bind_height_guard(const char *snap_path,
                                            int64_t tip_height)
{
    /* Bind-height guard, surfaced on the TERMINAL (the service re-enforces the
     * same predicate internally before its transaction): refuse to manufacture
     * a height-mismatched datadir. tip_height above IS the target's fold-
     * resume anchor by construction, so this probe is defense-in-depth — it
     * catches a caller that bypasses the verb with a foreign height, and any
     * drift of the target's coins authority between the two derives. Nothing
     * is committed on this path (the import transaction never begins). */
    int32_t bind_coins_best = -1;
    if (!shielded_history_import_bind_guard_probe(progress_store_db(),
                                                  tip_height,
                                                  &bind_coins_best)) {
        progress_store_close();
        (void)zcl_tree_remove(snap_path);
        if (bind_coins_best >= 0) {
            fprintf(stderr,
                    "IMPORT REFUSED — bind height mismatch: the requested "
                    "bind h=%lld does not match the target datadir's "
                    "fold-resume anchor (coins island root) h=%lld. Binding "
                    "the shielded frontier there manufactures a datadir "
                    "whose fold wedges deterministically at the first "
                    "Sapling-commitment block above the island "
                    "(hashFinalSaplingRoot mismatch, H* pinned). Nothing "
                    "committed; the wedge is intact.\n",
                    (long long)tip_height, (long long)bind_coins_best);
        } else {
            fprintf(stderr,
                    "IMPORT REFUSED — cannot derive the target datadir's "
                    "fold-resume anchor from progress.kv (read error). See "
                    "node.log [shielded_import]; nothing committed.\n");
        }
        return 1;
    }
    return 0;
}

/* Best-effort register of the cured coins tip as a cold-import trust anchor. */
static void import_shielded_persist_cured_tip(const char *target)
{
    /* On success, register the cured coins tip as a cold-import TRUST anchor so
     * the next normal boot's Invariant A gate installs it into the active chain
     * (instead of refusing the detached island and stalling getheaders at
     * genesis). Durable node_db seed + in-memory; best-effort — a derive miss
     * logs but never undoes the committed import. progress_store stays open so
     * the coins-best derivation + the durable count token read the canonical
     * store. */
    char ndb_path[600];
    int nn = snprintf(ndb_path, sizeof(ndb_path), "%s/node.db", target);
    struct node_db ndb2;
    if (nn > 0 && (size_t)nn < sizeof(ndb_path) &&
        node_db_open(&ndb2, ndb_path)) {
        (void)shielded_history_import_register_cured_tip_trust_anchor(
            progress_store_db(), &ndb2);
        node_db_close(&ndb2);
    } else {
        fprintf(stderr,
                "WARNING: import committed but could not reopen %s to "
                "persist the cured-tip trust anchor; the coins tip may need "
                "one extra boot to install into the active chain.\n",
                ndb_path);
    }
}

/* Re-arm proof_validate over NULL-block_hash rows and report a rewind, refusal, or error. */
static void import_shielded_rearm_proof_validate(void)
{
    /* Re-arm proof_validate over any NULL-block_hash suffix so the post-cure
     * fold is not wedged at utxo_apply's label_splice guard (which refuses a
     * hashless proof verdict). The rewind FLOOR is utxo_apply's own cursor
     * (never rewinds an already-applied height). A rewind beyond the recovery
     * block-rollback cap (default 100) is REFUSED; raise ZCL_MAX_BLOCK_ROLLBACK
     * past the reported depth after a copy proof. progress_store is still open
     * here. */
    struct proof_validate_rearm_report rr;
    memset(&rr, 0, sizeof(rr));
    enum proof_validate_rearm_outcome ro =
        proof_validate_null_hash_rearm(progress_store_db(), NULL, &rr);
    if (ro == PV_REARM_REARMED) {
        printf("proof_validate re-arm: rewound cursor %llu->%llu, deleted "
               "%lld NULL-block_hash rows; the next boot re-derives them.\n",
               (unsigned long long)rr.pv_cursor_before,
               (unsigned long long)rr.rewound_to, (long long)rr.deleted_rows);
    } else if (ro == PV_REARM_REFUSED) {
        fprintf(stderr,
                "WARNING: proof_validate re-arm REFUSED — rewinding to h=%d "
                "(%lld NULL-block_hash rows) exceeds the recovery "
                "block-rollback cap. Raise ZCL_MAX_BLOCK_ROLLBACK past it "
                "and re-run, else the post-cure fold wedges at utxo_apply.\n",
                rr.lowest_null_height, (long long)rr.null_row_count);
    } else if (ro == PV_REARM_ERROR) {
        fprintf(stderr, "WARNING: proof_validate re-arm ERROR — see "
                        "node.log [proof_validate]; the fold may wedge.\n");
    }
    /* PV_REARM_NOT_NEEDED: the fold above utxo_apply is already
     * hash-complete — nothing to do. */
}

int import_complete_shielded_mode(int argc, char **argv)
{
    /* UX: glibc block-buffers stdout when it isn't a tty (the common case
     * for a redirected/logged import run), so every printf() below would
     * sit in the buffer until process exit. For a run that goes CPU-bound
     * inside shielded_history_import_from_chainstate() for many minutes,
     * that means the operator watches a blank terminal with no way to
     * tell "running" from "stuck" — a silent stall, which the node's
     * prime invariant forbids. Force line buffering up front so every
     * banner below (Source/Target/Chainstate snapshot/Tip bind/
     * IMPORT COMPLETE|REFUSED) lands on the terminal/log the instant it's
     * printed. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    const char *src = NULL;
    char target[512];
    if (import_shielded_default_target(target, sizeof(target)) != 0)
        return 2;
    if (import_shielded_parse_invocation(argc, argv, &src, target,
                                        sizeof(target)) != 0)
        return 2;

    printf("=== ZClassic Complete Shielded-History Import ===\n");
    printf("Source chainstate: %s/chainstate\n", src);
    printf("Target datadir:    %s\n", target);

    /* Containment: NEVER write shielded history into a live datadir. The cure
     * is copy-proven on a COPY first (see §6); the operator points -datadir at
     * the copy, then cuts over by re-running against canonical after a green
     * copy-prove. This mode itself refuses the two known live paths. */
    if (import_shielded_is_live_datadir(target)) {
        fprintf(stderr,
                "REFUSING: %s is a live datadir. Copy-prove on a COPY first "
                "(cp -a the datadir + chainstate, run this against the copy, "
                "gate on H* climb + tip-hash parity vs zclassicd), then cut "
                "over. See docs/node/shielded-history-importer.md §6.\n",
                target);
        return 1;
    }

    char snap_path[900];
    if (import_shielded_snapshot_chainstate(src, target, snap_path,
                                           sizeof(snap_path)) != 0)
        return 1;

    int64_t tip_height = 0;
    if (import_shielded_read_resume_anchor(target, snap_path, &tip_height) != 0)
        return 1;

    struct uint256 tip_block_hash, tip_sapling_root;
    if (import_shielded_read_tip_root(target, snap_path, tip_height,
                                     &tip_block_hash, &tip_sapling_root) != 0)
        return 1;

    if (import_shielded_bind_height_guard(snap_path, tip_height) != 0)
        return 1;

    struct shielded_import_report rep = {0};
    bool ok = shielded_history_import_from_chainstate(
        progress_store_db(), snap_path, tip_height, &tip_block_hash,
        &tip_sapling_root, &rep);

    if (ok)
        import_shielded_persist_cured_tip(target);
    if (ok)
        import_shielded_rearm_proof_validate();

    progress_store_close();
    (void)zcl_tree_remove(snap_path);

    if (!ok) {
        fprintf(stderr,
                "IMPORT REFUSED — nothing committed, wedge intact (both "
                "activation cursors stay POSITIVE, gap blockers remain). See "
                "node.log [shielded_import] for the exact anomaly.\n");
        return 1;
    }
    printf("IMPORT COMPLETE (committed=%d): sapling_anchors=%lld "
           "sprout_anchors=%lld sapling_nf=%lld sprout_nf=%lld\n"
           "Both activation cursors flipped to 0; the reducer resumes folding "
           "from %lld. Copy-prove H* climb + tip-hash parity vs zclassicd "
           "before cutover.\n",
           rep.committed, (long long)rep.sapling_anchors,
           (long long)rep.sprout_anchors, (long long)rep.sapling_nullifiers,
           (long long)rep.sprout_nullifiers, (long long)tip_height + 1);
    return 0;
}
#endif /* ZCL_RPC_COMPOSER_TEST */
