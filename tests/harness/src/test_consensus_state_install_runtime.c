/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_consensus_state_install_runtime: boot wiring of the sovereign
 * consensus-state install (engine/composition/src/
 * consensus_state_install_runtime.c).
 *
 *   (a) boot_autodetect_consensus_bundle picks the lexicographically greatest
 *       <datadir>/bundles/<name>.sqlite; skips when absent, when the
 *       sovereign-install marker is set, or when <name>.failed exists.
 *   (b) consensus_state_install_from_bundle returns a typed result (no
 *       _exit()); a bogus path fails closed with state_installed=false.
 *   (c) the install-on-next-boot request round-trips (arm, pending, consume,
 *       clear); the budget goes TERMINAL after BOOT_INSTALL_BUNDLE_MAX
 *       attempts and is never re-armed.
 *   (d) boot_post_install_fold_span_check: no local advance past
 *       installed_height, or a gapless one, is a no-op; a body gap raises
 *       refold.body_gap at the first missing height; ms==NULL / negative
 *       installed_height are safe no-ops.
 *   (d2) boot_post_install_drop_borrowed_have_data floors non-seed HAVE_DATA
 *       claims to header-only, protects the seed block, retracts the active
 *       tip to the installed height; NULL/negative guards are no-ops.
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "coins/coins_view.h"
#include "conditions/checkpoint_bundle_install_ready.h"
#include "conditions/checkpoint_header_solution_repair.h"
#include "config/boot.h"
#include "config/boot_consensus_bundle_marker.h"
#include "config/consensus_state_install_runtime.h"
#include "core/uint256.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/validate_headers_stage.h"
#include "services/chain_state_service.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "util/rpc_paths.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <limits.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CSIR_CHECK(desc, cond)                                               \
    do {                                                                     \
        printf("consensus_state_install_runtime: %s... ", (desc));           \
        if (cond) printf("OK\n");                                            \
        else { printf("FAIL\n"); failures++; }                              \
    } while (0)

void validate_headers_ensure_set_validator_for_test(vh_validator_fn fn,
                                                     void *user);

static bool csir_header_pass(const struct block_index *bi,
                             const char *datadir, char *reason,
                             size_t reason_size, void *user)
{
    (void)bi;
    (void)datadir;
    (void)reason;
    (void)reason_size;
    (void)user;
    return true;
}

/* Best-effort touch of an empty file at <dir>/<name>. */
static bool csir_touch(const char *dir, const char *name)
{
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    fclose(f);
    return true;
}

/* (a) Autodetect discovery + gating. */
static int case_autodetect(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "csir_autodetect", "ok");

    /* No bundles/ directory at all → NULL. */
    char *p = boot_autodetect_consensus_bundle(dir);
    CSIR_CHECK("no bundles/ dir -> NULL", p == NULL);
    free(p);

    /* Empty bundles/ dir (no *.sqlite) → NULL. */
    char bundles[320];
    snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
    CSIR_CHECK("mkdir bundles/", mkdir(bundles, 0700) == 0);
    p = boot_autodetect_consensus_bundle(dir);
    CSIR_CHECK("empty bundles/ -> NULL", p == NULL);
    free(p);

    /* A non-.sqlite file is ignored. */
    CSIR_CHECK("touch bundles/readme.txt", csir_touch(bundles, "readme.txt"));
    p = boot_autodetect_consensus_bundle(dir);
    CSIR_CHECK("only non-sqlite -> NULL", p == NULL);
    free(p);

    /* One *.sqlite present → chosen, absolute path ends in that name. */
    CSIR_CHECK("touch bundles/a-100.sqlite", csir_touch(bundles, "a-100.sqlite"));
    p = boot_autodetect_consensus_bundle(dir);
    CSIR_CHECK("one *.sqlite -> chosen",
               p != NULL &&
                   strcmp(p + strlen(p) - strlen("/bundles/a-100.sqlite"),
                          "/bundles/a-100.sqlite") == 0);
    free(p);

    /* A lexicographically-greater candidate wins (stable, deterministic). */
    CSIR_CHECK("touch bundles/z-200.sqlite", csir_touch(bundles, "z-200.sqlite"));
    p = boot_autodetect_consensus_bundle(dir);
    CSIR_CHECK("greatest name wins (z-200)",
               p != NULL && strlen(p) >= strlen("z-200.sqlite") &&
                   strcmp(p + strlen(p) - strlen("z-200.sqlite"),
                          "z-200.sqlite") == 0);
    free(p);

    /* A sibling .failed marker on the winner skips it → falls back to the other. */
    CSIR_CHECK("touch bundles/z-200.sqlite.failed",
               csir_touch(bundles, "z-200.sqlite.failed"));
    p = boot_autodetect_consensus_bundle(dir);
    CSIR_CHECK("failed winner skipped -> a-100 chosen",
               p != NULL &&
                   strcmp(p + strlen(p) - strlen("a-100.sqlite"),
                          "a-100.sqlite") == 0);
    free(p);

    /* The sovereign-install marker present → never re-install (NULL even with a
     * live bundle present). */
    uint8_t digest[32];
    memset(digest, 0x5a, sizeof(digest));
    CSIR_CHECK("write sovereign-install marker",
               boot_consensus_bundle_marker_write(dir, 100, digest));
    p = boot_autodetect_consensus_bundle(dir);
    CSIR_CHECK("marker set -> NULL (never re-install)", p == NULL);
    free(p);

    test_rm_rf_recursive(dir);
    return failures;
}

/* (a2) A stale .failed marker cleared via the install-success wiring makes
 * the bundle detectable again, so autodetect does not skip a good bundle on
 * every later scan. */
static int case_failed_marker_cleared_on_success(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "csir_clear_failed", "ok");

    char bundles[320];
    snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
    CSIR_CHECK("mkdir bundles/", mkdir(bundles, 0700) == 0);
    CSIR_CHECK("touch bundle", csir_touch(bundles, "b-100.sqlite"));
    CSIR_CHECK("touch stale .failed marker",
               csir_touch(bundles, "b-100.sqlite.failed"));

    char *p = boot_autodetect_consensus_bundle(dir);
    CSIR_CHECK("marked bundle skipped by autodetect", p == NULL);
    free(p);

    char path[384];
    snprintf(path, sizeof(path), "%s/bundles/b-100.sqlite", dir);
    boot_auto_install_clear_failed_marker(path);

    p = boot_autodetect_consensus_bundle(dir);
    CSIR_CHECK("cleared marker -> bundle detectable again",
               p != NULL && strstr(p, "b-100.sqlite") != NULL);
    free(p);

    /* Idempotent on a missing marker; benign on bad args. */
    boot_auto_install_clear_failed_marker(path);
    boot_auto_install_clear_failed_marker(NULL);
    boot_auto_install_clear_failed_marker("");

    test_rm_rf_recursive(dir);
    return failures;
}

/* (b) The runtime entry is callable and RETURNS (no _exit) on a bogus bundle. */
static int case_runtime_returns(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "csir_runtime", "ok");

    char bogus[320];
    snprintf(bogus, sizeof(bogus), "%s/bundles/does-not-exist.sqlite", dir);

    struct consensus_state_install_runtime_result rr;
    /* ndb/ms are unused on this fail-closed early-return path (admission fails
     * before any state is touched); a valid temp datadir keeps the classify step
     * in the COPY_PROOF lane so no canonical gate fires. */
    struct zcl_result r =
        consensus_state_install_from_bundle(NULL, NULL, bogus, dir, &rr);

    CSIR_CHECK("bogus bundle -> not ok (returned, did not _exit)", !r.ok);
    CSIR_CHECK("bogus bundle -> state NOT installed", !rr.state_installed);
    CSIR_CHECK("bogus bundle -> marker NOT written", !rr.marker_written);
    CSIR_CHECK("bogus bundle -> non-empty reason", rr.reason[0] != '\0');
    CSIR_CHECK("bogus bundle -> reason names admission",
               strstr(rr.reason, "admission") != NULL ||
                   strstr(rr.reason, "bundle") != NULL);
    /* A GENUINE refusal (admission failure — the flip-a-byte / corrupt-bundle
     * class) must NOT be flagged retriable: it is a real rejection the boot seam
     * SHOULD mark .failed, not a "headers not yet at checkpoint" wait. */
    CSIR_CHECK("bogus bundle -> NOT flagged retriable (boot seam .fails it)",
               !rr.retriable_headers_not_ready);

    /* Empty path/datadir also fail closed without dereferencing anything. */
    struct consensus_state_install_runtime_result rr2;
    struct zcl_result r2 =
        consensus_state_install_from_bundle(NULL, NULL, "", dir, &rr2);
    CSIR_CHECK("empty bundle path -> not ok", !r2.ok && !rr2.state_installed);

    /* out==NULL is tolerated (the core uses a local). */
    struct zcl_result r3 =
        consensus_state_install_from_bundle(NULL, NULL, bogus, dir, NULL);
    CSIR_CHECK("out==NULL tolerated -> not ok", !r3.ok);

    test_rm_rf_recursive(dir);
    return failures;
}

/* (c) The durable install-on-next-boot request round-trips + bounded budget. */
static int case_durable_request(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "csir_request", "ok");

    const char *bundle = "/some/where/produced-bundle-3056758.sqlite";

    CSIR_CHECK("fresh: not pending", !boot_install_bundle_pending(dir));

    /* Arm. */
    CSIR_CHECK("arm -> 1 (freshly armed)",
               boot_install_bundle_request(dir, bundle) == 1);
    CSIR_CHECK("armed -> pending", boot_install_bundle_pending(dir));

    /* Re-arm is idempotent while pending (attempts bump only at consume). */
    CSIR_CHECK("re-arm idempotent -> current count (1)",
               boot_install_bundle_request(dir, bundle) == 1);

    /* Consume returns the exact armed path and stays pending (budget not spent). */
    char got[512];
    CSIR_CHECK("consume #1 -> true",
               boot_install_bundle_consume(dir, got, sizeof(got)));
    CSIR_CHECK("consume #1 -> path round-trips", strcmp(got, bundle) == 0);
    CSIR_CHECK("still pending after consume #1", boot_install_bundle_pending(dir));

    /* Clear once committed → no longer pending, and consume is a no-op. */
    boot_install_bundle_clear(dir);
    CSIR_CHECK("cleared -> not pending", !boot_install_bundle_pending(dir));
    char got2[512];
    CSIR_CHECK("consume after clear -> false",
               !boot_install_bundle_consume(dir, got2, sizeof(got2)) &&
                   got2[0] == '\0');

    /* Bounded budget: re-arm, then consume MAX times, the next consume marks
     * TERMINAL and refuses; the request is then present-but-not-pending and can
     * never be re-armed. */
    CSIR_CHECK("re-arm after clear -> 1", boot_install_bundle_request(dir, bundle) == 1);
    for (int i = 0; i < BOOT_INSTALL_BUNDLE_MAX; i++) {
        char b[512];
        char label[64];
        snprintf(label, sizeof(label), "budget consume #%d -> true", i + 1);
        CSIR_CHECK(label, boot_install_bundle_consume(dir, b, sizeof(b)) &&
                              strcmp(b, bundle) == 0);
    }
    char bx[512];
    CSIR_CHECK("consume past budget -> false (TERMINAL)",
               !boot_install_bundle_consume(dir, bx, sizeof(bx)));
    CSIR_CHECK("terminal -> present-but-not-pending",
               !boot_install_bundle_pending(dir));
    CSIR_CHECK("re-arm over TERMINAL -> TERMINAL (never re-armed)",
               boot_install_bundle_request(dir, bundle) ==
                   BOOT_INSTALL_BUNDLE_TERMINAL);

    /* Rejects an embedded-newline path (line-oriented codec). */
    CSIR_CHECK("newline path rejected",
               boot_install_bundle_request(dir, "/a\n/b") == 0);

    test_rm_rf_recursive(dir);
    return failures;
}

/* (d) boot_post_install_fold_span_check — the post-install "catch the tail"
 * wiring. Synthetic block_index construction mirrors
 * test_refold_body_span_contiguous.c's bsc_install: heights are inserted via
 * chainstate_insert_block_index and installed ascending with
 * active_chain_install_tip_slot (each install accumulates lower slots; a
 * skipped height or a have_data=false slot is the hole). No datadir, no disk
 * block bodies — the gate reads only the BLOCK_HAVE_DATA bit. */
#define CSIR_INSTALLED_H 5000

static void csir_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[31] = 0xc7;
}

static bool csir_install(struct main_state *ms, int height, bool have_data)
{
    struct uint256 h;
    csir_hash_for(height, &h);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &h);
    if (!bi)
        return false;
    bi->nHeight = height;
    bi->nStatus = BLOCK_VALID_TREE | (have_data ? BLOCK_HAVE_DATA : 0);
    bi->nFile = have_data ? 0 : -1;
    bi->nDataPos = 0;
    return active_chain_install_tip_slot(&ms->chain_active, bi);
}

static int case_post_install_fold_span_check(void)
{
    int failures = 0;

    /* (d1) ms==NULL is a safe no-op — no crash, no blocker. */
    blocker_reset_for_testing();
    boot_post_install_fold_span_check(NULL, CSIR_INSTALLED_H);
    CSIR_CHECK("fold-span-check: ms==NULL is a safe no-op",
               !blocker_exists("refold.body_gap"));

    /* (d2) installed_height<0 is a safe no-op even with a real ms. */
    {
        struct main_state ms;
        main_state_init(&ms);
        blocker_reset_for_testing();
        boot_post_install_fold_span_check(&ms, -1);
        CSIR_CHECK("fold-span-check: installed_height<0 is a safe no-op",
                   !blocker_exists("refold.body_gap"));
        main_state_free(&ms);
    }

    /* (d3) Fresh install, no local advance past installed_height yet (the
     * common case: only the checkpoint height itself is on the local chain) —
     * a no-op. body_fetch simply resumes at installed_height+1 and pulls the
     * tail via normal P2P; nothing local to check yet. */
    {
        struct main_state ms;
        main_state_init(&ms);
        CSIR_CHECK("fold-span-check: seed only the checkpoint height",
                   csir_install(&ms, CSIR_INSTALLED_H, true));
        blocker_reset_for_testing();
        boot_post_install_fold_span_check(&ms, CSIR_INSTALLED_H);
        CSIR_CHECK("fold-span-check: no local advance -> no-op, no blocker",
                   !blocker_exists("refold.body_gap"));
        main_state_free(&ms);
    }

    /* (d4) Local chain already extends past installed_height with EVERY body
     * present (the Move 2 self-heal case on an already-synced node) — passes,
     * no false-positive blocker. */
    {
        struct main_state ms;
        main_state_init(&ms);
        bool seeded = true;
        for (int h = CSIR_INSTALLED_H; h <= CSIR_INSTALLED_H + 10; h++)
            seeded = seeded && csir_install(&ms, h, /*have_data=*/true);
        CSIR_CHECK("fold-span-check: self-heal chain (contiguous) installed",
                   seeded);
        blocker_reset_for_testing();
        boot_post_install_fold_span_check(&ms, CSIR_INSTALLED_H);
        CSIR_CHECK("fold-span-check: contiguous tail -> no-op, no blocker",
                   !blocker_exists("refold.body_gap"));
        main_state_free(&ms);
    }

    /* (d5) Local chain extends past installed_height but a body is MISSING
     * partway through the span — the NAMED blocker refold.body_gap fires
     * (never a silent fold-into-a-hole); the reducer's body_fetch (already
     * resuming at installed_height+1 via the forced stage cursors) is named
     * as the dependency that fills it. */
    {
        struct main_state ms;
        main_state_init(&ms);
        const int hole = CSIR_INSTALLED_H + 4;
        bool seeded = true;
        for (int h = CSIR_INSTALLED_H; h <= CSIR_INSTALLED_H + 10; h++)
            seeded = seeded && csir_install(&ms, h, /*have_data=*/(h != hole));
        CSIR_CHECK("fold-span-check: self-heal chain with one body hole "
                   "installed", seeded);
        blocker_reset_for_testing();
        boot_post_install_fold_span_check(&ms, CSIR_INSTALLED_H);
        CSIR_CHECK("fold-span-check: body gap -> NAMED blocker refold.body_gap "
                   "raised", blocker_exists("refold.body_gap"));
        CSIR_CHECK("fold-span-check: blocker class is DEPENDENCY",
                   blocker_class_for("refold.body_gap") == BLOCKER_DEPENDENCY);
        main_state_free(&ms);
        blocker_reset_for_testing();
    }

    return failures;
}

/* (d2) boot_post_install_drop_borrowed_have_data — the post-install wiring
 * that drops HAVE_DATA claims borrowed from the bundle PUBLISHER's blk-file
 * layout (the verbatim ladder load of a swarm-served block_index.bin) before
 * the staged pipeline starts, then retracts the active tip to the installed
 * height. Fixture mirrors the measured cold-sync defect: rows carry
 * HAVE_DATA + (nFile=49, nDataPos) but this node's blocks/ holds no such
 * file. */
static bool csir_install_borrowed(struct main_state *ms, int height,
                                  struct block_index *prev,
                                  struct block_index **out)
{
    struct uint256 h;
    csir_hash_for(height, &h);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &h);
    if (!bi)
        return false;
    bi->nHeight = height;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    bi->nFile = 49;                 /* the publisher's blk-file layout */
    bi->nDataPos = 47565546u + (unsigned int)height;
    bi->nTx = 2;
    bi->pprev = prev;
    *out = bi;
    return active_chain_install_tip_slot(&ms->chain_active, bi);
}

static bool csir_is_header_only(const struct block_index *bi)
{
    return bi &&
           !(bi->nStatus & BLOCK_HAVE_DATA) &&
           (bi->nStatus & BLOCK_VALID_MASK) == BLOCK_VALID_TREE &&
           bi->nFile == -1 &&
           bi->nDataPos == 0 &&
           bi->nTx == 0;
}

/* The three no-op guards (NULL ms, NULL datadir, negative installed height)
 * as one bool so the case body stays under the complexity cap. */
static bool csir_drop_guards_pass(struct main_state *ms)
{
    return boot_post_install_drop_borrowed_have_data(
               NULL, "/nonexistent", 10, false) == 0 &&
           boot_post_install_drop_borrowed_have_data(
               ms, NULL, 10, false) == 0 &&
           boot_post_install_drop_borrowed_have_data(
               ms, "/nonexistent", -1, false) == 0;
}

/* Install the 5-entry publisher-layout chain [inst-1 .. inst+3], pprev-linked
 * and tip-slot installed ascending. out[0]=below-seed, out[1]=seed,
 * out[2..4]=above-seed. */
static bool csir_seed_borrowed_chain(struct main_state *ms, int inst,
                                     struct block_index *out[5])
{
    struct block_index *prev = NULL;
    for (int i = 0; i < 5; i++) {
        if (!csir_install_borrowed(ms, inst - 1 + i, prev, &out[i]))
            return false;
        prev = out[i];
    }
    return true;
}

static bool csir_all_four_cleared(size_t dropped, struct block_index *const c[5])
{
    return dropped == 4 && csir_is_header_only(c[0]) &&
           csir_is_header_only(c[2]) && csir_is_header_only(c[3]) &&
           csir_is_header_only(c[4]);
}

static bool csir_seed_still_protected(const struct block_index *seed)
{
    return seed && (seed->nStatus & BLOCK_HAVE_DATA) &&
           (seed->nStatus & BLOCK_VALID_MASK) == BLOCK_VALID_SCRIPTS &&
           seed->nFile == 49;
}

static int case_post_install_drop_borrowed_have_data(void)
{
    int failures = 0;

    /* Guards: NULL state/datadir and a negative installed height are safe
     * no-ops (0 dropped, no crash). */
    {
        struct main_state ms;
        main_state_init(&ms);
        CSIR_CHECK("drop-borrowed: NULL/negative guards return 0",
                   csir_drop_guards_pass(&ms));
        main_state_free(&ms);
    }

    /* Borrowed coordinates with absent blk files: every non-seed claim is
     * cleared to header-only, the seed block is protected, and the active
     * tip retracts to the installed height. */
    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "post_install_drop", "borrowed");
        char blocks[512];
        int bn = snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
        CSIR_CHECK("drop-borrowed: blocks dir created",
                   bn > 0 && (size_t)bn < sizeof(blocks) &&
                   mkdir(blocks, 0755) == 0);

        struct main_state ms;
        main_state_init(&ms);
        const int inst = CSIR_INSTALLED_H;
        struct block_index *c[5] = {0};
        bool seeded = csir_seed_borrowed_chain(&ms, inst, c);
        CSIR_CHECK("drop-borrowed: publisher-layout chain installed",
                   seeded && active_chain_height(&ms.chain_active) == inst + 3);

        size_t dropped = boot_post_install_drop_borrowed_have_data(
            &ms, dir, inst, /*trust_existing_block_files=*/false);

        CSIR_CHECK("drop-borrowed: all non-seed borrowed claims dropped",
                   csir_all_four_cleared(dropped, c));
        CSIR_CHECK("drop-borrowed: seed block protected",
                   csir_seed_still_protected(c[1]));
        CSIR_CHECK("drop-borrowed: active tip retracted to installed height",
                   active_chain_height(&ms.chain_active) == inst);

        main_state_free(&ms);
        test_rm_rf_recursive(dir);
    }

    return failures;
}

/* ── (e) Deferral / retry — the fresh-boot install-timing seam ─────────────── */

/* Install a temporary SHA3 checkpoint override at `height` whose block_hash is
 * csir_hash_for(height) — so a fixture header at that height byte-matches it. */
static void cbir_set_override(int height)
{
    static struct sha3_utxo_checkpoint cp; /* borrowed by the seam; keep static */
    struct uint256 h;
    csir_hash_for(height, &h);
    memset(&cp, 0, sizeof(cp));
    cp.height = height;
    memcpy(cp.block_hash, h.data, 32);
    checkpoints_set_sha3_override_for_test(&cp);
}

/* Insert a pprev-linked block chain [lo..hi] into ms and return the tip. The
 * links let block_index_get_ancestor walk from a higher header down to the
 * checkpoint height (the real above-checkpoint case). */
static struct block_index *cbir_link_chain(struct main_state *ms, int lo, int hi)
{
    struct block_index *prev = NULL, *tip = NULL;
    for (int h = lo; h <= hi; h++) {
        struct uint256 hh;
        csir_hash_for(h, &hh);
        struct block_index *bi =
            chainstate_insert_block_index((struct chainstate *)ms, &hh);
        if (!bi)
            return NULL;
        bi->nHeight = h;
        bi->nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
        bi->pprev = prev;
        prev = bi;
        tip = bi;
    }
    return tip;
}

/* (e1) consensus_state_checkpoint_header_ready — the exact discriminator between
 * a retriable WAIT (headers below / not owning the checkpoint) and a genuine
 * "ready to bind" chain. */
static int case_checkpoint_header_ready(void)
{
    int failures = 0;
    const int CP = 5000;
    cbir_set_override(CP);

    CSIR_CHECK("ready: ms==NULL -> false",
               !consensus_state_checkpoint_header_ready(NULL));

    /* Header frontier BELOW the checkpoint -> WAIT (the fresh-boot case). */
    {
        struct main_state ms;
        main_state_init(&ms);
        ms.pindex_best_header = cbir_link_chain(&ms, CP - 50, CP - 1);
        CSIR_CHECK("ready: header frontier below checkpoint -> false (wait)",
                   ms.pindex_best_header &&
                       !consensus_state_checkpoint_header_ready(&ms));
        main_state_free(&ms);
    }

    /* Header frontier EXACTLY at the checkpoint with the matching hash -> ready. */
    {
        struct main_state ms;
        main_state_init(&ms);
        ms.pindex_best_header = cbir_link_chain(&ms, CP - 3, CP);
        CSIR_CHECK("ready: header frontier at checkpoint (hash matches) -> true",
                   ms.pindex_best_header &&
                       consensus_state_checkpoint_header_ready(&ms));
        main_state_free(&ms);
    }

    /* Header frontier ABOVE the checkpoint, ancestor at CP matches -> ready. */
    {
        struct main_state ms;
        main_state_init(&ms);
        ms.pindex_best_header = cbir_link_chain(&ms, CP - 3, CP + 6);
        CSIR_CHECK("ready: header frontier above checkpoint (ancestor matches) "
                   "-> true",
                   ms.pindex_best_header &&
                       consensus_state_checkpoint_header_ready(&ms));
        main_state_free(&ms);
    }

    /* Header at the checkpoint height but the compiled checkpoint expects a
     * DIFFERENT block hash there (a different chain) -> not ready. */
    {
        struct main_state ms;
        main_state_init(&ms);
        ms.pindex_best_header = cbir_link_chain(&ms, CP - 3, CP);
        static struct sha3_utxo_checkpoint bad;
        struct uint256 other;
        csir_hash_for(CP, &other);
        other.data[7] ^= 0xFF; /* checkpoint expects a hash the chain does not have */
        memset(&bad, 0, sizeof(bad));
        bad.height = CP;
        memcpy(bad.block_hash, other.data, 32);
        checkpoints_set_sha3_override_for_test(&bad);
        CSIR_CHECK("ready: checkpoint-height hash mismatch -> false",
                   ms.pindex_best_header &&
                       !consensus_state_checkpoint_header_ready(&ms));
        cbir_set_override(CP); /* restore the matching override */
        main_state_free(&ms);
    }

    checkpoints_reset_sha3_override_for_test();
    return failures;
}

/* The D8 recovery must publish only a map-resident, baked-hash checkpoint
 * after the canonical validator has recorded a pass. The served chain stays
 * untouched while the header view becomes install-ready. */
static int case_checkpoint_header_frontier_restore(void)
{
    int failures = 0;
    const int cp_height = 5000;
    cbir_set_override(cp_height);

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "csir_hdr_restore", "ok");
    CSIR_CHECK("restore: progress store opens", progress_store_open(dir));

    struct main_state ms;
    main_state_init(&ms);
    struct block_index *tip =
        cbir_link_chain(&ms, cp_height - 3, cp_height);
    ms.pindex_best_header =
        block_index_get_ancestor(tip, cp_height - 3);

    struct coins_view backing;
    memset(&backing, 0, sizeof(backing));
    struct coins_view_cache cache;
    coins_view_cache_init(&cache, &backing);
    csr_init(csr_instance(), &ms.map_block_index, &ms.chain_active,
             &ms.pindex_best_header, &cache, NULL, NULL);
    validate_headers_ensure_set_validator_for_test(csir_header_pass, NULL);

    CSIR_CHECK("restore: reset header view is not checkpoint-ready",
               tip && !consensus_state_checkpoint_header_ready(&ms));
    CSIR_CHECK("restore: validates and republishes checkpoint header",
               consensus_state_install_restore_checkpoint_header_frontier(
                   &ms));
    CSIR_CHECK("restore: header view now owns checkpoint",
               ms.pindex_best_header == tip &&
                   consensus_state_checkpoint_header_ready(&ms));
    CSIR_CHECK("restore: served tip remains untouched",
               active_chain_tip(&ms.chain_active) == NULL);
    CSIR_CHECK("restore: durable validated-header fact exists",
               validate_headers_stage_has_pass_record(
                   cp_height, tip->phashBlock));
    CSIR_CHECK("restore: second call is idempotent",
               consensus_state_install_restore_checkpoint_header_frontier(
                   &ms));

    validate_headers_ensure_set_validator_for_test(NULL, NULL);
    coins_view_cache_free(&cache);
    main_state_free(&ms);
    progress_store_close();
    checkpoints_reset_sha3_override_for_test();
    test_rm_rf_recursive(dir);
    return failures;
}

/* (e3) checkpoint_header_solution_repair detect WIDENING: the checkpoint-header
 * solution fetch must arm REGARDLESS of tip position — the live-cure node sits
 * ABOVE the checkpoint (e.g. H*=3,176,325 on borrowed shielded state) yet still
 * needs the checkpoint header's Equihash solution to bind the staged bundle. The
 * staged-bundle predicate remains the real scope (a sovereign node's marker makes
 * autodetect NULL, short-circuiting the fetch). */
static int case_solution_repair_detect_window(void)
{
    int failures = 0;
    const int CP = 5000;
    cbir_set_override(CP);
    checkpoint_header_solution_repair_test_reset();

    struct main_state ms;
    main_state_init(&ms);
    ms.pindex_best_header = cbir_link_chain(&ms, CP - 3, CP + 4); /* owns CP */
    checkpoint_header_solution_repair_test_set_main_state(&ms);
    checkpoint_header_solution_repair_test_set_peer_count(1);

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "chsr_detect", "ok");
    checkpoint_header_solution_repair_test_set_datadir(dir);
    CSIR_CHECK("chsr: progress store opens", progress_store_open(dir));

    /* Tip above the checkpoint. */
    reducer_frontier_provable_tip_set(CP + 100000);

    /* No staged bundle -> nothing to unblock -> detect FALSE. */
    CSIR_CHECK("chsr: detect false with no staged bundle",
               !checkpoint_header_solution_repair_test_detect());

    /* Stage a bundle -> header ready + staged bundle + solution absent + tip ABOVE
     * the checkpoint -> detect TRUE (the widening the live cure needs). */
    char bundles[320];
    snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
    CSIR_CHECK("chsr: mkdir bundles/", mkdir(bundles, 0700) == 0);
    CSIR_CHECK("chsr: stage bundle",
               csir_touch(bundles, "consensus-state-bundle-5000.sqlite"));
    CSIR_CHECK("chsr: detect FIRES above the checkpoint (live-cure widening)",
               checkpoint_header_solution_repair_test_detect());

    /* Healthy sovereign node: the install marker makes autodetect return NULL, so
     * detect short-circuits FALSE even with the solution still absent. */
    {
        struct uint256 dg;
        memset(&dg, 0x5a, sizeof(dg));
        (void)boot_consensus_bundle_marker_write(dir, CP, dg.data);
        CSIR_CHECK("chsr: detect false once the sovereign marker exists (healthy)",
                   !checkpoint_header_solution_repair_test_detect());
    }

    reducer_frontier_provable_tip_reset();
    checkpoint_header_solution_repair_test_reset();
    progress_store_close();
    test_rm_rf_recursive(dir);
    checkpoints_reset_sha3_override_for_test();
    main_state_free(&ms);
    return failures;
}

/* (e2) checkpoint_bundle_install_ready: detect gates on headers-reached-
 * checkpoint + a staged bundle + the checkpoint solution, and the remedy arms
 * the bounded install-on-next-boot request without a retry storm. Tip
 * position does not gate the arm. */
static int case_retry_condition(void)
{
    int failures = 0;
    const int CP = 5000;
    cbir_set_override(CP);
    reducer_frontier_provable_tip_reset(); /* H* unknown/0 -> below checkpoint */
    checkpoint_bundle_install_ready_test_reset();
    checkpoint_bundle_install_ready_test_suppress_restart(true);

    /* Registered-cadence pin: both cold-sync arm-path conditions poll at 5s
     * (the detect is ms-class — one ancestor walk, an indexed read, a
     * repair-row probe, a bundles/ dir scan), so the arm is not held behind
     * a 15s/10s detect cadence; backoff/attempts/witness are untouched. */
    condition_engine_reset_for_testing();
    register_checkpoint_bundle_install_ready();
    register_checkpoint_header_solution_repair();
    struct condition_runtime_snapshot snap;
    CSIR_CHECK("cond: registered checkpoint_bundle_install_ready poll_secs==5",
               condition_engine_get_registered_snapshot(
                   "checkpoint_bundle_install_ready", &snap) &&
                   snap.poll_secs == 5);
    CSIR_CHECK("cond: registered checkpoint_header_solution_repair "
               "poll_secs==5 (sibling owns solution fetch when the IBD "
               "capture path does not fire)",
               condition_engine_get_registered_snapshot(
                   "checkpoint_header_solution_repair", &snap) &&
                   snap.poll_secs == 5);

    struct main_state ms;
    main_state_init(&ms);
    /* Header chain owns the checkpoint block (ready). */
    ms.pindex_best_header = cbir_link_chain(&ms, CP - 3, CP + 4);
    checkpoint_bundle_install_ready_test_set_main_state(&ms);

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "cbir_cond", "ok");
    char bundles[320];
    snprintf(bundles, sizeof(bundles), "%s/bundles", dir);
    CSIR_CHECK("cond: mkdir bundles/", mkdir(bundles, 0700) == 0);
    CSIR_CHECK("cond: stage bundle", csir_touch(bundles, "consensus-state-bundle-5000.sqlite"));
    checkpoint_bundle_install_ready_test_set_datadir(dir);

     /* The install-ready gate requires the checkpoint header's Equihash
      * solution to be durable; land a pass record so the install can bind. */
    CSIR_CHECK("cond: progress store opens", progress_store_open(dir));
    validate_headers_ensure_set_validator_for_test(csir_header_pass, NULL);
    CSIR_CHECK("cond: checkpoint header solution landed (pass record minted)",
               validate_headers_stage_ensure_pass_record(&ms, CP));

    /* detect FIRES: headers ready + solution available + bundle staged. */
    CSIR_CHECK("cond: detect fires when headers reach checkpoint + bundle staged",
               checkpoint_bundle_install_ready_test_detect());

     /* H* above the checkpoint does not suppress the arm: a live node on
      * borrowed shielded state still needs the install; the staged-bundle
      * predicate is the scope (a sovereign node has the marker, so detect is
      * false). */
    reducer_frontier_provable_tip_set(CP + 100000);
    CSIR_CHECK("cond: detect STILL fires above checkpoint (live-cure path)",
               checkpoint_bundle_install_ready_test_detect());
    reducer_frontier_provable_tip_reset();

    /* Header frontier below the checkpoint -> WAIT (no premature fire). */
    {
        struct main_state below;
        main_state_init(&below);
        below.pindex_best_header = cbir_link_chain(&below, CP - 50, CP - 1);
        checkpoint_bundle_install_ready_test_set_main_state(&below);
        CSIR_CHECK("cond: detect waits while header frontier below checkpoint",
                   !checkpoint_bundle_install_ready_test_detect());
        checkpoint_bundle_install_ready_test_set_main_state(&ms);
        main_state_free(&below);
    }

    /* remedy ARMS the durable install-on-next-boot request (bounded budget). */
    CSIR_CHECK("cond: fresh datadir not pending", !boot_install_bundle_pending(dir));
    CSIR_CHECK("cond: remedy -> OK (armed)",
               checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_OK);
    CSIR_CHECK("cond: request now pending", boot_install_bundle_pending(dir));

    /* No retry-storm: repeated remedy ticks are idempotent (the attempt count
     * only bumps at CONSUME/boot), never inflating the budget. */
    CSIR_CHECK("cond: remedy again -> OK (idempotent arm, no storm)",
               checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_OK);
    CSIR_CHECK("cond: still pending (budget not inflated)",
               boot_install_bundle_pending(dir));

    /* Once the bounded budget is spent the request is TERMINAL and the remedy
     * REFUSES to respawn (operator paged) — the durable end-to-end bound. */
    for (int i = 0; i < BOOT_INSTALL_BUNDLE_MAX; i++) {
        char b[512];
        (void)boot_install_bundle_consume(dir, b, sizeof(b));
    }
    (void)boot_install_bundle_consume(dir, (char[512]){0}, 512); /* trip TERMINAL */
    CSIR_CHECK("cond: remedy over TERMINAL budget -> FAILED (no respawn storm)",
               checkpoint_bundle_install_ready_test_remedy() == (int)COND_REMEDY_FAILED);

    /* Sovereign-install marker present -> autodetect returns NULL -> detect
     * clears (the bundle installed; nothing to retry). */
    {
        struct uint256 dg;
        memset(&dg, 0x5a, sizeof(dg));
        (void)boot_consensus_bundle_marker_write(dir, CP, dg.data);
        CSIR_CHECK("cond: detect clears once sovereign marker exists",
                   !checkpoint_bundle_install_ready_test_detect());
    }

    validate_headers_ensure_set_validator_for_test(NULL, NULL);
    progress_store_close();
    test_rm_rf_recursive(dir);
    checkpoint_bundle_install_ready_test_reset();
    reducer_frontier_provable_tip_reset();
    checkpoints_reset_sha3_override_for_test();
    main_state_free(&ms);
    return failures;
}

static struct node_db *g_csir_ndb;

static bool csir_gate(const char *dir, const char *auth, bool *canon)
{
    const char *why = NULL;
    return boot_install_consensus_bundle_gate_for_test(dir, auth, g_csir_ndb,
                                                       canon, &why);
}

/* Fresh-datadir cutover: the canonical-lane owner gate protects existing chain
 * state. A canonical datadir whose consensus store holds no coins and no
 * tip_finalize/utxo_apply rows above genesis has nothing to protect, so the
 * first-node path (docs/node/GETTING_STARTED.md) admits the bundle without
 * ZCL_DEPLOY_ALLOW_CANONICAL. Any prior row keeps the gate closed. */
static bool csir_sql(const char *sql)
{
    char *err = NULL;
    bool ok = sqlite3_exec(progress_store_db(), sql, NULL, NULL, &err) ==
              SQLITE_OK;
    if (err)
        sqlite3_free(err);
    return ok;
}

/* The canonical datadir the product derives from `home`, through the same
 * routine the node control path uses, so the fixture spells no live path. */
static void csir_default_datadir(const char *home, char *out, size_t cap)
{
    char scratch[5][PATH_MAX];
    zcl_nodectl_build_default_paths(home, scratch[0], sizeof(scratch[0]),
                                    scratch[1], sizeof(scratch[1]),
                                    scratch[2], sizeof(scratch[2]), out, cap,
                                    scratch[3], sizeof(scratch[3]),
                                    scratch[4], sizeof(scratch[4]));
}

static int case_fresh_canonical_cutover(void)
{
    int failures = 0;
    char root[256], home[300], canonical[340];
    test_make_tmpdir(root, sizeof(root), "csir_fresh_canon", "ok");
    snprintf(home, sizeof(home), "%s/home", root);
    csir_default_datadir(home, canonical, sizeof(canonical));
    const char *old_home = getenv("HOME");
    char saved[PATH_MAX];
    snprintf(saved, sizeof(saved), "%s", old_home ? old_home : "");
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    char node_path[300];
    snprintf(node_path, sizeof(node_path), "%s/node.db", root);
    bool setup = mkdir(home, 0700) == 0 && mkdir(canonical, 0700) == 0 &&
                 setenv("HOME", home, 1) == 0 && node_db_open(&ndb, node_path);
    g_csir_ndb = &ndb;
    CSIR_CHECK("fresh canonical: fixture initializes", setup);

    bool is_canonical = false;
    CSIR_CHECK("fresh canonical: progress store opens",
               setup && progress_store_open(canonical));
    CSIR_CHECK("fresh canonical: empty store admits without owner gate",
               csir_gate(
                   canonical, NULL, &is_canonical) && is_canonical);
    CSIR_CHECK("fresh canonical: schema without rows still admits",
               csir_sql("CREATE TABLE IF NOT EXISTS tip_finalize_log("
                        "height INTEGER PRIMARY KEY, status TEXT NOT NULL,"
                        "ok INTEGER NOT NULL, work_delta_high INTEGER NOT NULL,"
                        "work_delta_low INTEGER NOT NULL,"
                        "utxo_size_after INTEGER NOT NULL,"
                        "reorg_depth INTEGER NOT NULL,"
                        "finalized_at INTEGER NOT NULL)") &&
               csir_gate(
                   canonical, NULL, &is_canonical));
    CSIR_CHECK("fresh canonical: genesis-only row still admits",
               csir_sql("INSERT INTO tip_finalize_log VALUES"
                        "(0,'ok',1,0,0,0,0,0)") &&
               csir_gate(
                   canonical, NULL, &is_canonical));
    CSIR_CHECK("fresh canonical: a finalized height above genesis refuses",
               csir_sql("INSERT INTO tip_finalize_log VALUES"
                        "(7,'ok',1,0,0,0,0,0)") &&
               !csir_gate(
                   canonical, NULL, &is_canonical) && is_canonical);
    CSIR_CHECK("fresh canonical: owner gate still admits existing state",
               csir_gate(
                   canonical, "1", &is_canonical));
    CSIR_CHECK("fresh canonical: removing the row reopens the fresh path",
               csir_sql("DELETE FROM tip_finalize_log WHERE height=7") &&
               csir_gate(
                   canonical, NULL, &is_canonical));
    CSIR_CHECK("fresh canonical: any coin refuses",
               csir_sql("CREATE TABLE IF NOT EXISTS coins(txid BLOB NOT NULL,"
                        "vout INTEGER NOT NULL, value INTEGER NOT NULL,"
                        "height INTEGER NOT NULL, is_coinbase INTEGER NOT NULL,"
                        "script BLOB NOT NULL, PRIMARY KEY(txid,vout))"
                        " WITHOUT ROWID") &&
               csir_sql("INSERT INTO coins VALUES(X'01',0,1,1,0,X'00')") &&
               !csir_gate(
                   canonical, NULL, &is_canonical));
    progress_store_close();
    CSIR_CHECK("fresh canonical: closed store fails closed",
               !csir_gate(
                   canonical, NULL, &is_canonical));
    node_db_close(&ndb);
    g_csir_ndb = NULL;

    if (old_home)
        (void)setenv("HOME", saved, 1);
    else
        (void)unsetenv("HOME");
    test_rm_rf_recursive(root);
    return failures;
}

/* A refusal by the canonical-lane owner gate says nothing about the bundle, so
 * it must leave no <name>.failed marker: a later boot with the owner
 * authorization has to find the bundle again. A genuinely unreadable bundle on
 * a fresh canonical datadir still degrades to a normal boot. */
static int case_owner_gate_refusal_writes_nothing(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    char root[256], home[300], canonical[340], bundles[380], bundle[420],
        failed[440];
    test_make_tmpdir(root, sizeof(root), "csir_gate_marker", "ok");
    snprintf(home, sizeof(home), "%s/home", root);
    csir_default_datadir(home, canonical, sizeof(canonical));
    snprintf(bundles, sizeof(bundles), "%s/bundles", canonical);
    snprintf(bundle, sizeof(bundle), "%s/b.sqlite", bundles);
    snprintf(failed, sizeof(failed), "%s.failed", bundle);
    char node_path[300];
    snprintf(node_path, sizeof(node_path), "%s/node.db", root);
    const char *old_home = getenv("HOME");
    char saved[PATH_MAX];
    snprintf(saved, sizeof(saved), "%s", old_home ? old_home : "");
    bool setup = mkdir(home, 0700) == 0 && mkdir(canonical, 0700) == 0 &&
                 mkdir(bundles, 0700) == 0 && csir_touch(bundles, "b.sqlite") &&
                 setenv("HOME", home, 1) == 0 && progress_store_open(canonical) &&
                 node_db_open(&ndb, node_path);
    CSIR_CHECK("gate marker: fixture initializes", setup);
    CSIR_CHECK("gate marker: seed one coin",
               setup &&
               csir_sql("CREATE TABLE IF NOT EXISTS coins(txid BLOB NOT NULL,"
                        "vout INTEGER NOT NULL, value INTEGER NOT NULL,"
                        "height INTEGER NOT NULL, is_coinbase INTEGER NOT NULL,"
                        "script BLOB NOT NULL, PRIMARY KEY(txid,vout))"
                        " WITHOUT ROWID") &&
               csir_sql("INSERT INTO coins VALUES(X'01',0,1,1,0,X'00')"));
    struct consensus_state_install_runtime_result rr;
    struct zcl_result r =
        consensus_state_install_from_bundle(&ndb, NULL, bundle, canonical, &rr);
    CSIR_CHECK("gate marker: existing state refuses", !r.ok &&
               rr.owner_gate_refused && !rr.state_installed);
    CSIR_CHECK("gate marker: boot seam installs nothing",
               !boot_maybe_auto_install_consensus_bundle(&ndb, NULL, canonical,
                                                        false));
    CSIR_CHECK("gate marker: refusal leaves no .failed marker",
               access(failed, F_OK) != 0);
    CSIR_CHECK("gate marker: bundle is still autodetected",
               boot_autodetect_consensus_bundle(canonical) != NULL);
    CSIR_CHECK("gate marker: clearing the state lets admission judge the bundle",
               csir_sql("DELETE FROM coins") &&
               !boot_maybe_auto_install_consensus_bundle(&ndb, NULL, canonical,
                                                        false) &&
               access(failed, F_OK) == 0);
    progress_store_close();
    node_db_close(&ndb);
    if (old_home)
        (void)setenv("HOME", saved, 1);
    else
        (void)unsetenv("HOME");
    test_rm_rf_recursive(root);
    return failures;
}

/* The owner gate fails closed: an unreadable or missing legacy mirror, a chain
 * table the gate does not know, and a consensus store opened under a different
 * datadir each keep a canonical datadir refused. */
struct csir_gate_fx {
    char root[256], home[300], canonical[340], other[300], saved[PATH_MAX];
    bool had_home;
    struct node_db ndb;
    bool ready;
};

static void csir_gate_fx_open(struct csir_gate_fx *fx)
{
    memset(fx, 0, sizeof(*fx));
    char node_path[300];
    test_make_tmpdir(fx->root, sizeof(fx->root), "csir_gate_closed", "ok");
    snprintf(fx->home, sizeof(fx->home), "%s/home", fx->root);
    csir_default_datadir(fx->home, fx->canonical, sizeof(fx->canonical));
    snprintf(fx->other, sizeof(fx->other), "%s/other", fx->root);
    snprintf(node_path, sizeof(node_path), "%s/node.db", fx->root);
    const char *old_home = getenv("HOME");
    fx->had_home = old_home != NULL;
    snprintf(fx->saved, sizeof(fx->saved), "%s", old_home ? old_home : "");
    fx->ready = mkdir(fx->home, 0700) == 0 && mkdir(fx->canonical, 0700) == 0 &&
                mkdir(fx->other, 0700) == 0 && setenv("HOME", fx->home, 1) == 0 &&
                node_db_open(&fx->ndb, node_path) &&
                progress_store_open(fx->canonical);
    g_csir_ndb = &fx->ndb;
}

static void csir_gate_fx_close(struct csir_gate_fx *fx)
{
    progress_store_close();
    node_db_close(&fx->ndb);
    g_csir_ndb = NULL;
    if (fx->had_home)
        (void)setenv("HOME", fx->saved, 1);
    else
        (void)unsetenv("HOME");
    test_rm_rf_recursive(fx->root);
}

static bool csir_gate_reason(const struct csir_gate_fx *fx, const char *auth,
                             struct node_db *ndb, const char *needle)
{
    bool canon = false;
    const char *why = NULL;
    bool admitted = boot_install_consensus_bundle_gate_for_test(
        fx->canonical, auth, ndb, &canon, &why);
    return !admitted && why && strstr(why, needle) != NULL;
}

static bool csir_gate_admits(const struct csir_gate_fx *fx, const char *auth,
                             struct node_db *ndb)
{
    bool canon = false;
    return boot_install_consensus_bundle_gate_for_test(fx->canonical, auth, ndb,
                                                       &canon, NULL);
}

static int case_gate_mirror_handle(void)
{
    int failures = 0;
    struct csir_gate_fx fx;
    csir_gate_fx_open(&fx);
    struct node_db closed;
    memset(&closed, 0, sizeof(closed));
    CSIR_CHECK("gate closed: fixture initializes", fx.ready);
    CSIR_CHECK("gate closed: empty store and empty mirror admit",
               csir_gate_admits(&fx, NULL, &fx.ndb));
    CSIR_CHECK("gate closed: NULL mirror handle refuses with a reason",
               csir_gate_reason(&fx, NULL, NULL, "legacy"));
    CSIR_CHECK("gate closed: closed mirror handle refuses",
               csir_gate_reason(&fx, NULL, &closed, "legacy"));
    CSIR_CHECK("gate closed: owner authorization still admits a closed mirror",
               csir_gate_admits(&fx, "1", &closed));
    csir_gate_fx_close(&fx);
    return failures;
}

static int case_gate_mirror_table(void)
{
    int failures = 0;
    struct csir_gate_fx fx;
    csir_gate_fx_open(&fx);
    bool dropped = node_db_exec(&fx.ndb, "DROP TABLE utxos");
    CSIR_CHECK("gate closed: dropped mirror table refuses (prepare error)",
               dropped && csir_gate_reason(&fx, NULL, &fx.ndb, "legacy"));
    bool restored = node_db_exec(&fx.ndb,
        "CREATE TABLE utxos(txid BLOB, vout INTEGER, height INTEGER, "
        "value INTEGER, script BLOB)");
    CSIR_CHECK("gate closed: restored mirror table admits again",
               restored && csir_gate_admits(&fx, NULL, &fx.ndb));
    bool row = node_db_exec(&fx.ndb,
                            "INSERT INTO utxos VALUES(X'01',0,1,1,X'00')");
    CSIR_CHECK("gate closed: a mirror row refuses",
               row && csir_gate_reason(&fx, NULL, &fx.ndb, "legacy"));
    bool emptied = node_db_exec(&fx.ndb, "DELETE FROM utxos");
    CSIR_CHECK("gate closed: emptied mirror admits",
               emptied && csir_gate_admits(&fx, NULL, &fx.ndb));
    csir_gate_fx_close(&fx);
    return failures;
}

static bool csir_applied(int32_t height)
{
    return csir_sql("BEGIN IMMEDIATE") &&
           coins_kv_set_applied_height_in_tx(progress_store_db(), height) &&
           csir_sql("COMMIT");
}

static int case_gate_unknown_tables(void)
{
    int failures = 0;
    struct csir_gate_fx fx;
    csir_gate_fx_open(&fx);
    bool seeded = csir_sql("CREATE TABLE legacy_chain(k INTEGER)") &&
                  csir_sql("INSERT INTO legacy_chain VALUES(1)");
    CSIR_CHECK("gate closed: unknown table with rows and no coins table refuses",
               seeded && csir_gate_reason(&fx, NULL, &fx.ndb, "chain state"));
    bool dropped = csir_sql("DROP TABLE legacy_chain");
    CSIR_CHECK("gate closed: dropping it admits again",
               dropped && csir_gate_admits(&fx, NULL, &fx.ndb));
    bool nf = csir_sql("CREATE TABLE nullifiers(nf BLOB, pool INTEGER, "
                       "height INTEGER)") &&
              csir_sql("INSERT INTO nullifiers VALUES(X'01',0,1)");
    CSIR_CHECK("gate closed: nullifier rows without a coins table refuse",
               nf && csir_gate_reason(&fx, NULL, &fx.ndb, "chain state"));
    bool cleaned = csir_sql("DELETE FROM nullifiers");
    CSIR_CHECK("gate closed: cleaned nullifiers admit",
               cleaned && csir_gate_admits(&fx, NULL, &fx.ndb));
    csir_gate_fx_close(&fx);
    return failures;
}

static int case_gate_applied_height(void)
{
    int failures = 0;
    struct csir_gate_fx fx;
    csir_gate_fx_open(&fx);
    bool high = csir_applied(500);
    CSIR_CHECK("gate closed: applied height above genesis refuses",
               high && csir_gate_reason(&fx, NULL, &fx.ndb, "chain state"));
    bool genesis = csir_applied(1);
    CSIR_CHECK("gate closed: genesis applied height admits",
               genesis && csir_gate_admits(&fx, NULL, &fx.ndb));
    csir_gate_fx_close(&fx);
    return failures;
}

static int case_gate_store_datadir(void)
{
    int failures = 0;
    struct csir_gate_fx fx;
    csir_gate_fx_open(&fx);
    progress_store_close();
    bool reopened = progress_store_open(fx.other);
    CSIR_CHECK("gate closed: store opened under another datadir", reopened);
    CSIR_CHECK("gate closed: mismatched store refuses with a named reason",
               csir_gate_reason(&fx, NULL, &fx.ndb, "does not belong"));
    CSIR_CHECK("gate closed: owner authorization admits a mismatched store",
               csir_gate_admits(&fx, "1", &fx.ndb));
    csir_gate_fx_close(&fx);
    return failures;
}

int test_consensus_state_install_runtime(void)
{
    printf("\n=== consensus_state_install_runtime ===\n");
    int failures = 0;
    failures += case_autodetect();
    failures += case_failed_marker_cleared_on_success();
    failures += case_runtime_returns();
    failures += case_durable_request();
    failures += case_post_install_fold_span_check();
    failures += case_post_install_drop_borrowed_have_data();
    failures += case_checkpoint_header_ready();
    failures += case_checkpoint_header_frontier_restore();
    failures += case_retry_condition();
    failures += case_solution_repair_detect_window();
    failures += case_fresh_canonical_cutover();
    failures += case_gate_mirror_handle();
    failures += case_gate_mirror_table();
    failures += case_gate_unknown_tables();
    failures += case_gate_applied_height();
    failures += case_gate_store_datadir();
    failures += case_owner_gate_refusal_writes_nothing();
    printf("=== consensus_state_install_runtime: %d failure(s) ===\n", failures);
    return failures;
}
