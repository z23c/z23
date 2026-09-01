/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_consensus_state_install_runtime — focused unit test for the boot-wiring
 * of the sovereign consensus-state install (engine/composition/src/
 * consensus_state_install_runtime.c). It proves the CODE WIRING + logic; the
 * full end-to-end copy-prove (fresh datadir → install a real produced bundle →
 * H* climbs to tip) needs a produced artifact and is a SEPARATE integration
 * step the orchestrator runs.
 *
 * Asserts:
 *   (a) boot_autodetect_consensus_bundle CHOOSES a <datadir>/bundles/<name>.sqlite
 *       bundle when present, skips when absent, when the sovereign-install
 *       marker is set, or when a sibling <name>.failed marker is present, and
 *       picks the lexicographically-greatest candidate deterministically.
 *   (b) consensus_state_install_from_bundle is callable and RETURNS a typed
 *       result (does NOT _exit()) — a bogus bundle path fails closed at
 *       admission with state_installed=false and a non-empty reason.
 *   (c) the durable install-on-next-boot request round-trips: arm → pending →
 *       consume (path matches, budget bumps) → clear → not pending, and the
 *       bounded budget marks TERMINAL after BOOT_INSTALL_BUNDLE_MAX attempts and
 *       is never re-armed.
 *   (d) boot_post_install_fold_span_check — the "catch the tail" wiring reused
 *       from boot_refold_body_span_contiguous after a successful install:
 *       a fresh install with no local chain advance past installed_height is a
 *       no-op (the common case: body_fetch resumes at installed_height+1 and
 *       the tail arrives via normal P2P sync); a local chain that already
 *       extends past installed_height with every body present (the Move 2
 *       self-heal case) is ALSO a no-op (no false-positive blocker); a local
 *       chain that extends past installed_height with a body GAP raises the
 *       NAMED blocker refold.body_gap at the first missing height rather than
 *       letting the fold walk silently into a hole; ms==NULL / negative
 *       installed_height are safe no-ops.
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "coins/coins_view.h"
#include "conditions/checkpoint_bundle_install_ready.h"
#include "conditions/checkpoint_header_solution_repair.h"
#include "config/boot_consensus_bundle_marker.h"
#include "config/consensus_state_install_runtime.h"
#include "core/uint256.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/validate_headers_stage.h"
#include "services/chain_state_service.h"
#include "storage/progress_store.h"
#include "util/blocker.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

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
 * the bundle detectable again — the 2026-07-27 live trap: a watchdog-killed
 * boot marked the bundle .failed at 04:28, a later boot installed it
 * successfully at 05:37, and nothing cleared the marker, so autodetect kept
 * skipping the GOOD bundle on every subsequent scan. */
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

    /* Tip ABOVE the checkpoint — the live-cure position the old guard blocked. */
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

/* (e2) The retry condition (checkpoint_bundle_install_ready): detect gates on
 * headers-reached-checkpoint + a staged bundle + the checkpoint solution, and
 * the remedy arms the bounded install-on-next-boot request without a retry-storm.
 * Widened: tip position no longer gates the arm (the live-cure node is above the
 * checkpoint yet still needs the install). */
static int case_retry_condition(void)
{
    int failures = 0;
    const int CP = 5000;
    cbir_set_override(CP);
    reducer_frontier_provable_tip_reset(); /* H* unknown/0 -> below checkpoint */
    checkpoint_bundle_install_ready_test_reset();
    checkpoint_bundle_install_ready_test_suppress_restart(true);

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

    /* The install-ready gate now also requires the checkpoint header's Equihash
     * solution to be durably available (its sibling checkpoint_header_solution_
     * repair peer-fetches + persists it). Land a pass record for the checkpoint
     * header so the install can actually bind — otherwise detect would (now
     * correctly) wait rather than burn the bounded install budget. */
    CSIR_CHECK("cond: progress store opens", progress_store_open(dir));
    validate_headers_ensure_set_validator_for_test(csir_header_pass, NULL);
    CSIR_CHECK("cond: checkpoint header solution landed (pass record minted)",
               validate_headers_stage_ensure_pass_record(&ms, CP));

    /* detect FIRES: headers ready + solution available + bundle staged. */
    CSIR_CHECK("cond: detect fires when headers reach checkpoint + bundle staged",
               checkpoint_bundle_install_ready_test_detect());

    /* WIDENED (live-cure): H* ABOVE the checkpoint no longer suppresses the arm.
     * The live-cure node sits above the checkpoint on BORROWED shielded state and
     * still needs the install to close its anchor/nullifier gap; the staged-bundle
     * predicate is the real scope (a sovereign node has the marker -> autodetect
     * NULL -> detect false, proven at the end of this case). */
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

int test_consensus_state_install_runtime(void)
{
    printf("\n=== consensus_state_install_runtime ===\n");
    int failures = 0;
    failures += case_autodetect();
    failures += case_failed_marker_cleared_on_success();
    failures += case_runtime_returns();
    failures += case_durable_request();
    failures += case_post_install_fold_span_check();
    failures += case_checkpoint_header_ready();
    failures += case_checkpoint_header_frontier_restore();
    failures += case_retry_condition();
    failures += case_solution_repair_detect_window();
    printf("=== consensus_state_install_runtime: %d failure(s) ===\n", failures);
    return failures;
}
