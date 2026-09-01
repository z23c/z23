/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_refold_from_anchor_artifact_reachable — SYNC-STRENGTH Workflow-1
 * Lane-4 (fold-from-checkpoint copy-prove harness). Pins the two production
 * predicates the cold-start/recovery seam is built on
 * (engine/composition/src/boot_refold_staged.c):
 *
 *   boot_refold_from_anchor_artifact_available(ndb, &h) — the READ-ONLY probe
 *     ("is a SHA3-checkpoint-bound anchor snapshot artifact reachable for
 *     boot_refold_from_anchor_reset to load?") that gates BOTH the boot.c
 *     -load-verify-boot AUTO-ARM (via its sibling boot_load_verify_snapshot_
 *     eligible, already covered by test_load_verify_boot.c) and the sticky
 *     escalator's terminal refold rung (sticky_escalator.c:351). This file
 *     closes the gap that neither test exercised THIS exact symbol directly:
 *       - ABSENT   (no snapshot artifact at all)              -> false
 *       - MISMATCH (snapshot present, body SHA3 != checkpoint) -> false
 *       - WRONG-COUNT (clean SHA3, but claimed count != cp->utxo_count) -> false
 *       - MATCH    (snapshot verified against the checkpoint)  -> true,
 *                   *anchor_height_out == the checkpoint height
 *     Fail-closed is the point: ABSENT/MISMATCH/WRONG-COUNT must never
 *     fabricate a reachable base — a false return here is exactly what lets
 *     boot.c's do_from_anchor gate fall through to the existing (genesis or
 *     legacy-import) path instead of seeding a fake anchor.
 *
 *   boot_refold_from_anchor_reset(ndb) — on a MATCHING artifact, forces ALL
 *     EIGHT reducer stage cursors (header_admit, validate_headers, body_fetch,
 *     body_persist, script_validate, proof_validate, utxo_apply, tip_finalize)
 *     to the compiled anchor height (config/boot.h:408-419) — NOT 0/genesis —
 *     so the staged pipeline resumes folding AT the anchor over on-disk
 *     bodies. test_refold_from_anchor_fatal.c's positive control already
 *     proves coins_kv becomes the proven authority at anchor+1; this file adds
 *     the direct stage_cursor assertion (the literal "cursors start at anchor,
 *     not genesis" claim) plus the refold_from_anchor_active() floor flag.
 *
 * Snapshot-building helper mirrors lv_build_snapshot (test_load_verify_boot.c)
 * / rfa_build_snapshot (test_refold_from_anchor_fatal.c) — a tiny 3-record USS
 * body, no multi-GB artifact required. Fixtures use a throwaway progress.kv +
 * node.db under test-tmp/, exactly like those two files, so this is
 * deterministic and does not touch a live/soaking datadir.
 */

#include "test/test_core.h"

#include "chain/checkpoints.h"
#include "config/boot.h"
#include "crypto/sha3.h"
#include "jobs/reducer_frontier.h"
#include "jobs/refold_progress.h"
#include "jobs/stage_helpers.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RAA_CHECK(name, expr) do {                                    \
    printf("refold_from_anchor_artifact_reachable: %s... ", (name));  \
    if (expr) { printf("OK\n"); }                                     \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static void raa_wle32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void raa_wle64(uint8_t *p, uint64_t v)
{ for (int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }

/* Same tiny 3-record USS body shape as lv_build_snapshot / rfa_build_snapshot.
 * `tamper` flips one body byte AFTER hashing so the on-disk body SHA3 no
 * longer matches the header's claimed root (models a corrupted/forged
 * artifact without needing the real multi-GB checkpoint file). */
struct raa_built {
    uint8_t  file[8192];
    size_t   file_len;
    uint8_t  body_sha3[32];
    uint64_t count;
    int64_t  total;
};
static void raa_build_snapshot(struct raa_built *b, bool tamper, uint32_t height)
{
    uint8_t body[4096] = {0};
    size_t off = 0;
    uint8_t txid[32];
    for (int i = 0; i < 32; i++) txid[i] = (uint8_t)(0x50 + i);

    struct rec { uint32_t vout; int64_t value; uint8_t s[5]; uint32_t sl;
                 uint32_t height; uint8_t cb; };
    struct rec recs[3] = {
        { 0, 44444, {0x76,0xa9,0x14,0,0}, 3, 40, 1 },
        { 1, 55555, {0x6a,0,0,0,0},       1, 50, 0 },
        { 2, 66666, {0x21,0x02,0x03,0x04,0x05}, 5, 60, 0 },
    };
    int64_t total = 0;
    for (int i = 0; i < 3; i++) {
        memcpy(body + off, txid, 32); off += 32;
        raa_wle32(body + off, recs[i].vout); off += 4;
        raa_wle64(body + off, (uint64_t)recs[i].value); off += 8;
        raa_wle32(body + off, recs[i].sl); off += 4;
        memcpy(body + off, recs[i].s, recs[i].sl); off += recs[i].sl;
        raa_wle32(body + off, recs[i].height); off += 4;
        body[off++] = recs[i].cb;
        total += recs[i].value;
    }
    size_t body_len = off;
    b->count = 3;
    b->total = total;

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, body, body_len);
    sha3_256_finalize(&ctx, b->body_sha3);

    if (tamper) body[20] ^= 0xff;   /* on-disk body != header-claimed root */

    uint8_t header[104] = {0};
    memcpy(header, "ZCLUTXO\x00", 8);
    raa_wle32(header + 8, 1);                 /* version */
    raa_wle32(header + 16, height);            /* header's own height field —
                                                 * boot_legacy_uss_matches_
                                                 * checkpoint cross-checks this
                                                 * against checkpoint->height,
                                                 * so callers must pass the
                                                 * SAME height they install as
                                                 * the override checkpoint's
                                                 * cp.height. */
    raa_wle64(header + 24, b->count);
    raa_wle64(header + 32, (uint64_t)b->total);
    /* anchor block hash header+40 left zero */
    memcpy(header + 72, b->body_sha3, 32);     /* claimed root = CLEAN body sha3 */

    memcpy(b->file, header, 104);
    memcpy(b->file + 104, body, body_len);
    b->file_len = 104 + body_len;
}

static bool raa_write_n(const char *path, const struct raa_built *b, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t w = fwrite(b->file, 1, len, f);
    fclose(f);
    return w == len;
}

/* Read one stage's DURABLY committed cursor via the same helper the real
 * reducer stages use (jobs/stage_helpers.h) — not the in-memory accessor —
 * so the assertion reflects exactly what boot_refold_from_anchor_reset
 * committed to progress.kv. */
static bool raa_cursor_is(sqlite3 *db, const char *stage, int32_t want)
{
    uint64_t cur = 0;
    if (!stage_cursor_read_or_zero(db, stage, "raa_test", &cur))
        return false;
    return cur == (uint64_t)want;
}

int test_refold_from_anchor_artifact_reachable(void);
int test_refold_from_anchor_artifact_reachable(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "refold_from_anchor_artifact",
                     "reachable");

    struct raa_built clean, tampered;
    raa_build_snapshot(&clean, /*tamper=*/false, /*height=*/4321);
    raa_build_snapshot(&tampered, /*tamper=*/true, /*height=*/4321);

    struct sha3_utxo_checkpoint cp;
    memset(&cp, 0, sizeof(cp));
    cp.height = 4321;
    memcpy(cp.sha3_hash, clean.body_sha3, 32);
    cp.utxo_count = clean.count;
    cp.total_supply = clean.total;
    checkpoints_set_sha3_override_for_test(&cp);

    /* A throwaway node_db is enough for every sub-case below: the artifact
     * path resolves via $ZCL_MINT_ANCHOR_OUT (preferred source, per
     * mint_snapshot_path in boot_refold_staged.c) in every case that sets it,
     * and an in-memory node_db's empty db_filename naturally makes the
     * datadir-derived fallback path resolve to nothing when it is unset —
     * exactly the ABSENT contract under test. */
    struct node_db ndb;
    bool ndb_ok = node_db_open(&ndb, ":memory:");
    RAA_CHECK("node_db opens", ndb_ok);

    /* ── ABSENT: no artifact at all (env var unset, no file). ────────────── */
    {
        unsetenv("ZCL_MINT_ANCHOR_OUT");
        int32_t h = -99;
        bool avail = ndb_ok &&
            boot_refold_from_anchor_artifact_available(&ndb, &h);
        RAA_CHECK("ABSENT: artifact_available() is false", !avail);
        RAA_CHECK("ABSENT: anchor_height_out still reports the compiled "
                  "checkpoint height (the probe fails on REACHABILITY, "
                  "not on the checkpoint's own existence)",
                  h == cp.height);
    }

    /* ── MISMATCH: snapshot present, but its body SHA3 != checkpoint ─────── */
    {
        char snap[400];
        snprintf(snap, sizeof(snap), "%s/mismatch.snapshot", dir);
        RAA_CHECK("MISMATCH: tampered snapshot written",
                  raa_write_n(snap, &tampered, tampered.file_len));
        setenv("ZCL_MINT_ANCHOR_OUT", snap, 1);
        int32_t h = -99;
        bool avail = ndb_ok &&
            boot_refold_from_anchor_artifact_available(&ndb, &h);
        RAA_CHECK("MISMATCH: artifact_available() is false "
                  "(body SHA3 recompute != header-claimed root)", !avail);
        RAA_CHECK("MISMATCH: anchor_height_out still == checkpoint height",
                  h == cp.height);
    }

    /* ── WRONG-COUNT: clean SHA3, but the CHECKPOINT's claimed count differs
     * from the snapshot's own count — the count cross-check inside
     * boot_legacy_uss_matches_checkpoint, a DISTINCT guard from the SHA3
     * recompute above. ─────────────────────────────────────────────────── */
    {
        char snap[400];
        snprintf(snap, sizeof(snap), "%s/wrongcount.snapshot", dir);
        RAA_CHECK("WRONG-COUNT: clean snapshot written",
                  raa_write_n(snap, &clean, clean.file_len));
        setenv("ZCL_MINT_ANCHOR_OUT", snap, 1);

        struct sha3_utxo_checkpoint cp_bad_count = cp;
        cp_bad_count.utxo_count = clean.count + 1;  /* count guard rejects */
        checkpoints_set_sha3_override_for_test(&cp_bad_count);

        int32_t h = -99;
        bool avail = ndb_ok &&
            boot_refold_from_anchor_artifact_available(&ndb, &h);
        RAA_CHECK("WRONG-COUNT: artifact_available() is false", !avail);
        RAA_CHECK("WRONG-COUNT: anchor_height_out still == checkpoint height",
                  h == cp_bad_count.height);

        checkpoints_set_sha3_override_for_test(&cp);  /* restore */
    }

    /* ── MATCH: a genuinely verified snapshot IS reachable. ──────────────── */
    {
        char snap[400];
        snprintf(snap, sizeof(snap), "%s/match.snapshot", dir);
        RAA_CHECK("MATCH: clean snapshot written",
                  raa_write_n(snap, &clean, clean.file_len));
        setenv("ZCL_MINT_ANCHOR_OUT", snap, 1);
        int32_t h = -99;
        bool avail = ndb_ok &&
            boot_refold_from_anchor_artifact_available(&ndb, &h);
        RAA_CHECK("MATCH: artifact_available() is true", avail);
        RAA_CHECK("MATCH: anchor_height_out == checkpoint height",
                  h == cp.height);
    }

    node_db_close(&ndb);

    /* ── Cursor assertion: a MATCHING artifact drives boot_refold_from_anchor_
     * reset, which must force ALL EIGHT stage cursors to (or just past) the
     * anchor height — never 0/genesis — and mark the refold_from_anchor
     * floor flag. ───────────────────────────────────────────────────────
     *
     * Two DISTINCT cursor conventions collide at the anchor (documented at
     * engine/jobs/src/tip_finalize_anchor.c:333-345, discovered empirically
     * while writing this test — step (iii) of boot_refold_from_anchor_reset
     * first stamps all 8 cursors to the bare anchor via
     * stage_repair_force_stage_cursor, but step (iv)'s
     * tip_finalize_stage_seed_anchor() then calls
     * stage_anchor_upstream_cursors_to(db, anchor+1, ...), which RAISES the
     * 7 upstream stages from anchor to anchor+1):
     *   - the 7 UPSTREAM stages (header_admit, validate_headers, body_fetch,
     *     body_persist, script_validate, proof_validate, utxo_apply) use the
     *     "next height to process" convention — cursor == anchor+1 (the same
     *     convention as coins_applied_height, asserted separately below).
     *   - tip_finalize alone uses the "served tip" convention — cursor ==
     *     anchor exactly (cursor C means "served tip at C").
     * Both conventions land STRICTLY ABOVE 0/genesis, which is the
     * discriminating claim this test exists to pin; the exact ±1 split is
     * asserted precisely (rather than loosely as ">= anchor") so a future
     * regression that quietly changes either convention is caught.
     *
     * Uses REDUCER_FRONTIER_TRUSTED_ANCHOR (the REAL compiled mainnet anchor,
     * 3,056,758) rather than the small override height above: cursor
     * forcing (stage_repair_force_stage_cursor) is independent of the
     * checkpoint height override, and pinning to the production constant
     * makes the "not genesis" claim unambiguous (0 vs 3,056,758, not 0 vs
     * 4321). */
    {
        char pdir[300];
        snprintf(pdir, sizeof(pdir), "%s/cursor_pos", dir);
        RAA_CHECK("cursor: mkdir", mkdir(pdir, 0755) == 0 || errno == EEXIST);

        /* A DEDICATED snapshot whose header's own height field ==
         * REDUCER_FRONTIER_TRUSTED_ANCHOR: boot_legacy_uss_matches_checkpoint
         * cross-checks header->height against checkpoint->height (a distinct
         * guard from the body-SHA3/count checks the sub-cases above already
         * cover), so reusing `clean` (header height 4321) against a
         * checkpoint override at the real anchor height would spuriously
         * fail as a "component mismatch" — not what this sub-case tests. */
        struct raa_built anchor_snap;
        raa_build_snapshot(&anchor_snap, /*tamper=*/false,
                           /*height=*/(uint32_t)REDUCER_FRONTIER_TRUSTED_ANCHOR);

        char psnap[400];
        snprintf(psnap, sizeof(psnap), "%s/utxo-anchor.snapshot", pdir);
        setenv("ZCL_MINT_ANCHOR_OUT", psnap, 1);
        RAA_CHECK("cursor: matching snapshot written",
                  raa_write_n(psnap, &anchor_snap, anchor_snap.file_len));

        struct sha3_utxo_checkpoint cp_real;
        memset(&cp_real, 0, sizeof(cp_real));
        cp_real.height = REDUCER_FRONTIER_TRUSTED_ANCHOR;
        memcpy(cp_real.sha3_hash, anchor_snap.body_sha3, 32);
        cp_real.utxo_count = anchor_snap.count;
        cp_real.total_supply = anchor_snap.total;
        checkpoints_set_sha3_override_for_test(&cp_real);

        progress_store_close();
        RAA_CHECK("cursor: progress store opens", progress_store_open(pdir));
        sqlite3 *pk = progress_store_db();
        RAA_CHECK("cursor: coins_kv schema", pk && coins_kv_ensure_schema(pk));

        char pdbpath[420];
        snprintf(pdbpath, sizeof(pdbpath), "%s/node.db", pdir);
        struct node_db pndb;
        RAA_CHECK("cursor: node_db opens", node_db_open(&pndb, pdbpath));

        boot_refold_from_anchor_reset(&pndb);

        static const char *const upstream_stages[] = {
            "header_admit", "validate_headers", "body_fetch", "body_persist",
            "script_validate", "proof_validate", "utxo_apply",
        };
        bool upstream_at_anchor_plus_1 = true;
        for (size_t i = 0;
             i < sizeof(upstream_stages) / sizeof(upstream_stages[0]); i++) {
            bool ok = pk && raa_cursor_is(pk, upstream_stages[i],
                                          REDUCER_FRONTIER_TRUSTED_ANCHOR + 1);
            if (!ok)
                fprintf(stderr,
                        "  [cursor] stage=%s did NOT land at anchor+1 "
                        "(%d)\n", upstream_stages[i],
                        (int)REDUCER_FRONTIER_TRUSTED_ANCHOR + 1);
            upstream_at_anchor_plus_1 = upstream_at_anchor_plus_1 && ok;
        }
        RAA_CHECK("cursor: the 7 upstream stage cursors == anchor+1 (the "
                  "'next height to process' convention) — never 0/genesis",
                  upstream_at_anchor_plus_1);

        RAA_CHECK("cursor: tip_finalize cursor == the anchor exactly (the "
                  "'served tip' convention) — never 0/genesis",
                  pk && raa_cursor_is(pk, "tip_finalize",
                                     REDUCER_FRONTIER_TRUSTED_ANCHOR));

        /* The negative half of the same claim: none of the eight sit at 0. A
         * cursor forcer that no-ops (leaves cursors at their fresh-init
         * default) would pass the above checks trivially wrong only if the
         * anchor itself were 0; make the "not genesis" half explicit too. */
        static const char *const all_stages[] = {
            "header_admit", "validate_headers", "body_fetch", "body_persist",
            "script_validate", "proof_validate", "utxo_apply", "tip_finalize",
        };
        bool none_at_genesis = true;
        for (size_t i = 0; i < sizeof(all_stages) / sizeof(all_stages[0]); i++)
            none_at_genesis = none_at_genesis &&
                pk && !raa_cursor_is(pk, all_stages[i], 0);
        RAA_CHECK("cursor: none of the eight stage cursors sit at genesis (0)",
                  none_at_genesis);

        int32_t applied = -1;
        RAA_CHECK("cursor: coins_kv is proven authority after the reset",
                  pk && coins_kv_is_proven_authority(pk, &applied));
        RAA_CHECK("cursor: coins_applied_height == anchor+1 (utxo_apply's "
                  "next-height convention)",
                  applied == cp_real.height + 1);

        /* boot_refold_from_anchor_reset() itself does NOT mark the durable
         * refold_from_anchor floor flag — engine/composition/src/boot.c's do_from_anchor
         * caller does that in a separate step right after the reset
         * (refold_progress_mark_started_from_anchor(progress_store_db(),
         * resume_target), boot.c:3870). Mirror that exact production
         * sequence here rather than assert a behavior the reset function
         * never promised on its own. */
        RAA_CHECK("cursor: refold_progress_mark_started_from_anchor "
                  "(the boot.c caller's next step) succeeds",
                  pk && refold_progress_mark_started_from_anchor(
                            pk, cp_real.height + 1000));
        RAA_CHECK("cursor: refold_progress_refresh reads the durable flag",
                  refold_progress_refresh(pk));
        RAA_CHECK("cursor: refold_from_anchor_active() floor flag is set "
                  "(the below-anchor self-repair stays suspended until the "
                  "fold reaches the resume target)",
                  refold_from_anchor_active());

        node_db_close(&pndb);
        progress_store_close();
    }

    checkpoints_reset_sha3_override_for_test();
    unsetenv("ZCL_MINT_ANCHOR_OUT");
    test_cleanup_tmpdir(dir);
    return failures;
}
