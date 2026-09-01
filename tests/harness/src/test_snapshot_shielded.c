/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_snapshot_shielded — copy-prove for the UTXO-snapshot SHIELDED frontier
 * (the birth-defect cure): the canonical writer's byte-identical v1/v2/v3
 * output, the loader round-trip, fail-closed current-state restore, and the
 * producer half.
 *
 * WHAT THIS PROVES (at the exact seam that gates the first post-seed shielded
 * tx, without a 3M-block boot):
 *
 *   1. The v3 writer folds the Sapling + Sprout frontiers AND the nullifier set
 *      into the SAME body SHA3 as the coins — the artifact stays
 *      single-hash-verifiable (uss_open verify_full_sha3 accepts it; a flipped
 *      byte in the shielded section is rejected).
 *   2. The loader round-trips every shielded region byte-for-byte via
 *      uss_shielded.
 *   3. Installing v3's current frontier makes output-only folding possible but
 *      keeps activation_cursor=seed_h: an older valid anchor and any omitted
 *      Sprout history remain HISTORY_INCOMPLETE, and supplied nullifier rows do
 *      not turn into an unsupported completeness claim.
 *   4. NEGATIVE control: the SAME coins WITHOUT the frontier section (a v1
 *      snapshot) restored the old way (reset the adoption cursor above genesis
 *      over an EMPTY table) reproduces the sapling-anchor-frontier-unavailable
 *      reject — anchor_kv_latest_tree(SAPLING) == HISTORY_INCOMPLETE.
 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "chain/utxo_snapshot_loader.h"
#include "config/boot_shielded_seed.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/coins_kv.h"
#include "storage/nullifier_kv.h"
#include "storage/progress_store.h"
#include "storage/snapshot_shielded.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SV_CHECK(name, expr) do {                              \
    printf("snapshot_shielded: %s... ", (name));               \
    if (expr) printf("OK\n");                                  \
    else { printf("FAIL\n"); failures++; }                     \
} while (0)

#define SEED_H 30

static void sv_u256(struct uint256 *o, uint8_t seed)
{
    for (int i = 0; i < 32; i++) o->data[i] = (uint8_t)(seed + i * 7);
}

static void sv_txid(uint8_t out[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(seed + i * 3);
}

/* Seed a tiny coins set into an in-memory db (same shape as the other snapshot
 * test) so the v3 file has a real body under its SHA3. */
static bool sv_seed_coins(sqlite3 *db)
{
    if (!coins_kv_ensure_schema(db)) return false;
    uint8_t txid[32];
    uint8_t sa[] = {0x76, 0xa9, 0x14, 0x01, 0x02};
    uint8_t sb[] = {0x6a};
    sv_txid(txid, 0x10);
    if (!coins_kv_add(db, txid, 0, 11111, 10, true, sa, sizeof(sa)))
        return false;
    sv_txid(txid, 0x20);
    return coins_kv_add(db, txid, 2, 22222, 20, false, sb, sizeof(sb));
}

static bool sv_meta_is(sqlite3 *db, const char *key, const char *want)
{
    char buf[24] = {0};
    size_t len = 0;
    bool found = false;
    size_t want_len = strlen(want);
    return progress_meta_get(db, key, buf, sizeof(buf), &len, &found) &&
           found && len == want_len && memcmp(buf, want, want_len) == 0;
}

int test_snapshot_shielded(void)
{
    printf("\n=== snapshot_shielded ===\n");
    int failures = 0;

    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "snapshot_shielded", "main");
    char v3_path[320], v1_path[320];
    snprintf(v3_path, sizeof(v3_path), "%s/shielded-v3.snapshot", dir);
    snprintf(v1_path, sizeof(v1_path), "%s/coins-only-v1.snapshot", dir);

    /* ── Build synthetic shielded state ─────────────────────────────────── */
    struct incremental_merkle_tree sap_tree;
    sapling_tree_init(&sap_tree);
    struct uint256 sap_old_root;
    uint256_set_null(&sap_old_root);
    for (uint8_t k = 1; k <= 3; k++) {
        struct uint256 leaf; sv_u256(&leaf, (uint8_t)(0x40 + k));
        incremental_tree_append(&sap_tree, &leaf);
        if (k == 2)
            incremental_tree_root(&sap_tree, &sap_old_root);
    }
    struct uint256 sap_root; incremental_tree_root(&sap_tree, &sap_root);
    struct uint256 empty_sap_root;
    { struct incremental_merkle_tree e; sapling_tree_init(&e);
      incremental_tree_root(&e, &empty_sap_root); }
    SV_CHECK("sapling frontier is non-empty",
             !uint256_eq(&sap_root, &empty_sap_root));

    struct byte_stream sap_bs; stream_init(&sap_bs, 4096);
    bool sap_ser = incremental_tree_serialize(&sap_tree, &sap_bs);
    SV_CHECK("sapling frontier serializes", sap_ser);

    struct incremental_merkle_tree spr_tree;
    sprout_tree_init(&spr_tree);
    for (uint8_t k = 1; k <= 2; k++) {
        struct uint256 leaf; sv_u256(&leaf, (uint8_t)(0x80 + k));
        incremental_tree_append(&spr_tree, &leaf);
    }
    struct byte_stream spr_bs; stream_init(&spr_bs, 4096);
    bool spr_ser = incremental_tree_serialize(&spr_tree, &spr_bs);
    SV_CHECK("sprout frontier serializes", spr_ser);

    /* Two nullifiers: one Sprout (pool 0), one Sapling (pool 1). */
    uint8_t nf0[32], nf1[32];
    for (int i = 0; i < 32; i++) { nf0[i] = (uint8_t)(0xc0 + i); nf1[i] = (uint8_t)(0x30 + i); }
    uint8_t nf_recs[2 * SNAPSHOT_NF_RECORD_BYTES];
    snapshot_shielded_pack_nf(nf_recs, 0, nf0, 12);
    snapshot_shielded_pack_nf(nf_recs + SNAPSHOT_NF_RECORD_BYTES, 1, nf1, 27);

    struct snapshot_shielded sh = {
        .sapling = sap_bs.data, .sapling_len = (uint32_t)sap_bs.size,
        .sprout  = spr_bs.data, .sprout_len  = (uint32_t)spr_bs.size,
        .nf_records = nf_recs,  .nf_count = 2,
    };

    /* GOLDEN CAPTURE (temporary) — whole-file SHA3 of v1/v2/v3 outputs. */
    char v2_path[320];
    snprintf(v2_path, sizeof(v2_path), "%s/sapling-only-v2.snapshot", dir);

    /* ── Write the v3 snapshot (+ a v1 coins-only control) ──────────────── */
    uint8_t v3_sha3[32] = {0}; uint64_t v3_count = 0; int64_t v3_supply = 0;
    uint8_t anchor_hash[32];
    for (int i = 0; i < 32; i++) anchor_hash[i] = (uint8_t)(0xa0 + i);
    {
        sqlite3 *src = NULL;
        bool ok = sqlite3_open(":memory:", &src) == SQLITE_OK && sv_seed_coins(src);
        ok = ok && coins_kv_snapshot_write(src, v3_path, SEED_H, anchor_hash,
                                           &sh, v3_sha3, &v3_count, &v3_supply);
        SV_CHECK("v3 snapshot written (coins + shielded)", ok && v3_count == 2);
        sqlite3_close(src);
    }
    {
        sqlite3 *src = NULL;
        uint8_t r[32]; uint64_t c = 0; int64_t s = 0;
        bool ok = sqlite3_open(":memory:", &src) == SQLITE_OK && sv_seed_coins(src);
        ok = ok && coins_kv_snapshot_write(src, v1_path, SEED_H, anchor_hash,
                                           /*shielded=*/NULL, r, &c, &s);
        SV_CHECK("v1 coins-only control written", ok && c == 2);
        sqlite3_close(src);
    }
    {
        /* Sapling-only shielded => the canonical writer emits format version 2,
         * the byte-identical twin of the historical Sapling-frontier-only file. */
        struct snapshot_shielded sap_only = {
            .sapling = sap_bs.data, .sapling_len = (uint32_t)sap_bs.size,
        };
        sqlite3 *src = NULL;
        uint8_t r[32]; uint64_t c = 0; int64_t s = 0;
        bool ok = sqlite3_open(":memory:", &src) == SQLITE_OK && sv_seed_coins(src);
        ok = ok && coins_kv_snapshot_write(src, v2_path, SEED_H, anchor_hash,
                                           &sap_only, r, &c, &s);
        SV_CHECK("v2 sapling-only control written", ok && c == 2);
        sqlite3_close(src);
    }

    /* ── BYTE-IDENTITY PROOF ─────────────────────────────────────────────
     * The whole-file SHA3-256 of each artifact, PINNED to values captured from
     * the pre-refactor per-version writers (coins_kv_snapshot_write /
     * _write_v2 / _write_v3). The canonical single writer must reproduce every
     * byte of every format for the same inputs, or the on-disk format changed. */
    {
        static const char *golden[3] = {
            /* v1 (coins only)            */
            "a892a617a7d30f7f4fc2e9aaffbc8be61906b30d62a89a82447117f3b806f268",
            /* v2 (Sapling frontier only) */
            "81a2265bff4d00537f13586eceb3639024d41666d5a435e76eb7f39c97534952",
            /* v3 (full shielded section) */
            "7ae309279450b3a9ac4a503ae99dbc5d559d5aa03e710985d045cc74b633eaf5",
        };
        const char *paths[3] = { v1_path, v2_path, v3_path };
        const char *names[3] = { "v1", "v2", "v3" };
        for (int p = 0; p < 3; p++) {
            FILE *f = fopen(paths[p], "rb");
            struct sha3_256_ctx c; sha3_256_init(&c);
            uint8_t buf[4096]; size_t rd;
            while (f && (rd = fread(buf, 1, sizeof(buf), f)) > 0)
                sha3_256_write(&c, buf, rd);
            if (f) fclose(f);
            uint8_t d[32]; sha3_256_finalize(&c, d);
            char hex[65];
            for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", d[i]);
            char nm[64];
            snprintf(nm, sizeof(nm),
                     "%s byte-identical to pre-refactor writer", names[p]);
            SV_CHECK(nm, f != NULL && strcmp(hex, golden[p]) == 0);
        }
    }

    /* ── Loader: single-hash verify + shielded round-trip ───────────────── */
    struct uss_header hdr; char err[128] = {0};
    struct uss_handle *h = uss_open(v3_path, /*verify_full_sha3=*/true,
                                    v3_sha3, &hdr, err, sizeof(err));
    SV_CHECK("v3 body SHA3 covers coins+shielded (uss_open verifies)",
             h != NULL && hdr.version == 3);

    struct uss_utxo_component v3_component;
    char component_err[128] = {0};
    bool component_ok = h && uss_utxo_component_compute(
        h, &v3_component, component_err, sizeof(component_err));
    SV_CHECK("v3 independently recomputes the transparent component",
             component_ok && v3_component.count == 2 &&
             v3_component.total_supply == 33333);
    SV_CHECK("v3 full-payload digest is distinct from its UTXO commitment",
             component_ok &&
             memcmp(hdr.sha3_hash, v3_component.sha3_hash, 32) != 0);

    const uint8_t *r_sap = NULL, *r_spr = NULL, *r_nf = NULL;
    uint32_t r_sap_len = 0, r_spr_len = 0; uint64_t r_nf_count = 0;
    bool got = h && uss_shielded(h, &r_sap, &r_sap_len, &r_spr, &r_spr_len,
                                 &r_nf, &r_nf_count);
    SV_CHECK("uss_shielded round-trips all three regions",
             got && r_sap_len == sap_bs.size && r_spr_len == spr_bs.size &&
             r_nf_count == 2 &&
             memcmp(r_sap, sap_bs.data, sap_bs.size) == 0 &&
             memcmp(r_spr, spr_bs.data, spr_bs.size) == 0 &&
             memcmp(r_nf, nf_recs, sizeof(nf_recs)) == 0);
    if (h) uss_close(h);

    /* A v1 handle exposes no shielded section. */
    h = uss_open(v1_path, true, NULL, &hdr, err, sizeof(err));
    SV_CHECK("v1 control has no shielded section",
             h != NULL && hdr.version == 1 &&
             !uss_shielded(h, &r_sap, &r_sap_len, &r_spr, &r_spr_len,
                           &r_nf, &r_nf_count));
    if (h) uss_close(h);

    /* Tamper: flipping a byte inside the shielded section breaks the body SHA3
     * (the single hash really commits it). */
    {
        long sz = 0;
        FILE *f = fopen(v3_path, "rb+");
        if (f) { fseek(f, 0, SEEK_END); sz = ftell(f);
                 fseek(f, sz - 1, SEEK_SET);
                 int c = fgetc(f); fseek(f, sz - 1, SEEK_SET);
                 fputc(c ^ 0xff, f); fclose(f); }
        char terr[128] = {0};
        struct uss_handle *th = uss_open(v3_path, true, NULL, &hdr, terr,
                                         sizeof(terr));
        SV_CHECK("tampered shielded byte fails body SHA3", th == NULL);
        if (th) uss_close(th);
    }

    /* ── v3 current-state install remains history-incomplete ────────────── */
    {
        sqlite3 *db = NULL;
        bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK;
        /* Exact primitive sequence of boot_seed_shielded_from_snapshot: reset to
         * seed_h (historical prefix unknown), seed current frontiers, and add
         * supplied nullifier rows under a positive completeness marker. */
        ok = ok && anchor_kv_reset_mark_empty_below_in_tx(db, SEED_H);
        ok = ok && anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING,
                                               &sap_tree, SEED_H, &sap_root);
        ok = ok && anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, &spr_tree, SEED_H);
        ok = ok && nullifier_kv_initialize_history(db, SEED_H);
        ok = ok && nullifier_kv_add(db, nf0, NULLIFIER_POOL_SPROUT, 12);
        ok = ok && nullifier_kv_add(db, nf1, NULLIFIER_POOL_SAPLING, 27);
        SV_CHECK("v3 current-state seed installs cleanly", ok);

        struct incremental_merkle_tree lt; struct uint256 lroot; int64_t lh = -1;
        enum anchor_kv_lookup_result lr =
            anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &lt, &lroot, &lh);
        SV_CHECK("current Sapling frontier is usable for forward folding (matches "
                 "seed root)",
                 lr == ANCHOR_KV_FOUND && uint256_eq(&lroot, &sap_root) &&
                 lh == SEED_H);
        SV_CHECK("current Sapling anchor row resolves by root",
                 anchor_kv_get(db, ANCHOR_POOL_SAPLING, &sap_root, NULL, NULL)
                     == ANCHOR_KV_FOUND);
        SV_CHECK("older valid Sapling root remains history-incomplete",
                 anchor_kv_get(db, ANCHOR_POOL_SAPLING, &sap_old_root,
                               NULL, NULL) == ANCHOR_KV_HISTORY_INCOMPLETE);
        bool f0 = false, f1 = false;
        SV_CHECK("supplied nullifier rows are retained",
                 nullifier_kv_get(db, nf0, NULLIFIER_POOL_SPROUT, &f0, NULL) &&
                 f0 &&
                 nullifier_kv_get(db, nf1, NULLIFIER_POOL_SAPLING, &f1, NULL) &&
                 f1);
        SV_CHECK("supplied rows do not claim complete nullifier history",
                 sv_meta_is(db, "nullifier_kv.activation_cursor", "30"));
        if (db) sqlite3_close(db);
    }

    /* v3 permits an omitted Sprout frontier. That omission is never an empty
     * complete pool: the positive cursor makes current/latest lookup report an
     * actionable history gap, matching the live reducer's JoinSplit hold. */
    {
        sqlite3 *db = NULL;
        bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK &&
                  anchor_kv_reset_mark_empty_below_in_tx(db, SEED_H) &&
                  anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING,
                                              &sap_tree, SEED_H, &sap_root);
        struct incremental_merkle_tree latest;
        struct uint256 root;
        int64_t height = -1;
        enum anchor_kv_lookup_result lr = ok ?
            anchor_kv_latest_tree(db, ANCHOR_POOL_SPROUT, &latest, &root,
                                  &height) : ANCHOR_KV_ERROR;
        SV_CHECK("omitted Sprout frontier remains HISTORY_INCOMPLETE",
                 ok && lr == ANCHOR_KV_HISTORY_INCOMPLETE);
        if (db) sqlite3_close(db);
    }

    /* ── NEGATIVE control: birth-defect restore reproduces the reject ───── */
    {
        sqlite3 *db = NULL;
        bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK;
        /* Today's coins-only restore: reset the adoption cursor above genesis
         * over an EMPTY sapling_anchors table. */
        ok = ok && anchor_kv_reset_mark_empty_below_in_tx(db, SEED_H);
        SV_CHECK("control restore (cursor above genesis, empty table) applies",
                 ok);
        struct incremental_merkle_tree lt; struct uint256 lroot; int64_t lh = -1;
        enum anchor_kv_lookup_result lr =
            anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &lt, &lroot, &lh);
        SV_CHECK("REJECT REPRODUCED: sapling-anchor-frontier-unavailable "
                 "(latest_tree HISTORY_INCOMPLETE)",
                 lr == ANCHOR_KV_HISTORY_INCOMPLETE);
        SV_CHECK("REJECT REPRODUCED: a non-empty anchor lookup is "
                 "HISTORY_INCOMPLETE",
                 anchor_kv_get(db, ANCHOR_POOL_SAPLING, &sap_root, NULL, NULL)
                     == ANCHOR_KV_HISTORY_INCOMPLETE);
        if (db) sqlite3_close(db);
    }

    /* ── v2 seed CO-COMMITS the frontier row (birth-defect CURE at source) ─
     * The producer fix: boot_shielded_cure_or_reset_in_tx for a v2 snapshot
     * (Sapling frontier only, shielded_v3=false) now seeds the root-verified
     * Sapling frontier row in the SAME transaction as the empty-below reset, so
     * a snapshot-seeded node NEVER commits the empty-below cursor over an empty
     * sapling_anchors table. Proven at the exact seam anchor_kv_latest_tree
     * gates, without a 3M-block boot: after the seed, latest_tree(SAPLING) is
     * FOUND (not HISTORY_INCOMPLETE) yet the adoption cursor stays at seed_h
     * (historical prefix remains honestly incomplete). */
    {
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 bh;
        sv_u256(&bh, 0x5a);
        struct block_index *bi =
            chainstate_insert_block_index((struct chainstate *)&ms, &bh);
        bool have_bi = bi != NULL;
        if (have_bi) {
            bi->nHeight = SEED_H;
            bi->hashFinalSaplingRoot = sap_root;   /* header commits the seed root */
            have_bi = active_chain_install_tip_slot(&ms.chain_active, bi);
        }
        SV_CHECK("v2 fixture: seed block_index at SEED_H with header root",
                 have_bi &&
                 active_chain_at(&ms.chain_active, SEED_H) == bi);

        sqlite3 *db = NULL;
        bool ok = have_bi && sqlite3_open(":memory:", &db) == SQLITE_OK &&
                  sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) ==
                      SQLITE_OK &&
                  boot_shielded_cure_or_reset_in_tx(
                      db, &ms, SEED_H,
                      /*sapling_verified=*/false, /*shielded_v3=*/false,
                      sap_bs.data, (uint32_t)sap_bs.size,
                      NULL, 0, NULL, 0) &&
                  sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
        SV_CHECK("v2 cure_or_reset commits (frontier co-committed)", ok);

        struct incremental_merkle_tree lt; struct uint256 lroot; int64_t lh = -1;
        enum anchor_kv_lookup_result lr = ok ?
            anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &lt, &lroot, &lh)
            : ANCHOR_KV_ERROR;
        SV_CHECK("CURE: v2 seed makes Sapling frontier FOUND at seed_h "
                 "(no empty-table stall)",
                 ok && lr == ANCHOR_KV_FOUND &&
                 uint256_eq(&lroot, &sap_root) && lh == SEED_H);
        int64_t sap_cursor = -1; bool sap_found = false;
        SV_CHECK("v2 seed keeps the historical prefix incomplete "
                 "(adoption cursor == seed_h)",
                 ok && anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING,
                                                   &sap_cursor, &sap_found) &&
                 sap_found && sap_cursor == SEED_H);
        if (db) sqlite3_close(db);
        main_state_free(&ms);
    }

    /* ── PRODUCER: snapshot_shielded_collect_from_db round-trips ─────────
     * Populate a fixture db's shielded state (the reverse of the restore path),
     * collect it with the canonical producer, and prove the collected struct
     * (a) matches the known frontiers + nullifiers byte-for-byte and (b) writes
     * a v3 snapshot the loader round-trips — i.e. collect -> write -> read is a
     * closed loop for the frozen legacy v3 current-state path. */
    {
        sqlite3 *db = NULL;
        bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK;
        ok = ok && anchor_kv_reset_mark_complete_in_tx(db);
        ok = ok && anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING,
                                               &sap_tree, SEED_H, &sap_root);
        ok = ok && anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, &spr_tree, SEED_H);
        ok = ok && nullifier_kv_ensure_schema(db);
        ok = ok && nullifier_kv_add(db, nf0, NULLIFIER_POOL_SPROUT, 12);
        ok = ok && nullifier_kv_add(db, nf1, NULLIFIER_POOL_SAPLING, 27);
        SV_CHECK("producer fixture shielded state installs", ok);

        struct snapshot_shielded col;
        memset(&col, 0, sizeof(col));
        bool cok = ok && snapshot_shielded_collect_from_db(db, SEED_H, &col);
        SV_CHECK("collect_from_db succeeds", cok);

        /* Sapling frontier round-trips (serialize of the stored tree == the
         * original serialization). */
        SV_CHECK("collected Sapling frontier matches",
                 cok && col.sapling_len == sap_bs.size &&
                 memcmp(col.sapling, sap_bs.data, sap_bs.size) == 0);
        SV_CHECK("collected Sprout frontier matches",
                 cok && col.sprout_len == spr_bs.size &&
                 memcmp(col.sprout, spr_bs.data, spr_bs.size) == 0);
        /* Nullifiers: 2 rows, deterministic (pool, nf) order == nf0 then nf1. */
        SV_CHECK("collected nullifier set matches (count + bytes)",
                 cok && col.nf_count == 2 &&
                 memcmp(col.nf_records, nf_recs, sizeof(nf_recs)) == 0);

        /* collect -> write -> read closes the loop: the collected struct emits a
         * v3 snapshot whose shielded regions the loader returns unchanged. */
        char cpath[320];
        snprintf(cpath, sizeof(cpath), "%s/collected-v3.snapshot", dir);
        sqlite3 *csrc = NULL;
        uint8_t csha3[32] = {0}; uint64_t cc = 0; int64_t cs = 0;
        bool wok = cok && sqlite3_open(":memory:", &csrc) == SQLITE_OK &&
                   sv_seed_coins(csrc) &&
                   coins_kv_snapshot_write(csrc, cpath, SEED_H, anchor_hash,
                                           &col, csha3, &cc, &cs);
        SV_CHECK("collected struct writes a v3 snapshot", wok && cc == 2);
        if (csrc) sqlite3_close(csrc);

        char cerr[128] = {0}; struct uss_header chdr;
        struct uss_handle *ch = wok ? uss_open(cpath, true, csha3, &chdr, cerr,
                                               sizeof(cerr)) : NULL;
        const uint8_t *c_sap = NULL, *c_spr = NULL, *c_nf = NULL;
        uint32_t c_sap_len = 0, c_spr_len = 0; uint64_t c_nf_count = 0;
        bool rok = ch && chdr.version == 3 &&
                   uss_shielded(ch, &c_sap, &c_sap_len, &c_spr, &c_spr_len,
                                &c_nf, &c_nf_count);
        SV_CHECK("collected v3 snapshot loader round-trips all regions",
                 rok && c_sap_len == sap_bs.size && c_spr_len == spr_bs.size &&
                 c_nf_count == 2 &&
                 memcmp(c_sap, sap_bs.data, sap_bs.size) == 0 &&
                 memcmp(c_spr, spr_bs.data, spr_bs.size) == 0 &&
                 memcmp(c_nf, nf_recs, sizeof(nf_recs)) == 0);
        if (ch) uss_close(ch);

        snapshot_shielded_free_collected(&col);
        if (db) sqlite3_close(db);
    }

    /* Legacy/v1/v2 reset cannot inherit an old explicit-complete nullifier
     * marker after its rows are cleared. Both shielded histories become
     * incomplete at the seed boundary in the same outer transaction. */
    {
        sqlite3 *db = NULL;
        bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK &&
                  progress_meta_table_ensure(db) &&
                  progress_meta_set(db, "nullifier_kv.activation_cursor",
                                    "0", 1) &&
                  sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) ==
                      SQLITE_OK &&
                  boot_shielded_cure_or_reset_in_tx(
                      db, NULL, SEED_H, false, false,
                      NULL, 0, NULL, 0, NULL, 0) &&
                  sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
        int64_t sprout_cursor = -1, sapling_cursor = -1;
        bool sprout_found = false, sapling_found = false;
        ok = ok && anchor_kv_activation_cursor(
                       db, ANCHOR_POOL_SPROUT, &sprout_cursor, &sprout_found) &&
                  anchor_kv_activation_cursor(
                       db, ANCHOR_POOL_SAPLING, &sapling_cursor,
                       &sapling_found);
        SV_CHECK("legacy reset marks both shielded histories incomplete",
                 ok && sprout_found && sapling_found &&
                 sprout_cursor == SEED_H && sapling_cursor == SEED_H &&
                 sv_meta_is(db, "nullifier_kv.activation_cursor", "30"));
        if (db) sqlite3_close(db);
    }

    /* Legacy dynamic-typing regression: SQLite's column_int64 would coerce
     * TEXT 'junk' to zero. Every non-INTEGER durable storage class must fail
     * closed, and the strengthened new schema must reject it at insertion. */
    {
        sqlite3 *db = NULL;
        bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK &&
                  anchor_kv_ensure_schema(db);
        int rc = ok ? sqlite3_exec(db,
            "INSERT INTO anchor_state(pool,activation_cursor) "
            "VALUES(0,'junk')", NULL, NULL, NULL) : SQLITE_ERROR;
        SV_CHECK("new anchor_state schema rejects non-INTEGER cursor",
                 ok && rc != SQLITE_OK);
        if (db) sqlite3_close(db);
    }
    {
        static const char *const bad_values[] = {
            "'junk'", "X'00'", "1.5",
        };
        static const char *const names[] = { "TEXT", "BLOB", "REAL" };
        for (size_t i = 0; i < sizeof(bad_values) / sizeof(bad_values[0]); i++) {
            sqlite3 *db = NULL;
            bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK &&
                      sqlite3_exec(db,
                          "CREATE TABLE anchor_state("
                          "pool INTEGER PRIMARY KEY, activation_cursor) "
                          "WITHOUT ROWID", NULL, NULL, NULL) == SQLITE_OK;
            char sql[128];
            snprintf(sql, sizeof(sql),
                     "INSERT INTO anchor_state VALUES(0,%s)", bad_values[i]);
            ok = ok && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
            int64_t cursor = 99;
            bool found = true;
            bool read_ok = ok && anchor_kv_activation_cursor(
                                      db, ANCHOR_POOL_SPROUT,
                                      &cursor, &found);
            char label[96];
            snprintf(label, sizeof(label),
                     "legacy anchor cursor %s storage fails closed", names[i]);
            SV_CHECK(label, ok && !read_ok && !found && cursor == 0);
            if (db) sqlite3_close(db);
        }
    }

    stream_free(&sap_bs);
    stream_free(&spr_bs);

    printf("=== snapshot_shielded: %d failure(s) ===\n", failures);
    return failures;
}
