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

/* A nullifier row whose blob is not 32 bytes must fail the collect WITHOUT
 * parking the scan cursor: an un-finalized SELECT keeps the connection's WAL
 * read snapshot pinned and wedges every later writer on that connection with
 * SQLITE_BUSY_SNAPSHOT — the 2026-09-29 node.db wedge class, on the
 * progress.kv/snapshot-export handle. The production writer always binds
 * exactly 32 bytes, so only a raw INSERT can stage the corrupt row; the
 * observable is the connection holding zero live statements afterwards
 * (the same sqlite3_next_stmt walk the db_service Shape B rail performs). */
static int sv_collect_bad_row_releases_cursor(void)
{
    int failures = 0;
    sqlite3 *db = NULL;
    struct incremental_merkle_tree sap_tree;
    struct uint256 sap_root;
    struct uint256 leaf;
    struct incremental_merkle_tree spr_tree;
    sapling_tree_init(&sap_tree);
    sv_u256(&leaf, 0x51);
    incremental_tree_append(&sap_tree, &leaf);
    incremental_tree_root(&sap_tree, &sap_root);
    sprout_tree_init(&spr_tree);

    bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK &&
              anchor_kv_reset_mark_complete_in_tx(db) &&
              anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING,
                                          &sap_tree, SEED_H, &sap_root) &&
              anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, &spr_tree, SEED_H) &&
              nullifier_kv_ensure_schema(db);
    SV_CHECK("bad-row fixture shielded state installs", ok);

    char sql[160];
    snprintf(sql, sizeof(sql),
             "INSERT INTO nullifiers(nf,pool,height) VALUES(X'"
             "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a"
             "',%d,1)", NULLIFIER_POOL_SAPLING);
    bool staged = ok &&
                  sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    SV_CHECK("31-byte nullifier row staged", staged);

    struct snapshot_shielded col;
    memset(&col, 0, sizeof(col));
    bool cok = staged && snapshot_shielded_collect_from_db(db, SEED_H, &col);
    SV_CHECK("collect fails closed on a bad nullifier blob", staged && !cok);
    snapshot_shielded_free_collected(&col);

    int leaked = 0;
    for (sqlite3_stmt *p = sqlite3_next_stmt(db, NULL); p;
         p = sqlite3_next_stmt(db, p)) {
        printf("snapshot_shielded: LEAKED statement: %s\n", sqlite3_sql(p));
        leaked++;
    }
    SV_CHECK("failed collect releases its scan cursor (no live statements)",
             leaked == 0);
    if (db)
        sqlite3_close(db);
    return failures;
}

static void sv_append_sapling_leaves(struct incremental_merkle_tree *sap_tree,
                                    struct uint256 *sap_old_root,
                                    struct uint256 *sap_root)
{
    sapling_tree_init(sap_tree);
    uint256_set_null(sap_old_root);
    for (uint8_t k = 1; k <= 3; k++) {
        struct uint256 leaf; sv_u256(&leaf, (uint8_t)(0x40 + k));
        incremental_tree_append(sap_tree, &leaf);
        if (k == 2)
            incremental_tree_root(sap_tree, sap_old_root);
    }
    incremental_tree_root(sap_tree, sap_root);
}

static void sv_append_sprout_leaves(struct incremental_merkle_tree *spr_tree)
{
    sprout_tree_init(spr_tree);
    for (uint8_t k = 1; k <= 2; k++) {
        struct uint256 leaf; sv_u256(&leaf, (uint8_t)(0x80 + k));
        incremental_tree_append(spr_tree, &leaf);
    }
}

static void sv_pack_fixture_nullifiers(uint8_t nf0[32], uint8_t nf1[32],
                                      uint8_t nf_recs[])
{
    for (int i = 0; i < 32; i++) { nf0[i] = (uint8_t)(0xc0 + i); nf1[i] = (uint8_t)(0x30 + i); }
    snapshot_shielded_pack_nf(nf_recs, 0, nf0, 12);
    snapshot_shielded_pack_nf(nf_recs + SNAPSHOT_NF_RECORD_BYTES, 1, nf1, 27);
}

static void sv_fill_anchor_hash(uint8_t anchor_hash[32])
{
    for (int i = 0; i < 32; i++)
        anchor_hash[i] = (uint8_t)(0xa0 + i);
}

static bool sv_write_seeded_snapshot(bool gate, const char *path,
                                    const uint8_t anchor_hash[32],
                                    const struct snapshot_shielded *shielded,
                                    uint8_t sha3_out[32], sqlite3 **src_out)
{
    sqlite3 *src = NULL;
    uint64_t count = 0;
    int64_t supply = 0;
    bool ok = gate &&
              sqlite3_open(":memory:", &src) == SQLITE_OK &&
              sv_seed_coins(src) &&
              coins_kv_snapshot_write(src, path, SEED_H, anchor_hash,
                                     shielded, sha3_out, &count, &supply);
    *src_out = src;
    return ok && count == 2;
}

static bool sv_snapshot_file_matches(const char *path, const char *golden_hex)
{
    FILE *f = fopen(path, "rb");
    struct sha3_256_ctx c; sha3_256_init(&c);
    uint8_t buf[4096]; size_t rd;
    while (f && (rd = fread(buf, 1, sizeof(buf), f)) > 0)
        sha3_256_write(&c, buf, rd);
    if (f) fclose(f);
    uint8_t d[32]; sha3_256_finalize(&c, d);
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + 2 * i, 3, "%02x", d[i]);
    return f != NULL && strcmp(hex, golden_hex) == 0;
}

static bool sv_shielded_regions_match(bool ok,
                                     const uint8_t *sap, uint32_t sap_len,
                                     const uint8_t *spr, uint32_t spr_len,
                                     const uint8_t *nf, uint64_t nf_count,
                                     const struct byte_stream *sap_bs,
                                     const struct byte_stream *spr_bs,
                                     const uint8_t *nf_recs, size_t nf_len)
{
    return ok && sap_len == sap_bs->size && spr_len == spr_bs->size &&
           nf_count == 2 &&
           memcmp(sap, sap_bs->data, sap_bs->size) == 0 &&
           memcmp(spr, spr_bs->data, spr_bs->size) == 0 &&
           memcmp(nf, nf_recs, nf_len) == 0;
}

static bool sv_len_and_bytes_match(bool ok, uint64_t got_len, uint64_t want_len,
                                  const void *got, const void *want, size_t n)
{
    return ok && got_len == want_len && memcmp(got, want, n) == 0;
}

static bool sv_shielded_handle_matches(bool gate, struct uss_handle *h,
                                     const struct byte_stream *sap_bs,
                                     const struct byte_stream *spr_bs,
                                     const uint8_t *nf_recs, size_t nf_len)
{
    const uint8_t *sap = NULL, *spr = NULL, *nf = NULL;
    uint32_t sap_len = 0, spr_len = 0; uint64_t nf_count = 0;
    bool got = gate && h &&
               uss_shielded(h, &sap, &sap_len, &spr, &spr_len, &nf, &nf_count);
    return sv_shielded_regions_match(got, sap, sap_len, spr, spr_len,
                                    nf, nf_count, sap_bs, spr_bs,
                                    nf_recs, nf_len);
}

static bool sv_v3_body_verified(const char *path, const uint8_t sha3[32],
                               struct uss_header *hdr, char *err, size_t err_len,
                               struct uss_handle **h_out)
{
    struct uss_handle *h = uss_open(path, /*verify_full_sha3=*/true,
                                    sha3, hdr, err, err_len);
    *h_out = h;
    return h != NULL && hdr->version == 3;
}

static void sv_v3_component_flags(struct uss_handle *h,
                                 const struct uss_header *hdr,
                                 bool *counts_ok, bool *digest_distinct)
{
    struct uss_utxo_component v3_component;
    char component_err[128] = {0};
    bool component_ok = h && uss_utxo_component_compute(
        h, &v3_component, component_err, sizeof(component_err));
    *counts_ok = component_ok && v3_component.count == 2 &&
                 v3_component.total_supply == 33333;
    *digest_distinct = component_ok &&
                       memcmp(hdr->sha3_hash, v3_component.sha3_hash, 32) != 0;
}

static bool sv_v1_has_no_shielded(const char *path, struct uss_header *hdr,
                                 char *err, size_t err_len,
                                 struct uss_handle **h_out)
{
    const uint8_t *r_sap = NULL, *r_spr = NULL, *r_nf = NULL;
    uint32_t r_sap_len = 0, r_spr_len = 0; uint64_t r_nf_count = 0;
    struct uss_handle *h = uss_open(path, true, NULL, hdr, err, err_len);
    *h_out = h;
    return h != NULL && hdr->version == 1 &&
           !uss_shielded(h, &r_sap, &r_sap_len, &r_spr, &r_spr_len,
                         &r_nf, &r_nf_count);
}

static void sv_open_tampered_snapshot(const char *path, struct uss_header *hdr,
                                     struct uss_handle **th_out)
{
    long sz = 0;
    FILE *f = fopen(path, "rb+");
    if (f) { fseek(f, 0, SEEK_END); sz = ftell(f);
             fseek(f, sz - 1, SEEK_SET);
             int c = fgetc(f); fseek(f, sz - 1, SEEK_SET);
             fputc(c ^ 0xff, f); fclose(f); }
    char terr[128] = {0};
    *th_out = uss_open(path, true, NULL, hdr, terr, sizeof(terr));
}

static bool sv_seed_shielded_rows(sqlite3 **db_out, bool history_complete,
                                 const struct incremental_merkle_tree *sap_tree,
                                 const struct incremental_merkle_tree *spr_tree,
                                 const struct uint256 *sap_root,
                                 const uint8_t nf0[32], const uint8_t nf1[32])
{
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK;
    if (history_complete)
        ok = ok && anchor_kv_reset_mark_complete_in_tx(db);
    else
        ok = ok && anchor_kv_reset_mark_empty_below_in_tx(db, SEED_H);
    ok = ok && anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING,
                                           sap_tree, SEED_H, sap_root);
    ok = ok && anchor_kv_add_tree(db, ANCHOR_POOL_SPROUT, spr_tree, SEED_H);
    if (history_complete)
        ok = ok && nullifier_kv_ensure_schema(db);
    else
        ok = ok && nullifier_kv_initialize_history(db, SEED_H);
    ok = ok && nullifier_kv_add(db, nf0, NULLIFIER_POOL_SPROUT, 12);
    ok = ok && nullifier_kv_add(db, nf1, NULLIFIER_POOL_SAPLING, 27);
    *db_out = db;
    return ok;
}

static bool sv_found_sapling_root(enum anchor_kv_lookup_result lr,
                                 const struct uint256 *got,
                                 const struct uint256 *want, int64_t height)
{
    return lr == ANCHOR_KV_FOUND && uint256_eq(got, want) && height == SEED_H;
}

static bool sv_supplied_nullifiers_retained(sqlite3 *db, const uint8_t nf0[32],
                                           const uint8_t nf1[32])
{
    bool f0 = false, f1 = false;
    return nullifier_kv_get(db, nf0, NULLIFIER_POOL_SPROUT, &f0, NULL) &&
           f0 &&
           nullifier_kv_get(db, nf1, NULLIFIER_POOL_SAPLING, &f1, NULL) &&
           f1;
}

static bool sv_omitted_sprout_incomplete(sqlite3 **db_out,
                                        const struct incremental_merkle_tree *sap_tree,
                                        const struct uint256 *sap_root)
{
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK &&
              anchor_kv_reset_mark_empty_below_in_tx(db, SEED_H) &&
              anchor_kv_seed_frontier_row(db, ANCHOR_POOL_SAPLING,
                                          sap_tree, SEED_H, sap_root);
    struct incremental_merkle_tree latest;
    struct uint256 root;
    int64_t height = -1;
    enum anchor_kv_lookup_result lr = ok ?
        anchor_kv_latest_tree(db, ANCHOR_POOL_SPROUT, &latest, &root, &height)
        : ANCHOR_KV_ERROR;
    *db_out = db;
    return ok && lr == ANCHOR_KV_HISTORY_INCOMPLETE;
}

static bool sv_birth_defect_cursor_applied(sqlite3 **db_out)
{
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK;
    /* Today's coins-only restore: reset the adoption cursor above genesis
     * over an EMPTY sapling_anchors table. */
    ok = ok && anchor_kv_reset_mark_empty_below_in_tx(db, SEED_H);
    *db_out = db;
    return ok;
}

static void sv_commit_v2_cure(struct main_state *ms,
                             const struct uint256 *sap_root,
                             const uint8_t *sap_data, uint32_t sap_len,
                             sqlite3 **db_out, bool *fixture_ok, bool *committed)
{
    main_state_init(ms);
    struct uint256 bh;
    sv_u256(&bh, 0x5a);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &bh);
    bool have_bi = bi != NULL;
    if (have_bi) {
        bi->nHeight = SEED_H;
        bi->hashFinalSaplingRoot = *sap_root;   /* header commits the seed root */
        have_bi = active_chain_install_tip_slot(&ms->chain_active, bi);
    }
    *fixture_ok = have_bi &&
                  active_chain_at(&ms->chain_active, SEED_H) == bi;
    sqlite3 *db = NULL;
    *committed = have_bi && sqlite3_open(":memory:", &db) == SQLITE_OK &&
                 sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) ==
                     SQLITE_OK &&
                 boot_shielded_cure_or_reset_in_tx(
                     db, ms, SEED_H,
                     /*sapling_verified=*/false, /*shielded_v3=*/false,
                     sap_data, sap_len,
                     NULL, 0, NULL, 0) &&
                 sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    *db_out = db;
}

static bool sv_sapling_cursor_at_seed(bool ok, sqlite3 *db)
{
    int64_t sap_cursor = -1; bool sap_found = false;
    return ok && anchor_kv_activation_cursor(db, ANCHOR_POOL_SAPLING,
                                            &sap_cursor, &sap_found) &&
           sap_found && sap_cursor == SEED_H;
}

static bool sv_collect_shielded_ok(bool ok, sqlite3 *db,
                                  struct snapshot_shielded *col)
{
    return ok && snapshot_shielded_collect_from_db(db, SEED_H, col);
}

static bool sv_reload_collected_regions(bool wok, const char *path,
                                       const uint8_t sha3[32],
                                       const struct byte_stream *sap_bs,
                                       const struct byte_stream *spr_bs,
                                       const uint8_t *nf_recs, size_t nf_len,
                                       struct uss_handle **ch_out)
{
    char cerr[128] = {0}; struct uss_header chdr;
    struct uss_handle *ch = wok ? uss_open(path, true, sha3, &chdr, cerr,
                                           sizeof(cerr)) : NULL;
    *ch_out = ch;
    return sv_shielded_handle_matches(ch && chdr.version == 3, ch,
                                     sap_bs, spr_bs, nf_recs, nf_len);
}

static bool sv_legacy_reset_committed(sqlite3 **db_out)
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
    *db_out = db;
    return ok;
}

static bool sv_legacy_markers_at_seed(bool ok, sqlite3 *db)
{
    int64_t sprout_cursor = -1, sapling_cursor = -1;
    bool sprout_found = false, sapling_found = false;
    ok = ok && anchor_kv_activation_cursor(
                   db, ANCHOR_POOL_SPROUT, &sprout_cursor, &sprout_found) &&
              anchor_kv_activation_cursor(
                   db, ANCHOR_POOL_SAPLING, &sapling_cursor, &sapling_found);
    return ok && sprout_found && sapling_found &&
           sprout_cursor == SEED_H && sapling_cursor == SEED_H &&
           sv_meta_is(db, "nullifier_kv.activation_cursor", "30");
}

static bool sv_schema_rejects_text_cursor(sqlite3 **db_out)
{
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK &&
              anchor_kv_ensure_schema(db);
    int rc = ok ? sqlite3_exec(db,
        "INSERT INTO anchor_state(pool,activation_cursor) "
        "VALUES(0,'junk')", NULL, NULL, NULL) : SQLITE_ERROR;
    *db_out = db;
    return ok && rc != SQLITE_OK;
}

static bool sv_legacy_storage_class_fails(const char *bad_value, sqlite3 **db_out)
{
    sqlite3 *db = NULL;
    bool ok = sqlite3_open(":memory:", &db) == SQLITE_OK &&
              sqlite3_exec(db,
                  "CREATE TABLE anchor_state("
                  "pool INTEGER PRIMARY KEY, activation_cursor) "
                  "WITHOUT ROWID", NULL, NULL, NULL) == SQLITE_OK;
    char sql[128];
    snprintf(sql, sizeof(sql),
             "INSERT INTO anchor_state VALUES(0,%s)", bad_value);
    ok = ok && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    int64_t cursor = 99;
    bool found = true;
    bool read_ok = ok && anchor_kv_activation_cursor(
                              db, ANCHOR_POOL_SPROUT, &cursor, &found);
    *db_out = db;
    return ok && !read_ok && !found && cursor == 0;
}

static void sv_close_sqlite(sqlite3 *db)
{
    if (db)
        sqlite3_close(db);
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
    struct uint256 sap_old_root;
    struct uint256 sap_root;
    sv_append_sapling_leaves(&sap_tree, &sap_old_root, &sap_root);
    struct uint256 empty_sap_root;
    { struct incremental_merkle_tree e; sapling_tree_init(&e);
      incremental_tree_root(&e, &empty_sap_root); }
    SV_CHECK("sapling frontier is non-empty",
             !uint256_eq(&sap_root, &empty_sap_root));

    struct byte_stream sap_bs; stream_init(&sap_bs, 4096);
    bool sap_ser = incremental_tree_serialize(&sap_tree, &sap_bs);
    SV_CHECK("sapling frontier serializes", sap_ser);

    struct incremental_merkle_tree spr_tree;
    sv_append_sprout_leaves(&spr_tree);
    struct byte_stream spr_bs; stream_init(&spr_bs, 4096);
    bool spr_ser = incremental_tree_serialize(&spr_tree, &spr_bs);
    SV_CHECK("sprout frontier serializes", spr_ser);

    /* Two nullifiers: one Sprout (pool 0), one Sapling (pool 1). */
    uint8_t nf0[32], nf1[32];
    uint8_t nf_recs[2 * SNAPSHOT_NF_RECORD_BYTES];
    sv_pack_fixture_nullifiers(nf0, nf1, nf_recs);

    struct snapshot_shielded sh = {
        .sapling = sap_bs.data, .sapling_len = (uint32_t)sap_bs.size,
        .sprout  = spr_bs.data, .sprout_len  = (uint32_t)spr_bs.size,
        .nf_records = nf_recs,  .nf_count = 2,
    };

    /* GOLDEN CAPTURE (temporary) — whole-file SHA3 of v1/v2/v3 outputs. */
    char v2_path[320];
    snprintf(v2_path, sizeof(v2_path), "%s/sapling-only-v2.snapshot", dir);

    /* ── Write the v3 snapshot (+ a v1 coins-only control) ──────────────── */
    uint8_t v3_sha3[32] = {0};
    uint8_t anchor_hash[32];
    sv_fill_anchor_hash(anchor_hash);
    {
        sqlite3 *src = NULL;
        bool ok = sv_write_seeded_snapshot(true, v3_path, anchor_hash, &sh,
                                          v3_sha3, &src);
        SV_CHECK("v3 snapshot written (coins + shielded)", ok);
        sqlite3_close(src);
    }
    {
        sqlite3 *src = NULL;
        uint8_t r[32];
        bool ok = sv_write_seeded_snapshot(true, v1_path, anchor_hash,
                                          /*shielded=*/NULL, r, &src);
        SV_CHECK("v1 coins-only control written", ok);
        sqlite3_close(src);
    }
    {
        /* Sapling-only shielded => the canonical writer emits format version 2,
         * the byte-identical twin of the historical Sapling-frontier-only file. */
        struct snapshot_shielded sap_only = {
            .sapling = sap_bs.data, .sapling_len = (uint32_t)sap_bs.size,
        };
        sqlite3 *src = NULL;
        uint8_t r[32];
        bool ok = sv_write_seeded_snapshot(true, v2_path, anchor_hash,
                                          &sap_only, r, &src);
        SV_CHECK("v2 sapling-only control written", ok);
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
            char nm[64];
            snprintf(nm, sizeof(nm),
                     "%s byte-identical to pre-refactor writer", names[p]);
            SV_CHECK(nm, sv_snapshot_file_matches(paths[p], golden[p]));
        }
    }

    /* ── Loader: single-hash verify + shielded round-trip ───────────────── */
    struct uss_header hdr; char err[128] = {0};
    struct uss_handle *h = NULL;
    bool v3_open = sv_v3_body_verified(v3_path, v3_sha3, &hdr, err, sizeof(err),
                                      &h);
    SV_CHECK("v3 body SHA3 covers coins+shielded (uss_open verifies)", v3_open);

    bool component_counts = false, digest_distinct = false;
    sv_v3_component_flags(h, &hdr, &component_counts, &digest_distinct);
    SV_CHECK("v3 independently recomputes the transparent component",
             component_counts);
    SV_CHECK("v3 full-payload digest is distinct from its UTXO commitment",
             digest_distinct);

    SV_CHECK("uss_shielded round-trips all three regions",
             sv_shielded_handle_matches(true, h, &sap_bs, &spr_bs,
                                       nf_recs, sizeof(nf_recs)));
    if (h) uss_close(h);

    /* A v1 handle exposes no shielded section. */
    h = NULL;
    bool v1_bare = sv_v1_has_no_shielded(v1_path, &hdr, err, sizeof(err), &h);
    SV_CHECK("v1 control has no shielded section", v1_bare);
    if (h) uss_close(h);

    /* Tamper: flipping a byte inside the shielded section breaks the body SHA3
     * (the single hash really commits it). */
    {
        struct uss_handle *th = NULL;
        sv_open_tampered_snapshot(v3_path, &hdr, &th);
        SV_CHECK("tampered shielded byte fails body SHA3", th == NULL);
        if (th) uss_close(th);
    }

    /* ── v3 current-state install remains history-incomplete ────────────── */
    {
        sqlite3 *db = NULL;
        /* Exact primitive sequence of boot_seed_shielded_from_snapshot: reset to
         * seed_h (historical prefix unknown), seed current frontiers, and add
         * supplied nullifier rows under a positive completeness marker. */
        bool ok = sv_seed_shielded_rows(&db, false, &sap_tree, &spr_tree,
                                       &sap_root, nf0, nf1);
        SV_CHECK("v3 current-state seed installs cleanly", ok);

        struct incremental_merkle_tree lt; struct uint256 lroot; int64_t lh = -1;
        enum anchor_kv_lookup_result lr =
            anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &lt, &lroot, &lh);
        SV_CHECK("current Sapling frontier is usable for forward folding (matches "
                 "seed root)",
                 sv_found_sapling_root(lr, &lroot, &sap_root, lh));
        SV_CHECK("current Sapling anchor row resolves by root",
                 anchor_kv_get(db, ANCHOR_POOL_SAPLING, &sap_root, NULL, NULL)
                     == ANCHOR_KV_FOUND);
        SV_CHECK("older valid Sapling root remains history-incomplete",
                 anchor_kv_get(db, ANCHOR_POOL_SAPLING, &sap_old_root,
                               NULL, NULL) == ANCHOR_KV_HISTORY_INCOMPLETE);
        SV_CHECK("supplied nullifier rows are retained",
                 sv_supplied_nullifiers_retained(db, nf0, nf1));
        SV_CHECK("supplied rows do not claim complete nullifier history",
                 sv_meta_is(db, "nullifier_kv.activation_cursor", "30"));
        sv_close_sqlite(db);
    }

    /* v3 permits an omitted Sprout frontier. That omission is never an empty
     * complete pool: the positive cursor makes current/latest lookup report an
     * actionable history gap, matching the live reducer's JoinSplit hold. */
    {
        sqlite3 *db = NULL;
        bool gap = sv_omitted_sprout_incomplete(&db, &sap_tree, &sap_root);
        SV_CHECK("omitted Sprout frontier remains HISTORY_INCOMPLETE", gap);
        sv_close_sqlite(db);
    }

    /* ── NEGATIVE control: birth-defect restore reproduces the reject ───── */
    {
        sqlite3 *db = NULL;
        bool ok = sv_birth_defect_cursor_applied(&db);
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
        sv_close_sqlite(db);
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
        sqlite3 *db = NULL;
        bool fixture_ok = false, ok = false;
        sv_commit_v2_cure(&ms, &sap_root, sap_bs.data, (uint32_t)sap_bs.size,
                          &db, &fixture_ok, &ok);
        SV_CHECK("v2 fixture: seed block_index at SEED_H with header root",
                 fixture_ok);
        SV_CHECK("v2 cure_or_reset commits (frontier co-committed)", ok);

        struct incremental_merkle_tree lt; struct uint256 lroot; int64_t lh = -1;
        enum anchor_kv_lookup_result lr = ok ?
            anchor_kv_latest_tree(db, ANCHOR_POOL_SAPLING, &lt, &lroot, &lh)
            : ANCHOR_KV_ERROR;
        SV_CHECK("CURE: v2 seed makes Sapling frontier FOUND at seed_h "
                 "(no empty-table stall)",
                 ok && sv_found_sapling_root(lr, &lroot, &sap_root, lh));
        SV_CHECK("v2 seed keeps the historical prefix incomplete "
                 "(adoption cursor == seed_h)",
                 sv_sapling_cursor_at_seed(ok, db));
        sv_close_sqlite(db);
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
        bool ok = sv_seed_shielded_rows(&db, true, &sap_tree, &spr_tree,
                                       &sap_root, nf0, nf1);
        SV_CHECK("producer fixture shielded state installs", ok);

        struct snapshot_shielded col;
        memset(&col, 0, sizeof(col));
        bool cok = sv_collect_shielded_ok(ok, db, &col);
        SV_CHECK("collect_from_db succeeds", cok);

        /* Sapling frontier round-trips (serialize of the stored tree == the
         * original serialization). */
        SV_CHECK("collected Sapling frontier matches",
                 sv_len_and_bytes_match(cok, col.sapling_len, sap_bs.size,
                                       col.sapling, sap_bs.data, sap_bs.size));
        SV_CHECK("collected Sprout frontier matches",
                 sv_len_and_bytes_match(cok, col.sprout_len, spr_bs.size,
                                       col.sprout, spr_bs.data, spr_bs.size));
        /* Nullifiers: 2 rows, deterministic (pool, nf) order == nf0 then nf1. */
        SV_CHECK("collected nullifier set matches (count + bytes)",
                 sv_len_and_bytes_match(cok, col.nf_count, 2,
                                       col.nf_records, nf_recs, sizeof(nf_recs)));

        /* collect -> write -> read closes the loop: the collected struct emits a
         * v3 snapshot whose shielded regions the loader returns unchanged. */
        char cpath[320];
        snprintf(cpath, sizeof(cpath), "%s/collected-v3.snapshot", dir);
        sqlite3 *csrc = NULL;
        uint8_t csha3[32] = {0};
        bool wok = sv_write_seeded_snapshot(cok, cpath, anchor_hash, &col,
                                           csha3, &csrc);
        SV_CHECK("collected struct writes a v3 snapshot", wok);
        sv_close_sqlite(csrc);

        struct uss_handle *ch = NULL;
        bool roundtrip = sv_reload_collected_regions(
            wok, cpath, csha3, &sap_bs, &spr_bs, nf_recs, sizeof(nf_recs), &ch);
        SV_CHECK("collected v3 snapshot loader round-trips all regions",
                 roundtrip);
        if (ch) uss_close(ch);

        snapshot_shielded_free_collected(&col);
        sv_close_sqlite(db);
    }

    /* Legacy/v1/v2 reset cannot inherit an old explicit-complete nullifier
     * marker after its rows are cleared. Both shielded histories become
     * incomplete at the seed boundary in the same outer transaction. */
    {
        sqlite3 *db = NULL;
        bool ok = sv_legacy_reset_committed(&db);
        SV_CHECK("legacy reset marks both shielded histories incomplete",
                 sv_legacy_markers_at_seed(ok, db));
        sv_close_sqlite(db);
    }

    /* Legacy dynamic-typing regression: SQLite's column_int64 would coerce
     * TEXT 'junk' to zero. Every non-INTEGER durable storage class must fail
     * closed, and the strengthened new schema must reject it at insertion. */
    {
        sqlite3 *db = NULL;
        bool rejected = sv_schema_rejects_text_cursor(&db);
        SV_CHECK("new anchor_state schema rejects non-INTEGER cursor", rejected);
        sv_close_sqlite(db);
    }
    {
        static const char *const bad_values[] = {
            "'junk'", "X'00'", "1.5",
        };
        static const char *const names[] = { "TEXT", "BLOB", "REAL" };
        for (size_t i = 0; i < sizeof(bad_values) / sizeof(bad_values[0]); i++) {
            sqlite3 *db = NULL;
            bool closed = sv_legacy_storage_class_fails(bad_values[i], &db);
            char label[96];
            snprintf(label, sizeof(label),
                     "legacy anchor cursor %s storage fails closed", names[i]);
            SV_CHECK(label, closed);
            sv_close_sqlite(db);
        }
    }

    stream_free(&sap_bs);
    stream_free(&spr_bs);

    failures += sv_collect_bad_row_releases_cursor();

    printf("=== snapshot_shielded: %d failure(s) ===\n", failures);
    return failures;
}
