/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the OP_RETURN catalog projection (op_return_index):
 *  1. op_return_index_extract (pure): ZNAM/ZSLP-lokad tag rendering, unknown
 *     4-byte tag, non-printable tags as hex, malformed/truncated push as a
 *     raw-byte tag, payload_len/payload_sha3.
 *  2. explorer_index_block wiring: a tx with two OP_RETURN outputs plus a
 *     P2PKH output gets exactly 2 op_return_index rows (per output, unlike
 *     the legacy per-tx op_returns table, left at 1 row); re-indexing is
 *     idempotent.
 *  3. op_return_index_fold_block_digest (pure): deterministic, sensitive to
 *     height/rows, folds height with zero rows too; base_height/base_digest
 *     are part of every preimage (the declared range).
 *  3b. Persisted cursor record: base round-trip, out-of-range cursor
 *     refused, legacy v1 record rejected loudly (truncate is the escape).
 *  4. The supervised backfill service on real on-disk blocks:
 *     op_return_backfill_run_once folds to the provable tip in one bounded
 *     batch, is idempotent, and truncate + fresh backfill reproduces the
 *     same rows and running digest.
 *  5. Declared partial coverage: on a snapshot-seeded datadir the fold
 *     adopts the seed floor as its base and fills forward. */

#include "test/test_core.h"
#include "config/command_catalog.h"
#include "command/native_command.h"
#include "controllers/op_return_index_controller.h"
#include "controllers/rpc_client.h"
#include "validation/main_state.h"
#include "models/database.h"
#include "models/explorer_index.h"
#include "models/op_return_index.h"
#include "services/op_return_backfill_service.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "script/op_return_push.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "chain/chain.h"
#include "storage/disk_block_io.h"
#include "core/serialize.h"
#include "core/amount.h"
#include "core/uint256.h"
#include "crypto/sha3.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Small shared helpers ─────────────────────────────────────────── */

static int count_rows(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
            n = sqlite3_column_int(s, 0);
    }
    if (s) sqlite3_finalize(s);
    return n;
}

/* Build "OP_RETURN <push tag> <raw rest>" into out; returns the length. */
static size_t build_opret(uint8_t *out, const uint8_t *tag, size_t tag_len,
                          const uint8_t *rest, size_t rest_len)
{
    size_t off = 0;
    out[off++] = 0x6a;
    off += push_data(out + off, tag, tag_len);
    if (rest_len) {
        memcpy(out + off, rest, rest_len);
        off += rest_len;
    }
    return off;
}

/* ── (1) Pure extract() ──────────────────────────────────────────── */

static bool test_extract_pure_rejects_non_opreturn(void)
{
    uint8_t s[] = {0x76, 0x04, 'Z', 'N', 'A', 'M'};
    struct op_return_index_row row;
    bool ok = !op_return_index_extract(s, sizeof(s), &row);
    return ok;
}

static bool test_extract_pure_rejects_null_empty(void)
{
    struct op_return_index_row row;
    bool ok = !op_return_index_extract(NULL, 0, &row) &&
              !op_return_index_extract((const uint8_t *)"", 0, &row);
    return ok;
}

static bool test_extract_pure_znam_tag_text(void)
{
    uint8_t rest[] = {0x01, 0x01, 0x01, 'a'};
    uint8_t script[64];
    size_t len = build_opret(script, (const uint8_t *)"ZNAM", 4,
                             rest, sizeof(rest));
    struct op_return_index_row row;
    bool ok = op_return_index_extract(script, len, &row) &&
              row.tag_len == 4 && memcmp(row.tag, "ZNAM", 4) == 0 &&
              strcmp(row.tag_text, "ZNAM") == 0 &&
              row.payload_len == (uint32_t)(len - 1);
    return ok;
}

static bool test_extract_pure_zslp_trims_nul(void)
{
    uint8_t lokad[4] = {'S', 'L', 'P', '\0'};
    uint8_t script[64];
    size_t len = build_opret(script, lokad, 4, NULL, 0);
    struct op_return_index_row row;
    bool ok = op_return_index_extract(script, len, &row) &&
              row.tag_len == 4 && strcmp(row.tag_text, "SLP") == 0;
    return ok;
}

static bool test_extract_pure_unknown_lokad_verbatim(void)
{
    uint8_t script[64];
    size_t len = build_opret(script, (const uint8_t *)"WXYZ", 4, NULL, 0);
    struct op_return_index_row row;
    bool ok = op_return_index_extract(script, len, &row) &&
              strcmp(row.tag_text, "WXYZ") == 0;
    return ok;
}

static bool test_extract_pure_nonprintable_hex(struct op_return_index_row *row)
{
    uint8_t tag[4] = {0x01, 0x02, 0xFE, 0xFF};
    uint8_t script[64];
    size_t len = build_opret(script, tag, 4, NULL, 0);
    bool ok = op_return_index_extract(script, len, row) &&
              strcmp(row->tag_text, "0102feff") == 0;
    return ok;
}

static bool test_extract_pure_empty_push(void)
{
    uint8_t script[2] = {0x6a, 0x00}; /* OP_RETURN OP_0 (canonical empty push) */
    struct op_return_index_row row;
    bool ok = op_return_index_extract(script, sizeof(script), &row) &&
              row.tag_len == 0 && row.tag_text[0] == '\0' &&
              row.payload_len == 1;
    return ok;
}

static bool test_extract_pure_malformed_raw_tag(void)
{
    /* OP_PUSHDATA1 claims a 0xC8-byte push but the script has only 2
     * bytes left; read_push fails. extract must still succeed via the
     * raw-prefix fallback (still "unknown lokad" cataloged). */
    uint8_t script[4] = {0x6a, 0x4c, 0xC8, 0xAB};
    struct op_return_index_row row;
    bool ok = op_return_index_extract(script, sizeof(script), &row) &&
              row.tag_len == 3 && memcmp(row.tag, script + 1, 3) == 0;
    return ok;
}

static bool test_extract_pure_payload_sha3(void)
{
    uint8_t rest[] = {0x01, 0x02, 'h', 'e', 'l', 'l', 'o'};
    uint8_t script[64];
    size_t len = build_opret(script, (const uint8_t *)"ZANC", 4,
                             rest, sizeof(rest));
    struct op_return_index_row row;
    op_return_index_extract(script, len, &row);
    uint8_t want[32];
    zcl_sha3_256(script + 1, len - 1, want);
    bool ok = memcmp(row.payload_sha3, want, 32) == 0 &&
              row.payload_len == (uint32_t)(len - 1);
    return ok;
}

static int test_extract_pure(void)
{
    int failures = 0;

    printf("op_return_index_extract: rejects non-OP_RETURN script... ");
    {
        bool ok = test_extract_pure_rejects_non_opreturn();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: rejects NULL/empty... ");
    {
        bool ok = test_extract_pure_rejects_null_empty();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: ZNAM lokad -> tag_text==\"ZNAM\"... ");
    {
        bool ok = test_extract_pure_znam_tag_text();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: ZSLP lokad \"SLP\\0\" trims to \"SLP\"... ");
    {
        bool ok = test_extract_pure_zslp_trims_nul();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: unrecognized 4-byte lokad cataloged verbatim... ");
    {
        bool ok = test_extract_pure_unknown_lokad_verbatim();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: non-printable tag falls back to hex... ");
    {
        struct op_return_index_row row;
        bool ok = test_extract_pure_nonprintable_hex(&row);
        if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", row.tag_text); failures++; }
    }

    printf("op_return_index_extract: empty push -> tag_len=0, payload_len=1... ");
    {
        bool ok = test_extract_pure_empty_push();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: malformed push falls back to raw-byte tag... ");
    {
        bool ok = test_extract_pure_malformed_raw_tag();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: payload_sha3 matches independent SHA3-256... ");
    {
        bool ok = test_extract_pure_payload_sha3();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* ── (2) explorer_index_block wiring ─────────────────────────────── */

static int test_explorer_wiring(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    printf("explorer wiring: open in-memory node.db... ");
    if (node_db_open(&ndb, ":memory:") && ndb.open) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* One tx: vout[0] ZNAM-tagged OP_RETURN, vout[1] unknown-tagged
     * OP_RETURN, vout[2] plain P2PKH. */
    struct transaction tx;
    transaction_init(&tx);
    transaction_alloc(&tx, 1, 3);
    uint256_set_null(&tx.vin[0].prevout.hash);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].sequence = 0xFFFFFFFFu;

    uint8_t znam_rest[] = {0x01, 0x01, 0x03, 'p', 'u', 'b'};
    size_t l0 = build_opret(tx.vout[0].script_pub_key.data,
                            (const uint8_t *)"ZNAM", 4,
                            znam_rest, sizeof(znam_rest));
    tx.vout[0].script_pub_key.size = l0;
    tx.vout[0].value = 0;

    size_t l1 = build_opret(tx.vout[1].script_pub_key.data,
                            (const uint8_t *)"TEST", 4, NULL, 0);
    tx.vout[1].script_pub_key.size = l1;
    tx.vout[1].value = 0;

    {
        struct script *sp = &tx.vout[2].script_pub_key;
        sp->data[0] = 0x76; sp->data[1] = 0xa9; sp->data[2] = 0x14;
        for (int i = 0; i < 20; i++) sp->data[3 + i] = (unsigned char)(0x30 + i);
        sp->data[23] = 0x88; sp->data[24] = 0xac;
        sp->size = 25;
    }
    tx.vout[2].value = 5 * COIN;
    tx.lock_time = 0;
    transaction_compute_hash(&tx);

    struct block blk;
    block_init(&blk);
    blk.vtx = &tx;
    blk.num_vtx = 1;
    blk.header.nTime = 1700000000;

    struct uint256 bhash;
    memset(bhash.data, 0x77, 32);
    struct block_index pindex;
    memset(&pindex, 0, sizeof(pindex));
    pindex.nHeight = 1;
    pindex.phashBlock = &bhash;

    uint8_t prev_receipt[32] = {0}, out_receipt[32];
    printf("explorer wiring: index the block... ");
    bool indexed = explorer_index_block(&ndb, &blk, &pindex, prev_receipt,
                                        out_receipt, NULL, NULL);
    if (indexed) printf("OK\n"); else { printf("FAIL\n"); failures++; }

    printf("explorer wiring: op_return_index has 2 rows (per-OUTPUT, not per-tx)... ");
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM op_return_index");
      if (n == 2) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer wiring: legacy op_returns still has exactly 1 row (unchanged semantics)... ");
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM op_returns");
      if (n == 1) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer wiring: vout=0 row tag_text==\"ZNAM\"... ");
    { int n = count_rows(&ndb,
        "SELECT COUNT(*) FROM op_return_index WHERE vout_n=0 AND tag_text='ZNAM'");
      if (n == 1) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer wiring: vout=1 row tag_text==\"TEST\"... ");
    { int n = count_rows(&ndb,
        "SELECT COUNT(*) FROM op_return_index WHERE vout_n=1 AND tag_text='TEST'");
      if (n == 1) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer wiring: non-OP_RETURN output (vout=2) not cataloged... ");
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM op_return_index WHERE vout_n=2");
      if (n == 0) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer wiring: tx_outputs still has 3 rows (untouched loop)... ");
    { int n = count_rows(&ndb, "SELECT COUNT(*) FROM tx_outputs");
      if (n == 3) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("explorer wiring: re-indexing the same block is idempotent (still 2 rows)... ");
    {
        uint8_t pr2[32] = {0}, or2[32];
        explorer_index_block(&ndb, &blk, &pindex, pr2, or2, NULL, NULL);
        int n = count_rows(&ndb, "SELECT COUNT(*) FROM op_return_index");
        if (n == 2) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; }
    }

    blk.vtx = NULL;
    blk.num_vtx = 0;
    transaction_free(&tx);
    node_db_close(&ndb);
    return failures;
}

/* ── (3) op_return_index_fold_block_digest (pure) ────────────────── */

static void mk_row(struct op_return_index_row *r, uint8_t txid_fill,
                   uint32_t vout_n, int32_t height, const char *tag)
{
    memset(r, 0, sizeof(*r));
    memset(r->txid, txid_fill, 32);
    r->vout_n = vout_n;
    r->height = height;
    r->tag_len = (uint8_t)strlen(tag);
    memcpy(r->tag, tag, r->tag_len);
    r->payload_len = 10;
    memset(r->payload_sha3, txid_fill, 32);
}

static int test_digest_pure(void)
{
    int failures = 0;
    uint8_t zero[32] = {0};
    uint8_t bhash[32];
    memset(bhash, 0xAA, 32);

    struct op_return_index_row rows[2];
    mk_row(&rows[0], 0x11, 0, 5, "ZNAM");
    mk_row(&rows[1], 0x22, 1, 5, "TEST");

    printf("fold_block_digest: deterministic given identical inputs... ");
    {
        uint8_t d1[32], d2[32];
        op_return_index_fold_block_digest(0, zero, zero, 5, bhash, rows, 2, d1);
        op_return_index_fold_block_digest(0, zero, zero, 5, bhash, rows, 2, d2);
        bool ok = memcmp(d1, d2, 32) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("fold_block_digest: sensitive to height... ");
    {
        uint8_t d1[32], d2[32];
        op_return_index_fold_block_digest(0, zero, zero, 5, bhash, rows, 2, d1);
        op_return_index_fold_block_digest(0, zero, zero, 6, bhash, rows, 2, d2);
        bool ok = memcmp(d1, d2, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("fold_block_digest: sensitive to row order... ");
    {
        struct op_return_index_row swapped[2] = { rows[1], rows[0] };
        uint8_t d1[32], d2[32];
        op_return_index_fold_block_digest(0, zero, zero, 5, bhash, rows, 2, d1);
        op_return_index_fold_block_digest(0, zero, zero, 5, bhash, swapped, 2,
                                          d2);
        bool ok = memcmp(d1, d2, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("fold_block_digest: an empty-row height still advances the chain "
          "(no-OP_RETURN blocks are not skipped)... ");
    {
        uint8_t d_empty[32], d_prev_carried[32];
        op_return_index_fold_block_digest(0, zero, zero, 7, bhash, NULL, 0,
                                          d_empty);
        /* Folding a DIFFERENT prev digest at the same (height, 0 rows)
         * must differ — proves prev_digest genuinely participates. */
        uint8_t other_prev[32];
        memset(other_prev, 0x99, 32);
        op_return_index_fold_block_digest(0, zero, other_prev, 7, bhash, NULL,
                                          0, d_prev_carried);
        bool ok = memcmp(d_empty, zero, 32) != 0 &&
                  memcmp(d_empty, d_prev_carried, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* ── Declared range: the base is part of the commitment ─────────── */

    printf("make_base_digest: genesis-rooted base (0, no anchor) is the "
          "all-zero IV; a based chain is not... ");
    {
        uint8_t d0[32], d1[32];
        op_return_index_make_base_digest(0, NULL, d0);
        op_return_index_make_base_digest(3196557, NULL, d1);
        bool ok = memcmp(d0, zero, 32) == 0 && memcmp(d1, zero, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("make_base_digest: deterministic, and sensitive to base_height "
          "and to the floor block hash... ");
    {
        uint8_t a[32], b[32], c[32], d[32];
        op_return_index_make_base_digest(1000, bhash, a);
        op_return_index_make_base_digest(1000, bhash, b);
        op_return_index_make_base_digest(1001, bhash, c);
        uint8_t other_hash[32];
        memset(other_hash, 0x5C, 32);
        op_return_index_make_base_digest(1000, other_hash, d);
        bool ok = memcmp(a, b, 32) == 0 && memcmp(a, c, 32) != 0 &&
                  memcmp(a, d, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("fold_block_digest: TWO DIFFERENT BASES over the SAME heights and "
          "rows produce DIFFERENT digests (a range digest can never be read "
          "as a genesis-rooted one)... ");
    {
        uint8_t base_a[32], base_b[32];
        op_return_index_make_base_digest(0, NULL, base_a);       /* genesis */
        op_return_index_make_base_digest(1000, bhash, base_b);   /* based   */

        /* Same prev, same height, same block hash, same rows — only the
         * declared base differs. */
        uint8_t da[32], db[32];
        op_return_index_fold_block_digest(0, base_a, zero, 1005, bhash,
                                          rows, 2, da);
        op_return_index_fold_block_digest(1000, base_b, zero, 1005, bhash,
                                          rows, 2, db);
        bool ok = memcmp(da, db, 32) != 0;

        /* And base_height alone is enough, even with an identical IV. */
        uint8_t dc[32], dd[32];
        op_return_index_fold_block_digest(0, base_a, zero, 1005, bhash,
                                          rows, 2, dc);
        op_return_index_fold_block_digest(7, base_a, zero, 1005, bhash,
                                          rows, 2, dd);
        ok = ok && memcmp(dc, dd, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("fold_block_digest: a based chain still folds an EMPTY height "
          "(the no-height-was-skipped property survives the base)... ");
    {
        uint8_t base_b[32];
        op_return_index_make_base_digest(1000, bhash, base_b);
        uint8_t d_empty[32], d_next[32];
        op_return_index_fold_block_digest(1000, base_b, base_b, 1000, bhash,
                                          NULL, 0, d_empty);
        op_return_index_fold_block_digest(1000, base_b, d_empty, 1001, bhash,
                                          NULL, 0, d_next);
        bool ok = memcmp(d_empty, base_b, 32) != 0 &&
                  memcmp(d_next, d_empty, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* ── (3b) Persisted cursor state: round-trip + version refusal ────── */

static int test_cursor_state_legacy_backoff(struct node_db *ndb);
static int test_cursor_state_legacy_catalog_warn(struct node_db *ndb);

static bool test_cursor_state_open_memory_db(struct node_db *ndb)
{
    bool ok = node_db_open(ndb, ":memory:") && ndb->open;
    return ok;
}

static bool test_cursor_state_empty_default(struct node_db *ndb)
{
    struct op_return_index_cursor cur;
    memset(&cur, 0xEE, sizeof(cur));
    uint8_t zero[32] = {0};
    bool ok = op_return_index_state_version(ndb) ==
                  OP_RETURN_INDEX_STATE_EMPTY &&
              op_return_index_get_cursor(ndb, &cur) &&
              cur.base_height == 0 && cur.height == -1 &&
              memcmp(cur.base_digest, zero, 32) == 0 &&
              memcmp(cur.digest, zero, 32) == 0;
    return ok;
}

static bool test_cursor_state_v2_round_trip(struct node_db *ndb)
{
    struct op_return_index_cursor set;
    memset(&set, 0, sizeof(set));
    set.base_height = 3196557;
    for (int i = 0; i < 32; i++) set.base_digest[i] = (uint8_t)(0xA0 + i);
    set.height = 3196600;
    for (int i = 0; i < 32; i++) set.digest[i] = (uint8_t)(0x10 + i);

    struct op_return_index_cursor got;
    memset(&got, 0, sizeof(got));
    bool ok = op_return_index_set_cursor(ndb, &set) &&
              op_return_index_state_version(ndb) ==
                  OP_RETURN_INDEX_STATE_V2 &&
              op_return_index_get_cursor(ndb, &got) &&
              got.base_height == set.base_height &&
              got.height == set.height &&
              memcmp(got.base_digest, set.base_digest, 32) == 0 &&
              memcmp(got.digest, set.digest, 32) == 0;
    return ok;
}

static bool test_cursor_state_bad_range_refused(struct node_db *ndb)
{
    struct op_return_index_cursor bad;
    memset(&bad, 0, sizeof(bad));
    bad.base_height = 100;
    bad.height = 50;
    bool ok = !op_return_index_set_cursor(ndb, &bad);
    return ok;
}

static bool test_cursor_state_legacy_v1_refused(struct node_db *ndb)
{
    uint8_t legacy_digest[32];
    memset(legacy_digest, 0x3C, 32);
    bool wrote =
        node_db_state_set_int(ndb, "op_return_index_cursor_height",
                              1234) &&
        node_db_state_set(ndb, "op_return_index_digest", legacy_digest,
                          32);

    struct op_return_index_cursor cur;
    memset(&cur, 0, sizeof(cur));
    cur.height = 999;
    bool refused = !op_return_index_get_cursor(ndb, &cur);
    bool named = op_return_index_state_version(ndb) ==
                 OP_RETURN_INDEX_STATE_LEGACY_V1;
    bool ok = wrote && refused && named &&
              strcmp(op_return_index_state_version_name(
                         OP_RETURN_INDEX_STATE_LEGACY_V1),
                     "legacy_v1") == 0;
    return ok;
}

static int test_cursor_state(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    printf("cursor state: open in-memory node.db... ");
    if (test_cursor_state_open_memory_db(&ndb)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    printf("cursor state: a fresh db reports EMPTY and the genesis-rooted "
          "default (base=0, height=-1)... ");
    {
        bool ok = test_cursor_state_empty_default(&ndb);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cursor state: base_height/base_digest ROUND-TRIP through the "
          "persisted v2 record... ");
    {
        bool ok = test_cursor_state_v2_round_trip(&ndb);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cursor state: set_cursor REFUSES a cursor outside its declared "
          "range (height < base_height-1)... ");
    {
        bool ok = test_cursor_state_bad_range_refused(&ndb);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    node_db_close(&ndb);

    /* ── v1 refusal, on a db that only ever saw the legacy keys ───── */
    memset(&ndb, 0, sizeof(ndb));
    printf("cursor state: fresh db for the v1-refusal case... ");
    if (test_cursor_state_open_memory_db(&ndb)) printf("OK\n");
    else { printf("FAIL\n"); return failures + 1; }

    printf("cursor state: a LEGACY v1 record is classified legacy_v1 and "
          "get_cursor REFUSES it (never reinterpreted as a v2 chain)... ");
    {
        bool ok = test_cursor_state_legacy_v1_refused(&ndb);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    failures += test_cursor_state_legacy_backoff(&ndb);

    node_db_close(&ndb);
    return failures;
}

/* Split out of test_cursor_state (cyclomatic complexity): a legacy_v1 refusal
 * logs/re-classifies once then backs off across 100 polls, the
 * catalog_completeness WARN is throttled likewise, and both clear when the
 * rebuild lands. `ndb` carries the planted legacy v1 record. */
static int test_cursor_state_legacy_backoff(struct node_db *ndb)
{
    int failures = 0;

    printf("cursor state: a legacy refusal logs/re-classifies once, then "
          "backs off across 100 repeated polls (no log storm)... ");
    {
        struct op_return_index_cursor cur;
        int64_t backoff_after_first = 0, retry_after_first = 0;
        bool ok = true;
        for (int i = 0; i < 100; i++) {
            memset(&cur, 0xEE, sizeof(cur));
            bool refused = !op_return_index_get_cursor(ndb, &cur);
            ok = ok && refused;
            int64_t backoff = atomic_load(&ndb->oprindex_legacy_backoff_secs);
            int64_t retry_at =
                atomic_load(&ndb->oprindex_legacy_retry_at_unix);
            if (i == 0) {
                /* First poll classifies + logs once and arms the initial
                 * backoff window. */
                backoff_after_first = backoff;
                retry_after_first = retry_at;
                ok = ok && backoff > 0;
            } else {
                /* Every later poll within the same backoff window must be
                 * served from the cached refusal — no re-classify, no new
                 * backoff/retry state, i.e. no repeated log. */
                ok = ok && backoff == backoff_after_first &&
                     retry_at == retry_after_first;
            }
        }
        ok = ok && op_return_index_state_is_legacy_refused(ndb) &&
             op_return_index_legacy_state_cached(ndb);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    failures += test_cursor_state_legacy_catalog_warn(ndb);
    return failures;
}

/* Split out of test_cursor_state_legacy_backoff (cyclomatic complexity):
 * catalog_completeness WARN throttle, both sides of the rebuild. `ndb` still
 * carries the legacy v1 record; also performs the documented-escape truncate. */
static int test_cursor_state_legacy_catalog_warn(struct node_db *ndb)
{
    int failures = 0;

    printf("cursor state: catalog_completeness's own legacy-state WARN "
          "fires once, then throttles across repeated calls... ");
    {
        int32_t h = -1, base = 0;
        uint64_t suppressed = 0;
        (void)op_return_index_get_cursor_heights(ndb, &h, &base);
        bool ok = op_return_index_legacy_catalog_warn_due(ndb, &suppressed);
        for (int i = 0; i < 20; i++) {
            (void)op_return_index_get_cursor_heights(ndb, &h, &base);
            bool due = op_return_index_legacy_catalog_warn_due(ndb,
                                                               &suppressed);
            ok = ok && !due;   /* throttled: keepalive is 1 hour */
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cursor state: truncate is the documented escape — it retires the "
          "v1 record and the chain reads EMPTY again... ");
    {
        struct op_return_index_cursor cur;
        memset(&cur, 0xEE, sizeof(cur));
        bool ok = op_return_index_truncate(ndb) &&
                  op_return_index_state_version(ndb) ==
                      OP_RETURN_INDEX_STATE_V2 &&
                  op_return_index_get_cursor(ndb, &cur) &&
                  cur.base_height == 0 && cur.height == -1;
        /* The rebuild also clears the cached refusal/backoff so a later legacy
         * sighting logs immediately. */
        ok = ok && atomic_load(&ndb->oprindex_legacy_backoff_secs) == 0 &&
             !op_return_index_legacy_state_cached(ndb);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cursor state: catalog_completeness's WARN stops firing once the "
          "rebuild lands... ");
    {
        int32_t h = -1, base = 0;
        uint64_t suppressed = 0;
        bool got = op_return_index_get_cursor_heights(ndb, &h, &base);
        bool due = op_return_index_legacy_catalog_warn_due(ndb, &suppressed);
        bool ok = got && !due;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

/* ── (4) Backfill service end-to-end on real on-disk blocks ──────── */

#define OPRIDX_E2E_DIR_FMT "./test-tmp/%d_opridx_e2e"
#define OPRIDX_E2E_HEIGHTS 3

struct e2e_fixture {
    char datadir[256];
    struct block_index blocks[OPRIDX_E2E_HEIGHTS];
    struct uint256 hashes[OPRIDX_E2E_HEIGHTS];
    struct main_state ms;
    struct node_db ndb;
};

/* height 0: no OP_RETURN outputs at all.
 * height 1: one ZNAM-tagged OP_RETURN + one plain output.
 * height 2: one unknown-tagged ("ABCD") OP_RETURN + one plain output. */
static bool e2e_build_block(struct block *b, int height)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = 1700000000u + (uint32_t)height;
    b->header.nBits = 0x2000ffff;
    b->header.nNonce.data[0] = (uint8_t)height;

    b->num_vtx = 1;
    b->vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    if (!b->vtx) return false;
    struct transaction *tx = &b->vtx[0];
    transaction_init(tx);

    if (height == 0) {
        transaction_alloc(tx, 1, 1);
        tx->vout[0].value = 50 * COIN; /* coinbase-style sole output */
    } else if (height == 1) {
        transaction_alloc(tx, 1, 2);
        size_t l = build_opret(tx->vout[0].script_pub_key.data,
                               (const uint8_t *)"ZNAM", 4,
                               (const uint8_t *)"\x01\x01\x01x", 4);
        tx->vout[0].script_pub_key.size = l;
        tx->vout[0].value = 0;
        tx->vout[1].value = 1 * COIN;
    } else {
        transaction_alloc(tx, 1, 2);
        size_t l = build_opret(tx->vout[0].script_pub_key.data,
                               (const uint8_t *)"ABCD", 4, NULL, 0);
        tx->vout[0].script_pub_key.size = l;
        tx->vout[0].value = 0;
        tx->vout[1].value = 2 * COIN;
    }
    tx->vin[0].sequence = 0xffffffff;
    transaction_compute_hash(tx);
    return true;
}

static bool e2e_fixture_init(struct e2e_fixture *f)
{
    memset(f, 0, sizeof(*f));
    snprintf(f->datadir, sizeof(f->datadir), OPRIDX_E2E_DIR_FMT, (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(f->datadir, 0755);
    char blocks_dir[300];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", f->datadir);
    mkdir(blocks_dir, 0755);

    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    for (int h = 0; h < OPRIDX_E2E_HEIGHTS; h++) {
        struct block b;
        if (!e2e_build_block(&b, h)) return false;

        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        bool wrote = write_block_to_disk(&b, &pos, f->datadir, msg_start);

        struct uint256 hash;
        block_get_hash(&b, &hash);
        block_free(&b);
        if (!wrote) return false;

        f->hashes[h] = hash;
        block_index_init(&f->blocks[h]);
        f->blocks[h].nHeight = h;
        f->blocks[h].phashBlock = &f->hashes[h];
        f->blocks[h].nFile = pos.nFile;
        f->blocks[h].nDataPos = pos.nPos;
        f->blocks[h].nStatus |= BLOCK_HAVE_DATA;
        if (h > 0) f->blocks[h].pprev = &f->blocks[h - 1];
    }

    active_chain_init(&f->ms.chain_active);
    active_chain_move_window_tip(&f->ms.chain_active,
                                 &f->blocks[OPRIDX_E2E_HEIGHTS - 1]);

    if (!node_db_open(&f->ndb, ":memory:") || !f->ndb.open) return false;
    return true;
}

static void e2e_fixture_free(struct e2e_fixture *f)
{
    active_chain_free(&f->ms.chain_active);
    node_db_close(&f->ndb);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", f->datadir);
     TEST_DISCARD(system(cmd));
}

static bool e2e_cursor_at_h_star(const struct op_return_index_cursor *cur)
{
    bool ok = cur->height == OPRIDX_E2E_HEIGHTS - 1 && cur->base_height == 0;
    return ok;
}

static bool e2e_truncate_resets(struct node_db *ndb)
{
    bool ok = op_return_index_truncate(ndb);
    struct op_return_index_cursor after;
    memset(&after, 0xEE, sizeof(after));
    op_return_index_get_cursor(ndb, &after);
    int rows_after = count_rows(ndb, "SELECT COUNT(*) FROM op_return_index");
    uint8_t zero[32] = {0};
    ok = ok && after.height == -1 && after.base_height == 0 &&
         rows_after == 0 &&
         memcmp(after.digest, zero, 32) == 0 &&
         memcmp(after.base_digest, zero, 32) == 0;
    return ok;
}

static int test_backfill_e2e(void)
{
    int failures = 0;
    struct e2e_fixture f;

    printf("backfill e2e: fixture (3 on-disk blocks + in-memory node.db)... ");
    if (e2e_fixture_init(&f)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    g_op_return_backfill_test_ndb = &f.ndb;
    g_op_return_backfill_test_ms = &f.ms;
    g_op_return_backfill_test_datadir = f.datadir;
    op_return_backfill_reset_for_test();
    reducer_frontier_provable_tip_set(OPRIDX_E2E_HEIGHTS - 1); /* H*=2 */

    printf("backfill e2e: one bounded batch folds all 3 blocks (0,1,2)... ");
    {
        int folded = op_return_backfill_run_once();
        if (folded == OPRIDX_E2E_HEIGHTS) printf("OK\n");
        else { printf("FAIL (got %d)\n", folded); failures++; }
    }

    printf("backfill e2e: cursor advanced to H*=2, base still genesis (0)... ");
    {
        struct op_return_index_cursor cur;
        memset(&cur, 0, sizeof(cur));
        op_return_index_get_cursor(&f.ndb, &cur);
        bool ok = e2e_cursor_at_h_star(&cur);
        if (ok)
            printf("OK\n");
        else {
            printf("FAIL (cursor=%d base=%d)\n", cur.height, cur.base_height);
            failures++;
        }
    }

    printf("backfill e2e: catalog has exactly 2 rows (h=1 ZNAM + h=2 ABCD; "
          "h=0's sole output and both plain outputs ignored)... ");
    { int n = count_rows(&f.ndb, "SELECT COUNT(*) FROM op_return_index");
      if (n == 2) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    printf("backfill e2e: rows carry the right tag_text... ");
    {
        int znam = count_rows(&f.ndb,
            "SELECT COUNT(*) FROM op_return_index WHERE height=1 AND tag_text='ZNAM'");
        int abcd = count_rows(&f.ndb,
            "SELECT COUNT(*) FROM op_return_index WHERE height=2 AND tag_text='ABCD'");
        bool ok = znam == 1 && abcd == 1;
        if (ok) printf("OK\n"); else { printf("FAIL (znam=%d abcd=%d)\n", znam, abcd); failures++; }
    }

    printf("backfill e2e: idempotent once caught up to H* (second call folds 0)... ");
    {
        int folded = op_return_backfill_run_once();
        if (folded == 0) printf("OK\n"); else { printf("FAIL (got %d)\n", folded); failures++; }
    }

    struct op_return_index_cursor before;
    memset(&before, 0, sizeof(before));
    op_return_index_get_cursor(&f.ndb, &before);
    int32_t cursor_before = before.height;
    int rows_before = count_rows(&f.ndb, "SELECT COUNT(*) FROM op_return_index");

    printf("backfill e2e: op_return_index_truncate resets cursor + rows... ");
    {
        bool ok = e2e_truncate_resets(&f.ndb);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("backfill e2e: a fresh re-derive reproduces the exact row count "
          "and the exact running digest (rebuild == original)... ");
    {
        int folded = op_return_backfill_run_once();
        int rows_after = count_rows(&f.ndb, "SELECT COUNT(*) FROM op_return_index");
        struct op_return_index_cursor after;
        memset(&after, 0, sizeof(after));
        op_return_index_get_cursor(&f.ndb, &after);
        int32_t cursor_after = after.height;
        bool ok = folded == OPRIDX_E2E_HEIGHTS &&
                  rows_after == rows_before &&
                  cursor_after == cursor_before &&
                  after.base_height == before.base_height &&
                  memcmp(after.digest, before.digest, 32) == 0;
        if (ok) printf("OK\n");
        else {
            printf("FAIL (folded=%d rows=%d/%d cursor=%d/%d)\n", folded,
                   rows_after, rows_before, cursor_after, cursor_before);
            failures++;
        }
    }

    g_op_return_backfill_test_ndb = NULL;
    g_op_return_backfill_test_ms = NULL;
    g_op_return_backfill_test_datadir = NULL;
    reducer_frontier_provable_tip_reset();
    e2e_fixture_free(&f);
    return failures;
}

/* On a seeded datadir the genesis index entry carries BLOCK_HAVE_DATA with a
 * fake (file=0, pos=0), so its body is never on disk. The fold must skip the
 * read for h=0 (genesis has no OP_RETURN outputs) and advance. */
static int test_backfill_genesis_fake_pos(void)
{
    int failures = 0;
    struct e2e_fixture f;

    printf("backfill genesis fake pos: fixture... ");
    if (e2e_fixture_init(&f)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* Re-point h=0 at offset 0: the msg_start/size prefix, not a block —
     * the same lie the block-index loader persists for genesis. */
    f.blocks[0].nFile = 0;
    f.blocks[0].nDataPos = 0;

    g_op_return_backfill_test_ndb = &f.ndb;
    g_op_return_backfill_test_ms = &f.ms;
    g_op_return_backfill_test_datadir = f.datadir;
    op_return_backfill_reset_for_test();
    reducer_frontier_provable_tip_set(OPRIDX_E2E_HEIGHTS - 1); /* H*=2 */

    printf("backfill genesis fake pos: fake h=0 pos does not wedge the fold "
          "(folds all 3 blocks, cursor reaches H*=2)... ");
    {
        int folded = op_return_backfill_run_once();
        struct op_return_index_cursor cur;
        memset(&cur, 0, sizeof(cur));
        op_return_index_get_cursor(&f.ndb, &cur);
        if (folded == OPRIDX_E2E_HEIGHTS && cur.height == OPRIDX_E2E_HEIGHTS - 1)
            printf("OK\n");
        else {
            printf("FAIL (folded=%d cursor=%d)\n", folded, cur.height);
            failures++;
        }
    }

    printf("backfill genesis fake pos: catalog rows identical to a real "
          "genesis body (h=0 contributes zero OP_RETURN rows)... ");
    { int n = count_rows(&f.ndb, "SELECT COUNT(*) FROM op_return_index");
      if (n == 2) printf("OK\n"); else { printf("FAIL (got %d)\n", n); failures++; } }

    g_op_return_backfill_test_ndb = NULL;
    g_op_return_backfill_test_ms = NULL;
    g_op_return_backfill_test_datadir = NULL;
    reducer_frontier_provable_tip_reset();
    e2e_fixture_free(&f);
    return failures;
}

/* Read one integer out of `z23 dumpstate op_return_index` (the shipped dumper,
 * not a test-only accessor). */
static int64_t oprix_dump_int(const char *key)
{
    struct json_value out;
    json_init(&out);
    int64_t v = -1;
    if (op_return_index_dump_state_json(&out, NULL)) {
        const struct json_value *f = json_get(&out, key);
        if (f) v = json_get_int(f);
    }
    json_free(&out);
    return v;
}

/* HOT-LOOP: a body the index flags BLOCK_HAVE_DATA that does not read back is
 * not transient (nothing repairs a height this far below the fold frontier),
 * so the batch must back off and latch into a named condition. `holes` is the
 * counter bumped once per failed read: it must move once, then the backoff
 * eats the tick without a read, a 2 MB buffer or a log line. The deferrals
 * are counted and the outcome stays BLOCKED, so the NO_PROGRESS clock runs. */
static int test_backfill_unreadable_body_backoff(void)
{
    int failures = 0;
    struct e2e_fixture f;
    const int RUNS = 12;

    printf("backfill unreadable-body: fixture... ");
    if (e2e_fixture_init(&f)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* Tear h=1: keep BLOCK_HAVE_DATA but point its position into the middle
     * of h=0 record, where no frame header sits (a flagged entry whose
     * (nFile,nDataPos) names bytes that are not that block). h=0 is left
     * alone so the fold wedges at h=1. */
    int32_t good_file = f.blocks[1].nFile;
    uint32_t good_pos = f.blocks[1].nDataPos;
    f.blocks[1].nFile = f.blocks[0].nFile;
    f.blocks[1].nDataPos = f.blocks[0].nDataPos + 24;

    g_op_return_backfill_test_ndb = &f.ndb;
    g_op_return_backfill_test_ms = &f.ms;
    g_op_return_backfill_test_datadir = f.datadir;
    op_return_backfill_reset_for_test();
    reducer_frontier_provable_tip_set(OPRIDX_E2E_HEIGHTS - 1); /* H*=2 */

    printf("backfill unreadable-body: the fold stops at the torn height "
          "(h=0 folds, h=1 does not)... ");
    {
        int folded = op_return_backfill_run_once();
        if (folded == 1) printf("OK\n");
        else { printf("FAIL (folded=%d)\n", folded); failures++; }
    }

    int64_t holes_after_first = oprix_dump_int("holes");
    printf("backfill unreadable-body: first failed read is counted... ");
    if (holes_after_first == 1) printf("OK\n");
    else { printf("FAIL (holes=%lld)\n", (long long)holes_after_first);
           failures++; }

    printf("backfill unreadable-body: %d further runs re-read the dead "
          "position ZERO times (backoff, not a hot loop)... ", RUNS);
    {
        for (int i = 0; i < RUNS; i++)
            (void)op_return_backfill_run_once();
        int64_t holes = oprix_dump_int("holes");
        /* One wasted block read, one 2 MB buffer and one WARN per run would be a hot loop. */
        if (holes == holes_after_first) printf("OK\n");
        else {
            printf("FAIL (holes=%lld, expected %lld — still hot-looping)\n",
                   (long long)holes, (long long)holes_after_first);
            failures++;
        }
    }

    printf("backfill unreadable-body: the deferrals are COUNTED, not "
          "swallowed... ");
    {
        int64_t deferrals = oprix_dump_int("unreadable_deferrals");
        int64_t latched = oprix_dump_int("unreadable_height");
        if (deferrals == (int64_t)RUNS && latched == 1) printf("OK\n");
        else {
            printf("FAIL (deferrals=%lld latched_height=%lld)\n",
                   (long long)deferrals, (long long)latched);
            failures++;
        }
    }

    printf("backfill unreadable-body: repairing the position clears the "
          "latch and the fold resumes... ");
    {
        /* Restore the real position, exactly as a repaired index entry would
         * look, and drop the latch the way the next due retry does. */
        f.blocks[1].nFile = good_file;
        f.blocks[1].nDataPos = good_pos;
        op_return_backfill_reset_for_test();
        (void)op_return_index_truncate(&f.ndb);
        int folded = op_return_backfill_run_once();
        int64_t latched = oprix_dump_int("unreadable_height");
        if (folded == OPRIDX_E2E_HEIGHTS && latched == -1) printf("OK\n");
        else {
            printf("FAIL (folded=%d latched=%lld)\n", folded,
                   (long long)latched);
            failures++;
        }
    }

    g_op_return_backfill_test_ndb = NULL;
    g_op_return_backfill_test_ms = NULL;
    g_op_return_backfill_test_datadir = NULL;
    reducer_frontier_provable_tip_reset();
    e2e_fixture_free(&f);
    return failures;
}

static bool e2e_check_adopted_base(struct node_db *ndb,
                                      struct op_return_index_cursor *cur)
{
    uint8_t zero[32] = {0};
    bool got = op_return_index_get_cursor(ndb, cur);
    /* "based, nothing folded yet" == base_height-1. */
    bool ok = got && cur->base_height == 2 && cur->height == 1 &&
              memcmp(cur->base_digest, zero, 32) != 0;
    return ok;
}

/* On a snapshot-seeded datadir the bodies below reducer_trusted_base_height
 * were never downloaded. The fold must adopt the seed floor as its declared
 * base and fill forward, converting the coverage limit into a named standing
 * declaration (index_fold_declare_partial_coverage) rather than a per-tick
 * spin. Fixture: heights 0 and 1 have no body (seed floor 1), height 2 does. */
static int test_backfill_declared_partial_coverage(void)
{
    int failures = 0;
    struct e2e_fixture f;

    printf("declared partial coverage: fixture... ");
    if (e2e_fixture_init(&f)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* Bodies below the seed floor are structurally absent. */
    f.blocks[0].nStatus &= ~(uint32_t)BLOCK_HAVE_DATA;
    f.blocks[1].nStatus &= ~(uint32_t)BLOCK_HAVE_DATA;

    g_op_return_backfill_test_ndb = &f.ndb;
    g_op_return_backfill_test_ms = &f.ms;
    g_op_return_backfill_test_datadir = f.datadir;
    op_return_backfill_reset_for_test();
    reducer_frontier_provable_tip_set(OPRIDX_E2E_HEIGHTS - 1);  /* H*=2 */
    atomic_store(&g_op_return_backfill_test_seed_floor, 1);     /* seed=1 */

    printf("declared partial coverage: the first run ADOPTS base_height=2 "
          "(seed_floor+1) instead of spinning below the floor... ");
    {
        (void)op_return_backfill_run_once();
        struct op_return_index_cursor cur;
        memset(&cur, 0, sizeof(cur));
        bool ok = e2e_check_adopted_base(&f.ndb, &cur);
        if (ok) printf("OK\n");
        else {
            printf("FAIL (base=%d cursor=%d)\n", cur.base_height, cur.height);
            failures++;
        }
    }

    printf("declared partial coverage: the catalog then FILLS FORWARD from "
          "the base (h=2 folds, its ABCD row lands)... ");
    {
        int folded = op_return_backfill_run_once();
        struct op_return_index_cursor cur;
        memset(&cur, 0, sizeof(cur));
        op_return_index_get_cursor(&f.ndb, &cur);
        int n = count_rows(&f.ndb, "SELECT COUNT(*) FROM op_return_index");
        int abcd = count_rows(&f.ndb,
            "SELECT COUNT(*) FROM op_return_index WHERE height=2 "
            "AND tag_text='ABCD'");
        bool ok = folded == 1 && cur.height == 2 && cur.base_height == 2 &&
                  n == 1 && abcd == 1;
        if (ok) printf("OK\n");
        else {
            printf("FAIL (folded=%d cursor=%d base=%d rows=%d abcd=%d)\n",
                   folded, cur.height, cur.base_height, n, abcd);
            failures++;
        }
    }

    printf("declared partial coverage: once caught up it is IDLE, and the "
          "base never re-adopts (a published range is not rewritten)... ");
    {
        struct op_return_index_cursor before;
        memset(&before, 0, sizeof(before));
        op_return_index_get_cursor(&f.ndb, &before);
        int folded = op_return_backfill_run_once();
        struct op_return_index_cursor after;
        memset(&after, 0, sizeof(after));
        op_return_index_get_cursor(&f.ndb, &after);
        bool ok = folded == 0 && after.base_height == before.base_height &&
                  after.height == before.height &&
                  memcmp(after.base_digest, before.base_digest, 32) == 0 &&
                  memcmp(after.digest, before.digest, 32) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL (folded=%d)\n", folded); failures++; }
    }

    printf("declared partial coverage: the based digest differs from the "
          "genesis-rooted digest over the same height... ");
    {
        struct op_return_index_cursor cur;
        memset(&cur, 0, sizeof(cur));
        op_return_index_get_cursor(&f.ndb, &cur);
        uint8_t zero[32] = {0};
        /* Re-fold h=2 from a genesis-rooted base with the SAME prev IV. */
        struct op_return_index_row rows[8];
        size_t n = 0;
        (void)rows; (void)n;
        uint8_t genesis_rooted[32];
        op_return_index_fold_block_digest(0, zero, cur.base_digest, 2,
                                          f.hashes[2].data, NULL, 0,
                                          genesis_rooted);
        bool ok = memcmp(genesis_rooted, cur.digest, 32) != 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    atomic_store(&g_op_return_backfill_test_seed_floor, -1);
    g_op_return_backfill_test_ndb = NULL;
    g_op_return_backfill_test_ms = NULL;
    g_op_return_backfill_test_datadir = NULL;
    reducer_frontier_provable_tip_reset();
    op_return_backfill_reset_for_test();
    e2e_fixture_free(&f);
    return failures;
}

/* Exercise the typed writer against the real controller/model on a file
 * fixture, including SQLite refusals after earlier reset steps succeeded. */
static struct rpc_table *g_rebuild_rpc_table;
static int g_rebuild_rpc_calls;

static char *rebuild_fixture_rpc(const char *method, const char *params_json)
{
    (void)params_json;
    g_rebuild_rpc_calls++;
    struct json_value params = {0}, result = {0};
    json_set_array(&params);
    (void)rpc_table_execute(g_rebuild_rpc_table, method, &params, &result);
    char buf[2048];
    size_t len = json_write(&result, buf, sizeof(buf));
    char *raw = len < sizeof(buf) ? strdup(buf) : NULL;
    json_free(&params);
    json_free(&result);
    return raw;
}

static bool rebuild_seed_legacy(struct node_db *ndb)
{
    struct op_return_index_row row = {0};
    uint8_t script[] = {0x6a, 4, 'T', 'E', 'S', 'T'};
    uint8_t digest[32] = {1};
    if (!op_return_index_extract(script, sizeof(script), &row))
        return false;
    row.txid[0] = 1;
    row.height = 1;
    return db_op_return_index_save(ndb, &row) &&
        node_db_state_delete(ndb, "op_return_index_state.v2") &&
        node_db_state_set_int(ndb, "op_return_index_cursor_height", 1) &&
        node_db_state_set(ndb, "op_return_index_digest", digest, sizeof(digest));
}

static bool rebuild_typed_call(const struct zcl_command_spec *spec, bool confirm,
                                bool expect_success)
{
    struct json_value input = {0};
    json_set_object(&input);
    json_push_kv_bool(&input, "confirm", confirm);
    struct zcl_command_request req = {.spec = spec, .input = &input};
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, spec->output_schema);
    zcl_native_handle_oprindex_rebuild(&req, &reply);
    bool ok = expect_success ? reply.exit_code == ZCL_COMMAND_EXIT_OK
                             : reply.exit_code != ZCL_COMMAND_EXIT_OK;
    ok = ok && reply.error.mutated == (confirm && expect_success);
    if (!confirm) {
        const char *stage = json_get_str(json_get(&reply.data, "stage"));
        ok = ok && stage && !strcmp(stage, "plan");
    }
    if (!expect_success)
        ok = ok && reply.error.message[0];
    zcl_command_reply_free(&reply);
    json_free(&input);
    return ok;
}

static bool rebuild_backfill_busy(struct node_db *ndb)
{
    if (!op_return_index_fold_try_begin()) return false;
    int folded = op_return_backfill_run_once();
    struct op_return_index_cursor cur;
    bool ok = folded == 0 && op_return_index_count(ndb) == 0 &&
              op_return_index_get_cursor(ndb, &cur) && cur.height == -1;
    op_return_index_fold_end();
    return ok;
}

static bool rebuild_file_backfill(struct node_db *ndb)
{
    struct e2e_fixture f;
    if (!e2e_fixture_init(&f)) return false;
    g_op_return_backfill_test_ndb = ndb;
    g_op_return_backfill_test_ms = &f.ms;
    g_op_return_backfill_test_datadir = f.datadir;
    op_return_backfill_reset_for_test();
    reducer_frontier_provable_tip_set(OPRIDX_E2E_HEIGHTS - 1);
    bool ok = op_return_index_rebuild(ndb) && rebuild_backfill_busy(ndb);
    ok = op_return_backfill_run_once() == OPRIDX_E2E_HEIGHTS && ok;
    struct op_return_index_cursor first, second;
    int64_t rows = op_return_index_count(ndb);
    ok = op_return_index_get_cursor(ndb, &first) && ok;
    ok = op_return_index_rebuild(ndb) && ok;
    ok = op_return_backfill_run_once() == OPRIDX_E2E_HEIGHTS && ok;
    ok = op_return_index_get_cursor(ndb, &second) && ok &&
         rows > 0 && rows == op_return_index_count(ndb) &&
         first.height == second.height &&
         memcmp(first.digest, second.digest, sizeof(first.digest)) == 0;
    g_op_return_backfill_test_ndb = NULL;
    g_op_return_backfill_test_ms = NULL;
    g_op_return_backfill_test_datadir = NULL;
    reducer_frontier_provable_tip_reset();
    e2e_fixture_free(&f);
    return ok;
}

static bool rebuild_plan_busy(struct node_db *ndb,
                               const struct zcl_command_spec *spec)
{
    if (!rebuild_seed_legacy(ndb)) return false;
    g_rebuild_rpc_calls = 0;
    bool ok = rebuild_typed_call(spec, false, true) &&
         g_rebuild_rpc_calls == 0 && op_return_index_count(ndb) == 1 &&
         op_return_index_state_is_legacy_refused(ndb);
    if (!op_return_index_fold_try_begin()) return false;
    ok = rebuild_typed_call(spec, true, false) && ok &&
         op_return_index_count(ndb) == 1 &&
         op_return_index_state_is_legacy_refused(ndb);
    op_return_index_fold_end();
    return ok;
}

static int rebuild_check(const char *claim, bool ok)
{
    printf("OP_RETURN rebuild: %s... %s\n", claim, ok ? "OK" : "FAIL");
    return !ok;
}

static bool rebuild_legacy_unchanged(struct node_db *ndb)
{
    int64_t height = -1;
    uint8_t digest[32] = {0}, expected[32] = {1}, v2[82];
    size_t len = 0;
    bool legacy = node_db_state_get_int(ndb, "op_return_index_cursor_height", &height) &&
        height == 1 &&
        node_db_state_get(ndb, "op_return_index_digest", digest, sizeof(digest), &len) &&
        len == sizeof(digest) && memcmp(digest, expected, sizeof(digest)) == 0;
    return legacy &&
        !node_db_state_get(ndb, "op_return_index_state.v2", v2, sizeof(v2), &len) &&
        count_rows(ndb, "SELECT COUNT(*) FROM rebuild_child") == 0;
}

static bool rebuild_injected_failure(struct node_db *ndb,
                                      const struct zcl_command_spec *spec,
                                      const char *trigger)
{
    bool injected = sqlite3_exec(ndb->db, trigger, NULL, NULL, NULL) == SQLITE_OK;
    bool ok = injected && rebuild_typed_call(spec, true, false) &&
         op_return_index_count(ndb) == 1 &&
         op_return_index_state_version(ndb) == OP_RETURN_INDEX_STATE_LEGACY_V1 &&
         rebuild_legacy_unchanged(ndb);
    int dropped = sqlite3_exec(ndb->db, "DROP TRIGGER IF EXISTS reject_reset", NULL, NULL, NULL);
    return dropped == SQLITE_OK && ok;
}

static int rebuild_refusals(struct node_db *ndb,
                             const struct zcl_command_spec *spec)
{
    int failures = 0;
    /* A deferred FK violation fails COMMIT, after every reset step succeeds. */
    if (sqlite3_exec(ndb->db,
        "CREATE TABLE rebuild_parent(id INTEGER PRIMARY KEY);"
        "CREATE TABLE rebuild_child(id INTEGER REFERENCES rebuild_parent(id) DEFERRABLE INITIALLY DEFERRED)",
        NULL, NULL, NULL) != SQLITE_OK) failures++;
    const char *triggers[] = {
        "CREATE TRIGGER reject_reset BEFORE DELETE ON op_return_index BEGIN SELECT RAISE(ABORT,'reset row refusal'); END",
        "CREATE TRIGGER reject_reset BEFORE DELETE ON node_state WHEN OLD.key='op_return_index_digest' BEGIN SELECT RAISE(ABORT,'reset legacy refusal'); END",
        "CREATE TRIGGER reject_reset BEFORE INSERT ON node_state WHEN NEW.key='op_return_index_state.v2' BEGIN SELECT RAISE(ABORT,'reset cursor refusal'); END",
        "CREATE TRIGGER reject_reset AFTER INSERT ON node_state WHEN NEW.key='op_return_index_state.v2' BEGIN INSERT INTO rebuild_child VALUES(1); END",
    };
    for (size_t i = 0; i < sizeof(triggers)/sizeof(triggers[0]); i++)
        failures += rebuild_check("injected failure rolls back rows and legacy cursor",
                                  rebuild_injected_failure(ndb, spec, triggers[i]));
    return failures;
}

static bool rebuild_retry_empty(struct node_db *ndb,
                                 const struct zcl_command_spec *spec)
{
    struct op_return_index_cursor cur;
    return rebuild_typed_call(spec, true, true) &&
         op_return_index_count(ndb) == 0 &&
         op_return_index_get_cursor(ndb, &cur) && cur.height == -1 &&
         cur.base_height == 0 && !op_return_index_state_is_legacy_refused(ndb);
}

static bool rebuild_reopen_empty(struct node_db *ndb, const char *path)
{
    node_db_close(ndb);
    if (!node_db_open(ndb, path)) return false;
    uint8_t value[32]; size_t len = 0;
    struct op_return_index_cursor cur;
    return op_return_index_count(ndb) == 0 &&
         op_return_index_get_cursor(ndb, &cur) && cur.height == -1 &&
         !node_db_state_get(ndb, "op_return_index_cursor_height", value, sizeof(value), &len) &&
         !node_db_state_get(ndb, "op_return_index_digest", value, sizeof(value), &len);
}

static bool rebuild_canonical_transaction(struct node_db *ndb)
{
    bool ok = rebuild_seed_legacy(ndb) && node_db_begin_immediate(ndb);
    if (ok) {
        ok = !op_return_index_rebuild(ndb) &&
             !sqlite3_get_autocommit(ndb->db) &&
             op_return_index_count(ndb) == 1;
        if (!node_db_rollback(ndb)) ok = false;
    }
    return ok;
}

static const struct zcl_command_spec *rebuild_test_spec(void)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t i = 0; i < reg->count; i++)
        if (!strcmp(reg->commands[i].path, "app.oprindex.rebuild"))
            return &reg->commands[i];
    return NULL;
}

static int test_typed_rebuild(void)
{
    int failures = 0;
    mkdir("./test-tmp", 0755);
    char dir[] = "./test-tmp/opr-rebuild-XXXXXX";
    if (!mkdtemp(dir)) return 1;
    char path[256];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb = {0};
    if (!node_db_open(&ndb, path)) { rmdir(dir); return 1; }
    struct rpc_table table;
    rpc_table_init(&table);
    rpc_op_return_index_set_state(&ndb);
    register_op_return_index_rpc_commands(&table);
    set_rpc_warmup_finished();
    g_rebuild_rpc_table = &table;
    node_rpc_client_set_test_hook(rebuild_fixture_rpc);
    const struct zcl_command_spec *spec = rebuild_test_spec();
    if (spec) {
        failures += rebuild_check("plan and busy reset preserve legacy state", rebuild_plan_busy(&ndb, spec));
        failures += rebuild_refusals(&ndb, spec);
        failures += rebuild_check("retry commits empty v2 cursor", rebuild_retry_empty(&ndb, spec));
        failures += rebuild_check("reopened file retains reset and retires both v1 keys", rebuild_reopen_empty(&ndb, path));
        failures += rebuild_check("never borrows canonical transaction", rebuild_canonical_transaction(&ndb));
        failures += rebuild_check("held guard prevents backfill; reset and backfill reproduce digest", rebuild_file_backfill(&ndb));
    } else failures++;
    node_rpc_client_set_test_hook(NULL);
    g_rebuild_rpc_table = NULL;
    rpc_op_return_index_set_state(NULL);
    node_db_close(&ndb);
    unlink(path);
    snprintf(path, sizeof(path), "%s/node.db-wal", dir); unlink(path);
    snprintf(path, sizeof(path), "%s/node.db-shm", dir); unlink(path);
    rmdir(dir);
    return failures;
}

/* ── Entry point ──────────────────────────────────────────────────── */

int test_op_return_index(void)
{
    int failures = 0;
    printf("\n=== OP_RETURN Catalog (op_return_index) Tests ===\n");
    failures += test_extract_pure();
    failures += test_explorer_wiring();
    failures += test_digest_pure();
    failures += test_cursor_state();
    failures += test_typed_rebuild();
    failures += test_backfill_e2e();
    failures += test_backfill_genesis_fake_pos();
    failures += test_backfill_unreadable_body_backoff();
    failures += test_backfill_declared_partial_coverage();
    return failures;
}
