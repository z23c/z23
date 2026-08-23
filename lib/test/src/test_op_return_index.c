/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the OP_RETURN catalog projection (op_return_index):
 *
 *  1. op_return_index_extract (pure): ZNAM/ZSLP-lokad tag rendering,
 *     an unrecognized ("unknown lokad") 4-byte tag, non-printable tags
 *     falling back to hex, a malformed/truncated push falling back to a
 *     raw-byte tag, and payload_len/payload_sha3 correctness.
 *  2. explorer_index_block wiring: a block with a tx carrying TWO
 *     OP_RETURN outputs (ZNAM-tagged + an unknown-tagged one) plus a
 *     plain P2PKH output gets exactly 2 op_return_index rows (proving
 *     the catalog is per-OUTPUT, unlike the legacy per-tx op_returns
 *     table, which is left untouched at 1 row) and 0 rows for the
 *     non-OP_RETURN output; re-indexing the same block is idempotent.
 *  3. op_return_index_fold_block_digest (pure): deterministic given the
 *     same inputs, sensitive to height/rows, and folds height with
 *     zero rows too (so the digest also proves no height was skipped);
 *     plus the DECLARED RANGE — base_height/base_digest are part of every
 *     preimage, so two different bases over the same heights and rows
 *     produce different digests.
 *  3b. The persisted cursor record: base_height/base_digest round-trip,
 *     a cursor outside its declared range is refused, and a LEGACY v1
 *     record is rejected LOUDLY (never reinterpreted as v2), with
 *     truncate as the documented escape.
 *  4. The supervised backfill service end-to-end on real on-disk
 *     blocks: op_return_backfill_run_once folds the whole chain up to
 *     the (test-set) provable tip in one bounded batch, is idempotent
 *     once caught up, and op_return_index_truncate + a fresh backfill
 *     run reproduces the exact same row set and running digest
 *     ("rebuildable + integrity").
 *  5. DECLARED PARTIAL COVERAGE: on a snapshot-seeded datadir (bodies
 *     below the seed floor structurally absent) the fold adopts the floor
 *     as its base and fills forward from there instead of spinning below
 *     it forever — the live defect this range-declaring digest exists
 *     for. */

#include "test/test_core.h"
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

static int test_extract_pure(void)
{
    int failures = 0;

    printf("op_return_index_extract: rejects non-OP_RETURN script... ");
    {
        uint8_t s[] = {0x76, 0x04, 'Z', 'N', 'A', 'M'};
        struct op_return_index_row row;
        bool ok = !op_return_index_extract(s, sizeof(s), &row);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: rejects NULL/empty... ");
    {
        struct op_return_index_row row;
        bool ok = !op_return_index_extract(NULL, 0, &row) &&
                  !op_return_index_extract((const uint8_t *)"", 0, &row);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: ZNAM lokad -> tag_text==\"ZNAM\"... ");
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
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: ZSLP lokad \"SLP\\0\" trims to \"SLP\"... ");
    {
        uint8_t lokad[4] = {'S', 'L', 'P', '\0'};
        uint8_t script[64];
        size_t len = build_opret(script, lokad, 4, NULL, 0);
        struct op_return_index_row row;
        bool ok = op_return_index_extract(script, len, &row) &&
                  row.tag_len == 4 && strcmp(row.tag_text, "SLP") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: unrecognized 4-byte lokad cataloged verbatim... ");
    {
        uint8_t script[64];
        size_t len = build_opret(script, (const uint8_t *)"WXYZ", 4, NULL, 0);
        struct op_return_index_row row;
        bool ok = op_return_index_extract(script, len, &row) &&
                  strcmp(row.tag_text, "WXYZ") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: non-printable tag falls back to hex... ");
    {
        uint8_t tag[4] = {0x01, 0x02, 0xFE, 0xFF};
        uint8_t script[64];
        size_t len = build_opret(script, tag, 4, NULL, 0);
        struct op_return_index_row row;
        bool ok = op_return_index_extract(script, len, &row) &&
                  strcmp(row.tag_text, "0102feff") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL (%s)\n", row.tag_text); failures++; }
    }

    printf("op_return_index_extract: empty push -> tag_len=0, payload_len=1... ");
    {
        uint8_t script[2] = {0x6a, 0x00}; /* OP_RETURN OP_0 (canonical empty push) */
        struct op_return_index_row row;
        bool ok = op_return_index_extract(script, sizeof(script), &row) &&
                  row.tag_len == 0 && row.tag_text[0] == '\0' &&
                  row.payload_len == 1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: malformed push falls back to raw-byte tag... ");
    {
        /* OP_PUSHDATA1 claims a 0xC8-byte push but the script has only 2
         * bytes left; read_push fails. extract must still succeed via the
         * raw-prefix fallback (still "unknown lokad" cataloged). */
        uint8_t script[4] = {0x6a, 0x4c, 0xC8, 0xAB};
        struct op_return_index_row row;
        bool ok = op_return_index_extract(script, sizeof(script), &row) &&
                  row.tag_len == 3 && memcmp(row.tag, script + 1, 3) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("op_return_index_extract: payload_sha3 matches independent SHA3-256... ");
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

static int test_cursor_state(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    printf("cursor state: open in-memory node.db... ");
    if (node_db_open(&ndb, ":memory:") && ndb.open) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    printf("cursor state: a fresh db reports EMPTY and the genesis-rooted "
          "default (base=0, height=-1)... ");
    {
        struct op_return_index_cursor cur;
        memset(&cur, 0xEE, sizeof(cur));
        uint8_t zero[32] = {0};
        bool ok = op_return_index_state_version(&ndb) ==
                      OP_RETURN_INDEX_STATE_EMPTY &&
                  op_return_index_get_cursor(&ndb, &cur) &&
                  cur.base_height == 0 && cur.height == -1 &&
                  memcmp(cur.base_digest, zero, 32) == 0 &&
                  memcmp(cur.digest, zero, 32) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cursor state: base_height/base_digest ROUND-TRIP through the "
          "persisted v2 record... ");
    {
        struct op_return_index_cursor set;
        memset(&set, 0, sizeof(set));
        set.base_height = 3196557;
        for (int i = 0; i < 32; i++) set.base_digest[i] = (uint8_t)(0xA0 + i);
        set.height = 3196600;
        for (int i = 0; i < 32; i++) set.digest[i] = (uint8_t)(0x10 + i);

        struct op_return_index_cursor got;
        memset(&got, 0, sizeof(got));
        bool ok = op_return_index_set_cursor(&ndb, &set) &&
                  op_return_index_state_version(&ndb) ==
                      OP_RETURN_INDEX_STATE_V2 &&
                  op_return_index_get_cursor(&ndb, &got) &&
                  got.base_height == set.base_height &&
                  got.height == set.height &&
                  memcmp(got.base_digest, set.base_digest, 32) == 0 &&
                  memcmp(got.digest, set.digest, 32) == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cursor state: set_cursor REFUSES a cursor outside its declared "
          "range (height < base_height-1)... ");
    {
        struct op_return_index_cursor bad;
        memset(&bad, 0, sizeof(bad));
        bad.base_height = 100;
        bad.height = 50;
        bool ok = !op_return_index_set_cursor(&ndb, &bad);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    node_db_close(&ndb);

    /* ── v1 refusal, on a db that only ever saw the legacy keys ───── */
    memset(&ndb, 0, sizeof(ndb));
    printf("cursor state: fresh db for the v1-refusal case... ");
    if (node_db_open(&ndb, ":memory:") && ndb.open) printf("OK\n");
    else { printf("FAIL\n"); return failures + 1; }

    printf("cursor state: a LEGACY v1 record is classified legacy_v1 and "
          "get_cursor REFUSES it (never reinterpreted as a v2 chain)... ");
    {
        uint8_t legacy_digest[32];
        memset(legacy_digest, 0x3C, 32);
        bool wrote =
            node_db_state_set_int(&ndb, "op_return_index_cursor_height",
                                  1234) &&
            node_db_state_set(&ndb, "op_return_index_digest", legacy_digest,
                              32);

        struct op_return_index_cursor cur;
        memset(&cur, 0, sizeof(cur));
        cur.height = 999;
        bool refused = !op_return_index_get_cursor(&ndb, &cur);
        bool named = op_return_index_state_version(&ndb) ==
                     OP_RETURN_INDEX_STATE_LEGACY_V1;
        bool ok = wrote && refused && named &&
                  strcmp(op_return_index_state_version_name(
                             OP_RETURN_INDEX_STATE_LEGACY_V1),
                         "legacy_v1") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("cursor state: truncate is the documented escape — it retires the "
          "v1 record and the chain reads EMPTY again... ");
    {
        struct op_return_index_cursor cur;
        memset(&cur, 0xEE, sizeof(cur));
        bool ok = op_return_index_truncate(&ndb) &&
                  op_return_index_state_version(&ndb) ==
                      OP_RETURN_INDEX_STATE_V2 &&
                  op_return_index_get_cursor(&ndb, &cur) &&
                  cur.base_height == 0 && cur.height == -1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    node_db_close(&ndb);
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
    (void)system(cmd);
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
        if (cur.height == OPRIDX_E2E_HEIGHTS - 1 && cur.base_height == 0)
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
        bool ok = op_return_index_truncate(&f.ndb);
        struct op_return_index_cursor after;
        memset(&after, 0xEE, sizeof(after));
        op_return_index_get_cursor(&f.ndb, &after);
        int rows_after = count_rows(&f.ndb, "SELECT COUNT(*) FROM op_return_index");
        uint8_t zero[32] = {0};
        ok = ok && after.height == -1 && after.base_height == 0 &&
             rows_after == 0 &&
             memcmp(after.digest, zero, 32) == 0 &&
             memcmp(after.base_digest, zero, 32) == 0;
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

/* Regression: on a seeded datadir the genesis index entry carries
 * BLOCK_HAVE_DATA with a fake (file=0, pos=0) — its body is never on disk,
 * so a pread hashes whatever sits at offset 0 and the backfill wedged on
 * h=0 forever (~100k mismatch lines in node.log). The fold must skip the
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

/* Read one integer out of `z23 dumpstate op_return_index`. Reading the shipped
 * dumper (rather than a test-only accessor) keeps the assertion honest: the
 * number the operator sees is the number under test. */
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

/* HOT-LOOP REGRESSION. A body the index flags BLOCK_HAVE_DATA but that does
 * NOT read back is not a transient — nothing in this process repairs a height
 * this far below the fold frontier (have_data_unreadable only inspects tip+1
 * and the reducer stages). Live 2026-08-23 on node1 this service re-read h=1
 * every ~3 s for 14.5 h: 12,435 identical failures, 12,435 identical WARN
 * lines, and not one of them could ever have succeeded.
 *
 * The batch must back off and latch into a named condition instead. `holes` is
 * the pre-existing counter the fold bumps once per failed read, so it counts
 * the READS: pre-fix it climbed once per run (a true hot loop), post-fix it
 * moves once and then the backoff eats the tick without a read, a 2 MB buffer
 * or a log line. The blocker is the report, not a silencer — the deferrals are
 * counted and the outcome stays BLOCKED, so the supervisor's NO_PROGRESS quiet
 * clock still runs. */
static int test_backfill_unreadable_body_backoff(void)
{
    int failures = 0;
    struct e2e_fixture f;
    const int RUNS = 12;

    printf("backfill unreadable-body: fixture... ");
    if (e2e_fixture_init(&f)) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    /* Tear h=1's position: keep BLOCK_HAVE_DATA (the index still CLAIMS the
     * body) but point it into the middle of h=0's record, where no frame
     * header sits. This is the live shape — a foreign writer's appends over a
     * hardlinked blk file leave exactly this: a flagged entry whose recorded
     * (nFile,nDataPos) names bytes that are not that block. h=0 is left alone
     * so the fold takes its first step and then wedges at h=1. */
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
        /* Pre-fix this was 1 + RUNS: one wasted block read, one 2 MB buffer
         * and one WARN line per run, forever. */
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

/* The live defect this whole change exists for: on a snapshot-seeded datadir
 * the bodies below reducer_trusted_base_height were NEVER downloaded, so the
 * from-genesis fold could never take its first step. The canonical node sat at
 * total_rows=0, cursor_height=0, holes=2883, with
 * op_return_index.below_snapshot_seed fired 2,877 times and remedy=OWNER.
 *
 * The fold must instead ADOPT the seed floor as its declared base and fill
 * forward from there, with the coverage limit converted into a named standing
 * declaration (index_fold_declare_partial_coverage) rather than a per-tick
 * spin. Fixture: heights 0 and 1 have no body (below the seed floor of 1),
 * height 2 does. */
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
        uint8_t zero[32] = {0};
        bool got = op_return_index_get_cursor(&f.ndb, &cur);
        /* "based, nothing folded yet" == base_height-1. */
        bool ok = got && cur.base_height == 2 && cur.height == 1 &&
                  memcmp(cur.base_digest, zero, 32) != 0;
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

/* ── Entry point ──────────────────────────────────────────────────── */

int test_op_return_index(void)
{
    int failures = 0;
    printf("\n=== OP_RETURN Catalog (op_return_index) Tests ===\n");
    failures += test_extract_pure();
    failures += test_explorer_wiring();
    failures += test_digest_pure();
    failures += test_cursor_state();
    failures += test_backfill_e2e();
    failures += test_backfill_genesis_fake_pos();
    failures += test_backfill_unreadable_body_backoff();
    failures += test_backfill_declared_partial_coverage();
    return failures;
}
