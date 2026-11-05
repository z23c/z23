/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "coins/compressor.h"
#include "core/serialize.h"
#include "models/database.h"
#include "platform/logical_cpu.h"
#include "services/utxo_import_pipeline.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool build_large_ccoins_record(struct byte_stream *s, int outputs,
                                      uint32_t height)
{
    if (!s || outputs < 2 || ((outputs - 2) % 8) != 0)
        return false;

    int mask_bytes = (outputs - 2) / 8;
    uint64_t ncode = ((uint64_t)mask_bytes * 8u) | 0x07u;
    unsigned char hash[20];
    memset(hash, 0x51, sizeof(hash));

    bool ok = true;
    ok &= stream_write_varint(s, 1);      /* nVersion */
    ok &= stream_write_varint(s, ncode);  /* coinbase + vout0 + vout1 */
    for (int i = 0; i < mask_bytes; i++)
        ok &= stream_write_u8(s, 0xff);
    for (int i = 0; i < outputs; i++) {
        hash[0] = (unsigned char)(0x20 + (i % 64));
        ok &= stream_write_varint(s, compress_amount(1));
        ok &= stream_write_varint(s, 0); /* compressed P2PKH */
        ok &= stream_write_bytes(s, hash, sizeof(hash));
    }
    ok &= stream_write_varint(s, height);
    return ok && !s->error;
}

static bool decoded_row_fields_match(const struct utxo_import_row *rows,
                                     int outputs, uint32_t height)
{
    bool ok = rows[0].vout == 0;
    ok = ok && rows[0].height == (int32_t)height;
    ok = ok && rows[0].value == 1;
    ok = ok && rows[0].script_len == 25;
    ok = ok && rows[0].script_type == 1;
    ok = ok && rows[0].has_address == 1;
    ok = ok && rows[outputs - 1].vout == (uint32_t)(outputs - 1);
    ok = ok && rows[outputs - 1].height == (int32_t)height;
    ok = ok && rows[outputs - 1].value == 1;
    return ok;
}

static bool oversized_value_import_refused(void)
{
    uint32_t out_len = 0;
    struct zcl_result exact =
        utxo_import_value_len_checked(UTXO_IMPORT_VALUE_MAX_BYTES,
                                      &out_len);
    struct zcl_result too_large =
        utxo_import_value_len_checked(
            (size_t)UTXO_IMPORT_VALUE_MAX_BYTES + 1u, &out_len);
    struct zcl_result null_out =
        utxo_import_value_len_checked(16, NULL);

    bool ok = exact.ok;
    ok = ok && out_len == UTXO_IMPORT_VALUE_MAX_BYTES;
    ok = ok && !too_large.ok;
    ok = ok && !null_out.ok;
    return ok;
}

/* ---- value length: exact refusal codes, out_len untouched on refusal ---- */

static bool value_len_refusals_exact(void)
{
    uint32_t out = 0xDEADBEEFu;
    struct zcl_result null_out = utxo_import_value_len_checked(16, NULL);
    /* The NULL out_len check comes before the size check. */
    struct zcl_result null_big = utxo_import_value_len_checked(
        (size_t)UTXO_IMPORT_VALUE_MAX_BYTES + 1u, NULL);
    struct zcl_result big = utxo_import_value_len_checked(
        (size_t)UTXO_IMPORT_VALUE_MAX_BYTES + 1u, &out);
    bool ok = !null_out.ok && null_out.code == -1;
    ok = ok && !null_big.ok && null_big.code == -1;
    ok = ok && !big.ok && big.code == -2 && out == 0xDEADBEEFu;
    struct zcl_result huge = utxo_import_value_len_checked(SIZE_MAX, &out);
    ok = ok && !huge.ok && huge.code == -2 && out == 0xDEADBEEFu;
    struct zcl_result zero = utxo_import_value_len_checked(0, &out);
    ok = ok && zero.ok && out == 0;
    struct zcl_result one = utxo_import_value_len_checked(1, &out);
    ok = ok && one.ok && out == 1;
    return ok;
}

/* ---- writer bind/step checks against a real in-memory sqlite ---- */

static bool msg_has(const struct zcl_result *r, const char *needle)
{
    return strstr(r->message, needle) != NULL;
}

static bool bind_checked_codes(sqlite3_stmt *stmt)
{
    struct zcl_result null_stmt =
        utxo_import_writer_bind_checked(NULL, "lbl", SQLITE_OK, NULL, 3);
    struct zcl_result null_both =
        utxo_import_writer_bind_checked(NULL, NULL, SQLITE_ERROR, NULL, 3);
    struct zcl_result good =
        utxo_import_writer_bind_checked(stmt, "lbl", SQLITE_OK, NULL, 3);
    bool ok = !null_stmt.ok && null_stmt.code == -1 &&
              msg_has(&null_stmt, "label=lbl");
    ok = ok && !null_both.ok && null_both.code == -1;
    ok = ok && good.ok && good.code == 0;
    return ok;
}

static bool bind_checked_failure_text(sqlite3_stmt *stmt, sqlite3 *db)
{
    struct node_db no_db;
    memset(&no_db, 0, sizeof(no_db));
    struct node_db with_db;
    memset(&with_db, 0, sizeof(with_db));
    with_db.db = db;
    sqlite3_stmt *bad = NULL;
    (void)sqlite3_prepare_v2(db, "SELECT * FROM no_such_table", -1, &bad,
                             NULL);
    struct zcl_result a = utxo_import_writer_bind_checked(
        stmt, "col", SQLITE_BUSY, NULL, 7);
    struct zcl_result b = utxo_import_writer_bind_checked(
        stmt, "col", SQLITE_BUSY, &no_db, 7);
    struct zcl_result c = utxo_import_writer_bind_checked(
        stmt, NULL, SQLITE_BUSY, &with_db, 8);
    bool ok = !a.ok && a.code == -2 && msg_has(&a, "col failed row=7") &&
              msg_has(&a, "rc=5") && msg_has(&a, "db unavailable");
    /* ndb present but ndb->db NULL: still "db unavailable", never a
     * sqlite3_errmsg(NULL) "out of memory". */
    ok = ok && !b.ok && b.code == -2 && msg_has(&b, "db unavailable");
    ok = ok && !c.ok && c.code == -2 && msg_has(&c, "row=8") &&
         msg_has(&c, "no such table") && !msg_has(&c, "db unavailable");
    sqlite3_finalize(bad);
    return ok;
}

static bool step_dup_cases(sqlite3 *db, sqlite3_stmt *ins)
{
    struct node_db with_db;
    memset(&with_db, 0, sizeof(with_db));
    with_db.db = db;
    struct node_db no_db;
    memset(&no_db, 0, sizeof(no_db));
    struct zcl_result dup1 = utxo_import_writer_step_checked(ins, &with_db, 2);
    sqlite3_reset(ins);
    struct zcl_result dup2 = utxo_import_writer_step_checked(ins, NULL, 3);
    sqlite3_reset(ins);
    struct zcl_result dup3 = utxo_import_writer_step_checked(ins, &no_db, 4);
    bool ok = !dup1.ok && dup1.code == -4 && msg_has(&dup1, "row=2") &&
              msg_has(&dup1, "rc=19") && msg_has(&dup1, "UNIQUE");
    ok = ok && !dup2.ok && dup2.code == -4 && msg_has(&dup2, "db unavailable");
    ok = ok && !dup3.ok && dup3.code == -4 && msg_has(&dup3, "db unavailable");
    return ok;
}

static bool step_checked_cases(sqlite3 *db)
{
    struct node_db with_db;
    memset(&with_db, 0, sizeof(with_db));
    with_db.db = db;
    sqlite3_stmt *ins = NULL;
    if (sqlite3_exec(db, "CREATE TABLE t(a UNIQUE)", NULL, NULL, NULL) !=
            SQLITE_OK ||
        sqlite3_prepare_v2(db, "INSERT INTO t VALUES(1)", -1, &ins, NULL) !=
            SQLITE_OK)
        return false;
    struct zcl_result null_stmt =
        utxo_import_writer_step_checked(NULL, &with_db, 9);
    struct zcl_result first = utxo_import_writer_step_checked(ins, &with_db, 1);
    sqlite3_reset(ins);
    bool ok = !null_stmt.ok && null_stmt.code == -3 &&
              msg_has(&null_stmt, "row=9");
    ok = ok && first.ok && first.code == 0;
    ok = ok && step_dup_cases(db, ins);
    sqlite3_finalize(ins);
    return ok;
}

static bool writer_checks_hold(void)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_open(":memory:", &db) != SQLITE_OK || !db)
        return false;
    bool ok = sqlite3_prepare_v2(db, "SELECT 1", -1, &stmt, NULL) ==
              SQLITE_OK;
    ok = ok && bind_checked_codes(stmt);
    ok = ok && bind_checked_failure_text(stmt, db);
    sqlite3_finalize(stmt);
    ok = ok && step_checked_cases(db);
    sqlite3_close(db);
    return ok;
}

/* ---- decoder-count policy follows the host CPU count ---- */

static bool decoder_count_policy(void)
{
    uint32_t n = platform_logical_cpu_count();
    int want = n < 6 ? 4 : (n > 34 ? UTXO_IMPORT_NUM_DECODERS_MAX
                                    : (int)(n - 2));
    int got = utxo_import_num_decoders();
    return got == want && got >= 4 && got <= UTXO_IMPORT_NUM_DECODERS_MAX;
}

/* ---- single-output records with an exact raw script ---- */

static bool rec_one(struct byte_stream *s, bool coinbase, int64_t value,
                    const uint8_t *script, size_t slen, int64_t height)
{
    bool ok = stream_write_varint(s, 1);
    ok &= stream_write_varint(s, coinbase ? 0x03 : 0x02); /* vout0 only */
    ok &= stream_write_varint(s, compress_amount((uint64_t)value));
    ok &= stream_write_varint(s, (uint64_t)slen + 6u); /* raw script */
    ok &= stream_write_bytes(s, script, slen);
    if (height >= 0)
        ok &= stream_write_varint(s, (uint64_t)height);
    return ok && !s->error;
}

enum { SC_P2PKH, SC_P2SH, SC_OPRET, SC_ZERO_OPRET, SC_FILL };

static void script_base(uint8_t *b, int base)
{
    memset(b, base == SC_FILL ? 0x51 : 0x00, 128);
    if (base == SC_P2PKH) {
        b[0] = 0x76; b[1] = 0xa9; b[2] = 0x14; b[23] = 0x88; b[24] = 0xac;
        for (int i = 0; i < 20; i++) b[3 + i] = (uint8_t)(0x30 + i);
    } else if (base == SC_P2SH) {
        b[0] = 0xa9; b[1] = 0x14; b[22] = 0x87;
        for (int i = 0; i < 20; i++) b[2 + i] = (uint8_t)(0x60 + i);
    } else if (base == SC_OPRET) {
        memset(b, 0x02, 128);
        b[0] = 0x6a;
    } else if (base == SC_ZERO_OPRET) {
        b[1] = 0x6a;
    }
}

struct script_case {
    int base;
    int patch_at;
    uint8_t patch_val;
    size_t len;
    uint8_t type;
    bool addr;
};

static const struct script_case script_cases[] = {
    { SC_P2PKH, -1, 0, 25, 1, true },
    { SC_P2PKH, 0, 0x77, 25, 0, false },
    { SC_P2PKH, 1, 0xaa, 25, 0, false },
    { SC_P2PKH, 2, 0x15, 25, 0, false },
    { SC_P2PKH, 23, 0x89, 25, 0, false },
    { SC_P2PKH, 24, 0xad, 25, 0, false },
    { SC_P2PKH, -1, 0, 26, 0, false },
    { SC_P2PKH, -1, 0, 24, 0, false },
    { SC_P2SH, -1, 0, 23, 2, true },
    { SC_P2SH, 0, 0xaa, 23, 0, false },
    { SC_P2SH, 1, 0x15, 23, 0, false },
    { SC_P2SH, 22, 0x88, 23, 0, false },
    { SC_P2SH, -1, 0, 24, 0, false },
    { SC_P2SH, -1, 0, 22, 0, false },
    { SC_OPRET, -1, 0, 1, 3, false },
    { SC_OPRET, -1, 0, 4, 3, false },
    { SC_OPRET, -1, 0, 100, 3, false },
    { SC_ZERO_OPRET, -1, 0, 2, 0, false },
    { SC_FILL, -1, 0, 0, 0, false },
    { SC_FILL, -1, 0, 80, 0, false },
    { SC_FILL, -1, 0, 81, 0, false },
};

static bool row_script_matches(const struct utxo_import_row *r,
                               const uint8_t *want, size_t len)
{
    bool overflow = len > sizeof(r->script);
    if (r->script_len != len || (r->script_overflow != NULL) != overflow)
        return false;
    const uint8_t *got = overflow ? r->script_overflow : r->script;
    return len == 0 || memcmp(got, want, len) == 0;
}

static bool row_address_matches(const struct utxo_import_row *r,
                                const struct script_case *c,
                                const uint8_t *script)
{
    if (r->has_address != (c->addr ? 1 : 0))
        return false;
    if (c->addr) {
        size_t off = c->base == SC_P2PKH ? 3 : 2;
        return memcmp(r->address_hash, script + off, 20) == 0;
    }
    for (size_t i = 0; i < sizeof(r->address_hash); i++)
        if (r->address_hash[i] != 0xEE)
            return false;
    return true;
}

static bool script_case_holds(const struct script_case *c)
{
    uint8_t sc[128];
    script_base(sc, c->base);
    if (c->patch_at >= 0)
        sc[c->patch_at] = c->patch_val;
    struct byte_stream s;
    stream_init(&s, 1024);
    bool ok = rec_one(&s, false, 5000, sc, c->len, 77);
    struct utxo_import_row rows[4];
    memset(rows, 0xEE, sizeof(rows));
    struct utxo_import_raw_entry raw;
    memset(&raw, 0, sizeof(raw));
    for (int i = 0; i < 32; i++) raw.txid[i] = (uint8_t)(0x90 + i);
    raw.value = s.data;
    raw.value_len = (uint32_t)s.size;
    int n = ok ? utxo_import_decode_entry(&raw, rows, 4) : -1;
    ok = ok && n == 1 && rows[0].script_type == c->type &&
         memcmp(rows[0].txid, raw.txid, 32) == 0 &&
         rows[0].vout == 0 && rows[0].value == 5000 &&
         rows[0].is_coinbase == 0 && rows[0].height == 77 &&
         row_script_matches(&rows[0], sc, c->len) &&
         row_address_matches(&rows[0], c, sc);
    /* Only the one decoded row is written. */
    ok = ok && rows[1].height == (int32_t)0xEEEEEEEE;
    if (n > 0) free(rows[0].script_overflow);
    stream_free(&s);
    return ok;
}

static bool script_classification_table(void)
{
    for (size_t i = 0; i < sizeof(script_cases) / sizeof(script_cases[0]);
         i++) {
        if (!script_case_holds(&script_cases[i])) {
            fprintf(stderr, "script case %zu failed\n", i);
            return false;
        }
    }
    return true;
}

/* ---- height: stored only when found and inside the legacy range ---- */

static bool height_case(int64_t height_in, int32_t want)
{
    static const uint8_t p2pkh_like[3] = { 0x51, 0x52, 0x53 };
    struct byte_stream s;
    stream_init(&s, 256);
    bool ok = rec_one(&s, true, 1, p2pkh_like, sizeof(p2pkh_like), height_in);
    struct utxo_import_row rows[2];
    memset(rows, 0xEE, sizeof(rows));
    struct utxo_import_raw_entry raw;
    memset(&raw, 0, sizeof(raw));
    raw.value = s.data;
    raw.value_len = (uint32_t)s.size;
    int n = ok ? utxo_import_decode_entry(&raw, rows, 2) : -1;
    ok = ok && n == 1 && rows[0].height == want && rows[0].is_coinbase == 1;
    stream_free(&s);
    return ok;
}

static bool height_table(void)
{
    return height_case(-1, 0) &&           /* no height varint at all */
           height_case(0, 0) && height_case(1, 1) &&
           height_case(10000000, 10000000) &&
           /* found but above the legacy range: rows keep height 0 */
           height_case(10000001, 0);
}

/* ---- argument and bound refusals of decode_entry ---- */

static bool decode_refusals(void)
{
    struct byte_stream s;
    stream_init(&s, 1024);
    bool ok = build_large_ccoins_record(&s, 2, 9);
    struct utxo_import_raw_entry raw;
    memset(&raw, 0, sizeof(raw));
    raw.value = s.data;
    raw.value_len = (uint32_t)s.size;
    struct utxo_import_row rows[3];
    memset(rows, 0xEE, sizeof(rows));
    ok = ok && utxo_import_decode_entry(NULL, rows, 3) == 0;
    ok = ok && utxo_import_decode_entry(&raw, NULL, 3) == 0;
    ok = ok && utxo_import_decode_entry(&raw, rows, 0) == 0;
    ok = ok && utxo_import_decode_entry(&raw, rows, -1) == 0;
    /* max_rows 0 must not mean "unbounded": nothing is written. */
    ok = ok && rows[0].height == (int32_t)0xEEEEEEEE;
    ok = ok && utxo_import_decode_entry(&raw, rows, 1) == 1;
    ok = ok && rows[1].height == (int32_t)0xEEEEEEEE;
    ok = ok && utxo_import_decode_entry(&raw, rows, 2) == 2;
    ok = ok && rows[2].height == (int32_t)0xEEEEEEEE;
    /* Undecodable values draw 0 rows and leave the output untouched. */
    memset(rows, 0xEE, sizeof(rows));
    raw.value_len = 0;
    ok = ok && utxo_import_decode_entry(&raw, rows, 3) == 0;
    raw.value_len = 1;
    ok = ok && utxo_import_decode_entry(&raw, rows, 3) == 0;
    raw.value = NULL;
    ok = ok && utxo_import_decode_entry(&raw, rows, 3) == 0;
    ok = ok && rows[0].height == (int32_t)0xEEEEEEEE;
    stream_free(&s);
    return ok;
}

static int run_gap_checks(void)
{
    static const struct {
        const char *label;
        bool (*fn)(void);
    } checks[] = {
        { "value length refusals carry exact codes", value_len_refusals_exact },
        { "writer bind/step checks name the failure", writer_checks_hold },
        { "decoder count follows the CPU policy", decoder_count_policy },
        { "script classification and bounds table", script_classification_table },
        { "height only inside the legacy range", height_table },
        { "decode refusals leave rows untouched", decode_refusals },
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
        printf("utxo_import_pipeline: %s... ", checks[i].label);
        if (checks[i].fn()) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
    }
    return failures;
}

int test_utxo_import_pipeline(void)
{
    int failures = run_gap_checks();

    printf("utxo_import_pipeline: CCoins >65535 bytes decodes fully... ");
    {
        const int outputs = 3002;
        const uint32_t height = 3141592;
        struct byte_stream s;
        stream_init(&s, 70000);
        bool ok = build_large_ccoins_record(&s, outputs, height);

        struct utxo_import_row *rows =
            zcl_malloc(sizeof(*rows) * (size_t)outputs,
                       "test_utxo_import_rows");
        ok = ok && rows != NULL;
        if (rows)
            memset(rows, 0, sizeof(*rows) * (size_t)outputs);

        struct utxo_import_raw_entry raw;
        memset(&raw, 0, sizeof(raw));
        memset(raw.txid, 0x42, sizeof(raw.txid));
        raw.value = s.data;
        raw.value_len = (uint32_t)s.size;
        size_t record_len = s.size;

        int n = rows ? utxo_import_decode_entry(&raw, rows, outputs) : 0;
        ok = ok && record_len > 65535;
        ok = ok && n == outputs;
        if (rows && n == outputs)
            ok = ok && decoded_row_fields_match(rows, outputs, height);

        free(rows);
        stream_free(&s);
        if (ok) printf("OK\n");
        else { printf("FAIL (len=%zu rows=%d)\n", record_len, n); failures++; }
    }

    printf("utxo_import_pipeline: oversized CCoins value refuses import... ");
    {
        bool ok = oversized_value_import_refused();
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
