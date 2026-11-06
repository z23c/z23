/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: measure the importer's decoder against the legacy decoder over every
 * coins record of a real chainstate copy, and read an imported node.db back.
 *
 * To run: ZCL_LEGACY_CHAINSTATE=<copy>/chainstate ZCL_CENSUS_NODE_DB=<imported node.db> make t-fast-exact ONLY=chainstate_legacy_reader
 *
 * Runs only from test_chainstate_legacy_reader when ZCL_LEGACY_CHAINSTATE names
 * a directory. It reports numbers and judges nothing beyond a failed walk.
 */

#include "test/test_core.h"

#include "../../storage/src/coins_record_codec.h"

#include "coins/utxo_commitment.h"
#include "services/utxo_import_pipeline.h"
#include "storage/dbwrapper.h"
#include "util/safe_alloc.h"

#include <inttypes.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The importer's limits, node_db_import_internal.h:37 and :41. */
#define CENSUS_CHUNK_ENTRIES 2048
#define CENSUS_CHUNK_ROWS 32768
#define CENSUS_EXAMPLES 10

struct import_census {
    uint64_t records, bad_keys, empty_values;
    uint64_t legacy_refused, import_refused, import_zero_rows, import_partial;
    uint64_t legacy_outputs, import_rows;
    int64_t legacy_value, import_value;
    uint64_t missing, extra, wrong_vout, wrong_value, wrong_script;
    uint64_t wrong_height, wrong_coinbase;
    uint64_t max_vout, max_live, max_num_avail, max_script, max_value_len;
    uint64_t nsize_type[6], raw_scripts, over_520, over_10000, over_10240;
    uint64_t outputs_vout_ge_4096;
    uint64_t height_missing, height_out_of_range, rows_height_zero;
    int min_height, max_height;
    uint64_t peak_chunk_rows, chunk_rows, chunk_entries;
    uint64_t records_cut_by_space, entries_skipped_by_space;
    uint64_t examples;
};

struct census_record {
    struct import_census *c;
    const struct utxo_import_row *rows;
    int nrows;
    size_t emitted;
    const uint8_t *txid;
};

static void census_note_example(struct import_census *c, const uint8_t *txid,
                                const char *field, uint32_t vout)
{
    if (c->examples >= CENSUS_EXAMPLES)
        return;
    c->examples++;
    printf("census: example %s vout=%u txid(le)=", field, vout);
    for (int i = 0; i < 32; i++)
        printf("%02x", txid[i]);
    printf("\n");
}

static void census_note_script_size(struct import_census *c, uint64_t nsize)
{
    if (nsize < 6) {
        c->nsize_type[nsize]++;
        return;
    }
    uint64_t raw = nsize - 6;
    c->raw_scripts++;
    c->over_520 += raw > 520;
    c->over_10000 += raw > 10000;
    c->over_10240 += raw > 10240;
    if (raw > c->max_script)
        c->max_script = raw;
}

static void census_compare_row(struct census_record *r,
                               const struct coins_record_output *out,
                               const struct utxo_import_row *row)
{
    struct import_census *c = r->c;
    const uint8_t *script =
        row->script_overflow ? row->script_overflow : row->script;

    if (row->vout != out->vout) {
        c->wrong_vout++;
        census_note_example(c, r->txid, "vout", out->vout);
    }
    if (row->value != out->value) {
        c->wrong_value++;
        census_note_example(c, r->txid, "value", out->vout);
    }
    if (row->script_len != out->script_len ||
        memcmp(script, out->script, out->script_len) != 0) {
        c->wrong_script++;
        census_note_example(c, r->txid, "script", out->vout);
    }
    if ((bool)row->is_coinbase != out->is_coinbase) {
        c->wrong_coinbase++;
        census_note_example(c, r->txid, "coinbase", out->vout);
    }
}

static bool census_begin(const struct coins_record_header *hdr, void *ctx)
{
    struct census_record *r = ctx;
    if (hdr->live_outputs > r->c->max_live)
        r->c->max_live = hdr->live_outputs;
    if (hdr->num_avail > r->c->max_num_avail)
        r->c->max_num_avail = hdr->num_avail;
    return true;
}

static bool census_output(const struct coins_record_output *out, void *ctx)
{
    struct census_record *r = ctx;
    struct import_census *c = r->c;

    c->legacy_outputs++;
    c->legacy_value += out->value;
    if (out->vout > c->max_vout)
        c->max_vout = out->vout;
    c->outputs_vout_ge_4096 += out->vout >= 4096;
    census_note_script_size(c, out->nsize);

    if (r->emitted < (size_t)r->nrows) {
        census_compare_row(r, out, &r->rows[r->emitted]);
    } else {
        c->missing++;
        census_note_example(c, r->txid, "missing", out->vout);
    }
    r->emitted++;
    return true;
}

static void census_note_height(struct import_census *c,
                               const struct census_record *r,
                               const struct coins_record_decode_result *res)
{
    if (!res->height_found)
        c->height_missing++;
    else if (!res->height_in_legacy_import_range)
        c->height_out_of_range++;
    if (res->height < c->min_height)
        c->min_height = res->height;
    if (res->height > c->max_height)
        c->max_height = res->height;
    for (int i = 0; i < r->nrows; i++) {
        c->rows_height_zero += r->rows[i].height == 0;
        if (r->rows[i].height != res->height) {
            c->wrong_height++;
            census_note_example(c, r->txid, "height", r->rows[i].vout);
        }
    }
}

/* What the import decoder says about the record, apart from the rows it gives:
 * the importer's own entry point hides the status and the live count. */
static void census_import_status(struct import_census *c, const uint8_t *value,
                                 size_t value_len, int space)
{
    struct coins_record_decode_options opts = {
        .mode = COINS_RECORD_DECODE_UTXO_IMPORT,
        .max_outputs = (size_t)space,
        .scratch = NULL,
    };
    struct coins_record_decode_result res;
    enum coins_record_decode_status st =
        coins_record_decode(value, value_len, &opts, NULL, NULL, &res);
    if (st != COINS_RECORD_DECODE_OK) {
        c->import_refused++;
        printf("census: import status %s\n",
               coins_record_decode_status_name(st));
    } else if (res.outputs_emitted != res.live_outputs) {
        if (res.live_outputs > (size_t)space)
            c->records_cut_by_space++;
        else
            c->import_partial++;
    }
}

static void census_free_rows(struct utxo_import_row *rows, int n)
{
    for (int i = 0; i < n; i++)
        free(rows[i].script_overflow);
}

static int census_decode_import(struct import_census *c,
                                struct utxo_import_raw_entry *raw,
                                struct utxo_import_row *rows)
{
    int space = CENSUS_CHUNK_ROWS - (int)c->chunk_rows;
    if (space <= 0) {
        c->entries_skipped_by_space++;
        return 0;
    }
    census_import_status(c, raw->value, raw->value_len, space);
    int n = utxo_import_decode_entry(raw, rows, space);
    if (n == 0) {
        c->import_zero_rows++;
        census_note_example(c, raw->txid, "zero_rows", 0);
    }
    c->import_rows += (uint64_t)n;
    for (int i = 0; i < n; i++)
        c->import_value += rows[i].value;
    return n;
}

static void census_step_chunk(struct import_census *c, int nrows)
{
    c->chunk_rows += (uint64_t)nrows;
    if (c->chunk_rows > c->peak_chunk_rows)
        c->peak_chunk_rows = c->chunk_rows;
    if (++c->chunk_entries == CENSUS_CHUNK_ENTRIES) {
        c->chunk_entries = 0;
        c->chunk_rows = 0;
    }
}

static void census_record_visit(struct import_census *c, const uint8_t *key,
                                const char *value, size_t value_len,
                                struct utxo_import_row *rows,
                                struct coins_record_scratch *scratch)
{
    struct utxo_import_raw_entry raw = {
        .value = (uint8_t *)(uintptr_t)value,
        .value_len = (uint32_t)value_len,
    };
    memcpy(raw.txid, key, 32);
    c->records++;
    if (value_len > c->max_value_len)
        c->max_value_len = value_len;

    int nrows = census_decode_import(c, &raw, rows);
    struct census_record r = {
        .c = c, .rows = rows, .nrows = nrows, .txid = raw.txid,
    };
    struct coins_record_decode_options opts = {
        .mode = COINS_RECORD_DECODE_CHAINSTATE_LEGACY,
        .scratch = scratch,
    };
    struct coins_record_decode_ops ops = {
        .begin = census_begin,
        .output = census_output,
    };
    struct coins_record_decode_result res;
    enum coins_record_decode_status st = coins_record_decode(
        raw.value, raw.value_len, &opts, &ops, &r, &res);
    if (st != COINS_RECORD_DECODE_OK) {
        c->legacy_refused++;
        printf("census: legacy status %s\n",
               coins_record_decode_status_name(st));
        census_note_example(c, raw.txid, "legacy_refused", 0);
    } else {
        census_note_height(c, &r, &res);
        if (r.emitted < (size_t)nrows)
            c->extra += (size_t)nrows - r.emitted;
    }
    census_free_rows(rows, nrows);
    census_step_chunk(c, nrows);
}

static void census_print(const struct import_census *c)
{
    printf("census: records=%" PRIu64 " bad_keys=%" PRIu64 " empty_values=%" PRIu64 "\n",
           c->records, c->bad_keys, c->empty_values);
    printf("census: refused legacy=%" PRIu64 " import_status=%" PRIu64
           " import_zero_rows=%" PRIu64 " import_partial=%" PRIu64 "\n",
           c->legacy_refused, c->import_refused, c->import_zero_rows,
           c->import_partial);
    printf("census: outputs legacy=%" PRIu64 " import=%" PRIu64
           " value_sat legacy=%" PRId64 " import=%" PRId64 "\n",
           c->legacy_outputs, c->import_rows, c->legacy_value, c->import_value);
    printf("census: differ missing=%" PRIu64 " extra=%" PRIu64 " vout=%" PRIu64
           " value=%" PRIu64 " script=%" PRIu64 " height=%" PRIu64
           " coinbase=%" PRIu64 "\n",
           c->missing, c->extra, c->wrong_vout, c->wrong_value, c->wrong_script,
           c->wrong_height, c->wrong_coinbase);
    printf("census: max vout=%" PRIu64 " live_per_record=%" PRIu64
           " num_avail=%" PRIu64 " raw_script=%" PRIu64 " value_len=%" PRIu64
           " outputs_vout_ge_4096=%" PRIu64 "\n",
           c->max_vout, c->max_live, c->max_num_avail, c->max_script,
           c->max_value_len, c->outputs_vout_ge_4096);
    printf("census: nsize 0=%" PRIu64 " 1=%" PRIu64 " 2=%" PRIu64 " 3=%" PRIu64
           " 4=%" PRIu64 " 5=%" PRIu64 " raw=%" PRIu64 "\n",
           c->nsize_type[0], c->nsize_type[1], c->nsize_type[2],
           c->nsize_type[3], c->nsize_type[4], c->nsize_type[5], c->raw_scripts);
    printf("census: raw_scripts over520=%" PRIu64 " over10000=%" PRIu64
           " over10240=%" PRIu64 "\n",
           c->over_520, c->over_10000, c->over_10240);
    printf("census: height missing=%" PRIu64 " out_of_range=%" PRIu64
           " rows_height_zero=%" PRIu64 " min=%d max=%d\n",
           c->height_missing, c->height_out_of_range, c->rows_height_zero,
           c->min_height, c->max_height);
    printf("census: chunk peak_rows=%" PRIu64 " of %d records_cut=%" PRIu64
           " entries_skipped=%" PRIu64 "\n",
           c->peak_chunk_rows, CENSUS_CHUNK_ROWS, c->records_cut_by_space,
           c->entries_skipped_by_space);
}

static int census_walk(const char *path, struct import_census *c,
                       struct utxo_import_row *rows)
{
    struct db_wrapper db;
    struct db_iterator it;
    struct coins_record_scratch scratch = {0};
    const char seek_key = 'c';
    bool clean;

    memset(&db, 0, sizeof(db));
    if (!db_wrapper_open(&db, path, 64u << 20, false, false)) {
        printf("census: cannot open %s\n", path);
        return 1;
    }
    db_iter_init(&it, &db);
    db_iter_seek(&it, &seek_key, 1);
    while (db_iter_valid(&it)) {
        size_t klen = 0;
        size_t vlen = 0;
        const char *k = db_iter_key(&it, &klen);
        if (klen < 1 || k[0] != 'c')
            break;
        const char *v = db_iter_value(&it, &vlen);
        if (klen != 33)
            c->bad_keys++;
        else if (!v || vlen == 0)
            c->empty_values++;
        else
            census_record_visit(c, (const uint8_t *)k + 1, v, vlen, rows,
                                &scratch);
        db_iter_next(&it);
    }
    clean = db_iter_check_error(&it);
    db_iter_free(&it);
    coins_record_scratch_free(&scratch);
    db_wrapper_close(&db);
    return clean ? 0 : 1;
}

/* Whole-table numbers from a node.db the import wrote, and its commitment. */
static int census_read_node_db(const char *path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    uint8_t sha3[32];
    uint64_t count = 0;
    const char *sql =
        "SELECT COUNT(*), COALESCE(SUM(value),0), "
        "COALESCE(SUM(height=0),0), COALESCE(MAX(LENGTH(script)),0), "
        "COALESCE(MIN(height),-1), COALESCE(MAX(height),-1) FROM utxos";

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        printf("census: cannot open %s\n", path);
        sqlite3_close(db);
        return 1;
    }
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW) {
        printf("census: node_db rows=%lld value_sat=%lld height_zero=%lld "
               "max_script=%lld min_height=%lld max_height=%lld\n",
               (long long)sqlite3_column_int64(st, 0),
               (long long)sqlite3_column_int64(st, 1),
               (long long)sqlite3_column_int64(st, 2),
               (long long)sqlite3_column_int64(st, 3),
               (long long)sqlite3_column_int64(st, 4),
               (long long)sqlite3_column_int64(st, 5));
    }
    sqlite3_finalize(st);
    utxo_commitment_sha3_compute(db, sha3, &count);
    printf("census: node_db sha3_count=%" PRIu64 " sha3=", count);
    for (int i = 0; i < 32; i++)
        printf("%02x", sha3[i]);
    printf("\n");
    sqlite3_close(db);
    return 0;
}

int chainstate_import_census_run(const char *path);

int chainstate_import_census_run(const char *path)
{
    struct import_census c = { .min_height = INT32_MAX, .max_height = -1 };
    struct utxo_import_row *rows =
        zcl_calloc(CENSUS_CHUNK_ROWS, sizeof(*rows), "census rows");
    const char *node_db = getenv("ZCL_CENSUS_NODE_DB");
    int failures;

    if (!rows)
        return 1;
    printf("census: walking %s\n", path);
    failures = census_walk(path, &c, rows);
    free(rows);
    census_print(&c);
    if (node_db && *node_db)
        failures += census_read_node_db(node_db);
    return failures;
}
