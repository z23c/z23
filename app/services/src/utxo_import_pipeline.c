/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "services/utxo_import_pipeline.h"

#include "../../../lib/storage/src/coins_record_codec.h"
#include "models/database.h"
#include "platform/logical_cpu.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

int utxo_import_num_decoders(void)
{
    uint32_t n = platform_logical_cpu_count();
    if (n < 6)
        return 4;
    if (n > 34)
        return UTXO_IMPORT_NUM_DECODERS_MAX;
    return (int)(n - 2);
}

struct zcl_result utxo_import_value_len_checked(size_t value_len,
                                                uint32_t *out_len)
{
    if (!out_len)
        return ZCL_ERR(-1, "utxo import value length: NULL out_len");
    if (value_len > UTXO_IMPORT_VALUE_MAX_BYTES) {
        LOG_WARN("sync",
                 "UTXO import: refusing oversized CCoins value (%zu bytes, "
                 "max=%u)", value_len, UTXO_IMPORT_VALUE_MAX_BYTES);
        return ZCL_ERR(-2, "utxo import value length %zu exceeds max %u",
                       value_len, UTXO_IMPORT_VALUE_MAX_BYTES);
    }
    *out_len = (uint32_t)value_len;
    return ZCL_OK;
}

struct zcl_result utxo_import_writer_bind_checked(sqlite3_stmt *stmt,
                                                  const char *label,
                                                  int rc,
                                                  const struct node_db *ndb,
                                                  int row_no)
{
    if (!stmt) {
        LOG_WARN("sync", "UTXO import writer: stmt is NULL for %s",
                 label ? label : "(unknown)");
        return ZCL_ERR(-1, "import writer bind: stmt is NULL label=%s",
                       label ? label : "");
    }
    if (rc != SQLITE_OK) {
        const char *err = (ndb && ndb->db) ? sqlite3_errmsg(ndb->db)
                                          : "db unavailable";
        LOG_WARN("sync",
                 "UTXO import writer: %s failed at row %d (rc=%d): %s",
                 label ? label : "(unknown)", row_no, rc, err);
        return ZCL_ERR(-2, "import writer bind: %s failed row=%d rc=%d: %s",
                       label ? label : "", row_no, rc, err);
    }
    return ZCL_OK;
}

struct zcl_result utxo_import_writer_step_checked(sqlite3_stmt *stmt,
                                                  const struct node_db *ndb,
                                                  int row_no)
{
    if (!stmt) {
        LOG_WARN("sync", "UTXO import writer: stmt is NULL at row %d",
                 row_no);
        return ZCL_ERR(-3, "import writer step: stmt is NULL row=%d",
                       row_no);
    }
    int step_rc = AR_STEP_WRITE(stmt);
    if (step_rc != SQLITE_DONE) {
        const char *err = (ndb && ndb->db) ? sqlite3_errmsg(ndb->db)
                                          : "db unavailable";
        LOG_WARN("sync",
                 "UTXO import writer: sqlite3_step failed at row %d "
                 "(rc=%d): %s", row_no, step_rc, err);
        return ZCL_ERR(-4, "import writer step failed row=%d rc=%d: %s",
                       row_no, step_rc, err);
    }
    return ZCL_OK;
}

struct utxo_import_decode_ctx {
    const struct utxo_import_raw_entry *raw;
    struct utxo_import_row *out;
    int nrows;
};

static void utxo_import_row_classify_script(struct utxo_import_row *r)
{
    const uint8_t *sc = r->script_overflow ? r->script_overflow : r->script;
    uint16_t slen = r->script_len;

    if (slen == 25 && sc[0] == 0x76 && sc[1] == 0xa9 &&
        sc[2] == 0x14 && sc[23] == 0x88 && sc[24] == 0xac) {
        memcpy(r->address_hash, sc + 3, 20);
        r->has_address = 1;
        r->script_type = 1;
    } else if (slen == 23 && sc[0] == 0xa9 && sc[1] == 0x14 &&
               sc[22] == 0x87) {
        memcpy(r->address_hash, sc + 2, 20);
        r->has_address = 1;
        r->script_type = 2;
    } else if (slen > 0 && sc[0] == 0x6a) {
        r->script_type = 3;
    }
}

static bool utxo_import_decode_output(const struct coins_record_output *out,
                                      void *ctx)
{
    struct utxo_import_decode_ctx *c = (struct utxo_import_decode_ctx *)ctx;
    if (!out || !c || !c->raw || !c->out)
        return false;

    struct utxo_import_row *r = &c->out[c->nrows];
    memcpy(r->txid, c->raw->txid, 32);
    r->vout = out->vout;
    r->value = out->value;
    r->is_coinbase = out->is_coinbase;
    r->height = 0;
    r->script_overflow = NULL;
    r->has_address = 0;
    r->script_type = 0;

    uint16_t slen = (uint16_t)out->script_len;
    r->script_len = slen;
    if (slen <= sizeof(r->script)) {
        memcpy(r->script, out->script, slen);
    } else {
        r->script_overflow = zcl_malloc(slen, "script overflow");
        if (r->script_overflow) {
            memcpy(r->script_overflow, out->script, slen);
        } else {
            r->script_len = (uint16_t)sizeof(r->script);
            memcpy(r->script, out->script, sizeof(r->script));
        }
    }

    utxo_import_row_classify_script(r);
    c->nrows++;
    return true;
}

int utxo_import_decode_entry(const struct utxo_import_raw_entry *raw,
                             struct utxo_import_row *out,
                             int max_rows)
{
    if (!raw || !out || max_rows <= 0)
        return 0;

    struct utxo_import_decode_ctx ctx = {
        .raw = raw,
        .out = out,
        .nrows = 0,
    };
    struct coins_record_decode_options opts = {
        .mode = COINS_RECORD_DECODE_UTXO_IMPORT,
        .max_outputs = (size_t)max_rows,
        .scratch = NULL,
    };
    struct coins_record_decode_ops ops = {
        .begin = NULL,
        .output = utxo_import_decode_output,
    };
    struct coins_record_decode_result res;
    enum coins_record_decode_status st =
        coins_record_decode(raw->value, raw->value_len, &opts, &ops, &ctx,
                            &res);
    if (st != COINS_RECORD_DECODE_OK)
        return 0;

    /* Replay-gated follow-up: preserve the old short-value behavior exactly.
     * If height is missing, malformed, or above the legacy importer sanity
     * range, decoded rows keep the initialized height=0.  Tightening this to a
     * reject requires full-history replay against real chainstate. */
    if (res.height_found && res.height_in_legacy_import_range) {
        for (int i = 0; i < ctx.nrows; i++)
            out[i].height = (int32_t)res.height;
    }

    return ctx.nrows;
}
