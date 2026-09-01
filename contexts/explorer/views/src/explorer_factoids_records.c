/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW - all-time records section renderer.
 *
 * Owns section 5's display-only records table. It reads already-indexed
 * explorer projections and emits HTML receipts; consensus validation remains
 * below the View layer. */

#include "views/explorer_factoids_internal.h"

/* Read a single REAL/double scalar (SELECT ... LIMIT 1). Returns `def` on
 * empty/error. The i64 helpers truncate, so hodl_history.older_1y_pct must use
 * this path. */
static double fq_double(sqlite3 *db, const char *sql, double def)
{
    sqlite3_stmt *s = NULL;
    double v = def;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW)
            v = sqlite3_column_double(s, 0);
        sqlite3_finalize(s);
    }
    return v;
}

size_t factoids_emit_section_5_records(uint8_t *buf, size_t cap, size_t off,
                                       sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max, "<h2 id='records'>5. All-Time Records</h2>"
        "<table class='txlist'>"
        "<tr><th>Record</th><th>Value</th><th>Block</th><th>Time</th><th>SHA3</th></tr>");

    #define RECORD_ROW(label, val_fmt, val_args, height_val, time_val) do { \
        char _ts[64], _rcpt[32] = ""; \
        fmt_time(_ts, sizeof(_ts), time_val); \
        compute_receipt(_rcpt, sizeof(_rcpt), height_val, "", label); \
        APPEND(off, r, max, \
            "<tr><td>" label "</td><td>" val_fmt "</td>" \
            "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>" \
            "<td>%s</td><td><code>%s</code></td></tr>", \
            val_args, (int64_t)(height_val), (int64_t)(height_val), _ts, _rcpt); \
    } while(0)

    /* Largest unspent transparent output: scans the live UTXO set, so it is
     * the largest coin still spendable today. */
    {
        struct sql_row_i64_3 row;
        const char *sql = "SELECT u.value, u.height, b.time FROM utxos u "
                          "JOIN blocks b ON u.height = b.height "
                          "ORDER BY u.value DESC LIMIT 1";
        if (sql_query_row_i64_3(db, sql, &row)) {
            char vstr[64];
            fmt_zcl(vstr, sizeof(vstr), row.v0);
            RECORD_ROW("Largest unspent transparent output",
                "%s ZCL", vstr, row.v1, row.v2);
        }
    }

    /* Largest transparent output ever created (includes coins since spent).
     * Pinning the exact tx by value times out, so no block link. */
    {
        int64_t max_ever = fq_i64(db, "SELECT MAX(value) FROM tx_outputs");
        if (max_ever > 0) {
            char vstr[64], rcpt[32] = "";
            fmt_zcl(vstr, sizeof(vstr), max_ever);
            compute_receipt_i64(rcpt, sizeof(rcpt), max_ever, 0,
                                "Largest transparent output ever");
            APPEND(off, r, max,
                "<tr><td>Largest transparent output ever</td><td>%s ZCL</td>"
                "<td style='color:#666'>spent</td>"
                "<td style='color:#666'>\xe2\x80\x94</td>"
                "<td><code>%s</code></td></tr>",
                vstr, rcpt);
        }
    }

    {
        struct sql_row_i64_3 row;
        const char *sql = "SELECT b.height, b.num_tx, b.time FROM blocks b "
                          "ORDER BY b.num_tx DESC LIMIT 1";
        if (sql_query_row_i64_3(db, sql, &row)) {
            RECORD_ROW("Most transactions in a block",
                "%" PRId64 " tx", row.v1, row.v0, row.v2);
        }
    }

    {
        struct sql_row_i64_2 row;
        const char *sql = "SELECT block_height, count(*) as cnt FROM joinsplits "
                          "GROUP BY block_height ORDER BY cnt DESC LIMIT 1";
        if (sql_query_row_i64_2(db, sql, &row)) {
            int64_t t = get_block_time(db, row.v0);
            RECORD_ROW("Most JoinSplits in a block",
                "%" PRId64, row.v1, row.v0, t);
        }
    }

    {
        struct sql_row_i64_2 row;
        const char *sql = "SELECT block_height, count(*) as cnt FROM sapling_outputs "
                          "GROUP BY block_height ORDER BY cnt DESC LIMIT 1";
        if (sql_query_row_i64_2(db, sql, &row)) {
            int64_t t = get_block_time(db, row.v0);
            RECORD_ROW("Most Sapling outputs in a block",
                "%" PRId64, row.v1, row.v0, t);
        }
    }

    {
        struct sql_row_i64_3 row;
        const char *sql = "SELECT height, bits, time FROM blocks "
                          "WHERE bits > 0 ORDER BY bits ASC LIMIT 1";
        if (sql_query_row_i64_3(db, sql, &row)) {
            double diff = explorer_difficulty_from_bits((uint32_t)row.v1);
            char dstr[64];
            snprintf(dstr, sizeof(dstr), "%.2f", diff);
            RECORD_ROW("Highest difficulty",
                "%s", dstr, row.v0, row.v2);
        }
    }

    {
        struct sql_row_i64_3 row;
        const char *sql =
            "SELECT a.height, a.time, (b.time - a.time) as gap "
            "FROM blocks a JOIN blocks b ON b.height = a.height + 1 "
            "WHERE a.time > 0 AND b.time > 0 "
            "ORDER BY gap DESC LIMIT 1";
        if (sql_query_row_i64_3(db, sql, &row)) {
            char gstr[64];
            snprintf(gstr, sizeof(gstr), "%" PRId64 "m %" PRId64 "s",
                     row.v2 / 60, row.v2 % 60);
            RECORD_ROW("Longest block gap",
                "%s", gstr, row.v0, row.v1);
        }
    }

    {
        struct sql_row_i64_3 row;
        const char *sql =
            "SELECT a.height, a.time, (b.time - a.time) as gap "
            "FROM blocks a JOIN blocks b ON b.height = a.height + 1 "
            "WHERE a.time > 0 AND b.time > 0 AND (b.time - a.time) > 0 "
            "ORDER BY gap ASC LIMIT 1";
        if (sql_query_row_i64_3(db, sql, &row)) {
            char gstr[64];
            snprintf(gstr, sizeof(gstr), "%" PRId64 "s", row.v2);
            RECORD_ROW("Shortest block gap",
                "%s", gstr, row.v0, row.v1);
        }
    }

    /* blocks.sapling_value uses zclassicd's valueDelta convention:
     * positive = t->z shielding (pool grew), negative = z->t unshielding
     * (pool shrank). */
    {
        struct sql_row_i64_3 row;
        const char *sql = "SELECT height, sapling_value, time FROM blocks "
                          "WHERE sapling_value > 0 ORDER BY sapling_value DESC LIMIT 1";
        if (sql_query_row_i64_3(db, sql, &row)) {
            char vstr[64];
            fmt_zcl(vstr, sizeof(vstr), row.v1);
            RECORD_ROW("Largest single-block shielding (t\xe2\x86\x92z)",
                "%s ZCL", vstr, row.v0, row.v2);
        }
    }

    {
        struct sql_row_i64_3 row;
        const char *sql = "SELECT height, sapling_value, time FROM blocks "
                          "WHERE sapling_value < 0 ORDER BY sapling_value ASC LIMIT 1";
        if (sql_query_row_i64_3(db, sql, &row)) {
            char vstr[64];
            fmt_zcl(vstr, sizeof(vstr), -row.v1);
            RECORD_ROW("Largest single-block unshielding (z\xe2\x86\x92t)",
                "%s ZCL", vstr, row.v0, row.v2);
        }
    }

    {
        struct sql_row_i64_2 row;
        const char *sql = "SELECT time/86400 AS d, COUNT(*) AS n FROM blocks "
                          "WHERE time>0 GROUP BY d ORDER BY n DESC LIMIT 1";
        if (sql_query_row_i64_2(db, sql, &row) && row.v1 > 0) {
            time_t day_ts = (time_t)(row.v0 * 86400);
            struct tm tmv;
            char day[16] = "?";
            if (gmtime_r(&day_ts, &tmv))
                strftime(day, sizeof(day), "%Y-%m-%d", &tmv);
            char nstr[32], rcpt[32] = "";
            fmt_comma(nstr, sizeof(nstr), row.v1);
            compute_receipt_i64(rcpt, sizeof(rcpt), row.v1, row.v0, "blocks_per_day");
            APPEND(off, r, max,
                "<tr><td>Most blocks mined in one UTC day</td><td>%s blocks</td>"
                "<td style='color:#666'>\xe2\x80\x94</td><td>%s UTC</td>"
                "<td><code>%s</code></td></tr>",
                nstr, day, rcpt);
        }
    }

    {
        struct sql_row_i64_3 row;
        const char *sql = "SELECT u.height, u.value, b.time FROM utxos u "
                          "JOIN blocks b ON u.height = b.height "
                          "ORDER BY u.height ASC LIMIT 1";
        if (sql_query_row_i64_3(db, sql, &row)) {
            char vstr[64];
            fmt_zcl(vstr, sizeof(vstr), row.v1);
            RECORD_ROW("Oldest coin still unspent",
                "%s ZCL", vstr, row.v0, row.v2);
        }
    }

    {
        double latest = fq_double(db,
            "SELECT older_1y_pct FROM hodl_history ORDER BY height DESC LIMIT 1", -1.0);
        double peak = fq_double(db,
            "SELECT MAX(older_1y_pct) FROM hodl_history", -1.0);
        int64_t sample_h = fq_i64(db,
            "SELECT height FROM hodl_history ORDER BY height DESC LIMIT 1");
        if (latest >= 0.0 && sample_h > 0) {
            char rcpt[32] = "";
            compute_receipt_i64(rcpt, sizeof(rcpt), sample_h,
                                (int64_t)(latest * 1000.0), "hodl_dormant_1y");
            APPEND(off, r, max,
                "<tr><td>Supply dormant &gt; 1 year (HODL wave)</td>"
                "<td>%.2f%% now \xc2\xb7 peak %.2f%%</td>"
                "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                "<td style='color:#666'>latest sample</td>"
                "<td><code>%s</code></td></tr>",
                latest, peak, sample_h, sample_h, rcpt);
        }
    }

    {
        int64_t pre_bc = fq_i64(db, "SELECT count(*) FROM utxos WHERE height < 707000");
        int64_t total_utxo = fq_i64(db, "SELECT count(*) FROM utxos");
        if (total_utxo > 0 && pre_bc > 0) {
            char pstr[32], tstr[32], valbuf[96];
            double pct = 100.0 * (double)pre_bc / (double)total_utxo;
            fmt_comma(pstr, sizeof(pstr), pre_bc);
            fmt_comma(tstr, sizeof(tstr), total_utxo);
            snprintf(valbuf, sizeof(valbuf), "%s of %s UTXOs (%.1f%%)",
                     pstr, tstr, pct);
            int64_t bc_time = get_block_time(db, BUTTERCUP_ACTIVATION_HEIGHT);
            RECORD_ROW("Coins predating Buttercup (still unspent)",
                "%s", valbuf, (int64_t)BUTTERCUP_ACTIVATION_HEIGHT, bc_time);
        }
    }

    #undef RECORD_ROW
    APPEND(off, r, max, "</table>");
    return off;
}
