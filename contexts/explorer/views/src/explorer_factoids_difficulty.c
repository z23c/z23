/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW — difficulty-history section renderer.
 *
 * Kept out of explorer_factoids_chaindata.c so the oversized chain-data
 * section file owns activity/archaeology orchestration while this file owns
 * the display-only compact-target and chainwork decoding used by section 16.
 * Consensus difficulty and PoW validation live below the View layer. */

#include "views/explorer_factoids_internal.h"
#include <math.h>

/* ── Display-only difficulty/chainwork decoders (consensus-neutral) ──
 *
 * These exist so Section 16 renders from the raw compact "bits" target and
 * stored chain_work blob directly, WITHOUT calling difficulty_from_bits
 * (which is under separate review for an inverted exponent). Pure arithmetic
 * on decoded targets — no consensus surface. */

/* Decode a compact "bits" word into its full 256-bit target as a double.
 * target = mantissa * 256^(exponent-3); mantissa = bits & 0x00ffffff,
 * exponent = bits >> 24. Good enough for magnitude/ratio display. */
static double cd_target_from_bits(uint32_t bits)
{
    int exp = (int)(bits >> 24);
    double mant = (double)(bits & 0x00ffffffu);
    return mant * pow(256.0, (double)(exp - 3));
}

/* Decode a hex-encoded little-endian chain_work blob (storage order:
 * byte[0] = least-significant) into a double magnitude. SQLite hex()
 * emits the bytes in storage order, so we accumulate from the most-
 * significant byte down. Returns 0.0 on a malformed/empty string. */
static double cd_chainwork_to_double(const char *hex_le)
{
    if (!hex_le) return 0.0;
    size_t n = strlen(hex_le);
    size_t nbytes = n / 2;
    if (nbytes == 0 || nbytes > 64) return 0.0;

    uint8_t bytes[64] = {0};
    for (size_t i = 0; i < nbytes; i++) {
        char hi = hex_le[2 * i], lo = hex_le[2 * i + 1];
        int h = (hi >= '0' && hi <= '9') ? hi - '0'
              : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
              : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : 0;
        int l = (lo >= '0' && lo <= '9') ? lo - '0'
              : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
              : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : 0;
        bytes[i] = (uint8_t)((h << 4) | l);
    }

    double val = 0.0;
    for (size_t i = nbytes; i-- > 0;)
        val = val * 256.0 + (double)bytes[i];
    return val;
}

size_t factoids_emit_section_16_difficulty(uint8_t *buf, size_t cap, size_t off,
                                           sqlite3 *db)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='difficulty'>16. Difficulty History</h2>");

    /* Difficulty records — rendered from DECODED compact-bits targets and the
     * stored chain_work blob, NOT difficulty_from_bits. All math here is
     * display-only and consensus-neutral. */
    {
        int64_t tip = fq_i64(db, "SELECT COALESCE(MAX(height),0) FROM blocks");

        /* One scan: global hardest target (MIN bits) + powLimit-floor stats
         * (0x1f07ffff = 520617983, the maximum target / minimum difficulty). */
        int64_t min_bits = 0, pl_count = 0, pl_last = 0;
        {
            sqlite3_stmt *s = NULL;
            const char *sql =
                "SELECT MIN(bits), "
                "SUM(CASE WHEN bits = 520617983 THEN 1 ELSE 0 END), "
                "MAX(CASE WHEN bits = 520617983 THEN height END) "
                "FROM blocks WHERE bits > 0";
            if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
                if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                    min_bits = sqlite3_column_int64(s, 0);
                    pl_count = sqlite3_column_int64(s, 1);
                    pl_last  = sqlite3_column_int64(s, 2);
                }
                sqlite3_finalize(s);
            }
        }
        int64_t hard_h = 0, hard_t = 0;
        {
            char sql[160];
            snprintf(sql, sizeof(sql),
                "SELECT height, time FROM blocks WHERE bits = %" PRId64 " "
                "ORDER BY height LIMIT 1", min_bits);
            struct sql_row_i64_2 row = {0};
            if (sql_query_row_i64_2(db, sql, &row)) {
                hard_h = row.v0;
                hard_t = row.v1;
            }
        }
        int64_t tip_bits = 0;
        {
            char sql[128];
            snprintf(sql, sizeof(sql),
                "SELECT bits FROM blocks WHERE height = %" PRId64, tip);
            tip_bits = fq_i64(db, sql);
        }
        /* Recent retarget uniqueness — bounded window (the all-time
         * COUNT(DISTINCT bits) over 3.16M rows exceeds the page budget). */
        struct sql_row_i64_2 uniq = {0};
        sql_query_row_i64_2(db,
            "SELECT count(DISTINCT bits), count(*) FROM blocks WHERE height >= 3000000",
            &uniq);
        /* Cumulative chain-work at the tip (stored little-endian blob). */
        char cw_hex[80] = "";
        {
            char sql[128];
            snprintf(sql, sizeof(sql),
                "SELECT hex(chain_work) FROM blocks WHERE height = %" PRId64, tip);
            fq_text(db, sql, cw_hex, sizeof(cw_hex));
        }

        double tgt_peak = cd_target_from_bits((uint32_t)min_bits);
        double tgt_now  = cd_target_from_bits((uint32_t)tip_bits);
        double fall = (tgt_peak > 0.0) ? tgt_now / tgt_peak : 0.0;
        double cw = cd_chainwork_to_double(cw_hex);
        int cw_exp10 = (cw > 0.0) ? (int)floor(log10(cw)) : 0;
        double cw_mant = (cw > 0.0) ? cw / pow(10.0, (double)cw_exp10) : 0.0;
        double cw_log2 = (cw > 0.0) ? log2(cw) : 0.0;
        double uniq_pct = uniq.v1 > 0 ? (double)uniq.v0 * 100.0 / (double)uniq.v1 : 0.0;

        char hard_ts[64], fall_s[32], pl_s[32], uq_s[32], ub_s[32], rcpt[32] = "";
        fmt_time(hard_ts, sizeof(hard_ts), hard_t);
        fmt_comma(fall_s, sizeof(fall_s), (int64_t)(fall + 0.5));
        fmt_comma(pl_s, sizeof(pl_s), pl_count);
        fmt_comma(uq_s, sizeof(uq_s), uniq.v0);
        fmt_comma(ub_s, sizeof(ub_s), uniq.v1);
        compute_receipt(rcpt, sizeof(rcpt), hard_h, "", "hardest_block");

        APPEND(off, r, max,
            "<div class='card'>"
            "<h3>Difficulty Records</h3>"
            "<p><b>All-time hardest block:</b> compact target "
            "<code>0x%08" PRIx64 "</code> at block "
            "<a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a> (%s)</p>"
            "<p><b>Easiest (powLimit) target <code>0x1f07ffff</code>:</b> used "
            "by %s blocks (genesis through block %" PRId64 ")</p>"
            "<p><b>Per-block retarget:</b> %s distinct targets across the most "
            "recent %s blocks (%.1f%% unique)</p>"
            "<p><b>Cumulative chain-work at tip:</b> ~%.2f &times; "
            "10<sup>%d</sup> (~2<sup>%.1f</sup>)</p>"
            "<p><b>Difficulty vs. the Feb-2018 peak:</b> ~%s&times; lower "
            "(from decoded compact-bits targets)</p>"
            "<p><b>SHA3 Receipt:</b> <code>%s</code></p>"
            "</div>",
            (uint64_t)((uint32_t)min_bits), hard_h, hard_h, hard_ts,
            pl_s, pl_last,
            uq_s, ub_s, uniq_pct,
            cw_mant, cw_exp10, cw_log2,
            fall_s, rcpt);
    }

    APPEND(off, r, max,
        "<p style='color:#888'>Peak difficulty per calendar year.</p>"
        "<table class='txlist'>"
        "<tr><th>Year</th><th>Peak Difficulty</th><th>Block</th><th>SHA3</th></tr>");
    {
        sqlite3_stmt *s = NULL;
        const char *sql =
            "SELECT CAST(strftime('%Y', b1.time, 'unixepoch') AS INTEGER) AS yr, "
            "MIN(b1.bits) AS min_bits, "
            "(SELECT b2.height FROM blocks b2 "
            " WHERE b2.bits = MIN(b1.bits) "
            " AND CAST(strftime('%Y', b2.time, 'unixepoch') AS INTEGER) = "
            "     CAST(strftime('%Y', b1.time, 'unixepoch') AS INTEGER) "
            " LIMIT 1) AS peak_height "
            "FROM blocks b1 "
            "WHERE b1.time > 0 AND b1.bits > 0 "
            "GROUP BY yr ORDER BY yr";
        if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
            while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
                int yr = sqlite3_column_int(s, 0);
                uint32_t bits = (uint32_t)sqlite3_column_int64(s, 1);
                int64_t ph = sqlite3_column_int64(s, 2);
                double diff = explorer_difficulty_from_bits(bits);
                char dstr[64], rcpt[32] = "";
                snprintf(dstr, sizeof(dstr), "%.4f", diff);
                compute_receipt_i64(rcpt, sizeof(rcpt), ph, (int64_t)bits,
                                    "difficulty_peak");
                APPEND(off, r, max,
                    "<tr><td>%d</td><td>%s</td>"
                    "<td><a href='/explorer/block/%" PRId64 "'>%" PRId64 "</a></td>"
                    "<td><code>%s</code></td></tr>",
                    yr, dstr, ph, ph, rcpt);
            }
            sqlite3_finalize(s);
        }
    }
    APPEND(off, r, max, "</table>");
    return off;
}
