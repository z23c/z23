/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW — shared internals for the multi-TU split.
 *
 * The factoids page is large (17 archaeology sections + a JSON API), so
 * the View is split across focused translation units that all live in
 * contexts/explorer/views/src/ and share these helpers:
 *
 *   - explorer_factoids_view.c     — public entry points (HTML page +
 *                                    JSON API orchestration) and the
 *                                    degraded "verified summary" fallback.
 *   - explorer_factoids_history.c  — sections 1-4 and 6: genesis, upgrades,
 *                                    mining eras, milestones, and supply.
 *   - explorer_factoids_records.c  — section 5: all-time records.
 *   - explorer_factoids_addresses.c — section 7: address statistics.
 *   - explorer_factoids_checkpoints.c — immutable checkpoint row data +
 *                                    renderer for section 12.
 *   - explorer_factoids_blocktimes.c — section 13: cadence and interval
 *                                    records.
 *   - explorer_factoids_transactions.c — section 14: transaction totals,
 *                                    records, and output script split.
 *   - explorer_factoids_empty_blocks.c — section 15: empty-block totals,
 *                                    yearly table, and records.
 *   - explorer_factoids_difficulty.c — section 16: difficulty records,
 *                                    chainwork decoding, and yearly peaks.
 *   - explorer_factoids_integrity.c — section 17: last-100-block integrity
 *                                    hash and verification instructions.
 *   - explorer_factoids_chaindata.c— sections 8-12: privacy, ZSLP,
 *                                    OP_RETURN, dust/UTXO, checkpoints.
 *
 * Each section emitter appends one logical section of HTML starting at
 * `off` and returns the new offset. The SHA3 receipt + format helpers are
 * declared `static inline` here so each TU keeps a single internal copy.
 * This is
 * a private header for the factoids view only — not part of the public
 * surface in views/explorer_factoids_view.h. */

#ifndef ZCL_VIEWS_EXPLORER_FACTOIDS_INTERNAL_H
#define ZCL_VIEWS_EXPLORER_FACTOIDS_INTERNAL_H

#include "util/ar_step_readonly.h"
#include "controllers/explorer_internal.h"
#include "crypto/sha3.h"
#include "util/template.h"
#include "views/wallet_templates_gen.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <time.h>

#define fq_i64 sql_query_i64
#define fq_text sql_query_text

/* ── SHA3-256 receipt computation ─────────────────────────── */

static inline void compute_receipt(char *hex_out, size_t hex_max,
                                   int64_t height, const char *block_hash,
                                   const char *fact_name)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    uint8_t h_le[8];
    for (int i = 0; i < 8; i++)
        h_le[i] = (uint8_t)((height >> (i * 8)) & 0xff);
    sha3_256_write(&ctx, h_le, 8);

    if (block_hash)
        sha3_256_write(&ctx, (const unsigned char *)block_hash, strlen(block_hash));
    if (fact_name)
        sha3_256_write(&ctx, (const unsigned char *)fact_name, strlen(fact_name));

    unsigned char digest[32];
    sha3_256_finalize(&ctx, digest);

    for (size_t i = 0; i < 8 && i * 2 + 2 <= hex_max; i++)
        snprintf(hex_out + i * 2, hex_max - i * 2, "%02x", digest[i]);
}

static inline void compute_full_hash(char *hex_out, size_t hex_max,
                                     const unsigned char *data, size_t data_len)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, data, data_len);
    unsigned char digest[32];
    sha3_256_finalize(&ctx, digest);
    for (int i = 0; i < 32 && (size_t)(i * 2 + 2) <= hex_max; i++)
        snprintf(hex_out + i * 2, hex_max - (size_t)(i * 2), "%02x", digest[i]);
}

/* Rolling SHA3-256 over the last 100 blocks' packed data + hash string.
 * Shared by the HTML "Data Integrity" section and the JSON API so the
 * receipt is computed in exactly one place. Writes the full 64-hex
 * digest into hex_out (must be >= 65 bytes). */
static inline void compute_integrity_hash(sqlite3 *db, int64_t chain_height,
                                          char *hex_out, size_t hex_max)
{
    if (hex_max > 0) hex_out[0] = '\0';

    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);

    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT height, hash, time, num_tx, sapling_value, "
        "COALESCE(sprout_value, 0) "
        "FROM blocks WHERE height > %" PRId64 " ORDER BY height",
        chain_height > 100 ? chain_height - 100 : (int64_t)0);

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        while (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
            int64_t h = sqlite3_column_int64(s, 0);
            const char *hash = (const char *)sqlite3_column_text(s, 1);
            int64_t t = sqlite3_column_int64(s, 2);
            int64_t ntx = sqlite3_column_int64(s, 3);
            int64_t sv = sqlite3_column_int64(s, 4);
            int64_t spv = sqlite3_column_int64(s, 5);

            /* Pack: height(8) + time(8) + num_tx(4) + sapling_value(8) +
             *       sprout_value(8) = 36 bytes */
            uint8_t data[36];
            for (int j = 0; j < 8; j++) data[j]      = (uint8_t)((h   >> (j*8)) & 0xff);
            for (int j = 0; j < 8; j++) data[8 + j]  = (uint8_t)((t   >> (j*8)) & 0xff);
            for (int j = 0; j < 4; j++) data[16 + j] = (uint8_t)((ntx >> (j*8)) & 0xff);
            for (int j = 0; j < 8; j++) data[20 + j] = (uint8_t)((sv  >> (j*8)) & 0xff);
            for (int j = 0; j < 8; j++) data[28 + j] = (uint8_t)((spv >> (j*8)) & 0xff);

            sha3_256_write(&ctx, data, 36);
            if (hash)
                sha3_256_write(&ctx, (const unsigned char *)hash, strlen(hash));
        }
        sqlite3_finalize(s);
    }

    unsigned char digest[32];
    sha3_256_finalize(&ctx, digest);
    compute_full_hash(hex_out, hex_max, digest, 32);
}

/* Receipt from two int64s + label */
static inline void compute_receipt_i64(char *hex_out, size_t hex_max,
                                       int64_t val1, int64_t val2,
                                       const char *label)
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t buf[16];
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)((val1 >> (i*8)) & 0xff);
    for (int i = 0; i < 8; i++) buf[8+i] = (uint8_t)((val2 >> (i*8)) & 0xff);
    sha3_256_write(&ctx, buf, 16);
    if (label) sha3_256_write(&ctx, (const unsigned char *)label, strlen(label));
    unsigned char digest[32];
    sha3_256_finalize(&ctx, digest);
    for (size_t i = 0; i < 8 && i * 2 + 2 <= hex_max; i++)
        snprintf(hex_out + i * 2, hex_max - i * 2, "%02x", digest[i]);
}

/* ── Format helpers ───────────────────────────────────────── */

/* Thin aliases over the canonical formatters in explorer_internal.h /
 * format_helpers.h — one definition, no reimplementation. */
static inline void fmt_time(char *buf, size_t max, int64_t t)
{
    explorer_format_time(buf, max, (uint32_t)t);
}

static inline void fmt_zcl(char *buf, size_t max, int64_t zatoshi)
{
    zcl_format_zcl(buf, max, zatoshi);
}

static inline void fmt_comma(char *buf, size_t max, int64_t val)
{
    format_with_commas(buf, max, val);
}

/* ── Shared: get block hash + time at height ─────────────── */

/* Estimate block time from height using Buttercup spacing.
 * Pre-707000: 150s/block, Post-707000: 75s/block.
 * Used as fallback when block isn't in the SQLite index. */
static inline int64_t estimate_block_time(int64_t height)
{
    const int64_t genesis_time = ZCL_EXPLORER_GENESIS_TIME;
    const int64_t buttercup_height = 707000;
    const int64_t pre_spacing = 150;
    const int64_t post_spacing = 75;

    if (height <= 0) return genesis_time;
    if (height <= buttercup_height)
        return genesis_time + height * pre_spacing;
    return genesis_time + buttercup_height * pre_spacing +
           (height - buttercup_height) * post_spacing;
}

static inline void get_block_at(sqlite3 *db, int64_t height,
                                char *hash_out, size_t hmax,
                                int64_t *time_out)
{
    hash_out[0] = '\0';
    *time_out = 0;

    /* Genesis block (height 0) is not in the SQLite index — use constants */
    if (height == 0) {
        snprintf(hash_out, hmax,
            ZCL_EXPLORER_GENESIS_HASH_DISPLAY_HEX);
        *time_out = ZCL_EXPLORER_GENESIS_TIME;
        return;
    }

    char sql[256];
    snprintf(sql, sizeof(sql),
        "SELECT hex(hash), time FROM blocks WHERE height = %" PRId64, height);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (AR_STEP_ROW_READONLY(s) == SQLITE_ROW) {
            const char *h = (const char *)sqlite3_column_text(s, 0);
            if (h) snprintf(hash_out, hmax, "%s", h);
            *time_out = sqlite3_column_int64(s, 1);
        }
        sqlite3_finalize(s);
    }

    /* Fallback: if block not in index or time=0, estimate from height */
    if (*time_out == 0 && height > 0)
        *time_out = estimate_block_time(height);
}

/* Get block time from SQLite, fallback to height-based estimate */
static inline int64_t get_block_time(sqlite3 *db, int64_t height)
{
    char sql[128];
    snprintf(sql, sizeof(sql),
        "SELECT time FROM blocks WHERE height = %" PRId64, height);
    int64_t t = fq_i64(db, sql);
    if (t <= 0 && height > 0)
        t = estimate_block_time(height);
    return t;
}

/* ── Section emitters (definitions split across the two section TUs) ──
 *
 * Each appends one logical section of the factoids HTML page starting at
 * `off` and returns the new offset. Project-internal linkage so the
 * orchestrator in explorer_factoids_view.c can call them. */

/* explorer_factoids_history.c — sections 1-4 and 6 */
size_t factoids_emit_section_1_genesis(uint8_t *buf, size_t cap, size_t off,
                                       sqlite3 *db);
size_t factoids_emit_section_2_upgrades(uint8_t *buf, size_t cap, size_t off,
                                        sqlite3 *db);
size_t factoids_emit_section_3_mining_eras(uint8_t *buf, size_t cap, size_t off,
                                           int64_t chain_height);
size_t factoids_emit_section_4_milestones(uint8_t *buf, size_t cap, size_t off,
                                          sqlite3 *db, int64_t chain_height);
size_t factoids_emit_section_6_supply(uint8_t *buf, size_t cap, size_t off,
                                      sqlite3 *db, int64_t chain_height);

/* explorer_factoids_records.c — section 5 */
size_t factoids_emit_section_5_records(uint8_t *buf, size_t cap, size_t off,
                                       sqlite3 *db);

/* explorer_factoids_addresses.c — section 7 */
size_t factoids_emit_section_7_addresses(uint8_t *buf, size_t cap, size_t off,
                                         sqlite3 *db);

/* explorer_factoids_chaindata.c — sections 8-12 */
size_t factoids_emit_section_8_privacy(uint8_t *buf, size_t cap, size_t off,
                                       sqlite3 *db);
size_t factoids_emit_section_9_zslp(uint8_t *buf, size_t cap, size_t off,
                                    sqlite3 *db);
size_t factoids_emit_section_10_opreturn(uint8_t *buf, size_t cap, size_t off,
                                         sqlite3 *db);
size_t factoids_emit_section_11_dust(uint8_t *buf, size_t cap, size_t off,
                                     sqlite3 *db);
size_t factoids_emit_section_12_checkpoints(uint8_t *buf, size_t cap, size_t off,
                                            sqlite3 *db, int64_t chain_height);
size_t factoids_emit_checkpoint_rows(uint8_t *buf, size_t cap, size_t off,
                                     sqlite3 *db, int64_t chain_height);

/* explorer_factoids_blocktimes.c — section 13 */
size_t factoids_emit_section_13_blocktimes(uint8_t *buf, size_t cap, size_t off,
                                           sqlite3 *db, int64_t chain_height);

/* explorer_factoids_transactions.c — section 14 */
size_t factoids_emit_section_14_transactions(uint8_t *buf, size_t cap, size_t off,
                                             sqlite3 *db);

/* explorer_factoids_empty_blocks.c — section 15 */
size_t factoids_emit_section_15_empty_blocks(uint8_t *buf, size_t cap, size_t off,
                                             sqlite3 *db);

/* explorer_factoids_difficulty.c — section 16 */
size_t factoids_emit_section_16_difficulty(uint8_t *buf, size_t cap, size_t off,
                                           sqlite3 *db);

/* explorer_factoids_integrity.c — section 17 */
size_t factoids_emit_section_17_integrity(uint8_t *buf, size_t cap, size_t off,
                                          sqlite3 *db, int64_t chain_height,
                                          int64_t block_count);

#endif
