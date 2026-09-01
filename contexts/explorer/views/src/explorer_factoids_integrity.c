/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW — data-integrity section renderer.
 *
 * Kept out of explorer_factoids_chaindata.c so the oversized chain-data
 * section file owns chain archaeology, while this file owns the last-100-block
 * integrity receipt and verification copy. Display-only; consensus and
 * projection integrity checks live below the View layer. */

#include "views/explorer_factoids_internal.h"

size_t factoids_emit_section_17_integrity(uint8_t *buf, size_t cap, size_t off,
                                          sqlite3 *db, int64_t chain_height,
                                          int64_t block_count)
{
    char *r = (char *)buf;
    size_t max = cap;

    APPEND(off, r, max,
        "<h2 id='integrity'>17. Data Integrity</h2>");

    struct explorer_transaction_stats integrity_tx_stats = {0};
    explorer_query_transaction_stats(db, &integrity_tx_stats);
    int64_t tx_count = integrity_tx_stats.total;

    char integrity_hash[128] = "";
    compute_integrity_hash(db, chain_height, integrity_hash,
                           sizeof(integrity_hash));

    {
        char blk_str[32], tx_str[32];
        fmt_comma(blk_str, sizeof(blk_str), block_count);
        fmt_comma(tx_str, sizeof(tx_str), tx_count);

        APPEND(off, r, max,
            "<div class='card'>"
            "<p><b>Chain height:</b> %" PRId64 "</p>"
            "<p><b>Indexed blocks:</b> %s</p>"
            "<p><b>Indexed transactions:</b> %s</p>"
            "<p><b>SHA3-256 coverage:</b> blocks %" PRId64 " \xe2\x80\x93 %" PRId64
            " (last 100)</p>"
            "<p><b>Integrity hash:</b><br>"
            "<code style='word-break:break-all;color:#33ff99'>%s</code></p>"
            "</div>",
            chain_height, blk_str, tx_str,
            /* compute_integrity_hash covers heights > (chain_height-100),
             * i.e. chain_height-99 .. chain_height = exactly 100 blocks.
             * The printed lower bound must be chain_height-99 (was -100,
             * which advertised 101 heights). */
            chain_height > 100 ? chain_height - 99 : (int64_t)1, chain_height,
            integrity_hash);
    }

    APPEND(off, r, max,
        "<div class='card' style='margin-top:16px'>"
        "<h3>How to Verify</h3>"
        "<p style='color:#888'>Recompute by replaying blocks from genesis. "
        "Each block's hash chains:</p>"
        "<code style='display:block;padding:12px;background:#0c0c0c;border-radius:4px;"
        "word-break:break-all;color:#ccc'>"
        "rolling_SHA3 += (height_le64 || time_le64 || num_tx_le32 || "
        "sapling_value_le64 || sprout_value_le64 || block_hash_hex_string)"
        "</code>"
        "<p style='color:#888;margin-top:8px'>36 bytes of packed integers + "
        "variable-length hex hash string per block, fed sequentially into SHA3-256.</p>"
        "<p style='color:#888;margin-top:12px'>Milestone receipts: "
        "<code>SHA3(height_le64 || block_hash_hex || fact_name_ascii)</code> "
        "\xe2\x80\x94 first 16 hex chars.</p>"
        "<p style='color:#888'>Record receipts: "
        "<code>SHA3(val1_le64 || val2_le64 || label_ascii)</code> "
        "\xe2\x80\x94 first 16 hex chars.</p>"
        "</div>");
    return off;
}
