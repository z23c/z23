/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer block view: block detail page renderers for native and RPC-proxy
 * data plus the "block not found" error page. The controller parses the
 * request, fetches block data, packs the structs below, and delegates all HTML
 * assembly here. */

#ifndef ZCL_VIEWS_EXPLORER_BLOCK_VIEW_H
#define ZCL_VIEWS_EXPLORER_BLOCK_VIEW_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* One transaction row in the native block page table. The controller
 * fills these from the on-disk block; the view emits each via the
 * TMPL_EXPLORER_TX_ROW template. */
struct explorer_block_tx_row {
    char   txid[65];        /* full 64-hex txid + NUL */
    char   short_txid[18];  /* "AAAAAAAA...BBBB" */
    char   type_tags[256];  /* pre-rendered Coinbase/Shielded/ZSLP tag spans */
    size_t inputs;          /* transparent + shielded + joinsplit inputs */
    size_t outputs;         /* transparent + shielded + joinsplit outputs */
    char   value[32];       /* formatted "X.YYYYYYYY" value out */
};

/* Fully-fetched native block, ready to render. The controller fills
 * every field from the block_index + on-disk block. */
struct explorer_block_view_data {
    int     height;
    int     tip;
    char    hash[65];
    char    merkle[65];
    char    sapling_root[65];
    char    nonce[65];
    char    ts[32];
    uint32_t n_tx;
    double  difficulty;
    uint32_t n_bits;
    char    sapling_val[32];  /* formatted "X.YYYYYYYY" */
    char    sprout_val[32];   /* formatted "X.YYYYYYYY" */

    bool    loaded;           /* block body available on disk */
    size_t  num_vtx;          /* tx count from the loaded block (0 if !loaded) */
    const struct explorer_block_tx_row *rows; /* up to `num_rows` rows */
    size_t  num_rows;         /* number shown (min(num_vtx, 100)) */
};

/* Render the native block detail page. Returns bytes written. */
size_t explorer_view_block(const struct explorer_block_view_data *d,
                           uint8_t *r, size_t max);

/* One transaction row for the RPC-proxy block page table. */
struct explorer_block_rpc_tx_row {
    int  index;
    char txid[65];          /* full txid (up to 64 hex) + NUL */
    char short_txid[18];    /* "AAAAAAAA...BBBB" or full if < 64 */
};

/* Fully-fetched RPC-proxy block, ready to render. */
struct explorer_block_rpc_view_data {
    int    height;
    char   hash[65];
    char   ts[32];
    int    tx_count;
    double difficulty;
    char   merkle[65];
    char   prev[65];
    char   next_hash[65];
    bool   has_tx_array;     /* the "tx":[ array was present in the block */
    const struct explorer_block_rpc_tx_row *rows;
    size_t num_rows;         /* number shown (min(tx_count, 100), capped by buf) */
};

/* Render the RPC-proxy block detail page. Returns bytes written. */
size_t explorer_view_block_rpc(const struct explorer_block_rpc_view_data *d,
                               uint8_t *r, size_t max);

/* Render the "Block Not Found" 404 page (native path). `safe_param` is
 * the already-html-escaped requested param. Returns bytes written. */
size_t explorer_view_block_not_found(const char *safe_param,
                                     uint8_t *r, size_t max);

/* Render the "Block Not Found" 404 page (RPC-proxy path — no param echo).
 * Returns bytes written. */
size_t explorer_view_block_not_found_rpc(uint8_t *r, size_t max);

#endif
