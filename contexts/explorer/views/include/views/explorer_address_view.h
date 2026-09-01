/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer address + search views. The controller parses the request,
 * decodes the address, fetches the balance + UTXO list via its existing
 * projection calls, packs the results into the structs below, and
 * delegates here. The search controller keeps routing/dispatch logic and
 * delegates only the error/not-found page assembly here. All address/search
 * HTML lives in this view. */

#ifndef ZCL_VIEWS_EXPLORER_ADDRESS_VIEW_H
#define ZCL_VIEWS_EXPLORER_ADDRESS_VIEW_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* One unspent-output row in the address page table. */
struct explorer_address_utxo_row {
    char     txid_hex[65];   /* full 64-hex txid (display byte order) + NUL */
    char     short_txid[18]; /* "AAAAAAAA...BBBB" */
    uint32_t vout;
    char     value[32];      /* formatted "X.YYYYYYYY" */
    int      height;
    bool     is_coinbase;
};

/* Fully-fetched address page data. The controller fills every field. */
struct explorer_address_view_data {
    const char *safe_addr;   /* already-html-escaped address string */
    bool   is_p2pkh;         /* true = P2PKH, false = P2SH */
    bool   have_balance;     /* node_db + addr_hash available */
    char   balance[32];      /* formatted "X.YYYYYYYY" (valid if have_balance) */
    bool   have_utxos;       /* node_db + addr_hash available (UTXO index up) */
    int    utxo_count;       /* total count reported (header), <= num_rows shown */
    const struct explorer_address_utxo_row *rows;
    size_t num_rows;         /* number of rows packed (min(count, 100)) */
};

/* Render the address detail page. Returns bytes written. */
size_t explorer_view_address(const struct explorer_address_view_data *d,
                             uint8_t *r, size_t max);

/* Render the "Invalid Address" 400 page. `safe_addr` is already escaped. */
size_t explorer_view_address_invalid(const char *safe_addr,
                                     uint8_t *r, size_t max);

/* ── Search page helpers ──────────────────────────────────── */

/* Render the "Invalid Search Query" 400 page with the given one-line
 * `detail` message (e.g. "Malformed percent-encoding in query."). */
size_t explorer_view_search_invalid(const char *detail, uint8_t *r, size_t max);

/* Render the "Search Results — no results" page. `safe_query` is the
 * already-html-escaped query string. Returns bytes written. */
size_t explorer_view_search_not_found(const char *safe_query,
                                      uint8_t *r, size_t max);

#endif
