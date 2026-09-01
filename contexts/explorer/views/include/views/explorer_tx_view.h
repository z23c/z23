/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer transaction view — the /explorer/tx/{txid} page (native +
 * RPC-proxy variants) and the bad-request / not-found error pages. The
 * controller parses the request, fetches the transaction (from mempool /
 * tx index / on-disk block, or via the RPC proxy), packs the fields it has
 * already computed into the structs below, and delegates all HTML assembly
 * here. */

#ifndef ZCL_VIEWS_EXPLORER_TX_VIEW_H
#define ZCL_VIEWS_EXPLORER_TX_VIEW_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* ── Shared output/input row kinds ─────────────────────────── */
enum explorer_tx_io_kind {
    EXPLORER_TX_IO_OP_RETURN = 0, /* OP_RETURN / nulldata */
    EXPLORER_TX_IO_ADDRESS,       /* has a destination address */
    EXPLORER_TX_IO_UNKNOWN,       /* non-standard / unknown */
};

/* ── RPC-proxy transaction page ────────────────────────────── */

/* One output row for the RPC-proxy tx page. */
struct explorer_tx_rpc_out_row {
    enum explorer_tx_io_kind kind;
    int  index;
    char addr[64];   /* destination address (kind == ADDRESS) */
    char value[32];  /* formatted "X.YYYYYYYY" */
};

struct explorer_tx_rpc_view_data {
    char    txid[65];
    int64_t confirmations;
    int64_t size;
    int64_t version;
    int64_t locktime;

    bool    has_block;
    char    blockhash[65];
    int64_t block_height;

    bool    has_expiry;
    int64_t expiry;

    bool    has_value_balance;
    char    value_balance[32]; /* formatted "X.YYYYYYYY" */

    bool    has_outputs;       /* the "vout":[ array was present */
    const struct explorer_tx_rpc_out_row *out_rows;
    size_t  num_out_rows;

    int64_t shielded_spend;
    int64_t shielded_output;
    int64_t joinsplit;
};

/* Render the RPC-proxy tx detail page. Returns bytes written. */
size_t explorer_view_tx_rpc(const struct explorer_tx_rpc_view_data *d,
                            uint8_t *r, size_t max);

/* Render the RPC-proxy "Transaction Not Found" 404 page. `param` is the raw
 * (already validated as 64-hex) txid echoed in the page. Returns bytes. */
size_t explorer_view_tx_not_found_rpc(const char *param,
                                      uint8_t *r, size_t max);

/* ── Native transaction page ───────────────────────────────── */

/* One input row for the native tx page. */
struct explorer_tx_in_row {
    bool is_coinbase;
    /* coinbase row */
    char subsidy[32];     /* formatted block reward */
    /* prevout row */
    char prev_hash[65];   /* full 64-hex prevout txid */
    char prev_short[18];  /* "AAAAAAAA...BBBB" */
    uint32_t prev_n;
    bool have_value;      /* prev output value was found */
    char value[32];       /* formatted prev output value (have_value) */
    size_t index;
};

/* One output row for the native tx page. */
struct explorer_tx_out_row {
    enum explorer_tx_io_kind kind;
    size_t index;
    char addr[64];        /* destination address (kind == ADDRESS) */
    size_t script_size;   /* scriptPubKey byte length (OP_RETURN / unknown) */
    char value[32];       /* formatted "X.YYYYYYYY" */
};

/* ZSLP token sub-card. */
enum explorer_tx_slp_kind {
    EXPLORER_TX_SLP_NONE = 0,
    EXPLORER_TX_SLP_GENESIS,
    EXPLORER_TX_SLP_SEND,
    EXPLORER_TX_SLP_MINT,
};

struct explorer_tx_slp_data {
    enum explorer_tx_slp_kind kind;
    /* GENESIS */
    char     ticker[128];        /* html-escaped */
    char     name[256];          /* html-escaped */
    unsigned decimals;
    char     initial_supply[32]; /* decimal string */
    bool     has_doc_url;
    char     doc_url[512];       /* html-escaped */
    /* SEND / MINT */
    char     token_id[65];
    /* SEND */
    int      num_outputs;
    uint64_t output_quantities[20]; /* matches struct slp_message */
    /* MINT */
    char     mint_quantity[32];     /* decimal string */
};

struct explorer_tx_view_data {
    char    txid[65];
    bool    in_mempool;
    int     confirmations;

    bool    has_block;
    int     block_height;
    char    block_height_fmt[32]; /* comma-formatted */

    int     version;
    bool    overwintered;
    size_t  size;
    uint32_t lock_time;

    bool    has_expiry;
    uint32_t expiry_height;

    bool    has_value_balance;    /* overwintered && version>=4 */
    char    value_balance[32];

    /* Inputs */
    size_t  num_vin;
    const struct explorer_tx_in_row *in_rows;
    size_t  num_in_rows;

    /* Outputs */
    size_t  num_vout;
    const struct explorer_tx_out_row *out_rows;
    size_t  num_out_rows;
    char    total_out[32];        /* formatted total */

    /* Shielded */
    size_t  num_shielded_spend;
    size_t  num_shielded_output;
    size_t  num_joinsplit;
    char    joinsplit_in[32];     /* formatted vpub_old sum */
    char    joinsplit_out[32];    /* formatted vpub_new sum */

    /* ZSLP */
    struct explorer_tx_slp_data slp;
};

/* Render the native tx detail page. Returns bytes written. */
size_t explorer_view_tx(const struct explorer_tx_view_data *d,
                        uint8_t *r, size_t max);

/* Render the native "Invalid Transaction ID" 400 page. Returns bytes. */
size_t explorer_view_tx_invalid(uint8_t *r, size_t max);

/* Render the native "Transaction Not Found" 404 page. `safe_param` is the
 * already-html-escaped requested txid. Returns bytes. */
size_t explorer_view_tx_not_found(const char *safe_param,
                                  uint8_t *r, size_t max);

#endif
