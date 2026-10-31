/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_WALLET_VIEW_H
#define ZAPP_WALLET_VIEW_H
#include <stdbool.h>
#include <stddef.h>

/* Display strings for the Android funds screens, built from the JSON reply of
 * `z23 core wallet summary` (schema zcl.wallet_summary.v1). Pure: no I/O, no
 * Android API, no node headers. Every required field must be present and well
 * formed; otherwise known is false and every line says it is unknown, so the
 * screen never shows a zero balance that was not read. */

#define WALLET_VIEW_LINE 128

struct wallet_view {
    bool known;
    /* "1.23456789 ZCL", or "Balance unknown". */
    char balance[WALLET_VIEW_LINE];
    /* "0.5 ZCL arriving, 7 more confirmations", or "" when nothing is arriving. */
    char pending[WALLET_VIEW_LINE];
    /* "0.1 ZCL public", or "" when there is no public balance. */
    char public_line[WALLET_VIEW_LINE];
    /* "Up to date at block N", or "Catching up, N blocks behind: amounts may change". */
    char sync[WALLET_VIEW_LINE];
    /* "" when sending is allowed, otherwise one plain sentence. */
    char send[WALLET_VIEW_LINE];
    bool send_allowed;
};

/* Parse the reply and fill out. Returns false, with out set to the unknown
 * state, for a null input, invalid JSON, ok false, a wrong schema, or any
 * missing or malformed required field. */
bool wallet_view_from_summary(const char *json, struct wallet_view *out);

/* Group an address into blocks of four characters separated by one space, for
 * display: "abcdefghij" becomes "abcd efgh ij". Returns false, with out set to
 * "", for an empty or over-long address, any byte outside printable ASCII
 * without space, or an output buffer of cap bytes that is too small. */
bool wallet_view_group_address(const char *address, char *out, size_t cap);

#endif
