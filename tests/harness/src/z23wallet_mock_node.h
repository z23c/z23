/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: loopback JSON-RPC mock node for z23-wallet tests. Replies come
 * from tests/fixtures/z23wallet/rpc/<scenario>/<method>.json (the result),
 * <method>.err or _all.err ("code<TAB>message"), and _script.tsv rows
 * "method<TAB>http_status<TAB>delay_ms<TAB>times<TAB>file" (method * matches any).
 * Hostile http_status values: -1 closes without a byte, -2 sends a truncated
 * header and closes, -3 never answers (holds the socket until the peer goes),
 * 999 accepts and never replies (holds delay_ms, then hangs up). No real keys. */
#ifndef Z23WALLET_MOCK_NODE_H
#define Z23WALLET_MOCK_NODE_H

#include <stdbool.h>
#include <stdint.h>

struct zw_mock;

/* Binds 127.0.0.1:0. The datadir's .cookie is read on every request. */
struct zw_mock *zw_mock_start(const char *scenario_dir, const char *datadir,
                              uint16_t *port_out);
void zw_mock_stop(struct zw_mock *m);
unsigned zw_mock_request_count(const struct zw_mock *m);
/* Request bodies seen so far contain this text? */
bool zw_mock_saw(const struct zw_mock *m, const char *needle);
/* Test helper: create datadir with a fixture cookie; returns false on failure. */
bool zw_mock_write_cookie(const char *datadir, const char *cookie_body);
/* Accept Basic "user:pass" (zclassic.conf credentials) instead of the cookie;
 * NULL or "" goes back to the cookie. */
void zw_mock_set_auth(struct zw_mock *m, const char *userpass);

#endif
