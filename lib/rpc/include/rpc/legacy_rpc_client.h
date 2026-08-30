/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Legacy-node JSON-RPC client.
 *
 * A tiny POSIX-sockets HTTP/1.1 JSON-RPC client used to talk to a
 * sibling zclassicd (the legacy C++ daemon) when bootstrapping our
 * tip from its already-synced datadir. Bookkeeping that was previously
 * private to header_probe.c lives here so other consumers
 * (legacy_body_pull, ad-hoc tooling) can share the transport without
 * forking the code.
 *
 * Design constraints:
 *   - No external HTTP/JSON deps; reuses libjson + AF_INET sockets.
 *   - Caller supplies the credentials (or asks the parser to read
 *     ~/.zclassic/zclassic.conf).
 *   - The response buffer is malloc'd by the library and ownership
 *     transfers to the caller on success — caller frees with free().
 *   - Both per-call timeout (5 s) and dynamic response growth (up
 *     to 1 MB) are baked in; this is a transport, not a streamer.
 */

#ifndef ZCL_RPC_LEGACY_RPC_CLIENT_H
#define ZCL_RPC_LEGACY_RPC_CLIENT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Parse ~/.zclassic/zclassic.conf into the supplied buffers. Returns
 * true iff both rpcuser and rpcpassword were found. *out_port (if
 * non-NULL) is updated only when rpcport is present; otherwise it
 * is left untouched. */
bool legacy_rpc_parse_conf(char *out_user, size_t user_sz,
                           char *out_pass, size_t pass_sz,
                           int *out_port);

/* Fill any empty credential field from ~/.zclassic/zclassic.conf.
 *
 * If `user` and `pass` are both already non-empty, this is a no-op and
 * returns true. Otherwise it parses the conf and copies only the
 * missing field(s) — a caller-supplied credential always wins. When
 * `port` is non-NULL and `port_is_explicit` is false, *port is also
 * updated from the conf's rpcport (if present); an explicit port is
 * never overridden.
 *
 * Returns true iff, after the fill attempt, both `user` and `pass` are
 * non-empty. Callers decide for themselves whether an incomplete set
 * is fatal (the oracle treats it as an init error; the mirror defers
 * to a later have-creds check). */
bool legacy_rpc_fill_missing_creds(char *user, size_t user_sz,
                                   char *pass, size_t pass_sz,
                                   int *port, bool port_is_explicit);

/* POST `body_json` to the local sibling zclassicd using credentials
 * parsed from ~/.zclassic/zclassic.conf. The default target is
 * 127.0.0.1:ZCLASSICD_RPC_DEFAULT_PORT unless rpcport is set in the
 * conf file.
 *
 * On success: *out_resp = NUL-terminated response buffer (HTTP
 * headers + blank line + JSON body). Caller must free(). Returns
 * true.
 *
 * On failure: *out_resp = NULL, err populated, returns false. */
bool legacy_rpc_authenticated_call(const char *body_json,
                                   char **out_resp,
                                   char *err, size_t err_sz);

/* Bounded variant for latency-sensitive observations. `timeout_ms` applies
 * independently to socket send and receive and must be in 1..60000. The
 * ordinary call above retains its five-second compatibility budget. */
bool legacy_rpc_authenticated_call_with_timeout(const char *body_json,
                                                uint32_t timeout_ms,
                                                char **out_resp,
                                                char *err, size_t err_sz);

/* POST `body_json` to host:port with HTTP Basic auth user:pass and
 * receive the full response body into a newly malloc'd buffer.
 *
 * On success: *out_resp = NUL-terminated response buffer (HTTP
 * headers + blank line + JSON body). Caller must free(). Returns
 * true.
 *
 * On failure: *out_resp = NULL, err populated, returns false.
 *
 * Buffer grows up to 1 MB; larger responses fail. 5 s send + recv
 * timeout. */
bool legacy_rpc_call(const char *host, int port,
                     const char *user, const char *pass,
                     const char *body_json,
                     char **out_resp,
                     char *err, size_t err_sz);

bool legacy_rpc_call_with_timeout(const char *host, int port,
                                  const char *user, const char *pass,
                                  const char *body_json,
                                  uint32_t timeout_ms,
                                  char **out_resp,
                                  char *err, size_t err_sz);

/* Extract the HTTP body (after the first "\r\n\r\n") from a raw
 * response. Returns NULL if no separator found. */
const char *legacy_rpc_http_body(const char *raw);

/* Parse a JSON-RPC response object whose `.result` is an integer. */
bool legacy_rpc_parse_result_int(const char *raw,
                                 int64_t *out,
                                 char *err, size_t err_sz);

/* Parse a JSON-RPC response object whose `.result` is a string. */
bool legacy_rpc_parse_result_string(const char *raw,
                                    char *out, size_t out_sz,
                                    char *err, size_t err_sz);

/* Parse a JSON-RPC batch response array. Each item must contain a string
 * `.result`. `out_strs` is an array of `expected` fixed-size slots. */
bool legacy_rpc_parse_result_string_array(const char *raw,
                                          int expected,
                                          char *out_strs,
                                          size_t slot_sz,
                                          char *err, size_t err_sz);

#endif /* ZCL_RPC_LEGACY_RPC_CLIENT_H */
