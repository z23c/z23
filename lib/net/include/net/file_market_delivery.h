/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: buyer-authenticated paid-file request and delivery gate. */

#ifndef ZCL_NET_FILE_MARKET_DELIVERY_H
#define ZCL_NET_FILE_MARKET_DELIVERY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FILE_MARKET_DELIVERY_VERSION 3u
#define FILE_MARKET_DELIVERY_BODY_BYTES 150u
#define FILE_MARKET_DELIVERY_WIRE_BYTES 214u
/* The seal helper stamps issued_unix and the server refuses a request whose
 * signed stamp sits outside this window in either direction. This bounds a
 * leaked or logged request to a short bearer lifetime instead of the life of
 * the offer. */
#define FILE_MARKET_DELIVERY_MAX_AGE_SECS 900
#define FILE_MARKET_DELIVERY_REPLY_BYTES 84u
#define FS_MARKET_REPLY 0x07u

struct fs_session;

/* zfileget.v3 names one encrypted chunk from one signed offer. session_id is
 * derived from network genesis plus the initiator/responder handshake nonces.
 * issued_unix makes the whole wire a short-lived bearer: the onion route logs
 * full request lines to tor.log, so an unexpiring credential there would let
 * any log reader re-fetch paid chunks forever. The buyer signature therefore
 * cannot be copied onto another file-service connection or reused after the
 * freshness window. The buyer seed is accepted only by the seal helper and
 * never enters this struct, the wire, persistence, logs, or public output. */
struct file_market_delivery_request {
    uint16_t version;
    uint8_t network_genesis[32];
    uint8_t offer_id[32];
    uint32_t chunk_index;
    uint8_t buyer_pubkey[32];
    uint8_t session_id[32];
    int64_t issued_unix;
    uint8_t buyer_signature[64];
};

enum file_market_delivery_error {
    FILE_MARKET_DELIVERY_OK = 0,
    FILE_MARKET_DELIVERY_ERR_NULL,
    FILE_MARKET_DELIVERY_ERR_VERSION,
    FILE_MARKET_DELIVERY_ERR_WIRE_SIZE,
    FILE_MARKET_DELIVERY_ERR_WIRE_MAGIC,
    FILE_MARKET_DELIVERY_ERR_NETWORK,
    FILE_MARKET_DELIVERY_ERR_OFFER_ID,
    FILE_MARKET_DELIVERY_ERR_BUYER_KEY,
    FILE_MARKET_DELIVERY_ERR_SESSION,
    FILE_MARKET_DELIVERY_ERR_SIGNATURE,
    FILE_MARKET_DELIVERY_ERR_KEY_MISMATCH,
    FILE_MARKET_DELIVERY_ERR_EXPIRED,
};

const char *file_market_delivery_error_string(
    enum file_market_delivery_error error);
void file_market_delivery_session_id(
    const uint8_t network_genesis[32],
    const uint8_t initiator_nonce[32],
    const uint8_t responder_nonce[32], uint8_t out[32]);
/* Onion delivery has no fs handshake to bind nonces to, so the session id
 * is derived from the chain genesis, the signed offer identity, and the
 * buyer key instead: SHA3(session_domain || genesis || "onion" || offer_id
 * || buyer_pubkey). The named weakening vs the clearnet rule: a copied
 * onion request only re-serves an already-paid chunk to the buyer's own key
 * over an encrypted channel. */
void file_market_delivery_onion_session_id(
    const uint8_t network_genesis[32],
    const uint8_t offer_id[32],
    const uint8_t buyer_pubkey[32], uint8_t out[32]);
enum file_market_delivery_error file_market_delivery_request_encode(
    const struct file_market_delivery_request *request,
    uint8_t out[FILE_MARKET_DELIVERY_WIRE_BYTES]);
enum file_market_delivery_error file_market_delivery_request_decode(
    const uint8_t *wire, size_t wire_len,
    struct file_market_delivery_request *out);
enum file_market_delivery_error file_market_delivery_request_seal(
    struct file_market_delivery_request *request,
    const uint8_t buyer_seed[32]);
enum file_market_delivery_error file_market_delivery_request_verify(
    const struct file_market_delivery_request *request,
    const uint8_t expected_network_genesis[32],
    const uint8_t expected_session_id[32]);

/* App-layer authorization is deliberately separate from content loading.
 * file_market_delivery_prepare() always calls authorize first and calls load
 * only for FILE_MARKET_DELIVERY_AUTHORIZED. This ordering is the fail-closed
 * boundary that prevents stale, pending, conflicted, or unauthenticated
 * payment state from causing a seller content read. */
enum file_market_delivery_authorization {
    FILE_MARKET_DELIVERY_AUTHORIZED = 0,
    FILE_MARKET_DELIVERY_PENDING,
    FILE_MARKET_DELIVERY_UNKNOWN,
    FILE_MARKET_DELIVERY_CONFLICTED,
    FILE_MARKET_DELIVERY_REJECTED,
};

typedef enum file_market_delivery_authorization
(*file_market_delivery_authorize_fn)(
    const uint8_t offer_id[32], const uint8_t buyer_pubkey[32],
    uint32_t chunk_index, void *ctx);

struct file_market_delivery_chunk {
    uint8_t *data;       /* zcl_malloc-owned; delivery layer frees it */
    uint32_t size;
    uint8_t sha3[32];
};

typedef bool (*file_market_delivery_load_fn)(
    const uint8_t offer_id[32], uint32_t chunk_index,
    struct file_market_delivery_chunk *out, void *ctx);

enum file_market_delivery_status {
    FILE_MARKET_DELIVERY_READY = 0,
    FILE_MARKET_DELIVERY_MALFORMED,
    FILE_MARKET_DELIVERY_UNAUTHENTICATED,
    FILE_MARKET_DELIVERY_PAYMENT_PENDING,
    FILE_MARKET_DELIVERY_PAYMENT_UNKNOWN,
    FILE_MARKET_DELIVERY_PAYMENT_CONFLICTED,
    FILE_MARKET_DELIVERY_PAYMENT_REJECTED,
    FILE_MARKET_DELIVERY_CONTENT_UNAVAILABLE,
    FILE_MARKET_DELIVERY_RESOURCE_LIMIT,
};

struct file_market_delivery_reply {
    uint16_t version;
    enum file_market_delivery_status status;
    uint8_t offer_id[32];
    uint32_t chunk_index;
    uint32_t size;
    uint8_t sha3[32];
};

const char *file_market_delivery_status_string(
    enum file_market_delivery_status status);
bool file_market_delivery_reply_encode(
    const struct file_market_delivery_reply *reply,
    uint8_t out[FILE_MARKET_DELIVERY_REPLY_BYTES]);
bool file_market_delivery_reply_decode(
    const uint8_t *wire, size_t wire_len,
    struct file_market_delivery_reply *out);

/* Immutable-after-boot dependency injection. A NULL load callback keeps the
 * production path fail-closed until owner-registered seller content exists. */
void file_market_delivery_set_handlers(
    const uint8_t expected_network_genesis[32],
    file_market_delivery_authorize_fn authorize,
    file_market_delivery_load_fn load, void *ctx);
void file_market_delivery_reset_handlers(void);

/* Purely recognizes the zfileget magic, including malformed/truncated bodies
 * long enough to carry it. Other FS_REQUEST protocols remain untouched. */
bool file_market_delivery_is_request(const uint8_t *payload, uint32_t plen);

/* Verify + authorize + conditionally load. `out_chunk->data` is non-NULL only
 * for READY and belongs to the caller, which must free it. */
enum file_market_delivery_status file_market_delivery_prepare(
    const struct fs_session *session, const uint8_t *payload, uint32_t plen,
    struct file_market_delivery_reply *out_reply,
    struct file_market_delivery_chunk *out_chunk);

/* Onion variant of prepare: identical authorize-before-read gate, but the
 * expected session id is the onion-derived one (no fs handshake exists).
 * Reuses the same injected authorize/load ports. */
enum file_market_delivery_status file_market_delivery_prepare_onion(
    const uint8_t *payload, uint32_t plen,
    struct file_market_delivery_reply *out_reply,
    struct file_market_delivery_chunk *out_chunk);

/* Server integration: prepare, send one encrypted typed reply, then send
 * authenticated-encrypted bytes only for READY. Returns false only on a
 * transport error. */
bool file_market_delivery_serve(
    struct fs_session *session, const uint8_t client_ip[16],
    const uint8_t *payload, uint32_t plen);

/* Buyer client half. The session variant consumes an already-handshaken
 * encrypted file-service connection and is directly loopback-testable. The
 * endpoint variant targets the exact signed offer endpoint, performs a
 * bounded connection + handshake, and closes it before returning. Neither
 * function logs or renders the endpoint or buyer credential. `out_chunk` is
 * zcl_malloc-owned only when READY. */
enum file_market_delivery_status file_market_delivery_fetch_session(
    struct fs_session *session, const uint8_t network_genesis[32],
    const uint8_t offer_id[32], uint32_t chunk_index,
    const uint8_t buyer_pubkey[32], const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk);
enum file_market_delivery_status file_market_delivery_fetch_endpoint(
    const uint8_t peer_ip[16], uint16_t peer_port,
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk);
enum file_market_delivery_status file_market_delivery_fetch_session_until(
    struct fs_session *session, const uint8_t network_genesis[32],
    const uint8_t offer_id[32], uint32_t chunk_index,
    const uint8_t buyer_pubkey[32], const uint8_t buyer_seed[32],
    int64_t deadline_ms, struct file_market_delivery_chunk *out_chunk);
enum file_market_delivery_status file_market_delivery_fetch_endpoint_until(
    const uint8_t peer_ip[16], uint16_t peer_port,
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out_chunk);

/* ── Onion delivery (offer endpoint_type == FILE_MARKET_ENDPOINT_ONION) ──
 *
 * Transport: GET /market/chunk/<full hex of the signed zfileget.v3 request> with
 * an optional ?slice=k query. The GET-hex-in-path shape exists so the
 * vendored dynhost client (GET-only) needs no change. Responses carry a
 * fixed binary header followed by one chunk slice; the dynhost webserver
 * buffer caps a response at 64 KiB, so slices are 60 KiB.
 */

#define FILE_MARKET_ONION_PATH_PREFIX "/market/chunk/"
#define FILE_MARKET_ONION_SLICE_BYTES (60u * 1024u)

/* magic[8] + version u16 + status u16 + offer_id[32] + chunk_index u32 +
 * chunk_size u32 + slice_index u32 + slice_count u32 + chunk_sha3[32] +
 * slice_sha3[32] */
#define FILE_MARKET_ONION_REPLY_HEADER_BYTES 124u
#define FILE_MARKET_ONION_REPLY_MAX \
    (FILE_MARKET_ONION_REPLY_HEADER_BYTES + FILE_MARKET_ONION_SLICE_BYTES)

/* Onion-only site-route handler (the /market/chunk row in
 * net/site_routes.def). GET-only; any decodable signed request gets a 200
 * with the binary slice header (status field distinguishes READY from
 * payment-gate refusals); an undecodable path gets a 400. Returns 0 (which
 * the FAILCLOSED-style flavor turns into a 503) only when the response
 * buffer cannot hold the framed reply. */
size_t file_market_delivery_onion_handle_request(
    const char *method, const char *path,
    const uint8_t *body, size_t body_len,
    uint8_t *response, size_t response_max);

/* Buyer-side onion GET, injected so tests can loopback against
 * file_market_delivery_onion_handle_request without Tor. Writes the raw
 * response body (at most body_cap bytes) and returns false on transport
 * failure, oversize, or non-200 status. */
typedef bool (*file_market_delivery_onion_get_fn)(
    void *ctx, const char *onion_address, const char *path,
    uint8_t *body_out, size_t body_cap, size_t *body_len);

/* Deadline-aware GET port. timeout_secs is the caller's remaining bounded
 * per-request allowance, always in [1, 60]. */
typedef bool (*file_market_delivery_onion_timed_get_fn)(
    void *ctx, const char *onion_address, const char *path, int timeout_secs,
    uint8_t *body_out, size_t body_cap, size_t *body_len);

/* Fetch one paid chunk from an onion-endpoint offer: seals the onion-bound
 * signed request once, then runs the slice loop — each slice's sha3 is
 * verified before assembly and the assembled bytes are verified against the
 * reply's whole-chunk sha3. out_chunk is zcl_malloc-owned only on READY. */
enum file_market_delivery_status file_market_delivery_fetch_onion_with(
    file_market_delivery_onion_get_fn get, void *get_ctx,
    const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk);
enum file_market_delivery_status file_market_delivery_fetch_onion_with_deadline(
    file_market_delivery_onion_timed_get_fn get, void *get_ctx,
    int64_t deadline_ms, const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk);

/* Production variant: dials through the embedded Tor client
 * (tor_integration_fetch_onion_blocking). Callers must check
 * tor_integration_is_ready() first and refuse with their own named error —
 * there is never an automatic clearnet fallback. */
enum file_market_delivery_status file_market_delivery_fetch_onion_endpoint(
    const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32],
    struct file_market_delivery_chunk *out_chunk);
enum file_market_delivery_status file_market_delivery_fetch_onion_endpoint_until(
    const uint8_t seller_onion_pubkey[32],
    const uint8_t network_genesis[32], const uint8_t offer_id[32],
    uint32_t chunk_index, const uint8_t buyer_pubkey[32],
    const uint8_t buyer_seed[32], int64_t deadline_ms,
    struct file_market_delivery_chunk *out_chunk);

#endif /* ZCL_NET_FILE_MARKET_DELIVERY_H */
