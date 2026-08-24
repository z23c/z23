/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Fast File Service — SHA3-encrypted, direct TCP, max bandwidth.
 *
 * Protocol: direct TCP connection, SHA3-CTR encrypted stream.
 * - Handshake: exchange ephemeral X25519 public keys, derive with HKDF-SHA3-256
 * - Transfer: 64KB frames, all same size, SHA3-authenticated
 * - Chunks: 50MB blocks of chain data, addressed by SHA3 hash
 *
 * Frame format (64KB fixed):
 *   [4-byte type][4-byte payload_len][payload][padding][32-byte MAC]
 *   Total: always exactly 65536 bytes. Indistinguishable from random.
 *
 * Frame types:
 *   0x01 HELLO     — nonce exchange (32-byte nonce)
 *   0x02 MANIFEST  — chunk list (sha3 hashes + sizes)
 *   0x03 REQUEST   — request chunk by sha3 hash
 *   0x04 DATA      — chunk data (may span multiple frames)
 *   0x05 DONE      — transfer complete
 *   0xFF PADDING   — keepalive / anti-analysis padding */

#ifndef ZCL_FILE_SERVICE_H
#define ZCL_FILE_SERVICE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "net/fast_sync.h"
#include "net/puzzle.h"

#define FS_FRAME_SIZE    65536
#define FS_MAC_SIZE      32
#define FS_HEADER_SIZE   8     /* type(4) + payload_len(4) */
#define FS_MAX_PAYLOAD   (FS_FRAME_SIZE - FS_HEADER_SIZE - FS_MAC_SIZE)
#define FS_CHUNK_SIZE    (50 * 1024 * 1024)  /* 50 MB */
#define FS_PORT          18034               /* dedicated file service port */

/* Frame types */
#define FS_HELLO     0x01
#define FS_MANIFEST  0x02
#define FS_REQUEST   0x03
#define FS_DATA      0x04
#define FS_DONE      0x05
#define FS_CHALLENGE 0x06    /* PoW challenge (server→client) / challenge req */
#define FS_PADDING   0xFF

/* ── PoW-gated admission + resource caps (in-memory DDoS defense) ──────
 *
 * The bulk block/index stream (ALL/RNG) is public data, but streaming
 * multi-GB to any unauthenticated connection is a denial-of-service lever.
 * Before committing a worker to a large stream the server requires a valid
 * solution to a rotating, adaptive PoW challenge (struct puzzle_gate,
 * net/puzzle.h), then bounds the spend with the caps below. None of this
 * touches any consensus
 * predicate or wire consensus rule — the served bytes are byte-identical. */

/* PoW solution carried in a gated FS_REQUEST, prefixed before the request
 * body: [peer_token(32)][ts(8, LE)][nonce(8, LE)]. peer_token MUST equal the
 * handshake nonce the connection presented, binding the solution to this
 * connection. */
#define FS_POW_SOLUTION_SIZE 48

/* FS_CHALLENGE frame payload the server sends back:
 * [seed(32)][difficulty_bits(1)][server_time(8, LE)]. */
#define FS_CHALLENGE_PAYLOAD_SIZE 41

/* Per-IP concurrent large-serve cap. The honest client opens FS_NWORKERS (8)
 * parallel range connections to ONE seed, so this must clear that plus a
 * little slack for retries/manifest. */
#define FS_MAX_CONCURRENT_PER_IP 12

/* Per-connection ceilings — a single connection cannot stream forever. */
#define FS_CONN_MAX_BYTES   (4ULL * 1024 * 1024 * 1024) /* 4 GB / connection */
#define FS_CONN_MAX_SECONDS 1800                        /* 30 min / connection */

/* Per-IP volume ceiling. One full chain sync is ~7 GB across 8 workers; this
 * clears that plus retries while bounding a single abuser's uplink draw. */
#define FS_IP_MAX_BYTES_PER_HOUR (16ULL * 1024 * 1024 * 1024)

/* Per-IP accounting table size. */
#define FS_IP_TABLE_CAP 512

/* Admission verdict for a parsed large-serve request. */
enum fs_admit_result {
    FS_ADMIT_SERVE = 0,     /* valid puzzle within caps → stream the range   */
    FS_ADMIT_CHALLENGE,     /* missing/invalid/stale puzzle → send a challenge */
    FS_ADMIT_REFUSED_CAP    /* a resource cap tripped → refuse this serve     */
};

struct fs_session {
    int              fd;              /* TCP socket */
    uint8_t          key[32];         /* X25519/HKDF-SHA3 session key */
    bool             key_established; /* true after key confirmation */
    uint8_t          our_nonce[32];   /* our ephemeral public key / token */
    uint8_t          peer_nonce[32];  /* peer ephemeral public key / token */
    uint64_t         send_counter;    /* monotonic frame counter (nonce) */
    uint64_t         recv_counter;
    uint64_t         bytes_sent;
    uint64_t         bytes_received;
    int64_t          start_time;      /* for MB/s calculation */
    uint8_t          recv_payload[FS_MAX_PAYLOAD];
};

/* Initialize a session on an existing TCP socket. */
void fs_session_init(struct fs_session *s, int fd);

/* Erase session key material after the owning connection is finished. */
void fs_session_cleanup(struct fs_session *s);

/* Perform HELLO handshake — exchange ephemeral public keys and derive a
 * forward-secret shared key with X25519 + HKDF-SHA3-256. `utxo_root` is the
 * HKDF salt, binding key confirmation to the peers' shared chain state.
 * This protects against passive wire capture; the bare handshake does not
 * authenticate peer identity against an active MITM. Paid delivery separately
 * binds its signed request to these session public keys. This intentionally
 * has no fallback to the legacy all-public nonce KDF, so mixed-version peers
 * fail key confirmation instead of silently downgrading.
 * is_initiator: true if we opened the connection. */
bool fs_handshake(struct fs_session *s, const uint8_t utxo_root[32],
                   bool is_initiator);

/* Send a frame (encrypts, pads to 64KB, MACs, sends). */
bool fs_send_frame(struct fs_session *s, uint8_t type,
                    const uint8_t *payload, uint32_t payload_len);

/* Receive a frame (reads 64KB, verifies MAC, decrypts).
 * type_out and payload_out are set. payload_out points into the
 * session-local receive buffer and is valid until the next
 * fs_recv_frame call on the same session. */
bool fs_recv_frame(struct fs_session *s, uint8_t *type_out,
                    const uint8_t **payload_out, uint32_t *payload_len_out);

/* Send one raw authenticated chunk after an encrypted typed reply. */
bool fs_send_chunk_fast(struct fs_session *s, const uint8_t *data,
                        uint32_t size, const uint8_t sha3[32]);

/* Receive one raw authenticated chunk emitted by fs_send_chunk_fast().
 * `expected_sha3` comes from an already-authenticated protocol reply or
 * manifest. On success `*out` is zcl_malloc-owned and must be freed by the
 * caller. This is public so sibling protocols such as paid-file delivery can
 * reuse the one framing/MAC implementation instead of copying it. */
bool fs_recv_chunk_fast(struct fs_session *s, uint8_t **out,
                        uint32_t *out_size,
                        const uint8_t expected_sha3[32]);

/* Send and receive one private paid-file chunk with authenticated encryption.
 * This is deliberately separate from the raw authenticated fast path above:
 * public chain/package bytes do not require confidentiality, but purchased
 * content does. The receive side binds the authenticated wire size to the
 * already-encrypted market reply before allocating or reading the payload. */
bool fs_send_chunk_private(struct fs_session *s, const uint8_t *data,
                           uint32_t size, const uint8_t sha3[32]);
bool fs_recv_chunk_private(struct fs_session *s, uint8_t **out,
                           uint32_t *out_size, uint32_t expected_size,
                           const uint8_t expected_sha3[32]);

/* High-level: serve files on configured port. Runs in its own thread. */
void fs_server_start(const char *datadir, uint16_t port);
void fs_server_stop(void);
bool fs_server_is_running(void);
uint16_t fs_server_get_port(void);
bool fs_server_refresh_manifest(void);

/* Diagnostics dump (`ops state --subsystem=file_service`).
 * See CLAUDE.md "Adding state introspection". Reentrant-safe; initializes out. */
struct json_value;
bool file_service_dump_state_json(struct json_value *out, const char *key);

/* High-level: connect to peer and download all chunks. */
bool fs_client_sync(const char *peer_addr, uint16_t port,
                     const char *datadir, const uint8_t utxo_root[32]);

/* Get transfer speed stats. */
double fs_session_mbps(const struct fs_session *s);

/* ── PoW-gated admission + resource caps (testable, pure decisions) ────── */

/* The process-wide file-service PoW gate. */
struct puzzle_gate *fs_pow_gate(void);

/* Reset the gate + per-IP cap table (tests + a clean server start). */
void fs_pow_reset_state(void);

/* Parse a (possibly gated) FS_REQUEST payload. On return, *is_all / *is_rng
 * report the request kind, *puzzle points at the FS_POW_SOLUTION_SIZE-byte
 * solution prefix (or NULL if the request carried none), and for a range
 * request *rng_start / *rng_end are filled. Returns true if the payload is a
 * recognizable ALL or RNG request. */
bool fs_parse_serve_request(const uint8_t *payload, uint32_t plen,
                            bool *is_all, bool *is_rng,
                            const uint8_t **puzzle,
                            uint16_t *rng_start, uint16_t *rng_end);

/* Decide whether to admit a large serve. peer_token is the handshake nonce
 * this connection presented (the solution must be bound to it). On
 * FS_ADMIT_CHALLENGE, out_seed/out_bits/out_server_time are filled with a
 * fresh challenge to hand back to the client. Pure w.r.t. the wire — the
 * caller does the framing. */
enum fs_admit_result fs_admit_serve_pow(const uint8_t *puzzle,
                                        const uint8_t peer_token[32],
                                        uint8_t out_seed[32], int *out_bits,
                                        int64_t *out_server_time);

/* Per-IP concurrency cap. acquire() returns false if the IP already holds
 * FS_MAX_CONCURRENT_PER_IP active serves; every successful acquire MUST be
 * matched by exactly one release. */
bool fs_ip_serve_acquire(const uint8_t ip[16]);
void fs_ip_serve_release(const uint8_t ip[16]);

/* Charge n bytes to the IP's rolling hour budget. Returns false once the IP
 * exceeds FS_IP_MAX_BYTES_PER_HOUR (caller should stop serving). */
bool fs_ip_bytes_charge(const uint8_t ip[16], uint64_t n);

/* Per-connection budget predicate: false once the connection exceeds its
 * byte or wall-time ceiling. */
bool fs_conn_budget_ok(uint64_t bytes_sent, int64_t start_time, int64_t now);

/* ── Free-tier ROM artifact serving ──────────────────────────────────
 *
 * A ROM artifact chunk request rides the same fs_session transport but is
 * recognized independently of the ALL/RNG bulk-stream path:
 *   body = ["ROM"(3)][root_hash(32)][chunk_index(4, LE)]  (39 bytes)
 * ROM chunks are served FREE (no payment gate) but bounded by the rom_seed
 * per-peer concurrency + per-peer/global byte-rate caps — never the PoW/ALL
 * gate. Parsing is pure/testable. Returns true on a well-formed ROM request. */
#define FS_ROM_REQUEST_SIZE 39
bool fs_parse_rom_request(const uint8_t *payload, uint32_t plen,
                          uint8_t root_out[32], uint32_t *idx_out);

/* Per-chunk manifest request (WF2 artifact-protocol): a sibling of the "ROM"
 * chunk request that rides the same fs_session transport —
 *   body = ["RMF"(3)][chunk_root(32)]  (35 bytes)
 * — and asks the seeder for the artifact's per-chunk SHA3 manifest. Recognized
 * independently of the ROM/ALL/RNG paths. Parsing is pure/testable; returns
 * true on a well-formed manifest request. */
#define FS_ROM_MANIFEST_REQUEST_SIZE 35
bool fs_parse_rom_manifest_request(const uint8_t *payload, uint32_t plen,
                                   uint8_t root_out[32]);

/* ROM directory-listing request (RLS): a sibling of the "ROM"/"RMF" requests
 * that rides the same fs_session transport —
 *   body = ["RLS"(3)]  (3 bytes)
 * — and asks the seeder for its artifact catalog (the same {"artifacts":[...]}
 * body the onion /directory.json path serves) so a fresh clearnet node can
 * discover the checkpoint bundle manifest without the onion path. Recognized
 * independently of the ROM/RMF/ALL/RNG paths; served FREE under the same
 * rom_seed per-peer concurrency + byte-rate caps. Parsing is pure/testable;
 * returns true on a well-formed listing request. */
#define FS_ROM_LIST_REQUEST_SIZE 3
bool fs_parse_rom_list_request(const uint8_t *payload, uint32_t plen);

/* ── ROM chunk refusal reply (server→client) ─────────────────────────
 *
 * A chunk request the server declines (unknown artifact, per-connection
 * budget, per-peer inflight cap, or per-peer/global byte-rate window) is
 * answered with a small typed refusal frame on the SAME raw transport as a
 * chunk reply (fs_send_chunk_fast) — NOT the 64 KB encrypted FS_DONE frame,
 * whose ciphertext leading bytes the raw chunk reader misparses as a garbage
 * "implausible chunk size". The refusal's 4-byte size field carries an
 * impossible-as-a-chunk-size sentinel so the client decodes it unambiguously
 * (a real chunk size never exceeds ROM_SEED_CHUNK_SIZE):
 *
 *   [4B size = FS_ROM_REFUSAL_SENTINEL (LE)][1B reason][32B MAC]
 *   MAC = SHA3-256(key || send_counter || FS_ROM_REFUSAL_MAC_TAG || reason)
 *
 * The MAC binds the refusal to the session key + counter (an off-path injector
 * cannot forge one); the fixed 33-byte tail after the sentinel bounds the
 * client read (a malicious seeder cannot make the client over-read). The client
 * treats a verified refusal as a clean, retryable "peer busy — back off and
 * retry", never garbage. Per-chunk content verification remains the integrity
 * authority for delivered bytes. */
#define FS_ROM_REFUSAL_SENTINEL 0xFFFFFFFFu

enum fs_rom_refusal_reason {
    FS_ROM_REFUSE_UNKNOWN     = 0, /* unknown/undeserved chunk_root or index  */
    FS_ROM_REFUSE_CONN_BUDGET = 1, /* per-connection byte/time budget tripped */
    FS_ROM_REFUSE_INFLIGHT    = 2, /* per-peer concurrent-serve cap tripped   */
    FS_ROM_REFUSE_RATE        = 3, /* per-peer/global byte-rate window full    */
    FS_ROM_REFUSE_IO          = 4, /* server-side chunk read/alloc failure     */
    FS_ROM_REFUSE_MAX
};

/* Send a typed ROM chunk refusal frame (see the block comment above). Returns
 * false on a socket write failure. The connection is terminal after a refusal.
 * `reason` is one of enum fs_rom_refusal_reason. */
bool fs_send_chunk_refusal(struct fs_session *s, uint8_t reason);

#endif
