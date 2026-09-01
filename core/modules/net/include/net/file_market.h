/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Market: Crypto-incentivized P2P file sharing.
 *
 * BitTorrent-style file distribution with shielded ZCL payments
 * instead of ratio tracking. Seeders announce files with price/MB,
 * downloaders pay per batch of chunks via Sapling shielded tx.
 *
 * Privacy: shielded payments + SHA3-CTR transport + Tor onion.
 * Sybil resistance: random chunk challenges before payment. */

#ifndef ZCL_NET_FILE_MARKET_H
#define ZCL_NET_FILE_MARKET_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* P2P message commands (max 12 chars) */
#define MSG_FILE_LIST   "zfilelist"    /* gossip: file announcements */
#define MSG_FILE_OFFER  "zfileoffer"   /* signed paid offer */
#define MSG_FILE_CHAL   "zfilechal"   /* challenge: prove you have data */
#define MSG_FILE_PROOF  "zfileproof"  /* response: SHA3 of challenged chunk */
#define MSG_FILE_PAY    "zfilepay"    /* payment notification */

/* Gossip limits */
#define FILE_MARKET_MAX_TTL        4
#define FILE_MARKET_MAX_OFFERS     256   /* per-node offer cache */
#define FILE_MARKET_CHALLENGES     3     /* random chunks to challenge */
#define FILE_MARKET_BATCH_SIZE     10    /* chunks per payment batch */
#define FILE_MARKET_OFFER_VERSION  1u
#define FILE_MARKET_OFFER_VERSION_V2 2u
#define FILE_MARKET_OFFER_VERSION_LATEST FILE_MARKET_OFFER_VERSION_V2
#define FILE_MARKET_OFFER_MAX_LIFETIME_SECS 3600LL
#define FILE_MARKET_OFFER_BODY_BYTES 471u
#define FILE_MARKET_OFFER_WIRE_BYTES 535u
/* v2 appends endpoint_type u8 + onion_pubkey[32] to the v1 body. */
#define FILE_MARKET_OFFER_BODY_BYTES_V2 504u
#define FILE_MARKET_OFFER_WIRE_BYTES_V2 568u
#define FILE_MARKET_OFFER_WIRE_BYTES_MAX FILE_MARKET_OFFER_WIRE_BYTES_V2

/* Signed offer endpoint kinds (v2 endpoint_type). v1 wires imply CLEARNET. */
#define FILE_MARKET_ENDPOINT_CLEARNET 0u
#define FILE_MARKET_ENDPOINT_ONION    1u
#define FILE_MARKET_PAYMENT_VERSION  1u
#define FILE_MARKET_PAYMENT_BODY_BYTES 154u
#define FILE_MARKET_PAYMENT_WIRE_BYTES 218u
#define FILE_MARKET_PAYMENT_MEMO_BYTES 512u
#define FILE_MARKET_PAYMENT_MEMO_BODY_BYTES 120u
#define FILE_MARKET_PAYMENT_MIN_CONFIRMATIONS 1u
#define FILE_MARKET_PEER_SLOTS 64
#define FILE_MARKET_PEER_WINDOW_SECS 10
#define FILE_MARKET_PEER_WINDOW_MAX_OFFERS 8
#define FILE_MARKET_PEER_WINDOW_MAX_ATTEMPTS 32

/* Chunk size matches file_service.h: 50MB */
#define FILE_MARKET_CHUNK_SIZE     (50 * 1024 * 1024)

/* ── File Offer ─────────────────────────────────────────────────── */

struct file_offer {
    uint8_t  root_hash[32];       /* SHA3-256 of file manifest */
    char     filename[256];       /* human-readable name */
    uint64_t size_bytes;          /* total file size */
    uint32_t num_chunks;          /* ceil(size / CHUNK_SIZE) */
    int64_t  price_per_mb;        /* price in zatoshis per MB */
    uint8_t  z_addr[43];         /* seeder's Sapling payment address (raw) */
    uint8_t  peer_ip[16];        /* seeder's IP */
    uint16_t peer_port;          /* seeder's file service port */
    /* v2 endpoint: CLEARNET uses peer_ip/peer_port (onion_pubkey zero);
     * ONION uses onion_pubkey (peer_ip/peer_port zero). v1 wires decode as
     * CLEARNET with a zero onion_pubkey. */
    uint8_t  endpoint_type;
    uint8_t  onion_pubkey[32];   /* seeder's Tor v3 ed25519 key (ONION) */
    int64_t  last_seen;          /* unix timestamp */
    uint8_t  ttl;                /* remaining gossip hops */
    /* Paid offers are self-authenticating v1 contracts. These fields are
     * absent (auth_version=0) only for the free legacy ROM-artifact path. */
    uint16_t auth_version;
    uint8_t  network_genesis[32];
    uint8_t  seller_pubkey[32];
    uint64_t nonce;
    int64_t  issued_unix;
    int64_t  expires_unix;
    uint8_t  seller_signature[64];
    uint8_t  offer_id[32];       /* SHA3 of the complete signed wire */
};

/* A content root belongs to its first accepted listing. Signed refreshes
 * retain that seller; unsigned legacy refreshes may change only transport
 * freshness fields. */
bool file_market_offer_can_replace(const struct file_offer *existing,
                                   const struct file_offer *candidate);

enum file_offer_auth_error {
    FILE_OFFER_AUTH_OK = 0,
    FILE_OFFER_AUTH_ERR_NULL,
    FILE_OFFER_AUTH_ERR_VERSION,
    FILE_OFFER_AUTH_ERR_WIRE_SIZE,
    FILE_OFFER_AUTH_ERR_WIRE_MAGIC,
    FILE_OFFER_AUTH_ERR_NETWORK,
    FILE_OFFER_AUTH_ERR_CONTENT_ROOT,
    FILE_OFFER_AUTH_ERR_SELLER_KEY,
    FILE_OFFER_AUTH_ERR_NONCE,
    FILE_OFFER_AUTH_ERR_FILENAME,
    FILE_OFFER_AUTH_ERR_SIZE,
    FILE_OFFER_AUTH_ERR_CHUNKS,
    FILE_OFFER_AUTH_ERR_PRICE,
    FILE_OFFER_AUTH_ERR_TOTAL_PRICE,
    FILE_OFFER_AUTH_ERR_PAYMENT_ADDRESS,
    FILE_OFFER_AUTH_ERR_ENDPOINT,
    FILE_OFFER_AUTH_ERR_TIME,
    FILE_OFFER_AUTH_ERR_LIFETIME,
    FILE_OFFER_AUTH_ERR_SIGNATURE,
    FILE_OFFER_AUTH_ERR_KEY_MISMATCH,
    FILE_OFFER_AUTH_ERR_NETWORK_MISMATCH,
    FILE_OFFER_AUTH_ERR_EXPIRED,
    FILE_OFFER_AUTH_ERR_NOT_YET_VALID,
};

const char *file_offer_auth_error_string(enum file_offer_auth_error error);
/* Versions this binary verifies: v1 (535-byte wire) and v2 (568-byte wire).
 * Anything else is FILE_OFFER_AUTH_ERR_VERSION on decode/validate, which is
 * also how old nodes drop v2 wires cleanly. */
bool file_offer_auth_version_supported(uint16_t version);
/* Exact signed wire size for a supported version, 0 otherwise. */
size_t file_offer_auth_wire_size(uint16_t version);
/* Exact seller amount: ceil(size_bytes * price_per_mb / 1 MiB), bounded to
 * ZClassic MAX_MONEY. No floating point is permitted in settlement logic. */
bool file_market_offer_total_zat(const struct file_offer *offer,
                                 int64_t *out_total_zat);
/* Exact price for one contiguous chunk range. The final partial chunk is
 * charged only for its real bytes; every range uses integer ceil division and
 * is bounded to MAX_MONEY. */
bool file_market_offer_range_zat(const struct file_offer *offer,
                                 uint32_t chunk_start,
                                 uint32_t chunks_paid,
                                 int64_t *out_total_zat);
enum file_offer_auth_error file_offer_auth_validate(
    const struct file_offer *offer);
enum file_offer_auth_error file_offer_auth_validate_at(
    const struct file_offer *offer, int64_t now_unix);
enum file_offer_auth_error file_offer_auth_encode(
    const struct file_offer *offer,
    uint8_t out[FILE_MARKET_OFFER_WIRE_BYTES]);
/* Capacity-taking encode: v1 produces exactly 535 bytes, v2 exactly 568.
 * Callers handling both versions size out with
 * FILE_MARKET_OFFER_WIRE_BYTES_MAX. */
enum file_offer_auth_error file_offer_auth_encode_into(
    const struct file_offer *offer, uint8_t *out, size_t out_cap,
    size_t *out_len);
enum file_offer_auth_error file_offer_auth_decode(
    const uint8_t *wire, size_t wire_len, struct file_offer *out);
enum file_offer_auth_error file_offer_auth_body_root(
    const struct file_offer *offer, uint8_t out[32]);
enum file_offer_auth_error file_offer_auth_offer_id(
    const struct file_offer *offer, uint8_t out[32]);
enum file_offer_auth_error file_offer_auth_seal(
    struct file_offer *offer, const uint8_t seller_seed[32]);
enum file_offer_auth_error file_offer_auth_verify_signature(
    const struct file_offer *offer);
enum file_offer_auth_error file_offer_auth_verify_at(
    const struct file_offer *offer,
    const uint8_t expected_network_genesis[32], int64_t now_unix);

enum file_market_offer_ingest {
    FILE_MARKET_INGEST_NEW = 0,
    FILE_MARKET_INGEST_DEDUP,
    FILE_MARKET_INGEST_INVALID,
    FILE_MARKET_INGEST_EXPIRED,
    FILE_MARKET_INGEST_RATE_LIMITED,
    FILE_MARKET_INGEST_CONFLICT,
    FILE_MARKET_INGEST_PERSIST_FAILED,
};

typedef bool (*file_market_offer_persist_fn)(
    const struct file_offer *offer, void *ctx);

/* Verify a paid offer before it enters cache/persistence. The exact signed
 * wire is network-bound, expiry-checked, deduplicated, and peer-rate-limited.
 * NEW/DEDUP fill out_offer; only NEW may be forwarded. */
enum file_market_offer_ingest file_market_ingest_offer_wire(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_network_genesis[32],
    int64_t peer_id, int64_t now_unix, struct file_offer *out_offer);

/* The network ingress uses this form so persistence succeeds before the
 * cache changes or the wire becomes relay-eligible. The callback runs while
 * the bounded offer-cache lock is held and must not call file-market APIs. */
enum file_market_offer_ingest file_market_ingest_offer_wire_persist(
    const uint8_t *wire, size_t wire_len,
    const uint8_t expected_network_genesis[32],
    int64_t peer_id, int64_t now_unix, struct file_offer *out_offer,
    file_market_offer_persist_fn persist, void *persist_ctx);

/* ── Chunk Challenge ────────────────────────────────────────────── */

struct file_challenge {
    uint8_t  root_hash[32];       /* which file */
    uint32_t chunk_index;         /* which chunk to prove */
};

struct file_proof {
    uint8_t  root_hash[32];       /* which file */
    uint32_t chunk_index;         /* which chunk */
    uint8_t  chunk_hash[32];      /* SHA3-256 of that chunk's data */
};

/* ── Payment Notification ───────────────────────────────────────── */

/* zfilepay.v1 is a signed payment CLAIM, not payment authority. The seller
 * unlocks only after the app service independently finds the exact confirmed
 * Sapling output and canonical memo in wallet_sapling_notes + chain
 * projections. buyer_pubkey binds that output to subsequent file requests;
 * the corresponding private seed never enters this struct or the wire. */
struct file_payment {
    uint16_t version;
    uint8_t  network_genesis[32];
    uint8_t  offer_id[32];
    uint8_t  txid[32];
    uint32_t chunk_start;
    uint32_t chunks_paid;
    int64_t  amount_zat;
    uint8_t  buyer_pubkey[32];
    uint8_t  buyer_signature[64];
    uint8_t  claim_id[32];       /* SHA3 of the complete signed wire */
};

enum file_payment_auth_error {
    FILE_PAYMENT_AUTH_OK = 0,
    FILE_PAYMENT_AUTH_ERR_NULL,
    FILE_PAYMENT_AUTH_ERR_VERSION,
    FILE_PAYMENT_AUTH_ERR_WIRE_SIZE,
    FILE_PAYMENT_AUTH_ERR_WIRE_MAGIC,
    FILE_PAYMENT_AUTH_ERR_NETWORK,
    FILE_PAYMENT_AUTH_ERR_OFFER_ID,
    FILE_PAYMENT_AUTH_ERR_TXID,
    FILE_PAYMENT_AUTH_ERR_RANGE,
    FILE_PAYMENT_AUTH_ERR_AMOUNT,
    FILE_PAYMENT_AUTH_ERR_BUYER_KEY,
    FILE_PAYMENT_AUTH_ERR_SIGNATURE,
    FILE_PAYMENT_AUTH_ERR_KEY_MISMATCH,
    FILE_PAYMENT_AUTH_ERR_CLAIM_ID,
    FILE_PAYMENT_AUTH_ERR_NETWORK_MISMATCH,
    FILE_PAYMENT_AUTH_ERR_OFFER_MISMATCH,
    FILE_PAYMENT_AUTH_ERR_MEMO,
};

const char *file_payment_auth_error_string(
    enum file_payment_auth_error error);
enum file_payment_auth_error file_payment_auth_encode(
    const struct file_payment *payment,
    uint8_t out[FILE_MARKET_PAYMENT_WIRE_BYTES]);
enum file_payment_auth_error file_payment_auth_decode(
    const uint8_t *wire, size_t wire_len, struct file_payment *out);
enum file_payment_auth_error file_payment_auth_body_root(
    const struct file_payment *payment, uint8_t out[32]);
enum file_payment_auth_error file_payment_auth_claim_id(
    const struct file_payment *payment, uint8_t out[32]);
enum file_payment_auth_error file_payment_auth_seal(
    struct file_payment *payment, const uint8_t buyer_seed[32]);
enum file_payment_auth_error file_payment_auth_verify(
    const struct file_payment *payment,
    const uint8_t expected_network_genesis[32]);
enum file_payment_auth_error file_payment_auth_verify_for_offer(
    const struct file_payment *payment, const struct file_offer *offer);
/* The on-chain Sapling memo is exactly 512 bytes. It binds the payment output
 * to the network, signed offer, chunk range, exact amount, and buyer public
 * key; all unused bytes must be zero. */
enum file_payment_auth_error file_payment_memo_encode(
    const struct file_payment *payment,
    uint8_t out[FILE_MARKET_PAYMENT_MEMO_BYTES]);
enum file_payment_auth_error file_payment_memo_verify(
    const struct file_payment *payment, const uint8_t *memo, size_t memo_len);

enum file_payment_ingest_result {
    FILE_PAYMENT_INGEST_CONFIRMED = 0,
    FILE_PAYMENT_INGEST_PENDING,
    FILE_PAYMENT_INGEST_UNKNOWN,
    FILE_PAYMENT_INGEST_CONFLICTED,
    FILE_PAYMENT_INGEST_REJECTED,
};

/* ── Download Session ───────────────────────────────────────────── */

enum file_download_state {
    FDL_IDLE        = 0,
    FDL_CHALLENGING = 1,   /* sending chunk challenges */
    FDL_PAYING      = 2,   /* creating/sending payment */
    FDL_DOWNLOADING = 3,   /* receiving chunks */
    FDL_COMPLETE    = 4,
    FDL_FAILED      = 5
};

struct file_download {
    struct file_offer offer;
    enum file_download_state state;
    uint32_t chunks_received;
    uint32_t chunks_paid_through;   /* last chunk index paid for */
    uint32_t challenges_sent;
    uint32_t challenges_passed;
    int peer_id;                    /* P2P peer serving this file */
    char output_path[512];          /* where to save */
};

/* ── Size Validation ─────────────────────────────────────────────── */

/* Compute num_chunks = ceil(size_bytes / CHUNK_SIZE) with overflow
 * guards. Returns false (and leaves *out_chunks untouched) if
 * size_bytes would make num_chunks overflow uint32_t — i.e., if
 * size_bytes > (uint64_t)UINT32_MAX * FILE_MARKET_CHUNK_SIZE. Also
 * rejects NULL out_chunks.
 *
 * Fixes zmarket_offer previously silently truncated 225 PB+
 * files to a wrong u32 chunk count via (uint32_t)(u64_expr). */
bool file_market_num_chunks_for_size(uint64_t size_bytes,
                                     uint32_t *out_chunks);

/* ── Serialization ──────────────────────────────────────────────── */

struct byte_stream;

bool file_offer_serialize(const struct file_offer *offer,
                          struct byte_stream *s);
bool file_offer_deserialize(struct file_offer *offer,
                            struct byte_stream *s);

bool file_challenge_serialize(const struct file_challenge *chal,
                              struct byte_stream *s);
bool file_challenge_deserialize(struct file_challenge *chal,
                                struct byte_stream *s);

bool file_proof_serialize(const struct file_proof *proof,
                          struct byte_stream *s);
bool file_proof_deserialize(struct file_proof *proof,
                            struct byte_stream *s);

bool file_payment_serialize(const struct file_payment *pay,
                            struct byte_stream *s);
bool file_payment_deserialize(struct file_payment *pay,
                              struct byte_stream *s);

/* ── Offer Management ───────────────────────────────────────────── */

/* Add or update an offer in the local cache. Returns true if new. */
bool file_market_add_offer(const struct file_offer *offer);

/* Get all known offers. Returns count written to out (up to max). */
int file_market_get_offers(struct file_offer *out, size_t max);

/* Find offers by root hash. Returns true if found. */
bool file_market_find_offer(const uint8_t root_hash[32],
                            struct file_offer *out);

/* Remove expired offers (older than max_age seconds). */
int file_market_prune(int64_t max_age);

/* Get offer count. */
int file_market_count(void);

/* ── Download Management ────────────────────────────────────────── */

/* Start a download. Returns session index or -1 on error. */
int file_market_start_download(const uint8_t root_hash[32],
                               const char *output_path);

/* Get active download status. Returns false if not found. */
bool file_market_get_download(const uint8_t root_hash[32],
                              struct file_download *out);

/* Update download state. Returns false if not found. */
bool file_market_update_download(const uint8_t root_hash[32],
                                 enum file_download_state state,
                                 uint32_t chunks_received,
                                 uint32_t chunks_paid_through);

/* Increment challenges_passed for a download. */
bool file_market_download_challenge_passed(const uint8_t root_hash[32]);

/* ── SQLite Persistence ─────────────────────────────────────────── */

struct node_db;

bool db_file_offer_save(struct node_db *ndb,
                        const struct file_offer *offer);
int db_file_offer_list(struct node_db *ndb,
                       struct file_offer *out, size_t max);
bool db_file_offer_find(struct node_db *ndb,
                        const uint8_t root_hash[32],
                        struct file_offer *out);
int db_file_offer_prune(struct node_db *ndb, int64_t max_age);

#endif
