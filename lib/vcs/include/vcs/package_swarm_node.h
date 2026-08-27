/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_swarm_node — the ZCODE package swarm engine (slice 12): the
 * manifest-first, rarest-first, multi-peer download scheduler plus the
 * serving decisions and the slice-11 accounting wiring, over the frozen
 * content.v2 swarm wire codec (package_swarm.*). This layer is PURE: it
 * has no sockets, no threads of its own, and no wall clock — the caller
 * (the transport glue) drives it with explicit tick values, delivers
 * received frames, and drains the bounded outbound queue onto whatever
 * P2P transport the node already runs. The Noise v2 transport is NOT
 * required and NOT armed by this layer: chunk bytes are authenticated
 * against the content.v2 manifest (SHA3-256 per chunk, root-committed)
 * before they are ever stored, which is what "authenticated package
 * swarm" means here.
 *
 * CHUNK BINDING (owner directive): every chunk is bound to the package
 * root, the verified manifest, the file index, the chunk index, the
 * exact expected length, the SHA3-256 hash, a distinct nonzero request
 * id, and the peer session (the engine's peer handle + derived local
 * accounting key). Verification runs through
 * vcs_package_swarm_verify_data() against the exact outstanding WANT
 * BEFORE vcs_package_store_put_chunk() ever sees the bytes.
 *
 * CREDIT DISCIPLINE (slice-11 never-credit list, wired here): peers
 * never earn credit for announcements (VCS_POLICY_NO_CREDIT_ANNOUNCEMENT
 * on every ANNOUNCE), unverified bytes (UNVERIFIED), repeated copies of
 * the same request (DUPLICATE_REQUEST offence + no-credit), bytes not
 * requested (UNREQUESTED_BYTES offence), invalid chunks (INVALID_CHUNK
 * offence), or incomplete staging data. Verified chunk bytes received
 * credit vcs_service_credit_download; verified bytes served credit
 * vcs_service_credit_upload; both keyed by a domain-separated 32-byte
 * request id derived from (peer key, wire request id, package root), so
 * the slice-11 replayed-request dedup is the second line of defense
 * after the engine's own outstanding/tombstone tables.
 *
 * ACCOUNTING KEY LOCALITY: the P2P transport is unauthenticated, so a
 * peer's 33-byte accounting key is a LOCAL session pseudo-key the caller
 * derives (0x02 || SHA3-256(domain || host identity)); it scopes the
 * local service book to a transport session, it is NOT a contributor
 * identity claim, and it never reaches the reward ledger.
 *
 * POLICY CONSUMPTION (package_policy.*): inbound ANNOUNCEs are rate
 * limited per hour (announce-rate-limit → ANNOUNCE_FLOOD offence),
 * inbound WANTs per 10-minute window (request-burst-limit →
 * REQUEST_FLOOD offence), and the engine's own per-peer pulling is
 * gated by the peer tier's weekly download allowance — the FREE
 * allowance (256 MiB/week for a zero-score peer) is always honored: a
 * denial is a per-window rate limit named download-allowance-exhausted,
 * never an offence and never a ban. Tiers resolve from earned score
 * (caller-supplied callback; zero for transport pseudo-keys) plus the
 * local verified-bytes ratio, so bandwidth alone never leaves NEW_USER.
 * A peer whose book offence total reaches
 * VCS_POLICY_OFFENCE_DISCONNECT_THRESHOLD is flagged disconnect_peer.
 *
 * SCHEDULER: manifest-first (no chunk WANT before the verified manifest
 * is staged), then chunks rarest-first ACROSS downloads (downloads with
 * fewer advertising peers schedule first — package-level announcements
 * carry no per-chunk bitfield, so that is the rarity the wire honestly
 * supports) and spread least-in-flight-first across advertising peers
 * within a download. Per-peer in-flight is bounded
 * (VCS_SWARM_PEER_INFLIGHT_MAX), requests carry distinct nonzero ids
 * with a timeout and bounded attempts (each retry is a FRESH request id
 * — a repeated id is always a replay), cancellation queues CANCEL
 * frames and tombstones the outstanding ids (late DATA for a tombstone
 * earns no credit and is NOT an offence; DATA for a fulfilled id is a
 * DUPLICATE_REQUEST offence), and a peer drop requeues its in-flight
 * work onto the remaining advertisers.
 *
 * RESUME: a fetch persists a bounded record under
 * <zcode_dir>/downloads/<root-hex> (temp + fsync + atomic rename,
 * deleted on completion/cancel/failure). Engine creation replays the
 * directory: downloads whose manifest is already staged/committed in
 * the store resume in CHUNKS state with the have-bitmap rebuilt from
 * pure CAS presence probes (staging bytes never earned credit and never
 * will); the rest resume WANT_MANIFEST. A crash mid-download therefore
 * resumes from verified state only. Request-id uniqueness across
 * restarts is anchored by a persisted boot nonce
 * (<zcode_dir>/swarm_nonce, incremented and rewritten at every create):
 * request_id = (nonce << 32) | counter, so the slice-11 replayed-
 * request dedup can never swallow credit for work reissued after a
 * restart.
 *
 * THREADING: every public entry point takes the engine's internal
 * mutex. The borrowed store and service book are touched only under
 * that mutex (the store has its own lock). The DATA reply in
 * vcs_swarm_frame_result is heap-owned by the CALLER (free(3)). */

#ifndef ZCL_VCS_PACKAGE_SWARM_NODE_H
#define ZCL_VCS_PACKAGE_SWARM_NODE_H

#include "vcs/package_policy.h"
#include "vcs/package_swarm.h"
#include "vcs/package_transport.h"
#include "vcs/service_receipt.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── bounds (frozen) ────────────────────────────────────────────────── */

#define VCS_SWARM_MAX_PEERS 64u
#define VCS_SWARM_MAX_DOWNLOADS 16u
#define VCS_SWARM_PEER_INFLIGHT_MAX 8u
#define VCS_SWARM_GLOBAL_INFLIGHT_MAX 64u
#define VCS_SWARM_MAX_REQUEST_ATTEMPTS 4u /* per (chunk, peer) assignment */
#define VCS_SWARM_MAX_CHUNK_ATTEMPTS 8u   /* per chunk, all peers */
#define VCS_SWARM_REQUEST_TIMEOUT_TICKS 30u
#define VCS_SWARM_MAX_PEER_ADS 128u      /* advertised roots per peer */
#define VCS_SWARM_SEEN_IDS_PER_PEER 256u /* inbound WANT replay window */
#define VCS_SWARM_TOMBSTONES_PER_DL 64u  /* fulfilled/cancelled req ids */
#define VCS_SWARM_OUTBOUND_MAX 128u      /* queued small frames */
#define VCS_SWARM_OUTBOUND_FRAME_MAX 92u /* largest non-DATA frame */
#define VCS_SWARM_MAX_LOCAL_ANNOUNCES 64u
#define VCS_SWARM_PROVIDER_MAX 16u
#define VCS_SWARM_BURST_WINDOW_TICKS 600u   /* request burst: 10 min @1s */
#define VCS_SWARM_ANNOUNCE_WINDOW_TICKS 3600u /* announce rate: 1 h @1s */
#define VCS_SWARM_RECORD_WIRE_BYTES 59u

struct vcs_package_store;
struct vcs_service_book;
struct vcs_swarm_engine;

/* Earned-score lookup for tier resolution (the caller reads the reward
 * ledger; transport pseudo-keys normally resolve to zero). */
typedef uint64_t (*vcs_swarm_score_fn)(const uint8_t contributor[33],
                                       void *ctx);

/* Create/free. All three borrowed/owned inputs may be NULL: no store →
 * fetch/serve refuse (named), no book → accounting is skipped (tests),
 * no zcode_dir → no persistence/resume. Creation replays
 * <zcode_dir>/downloads for resume. NULL only on allocation failure
 * (logged). */
struct vcs_swarm_engine *vcs_swarm_engine_create(
    struct vcs_package_store *store, struct vcs_service_book *book,
    const char *zcode_dir, vcs_swarm_score_fn score_fn, void *score_ctx);
void vcs_swarm_engine_free(struct vcs_swarm_engine *engine);

/* The node-global engine (set by the transport glue at boot; commands
 * read it to tell live state from one-shot state). Never freed through
 * the accessor. */
void vcs_swarm_engine_set_global(struct vcs_swarm_engine *engine);
struct vcs_swarm_engine *vcs_swarm_engine_global(void);

/* Import one already-complete signed package carrier while holding the
 * engine's store-ownership lock. This is reconstruction only: it admits the
 * inner release/recipe/manifest and reuses verified CAS objects; it never
 * builds, installs, loads, or executes package code. */
enum vcs_package_transport_result vcs_swarm_engine_import_transport(
    struct vcs_swarm_engine *engine, const uint8_t transport_root[32],
    struct vcs_package_transport_import *receipt);

/* ── peer lifecycle (caller = transport glue) ───────────────────────── */

/* Register a session peer with its LOCAL accounting pseudo-key.
 * Idempotent re-add is a no-op. False (logged) when the peer table is
 * full — the named refusal, the peer is simply not swarmed with. */
bool vcs_swarm_engine_peer_add(struct vcs_swarm_engine *engine,
                               uint64_t peer, const uint8_t key[33]);
/* Drop a peer: its in-flight requests are requeued (fresh ids on
 * reassignment), its advertisements forgotten. Unknown peer: no-op. */
void vcs_swarm_engine_peer_drop(struct vcs_swarm_engine *engine,
                                uint64_t peer);
bool vcs_swarm_engine_peer_known(const struct vcs_swarm_engine *engine,
                                 uint64_t peer);

/* Apply one package-root advertisement for a registered peer from
 * LOCALLY VERIFIED evidence — e.g. a signed provider record recovered
 * from the DHT naming that root. This is not an announce frame: it does
 * not consume announce quota, raise ANNOUNCE_FLOOD, or mark the download
 * provider-restricted, because the evidence was authenticated by this
 * node before being handed in (the caller owns that duty). Idempotent on
 * both the root and re-application; true when the peer now offers the
 * root to the scheduler, false when the peer is unknown or its ad table
 * is full. Wake scheduling with vcs_swarm_engine_schedule_ready(). */
bool vcs_swarm_engine_peer_offer(struct vcs_swarm_engine *engine,
                                 uint64_t peer, const uint8_t root[32]);

/* All registered peer ids (bounded, ascending slot order). For the
 * transport glue's membership sync (drop detection). */
size_t vcs_swarm_engine_peer_ids(struct vcs_swarm_engine *engine,
                                 uint64_t *out, size_t max);

/* Queue ANNOUNCE frames to one peer for every complete tracked package
 * not already announced to this peer (bounded
 * VCS_SWARM_MAX_LOCAL_ANNOUNCES). Per-peer dedupe makes repeat calls
 * cheap: the transport glue calls this on every membership sync so
 * content completed or published AFTER the peer joined still propagates.
 * Returns the count queued. */
size_t vcs_swarm_engine_announce_to(struct vcs_swarm_engine *engine,
                                    uint64_t peer);

/* Dual-signed verified-byte receipts sit beside the frozen v1 swarm
 * wire. The engine records the dominant verified transfer with a peer;
 * the caller supplies real secp256k1 identities (not transport
 * pseudo-keys), signs, and may accept the 286-byte receipt into a
 * service book. Advisory reputation only. */
struct vcs_swarm_transfer {
    uint8_t package_root[32];
    uint64_t served;
    uint64_t fetched;
};

enum vcs_swarm_receipt_status {
    VCS_SWARM_RECEIPT_OK = 0,
    VCS_SWARM_RECEIPT_NO_TRANSFER,
    VCS_SWARM_RECEIPT_BYTES_MISMATCH,
    VCS_SWARM_RECEIPT_UNVERIFIED,
    VCS_SWARM_RECEIPT_NOT_PARTY,
    VCS_SWARM_RECEIPT_WINDOW,
    VCS_SWARM_RECEIPT_DUPLICATE,
    VCS_SWARM_RECEIPT_BAD_INPUT,
    VCS_SWARM_RECEIPT_STALE, /* claimed bytes already superseded locally */
};

const char *vcs_swarm_receipt_status_string(
    enum vcs_swarm_receipt_status status);

bool vcs_swarm_engine_transfer_snapshot(
    struct vcs_swarm_engine *engine, uint64_t peer,
    struct vcs_swarm_transfer *out);

bool vcs_swarm_receipt_draft(
    const struct vcs_swarm_transfer *xfer,
    const uint8_t local_pub[33], const uint8_t remote_pub[33],
    int64_t day_start, int64_t day_end,
    struct vcs_service_receipt *out,
    enum vcs_service_receipt_role *local_role);

enum vcs_swarm_receipt_status vcs_swarm_receipt_accept(
    struct vcs_service_book *book, const struct vcs_swarm_transfer *xfer,
    const uint8_t local_pub[33], int64_t day,
    const uint8_t *wire, size_t len);

/* Session beside the frozen v1 swarm types. Identity (ZSID) and the
 * 286-byte ZSR1 receipt ride the existing zpkgswm command as magics the
 * codec never sees. Local key is NOT a wallet key: advisory reputation
 * only. Caller serializes every entry point. */
#define VCS_SWARM_RECEIPT_IDENTITY_MAGIC "ZSID"
#define VCS_SWARM_RECEIPT_IDENTITY_BYTES \
    (4u + VCS_SERVICE_RECEIPT_PUBKEY_BYTES)
#define VCS_SWARM_RECEIPT_KEY_FILE "receipt_secp256k1.key"

struct vcs_swarm_receipt_session;

struct vcs_swarm_receipt_session *vcs_swarm_receipt_session_open(
    const char *zcode_dir);
struct vcs_swarm_receipt_session *vcs_swarm_receipt_session_open_secret(
    const uint8_t secret[32]);
void vcs_swarm_receipt_session_free(struct vcs_swarm_receipt_session *s);

bool vcs_swarm_receipt_session_local_pub(
    const struct vcs_swarm_receipt_session *s, uint8_t out[33]);
bool vcs_swarm_receipt_session_remote_pub(
    const struct vcs_swarm_receipt_session *s, uint64_t peer,
    uint8_t out[33]);
bool vcs_swarm_receipt_session_settled(
    const struct vcs_swarm_receipt_session *s, uint64_t peer);

/* Used receipt-session peer ids (bounded, slot order). Read-only. */
size_t vcs_swarm_receipt_session_peer_ids(
    const struct vcs_swarm_receipt_session *s, uint64_t *out, size_t max);

bool vcs_swarm_receipt_identity_encode(
    const struct vcs_swarm_receipt_session *s, uint8_t *out, size_t cap,
    size_t *len);
/* Encode once per peer. False if already sent or the table is full. */
bool vcs_swarm_receipt_identity_take(
    struct vcs_swarm_receipt_session *s, uint64_t peer, uint8_t *out,
    size_t cap, size_t *len);
bool vcs_swarm_receipt_identity_note(
    struct vcs_swarm_receipt_session *s, uint64_t peer,
    const uint8_t *payload, size_t len);

bool vcs_swarm_receipt_session_offer(
    struct vcs_swarm_receipt_session *s,
    const struct vcs_swarm_transfer *xfer, uint64_t peer, int64_t day,
    uint8_t out[VCS_SERVICE_RECEIPT_WIRE_BYTES]);

enum vcs_swarm_receipt_status vcs_swarm_receipt_session_handle(
    struct vcs_swarm_receipt_session *s, struct vcs_service_book *book,
    const struct vcs_swarm_transfer *xfer, uint64_t peer, int64_t day,
    const uint8_t *wire, size_t len, uint8_t **reply, size_t *reply_len);

/* ── inbound frames ─────────────────────────────────────────────────── */

enum vcs_swarm_penalty {
    VCS_SWARM_PENALTY_NONE = 0,
    VCS_SWARM_PENALTY_MALFORMED,        /* codec parse failure */
    VCS_SWARM_PENALTY_ANNOUNCE_FLOOD,   /* over announce-rate-limit */
    VCS_SWARM_PENALTY_REQUEST_FLOOD,    /* over request-burst-limit */
    VCS_SWARM_PENALTY_REPLAYED_REQUEST, /* repeated inbound WANT id */
    VCS_SWARM_PENALTY_UNREQUESTED_DATA, /* DATA we never asked for */
    VCS_SWARM_PENALTY_REPLAYED_DATA,    /* DATA for a fulfilled id */
    VCS_SWARM_PENALTY_INVALID_DATA,     /* hash/coordinate mismatch */
};

struct vcs_swarm_frame_result {
    enum vcs_swarm_penalty penalty;
    const char *rule;      /* static string naming the rule; NULL/none */
    bool disconnect_peer;  /* book offence total >= the threshold */
    uint8_t *reply;        /* DATA frame, heap, CALLER frees; may be NULL */
    size_t reply_len;
};

/* Deliver one received frame (the exact payload bytes of the transport
 * message). Malformed frames never reach the codec's callers twice:
 * they are penalized and dropped here. `day` is the civil day, `now` the
 * caller's tick clock. */
struct vcs_swarm_frame_result vcs_swarm_engine_handle_frame(
    struct vcs_swarm_engine *engine, uint64_t peer, const uint8_t *frame,
    size_t frame_len, int64_t day, uint64_t now);

/* ── operator fetch / cancel ────────────────────────────────────────── */

enum vcs_swarm_fetch_result {
    VCS_SWARM_FETCH_OK = 0,        /* download active (new or resumed) */
    VCS_SWARM_FETCH_ALREADY_COMPLETE, /* store already holds every chunk */
    VCS_SWARM_FETCH_NO_STORE,      /* engine has no store */
    VCS_SWARM_FETCH_FULL,          /* VCS_SWARM_MAX_DOWNLOADS reached */
    VCS_SWARM_FETCH_RECORD_IO,     /* download record would not persist */
    VCS_SWARM_FETCH_BYTE_LIMIT,    /* package exceeds caller-owned bound */
    VCS_SWARM_FETCH_BOUND_NOT_OWNED, /* existing work has a looser bound */
    VCS_SWARM_FETCH_BAD_INPUT,
    VCS_SWARM_FETCH_NO_PROVIDER,   /* directed fetch has no usable peer */
};
const char *vcs_swarm_fetch_result_string(enum vcs_swarm_fetch_result r);

/* Fetch a package by root from the swarm (idempotent: an active download
 * for the same root reports OK). Persists the resumable record FIRST;
 * the caller may schedule immediately with vcs_swarm_engine_schedule_ready()
 * or let the periodic tick do so. */
enum vcs_swarm_fetch_result vcs_swarm_engine_fetch(
    struct vcs_swarm_engine *engine, const uint8_t package_root[32],
    int64_t day, uint64_t now);

/* Provider-directed form used by semantic discovery. The root is permanently
 * marked restricted in its resumable record; only these current authenticated
 * transport peer handles may receive manifest/chunk WANTs. At least one
 * nonzero authenticated handle is required; an empty/zero-only set is
 * refused without creating resumable state. Re-invocation replaces the
 * transient handles after reconnect/restart. */
enum vcs_swarm_fetch_result vcs_swarm_engine_fetch_from(
    struct vcs_swarm_engine *engine, const uint8_t package_root[32],
    int64_t day, uint64_t now, const uint64_t *provider_peers,
    size_t provider_count);

/* Generic provider-directed fetch with a persistent content-byte ceiling.
 * The manifest is verified and parsed first; an oversized package is failed
 * before any content chunk is requested or stored. */
enum vcs_swarm_fetch_result vcs_swarm_engine_fetch_from_bounded(
    struct vcs_swarm_engine *engine, const uint8_t package_root[32],
    int64_t day, uint64_t now, const uint64_t *provider_peers,
    size_t provider_count, uint64_t maximum_package_bytes);

/* Cancel an active download: queues CANCEL per outstanding request,
 * tombstones the ids, deletes the record. False when not active. */
bool vcs_swarm_engine_cancel(struct vcs_swarm_engine *engine,
                             const uint8_t package_root[32], uint64_t now);

/* ── scheduler tick + outbound drain ────────────────────────────────── */

/* Drive timeouts/retries and new assignments. Tick-rate independent:
 * deadlines and windows are in the caller's tick units. */
void vcs_swarm_engine_tick(struct vcs_swarm_engine *engine, int64_t day,
                           uint64_t now);

/* Event-driven scheduler edge. Issues assignments that are ready from facts
 * already held by the engine, but deliberately does NOT advance timeouts,
 * windows, or any lifecycle clock. Safe to call after a fetch registration or
 * verified DATA frame; repeated calls deduplicate against in-flight requests. */
void vcs_swarm_engine_schedule_ready(struct vcs_swarm_engine *engine,
                                     int64_t day, uint64_t now);

/* Pop one queued outbound frame (ANNOUNCE/WANT/CANCEL, bounded
 * VCS_SWARM_OUTBOUND_FRAME_MAX). peer_filter != 0 pops only frames for
 * that peer. False when empty. */
bool vcs_swarm_engine_next_outbound(struct vcs_swarm_engine *engine,
                                    uint64_t peer_filter, uint64_t *peer_out,
                                    uint8_t *out, size_t *out_len);

/* ── status (typed-command + diagnostics surfaces) ──────────────────── */

enum vcs_swarm_download_state {
    VCS_SWARM_DL_INACTIVE = 0,   /* no engine record */
    VCS_SWARM_DL_WANT_MANIFEST,  /* manifest WANT outstanding/awaiting */
    VCS_SWARM_DL_CHUNKS,         /* manifest verified; chunks in flight */
    VCS_SWARM_DL_COMPLETE,       /* every chunk verified into the CAS */
    VCS_SWARM_DL_FAILED,         /* named terminal failure (rule set) */
};
const char *vcs_swarm_download_state_string(enum vcs_swarm_download_state s);

struct vcs_swarm_download_status {
    enum vcs_swarm_download_state state;
    const char *rule;         /* static; the named failure when FAILED */
    uint32_t advertisers;     /* known peers advertising the root */
    uint32_t inflight;        /* outstanding requests */
    uint32_t present_chunks;  /* verified into the CAS */
    uint32_t total_chunks;    /* 0 until the manifest is verified */
    uint64_t present_bytes;
    uint64_t total_bytes;     /* manifest total; 0 until verified */
    uint64_t fetched_bytes;   /* verified bytes pulled by this download */
    /* Volatile transfer accounting for this engine run. Request counters
     * include retries; transferred counters include only verified DATA.
     * Reused counters snapshot CAS hits immediately after the manifest is
     * admitted, before any missing chunk is requested. */
    uint64_t requested_bytes;
    uint64_t transferred_bytes;
    uint64_t reused_bytes;
    uint32_t requested_objects;
    uint32_t transferred_objects;
    uint32_t reused_objects;
    uint64_t maximum_package_bytes; /* 0 unbounded; persisted fetch ceiling */
};

bool vcs_swarm_engine_download_status(struct vcs_swarm_engine *engine,
                                      const uint8_t package_root[32],
                                      struct vcs_swarm_download_status *out);

/* Downloads currently in flight (want-manifest or downloading). The
 * transport glue's timer uses it for the honest idle report: zero active
 * downloads + an empty outbound queue is "legitimately nothing to do". */
size_t vcs_swarm_engine_active_downloads(struct vcs_swarm_engine *engine);

struct vcs_swarm_peer_info {
    uint64_t peer;
    uint8_t key[33];
    enum vcs_policy_tier tier;
    uint32_t inflight;
    uint64_t verified_served;  /* bytes we verifiably served this peer */
    uint64_t verified_from;    /* verified bytes this peer served us */
    bool allowance_exhausted;  /* download-allowance-exhausted this week */
    uint32_t offence_total;    /* book offence tally for the key */
};

/* Peers currently advertising a root, ascending peer id (deterministic).
 * Returns the row count written (<= out_max). */
size_t vcs_swarm_engine_peers_for(struct vcs_swarm_engine *engine,
                                  const uint8_t package_root[32],
                                  struct vcs_swarm_peer_info *out,
                                  size_t out_max);

/* Union of roots peers have ANNOUNCEd this session, sorted by root.
 * `advertisers` is how many known peers listed that root. Does not
 * invent replica counts beyond this engine's live advertisements. */
struct vcs_swarm_advertised {
    uint8_t root[32];
    uint32_t advertisers;
};

size_t vcs_swarm_engine_advertised(struct vcs_swarm_engine *engine,
                                   struct vcs_swarm_advertised *out,
                                   size_t max);

#endif /* ZCL_VCS_PACKAGE_SWARM_NODE_H */
