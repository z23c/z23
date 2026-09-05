/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Authenticated confined-terminal service on the mesh stream
 * primitive.
 *
 * The terminal is a service on mesh_stream (config/mesh_stream.h): it
 * registers the name "terminal" and receives open/data/close/tick for
 * every stream of that name, whichever side opened it. The stream
 * primitive owns the wire framing, the one session table both sides
 * share, the credit window, the per-peer cap, and the single drain, so
 * this lane carries no prefix parser, no session table and no pump of its
 * own. Streams ride the same frozen "zpkgswm" P2P message as mesh status:
 * no new wire message, no listener, no port, and the established Noise
 * session, the onion path and connman session management are inherited.
 *
 * A stream OPEN carries a mesh_terminal_open_v1 (binding the live session,
 * the pairing, and a 60-second answer window) and is answered with a
 * signed mesh_terminal_receipt_v1 — OK carrying the granted session
 * bounds as the stream's first DATA, or a named refusal riding the CLOSE
 * — only when the session is an established Noise session bound to a live
 * ZID delegation whose pairing row carries the commit-time
 * MESH_PAIRING_CAP_TERMINAL_EXEC capability. That same capability is what
 * the stream primitive demands of the peer's pairing row before an OPEN
 * ever reaches this lane. Anything less is dropped quietly or refused by
 * name; responder key material never crosses an unauthenticated channel.
 *
 * An OK receipt opens one confined terminal worker (mesh_terminal_worker):
 * the granted shell on a PTY inside the terminal-worker sandbox profile,
 * in a fresh per-terminal working directory under <datadir>/terminals.
 * Keyboard bytes arrive as bounded DATA frames under a strictly increasing
 * per-terminal sequence; screen bytes leave as bounded DATA frames from
 * the supervised pump tick. Every session ends with a named close reason,
 * a CLOSED receipt carrying the byte/duration evidence capsule, and a
 * census-verified process-group kill. The granted shell binary is the
 * operator's choice via -terminalshell=<abs path>; without it the lane
 * answers CONFINEMENT_UNAVAILABLE — an honest refusal, never a simulated
 * terminal. */

#ifndef ZCL_CONFIG_BOOT_MESH_TERMINAL_H
#define ZCL_CONFIG_BOOT_MESH_TERMINAL_H

#include "session/mesh_terminal_proto.h"
#include "session/mesh_terminal_worker.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct msg_processor;
struct node_db;
struct noise_transport_snapshot;
struct p2p_node;
struct rpc_table;
struct vcs_zcode_dht_delegation;

/* The stream service name this lane registers. */
#define MESH_TERMINAL_SERVICE_NAME "terminal"

/* The lane's own message set, carried inside a stream DATA or CLOSE
 * payload as one leading kind byte then the mesh_terminal_proto wire. A
 * stream OPEN's payload is a mesh_terminal_open_v1 and carries no kind
 * byte: an open is the only thing an open can be.
 *
 * RESIZE is a terminal-level message inside DATA, not a stream control
 * frame: geometry is the terminal's business and the stream primitive has
 * no opinion about it. RECEIPT rides DATA when the stream is live (the OK
 * grant, the CLOSED evidence) and rides CLOSE when the open was refused
 * and no stream exists to carry it. */
#define MESH_TERMINAL_MSG_RECEIPT 0x01u
#define MESH_TERMINAL_MSG_DATA 0x02u
#define MESH_TERMINAL_MSG_RESIZE 0x03u
#define MESH_TERMINAL_MSG_CLOSE 0x04u
#define MESH_TERMINAL_MSG_MAX                                \
    (1u + (MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES >         \
                   MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES      \
               ? MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES     \
               : MESH_TERMINAL_DATA_V1_MAX_WIRE_BYTES))

/* Responder-side session policy. These are the node's OWN ceilings — the
 * OK receipt's capsule states exactly these bounds and the worker enforces
 * exactly these, so a requester can never talk a node into a larger grant
 * than its receipt proves. */
#define MESH_TERMINAL_SERVICE_LIFETIME_SECONDS UINT64_C(3600)
#define MESH_TERMINAL_SERVICE_IDLE_SECONDS UINT64_C(600)
#define MESH_TERMINAL_SERVICE_MAX_BYTES_IN UINT64_C(65536)
#define MESH_TERMINAL_SERVICE_MAX_BYTES_OUT UINT64_C(1048576)

/* Four concurrent confined terminals per node. A fifth concurrent OPEN is
 * refused with CONCURRENCY_LIMIT, never queued. The streams themselves
 * live in the stream table; this is the lane's own ceiling on how many of
 * them may hold a live confined worker. */
#define MESH_TERMINAL_SESSIONS_MAX 4u

/* Receipts are valid at most this long after observation; bounded well
 * under the protocol lifetime ceiling so matches_open accepts them. */
#define MESH_TERMINAL_RECEIPT_VALIDITY_SECONDS 30u
#define MESH_TERMINAL_OPEN_ADMIT_MAX 32u
#define MESH_TERMINAL_OPEN_ADMIT_MS UINT64_C(30000)
#define MESH_TERMINAL_OPEN_RATE_PER_SECOND 4u

/* DATA messages the stream drain moves per live session per tick;
 * leftover output waits for the next tick, so a noisy shell is throttled,
 * never unbounded. With the 100 ms drain cadence this is ~640 KiB/s worst
 * case per session, far above interactive use and far under the 1 MiB
 * lifetime byte cap — and the stream's credit window stops the sender
 * dead when the requester has not read what it already has. */
#define MESH_TERMINAL_PUMP_CHUNKS_PER_TICK 16

/* Records the composition context and registers the "terminal" stream
 * service. Shutdown unregisters it, which ends every live stream: each
 * one kills its worker (census-verified) and removes its working
 * directory. */
void boot_mesh_terminal_wire(struct boot_svc_ctx *svc);
void boot_mesh_terminal_shutdown(void);

/* Registers the requester lane's nonblocking mesh_terminal_* RPC commands
 * (defined in boot_mesh_terminal_rpc.c). */
void boot_mesh_terminal_register_rpc(struct rpc_table *table);

/* Pure responder decision for an OPEN: no sockets, no locks, no I/O beyond
 * the pairing reads on ndb. `delegations` is the held-delegation snapshot;
 * `session` must be an established Noise snapshot.
 * revocation_generation_out is set on OK. Exported so the wire group test
 * drives the exact production decision without sockets. */
enum mesh_terminal_receipt_status boot_mesh_terminal_decide(
    struct node_db *ndb, const struct mesh_terminal_open_v1 *open,
    const struct noise_transport_snapshot *session,
    const struct vcs_zcode_dht_delegation *delegations,
    size_t delegation_count, const uint8_t network_genesis[32],
    uint64_t now_unix, uint64_t *revocation_generation_out);

/* Pure receipt composition + online-key signature. Capsule bytes are
 * required iff status is OK or CLOSED; refusal statuses are composed with
 * no capsule however the caller argues. For CLOSED the validity window is
 * measured from `now_unix` and is NOT clamped to the open's 60-second
 * answer window (the session outlives it; matches_open accepts CLOSED on
 * observed >= issued alone). */
bool boot_mesh_terminal_compose_receipt(
    const struct mesh_terminal_open_v1 *open,
    const struct noise_transport_snapshot *session,
    enum mesh_terminal_receipt_status status,
    const uint8_t network_genesis[32],
    const uint8_t responder_master_pubkey[32],
    const uint8_t responder_online_pubkey[32],
    const uint8_t responder_noise_static[32], uint64_t revocation_generation,
    uint64_t now_unix, const uint8_t *capsule, size_t capsule_len,
    const uint8_t responder_online_seed[32],
    struct mesh_terminal_receipt_v1 *out);

/* Render the granted-session-bounds capsule an OK receipt carries. */
bool boot_mesh_terminal_render_grant_capsule(
    uint8_t out[MESH_TERMINAL_CAPSULE_MAX], size_t *out_len);

/* Render the close-evidence capsule a CLOSED receipt carries. */
bool boot_mesh_terminal_render_close_capsule(
    uint64_t bytes_in, uint64_t bytes_out, uint64_t duration_seconds,
    enum mesh_terminal_close_reason reason,
    uint8_t out[MESH_TERMINAL_CAPSULE_MAX], size_t *out_len);

/* Mid-session authority re-check for a live responder session: true when
 * the local pairing row no longer grants terminal-exec — vanished row or
 * revoked_at stamped (REVOKED), capability stripped (REVOKED), past its
 * expiry (EXPIRED). The row is keyed by the id derived from the OPEN's
 * requester identity, exactly as the open decision keyed it — pairing ids
 * are per-side, so the open's own pairing_id (the requester-side row)
 * can never be the lookup key here. The pump tick runs this for every
 * live session so an `ops mesh pair revoke` ends the terminal within one
 * tick. The delegation itself was verified and bound at OPEN; the row is
 * the operator's live authority over the grant, and an unreadable row or
 * a failed derivation fails closed. Exported so the wire group test
 * drives the exact check. */
bool boot_mesh_terminal_pairing_lost(struct node_db *ndb,
                                     const struct mesh_terminal_open_v1 *open,
                                     uint64_t now_unix,
                                     enum mesh_terminal_close_reason *reason_out);

/* ── Requester lane ──────────────────────────────────────────────────── */

/* Named outcomes of an open attempt; every non-OK value is a final,
 * honest refusal with no session reserved. */
enum boot_mesh_terminal_open_result {
    MESH_TERMINAL_OPEN_OK = 0,
    MESH_TERMINAL_OPEN_BAD_ARGUMENT = 1,
    MESH_TERMINAL_OPEN_UNAVAILABLE = 2,
    MESH_TERMINAL_OPEN_NOISE_DISABLED = 3,
    MESH_TERMINAL_OPEN_NOT_PAIRED = 4,
    MESH_TERMINAL_OPEN_REVOKED = 5,
    MESH_TERMINAL_OPEN_EXPIRED = 6,
    MESH_TERMINAL_OPEN_PEER_NOT_CONNECTED = 7,
    MESH_TERMINAL_OPEN_IDENTITY_UNAVAILABLE = 8,
    MESH_TERMINAL_OPEN_PEER_IDENTITY_UNAVAILABLE = 9,
    MESH_TERMINAL_OPEN_BUSY = 10,
    MESH_TERMINAL_OPEN_SEND_FAILED = 11,
};

/* Requester-side session state. OPENING waits for the OK receipt inside
 * the answer window; LIVE pumps bounded DATA both ways; REFUSED carries
 * the responder's named refusal verdict; ENDED covers close, watchdog
 * expiry, and the responder's CLOSED receipt. */
enum boot_mesh_terminal_client_state {
    MESH_TERMINAL_CLIENT_OPENING = 0,
    MESH_TERMINAL_CLIENT_LIVE = 1,
    MESH_TERMINAL_CLIENT_REFUSED = 2,
    MESH_TERMINAL_CLIENT_ENDED = 3,
    MESH_TERMINAL_CLIENT_UNKNOWN = 4,
};

/* Bounded client session table, symmetric with the responder's: a fifth
 * concurrent open is refused with BUSY, never queued. */
#define MESH_TERMINAL_CLIENT_SESSIONS_MAX 4u

/* Bounded pending-screen FIFO per client session: the responder's own
 * 1 MiB byte-out ceiling bounds what can ever be in flight, so a laggard
 * reader sees drops at this mark, not unbounded growth. */
#define MESH_TERMINAL_CLIENT_OUTPUT_MAX (size_t)(64u * 1024u)

/* An OPEN receipt must arrive inside the answer window; a little slack for
 * the responder's pump, then the local watchdog is the honest signal. */
#define MESH_TERMINAL_CLIENT_RECEIPT_TIMEOUT_SECONDS \
    (MESH_TERMINAL_RECEIPT_VALIDITY_SECONDS + 5u)

/* One poll's honest view of a session. close_reason is meaningful only
 * when close_reason_named is set — a CLOSED receipt's reason lives in its
 * evidence capsule on the responder, so the local view does not invent
 * one. */
struct boot_mesh_terminal_client_view {
    enum mesh_terminal_receipt_status verdict;
    enum mesh_terminal_close_reason close_reason;
    bool close_reason_named;
    uint16_t cols;
    uint16_t rows;
    uint64_t bytes_in;  /* keyboard bytes sent */
    uint64_t bytes_out; /* screen bytes received */
    size_t output_pending;
    uint64_t idle_seconds;
};

const char *boot_mesh_terminal_open_result_string(
    enum boot_mesh_terminal_open_result result);
const char *boot_mesh_terminal_client_state_string(
    enum boot_mesh_terminal_client_state state);

/* Open one pairing-bound confined terminal against the paired peer's live
 * established Noise session (no dial is attempted). On OK the terminal id
 * is minted and the session is reserved before the OPEN frame is sent, so
 * a fast receipt can never arrive to a missing session. */
enum boot_mesh_terminal_open_result boot_mesh_terminal_client_open(
    const char *pairing_id_hex, uint16_t cols, uint16_t rows,
    uint8_t terminal_id_out[32]);

/* Advance watchdogs and read the session's state; safe on any id. */
enum boot_mesh_terminal_client_state boot_mesh_terminal_client_poll(
    const uint8_t terminal_id[32],
    struct boot_mesh_terminal_client_view *view_out);

/* Drain pending screen output (FIFO order, up to out_cap bytes). */
size_t boot_mesh_terminal_client_drain(const uint8_t terminal_id[32],
                                       uint8_t *out, size_t out_cap);

/* Send keyboard bytes, chunked to the DATA payload bound under the
 * strictly increasing per-terminal sequence. Refused when the session is
 * not live, the bound peer session is gone, or the keyboard budget would
 * be exceeded. */
bool boot_mesh_terminal_client_write(const uint8_t terminal_id[32],
                                     const uint8_t *bytes, size_t len);

/* Best-effort geometry change on a live session. */
bool boot_mesh_terminal_client_resize(const uint8_t terminal_id[32],
                                      uint16_t cols, uint16_t rows);

/* End a session: best-effort CLOSE to the bound peer, then end locally.
 * Idempotent; returns false only for an unknown id. */
bool boot_mesh_terminal_client_close(const uint8_t terminal_id[32]);

#ifdef ZCL_TESTING
bool boot_mesh_terminal_test_open_admit(
    const struct mesh_terminal_open_v1 *open,
    const struct noise_transport_snapshot *session, uint64_t now_mono_ms);

/* Test seam: reserve one requester stream and its session directly,
 * bypassing the send path (which needs a live composition context). The
 * open's own binding fields must be real — the watchdogs and every
 * ingress path verify against them. opened/last_activity 0 means "now".
 * The stream id is returned so a test can address the exact stream the
 * wire would. */
bool boot_mesh_terminal_client_test_inject(
    const struct mesh_terminal_open_v1 *open,
    const uint8_t expected_responder_master[32],
    const uint8_t expected_responder_online[32],
    const uint8_t peer_noise_static[32], const char *pairing_id_hex,
    uint64_t opened_unix, uint64_t last_activity_unix, bool open_confirmed,
    uint8_t terminal_id_out[32], uint64_t *stream_id_out);
void boot_mesh_terminal_client_test_reset(void);
#endif

#endif /* ZCL_CONFIG_BOOT_MESH_TERMINAL_H */
