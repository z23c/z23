/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: One multiplexed stream primitive over the authenticated peer
 * link, and the service registry that dispatches its frames.
 *
 * A stream is an ordered, credit-bounded byte channel between two paired
 * machines, carried inside the frozen "zpkgswm" P2P message with a
 * "ZSTRM" prefix: no new wire message, no listener, no port. It inherits
 * the established Noise session, the onion path, and connman session
 * management, exactly as the mesh status and mesh terminal lanes always
 * did — a stream is never accepted over a link that is not an established
 * Noise session, and never from a peer whose local pairing row does not
 * grant the capability the service asked for.
 *
 * Four typed frames, and nothing else:
 *
 *   OPEN   stream_id, service name, initial credit, service payload
 *   DATA   stream_id, service payload (never larger than the credit left)
 *   WINDOW stream_id, credit the peer may now spend toward us
 *   CLOSE  stream_id, named reason, service payload
 *
 * A service registers a name once and receives open/data/close/tick
 * callbacks for every stream of that name, whichever side opened it.
 * There is ONE stream table and ONE lane lock: both halves of a service
 * (the side that dials and the side that answers) live in the same table,
 * told apart by `local_initiator` and by the parity of the stream id —
 * the peer that dialed the connection mints even ids, the peer that
 * accepted it mints odd ids, so two sides can open streams at once and
 * never collide.
 *
 * Flow control is credit, not hope. Each direction starts with the
 * initial credit named in the OPEN (never above
 * MESH_STREAM_INITIAL_WINDOW), a DATA frame that would spend more credit
 * than the sender holds is refused before it reaches the wire, a DATA
 * frame that arrives beyond the credit granted to the peer closes the
 * stream by name, and a receiver replenishes with WINDOW as it consumes.
 * One frame never exceeds MESH_STREAM_FRAME_MAX, a peer never holds more
 * than MESH_STREAM_PER_PEER_MAX streams, and an idle stream is reaped —
 * so one stream can never starve the link and one peer can never starve
 * the node.
 *
 * Every refusal is named (mesh_stream_refusal_string) and fails closed.
 */

#ifndef ZCL_CONFIG_MESH_STREAM_H
#define ZCL_CONFIG_MESH_STREAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct msg_processor;
struct p2p_node;

#define MESH_STREAM_FRAME_PREFIX "ZSTRM"
#define MESH_STREAM_FRAME_PREFIX_LEN 5u
#define MESH_STREAM_KIND_OPEN 0x01u
#define MESH_STREAM_KIND_DATA 0x02u
#define MESH_STREAM_KIND_WINDOW 0x03u
#define MESH_STREAM_KIND_CLOSE 0x04u

/* Service names are short, printable, and fixed-bound so an OPEN frame
 * can never make the node read an unbounded name. */
#define MESH_STREAM_SERVICE_NAME_MAX 16u
#define MESH_STREAM_SERVICES_MAX 8u

/* One frame stays well under the 64 KiB ceiling so a single stream can
 * never monopolise the peer's send queue; the header is the difference. */
#define MESH_STREAM_FRAME_MAX (size_t)(64u * 1024u)
#define MESH_STREAM_PAYLOAD_MAX (size_t)(64u * 1024u - 256u)

/* The bound on the reply an acceptor's on_open may compose: enough for a
 * service's signed evidence, small enough to sit on the frame path's
 * stack. A service that writes more has its reply dropped, never
 * truncated. */
#define MESH_STREAM_SERVICE_REPLY_MAX (size_t)(8u * 1024u)

/* The ceiling on credit either side may hold: 256 KiB in flight is far
 * above an interactive session and far under any queue the node keeps.
 * An OPEN naming more than this is refused; a WINDOW that would push a
 * sender above it is refused. */
#define MESH_STREAM_INITIAL_WINDOW (uint32_t)(256u * 1024u)

/* Bounded tables: streams per peer, streams in total, and the per-peer
 * OPEN cadence that keeps a paired peer from making the node do a
 * service's admission work faster than it can be worth doing. */
#define MESH_STREAM_PER_PEER_MAX 8u
#define MESH_STREAM_TABLE_MAX 32u
#define MESH_STREAM_OPEN_RATE_PER_SECOND 8u

/* A stream with no traffic either way is reaped at this mark. Services
 * with a shorter idle policy of their own enforce it in on_tick. */
#define MESH_STREAM_IDLE_SECONDS INT64_C(600)

/* An ended stream keeps its slot this long so the side that asked for it
 * can still read the verdict, then the pump reaps it. An ended stream
 * carries no credit and never counts toward the per-peer cap, so a
 * lingering verdict can never keep a peer from opening a new stream. */
#define MESH_STREAM_LINGER_SECONDS INT64_C(60)

/* Every named end of a stream. Values below MESH_STREAM_CLOSED_BY_SERVICE
 * are the primitive's own verdicts; MESH_STREAM_CLOSED_BY_SERVICE says
 * the service ended the stream and named the reason in its own terms
 * inside the CLOSE payload. */
enum mesh_stream_refusal {
    MESH_STREAM_OK = 0,
    MESH_STREAM_REFUSED_LINK_NOT_NOISE = 1,
    MESH_STREAM_REFUSED_PEER_UNPAIRED = 2,
    MESH_STREAM_REFUSED_SERVICE_UNKNOWN = 3,
    MESH_STREAM_REFUSED_CAP = 4,
    MESH_STREAM_REFUSED_CREDIT_EXCEEDED = 5,
    MESH_STREAM_REFUSED_MALFORMED = 6,
    MESH_STREAM_REFUSED_ID_PARITY = 7,
    MESH_STREAM_REFUSED_ID_IN_USE = 8,
    MESH_STREAM_REFUSED_RATE = 9,
    MESH_STREAM_REFUSED_UNAVAILABLE = 10,
    MESH_STREAM_REFUSED_PEER_NOT_CONNECTED = 11,
    MESH_STREAM_ENDED_IDLE = 12,
    MESH_STREAM_ENDED_SESSION_LOST = 13,
    MESH_STREAM_ENDED_SHUTDOWN = 14,
    MESH_STREAM_CLOSED_BY_SERVICE = 15,
};

/* "stream_peer_unpaired", "stream_link_not_noise", "stream_service_unknown",
 * "stream_cap", "stream_credit_exceeded", ... — one stable token per
 * value, the same token operator surfaces and logs print. */
const char *mesh_stream_refusal_string(enum mesh_stream_refusal reason);

/* One stream, in the one table both sides share. Services read this and
 * hang their own per-stream state off `service_state`; every mutation
 * that touches the wire goes through the verbs below. */
struct mesh_stream {
    bool used;
    bool local_initiator;  /* this node sent the OPEN */
    bool peer_answered;    /* at least one frame arrived on this stream */
    /* Half-closed: on_close has run, no frame passes either way, and the
     * slot lingers only so the side that asked for the stream can still
     * read the verdict. */
    bool ended;
    enum mesh_stream_refusal end_reason;
    uint64_t id;           /* initiator parity in bit 0 */
    uint16_t service;      /* index into the service registry */
    /* The exact established Noise session the stream is bound to. A frame
     * arriving on any other session is not this stream's frame. */
    uint8_t peer_static[32];
    uint8_t transcript_hash[32];
    uint64_t connection_generation;
    uint32_t send_credit; /* bytes this node may still send */
    uint32_t recv_credit; /* bytes the peer may still send */
    uint64_t bytes_sent;
    uint64_t bytes_received;
    int64_t opened_unix;
    int64_t last_activity_unix;
    void *service_state;
};

/* One service. `name` is the wire tag inside OPEN;
 * `required_pairing_capability` is the MESH_PAIRING_CAP_* bit the peer's
 * local pairing row must carry before an inbound OPEN reaches on_open —
 * zero means the service performs its own, stronger authority decision
 * and the primitive demands only an established Noise session.
 *
 * The lifecycle is open → data/tick → close → release, and every stream
 * walks all of it exactly once. on_open answers an inbound OPEN:
 * MESH_STREAM_OK accepts the stream (and may write a reply payload the
 * acceptor sends back as its first DATA); anything else refuses it, and
 * the reply payload rides the CLOSE so a refusal can carry the service's
 * own signed evidence. on_data delivers one peer DATA payload. on_tick
 * runs on every live stream from the single stream pump: it is where a
 * service moves its output into DATA frames within the credit it holds,
 * so no service ever needs a pump of its own. on_close says the stream
 * ended and names why — the verdict is readable from here on, and the
 * slot lingers so the side that asked can read it. on_release says the
 * slot is going back: free whatever hangs off service_state, and read
 * nothing afterwards.
 *
 * Every callback runs under the lane lock. A callback may call
 * mesh_stream_send/_grant/_close on its own stream; it must not call
 * mesh_stream_open or mesh_stream_visit. */
struct mesh_stream_service {
    const char *name;
    uint64_t required_pairing_capability;
    enum mesh_stream_refusal (*on_open)(struct mesh_stream *st,
                                        const uint8_t *payload, size_t len,
                                        uint8_t *reply, size_t reply_cap,
                                        size_t *reply_len, void *ctx);
    void (*on_data)(struct mesh_stream *st, const uint8_t *payload,
                    size_t len, void *ctx);
    void (*on_close)(struct mesh_stream *st, enum mesh_stream_refusal reason,
                     const uint8_t *payload, size_t len, void *ctx);
    void (*on_tick)(struct mesh_stream *st, int64_t now_unix, void *ctx);
    void (*on_release)(struct mesh_stream *st, void *ctx);
    void *ctx;
};

/* Register one service. Names are unique; a second registration of the
 * same name replaces the first only after it is unregistered. Refused
 * when the registry is full or the name is out of bounds. */
bool mesh_stream_service_register(const struct mesh_stream_service *service);
void mesh_stream_service_unregister(const char *name);

/* Records the composition context and starts the single supervised stream
 * pump. Shutdown closes every live stream by name and unregisters the
 * tick. */
void mesh_stream_wire(struct boot_svc_ctx *svc);
void mesh_stream_shutdown(void);

/* msg_zcode_swarm_frame_fn adapter: true only when the ZSTRM namespace
 * matched and the frame was consumed (dispatched, answered, or dropped by
 * policy). Unknown prefixes return false so later swarm dispatchers see
 * the frame unchanged. */
bool mesh_stream_frame(struct msg_processor *mp, struct p2p_node *node,
                       const uint8_t *payload, size_t payload_len,
                       struct boot_svc_ctx *svc);

/* Open one stream to a connected peer's live established Noise session
 * (no dial is attempted). The slot is reserved before the OPEN reaches
 * the wire, so a fast answer can never arrive to a missing stream.
 * `initial_window` is the credit each direction starts with; zero means
 * MESH_STREAM_INITIAL_WINDOW. Not callable from inside a callback. */
enum mesh_stream_refusal mesh_stream_open(
    const char *service_name, const uint8_t peer_noise_static[32],
    uint32_t initial_window, const uint8_t *payload, size_t payload_len,
    void *service_state, uint64_t *stream_id_out);

/* Send one DATA payload. Refused when the payload is larger than one
 * frame or than the credit this node holds — the frame never reaches the
 * wire and no credit is spent. Callable only under the lane lock (from a
 * callback or a visitor). */
bool mesh_stream_send(struct mesh_stream *st, const uint8_t *payload,
                      size_t payload_len);

/* Grant the peer `credit` more bytes toward this node, up to the ceiling.
 * Callable only under the lane lock. */
bool mesh_stream_grant(struct mesh_stream *st, uint32_t credit);

/* End the stream by name, with an optional service payload. on_close runs
 * once, the CLOSE frame goes out, and the stream becomes half-closed: no
 * frame passes, but the slot lingers so the verdict stays readable until
 * mesh_stream_release or the linger mark. Idempotent. Callable only under
 * the lane lock. */
void mesh_stream_close(struct mesh_stream *st, enum mesh_stream_refusal reason,
                       const uint8_t *payload, size_t payload_len);

/* Give a half-closed stream's slot back now: on_release runs, then the
 * slot is free. Callable only under the lane lock; a service calls it
 * from on_close when it keeps nothing a caller could read afterwards. */
void mesh_stream_release(struct mesh_stream *st);

/* Visit every live stream of one service under the lane lock, newest slot
 * last. The visitor returns false to stop early. Not callable from inside
 * a callback. */
typedef bool (*mesh_stream_visitor)(struct mesh_stream *st, void *ctx);
void mesh_stream_visit(const char *service_name, mesh_stream_visitor visit,
                       void *ctx);

#ifdef ZCL_TESTING
/* Test seams: drive the exact production frame path and table without a
 * live composition context. reset clears the table and the OPEN cadence;
 * the registry survives so a test service stays registered. inject
 * reserves one stream bound to the given session exactly as the open path
 * would, without a wire send, so ingress and the session verbs can be
 * driven directly. */
void mesh_stream_test_reset(void);
size_t mesh_stream_test_live_count(const char *service_name);
bool mesh_stream_test_inject(const char *service_name,
                             const uint8_t peer_static[32],
                             const uint8_t transcript_hash[32],
                             uint64_t connection_generation,
                             bool local_initiator, uint64_t id,
                             uint32_t initial_window, void *service_state);
/* Binds the composition context a loopback test supplies (one message
 * processor over a net manager holding both peers) WITHOUT registering a
 * supervised drain, so a test can put real frames on the wire. Pass NULL
 * to unbind. */
void mesh_stream_test_bind(struct boot_svc_ctx *svc);
#endif

#endif /* ZCL_CONFIG_MESH_STREAM_H */
