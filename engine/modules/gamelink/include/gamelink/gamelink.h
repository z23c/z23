/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gamelink — the DATAGRAM profile of the UDP session transport designed in
 * docs/work/DIRECT_TRANSPORT.md "Component 1". One unreliable-sequenced,
 * authenticated-encrypted datagram channel between two fleet peers that have
 * ALREADY paired over Noise, for traffic where a late packet is worthless:
 * aircraft state at 30-60 Hz, telemetry, a latency probe.
 *
 * What it is not: it is not a handshake, not a rendezvous, and not a reliable
 * stream. The peers must already share session key material and must already
 * be able to reach each other. The reliable side channel a match setup uses is
 * the ZSTRM mux over the paired session (engine/composition/src/mesh_stream.c);
 * this module never retransmits and never reorders, because a game snapshot
 * that arrives late is worse than one that never arrives.
 *
 * The design is deliberately small enough to reason about:
 *   - every packet is sealed with ChaCha20-Poly1305 under a per-direction
 *     subkey derived from the session material by HKDF-SHA3-256;
 *   - the AEAD nonce IS the 64-bit sequence number, so a nonce is never
 *     reused and the module REFUSES to send rather than wrap;
 *   - a bounded replay window drops old and duplicate sequence numbers
 *     before any decryption happens;
 *   - a packet that fails any bound or the AEAD tag is dropped silently and
 *     counted. The session stays up: on an open UDP port anyone may send
 *     bytes, so a bad packet is ordinary weather, not an incident.
 *
 * Payload ceiling is GAMELINK_MAX_PAYLOAD bytes, chosen to stay inside a
 * 1280-byte IPv6 minimum MTU with the header and tag. It holds roughly two
 * dozen aircraft states (apps/skycombat aircraft_t is 48 bytes), which is a
 * whole match in one datagram.
 *
 * The clock is injected. Nothing here reads a wall clock, so a test can
 * assert an exact RTT instead of a tolerance.
 *
 * See docs/GAMELINK.md.
 */

#ifndef ZCL_GAMELINK_H
#define ZCL_GAMELINK_H

#include "platform/clock.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Wire geometry ───────────────────────────────────────────────────── */

/* magic[3] "ZGL" | version | session_id:8 | seq:8 | ack:8 | ack_bits:4 |
 * flags:1 | reserved:1, all big-endian. The whole header is the AEAD's
 * additional data, so a single flipped bit anywhere in it fails the tag. */
#define GAMELINK_HEADER_BYTES 34u
#define GAMELINK_TAG_BYTES 16u
#define GAMELINK_MAX_PAYLOAD 1200u
#define GAMELINK_MAX_DATAGRAM \
    (GAMELINK_HEADER_BYTES + GAMELINK_MAX_PAYLOAD + GAMELINK_TAG_BYTES)
#define GAMELINK_VERSION 1u

/* Header flag bits. PING and PONG are control frames: they are answered and
 * measured inside the module and are never handed to the receive callback. */
#define GAMELINK_FLAG_PING 0x01u
#define GAMELINK_FLAG_PONG 0x02u

/* How far behind the highest accepted sequence number a datagram may be and
 * still be delivered. Anything older is `dropped_old`: on a link where 60
 * snapshots a second are in flight, a packet 64 behind is a second stale. */
#define GAMELINK_REPLAY_WINDOW 64u

/* Byte caps, enforced numerically rather than by convention. The bucket is
 * the pacing cap of the design note: a session may burst BURST bytes and
 * then sustain RATE bytes per second. The blockchain wins contention by
 * construction because this transport shares no code and no socket with it. */
#define GAMELINK_DEFAULT_RATE_BYTES_PER_S (4u * 1024u * 1024u)
#define GAMELINK_DEFAULT_BURST_BYTES (1u * 1024u * 1024u)

/* ── Key material ────────────────────────────────────────────────────── */

/* What a paired Noise session hands this module. The Noise implementation
 * exposes no dedicated exporter — noise_hs_split() zeroizes the chaining key
 * it would have to come from — so the caller passes the material it DOES
 * hold: the two directional record-layer keys and the transcript hash. The
 * security consequences are written down in docs/GAMELINK.md; they are not
 * hidden behind this struct. */
#define GAMELINK_MATERIAL_BYTES 96u

/* ── Statistics ──────────────────────────────────────────────────────── */

struct gamelink_stats {
    /* Latency, from ping/pong round trips. Zero until the first pong. */
    uint64_t rtt_us;
    uint64_t jitter_us;   /* EWMA of |rtt - previous rtt|, RFC 3550 shape */
    uint64_t loss_ppm;    /* parts per million, from receive-side seq gaps */
    /* Volume. */
    uint64_t sent;        /* datagrams handed to the socket */
    uint64_t recv;        /* datagrams that authenticated and were accepted */
    uint64_t sent_bytes;
    uint64_t recv_bytes;
    /* Every way a datagram did not become a delivery. Separate counters,
     * because "it did not arrive" and "somebody sent us garbage" are
     * different facts and one refusal must never be read as the other. */
    uint64_t dropped_old;       /* behind the replay window, or a duplicate */
    uint64_t dropped_auth;      /* header parsed, AEAD tag did not verify */
    uint64_t dropped_malformed; /* short, wrong magic/version, bad reserved */
    uint64_t pings_sent;
    uint64_t pongs_recv;
};

/* ── A session ───────────────────────────────────────────────────────── */

/* The caller owns the storage: this module allocates nothing, so a game loop
 * can hold the session in its own arena and a test can hold it on the stack.
 * The fields are readable — an operator surface prints several of them — but
 * only gamelink_* functions may write them, with one documented exception:
 * a test may set send_seq to exercise the nonce-wrap refusal. */
struct gamelink {
    bool open;
    bool initiator;
    uint64_t session_id;
    uint8_t tx_key[32];
    uint8_t rx_key[32];

    /* Socket + peer. The address is stored in its wire form so the send path
     * does no resolution and no allocation. */
    intptr_t socket;          /* -1 when closed; a platform_socket_t widened
                               * so this header need not pull in winsock */
    uint8_t peer_addr[4];     /* IPv4, network byte order */
    uint16_t peer_port;       /* host byte order */
    uint16_t local_port;      /* the port the bind actually got */

    /* Sequencing. send_seq is the next nonce; it never repeats. */
    uint64_t send_seq;
    uint64_t recv_highest;    /* highest sequence accepted so far */
    uint64_t recv_window;     /* bitmap of the 64 sequences at or below it */
    bool recv_any;            /* false until the first accepted datagram */
    uint64_t recv_first;      /* the first sequence accepted, for loss */

    /* Pacing. */
    uint64_t rate_bytes_per_s;
    uint64_t burst_bytes;
    int64_t bucket_bytes;
    int64_t bucket_last_ns;

    /* Latency. */
    uint64_t rtt_us;
    /* Jitter is held in SIXTEENTHS of a microsecond, which is what RTP's own
     * implementation of the RFC 3550 estimator does. The divide-by-16 is the
     * filter; applying it to the stored value instead would quantize every
     * jitter under 16 us to a flat zero, which on a loopback link is all of
     * them. gamelink_stats() reports the microseconds. */
    int64_t jitter_scaled_us16;
    bool have_rtt;

    const clock_iface_t *clock;
    struct gamelink_stats stats;
};

/* Every way this refuses. There is no generic failure. */
enum gamelink_status {
    GAMELINK_OK = 0,
    GAMELINK_ARGUMENT,      /* a NULL, or a field over its bound */
    GAMELINK_ADDRESS,       /* the bind or peer address is not parseable */
    GAMELINK_SOCKET,        /* the operating system refused the socket */
    GAMELINK_CLOSED,        /* the session is not open */
    GAMELINK_TOO_LARGE,     /* payload over GAMELINK_MAX_PAYLOAD */
    GAMELINK_RATE,          /* the byte cap says not yet */
    GAMELINK_NONCE_EXHAUSTED, /* sending would reuse a nonce; refuse instead */
    GAMELINK_SEND_FAILED    /* the socket accepted nothing */
};

const char *gamelink_status_label(enum gamelink_status status);

/* Derive the two directional datagram subkeys and the session id from a
 * paired session's material. Exposed on its own so a caller can derive
 * without opening a socket, and so the derivation has a test of its own.
 * `initiator` must differ between the two ends: it decides which subkey each
 * end seals with. Returns false only on a NULL or a short material. */
bool gamelink_derive_keys(const uint8_t *material, size_t material_len,
                          bool initiator, uint8_t tx_key[32],
                          uint8_t rx_key[32], uint64_t *session_id);

/* Open a datagram session.
 *   material     — the paired session's key material (>= 32 bytes).
 *   initiator    — true on exactly one of the two ends.
 *   local_bind   — "ip:port" to bind, e.g. "127.0.0.1:0" for an ephemeral
 *                  port; read the port back from link->local_port.
 *   peer_addr    — "ip:port" of the peer, or NULL to bind without a peer
 *                  (an echo endpoint learns its peer from the first
 *                  datagram that authenticates).
 *   clock        — injected clock, or NULL for the process default.
 * The socket is non-blocking: gamelink_poll never waits. */
enum gamelink_status gamelink_open(struct gamelink *link,
                                   const uint8_t *material,
                                   size_t material_len, bool initiator,
                                   const char *local_bind,
                                   const char *peer_addr,
                                   const clock_iface_t *clock);

/* Send one datagram. `len` <= GAMELINK_MAX_PAYLOAD. The sequence number used
 * is returned through `out_seq` when it is not NULL. Refuses rather than
 * wrapping the nonce, and refuses when the byte cap is exhausted. */
enum gamelink_status gamelink_send(struct gamelink *link,
                                   const uint8_t *payload, size_t len,
                                   uint64_t *out_seq);

/* Drain everything the socket holds right now, delivering each accepted
 * datagram to `cb`. Control frames (ping/pong) are answered and measured
 * here and are never delivered. Returns the number of datagrams delivered;
 * `cb` may be NULL to drain and count without delivering. */
typedef void (*gamelink_recv_fn)(void *user, uint64_t seq,
                                 const uint8_t *payload, size_t len);
size_t gamelink_poll(struct gamelink *link, gamelink_recv_fn cb, void *user);

/* Send one ping. The peer's poll answers it with a pong carrying the same
 * send time, so the round trip is measured with one clock and no clock
 * comparison between machines. */
enum gamelink_status gamelink_ping(struct gamelink *link);

/* A consistent snapshot of the counters, with the derived rates filled in. */
void gamelink_stats(const struct gamelink *link, struct gamelink_stats *out);

/* Close the socket and zeroize both subkeys. Safe on an already-closed
 * session. */
void gamelink_close(struct gamelink *link);

/* ── The probe (gamelink_probe.c) ────────────────────────────────────── */

/* Run a ping/pong probe for `rounds` exchanges against `peer`, driving the
 * echo side through `echo` when it is not NULL (the in-process loopback
 * form the operator leaf and the tests both use). `interval_ns` is the gap
 * between pings on the injected clock. Returns the number of pongs seen. */
size_t gamelink_probe_run(struct gamelink *link, struct gamelink *echo,
                          size_t rounds, int64_t interval_ns);

/* Answer pings for one drain of the socket, replying to each. This is what
 * an echo endpoint calls in its loop; gamelink_poll already does it, so this
 * is only a name for that intent. Returns datagrams processed. */
size_t gamelink_probe_serve(struct gamelink *echo);

/* Append this link's latency vitals to the fleet ledger. The metric ids are
 * `link.rtt_us`, `link.jitter_us` and `link.loss_ppm` in
 * engine/composition/fleet_vitals.def; appending rows to that catalog is not
 * a schema change, because a vital's identity is its position and these were
 * added at the end. Writes one row per known statistic and returns how many
 * rows were appended, 0 when nothing is known yet or the ledger refused. */
struct zcl_fleet_ledger;
size_t gamelink_probe_write_vitals(const struct gamelink *link,
                                   struct zcl_fleet_ledger *ledger,
                                   const uint8_t seed[32]);

#endif /* ZCL_GAMELINK_H */
