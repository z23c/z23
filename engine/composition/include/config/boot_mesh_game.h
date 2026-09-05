/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `game` service on the mesh stream primitive — the wire
 * contract two paired fleets play over, and nothing else.
 *
 * THERE IS NO GAME IN HERE. No physics, no simulation, no scoring, no
 * roster generation. This is the typed envelope an imported game drives:
 * five frame kinds, each fixed-shape and bounded, every one of them
 * refused by name when it does not fit. Keeping the rules out of the
 * transport is what lets the game change without the wire changing, and
 * what lets this file be read for what it admits rather than for what it
 * plays.
 *
 * Five kinds, in the one order a session walks them:
 *
 *   HELLO        who is talking and which roster they will send. It rides
 *                in the stream OPEN, so a session whose identity does not
 *                check ends before a DATA frame ever exists. The acceptor
 *                sends no HELLO back: it would have to state an identity
 *                the dialer already resolved locally when it chose which
 *                Noise static to open to, and a second statement of an
 *                identity is a second thing that can disagree. A peer that
 *                wants to greet in the other direction opens its own
 *                stream, which the primitive already keeps apart by id
 *                parity.
 *   ROSTER       the sending fleet's machines and what each earned, with
 *                verified fields only. A roster whose ZID is not the
 *                paired peer's ends the stream: a fleet may only ever
 *                claim its own machines.
 *   MATCH_OPEN   the shared seed and the airship count this match will
 *                fly. That count is the ceiling every later frame is
 *                measured against.
 *   MATCH_STATE  one tick and one opaque pose per airship. The service
 *                never reads inside a pose — that is the game's shape,
 *                not the wire's — but it does refuse a frame carrying
 *                more airships than MATCH_OPEN declared.
 *   MATCH_CLOSE  the named end.
 *
 * EVERYTHING FAILS CLOSED. An unknown kind, a short or long body, a frame
 * out of order, a mismatched identity, an overflowing state: each ends
 * the stream with its own token in the CLOSE payload, and none of them is
 * ever skipped, truncated or read as an empty success. An idle stream is
 * reaped by the primitive's own timeout; this service adds no clock.
 *
 * IDENTITY COMES FROM ONE PLACE. The peer's ZID is read from the local
 * pairing row that already authorized the stream — the same row the
 * terminal lane reads. Nothing here derives, fingerprints or accepts an
 * identity off the wire; the wire is only ever compared against that row.
 */

#ifndef ZCL_CONFIG_BOOT_MESH_GAME_H
#define ZCL_CONFIG_BOOT_MESH_GAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;

#define MESH_GAME_SERVICE_NAME "game"

/* Bounds. The airship ceiling is the roster leaf's row cap for the same
 * reason: a match may not fly more machines than a roster can name. */
#define MESH_GAME_AIRSHIPS_MAX 32u
#define MESH_GAME_ROSTER_ROWS_MAX 32u
/* One pose is opaque to this file and bounded by it: 64 bytes is room for
 * a position, an orientation and a velocity at double width, and a hard
 * stop on a peer describing an airship in a megabyte. */
#define MESH_GAME_POSE_BYTES 64u
/* The asset vocabulary a roster row carries counts for. It is checked
 * against engine/composition/fleet_airship_rules.def at compile time, so
 * growing that table past this bound breaks the build rather than
 * silently truncating a fleet's escorts. */
#define MESH_GAME_ASSET_MAX 4u
#define MESH_GAME_REASON_MAX 32u

enum mesh_game_kind {
    MESH_GAME_KIND_HELLO = 0x01,
    MESH_GAME_KIND_ROSTER = 0x02,
    MESH_GAME_KIND_MATCH_OPEN = 0x03,
    MESH_GAME_KIND_MATCH_STATE = 0x04,
    MESH_GAME_KIND_MATCH_CLOSE = 0x05,
};

/* Every named end this service can give a stream. One stable token each,
 * the same token the CLOSE payload carries and an operator surface
 * prints. */
enum mesh_game_refusal {
    MESH_GAME_OK = 0,
    MESH_GAME_UNKNOWN_KIND,
    MESH_GAME_MALFORMED,
    MESH_GAME_SEQUENCE,
    MESH_GAME_HELLO_IDENTITY_MISMATCH,
    MESH_GAME_ROSTER_IDENTITY_MISMATCH,
    MESH_GAME_ROSTER_OVERFLOW,
    MESH_GAME_ASSET_VOCABULARY,
    MESH_GAME_STATE_OVERFLOW,
    MESH_GAME_PEER_UNPAIRED,
    MESH_GAME_UNAVAILABLE,
};

/* "game_unknown_kind", "game_roster_identity_mismatch",
 * "game_state_overflow", ... */
const char *mesh_game_refusal_string(enum mesh_game_refusal reason);

struct mesh_game_hello {
    uint8_t zid[32];           /* the sender's chain identity */
    uint8_t roster_digest[32]; /* what roster the sender will send */
};

struct mesh_game_roster_row {
    uint8_t noise_fingerprint[32];
    bool reachable; /* peer-verified; there is no self-reported field here */
    uint8_t assets[MESH_GAME_ASSET_MAX];
};

struct mesh_game_roster {
    uint8_t zid[32];
    uint8_t asset_count; /* must equal this build's asset vocabulary */
    uint8_t row_count;
    struct mesh_game_roster_row rows[MESH_GAME_ROSTER_ROWS_MAX];
};

struct mesh_game_match_open {
    uint64_t seed;
    uint8_t airships; /* the ceiling every MATCH_STATE is measured against */
};

struct mesh_game_match_state {
    uint32_t tick;
    uint8_t airships;
    uint8_t poses[MESH_GAME_AIRSHIPS_MAX][MESH_GAME_POSE_BYTES];
};

struct mesh_game_match_close {
    uint8_t reason_len;
    char reason[MESH_GAME_REASON_MAX + 1];
};

/* One frame, whichever kind it is. The union is what keeps the codec a
 * single pair of verbs: a caller that can compose one kind can compose
 * all five, and a test drives the exact bytes the service does. */
struct mesh_game_frame {
    enum mesh_game_kind kind;
    union {
        struct mesh_game_hello hello;
        struct mesh_game_roster roster;
        struct mesh_game_match_open match_open;
        struct mesh_game_match_state match_state;
        struct mesh_game_match_close match_close;
    } body;
};

/* The largest frame this service can put on the wire, well under the
 * stream primitive's own payload ceiling. */
#define MESH_GAME_FRAME_MAX \
    (2u + 4u + (size_t)MESH_GAME_AIRSHIPS_MAX * MESH_GAME_POSE_BYTES)

/* Compose returns the byte count written, or 0 when the frame does not
 * fit or does not describe a legal frame — never a partial write. */
size_t mesh_game_compose(const struct mesh_game_frame *frame, uint8_t *out,
                         size_t cap);

/* Parse names why it refused. MESH_GAME_OK is the only value that leaves
 * `out` filled. */
enum mesh_game_refusal mesh_game_parse(const uint8_t *in, size_t len,
                                       struct mesh_game_frame *out);

/* Registers the `game` stream service. Separate from wire() so a test can
 * register without a composition context, exactly as the terminal lane
 * does. */
bool boot_mesh_game_register_service(void);
void boot_mesh_game_wire(struct boot_svc_ctx *svc);
void boot_mesh_game_shutdown(void);

#endif /* ZCL_CONFIG_BOOT_MESH_GAME_H */
