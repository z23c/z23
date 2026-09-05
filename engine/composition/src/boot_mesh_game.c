/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `game` stream service: the codec for its five frames and
 * the session that admits them in order (see the header). The stream owns
 * the framing, the table, the credit and the tick; this owns the shape of
 * what rides inside and the named end of anything that does not fit. */

// one-result-type-ok:closed-security-verdict — parse and the admission
// steps return one bounded verdict a caller must branch on; no diagnostic
// text crosses the wire, only the refusal token.

#include "config/boot_mesh_game.h"
#include "config/mesh_stream.h"

#include "config/runtime.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "models/mesh_pairing.h"
#include "services/mesh_pairing_service.h"
#include "util/log_macros.h"

#include <string.h>

#define GAME_TAG "net.mesh_game"

/* The asset vocabulary this build carries, counted from the rule table
 * itself. A table that grows past the wire's bound stops the build here
 * rather than truncating a fleet's escorts on the wire. */
enum {
    MESH_GAME_LOCAL_ASSETS = 0
#define AIRSHIP_ASSET(name_) +1
#include "../fleet_airship_rules.def"
#undef AIRSHIP_ASSET
};
static_assert(MESH_GAME_LOCAL_ASSETS > 0,
              "the airship rule table declares no asset for a roster to carry");
static_assert(MESH_GAME_LOCAL_ASSETS <= (int)MESH_GAME_ASSET_MAX,
              "engine/composition/fleet_airship_rules.def declares more assets "
              "than one game roster row can carry; raise MESH_GAME_ASSET_MAX "
              "and the wire contract together");

static struct boot_svc_ctx *g_game_svc; /* borrowed; set by wire() */

/* ── Frame codec ─────────────────────────────────────────────────────── */

const char *mesh_game_refusal_string(enum mesh_game_refusal reason)
{
    switch (reason) {
    case MESH_GAME_OK:
        return "game_ok";
    case MESH_GAME_UNKNOWN_KIND:
        return "game_unknown_kind";
    case MESH_GAME_MALFORMED:
        return "game_malformed";
    case MESH_GAME_SEQUENCE:
        return "game_sequence";
    case MESH_GAME_HELLO_IDENTITY_MISMATCH:
        return "game_hello_identity_mismatch";
    case MESH_GAME_ROSTER_IDENTITY_MISMATCH:
        return "game_roster_identity_mismatch";
    case MESH_GAME_ROSTER_OVERFLOW:
        return "game_roster_overflow";
    case MESH_GAME_ASSET_VOCABULARY:
        return "game_asset_vocabulary";
    case MESH_GAME_STATE_OVERFLOW:
        return "game_state_overflow";
    case MESH_GAME_PEER_UNPAIRED:
        return "game_peer_unpaired";
    case MESH_GAME_UNAVAILABLE:
        return "game_unavailable";
    }
    return "game_unavailable";
}

static size_t game_roster_bytes(const struct mesh_game_roster *roster)
{
    return 35u + (size_t)roster->row_count * (33u + roster->asset_count);
}

size_t mesh_game_compose(const struct mesh_game_frame *frame, uint8_t *out,
                         size_t cap)
{
    size_t used = 0;

    if (!frame || !out)
        return 0;
    out[used++] = (uint8_t)frame->kind;
    switch (frame->kind) {
    case MESH_GAME_KIND_HELLO:
        if (cap < 65u)
            return 0;
        memcpy(out + used, frame->body.hello.zid, 32);
        memcpy(out + used + 32u, frame->body.hello.roster_digest, 32);
        return 65u;
    case MESH_GAME_KIND_ROSTER: {
        const struct mesh_game_roster *r = &frame->body.roster;

        if (r->row_count > MESH_GAME_ROSTER_ROWS_MAX ||
            r->asset_count > MESH_GAME_ASSET_MAX || cap < game_roster_bytes(r))
            return 0;
        memcpy(out + used, r->zid, 32);
        used += 32u;
        out[used++] = r->asset_count;
        out[used++] = r->row_count;
        for (uint8_t i = 0; i < r->row_count; i++) {
            memcpy(out + used, r->rows[i].noise_fingerprint, 32);
            used += 32u;
            out[used++] = r->rows[i].reachable ? 1u : 0u;
            memcpy(out + used, r->rows[i].assets, r->asset_count);
            used += r->asset_count;
        }
        return used;
    }
    case MESH_GAME_KIND_MATCH_OPEN:
        if (cap < 10u || frame->body.match_open.airships > MESH_GAME_AIRSHIPS_MAX)
            return 0;
        zcl_write_u64_le(out + used, frame->body.match_open.seed);
        out[used + 8u] = frame->body.match_open.airships;
        return 10u;
    case MESH_GAME_KIND_MATCH_STATE: {
        const struct mesh_game_match_state *s = &frame->body.match_state;
        size_t need = 6u + (size_t)s->airships * MESH_GAME_POSE_BYTES;

        if (s->airships > MESH_GAME_AIRSHIPS_MAX || cap < need)
            return 0;
        zcl_write_u32_le(out + used, s->tick);
        used += 4u;
        out[used++] = s->airships;
        for (uint8_t i = 0; i < s->airships; i++) {
            memcpy(out + used, s->poses[i], MESH_GAME_POSE_BYTES);
            used += MESH_GAME_POSE_BYTES;
        }
        return used;
    }
    case MESH_GAME_KIND_MATCH_CLOSE: {
        uint8_t len = frame->body.match_close.reason_len;

        if (len > MESH_GAME_REASON_MAX || cap < (size_t)len + 2u)
            return 0;
        out[used++] = len;
        memcpy(out + used, frame->body.match_close.reason, len);
        return used + len;
    }
    }
    return 0;
}

enum mesh_game_refusal mesh_game_parse(const uint8_t *in, size_t len,
                                       struct mesh_game_frame *out)
{
    size_t at = 1;

    if (!in || !out || len < 1u)
        return MESH_GAME_MALFORMED;
    memset(out, 0, sizeof(*out));
    switch (in[0]) {
    case MESH_GAME_KIND_HELLO:
        if (len != 65u)
            return MESH_GAME_MALFORMED;
        out->kind = MESH_GAME_KIND_HELLO;
        memcpy(out->body.hello.zid, in + at, 32);
        memcpy(out->body.hello.roster_digest, in + at + 32u, 32);
        return MESH_GAME_OK;
    case MESH_GAME_KIND_ROSTER: {
        struct mesh_game_roster *r = &out->body.roster;

        if (len < 35u)
            return MESH_GAME_MALFORMED;
        out->kind = MESH_GAME_KIND_ROSTER;
        memcpy(r->zid, in + at, 32);
        at += 32u;
        r->asset_count = in[at++];
        r->row_count = in[at++];
        if (r->asset_count != (uint8_t)MESH_GAME_LOCAL_ASSETS)
            return MESH_GAME_ASSET_VOCABULARY;
        if (r->row_count > MESH_GAME_ROSTER_ROWS_MAX)
            return MESH_GAME_ROSTER_OVERFLOW;
        if (len != game_roster_bytes(r))
            return MESH_GAME_MALFORMED;
        for (uint8_t i = 0; i < r->row_count; i++) {
            memcpy(r->rows[i].noise_fingerprint, in + at, 32);
            at += 32u;
            r->rows[i].reachable = in[at++] != 0u;
            memcpy(r->rows[i].assets, in + at, r->asset_count);
            at += r->asset_count;
        }
        return MESH_GAME_OK;
    }
    case MESH_GAME_KIND_MATCH_OPEN:
        if (len != 10u)
            return MESH_GAME_MALFORMED;
        out->kind = MESH_GAME_KIND_MATCH_OPEN;
        out->body.match_open.seed = zcl_read_u64_le(in + at);
        out->body.match_open.airships = in[at + 8u];
        if (out->body.match_open.airships > MESH_GAME_AIRSHIPS_MAX)
            return MESH_GAME_STATE_OVERFLOW;
        return MESH_GAME_OK;
    case MESH_GAME_KIND_MATCH_STATE: {
        struct mesh_game_match_state *s = &out->body.match_state;

        if (len < 6u)
            return MESH_GAME_MALFORMED;
        out->kind = MESH_GAME_KIND_MATCH_STATE;
        s->tick = zcl_read_u32_le(in + at);
        at += 4u;
        s->airships = in[at++];
        if (s->airships > MESH_GAME_AIRSHIPS_MAX)
            return MESH_GAME_STATE_OVERFLOW;
        if (len != 6u + (size_t)s->airships * MESH_GAME_POSE_BYTES)
            return MESH_GAME_MALFORMED;
        for (uint8_t i = 0; i < s->airships; i++) {
            memcpy(s->poses[i], in + at, MESH_GAME_POSE_BYTES);
            at += MESH_GAME_POSE_BYTES;
        }
        return MESH_GAME_OK;
    }
    case MESH_GAME_KIND_MATCH_CLOSE: {
        struct mesh_game_match_close *c = &out->body.match_close;

        if (len < 2u)
            return MESH_GAME_MALFORMED;
        out->kind = MESH_GAME_KIND_MATCH_CLOSE;
        c->reason_len = in[at++];
        if (c->reason_len > MESH_GAME_REASON_MAX ||
            len != (size_t)c->reason_len + 2u)
            return MESH_GAME_MALFORMED;
        memcpy(c->reason, in + at, c->reason_len);
        c->reason[c->reason_len] = '\0';
        return MESH_GAME_OK;
    }
    default:
        break;
    }
    return MESH_GAME_UNKNOWN_KIND;
}

/* ── Session ─────────────────────────────────────────────────────────── */

enum game_phase {
    GAME_AWAIT_ROSTER = 0,
    GAME_AWAIT_MATCH,
    GAME_IN_MATCH,
    GAME_ENDED,
};

/* What a game adds to a stream. The stream owns the identity binding, the
 * peer, the credit window and the lifetime; this is the order the frames
 * must arrive in and the ceiling MATCH_OPEN set. */
struct mesh_game_session {
    enum game_phase phase;
    uint8_t peer_zid[32]; /* from the local pairing row, never off the wire */
    uint8_t declared_airships;
    uint32_t last_tick;
};

/* The ZID the local pairing store binds to this Noise static. This is the
 * one identity source; the wire is only ever compared against it. */
static bool game_peer_zid(const uint8_t peer_static[32], uint8_t out[32])
{
    struct node_db *ndb = app_runtime_node_db();
    struct db_mesh_pairing rows[MESH_PAIRING_LIST_MAX];
    int count;

    if (!ndb)
        return false;
    count = db_mesh_pairing_list(ndb, rows, sizeof(rows) / sizeof(rows[0]));
    if (count <= 0)
        return false;
    for (int i = 0; i < count; i++) {
        if (memcmp(rows[i].peer_noise_pubkey, peer_static, 32) != 0)
            continue;
        memcpy(out, rows[i].peer_master_pubkey, 32);
        return true;
    }
    return false;
}

/* End the stream with this service's own token in the CLOSE payload, so
 * the other side reads the same name the log prints. */
static void game_end(struct mesh_stream *st, enum mesh_game_refusal reason)
{
    const char *token = mesh_game_refusal_string(reason);
    struct mesh_game_session *s = st->service_state;

    if (s)
        s->phase = GAME_ENDED;
    LOG_INFO(GAME_TAG, "stream %llu ended: %s", (unsigned long long)st->id,
             token);
    mesh_stream_close(st, MESH_STREAM_CLOSED_BY_SERVICE,
                      (const uint8_t *)token, strlen(token));
}

static enum mesh_stream_refusal game_service_open(struct mesh_stream *st,
                                                  const uint8_t *payload,
                                                  size_t len, uint8_t *reply,
                                                  size_t reply_cap,
                                                  size_t *reply_len, void *ctx)
{
    struct mesh_game_frame frame;
    struct mesh_game_session *s;
    uint8_t zid[32];

    (void)ctx;
    (void)reply;
    (void)reply_cap;
    *reply_len = 0; /* the acceptor states no identity of its own */

    if (!game_peer_zid(st->peer_static, zid))
        return MESH_STREAM_REFUSED_PEER_UNPAIRED;
    /* The OPEN payload is the HELLO. A session whose identity does not
     * check never reaches a DATA frame. */
    if (mesh_game_parse(payload, len, &frame) != MESH_GAME_OK ||
        frame.kind != MESH_GAME_KIND_HELLO)
        return MESH_STREAM_REFUSED_MALFORMED;
    if (memcmp(frame.body.hello.zid, zid, 32) != 0) {
        LOG_ERROR(GAME_TAG, "open refused: %s",
                  mesh_game_refusal_string(MESH_GAME_HELLO_IDENTITY_MISMATCH));
        return MESH_STREAM_REFUSED_MALFORMED;
    }
    s = zcl_calloc(1, sizeof(*s), "mesh_game_session");
    if (!s)
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    s->phase = GAME_AWAIT_ROSTER;
    memcpy(s->peer_zid, zid, 32);
    st->service_state = s;
    return MESH_STREAM_OK;
}

/* One inbound frame, admitted only where the session is. This is the
 * whole policy: order, identity, and the MATCH_OPEN ceiling. */
static enum mesh_game_refusal game_admit(struct mesh_game_session *s,
                                         const struct mesh_game_frame *frame)
{
    switch (frame->kind) {
    case MESH_GAME_KIND_ROSTER:
        if (s->phase != GAME_AWAIT_ROSTER)
            return MESH_GAME_SEQUENCE;
        if (memcmp(frame->body.roster.zid, s->peer_zid, 32) != 0)
            return MESH_GAME_ROSTER_IDENTITY_MISMATCH;
        s->phase = GAME_AWAIT_MATCH;
        return MESH_GAME_OK;
    case MESH_GAME_KIND_MATCH_OPEN:
        if (s->phase != GAME_AWAIT_MATCH)
            return MESH_GAME_SEQUENCE;
        s->declared_airships = frame->body.match_open.airships;
        s->last_tick = 0;
        s->phase = GAME_IN_MATCH;
        return MESH_GAME_OK;
    case MESH_GAME_KIND_MATCH_STATE:
        if (s->phase != GAME_IN_MATCH)
            return MESH_GAME_SEQUENCE;
        if (frame->body.match_state.airships > s->declared_airships)
            return MESH_GAME_STATE_OVERFLOW;
        s->last_tick = frame->body.match_state.tick;
        return MESH_GAME_OK;
    case MESH_GAME_KIND_MATCH_CLOSE:
        if (s->phase != GAME_IN_MATCH)
            return MESH_GAME_SEQUENCE;
        s->phase = GAME_ENDED;
        return MESH_GAME_OK;
    case MESH_GAME_KIND_HELLO:
        /* HELLO is the OPEN payload and is never a DATA frame: a second
         * greeting mid-session is a second identity claim. */
        return MESH_GAME_SEQUENCE;
    }
    return MESH_GAME_UNKNOWN_KIND;
}

static void game_service_data(struct mesh_stream *st, const uint8_t *payload,
                              size_t len, void *ctx)
{
    struct mesh_game_session *s = st->service_state;
    struct mesh_game_frame frame;
    enum mesh_game_refusal reason;

    (void)ctx;
    if (!s || s->phase == GAME_ENDED) {
        game_end(st, MESH_GAME_SEQUENCE);
        return;
    }
    reason = mesh_game_parse(payload, len, &frame);
    if (reason == MESH_GAME_OK)
        reason = game_admit(s, &frame);
    if (reason != MESH_GAME_OK) {
        game_end(st, reason);
        return;
    }
    if (frame.kind == MESH_GAME_KIND_MATCH_CLOSE)
        game_end(st, MESH_GAME_OK);
}

static void game_service_close(struct mesh_stream *st,
                               enum mesh_stream_refusal reason,
                               const uint8_t *payload, size_t len, void *ctx)
{
    struct mesh_game_session *s = st->service_state;

    (void)reason;
    (void)payload;
    (void)len;
    (void)ctx;
    if (s)
        s->phase = GAME_ENDED;
}

static void game_service_release(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    free(st->service_state);
    st->service_state = NULL;
}

/* ── Lifecycle ───────────────────────────────────────────────────────── */

/* One registration serves both halves; the primitive tells them apart by
 * which side opened the stream. STATUS_READ is the capability a pairing
 * grants by default, and it is the right one: a roster of peer-verified
 * facts is exactly the status this peer already answers. */
bool boot_mesh_game_register_service(void)
{
    struct mesh_stream_service service;

    memset(&service, 0, sizeof(service));
    service.name = MESH_GAME_SERVICE_NAME;
    service.required_pairing_capability = MESH_PAIRING_CAP_STATUS_READ;
    service.on_open = game_service_open;
    service.on_data = game_service_data;
    service.on_close = game_service_close;
    service.on_release = game_service_release;
    return mesh_stream_service_register(&service);
}

void boot_mesh_game_wire(struct boot_svc_ctx *svc)
{
    if (g_game_svc) {
        LOG_ERROR(GAME_TAG, "wire: already wired");
        return;
    }
    g_game_svc = svc;
    if (!boot_mesh_game_register_service())
        LOG_ERROR(GAME_TAG, "game stream service refused");
}

void boot_mesh_game_shutdown(void)
{
    /* Unregistering ends every live game stream by name; each on_close
     * marks its session ended and on_release frees it. */
    mesh_stream_service_unregister(MESH_GAME_SERVICE_NAME);
    g_game_svc = NULL;
}
