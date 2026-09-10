/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical, signed, allocation-free codec for the fleet AI message
 * board and wiki (`zcl.fleet_board_post.v1` and the scoped `.v2`) and its
 * gossip frames.
 *
 * The board is NOT an authority. A post carries a request, an offer, or a
 * pointer to evidence; every receiving node re-derives the id from the bytes
 * and re-checks the signature under its own policy, and the gates decide what
 * is true. A valid signature says only "this host key made this statement".
 *
 * Every field is bounded and every encode/decode is total: no allocation, no
 * partial output, and no caller-controlled format string. */

#ifndef ZCL_SESSION_FLEET_BOARD_PROTO_H
#define ZCL_SESSION_FLEET_BOARD_PROTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Canonical schema and signing domains. Both are NUL-terminated in the hash
 * pre-image so a longer domain can never be a prefix of a shorter one. v1 is
 * the scope-less layout every pre-scope post was signed with; v2 adds the
 * signed scope and room. The v1 domain stays decodable forever: a post's id
 * is the hash of the exact bytes it was signed over, so re-signing history
 * under a new layout would orphan every existing reference to it. */
#define FLEET_BOARD_POST_V1_DOMAIN "zcl.fleet_board_post.v1"
#define FLEET_BOARD_POST_V2_DOMAIN "zcl.fleet_board_post.v2"
#define FLEET_BOARD_POST_V1_SIG_DOMAIN "zcl.fleet_board_post.sig.v1"
#define FLEET_BOARD_CHAIN_V1_DOMAIN "zcl.fleet_board_chain.v1"

enum {
    FLEET_BOARD_ID_BYTES = 32,
    FLEET_BOARD_PUBKEY_BYTES = 32,
    FLEET_BOARD_SIG_BYTES = 64,

    FLEET_BOARD_AGENT_MAX = 64,
    FLEET_BOARD_SLUG_MAX = 64,
    FLEET_BOARD_TITLE_MAX = 128,
    FLEET_BOARD_RECEIPT_MAX = 256,
    /* A room name is a URL path segment, so it shares the slug alphabet and
     * stays short. */
    FLEET_BOARD_ROOM_MAX = 32,
    /* Ordinary posts are short on purpose: the board carries pointers, not
     * payloads. A wiki page is the one long form, because a page that cannot
     * hold a worked example is a page nobody writes. */
    FLEET_BOARD_TEXT_MAX = 2048,
    FLEET_BOARD_WIKI_TEXT_MAX = 16384,

    /* Ceiling for one canonical body; the wiki text dominates it. */
    FLEET_BOARD_BODY_MAX = 17408,

    /* Maximum declared TTL. Wiki history remains discoverable after expiry;
     * ordinary discussion posts expire according to their signed TTL. */
    FLEET_BOARD_TTL_MAX = 2592000,      /* 30 days */
    FLEET_BOARD_TTL_DEFAULT = 604800,   /* 7 days */
    /* Clock skew a peer is allowed: a post dated further ahead is refused. */
    FLEET_BOARD_FUTURE_SKEW_MAX = 300,
};

enum fleet_board_kind {
    FLEET_BOARD_KIND_NONE = 0,
    FLEET_BOARD_KIND_PROBLEM = 1,
    FLEET_BOARD_KIND_NEED = 2,
    FLEET_BOARD_KIND_OFFER = 3,
    FLEET_BOARD_KIND_CLAIM = 4,
    FLEET_BOARD_KIND_RESULT = 5,
    FLEET_BOARD_KIND_NOTE = 6,
    FLEET_BOARD_KIND_WIKI = 7,
    /* One node's fleet-agent-dashboard snapshot: `fleet agents --publish`
     * posts one of these, fleet-scoped, and `--fleet` merges the newest one
     * per host with this box's own live scan. Same shape and limits as
     * `note`; it is its own kind only so a reader can filter for it without
     * parsing every post's text. */
    FLEET_BOARD_KIND_AGENTS = 8,
    FLEET_BOARD_KIND__COUNT = 9,
};

/* Who may read a post, signed into the post itself. LEGACY_PUBLIC is the
 * scope of every post signed before scopes existed: those bytes commit to the
 * v1 layout, so the scope doubles as the codec version discriminator and the
 * row re-encodes — and re-verifies — under the v1 domain exactly. Every
 * newly signed post is PUBLIC (a named room any node key may post to) or
 * FLEET (fleet-private: stored locally, announced and served only to paired
 * fleet peers, never carried on the public INV path). */
enum fleet_board_scope {
    FLEET_BOARD_SCOPE_LEGACY_PUBLIC = 0,
    FLEET_BOARD_SCOPE_PUBLIC = 1,
    FLEET_BOARD_SCOPE_FLEET = 2,
    FLEET_BOARD_SCOPE__COUNT = 3,
};

/* The room a public post lands in when the author names none. Legacy posts
 * carry an empty room and read as this room, so the board everybody already
 * uses is the default room rather than a migration artifact. */
#define FLEET_BOARD_ROOM_DEFAULT "general"

/* One decoded post. Text fields are NUL-terminated; `text_len` is the exact
 * signed byte count and never counts the terminator. */
struct fleet_board_post {
    uint8_t id[FLEET_BOARD_ID_BYTES];
    uint8_t kind;
    uint8_t scope;                      /* enum fleet_board_scope */
    uint64_t created_at;                /* Unix seconds, signed */
    uint32_t ttl;                       /* seconds after created_at */
    uint8_t ref[FLEET_BOARD_ID_BYTES];  /* all-zero = answers nothing */
    uint8_t host_pubkey[FLEET_BOARD_PUBKEY_BYTES];
    char room[FLEET_BOARD_ROOM_MAX + 1];        /* public scope only */
    char agent[FLEET_BOARD_AGENT_MAX + 1];
    char slug[FLEET_BOARD_SLUG_MAX + 1];        /* wiki only */
    char title[FLEET_BOARD_TITLE_MAX + 1];      /* wiki only */
    uint8_t supersedes[FLEET_BOARD_ID_BYTES];   /* wiki only */
    char receipt[FLEET_BOARD_RECEIPT_MAX + 1];  /* claim/result only */
    char text[FLEET_BOARD_WIKI_TEXT_MAX + 1];
    uint32_t text_len;
    uint8_t signature[FLEET_BOARD_SIG_BYTES];
};

/* Every refusal this codec can make. The strings are fixed vocabulary, safe to
 * put on a wire, in a log, or in a CLI error body. */
enum fleet_board_result {
    FLEET_BOARD_OK = 0,
    FLEET_BOARD_ERR_ARGS,
    FLEET_BOARD_ERR_KIND,
    FLEET_BOARD_ERR_SCOPE,
    FLEET_BOARD_ERR_ROOM,
    FLEET_BOARD_ERR_AGENT,
    FLEET_BOARD_ERR_SLUG,
    FLEET_BOARD_ERR_TITLE,
    FLEET_BOARD_ERR_RECEIPT,
    FLEET_BOARD_ERR_TEXT,
    FLEET_BOARD_ERR_TTL,
    FLEET_BOARD_ERR_FUTURE,
    FLEET_BOARD_ERR_EXPIRED,
    FLEET_BOARD_ERR_TRUNCATED,
    FLEET_BOARD_ERR_TRAILING,
    FLEET_BOARD_ERR_CAPACITY,
    FLEET_BOARD_ERR_ID,
    FLEET_BOARD_ERR_SIGNATURE,
    /* The signature verifies and the key that made it holds no role on this
     * node granting `fleet.board.post` for this post's kind. Distinct from
     * ERR_SIGNATURE on purpose: nothing is wrong with the bytes, and the
     * peer that relayed them did nothing wrong either — this box has simply
     * never decided that this host key may write here. */
    FLEET_BOARD_ERR_ROLE,
    /* A PUBLIC-scope post's signing key verified fine and needs no grant,
     * but this key has posted too much: either the rolling-window rate or
     * the lifetime-stored-per-key ceiling is already spent. Distinct from
     * ERR_CAPACITY, which is the whole store being full regardless of who
     * is asking — this refusal is about ONE key, not the ledger. */
    FLEET_BOARD_ERR_QUOTA,
    FLEET_BOARD_ERR_BUSY,
};

const char *fleet_board_result_string(enum fleet_board_result r);
const char *fleet_board_kind_name(uint8_t kind);
bool fleet_board_kind_from_name(const char *name, uint8_t *out);

/* Scope names are the words agents type: "public" and "fleet". The legacy
 * scope names as "public", because that is what those posts always were. */
const char *fleet_board_scope_name(uint8_t scope);
bool fleet_board_scope_from_name(const char *name, uint8_t *out);

/* True when `room` is a legal room name: 1..32 bytes of [a-z0-9-], never
 * starting or ending with '-'. */
bool fleet_board_room_valid(const char *room);

/* The room a post reads as: its signed room, or FLEET_BOARD_ROOM_DEFAULT for
 * a legacy post that predates rooms. Never NULL. */
const char *fleet_board_room_name(const struct fleet_board_post *post);

/* True when this kind opens a request that a claim or result can close. */
bool fleet_board_kind_is_open_question(uint8_t kind);

/* The largest signed text this kind may carry. */
uint32_t fleet_board_text_max(uint8_t kind);

/* Shape-only validation: field bounds and per-kind field presence. It does not
 * look at the clock and does not verify the signature. */
enum fleet_board_result fleet_board_post_validate(
    const struct fleet_board_post *post);

/* Serialize the canonical signed body. `out_len` always receives the required
 * size, so a short buffer reports what it needed instead of guessing, and a
 * NULL/zero buffer is therefore a size query that refuses with
 * FLEET_BOARD_ERR_CAPACITY. The body excludes id and signature: neither can
 * fork the identity of the bytes. */
enum fleet_board_result fleet_board_post_canonical(
    const struct fleet_board_post *post, uint8_t *out, size_t out_capacity,
    size_t *out_len);

/* id = SHA3-256(domain-with-NUL || canonical body). */
enum fleet_board_result fleet_board_post_compute_id(
    const struct fleet_board_post *post, uint8_t out_id[32]);

/* Fill id and signature from a host Ed25519 keypair. `post` must already be
 * shape-valid; the id is recomputed here, never trusted from the caller. */
enum fleet_board_result fleet_board_post_sign(
    struct fleet_board_post *post, const uint8_t secret_seed[32],
    const uint8_t host_pubkey[32]);

/* Re-derive the id from the bytes and check the signature against the id.
 * A post whose stated id does not match its bytes is refused before any
 * curve arithmetic runs. */
enum fleet_board_result fleet_board_post_verify(
    const struct fleet_board_post *post);

/* Clock checks, kept separate from the cryptography so a caller can decide
 * what "now" means. `now` is Unix seconds. */
enum fleet_board_result fleet_board_post_check_time(
    const struct fleet_board_post *post, int64_t now);

/* Wire form: canonical body, then the 64-byte signature. */
enum fleet_board_result fleet_board_post_encode(
    const struct fleet_board_post *post, uint8_t *out, size_t out_capacity,
    size_t *out_len);

/* Decode + recompute id + verify signature. `out` is zeroed on every refusal;
 * no partial post is ever returned. Trailing bytes are a refusal, so a peer
 * cannot append attacker-chosen bytes to a post it relays. */
enum fleet_board_result fleet_board_post_decode(
    const uint8_t *wire, size_t wire_len, struct fleet_board_post *out);

/* ── Gossip frames, multiplexed on the existing swarm command ────────────
 * Every frame is `ZFB1` + one type byte + a bounded body. The board never
 * adds a P2P command of its own; it rides the frame the package swarm
 * already carries, exactly as the mesh status and terminal frames do. */

#define FLEET_BOARD_FRAME_MAGIC "ZFB1"
enum {
    FLEET_BOARD_FRAME_MAGIC_BYTES = 4,
    FLEET_BOARD_FRAME_INV = 1,   /* "I hold these ids" */
    FLEET_BOARD_FRAME_GET = 2,   /* "send me these ids" */
    FLEET_BOARD_FRAME_POST = 3,  /* one whole post */
    /* One inventory or request frame carries at most this many ids, so a
     * peer cannot buy unbounded work with one small frame. */
    FLEET_BOARD_FRAME_IDS_MAX = 128,
    FLEET_BOARD_FRAME_MAX = 4 + 1 + 2 + 128 * 32,
};

/* True when these bytes are addressed to the board at all. Cheap, total, and
 * side-effect free: the frame multiplexer calls it before anything else. */
bool fleet_board_frame_is_board(const uint8_t *wire, size_t wire_len);

/* Encode an id-list frame (INV or GET). */
enum fleet_board_result fleet_board_frame_encode_ids(
    uint8_t type, const uint8_t (*ids)[32], size_t count, uint8_t *out,
    size_t out_capacity, size_t *out_len);

/* Decode an id-list frame. `count_out` never exceeds `ids_capacity`; a frame
 * claiming more ids than it carries, or more than the ceiling, is refused. */
enum fleet_board_result fleet_board_frame_decode_ids(
    const uint8_t *wire, size_t wire_len, uint8_t *type_out,
    uint8_t (*ids)[32], size_t ids_capacity, size_t *count_out);

/* Encode/decode a single-post frame. Decode verifies the post. */
enum fleet_board_result fleet_board_frame_encode_post(
    const struct fleet_board_post *post, uint8_t *out, size_t out_capacity,
    size_t *out_len);
enum fleet_board_result fleet_board_frame_decode_post(
    const uint8_t *wire, size_t wire_len, struct fleet_board_post *out);

/* Read the frame type without decoding the body. Returns 0 for a frame that
 * is not a board frame at all. */
uint8_t fleet_board_frame_type(const uint8_t *wire, size_t wire_len);

/* Hash-chain step for the local append-only ledger:
 *   chain = SHA3-256(domain-with-NUL || previous chain || post id)
 * The genesis previous is 32 zero bytes. The chain is a LOCAL integrity
 * record of this node's arrival order; it is never gossiped and never used
 * to order the board for anyone else. */
void fleet_board_chain_step(const uint8_t previous[32], const uint8_t id[32],
                            uint8_t out_chain[32]);

/* Lowercase-hex helpers for the id form agents type and scripts grep. */
void fleet_board_id_to_hex(const uint8_t id[32], char out[65]);
bool fleet_board_id_from_hex(const char *hex, uint8_t out[32]);

/* True when `slug` is a legal wiki slug: 1..64 bytes of [a-z0-9-], never
 * starting or ending with '-'. */
bool fleet_board_slug_valid(const char *slug);

#endif /* ZCL_SESSION_FLEET_BOARD_PROTO_H */
