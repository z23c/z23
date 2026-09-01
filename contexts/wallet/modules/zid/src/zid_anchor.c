/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZID on-chain anchor overlay — OP_RETURN parser and builder. See
 * zid/zid_anchor.h for the wire grammar and docs/spec/sovereign-identity-layer.md
 * for why the anchor exists. Built on the overlay SDK
 * (overlay/overlay_codec.h), so this file hand-rolls only the ZID field
 * grammar; the lokad framing, the bounds-checked push reads, and the bounded
 * builder all come from the shared cursors.
 *
 * Strictness follows contexts/commons/modules/zanc (reject trailing bytes, validate hard), not
 * contexts/naming/modules/znam. No logging: these are pure predicates over adversarial chain
 * bytes, so a rejected script is a normal negative result, not an error to
 * record — same contract as engine/modules/overlay and contexts/commons/modules/zanc. */

#include "zid/zid_anchor.h"
#include "overlay/overlay_codec.h"
#include <string.h>

/* An all-zero key is the canonical "unset" sentinel and is not a usable
 * ed25519 public key; refusing it keeps an uninitialized caller buffer from
 * ever reaching the chain, and keeps a zeroed parse result unambiguous. */
static bool zid_anchor_key_usable(const uint8_t *key)
{
    if (!key) return false;
    uint8_t acc = 0;
    for (size_t i = 0; i < ZID_ANCHOR_PUBKEY_LEN; i++)
        acc |= key[i];
    return acc != 0;
}

bool zid_anchor_command_valid(uint8_t c)
{
    return c == ZID_ANCHOR_CMD_ANCHOR ||
           c == ZID_ANCHOR_CMD_ROTATE ||
           c == ZID_ANCHOR_CMD_REVOKE;
}

const char *zid_anchor_command_name(enum zid_anchor_command c)
{
    switch (c) {
    case ZID_ANCHOR_CMD_ANCHOR: return "anchor";
    case ZID_ANCHOR_CMD_ROTATE: return "rotate";
    case ZID_ANCHOR_CMD_REVOKE: return "revoke";
    case ZID_ANCHOR_CMD_INVALID:
    default: return "unknown";
    }
}

/* ── Parser ─────────────────────────────────────────────────────────── */

static bool zid_anchor_parse_fields(const uint8_t *script, size_t script_len,
                                    struct zid_anchor_message *msg)
{
    /* A script that could never have been relayed is not a ZID anchor. */
    if (script_len > ZID_ANCHOR_RELAY_MAX) return false;

    /* Fields 0-1: lokad "ZID\0" + version — the shared overlay framing. The
     * version is dispatched FIRST: nothing after it is interpreted until the
     * reader has agreed on which grammar it is reading. */
    struct overlay_reader r;
    if (!overlay_reader_begin(&r, script, script_len, ZID_ANCHOR_LOKAD_BYTES))
        return false;
    if (!overlay_expect_u8(&r, ZID_ANCHOR_VERSION)) return false;
    msg->version = ZID_ANCHOR_VERSION;

    /* Field 2: command (1 byte, whitelisted). */
    uint8_t cmd = 0;
    if (!overlay_read_u8(&r, &cmd)) return false;
    if (!zid_anchor_command_valid(cmd)) return false;
    msg->command = (enum zid_anchor_command)cmd;

    /* Field 3 (ROTATE only): the superseded key (exactly 32 bytes). */
    if (msg->command == ZID_ANCHOR_CMD_ROTATE) {
        if (!overlay_read_fixed(&r, msg->old_pubkey, ZID_ANCHOR_PUBKEY_LEN))
            return false;
        msg->has_old_pubkey = true;
    }

    /* Final field: the subject key (exactly 32 bytes). */
    if (!overlay_read_fixed(&r, msg->pubkey, ZID_ANCHOR_PUBKEY_LEN))
        return false;

    /* No trailing bytes after the last key push. */
    if (!overlay_reader_finish(&r)) return false;

    if (!zid_anchor_key_usable(msg->pubkey)) return false;
    if (msg->has_old_pubkey) {
        if (!zid_anchor_key_usable(msg->old_pubkey)) return false;
        /* A rotation to the same key carries no information and would let a
         * projection record a rotation that changed nothing. */
        if (memcmp(msg->old_pubkey, msg->pubkey, ZID_ANCHOR_PUBKEY_LEN) == 0)
            return false;
    }
    return true;
}

bool zid_anchor_parse(const uint8_t *script, size_t script_len,
                      struct zid_anchor_message *msg)
{
    if (!msg) return false;
    memset(msg, 0, sizeof(*msg));
    msg->command = ZID_ANCHOR_CMD_INVALID;

    if (zid_anchor_parse_fields(script, script_len, msg))
        return true;

    /* Leave nothing half-parsed behind for a caller that ignores the bool. */
    memset(msg, 0, sizeof(*msg));
    msg->command = ZID_ANCHOR_CMD_INVALID;
    return false;
}

/* ── Builder ────────────────────────────────────────────────────────── */

/* old_pubkey is non-NULL only for ROTATE; pubkey is always the subject. */
static size_t zid_anchor_build(uint8_t *out, size_t out_len, uint8_t command,
                               const uint8_t *old_pubkey,
                               const uint8_t *pubkey)
{
    if (!out || out_len == 0) return 0;
    if (!zid_anchor_command_valid(command)) return 0;
    if (!zid_anchor_key_usable(pubkey)) return 0;

    if (command == ZID_ANCHOR_CMD_ROTATE) {
        if (!zid_anchor_key_usable(old_pubkey)) return 0;
        if (memcmp(old_pubkey, pubkey, ZID_ANCHOR_PUBKEY_LEN) == 0) return 0;
    } else if (old_pubkey) {
        return 0;  /* caller passed a rotation argument to a one-key command */
    }

    struct overlay_writer w;
    overlay_writer_begin(&w, out, out_len, ZID_ANCHOR_LOKAD_BYTES);
    overlay_put_u8(&w, ZID_ANCHOR_VERSION);
    overlay_put_u8(&w, command);
    if (command == ZID_ANCHOR_CMD_ROTATE)
        overlay_put_field(&w, old_pubkey, ZID_ANCHOR_PUBKEY_LEN);
    overlay_put_field(&w, pubkey, ZID_ANCHOR_PUBKEY_LEN);

    size_t n = overlay_writer_finish(&w);
    /* Never hand back a script that standard relay policy would drop. The
     * grammar above tops out at ZID_ANCHOR_SCRIPT_MAX (76), so this cannot
     * fire today — it is the explicit contract that keeps it true if the
     * grammar ever grows a field. Same shape as blog_anchor_script_build. */
    if (n > ZID_ANCHOR_RELAY_MAX) return 0;
    return n;
}

size_t zid_anchor_build_anchor(uint8_t *out, size_t out_len,
                               const uint8_t pubkey[ZID_ANCHOR_PUBKEY_LEN])
{
    return zid_anchor_build(out, out_len, ZID_ANCHOR_CMD_ANCHOR, NULL, pubkey);
}

size_t zid_anchor_build_rotate(uint8_t *out, size_t out_len,
                               const uint8_t old_pubkey[ZID_ANCHOR_PUBKEY_LEN],
                               const uint8_t new_pubkey[ZID_ANCHOR_PUBKEY_LEN])
{
    return zid_anchor_build(out, out_len, ZID_ANCHOR_CMD_ROTATE,
                            old_pubkey, new_pubkey);
}

size_t zid_anchor_build_revoke(uint8_t *out, size_t out_len,
                               const uint8_t pubkey[ZID_ANCHOR_PUBKEY_LEN])
{
    return zid_anchor_build(out, out_len, ZID_ANCHOR_CMD_REVOKE, NULL, pubkey);
}
