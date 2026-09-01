/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZDIR — OP_RETURN parser and builder for the on-chain node directory.
 * See zdir/zdir.h for the wire grammar and what a directory record is (and
 * is not). Built on the overlay SDK, so ZDIR hand-rolls only its own field
 * grammar. Pure: no clock, no RNG, no I/O, no alloc. */

#include "zdir/zdir.h"

#include "net/onion_peer_merge.h"
#include "overlay/overlay_codec.h"
#include "script/standard.h"

#include <string.h>

bool zdir_command_valid(uint8_t c)
{
    return c == ZDIR_CMD_REGISTER || c == ZDIR_CMD_DEREGISTER;
}

const char *zdir_command_name(uint8_t c)
{
    switch (c) {
    case ZDIR_CMD_REGISTER:   return "register";
    case ZDIR_CMD_DEREGISTER: return "deregister";
    default:                  return "unknown";
    }
}

/* True iff every byte of the 32-byte key is zero — an all-zero ed25519 key is
 * not a key, so a binding to one is refused rather than stored. */
static bool zdir_key_is_zero(const uint8_t k[ZDIR_PUBKEY_LEN])
{
    for (size_t i = 0; i < ZDIR_PUBKEY_LEN; i++)
        if (k[i]) return false;
    return true;
}

bool zdir_parse(const uint8_t *script, size_t script_len,
                struct zdir_message *msg)
{
    if (!msg) return false;
    memset(msg, 0, sizeof(*msg));

    /* Fields 0-1: lokad "ZDIR" + version — the shared overlay framing. */
    struct overlay_reader r;
    if (!overlay_reader_begin(&r, script, script_len, ZDIR_LOKAD_BYTES))
        return false;
    if (!overlay_expect_u8(&r, ZDIR_VERSION)) return false;
    msg->version = ZDIR_VERSION;

    /* Field 2: command. Reserved/unknown bytes (including 3, TRANSFER) are
     * rejected outright — a record this version cannot act on must not be
     * half-projected. */
    if (!overlay_read_u8(&r, &msg->command)) return false;
    if (!zdir_command_valid(msg->command)) return false;

    /* Field 3: hostname, EXACTLY 62 bytes. Attacker-controlled: it reaches
     * the peer table, dial attempts, JSON and HTML, so it is held to the one
     * v3 onion rule the node has (core/modules/net), never sanitized. */
    if (!overlay_read_fixed(&r, (uint8_t *)msg->hostname, ZDIR_HOSTNAME_LEN))
        return false;
    msg->hostname[ZDIR_HOSTNAME_LEN] = '\0';
    if (!onion_hostname_valid(msg->hostname)) return false;

    /* Field 4: optional 32-byte zid master-key binding; empty push = unbound.
     * DEREGISTER never carries one. */
    size_t pk_len = 0;
    if (!overlay_read_bounded(&r, msg->pubkey, ZDIR_PUBKEY_LEN, &pk_len))
        return false;
    if (pk_len != 0 && pk_len != ZDIR_PUBKEY_LEN) return false;
    if (pk_len == ZDIR_PUBKEY_LEN) {
        if (msg->command != ZDIR_CMD_REGISTER) return false;
        if (zdir_key_is_zero(msg->pubkey)) return false;
        msg->has_pubkey = true;
    } else {
        memset(msg->pubkey, 0, sizeof(msg->pubkey));
    }

    /* No trailing bytes after the last push. */
    return overlay_reader_finish(&r);
}

/* The one builder both commands share: `pubkey` NULL emits the empty push. */
static size_t zdir_build(uint8_t *out, size_t out_len, uint8_t command,
                         const char *hostname,
                         const uint8_t pubkey[ZDIR_PUBKEY_LEN])
{
    if (!out) return 0;
    if (!zdir_command_valid(command)) return 0;
    if (!onion_hostname_valid(hostname)) return 0;
    if (pubkey && zdir_key_is_zero(pubkey)) return 0;

    struct overlay_writer w;
    overlay_writer_begin(&w, out, out_len, ZDIR_LOKAD_BYTES);
    overlay_put_u8(&w, ZDIR_VERSION);
    overlay_put_u8(&w, command);
    overlay_put_field(&w, (const uint8_t *)hostname, ZDIR_HOSTNAME_LEN);
    overlay_put_field(&w, pubkey, pubkey ? ZDIR_PUBKEY_LEN : 0);

    size_t n = overlay_writer_finish(&w);
    /* Standard relay policy caps an OP_RETURN script at MAX_OP_RETURN_RELAY
     * (223) bytes; a longer script is non-standard and would never relay, so
     * never hand one back. The ZDIR grammar tops out at ZDIR_SCRIPT_MAX (106),
     * so this cannot fire today — it is the contract that keeps it true if the
     * grammar ever grows a field. Same shape as zanc_build_anchor. */
    if (n > MAX_OP_RETURN_RELAY || n > ZDIR_SCRIPT_MAX) return 0;
    return n;
}

size_t zdir_build_register(uint8_t *out, size_t out_len, const char *hostname,
                           const uint8_t pubkey[ZDIR_PUBKEY_LEN])
{
    return zdir_build(out, out_len, ZDIR_CMD_REGISTER, hostname, pubkey);
}

size_t zdir_build_deregister(uint8_t *out, size_t out_len,
                             const char *hostname)
{
    return zdir_build(out, out_len, ZDIR_CMD_DEREGISTER, hostname, NULL);
}
