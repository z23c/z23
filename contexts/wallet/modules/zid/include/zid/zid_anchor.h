/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZID on-chain anchor overlay — the write-once binding of a sovereign
 * identity's ed25519 MASTER KEY to the PoW-committed chain.
 *
 * contexts/wallet/modules/zid already carries the off-chain half of the sovereign identity layer
 * (signed documents, blinded record keys, the anchor-domain MMR, inclusion
 * proofs, release records). This header is the missing on-chain half: the
 * v2 "dedicated ZID overlay" of docs/spec/sovereign-identity-layer.md
 * ("On-chain anchor formats"), lokad `ZID\0`, commands ANCHOR / ROTATE /
 * REVOKE carrying raw 32-byte keys. It is what lets a verifier answer "which
 * master key is this identity, and is it still live?" from chain bytes alone,
 * instead of trusting an out-of-band copy of the key.
 *
 * Parity-safe overlay, exactly like ZNAM/ZSLP/ZANC: a lokad-tagged, versioned
 * PUSH sequence inside a standard OP_RETURN output. NO new opcode, NO
 * consensus-rule change. Encoding comes from the overlay SDK
 * (overlay/overlay_codec.h), so the wire bytes are the one shared push
 * encoding every overlay speaks.
 *
 * OP_RETURN payload (Bitcoin script PUSH fields after 0x6a OP_RETURN):
 *   [PUSH "ZID\0"      (4)]   lokad id
 *   [PUSH version      (1)]   = ZID_ANCHOR_VERSION (1); dispatched FIRST,
 *                             before the command byte is even read, so a
 *                             future version can redefine every later field
 *   [PUSH command      (1)]   1=ANCHOR, 2=ROTATE, 3=REVOKE
 *   ANCHOR:  [PUSH pubkey     (32)]   the master key being anchored
 *   ROTATE:  [PUSH old_pubkey (32)]   the key being superseded
 *            [PUSH pubkey     (32)]   its replacement
 *   REVOKE:  [PUSH pubkey     (32)]   the key being retired
 * No trailing bytes are permitted after the final push.
 *
 * Strictness (the contexts/commons/modules/zanc model, NOT the contexts/naming/modules/znam model): every length is
 * exact, the version and command bytes are whitelisted, an all-zero key is
 * refused (it is not a usable ed25519 point and is the canonical "unset"
 * sentinel), a ROTATE from a key to itself is refused, trailing bytes reject,
 * and a script longer than the relay cap rejects on BOTH sides.
 *
 * Pure: no clock, no RNG, no I/O, no allocation. Caller buffers only. */

#ifndef ZCL_ZID_ANCHOR_H
#define ZCL_ZID_ANCHOR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define ZID_ANCHOR_LOKAD_BYTES  "\x5a\x49\x44\x00"  /* "ZID\0" */
#define ZID_ANCHOR_VERSION      1

#define ZID_ANCHOR_PUBKEY_LEN   32

enum zid_anchor_command {
    ZID_ANCHOR_CMD_INVALID = 0,
    ZID_ANCHOR_CMD_ANCHOR  = 1,  /* first publication of a master key */
    ZID_ANCHOR_CMD_ROTATE  = 2,  /* old key -> new key */
    ZID_ANCHOR_CMD_REVOKE  = 3,  /* retire a key with no replacement */
};

/* The longest script this overlay can emit: ROTATE, the only two-key form.
 *   1 (OP_RETURN) + 5 (lokad) + 2 (version) + 2 (command) + 33 + 33 = 76. */
#define ZID_ANCHOR_SCRIPT_MAX 76

/* Standard-relay ceiling for an OP_RETURN script. This is deliberately a
 * LOCAL copy of MAX_OP_RETURN_RELAY (core/modules/script/include/script/standard.h):
 * contexts/wallet/modules/zid sits BELOW core/modules/script in engine/composition/lib_module_order.def, so contexts/wallet/modules/zid
 * may not reference core/modules/script. The two are pinned equal by a static
 * assertion in tests/harness/src/test_zid.c, which is above both and can include
 * either — so this copy cannot silently drift. */
#define ZID_ANCHOR_RELAY_MAX 223

/* Parsed ZID anchor message. `pubkey` is always the SUBJECT of the command
 * (the key anchored / the replacement / the key revoked); `old_pubkey` is
 * populated only by ROTATE and only when has_old_pubkey is true. */
struct zid_anchor_message {
    uint8_t version;
    enum zid_anchor_command command;
    bool has_old_pubkey;                            /* true iff ROTATE */
    uint8_t old_pubkey[ZID_ANCHOR_PUBKEY_LEN];      /* ROTATE: superseded */
    uint8_t pubkey[ZID_ANCHOR_PUBKEY_LEN];          /* subject key */
};

/* True iff c is one of the three defined command bytes. */
bool zid_anchor_command_valid(uint8_t c);

/* Human name for a command byte ("anchor"/"rotate"/"revoke"/"unknown"). */
const char *zid_anchor_command_name(enum zid_anchor_command c);

/* Parse an OP_RETURN script into a ZID anchor message. Fail-anything: a
 * script over ZID_ANCHOR_RELAY_MAX, a bad lokad, an unknown version, an
 * unknown command, a wrong-length key push, an all-zero key, a self-ROTATE,
 * or ANY trailing byte all reject. On rejection *msg is zeroed with
 * command == ZID_ANCHOR_CMD_INVALID. Returns true only on a fully
 * well-formed anchor. */
bool zid_anchor_parse(const uint8_t *script, size_t script_len,
                      struct zid_anchor_message *msg);

/* Builders. Each writes the OP_RETURN script into out and returns the byte
 * count, or 0 on invalid input, an undersized buffer, or a script that would
 * exceed ZID_ANCHOR_RELAY_MAX (a non-standard script that would not relay is
 * never emitted). Keys must be non-NULL and not all-zero. */
size_t zid_anchor_build_anchor(uint8_t *out, size_t out_len,
                               const uint8_t pubkey[ZID_ANCHOR_PUBKEY_LEN]);

/* ROTATE additionally requires old_pubkey != pubkey. */
size_t zid_anchor_build_rotate(uint8_t *out, size_t out_len,
                               const uint8_t old_pubkey[ZID_ANCHOR_PUBKEY_LEN],
                               const uint8_t new_pubkey[ZID_ANCHOR_PUBKEY_LEN]);

size_t zid_anchor_build_revoke(uint8_t *out, size_t out_len,
                               const uint8_t pubkey[ZID_ANCHOR_PUBKEY_LEN]);

#endif /* ZCL_ZID_ANCHOR_H */
