/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Anchors (ZANC) — on-chain software/package digest anchoring.
 *
 * Anchors a SHA-256 or SHA3-256 digest into the ZClassic chain via a
 * standard OP_RETURN output — the same parity-safe overlay pattern as
 * ZNAM/ZSLP (no new opcodes, no consensus change). The chain's PoW-committed
 * history timestamps the digest; verification recomputes the digest and finds
 * the anchoring tx. Anchoring is permissionless — anyone may anchor any
 * digest; the anchor proves existence-at-height, not authorship (see
 * docs/SOFTWARE_ANCHORING.md).
 *
 * Lokad ID: "ZANC" (0x5a414e43). Encoded in the tx's first OP_RETURN output.
 *
 * OP_RETURN payload (Bitcoin script PUSH fields after 0x6a OP_RETURN):
 *   [PUSH "ZANC"     (4)]   lokad id
 *   [PUSH version    (1)]   = ZANC_VERSION (1)
 *   [PUSH hash_type  (1)]   1=SHA2-256, 2=SHA3-256
 *   [PUSH digest    (32)]   the anchored digest
 *   [PUSH label   (0..32)]  optional UTF-8 label ("name@version"); may be empty
 * No trailing bytes are permitted after the label push. */

#ifndef ZCL_ZANC_H
#define ZCL_ZANC_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define ZANC_LOKAD_BYTES   "ZANC"
#define ZANC_VERSION       1

#define ZANC_HASH_SHA2_256 1
#define ZANC_HASH_SHA3_256 2

#define ZANC_DIGEST_LEN    32
#define ZANC_LABEL_MAX     32

/* Parsed ZANC message from an OP_RETURN script. */
struct zanc_message {
    uint8_t version;
    uint8_t hash_type;                  /* ZANC_HASH_* */
    uint8_t digest[ZANC_DIGEST_LEN];
    uint8_t label_len;                  /* 0..ZANC_LABEL_MAX */
    char label[ZANC_LABEL_MAX + 1];     /* NUL-terminated */
};

/* True iff t is a supported hash-type byte. */
bool zanc_hash_type_valid(uint8_t t);

/* Human name for a hash-type byte ("sha2-256"/"sha3-256"/"unknown"). */
const char *zanc_hash_type_name(uint8_t t);

/* True iff label[0..len) is a bounded (<=ZANC_LABEL_MAX) well-formed UTF-8
 * string with no embedded NUL and no C0 control bytes. len==0 is valid. */
bool zanc_label_valid(const char *label, size_t len);

/* Parse an OP_RETURN script into a ZANC message. Strict: every field length,
 * the version, and the hash-type byte are checked, the label is UTF-8
 * validated, and any trailing bytes reject. Returns true only on a fully
 * well-formed ZANC anchor. */
bool zanc_parse(const uint8_t *script, size_t script_len,
                struct zanc_message *msg);

/* Build the ZANC OP_RETURN script into out. Requires a valid hash_type and a
 * non-NULL 32-byte digest; label may be NULL/empty and if present must pass
 * zanc_label_valid. Returns bytes written, or 0 on invalid input, if out is
 * too small, or if the script would exceed MAX_OP_RETURN_RELAY (223,
 * script/standard.h) — a non-standard OP_RETURN is never emitted. The ZANC
 * grammar tops out at 76 bytes, so the cap is a contract, not a live
 * constraint. */
size_t zanc_build_anchor(uint8_t *out, size_t out_len, uint8_t hash_type,
                         const uint8_t digest[ZANC_DIGEST_LEN],
                         const char *label);

#endif /* ZCL_ZANC_H */
