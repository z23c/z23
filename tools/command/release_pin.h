/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: owner-key pins for signed release docs. A signature proves a doc
 *          was made by the key it names; a PIN is the receiver's own prior
 *          decision that this key is one it trusts. This leaf-free helper
 *          holds the pin set, the typed refusals and the fingerprint so
 *          `zcode release verify --pin` and `ops slot install` can never
 *          disagree about what "pinned" means.
 *
 * A pin is either a bare 64-hex Ed25519 public key (an Ed25519-only pin) or
 * a PAIR `zrs1 <ed25519_hex64> <param:0> <slhdsa_pk_hex64>` (Ed25519 master
 * key plus its SLH-DSA-SHAKE-128s key), given inline (`pin`) or one per line
 * in a local owner-pins file (`pin_file`; blank lines and lines starting
 * with '#' are ignored; a line `require-pq` is a directive, see below). Both
 * may be given; the pin set is their union. Nothing here touches the chain,
 * the network or a subprocess.
 *
 * Acceptance (docs/work/PQ_HYBRID_RELEASE_SIGNATURE.md section 6.1):
 *   v1 doc  - signer must match an Ed25519-only pin or the Ed25519 half of a
 *             pair (phase 2); with `require_pq` (input bool, or the
 *             `require-pq` pin-file directive) it is RELEASE_PQ_REQUIRED.
 *   v2 doc  - needs a PAIR pin matching BOTH its master key and its
 *             container SLH-DSA key, and both signatures must verify. A
 *             master key pinned only Ed25519-only is RELEASE_PQ_UNPINNED:
 *             the AND property is never weakened to the Ed25519 half.
 */
#ifndef ZCL_COMMAND_RELEASE_PIN_H
#define ZCL_COMMAND_RELEASE_PIN_H

#include "zid/zid.h"
#include "zid/zid_hybrid.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;
struct zcl_command_reply;

#define RELEASE_PIN_MAX 256u
#define RELEASE_PIN_FILE_MAX_BYTES (64u * 1024u)
#define RELEASE_PIN_FINGERPRINT_HEX 16u
#define RELEASE_PIN_PAIR_TAG "zrs1"
#define RELEASE_PIN_REQUIRE_PQ_LINE "require-pq"

struct release_pin_pair {
    uint8_t ed[32];
    uint8_t pq[ZRS1_PQ_PK_SIZE];
};

/* keys + pairs together hold at most RELEASE_PIN_MAX distinct entries. */
struct release_pin_set {
    uint8_t keys[RELEASE_PIN_MAX][32];
    size_t count;
    struct release_pin_pair pairs[RELEASE_PIN_MAX];
    size_t pair_count;
    bool given;      /* pin or pin_file was supplied (even if it listed nothing) */
    bool require_pq; /* refuse v1 docs (phase 3) */
};

/* A saved release doc of either version. `doc` is the v1-shaped view (for
 * v2 the signature field stays zero); `v2` is filled only when version==2. */
struct release_pin_doc {
    struct zid_doc doc;
    struct zid_doc_v2 v2;
    uint8_t version;   /* 1 or 2 */
    bool pq_verified;  /* set by release_pin_doc_gate: both signatures held */
};

/* Fingerprint of an owner key: the first 8 bytes of SHA-256(pubkey) as 16
 * lowercase hex characters plus NUL. Short enough to read aloud. */
void release_pin_fingerprint(const uint8_t pubkey[32],
                             char out[RELEASE_PIN_FINGERPRINT_HEX + 1]);

/* Read `pin` / `pin_file` / `require_pq` from the command input into *set.
 * Returns false after failing `reply` with a typed code (BAD_PIN,
 * PIN_FILE_UNREADABLE, PIN_FILE_INVALID with the line number,
 * PIN_FILE_EMPTY, TOO_MANY_PINS). No pin keys given is success with
 * set->given == false. */
bool release_pin_collect(const struct json_value *in,
                         struct release_pin_set *set,
                         struct zcl_command_reply *reply, const char *command);

/* True iff a v1 doc signed by `pubkey` is pinned: an Ed25519-only pin or the
 * Ed25519 half of a pair. */
bool release_pin_contains(const struct release_pin_set *set,
                          const uint8_t pubkey[32]);

/* The shared gate for a v1 signer. With a pin set, a signer outside it fails
 * with RELEASE_UNPINNED. With require_pq it then fails RELEASE_PQ_REQUIRED.
 * With `package_root` in the input, a manifest root that differs fails with
 * RELEASE_ROOT_MISMATCH. With none of these, the gate is a no-op that
 * returns true, so existing callers see no change. `require_pin` turns an
 * absent pin into a typed PIN_REQUIRED refusal. Returns false after failing
 * `reply`. */
bool release_pin_gate(const struct json_value *in, bool require_pin,
                      const uint8_t signer[32], const uint8_t manifest_root[32],
                      struct zcl_command_reply *reply, const char *command);

/* The gate for a doc of either version. A v1 doc must already be verified
 * and `rel` filled (release_pin_gate then runs). A v2 doc is verified here
 * against the pinned pair and `rel` is filled; d->pq_verified is set. Failure
 * codes for v2: PIN_REQUIRED, RELEASE_UNPINNED, RELEASE_PQ_UNPINNED, then the
 * zid_hybrid status code (PQ_KEY_MISMATCH, BAD_SIGNATURE, BAD_PQ_SIGNATURE,
 * DOC_EXPIRED ...), then RELEASE_ROOT_MISMATCH. */
bool release_pin_doc_gate(const struct json_value *in, bool require_pin,
                          struct release_pin_doc *d, uint64_t now_unix,
                          struct zid_release *rel,
                          struct zcl_command_reply *reply, const char *command);

/* Read a saved .zid v1 release doc (hex text, at most ZID_DOC_MAX*2 chars
 * plus whitespace) and decode it. A v2 file is refused. On failure returns
 * false and sets *code to DOC_UNREADABLE, BAD_DOC_HEX or DOC_DECODE_FAILED. */
bool release_pin_read_doc(const char *path, struct zid_doc *doc,
                          const char **code);

/* Like release_pin_read_doc, but accepts a v1 or a v2 file. A malformed v2
 * file reports its distinct container code (zid_hybrid_status_code). */
bool release_pin_read_any(const char *path, struct release_pin_doc *d,
                          const char **code);

#endif
