/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: owner-key pins for signed release docs. A signature proves a doc
 *          was made by the key it names; a PIN is the receiver's own prior
 *          decision that this key is one it trusts. This leaf-free helper
 *          holds the pin set, the typed refusals and the fingerprint so
 *          `zcode release verify --pin` and `ops slot install` can never
 *          disagree about what "pinned" means.
 *
 * A pin is a 64-hex Ed25519 public key given inline (`pin`) or listed one
 * per line in a local owner-pins file (`pin_file`; blank lines and lines
 * starting with '#' are ignored). Both may be given; the pin set is their
 * union. Nothing here touches the chain, the network or a subprocess.
 */
#ifndef ZCL_COMMAND_RELEASE_PIN_H
#define ZCL_COMMAND_RELEASE_PIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;
struct zcl_command_reply;
struct zid_doc;

#define RELEASE_PIN_MAX 256u
#define RELEASE_PIN_FILE_MAX_BYTES (64u * 1024u)
#define RELEASE_PIN_FINGERPRINT_HEX 16u

struct release_pin_set {
    uint8_t keys[RELEASE_PIN_MAX][32];
    size_t count;
    bool given; /* pin or pin_file was supplied (even if it listed nothing) */
};

/* Fingerprint of an owner key: the first 8 bytes of SHA-256(pubkey) as 16
 * lowercase hex characters plus NUL. Short enough to read aloud. */
void release_pin_fingerprint(const uint8_t pubkey[32],
                             char out[RELEASE_PIN_FINGERPRINT_HEX + 1]);

/* Read `pin` / `pin_file` from the command input into *set. Returns false
 * after failing `reply` with a typed code (BAD_PIN, PIN_FILE_UNREADABLE,
 * PIN_FILE_INVALID, PIN_FILE_EMPTY, TOO_MANY_PINS). No pin keys given is
 * success with set->given == false. */
bool release_pin_collect(const struct json_value *in,
                         struct release_pin_set *set,
                         struct zcl_command_reply *reply, const char *command);

bool release_pin_contains(const struct release_pin_set *set,
                          const uint8_t pubkey[32]);

/* The shared gate. With a pin set, a signer outside it fails with
 * RELEASE_UNPINNED. With `package_root` in the input, a manifest root that
 * differs fails with RELEASE_ROOT_MISMATCH. With neither, the gate is a
 * no-op that returns true, so existing callers see no change. `require_pin`
 * turns an absent pin into a typed PIN_REQUIRED refusal. Returns false
 * after failing `reply`. */
bool release_pin_gate(const struct json_value *in, bool require_pin,
                      const uint8_t signer[32], const uint8_t manifest_root[32],
                      struct zcl_command_reply *reply, const char *command);

/* Read a saved .zid release doc (hex text, at most ZID_DOC_MAX*2 chars plus
 * whitespace) and decode it. On failure returns false and sets *code to
 * DOC_UNREADABLE, BAD_DOC_HEX or DOC_DECODE_FAILED. */
bool release_pin_read_doc(const char *path, struct zid_doc *doc,
                          const char **code);

#endif
