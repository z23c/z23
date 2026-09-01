/* zotpcli — TOTP/HOTP authenticator store and code generation (C23)
 *
 * Apache-2.0 licensed. The non-UI half of an oathtool-style authenticator:
 *
 *  - HOTP codes (RFC 4226, built on the Commons zotp package);
 *  - TOTP codes (RFC 6238): the HOTP counter is floor(now / period),
 *    where `now` is Unix seconds supplied by the caller, so library
 *    tests are fully deterministic. The CLI app passes time(2) unless
 *    --now overrides it;
 *  - a local entry store serialized as length-framed (LEB128 via
 *    zvarint) JSON records (zjson writer, zjsonp parser) with a
 *    trailing HMAC-SHA256 (zsha256) integrity record keyed by scrypt
 *    (zscrypt) + HKDF (zhkdf) stretching of an optional passphrase;
 *  - otpauth:// URI import/export (zurl parse, zpct percent codec,
 *    zb32 base32 secrets).
 *
 * HONESTY NOTE — what the store MAC is and is not:
 * The trailing MAC provides INTEGRITY (tamper evidence) and the KDF
 * provides passphrase STRETCHING. It is NOT encryption at rest.
 * Records are plain JSON: secrets are stored obscured-but-readable
 * (base64), and anyone who can read the file can read every secret.
 * When no passphrase is set, anyone who can write the file can also
 * recompute the MAC, so the MAC then detects only accidental
 * corruption, not a deliberate attacker. This package makes no
 * confidentiality claim.
 *
 * Bounds: all strings are caller-visible fixed caps, the entry count
 * and file size are hard-bounded, every allocation is checked, and
 * malformed input is a clean error, never a crash.
 */
#ifndef ZOTPCLI_H
#define ZOTPCLI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zbuf/zbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZOTPCLI_MAX_ENTRIES 256u
#define ZOTPCLI_MAX_LABEL   128u /* bytes, UTF-8 */
#define ZOTPCLI_MAX_ISSUER  128u
#define ZOTPCLI_MAX_SECRET  128u /* raw secret bytes */
#define ZOTPCLI_MAX_URI     2048u
#define ZOTPCLI_MAX_FILE    (1024u * 1024u)
#define ZOTPCLI_SALT_LEN    16u
#define ZOTPCLI_MAC_LEN     32u

#define ZOTPCLI_DEFAULT_DIGITS 6u
#define ZOTPCLI_MIN_DIGITS     6u
#define ZOTPCLI_MAX_DIGITS     8u
#define ZOTPCLI_DEFAULT_PERIOD 30u
#define ZOTPCLI_MAX_PERIOD     3600u

/* scrypt parameters for store-MAC key stretching (RFC 7914
 * interactive-login suggestion), recorded in the store header. */
#define ZOTPCLI_SCRYPT_N 16384u
#define ZOTPCLI_SCRYPT_R 8u
#define ZOTPCLI_SCRYPT_P 1u

typedef enum {
    ZOTPCLI_TOTP = 0,
    ZOTPCLI_HOTP = 1
} zotpcli_kind;

typedef enum {
    ZOTPCLI_OK = 0,
    ZOTPCLI_ERR_ARG,     /* NULL or out-of-range argument */
    ZOTPCLI_ERR_NOMEM,   /* allocation failed */
    ZOTPCLI_ERR_LABEL,   /* label invalid UTF-8, empty, or duplicate */
    ZOTPCLI_ERR_FULL,    /* store at ZOTPCLI_MAX_ENTRIES */
    ZOTPCLI_ERR_NOTFOUND,/* no entry with that label */
    ZOTPCLI_ERR_SECRET,  /* bad base32 or out-of-range secret */
    ZOTPCLI_ERR_URI,     /* malformed or unsupported otpauth URI */
    ZOTPCLI_ERR_FORMAT,  /* store bytes malformed */
    ZOTPCLI_ERR_MAC,     /* integrity check failed (tampered or wrong
                            passphrase) */
    ZOTPCLI_ERR_KDF,     /* key derivation failed */
    ZOTPCLI_ERR_TRUNC    /* caller output buffer too small */
} zotpcli_err;

const char *zotpcli_err_str(zotpcli_err e);

typedef struct {
    char label[ZOTPCLI_MAX_LABEL + 1];   /* NUL-terminated, UTF-8 */
    char issuer[ZOTPCLI_MAX_ISSUER + 1]; /* "" when absent */
    uint8_t secret[ZOTPCLI_MAX_SECRET];
    size_t secret_len;
    zotpcli_kind kind;
    unsigned digits;    /* 6..8 */
    unsigned period;    /* TOTP step in seconds, 1..3600 */
    uint64_t counter;   /* HOTP: next counter to use */
} zotpcli_entry;

/* Zero *e and set defaults (TOTP, 6 digits, 30 s period, counter 0). */
void zotpcli_entry_init(zotpcli_entry *e);

typedef struct {
    zotpcli_entry *entries; /* owned; capacity ZOTPCLI_MAX_ENTRIES */
    size_t count;
    uint8_t salt[ZOTPCLI_SALT_LEN]; /* KDF salt of the loaded/next
                                       encoding; set by _decode or by
                                       the caller before first _encode */
} zotpcli_store;

/* Allocate the entry array. Returns ZOTPCLI_ERR_NOMEM on failure. */
zotpcli_err zotpcli_store_init(zotpcli_store *s);

/* Free the entry array and zeroize all secret material. Safe on a
 * zeroed or already-freed store. */
void zotpcli_store_free(zotpcli_store *s);

size_t zotpcli_store_count(const zotpcli_store *s);
const zotpcli_entry *zotpcli_store_get(const zotpcli_store *s, size_t i);
const zotpcli_entry *zotpcli_store_find(const zotpcli_store *s,
                                        const char *label);
zotpcli_entry *zotpcli_store_find_mut(zotpcli_store *s, const char *label);

/* Validate and append a copy of *e: label must be nonempty well-formed
 * UTF-8 (checked with zutf8) and unique, issuer well-formed UTF-8,
 * secret_len in 1..ZOTPCLI_MAX_SECRET, digits 6..8, period 1..3600. */
zotpcli_err zotpcli_store_add(zotpcli_store *s, const zotpcli_entry *e);

/* Remove the entry with `label`; false when absent. */
bool zotpcli_store_remove(zotpcli_store *s, const char *label);

/* --- code generation --------------------------------------------- */

/* HOTP for an explicit counter (RFC 4226). out must hold digits+1
 * bytes. Returns 1 on success, 0 on bad arguments. */
int zotpcli_hotp_code(const zotpcli_entry *e, uint64_t counter,
                      char *out);

/* TOTP counter for a Unix time: floor(now / period). now must be
 * non-negative. */
uint64_t zotpcli_totp_counter(const zotpcli_entry *e, int64_t now);

/* TOTP (RFC 6238) at Unix time `now`. Returns 1 on success, 0 on bad
 * arguments (negative now, bad entry). */
int zotpcli_totp_code(const zotpcli_entry *e, int64_t now, char *out);

/* Dispatch on entry kind: HOTP uses e->counter, TOTP uses `now`. */
int zotpcli_code(const zotpcli_entry *e, int64_t now, char *out);

/* --- base32 secrets (RFC 4648) ------------------------------------ */

/* Decode a base32 secret as otpauth tools accept it: case-insensitive,
 * padding optional (added internally before zb32 strict decoding).
 * Returns ZOTPCLI_ERR_SECRET on any malformed character or length. */
zotpcli_err zotpcli_b32_decode_secret(const char *text, uint8_t *out,
                                      size_t cap, size_t *out_len);

/* Encode secret bytes as uppercase base32 WITHOUT '=' padding (the
 * conventional otpauth rendering). out is NUL-terminated. */
zotpcli_err zotpcli_b32_encode_secret(const uint8_t *secret, size_t len,
                                      char *out, size_t cap);

/* --- otpauth:// URIs ----------------------------------------------- */

/* Parse an otpauth://totp/... or otpauth://hotp/... URI (Google
 * Authenticator KeyUriFormat). Only SHA-1 is supported; an explicit
 * algorithm=SHA256/SHA512 is rejected, fail-closed. The label is
 * percent-decoded and must be well-formed UTF-8. */
zotpcli_err zotpcli_otpauth_parse_n(const char *uri, size_t len,
                                    zotpcli_entry *out);
zotpcli_err zotpcli_otpauth_parse(const char *uri, zotpcli_entry *out);

/* Render *e as an otpauth URI into out (capacity cap). The secret is
 * unpadded base32; issuer and label are percent-encoded. */
zotpcli_err zotpcli_otpauth_format(const zotpcli_entry *e, char *out,
                                   size_t cap);

/* --- store serialization ------------------------------------------- */

/* Serialize the store into `out`:
 *
 *   magic "ZOTPCLI1"
 *   record 0: header JSON {"v":1,"kdf":"scrypt","n":..,"r":..,"p":..,
 *                          "salt":<base64>}
 *   record 1..N: one JSON object per entry (secret base64-encoded)
 *   record N+1: {"mac":<base64 HMAC-SHA256>}
 *
 * Each record is framed as LEB128 length + payload. The MAC covers
 * every preceding byte and is keyed by
 * HKDF-SHA256(scrypt(passphrase, salt), "zotpcli-store-mac-v1").
 * A NULL passphrase is treated as ""; see the honesty note above.
 * `salt` (16 bytes) becomes the store's KDF salt; callers generating a
 * new store should fill it from a CSPRNG. */
zotpcli_err zotpcli_store_encode(const zotpcli_store *s,
                                 const char *passphrase,
                                 const uint8_t salt[ZOTPCLI_SALT_LEN],
                                 zbuf *out);

/* Parse and verify a store from data[0..len). The MAC is verified
 * BEFORE any entry is accepted: tampered bytes or a wrong passphrase
 * yield ZOTPCLI_ERR_MAC. On success the store (freshly initialized by
 * the caller) owns the decoded entries and s->salt is the header salt. */
zotpcli_err zotpcli_store_decode(zotpcli_store *s, const void *data,
                                 size_t len, const char *passphrase);

#ifdef __cplusplus
}
#endif

#endif /* ZOTPCLI_H */
