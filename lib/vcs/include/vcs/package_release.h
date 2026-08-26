/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_release — the signed ZCODE package release envelope. One release
 * binds a publisher-namespaced package name, a semantic version, the
 * content.v2 package root (lib/vcs/package_manifest.* — one root commits
 * to the manifest and, through it, every chunk), a declarative C23 build
 * recipe root, publisher lineage (optional
 * parent release root + monotonic per-publisher sequence), a ZClassic chain
 * id, an SPDX license, an optional contributor reward address, an optional
 * ZNAM pointer name, and the publisher's secp256k1 key — all under one
 * signature. This layer parses, serializes, hashes, and verifies only; it
 * has no filesystem, network, wallet, payment, install, build, execution,
 * or node-state authority. Signing happens outside this layer (the wallet
 * broker); private keys never enter lib/vcs.
 *
 * Canonical wire encoding (all integers little-endian, exactly one legal
 * encoding per release):
 *   [8  magic = "ZCLREL\r\n"]
 *   [2  schema_version = 1]
 *   [2  name_len][name bytes]              "publisher/package"
 *   [2  semver_len][semver bytes]          strict semver 2.0.0
 *   [32 package_root]                      content.v2 package root
 *   [1  parent_present (0|1)]
 *   [32 parent_root]                       only when parent_present = 1
 *   [33 publisher_pubkey]                  compressed secp256k1
 *   [8  publisher_sequence]                monotonic per publisher, >= 1
 *   [2  reward_len][reward bytes]          contributor reward address,
 *                                          empty (len 0) = none
 *   [2  license_len][license bytes]        v1 SPDX allowlist, exact match
 *   [32 recipe_root]                       declarative C23 build recipe root
 *   [1  znam_present (0|1)]
 *   [2  znam_len][znam bytes]              only when znam_present = 1;
 *                                          a pointer, never identity
 *   [2  chain_id_len][chain_id bytes]      ZClassic chain identifier
 *   [64 signature]                         secp256k1 ECDSA compact r||s,
 *                                          low-S, over the release id
 *
 * The RELEASE ID is SHA3-256 over (domain || the canonical encoding above
 * minus the trailing 64-byte signature). The domain is the ASCII string
 * "zcl.zcode_release.v1" hashed WITH its single trailing 0x00 byte (sizeof
 * the string literal), exactly the package_manifest convention. JSON is
 * display-only and is never signed or hashed.
 *
 * Field grammars (frozen for v1):
 *   name     — exactly one '/'; publisher and package are each 1..63 chars
 *              of [a-z0-9-], starting and ending with [a-z0-9]. No
 *              uppercase, no leading/trailing hyphen, total <= 127.
 *   semver   — semver 2.0.0: MAJOR.MINOR.PATCH decimal without leading
 *              zeros, optional "-prerelease" and "+build" dot-separated
 *              identifiers of [0-9A-Za-z-] (numeric prerelease identifiers
 *              without leading zeros). No "v" prefix. Total <= 64.
 *   roots    — package_root and recipe_root are SHA3-256 commitments and
 *              must not be all-zero; parent_root, when present, must not
 *              be all-zero either (an all-zero root is the "no object"
 *              sentinel, never a real commitment).
 *   sequence — publisher_sequence is >= 1 and monotonic per publisher
 *              (the acceptance layer, lib/vcs/package_accept.*, enforces
 *              the monotonicity and equivocation rules; the codec enforces
 *              only >= 1).
 *   license  — exactly one of: 0BSD, MIT, Apache-2.0, BSD-2-Clause,
 *              BSD-3-Clause, ISC, Zlib. No compound ("MIT OR Apache-2.0"),
 *              no unknown, no empty.
 *   reward   — 0..128 printable ASCII bytes (0x21..0x7e).
 *   znam     — same grammar as one name half (1..63 of [a-z0-9-],
 *              hyphen never leading/trailing).
 *   chain_id — 1..32 chars of [a-z0-9-].
 *   pubkey   — a 33-byte compressed secp256k1 point that parses on the
 *              curve.
 *   signature— 64-byte compact r||s with s <= n/2 (low-S); malleated
 *              high-S encodings are rejected before verification. */

#ifndef ZCL_VCS_PACKAGE_RELEASE_H
#define ZCL_VCS_PACKAGE_RELEASE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_PACKAGE_RELEASE_VERSION 1u
#define VCS_PACKAGE_RELEASE_ID_DOMAIN "zcl.zcode_release.v1"
#define VCS_PACKAGE_RELEASE_WIRE_MAGIC_BYTES 8u
#define VCS_PACKAGE_RELEASE_NAME_HALF_MAX 63u
#define VCS_PACKAGE_RELEASE_NAME_MAX \
    (2u * VCS_PACKAGE_RELEASE_NAME_HALF_MAX + 1u)
#define VCS_PACKAGE_RELEASE_SEMVER_MAX 64u
#define VCS_PACKAGE_RELEASE_REWARD_MAX 128u
#define VCS_PACKAGE_RELEASE_LICENSE_MAX 32u
#define VCS_PACKAGE_RELEASE_ZNAM_MAX VCS_PACKAGE_RELEASE_NAME_HALF_MAX
#define VCS_PACKAGE_RELEASE_CHAIN_ID_MAX 32u
#define VCS_PACKAGE_RELEASE_PUBKEY_BYTES 33u
#define VCS_PACKAGE_RELEASE_SIGNATURE_BYTES 64u
#define VCS_PACKAGE_RELEASE_ID_BYTES 32u

/* Largest possible canonical envelope: every optional field present and
 * every string at its bound. */
#define VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES \
    (VCS_PACKAGE_RELEASE_WIRE_MAGIC_BYTES + 2u + \
     2u + VCS_PACKAGE_RELEASE_NAME_MAX + \
     2u + VCS_PACKAGE_RELEASE_SEMVER_MAX + \
     32u + 1u + 32u + \
     VCS_PACKAGE_RELEASE_PUBKEY_BYTES + 8u + \
     2u + VCS_PACKAGE_RELEASE_REWARD_MAX + \
     2u + VCS_PACKAGE_RELEASE_LICENSE_MAX + \
     32u + \
     1u + 2u + VCS_PACKAGE_RELEASE_ZNAM_MAX + \
     2u + VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + \
     VCS_PACKAGE_RELEASE_SIGNATURE_BYTES)

/* Every rejection names the failed rule. The enum order is frozen: tests
 * and callers may compare against these values. */
enum vcs_package_release_error {
    VCS_PACKAGE_RELEASE_OK = 0,
    VCS_PACKAGE_RELEASE_ERR_NULL,          /* null argument */
    VCS_PACKAGE_RELEASE_ERR_ALLOC,         /* serialization alloc failed */
    VCS_PACKAGE_RELEASE_ERR_SCHEMA_VERSION,/* schema_version != 1 */
    VCS_PACKAGE_RELEASE_ERR_NAME,          /* publisher/package grammar */
    VCS_PACKAGE_RELEASE_ERR_SEMVER,        /* semver 2.0.0 grammar */
    VCS_PACKAGE_RELEASE_ERR_PARENT_FLAG,   /* parent flag byte not 0/1 */
    VCS_PACKAGE_RELEASE_ERR_PUBKEY,        /* not a compressed curve point */
    VCS_PACKAGE_RELEASE_ERR_REWARD,        /* reward address charset/bound */
    VCS_PACKAGE_RELEASE_ERR_LICENSE,       /* not on the v1 SPDX allowlist */
    VCS_PACKAGE_RELEASE_ERR_ZNAM_FLAG,     /* znam flag byte not 0/1 */
    VCS_PACKAGE_RELEASE_ERR_ZNAM,          /* znam grammar */
    VCS_PACKAGE_RELEASE_ERR_CHAIN_ID,      /* chain id charset/bound */
    VCS_PACKAGE_RELEASE_ERR_SIG_LOW_S,     /* high-S (malleated) signature */
    VCS_PACKAGE_RELEASE_ERR_SIG_VERIFY,    /* ECDSA verification failed */
    VCS_PACKAGE_RELEASE_ERR_WIRE_MAGIC,    /* bad magic */
    VCS_PACKAGE_RELEASE_ERR_WIRE_OVERSIZE, /* exceeds MAX_WIRE_BYTES */
    VCS_PACKAGE_RELEASE_ERR_WIRE_TRUNCATED,/* a field runs past the end */
    VCS_PACKAGE_RELEASE_ERR_WIRE_TRAILING, /* bytes after the signature */
    VCS_PACKAGE_RELEASE_ERR_PACKAGE_ROOT,  /* all-zero package root */
    VCS_PACKAGE_RELEASE_ERR_RECIPE_ROOT,   /* all-zero recipe root */
    VCS_PACKAGE_RELEASE_ERR_SEQUENCE,      /* publisher sequence 0 */
    VCS_PACKAGE_RELEASE_ERR_PARENT_ROOT,   /* parent flagged but all-zero */
};

/* Value type: fixed-size buffers, no heap, no init/free needed. Zeroing the
 * whole struct is a defined (invalid) state — validate() rejects it. */
struct vcs_package_release {
    uint16_t schema_version;   /* must be VCS_PACKAGE_RELEASE_VERSION */
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];          /* NUL-terminated */
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];      /* NUL-terminated */
    uint8_t package_root[32];
    bool has_parent;
    uint8_t parent_root[32];   /* meaningful only when has_parent */
    uint8_t publisher_pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES];
    uint64_t publisher_sequence;
    char reward_address[VCS_PACKAGE_RELEASE_REWARD_MAX + 1u]; /* "" = none */
    char license[VCS_PACKAGE_RELEASE_LICENSE_MAX + 1u];    /* NUL-terminated */
    uint8_t recipe_root[32];
    bool has_znam;
    char znam[VCS_PACKAGE_RELEASE_ZNAM_MAX + 1u];          /* when has_znam */
    char chain_id[VCS_PACKAGE_RELEASE_CHAIN_ID_MAX + 1u];  /* NUL-terminated */
    uint8_t signature[VCS_PACKAGE_RELEASE_SIGNATURE_BYTES];
};

/* Stable string for an error code (for logs/tests); never NULL. */
const char *vcs_package_release_error_string(
    enum vcs_package_release_error error);

/* True when `license` (NUL-terminated) is an exact, case-sensitive member of
 * the frozen v1 SPDX allowlist above. Exported so sibling layers (the C23
 * corpus census) apply the identical license policy through this one
 * authority instead of duplicating the list. Pure query; never logs. */
bool vcs_package_release_license_allowed(const char *license);

/* The largest LICENSE text this rule will read. The longest allowlisted
 * license (Apache-2.0) is ~11 KiB; anything past this is not a license file
 * and is refused rather than scanned. */
#define VCS_PACKAGE_RELEASE_LICENSE_TEXT_MAX_BYTES (256u * 1024u)

/* True when `text` plausibly IS the license `license` names: the canonical
 * phrases of that identifier appear in it (case-insensitively). Refuses an
 * empty file, a placeholder, and text belonging to a different license, so
 * "declares MIT, ships something else" cannot pass. It does not and cannot
 * prove the text is an unmodified official copy. A license not on the v1
 * allowlist never matches. Pure query; never logs. */
bool vcs_package_release_license_text_matches(const char *license,
                                              const uint8_t *text, size_t len);

/* True when `text` matches at least one member of the frozen permissive
 * allowlist. Source carriers have root-committed LICENSE bytes but no
 * separate release-envelope SPDX field, so their creation, public-hosting,
 * and checkout gates use this shared authority rather than duplicating or
 * weakening the release policy. Pure query; never logs. */
bool vcs_package_release_license_text_allowed(const uint8_t *text,
                                              size_t len);

/* Validate every field against the v1 grammars above. Does NOT look at the
 * signature. Returns VCS_PACKAGE_RELEASE_OK or the first failed rule. */
enum vcs_package_release_error vcs_package_release_validate(
    const struct vcs_package_release *release);

/* Compute the release id: SHA3-256 over the frozen domain (with its NUL)
 * and the canonical encoding of every field except the signature. Fields
 * are validated first; an invalid release has no id. */
enum vcs_package_release_error vcs_package_release_id(
    const struct vcs_package_release *release,
    uint8_t out[VCS_PACKAGE_RELEASE_ID_BYTES]);

/* Canonically serialize a validated release (signature included). Allocates
 * *out; caller frees. On failure *out is NULL and *out_len is zero. */
enum vcs_package_release_error vcs_package_release_serialize(
    const struct vcs_package_release *release, uint8_t **out,
    size_t *out_len);

/* Parse only the exact canonical wire form. *out is zeroed on entry and on
 * every rejection. Bad flags, bad field grammars, an off-curve pubkey,
 * truncation, oversize input, and any trailing byte are rejected with the
 * matching error. The signature is NOT verified here — call
 * vcs_package_release_verify() after parsing. */
enum vcs_package_release_error vcs_package_release_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_package_release *out);

/* Full envelope check: validate fields, recompute the release id, require
 * the low-S canonical form, and verify the secp256k1 ECDSA signature over
 * the id against the embedded publisher pubkey. Every rejection returns the
 * distinct error naming the failed rule. This proves authorship of the
 * exact bytes only; it grants no trust, install, or execution authority. */
enum vcs_package_release_error vcs_package_release_verify(
    const struct vcs_package_release *release);

/* Codec-level duplicate detection: two envelopes are the same release when
 * publisher pubkey, publisher sequence, and package root all match.
 * Storage/swarm layers decide what to do with duplicates; this only names
 * them. */
bool vcs_package_release_is_duplicate(
    const struct vcs_package_release *a,
    const struct vcs_package_release *b);

/* Parent-lineage helper: returns true and copies the parent release root
 * when present; returns false (and zeroes out_root) for a root release. */
bool vcs_package_release_parent(const struct vcs_package_release *release,
                                uint8_t out_root[32]);

#endif /* ZCL_VCS_PACKAGE_RELEASE_H */
