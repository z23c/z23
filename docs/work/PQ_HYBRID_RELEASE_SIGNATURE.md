# ZRS1 hybrid release signature — design proposal

Status: PROPOSED. Nothing here is implemented; the owner has not chosen any
marked decision. This document specifies a hybrid container ("ZRS1") in which
a release doc carries an Ed25519 signature and an SLH-DSA-SHAKE-128s signature
over the same bytes, and verification requires both. It covers the doc wire
(`contexts/wallet/modules/zid/include/zid/zid.h`), the verify path
(`contexts/wallet/modules/zid/src/zid.c`) and the `zcode.release.sign` /
`zcode.release.verify` handlers (`tools/command/native_zcode_release_command.c`).
The SLH-DSA primitive is the module at platform/modules/slhdsa (header
platform/modules/slhdsa/include/slhdsa/slhdsa.h), landed in the same series as
this proposal; the ZRS1 container and its wiring remain unimplemented.

## 1. Overview & goals

Today a release doc is signed by one Ed25519 key. A future quantum adversary
who can break Ed25519 could forge a release doc for a pinned identity.
SLH-DSA (FIPS 205) is hash-based, so its security does not rest on the
discrete log. A hybrid AND scheme gives: forgery needs breaking BOTH
primitives; a flaw found in either one alone does not let an attacker publish.

Goals:
- Both signatures must verify. Valid Ed25519 alone, or SLH-DSA alone, rejects.
- The signed content (the zid signed prefix) does not change meaning.
- Old version-1 docs keep verifying unchanged; old verifiers refuse new docs
  loudly rather than accept half of them.
- Every length is derived from a checked parameter byte, never trusted.

## 2. Non-goals

- ML-DSA or any third scheme; a plugin scheme registry.
- The k-of-n owner gate code and the owner pin-set doc (shape only, section 6).
- Any change to consensus, wallet keys or transaction signing.
- HashSLH-DSA pre-hash (the slhdsa header exposes the pure FIPS 205 API with a
  context string only).
- Auto-signing in a release pipeline.

## 3. Wire layout

### 3.1 Facts about the current format (verified on main)

- `ZID_DOC_VERSION` is 1, `ZID_BODY_MAX` is 1024, and
  `ZID_DOC_MAX = 1 + 32 + 8 + 8 + 2 + ZID_BODY_MAX + 64` (zid.h lines 26-28).
- Version-1 wire: version:1 | master_pubkey:32 | seq:8 LE | expiry:8 LE |
  body_len:2 LE | body | signature:64. The signed prefix is everything before
  the signature, 51 + body_len bytes (zid.h around line 47; `zid_encode_prefix`
  at zid.c:104).
- `struct zid_doc.signature` is a fixed `uint8_t[64]` (zid.h line 38 region).
- `zid_doc_decode` rejects any length above `ZID_DOC_MAX` and any version byte
  other than `ZID_DOC_VERSION` (zid.c:147-152).

### 3.2 Why a new doc version is forced

A ZRS1 container is 7957 bytes (below), but the v1 signature field is 64
bytes and the v1 body is capped at 1024 bytes, and the signature is not part
of the body. Neither field can hold it. Putting the SLH-DSA signature in the
body would also put it inside the signed prefix (circular) and would exceed
`ZID_BODY_MAX`. So the doc itself must change shape.

PROPOSED choice (a): doc version 2 carries the container as a trailer.
The rejected option (b), a sidecar file referenced by digest, splits one
release across two artifacts that can be separated or substituted in transit;
the doc would no longer be self-verifying.

Version-2 wire (PROPOSED):

    version:1 (=2) | master_pubkey:32 | seq:8 LE | expiry:8 LE |
    body_len:2 LE | body | trailer_len:2 LE | trailer (a ZRS1 container)

The signed prefix is still everything up to and including `body`
(51 + body_len bytes), but its first byte is now 2, so the bytes signed by a
v2 doc can never equal the bytes signed by a v1 doc. A v2 doc has no separate
64-byte signature field; its Ed25519 signature lives in the container.

### 3.3 ZRS1 container (SLH-DSA-SHAKE-128s, param byte 0)

| Offset | Length | Field |
|-------:|-------:|-------|
| 0 | 4 | magic "ZRS1" |
| 4 | 1 | param byte (0 = SHAKE-128s; 1 = SHAKE-192s reserved, rejected until enabled) |
| 5 | 64 | Ed25519 signature over the signed prefix |
| 69 | 32 | SLH-DSA public key (pk_len for the param) |
| 101 | 7856 | SLH-DSA signature over the signed prefix |
| 7957 | - | end |

Arithmetic: 4 + 1 + 64 + 32 + 7856 = 7957 bytes. Offsets: 5 + 64 = 69;
69 + 32 = 101; 101 + 7856 = 7957.

The 192s variant (option, not recommended): pk 48, sig 16224, so
4 + 1 + 64 + 48 + 16224 = 16341 bytes (pk at 69..116, sig at 117..16340).

Largest v2 doc with 128s: 51 + 1024 + 2 + 7957 = 9034 bytes (192s: 17418).
`trailer_len` is u16, which holds both (limit 65535). This is more than
seven times the v1 maximum of 1139 bytes.

Length rules, all fail-closed:
- Read the param byte first; unknown param is a refusal.
- Derive pk_len and sig_len from the param (the slhdsa header provides
  `zcl_slhdsa_public_key_size` and `zcl_slhdsa_signature_size`), compute the
  expected total, and require `trailer_len` to equal it exactly before reading
  any other field. The container's own fields carry no length to trust.
- Require the doc length to equal the fixed fields plus `body_len` plus
  `2 + trailer_len` exactly; no trailing bytes.
- `ZID_DOC_MAX` must be re-derived for v2 (at least 9034 for 128s). The v1
  limit must stay enforced for v1 docs. The final constant is open (section 8).

## 4. Domain separation

Both signatures cover the same canonical bytes: the signed prefix of the
release doc (version byte 2, pubkey, seq, expiry, body_len, body whose first
four bytes are the "ZIDR" release tag).

| Signature | Separation |
|-----------|-----------|
| Ed25519 | No context parameter exists. Separation comes from the prefix itself: version byte 2 (never a v1 doc) and the "ZIDR" body tag. |
| SLH-DSA | Pure FIPS 205 context string, at most 255 bytes: "z23.zrs1.release.v1" (PROPOSED literal). |

Rules:
- The SLH-DSA context must not reuse the body tags "ZIDR", "ZIDD", "ZIDE",
  "ZIDB" or "ZIDL" (used in zid.c, zdesc.h, zendp.h, which are body or hash
  tags, not signature contexts).
- A future ZRS2 or a different record kind uses a different context literal;
  the literal carries the scheme version.
- The container magic is a parsing tag, not a signed domain; it does not
  replace the context string.
- An SLH-DSA signature made under another context (or none) over the same
  prefix must not verify. This is tested (section 9).

Known gap (open question 3): the SLH-DSA public key is carried in the
container and is not covered by the signed prefix. Without a pin, a verifier
learns only that the signer holds some SLH-DSA key.

## 5. Verify path

Hook: `zid_release_verify` (zid.c:701-712) currently calls `zid_doc_verify`
(expiry check, then Ed25519 over the prefix, zid.c:169-190) and then decodes
the body. For v2 docs the hybrid check runs inside `zid_release_verify`,
after the Ed25519 check and before body decode, keeping the change
release-specific; other doc kinds are untouched.

Order for a v2 doc (all steps must pass):
1. Decode: version 2, exact lengths (section 3.3), body_len <= `ZID_BODY_MAX`.
2. Expiry: `now >= expiry` is DOC_EXPIRED (same as today).
3. Ed25519 verify of container bytes 5..68 over the prefix with
   master_pubkey.
4. Param byte known, then SLH-DSA verify (`zcl_slhdsa_verify`, which returns
   OK only for a valid signature) of the prefix, context
   "z23.zrs1.release.v1", with the container's pk.
5. Pin check: the container pk must equal the pinned SLH-DSA key for this
   master_pubkey (section 6).
6. Body decode ("ZIDR" release record).

Handlers: `zcode.release.sign` (handler at lines 624-720, calling
`zid_release_sign` at 719, then `memory_cleanse` of the seed) gains a
second key input and writes v2. `zcode.release.verify` (handler from line 807,
`zid_doc_decode` at 908, `zid_release_verify` at 921) gains named failures.
Existing codes are NOT_A_RELEASE_BODY, DOC_EXPIRED and BAD_SIGNATURE (message
at about line 963). PROPOSED new codes, each distinct and never folded into
`valid:false`: BAD_PQ_SIGNATURE (SLH-DSA fails), PQ_KEY_MISMATCH (container pk
differs from the pin), PQ_CONTAINER_MALFORMED (length, magic or param error).
BAD_SIGNATURE keeps meaning the Ed25519 half. Output adds the SLH-DSA pk and
the param to the existing fields (name, version, manifest_root,
master_pubkey, seq, expiry, verified_at, valid).

Version-1 verifier behavior: a deployed verifier calls `zid_doc_decode`,
which logs "unsupported version 2" and returns false for buf[0] != 1
(zid.c:150-152). The handler already fails closed on a decode failure
(handler line 908 region), so an old verifier refuses a v2 doc loudly; it
can never accept the Ed25519 half alone. This is a deliberate wire break.
`zid_doc_supersedes` compares seq only and does not verify signatures
(zid.c:224), so replacement ordering needs no change; a v2 doc must still be
verified before it is allowed to supersede anything.

## 6. Pins and the k-of-n gate plan

### 6.1 Pin model (PROPOSED)

A pin identifies a signer as a PAIR of keys: the Ed25519 master_pubkey and
the SLH-DSA pk (with its param). A release is accepted for a pin only if the
doc's master_pubkey and the container pk both equal the pinned pair and both
signatures verify. Pinning only the Ed25519 key would let an attacker who
breaks Ed25519 attach their own SLH-DSA key, defeating the AND property.

Pin file extension: the pin file gains a new versioned entry type for pairs
(a new version tag, not a reinterpretation of an existing one) carrying
ed25519 pk hex, param, SLH-DSA pk hex. Old pin lines keep their meaning;
a pin that is Ed25519-only can accept v1 docs only (and a v2 doc is refused
for it, since the pair cannot be matched). The release pin gate
(`release_pin_gate`, signature taking one 32-byte signer and a manifest root,
with a pin-set maximum of 256 per the packet) is not on main at this base;
its existing semantics are out of scope here and are not re-verified.

### 6.2 k-of-n owner gate (later packet)

Shape only:
- n owner hybrid keys (pairs), threshold k.
- Each signer produces a complete, independent ZRS1 doc over the same
  release body; the gate receives a set of docs, not a merged signature.
- Verification counts DISTINCT pinned pairs that fully verify. Two docs from
  the same pair count once; a pair not in the pinned set counts zero.
- The result reports the matched count and the threshold; the single
  `signer[32]` argument of the current gate cannot express this, so the
  gate API changes in that packet.
- All docs in a set must agree on name, version and manifest_root; any
  disagreement refuses.

## 7. Migration from Ed25519-only

All phases PROPOSED; the owner decides when each starts, in particular phase 3.
1. Verifier accepts both v1 (Ed25519 only, unchanged behavior) and v2 ZRS1.
   Ship the verifier everywhere first, because old verifiers refuse v2.
2. Signer emits v2 by default (and still can emit v1 on request). Owner
   generates the SLH-DSA key and publishes the pair pin.
3. Pins require ZRS1 for new releases. A pin may still mark an old release
   range as v1-acceptable.
Existing v1 docs keep verifying; no re-sign is forced. Rollback before phase 3
is switching the signer back to v1.

## 8. Open questions

1. Version number: version byte 2 with a trailer (recommended here) versus
   keeping version 1 and a tag inside the body. Tag-in-body is not
   viable if the container must stay outside the signed prefix.
2. Final `ZID_DOC_MAX` and trailer cap for v2 (at least 9034 for 128s).
3. Binding the SLH-DSA pk: include its digest in the signed prefix (for
   example in the body) so unpinned verification still authenticates the pair,
   or accept that unpinned verification proves only the Ed25519 half. Should
   an unpinned v2 verify report valid at all?
4. Parameter set: 128s (7856-byte signature, recommended) versus 192s (16224).
5. Deterministic versus hedged SLH-DSA signing for the release signer
   (the slhdsa header offers both).
6. Seed handling: derive the SLH-DSA key material from the existing 32-byte
   master seed, or a separate seed file (the signer reads a 0600 seed file).
7. Expiry and seq semantics for the two halves (single doc, so one value).

## 9. Test vector plan

- SLH-DSA primitive: NIST ACVP keyGen, sigGen and sigVer vectors for
  SHAKE-128s (and 192s if enabled), including non-empty contexts. These live
  with the primitive in platform/modules/slhdsa/tests.
- ZRS1 positive: a fixed seed pair signs a fixed release body; a known-answer
  v2 doc hex; encode/decode round-trip; exact 7957-byte trailer.
- Negative, each must refuse with the named code:
  - valid Ed25519, corrupted SLH-DSA signature (BAD_PQ_SIGNATURE);
  - corrupted Ed25519, valid SLH-DSA signature (BAD_SIGNATURE);
  - SLH-DSA signed under a different context, or with no context;
  - Ed25519 or SLH-DSA signature over a different doc version byte;
  - swapped fields (Ed25519 signature bytes in the SLH-DSA slot and back);
  - container pk not equal to the pin (PQ_KEY_MISMATCH);
  - truncated trailer, trailer one byte long, trailer_len mismatch, trailing
    bytes after the container, unknown param byte, bad magic
    (PQ_CONTAINER_MALFORMED);
  - v2 doc given to the v1 decode path (refused, version mismatch);
  - expired v2 doc (DOC_EXPIRED).
- Regression: every existing v1 vector still verifies unchanged.
