# ZRS1 hybrid release signature

Status: ACCEPTED (phases 1 and 2 and the phase 3 switch implemented for `ops slot install`; k-of-n pending)

This document specifies a hybrid container ("ZRS1") in which a release doc
carries an Ed25519 signature and an SLH-DSA-SHAKE-128s signature over the same
bytes, and verification requires both. It covers the doc wire
(`contexts/wallet/modules/zid/include/zid/zid_hybrid.h`), the codec, sign and
verify path (`contexts/wallet/modules/zid/src/zid_hybrid.c`) and the
`zcode.release.sign` / `zcode.release.verify` handlers
(`tools/command/native_zcode_release_command.c`). The SLH-DSA primitive is the
module at platform/modules/slhdsa (header
platform/modules/slhdsa/include/slhdsa/slhdsa.h).

Implemented: migration phase 1 (the verifier accepts v1 and v2), the signer
half of phase 2 (`zcode.release.sign` emits v2 when given a PQ seed file; v1
otherwise), the pair-pin file format and gate in `release_pin` (section 6.1),
`ops slot install` accepting a v2 doc only under a pair pin, the `require_pq`
phase 3 switch, v2 docs in the `<datadir>/zcode/releases/` batch (saved as
`<name>-<version>.v2.zid`) and the `zcode.release.keygen_pq` leaf. Not
implemented: any default switch to v2. Implemented since: the k-of-n owner
gate (6.2), `threshold K` in a pin file plus `cosigs`, in `ops slot install`
is the PQ-secure native install path.
`zcode.release.verify` takes the same pin gate as `ops slot install`: a v2 doc
needs a pair pin (an Ed25519-only pin gives RELEASE_PQ_UNPINNED). The fleet
signer is `ops release sign` (section 10).

<!-- claim: symbol-present zid_hybrid_release_sign contexts/wallet/modules/zid -->
<!-- claim: file-present contexts/wallet/modules/zid/include/zid/zid_hybrid.h -->

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

### 3.1 Facts about the version-1 format (unchanged)

- `ZID_DOC_VERSION` is 1, `ZID_BODY_MAX` is 1024, and
  `ZID_DOC_MAX = 1 + 32 + 8 + 8 + 2 + ZID_BODY_MAX + 64` = 1139. These
  constants are unchanged and still bound v1 docs.
- Version-1 wire: version:1 | master_pubkey:32 | seq:8 LE | expiry:8 LE |
  body_len:2 LE | body | signature:64. The signed prefix is everything before
  the signature, 51 + body_len bytes.
- `struct zid_doc.signature` is a fixed `uint8_t[64]`; `struct zid_doc` is
  unchanged, so no existing caller changes shape. v2 uses a separate
  `struct zid_doc_v2`.
- `zid_doc_decode` rejects any version byte other than 1 (checked before the
  length bound, so a v2 doc is refused as a version mismatch) and any length
  above `ZID_DOC_MAX`.

### 3.2 Doc version 2 carries the container as a trailer

RESOLVED (section 8, item 1): doc version byte 2, option (a). A ZRS1
container is 7957 bytes, which neither the 64-byte v1 signature field nor the
1024-byte body can hold, and putting it in the body would place it inside the
signed prefix (circular). The rejected option (b), a sidecar file referenced by
digest, splits one release across two artifacts that can be separated or
substituted in transit; the doc would no longer be self-verifying.

Version-2 wire:

    version:1 (=2) | master_pubkey:32 | seq:8 LE | expiry:8 LE |
    body_len:2 LE | body | pq_param:1 | pq_pk_sha3_256:32 |
    trailer_len:2 LE | trailer (a ZRS1 container)

The signed prefix is everything up to and including `pq_pk_sha3_256`
(51 + body_len + 33 bytes). Its first byte is 2, so the bytes signed by a v2
doc can never equal the bytes signed by a v1 doc. `pq_param` is the checked
parameter byte (0 only) and `pq_pk_sha3_256` is SHA3-256 of the container's
SLH-DSA public key, so the Ed25519 signature authenticates the SLH-DSA key
even without a pin. There is one `seq` and one `expiry` for the whole doc. A
v2 doc has no separate 64-byte signature field; its Ed25519 signature lives in
the container.

### 3.3 ZRS1 container (SLH-DSA-SHAKE-128s, param byte 0)

| Offset | Length | Field |
|-------:|-------:|-------|
| 0 | 4 | magic "ZRS1" |
| 4 | 1 | param byte (0 = SHAKE-128s; 1 = SHAKE-192s is refused) |
| 5 | 64 | Ed25519 signature over the signed prefix |
| 69 | 32 | SLH-DSA public key (pk_len for the param) |
| 101 | 7856 | SLH-DSA signature over the signed prefix |
| 7957 | - | end |

Arithmetic: 4 + 1 + 64 + 32 + 7856 = 7957 bytes. Offsets: 5 + 64 = 69;
69 + 32 = 101; 101 + 7856 = 7957.

Only SHAKE-128s is accepted (RESOLVED, item 4). Param byte 1 (192s: pk 48,
sig 16224, container 16341) is refused as `PQ_CONTAINER_MALFORMED`.

Largest v2 doc: 51 + 1024 + 33 + 2 + 7957 = 9067 bytes, seven times the v1
maximum of 1139. `ZID_DOC_V2_MAX` is exactly this value, computed from the
container size and tied to the slhdsa module's key and signature sizes by
`static_assert`s in `zid_hybrid.c`; `ZID_DOC_MAX` is not changed (RESOLVED,
item 2). `trailer_len` is u16, which holds the container (limit 65535).

Length rules, all fail-closed:
- Read the param byte first; an unknown or disabled param is a refusal.
- Derive pk_len and sig_len from the param (`zcl_slhdsa_public_key_size`,
  `zcl_slhdsa_signature_size`), compute the expected container size, and
  require `trailer_len` to equal it exactly and the bytes present to equal it
  exactly before reading any other field. The container's own fields carry no
  length to trust.
- The signed `pq_param` must equal the container's param byte.
- The doc length must equal the fixed fields plus `body_len` plus
  `2 + trailer_len` exactly; no trailing bytes.

## 4. Domain separation

Both signatures cover the same canonical bytes: the v2 signed prefix
(version byte 2 | master_pubkey | seq | expiry | body_len | body | pq_param |
pq_pk_sha3_256, where the body's first four bytes are the "ZIDR" release tag).

| Signature | Separation |
|-----------|-----------|
| Ed25519 | No context parameter exists. Ed25519 signs the prefix directly. Separation comes from the prefix itself: version byte 2 (never a v1 doc) and the "ZIDR" body tag. |
| SLH-DSA | Pure FIPS 205 context string (at most 255 bytes) `z23.zrs1.release.v1`. The signed message is the same prefix. |

Rules:
- The SLH-DSA context must not reuse the body tags "ZIDR", "ZIDD", "ZIDE",
  "ZIDB" or "ZIDL" (used in zid.c, zdesc.h, zendp.h, which are body or hash
  tags, not signature contexts).
- A future ZRS2 or a different record kind uses a different context literal;
  the literal carries the scheme version.
- The container magic is a parsing tag, not a signed domain; it does not
  replace the context string.
- An SLH-DSA signature made under another context (or none) over the same
  prefix does not verify. This is tested (section 9).

Key binding (RESOLVED, item 3): the SLH-DSA public key is bound inside the
Ed25519-signed bytes through `pq_pk_sha3_256`, and SLH-DSA signs the same
prefix, so both signatures cover the digest. The verifier recomputes SHA3-256
of the container pk and requires it to equal the prefix digest
(`PQ_KEY_MISMATCH` otherwise). Unpinned verification therefore authenticates
the pair as one signer: a forger must produce a valid Ed25519 signature over
a prefix naming the forger's own SLH-DSA key, which needs the Ed25519 key. An
unpinned v2 verify still proves only that SOME pair signed; WHICH pair is
trusted is the pin's job (section 6).

## 5. Verify path

`zid_hybrid_release_verify` (zid_hybrid.c) is the v2 verify; the v1
`zid_release_verify` is untouched and other doc kinds are untouched.

Order for a v2 doc (all steps must pass):
1. Decode: version 2, exact lengths (section 3.3), body_len <= `ZID_BODY_MAX`.
2. Expiry: `now >= expiry` is DOC_EXPIRED (same as today).
3. Ed25519 verify of container bytes 5..68 over the prefix with
   master_pubkey (`BAD_SIGNATURE`).
4. SHA3-256 of the container pk equals the prefix digest (`PQ_KEY_MISMATCH`).
5. SLH-DSA verify (`zcl_slhdsa_verify`, which returns OK only for a valid
   signature) of the prefix, context `z23.zrs1.release.v1`, with the
   container's pk (`BAD_PQ_SIGNATURE`).
6. Pin check, when a pinned SLH-DSA key is supplied: the container pk must
   equal it (`PQ_KEY_MISMATCH`). The API takes the pinned key; the pin file
   format that supplies it is the next packet.
7. Body decode ("ZIDR" release record; `NOT_A_RELEASE_BODY` otherwise).

Handlers: `zcode.release.sign` gains an optional `pq_seed_file`. With it the
leaf emits v2; without it the output is v1 exactly as before. The seed file
holds 96 hex chars (48 bytes, SK.seed | SK.prf | PK.seed), is opened with the
same reader as the Ed25519 seed (refused unless mode 0600 or 0400, never
printed), signing is deterministic (RESOLVED, item 5), and every secret buffer
is wiped on every path, each right after its last use. A v2 doc is saved as
`<datadir>/zcode/releases/<name>-<version>.v2.zid`, next to (never over) a v1
doc of the same release; the batch loader reads both versions and digests the
wire bytes, so `release.anchor` and `release.prove` fold a v2 doc like a v1
one. The reply adds
`doc_version`, `pq` and, for v2, `pq_pubkey` and `pq_param`.

`zcode.release.verify` accepts v1 and v2 and reports `doc_version` and
`pq: true/false` (plus `pq_pubkey` for v2). Existing codes are
NOT_A_RELEASE_BODY, DOC_EXPIRED, BAD_SIGNATURE and DOC_DECODE_FAILED. New
codes, each distinct and never folded into `valid:false` or into one another:
BAD_PQ_SIGNATURE (SLH-DSA fails), PQ_KEY_MISMATCH (container pk differs from
the signed digest or the pin), PQ_CONTAINER_MALFORMED (length, magic or param
error). BAD_SIGNATURE keeps meaning the Ed25519 half.

Version-1 verifier behavior: a deployed verifier calls `zid_doc_decode`,
which logs "unsupported version 2" and returns false for buf[0] != 1. The
handler already fails closed on a decode failure, so an old verifier refuses a
v2 doc loudly; it can never accept the Ed25519 half alone. This is a
deliberate wire break. `zid_doc_supersedes` compares seq only and does not
verify signatures, so replacement ordering needs no change; a v2 doc must still
be verified before it is allowed to supersede anything.

## 6. Pins and the k-of-n gate plan

### 6.1 Pin model (IMPLEMENTED in tools/command/release_pin.c)

A pin identifies a signer as a PAIR of keys: the Ed25519 master_pubkey and
the SLH-DSA pk (with its param). A release is accepted for a pin only if the
doc's master_pubkey and the container pk both equal the pinned pair and both
signatures verify. Pinning only the Ed25519 key would let an attacker who
breaks Ed25519 attach their own SLH-DSA key, defeating the AND property.

Pin file: a new versioned line type for pairs,
`zrs1 <ed25519_hex64> <param:0> <slhdsa_pk_hex64>` (SLH-DSA-SHAKE-128s pk is
32 bytes). A bare 64-hex line keeps its meaning (an Ed25519-only pin), `#`
comments and blank lines are still ignored, and keys plus pairs together
hold at most 256 entries. A malformed pair line is `PIN_FILE_INVALID` with
its line number. The inline `pin` input accepts either form.

Acceptance in `ops slot install` (`release_pin_doc_gate`):
- v2 doc: needs a pair pin matching BOTH master_pubkey and container pk, and
  both signatures verify (`zid_hybrid_release_verify` with the pinned pk). A
  differing container key is `PQ_KEY_MISMATCH`. A master key pinned only
  Ed25519-only is `RELEASE_PQ_UNPINNED` (the AND property is kept); a master
  key in no pin at all stays `RELEASE_UNPINNED`.
- v1 doc: accepted by an Ed25519-only pin exactly as before, and by the
  Ed25519 half of a pair pin (phase 2).
- Phase 3: `require_pq` (input bool) or a `require-pq` pin-file line refuses
  every v1 doc with `RELEASE_PQ_REQUIRED`.
- The reply reports `doc_version` and `pq_verified`.

`zcode.release.keygen_pq` mints the SLH-DSA seed file (48 CSPRNG bytes as 96
hex, 0600, exclusive create) and prints only the public key and a ready pin
line. Every earlier refusal code is unchanged.

### 6.2 k-of-n owner gate

IMPLEMENTED. A pin file with a `threshold K` line makes a receiver accept a
release only when at least K DISTINCT pinned pairs each hold a valid hybrid
(v2) doc over the same (name, version, manifest_root). With no `threshold`
line nothing changes: the single-doc path is the same code as before.

Design choice: sibling docs, not a multi-signer container. Each signer
produces an ordinary, complete, independent ZIDR v2 doc over the same
release body, unchanged on the wire (no new version byte, no container
change, signers never need to meet or share a secret, and any one signer's
doc still verifies on its own under the old verifier). The primary doc is the
usual `release=` / `file=` input; the others are named by the comma-separated
input `cosigs=<a.zid>,<b.zid>,...` (at most 7, so 8 docs in all). The gate
receives a set of docs, not a merged signature.

One gate, no forks: `release_pin_multi_gate` in `tools/command/release_pin.c`
is called by both `ops slot install` and `zcode release verify`, and verifies
each doc through the same `zid_hybrid_release_verify` path as the single-doc
gate (shared helper `rp_verify_v2`). It reports `threshold` and
`signers_matched` in the reply, only when a threshold applied.

Rules, each with a typed refusal:
- `threshold K` with K < 1: `THRESHOLD_BELOW_ONE`. A non-numeric K or a second
  `threshold` line: `PIN_FILE_INVALID`.
- K greater than the number of distinct pinned pairs (`zrs1` lines; the same
  pair pinned twice counts once; Ed25519-only pins count zero):
  `THRESHOLD_EXCEEDS_PINS`, refused when the pin file loads.
- One doc when K >= 2: `THRESHOLD_SINGLE_DOC`.
- Two docs from one signer, whether the same pair or a shared Ed25519 or
  SLH-DSA key: `THRESHOLD_DUPLICATE_SIGNER`. A signer counts once, so
  repeating a doc never raises the count.
- Docs that verify but disagree on name, version or manifest_root:
  `THRESHOLD_DISAGREE`.
- Fewer than K pinned pairs verify (a doc by an unpinned pair counts zero):
  `THRESHOLD_NOT_MET`.
- A doc that is pinned but fails verification (`PQ_KEY_MISMATCH`,
  `BAD_SIGNATURE`, `BAD_PQ_SIGNATURE`, `DOC_EXPIRED`...) refuses the whole
  set with its own code; a bad doc is never silently dropped.
- A v1 doc in a threshold set: `RELEASE_PQ_REQUIRED`. A threshold implies
  `require-pq`: only hybrid pairs count.
- `cosigs` without a `threshold` line: `THRESHOLD_MISSING`; extra docs are
  never ignored.
- `package_root`, when given, is checked against the agreed root afterwards
  (`RELEASE_ROOT_MISMATCH`), as for a single doc.

Operator adoption: generate a second owner hybrid key pair and keep it
offline with a different custodian; pin both pairs in the owner-pins file and
add `threshold 2`; distribute that pin file to receivers. A release is then
signed twice (`zcode release sign` once per key, same name, version and
root) and installed with `cosigs=` naming the second doc. Until a receiver
adopts the new pin file it keeps accepting a single signer.



## 7. Migration from Ed25519-only

1. DONE: the verifier accepts both v1 (Ed25519 only, unchanged behavior) and
   v2 ZRS1. Ship the verifier everywhere first, because old verifiers refuse
   v2.
2. DONE for native install: the signer emits v2 when given a PQ seed file and v1
   otherwise, `zcode.release.keygen_pq` generates the SLH-DSA key and prints
   the pair pin line. Not done: emitting v2 by default.
3. SWITCH IMPLEMENTED: `require_pq` / `require-pq` make a pin set require ZRS1. A pin may still mark an
   old release range as v1-acceptable. The owner decides when this starts.
Existing v1 docs keep verifying; no re-sign is forced. Rollback before phase 3
is leaving out the PQ seed file.

The Z23 fleet pins. Two ZRS1 pairs exist: `r1-fleet`, the dedicated r1
release key that signs landed main only, and `owner-offline`, the owner's
second key, to be held on offline media. Their public halves are committed in
`platform/packaging/release/`:

- `z23-release-pins.txt` is the receivers' `pin_file` now: both pairs and
  `require-pq`, no `threshold` line, so either pair installs a release (1 of
  2). A receiver without the k-of-n gate refuses any `threshold` line as
  `PIN_FILE_INVALID`, so the line is left out rather than written as
  `threshold 1`.
- `z23-release-pins.threshold2.txt` adds `threshold 2`. It replaces the first
  file only after every receiver has the k-of-n gate (section 6.2) and the
  owner-offline key signs from offline media; from then on an r1-only
  signature no longer installs.

Group `test_zcode_release` loads the first file through `release_pin_collect`
and checks that both files pin the same two pairs. The seeds never enter the
repository. The conveyor signs each landed release with r1-fleet through
the fleet signer (ops release sign), with a datadir that is not the node's.

## 8. Decisions

The owner delegated the open decisions on 2026-10-19 ("you have authority,
fix everything, do your best"). Resolutions:

1. Version number: doc version byte 2 carrying a ZRS1 trailer (section 3.2,
   option a).
2. `ZID_DOC_MAX` stays 1139 for v1. `ZID_DOC_V2_MAX` is 9067, computed exactly
   from the 128s container and tied to the container layout by `static_assert`.
3. Key binding: the PQ key is bound inside the Ed25519-signed bytes. The v2
   signed prefix is version(=2) | master_pubkey | seq | expiry | body_len |
   body | pq_param:1 | pq_pk_sha3_256:32. Ed25519 signs it directly; SLH-DSA
   signs it with the context string `z23.zrs1.release.v1`. Unpinned
   verification authenticates the pair; whether to trust the pair is the pin's
   job.
4. Parameter set: SHAKE-128s only. Param byte 1 (192s) is refused.
5. Deterministic SLH-DSA signing.
6. The PQ secret comes from a separate seed file (not derived from the Ed25519
   master seed), opened 0600/0400, refused if broader, never printed, wiped on
   every path.
7. One seq and one expiry for the whole doc.

Still open: when migration phase 3 starts. (Pair pins and the k-of-n gate, 6.2,
are implemented.)

## 9. Test vectors

Implemented in `tests/harness/src/test_zid.c` (group `test_zid`, function
`test_zid_hybrid`) and `tests/harness/src/test_zcode_release.c` (group
`test_zcode_release`, function `test_zr_hybrid`):

- SLH-DSA primitive: NIST ACVP keyGen, sigGen and sigVer vectors for
  SHAKE-128s and 192s, with the primitive in platform/modules/slhdsa/tests.
- ZRS1 positive: a fixed seed pair signs a fixed release body; a known-answer
  v2 doc (prefix, Ed25519 signature, SLH-DSA key, SHA3-256 of the whole doc);
  encode/decode round-trip; exact 7957-byte trailer; the handler's doc equals
  the library's doc for the same seeds.
- Negative, each asserting its named code:
  - valid Ed25519, corrupted SLH-DSA signature (BAD_PQ_SIGNATURE);
  - corrupted Ed25519, valid SLH-DSA signature (BAD_SIGNATURE);
  - SLH-DSA signed under a different context, or with no context
    (BAD_PQ_SIGNATURE);
  - Ed25519 signature over a version-1 prefix (BAD_SIGNATURE) and SLH-DSA
    signature over a version-1 prefix (BAD_PQ_SIGNATURE);
  - swapped fields (Ed25519 signature bytes in the SLH-DSA slot and back);
  - container pk not equal to the pin, container pk swapped, and a signed pk
    digest that does not match the container pk with a valid Ed25519
    signature (PQ_KEY_MISMATCH);
  - truncated trailer, trailer one byte long, trailer_len mismatch, trailing
    bytes after the container, unknown param byte, 192s param byte, signed
    param differing from the container param, bad magic
    (PQ_CONTAINER_MALFORMED);
  - v2 doc given to the v1 decode path (refused, version mismatch) and a v1
    doc given to the v2 decoder (NOT_V2_DOC);
  - expired v2 doc (DOC_EXPIRED);
  - a PQ seed file with mode 0644 (and 0640, 0660, 0604, 0700, 0666) refused;
  - a v2 doc refused by `release_pin_read_doc`, and by an Ed25519-only
    `pin`/`pin_file` on `zcode.release.verify` (RELEASE_PQ_UNPINNED).
- Regression: every existing v1 vector still verifies unchanged.

## 10. The fleet signer: `ops release sign`

A dedicated release key signs landed main only. `ops release sign` takes
`release_dir`, `commit` (40 lowercase hex), `seed_file` (Ed25519 master seed)
and `pq_seed_file` (SLH-DSA seed), plus optional `seq` (default: now),
`expiry` (default: now + 365 days), `repo` (default: the working directory,
whose fetched `refs/remotes/origin/main` is the landed tip) and `datadir`.
Every refusal comes before any write:

- `RELEASE_NOT_LANDED`: `merge-base <commit> origin/main` is not the commit
  (also an unknown commit); `RELEASE_ORIGIN_UNKNOWN`: no fetched origin/main.
  The leaf never fetches; the conveyor already fetches before it signs.
- `RELEASE_MANIFEST_MISMATCH`: `MANIFEST.sha256` (`sha256sum` lines) does not
  re-derive: a listed file is missing, not a plain file, or its sha256 differs.
- `RELEASE_DOC_EXISTS`: `<release_dir>/z23-<commit12>.v2.zid` is present.

**Manifest root (decision).** The signed `manifest_root` is the vcs package
root (`vcs_package_manifest_root`, domain `zcl.package_manifest.v1`) of the
package whose files are those `MANIFEST.sha256` lists plus `MANIFEST.sha256`
itself: flat paths, mode 0755 if any exec bit is set else 0644, ordered 1 MiB
SHA3-256 chunk hashes. It is exactly the `package_root` that `ops slot install`
recomputes from the package store and that `zcode release verify
--package_root` and the pin gate compare. A plain SHA-256 of MANIFEST.sha256
could never pass `ops slot install` (it loads a vcs manifest for the root), so
it is not used. The receiver still needs that manifest and the `z23` chunks in
its package store, which `zcode package` distribution provides; this leaf does
not publish them.

**Version (deviation).** The doc `version` field is capped at 32 characters, so
it carries the first 32 hex characters of the commit (128 bits); the doc name is
`z23`, the file name and the receipt carry the first 12.

The doc is written 0600 through an exclusive staging file and a no-clobber
publish, read back, and verified through the pair-pin gate (with `package_root`
and `require_pq`) before the leaf reports ok; a doc that fails read-back is
removed. A receipt `release-sign-<commit12>.receipt` (authority_receipt header,
schema `z23.release_sign.v1`: artifact = package root, anchor = SHA3-256 of the
commit, detail = SHA3-256 of the doc bytes) is sealed under the datadir. Seeds
come from files only and never reach argv, the reply, a log or the receipt; the
reply carries the public keys and the ready `zrs1` pin line.
