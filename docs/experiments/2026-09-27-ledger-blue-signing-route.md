<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue signing route candidate

## Rejected payment request recovery

At 2026-09-27T16:35:52-04:00 (2026-09-27T20:35:52Z), review of the
transparent Wallet 0.3.2 command path found that a rejected payment APDU
aborted its transaction state and then unconditionally marked the payment
screen visible. The device loop would redraw that stale payment view after
sending the error. A new SDK-shim test stages an approved review, sends a
malformed INS `29` frame, and requires zero reply data, no signer call, a
cleared approval and timer, and a hidden payment view. Reintroducing the
old visibility assignment made this test fail on its visibility assertion;
restoring the fix made it pass. The device loop now redraws the receive
screen after a rejected payment APDU when a receive address exists. If
address derivation failed, its error screen remains visible.

Wallet 0.3.3 passed the Blue SDK C23 build, zero initialized `.data`, and
the named stack gate. Two clean builds from independently patched SDK
trees at revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`
produced identical 41,216-byte `.text` images, SHA-256
`0ea32dcda1cb24a3ed0f79edccaffa884f7ac118dccd8c4ab101070ae7d4802d`.
The image has 5,476 bytes `.bss` including its 2,048-byte stack; the
largest named signing path remains 736 bytes before BOLOS frames. Clang
22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release each passed the full 47/47
Ledger tests on an AMD Ryzen 7 PRO 8840U. The installer allowed the exact
0.3.3 image to reach missing-CA-key handling, while a one-byte mutation
and the older 0.3.2 image were rejected by the hash allowlist before Blue
access. Older Wallet images are no longer installable through Z23. This
does not prove USB recovery or touchscreen response on the physical Blue;
0.3.3 has not been installed there.

## Shielded review visual simulation

At 2026-09-27T16:27:29-04:00 (2026-09-27T20:27:29Z), the C23 screen
simulator replayed the published 4,118-byte, 3-spend/3-output Sapling
fixture through the same six-pass app controller as the Blue image. It
produced 41 PNGs: ready, the start and completion of each pass, summary
and digest in light and dark modes, and all six large-text details for
both pages and both themes. A C23 integration test checked every named
artifact's PNG signature and 320×480 dimensions, then removed its test
files. Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release each passed
that test on an AMD Ryzen 7 PRO 8840U. Representative images were opened
at original size: the summary, digest, upload progress, large warning,
and dark pages were legible and kept the no-signing warning visible.

The renderer reuses Blue layout constants and the app's actual screen
lines, but it draws fonts with a host C23 canvas rather than the BOLOS
BAGL rasterizer. These PNGs do not prove pixel identity with the Blue,
touch response, USB behavior, or signing safety. The next evidence step
is a host harness for the device event callbacks or a supervised Blue
screen comparison before physical installation.

## OpenSSL-free shielded review host protocol

At 2026-09-27T16:19:10-04:00 (2026-09-27T20:19:10Z), the ISO C23
`zcl-blue-shielded-review` host command exercised the exact version-7
six-pass APDU protocol. It checks the app identity, each chunk's pass and
byte count, each pass transition, the final 44-byte public summary, and
the full ZIP-243 digest against Z23's host parser and hasher. Failure
requests a best-effort device erase and returns zero result fields. A
1425-byte synthetic one-spend/one-output fixture passed; injected USB
disconnect, changed progress, changed final digest, and old protocol
version each failed and erased the simulated review. The published
4118-byte ZIP-243 Sapling vector with three spends and three outputs
returned digest
`63d18534de5f2d1c9e169b73f9c783718adbef5c8a7d55b5e7a37affa1dd3ff3`,
matching its existing independent test vector.

Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release each passed 46/46
Ledger tests on an AMD Ryzen 7 PRO 8840U. The staged-source complexity
ratchet passed 61,294 functions at cap 15. Clang and GCC also built the
review-only C23 host command without OpenSSL or PNG, and both command
simulations returned the published vector digest. The Clang review-only
binary dynamically links only libc and the ELF loader. These are host
and C23 screen-model tests; the new app image has not been installed or
tested over physical Blue USB. The command has no signing or broadcasting
path. It does not establish shielded recipients, amounts, fee, proofs,
memo contents, account ownership, or a verified chain tip.

## Shielded key compatibility and image substitution

At 2026-09-27T16:06:13-04:00 (2026-09-27T20:06:13Z), the offline
`ZCL Shielded Review` image hash
`42fc4fe0c7e9ac3864ed4977b0ac601b742c95868798fa80807034b83fd0eec2`
was added to the installer allowlist under its distinct name and version
0.5.0. Its profile grants no ZCL signing path. In a no-device test using
`--ca-verify`, the exact 26,624-byte image advanced to CA-key loading; a
one-byte substitution was rejected by the SHA-256 allowlist before key
loading or Blue access. The new delete option reached CA-key loading for
the distinct shielded-review name. Clang 22.1.6 Debug ASan/UBSan and GCC
16.1.1 Release each passed all 45/45 Ledger tests on an AMD Ryzen 7 PRO
8840U; the complexity ratchet passed 61,266 functions at cap 15. The
existing host installer still depends on
OpenSSL; the Blue image does not.

The [ZIP-32 specification](https://zips.z.cash/zip-0032) derives a Sapling
master from the wallet seed using personalized BLAKE2b-512, then derives
`m/32'/147'/account'` for ZCL. Z23's current Sapling keystore generates or
imports its own 32-byte seed before calling `zip32_xsk_master`. The reviewed
[Blue 2.1.x SDK API](https://github.com/LedgerHQ/blue-secure-sdk/blob/master/include/os.h)
exposes BIP-32 derivation and a custom HMAC seed-key variant, but neither a
raw seed output nor a ZIP-32 derivation call. These interfaces cannot prove
that a Blue-derived Sapling key equals an existing Z23 software-wallet key.
The [Zcash Ledger security audit](https://zecsec.com/audits/zcash-ledger-audit-report-v2.pdf)
documents the analogous nonstandard-derivation recovery and cross-pool
key-isolation risks. A potential Blue-specific Sapling account must use
separate domain-derived material, publish a recovery algorithm with
independent C23 test vectors, and disclose its distinct account identity
before real funds are accepted. The next experiment is an offline recovery
comparison from a public test mnemonic against a device-derived public
viewing key; no recovery words or secret keys should cross USB. Until that
experiment and full transaction approval are complete, Sapling signing
remains unavailable.

## Offline Ledger Blue shielded review image

At 2026-09-27T15:57:12-04:00 (2026-09-27T19:57:12Z), a separate ISO C23
Ledger Blue 2.1.x app image linked the six-pass shielded review controller
to the existing BAGL interface. The read-only app is named `ZCL Shielded
Review`, protocol version 7. The host controller test drove a synthetic
1,425-byte one-spend/one-output transaction through all six APDU passes and
checked upload progress, public summary, full digest page, large text, dark
mode, reset, and interrupted review. A physical screen redraw during upload
requires tapping `NEXT / REFRESH`; the host test checks the screen model,
not the BOLOS event renderer. The test wire has arbitrary proof bytes
and cannot be broadcast. A second host test used the published 4,118-byte
Sapling vector, 10,000 deterministic arbitrary APDU frames, a changed
second pass, interrupted upload, and malformed commands. The UI uses
`ZIP243 PREFIX` for the digest prefix and shows `FEE UNKNOWN` and
`SHIELDED HIDDEN; NO SIGNING`.

Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release each passed 45/45
Ledger tests on an AMD Ryzen 7 PRO 8840U. The C23 complexity ratchet passed
61,265 functions at cap 15. Clang 22.1.6 and ARM GCC 16.2.0 built the Blue
image with strict C23 warnings. The image has 26,624 bytes `.text`, no
initialized `.data`, and 4,304 bytes `.bss` including the linker-reserved
2,048-byte stack. The shielded stack gate modeled begin at 300 bytes,
upload parsing at 368, upload SHA-256 at 632, pass advancement at 760,
finish at 824, progress formatting at 216, summary at 184, and digest page
at 88; each stays below 1,536 bytes after a 512-byte reserve margin. A
synthetic 1,900-byte `complete_pass` frame caused the gate to reject the
image. The gate requires all named frames, but excludes BOLOS and SDK
internals. Two clean builds produced identical `.text` bytes, SHA-256
`42fc4fe0c7e9ac3864ed4977b0ac601b742c95868798fa80807034b83fd0eec2`.
The app is not installed or physically tested. No shielded signing, key
derivation, verified branch selection, fee, recipient, proof, or memo
verification is present.

## Shielded review display semantics

At 2026-09-27T15:45:41-04:00 (2026-09-27T19:45:41Z), the read-only
six-pass APDU simulator gained a screen-formatting check. The upload screen
shows the current pass, bytes received, and `READ ONLY; NO SIGNING`. The
completed summary reuses independently parsed public facts, retains `FEE
UNKNOWN` and `SHIELDED HIDDEN; NO SIGNING`, and labels its displayed digest
prefix `ZIP243 PREFIX`. This prevents the existing SHA-256 screen label from
misidentifying the six-pass signing digest. The simulator checks the screen
at the start, after each pass, and after finish; it rejects an invalid pass
number. Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release each passed
44/44 Ledger tests on an AMD Ryzen 7 PRO 8840U. ARM GCC 16.2.0 compiled the
screen module for Cortex-M3 with ISO C23 and strict warnings. The entire
module object, including older formatters, has 2,276 bytes `.text`,
421 bytes `.rodata`, and no static RAM. The C23 complexity ratchet passed
61,101 functions at cap 15. No actual Blue touchscreen interaction is
connected or tested by this host formatter.

## Read-only six-pass shielded review APDU

At 2026-09-27T15:42:26-04:00 (2026-09-27T19:42:26Z), an ISO C23
controller added a version 7 read-only APDU interface around the bounded
replay. A begin command names the full wire length and a known ZCL mainnet
branch. A feed command accepts at most 220 bytes and reports the pass and
received count. After six complete, identical passes, finish returns 44 bytes
of independently parsed public facts and the 32-byte ZIP-243 digest. A
rejected command or explicit erase clears the controller state. There is no
signing command, key access, or payment approval.

The host APDU simulator uploaded the published 4,118-byte Sapling vector in
220-byte chunks across all six passes, matched the full-wire ZIP-243 digest,
and checked the returned public counts. It rejected a changed second pass,
an early pass advance, an oversized chunk, a malformed frame, an unknown
branch, and an attempted signing instruction; rejected commands erased the
state. Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release passed all 44/44
Ledger tests on an AMD Ryzen 7 PRO 8840U. The complexity ratchet passed
61,097 functions at cap 15. ARM GCC 16.2.0 compiled the controller for
Cortex-M3 with ISO C23 and strict warnings; its object has 924 bytes
`.text`, 6 bytes `.rodata`, no static RAM, and a 72-byte reported frame for
its public handler. Its compile-time state bound is 672 bytes; linked stack
and memory costs are not yet measured. The controller has no direct OpenSSL
dependency. It is not linked into a BOLOS image or installed on the Blue.
The branch is only checked against a known-ID list, not a verified chain tip;
shielded recipients, amounts, fee, proofs, and memos cannot yet be reviewed
from verified device inputs. This protocol grants no signing authority.

## Six-pass bounded-memory shielded ZIP-243 replay

At 2026-09-27T15:33:31-04:00 (2026-09-27T19:33:31Z), the streaming
scanner gained a C23 replay controller. The host uploads the complete wire
six times. Each pass derives one independently parsed ZIP-243 section hash
using one BLAKE2b context, while Z23's C23 SHA-256 commits to every byte of
the first pass and rejects any later pass with a different whole-wire hash.
The Cortex-M3 state is 536 bytes, excluding the caller-owned BLAKE2b
context. ARM GCC 16.2.0 compiled the controller to 996 bytes `.text`,
128 bytes `.rodata`, and no `.data` or `.bss`; its largest named function
frame is 104 bytes, excluding nested calls.

Replay output matches the established full-wire ZIP-243 digest for the
4,118-byte published Sapling vector, 1,425-byte spend/output fixture,
245-byte transparent fixture, and 1,759-byte JoinSplit fixture. Both
`76b809bb` and `930b540d` branches match on the published vector. A
structurally valid changed byte in each of passes two through six is
rejected; a truncated pass also fails. Failed replay leaves the caller's
digest buffer unchanged. Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1
Release each passed the full 43/43 Ledger suite on an AMD Ryzen 7 PRO
8840U. The C23 complexity ratchet passed 61,071 functions at cap 15.
The controller has no OpenSSL dependency. It is
not yet in the Blue app's APDU or touchscreen path, and its host-supplied
branch ID is not bound to a verified chain tip. It grants no signing
authority.

## Bounded-state Sapling transaction scanner

At 2026-09-27T15:26:20-04:00 (2026-09-27T19:26:20Z), a separate ISO C23
Sapling-v4 streaming parser was added. Its state is 96 bytes and emits
provisional wire spans for the eight ZIP-243 categories while deriving
transparent and shielded counts, public output total, value balance, lock
time, and expiry height. The established full-wire parser independently
matched those facts for the published 4,118-byte Sapling vector, a 245-byte
transparent vector, the 1,425-byte spend/output fixture, and a 1,759-byte
synthetic JoinSplit fixture. The 4,118-byte vector was fed at every chunk
size from 1 through 256 bytes. Across the four fixtures, 16,384
deterministic byte/length mutations produced the same accept/reject result
as the existing parser. Truncation, changed header, and observer rejection
invalidate the stream.

A host-only test used six BLAKE2b contexts to hash the emitted sections and
reconstructed the exact ZIP-243 digest of each fixture using Z23's C23
hash implementation. That test validates section boundaries; six concurrent
hash contexts are not proposed as a Blue memory layout. ARM GCC 16.2.0
compiled the parser for Cortex-M3 with `-std=c23 -O2 -Wall -Wextra -Werror
-pedantic`; the object has 1,972 bytes `.text`, 8 bytes `.rodata`, and no
`.data` or `.bss`. Its largest reported function frame is 40 bytes. The
parser does not yet authenticate repeated passes or feed a Blue signing
command. A future bounded-memory digest must replay identical wire bytes,
then bind verified branch selection and reviewed transaction facts before
any signature may be released.

## Synthetic Sapling wire through review and signature tests

At 2026-09-27T15:16:20-04:00 (2026-09-27T19:16:20Z), one 1,425-byte
Sapling-v4 fixture with one spend and one output was shared by the host
signing and Blue review simulator tests. Its spend, output, and proof bytes
are arbitrary; it is structurally parseable but is not a valid transaction
for broadcast. The ZIP-243 SIGHASH_ALL digest under branch `76b809bb` is
`df7c3c4c47ac47fb23844b196c895abc5640ef2fb04a0ce5b792cc2c9871424e`.
The isolated signer, with public scalar 23 and entropy bytes 0 through 79,
produced `Rbar=473240ce569bb29ec88ebb7a7b01c824e11e450ecf60fcba44dff83f21a0422d`
and `Sbar=dd6824f3bcc664aa4577b40551625f6e3c6f81d55c2ccd5664754ab4b2980705`.
Z23's separate Jubjub verifier accepts that signature for the digest and
rejects it after a shielded output byte or branch ID changes the digest.
The digest correctly excludes the spend authorization signature and binding
signature bytes.

The read-only Blue review simulator uploaded the same wire in 220-byte USB
chunks, compared its ZIP-243 reply to the host digest, completed the summary,
and checked the page text `SHIELDED SPEND/OUT: 1/1`, `FEE UNKNOWN`, and
`SHIELDED HIDDEN; NO SIGNING`. A malformed frame after the first 220-byte
chunk erased the pending transaction and refused a later digest request.
This does not authorize the isolated signer;
the review and signing tests have no shared approval state. QEMU 11.0.1
`mps2-an385` signed the pinned digest and matched the exact 64-byte host
signature. Its `TXSIGN` stage used 1,452 of 2,048 stack bytes; the suite
maximum remained 1,500. The harness has 32,152 bytes `.text`, 1,360 bytes
`.data`, and 2,220 bytes `.bss` in the 6 KiB RAM model. Clang 22.1.6
Debug ASan/UBSan and GCC 16.1.1 Release passed 42/42 Ledger tests on an
AMD Ryzen 7 PRO 8840U; the C23 complexity ratchet passed 61,016 functions
at cap 15. Device-side shielded recipient, amount, fee, proof, and memo
review, verified branch selection, protected keys, approval binding, and
physical signing remain unimplemented or unverified.

## Complete isolated SpendAuth signature fixture

At 2026-09-27T15:10:21-04:00 (2026-09-27T19:10:21Z), an isolated C23
signing candidate combined the fixed SpendAuth generator, low-memory point
multiplication and encoding, entropy-seeded nonce, personalized RedJubjub
challenge, and canonical Fs response. The public fixture uses secret scalar
23, entropy bytes 0 through 79, and digest bytes 0 through 31. It produces
`Rbar=8f40696890377cb1a4146a7117d9ceecd6014d9136de23f2f7781ad10f8850d2`
and
`Sbar=ffe3a89b2c2105c9b216070288b519e68c829a95aa9fca3307611d6dd277d306`.
Z23's separate Sapling Jubjub implementation verifies the public signature;
mutating the digest or response breaks verification. Changing the entropy
changes the signature while preserving verification. Zero entropy or a zero
secret is rejected without changing the signature output.

Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release each passed 42/42
Ledger tests on an AMD Ryzen 7 PRO 8840U. ARM GCC 16.2.0 built the C23
fixture; QEMU 11.0.1 `mps2-an385` matched the exact 64-byte signature.
The new `SIGN` stage used 1,484 of 2,048 stack bytes, while the suite's
maximum stage remained 1,500 bytes. The QEMU harness uses 31,864 bytes
`.text`, 1,360 bytes `.data`, and 2,220 bytes `.bss`, leaving 516 bytes
outside its reserved 2 KiB stack in a 6 KiB RAM region. The C23 complexity
ratchet passed 61,009 functions at cap 15. This is a public fixed fixture;
the signer is not connected to BOLOS keys, the USB protocol, device CSPRNG,
reviewed transaction facts, or a physical Blue. Target timing with secret
material and a complete linked Blue app remain unverified.

## Isolated RedJubjub response step

At 2026-09-27T15:05:05-04:00 (2026-09-27T19:05:05Z), a C23 helper
extracted the RedJubjub scalar response `S = r + c·sk mod Fs` from the
public signing fixtures. It accepts only canonical little-endian Fs
scalars, rejects zero nonce and zero secret, leaves the output unchanged on
failure, and wipes its local nonce, challenge, secret, product, and sum.
The host test compares its response with Z23's separate Sapling Fs
implementation and verifies the resulting public signature with Z23's
separate Jubjub operations. It also rejects the scalar order in each input
position. The helper replaces the inlined response step in the Cortex-M3
QEMU signature fixture.

Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release each passed 42/42
Ledger tests on an AMD Ryzen 7 PRO 8840U. ARM GCC 16.2.0 built the C23
QEMU image; QEMU 11.0.1 `mps2-an385` passed the response equation. Its
maximum per-stage measured stack use remains 1,500 of 2,048 bytes, leaving
548 bytes. The image uses 31,136 bytes `.text`, 1,360 bytes `.data`, and
2,076 bytes `.bss`; these are harness figures, not a BOLOS app budget. The
C23 complexity ratchet passed 61,004 functions at cap 15. Secret-dependent
timing, device CSPRNG quality, protected key derivation, transaction approval,
BOLOS integration, and physical Sapling signing remain unverified. The helper
is not exposed through an APDU.

## Review upload rejection and memory clearance

At 2026-09-27T14:57:55-04:00 (2026-09-27T18:57:55Z), the read-only Blue
Review 0.4.5 candidate was changed to erase its 2,304-byte transaction
buffer and counters on every rejected APDU, explicit clear, and new review.
The screen controller resets its display state to `CONNECT Z23` on rejection;
the BOLOS
exception path also erases the review state. Host checks cover rejection
during upload, rejection after a completed review, clearing an old review,
and the screen reset after a malformed frame. The 10,000-case deterministic
malformed-APDU simulator still passes.

Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release each passed 42/42 Ledger
tests on an AMD Ryzen 7 PRO 8840U. ARM GCC 16.2.0 and Clang 22.1.6 built the
Blue image with ISO C23, `-Wall -Wextra -Werror -pedantic`; the SDK stack
gate reported a 2,048-byte reserve, 776-byte APDU path, 888-byte screen
path, and 512-byte required margin. The image has 33,536 bytes `.text`,
6,000 bytes `.bss`, zero `.data`, and 144 bytes of 6 KiB SRAM outside `.bss`.
Its `.text` SHA-256 is
`c23c78c978245da12af43dd44b44e63f8a695857be8a2c9ca632804d2c00d37c`.
The C23 complexity ratchet passed 61,003 functions at cap 15. This image
has not been installed or tested on a physical Blue. The app remains
read-only and does not authorize or sign a shielded payment.

## Question

Can the reviewed transparent payment state reach the pinned Blue signing
callback only after a separate final touchscreen approval, while preserving
ordered digest binding and the Blue memory and stack limits?

## Method

At 2026-09-27T12:05:17-04:00 (2026-09-27T16:05:17Z), the C23 SDK-shim
test compiled the actual payment screen and command router. It simulated
output review, fee and totals pages, `NO SIGN`, `SIGN ZCL`, duplicate taps,
ordered signing, replay, no-touch signing, and malformed APDU refusal. The
signer was a test stub; no hardware key or physical touchscreen was used.
The protocol test checked identity versions 8, 11, and 12. Clang 22.1.6 Debug
ASan/UBSan and GCC 16.1.1 Release each passed the three focused tests:
`blue-wallet-protocol`, `blue-payment-sign`, and `blue-wallet-device-ui`.
The complete Clang Debug Ledger CMake suite then passed 31 of 31 tests.
After installer pinning and the abort test, the final candidate again passed
31 of 31 tests under Clang Debug ASan/UBSan and 31 of 31 under GCC Release.
The host CPU was an AMD Ryzen 7 PRO 8840U.

The wallet image was built twice with Clang 22.1.6 and ARM GCC 16.2.0 from
independently patched Blue SDK trees pinned to revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`. Both `.text` binaries
had SHA-256
`b4ff51df36cb805dfeda0524a14a46bffe30314925d178e571fe335d067710f7`.
The image has 40,448 bytes of `.text`, 5,476 bytes of `.bss`, and zero
initialized `.data`. The gate reported a 2,048-byte stack reservation and
720 bytes for its largest named signing path, excluding BOLOS firmware
frames. The C23 cyclomatic-complexity ratchet passed at cap 15 after the
display selector was split into a separate function.
The installer pins that exact `.text` SHA-256 to version 0.3.0. An offline
installer invocation with the reproduced binary passed image validation and
then stopped at the deliberately invalid `/dev/hidraw999` path. The existing
installer rejection suite passed with Clang and GCC. No install command was
sent to the physical Blue.

## Result and limit

In the shim, no signer call occurred before `SIGN ZCL`. The first ordered
INS `29` call returned one signature reply; replay and malformed frames
aborted the review without a second signer call. The `NO SIGN` path retained
read-only behavior. The candidate advertises protocol version 12 and
capability byte 31; the host still accepts the read-only version 11 image.
The host review simulator also accepts version 12 identity and completes
its read-only three-pass review without requesting a signature.
The final 320 × 480 signing page rendered to RGB SHA-256
`d64862aa9c24cc1839ffd77b17a7eb94dae7dd91aa1553193cdd052135d008bf`;
the SDK-shim touchscreen test pins that pixel result on Clang and GCC.
Its version 12 synthetic one-input flow also ran the bound previous-wire
review, simulated final approval, obtained a software ECDSA reply, verified
that reply against the ZIP-243 digest and owned public-key hash, and assembled
a transparent v4 transaction. The same end-to-end test passed with Clang
Debug sanitizers and GCC Release. This uses a generated test key, not BOLOS.
A separate two-input signer test requested indices zero and one in order,
verified the second ECDSA signature over its distinct bound digest, and
confirmed that the approval latch closed after the second reply. Clang Debug
sanitizers and GCC Release both passed it.
The SDK-shim UI test also aborted the session immediately after approval,
then requested INS `29`; the route refused it without calling the signer.
The C23 host collector required identity 12/31, made its final approval
callback, requested INS `29`, verified the reply, and fed the result into
assembly. An identity 11/15 device caused zero signer calls. A corrupted
signature reply cleared all host result slots and sent INS `24` to abort
the simulated device review. Both Clang Debug and GCC Release passed.
A two-input failure test corrupted the second reply after the first had
verified; the collector cleared both result slots and aborted the device
state, leaving no verified signatures for assembly. Both compilers passed
this case as well.
With the host collector included, the complete Ledger suite passed 31 of 31
tests under Clang Debug ASan/UBSan and 31 of 31 under GCC Release.

No payment has been signed by this image on a physical Blue. The shim cannot
establish real touchscreen event ordering, physical framebuffer rendering,
USB exchange behavior, firmware stack frames, or BOLOS ECDSA behavior. The
host has a fixture-only live INS `29` path, but it has not been tried on
physical hardware. Chain inclusion and active
branch selection remain unchecked on the device and are labeled on its
approval screen. Sapling, shielded multisig, and ZSLP are outside this
candidate's protocol.

## Next experiment

Run an end-to-end host fixture through the physical app with a public test
seed, verify the returned signature against the exact device ZIP-243 digest,
then test cancellation, USB reset, and restart before enabling any live
wallet signing workflow.

## Fixture preparation

At 2026-09-27T12:38:34-04:00 (2026-09-27T16:38:34Z), the C23 fixture
builder created an 85-byte previous wire paying 4 ZCL to a supplied
compressed public key and a 136-byte unsigned v4 spend. Its two outputs
send 1 ZCL to the same key and 2 ZCL to a fixed P2SH test address, with a
calculated 1 ZCL fee. The host previous-wire binder accepted the matching
outpoint and digest, then rejected a modified previous wire. The offline CLI
derived a transparent address from the secp256k1 generator key and reported
the fee and the absence of chain provenance. An invalid public key and a
nonexistent HID path were rejected.

Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release both passed the
complete 33/33 Ledger CMake suite, including the new fixture and CLI smoke
tests. The CPU was an AMD Ryzen 7 PRO 8840U. The fixture CLI checks
protocol 12/capability 31 before requesting the Blue public key. Its live
path streams the bounded review, waits for each output's CONTINUE touch,
waits for a final SIGN ZCL touch and terminal confirmation, verifies the
returned signature, and assembles signed bytes in memory. This live path
has not been exercised on the Blue. No fixture output was saved or broadcast.

At 2026-09-27T12:43:24-04:00 (2026-09-27T16:43:24Z), the complete
simulated review-to-signature test switched to the same fixture builder used
by the physical-test CLI. The 85-byte previous wire and 136-byte unsigned
spend passed host preflight, simulated Blue output touches, device digest
binding, final approval, signature verification, and signed-wire assembly.
The `blue-payment-review` test passed 1/1 with Clang 22.1.6 Debug
ASan/UBSan and GCC 16.1.1 Release. This aligns simulated bytes with the
CLI fixture; USB and physical touchscreen behavior remain untested.
The CLI's protocol 12/capability 31 response is not evidence that the
installed app equals the pinned build. Authenticated BOLOS catalog
verification and session binding are still required before real payment
signing; the synthetic fixture does not supply that evidence.

## Review restart and image 0.3.1

At 2026-09-27T12:53:58-04:00 (2026-09-27T16:53:58Z), the SDK-shim UI
test reproduced a stale signing page when a new review began after a
previous `SIGN ZCL` touch. The old code failed the assertion that the new
review showed its waiting page. Resetting the payment view before processing
INS `20` made the same test pass under Clang 22.1.6 Debug ASan/UBSan and
GCC 16.1.1 Release. A new begin discards the earlier approval latch.

Wallet 0.3.1 built cleanly from two independently patched SDK trees at
revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`; the SDK patch
SHA-256 was
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Clang 22.1.6 and ARM GCC 16.2.0 produced identical 40,704-byte `.text`
images with SHA-256
`502c4904a624bd8e8e9d02d5f9992b76bdac728b3687a0f24964427c54e24ecf`.
The image has 5,476 bytes of `.bss` and zero initialized `.data`. Its
largest named signing path is 728 bytes, excluding BOLOS frames. Both
builds passed the 2,048-byte stack-reservation and 512-byte SRAM-margin
gates. On an AMD Ryzen 7 PRO 8840U, the Ledger CMake suite passed 33/33
with Clang Debug ASan/UBSan and 33/33 with GCC Release. The complexity
ratchet passed 60,901 functions at cap 15 after two fixture helpers were
split. A valid 0.3.1 binary passed the installer's image pin before the
deliberately nonexistent HID path; a one-byte mutation was rejected before
USB access. No physical install or payment signing occurred.

At 2026-09-27T12:58:09-04:00 (2026-09-27T16:58:09Z), a simulator
regression showed that a host collector called with a missing expected
hash after device approval cleared its output slot but left the Blue review
armed. The old code failed this test. The collector now attempts INS `24`
on every invalid-argument failure when a transport callback is available;
the device clears its approval and fee-ready state without calling the
signer. The focused `blue-payment-review` test passed under Clang 22.1.6
Debug ASan/UBSan and GCC 16.1.1 Release; the complete Ledger suite then
passed 33/33 under each compiler. The C23 complexity ratchet passed
60,902 functions at cap 15. This is simulator evidence; a real USB
disconnect can prevent delivery of the abort command.

At 2026-09-27T13:00:34-04:00 (2026-09-27T17:00:34Z), the same generated
fixture passed a simulated review and then lost USB at each of two signing
reply boundaries: immediately after the protocol identity response and
immediately after the device had produced an ECDSA reply. In both cases the
host collector returned no verified signature, the simulator cleared the
approval state, and a resumed INS `29` request was refused without another
signer call. The focused test passed with Clang 22.1.6 Debug ASan/UBSan and
GCC 16.1.1 Release; the complete Ledger suite passed 33/33 with each
compiler, and the complexity ratchet passed 60,903 functions at cap
15. This simulates loss and restart behavior but does not establish that
physical BOLOS clears state on a USB disconnect or power interruption.

## Bounded approval lifetime

At 2026-09-27T13:05:56-04:00 (2026-09-27T17:05:56Z), an SDK-shim test
showed that the final `SIGN ZCL` touch did not start any timeout. The Blue
SDK documents a 100-ms ticker callback and a one-shot interval. Wallet
0.3.2 starts a 30,000-ms interval only after the final touch, displays
`APPROVAL EXPIRES 30S`, and clears the approval and review state when the
callback expires. The shim verified that a subsequent INS `29` returns a
refusal without calling the signer. The timer also clears when the final
signature is consumed or the review aborts. A red-green test found that
request and reply share one APDU buffer: examining INS `29` after dispatch
read the reply path byte instead. The handler now snapshots the instruction
before dispatch. USB reset and suspend continue to abort the review.

Two clean builds from the independently patched Blue SDK trees at
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` produced identical
41,216-byte `.text` images with SHA-256
`272aab984115b063b2cbb62ea6682b7e3fcca082a7761edf6c1fd9117bc2596e`.
The patch digest remained
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
The image has 5,476 bytes of `.bss`, zero `.data`, and a largest named
signing path of 736 bytes, excluding BOLOS frames. Both builds passed the
2,048-byte stack reservation and 512-byte SRAM margin gates. Physical
ticker cadence and actual expiry behavior have not yet been measured.
The full Ledger CMake suite passed 33/33 under Clang 22.1.6 Debug
ASan/UBSan and 33/33 under GCC 16.1.1 Release on an AMD Ryzen 7 PRO 8840U.
The complexity ratchet passed 60,907 functions at cap 15. The installer
accepted the exact 0.3.2 `.text` hash before stopping at a deliberately
nonexistent HID path; a one-byte mutation was rejected before USB access.

## Exact assembled-wire check

At 2026-09-27T13:12:56-04:00 (2026-09-27T17:12:56Z), the host assembler
began rejecting overlap between its output and each reviewed input buffer,
including the unsigned wire, signature records, and expected digest array.
After constructing an all-transparent v4 transaction, it independently
parses the signed inputs and checks that removing only their inserted scripts
reproduces every byte of the reviewed unsigned transaction. A two-input
test rejects both exact and one-byte-shifted output overlap. The focused
review test and full CMake suite passed 33/33 under Clang 22.1.6 Debug
ASan/UBSan and 33/33 under GCC 16.1.1 Release on an AMD Ryzen 7 PRO 8840U.
The C23 complexity ratchet passed 60,910 functions at cap 15. This check
does not independently establish chain provenance, authenticate the device
app image, or enable shielded signing.

## Cortex-M3 Sapling arithmetic execution

At 2026-09-27T14:21:43-04:00 (2026-09-27T18:21:43Z), ARM GCC 16.2.0
compiled the C23 Fr/Fs, low-memory Jubjub, and Z23 scalar-reduction sources
for Cortex-M3. QEMU 11.0.1 `mps2-an385` executed a public SpendAuth
`ask`-to-`ak` vector, an Fs boundary multiplication, and four 512-bit
scalar-reduction vectors. The UART reported `M3 STACK 0x05b4` and
`M3 PASS`. The 0x05b4 watermark is 1,460 bytes of a 2,048-byte reserved
test stack; it includes C library frames used by this test but excludes
BOLOS, USB, and touchscreen frames. The linked test image used 12,888 bytes
of flash sections (`.vectors`, `.text`, `.ARM.exidx`), 1,360 bytes of
initialized RAM, and 580 bytes of zero-initialized RAM, within a simulated
6 KiB RAM map. These are test-image measurements, not a full Blue app image.

Replacing the reducer's 128-bit multiplication by a mask for the secret
one-bit choice, and computing the public 3r constant with 64-bit additions,
removed the ARM GCC `__mulbitint3` dependency. The same QEMU linked test
used 13,996 flash bytes before this change and 12,888 afterward, a
1,108-byte decrease. A deliberately changed expected point produced
`M3 FAIL`, which CTest rejected; the original fixture was restored before
the passing run. A permanent host differential test compares 259 fixed and
deterministic 512-bit inputs against `fs_to_uniform`. The complete Ledger
suite passed 40/40 under Clang 22.1.6 Debug ASan/UBSan and 40/40 under GCC
16.1.1 Release on an AMD Ryzen 7 PRO 8840U. The C23 complexity ratchet
passed 60,963 functions at cap 15. QEMU CPU execution does not validate
physical timing, BOLOS calls, the display, USB, or Ledger Blue power loss.

The same ARM test also computed a fixed public RedJubjub signing equation
on Cortex-M3:
`S = r + c·ask` and `S·G = R + c·ak`, for public fixture scalars
`ask=23`, `r=97`, and `c=31337`. A one-bit change to `S` failed the
equation. QEMU reported `M3 STACK 0x062c` and `M3 PASS`: 1,580 bytes of
the 2,048-byte test stack. The enlarged test image used 13,504 flash
bytes, 1,360 initialized RAM bytes, and 1,220 zero-initialized RAM bytes.
This validates arithmetic on an emulated Cortex-M3; it does not implement
nonce generation, message challenge hashing, transaction binding, device
key derivation, or a Sapling signing APDU.

## Existing RedJubjub signer cleanup

The C23 Sapling signer now calls `memory_cleanse` for its nonce seed, scalar
intermediates, and field values after producing a signature. It also cleanses
the seed when the RNG reports failure after possibly writing partial bytes.
The existing cleanse API provides an optimization barrier for the store;
ordinary `memset` did not provide that contract. Clang 22.1.6 and GCC
16.1.1 each accepted `sapling.c` under `-std=c23 -Wall -Wextra -Werror
-pedantic -fsyntax-only`. The complexity ratchet passed 60,977 functions
at cap 15. The focused `make t ONLY=sapling_crypto` was not completed:
this checkout began fetching and building a missing vendored zlib archive,
so the build was stopped. No signer runtime result is claimed for this
cleanup.

## Transaction-digest challenge on host and Cortex-M3

At 2026-09-27T14:33:53-04:00 (2026-09-27T18:33:53Z), the isolated C23
RedJubjub challenge helper hashed the 32-byte `Rbar`, 32-byte `vkbar`, and
32-byte message digest with the 16-byte `Zcash_RedJubjubH` personalization,
then reduced the 64-byte BLAKE2b output modulo the Jubjub scalar order.
An independent personalized BLAKE2b calculation produced the expected
little-endian scalar
`17b7ba4df18cc10026143ed72d67bf355a7dac21164951edb121643d551d4d0b`
for sequential fixture bytes 0–95. The host test checks the exact scalar,
then changes each of the three inputs separately and checks that its output
changes. The QEMU Cortex-M3 test checks the same scalar.

Using host-compressed public fixture points `R=[97]G` and `vk=[23]G`, the
ARM test also checks the challenge for message bytes 0–31 and the resulting
`S=97+c·23 (mod Fs)` against independently calculated expected bytes. It
checks `S·G=R+c·vk`, rejects a one-bit change to `S`, and rejects a one-bit
change to the message without changing `S`. QEMU reported `M3 STACK
0x068c` and `M3 PASS`: 1,676 bytes of the 2,048-byte simulated test
stack. The test image uses 28,776 flash bytes, 1,360 initialized RAM
bytes, and 1,436 zero-initialized RAM bytes. Its static points are public
test fixtures; this is not a device signer or a full Blue app image. The
challenge helper does not generate a nonce, derive a device key, validate
a ZIP-243 transaction digest, or create a signing APDU.
The QEMU harness refuses a result if fewer than 256 bytes remain at the
bottom of its reserved stack; this run left 372 bytes. The threshold is
an emulator test gate and does not account for BOLOS call frames.

## Cortex-M3 point encoding

At 2026-09-27T14:40:56-04:00 (2026-09-27T18:40:56Z), an isolated C23
encoder converted projective Jubjub points to canonical 32-byte form with
the portable Montgomery field path. A host differential test matched Z23's
existing point encoder for the SpendAuth generator, identity, six fixed
public signing points, and 32 deterministic scalar points. It rejected a
zero projective denominator without modifying the caller's output. The
QEMU Cortex-M3 run derived `vk=[23]G` and `R=[97]G`, encoded both on the
emulated CPU, matched their expected public byte vectors, and fed those
computed bytes to the message challenge. The challenge, response equation,
changed-response rejection, and changed-message rejection still passed.

QEMU reported `M3 STACK 0x06dc` and `M3 PASS`: 1,756 bytes used in its
2,048-byte test stack, leaving 292 bytes above the 256-byte test margin.
The linked test image used 29,504 flash bytes, 1,360 initialized RAM bytes,
and 1,436 zero-initialized RAM bytes. This remains an arithmetic test image;
BOLOS, USB, screen, nonce source, device key derivation, transaction review,
and complete signer stack use are not measured.

## Fixed public signature compatibility

At 2026-09-27T14:43:32-04:00 (2026-09-27T18:43:32Z), a host C23 test
assembled a fixed public 64-byte SpendAuth signature using the isolated
point encoder, challenge helper, and Fs arithmetic. Its independent check
decoded the public points with Z23's existing Jubjub decoder, hashed
`Rbar || vkbar || message` through a separate BLAKE2b call sequence,
required a canonical response scalar, and checked the cofactored
RedJubjub group equation with Z23's existing point arithmetic. The valid
signature passed; changing one response bit, changing one message bit, or
replacing the response with the scalar-field order was rejected. This
test does not call the node's `redjubjub_verify` entry point, nor does it
bind the synthetic message to a real ZCL transaction or use device keys.

## Entropy-seeded nonce fixture

At 2026-09-27T14:49:59-04:00 (2026-09-27T18:49:59Z), an isolated C23
helper implemented the existing RedJubjub nonce equation
`r = H*(T || vkbar || message)` for an 80-byte seed and a 32-byte
transaction digest. Independent personalized BLAKE2b and scalar reduction
on the public seed bytes 0–79, the public `[23]G` key encoding, and message
bytes 0–31 yielded little-endian scalar
`923570e916048b7c59ac0e27affb7a1db7acf6e2fbb4d1be2b9077466e48f806`.
The host and QEMU Cortex-M3 runs matched it. Host checks changed entropy
and changed message bytes separately; an all-zero seed or null input is
rejected without modifying the output. The helper also refuses a reduced
zero scalar and wipes its local hash context, digest, and candidate nonce.

The emulated ARM path used that public seed to derive `r`, `R=[r]G`, a
message challenge, and `S=r+c·23 (mod Fs)`, then checked the public group
equation. QEMU reported `M3 STACK 0x06f4` and `M3 PASS`: 1,780 bytes of
the 2,048-byte simulated test stack, leaving 268 bytes above the 256-byte
minimum margin. The linked test image used 30,544 flash bytes, 1,360
initialized RAM bytes, and 2,076 zero-initialized RAM bytes within its
6 KiB simulated RAM map. A nonzero fixture seed is no proof of entropy
quality or freshness. No Blue CSPRNG, real device key, BOLOS frame,
transaction digest verification, or physical signing was exercised.

## Per-stage Cortex-M3 stack budget

At 2026-09-27T14:53:00-04:00 (2026-09-27T18:53:00Z), the QEMU harness
ran each public arithmetic case from the same reset-level call site and
repainted its 1,536-byte stack canary between cases. It reported stack
watermarks of 1,268 bytes for the SpendAuth key vector, 540 for an Fs
boundary, at most 512 for scalar reduction, 1,500 for the fixed response
equation, 1,140 for the challenge vector, and 1,500 for the entropy-seeded
response equation. The overall measured peak was 1,500 of 2,048 bytes,
leaving 548 bytes. The gate now refuses any case with fewer than 512 bytes
left. The earlier 1,780-byte measurement included the local frame of a
single wrapper that held intermediate test values while calling every
case. Splitting the test stages removed that wrapper overlap; it does not
measure a production signer, BOLOS, USB, or touchscreen stack frames.

## Host input ownership plan

At 2026-09-27T13:20:38-04:00 (2026-09-27T17:20:38Z), a C23 host planner
bound every unsigned transparent input to its supplied previous transaction
before classifying the selected P2PKH hash against two distinct fixed Blue
account hashes. A two-input synthetic fixture produced external and internal
paths in order. An unknown second-input hash, identical account hashes, and
a modified previous wire were rejected without changing the caller's plan.
The focused test passed under Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1
Release; each full Ledger suite passed 34/34 on an AMD Ryzen 7 PRO 8840U.
The staged-source C23 complexity ratchet passed 60,914 functions at cap 15.
The planner is not connected to physical signing, and supplied public hashes
must still be authenticated against the installed device app. The local node
UTXO check does not establish independent peer synchronization.

## Two-path signing simulation

At 2026-09-27T13:25:36-04:00 (2026-09-27T17:25:36Z), the C23 review test
constructed a synthetic v4 spend of two separately hash-bound previous
outputs. Distinct generated secp256k1 test keys represented the external and
internal Blue paths. The host ownership planner classified both inputs;
the simulated device derived and returned ordered ZIP-243 digests after
reviewing every output and calculating the fee; one final approval enabled
two ECDSA signatures. The host verified each signature against its expected
public-key hash and digest, then assembled and parsed both input scripts.
The focused test and complete Ledger suite passed 34/34 under Clang 22.1.6
Debug ASan/UBSan and 34/34 under GCC 16.1.1 Release on an AMD Ryzen 7 PRO
8840U. The C23 complexity ratchet passed 60,918 functions at cap 15.
The previous wires are synthetic, the device is simulated, and no transaction
was saved or broadcast. Physical BOLOS execution, verified chain provenance,
installed-image authentication, and Sapling signing remain unverified.

## Sapling device memory gate

At 2026-09-27T13:27:19-04:00 (2026-09-27T17:27:19Z), Clang 22.1.6 compiled
an ISO C23 size probe with `-Wall -Wextra -Werror -pedantic` against the Z23
Sapling field header. It measured `struct fr` and `struct fs` at 32 bytes
each and `struct jub_point` at 128 bytes. The current C23 RedJubjub source
allocates six static Jubjub generators, or 768 bytes before its initialized
flag and other signer state. The independently built Wallet 0.3.2 ELF has
5,476 bytes of `.bss` in a 6,144-byte Blue SRAM region, including its
2,048-byte stack reservation, leaving 668 bytes. Adding the existing six
generator array unmodified would exceed the region by at least 100 bytes.
Even one 128-byte static generator would leave only 540 bytes, or 28 bytes
above the current 512-byte margin gate before other Sapling state.

This excludes direct reuse of the current six-generator storage layout in
Wallet 0.3.2. It does not measure a minimal signer, stack depth, execution
time, or any Blue crypto primitive. The next experiment is an isolated C23
SpendAuth-only RedJubjub implementation with one generator, host vectors
from Z23's existing shielded spend tests, ARM stack usage, and two clean SDK
image builds. No device Sapling key or signing APDU should be enabled until
the transaction, note, outputs, value balance, memo policy, and nonce source
can be verified within the measured limits.

At 2026-09-27T13:31:19-04:00 (2026-09-27T17:31:19Z), ARM GCC 16.2.0
compiled the existing Jubjub scalar reduction source for Cortex-M3 with
ISO C23, `-Wall -Wextra -Werror -pedantic`; its isolated object contained
2,888 bytes of `.text` and no `.bss`. The same compiler rejected the
existing `fr.c` field arithmetic because this 32-bit target does not support
its `unsigned __int128` spelling. A temporary, uncommitted replacement of
that spelling with ISO C23 `unsigned _BitInt(128)` compiled and found
`__mulbitint3` in the toolchain's `libgcc`. Its isolated object contained
6,840 bytes of `.text`, 40 bytes of `.bss`, and 208 bytes of `.rodata`.
The compiler's `.su` file measured a 2,368-byte static frame for the
existing 16-entry-table `jub_scalar_mul`, above Wallet's 2,048-byte stack
reservation before its caller frames. These are object measurements, not a
linked signer image or a timing/security validation of the temporary
conversion. A device signer needs both portable field arithmetic and a
measured constant-time scalar multiplication with a smaller stack footprint.

## Isolated low-memory Jubjub candidate

At 2026-09-27T13:39:03-04:00 (2026-09-27T17:39:03Z), a C23 scalar
multiplication candidate used one accumulator and one sum point, with 256
unconditional double/add/select rounds and no precomputed table. It is an
isolated host test target and has no device key, app command, or Sapling
signature route. The differential test compared compressed results against
Z23's existing `jub_scalar_mul` for zero, all-one, lowest-bit, and
highest-bit scalars, then 64 deterministic scalars on each of three points.
It also checked result/input aliasing and null arguments. Clang 22.1.6
Debug ASan/UBSan and GCC 16.1.1 Release passed the full Ledger suite, 35/35
tests each, on an AMD Ryzen 7 PRO 8840U. The Debug test target uses `-O2`
because the existing x86 field assembly cannot compile at Clang `-O0` due
to register pressure; sanitizers remain enabled for this target.
The staged-source C23 complexity ratchet passed 60,928 functions at cap 15.

ARM GCC 16.2.0 compiled the isolated primitive for Cortex-M3 with ISO C23,
`-Wall -Wextra -Werror -pedantic -O2`, producing 404 bytes of `.text`, zero
`.bss`, and a 352-byte static frame. ARM Clang 22.1.6 produced a 312-byte
static frame. Manual inspection of the GCC object found branches for null
arguments and public loop bounds, with bitwise selection rather than a
branch on each scalar bit. This does not prove constant-time execution:
the existing `fr_add`, `fr_sub`, and `fr_neg` called by Jubjub arithmetic
branch on field values, and the isolated frame excludes their call depth.
The current host test also uses x86 field acceleration. The primitive must
not process secret scalars until portable Cortex-M3 field arithmetic has
been made constant-time, tested against independent vectors, checked in
target assembly, and measured as one linked signing path.

## Portable field candidate

At 2026-09-27T13:47:42-04:00 (2026-09-27T17:47:42Z), an isolated C23
eight-limb, 32-bit Montgomery field candidate implemented add, subtract,
negate, and multiply for canonical BLS12-381 scalar-field elements in Z23's
existing Montgomery representation. It has no device key, signing command,
or connection to the Jubjub candidate. A deterministic differential test
compared each result to the existing Z23 field implementation for zero,
one, modulus minus one, 4,096 random operand pairs, equal operands, and
both output/input alias directions. The Clang 22.1.6 Debug ASan/UBSan and
GCC 16.1.1 Release Ledger suites each passed 36/36 on an AMD Ryzen 7 PRO
8840U. The test target uses `-O2` with sanitizers because the reference
x86 field assembly fails at Clang `-O0` from register pressure. The staged
C23 complexity ratchet passed 60,942 functions at cap 15.

ARM GCC 16.2.0 compiled the candidate for Cortex-M3 under ISO C23 with
`-Wall -Wextra -Werror -pedantic -O2`: 840 bytes `.text`, 32 bytes
`.rodata`, zero `.bss`, and a largest static function frame of 288 bytes.
ARM Clang 22.1.6 compiled it with a largest frame of 156 bytes. Manual ARM
GCC and Clang disassembly inspection found loop and public-index branches;
no data-dependent branch was identified in the selection or field loops.
This is not a constant-time proof or a device signing result. The test
reference uses x86 acceleration, no Cortex-M3 executable or linked Jubjub
path ran, and target multiplication timing was not measured. Independent
field vectors, architecture-level timing, and linked stack/image checks
remain required before processing any secret device scalar.

## Combined portable Jubjub arithmetic path

At 2026-09-27T13:50:19-04:00 (2026-09-27T17:50:19Z), the isolated
fixed-iteration scalar loop switched from Z23's variable-time field
functions to the 32-bit field candidate through local Jubjub identity,
addition, and doubling functions. Its differential test still matched
Z23's scalar multiplication on four edge scalars and 64 deterministic
scalars across three points. The full Ledger suite passed 36/36 under
Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release on an AMD Ryzen 7
PRO 8840U. The staged C23 complexity ratchet passed 60,945 functions at
cap 15.

ARM GCC 16.2.0 compiled all three arithmetic objects for Cortex-M3 with
ISO C23 and `-Wall -Wextra -Werror -pedantic -O2`. A relocatable partial
link measured 1,700 bytes `.text`, 96 bytes `.rodata`, and zero `.bss`.
The largest named static call path was 352 bytes for scalar multiplication,
344 for Jubjub addition, and 288 for field multiplication, or 984 bytes
before `memcpy`, `memset`, callers, and BOLOS frames. The partial link still
references `memcpy` and `memset`; it is not a Blue app image. No ARM code
was executed, no independent SpendAuth vector was checked, and neither
target timing nor physical stack use was measured. Secret keys remain
excluded from this candidate.

At 2026-09-27T13:53:38-04:00 (2026-09-27T17:53:38Z), explicit volatile
wipes were added to the field and Jubjub intermediate arrays after their
last use. The focused field and scalar tests and both complete Ledger
suites passed 36/36 under Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1
Release on an AMD Ryzen 7 PRO 8840U. ARM GCC 16.2.0 still compiled the
three-object Cortex-M3 partial link with zero `.bss`; its `.text` grew from
1,700 to 2,288 bytes. The largest named path grew from 984 to 1,024 bytes
(352 scalar + 368 point addition + 304 field multiplication), excluding
`memcpy`, `memset`, callers, and BOLOS. The staged C23 complexity ratchet
passed 60,947 functions at cap 15. The wipes cover named C temporaries;
they do not establish that registers or firmware buffers are cleared.

## SpendAuth generator vector

At 2026-09-27T13:57:44-04:00 (2026-09-27T17:57:44Z), a temporary ISO
C23 probe used Z23's BLAKE2s and Jubjub code to derive the fixed Sapling
SpendingKey generator. It hashed the 64 ASCII bytes
`096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0`
followed by one counter byte under the eight-byte personalization
`Zcash_G_`, decoded the hash as a Jubjub point, multiplied by the cofactor,
and rejected the identity. Counter 2 was the first accepted point; its
compressed little-endian form was
`30b5f2aaad325630bcdddbce4d67656d05fd1cc2d037bb5375b6e96d9e01a1d7`.
The probe was compiled with GCC 16.1.1, `-std=c23 -O2 -Wall -Wextra
-Werror -pedantic`, and existing Z23 C23 arithmetic, BLAKE2s, logging,
and cleanse objects on an AMD Ryzen 7 PRO 8840U.

The Blue arithmetic test decoded that fixed point, multiplied it by the
recorded `ask` from `tests/harness/src/test_sapling.c`, and compared the
compressed result to the same file's expected `ak` vector. Both values
were converted from that test's displayed big-endian hex to little-endian
bytes. The focused test and both complete Ledger suites passed 36/36 under
Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release. The staged C23
complexity ratchet passed 60,949 functions at cap 15. This verifies public
SpendAuth multiplication against a known vector, not a signature, target
timing, or Blue execution.

## Shared Fr and Fs Montgomery core

At 2026-09-27T14:01:48-04:00 (2026-09-27T18:01:48Z), the isolated field
candidate moved its eight-limb C23 arithmetic into one modulus-parameterized
core. Thin wrappers retain Fr's Montgomery representation and implement
raw Fs multiplication through the existing two-step Montgomery conversion
using Fs `R²`. A new differential test compared Fs add, subtract, negate,
and multiply with Z23's existing Fs routines on zero, one, modulus minus
one, 4,096 deterministic operand pairs, equal operands, and both alias
directions. The Fr differential test and SpendAuth multiplication vector
still pass. Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release each
passed the full 37/37 Ledger CMake suite on an AMD Ryzen 7 PRO 8840U.
The staged-source C23 complexity ratchet passed 60,961 functions at cap 15.

ARM GCC 16.2.0 compiled the shared core and Fs wrapper for Cortex-M3 with
ISO C23, `-Wall -Wextra -Werror -pedantic -O2`. The shared core measured
1,188 bytes `.text`, zero `.bss`, and a maximum 320-byte function frame;
the Fs wrapper measured 112 bytes `.text`, 72 bytes `.rodata`, zero `.bss`,
and a 48-byte `blue_fs_mul_ct` frame. The refactored Fr/Jubjub partial link
measured 2,388 bytes `.text`, 104 bytes `.rodata`, and zero `.bss`. Its
largest named stack path is 352 + 368 + 320 = 1,040 bytes before library,
caller, or firmware frames. ARM Clang 22.1.6 also compiled the shared core,
but produced 8,514 bytes `.text` and a 424-byte maximum function frame at
`-O2`; this compiler-size difference remains a target-build decision.
Manual disassembly inspection identified no secret-dependent branch in the
shared arithmetic, but target timing, independent scalar-field vectors,
RedJubjub signature vectors, and a complete linked Blue image remain
unverified. These primitives remain disconnected from device keys.

## Public RedJubjub signing equation

At 2026-09-27T14:04:43-04:00 (2026-09-27T18:04:43Z), an isolated host
test combined the portable SpendAuth point multiplication and Fs
arithmetic for three fixed public triples of signing scalar, nonce scalar,
and challenge scalar. It computed `vk = sk·G`, `R = r·G`, and
`S = r + c·sk mod Fs`, then checked `S·G = R + c·vk` using Z23's separate
Jubjub implementation. Altering one bit of `S` broke equality in each
case. The fixed generator bytes are shared with the existing `ask` to `ak`
test. Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release passed the
complete 38/38 Ledger suite on an AMD Ryzen 7 PRO 8840U. The staged C23
complexity ratchet passed 60,963 functions at cap 15.

This test covers the algebra used by RedJubjub signing. It does not derive
`c` from a message and `R`/`vk`, generate a safe nonce, prove the seed-derived
SpendAuth key path, test malformed signatures, execute ARM code, or sign on
the Blue. The test exposes no signing APDU and uses only public constants.

## Host fixture crypto dependency reduction

At 2026-09-27T16:44:23-04:00 (2026-09-27T20:44:23Z), the transparent
fixture CLI and address encoder replaced host OpenSSL calls with Z23's
C23 SHA-256 and RIPEMD-160 implementations and libsecp256k1 public-key
parsing and ECDSA verification. A differential signing test generated a
signature with OpenSSL, verified it through both paths, compared the
HASH160 values, and rejected a changed digest. Both complete Ledger suites
passed 47/47 under Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release
on an AMD Ryzen 7 PRO 8840U. `ldd` on the GCC fixture executable showed
only libc and the ELF loader; it did not link `libcrypto`.
The staged C23 complexity ratchet passed 61,311 functions at cap 15.

The host still links the repository's integrity-locked
`vendor/lib/libsecp256k1.a`. Its manifest records an unresolved original
source import, so this result removes an OpenSSL runtime dependency but
does not establish source provenance for every linked host crypto byte.
The test's OpenSSL reference remains a development-only differential check.
No physical Blue payment signing or chain spend was performed.

## Rejected isolated SpendAuth signature cleanup

At 2026-09-27T16:48:08-04:00 (2026-09-27T20:48:08Z), the isolated C23
SpendAuth signer began clearing a non-null 64-byte signature output when
an input is missing or an entropy/scalar check fails. Previously a rejected
call left any earlier signature bytes in the caller's output buffer.
The host test checked zero entropy, a zero secret, and a null secret after
preloading the output. The Cortex-M3 QEMU fixture checked zero entropy
after a successful fixed signature. Both focused tests passed under Clang
22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release; the ARM image compiled
with GCC 16.2.0 in ISO C23 mode and passed under QEMU. The behavior is
isolated from BOLOS keys and USB, so it does not establish physical Blue
Sapling signing or a completed shielded payment flow.
The staged complexity ratchet passed 61,311 functions at cap 15.

## Isolated ZIP32 master expanded key on Cortex M3

At 2026-09-27T16:54:55-04:00 (2026-09-27T20:54:55Z), a C23 routine
derived master Sapling `ask`, `nsk`, and `ovk` from a 32-byte synthetic
seed using ZIP32's BLAKE2b personalizations and Jubjub scalar reduction.
All three fields matched the existing Z23 reference vector for seed bytes
`00` through `1f` on the host and in Cortex-M3 QEMU. A missing seed cleared
the entire output. The first ARM build measured 1,564 bytes of stack for
the ZIP32 case and failed the 1,536-byte test gate. Removing a redundant
96-byte temporary reduced the case to 1,468 bytes; the suite peak remained
1,500 bytes, leaving 548 bytes of its 2 KiB test stack. The focused host
and QEMU tests passed under Clang 22.1.6 Debug ASan/UBSan, GCC 16.1.1
Release, and ARM GCC 16.2.0 ISO C23 on an AMD Ryzen 7 PRO 8840U.
The shared `jubjub_to_scalar` reducer now performs volatile C23 stores over
its secret accumulator before returning. ARM disassembly of the QEMU image
shows the resulting byte-store loop before the function epilogue. Both
complete Ledger suites passed 48/48 after this change under the same host
compilers, and the QEMU ZIP32 and suite stack peaks remained 1,468 and
1,500 bytes respectively. This establishes the named stack object's wipe,
not a guarantee about register copies or firmware memory.
The staged C23 complexity ratchet passed 61,316 functions at cap 15.

The fixture supplies a public seed. This result does not select a Ledger
seed derivation path, establish recovery compatibility with a Z23 wallet,
derive ZIP32 children or a Sapling address, or execute inside BOLOS. It
does not link keys to transaction authorization or establish device timing.

At 2026-09-27T17:03:33-04:00 (2026-09-27T21:03:33Z), the same isolated
path produced the complete ZIP32 master record. Host and Cortex-M3 QEMU
fixtures matched the existing Z23 vector for depth, parent tag, child
index, expanded spending key, chain code, and diversifier key. A missing
seed cleared the complete record. The QEMU ZIP32 case measured 1,332 bytes
of the 2 KiB test stack, and the overall suite peak remained 1,500 bytes.
The record is still derived only from a public fixture seed; no BOLOS seed
path, ZIP32 child account, or address has been verified.
Both complete Ledger suites passed 48/48 under Clang 22.1.6 Debug
ASan/UBSan and GCC 16.1.1 Release. The staged C23 complexity ratchet
passed 61,319 functions at cap 15.

## Full viewing key projection on Cortex M3

At 2026-09-27T17:18:43-04:00 (2026-09-27T21:18:43Z), the isolated C23
path projected a synthetic master expanded spending key to `ak`, `nk`, and
`ovk`, then calculated its ZIP32 full-viewing-key parent fingerprint tag.
The host compared `ak` and `nk` with Z23's independently linked Sapling
implementation and matched the existing `0x3a71c214` master fingerprint
vector. Cortex-M3 QEMU checked the same tag and both fixed generator
encodings. The separate viewing-key case measured 1,500 bytes
of its 2 KiB test stack, leaving 548 bytes; its 96-byte viewing-key output
was held in test BSS and wiped after comparison. This does not measure a
complete BOLOS app image or its USB and screen frames.

The first candidate failed the fingerprint vector and measured 1,620
bytes of stack. Diagnosis showed that its generator probe hashed the
human-readable name `ProofGenerationKey` as the group-hash tag. Z23's
fixed-generator specification uses an empty tag with the `Zcash_H_`
personalization. Repeating the source derivation with that tag produced
the reference proof generator encoding
`e7e85de0f7f97a46d249a1f5ea51df50cc48490f8401c9de7a2adf1807d1b6d4`.
The corrected constant, a bounded BSS output, and separate QEMU cases
passed the focused host and ARM tests. A ZIP32 child account, recoverable
Blue seed path, and physical Sapling signature remain unverified.
Both complete Ledger suites passed 48/48 under Clang 22.1.6 Debug
ASan/UBSan and GCC 16.1.1 Release. The staged C23 complexity ratchet
passed 61,324 functions at cap 15.

## ZIP32 child derivation and bounded ARM stack

At 2026-09-27T17:34:21-04:00 (2026-09-27T21:34:21Z), an isolated C23
implementation derived normal child index 1 and hardened grandchild index
`0x80000002` from the public seed `00` through `1f`. Host tests compared
depth, parent fingerprint, child index, chain code, `ask`, `nsk`, `ovk`, and
`dk` byte for byte with Z23's independently linked ZIP32 implementation.
They also checked cleared scratch, null-parent failure, and rejected aliases.
Cortex-M3 QEMU checked both child paths and their parent fingerprints and
spending scalars. The emulator test keeps parent, child, and scratch in bounded
RAM and wipes them after comparison. The child case and suite peak measured
1,476 bytes of the 2,048-byte test stack, leaving 572 bytes. The first child
candidate measured 1,836 bytes and failed the 1,536-byte gate. Reusing the
full viewing-key buffer for the child root, holding test records in bounded
RAM, and removing a redundant Jubjub point accumulator brought the measured
peak below the gate. The scalar multiplication alias branch retains its
existing regression test. ARM GCC 16.2.0 compiled the C23 emulator image.

Both complete Ledger suites passed 48/48 under Clang 22.1.6 Debug
ASan/UBSan and GCC 16.1.1 Release. This verifies synthetic ZIP32 derivation
on a Cortex-M3 CPU model. The Wallet has no BOLOS seed access, child-key APDU,
Sapling signing command, or physical shielded spend verification.

At 2026-09-27T17:37:37-04:00 (2026-09-27T21:37:37Z), the host signed a
fixed 32-byte digest with the synthetic normal child's `ask`. Z23's
independent public Jubjub verifier accepted the signature against the child
`ak` and rejected the same signature for a changed digest. Cortex-M3 QEMU
derived that child, signed the same digest with fixed public fixture entropy,
and matched the host's complete 64-byte signature. The QEMU case and suite
peak measured 1,468 bytes; focused Clang and GCC tests passed. This is an
isolated SpendAuth equation check using public test material. No approved
transaction digest or BOLOS-protected child key was involved.

At 2026-09-27T17:43:12-04:00 (2026-09-27T21:43:12Z), the child-key test
used the ZIP243 shielded digest computed by Z23 from its synthetic Sapling-v4
transaction fixture. The host matched the known digest, signed it with the
normal child `ask`, and verified the signature with the independently derived
child `ak`. Changing one byte in the transaction changed the digest and made
the original signature fail public verification. Cortex-M3 QEMU matched the
resulting complete signature against the host vector while retaining a
1,468-byte stack peak. The device still does not parse, review, approve, or
sign a shielded transaction with protected keys.

## Ledger-specific Sapling seed bridge

At 2026-09-27T17:51:53-04:00 (2026-09-27T21:51:53Z), inspection of the
pinned Ledger Blue SDK 2.1 header found `os_perso_derive_node_bip32` and
`os_perso_derive_node_bip32_seed_key`, which return BIP32 node material.
The inspected header did not expose a raw BIP39 seed read. A C23 candidate
therefore maps the device-protected secp256k1 node at `m/32'/147'/0'` to a
32-byte ZIP32 input by BLAKE2b-256 with the 16-byte personalization
`Z23BlueSaplingV1` over `private_key[32] || chain_code[32]`. This is a
Ledger-specific account derivation, distinct from standard ZIP32 directly
over wallet seed bytes. Both input buffers and the mapped root share a
64-byte workspace that is wiped before and after each use. The candidate
BOLOS adapter checks PIN validation before invoking the syscall and never
formats node bytes as an APDU response.

Python 3 `hashlib.blake2b` independently produced
`2d267685b11436269583fd90cf71a413fe25c46a9d670a069f4ce752bba34e1e`
for synthetic node bytes `00` through `3f`; the host test matched the
complete mapped ZIP32 master record against the same root supplied directly
to Z23's master routine. It rejected a locked PIN without invoking the mock
syscall and cleared a partial node after a source failure. Cortex-M3 QEMU
matched the same master record, measured 1,388 bytes for its bridge case,
and retained the 1,468-byte suite peak. The adapter also compiled against
the pinned Blue SDK with Clang in ARMv6-M C23 mode. The existing Wallet
0.3.3 image and stack gate still build with this candidate outside its
auto-linked `src` directory. Both complete host suites passed 48/48 under
Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release.

BOLOS has not been called by this candidate on physical hardware. The
actual device node, recovery behavior, BOLOS exception cleanup, Wallet RAM
integration, transaction approval, and Sapling signing APDU remain unverified.

## Randomized Sapling spend authorization equation

At 2026-09-27T18:03:45-04:00 (2026-09-27T22:03:45Z), the isolated signing
candidate added the Sapling spend randomizer required by Z23's prover:
`rsk = ask + ar (mod Fs)` and `rk = rsk * SpendAuthSig.G`. The device-side
candidate parses both scalars canonically, rejects zero `rsk`, computes
`rk` itself, compares it with the caller-supplied expected `rk` in fixed work,
and only then calls the existing entropy-seeded RedJubjub signer. It clears
the signature, scalar, and 128-byte caller workspace on normal failure.
The transaction digest and `rk` still need device-side transaction parsing
and user approval before this primitive can be reached in Wallet.

The host test mapped synthetic BIP32 node bytes `00` through `3f` into the
Ledger-specific ZIP32 root, derived hardened child `0x80000000`, calculated
the synthetic Sapling-v4 ZIP243 digest, and computed `rk` independently as
`ak + ar * G` using Z23's public Jubjub implementation with `ar = 7`.
It verified the complete resulting signature and rejected a changed `rk`,
noncanonical `ar`, and `ar = -ask`, all with zero signature output. The
Cortex-M3 QEMU case followed the same root-to-signature path and matched the
host's 64-byte signature. Its bridge case and suite peak measured 1,492
bytes of the 2,048-byte test stack, leaving 556 bytes. Clang also compiled
the signer for the Blue's ARMv6-M target in ISO C23 mode. The code uses
public fixture secrets only and has no BOLOS key, APDU, screen, or approval
route. It has not produced a Sapling transaction on physical hardware.

## Device-parsed spend key bound to shielded replay

At 2026-09-27T18:15:10-04:00 (2026-09-27T22:15:10Z), the bounded C23
six-pass ZIP243 replay gained an optional indexed Sapling spend `rk` capture.
It reads the 32 bytes at offset 96 of the selected 384-byte spend item
(`cv`, anchor, and nullifier precede `rk`). The captured bytes remain
provisional until the full-wire SHA-256 matches across all six uploads and
the final ZIP243 digest succeeds. The replay clears provisional `rk` on
invalid spend index, later-pass substitution, short upload, or explicit
abort. On success it detaches the caller-owned verified `rk` before clearing
replay state. A synthetic two-spend wire checked index 1 independently of
index 0. One-spend fixtures passed with 1-byte and 220-byte upload chunks.

A host integration test patched the synthetic transaction's spend `rk` to
match the independently calculated randomized child key, captured that
exact `rk` through the six-pass parser, and signed only the resulting
device-derived ZIP243 digest. Z23's independent public Jubjub verifier
accepted the signature. Cortex-M3 QEMU matched its fixed signature vector
with a 1,492-byte suite stack peak. The replay state measured 568 bytes
and the read-only APDU controller 656 bytes on the host, within their
576-byte and 672-byte compile-time limits. Both sources compiled for the
Blue ARMv6-M target; the existing Blue Review image and stack gate built.
That image does not yet invoke indexed capture or any signing command.
The synthetic spend proof is arbitrary and is not a valid chain payment.

The actual Blue Shielded Review 0.5.1 image also rebuilt from two separate
pinned SDK checkouts at `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`.
The clean builds produced byte-identical 26,112-byte `.text` images with
SHA-256 `877b78747b4f57364292aa4d70bf7af56a0ac9424d4a28f56770e64eb4e60197`.
The installer allows this hash under its 0.5.1 read-only profile while
retaining the earlier 0.5.0 image profile. A no-device installer test
advanced the exact 0.5.1 image to CA-key loading; a one-byte substitution
was rejected by the SHA-256 allowlist before key loading or USB access.
The ELF built from the second SDK has `.text` 26,112 bytes, `.data` zero,
and `.bss` 4,312 bytes including its 2,048-byte stack reservation. Its largest
modeled finish path of 816 bytes. Its ELF SHA-256 was
`6ae5a49caaa0621c83f7e95789970d434401bcbe8ddb04788a5bcecb26b15651`.
The image still calls the plain read-only replay entry point, so these
measurements do not prove an on-device rk capture or signing flow. Both
complete Ledger suites passed 48/48 under Clang 22.1.6 Debug ASan/UBSan
and GCC 16.1.1 Release. The staged C23 complexity ratchet passed at cap 15.

At 2026-09-27T18:27:31-04:00 (2026-09-27T22:27:31Z), the C23 Blue
shielded-review app simulator exercised interruption after each of its six
complete upload passes. Odd passes ended with a malformed finish APDU;
even passes used the app reset path. Each case left the transaction and
cached 76-byte summary fully erased, returned the screen to `CONNECT Z23`,
and rejected a stale finish. A new six-pass review succeeded after those
interruptions. The simulator then rejected the transparent signing opcode
`29` after review and erased that review. The focused app test passed under
Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release. These reset and APDU
tests do not reproduce Blue power loss or physical USB timing.

The captured spend `rk` was also changed at byte 7 on each later replay
pass, two through six. Each altered full transaction parsed structurally,
but the replay rejected its changed SHA-256 commitment and erased the
provisional `rk`. The targeted stream test passed under the same Clang and
GCC builds. This checks a signing-relevant wire field rather than relying
only on a substitution elsewhere in the transaction.

## Current-main integration candidate

At 2026-09-27T18:34:58-04:00 (2026-09-27T22:34:58Z), the complete local
Blue batch through `ddb6b5fde` was applied in an isolated worktree based on
`origin/main` `3c752c513af6266c590e78b979b293882ce76815`. A read-only
merge preview identified twelve content-conflicted files. Each conflict
retained the newer Blue behavior while preserving nonconflicting main
changes; an automatically combined UI test contained a duplicate
`expect_pixels` helper, which was removed. This integration produced a
158-file staged candidate. The Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1
Release Ledger suites each passed 48/48, including Cortex-M3 QEMU. The
actual Shielded Review 0.5.1 image rebuilt with the pinned SDK and retained
the exact `.text` SHA-256
`877b78747b4f57364292aa4d70bf7af56a0ac9424d4a28f56770e64eb4e60197`.
The C23 complexity ratchet passed with 62,884 functions at cap 15. The
candidate is not installed on physical hardware, and these host checks do
not establish safe payment signing.
The repository `lint-fast` gate passed all 33 checks after this integration.

## Consensus-verified Sapling spend replay

At 2026-09-27T19:23:42-04:00 (2026-09-27T23:23:42Z), Z23's strict
`groth16_selfverify` group passed with no failures in 58.1 seconds. The
native C23 prover built Spend and Output proofs that the independent
consensus verifier accepted. The deterministic
`simnet_sapling_shielded_send` group then passed with no failures in
146.3 seconds. Its public seed `c0dec0dec0dec0de` produced a 1,425-byte
z-to-z transaction containing one Sapling spend and one output. The real
`contextual_check_transaction` verifier accepted that transaction under
branch `76b809bb`. The core ZIP243 sighash was
`d4967a8269007709fd063a592f7359b864fa390c76f4609dc9f9b96069c27c8b`.
Its funding exists only in the simulated chain; the wire is not a public-chain
payment.

The export flag `ZCL_BLUE_EXPORT_SAPLING_WIRE=1` emits the public test wire
only after consensus acceptance and fails if proving parameters are absent
or verification rejects it. The exported bytes are recorded in
`apps/zcl-ledger/tests/fixtures/simnet-sapling-spend.hex`. Clang 22.1.6
Debug ASan/UBSan tests replayed those bytes over the Blue's six-pass APDU
simulator and through the indexed spend-`rk` parser. Both agreed with the
core sighash, the parsed one-spend/one-output counts, and the serialized
spend's `rk` at byte offset 123; both focused tests passed. The simulator
also displayed the shielded count and digest page, toggled large text and
dark mode, then reset to `CONNECT Z23`. The full Ledger suite passed 48/48
under Clang 22.1.6 Debug ASan/UBSan and 48/48 under GCC 16.1.1 Release,
including Cortex-M3 QEMU. This validates transaction parsing and digest
agreement using a consensus-accepted fixture.
The final strict simulator rerun passed with no failures in 182.3 seconds;
its exported transaction bytes matched the committed fixture exactly.
The Blue image remains read-only and has no device approval or signing route.

At 2026-09-27T19:41:20-04:00 (2026-09-27T23:41:20Z), the same strict
simulator export reproduced the committed wire and recorded `ask` and `ar`
only with the additional `ZCL_BLUE_EXPORT_TEST_KEYS=1` flag. These keys are
derived from the public simulator seed and have no hardware or public-chain
funds. The fixed C23 fixture records their `rk`, the core digest, and the
Blue signer's deterministic 64-byte signature. A host test replays the
consensus-accepted wire, verifies Z23's original spend signature, signs the
same digest with the Blue primitive, verifies the new signature, rejects a
changed digest and mismatched `rk`, and checks signature zeroization on
failure. The focused Clang Debug ASan/UBSan test passed. Cortex-M3 QEMU
reproduced the 64-byte signature; this case used 1,460 bytes of its 2,048-byte
test stack, while the suite peak remained 1,492 bytes. The full Ledger suites
passed 48/48 with Clang 22.1.6 Debug ASan/UBSan and 48/48 with GCC 16.1.1
Release; the C23 complexity ratchet passed at cap 15. This exercises the
signing primitive with real simulated Sapling proof bytes and does not add a
signing APDU or physical approval flow to the installed Blue image.

## Shielded Review 0.5.2 output label

At 2026-09-27T19:52:21-04:00 (2026-09-27T23:52:21Z), the public output
amount label changed from `OUTPUTS` to `PUB OUT`. The prior label could be
read as including a shielded output; the new text distinguishes the public
amount from the separate Sapling output count. A maximum `21,000,000 ZCL`
value fits the 32-byte line buffer and rendered in both normal and large
dark screens. The C23 screen simulator produced 41 frames from the
consensus-accepted Sapling fixture; the summary and large-text pages were
visually inspected. Its font renderer approximates Blue BAGL pixels.

Two independent C23 builds with the patched Blue SDK at
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff` produced byte-identical
26,112-byte `.text` images with SHA-256
`8d37f0de33408ce3d6e72012163646908b8978e3fd88e19d7aa92d08460f085b`.
The build host was an AMD Ryzen 7 PRO 8840U using Clang 22.1.6 and ARM
GCC 16.2.0.
The ELF has zero initialized `.data` and 4,312 bytes of `.bss`, including
the 2,048-byte reserved stack. The modeled finish path remains 816 bytes.
The 0.5.2 read-only installer profile accepted the exact image through its
hash gate to the deliberately absent CA-key check; it rejected a one-byte
altered image before key loading or USB access. This version was not
installed on a physical Blue.
The complete Ledger suites passed 48/48 under Clang 22.1.6 Debug
ASan/UBSan and 48/48 under GCC 16.1.1 Release, including Cortex-M3 QEMU.
The two simulator-only fixture export flags were registered in the closed
flag catalog. The local `lint-fast` gate then passed all 33 checks.
The Clang 22.1.6 review-only CMake profile built without OpenSSL. Its
`zcl-blue-shielded-review --simulate` command matched the 1,425-byte
consensus-accepted fixture's one spend, one output, and core ZIP243 digest;
`ldd` reported no `libcrypto` or `libssl` dependency. This host simulation
did not connect to the Blue.

## Shielded review APDU interaction fuzzing

At 2026-09-27T20:09:14-04:00 (2026-09-28T00:09:14Z), a C23 libFuzzer
harness exercised the read-only Blue Shielded Review controller under Clang
22.1.6 Debug ASan/UBSan. Its public synthetic one-spend/one-output fixture
seeds idle, begun, partially uploaded, and completed states. Fuzzed APDUs
vary command bytes, lengths, and reply capacities; each step can also change
the page, large-text mode, dark mode, or reset the app. Invariants check reply
buffer bounds, terminated screen lines, and complete zeroization of
transaction state and cached digest after rejected commands. The final
20,000-run corpus completed with zero sanitizer findings or invariant
failures, 9,391 covered edges, and 60 MiB peak resident memory. This
exercises parser and UI interactions; it does not validate cryptographic
proofs, a physical Blue screen, or a signing approval flow.
The local `lint-fast` gate passed 33/33 checks. The staged C23 complexity
ratchet passed 62,901 functions at cap 15. Focused Clang Debug ASan/UBSan
tests passed 5/5, including Cortex-M3 QEMU, the Shielded Review APDU and
client, and the screen simulator.

At 2026-09-27T20:13:55-04:00 (2026-09-28T00:13:55Z), the host Shielded
Review client injected a failed exchange at each of the 50 APDUs used to
replay the 1,425-byte one-spend/one-output fixture. Each position produced
one erase command, no active or completed device review, and zeroed host
facts and digest. The focused test passed under Clang 22.1.6 Debug
ASan/UBSan and GCC 16.1.1 Release. This tests simulated exchange failures;
it does not assert that a disconnected physical Blue received the erase.

At 2026-09-27T20:20:31-04:00 (2026-09-28T00:20:31Z), the same host test
substituted four response forms at each of the 50 exchanges: a truncated
reply, changed status, reported length above the receive capacity, and a
changed response-body byte. Each of the 200 cases failed closed, cleared
the host facts and digest, and sent one erase. Clang 22.1.6 Debug
ASan/UBSan and GCC 16.1.1 Release each passed the focused test. The
result validates the simulated response boundary, not physical USB timing.

## Sapling output recovery prerequisite

At 2026-09-27T20:34:25-04:00 (2026-09-28T00:34:25Z), Z23's strict
`simnet_sapling_shielded_send` group passed with zero failures using the
exact staged C23 source. After building and independently verifying the
one-spend/one-output z-to-z transaction, the simulator derived the outgoing
cipher key from its public-seed test `ovk`, authenticated the 80-byte
outgoing ciphertext, recovered the recipient key and ephemeral secret,
checked the ephemeral public key, authenticated the 580-byte note
ciphertext, and confirmed the diversifier, 99,990,000-zat value, absent
memo marker, and note commitment. Changed outgoing and note authentication
tags, commitment, and expected amount were rejected. The exported
1,425-byte wire remained byte-identical to the committed fixture, with
SHA-256 `683cec314305410a0d90146856ea503dffc1c74a8e01d6fa89eff79403cd2216`.
The optional test-key export now includes `ovk`, diversifier, and recipient
key from the same public simulator seed. This is host reference evidence for
future device output review; the physical Blue app does not decrypt outputs
or sign Sapling transactions.
The staged C23 complexity ratchet passed 62,907 functions at cap 15, and
`lint-fast` passed 33/33 checks.

## Isolated outgoing-key derivation

At 2026-09-27T20:41:49-04:00 (2026-09-28T00:41:49Z), a C23
`blue_sapling_ock` module derived the Sapling outgoing cipher key from the
consensus fixture's public-seed test `ovk`, value commitment, note
commitment, and ephemeral key. Its 32-byte result matched
`d95384f81b92c907c1327986cb66b76542837372595ea05fffec206d4d4440bb`,
calculated independently with BLAKE2b-256 personalization
`Zcash_Derive_ock`. A changed value commitment changed the key; failed
hash finalization and a missing hasher cleared the result. The focused test
passed under Clang 22.1.6 Debug ASan/UBSan and GCC 16.1.1 Release. The
Cortex-M3 C23 object compiled with ARM GCC 16.2.0 at `-Os`: 160 bytes of
`.text`, no `.data` or `.bss`, and 32 bytes of static frame use for this
wrapper. Those figures exclude the BLAKE2b callback and its context.
The host test binary had no dynamic OpenSSL link. This module is isolated;
the physical Blue app still has no Sapling output decryption or signing.
The staged C23 complexity ratchet passed 62,913 functions at cap 15.

## Isolated Sapling note-key derivation

At 2026-09-27T21:07:38-04:00 (2026-09-28T01:07:38Z), C23
`blue_sapling_kdf` derived the note cipher key from a supplied 32-byte DH
result and output ephemeral public key. For DH bytes `00..1f` and epk bytes
`80..9f`, the result was
`b13acd7ce408edc68b210012b8b63e1d48d5255bd61b28e12b7c39fa4383f427`.
Python's `hashlib.blake2b` with 32-byte output and personalization
`Zcash_SaplingKDF` independently matched that result. Altering either input
changed the key; a failed hash finalization and a missing hasher cleared the
output. The focused test passed under Clang 22.1.6 Debug ASan/UBSan and GCC
16.1.1 Release. ARM GCC 16.2.0 compiled the Cortex-M3 C23 object at `-Os`:
132 bytes of `.text`, no `.data` or `.bss`, and 24 bytes of static frame use.
These measurements exclude the BLAKE2b callback and its context. The module
is not linked into the physical Blue image and does not authenticate the DH
result, decrypt a note, display a recipient, or authorize signing.

## Wallet 0.3.4 account check before ECDSA

At 2026-09-27T21:18:39-04:00 (2026-09-28T01:18:39Z), inspection of the
transparent Wallet signer found that its BOLOS callback signed a ZIP-243
digest before the portable wrapper checked the returned public key against
the selected account HASH160. Wallet 0.3.4 passes the two hashes derived at
app startup to the callback and requires the selected key's HASH160 to match
before calling `cx_ecdsa_sign`. A host SDK shim verifies that a mismatched
account hash, failed public-key hash, or missing binding produces zero signing
calls and an empty result; valid external and internal paths each sign once.
The full Ledger CTest suite passed 49/49 under both Clang 22.1.6 Debug
ASan/UBSan and GCC 16.1.1 Release on an AMD Ryzen 7 PRO 8840U. The staged
C23 complexity ratchet passed 62,918 functions at cap 15.

Two clean Blue SDK C23 builds at revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`, each with the reviewed
patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`,
produced byte-identical 41,472-byte `.text` images with SHA-256
`e6c158621a68bbf30ae92a7223fe151aa9d57fd184466b0c6537c0cf39c5bf6a`.
The image has zero initialized `.data` and 5,476 bytes `.bss` including the
2,048-byte stack reserve. The stack gate reports a 736-byte named public-hash
signing path and excludes BOLOS firmware frames. The installer accepted the
exact image through hash validation to its intentionally missing CA-key
error. Changing byte 100 from `95` to `ff` caused rejection at the image
hash gate before CA-key loading or Blue USB access. This is offline evidence;
Wallet 0.3.4 has not been installed or tested on a physical Blue. The app
still cannot verify chain inclusion, the active branch, or account policy.
