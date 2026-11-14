<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Android unsigned package acceptance

On 2026-11-14, the `aligned-apk` target was exercised with Android NDK r30,
API 35 and a separate build directory. The application source was based on
`6fab082699c0a328de0dd9aea956f9482c893705`; the packaged node was built from
`4fcd8da60c28bcb6060e03b6baf1f829af09e6e8`. This is a packaging check, not a
same-source release or device deployment.

The aligned APK SHA-256 was
`a74354fcfdadfb8e89d53913fa4de51fbf4865653c6a709e32d64577c37cfeda`.
Its packaged node matched the input SHA-256
`a1a9a98541117562688fd0fa91871f8d3fb70d50202156e433c2a7d80f939ad2`,
and both packaged parameter hashes matched their checked inputs. The Android
build configured `Z23_DEVKEY_PROBE=OFF` and `ZAPP_SHARE_FIXTURE=OFF`.
`zipalign -c -P 16 4` passed; `apksigner verify` refused the unsigned APK.
No keystore or signed APK was created by the unsigned target.

A missing node and missing parameters each refused without an aligned output.
The `apk` target produced a verified signed APK using an isolated disposable
fixture key. A deliberately wrong `EXPECTED_SIGNER_SHA256` refused after
creating the signed fixture APK, matching the existing signer-check order.
No installation or deployment was tested.

## Native command smoke

The native plan, prepare and status commands were exercised on 2026-11-14
with application source `e12eea17c8de9014502e2c6c8fa7052163720fcd` and the
node from `4fcd8da60c28bcb6060e03b6baf1f829af09e6e8`. The unsigned APK
SHA-256 was `9223422168b6c3a14641740331bf99e558d8a62ba01e9605db095f9b0fe35dab`.
The package name, alignment and embedded node hash were independently checked;
the node hash matched `a1a9a98541117562688fd0fa91871f8d3fb70d50202156e433c2a7d80f939ad2`.
Focused command tests passed three groups with no skips; the vendor-input
repair passed its focused group with no skips. The plan took 595 ms against
its 250 ms budget and status took 1494 ms against its 900 ms budget. These are
observed budget misses, not total build duration. No deployment was performed.

## Native APK verification

On 2026-11-14, candidate `6037fd999b3985d32af6cb1e4dd0a9808fe76e5d`
verified an existing unsigned APK with SHA-256
`f09b01d79c69e8050b1cf518edd025303e245567811d849716b3718770bba997`.
The package name, 16 KiB alignment and embedded node hash passed; the node
hash matched
`a1a9a98541117562688fd0fa91871f8d3fb70d50202156e433c2a7d80f939ad2`.
The command did not check a signature or establish node source provenance.

A real ZIP fixture exercised status-to-verify input serialization and
successful verification. Wrong package, failed alignment, changed APK hash,
missing node, wrong node bytes and duplicate node entries were refused.
The focused command, registry and API groups passed with no skips. The wider
35-group candidate proof passed with one load-flaky retry in a checkout
fixture; its first failure was retained. Candidate full lint passed 223 of
224 checks and identified an undeclared status input read; that finding was
repaired in the shared status observation path.
