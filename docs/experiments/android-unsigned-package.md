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
