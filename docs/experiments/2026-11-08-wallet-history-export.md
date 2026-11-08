<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Private wallet history export

Base: `9105face8a7795fb9020920c6f9676f9756ff67d` (landed isolated-index
dependency plus the reviewed manifest checkpoint).

The Linux exporter accepts an independently admitted endpoint and copies a
pinned index and the referenced block-file prefixes into private staging. It
validates header ancestry and every selected body hash and transaction Merkle
root, builds a complete file manifest, and publishes without replacement.
It does not establish chain authority or advertise the result. The caller owns
the staging namespace exclusively. An unknown publication outcome requires
reconciliation before cleanup. Cancellation is polled during copying and
between phases; archive validation and manifest hashing can delay it.

<!-- claim: symbol-present wallet_history_export_run engine/services/src/wallet_history_export.c # private history exporter -->

On Linux, the focused `wallet_history_export`, `zcode_release`,
`file_controller` and `block_index_loader` groups passed with no skips. Log
SHA-256: `63dc97180e17f8d7c4abe07e9a0fb6b1f7aadbb96a9a9bb1077d70e0c6945f85`.
A subsequent exporter-focused run passed after the probe registry changes; log
SHA-256: `a9e63b4b5aa51358c72067aa0dc2ee63fbcf95b39fa05f11ba1ba1ffdc70d602`.
Production-scan `make lint-fast` passed, including precheck; log SHA-256:
`2777cf97863c2aa209080d31e0ba70e9bfc9c61c7fe1128b8bdc08f0204042e8`.

A separate private fixture of public history at height 3309900 passed the
production exporter probe: 165 chunks, 7,429,442,226 bytes, manifest root
`f718d878c8564e5a3442a715baa1ad15374d7b8633b68481694d34e5de669ea6`,
370271 ms elapsed, 129483578 microseconds CPU and 2560724 KiB peak RSS.
The compiler was Ubuntu clang 18.1.3; CPU was AMD Ryzen 9 7950X3D; date was
2026-11-08. Source file metadata matched before and after; this is not a source
byte-hash comparison. Log SHA-256:
`2fa615bfb8eead50f5ca1338431e4473f61aa4b5f59532fef97256fbb369bac8`.

The optional test probe requires `ZCL_HISTORY_ARCHIVE_DIR`,
`ZCL_HISTORY_ARCHIVE_HASH`, `ZCL_HISTORY_ARCHIVE_HEIGHT`,
`ZCL_HISTORY_ARCHIVE_MAX_ROWS`, `ZCL_HISTORY_EXPORT_PARENT`,
`ZCL_HISTORY_EXPORT_STAGE`, `ZCL_HISTORY_EXPORT_DEST`,
`ZCL_HISTORY_EXPORT_MAX_BYTES` and `ZCL_HISTORY_EXPORT_MIN_FREE_BYTES`.
The runner `--timeout` is a silence watchdog, not a total wall deadline.
Published and unknown-outcome outputs are retained. Production serving, phone
qualification and landing remain pending.
