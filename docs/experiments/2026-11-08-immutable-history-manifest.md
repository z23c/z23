<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Immutable history manifest

2026-11-08. Base: `cbfc58c7bafd4396950d0b4884a35eecdd94de2e`.

The immutable manifest builder accepts an explicitly immutable private tree and
an exact contiguous block-file count. It rejects incomplete or unexpected block
inventories, reserved indices, oversized output and unreadable inputs. It hashes
files in 64 KiB buffers and returns no partial manifest on refusal. This API
does not publish files or establish chain authority; Windows returns refusal.

<!-- claim: symbol-present file_controller_build_immutable_manifest engine/controllers/src/file_controller.c # immutable manifest builder -->

On Linux, `devbuild --wait make t-fast-exact ONLY=file_controller` passed one
cold group with no skips. Log SHA-256:
`ad3e963edd5cd6a7ca9e3d2f7deea355e626011f742a9145f7ef338fb0615703`.
An initial `make lint-fast` returned failure when its precheck scanned generated
paths and reported a derived buffer overflow. With `ZCL_LINT_PRODUCTION_SCAN=1`,
`devbuild --wait make lint-fast` passed all fast gates and precheck; log SHA-256:
`07977680d522ee345c07887a885b526c761cf5977d7b6c5acd43d331dceac88b`.
The production scan independently covered 2,115 in-scope headers and definitions.
Full lint, landing proof, serving integration and device qualification remain
pending.
