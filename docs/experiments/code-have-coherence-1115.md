<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
<!-- claim: symbol-present codeindex_capability_confidence cognition/modules/codeindex/src/codeindex_capability.c # capability evidence confidence -->

# Capability query coherence

On 2026-11-15, the capability query `peer observation database repair` returned a high-confidence `ALREADY EXISTS` result whose matched symbols addressed distinct concerns. The query combines lexical evidence at a file anchor; that combination alone does not establish a single matching capability.

High confidence now requires all query terms in one symbol with its file purpose and path, or in that file context alone. It also requires recorded callers of coherent symbol witnesses. Ranking and aggregate caller counts are unchanged. Results expose `coherent_terms_matched` and `coherent_used_by_files` separately. This is lexical evidence and a recorded caller count, not proof of behavior.

The registered `code_have` fixture exercises unrelated matching symbols with three real callers, an uncalled coherent symbol beside called unrelated symbols, and a called coherent symbol. The first two cannot assert `ALREADY EXISTS`; the last can. The existing live-capability positive and warm-cache checks remain. The initial red run also exposed a test-buffer reuse error; an intermediate bounded-witness approach failed the existing live validation positive and was replaced by a complete witness query.

Validation uses `DEVBUILD_CLASS=normal devbuild --wait make -j28 t-fast-exact ONLY=code_have T_FAST_EXACT_ARGS="--no-cache"` on GCC 14.2.0 and an AMD Ryzen 9 7950X3D. Separate retained logs record failed and passing runs.

Caller evidence uses the same declaring-header ownership and include-guard eligibility as the symbol scan. The synthetic paired header and implementation fixture checks that an implementation cannot borrow callers of a header-owned symbol. Caller references are indexed by name, so identically named distinct symbols remain an attribution limit.
