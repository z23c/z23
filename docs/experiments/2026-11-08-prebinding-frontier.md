<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Prebinding frontier restoration

A startup-only restore can recover an in-memory chain view from coherent
proven coins and served-frontier evidence. It rechecks the authority generation
and both frontier identities before publishing the view. The operation requires
an already validated full ancestry and initialized genesis; it performs no
persistent writes or wallet mutation. Empty genesis and sparse islands are not
supported by this path.

On a candidate based on `ff411f677a3b193b5b3f159f62aec37ffe94183c`,
`make t-fast ONLY=recovery_no_worse` passed without skips. Its isolated fixture
exercised distinct served and coins heights, stale generation, failed ancestry,
CSR refusal and an unverified runtime-genesis fallback. It read two headers for
a matching best header and three for a one-header extension. These fixture
counts are not phone startup latency measurements; cold map loading and
clean-genesis recovery need independent qualification.
