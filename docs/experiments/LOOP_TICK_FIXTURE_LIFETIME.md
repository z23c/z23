<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Loop tick fixture worker ownership

The slow-gate fixture previously launched background shell writers and
returned their log paths before the writers published results. Foreground
capture completion did not establish the background producers' continued
lifetime. The fixture now keeps its delayed producers in a C23 worker
thread owned by the test case.

Fake gates publish checked atomic requests and advertise the same log
paths. The worker validates each bounded request, waits one second using
monotonic time, then checks a temporary-file write and atomic rename.
The case requests stop and joins the worker before returning; failures
include operation and path context. Normal fast gates, every original
assertion, the ten-second gate wait and the 120-second tool timeout remain
unchanged.

The claim-finish assertion also has a failure-only diagnostic: actual exit
status, captured byte count, conservative saturation indicator and merged
output bounded by the existing 8192-byte buffer. It does not infer timeout
classification or root cause from the exit status.

## Qualification

On 2026-10-27, the actual registered route passed one group with zero
failures, skips, unobserved or load-flaky results:

~~~sh
make -j28 t-fast ONLY=loop_tick
~~~

The tested source blob was d595b098dd1abb6c01a66538e175e54da59e28a8.
The focused transcript SHA-256 was
1a284814e415e60a5b35f34ec05130d0e5eae1f86314361b41ec98c550c2b2fa.
The runner reported test_body_ms=81025 for the complete group invocation,
not an isolated claim case. Canonical complexity, file-size, wall-clock
assertion and real-clock deadline checks passed without baseline,
threshold or exception changes. GCC 14.2.0 and an AMD Ryzen 9 7950X3D were
recorded. No speedup is claimed.

Two isolated fixture controls retained the same actual finish path and
unchanged assertion. Each registered invocation failed as intended in both
the initial attempt and native isolated retry; separate qualification
checks verified the actual diagnostic fields and exact expected failures:

| Control | Actual result in both attempts | Verified failure evidence |
| --- | --- | --- |
| Existing claim-refusal file | rc=1, 307 captured bytes, saturation=0 | Original finish assertion and three consequent claim assertions fail; refusal output retained. |
| Generated submit response changed once from sequence 7 to 8 | rc=0, 345 captured bytes, saturation=0 | Only the original finish assertion fails; actual submitted sequence 8 output retained. |

The worker start and joined-stop checks passed in every control attempt.
The exact tested source was restored after each control. Complete frozen
proof-dependency donor manifests compared equal before and after normal
qualification and both controls.

Control transcript SHA-256 identities were:

~~~text
claim first 5de51d76caba1e2aeb947a50541971e6b223f211968c0cc44025d35b0f8e75f0
claim retry b55e721da2dee049ca3ca7e09bb67ad3f3ffe3d593c344cf62956431c8906cc1
seq8 first  dfce93e3a61fb4a7257651139f07882042af0c7cc5065e48de90a0492a976037
seq8 retry  371d759938e5948fe06fa0755dfe83fc90b4ceb2889d4f4518f206aa69f9bffb
~~~

## Historical limits

Before the worker change, a sequence-control first attempt demonstrated the
rc=0 diagnostic, but its native retry encountered missing gate logs and
the existing gate wait. That aggregate control qualification failed. The
immediate missing-log condition was observed; the producer's exit cause
was not recovered.

One later traced observation of the diagnostic-only source passed. Its
two relevant fake-gate background writers slept, published rc=0 logs and
exited normally; no relevant SIGKILL sender was observed. Tracing can
perturb timing. This success neither establishes a historical signal cause
nor disproves the unsupported lifetime assumption removed by this change.
The earlier train failure's cause remains UNKNOWN.

Native exact-candidate full proof and landing remain pending.
