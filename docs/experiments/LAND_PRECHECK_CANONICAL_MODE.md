<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Canonical file-purpose mode during intake

The native landing precheck invoked the file-purpose checker directly. Its
default WARN mode can report a new violation while returning success. The
canonical lint runner instead selects RATCHET for that gate.

The proposed intake path reads the supported runner command table with
Bash and its existing --print-command interface, validates the bounded
single-line command with the existing shell, then executes it in the
candidate worktree. Discovery, validation and execution share the existing
precheck deadline. Production scanning is enabled only for that child;
the canonical command selects RATCHET without changing the parent mode.

Missing, empty, failed, oversized or malformed command metadata refuses
intake before a queue row is appended. No Make target, prerequisite build,
worker verdict API or additional mode registry is introduced. Other gates
retain their existing invocation and missing-input behavior. Windows
retains the existing unavailable-precheck refusal.

The proposed registered fixture uses the actual file-purpose checker and
unchanged canonical command table: a missing-purpose source first succeeds
under raw WARN, then refuses native intake; its repaired control queues.
Additional fixture cases reject unavailable or malformed metadata.
A thread-local test-only budget override exercises a slow reader and a
reader followed by a command that exceeds the shared remainder. Both cases
require timeout refusal, no queue row and no completion marker. The
production budget remains 180000 ms; no public setting is added.

## Observed qualification

On 2026-10-27 the actual registered shard passed all 51 selected scenarios:
one group ran, with zero failures, skips, unobserved or load-flaky results.
The three new cases passed: the phase-marked shared deadline, the actual checker's
WARN success followed by canonical refusal and repaired control, and
unavailable or malformed command metadata. The focused command was:

~~~sh
make -j28 t-fast ONLY=dev_land_shard_02
~~~

The tested production source, header and test identities were:

~~~text
production 1637e0b9e23e6800c1e25d6791fc8f8b1d169a33
header     2702c35879e944c57d2e53103a43cde90b6d98c1
test       c90bf39af39cca566084ecb6cc15c712090db5ae
~~~

The focused log SHA-256 was
11750d0bca22fecadc1c203e87a88e8caf9fa41a9df29173ea33ef18514c525b.

An initial fixture advertised the checker but omitted the historical
failed-gate selection input. Its deadline assertion failed in both runner
attempts; its later WARN/control and metadata cases did not run. The
fixture repair seeds the native selection input and requires the exact
refusing gate and successful control's executed-gate receipt. Production
source and header were unchanged by that repair.

The failed first and retry transcript SHA-256 identities were:

~~~text
first 8cbd8387eeb86dd1678599409567dd7416bb75f31878ddd4b16e854704dd32eb
retry 455f3543a73f277033cbf4f04264db0df5104e545c7fb6eebc48670f56bc06d7
~~~

The canonical purpose, architecture and documentation checks passed before
the test-only repair. Complexity and file-size checks passed again for the
repaired test. The passing runner reported test_body_ms=146560, covering
the complete selected shard invocation rather than an isolated case.
The admitted repaired batch, including checks and compilation, recorded
zero queue wait, 241 seconds runtime, 1389 MiB peak memory and 65 CPU
seconds. It used GCC 14.2.0 on an AMD Ryzen 9 7950X3D. These observations
do not establish a speedup or Windows runtime qualification.

Native exact-candidate full proof and landing remain pending.
