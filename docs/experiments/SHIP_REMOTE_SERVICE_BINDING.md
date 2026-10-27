<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Remote shipping service binding

## Scope

A canonical node can retain the legacy `zclassic23.service` name while the
remote shipping transaction addresses `z23-node.service`. The compatibility
change selects one explicit remote service through `ZCL_SHIP_NODE_UNIT`.
The default remains `z23-node.service`. Local deployment is unchanged.

The isolated fixture executes the transaction embedded in `tools/ship.sh`
against a stand-in service manager and real temporary processes. It checks
legacy selection, reload and restart rollback, unchanged default behavior,
refusal of missing or ambiguous service bindings, and the pre-transfer
binding barrier. It does not activate or qualify a live node.

## Evidence

The source baseline was `d901abd198d31bd673caf4e7470130840750e93e`.
The registered gate ran through native admission:

```sh
DEVBUILD_CLASS=light devbuild --wait make -j2 check-ship-remote-transaction
```

The candidate passed with exit status 0. Its log SHA-256 was
`58a97eabacf56997c8c7e07e0bc7a77ef5ae3dc5eef9a8087287fc7003270f27`.

A single-line mutation replaced the remote activation program's assignment
`node_unit="${18:-z23-node.service}"` with
`node_unit="z23-node.service"`, ignoring the explicit legacy selection.
The fixture and documentation were unchanged. The same registered gate
failed with exit status 2 in the isolated transaction check; the preceding
shipping self-tests passed. The mutation log SHA-256 was
`71b4115deec557ae770d0849492e54f32f0ba7bb64da749ee68eb4defbab6f64`.
The fixture did not trace its internal failure line. A rejected read of the
forced service during the legacy transaction is inferred from the program
and fixture, rather than claimed as a traced observation.

After the mutation, the shipping source was restored and its Git blob
verified as `dbb5e8df3ed6befed845f1daeb831356b9c18718`. The fixture blob
remained `41c2f1350de86b75b5eb04fea08dce1660e7dd0e`, and the developer
manual blob remained `6a658e6a14a6f1448d03325b90dd6b46046ab4de`.

These results establish the isolated gate's sensitivity to the selected
service binding. They make no performance claim and do not establish live
activation, production health, or full candidate qualification.

## Native fixture control revision

The remote transaction gate retains the production shell programs extracted
from the candidate and the scenario assertions above. Its fixture-only
systemctl behavior, real node process, program extraction, release staging,
reset and cleanup are implemented in C23. Unit selection, fault injection and
binding state are passed in an isolated state file; they are not new public
environment flags.

The helper requires an owner-private physical fixture directory and marker
before filesystem cleanup or control-channel access. Each real fixture node
inherits a Unix-domain listening socket. Stop requests use that owned channel
and wait for endpoint EOF at node exit; recorded numeric PIDs are observation
data, never a stop authority. The actual target writes READY after exec and
before the controller publishes its PID. Startup failures settle and reap
the controller's direct child before returning failure. The existing gate
also repeats stop requests after its reset/restart scenarios.
No real system service or network endpoint is used.
<!-- claim: symbol-present owned_root tools/lint/ship_remote_fixture.c -->
<!-- claim: symbol-present stop_fixture tools/lint/ship_remote_fixture.c -->

The earlier runtime and mutation results identify the historical shell
fixture blob above. The portable revision has the separate Linux observations
below. The public service selector remains ZCL_SHIP_NODE_UNIT, defaulting
to z23-node.service and accepting only that service or zclassic23.service.

## Portable revision observations

On 2026-10-27, the unchanged production source
dbb5e8df3ed6befed845f1daeb831356b9c18718 passed
make -j2 check-ship-remote-transaction with the C23 fixture. The gate compiled
both fixture variants and passed the shipping self-tests and actual remote
program scenarios, including reset/restart, immutable identity, rollback,
legacy selection and repeated stops. The fixture script blob was
29d729a6f7f996680d1929c520bd6a4ba28a5ba5 and its C23 helper blob was
24fc24521df178eae175643339aa17d9e95e0748.

The same single-line binding mutation described above produced source blob
642f47dc567832b9dbe059ee2ce7137789ccef45. With the fixture and its
assertions unchanged, the same gate exited 2 in the actual transaction script;
the preceding shipping self-tests passed. The script did not log its internal
failure location. Failure at the positive legacy-service activation is inferred
from the sole production change and the fixture path, rather than reported
as a traced observation.

After the mutant run, the production source was restored to
dbb5e8df3ed6befed845f1daeb831356b9c18718. The fixture and helper hashes
above remained unchanged. Protected development inputs also matched their
before/after content and metadata snapshots. No additional GREEN run was
needed to qualify the identical restored source.

The fixture variants used GCC 14.2.0 with -std=c2x, -O0 or -O2,
-Wall, -Wextra and -Werror on an AMD Ryzen 9 7950X3D 16-Core Processor.
The observations are dated 2026-10-27.

Both invocations used light native admission and idle I/O. The GREEN receipt
recorded zero queue seconds, 102 run seconds, 156 MiB peak memory and 13 CPU
seconds; the mutant receipt recorded zero queue seconds, 83 run seconds,
155 MiB peak memory and 10 CPU seconds. These are separate observations,
not a performance comparison.

- Portable GREEN log SHA256:
  d82cf2e85193714a4f2b804e6351bae03dd3ac7afb2e7ef4744c72150f3b8617.
- Portable mutant log SHA256:
  65fc1c20aac68c996c7cd44b9f598c07a40f60bf290c32e5d412bc9cf71133ca.

This qualifies the portable revision on the observed Linux host only.
Darwin compilation and runtime remain NOTRUN; portable source review does
not replace that observation. No live activation, production health, full
candidate qualification or performance improvement is established here.
