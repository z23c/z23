<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Verified action input to component lookup key

Date: 2026-09-25T03:36:00Z. Host: AMD Ryzen 7 PRO 8840U. Compiler:
GCC 16.1.1 20260430, C23. Source roots:

| File | SHA-256 |
| --- | --- |
| `contexts/commons/modules/vcs/src/zcode_action_input.c` | `803b574c048f802208e44f4fe58ca34d8762eb12cca6786c34012ac9f73f869b` |
| `contexts/commons/modules/vcs/include/vcs/zcode_action_input.h` | `b933ea25a9de6b3fcb2f6d0cf49e789fc8b8cb29f7038db7cf98fe4584ccdcea` |
| `tests/harness/src/test_zcode_dev_objects.c` | `328639ae1628f54078c05aed2d9c61b6657910565b276e24de225247148aa3ed` |
| `docs/CAPABILITY_INVENTORY.jsonl` | `ce40e103f9c0ec4c98bb3d6cd41883250be808505ccd403f684387d4ece36c49` |

The candidate-bound action input root contains task and candidate identity.
It therefore cannot identify an otherwise identical component computation in
another action. The new `zcl.zcode.component_input_key.v1` lookup key excludes
task, candidate, action, producer, verdict and time. It binds the
CAS-verified candidate source tree, adapter policy, dependency lock, accepted
test recipe, payload blob and path, work kind, and caller-supplied execution
closure: toolchain, compiler, flags, environment, build graph, harness, proof
and sandbox policies, policy generation, target and resource limits. The
derivation refuses missing roots, limits beyond the task, or a toolchain or
proof policy different from the task.

The caller must derive and independently verify the supplied execution roots.
This key is a lookup hint. An equal key does not authorize artifact reuse,
receipt projection, DEV acceptance, publication, or deployment. The receiver
must still verify artifact bytes, signed observations, policy generation,
freshness, required independent trust domains, all receiver-known conflicts,
and a separately bound receipt for the requested action. No local index, peer
query, transfer, or acceptance path uses this key yet.

Focused registered acceptance, after the final source refactor:

```bash
make CC=gcc -j4 t-fast ONLY=zcode_dev_objects \
  > test-tmp/component-input-key-final.log 2>&1
make CC=gcc check-cyclomatic-complexity
make CC=gcc docs-capability-inventory
make CC=gcc check-capability-inventory-generated
make CC=gcc -j4 lint-fast
git diff --check
```

The focused group passed 1/1 with zero skips and no cached group. Its log
SHA-256 is
`1a3fb07a8833a276103981bffcfc966dc5bb9f85dd0b58035d5d6bf45826fbdf`.
The test checks stable repeat derivation, changed policy generation, absent
environment root and changed payload bytes. The complexity gate passed across
57,289 functions in 4,262 files with the existing cap of 15. The first
pre-refactor focused run also passed 1/1; its log SHA-256 was
`7959209099fd49853565cbbe54d22c6527da82aa75295b861e9e581f5ef38cd6`.
The full first command took 264.302 s and the final incremental command
104.421 s under concurrent full proof load; those are build/test wall times,
not lookup latency or reusable-computation speedups. During the build, a
one-second `vmstat` sample showed zero idle CPU and about 1.3 GiB free RAM;
no node-health causal claim follows from that sample.
The generated inventory check passed after regeneration; its log SHA-256 is
`8854b342b12f5eeae4617ced02e9b36af026e7a89f807a0e1079f8985977e3fc`.
Lint-fast passed 32/32; its log SHA-256 is
`08ae54bc0a0d1f5046a943f5618fba101b0e6a1b3fb2656a23ecd6490e61f599`.

The prior executable duplicate-dispatch counterexample remains in
`2026-09-25-component-input-duplicate.md`: two distinct action roots with
equal input produced two dispatchable jobs. This key alone does not prevent
those jobs. The next acceptance requires a receiver-owned lookup over signed
observation roots, exact closure verification and an attached action with its
own bound result receipt. Its tests must keep eligible PASS/FAIL conflict
visible, refuse stale and wrong-domain receipts, and count physical jobs and
network payload bytes under repeat, worker death and partition.
