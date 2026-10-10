<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Native train checkout root normalization

A train invoked without an explicit source root must create its stack beside
its Git checkout, including when invoked from a checkout subdirectory.
Build, check, status, and drop now resolve the selected source-root hint with
`git rev-parse --show-toplevel` and the platform canonical-directory API before
deriving stack paths. An invalid checkout root refuses before worktree mutation.

## Experiment

- Base: `a4af54d7f28d4a0560cf29e7e0c7e5d4ff180c0c`.
- Host: Linux x86_64, AMD Ryzen 9 7950X3D, GCC 14.2.0.
- Observation date: 2026-10-10; host local time zone UTC.
- Execution: installed native admission, normal profile, 28 make jobs.
- Fixture: temporary bare origin, main checkout, source clones, and real native
  handlers in the registered `dev_train` group. Fixture build targets are no-ops;
  this experiment does not qualify real dependency priming or Tor provenance.
- The original explicit-root controls remain unchanged. Added cases omit the
  context root, unset `ZCL_DEV_SOURCE_ROOT`, and run from the checkout root and
  a subdirectory. Each invocation restores the exact previous directory and
  environment before assertions. The cases check sibling placement, absence of
  a nested target, duplicate refusal, status visibility, and forced drop.

The test-only parent run compiled successfully and failed in the actual build
handler: returned `./z23-stackimplicit_root` differed from the expected absolute
checkout sibling. All preceding explicit-root controls passed. Canonical make
returned 2; the registered group failed without cache hits or skipped groups.
The parent log SHA-256 is
`489f87541e0c27a418fa9e4b1dc3ece4344962cb1f5cdd0e03ee6059b7f91ff6`.

The first repaired run passed both `dev_train` and `dev_train_keep` cold, but
failed the complexity ratchet because root-refusal guards increased existing
handler counts. Stack preparation and status enumeration were extracted into
small helpers; no threshold or compiler warning flag was weakened.

The revised production/test patch SHA-256 is
`057f558fb4c87aa4c88f76ef0b2bb3500e6369d6a5a5b6844131439ca3a6aa0c`.
Native admission job `1604648-78656078-1791624605513049178` completed
`agent-verify` with exit 0: complexity, both focused groups, generated capability
inventory, and lint-fast passed. Both groups ran cold, with zero cached, failed,
or skipped groups. This qualifies the isolated train fixture, not a production
runtime integration train.

Native admission job `1843686-78671789-1791624762620645510` completed
`lint-preflight` with exit 0. Its log SHA-256 is
`7153988bb9caff503d13a07d490e4b6c5c6c2d46e0f5cf33e626c55ca72daf7b`.
This is source/build preflight evidence, not runtime integration evidence.

## Reproduction

```sh
devbuild --wait --class normal make -j28 agent-verify ONLY=dev_train,dev_train_keep
devbuild --wait --class normal make -j28 lint-preflight
```

Logs and exact patch receipts are retained in the isolated lane's
`build/scratch/train-root-*` files. No production state was accessed; no proof,
push, deployment, or runtime integration train was performed by this experiment.
