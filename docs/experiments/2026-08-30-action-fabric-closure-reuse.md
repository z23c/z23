<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Action-fabric closure reuse and foreground-build failure

## Intent

Bind one candidate source closure to one canonical action identity, restore an
accepted action-bound output without executing a compiler, let proof assembly
reuse the same physical observation, and reconstruct the closure in an
independent checkout without translating it through another evidence model.

## Environment

- Local time: `2026-08-30T23:24:14-04:00`
- UTC time: `2026-08-31T03:24:14+00:00`
- Base commit: `58fd7084eb337911118902df69cd6800df64b1da`
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics, 16 logical CPUs
- Compiler: GCC 16.1.1 20260430 through `build/bin/zcc`
- Caller-reported token count: not derivable from the build or test tools

## Result

The changed C23 translation units compiled with the repository's test-fast
profile. The generated capability inventory and file-size policy passed. The
capability-closure self-test passed 10/10; the repository-wide scan was
unproven because the pre-existing development epoch lacked three unrelated
objects: `os_sandbox_stub.o`, `test_thread_qos.o`, and `rebuild_recent.o`.

The exact focused suite did not run. Both native and legacy object backends
reached the link step while declared response-file objects were absent. The
native attempt ended after 45.095 seconds with 537 of 3,141 response-file
objects present and 2,604 absent. The legacy attempt ended after 44.559
seconds with the same class of missing-object link failure. No test verdict is
claimed.

The failure establishes a coordinator ordering defect rather than a source
compile defect: a previous interrupted build leaves the epoch marked
unverified; a later session quarantines that generation after Make has already
classified its object targets as present. The linker then consumes the fixed
response file against the replacement, incomplete generation. Retrying the
foreground gate is not an acceptable development workflow.

## Commands

```bash
make docs-capability-inventory
make check-capability-inventory-generated check-file-size-ceiling
make check-capability-closure
make -j8 t-fast-exact \
  ONLY='test_build_fabric,test_zcode_dev_objects,test_zcode_store'
make -j16 ZCL_OBJECT_BACKEND=legacy t-fast-exact \
  ONLY='test_build_fabric,test_zcode_dev_objects,test_zcode_store'
```

## Next experiment

Move admission to a resident commit promoter. Agent handoff must only persist
the signed commit and enqueue its exact source identity. A private coordinator
must acquire one generation, validate the complete object manifest before
linking, materialize immutable child receipts, and promote the commit only
after the aggregate receipt exists. Foreground `pre-push` must perform only
ancestry and exact-receipt lookup.
