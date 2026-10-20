<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Qualifier test-worker cap: 2026-10-20

## Behavior and source

The qualifier already propagated an explicit admitted Make cap, but its focused
runner could still inherit a larger `T_FAST_EXACT_ARGS` worker count. The
additive correction preserves inherited arguments and appends the admitted
worker cap as a Make command-line assignment. For example, inherited
`--no-cache --jobs=28` under an explicit cap of four ends with `--jobs=4`.
Without an explicit cap, the existing Makefile/environment default remains
unchanged. Arguments that exceed the bounded construction buffer refuse
before test execution rather than being truncated.

<!-- claim: symbol-present dlq_test_args tools/command/native_dev_land_qualify.c -->
<!-- claim: symbol-present test_dev_land_qualify_job_caps tests/harness/src/test_dev_land.c -->

This 817 additive slice uses signed 827 source
`d5be3f3d53fe266a43e9bc7f0fa3b5e766c1aab0` as its base. The original 817
proposal and 827 source history remain preserved. Canonical group IDs,
existing Make-cap propagation and seven-phase long-trace verification remain
included. This experiment records focused evidence, not landing.

Reviewed original patch SHA256:
`e478dcebe67e3a67e861313da439ce4363d2930794d8d11621a26c86d569e72d`.
Canonical two-source-file diff SHA256:
`303281d3f5d457e5e825f06e025999798cf73054bdf766f6229bb84fe35f750b`.
Qualifier SHA256:
`247929f63f2ee106e42cfefcf4bb89c5d2e29252930fb36b250e92b99d5437cb`.
Fixture SHA256:
`9c719d8f13d3b4b0bfa5e371b4f127cc1a52c0df15e298162bf85969e1f82dff`.

## Method and measured results

Observed platform: Linux, AMD Ryzen 9 7950X3D. Installed Clang 18.1.3 was
observed; the focused build compiler was not independently established from
quiet build output. Date: 2026-10-20.

Canonical complexity passed with 86,848 functions, 3,888 exact baseline pins
and cap 15; no pin changed. Focused execution used normal admission with an
8 GiB memory limit, actual CPU quota four, Make jobs four and four cold-runner
workers. Both phases used the exact registered `dev_land` group.

| Phase | Observation |
| --- | --- |
| RED | Build succeeded; three new job-argument assertions failed at fixture line 7447; one failed group, zero skips/UNOBSERVED/load-flaky |
| RED retry | One canonical automatic alone retry; total group wall 272.4 s; no manual retry |
| GREEN | Exact candidate restored; one cold group passed on its first attempt in 153.8 s; zero failures/skips/UNOBSERVED/load-flaky |
| GREEN admission | Wait 50.968 s; peak 659,849,216 bytes; zero limit-hit/OOM/OOM-kill events |

RED removed only the new goals-argument forwarding entry. It retained argument
construction, overflow refusal and the fixtures. Its mutation SHA256 is
`c1e9cdec047e8ce73211e42e77d9c1ba2e5f88195aed5e03200297890d4cad5c`.
The terminal retry log preserves the decisive assertion text; the runner
replaced the first detailed group file, so the first assertion text is not
independently retained beyond the first-failure marker.

GREEN covers explicit caps, inherited `--jobs=28` overridden by final
`--jobs=4`, uncapped defaults, 3,900-byte valid inherited arguments, bounded
overflow refusal and invalid caps. RED output SHA256:
`e664c6978307547750cb49af7170fd92aeddab7b2336acc003ae9c0358af2b7f`.
GREEN output SHA256:
`0cdda234e6988f38f4dc196cd6efe92c1d7c0c5897e1cf85a37490f6c3ece4f2`.

## Reproduction and limits

Through host admission with `ZCL_BUILD_MAX_JOBS=4`:

```sh
make -j4 t-fast-exact ONLY=dev_land \
  T_FAST_EXACT_ARGS='--no-cache --jobs=4'
```

The preserved local handoff holds complete commands, phase-specific source
hashes, resource counters and output. No private operational paths are
published here. Full native qualification, queue admission, landing, other
platforms and the separate future runner retry optimization are not established
by these focused results.
