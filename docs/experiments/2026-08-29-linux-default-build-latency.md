<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Linux default-build latency

## Intent

Make the documented bare `make` entry point perform exactly the same work as
`make z23`. A default node build must not fingerprint unrelated compiler
profiles or import their dependency graphs.

## Environment

- Local date: `2026-08-29` (`America/Puerto_Rico`)
- UTC date: `2026-08-30`
- CPU: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics
- Logical CPUs: 16
- Memory: 64,444,460 KiB
- Compiler: GCC 16.1.1 20260430

## Method

Build the node to a stable epoch, then time unchanged invocations with the
bash `time` builtin. Compare bare `make -j16` with explicit `make -j16 z23`.
The resulting binary source identifier must be identical. Run
`make check-dev-loop-profiles` to retain the non-LTO development boundaries.

## Baseline

An unchanged bare build took 17.996 seconds. An unchanged explicit `z23`
build took 8.209 seconds. The bare spelling selected the same default target
but conservatively fingerprinted every build profile and imported every
profile's dependency graph.

## Result

After one required rebuild into the changed build-system epoch, two unchanged
bare builds took 11.375 and 9.580 seconds. The immediately following explicit
`make -j16 z23` took 9.836 seconds. All three reported the identical binary
source prefix `667606eb9600`.

The stable warm comparison is 17.996 to 9.580 seconds: 8.416 seconds removed,
or 46.8%. The change removes no source, compiler, dependency, epoch, or
post-build verification. It makes the empty spelling inherit the already
declared `z23` default when choosing dependency and compiler-profile scope;
mixed and unknown explicit goals retain the conservative all-profile path.
