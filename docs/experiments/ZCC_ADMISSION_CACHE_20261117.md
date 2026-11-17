<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Admission unit and compiler cache

A controlled R1 light-class experiment on 2026-11-16T19:30:50Z compiled identical C23 source with a private zcc cache and changed only `DEVBUILD_UNIT`: probe-a, probe-b, probe-a. The results were MISS, MISS, HIT; all object SHA-256 values were `33de7ffa6fbd7c90585c67a930f6b6b0cddfd8b2c42eeecf54639ae2bdb74e01`. The compiler was Ubuntu GCC 14.2.0-4ubuntu2~24.04.1 on an AMD Ryzen 9 7950X3D. The experiment establishes a cache-key difference for this fixture, not production savings.

`DEVBUILD_UNIT` is admission bookkeeping. The compiler cache excludes this exact variable from both the compiler child environment and its cache key. Other compiler-visible variables remain keyed. The `check-zcc-cache` filtered-environment fixture checks child isolation, reuse across unit values and invalidation when a compiler-visible variable changes.
