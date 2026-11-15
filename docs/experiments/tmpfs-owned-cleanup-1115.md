<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
<!-- claim: symbol-present tmpfs_cleanup tests/harness/src/test_parallel.c # runner-owned scratch cleanup -->

# Runner scratch ownership

A runner removes its own successful scratch root and retains its failed or otherwise retained root. It does not retire another run's root at startup. An unlocked, old directory does not establish that its owner has stopped or that retained evidence is disposable.

A private tmpfs and PID namespace isolated the baseline experiment from host scratch. At base `845c403fa983eebc1cb851128aabb37224830d2c`, the selector regression failed its foreign-root preservation assertion on both attempts. Existing inherited-root and early-exit own-root checks passed. One selected group failed with zero self-skips, unobserved environments or load-flaky groups. The private baseline root was archived; no host-wide deletion was exercised. The final patched run passed one group with zero failures, self-skips, unobserved environments or load-flaky groups in 57.6 seconds.

The lifetime lock remains for compatibility with older runners that scan scratch roots; it grants no authority to retire another run's evidence.

The baseline test-only diff SHA256 was `f987e97f8b00a13bfa688c3e6242b6b41eb697c278010651c256ccb74425c276`. The focused command was `make -j2 t-fast-exact ONLY=test_group_selector T_FAST_EXACT_ARGS=--no-cache` under light admission, with private tmpfs, PID and network namespaces. An intermediate patched complexity check passed; full candidate gates were not run. The 2026-11-15 host used GCC 14.2.0 on AMD Ryzen 9 7950X3D.
