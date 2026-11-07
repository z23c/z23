<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Absent app log paths in the strict build

The release test build at `60958bd181` failed before running tests. GCC 14 with fortified libc headers diagnosed a possibly null path passed to `open` after inlining the resident-launch wait path. That path supplies a file descriptor and no pathname; the shared wait helper also supports a pathname fallback.

The pathname reader now returns false immediately when no pathname is supplied. Valid pathname reads and descriptor-based readiness checks retain their behavior. Compiler diagnostics remain enabled.

On 2026-11-07, the strict `app_launch` group passed cold with no skips after this guard was added on base `3f614a6de6`. The group exercises resident launch success and refusal. The same strict build had previously failed at the unchecked pathname reader.

```sh
devbuild --wait --project z23 --class normal \
  make test-parallel TEST_PARALLEL_ARGS=--exact=test_app_launch
```
