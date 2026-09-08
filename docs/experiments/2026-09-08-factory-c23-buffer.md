<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Package-factory mutable diagnostic buffer

The full publication prebuild for `a5c1d961d58406d77a8b761d2191d04ac9c97eed`
exposed a C23 compile error in `pf_cli_report_exit_error`: `strchr` preserved
the const qualification of its argument, but the helper assigned that result
to a mutable pointer and truncated the reply at its first newline.

The helper's only caller supplies an owned mutable allocation and frees it
immediately after reporting the failure. Its parameter now declares that
existing mutability. Formatting, ownership, and execution logic are unchanged;
no cast or diagnostic suppression was introduced.

On 2026-09-08T03:13:47-04:00 / 2026-09-08T07:13:47+00:00, GCC 16.1.1
20260430 on x86_64 Linux rebuilt the tool successfully with the existing
`-std=c23 -O2 -Wall -Wextra -Werror -pedantic` target:

```bash
make -j4 build/bin/package-factory
```

The usage path also returned its documented argument-error status of 2.
This is compile and startup evidence, not a package-publication acceptance
claim. The earlier full prebuild was stopped after preserving its compiler
failure; it did not produce a passing publication receipt.
