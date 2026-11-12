/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Build the ordinary C23 node at the Linux ABI floor. */

#ifndef ZCL_C23_PORTABLE_RELEASE_H
#define ZCL_C23_PORTABLE_RELEASE_H

/* 0 when before, after, and baked are the same 64 lowercase hex digits.
 * 1, with a c23-portable-release: line on stderr, otherwise. */
int zcl_c23_portable_release_verify(const char *before, const char *after,
                                    const char *baked);

/* selftest non-zero runs the source-epoch selftest and ignores repo.
 * Otherwise repo is the checkout whose portable sysroot tool and
 * tools/scripts drive the release. Returns 0 after the PASS line. */
int zcl_c23_portable_release(const char *repo, int selftest);

#endif
