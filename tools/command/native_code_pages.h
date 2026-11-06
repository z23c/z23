/* purpose: Declare the native code pages import and read commands. */
/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_NATIVE_CODE_PAGES_H
#define ZCL_NATIVE_CODE_PAGES_H
#include <stdbool.h>
/* Resolves a directory tree from an exact commit; never observes worktree bytes. */
bool zcl_code_pages_subject(const char *repo, const char *commit,
                            const char *directory, char tree[65]);
#endif
