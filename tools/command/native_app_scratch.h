/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Retained private directory for one owned app networking worker. */
#ifndef ZCL_NATIVE_APP_SCRATCH_H
#define ZCL_NATIVE_APP_SCRATCH_H
#define AG_PATH 4400u
#if !defined(_WIN32)
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
/* Copy a terminated string within capacity; allow_empty controls whether an empty string is valid. */
bool an_scratch_copy_text(char *out, size_t cap, const char *text, bool allow_empty);
/* Exact bounded read: retry EINTR, reject EOF and other errors. */
bool an_scratch_read_exact(int fd, uint8_t *bytes, size_t n);
/* Canonical decimal, no leading zeros, bounded by max. */
bool an_scratch_decimal(const char *s, uint64_t max, uint64_t *out);
struct an_scratch {
    int parent, root;
    char anchor[AG_PATH], leaf[48], path[AG_PATH];
    dev_t dev; ino_t ino; bool created;
};
bool an_scratch_bound(const struct an_scratch *);
bool an_scratch_create(struct an_scratch *, const char *anchor, const char *token);
bool an_scratch_cleanup(struct an_scratch *, bool child_reaped);
#endif
#endif
