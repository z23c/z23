/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SHARE_MEDIA_H
#define ZAPP_SHARE_MEDIA_H
#include <stdbool.h>

#define SHARE_MEDIA_MAX 32

static inline bool media_count_valid(int count) { return count > 0 && count <= SHARE_MEDIA_MAX; }
static inline int merge_media_kind(int kind, int current)
{
    if (current == 0 || kind == 3) return 3;
    if (kind == 0) return current;
    return kind == current ? kind : 3;
}
#endif
