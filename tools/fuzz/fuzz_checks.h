/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: The check the wire-decoder fuzz targets share. A decode error must
 * leave its output zeroed, so a caller that reads it anyway sees nothing. */

#ifndef ZCL_FUZZ_CHECKS_H
#define ZCL_FUZZ_CHECKS_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static inline void require_zeroed(const void *out, size_t len)
{
    const uint8_t *p = out;
    for (size_t i = 0; i < len; i++)
        if (p[i] != 0)
            abort();
}

#endif
