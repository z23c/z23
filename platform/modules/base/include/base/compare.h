/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: shared qsort comparators for foundation and tool code. */
#ifndef ZCL_BASE_COMPARE_H
#define ZCL_BASE_COMPARE_H

#include <stdint.h>

/* qsort comparator ordering int64_t values ascending. Subtraction-free, so
 * extreme values never overflow. */
static inline int zcl_cmp_i64(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

#endif /* ZCL_BASE_COMPARE_H */
