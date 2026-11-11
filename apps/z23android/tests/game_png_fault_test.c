/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "util/png_writer.h"
#include "base/safe_alloc.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>
#ifdef ZCL_PNG_TEST_DIRECT_COMPRESS2
#undef compress2
extern int compress2(Bytef *, uLongf *, const Bytef *, uLong, int);
#endif

static bool fail_compress;
#ifdef ZCL_PNG_TEST_DIRECT_COMPRESS2
int png_fault_compress2(Bytef *dest, uLongf *dest_len, const Bytef *source, uLong source_len, int level)
{
    if (fail_compress) return Z_BUF_ERROR;
    return compress2(dest, dest_len, source, source_len, level);
}
#else
extern int __real_compress2(Bytef *, uLongf *, const Bytef *, uLong, int);
int __wrap_compress2(Bytef *dest, uLongf *dest_len, const Bytef *source, uLong source_len, int level)
{
    if (fail_compress) return Z_BUF_ERROR;
    return __real_compress2(dest, dest_len, source, source_len, level);
}
#endif
static void unchanged(const uint8_t *output, size_t n)
{
    for (size_t i = 0; i < n; ++i) assert(output[i] == 0xa5);
}
static void compression_failure_leaves_destination(void)
{
    static const uint8_t pixels[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    uint8_t output[128];
    fail_compress = true;
    size_t written = 123;
    assert(!png_encode_rgb(pixels, 2, 2, NULL, 0, &written));
    assert(written == 0);
    memset(output, 0xa5, sizeof(output));
    written = 123;
    assert(!png_encode_rgb(pixels, 2, 2, output, sizeof(output), &written));
    assert(written == 0);
    unchanged(output, sizeof(output));
    fail_compress = false;
}
static void encoding_failure_clears_written(void)
{
    static const uint8_t pixels[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    uint8_t output[82];
    memset(output, 0xa5, sizeof(output));
    size_t written = 123;
    zcl_alloc_fault_fail_next("png_filtered");
    assert(!png_encode_rgb(pixels, 2, 2, output, sizeof(output), &written));
    assert(written == 0);
    for (size_t i = 0; i < sizeof(output); ++i) assert(output[i] == 0xa5);
    zcl_alloc_fault_fail_next("png_filtered");
    written = 123;
    assert(!png_encode_rgb(pixels, 2, 2, NULL, 0, &written));
    assert(written == 0);
    zcl_alloc_fault_fail_next("png_idat");
    written = 123;
    assert(!png_encode_rgb(pixels, 2, 2, output, sizeof(output), &written));
    assert(written == 0);
    unchanged(output, sizeof(output));
    assert(!zcl_alloc_fault_armed_label());
}
int main(void)
{
    zcl_alloc_fault_clear();
    compression_failure_leaves_destination();
    encoding_failure_clears_written();
    zcl_alloc_fault_clear();
    puts("game PNG fault tests passed");
    return 0;
}
