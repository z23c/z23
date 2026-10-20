/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * One-shot plugin (interface 2) built from the zhex package: reads standard
 * input to end of file and writes its bytes as lowercase hex followed by one
 * newline. Streams in bounded chunks, so the input size is not limited here.
 * Exits 0, or 1 when a read, encode or write fails. */

#include "zhex/zhex.h"

#include <stdint.h>
#include <stdio.h>

#define ZHEXENC_CHUNK 4096U

int main(void)
{
    uint8_t in[ZHEXENC_CHUNK];
    char out[2U * ZHEXENC_CHUNK];
    size_t n;
    while ((n = fread(in, 1, sizeof(in), stdin)) > 0) {
        if (zhex_encode(in, n, out) != ZHEX_OK)
            return 1;
        if (fwrite(out, 1, zhex_encoded_len(n), stdout) != zhex_encoded_len(n))
            return 1;
    }
    if (ferror(stdin))
        return 1;
    return fputs("\n", stdout) == EOF || fflush(stdout) != 0 ? 1 : 0;
}
