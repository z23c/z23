/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * One-shot plugin (interface 2) built from the zcrc package: reads standard
 * input to end of file and writes its CRC-32 as eight lowercase hex digits
 * followed by one newline. Streams in bounded chunks. Exits 0, or 1 when a
 * read or write fails. */

#include "zcrc/zcrc.h"

#include <stdint.h>
#include <stdio.h>

#define ZCRC32_CHUNK 4096U

int main(void)
{
    unsigned char buf[ZCRC32_CHUNK];
    uint32_t state = zcrc32_init();
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0)
        state = zcrc32_update(state, buf, n);
    if (ferror(stdin))
        return 1;
    if (printf("%08x\n", zcrc32_final(state)) < 0)
        return 1;
    return fflush(stdout) != 0 ? 1 : 0;
}
