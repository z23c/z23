/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include <stdio.h>
#include <string.h>

int main(void)
{
    static char block[1 << 20];
    memset(block, 0x5a, sizeof(block));
    for (int f = 0; f < 64; f++) {
        char name[32];
        snprintf(name, sizeof(name), "fill%02d.bin", f);
        FILE *out = fopen(name, "wb");
        if (!out)
            return 2;
        for (int i = 0; i < 12; i++)
            if (fwrite(block, 1, sizeof(block), out) != sizeof(block))
                break;
        fclose(out);
    }
    puts("filled");
    return 0;
}
