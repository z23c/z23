/* purpose: Generate resident Ironwood verifier parameters from public bytes. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

static bool emit(FILE *out, const char *path, size_t size, size_t row)
{
    FILE *in = fopen(path, "rb");
    if (!in) return false;
    bool ok = true;
    for (size_t i = 0; i < size; i++) {
        int c = fgetc(in);
        if (c == EOF) { ok = false; break; }
        if (row && i % row == 0) fputs("{", out);
        fprintf(out, "%u,", (unsigned)c);
        if (row && i % row == row - 1) fputs("},\n", out);
        else if (!row && i % 32 == 31) fputc('\n', out);
    }
    if (fgetc(in) != EOF || ferror(in)) ok = false;
    if (fclose(in) != 0) ok = false;
    return ok && !ferror(out);
}
static bool emit_blinding(FILE *out, const char *path)
{
    FILE *in = fopen(path, "rb");
    if (!in) return false;
    bool ok = true;
    for (size_t i = 0; i < 64; i++) {
        int c = fgetc(in);
        if (c == EOF) { ok = false; break; }
        if (i == 32) fputs("}, .w = {", out);
        fprintf(out, "%u,", (unsigned)c);
    }
    if (fgetc(in) != EOF || ferror(in)) ok = false;
    if (fclose(in) != 0) ok = false;
    return ok && !ferror(out);
}
int main(int argc, char **argv)
{
    if (argc != 8) return 2;
    FILE *out = fopen(argv[7], "wb");
    if (!out) return 1;
    fputs("/* Generated from public Ironwood resources; do not edit. */\n"
          "#include \"services/ironwood_resident_params.h\"\n"
          "const struct ironwood_opening_basis ironwood_resident_basis = { .generators = {\n", out);
    bool ok = emit(out, argv[1], 65536, 32);
    fputs("}, .u = {", out);
    ok = emit_blinding(out, argv[2]) && ok;
    fputs("}};\nconst uint8_t ironwood_resident_custom[48484] = {\n", out);
    ok = emit(out, argv[3], 48484, 0) && ok;
    fputs("};\nconst uint8_t ironwood_resident_permutation[997] = {\n", out);
    ok = emit(out, argv[4], 997, 0) && ok;
    fputs("};\nconst uint8_t ironwood_resident_lookup[1159] = {\n", out);
    ok = emit(out, argv[5], 1159, 0) && ok;
    fputs("};\n", out);
    fputs("static const uint8_t ironwood_merkle_parameters[32800] = {\n", out);
    ok = emit(out, argv[6], 32800, 0) && ok;
    fputs("};\nconst uint8_t *ironwood_resident_merkle_parameters(size_t *size)\n"
          "{ if (size) *size = sizeof ironwood_merkle_parameters; "
          "return ironwood_merkle_parameters; }\n", out);
    if (fclose(out) != 0) ok = false;
    if (!ok) (void)remove(argv[7]);
    return ok ? 0 : 1;
}
