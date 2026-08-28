/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Hash canonical codeindex symbol rows for verification on read. */

#include "codeindex_priv.h"

#include <string.h>

void ci_symbol_row_hash(const struct ci_symbol *sym, uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const uint8_t tag = 0x01;
    sha3_256_write(&ctx, &tag, 1);
    const char *fields[] = {sym->name, sym->def_path, sym->decl_path,
                            sym->signature, sym->doc, sym->guard, sym->group};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
        sha3_256_write(&ctx, (const unsigned char *)fields[i],
                       strlen(fields[i]) + 1);
    unsigned char scalars[6] = {
        (unsigned char)sym->kind,
        sym->partial ? 1u : 0u,
        (unsigned char)(sym->def_line & 0xff),
        (unsigned char)((sym->def_line >> 8) & 0xff),
        (unsigned char)(sym->decl_line & 0xff),
        (unsigned char)((sym->decl_line >> 8) & 0xff),
    };
    sha3_256_write(&ctx, scalars, sizeof(scalars));
    sha3_256_finalize(&ctx, out);
}
