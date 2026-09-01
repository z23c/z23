/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids VIEW — immutable checkpoint row data for section 12.
 *
 * Kept out of explorer_factoids_chaindata.c so the oversized chain-data
 * section file owns orchestration while this file owns the static checkpoint
 * table and row rendering. Display-only; consensus checkpoint enforcement
 * lives in the chain/validation layers. */

#include "views/explorer_factoids_internal.h"

struct factoids_checkpoint_row {
    int64_t height;
    const char *hash;
};

static const struct factoids_checkpoint_row g_factoid_checkpoints[] = {
    { 0,       "0007104ccda289427919efc39dc9e4d499804b7bebc22df55f8b834301260602" },
    { 30000,   "000000005c2ad200c3c7c8e627f67b306659efca1268c9bb014335fdadc0c392" },
    { 160000,  "000000065093005a1a46ee95d6d66c2b07008220ca64dd3b3a93bbd1945480c0" },
    { 468200,  "000000009bd5548c851c2b237894d6807a53bf1e2808402545e27a995ae4f3c3" },
    { 2013514, "000019679aa2ea97a3f18bd9265bc91a09929ea0b1acc0fc5ef77cdf3cf906e7" },
    { 2879438, "000007e8fccb9e4831c7d7376a283b016ead6166491f951f4f083dbe366992b2" },
    { 3054000, "000005aa8e8c321cf364788e81b94619434b0dc1a85e658a022b44f23eb85662" },
};

size_t factoids_emit_checkpoint_rows(uint8_t *buf, size_t cap, size_t off,
                                     sqlite3 *db, int64_t chain_height)
{
    char *r = (char *)buf;
    size_t max = cap;

    for (size_t i = 0; i < sizeof(g_factoid_checkpoints) /
                            sizeof(g_factoid_checkpoints[0]); i++) {
        const struct factoids_checkpoint_row *cp = &g_factoid_checkpoints[i];
        int64_t btime = 0;
        char bhash_unused[128] = "";
        get_block_at(db, cp->height, bhash_unused, sizeof(bhash_unused),
                     &btime);

        char height_s[32], ts[64], rcpt[32] = "";
        char hash_short[20];
        snprintf(height_s, sizeof(height_s), "%" PRId64, cp->height);
        fmt_time(ts, sizeof(ts), btime);
        compute_receipt(rcpt, sizeof(rcpt), cp->height, cp->hash,
                        "checkpoint");
        snprintf(hash_short, sizeof(hash_short), "%.16s", cp->hash);

        struct template_var vars[] = {
            { "height",     height_s },
            { "time",       cp->height <= chain_height
                              ? ts
                              : "<span style='color:#666'>Not yet reached</span>" },
            { "hash_short", hash_short },
            { "receipt",    cp->height <= chain_height ? rcpt : "--" },
        };
        if (off >= max)
            return off;
        off += template_render(TMPL_CHECKPOINT_ROW,
                               vars, sizeof(vars) / sizeof(vars[0]),
                               r + off, max - off);
    }

    return off;
}
