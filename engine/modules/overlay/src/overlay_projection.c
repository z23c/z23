/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Overlay SDK — rebuildable-projection scaffold: the shared lokad registry and
 * the explorer-ingestion seam. See overlay/overlay_projection.h. Pure and
 * alloc-free; the per-overlay apply callback (which touches ActiveRecord
 * models) is supplied by the app layer. Registry operations log context on
 * rejection; the ingest seam is a hot-path predicate over chain bytes and does
 * not log on a non-overlay miss (a normal negative result). */

#include "overlay/overlay_projection.h"
#include "util/log_macros.h"

#include <string.h>

void overlay_registry_init(struct overlay_registry *reg)
{
    if (!reg) return;
    memset(reg, 0, sizeof(*reg));
}

/* A well-formed lokad tag is 1-4 non-NUL bytes, NUL-padded to four (the
 * on-chain PUSH is always four bytes wide). Trailing NUL padding is legal
 * because it is what the chain actually carries: the SLP lineage spells a
 * three-character tag with a NUL pad — ZSLP's tag is "SLP\0" and ZID's is
 * "ZID\0". An EMBEDDED NUL is still refused: tag[0] must be non-NUL, and once
 * a NUL is seen every later byte must be NUL too, so "ZF\0X" rejects. */
static bool lokad_well_formed(const char tag[OVERLAY_LOKAD_LEN])
{
    if (!tag || tag[0] == '\0') return false;
    bool padding = false;
    for (int i = 1; i < OVERLAY_LOKAD_LEN; i++) {
        if (tag[i] == '\0')
            padding = true;
        else if (padding)
            return false;              /* NUL followed by a non-NUL byte */
    }
    return true;
}

bool overlay_registry_add(struct overlay_registry *reg,
                          const struct overlay_descriptor *desc)
{
    if (!reg || !desc)
        LOG_FAIL("overlay", "overlay_registry_add: NULL reg/desc");
    if (!desc->apply)
        LOG_FAIL("overlay", "overlay_registry_add: NULL apply callback");
    if (!desc->name || !desc->name[0])
        LOG_FAIL("overlay", "overlay_registry_add: missing overlay name");
    if (!lokad_well_formed(desc->lokad))
        LOG_FAIL("overlay", "overlay_registry_add: malformed lokad tag");
    if (reg->count >= OVERLAY_REGISTRY_MAX)
        LOG_FAIL("overlay", "overlay_registry_add: registry full (%d)",
                 OVERLAY_REGISTRY_MAX);
    if (overlay_registry_find(reg, desc->lokad))
        LOG_FAIL("overlay", "overlay_registry_add: duplicate lokad '%.4s'",
                 desc->lokad);

    reg->entries[reg->count++] = *desc;
    return true;
}

const struct overlay_descriptor *
overlay_registry_find(const struct overlay_registry *reg,
                      const char lokad[OVERLAY_LOKAD_LEN])
{
    if (!reg || !lokad) return NULL;
    for (size_t i = 0; i < reg->count; i++)
        if (memcmp(reg->entries[i].lokad, lokad, OVERLAY_LOKAD_LEN) == 0)
            return &reg->entries[i];
    return NULL;
}

size_t overlay_registry_count(const struct overlay_registry *reg)
{
    return reg ? reg->count : 0;
}

bool overlay_peek_lokad(const uint8_t *script, size_t script_len,
                        char out_tag[OVERLAY_LOKAD_LEN])
{
    if (!out_tag) return false;

    struct overlay_reader r;
    if (!overlay_reader_open(&r, script, script_len)) return false;

    const uint8_t *data = NULL;
    size_t len = 0;
    if (!overlay_read_field(&r, &data, &len)) return false;
    if (len != OVERLAY_LOKAD_LEN) return false;

    memcpy(out_tag, data, OVERLAY_LOKAD_LEN);
    return true;
}

bool overlay_ingest(const struct overlay_registry *reg, struct node_db *ndb,
                    const struct transaction *tx, const uint8_t *script,
                    size_t script_len, int height)
{
    if (!reg || !ndb || !script) return false;

    char tag[OVERLAY_LOKAD_LEN];
    if (!overlay_peek_lokad(script, script_len, tag))
        return false;                              /* not an overlay */

    const struct overlay_descriptor *d = overlay_registry_find(reg, tag);
    if (!d) return false;                          /* no overlay for this tag */

    return d->apply(ndb, tx, script, script_len, height, d->ctx);
}
