/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The generated telemetry descriptor tables and the domain registry.
 *
 * Every table here is produced by pasting a domain's `<domain>_fields.def`
 * with the TL_* row macros defined for one purpose at a time — groups, then
 * leaves, then the schema itself. The leaf pass runs offsetof() over the SAME
 * member token that declared the member in util/telemetry_snapshots.h, so a
 * descriptor cannot address a field other than the one its row declared.
 *
 * Everything is static const data plus three pure lookups: no locks, no I/O,
 * no node state, safe before boot and from any thread.
 *
 * DANGER: `snapshot_size` is the only thing standing between the render layer
 * and an out-of-bounds read. It is `sizeof(struct <domain>_snapshot)` taken in
 * this translation unit, which also compiled the offsets — never hand-write a
 * schema, and never point one at a struct other than the one its field table
 * generated.
 */

#include "util/telemetry_snapshots.h"

#include "util/log_macros.h"

#include <stddef.h>
#include <string.h>

#define TL_ARRAY_LEN(a_) (sizeof(a_) / sizeof((a_)[0]))

/* ── pass A: the group tables ────────────────────────────────────────── */
#define TL_DOMAIN_META(d_, id_, desc_)
#define TL_GROUP(g_, desc_) { .name = TL_STR(g_), .desc = (desc_) },
#define TL_GROUP_END(g_)
#define TL_LEAF(...)

static const struct telemetry_group g_runtime_groups[] = {
#include "util/telemetry/runtime_fields.def"
};
static const struct telemetry_group g_sync_groups[] = {
#include "util/telemetry/sync_fields.def"
};
static const struct telemetry_group g_network_groups[] = {
#include "util/telemetry/network_fields.def"
};
static const struct telemetry_group g_storage_groups[] = {
#include "util/telemetry/storage_fields.def"
};
static const struct telemetry_group g_wallet_groups[] = {
#include "util/telemetry/wallet_fields.def"
};
static const struct telemetry_group g_agents_groups[] = {
#include "util/telemetry/agents_fields.def"
};
static const struct telemetry_group g_zcode_groups[] = {
#include "util/telemetry/zcode_fields.def"
};
static const struct telemetry_group g_metaverse_groups[] = {
#include "util/telemetry/metaverse_fields.def"
};

#undef TL_LEAF
#undef TL_GROUP_END
#undef TL_GROUP
#undef TL_DOMAIN_META

/* ── pass B: the leaf tables ─────────────────────────────────────────────
 * TL_SNAP names the struct the offsets are taken against and is redefined
 * around each include; it must match the domain whose table follows or every
 * offset in that table silently addresses the wrong struct. Pairing the
 * #define with the #include on adjacent lines is what keeps that honest. */
#define TL_DOMAIN_META(d_, id_, desc_)
#define TL_GROUP(g_, desc_)
#define TL_GROUP_END(g_)
#define TL_LEAF(g_, m_, ct_, unit_, tier_, rule_, op_, thr_, sev_,            \
                means_, implies_, next_)                                      \
    { .group = TL_STR(g_), .key = TL_STR(m_), .path = TL_PATH(g_, m_),        \
      .value_off = offsetof(struct TL_SNAP, m_),                              \
      .meta_off = offsetof(struct TL_SNAP, m_##_meta),                        \
      .ctype = (ct_), .unit = (unit_), .tier = (tier_) },

static const struct telemetry_leaf g_runtime_leaves[] = {
#define TL_SNAP runtime_snapshot
#include "util/telemetry/runtime_fields.def"
#undef TL_SNAP
};
static const struct telemetry_leaf g_sync_leaves[] = {
#define TL_SNAP sync_snapshot
#include "util/telemetry/sync_fields.def"
#undef TL_SNAP
};
static const struct telemetry_leaf g_network_leaves[] = {
#define TL_SNAP network_snapshot
#include "util/telemetry/network_fields.def"
#undef TL_SNAP
};
static const struct telemetry_leaf g_storage_leaves[] = {
#define TL_SNAP storage_snapshot
#include "util/telemetry/storage_fields.def"
#undef TL_SNAP
};
static const struct telemetry_leaf g_wallet_leaves[] = {
#define TL_SNAP wallet_snapshot
#include "util/telemetry/wallet_fields.def"
#undef TL_SNAP
};
static const struct telemetry_leaf g_agents_leaves[] = {
#define TL_SNAP agents_snapshot
#include "util/telemetry/agents_fields.def"
#undef TL_SNAP
};
static const struct telemetry_leaf g_zcode_leaves[] = {
#define TL_SNAP zcode_snapshot
#include "util/telemetry/zcode_fields.def"
#undef TL_SNAP
};
static const struct telemetry_leaf g_metaverse_leaves[] = {
#define TL_SNAP metaverse_snapshot
#include "util/telemetry/metaverse_fields.def"
#undef TL_SNAP
};

#undef TL_LEAF
#undef TL_GROUP_END
#undef TL_GROUP
#undef TL_DOMAIN_META

/* ── pass C: the schemas ─────────────────────────────────────────────────
 * TL_DOMAIN_META carries the domain token, so this pass needs no per-domain
 * helper macro: the schema, its two tables and its snapshot size are all
 * pasted from the one row that opens the field table. */
#define TL_DOMAIN_META(d_, id_, desc_)                                        \
    const struct telemetry_domain_schema g_##d_##_schema = {                  \
        .domain = TL_STR(d_),                                                 \
        .schema_id = (id_),                                                   \
        .desc = (desc_),                                                      \
        .snapshot_size = sizeof(struct d_##_snapshot),                        \
        .groups = g_##d_##_groups,                                            \
        .group_count = TL_ARRAY_LEN(g_##d_##_groups),                         \
        .leaves = g_##d_##_leaves,                                            \
        .leaf_count = TL_ARRAY_LEN(g_##d_##_leaves),                          \
    };
#define TL_GROUP(g_, desc_)
#define TL_GROUP_END(g_)
#define TL_LEAF(...)

#include "util/telemetry/runtime_fields.def"
#include "util/telemetry/sync_fields.def"
#include "util/telemetry/network_fields.def"
#include "util/telemetry/storage_fields.def"
#include "util/telemetry/wallet_fields.def"
#include "util/telemetry/agents_fields.def"
#include "util/telemetry/zcode_fields.def"
#include "util/telemetry/metaverse_fields.def"

#undef TL_LEAF
#undef TL_GROUP_END
#undef TL_GROUP
#undef TL_DOMAIN_META

/* ── the registry ────────────────────────────────────────────────────────
 * Driven from util/telemetry_domains.def, which is what makes the domain list
 * single-sourced: a domain added there but given no snapshot struct or schema
 * above fails to build rather than registering half a domain. */
#define TL_DOMAIN(d_) &g_##d_##_schema,
static const struct telemetry_domain_schema *const g_domains[] = {
#include "util/telemetry_domains.def"
};
#undef TL_DOMAIN

#define DOMAIN_COUNT TL_ARRAY_LEN(g_domains)

size_t telemetry_domain_count(void) { return DOMAIN_COUNT; }

const struct telemetry_domain_schema *telemetry_domain_at(size_t idx)
{
    return idx < DOMAIN_COUNT ? g_domains[idx] : NULL;
}

const struct telemetry_domain_schema *telemetry_domain_find(const char *domain)
{
    if (!domain || !domain[0])
        LOG_NULL("telemetry_render", "domain_find: empty domain name");
    for (size_t i = 0; i < DOMAIN_COUNT; i++) {
        if (strcmp(g_domains[i]->domain, domain) == 0)
            return g_domains[i];
    }
    return NULL;
}
