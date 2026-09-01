/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Generated telemetry snapshot structs, leaf-id enums and schema declarations
 * — one set per domain in util/telemetry_domains.def.
 *
 * Nothing here is hand-written data. Each domain's `<domain>_fields.def` is
 * pasted twice by this header with the TL_* row macros defined differently
 * each time, so the member declaration and the leaf-id enumerator come from
 * the SAME `member` token that telemetry_schemas.c later feeds to offsetof().
 * A field name therefore exists in exactly one place in the repository and
 * struct/key/path/enum drift is unrepresentable rather than merely policed.
 *
 * OWNERSHIP / lifetime. A `struct <domain>_snapshot` is a plain value the
 * PROVIDER owns, normally on its own stack for the duration of one dump call.
 * It holds no pointer into node state — text is copied, never referenced — so
 * it can outlive every lock the provider took to fill it. Zero-initialize it
 * (`= {0}`) and every leaf starts at TELEMETRY_UNSET, which is exactly the
 * provider-defect signal the render layer reports; a snapshot that skips the
 * zero-init produces indeterminate presences and is a bug.
 *
 * DANGER: the TL_* macros are #defined immediately before each pass and
 * #undef'd immediately after, so none of them survive this header. Do not add
 * a pass that leaves one defined — a later translation unit that includes a
 * field table would then silently expand it with the wrong meaning.
 *
 * Adding a DOMAIN means editing telemetry_domains.def, this header (two passes
 * per domain) and nothing else: the schema-declaration pass below is driven
 * straight from the domains table, so a domain added there but missed here
 * fails to link against a schema that was never defined.
 */
#ifndef ZCL_UTIL_TELEMETRY_SNAPSHOTS_H
#define ZCL_UTIL_TELEMETRY_SNAPSHOTS_H

#include "util/telemetry_field_table.h"

/* ── pass 1: the snapshot structs ────────────────────────────────────────
 * One member for the value, one for its provenance, both named from the same
 * token so `m` and `m##_meta` can never address different fields. */
#define TL_DOMAIN_META(d_, id_, desc_)
#define TL_GROUP(g_, desc_)
#define TL_GROUP_END(g_)
#define TL_LEAF(g_, m_, ct_, unit_, tier_, rule_, op_, thr_, sev_,            \
                means_, implies_, next_)                                      \
    TL_DECL_##ct_(m_)                                                         \
    struct telemetry_leaf_meta m_##_meta;

struct runtime_snapshot {
#include "util/telemetry/runtime_fields.def"
};
struct sync_snapshot {
#include "util/telemetry/sync_fields.def"
};
struct network_snapshot {
#include "util/telemetry/network_fields.def"
};
struct storage_snapshot {
#include "util/telemetry/storage_fields.def"
};
struct wallet_snapshot {
#include "util/telemetry/wallet_fields.def"
};
struct agents_snapshot {
#include "util/telemetry/agents_fields.def"
};
struct zcode_snapshot {
#include "util/telemetry/zcode_fields.def"
};
struct metaverse_snapshot {
#include "util/telemetry/metaverse_fields.def"
};

#undef TL_LEAF
#undef TL_GROUP_END
#undef TL_GROUP
#undef TL_DOMAIN_META

/* ── pass 2: the leaf-id enums ───────────────────────────────────────────
 * TL_ENUM_PREFIX is redefined around each include because the enumerator
 * spelling is <DOMAIN>_LEAF_<member> and the preprocessor cannot upper-case a
 * token. The trailing <DOMAIN>_LEAF__COUNT is the leaf count; it is NOT a leaf
 * id and must never be used as an index.
 *
 * These ids exist for providers that want a switch over their own leaves. The
 * render layer never uses them — it walks the descriptor table — so an id
 * whose numeric value shifts when a lane appends a row breaks nothing that is
 * persisted. Do not serialize one. */
#define TL_DOMAIN_META(d_, id_, desc_)
#define TL_GROUP(g_, desc_)
#define TL_GROUP_END(g_)
#define TL_ID_(p_, m_) p_##m_
#define TL_ID(p_, m_) TL_ID_(p_, m_)
#define TL_LEAF(g_, m_, ct_, unit_, tier_, rule_, op_, thr_, sev_,            \
                means_, implies_, next_)                                      \
    TL_ID(TL_ENUM_PREFIX, m_),

enum runtime_leaf_id {
#define TL_ENUM_PREFIX RUNTIME_LEAF_
#include "util/telemetry/runtime_fields.def"
#undef TL_ENUM_PREFIX
    RUNTIME_LEAF__COUNT
};
enum sync_leaf_id {
#define TL_ENUM_PREFIX SYNC_LEAF_
#include "util/telemetry/sync_fields.def"
#undef TL_ENUM_PREFIX
    SYNC_LEAF__COUNT
};
enum network_leaf_id {
#define TL_ENUM_PREFIX NETWORK_LEAF_
#include "util/telemetry/network_fields.def"
#undef TL_ENUM_PREFIX
    NETWORK_LEAF__COUNT
};
enum storage_leaf_id {
#define TL_ENUM_PREFIX STORAGE_LEAF_
#include "util/telemetry/storage_fields.def"
#undef TL_ENUM_PREFIX
    STORAGE_LEAF__COUNT
};
enum wallet_leaf_id {
#define TL_ENUM_PREFIX WALLET_LEAF_
#include "util/telemetry/wallet_fields.def"
#undef TL_ENUM_PREFIX
    WALLET_LEAF__COUNT
};
enum agents_leaf_id {
#define TL_ENUM_PREFIX AGENTS_LEAF_
#include "util/telemetry/agents_fields.def"
#undef TL_ENUM_PREFIX
    AGENTS_LEAF__COUNT
};
enum zcode_leaf_id {
#define TL_ENUM_PREFIX ZCODE_LEAF_
#include "util/telemetry/zcode_fields.def"
#undef TL_ENUM_PREFIX
    ZCODE_LEAF__COUNT
};
enum metaverse_leaf_id {
#define TL_ENUM_PREFIX METAVERSE_LEAF_
#include "util/telemetry/metaverse_fields.def"
#undef TL_ENUM_PREFIX
    METAVERSE_LEAF__COUNT
};

#undef TL_LEAF
#undef TL_ID
#undef TL_ID_
#undef TL_GROUP_END
#undef TL_GROUP
#undef TL_DOMAIN_META

/* ── pass 3: the per-domain schema declarations ──────────────────────────
 * Driven from the domains table itself, so this pass cannot fall behind it.
 * The definitions live in platform/modules/util/src/telemetry_schemas.c; a provider that
 * wants one directly (rather than through telemetry_domain_find) names it
 * here. */
#define TL_DOMAIN(d_)                                                         \
    extern const struct telemetry_domain_schema g_##d_##_schema;
#include "util/telemetry_domains.def"
#undef TL_DOMAIN

#endif /* ZCL_UTIL_TELEMETRY_SNAPSHOTS_H */
