/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The row grammar every `<domain>_fields.def` is written in, plus the helper
 * tokens its expansions need.
 *
 * A field table is DATA ONLY: no includes, no code, no conditionals. It is
 * pasted by several translation units that each define the TL_* macros
 * differently, so anything other than TL_ rows breaks a consumer.
 *
 * ── the row ────────────────────────────────────────────────────────────
 *
 *   TL_DOMAIN_META(domain, schema_id, desc)
 *       Once, first, per table.
 *
 *   TL_GROUP(group, desc)  ... rows ...  TL_GROUP_END(group)
 *       Rows for one group must be contiguous.
 *
 *   TL_LEAF(group, member, ctype, unit, tier,
 *           rule, operand, threshold, severity,
 *           means, implies, next)
 *
 *     group      the enclosing TL_GROUP name.
 *     member     THE TOKEN. Written exactly once in the repository: it becomes
 *                the C struct member, the JSON key, the ontology path leaf and
 *                the leaf-id enumerator. Never spell it anywhere else.
 *     ctype      TLC_I64 | TLC_BOOL | TLC_TEXT      (storage class)
 *     unit       enum telemetry_unit                (TFU_*, telemetry_ontology.h)
 *     tier       TLV_SUMMARY | TLV_NORMAL | TLV_FULL — the SHALLOWEST view
 *                that shows the field.
 *     rule       enum telemetry_rule                (TFR_*)
 *     operand    TL_REF(group, member) for the ratio rules, else TL_NONE.
 *     threshold  absolute for the *_ABS rules, PER MILLE for the *_RATIO_OF
 *                rules — so a rule is evaluable against this dump alone.
 *     severity   enum telemetry_severity            (TFS_*)
 *     means      what the number counts. REQUIRED on every row.
 *     implies    what an unhealthy value implies. Required unless rule is
 *                TFR_INFO.
 *     next       the exact next command or field to read. Required unless
 *                rule is TFR_INFO.
 *
 * `means`/`implies`/`next` carry the same contract as the subsystem-level
 * ontology in util/telemetry_ontology.def, and the same gate enforces them.
 *
 * ── what a row generates ───────────────────────────────────────────────
 *
 *   struct member    TL_DECL_<ctype>(member)  + struct telemetry_leaf_meta
 *   leaf id          <DOMAIN>_LEAF_<member>
 *   descriptor       offsetof() over the SAME member token, so the offset can
 *                    never address a different field than the declaration
 *   ontology row     one struct telemetry_field, merged into g_fields[]
 *
 * The struct is generated FROM the table. offsetof alone would still require
 * the member to be declared somewhere, and that declaration is the second
 * place a name could drift. Expanding one token twice in one translation unit
 * removes the second place entirely.
 *
 * ── arrays ─────────────────────────────────────────────────────────────
 * There is no array leaf and there will not be one: a fixed-offset table has
 * nowhere to put a variable-length list, and the ontology evaluator refuses
 * "[]" paths outright. Flatten to one leaf per known element — the stage
 * ladder and the peer slots are compile-time constant sets — which also buys
 * per-element health rules an array could never carry.
 */
#ifndef ZCL_UTIL_TELEMETRY_FIELD_TABLE_H
#define ZCL_UTIL_TELEMETRY_FIELD_TABLE_H

#include "util/telemetry_render.h"

/* Stringify through one level of expansion so a macro argument becomes its
 * spelling, not its definition. */
#define TL_STR_(x_) #x_
#define TL_STR(x_) TL_STR_(x_)

/* The canonical ontology path for a leaf. `values.` prefixes the value plane
 * so provenance ("leaves.") and verdicts ("health.") cannot collide with it. */
#define TL_PATH(g_, m_) ("values." TL_STR(g_) "." TL_STR(m_))

/* A sibling reference for the ratio rules — same spelling as the row it
 * points at, so a renamed field breaks the reference at compile time. */
#define TL_REF(g_, m_) TL_PATH(g_, m_)
#define TL_NONE NULL

/* Storage class -> the member DECLARATION. This takes the member name rather
 * than yielding a bare type because an array declarator wraps its name
 * (`char m[64]`, not `char[64] m`). The member's C type and the descriptor's
 * ctype both come from this one column, so a mismatch cannot be written. */
#define TL_DECL_TLC_I64(m_) int64_t m_;
#define TL_DECL_TLC_BOOL(m_) bool m_;
#define TL_DECL_TLC_TEXT(m_) char m_[TELEMETRY_TEXT_MAX];

/* The width the renderer reads at `value_off`, used to prove every offset
 * lies inside the declared snapshot before dereferencing it. */
#define TL_WIDTH_TLC_I64 (sizeof(int64_t))
#define TL_WIDTH_TLC_BOOL (sizeof(bool))
#define TL_WIDTH_TLC_TEXT ((size_t)TELEMETRY_TEXT_MAX)

#endif /* ZCL_UTIL_TELEMETRY_FIELD_TABLE_H */
