/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ONE registration form for both hot-swap generation tiers.
 *
 * Registering a controller used to cost about forty lines: two nearly
 * identical leaf tables, two #ifdef blocks choosing different headers, and a
 * hand-written structural self-test repeated verbatim per file. The tables
 * differ only in a struct name — Tier-1 spells its fields {path, handler} and
 * Tier-2 spells them {name, fn} — and both are plain positional
 * {string, function} initialisers, so one form can serve both.
 *
 * That tax was not free. A controller sitting at its file-size baseline could
 * not be registered at all, because forty lines of boilerplate tripped the
 * size ratchet before any of it did useful work. Making the fast dev loop
 * reach more of the tree means making registration nearly free.
 *
 * Use it like this, ONCE at file scope, with no trailing semicolons:
 *
 *     #if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
 *     #define ZCL_HOTSWAP_PROBE_LEAF "app.shop.status"
 *     #include "hotswap/hotswap_register.h"
 *     ZCL_HOTSWAP_LEAVES_BEGIN(shop)
 *     ZCL_HOTSWAP_LEAF("app.shop.status", zcl_native_handle_shop_status)
 *     ZCL_HOTSWAP_LEAVES_END(shop)
 *     #endif
 *
 * ZCL_HOTSWAP_PROBE_LEAF must be defined BEFORE this header: Tier-1 bakes it
 * into the manifest, and hotswap.h supplies a default the moment it is
 * included, which would silently be the wrong leaf.
 *
 * The tag is any C identifier unique within the TU; it only names the static
 * table and self-test. A normal node or release build defines neither tier
 * macro, so this whole header expands to nothing and the binary never carries
 * a leaf table.
 *
 * A TU whose leaves are bridged bodies rather than direct handlers still needs
 * ZCL_HOTSWAP_TRAMPOLINE from command/native_command.h, which lives there
 * because both tiers include that file and only one of them includes
 * hotswap.h. Declare the trampolines between the include and the table. */

#ifndef ZCL_HOTSWAP_REGISTER_H
#define ZCL_HOTSWAP_REGISTER_H

#if defined(ZCL_HOTSWAP_MODULE_GEN)

#include "hotswap/hotswap_module.h"

#include <stdio.h>

#define ZCL_HOTSWAP__LEAF_TYPE struct zcl_hotswap_leaf

/* The self-test the loader runs before it publishes anything. It is emitted
 * per TU rather than shared because the module ABI hands over a function
 * pointer, and it checks the one thing a generated table can still get wrong:
 * an entry with no name or no body would publish a leaf that dispatches into
 * nothing. A TU needing a stronger check writes the table and the manifest by
 * hand instead — ZCL_HOTSWAP_MODULE_LEAVES stays available for exactly that. */
#define ZCL_HOTSWAP__EMIT(tag_)                                              \
    static bool zcl_hotswap_##tag_##_selftest(char *zcl__err,                \
                                              size_t zcl__cap)               \
    {                                                                        \
        const size_t zcl__n = sizeof(zcl_hotswap_##tag_##_leaves) /          \
                              sizeof(zcl_hotswap_##tag_##_leaves[0]);        \
        for (size_t zcl__i = 0; zcl__i < zcl__n; zcl__i++) {                 \
            if (!zcl_hotswap_##tag_##_leaves[zcl__i].name ||                 \
                !zcl_hotswap_##tag_##_leaves[zcl__i].name[0] ||              \
                !zcl_hotswap_##tag_##_leaves[zcl__i].fn) {                   \
                if (zcl__err && zcl__cap)                                    \
                    (void)snprintf(zcl__err, zcl__cap,                       \
                                   "%s leaf %zu has no name or no body",     \
                                   #tag_, zcl__i);                           \
                return false;                                                \
            }                                                                \
        }                                                                    \
        return true;                                                         \
    }                                                                        \
    ZCL_HOTSWAP_MODULE_LEAVES(zcl_hotswap_##tag_##_leaves,                   \
                              zcl_hotswap_##tag_##_selftest)

#elif defined(ZCL_HOTSWAP_GEN)

#include "hotswap/hotswap.h"

#define ZCL_HOTSWAP__LEAF_TYPE struct zcl_hotswap_leaf_replacement

#define ZCL_HOTSWAP__EMIT(tag_)                                              \
    ZCL_HOTSWAP_EXPORT_LEAVES(zcl_hotswap_##tag_##_leaves,                   \
                              sizeof(zcl_hotswap_##tag_##_leaves) /          \
                                  sizeof(zcl_hotswap_##tag_##_leaves[0]))

#endif /* tier selection */

#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)

#define ZCL_HOTSWAP_LEAVES_BEGIN(tag_)                                       \
    static const ZCL_HOTSWAP__LEAF_TYPE zcl_hotswap_##tag_##_leaves[] = {

/* One row. Both tiers take the same positional {string, function} shape, which
 * is the whole reason a single form can serve them. */
#define ZCL_HOTSWAP_LEAF(leaf_, fn_) { (leaf_), (fn_) },

#define ZCL_HOTSWAP_LEAVES_END(tag_)                                         \
    }                                                                        \
    ;                                                                        \
    ZCL_HOTSWAP__EMIT(tag_)

#endif /* either tier */

#endif /* ZCL_HOTSWAP_REGISTER_H */
