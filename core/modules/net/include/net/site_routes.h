/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Site route registry — shared expansion machinery for
 * net/site_routes.def (the one inventory of the app MVC web mounts; see
 * the header comment in the def for the column contract and consumer
 * list). This header carries:
 *   1. the ZCL_SITE_F_* flag bits and the per-flavor flag bundles the
 *      descriptor table derives its introspection flags from
 *   2. the ZCL_SITE_COST_* aliases onto the onion_ratelimit tiers
 *   3. the ZCL_SITE_EXTERN_<flavor>() handler-prototype generators the two
 *      dispatch TUs expand (core/modules/net never includes app/ headers)
 *   4. the ZCL_SITE_POS_* and ZCL_SITE_POSNUM_* slot selectors that let a
 *      def row land at a FIXED position in a designated-initializer
 *      table, so nav order stays byte-stable while the data comes from
 *      the def
 *   5. the test-visible descriptor/nav/grid tables site_routes.c defines,
 *      plus the onion front-door nav emitter (the former ONION_GLOBAL_NAV
 *      literal, now generated). */

#ifndef ZCL_NET_SITE_ROUTES_H
#define ZCL_NET_SITE_ROUTES_H

#include "net/onion_ratelimit.h"

#include <stddef.h>
#include <stdint.h>

/* ── Method/transport/dispatch flags (descriptor-table introspection) ── */

#define ZCL_SITE_F_POST_ONION    (1u << 0) /* POST surface, onion-only    */
#define ZCL_SITE_F_HTTPS         (1u << 1) /* served (GET/HEAD) on HTTPS  */
#define ZCL_SITE_F_PREFIX_GUARD  (1u << 2) /* path[N] ∈ {NUL, '/', '?'}   */
#define ZCL_SITE_F_DATADIR       (1u << 3) /* 7-arg handler + datadir     */
#define ZCL_SITE_F_FAIL_CLOSED   (1u << 4) /* handler 0 → 503 fail_body   */

#define ZCL_SITE_F_ALL           (ZCL_SITE_F_POST_ONION | ZCL_SITE_F_HTTPS | \
                                  ZCL_SITE_F_PREFIX_GUARD | \
                                  ZCL_SITE_F_DATADIR | ZCL_SITE_F_FAIL_CLOSED)

/* Per-flavor flag bundles — the transport/guard/signature personality is
 * derived from the one flavor token, so the introspection table can never
 * disagree with the generated dispatch code about them. */
#define ZCL_SITE_FLAGS_STORE      (ZCL_SITE_F_DATADIR)
#define ZCL_SITE_FLAGS_PLAIN      (ZCL_SITE_F_HTTPS)
#define ZCL_SITE_FLAGS_DATADIR    (ZCL_SITE_F_HTTPS | ZCL_SITE_F_PREFIX_GUARD | \
                                   ZCL_SITE_F_DATADIR)
#define ZCL_SITE_FLAGS_FAILCLOSED (ZCL_SITE_F_HTTPS | ZCL_SITE_F_PREFIX_GUARD | \
                                   ZCL_SITE_F_FAIL_CLOSED)
/* Onion-only FAILCLOSED: the prefix guard and the 503-on-0 contract of
 * FAILCLOSED, but — like STORE — never dispatched on the HTTPS listener. */
#define ZCL_SITE_FLAGS_ONIONCLOSED (ZCL_SITE_F_PREFIX_GUARD | \
                                    ZCL_SITE_F_FAIL_CLOSED)

/* ── Cost-tier aliases (expanded only where the enum is compiled) ────── */

#define ZCL_SITE_COST_STATIC      ONION_ROUTE_STATIC
#define ZCL_SITE_COST_CHEAP       ONION_ROUTE_CHEAP
#define ZCL_SITE_COST_EXPENSIVE   ONION_ROUTE_EXPENSIVE

/* ── Handler-prototype generators ─────────────────────────────────────── */

#define ZCL_SITE_EXTERN_STORE(h) \
    extern size_t h(const char *, const char *, const uint8_t *, size_t, \
                    uint8_t *, size_t, const char *);
#define ZCL_SITE_EXTERN_PLAIN(h) \
    extern size_t h(const char *, const char *, const uint8_t *, size_t, \
                    uint8_t *, size_t);
#define ZCL_SITE_EXTERN_DATADIR(h)    ZCL_SITE_EXTERN_STORE(h)
#define ZCL_SITE_EXTERN_FAILCLOSED(h) ZCL_SITE_EXTERN_PLAIN(h)
#define ZCL_SITE_EXTERN_ONIONCLOSED(h) ZCL_SITE_EXTERN_PLAIN(h)

/* ── Fixed-position table slots ─────────────────────────────────────────
 *
 * A nav/grid row must land at its historical index regardless of def row
 * order (dispatch order ≠ nav order). The slot token pastes to a
 * designated-initializer row; NONE emits nothing. Three columns because
 * every consumer's row shape is {href, label, aux}. */

#define ZCL_SITE_POS_NONE(a, b, c)
#define ZCL_SITE_POS_P1(a, b, c)   [1] = { a, b, c },
#define ZCL_SITE_POS_P2(a, b, c)   [2] = { a, b, c },
#define ZCL_SITE_POS_P3(a, b, c)   [3] = { a, b, c },
#define ZCL_SITE_POS_P4(a, b, c)   [4] = { a, b, c },
#define ZCL_SITE_POS_P5(a, b, c)   [5] = { a, b, c },
#define ZCL_SITE_POS_P6(a, b, c)   [6] = { a, b, c },

#define ZCL_SITE_POSNUM_NONE 0
#define ZCL_SITE_POSNUM_P1   1
#define ZCL_SITE_POSNUM_P2   2
#define ZCL_SITE_POSNUM_P3   3
#define ZCL_SITE_POSNUM_P4   4
#define ZCL_SITE_POSNUM_P5   5
#define ZCL_SITE_POSNUM_P6   6

/* ── Test-visible generated tables (defined in site_routes.c) ────────── */

struct zcl_site_route {
    const char *id;
    const char *prefix;
    const char *handler_name;
    const char *flavor;
    enum onion_route_class cost;
    const char *route_key;    /* "" when the row binds no puzzle key      */
    unsigned flags;           /* ZCL_SITE_FLAGS_<flavor> | methods column  */
    int nav_app_pos;          /* 0 = not in the app-side global nav        */
    int nav_onion_pos;        /* 0 = not in the onion front-door nav       */
    int grid_pos;             /* 0 = not in the onion landing app grid     */
    const char *nav_label;    /* NULL when in no nav                       */
    const char *nav_href;
    const char *nav_id;       /* the site_emit_global_nav() `active` id    */
    const char *grid_desc;    /* NULL when not in the landing grid         */
    const char *fail_body;    /* 503 body for FAILCLOSED rows, else NULL   */
    const char *app_id;       /* app-catalog id this mount serves, or NULL */
};

struct zcl_site_nav_link {
    const char *href;
    const char *label;
    const char *id;
};

struct zcl_site_grid_entry {
    const char *href;
    const char *label;
    const char *desc;
};

/* Dispatch order == def row order; the test_site_routes group pins it. */
extern const struct zcl_site_route g_zcl_site_routes[];
extern const size_t g_zcl_site_routes_count;

/* The two global navs, chrome entries included, at their historical
 * positions. Both transports carry the same app set — Names, Store, Blog,
 * Metaverse, Yardsale, Zcode — between the Explorer [0] and Directory [7]
 * chrome entries. */
extern const struct zcl_site_nav_link g_zcl_site_nav_app[];
extern const size_t g_zcl_site_nav_app_count;
extern const struct zcl_site_nav_link g_zcl_site_nav_onion[];
extern const size_t g_zcl_site_nav_onion_count;

/* The onion landing-page "Power Node Apps" grid, chrome entries included. */
extern const struct zcl_site_grid_entry g_zcl_site_app_grid[];
extern const size_t g_zcl_site_app_grid_count;

/* Emits the onion front-door global nav — the generated successor of the
 * ONION_GLOBAL_NAV literal — into buf, clamped at max. Returns bytes
 * actually written (excluding the NUL snprintf writes). */
size_t zcl_site_onion_nav_emit(char *buf, size_t max);

#endif /* ZCL_NET_SITE_ROUTES_H */
