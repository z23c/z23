/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * purpose: Split bounded site routes from query strings for Commons controllers.
 */
#ifndef ZCL_COMMONS_SITE_ROUTE_INTERNAL_H
#define ZCL_COMMONS_SITE_ROUTE_INTERNAL_H

#include <stddef.h>

/* route_max is positive. The returned query points into path, or is NULL. */
static inline const char *site_split_route(const char *path, char *route,
                                           size_t route_max)
{
    size_t rlen = 0;
    while (path[rlen] && path[rlen] != '?' && rlen < route_max - 1) {
        route[rlen] = path[rlen];
        rlen++;
    }
    route[rlen] = '\0';
    return path[rlen] == '?' ? path + rlen + 1 : NULL;
}

#endif
