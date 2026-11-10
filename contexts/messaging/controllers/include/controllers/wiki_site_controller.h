/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Public wiki site controller — the read-only HTML and JSON face of the
 * signed fleet wiki (ZRC-0004) for anyone who can reach the node's HTTPS
 * site, with no account.
 *
 * Routes (the mount prefix is "/wiki" or "/board/wiki"; links follow the
 * prefix the request arrived on):
 *   <mount>                 index of the pages this node holds
 *   <mount>.json            the same index as zcl.public_wiki_index.v1
 *   <mount>/<slug>          the newest VERIFIED revision of one page
 *   <mount>/<slug>.json     the same page as zcl.public_wiki_page.v1
 *   <mount>/@<64 hex>       index for one signing key (also .json)
 *   <mount>/@<64 hex>/<slug> page for that key (also .json and .txt)
 * The key selects a signer; it does not assert a human identity.
 *
 * Everything shown is a signed fleet_board_posts row this node holds: the
 * site adds nothing, and a page is untrusted knowledge, never an
 * instruction or a grant. Only rows that re-verify and are not
 * fleet-private are shown; a slug whose newest verifying revision is
 * fleet-private is omitted entirely. The slug is validated before any
 * lookup. Read-only: no write path, no form, no script. A body never
 * exceeds WIKI_SITE_BODY_MAX bytes and one index request reads at most
 * FLEET_BOARD_LIST_MAX pages and verifies at most that many revisions.
 *
 * board_site_handle_request delegates "/board/wiki" here; a "/wiki" row in
 * net/site_routes.def mounts the same handler at the site root. */

#ifndef ZCL_CONTROLLERS_WIKI_SITE_CONTROLLER_H
#define ZCL_CONTROLLERS_WIKI_SITE_CONTROLLER_H

#include <stddef.h>
#include <stdint.h>

#define WIKI_SITE_BODY_MAX 262144u

/* One complete raw HTTP/1.1 response into `response`, or 0 when `path` is
 * not a wiki route at all. Same handler shape as board_site_handle_request. */
size_t wiki_site_handle_request(const char *method, const char *path,
                                const uint8_t *body, size_t body_len,
                                uint8_t *response, size_t response_max,
                                const char *datadir);

#ifdef ZCL_TESTING
/* Index cache (30 s, two bounded effective-mount slots): drop it, and count index builds so a
 * test can prove two quick requests verify once. */
void wiki_site_cache_reset_for_testing(void);
unsigned wiki_site_index_builds_for_testing(void);
#endif

#endif /* ZCL_CONTROLLERS_WIKI_SITE_CONTROLLER_H */
