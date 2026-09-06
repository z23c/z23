/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Board site controller — the read-only HTML face of the fleet board's
 * PUBLIC rooms. Every post the site shows is a signed fleet_board_posts row
 * this node holds; the site adds nothing, so a reader with the post bytes
 * can check every signature themselves.
 *
 * Routes:
 *   /board                room index — the public rooms this node carries
 *   /board/room/<name>    one room, newest first (name is [a-z0-9-])
 *
 * The scope discipline of ZRC-0009 applies here with full force: the site
 * reads only non-fleet rows, so a fleet-private post, its room, and even its
 * existence never reach a page. Rendering is read-only — no POST surface, no
 * form, no write path.
 *
 * Registered as the /board row in net/site_routes.def; dispatch (onion and
 * HTTPS) is generated from that registry. */

#ifndef ZCL_CONTROLLERS_BOARD_SITE_CONTROLLER_H
#define ZCL_CONTROLLERS_BOARD_SITE_CONTROLLER_H

#include <stddef.h>
#include <stdint.h>

/* One complete raw HTTP/1.1 response into `response`, or 0 when the path is
 * not a /board route at all. `datadir` is unused: the board lives in the
 * node database, reached through the process runtime like the fleet_board
 * RPC does, so the onion and HTTPS transports render the same rows. */
size_t board_site_handle_request(const char *method, const char *path,
                                 const uint8_t *body, size_t body_len,
                                 uint8_t *response, size_t response_max,
                                 const char *datadir);

#endif /* ZCL_CONTROLLERS_BOARD_SITE_CONTROLLER_H */
