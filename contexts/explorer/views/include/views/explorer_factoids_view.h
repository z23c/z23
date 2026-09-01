/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer factoids view — historian nerd stats page with SHA3 data
 * receipts. Renders the full HTML page and the /api/factoids JSON from
 * the read-only explorer projection. Controllers parse + delegate here. */

#ifndef ZCL_VIEWS_EXPLORER_FACTOIDS_VIEW_H
#define ZCL_VIEWS_EXPLORER_FACTOIDS_VIEW_H

#include <stdint.h>
#include <stddef.h>

/* Render the full factoids HTML page into buf. Returns bytes written,
 * 0 on error. datadir: path to data directory (for node.db). */
size_t explorer_factoids_build(uint8_t *buf, size_t buf_max, const char *datadir);

/* Render full factoids HTML while capping height-derived facts to the
 * currently served H* frontier. Pass served_height < 0 to publish the full
 * index tip. */
size_t explorer_factoids_build_for_served_tip(uint8_t *buf, size_t buf_max,
                                              const char *datadir,
                                              int64_t served_height);

/* Render the /api/factoids JSON response (with HTTP headers). */
size_t explorer_factoids_build_json(uint8_t *buf, size_t buf_max,
                                     const char *datadir);

/* Render /api/factoids while capping height-derived facts to the currently
 * served H* frontier. Pass served_height < 0 to publish the full index tip. */
size_t explorer_factoids_build_json_for_served_tip(uint8_t *buf,
                                                   size_t buf_max,
                                                   const char *datadir,
                                                   int64_t served_height);

#endif
