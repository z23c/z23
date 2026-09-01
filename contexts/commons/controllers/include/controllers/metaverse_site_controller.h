/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Metaverse HTML site controller — the `/metaverse*` route family, wired
 * into BOTH transport dispatch chains (onion_service.c and
 * https_server.c) the same way the ZCODE Library site is:
 *
 *   GET /metaverse                     landing (mission + projection
 *                                      summaries + section links)
 *   GET /metaverse/property[?kind=...] the sovereign property catalog
 *                                      (kinds, evidence grades, settlement
 *                                      classes, bounded property rows)
 *   GET /metaverse/space               locally known published spaces
 *                                      (space_manifest.v1 CAS records)
 *   GET /metaverse/commons             the ZC23 Living Commons projection
 *                                      (labelled SIMULATION)
 *
 * TRUTH DISCIPLINE (owner directive): every page reads through the SAME
 * projections the typed commands call — the property catalog
 * (services/property_catalog.h, behind `metaverse property list`, with the
 * same guarded read-only node.db open), the workspace-CAS space records
 * via metaverse_space_show (behind `metaverse space show`), and
 * vcs_zcode_commons_projection_build (behind `zcode commons status` /
 * `zcode commons epoch`). There is no website database and no second
 * metaverse truth; a one-shot CLI and this site render the same facts.
 *
 * Reads only: no POST surface, no CSRF/PoW gate (nothing here mutates),
 * and the reads themselves are read-only-including-on-open (the catalog
 * reaches store bytes by path; node.db is opened strictly read-only and
 * an unrecovered WAL is a named refusal, never a recovery sweep). All
 * pages are bounded (the view row caps mirror the typed-command render
 * caps) so a large store cannot blow the 64 KiB onion response buffer. */

#ifndef ZCL_CONTROLLERS_METAVERSE_SITE_CONTROLLER_H
#define ZCL_CONTROLLERS_METAVERSE_SITE_CONTROLLER_H

#include <stddef.h>
#include <stdint.h>

/* Handle any /metaverse request. `datadir` is the node's data directory;
 * when NULL it resolves through GetDataDir(true) (the HTTPS listener
 * carries no datadir context). Returns bytes written (a complete raw
 * HTTP/1.1 response), or 0 if `path`/`response` are missing. */
size_t metaverse_site_handle_request(const char *method, const char *path,
                                     const uint8_t *body, size_t body_len,
                                     uint8_t *response, size_t response_max,
                                     const char *datadir);

#endif /* ZCL_CONTROLLERS_METAVERSE_SITE_CONTROLLER_H */
