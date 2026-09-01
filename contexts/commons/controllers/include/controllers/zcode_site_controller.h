/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCODE Library HTML site controller (slice 13) — the `/zcode*` route
 * family, wired into BOTH transport dispatch chains (onion_service.c and
 * https_server.c) the same way the ZCL Names site is:
 *
 *   GET /zcode                              landing (projection counts)
 *   GET /zcode/packages[?q=<keyword>]       bounded search over the index
 *   GET /zcode/package/<package-root>       release envelope + publisher
 *                                           signature + manifest + verifier
 *                                           attestations + swarm advertisers
 *   GET /zcode/publisher/<publisher-key>    contributor profile + ZCODE
 *                                           Score + all-time rank + badges
 *                                           + packages
 *   GET /zcode/leaderboard                  period selector
 *   GET /zcode/leaderboard/daily|weekly|monthly|all
 *                                           the ZCODE Rankings table
 *   GET /zcode/badges                       earned-badge index
 *   GET /zcode/download/<package-root>      the manifest wire (attachment)
 *   GET /zcode/download/<package-root>/<file-index>/<chunk-index>
 *                                           one chunk (attachment)
 *
 * TRUTH DISCIPLINE (owner directive): every page reads through the SAME
 * contexts/commons/modules/vcs read projections the zcode.* typed commands call — the package
 * index (search/show), the persisted release envelope + manifest wires
 * (recipe/verify), the reward ledger (score/rank), the rank projection
 * (leaderboards), the badge store (badges), and the node-global swarm
 * engine (advertiser counts). There is no website database and no second
 * package truth; a one-shot CLI and this site render the same facts.
 *
 * SAFE DOWNLOADING: the download routes serve manifest/chunk bytes with
 * Content-Disposition: attachment + X-Content-Type-Options: nosniff and
 * engine/application/octet-stream — never anything executable inline, and the
 * node never compiles or executes published content. Chunk bytes are
 * rehashed against the manifest-committed SHA3-256 before serving (the
 * store's rehash-on-read discipline); a mismatch is a named integrity
 * error, never silently served bytes.
 *
 * Reads only: no POST surface, no CSRF/PoW gate (nothing here mutates).
 * All pages are bounded (the view row caps mirror the typed-command
 * render caps) so a large store cannot blow the 64 KiB onion response
 * buffer. */

#ifndef ZCL_CONTROLLERS_ZCODE_SITE_CONTROLLER_H
#define ZCL_CONTROLLERS_ZCODE_SITE_CONTROLLER_H

#include <stddef.h>
#include <stdint.h>

/* Handle any /zcode request. `datadir` is the node's data directory; when
 * NULL it resolves through GetDataDir(true) (the HTTPS listener carries
 * no datadir context). Returns bytes written (a complete raw HTTP/1.1
 * response), or 0 if `path`/`response` are missing. */
size_t zcode_site_handle_request(const char *method, const char *path,
                                 const uint8_t *body, size_t body_len,
                                 uint8_t *response, size_t response_max,
                                 const char *datadir);

#endif /* ZCL_CONTROLLERS_ZCODE_SITE_CONTROLLER_H */
