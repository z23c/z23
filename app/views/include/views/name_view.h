/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names (ZNAM) HTML site views — the presentation half of the names
 * MVC slice. Renders the browse index, a name's profile page (which doubles
 * as the default hosted site when a name has no onion/url binding), and the
 * on-chain register form (CSRF token + in-browser proof-of-work solver).
 *
 * Pure rendering: every function fills a caller-owned response buffer with a
 * complete raw HTTP/1.1 response and returns the byte count (0 = would not
 * fit). No storage, no chain access — the controller reads the projection
 * and hands typed rows in. */

#ifndef ZCL_VIEWS_NAME_VIEW_H
#define ZCL_VIEWS_NAME_VIEW_H

#include "models/znam.h"
#include "controllers/name_resolver.h"   /* struct name_history */

#include <stddef.h>
#include <stdint.h>

/* Shared HTTP wrappers (Content-Length-bearing). */
size_t name_html_response(const char *body, size_t body_len,
                          uint8_t *resp, size_t max);
size_t name_error_response(const char *status_code,
                           const char *body, size_t body_len,
                           uint8_t *resp, size_t max);

/* Shared page close (</main> + site footer). Exposed so sibling name views
 * (the onion gateway) close a page exactly the way this one does. */
int name_view_body_end(char *buf, size_t max);

/* GET /names — browse index of registered names. `total` is the whole
 * registry's size and is what the headline reports; the page renders at
 * most a newest-first window over it and says so when it stops short.
 * A negative total (store unreadable) keeps any count off the page
 * rather than implying the window is everything. */
size_t name_view_index(const struct znam_entry *entries, int count,
                       int total, uint8_t *resp, size_t max);

/* GET /names/{name} and the /n/{name} profile fallback — a name's public
 * profile page (owner, primary target, resolver records, and the on-chain
 * history that makes the name auditable). Serves as the default hosted site
 * when the name binds no onion/url target. `text`/`addr` arrays may be
 * empty; `hist` may be NULL (the history card is then omitted).
 * `total_text`/`total_addr` are the uncapped record counts behind the
 * arrays: when fewer rows actually render than a total reports, the page
 * says so instead of implying it showed everything. A negative total
 * disables that disclosure for its kind. */
size_t name_view_profile(const struct znam_entry *e,
                         const struct znam_text_record *text, int ntext,
                         int total_text,
                         const struct znam_addr_record *addr, int naddr,
                         int total_addr,
                         const struct name_history *hist,
                         uint8_t *resp, size_t max);

/* GET /names/register — the on-chain registration form. Embeds the CSRF
 * token and the product-style proof-of-work challenge; a from-scratch
 * SHA3-256 solver runs in the browser and fills pow_nonce before submit. */
size_t name_view_register_form(const char *csrf_tok, int64_t pow_ts,
                               uint8_t *resp, size_t max);

/* POST /names/register result page. On success txid is non-empty; on refusal
 * err carries the reason. */
size_t name_view_register_result(const char *name, const char *value,
                                 const char *txid, const char *err,
                                 uint8_t *resp, size_t max);

/* THE resolution-failure page. One renderer, one verdict per call, so the
 * three cases docs/spec/power-node-contract.md requires to stay apart —
 * malformed label, absent registration, registered-but-no-such-target —
 * reach a visitor as three different pages with three different HTTP
 * statuses. The machine-readable verdict also rides an
 * `X-ZCL-Name-Error: <code>` response header, so a scripted client does
 * not have to scrape the HTML. `entry` is the registration when there is
 * one (NAME_RESOLVE_NO_SUCH_TARGET), else NULL. `requested_type` is the
 * type the visitor asked for, or NULL. */
size_t name_view_resolve_error(const char *name,
                               enum name_resolve_status status,
                               const char *requested_type,
                               const struct znam_entry *entry,
                               uint8_t *resp, size_t max);

#endif /* ZCL_VIEWS_NAME_VIEW_H */
