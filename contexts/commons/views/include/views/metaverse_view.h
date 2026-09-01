/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Metaverse HTML site views — the server-rendered pages for the
 * `/metaverse*` route family, served identically over the embedded Tor
 * onion service and the public HTTPS listener. Rendering only: the
 * controller (contexts/commons/controllers/src/metaverse_site_controller.c) owns routing
 * and every projection read; these functions take the already-read
 * projection rows (the SAME projections the metaverse.* / zcode.commons.*
 * typed commands render) and emit bounded HTML on the shared design system
 * (views/site_layout.h + the compiled site_css), exactly like
 * views/zcode_view.c.
 *
 * Escaping contract: every user-controlled string (space names and
 * descriptions, owner principals, reasons) passes through html_escape()
 * before it touches the page; every hash/key renders as lowercase hex.
 * Pages are bounded: the row caps below mirror the typed-command render
 * caps so a large store can never blow the 64 KiB onion response buffer.
 * Nothing here mutates anything — the whole family is a read surface. */

#ifndef ZCL_VIEWS_METAVERSE_VIEW_H
#define ZCL_VIEWS_METAVERSE_VIEW_H

#include "services/property_catalog.h"
#include "vcs/zcode_commons_projection.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Row caps (mirror the typed-command render caps: metaverse.property.list
 * defaults to 16 items). */
#define METAVERSE_VIEW_MAX_ROWS 16u
#define METAVERSE_VIEW_MAX_SPACES 16u

/* Wrap a rendered HTML body in a raw HTTP/1.1 response (200 / custom
 * status), the zcode_view.c convention. */
size_t metaverse_html_response(const char *body, size_t body_len,
                               uint8_t *resp, size_t max);
size_t metaverse_error_response(const char *status_code,
                                const char *body, size_t body_len,
                                uint8_t *resp, size_t max);

/* Inputs for the /metaverse landing page. All borrowed. */
struct metaverse_view_index_input {
    /* The sovereign property catalog summary (metaverse.property.list). */
    bool property_read;         /* false: the projection itself failed */
    size_t property_total;      /* properties across every kind */
    size_t property_kinds;      /* kinds enumerated (always all of them) */
    size_t property_unavailable;

    /* Locally known published spaces (metaverse.space.show records). */
    bool space_read;
    size_t space_manifests;     /* space_manifest.v1 objects in the CAS */
    size_t space_services;      /* service_descriptor.v1 objects */

    /* The ZC23 Living Commons summary (zcode.commons.status) — a
     * SIMULATION, labelled as such on the page. */
    bool commons_built;
    const char *commons_status; /* "unknown" / "partial" / "complete" */
    size_t commons_creations;
    size_t commons_epochs;
    uint64_t commons_minted_atoms;
    uint64_t commons_attributed_atoms;
};

/* /metaverse — the landing page: the mission, the commons status summary
 * (labelled SIMULATION), and links to the three section pages. */
size_t metaverse_view_index(const struct metaverse_view_index_input *in,
                            uint8_t *resp, size_t max);

/* /metaverse/property[?kind=<name>] — the sovereign property catalog: the
 * per-kind coverage table (kind, authority, settlement class, availability)
 * plus the bounded property rows with status and evidence grade. `page` is
 * the projection the metaverse.property.list command renders;
 * `kind_filter` may be NULL (unfiltered). */
size_t metaverse_view_property(const struct property_catalog_page *page,
                               const char *kind_filter,
                               uint8_t *resp, size_t max);

/* One locally known published space (a space_manifest.v1 CAS record that
 * metaverse_space_show re-derived and identified). */
struct metaverse_view_space_row {
    char root_hex[65];
    char name[64];
    char owner_hex[65];         /* owner ZID (delegation master pubkey) */
    uint64_t sequence;
    uint64_t not_before;
    uint64_t expiry;
    uint32_t services;
    uint32_t objects;
    uint32_t portals;
    bool currently_active;      /* vcs_space_manifest_validate_at(now) */
    bool has_admission;
};

/* /metaverse/space — the locally known published spaces: every
 * space_manifest.v1 record in the workspace CAS, each re-parsed and
 * re-derived by the same metaverse_space_show read path the
 * metaverse.space.show command uses. `scanned` is the bounded number of
 * CAS objects inspected; `truncated` reports a scan or page cap. */
size_t metaverse_view_space(const struct metaverse_view_space_row *rows,
                            size_t shown, size_t total, size_t services,
                            size_t scanned, bool truncated,
                            uint8_t *resp, size_t max);

/* /metaverse/commons — the ZC23 Living Commons projection (the same
 * vcs_zcode_commons_projection_build read zcode.commons.status /
 * zcode.commons.epoch render): verification status, mint/attribution
 * totals, creation counts, and the epoch table. Clearly labelled a
 * SIMULATION. `projection` must not be NULL. */
size_t metaverse_view_commons(
    const struct vcs_zcode_commons_projection *projection,
    uint8_t *resp, size_t max);

/* Honest 404: an unknown /metaverse route. */
size_t metaverse_view_route_not_found(const char *path, uint8_t *resp,
                                      size_t max);

#endif /* ZCL_VIEWS_METAVERSE_VIEW_H */
