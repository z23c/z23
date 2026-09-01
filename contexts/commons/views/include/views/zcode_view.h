/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCODE Library HTML site views (slice 13) — the server-rendered pages for
 * the `/zcode*` route family, served identically over the embedded Tor
 * onion service and the public HTTPS listener. Rendering only: the
 * controller (contexts/commons/controllers/src/zcode_site_controller.c) owns routing and
 * every projection read; these functions take the already-read projection
 * rows (the SAME contexts/commons/modules/vcs projections the zcode.* typed commands render)
 * and emit bounded HTML on the shared design system (views/site_layout.h +
 * the compiled site_css), exactly like views/name_view.c.
 *
 * Escaping contract: every user-controlled string (package names, publisher
 * data, ZNAM pointers, detail text) passes through html_escape() before it
 * touches the page; every hash/key renders as lowercase hex. Pages are
 * bounded: the row caps in zcode_site_controller.c mirror the typed-command
 * render caps so a large store can never blow the 64 KiB onion response
 * buffer. Nothing here executes, installs, or builds published content —
 * the download route serves bytes with Content-Disposition: attachment and
 * X-Content-Type-Options: nosniff, never anything executable inline. */

#ifndef ZCL_VIEWS_ZCODE_VIEW_H
#define ZCL_VIEWS_ZCODE_VIEW_H

#include "vcs/package_attest.h"
#include "vcs/package_badge.h"
#include "vcs/package_contributor.h"
#include "vcs/package_index.h"
#include "vcs/package_manifest.h"
#include "vcs/package_rank.h"
#include "vcs/package_release.h"
#include "vcs/package_reward.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Row caps (mirror the typed-command render caps: search 16, show files
 * 32, leaderboard page VCS_RANK_MAX_PAGE_ROWS). The badge page caps higher
 * because a badge row is short. */
#define ZCODE_VIEW_MAX_ROWS 16u
#define ZCODE_VIEW_MAX_FILES 32u
#define ZCODE_VIEW_MAX_ATTESTS 16u
#define ZCODE_VIEW_MAX_BADGES 64u

/* Wrap a rendered HTML body in a raw HTTP/1.1 response (200 / custom
 * status), the name_view.c convention. */
size_t zcode_html_response(const char *body, size_t body_len,
                           uint8_t *resp, size_t max);
size_t zcode_error_response(const char *status_code,
                            const char *body, size_t body_len,
                            uint8_t *resp, size_t max);

/* Wrap arbitrary bytes (embedded NULs safe — memcpy, never printf %s) as
 * a 200 OK download: engine/application/octet-stream + Content-Disposition:
 * attachment + X-Content-Type-Options: nosniff. Returns 0 (nothing
 * written) when headers+body do not fit `max` — the caller must answer
 * with an honest capacity error, never a truncated payload. */
size_t zcode_download_response(const uint8_t *body, size_t body_len,
                               const char *download_filename,
                               uint8_t *resp, size_t max);

/* /zcode — the ZCODE Library landing page: projection counts + section
 * links. swarm_live reports whether the node-global swarm engine exists. */
size_t zcode_view_index(size_t packages, uint64_t settled_facts,
                        size_t badges, bool swarm_live,
                        uint8_t *resp, size_t max);

/* /zcode/packages[?q=...] — bounded search rows out of the package index
 * projection (the zcode.package.search row shape). query may be NULL. */
size_t zcode_view_packages(const struct vcs_package_index_entry **rows,
                           size_t rendered, size_t total, size_t scanned,
                           const char *query, uint8_t *resp, size_t max);

/* Inputs for the /zcode/package/<root> page. All borrowed. */
struct zcode_view_package_input {
    const struct vcs_package_index_entry *entry;   /* required */
    const struct vcs_package_release *release;     /* NULL when unreadable */
    const struct vcs_package_manifest *manifest;   /* NULL when absent */
    size_t files_shown;                            /* <= ZCODE_VIEW_MAX_FILES */
    const struct vcs_package_attest *attestations; /* may be NULL */
    size_t attest_shown;
    size_t attest_matching; /* attestation wires naming this root */
    size_t attest_scanned;  /* attestation wires scanned (bounded) */
    long swarm_advertisers; /* <0 when the swarm view is unavailable */
};

/* /zcode/package/<root> — release envelope (incl. the publisher signature
 * hex), manifest summary + bounded file page, verifier attestations, and
 * the local swarm's advertiser count for the root. */
size_t zcode_view_package(const struct zcode_view_package_input *in,
                          uint8_t *resp, size_t max);

/* Inputs for the /zcode/publisher/<pubkey> page. All borrowed. */
struct zcode_view_publisher_input {
    const struct vcs_zcode_contributor *contributor;   /* required */
    const struct vcs_reward_contributor_totals *totals; /* NULL: no ledger */
    const struct vcs_rank_entry *rank;  /* NULL when unranked (all-time) */
    const struct vcs_badge *badges;     /* may be NULL */
    size_t badges_shown;
    size_t badges_total;
    bool badge_policy;                  /* false: no policy lens configured */
    const struct vcs_package_index_entry **packages; /* may be NULL */
    size_t packages_shown;
    size_t packages_total;
};

/* /zcode/publisher/<pubkey> — contributor profile (authoritative release
 * facts + pointer), ZCODE Score (earned, never a balance), all-time rank,
 * earned badges, and the publisher's packages. */
size_t zcode_view_publisher(const struct zcode_view_publisher_input *in,
                            uint8_t *resp, size_t max);

/* /zcode/leaderboard — period selector. */
size_t zcode_view_leaderboard_index(uint8_t *resp, size_t max);

/* /zcode/leaderboard/<period> — the ZCODE Rankings table for one period:
 * ranked EARNED score (never a token balance), strict 1..N rows. */
size_t zcode_view_leaderboard(enum vcs_rank_period period,
                              const struct vcs_rank_window *window,
                              const struct vcs_rank_entry *rows,
                              size_t shown, size_t total,
                              size_t facts_used, size_t facts_dropped,
                              bool contributors_truncated,
                              uint8_t *resp, size_t max);

/* /zcode/badges — the earned-badge index. recognized_lens reports whether
 * the operator badge policy was loaded (rows are recognized badges) or not
 * (every signature-valid wire, honestly labelled). */
size_t zcode_view_badges(const struct vcs_badge *badges, size_t shown,
                         size_t total, bool recognized_lens,
                         uint32_t corrupt, bool truncated,
                         uint8_t *resp, size_t max);

/* Honest 404s: an unknown /zcode route, a package root no published
 * release names, and a publisher key that has never published here. */
size_t zcode_view_route_not_found(const char *path, uint8_t *resp,
                                  size_t max);
size_t zcode_view_package_not_found(const char *root_hex, uint8_t *resp,
                                    size_t max);
size_t zcode_view_publisher_not_found(const char *publisher_hex,
                                      uint8_t *resp, size_t max);

#endif /* ZCL_VIEWS_ZCODE_VIEW_H */
