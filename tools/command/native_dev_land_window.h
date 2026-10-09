/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The lander's side of the two-lander LAND-WINDOW mail protocol
 * (native_dev_land_window.c). dev.land calls these to defer a proof start
 * while another host proves on the same base, to announce its own window
 * with an estimate measured from this host's proof history, to re-announce
 * when a proof outlives that estimate, and to close the window with LANDED
 * or RELEASED. Every post goes through the dev.agent.mail post path and only
 * when the state root's mail dir already exists; a failed post is reported,
 * never fatal to the landing. */

#ifndef ZCL_NATIVE_DEV_LAND_WINDOW_H
#define ZCL_NATIVE_DEV_LAND_WINDOW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A foreign window counts this long past its expected-done time; after that
 * a window nobody closed is ignored (fail-open) and counted as stale. */
#define ZCL_LAND_WINDOW_GRACE_S (10 * 60)

/* Estimate bounds and the no-history fallback (proofs on the maintainer
 * host measured 7-35 min on 2026-10-09). */
#define ZCL_LAND_WINDOW_FALLBACK_S (30 * 60)
#define ZCL_LAND_WINDOW_FLOOR_S (5 * 60)
#define ZCL_LAND_WINDOW_CEIL_S (3 * 60 * 60)
#define ZCL_LAND_WINDOW_SAMPLE 20
#define ZCL_LAND_WINDOW_MIN_SAMPLES 3

/* Two re-announcements of one window are at least this far apart, and a
 * re-announced window is always at least this far ahead of now. */
#define ZCL_LAND_WINDOW_REANNOUNCE_S (5 * 60)

#define ZCL_LAND_WINDOW_HOST_MAX 64u

struct zcl_land_window_estimate {
    int64_t seconds; /* p75 clamped to [FLOOR, CEIL], or FALLBACK */
    int64_t p75_s;
    int64_t p90_s;
    int64_t max_s;
    int samples;   /* real proofs in the sample actually used */
    bool measured; /* false: fewer than MIN_SAMPLES, FALLBACK used */
    char shape[12]; /* "exact", "universal" or "any" */
};

/* Measured proof wall on this host: request epoch (line 4 of `request`) to
 * the last write of `phases.txt`, over attempts under
 * <proof_root>/.cache/zcl-dev-proof/attempts whose phases.txt records a
 * `step=test` row. The newest SAMPLE by start are used, restricted to
 * `shape` ("exact" or "universal", from logs/<pair>.test-selection.log) when
 * that shape alone has MIN_SAMPLES, else every shape. Never fails: no
 * history yields measured=false and FALLBACK. */
void zcl_land_window_estimate(const char *proof_root, const char *shape,
                              struct zcl_land_window_estimate *out);

/* The test-selection shape of the newest attempt for (local, base), or
 * false when that attempt has not written one yet. */
bool zcl_land_window_attempt_shape(const char *proof_root, const char *local,
                                   const char *base, char shape[12]);

struct zcl_land_window_hit {
    bool open;              /* a foreign window on the base counts now */
    char host[ZCL_LAND_WINDOW_HOST_MAX + 1];
    char candidate[11];
    char base[11];
    int64_t seconds_left;   /* of the latest-ending open window; <0 overran */
    int64_t open_count;
    int64_t stale;          /* past expected-done + grace, never closed */
    int64_t skipped;
};

/* Scan the mail dir for windows other hosts than `host` announced on `base`
 * (any base when NULL or empty), not closed, and not past expected-done +
 * grace_s. False only when the scan itself could not run. */
bool zcl_land_window_foreign(const char *host, const char *base, int64_t now,
                             int64_t grace_s, struct zcl_land_window_hit *hit);

/* This lander's own window, persisted in a sidecar file. */
struct zcl_land_window_self {
    const char *sidecar; /* e.g. <state>/land/window.state */
    const char *host;
    const char *from;    /* mail sender for every window and close row */
};

enum zcl_land_window_act {
    ZCL_LAND_WINDOW_NONE = 0,
    ZCL_LAND_WINDOW_ANNOUNCED,
    ZCL_LAND_WINDOW_REANNOUNCED,
    ZCL_LAND_WINDOW_CLOSED,
    ZCL_LAND_WINDOW_FAILED,
};

/* A proof of (candidate, base) starts now. Announces once per pair: a
 * sidecar already holding the pair is NONE. A sidecar holding another pair
 * is closed RELEASED first. `note` names what happened. */
enum zcl_land_window_act zcl_land_window_begin(
    const struct zcl_land_window_self *self, const char *candidate,
    const char *base, int64_t now, const struct zcl_land_window_estimate *est,
    char *note, size_t cap);

/* The proof is still running. Once now passes the announced expected-done,
 * and at most every REANNOUNCE_S, post the window again with expected-done
 * at proof start + the first of p75, p90, max (shape of this attempt when
 * known) that lies at least REANNOUNCE_S ahead, else now + 2*REANNOUNCE_S. */
enum zcl_land_window_act zcl_land_window_tick(
    const struct zcl_land_window_self *self, const char *proof_root,
    int64_t now, char *note, size_t cap);

/* Close the sidecar's window unless it is (keep_candidate, keep_base):
 * LANDED when its candidate is `landed_candidate`, else RELEASED. A failed
 * post keeps the sidecar so a later call closes it. */
enum zcl_land_window_act zcl_land_window_close(
    const struct zcl_land_window_self *self, const char *keep_candidate,
    const char *keep_base, const char *landed_candidate, char *note,
    size_t cap);

bool zcl_land_window_host_ok(const char *host);

#endif
