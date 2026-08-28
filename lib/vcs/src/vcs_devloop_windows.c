/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Fail-closed native Windows ZVCS publication surface. */

#if defined(_WIN32)

#include "vcs/vcs_devloop.h"

#include <stdio.h>
#include <string.h>

static bool devloop_windows_refuse_receipt(uint8_t root[32], bool *reused)
{
    if (root) memset(root, 0, 32);
    if (reused) *reused = false;
    return false;
}

bool vcs_devloop_publication_job_load(const char *r, const uint8_t j[32],
                                      struct vcs_devloop_publication_job *o)
{ (void)r; (void)j; if (o) memset(o, 0, sizeof(*o)); return false; }
bool vcs_devloop_publication_job_is_queued(const char *r, const uint8_t j[32])
{ (void)r; (void)j; return false; }
bool vcs_devloop_publication_job_requeue(const char *r, const uint8_t j[32],
                                         bool *u)
{ (void)r; (void)j; if (u) *u = false; return false; }
bool vcs_devloop_publication_receipt_load(
    const char *r, const uint8_t x[32], struct vcs_devloop_publication_receipt *o)
{ (void)r; (void)x; if (o) memset(o, 0, sizeof(*o)); return false; }
bool vcs_devloop_publication_progress_load(
    const char *r, const uint8_t j[32], struct vcs_devloop_publication_receipt *o,
    uint8_t x[32])
{ (void)r; (void)j; if (o) memset(o, 0, sizeof(*o)); if (x) memset(x, 0, 32); return false; }
bool vcs_devloop_publication_advance_waiting_acceptance(
    const char *r, const uint8_t j[32], uint8_t x[32], bool *u)
{ (void)r; (void)j; return devloop_windows_refuse_receipt(x, u); }
bool vcs_devloop_publication_advance_proven_work(
    const char *r, const uint8_t j[32], const uint8_t a[32], int64_t n,
    uint8_t x[32], bool *u)
{ (void)r; (void)j; (void)a; (void)n; return devloop_windows_refuse_receipt(x, u); }
bool vcs_devloop_publication_advance_package_mapping(
    const char *r, const uint8_t j[32], const uint8_t m[32], uint64_t b,
    uint32_t n, uint32_t q, uint8_t x[32], bool *u)
{ (void)r; (void)j; (void)m; (void)b; (void)n; (void)q; return devloop_windows_refuse_receipt(x, u); }
bool vcs_devloop_publication_advance_release(
    const char *r, const uint8_t j[32], const uint8_t m[32],
    const uint8_t a[32], uint8_t x[32], bool *u)
{ (void)r; (void)j; (void)m; (void)a; return devloop_windows_refuse_receipt(x, u); }
bool vcs_devloop_publication_advance_passport(
    const char *r, const uint8_t j[32], const uint8_t m[32],
    const uint8_t a[32], const uint8_t p[32], uint8_t x[32], bool *u)
{ (void)r; (void)j; (void)m; (void)a; (void)p; return devloop_windows_refuse_receipt(x, u); }
bool vcs_devloop_publication_advance_workspace(
    const char *r, const uint8_t j[32], const uint8_t m[32],
    const uint8_t a[32], const uint8_t p[32], const uint8_t w[32],
    uint8_t x[32], bool *u)
{ (void)r; (void)j; (void)m; (void)a; (void)p; (void)w; return devloop_windows_refuse_receipt(x, u); }
bool vcs_devloop_publication_advance_provider(
    const char *r, const uint8_t j[32], const uint8_t *w, size_t l,
    const struct vcs_zcode_dht_record_verify_context *v, uint8_t x[32], bool *u)
{ (void)r; (void)j; (void)w; (void)l; (void)v; return devloop_windows_refuse_receipt(x, u); }
bool vcs_devloop_publication_storage_ack_target(
    const char *r, const uint8_t j[32],
    const struct vcs_zcode_dht_record_verify_context *v,
    struct vcs_devloop_publication_ack_target *o)
{ (void)r; (void)j; (void)v; if (o) memset(o, 0, sizeof(*o)); return false; }
bool vcs_devloop_publication_advance_storage_acks(
    const char *r, const uint8_t j[32], const uint8_t *const w[],
    const size_t l[], size_t c,
    const struct vcs_zcode_dht_record_verify_context *v, uint8_t x[32], bool *u)
{ (void)r; (void)j; (void)w; (void)l; (void)c; (void)v; return devloop_windows_refuse_receipt(x, u); }
bool vcs_devloop_publication_source_reproduction_target(
    const char *r, const uint8_t j[32],
    const struct vcs_zcode_dht_record_verify_context *v,
    struct vcs_devloop_publication_ack_target *o)
{ (void)r; (void)j; (void)v; if (o) memset(o, 0, sizeof(*o)); return false; }
bool vcs_devloop_publication_advance_source_reproduction_ack(
    const char *r, const uint8_t j[32], const uint8_t *w, size_t l,
    const struct vcs_zcode_dht_record_verify_context *v, uint8_t x[32], bool *u)
{ (void)r; (void)j; (void)w; (void)l; (void)v; return devloop_windows_refuse_receipt(x, u); }

static void devloop_windows_anchor_refused(struct vcs_devloop_anchor_result *o)
{
    if (!o) return;
    memset(o, 0, sizeof(*o));
    o->status = VCS_DEVLOOP_ANCHOR_REFUSED;
    (void)snprintf(o->error, sizeof(o->error),
                   "native Windows ZVCS publication requires a validated directory-relative lock capability");
}

void vcs_devloop_run_initial_baseline(const char *r,
                                      struct vcs_devloop_anchor_result *o)
{ (void)r; devloop_windows_anchor_refused(o); }
void vcs_devloop_anchor_cycle(const char *r, const struct vcs_devloop_verdict *v,
                              struct vcs_devloop_anchor_result *o)
{ (void)r; (void)v; devloop_windows_anchor_refused(o); }
void vcs_devloop_publication_bind_accepted_candidate(
    const char *a, const char *c, const uint8_t w[32], const uint8_t s[32],
    int64_t n, struct vcs_devloop_accepted_candidate_result *o)
{
    (void)a; (void)c; (void)w; (void)s; (void)n;
    if (!o) return;
    memset(o, 0, sizeof(*o));
    (void)snprintf(o->error, sizeof(o->error),
                   "native Windows ZVCS publication is not qualified");
}

#else
typedef int vcs_devloop_windows_translation_unit_anchor;
#endif
