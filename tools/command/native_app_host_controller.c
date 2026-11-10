/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Synchronize link availability and the user's Stop/Copy decisions. */
#define _POSIX_C_SOURCE 200809L
#include "command/native_app_host_controller.h"
#include "command/native_app_scratch.h"
#if !defined(_WIN32)
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "util/thread_registry.h"
#include "base/safe_alloc.h"
#include "platform/time_compat.h"
bool app_host_state_init(struct app_host_state *s)
{
    if (!s) return false;
    memset(s, 0, sizeof(*s)); return pthread_mutex_init(&s->mutex, NULL) == 0;
}
void app_host_state_stop(struct app_host_state *s)
{
    if (!s) return;
    pthread_mutex_lock(&s->mutex); s->stop = true; s->available = false;
    pthread_mutex_unlock(&s->mutex);
}
bool app_host_state_cancel(void *context)
{
    struct app_host_state *s = context; if (!s) return true;
    pthread_mutex_lock(&s->mutex); bool stop = s->stop; pthread_mutex_unlock(&s->mutex); return stop;
}
/* Caller holds the state mutex. A failed/backward clock cannot authorize Copy. */
static void ahs_expire_locked(struct app_host_state *s)
{
    if (!s->deadline_ms) return;
    int64_t now = platform_time_monotonic_ms();
    if (now <= 0 || now < s->started_ms || now < s->last_ms || now >= s->deadline_ms) {
        s->available = false; s->terminal = true;
    } else s->last_ms = now;
}
bool app_host_state_publish(const struct app_host_ready *ready, void *context)
{
    struct app_host_state *s = context; if (!s || !ready) return false;
    pthread_mutex_lock(&s->mutex); ahs_expire_locked(s);
    bool ok = !s->stop && !s->terminal && !s->finished && !s->ever_ready;
    if (ok) { s->ready = *ready; s->available = true; s->ever_ready = true; }
    pthread_mutex_unlock(&s->mutex); return ok;
}
void app_host_state_unavailable(void *context)
{
    struct app_host_state *s = context; if (!s) return;
    pthread_mutex_lock(&s->mutex); s->available = false; s->terminal = true; pthread_mutex_unlock(&s->mutex);
}
void app_host_state_finish(struct app_host_state *s, enum app_host_outcome outcome)
{
    if (!s) return;
    pthread_mutex_lock(&s->mutex); s->available = false; s->finished = true; s->outcome = outcome;
    pthread_mutex_unlock(&s->mutex);
}
bool app_host_state_snapshot(struct app_host_state *s, struct app_host_snapshot *out)
{
    if (!s || !out) return false;
    pthread_mutex_lock(&s->mutex); ahs_expire_locked(s);
    *out = (struct app_host_snapshot){s->stop, s->available, s->ever_ready, s->terminal, s->finished, s->outcome, s->ready};
    pthread_mutex_unlock(&s->mutex); return true;
}
bool app_host_state_copy(struct app_host_state *s, app_host_copy_fn copy, void *context)
{
    if (!s || !copy) return false;
    pthread_mutex_lock(&s->mutex); ahs_expire_locked(s);
    bool ok = !s->stop && !s->terminal && !s->finished && s->available && copy(&s->ready, context);
    pthread_mutex_unlock(&s->mutex); return ok;
}
void app_host_state_destroy(struct app_host_state *s)
{ if (s) (void)pthread_mutex_destroy(&s->mutex); }
struct app_host_owner {
    struct app_host_state state; struct app_host_job_args args;
    struct app_host_job_result result; pthread_t thread; bool joined;
    char self[4400], scratch[4400], name[160], release[65], package[65], publisher[67], sha[65];
};
static bool aho_inputs(struct app_host_owner *o, const struct app_host_job_args *a)
{
    if (!a || !an_scratch_copy_text(o->self, sizeof(o->self), a->self_path, false) ||
        !an_scratch_copy_text(o->scratch, sizeof(o->scratch), a->scratch_path, false) ||
        !an_scratch_copy_text(o->name, sizeof(o->name), a->name, false) ||
        !an_scratch_copy_text(o->release, sizeof(o->release), a->release_root, false) ||
        !an_scratch_copy_text(o->package, sizeof(o->package), a->package_root, false) ||
        !an_scratch_copy_text(o->publisher, sizeof(o->publisher), a->publisher, false) ||
        !an_scratch_copy_text(o->sha, sizeof(o->sha), a->carrier_sha256, false)) return false;
    o->args = *a; o->args.self_path = o->self; o->args.scratch_path = o->scratch;
    o->args.name = o->name; o->args.release_root = o->release; o->args.package_root = o->package;
    o->args.publisher = o->publisher; o->args.carrier_sha256 = o->sha;
    o->args.cancel = app_host_state_cancel; o->args.cancel_context = &o->state; return true;
}
static void *aho_run(void *context)
{
    struct app_host_owner *o = context;
    (void)app_host_job_run(&o->args, app_host_state_publish, app_host_state_unavailable, &o->state, &o->result);
    app_host_state_finish(&o->state, o->result.outcome); return NULL;
}
struct app_host_owner *app_host_owner_start(const struct app_host_job_args *args)
{
    struct app_host_owner *o = zcl_calloc(1, sizeof(*o), "app.host.owner");
    if (!o) return NULL;
    if (!aho_inputs(o, args)) { free(o); return NULL; }
    int64_t start = platform_time_monotonic_ms();
    if (start <= 0 || o->args.duration_ms < 3000u || o->args.duration_ms > 86400000u ||
        start > INT64_MAX - (int64_t)o->args.duration_ms) { free(o); return NULL; }
    o->args.service_deadline_ms = start + (int64_t)o->args.duration_ms;
    if (!app_host_state_init(&o->state)) { free(o); return NULL; }
    o->state.started_ms = start; o->state.last_ms = start; o->state.deadline_ms = o->args.service_deadline_ms;
    if (thread_registry_spawn("app-host", aho_run, o, &o->thread)) {
        app_host_state_destroy(&o->state); free(o); return NULL;
    }
    return o;
}
void app_host_owner_stop(struct app_host_owner *o) { if (o) app_host_state_stop(&o->state); }
bool app_host_owner_snapshot(struct app_host_owner *o, struct app_host_snapshot *out)
{ return o && app_host_state_snapshot(&o->state, out); }
bool app_host_owner_copy(struct app_host_owner *o, app_host_copy_fn copy, void *ctx)
{ return o && app_host_state_copy(&o->state, copy, ctx); }
bool app_host_owner_join(struct app_host_owner *o, struct app_host_job_result *out)
{
    if (!o || !out || o->joined) return false;
    int rc; do { rc = pthread_join(o->thread, NULL); } while (rc == EINTR);
    if (rc || (o->result.launched && !o->result.reaped)) return false;
    o->joined = true; *out = o->result; return true;
}
void app_host_owner_free(struct app_host_owner *o)
{
    if (!o || !o->joined) return;
    app_host_state_destroy(&o->state); free(o);
}
#else
typedef int app_host_controller_unavailable;
#endif
