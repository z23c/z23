/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded resident jobs: swarm-fetch one signed plugin package root,
 *          then verify and install it through plugin_dist_receive (the same
 *          path `plugin fetch` uses) as a NEW generation. See plugin_fetch_job.h. */

#include "plugin/plugin_fetch_job.h"

#include "plugin_internal.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "util/sync.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include <stdio.h>
#include <string.h>

struct pfj_job {
    bool used;
    bool local_complete;
    uint64_t id;
    enum plugin_fetch_state state;
    uint8_t root[32];
    bool allow_downgrade;
    struct plugin_fetch_view view;
};

struct plugin_fetch_table {
    zcl_mutex_t lock;
    uint64_t next_id;
    struct pfj_job jobs[PLUGIN_FETCH_TABLE_MAX];
};

static const char *const k_state_names[] = {
    [PLUGIN_FETCH_FETCHING] = "fetching", [PLUGIN_FETCH_INSTALLING] = "installing",
    [PLUGIN_FETCH_INSTALLED] = "installed", [PLUGIN_FETCH_FAILED] = "failed"
};

const char *plugin_fetch_state_string(enum plugin_fetch_state state)
{
    return (unsigned)state < sizeof(k_state_names) / sizeof(k_state_names[0]) ? k_state_names[state]
                                                                              : "unknown";
}

static const char *const k_begin_codes[] = {
    [PLUGIN_FETCH_BEGIN_OK] = "OK", [PLUGIN_FETCH_BEGIN_ARGUMENT] = "PLUGIN_FETCH_ARGUMENT",
    [PLUGIN_FETCH_BEGIN_BUSY] = "PLUGIN_FETCH_BUSY",
    [PLUGIN_FETCH_BEGIN_NO_SWARM] = "PLUGIN_FETCH_NO_SWARM",
    [PLUGIN_FETCH_BEGIN_NO_PEERS] = "PLUGIN_FETCH_NO_PEERS",
    [PLUGIN_FETCH_BEGIN_UNKNOWN_PEER] = "PLUGIN_FETCH_UNKNOWN_PEER",
    [PLUGIN_FETCH_BEGIN_SWARM_REFUSED] = "PLUGIN_FETCH_SWARM_REFUSED"
};

const char *plugin_fetch_begin_code(enum plugin_fetch_begin_status status)
{
    return (unsigned)status < sizeof(k_begin_codes) / sizeof(k_begin_codes[0]) ? k_begin_codes[status]
                                                                               : "PLUGIN_FETCH_UNKNOWN";
}

struct plugin_fetch_table *plugin_fetch_table_new(void)
{
    struct plugin_fetch_table *t = zcl_calloc(1, sizeof(*t), "plugin_fetch_table");
    if (!t)
        return NULL;
    zcl_mutex_init(&t->lock);
    t->next_id = 1;
    return t;
}

void plugin_fetch_table_free(struct plugin_fetch_table *table)
{
    if (!table)
        return;
    zcl_mutex_destroy(&table->lock);
    free(table);
}

static bool pfj_terminal(const struct pfj_job *j)
{
    return j->state == PLUGIN_FETCH_INSTALLED || j->state == PLUGIN_FETCH_FAILED;
}

static unsigned pfj_active(const struct plugin_fetch_table *t)
{
    unsigned n = 0;
    for (size_t i = 0; i < PLUGIN_FETCH_TABLE_MAX; i++)
        if (t->jobs[i].used && !pfj_terminal(&t->jobs[i]))
            n++;
    return n;
}

/* A free slot, else the oldest finished job's. NULL only if every slot is
 * active, which PLUGIN_FETCH_ACTIVE_MAX < PLUGIN_FETCH_TABLE_MAX rules out. */
static struct pfj_job *pfj_slot(struct plugin_fetch_table *t)
{
    struct pfj_job *oldest = NULL;
    for (size_t i = 0; i < PLUGIN_FETCH_TABLE_MAX; i++) {
        struct pfj_job *j = &t->jobs[i];
        if (!j->used)
            return j;
        if (pfj_terminal(j) && (!oldest || j->id < oldest->id))
            oldest = j;
    }
    return oldest;
}

static void pfj_fail(struct pfj_job *j, const char *code, const char *next, const char *detail)
{
    j->state = PLUGIN_FETCH_FAILED;
    j->view.state = PLUGIN_FETCH_FAILED;
    snprintf(j->view.code, sizeof(j->view.code), "%s", code);
    snprintf(j->view.next_action, sizeof(j->view.next_action), "%s", next ? next : "");
    snprintf(j->view.detail, sizeof(j->view.detail), "%s", detail ? detail : "");
}

static void pfj_set_state(struct pfj_job *j, enum plugin_fetch_state state)
{
    j->state = state;
    j->view.state = state;
}

static enum plugin_fetch_begin_status pfj_peers(const struct plugin_fetch_ctx *ctx,
                                                const struct plugin_fetch_request *rq,
                                                uint64_t peers[PLUGIN_FETCH_PEERS_MAX],
                                                size_t *count, char *detail, size_t cap)
{
    if (rq->peer_count > PLUGIN_FETCH_PEERS_MAX) {
        snprintf(detail, cap, "at most %u peers may be named", PLUGIN_FETCH_PEERS_MAX);
        return PLUGIN_FETCH_BEGIN_ARGUMENT;
    }
    if (rq->peers && rq->peer_count) {
        for (size_t i = 0; i < rq->peer_count; i++) {
            if (rq->peers[i] == 0 || !vcs_swarm_engine_peer_known(ctx->engine, rq->peers[i])) {
                snprintf(detail, cap, "peer %llu is not a connected swarm peer",
                         (unsigned long long)rq->peers[i]);
                return PLUGIN_FETCH_BEGIN_UNKNOWN_PEER;
            }
            peers[i] = rq->peers[i];
        }
        *count = rq->peer_count;
        return PLUGIN_FETCH_BEGIN_OK;
    }
    *count = vcs_swarm_engine_peer_ids(ctx->engine, peers, PLUGIN_FETCH_PEERS_MAX);
    if (*count == 0) {
        snprintf(detail, cap, "this node has no swarm peer to fetch from");
        return PLUGIN_FETCH_BEGIN_NO_PEERS;
    }
    return PLUGIN_FETCH_BEGIN_OK;
}

static enum plugin_fetch_begin_status pfj_validate(const struct plugin_fetch_ctx *ctx,
                                                   const struct plugin_fetch_request *rq,
                                                   char *detail, size_t cap)
{
    static const uint8_t zero[32];
    if (!ctx || !ctx->engine || !ctx->store || !ctx->plugins_dir || !ctx->scratch_dir) {
        snprintf(detail, cap, "package hosting (the swarm) is not running on this node");
        return PLUGIN_FETCH_BEGIN_NO_SWARM;
    }
    if (!rq || !rq->name || !plugin_name_valid(rq->name) || memcmp(rq->root, zero, 32) == 0 ||
        rq->max_bytes > PLUGIN_FETCH_BYTES_MAX || rq->timeout_s > PLUGIN_FETCH_TIMEOUT_MAX_S) {
        snprintf(detail, cap,
                 "a valid name, a nonzero root, max_bytes <= %llu and timeout <= %u s are required",
                 (unsigned long long)PLUGIN_FETCH_BYTES_MAX, PLUGIN_FETCH_TIMEOUT_MAX_S);
        return PLUGIN_FETCH_BEGIN_ARGUMENT;
    }
    return PLUGIN_FETCH_BEGIN_OK;
}

static void pfj_fill(struct pfj_job *j, uint64_t id, const struct plugin_fetch_request *rq,
                     uint64_t now, bool local)
{
    memset(j, 0, sizeof(*j));
    j->used = true;
    j->id = id;
    j->local_complete = local;
    j->allow_downgrade = rq->allow_downgrade;
    memcpy(j->root, rq->root, 32);
    uint32_t timeout = rq->timeout_s ? rq->timeout_s : PLUGIN_FETCH_TIMEOUT_DEFAULT_S;
    j->view.job = id;
    j->view.started = now;
    j->view.deadline = now + timeout;
    j->view.max_bytes = rq->max_bytes ? rq->max_bytes : PLUGIN_FETCH_BYTES_DEFAULT;
    zcl_hex_encode(rq->root, 32, j->view.root_hex);
    snprintf(j->view.name, sizeof(j->view.name), "%s", rq->name);
    pfj_set_state(j, PLUGIN_FETCH_FETCHING);
}

static struct pfj_job *pfj_find_active_root(struct plugin_fetch_table *t, const uint8_t root[32])
{
    for (size_t i = 0; i < PLUGIN_FETCH_TABLE_MAX; i++)
        if (t->jobs[i].used && !pfj_terminal(&t->jobs[i]) && memcmp(t->jobs[i].root, root, 32) == 0)
            return &t->jobs[i];
    return NULL;
}

static void pfj_begin_locked(struct plugin_fetch_table *t, const struct plugin_fetch_ctx *ctx,
                             const struct plugin_fetch_request *rq, uint64_t now,
                             struct plugin_fetch_begin_result *out)
{
    uint64_t peers[PLUGIN_FETCH_PEERS_MAX];
    size_t peer_count = 0;
    struct pfj_job *active = pfj_find_active_root(t, rq->root);
    if (active) {
        out->job = active->id;
        out->existing = true;
        return;
    }
    if (pfj_active(t) >= PLUGIN_FETCH_ACTIVE_MAX) {
        out->status = PLUGIN_FETCH_BEGIN_BUSY;
        snprintf(out->detail, sizeof(out->detail), "%u fetch jobs are already running; wait for one to finish",
                 PLUGIN_FETCH_ACTIVE_MAX);
        return;
    }
    out->status = pfj_peers(ctx, rq, peers, &peer_count, out->detail, sizeof(out->detail));
    if (out->status != PLUGIN_FETCH_BEGIN_OK)
        return;
    uint64_t max_bytes = rq->max_bytes ? rq->max_bytes : PLUGIN_FETCH_BYTES_DEFAULT;
    enum vcs_swarm_fetch_result r = vcs_swarm_engine_fetch_from_bounded(
        ctx->engine, rq->root, (int64_t)(now / 86400u), now, peers, peer_count, max_bytes);
    if (r != VCS_SWARM_FETCH_OK && r != VCS_SWARM_FETCH_ALREADY_COMPLETE) {
        out->status = PLUGIN_FETCH_BEGIN_SWARM_REFUSED;
        snprintf(out->detail, sizeof(out->detail), "the swarm refused the fetch: %s",
                 vcs_swarm_fetch_result_string(r));
        return;
    }
    struct pfj_job *slot = pfj_slot(t);
    if (!slot) {
        out->status = PLUGIN_FETCH_BEGIN_BUSY;
        return;
    }
    pfj_fill(slot, t->next_id++, rq, now, r == VCS_SWARM_FETCH_ALREADY_COMPLETE);
    out->job = slot->id;
}

void plugin_fetch_begin(struct plugin_fetch_table *table, const struct plugin_fetch_ctx *ctx,
                        const struct plugin_fetch_request *request, uint64_t now,
                        struct plugin_fetch_begin_result *out)
{
    if (!out)
        return;
    memset(out, 0, sizeof(*out));
    if (!table) {
        out->status = PLUGIN_FETCH_BEGIN_ARGUMENT;
        return;
    }
    out->status = pfj_validate(ctx, request, out->detail, sizeof(out->detail));
    if (out->status != PLUGIN_FETCH_BEGIN_OK)
        return;
    zcl_mutex_lock(&table->lock);
    pfj_begin_locked(table, ctx, request, now, out);
    zcl_mutex_unlock(&table->lock);
}

/* One FETCHING job, under the table lock. True when it is ready to install. */
static bool pfj_poll(struct pfj_job *j, const struct plugin_fetch_ctx *ctx, uint64_t now)
{
    struct vcs_swarm_download_status st = {0};
    bool found = !j->local_complete &&
                 vcs_swarm_engine_download_status(ctx->engine, j->root, &st);
    if (j->local_complete || (found && st.state == VCS_SWARM_DL_COMPLETE))
        return true;
    if (found) {
        j->view.present_chunks = st.present_chunks;
        j->view.total_chunks = st.total_chunks;
        j->view.present_bytes = st.present_bytes;
        j->view.total_bytes = st.total_bytes;
    }
    if (found && st.state == VCS_SWARM_DL_FAILED) {
        char detail[128];
        snprintf(detail, sizeof(detail), "the swarm failed the download: %s", st.rule ? st.rule : "unnamed rule");
        pfj_fail(j, "PLUGIN_FETCH_SWARM_FAILED", "check the peer and the size cap, then start a new fetch", detail);
    } else if (!found || st.state == VCS_SWARM_DL_INACTIVE) {
        pfj_fail(j, "PLUGIN_FETCH_SWARM_LOST", "the download record is gone; start a new fetch",
                 "the swarm no longer tracks this download");
    } else if (now >= j->view.deadline) {
        (void)vcs_swarm_engine_cancel(ctx->engine, j->root, now);
        pfj_fail(j, "PLUGIN_FETCH_TIMEOUT", "check that a peer serves the root, then start a new fetch",
                 "the transfer did not complete before the job deadline");
    }
    return false;
}

static void pfj_install(struct plugin_fetch_table *t, const struct plugin_fetch_ctx *ctx, uint64_t id,
                        const uint8_t root[32], const char *name, bool allow)
{
    struct plugin_dist_receive_request rq = {
        .store = ctx->store, .name = name, .plugins_dir = ctx->plugins_dir,
        .scratch_dir = ctx->scratch_dir, .allow_downgrade = allow
    };
    struct plugin_dist_received got;
    memcpy(rq.requested_root, root, 32);
    enum plugin_dist_status ds = plugin_dist_receive(&rq, &got);
    zcl_mutex_lock(&t->lock);
    for (size_t i = 0; i < PLUGIN_FETCH_TABLE_MAX; i++) {
        struct pfj_job *j = &t->jobs[i];
        if (!j->used || j->id != id)
            continue;
        if (ds != PLUGIN_DIST_OK) {
            char detail[256];
            if (ds == PLUGIN_DIST_ERR_PLUGIN)
                snprintf(detail, sizeof(detail), "%s (%s)", got.detail, plugin_status_code(got.plugin));
            else
                snprintf(detail, sizeof(detail), "%s", got.detail);
            pfj_fail(j, plugin_dist_status_code(ds), plugin_dist_status_next_action(ds), detail);
        } else {
            snprintf(j->view.version, sizeof(j->view.version), "%s", got.version);
            snprintf(j->view.generation, sizeof(j->view.generation), "%s", got.generation);
            j->view.already_present = got.already_present;
            j->view.downgrade_allowed = got.downgrade_allowed;
            pfj_set_state(j, PLUGIN_FETCH_INSTALLED);
        }
    }
    zcl_mutex_unlock(&t->lock);
}

void plugin_fetch_advance(struct plugin_fetch_table *table, const struct plugin_fetch_ctx *ctx,
                          uint64_t now)
{
    struct { uint64_t id; uint8_t root[32]; char name[PLUGIN_NAME_MAX + 1]; bool allow; }
        ready[PLUGIN_FETCH_ACTIVE_MAX];
    size_t n = 0;
    if (!table || !ctx || !ctx->engine || !ctx->store)
        return;
    zcl_mutex_lock(&table->lock);
    for (size_t i = 0; i < PLUGIN_FETCH_TABLE_MAX && n < PLUGIN_FETCH_ACTIVE_MAX; i++) {
        struct pfj_job *j = &table->jobs[i];
        if (!j->used || j->state != PLUGIN_FETCH_FETCHING || !pfj_poll(j, ctx, now))
            continue;
        pfj_set_state(j, PLUGIN_FETCH_INSTALLING);
        ready[n].id = j->id;
        ready[n].allow = j->allow_downgrade;
        memcpy(ready[n].root, j->root, 32);
        snprintf(ready[n].name, sizeof(ready[n].name), "%s", j->view.name);
        n++;
    }
    zcl_mutex_unlock(&table->lock);
    for (size_t i = 0; i < n; i++)
        pfj_install(table, ctx, ready[i].id, ready[i].root, ready[i].name, ready[i].allow);
}

bool plugin_fetch_status(struct plugin_fetch_table *table, uint64_t job, struct plugin_fetch_view *out)
{
    bool found = false;
    if (!table || !out || job == 0)
        return false;
    zcl_mutex_lock(&table->lock);
    for (size_t i = 0; i < PLUGIN_FETCH_TABLE_MAX && !found; i++)
        if (table->jobs[i].used && table->jobs[i].id == job) {
            *out = table->jobs[i].view;
            found = true;
        }
    zcl_mutex_unlock(&table->lock);
    return found;
}

size_t plugin_fetch_list(struct plugin_fetch_table *table, struct plugin_fetch_view *out, size_t max)
{
    size_t n = 0;
    if (!table || !out)
        return 0;
    zcl_mutex_lock(&table->lock);
    for (size_t i = 0; i < PLUGIN_FETCH_TABLE_MAX; i++) {
        if (!table->jobs[i].used)
            continue;
        /* Insertion into a newest-first array bounded by max. */
        size_t at = 0;
        while (at < n && out[at].job > table->jobs[i].id)
            at++;
        if (at >= max)
            continue;
        size_t last = n < max ? n : max - 1;
        for (size_t k = last; k > at; k--)
            out[k] = out[k - 1];
        out[at] = table->jobs[i].view;
        if (n < max)
            n++;
    }
    zcl_mutex_unlock(&table->lock);
    return n;
}
