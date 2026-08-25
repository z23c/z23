// one-result-type-ok:target-admission-is-input-validation — the one bool
// export here is mesh_observation_collect_add_target(), whose false means
// the string is not a usable onion or the bounded target table is full.
// Both are named, non-exceptional states of a fixed-size table; neither is
// a fallible operation with a cause to format.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * mesh_observation_collect.c — the READER side's fetcher.
 *
 * It walks a bounded set of onion targets, fetches /observation.json from
 * one of them per round, parses the (UNTRUSTED) document, and files the
 * result into a fixed ring of slots. It reaches no conclusion of its own:
 * mesh_observation_compose() does that, and any reader may run it over the
 * same slots and get the same answer.
 *
 * WHY ITS OWN THREAD
 * ------------------
 * An onion fetch is BLOCKING I/O over a rendezvous circuit and can take
 * tens of seconds on a healthy network. Blocking I/O must never sit on the
 * shared tick runner — that is a hang the whole node pays for. So this owns
 * one dedicated thread, does one fetch at a time, one target per round, and
 * sleeps at least MESH_OBS_COLLECT_ROUND_SECS between rounds.
 *
 * WHAT A SLOW OR DARK TARGET COSTS
 * --------------------------------
 * Exactly one thing: coverage. A spent budget records DEADLINE_EXPIRED with
 * elapsed_us beside deadline_us and nothing else. There is no failure
 * counter here, no strike, no backoff penalty framed as a judgement, and no
 * path by which "this box was slow" becomes "this box was wrong". Lower
 * coverage moves a reader's conclusion toward UNVERIFIED, which is the true
 * statement.
 */

#include "services/mesh_observation.h"

#include "base/log_macros.h"
#include "net/tor_integration.h"
#include "platform/time_compat.h"
#include "supervisors/domains.h"
#include "util/supervisor.h"
#include "util/sync.h"
#include "util/thread_registry.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Per-fetch budget, published with every measurement it bounds. Generous on
 * purpose: a rendezvous circuit to a seek-bound box is slow, and the only
 * consequence of a slow answer here must be that the answer is late. */
#define MESH_OBS_FETCH_DEADLINE_SECS 45
#define MESH_OBS_COLLECT_ROUND_SECS  60
#define MESH_OBS_TARGETS_MAX         MESH_OBS_SLOTS_MAX
/* Comfortably larger than one fetch plus one whole sleep round, so the
 * liveness contract can only fire on a genuinely wedged worker — never on a
 * seek-bound box whose peers answer slowly. */
#define MESH_OBS_COLLECT_DEADLINE_SEC 600
/* Ten whole rounds (fetch budget + sleep), in microseconds. Supervision
 * timing only — it never reaches a published observation. */
#define MESH_OBS_COLLECT_QUIET_US                                      \
    ((int64_t)(MESH_OBS_FETCH_DEADLINE_SECS + MESH_OBS_COLLECT_ROUND_SECS) \
     * 10 * 1000 * 1000)

static struct {
    zcl_mutex_t lock;                 /* LEAF */
    bool        lock_ready;
    char        targets[MESH_OBS_TARGETS_MAX][MESH_OBS_ONION_MAX];
    int         target_count;
    struct mesh_obs_slot slots[MESH_OBS_SLOTS_MAX];
    int         slot_count;
    int         cursor;

    _Atomic bool stop_requested;
    _Atomic long long loop_ticks;
    /* Rounds that FILED an outcome. This, not loop_ticks, is the progress
     * marker: a loop that spins forever fetching nothing must not be able
     * to claim credit for the spinning. */
    _Atomic long long rounds_filed;
    _Atomic int supervisor_id;
    bool        thread_running;
    pthread_t   thread;
    bool        started;
} g_mc;

static pthread_once_t g_mc_once = PTHREAD_ONCE_INIT;
static struct liveness_contract g_mc_contract;

static void mc_lock_init(void)
{
    zcl_mutex_init(&g_mc.lock);
    g_mc.lock_ready = true;
}

static void mc_ensure_lock(void)
{
    pthread_once(&g_mc_once, mc_lock_init);
}

/* Accepts "<56 base32>" with or without the ".onion" suffix and normalises
 * to the suffixed form, so a target list and a published self.onion always
 * compare equal. */
static bool mc_normalise_onion(const char *in, char *out, size_t cap)
{
    if (!in || !out)
        return false;
    size_t n = strnlen(in, cap);
    if (n == 0 || n >= cap)
        return false;
    char base[MESH_OBS_ONION_MAX];
    if (n >= sizeof(base))
        return false;
    memcpy(base, in, n);
    base[n] = '\0';
    const char *suffix = ".onion";
    size_t sl = strlen(suffix);
    if (n > sl && strcmp(base + (n - sl), suffix) == 0)
        base[n - sl] = '\0';
    size_t bl = strlen(base);
    if (bl != 56)
        return false;
    for (size_t i = 0; i < bl; i++) {
        char c = base[i];
        bool lower = (c >= 'a' && c <= 'z');
        bool digit = (c >= '2' && c <= '7');
        if (!lower && !digit)
            return false;
    }
    int w = snprintf(out, cap, "%s%s", base, suffix);
    return w > 0 && (size_t)w < cap;
}

bool mesh_observation_collect_add_target(const char *onion)
{
    mc_ensure_lock();
    char norm[MESH_OBS_ONION_MAX];
    if (!mc_normalise_onion(onion, norm, sizeof(norm)))
        return false;   // raw-return-ok:not-a-usable-onion-is-input-validation

    bool added = false;
    zcl_mutex_lock(&g_mc.lock);
    bool present = false;
    for (int i = 0; i < g_mc.target_count; i++)
        if (strcmp(g_mc.targets[i], norm) == 0)
            present = true;
    if (present) {
        added = true;   /* idempotent, not an error */
    } else if (g_mc.target_count < MESH_OBS_TARGETS_MAX) {
        snprintf(g_mc.targets[g_mc.target_count], MESH_OBS_ONION_MAX, "%s",
                 norm);
        g_mc.target_count++;
        added = true;
    }
    zcl_mutex_unlock(&g_mc.lock);
    return added;
}

/* Find (or claim) the slot that belongs to this target. The ring is as wide
 * as the target set, so a target never evicts another target's record. */
static int mc_slot_for(const char *onion)
{
    for (int i = 0; i < g_mc.slot_count; i++)
        if (strcmp(g_mc.slots[i].onion, onion) == 0)
            return i;
    if (g_mc.slot_count < MESH_OBS_SLOTS_MAX) {
        int i = g_mc.slot_count++;
        memset(&g_mc.slots[i], 0, sizeof(g_mc.slots[i]));
        snprintf(g_mc.slots[i].onion, MESH_OBS_ONION_MAX, "%s", onion);
        return i;
    }
    return -1;   /* raw-return-ok:ring-full-is-coverage-not-error */
}

/* Seed targets from the onion peers THIS node is already talking to.
 *
 * There is no designated box, no hardcoded address and no operator list
 * anywhere in this path: a node reads observation records from the peers it
 * happens to have, so removing any one of them costs coverage and nothing
 * else. The set is bounded and does not evict, which means a long-lived
 * node keeps the first MESH_OBS_TARGETS_MAX onion peers it ever saw; that
 * is a known limitation, not a preference — it is bounded memory, and no
 * target has any standing the others lack. */
static void mc_seed_from_self(void)
{
    struct mesh_observation rec;
    if (!mesh_observation_snapshot(&rec))
        return;
    int n = rec.edge_count;
    if (n < 0)
        n = 0;
    if (n > MESH_OBS_EDGES_MAX)
        n = MESH_OBS_EDGES_MAX;
    for (int i = 0; i < n; i++) {
        if (!rec.edges[i].peer_onion[0])
            continue;
        /* Never fetch our own document over the network — we already have
         * it in memory, and the composer takes it as an ordinary slot. */
        if (rec.self.onion[0] &&
            strcmp(rec.edges[i].peer_onion, rec.self.onion) == 0)
            continue;
        (void)mesh_observation_collect_add_target(rec.edges[i].peer_onion);
    }
}

/* What one round achieved. Three states, never two: the difference between
 * "there is positively nothing to fetch" and "I could not file anything" is
 * exactly what a progress detector needs, and collapsing them is how a
 * worker reports itself healthy while achieving nothing forever. */
enum mc_round_outcome {
    MC_ROUND_NO_TARGETS = 0, /* this node has observed no onion peer yet */
    MC_ROUND_FILED,          /* an outcome was filed against a slot */
    MC_ROUND_UNFILED,        /* a target was chosen and nothing was filed */
};

/* Fetch and file exactly one target. */
static enum mc_round_outcome mc_round(void)
{
    char target[MESH_OBS_ONION_MAX];
    target[0] = '\0';

    mc_seed_from_self();

    zcl_mutex_lock(&g_mc.lock);
    if (g_mc.target_count > 0) {
        if (g_mc.cursor >= g_mc.target_count)
            g_mc.cursor = 0;
        snprintf(target, sizeof(target), "%s", g_mc.targets[g_mc.cursor]);
        g_mc.cursor++;
    }
    zcl_mutex_unlock(&g_mc.lock);

    if (!target[0])
        return MC_ROUND_NO_TARGETS;   // raw-return-ok:no-observed-onion-peer-is-a-state-not-an-error

    struct onion_fetch_result result;
    memset(&result, 0, sizeof(result));
    int64_t started = platform_time_monotonic_us();
    int rc = tor_integration_fetch_onion_blocking(target, "/observation.json",
                                                  &result,
                                                  MESH_OBS_FETCH_DEADLINE_SECS);
    int64_t elapsed = platform_time_monotonic_us() - started;

    struct mesh_observation parsed;
    memset(&parsed, 0, sizeof(parsed));
    char refusal[MESH_OBS_REASON_MAX];
    refusal[0] = '\0';
    bool ok = false;
    if (rc == 0 && result.body && result.body_len > 0)
        ok = mesh_observation_parse_json((const char *)result.body,
                                         result.body_len, &parsed, refusal);
    if (result.body)
        free(result.body);

    zcl_mutex_lock(&g_mc.lock);
    int si = mc_slot_for(target);
    if (si >= 0) {
        struct mesh_obs_slot *s = &g_mc.slots[si];
        s->fetched_unix = platform_time_wall_unix();
        s->elapsed_us   = elapsed;   /* populated on EVERY outcome, so a
                                      * spent budget and a refusal are never
                                      * byte-identical */
        s->deadline_us  = (int64_t)MESH_OBS_FETCH_DEADLINE_SECS * 1000000;
        s->parsed       = ok;
        snprintf(s->refusal, sizeof(s->refusal), "%s", ok ? "" : refusal);
        if (ok) {
            s->fetch = MESH_OBS_CONFIRMED;   /* bytes arrived and parsed */
            s->rec = parsed;
        } else if (refusal[0]) {
            /* A well-formed HTTP answer carrying a document we can name as
             * malformed is positive COUNTER-evidence about the document,
             * not about the box's reachability. */
            s->fetch = MESH_OBS_REFUSED;
        } else {
            /* Nothing usable came back. Silence is never refusal: the
             * budget ran out, and that is all this says. */
            s->fetch = MESH_OBS_DEADLINE;
        }
    }
    zcl_mutex_unlock(&g_mc.lock);
    return si >= 0 ? MC_ROUND_FILED : MC_ROUND_UNFILED;
}

int mesh_observation_collect_snapshot(struct mesh_obs_slot *out, size_t max)
{
    if (!out || max == 0)
        return 0;
    mc_ensure_lock();
    int n = 0;
    zcl_mutex_lock(&g_mc.lock);
    /* Every configured target appears, including one never yet fetched:
     * it reports NOT_PROBED, which is "I did not look" and is neither a
     * failure nor a pass. */
    for (int i = 0; i < g_mc.target_count && (size_t)n < max; i++) {
        int si = -1;
        for (int j = 0; j < g_mc.slot_count; j++)
            if (strcmp(g_mc.slots[j].onion, g_mc.targets[i]) == 0)
                si = j;
        if (si >= 0) {
            out[n] = g_mc.slots[si];
        } else {
            memset(&out[n], 0, sizeof(out[n]));
            snprintf(out[n].onion, MESH_OBS_ONION_MAX, "%s", g_mc.targets[i]);
            out[n].fetch = MESH_OBS_NOT_PROBED;
        }
        n++;
    }
    zcl_mutex_unlock(&g_mc.lock);
    return n;
}

/* A liveness tick only. It says "the thread is alive", which is a different
 * claim from "the thread achieved something", and the two must never share
 * one call — that conflation is what lets 13000 fruitless runs read
 * healthy. Progress is reported by mc_report_round() and nowhere else. */
static void mc_heartbeat(void)
{
    supervisor_child_id id =
        (supervisor_child_id)atomic_load(&g_mc.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    supervisor_tick(id);
}

/* Translate one round's outcome into the progress vocabulary.
 *
 *   FILED       → progress. Confirmed, refused and deadline-expired are all
 *                 filed outcomes: a named refusal IS the work.
 *   NO_TARGETS  → idle, and this is the ONLY idle path. It is positively
 *                 established: this node has observed no onion peer to ask,
 *                 so there is legitimately nothing to fetch.
 *   UNFILED     → neither. A target was chosen and no slot took it, which
 *                 is the wedged shape the detector exists to surface.
 */
static void mc_report_round(enum mc_round_outcome o)
{
    supervisor_child_id id =
        (supervisor_child_id)atomic_load(&g_mc.supervisor_id);
    if (id == SUPERVISOR_INVALID_ID)
        return;
    switch (o) {
    case MC_ROUND_FILED:
        supervisor_progress(id,
                            (int64_t)atomic_fetch_add(&g_mc.rounds_filed, 1)
                                + 1);
        break;
    case MC_ROUND_NO_TARGETS:
        supervisor_progress_idle(id);
        break;
    case MC_ROUND_UNFILED:
        break;
    }
}

/* The stall callback WARNS and returns. It does not restart the collector,
 * it does not feed the systemd watchdog, and it does not grade any peer: a
 * fetch that outlives its budget is that peer's document arriving late, not
 * this worker being wedged. The deadline below is sized so an entire
 * MESH_OBS_FETCH_DEADLINE_SECS fetch plus a full sleep round fits inside it
 * several times over, precisely so a slow box never trips it. */
static void mc_on_stall(struct liveness_contract *c)
{
    (void)c;
    LOG_WARN("mesh_observation",
             "collector heartbeat lapsed (ticks=%lld)",
             (long long)atomic_load(&g_mc.loop_ticks));
}

static void *mc_thread_fn(void *arg)
{
    (void)arg;
    while (!atomic_load(&g_mc.stop_requested)) {
        atomic_fetch_add(&g_mc.loop_ticks, 1);
        mc_heartbeat();
        enum mc_round_outcome outcome = mc_round();
        mc_heartbeat();
        mc_report_round(outcome);
        for (int slept = 0;
             slept < MESH_OBS_COLLECT_ROUND_SECS * 5 &&
             !atomic_load(&g_mc.stop_requested);
             slept++) {
            platform_sleep_ms(200);
            if ((slept % 25) == 0)
                mc_heartbeat();
        }
    }
    return NULL;
}

struct zcl_result mesh_observation_collect_register(void)
{
    if (g_mc.started)
        return ZCL_OK;
    mc_ensure_lock();
    atomic_store(&g_mc.stop_requested, false);
    atomic_store(&g_mc.loop_ticks, 0);
    atomic_store(&g_mc.rounds_filed, 0);
    atomic_store(&g_mc.supervisor_id, SUPERVISOR_INVALID_ID);
    g_mc.thread_running = true;
    int rc = thread_registry_spawn("zcl_mesh_obs_collect", mc_thread_fn, NULL,
                                   &g_mc.thread);
    if (rc != 0) {
        g_mc.thread_running = false;
        return ZCL_ERR(-4,
                       "mesh_observation: collector spawn failed (%d)", rc);
    }

    if (supervisor_start()) {
        liveness_contract_init(&g_mc_contract, "net.mesh_obs_collect");
        atomic_store(&g_mc_contract.period_secs, 0); /* self-heartbeats */
        atomic_store(&g_mc_contract.deadline_secs,
                     MESH_OBS_COLLECT_DEADLINE_SEC);
        g_mc_contract.on_stall = mc_on_stall;
        supervisor_domains_init();
        supervisor_child_id id =
            supervisor_register_in_domain(g_net_sup, &g_mc_contract);
        if (id == SUPERVISOR_INVALID_ID) {
            LOG_WARN("mesh_observation",
                     "collector supervisor registration declined");
        } else {
            atomic_store(&g_mc.supervisor_id, (int)id);
            /* ARMED. A node with no observed onion peer reports idle and
             * stays quiet legitimately; every other frozen-marker state is
             * a real wedge. The window fits several whole rounds — one
             * fetch budget plus a full sleep — so a slow box is never
             * called stuck for being slow, and none of this timing reaches
             * a published observation. */
            supervisor_set_progress_max_quiet(id, MESH_OBS_COLLECT_QUIET_US);
        }
    } else {
        LOG_WARN("mesh_observation", "supervisor_start declined (collector)");
    }

    g_mc.started = true;
    return ZCL_OK;
}

void mesh_observation_collect_unregister(void)
{
    if (!g_mc.started)
        return;
    atomic_store(&g_mc.stop_requested, true);
    atomic_store(&g_mc_contract.deadline_secs, 0); /* silence on shutdown */
    if (g_mc.thread_running) {
        pthread_join(g_mc.thread, NULL);
        g_mc.thread_running = false;
    }
    g_mc.started = false;
}
