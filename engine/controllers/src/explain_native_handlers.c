/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `z23 explain <topic>` composition. See explain_native_handlers.h.
 *
 * Pure topic composers (sync/blockers/health) render one prose `text` block +
 * structured fields from already-parsed JSON; explain_build fetches the RPC
 * bundle and dispatches through the g_explain_topics table.
 */

#include "controllers/explain_native_handlers.h"
#include "controllers/status_native_helpers.h"

#include "json/json.h"
#include "controllers/rpc_client.h"
#include "util/log_macros.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bounded prose accumulator: appends up to cap-1 bytes, always NUL-terminated. */
static void tline(char *buf, size_t cap, size_t *len, const char *fmt, ...)
{
    if (*len >= cap) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *len, cap - *len, fmt, ap);
    va_end(ap);
    if (n > 0) {
        *len += (size_t)n;
        if (*len >= cap) *len = cap - 1;
    }
}

/* ── sync ──────────────────────────────────────────────────────────── */

struct explain_sync_heights {
    int64_t hstar;
    int64_t served_floor;
    int64_t header_h;
    int64_t served_tip;
    int64_t target;
    int64_t gap;
    bool synced;
};

static void explain_sync_read_heights(const struct explain_inputs *in,
                                      struct explain_sync_heights *h)
{
    h->hstar = in->frontier
        ? status_json_int(in->frontier, "hstar", -1) : -1;
    h->served_floor = in->frontier
        ? status_json_int(in->frontier, "served_floor", -1) : -1;
    h->header_h = in->chain
        ? status_json_int(in->chain, "best_header_height", -1) : -1;
    h->served_tip = in->block_height_known ? in->block_height : h->hstar;

    /* Gap: prefer the validated header frontier; peer height is only a hint. */
    h->target = h->header_h >= 0 ? h->header_h
        : (in->peer_best_known ? in->peer_best : -1);
    h->gap = (h->target >= 0 && h->served_tip >= 0 && h->target > h->served_tip)
        ? h->target - h->served_tip : 0;
    h->synced = (h->target >= 0 && h->gap <= 0);
}

struct explain_sync_blocker {
    const struct json_value *dom;
    const char *dom_id;
    const char *dom_class;
    const char *dom_reason;
    const char *nh_stage;
    const char *nh_kind;
    const char *nh_reason;
};

static void explain_sync_read_blocker(const struct explain_inputs *in,
                                      struct explain_sync_blocker *b)
{
    b->dom = in->blockers
        ? status_dominant_blocker(in->blockers) : NULL;
    b->dom_id = b->dom ? status_json_str(b->dom, "id", "") : "";
    b->dom_class = b->dom ? status_json_str(b->dom, "class", "") : "";
    b->dom_reason = b->dom ? status_json_str(b->dom, "reason", "") : "";

    b->nh_stage = in->frontier
        ? status_json_str(in->frontier, "hstar_next_primary_stage",
                          status_json_str(in->frontier,
                                          "first_hstar_blocker_stage", ""))
        : "";
    b->nh_kind = in->frontier
        ? status_json_str(in->frontier, "hstar_next_primary_kind",
                          status_json_str(in->frontier,
                                          "first_hstar_blocker_kind", ""))
        : "";
    b->nh_reason = in->frontier
        ? status_json_str(in->frontier, "hstar_next_primary_detail",
                          status_json_str(in->frontier,
                                          "first_hstar_blocker_reason", ""))
        : "";
}

static void explain_sync_write_state(char *t, size_t cap, size_t *len,
                                     const struct explain_inputs *in,
                                     const struct explain_sync_heights *h)
{
    tline(t, cap, len, "explain sync\n");
    if (h->target < 0)
        tline(t, cap, len,
              "  state: UNKNOWN (no validated header target yet)\n");
    else if (h->synced)
        tline(t, cap, len, "  state: SYNCED at H*=%lld\n",
              (long long)h->hstar);
    else
        tline(t, cap, len, "  state: BEHIND by %lld blocks\n",
              (long long)h->gap);
    tline(t, cap, len,
          "  provable tip H*=%lld  header tip=%lld  served tip=%lld  gap=%lld\n",
          (long long)h->hstar, (long long)h->header_h, (long long)h->served_tip,
          (long long)h->gap);
    tline(t, cap, len, "  served floor=%lld  peer best=%s\n",
          (long long)h->served_floor,
          in->peer_best_known ? "" : "unknown");
    if (in->peer_best_known)
        tline(t, cap, len, "  peer best height=%lld (untrusted hint)\n",
              (long long)in->peer_best);
}

static void explain_sync_write_blockers(char *t, size_t cap, size_t *len,
                                        const struct explain_sync_blocker *b)
{
    if (b->dom && b->dom_id[0])
        tline(t, cap, len,
              "  dominant blocker: %s [%s] — %s\n", b->dom_id, b->dom_class,
              b->dom_reason);
    else
        tline(t, cap, len, "  dominant blocker: none\n");

    if (b->nh_stage[0] || b->nh_kind[0])
        tline(t, cap, len,
              "  next-height blocker: %s/%s — %s\n",
              b->nh_stage[0] ? b->nh_stage : "?",
              b->nh_kind[0] ? b->nh_kind : "?",
              b->nh_reason[0] ? b->nh_reason : "");
    else
        tline(t, cap, len,
              "  next-height blocker: none (frontier advancing)\n");
}

static void explain_sync_note_cursor(char *t, size_t cap, size_t *len,
                                     const struct json_value *c,
                                     int *nabove, int64_t *deepest,
                                     bool *marked)
{
    const struct json_value *depth =
        json_get(c, "heights_above_hstar");
    if (!depth)
        *marked = false;
    int64_t lead = json_get_int(depth);
    if (lead > 0) {
        (*nabove)++;
        if (lead > *deepest) *deepest = lead;
    }
    tline(t, cap, len, " %s=%lld%s",
          json_get_str(json_get(c, "stage")),
          (long long)json_get_int(json_get(c, "cursor")),
          lead > 0 ? "*" : "");
}

static void explain_sync_write_cursors(char *t, size_t cap, size_t *len,
                                       const struct explain_inputs *in)
{
    /* Per-stage cursors from the frontier snapshot. reducer_frontier emits an
     * ARRAY of {stage, cursor, heights_above_hstar, ...} objects; this block
     * tested for JSON_OBJ and so printed nothing at all — the plain-language
     * surface dropped the whole section. Each cursor above H* is marked, not
     * merely listed: a bare cursor next to H* is exactly what one reader
     * mistook for a better height than H*. */
    const struct json_value *cursors = in->frontier
        ? json_get(in->frontier, "stage_cursors") : NULL;
    if (cursors && cursors->type == JSON_ARR && cursors->num_children > 0) {
        int nabove = 0;
        int64_t deepest = 0;
        /* This composer runs in the CLI process against whatever node answered
         * the dumpstate RPC. A node that predates the per-cursor marking sends
         * no depth field at all, and reporting that absence as "nothing is
         * above H*" would be a false all-clear — say "unavailable" instead. */
        bool marked = true;
        tline(t, cap, len,
              "  stage cursors (next height each stage will consume):");
        for (size_t i = 0; i < cursors->num_children && i < 10; i++)
            explain_sync_note_cursor(t, cap, len, &cursors->children[i],
                                     &nabove, &deepest, &marked);
        tline(t, cap, len, "\n");
        if (!marked)
            tline(t, cap, len,
                  "  run-ahead marking: UNAVAILABLE from this node — these "
                  "cursors cannot be told apart from proven heights here; "
                  "H* above is the only proven height\n");
        else if (nabove > 0)
            tline(t, cap, len,
                  "  * = has consumed heights ABOVE H* (%d cursor(s), up to "
                  "%lld height(s)): unproven work that can sit on a losing "
                  "fork and be clamped back — never read such a cursor as a "
                  "better height than H*\n",
                  nabove, (long long)deepest);
        else
            tline(t, cap, len,
                  "  no cursor is above H* — every stage is within the "
                  "verified height\n");
        tline(t, cap, len,
              "  (per-stage step-EWMA rates: run `z23 ops profile`)\n");
    }
}

static int explain_sync_write_conditions(char *t, size_t cap, size_t *len,
                                         const struct explain_inputs *in)
{
    /* Active self-heal conditions. */
    char active[256];
    size_t alen = 0;
    active[0] = '\0';
    int nactive = 0;
    const struct json_value *conds = in->conditions
        ? json_get(in->conditions, "conditions") : NULL;
    if (conds && conds->type == JSON_ARR) {
        for (size_t i = 0; i < conds->num_children; i++) {
            const struct json_value *c = &conds->children[i];
            if (!status_json_bool(c, "currently_active", false)) continue;
            const char *nm = status_json_str(c, "name", "");
            if (!nm[0]) continue;
            int n = snprintf(active + alen, sizeof(active) - alen, "%s%s",
                             nactive ? ", " : "", nm);
            if (n > 0 && (size_t)n < sizeof(active) - alen) alen += (size_t)n;
            nactive++;
        }
    }
    tline(t, cap, len, "  active conditions: %s\n",
          nactive ? active : "none");
    return nactive;
}

void explain_compose_sync(const struct explain_inputs *in,
                          struct json_value *out)
{
    json_set_object(out);
    /* Sized so the restored stage-cursor section + its trust note cannot push
     * the "next action" line past the accumulator's cap. */
    char t[2048];
    size_t len = 0;

    struct explain_sync_heights h = {0};
    explain_sync_read_heights(in, &h);
    struct explain_sync_blocker b = {0};
    explain_sync_read_blocker(in, &b);

    explain_sync_write_state(t, sizeof(t), &len, in, &h);
    explain_sync_write_blockers(t, sizeof(t), &len, &b);
    explain_sync_write_cursors(t, sizeof(t), &len, in);
    int nactive = explain_sync_write_conditions(t, sizeof(t), &len, in);

    /* THE next action. */
    const char *action;
    if (h.target < 0)
        action = "wait for headers to validate a sync target, then re-run";
    else if (h.synced)
        action = "none — node is at the validated tip";
    else if (b.dom && b.dom_id[0])
        action = "clear the dominant blocker above (see `ops state "
                 "subsystem=blocker`)";
    else if (b.nh_stage[0])
        action = "inspect the next-height blocker's stage "
                 "(`ops state subsystem=<stage>`)";
    else
        action = "let the reducer advance; watch H* climb via `status`";
    tline(t, sizeof(t), &len, "  next action: %s", action);

    json_push_kv_str(out, "topic", "sync");
    json_push_kv_str(out, "text", t);
    status_push_int_if_known(out, "hstar", h.hstar >= 0, h.hstar);
    status_push_int_if_known(out, "header_height", h.header_h >= 0, h.header_h);
    status_push_int_if_known(out, "served_tip", h.served_tip >= 0, h.served_tip);
    json_push_kv_int(out, "gap", h.gap);
    json_push_kv_bool(out, "synced", h.synced);
    json_push_kv_str(out, "dominant_blocker",
                     b.dom_id[0] ? b.dom_id : "none");
    json_push_kv_int(out, "active_conditions", nactive);
}

/* ── blockers ──────────────────────────────────────────────────────── */

void explain_compose_blockers(const struct explain_inputs *in,
                              struct json_value *out)
{
    json_set_object(out);
    /* Sized for the header + dominant line + 8 rows at a full-length
     * blocker reason (~220 chars) each, so a reason never truncates
     * mid-sentence. */
    char t[3200];
    size_t len = 0;

    const struct json_value *arr = in->blockers;
    int total = (arr && arr->type == JSON_ARR) ? (int)arr->num_children : 0;
    const struct json_value *dom = arr ? status_dominant_blocker(arr) : NULL;
    const char *dom_id = dom ? status_json_str(dom, "id", "") : "";

    tline(t, sizeof(t), &len, "explain blockers\n");
    tline(t, sizeof(t), &len, "  active blockers: %d\n", total);
    if (dom && dom_id[0])
        tline(t, sizeof(t), &len,
              "  dominant: %s [%s] — %s\n", dom_id,
              status_json_str(dom, "class", ""),
              status_json_str(dom, "reason", ""));
    else
        tline(t, sizeof(t), &len, "  dominant: none — nothing is blocked\n");

    if (arr && arr->type == JSON_ARR) {
        for (size_t i = 0; i < arr->num_children && i < 8; i++) {
            const struct json_value *b = &arr->children[i];
            tline(t, sizeof(t), &len, "  - %s [%s] fires=%lld — %s\n",
                  status_json_str(b, "id", "?"),
                  status_json_str(b, "class", "?"),
                  (long long)status_json_int(b, "fire_count", 0),
                  status_json_str(b, "reason", ""));
        }
    }
    tline(t, sizeof(t), &len, "  next action: %s",
          (dom && dom_id[0])
              ? "address the dominant blocker's owner subsystem first"
              : "none — no blocker is active");

    json_push_kv_str(out, "topic", "blockers");
    json_push_kv_str(out, "text", t);
    json_push_kv_int(out, "active_count", total);
    json_push_kv_str(out, "dominant_blocker", dom_id[0] ? dom_id : "none");
}

/* ── health ────────────────────────────────────────────────────────── */

struct explain_health_facts {
    bool healthy;
    bool serving;
    int64_t rss;
    int64_t uptime;
    const struct json_value *checks;
    int64_t tage;
};

static void explain_health_read(const struct explain_inputs *in,
                                struct explain_health_facts *f)
{
    f->healthy = in->health && status_json_bool(in->health, "healthy", false);
    f->serving = in->health && status_json_bool(in->health, "serving", false);
    f->rss = in->health
        ? status_json_int(in->health, "memory_rss_mb", -1) : -1;
    f->uptime = in->health
        ? status_json_int(in->health, "uptime_seconds", -1) : -1;
    f->checks = in->health
        ? json_get(in->health, "checks") : NULL;
    f->tage = f->checks
        ? status_json_int(f->checks, "tip_advance_age_seconds", -1) : -1;
}

static bool explain_health_check_failed(const struct json_value *c)
{
    const struct json_value *ok = NULL;
    if (c->type == JSON_OBJ)
        ok = json_get(c, "ok");
    return ok && ok->type == JSON_BOOL && !ok->val.b;
}

static int explain_health_write_failing(char *t, size_t cap, size_t *len,
                                        const struct json_value *checks)
{
    /* Surface any unhealthy checks by name. */
    int unhealthy = 0;
    char names[256];
    size_t nlen = 0;
    names[0] = '\0';
    if (checks && checks->type == JSON_OBJ) {
        for (size_t i = 0; i < checks->num_children; i++) {
            const struct json_value *c = &checks->children[i];
            if (explain_health_check_failed(c)) {
                int n = snprintf(names + nlen, sizeof(names) - nlen, "%s%s",
                                 unhealthy ? ", " : "", checks->keys[i]);
                if (n > 0 && (size_t)n < sizeof(names) - nlen)
                    nlen += (size_t)n;
                unhealthy++;
            }
        }
    }
    tline(t, cap, len, "  failing checks: %s\n",
          unhealthy ? names : "none");
    return unhealthy;
}

static void explain_health_write_blocker_action(char *t, size_t cap, size_t *len,
                                                const struct explain_inputs *in,
                                                bool healthy, int unhealthy)
{
    const struct json_value *dom = in->blockers
        ? status_dominant_blocker(in->blockers) : NULL;
    const char *dom_id = dom ? status_json_str(dom, "id", "") : "";
    if (dom && dom_id[0])
        tline(t, cap, len, "  dominant blocker: %s — %s\n", dom_id,
              status_json_str(dom, "reason", ""));

    tline(t, cap, len, "  next action: %s",
          healthy ? "none — node is healthy"
                  : (unhealthy ? "inspect the failing checks above"
                               : "check `ops state subsystem=blocker`"));
}

void explain_compose_health(const struct explain_inputs *in,
                            struct json_value *out)
{
    json_set_object(out);
    char t[1600];
    size_t len = 0;

    struct explain_health_facts f = {0};
    explain_health_read(in, &f);

    tline(t, sizeof(t), &len, "explain health\n");
    tline(t, sizeof(t), &len, "  healthy: %s  serving: %s\n",
          f.healthy ? "yes" : "no", f.serving ? "yes" : "no");
    tline(t, sizeof(t), &len, "  rss=%lldMB  uptime=%llds  tip_advance_age=%llds\n",
          (long long)f.rss, (long long)f.uptime, (long long)f.tage);

    int unhealthy = explain_health_write_failing(t, sizeof(t), &len, f.checks);
    explain_health_write_blocker_action(t, sizeof(t), &len, in, f.healthy,
                                        unhealthy);

    json_push_kv_str(out, "topic", "health");
    json_push_kv_str(out, "text", t);
    json_push_kv_bool(out, "healthy", f.healthy);
    json_push_kv_bool(out, "serving", f.serving);
    json_push_kv_int(out, "unhealthy_checks", unhealthy);
}

/* ── topic table ───────────────────────────────────────────────────── */

typedef void (*explain_compose_fn)(const struct explain_inputs *,
                                   struct json_value *);
struct explain_topic {
    const char *name;
    explain_compose_fn compose;
    const char *summary;
};
static const struct explain_topic g_explain_topics[] = {
    { "sync",     explain_compose_sync,
      "H*/header-tip/gap, dominant blocker, stage cursors, next action" },
    { "blockers", explain_compose_blockers,
      "active typed blockers, the dominant one, and what to do" },
    { "health",   explain_compose_health,
      "healthy/serving, rss/uptime, failing checks, dominant blocker" },
};

size_t explain_topic_count(void)
{
    return sizeof(g_explain_topics) / sizeof(g_explain_topics[0]);
}
size_t explain_topics_csv(char *out, size_t out_size)
{
    if (!out || out_size == 0) return 0;
    out[0] = '\0';
    size_t len = 0;
    for (size_t i = 0; i < explain_topic_count(); i++) {
        int n = snprintf(out + len, out_size - len, "%s%s", i ? "," : "",
                         g_explain_topics[i].name);
        if (n > 0 && (size_t)n < out_size - len) len += (size_t)n;
        else { len = out_size - 1; break; }
    }
    return len;
}

/* ── node-contacting build ─────────────────────────────────────────── */

/* dumpstate <sub> and return the parsed body's `.state` sub-object into *dst
 * (an owned copy). Returns true if a state object was extracted. */
static bool fetch_dumpstate_state(const char *sub, struct json_value *dst)
{
    char params[96];
    snprintf(params, sizeof(params), "[\"%s\"]", sub);
    char *raw = node_rpc_call("dumpstate", params);
    struct json_value body;
    bool ok = false;
    if (status_parse_rpc_json(&body, raw, JSON_OBJ)) {
        const struct json_value *st = json_get(&body, "state");
        if (st && st->type == JSON_OBJ) {
            json_init(dst);
            json_copy(dst, st);
            ok = true;
        }
        json_free(&body);
    }
    free(raw);
    return ok;
}

static void explain_build_fill_inputs(struct explain_inputs *in,
                                      bool have_frontier,
                                      const struct json_value *frontier,
                                      bool have_blocker,
                                      const struct json_value *blocker_state,
                                      bool have_conditions,
                                      const struct json_value *conditions,
                                      bool have_health,
                                      const struct json_value *health,
                                      bool have_sync,
                                      const struct json_value *sync,
                                      bool have_chain,
                                      const struct json_value *chain,
                                      bool have_count,
                                      const struct json_value *count_j,
                                      bool have_peers,
                                      const struct peer_survey *survey)
{
    *in = (struct explain_inputs){
        .frontier = have_frontier ? frontier : NULL,
        .blockers = have_blocker ? json_get(blocker_state, "blockers") : NULL,
        .conditions = have_conditions ? conditions : NULL,
        .health = have_health ? health : NULL,
        .sync = have_sync ? sync : NULL,
        .chain = have_chain ? chain : NULL,
        .block_height = have_count ? count_j->val.i : 0,
        .block_height_known = have_count,
        .peer_best = have_peers ? survey->max_height : 0,
        .peer_best_known = have_peers && survey->max_height_known,
    };
}

static void explain_build_release(bool have_frontier,
                                  struct json_value *frontier,
                                  bool have_blocker,
                                  struct json_value *blocker_state,
                                  bool have_conditions,
                                  struct json_value *conditions,
                                  bool have_health, struct json_value *health,
                                  bool have_sync, struct json_value *sync,
                                  bool have_chain, struct json_value *chain,
                                  bool have_count, struct json_value *count_j,
                                  bool have_peers, struct json_value *peers,
                                  char *health_raw, char *sync_raw,
                                  char *chain_raw, char *count_raw,
                                  char *peers_raw)
{
    if (have_frontier) json_free(frontier);
    if (have_blocker) json_free(blocker_state);
    if (have_conditions) json_free(conditions);
    if (have_health) json_free(health);
    if (have_sync) json_free(sync);
    if (have_chain) json_free(chain);
    if (have_count) json_free(count_j);
    if (have_peers) json_free(peers);
    free(health_raw); free(sync_raw); free(chain_raw);
    free(count_raw); free(peers_raw);
}

bool explain_build(const char *topic, struct json_value *out)
{
    json_set_object(out);
    const struct explain_topic *sel = NULL;
    for (size_t i = 0; i < explain_topic_count(); i++) {
        if (strcmp(g_explain_topics[i].name, topic ? topic : "") == 0) {
            sel = &g_explain_topics[i];
            break;
        }
    }
    if (!sel) {
        char csv[128];
        explain_topics_csv(csv, sizeof(csv));
        char msg[192];
        snprintf(msg, sizeof(msg), "unknown topic '%s'; known: %s",
                 topic ? topic : "", csv);
        json_push_kv_str(out, "error", msg);
        LOG_FAIL("explain", "%s", msg);
    }

    /* Fetch the shared RPC bundle. Any piece may be missing; composers cope. */
    struct json_value frontier = {0}, blocker_state = {0}, conditions = {0};
    struct json_value health = {0}, sync = {0}, chain = {0}, peers = {0};
    bool have_frontier = fetch_dumpstate_state("reducer_frontier", &frontier);
    bool have_blocker = fetch_dumpstate_state("blocker", &blocker_state);
    bool have_conditions = fetch_dumpstate_state("condition_engine",
                                                 &conditions);

    char *health_raw = node_rpc_call("healthcheck", NULL);
    bool have_health = status_parse_rpc_json(&health, health_raw, JSON_OBJ);
    char *sync_raw = node_rpc_call("syncstate", NULL);
    bool have_sync = status_parse_rpc_json(&sync, sync_raw, JSON_OBJ);
    char *chain_raw = node_rpc_call("getblockchaininfo", NULL);
    bool have_chain = status_parse_rpc_json(&chain, chain_raw, JSON_OBJ);
    char *count_raw = node_rpc_call("getblockcount", NULL);
    struct json_value count_j;
    bool have_count = status_parse_rpc_json(&count_j, count_raw, JSON_INT);
    char *peers_raw = node_rpc_call("getpeerinfo", NULL);
    bool have_peers = status_parse_rpc_json(&peers, peers_raw, JSON_ARR) &&
                      status_peer_array_is_valid(&peers);

    struct peer_survey survey = {0};
    if (have_peers) status_peer_survey(&peers, &survey);

    struct explain_inputs in;
    explain_build_fill_inputs(&in, have_frontier, &frontier, have_blocker,
                              &blocker_state, have_conditions, &conditions,
                              have_health, &health, have_sync, &sync,
                              have_chain, &chain, have_count, &count_j,
                              have_peers, &survey);

    if (sel)
        sel->compose(&in, out);

    explain_build_release(have_frontier, &frontier, have_blocker,
                          &blocker_state, have_conditions, &conditions,
                          have_health, &health, have_sync, &sync, have_chain,
                          &chain, have_count, &count_j, have_peers, &peers,
                          health_raw, sync_raw, chain_raw, count_raw,
                          peers_raw);

    return sel != NULL;
}
