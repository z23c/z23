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

void explain_compose_sync(const struct explain_inputs *in,
                          struct json_value *out)
{
    json_set_object(out);
    /* Sized so the restored stage-cursor section + its trust note cannot push
     * the "next action" line past the accumulator's cap. */
    char t[2048];
    size_t len = 0;

    int64_t hstar = in->frontier
        ? status_json_int(in->frontier, "hstar", -1) : -1;
    int64_t served_floor = in->frontier
        ? status_json_int(in->frontier, "served_floor", -1) : -1;
    int64_t header_h = in->chain
        ? status_json_int(in->chain, "best_header_height", -1) : -1;
    int64_t served_tip = in->block_height_known ? in->block_height : hstar;

    /* Gap: prefer the validated header frontier; peer height is only a hint. */
    int64_t target = header_h >= 0 ? header_h
        : (in->peer_best_known ? in->peer_best : -1);
    int64_t gap = (target >= 0 && served_tip >= 0 && target > served_tip)
        ? target - served_tip : 0;
    bool synced = (target >= 0 && gap <= 0);

    const struct json_value *dom = in->blockers
        ? status_dominant_blocker(in->blockers) : NULL;
    const char *dom_id = dom ? status_json_str(dom, "id", "") : "";
    const char *dom_class = dom ? status_json_str(dom, "class", "") : "";
    const char *dom_reason = dom ? status_json_str(dom, "reason", "") : "";

    const char *nh_stage = in->frontier
        ? status_json_str(in->frontier, "hstar_next_primary_stage",
                          status_json_str(in->frontier,
                                          "first_hstar_blocker_stage", ""))
        : "";
    const char *nh_kind = in->frontier
        ? status_json_str(in->frontier, "hstar_next_primary_kind",
                          status_json_str(in->frontier,
                                          "first_hstar_blocker_kind", ""))
        : "";
    const char *nh_reason = in->frontier
        ? status_json_str(in->frontier, "hstar_next_primary_detail",
                          status_json_str(in->frontier,
                                          "first_hstar_blocker_reason", ""))
        : "";

    tline(t, sizeof(t), &len, "explain sync\n");
    if (target < 0)
        tline(t, sizeof(t), &len,
              "  state: UNKNOWN (no validated header target yet)\n");
    else if (synced)
        tline(t, sizeof(t), &len, "  state: SYNCED at H*=%lld\n",
              (long long)hstar);
    else
        tline(t, sizeof(t), &len, "  state: BEHIND by %lld blocks\n",
              (long long)gap);
    tline(t, sizeof(t), &len,
          "  provable tip H*=%lld  header tip=%lld  served tip=%lld  gap=%lld\n",
          (long long)hstar, (long long)header_h, (long long)served_tip,
          (long long)gap);
    tline(t, sizeof(t), &len, "  served floor=%lld  peer best=%s\n",
          (long long)served_floor,
          in->peer_best_known ? "" : "unknown");
    if (in->peer_best_known)
        tline(t, sizeof(t), &len, "  peer best height=%lld (untrusted hint)\n",
              (long long)in->peer_best);

    if (dom && dom_id[0])
        tline(t, sizeof(t), &len,
              "  dominant blocker: %s [%s] — %s\n", dom_id, dom_class,
              dom_reason);
    else
        tline(t, sizeof(t), &len, "  dominant blocker: none\n");

    if (nh_stage[0] || nh_kind[0])
        tline(t, sizeof(t), &len,
              "  next-height blocker: %s/%s — %s\n",
              nh_stage[0] ? nh_stage : "?", nh_kind[0] ? nh_kind : "?",
              nh_reason[0] ? nh_reason : "");
    else
        tline(t, sizeof(t), &len,
              "  next-height blocker: none (frontier advancing)\n");

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
        tline(t, sizeof(t), &len,
              "  stage cursors (next height each stage will consume):");
        for (size_t i = 0; i < cursors->num_children && i < 10; i++) {
            const struct json_value *c = &cursors->children[i];
            const struct json_value *depth =
                json_get(c, "heights_above_hstar");
            if (!depth)
                marked = false;
            int64_t lead = json_get_int(depth);
            if (lead > 0) {
                nabove++;
                if (lead > deepest) deepest = lead;
            }
            tline(t, sizeof(t), &len, " %s=%lld%s",
                  json_get_str(json_get(c, "stage")),
                  (long long)json_get_int(json_get(c, "cursor")),
                  lead > 0 ? "*" : "");
        }
        tline(t, sizeof(t), &len, "\n");
        if (!marked)
            tline(t, sizeof(t), &len,
                  "  run-ahead marking: UNAVAILABLE from this node — these "
                  "cursors cannot be told apart from proven heights here; "
                  "H* above is the only proven height\n");
        else if (nabove > 0)
            tline(t, sizeof(t), &len,
                  "  * = has consumed heights ABOVE H* (%d cursor(s), up to "
                  "%lld height(s)): unproven work that can sit on a losing "
                  "fork and be clamped back — never read such a cursor as a "
                  "better height than H*\n",
                  nabove, (long long)deepest);
        else
            tline(t, sizeof(t), &len,
                  "  no cursor is above H* — every stage is within the "
                  "verified height\n");
        tline(t, sizeof(t), &len,
              "  (per-stage step-EWMA rates: run `z23 ops profile`)\n");
    }

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
    tline(t, sizeof(t), &len, "  active conditions: %s\n",
          nactive ? active : "none");

    /* THE next action. */
    const char *action;
    if (target < 0)
        action = "wait for headers to validate a sync target, then re-run";
    else if (synced)
        action = "none — node is at the validated tip";
    else if (dom && dom_id[0])
        action = "clear the dominant blocker above (see `ops state "
                 "subsystem=blocker`)";
    else if (nh_stage[0])
        action = "inspect the next-height blocker's stage "
                 "(`ops state subsystem=<stage>`)";
    else
        action = "let the reducer advance; watch H* climb via `status`";
    tline(t, sizeof(t), &len, "  next action: %s", action);

    json_push_kv_str(out, "topic", "sync");
    json_push_kv_str(out, "text", t);
    status_push_int_if_known(out, "hstar", hstar >= 0, hstar);
    status_push_int_if_known(out, "header_height", header_h >= 0, header_h);
    status_push_int_if_known(out, "served_tip", served_tip >= 0, served_tip);
    json_push_kv_int(out, "gap", gap);
    json_push_kv_bool(out, "synced", synced);
    json_push_kv_str(out, "dominant_blocker", dom_id[0] ? dom_id : "none");
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

void explain_compose_health(const struct explain_inputs *in,
                            struct json_value *out)
{
    json_set_object(out);
    char t[1600];
    size_t len = 0;

    bool healthy = in->health && status_json_bool(in->health, "healthy", false);
    bool serving = in->health && status_json_bool(in->health, "serving", false);
    int64_t rss = in->health
        ? status_json_int(in->health, "memory_rss_mb", -1) : -1;
    int64_t uptime = in->health
        ? status_json_int(in->health, "uptime_seconds", -1) : -1;
    const struct json_value *checks = in->health
        ? json_get(in->health, "checks") : NULL;
    int64_t tage = checks
        ? status_json_int(checks, "tip_advance_age_seconds", -1) : -1;

    tline(t, sizeof(t), &len, "explain health\n");
    tline(t, sizeof(t), &len, "  healthy: %s  serving: %s\n",
          healthy ? "yes" : "no", serving ? "yes" : "no");
    tline(t, sizeof(t), &len, "  rss=%lldMB  uptime=%llds  tip_advance_age=%llds\n",
          (long long)rss, (long long)uptime, (long long)tage);

    /* Surface any unhealthy checks by name. */
    int unhealthy = 0;
    char names[256];
    size_t nlen = 0;
    names[0] = '\0';
    if (checks && checks->type == JSON_OBJ) {
        for (size_t i = 0; i < checks->num_children; i++) {
            const struct json_value *c = &checks->children[i];
            if (c->type != JSON_OBJ) continue;
            const struct json_value *ok = json_get(c, "ok");
            if (ok && ok->type == JSON_BOOL && !ok->val.b) {
                int n = snprintf(names + nlen, sizeof(names) - nlen, "%s%s",
                                 unhealthy ? ", " : "", checks->keys[i]);
                if (n > 0 && (size_t)n < sizeof(names) - nlen)
                    nlen += (size_t)n;
                unhealthy++;
            }
        }
    }
    tline(t, sizeof(t), &len, "  failing checks: %s\n",
          unhealthy ? names : "none");

    const struct json_value *dom = in->blockers
        ? status_dominant_blocker(in->blockers) : NULL;
    const char *dom_id = dom ? status_json_str(dom, "id", "") : "";
    if (dom && dom_id[0])
        tline(t, sizeof(t), &len, "  dominant blocker: %s — %s\n", dom_id,
              status_json_str(dom, "reason", ""));

    tline(t, sizeof(t), &len, "  next action: %s",
          healthy ? "none — node is healthy"
                  : (unhealthy ? "inspect the failing checks above"
                               : "check `ops state subsystem=blocker`"));

    json_push_kv_str(out, "topic", "health");
    json_push_kv_str(out, "text", t);
    json_push_kv_bool(out, "healthy", healthy);
    json_push_kv_bool(out, "serving", serving);
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

    struct explain_inputs in = {
        .frontier = have_frontier ? &frontier : NULL,
        .blockers = have_blocker ? json_get(&blocker_state, "blockers") : NULL,
        .conditions = have_conditions ? &conditions : NULL,
        .health = have_health ? &health : NULL,
        .sync = have_sync ? &sync : NULL,
        .chain = have_chain ? &chain : NULL,
        .block_height = have_count ? count_j.val.i : 0,
        .block_height_known = have_count,
        .peer_best = have_peers ? survey.max_height : 0,
        .peer_best_known = have_peers && survey.max_height_known,
    };

    if (sel)
        sel->compose(&in, out);

    if (have_frontier) json_free(&frontier);
    if (have_blocker) json_free(&blocker_state);
    if (have_conditions) json_free(&conditions);
    if (have_health) json_free(&health);
    if (have_sync) json_free(&sync);
    if (have_chain) json_free(&chain);
    if (have_count) json_free(&count_j);
    if (have_peers) json_free(&peers);
    free(health_raw); free(sync_raw); free(chain_raw);
    free(count_raw); free(peers_raw);

    return sel != NULL;
}
