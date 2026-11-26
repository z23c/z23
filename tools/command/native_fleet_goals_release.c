/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: G6 from the release conveyor's ledger. The conveyor
 *          (release-tick, then release-run) appends one line per event to
 *          <state>/tick.log: "<UTC ts> START <sha8> landing_seq=<n> ...",
 *          "<ts> RELEASED <sha8>", "<ts> FAILED <sha8> rc=<n>", HELD,
 *          CURRENT, FETCH_FAILED, STOPPED. Each attempt's own output is
 *          <state>/release-<sha8>.log. This reader streams both, read-only,
 *          and names the newest failure with the last step its attempt
 *          logged, so a conveyor that stops releasing is a FAIL on the card
 *          instead of a silent drift of every host's CLI. */

#include "native_fleet_goals_release.h"

#include "native_fleet_objectives.h"

#include "base/hex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GRL_LINE_MAX 1024
#define GRL_STEP_MAX 120
#define GRL_PATH_MAX 1024

static const char grl_next[] =
    "read tick.log and the named release-<sha8>.log, fix that step, "
    "and rerun the release conveyor";

struct grl_ledger {
    char released[9];
    int64_t released_seq, released_ts;
    bool have_released;
    char pending[9];
    int64_t pending_seq, newest_seq;
    char failed[9];
    int64_t failed_rc;
    size_t fails;
    char last_kind[24];
    size_t events;
};

static bool grl_sha8(const char *s)
{
    uint8_t raw[4];
    return zcl_hex_decode_lower(s, raw, sizeof raw);
}

/* The integer after `key` in line, or -1 when absent. */
static int64_t grl_field(const char *line, const char *key)
{
    const char *p = strstr(line, key);
    char *end;
    long long v;
    if (!p)
        return -1;
    v = strtoll(p + strlen(key), &end, 10);
    return end == p + strlen(key) ? -1 : (int64_t)v;
}

static void grl_released(struct grl_ledger *g, const char *sha,
                         const char *ts)
{
    int64_t unix_s = 0;
    (void)snprintf(g->released, sizeof(g->released), "%s", sha);
    g->released_seq = strcmp(sha, g->pending) == 0 ? g->pending_seq : -1;
    if (!zcl_objectives_parse_iso8601(ts, &unix_s))
        unix_s = 0;
    g->released_ts = unix_s;
    g->have_released = true;
    g->fails = 0;
    g->failed[0] = '\0';
}

static void grl_event(struct grl_ledger *g, const char *line)
{
    char ts[32], kind[24], sha[16];
    int n = sscanf(line, "%31s %23s %15s", ts, kind, sha);
    if (n < 2 || ts[0] != '2' || strcmp(kind, "BUSY") == 0)
        return;
    g->events++;
    (void)snprintf(g->last_kind, sizeof(g->last_kind), "%s", kind);
    if (n < 3 || !grl_sha8(sha))
        return;
    if (strcmp(kind, "START") == 0) {
        (void)snprintf(g->pending, sizeof(g->pending), "%s", sha);
        g->pending_seq = grl_field(line, "landing_seq=");
        if (g->pending_seq > g->newest_seq)
            g->newest_seq = g->pending_seq;
    } else if (strcmp(kind, "RELEASED") == 0) {
        grl_released(g, sha, ts);
    } else if (strcmp(kind, "FAILED") == 0) {
        (void)snprintf(g->failed, sizeof(g->failed), "%s", sha);
        g->failed_rc = grl_field(line, "rc=");
        g->fails++;
    }
}

static bool grl_read(const char *path, struct grl_ledger *g)
{
    char line[GRL_LINE_MAX];
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    memset(g, 0, sizeof(*g));
    g->released_seq = g->pending_seq = g->newest_seq = -1;
    while (fgets(line, sizeof(line), f))
        grl_event(g, line);
    (void)fclose(f);
    return true;
}

static void grl_chomp(char *s)
{
    s[strcspn(s, "\r\n")] = '\0';
}

/* Copy line into out without its leading ISO timestamp, capped. */
static void grl_step_text(const char *line, char *out, size_t cap)
{
    const char *p = line;
    const char *sp = strchr(line, ' ');
    const char *t = strchr(line, 'T');
    if (line[0] == '2' && sp && t && t < sp)
        p = sp + 1;
    (void)snprintf(out, cap, "%.*s", GRL_STEP_MAX, p);
}

/* The last non-blank line of release-<sha8>.log, or a fixed reason. When
 * `needle` is given, the first line holding it instead (false if none). */
static bool grl_attempt_line(const char *dir, const char *sha, const char *needle,
                             char *out, size_t cap)
{
    char path[GRL_PATH_MAX], line[GRL_LINE_MAX], last[GRL_LINE_MAX] = "";
    FILE *f;
    if (snprintf(path, sizeof(path), "%s/release-%s.log", dir, sha) >=
            (int)sizeof(path) ||
        !(f = fopen(path, "r"))) {
        (void)snprintf(out, cap, "no attempt log release-%s.log", sha);
        return needle == NULL;
    }
    while (fgets(line, sizeof(line), f)) {
        grl_chomp(line);
        if (needle && strstr(line, needle)) {
            (void)fclose(f);
            grl_step_text(line, out, cap);
            return true;
        }
        if (line[0])
            (void)snprintf(last, sizeof(last), "%s", line);
    }
    (void)fclose(f);
    if (needle)
        return false;
    if (last[0])
        grl_step_text(last, out, cap);
    else
        (void)snprintf(out, cap, "no step logged (exited before its first "
                                 "log line)");
    return true;
}

static int64_t grl_age_h(const struct grl_ledger *g, int64_t now)
{
    return g->released_ts > 0 && now >= g->released_ts
               ? (now - g->released_ts) / 3600
               : -1;
}

static struct zcl_goal_result grl_failed(const struct grl_ledger *g,
                                         const char *dir, int64_t now)
{
    char step[GRL_STEP_MAX + 8];
    (void)grl_attempt_line(dir, g->failed, NULL, step, sizeof(step));
    return zcl_goal_make(ZCL_GOAL_FAIL, grl_next,
                         "release conveyor failing: %zu attempt(s) failed since "
                         "release %s (landing_seq %lld, %lld h ago); newest "
                         "%s rc=%lld at step: %s; newest landing_seq %lld",
                         g->fails, g->have_released ? g->released : "none",
                         (long long)g->released_seq,
                         (long long)grl_age_h(g, now), g->failed,
                         (long long)g->failed_rc, step,
                         (long long)g->newest_seq);
}

static struct zcl_goal_result grl_current(const struct grl_ledger *g,
                                          const struct zcl_goals_release_in *in,
                                          int64_t behind_max)
{
    char miss[GRL_STEP_MAX + 8];
    int64_t behind = g->newest_seq >= 0 && g->released_seq >= 0
                         ? g->newest_seq - g->released_seq
                         : 0;
    if (behind > behind_max)
        return zcl_goal_make(ZCL_GOAL_FAIL, grl_next,
                             "release conveyor %lld landings behind (bar %lld): "
                             "last release %s at landing_seq %lld, newest "
                             "attempt landing_seq %lld; newest event %s",
                             (long long)behind, (long long)behind_max,
                             g->released, (long long)g->released_seq,
                             (long long)g->newest_seq, g->last_kind);
    if (grl_attempt_line(in->state_dir, g->released, "NOT updated", miss,
                         sizeof(miss)))
        return zcl_goal_make(ZCL_GOAL_FAIL, grl_next,
                             "release %s did not reach every host: %s",
                             g->released, miss);
    return zcl_goal_make(ZCL_GOAL_PARTIAL,
                         "card: probe each host's running z23 and z23-dev "
                         "source identity against the release",
                         "release conveyor current: release %s at landing_seq "
                         "%lld, %lld behind the newest attempt; processes on "
                         "%zu admitted host(s) not probed",
                         g->released, (long long)g->released_seq,
                         (long long)behind, in->admitted_hosts);
}

struct zcl_goal_result zcl_goals_release_measure(
    const struct zcl_goals_release_in *in)
{
    char path[GRL_PATH_MAX];
    struct grl_ledger g;
    int64_t behind_max;
    if (!in || !in->state_dir)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, grl_next,
                             "%zu admitted host(s); release conveyor ledger "
                             "probe skipped",
                             in ? in->admitted_hosts : 0);
    if (snprintf(path, sizeof(path), "%s/tick.log", in->state_dir) >=
            (int)sizeof(path) ||
        !grl_read(path, &g))
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, grl_next,
                             "no release conveyor ledger at %s; this host "
                             "does not run the conveyor",
                             path);
    if (g.fails > 0)
        return grl_failed(&g, in->state_dir, in->now_unix);
    if (strcmp(g.last_kind, "FETCH_FAILED") == 0 ||
        strcmp(g.last_kind, "STOPPED") == 0)
        return zcl_goal_make(ZCL_GOAL_FAIL, grl_next,
                             "release conveyor not running: newest event %s; "
                             "last release %s",
                             g.last_kind,
                             g.have_released ? g.released : "none");
    if (!g.have_released)
        return zcl_goal_make(ZCL_GOAL_UNMEASURED, grl_next,
                             "%s holds %zu event(s) and no RELEASED line",
                             path, g.events);
    behind_max = in->behind_max > 0 ? in->behind_max
                                    : ZCL_GOALS_RELEASE_BEHIND_MAX;
    return grl_current(&g, in, behind_max);
}
