/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Alert routing implementation — see alerts.h for the contract. */

#include "event/alerts.h"
#include "base/format_attribute.h"
#include "util/sd_notify.h"
#include "util/spawn.h"
#include "event/event.h"
#include "core/utiltime.h"
#include "zutf8/zutf8.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Per-rule runtime state ──────────────────────────────────── */

struct rule_state {
    struct alert_rule rule;
    int64_t  window_start_us;   /* start of current counting window */
    int      count_in_window;   /* events seen in this window */
    int64_t  last_fired_us;     /* timestamp of most recent fire */
    uint64_t total_fires;       /* lifetime fire count */
};

/* ── Global state ────────────────────────────────────────────── */

static struct rule_state g_rules[ALERT_MAX_RULES];
static size_t            g_num_rules;
static char              g_webhook_url[ALERT_WEBHOOK_LEN];
static bool              g_webhook_enabled;
static bool              g_initialized;
static pthread_mutex_t   g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Operator-needed latch. EV_OPERATOR_NEEDED means the auto-healing engine
 * exhausted its remedies and an operator must act. We latch it (rather than
 * relying on a rolling window) so the DEGRADED state stays visible in the
 * health surface until the underlying condition clears it. Touched from the
 * event-observer thread, read from the health/heartbeat thread → atomic. */
static _Atomic bool      g_operator_needed;
static _Atomic int64_t   g_operator_needed_since_unix;
static char              g_operator_needed_detail[
    ALERT_OPERATOR_NEEDED_DETAIL_LEN];

/* ── Sinks ───────────────────────────────────────────────────── */

static void sink_log(const char *rule_name, const char *payload)
{
    fprintf(stderr,  // obs-ok:alert-log-sink-is-the-observable-surface
            "[ALERT] %s: %s\n", rule_name, payload);
}

/* Fire-and-forget webhook POST via the no-shell spawn primitive. Alerts are
 * rare (a few per hour at most). zcl_spawn_detached double-forks + setsid()s,
 * so the grandchild that runs curl is reparented to init/subreaper and can
 * NEVER become a zombie of this process — which is precisely why alerts_init()
 * no longer installs SA_NOCLDWAIT (that process-wide install was what made
 * every other system()'s return code untrustworthy tree-wide). No shell:
 * argv is passed directly to execvp; stdout/stderr → /dev/null (log_path
 * NULL). */
static void sink_webhook(const char *url, const char *rule_name,
                          const char *payload)
{
    if (!url || !*url) return;

#if defined(_WIN32)
    /* External notification remains disabled until Windows process launch is
     * confined by a restricted token and Job Object. The alert has already
     * reached the in-process log sink; never approximate this with a shell or
     * allow CreateProcess to escape the node's lifetime/resource policy. */
    (void)rule_name;
    (void)payload;
    fprintf(stderr,
            "[ALERT] webhook delivery refused on Windows: external process "
            "sandbox is unavailable\n");
    return;
#else

    /* Build a small JSON body inline so we don't malloc in the
     * critical section.  Cap at a reasonable size. */
    char body[1024];
    int n = snprintf(body, sizeof(body),
        "{\"alert\":\"%s\",\"message\":\"%s\",\"ts\":%lld}",
        rule_name, payload, (long long)(GetTime()));
    if (n < 0 || (size_t)n >= sizeof(body)) return;

    const char *const argv[] = {
        "curl", "-s", "-X", "POST",
        "-H", "Content-Type: application/json",
        "-d", body, "--max-time", "5", url, NULL
    };
    ZCL_IGNORE_RESULT(zcl_spawn_detached(argv, NULL),
                      "best-effort notification; the alert is already in the "
                      "event log and a failed webhook must not stall the "
                      "caller or take a second delivery path");
#endif
}

/* ── Core logic ──────────────────────────────────────────────── */

static void dispatch_alert(struct rule_state *rs, const char *payload)
{
    int64_t now_us = GetTimeMicros();

    /* Cooldown check */
    if (rs->last_fired_us > 0) {
        int64_t cooldown_us = (int64_t)rs->rule.cooldown_sec * 1000000LL;
        if (now_us - rs->last_fired_us < cooldown_us) return;
    }

    rs->last_fired_us = now_us;
    rs->total_fires++;

    /* Dispatch to all sinks */
    sink_log(rs->rule.name, payload);
    if (g_webhook_enabled)
        sink_webhook(g_webhook_url, rs->rule.name, payload);
}

static void check_rule(struct rule_state *rs)
{
    if (!rs->rule.enabled) return;

    int64_t now_us = GetTimeMicros();
    int64_t window_us = (int64_t)rs->rule.window_sec * 1000000LL;

    /* Reset window if expired */
    if (now_us - rs->window_start_us > window_us) {
        rs->window_start_us = now_us;
        rs->count_in_window = 0;
    }

    rs->count_in_window++;

    if (rs->count_in_window >= rs->rule.threshold) {
        char payload[128];
        snprintf(payload, sizeof(payload),
            "threshold=%d count=%d window=%ds",
            rs->rule.threshold, rs->count_in_window,
            rs->rule.window_sec);
        dispatch_alert(rs, payload);
        /* Reset window after firing so we don't re-fire every event */
        rs->window_start_us = now_us;
        rs->count_in_window = 0;
    }
}

/* ── Event observer ──────────────────────────────────────────── */

/* Retain counted detail with visible NULs, validating even discarded bytes. */
static void operator_needed_detail(char *detail, size_t cap,
                                   const unsigned char *payload, size_t len)
{
    size_t used = 0;
    if (payload) {
        for (size_t i = 0; i < len; i++) {
            size_t width = payload[i] == 0 ? 2 : 1;
            if (width >= cap - used) break;
            if (payload[i] == 0) {
                detail[used++] = '\\';
                detail[used++] = '0';
            } else detail[used++] = (char)payload[i];
        }
    }
    detail[used] = '\0';
    if ((payload && !zutf8_validate_n((const char *)payload, len)) ||
        !zutf8_validate_n(detail, used))
        snprintf(detail, cap, "(operator detail refused: invalid UTF-8)");
}

/* Latch until the condition clears, even when its detail is refused. */
static void operator_needed_set(const unsigned char *payload, size_t len)
{
    char detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN];
    operator_needed_detail(detail, sizeof(detail), payload, len);
    pthread_mutex_lock(&g_lock);
    if (atomic_load(&g_operator_needed_since_unix) == 0)
        atomic_store(&g_operator_needed_since_unix, (int64_t)GetTime());
    snprintf(g_operator_needed_detail, sizeof(g_operator_needed_detail),
             "%s", *detail ? detail : "(unspecified)");
    atomic_store(&g_operator_needed, true);
    pthread_mutex_unlock(&g_lock);
    /* Make it impossible to miss: a STATUS= line systemd/operators see. */
    if (sd_notify_is_active()) {
        char status[256];
        snprintf(status, sizeof(status), "DEGRADED operator_needed: %s",
                 *detail ? detail : "(unspecified)");
        if (!zutf8_validate(status))
            snprintf(status, sizeof(status),
                     "DEGRADED operator_needed: (operator detail refused: invalid UTF-8)");
        sd_notify_status(status);
    }
}

static bool operator_needed_nonterminal(const char *payload, size_t len)
{
    const char marker[] = "terminal=0";
    if (!payload) return false;
    for (size_t i = 0; len - i >= sizeof(marker) - 1; i++) {
        if (memcmp(payload + i, marker, sizeof(marker) - 1) == 0)
            return true;
    }
    return false;
}

/* Read a space-delimited field without crossing the event extent. */
static const char *operator_needed_field(const char *text, size_t len,
                                         const char *key, size_t *value_len)
{
    size_t key_len = strlen(key);
    for (size_t i = 0; i < len;) {
        if (text[i] == ' ') { i++; continue; }
        size_t start = i;
        while (i < len && text[i] != ' ') i++;
        if (i - start > key_len &&
            memcmp(text + start, key, key_len) == 0) {
            *value_len = i - start - key_len;
            return text + start + key_len;
        }
    }
    return NULL;
}

static void operator_needed_clear_condition(const void *payload, size_t len)
{
    if (!payload) return;
    const char *text = payload;
    size_t name_len = 0, condition_len = 0;
    const char *name = operator_needed_field(text, strnlen(text, len),
                                            "name=", &name_len);
    if (!name) return;
    pthread_mutex_lock(&g_lock);
    const char *condition = operator_needed_field(g_operator_needed_detail,
        strlen(g_operator_needed_detail), "condition=", &condition_len);
    if (condition && name_len == condition_len &&
        memcmp(name, condition, name_len) == 0) {
        atomic_store(&g_operator_needed, false);
        atomic_store(&g_operator_needed_since_unix, 0);
        g_operator_needed_detail[0] = '\0';
    }
    pthread_mutex_unlock(&g_lock);
}

static void alert_observer(enum event_type type, uint32_t peer_id,
                            const void *payload, uint32_t payload_len,
                            void *ctx)
{
    (void)peer_id; (void)ctx;

    /* EV_OPERATOR_NEEDED is the loudest signal the framework emits: the
     * condition engine ran out of remedies. Latch it for the health surface
     * AND let it flow through the normal rule dispatch below for log/webhook. */
    if (type == EV_OPERATOR_NEEDED) {
        /* A page tagged `terminal=0` is the auto-recovery layer announcing
         * "still cycling, no human needed yet" (e.g. the sticky escalator's
         * ladder-cycling notice). Latching the DEGRADED health surface on it
         * makes a self-recovering wedge read as operator_needed forever — even
         * after the tip climbs back to the network. Only latch genuine
         * remedy-exhaustion pages, which omit the terminal=0 marker. */
        if (!operator_needed_nonterminal(payload, payload_len))
            operator_needed_set(payload, payload_len);
    }
    /* Only recovery of the latched condition resolves this symptom. */
    else if (type == EV_CONDITION_CLEARED)
        operator_needed_clear_condition(payload, payload_len);

    pthread_mutex_lock(&g_lock);
    for (size_t i = 0; i < g_num_rules; i++) {
        if (g_rules[i].rule.trigger == type && g_rules[i].rule.enabled)
            check_rule(&g_rules[i]);
    }
    pthread_mutex_unlock(&g_lock);
}

/* ── Seed rules ──────────────────────────────────────────────── */

static const struct alert_rule k_seed_rules[] = {
    {
        .name         = "disk_low",
        .trigger      = EV_DISK_LOW,
        .threshold    = 1,         /* fire on first occurrence */
        .window_sec   = 300,
        .cooldown_sec = 600,
        .enabled      = true,
    },
    {
        .name         = "peer_bans_high",
        .trigger      = EV_PEER_BANNED,
        .threshold    = 5,         /* 5 bans in 5 minutes */
        .window_sec   = 300,
        .cooldown_sec = 600,
        .enabled      = true,
    },
    {
        .name         = "rpc_ratelimit_spike",
        .trigger      = EV_RPC_TIMEOUT,
        .threshold    = 10,        /* 10 timeouts in 5 minutes */
        .window_sec   = 300,
        .cooldown_sec = 600,
        .enabled      = true,
    },
    {
        .name         = "chain_tip_rejected",
        .trigger      = EV_CHAIN_TIP_REJECTED,
        .threshold    = 1,         /* fire immediately */
        .window_sec   = 300,
        .cooldown_sec = 600,
        .enabled      = true,
    },
    {
        /* THE silent-halt fix. The condition engine emits EV_OPERATOR_NEEDED
         * once it exhausts remedies for a CRITICAL problem (e.g. a halted
         * tip). Before this rule it reached no sink. Fire on the first one. */
        .name         = "operator_needed",
        .trigger      = EV_OPERATOR_NEEDED,
        .threshold    = 1,         /* fire immediately — never let it be silent */
        .window_sec   = 300,
        .cooldown_sec = 300,
        .enabled      = true,
    },
    {
        /* A CRITICAL-severity condition firing at all is worth a heads-up
         * before remedies are even exhausted. Detected events carry the
         * severity in the payload; the engine only emits one per episode. */
        .name         = "condition_detected",
        .trigger      = EV_CONDITION_DETECTED,
        .threshold    = 1,
        .window_sec   = 300,
        .cooldown_sec = 600,
        .enabled      = true,
    },
};

/* ── Public API ──────────────────────────────────────────────── */

void alerts_init(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_initialized) {
        pthread_mutex_unlock(&g_lock);
        return;
    }

    /* Check disable flag */
    const char *disable = getenv("ZCL_ALERTS_DISABLE");
    if (disable && strcmp(disable, "1") == 0) {
        g_initialized = true;
        pthread_mutex_unlock(&g_lock);
        return;
    }

    /* Configure webhook */
    const char *url = getenv("ZCL_ALERT_WEBHOOK_URL");
    if (url && *url) {
        snprintf(g_webhook_url, sizeof(g_webhook_url), "%s", url);
        g_webhook_enabled = true;
    }

    /* No SIGCHLD/SA_NOCLDWAIT install here anymore. The webhook sink launches
     * curl via zcl_spawn_detached (double-fork + setsid), whose grandchild is
     * reparented to init/subreaper and can never be a zombie of this process,
     * so the old process-wide SA_NOCLDWAIT disposition is unnecessary. Its
     * removal is the LAST step of os-substrate Rung 0 (docs/work/
     * os-substrate-plan.md §1): it was the reason every system()'s return
     * code was untrustworthy tree-wide, so it could only be removed once every
     * other shell-out site had migrated off system()/popen(). With the default
     * SIGCHLD disposition restored, zcl_spawn_capture()'s waitpid() now yields
     * real child exit codes. */

    /* Register seed rules */
    size_t seed_count = sizeof(k_seed_rules) / sizeof(k_seed_rules[0]);
    for (size_t i = 0; i < seed_count && g_num_rules < ALERT_MAX_RULES; i++) {
        memset(&g_rules[g_num_rules], 0, sizeof(g_rules[g_num_rules]));
        g_rules[g_num_rules].rule = k_seed_rules[i];
        g_rules[g_num_rules].window_start_us = GetTimeMicros();
        g_num_rules++;
    }

    /* Publish only rules whose trigger subscription succeeded. */
    bool installed[EV_NUM_TYPES] = {false};
    size_t kept = 0;
    for (size_t i = 0; i < g_num_rules; i++) {
        enum event_type t = g_rules[i].rule.trigger;
        if (t < EV_NUM_TYPES && !installed[t]) {
            if (!event_observe(t, alert_observer, NULL)) {
                fprintf(stderr, "[ALERT] rule %s registration refused\n",
                        g_rules[i].rule.name);
                continue;
            }
            installed[t] = true;
        }
        g_rules[kept++] = g_rules[i];
    }
    g_num_rules = kept;

    /* EV_CONDITION_CLEARED has no threshold rule — it only clears the
     * operator-needed latch — but we still need to observe it. */
    if (!installed[EV_CONDITION_CLEARED] &&
        !event_observe(EV_CONDITION_CLEARED, alert_observer, NULL))
        fprintf(stderr, "[ALERT] condition-cleared registration refused\n");

    g_initialized = true;
    pthread_mutex_unlock(&g_lock);
}

void alerts_shutdown(void)
{
    pthread_mutex_lock(&g_lock);
    /* Clear observers for our trigger events */
    bool cleared[EV_NUM_TYPES] = {false};
    for (size_t i = 0; i < g_num_rules; i++) {
        enum event_type t = g_rules[i].rule.trigger;
        if (t < EV_NUM_TYPES && !cleared[t]) {
            event_clear_observers(t);
            cleared[t] = true;
        }
    }
    if (!cleared[EV_CONDITION_CLEARED])
        event_clear_observers(EV_CONDITION_CLEARED);
    g_num_rules = 0;
    g_webhook_enabled = false;
    g_webhook_url[0] = '\0';
    g_operator_needed_detail[0] = '\0';
    atomic_store(&g_operator_needed, false);
    atomic_store(&g_operator_needed_since_unix, 0);
    g_initialized = false;
    pthread_mutex_unlock(&g_lock);
}

bool alerts_add_rule(const struct alert_rule *rule)
{
    if (!rule || !rule->name[0] ||
        !memchr(rule->name, '\0', sizeof(rule->name))) return false;

    pthread_mutex_lock(&g_lock);

    /* Check for duplicate */
    for (size_t i = 0; i < g_num_rules; i++) {
        if (strcmp(g_rules[i].rule.name, rule->name) == 0) {
            pthread_mutex_unlock(&g_lock);
            return false;
        }
    }

    if (g_num_rules >= ALERT_MAX_RULES) {
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    if (g_initialized && rule->trigger < EV_NUM_TYPES &&
        !event_observe(rule->trigger, alert_observer, NULL)) {
        fprintf(stderr, "[ALERT] rule %s registration refused\n", rule->name);
        pthread_mutex_unlock(&g_lock);
        return false;
    }

    size_t idx = g_num_rules++;
    memset(&g_rules[idx], 0, sizeof(g_rules[idx]));
    g_rules[idx].rule = *rule;
    g_rules[idx].window_start_us = GetTimeMicros();

    pthread_mutex_unlock(&g_lock);
    return true;
}

uint64_t alerts_fire_count(const char *rule_name)
{
    if (!rule_name) return 0;
    pthread_mutex_lock(&g_lock);
    uint64_t v = 0;
    for (size_t i = 0; i < g_num_rules; i++) {
        if (strcmp(g_rules[i].rule.name, rule_name) == 0) {
            v = g_rules[i].total_fires;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return v;
}

size_t alerts_rule_count(void)
{
    pthread_mutex_lock(&g_lock);
    size_t n = g_num_rules;
    pthread_mutex_unlock(&g_lock);
    return n;
}

void alerts_reset(void)
{
    pthread_mutex_lock(&g_lock);
    for (size_t i = 0; i < g_num_rules; i++) {
        g_rules[i].count_in_window = 0;
        g_rules[i].last_fired_us = 0;
        g_rules[i].total_fires = 0;
        g_rules[i].window_start_us = GetTimeMicros();
    }
    g_operator_needed_detail[0] = '\0';
    atomic_store(&g_operator_needed, false);
    atomic_store(&g_operator_needed_since_unix, 0);
    pthread_mutex_unlock(&g_lock);
}

/* Never expose a split UTF-8 sequence through a smaller output buffer. */
static void operator_needed_copy(char *out, size_t cap, const char *detail)
{
    if (!out || cap == 0) return;
    int n = snprintf(out, cap, "%s", detail);
    if (n < 0) {
        out[0] = '\0';
        return;
    }
    if ((size_t)n >= cap && !zutf8_validate(out))
        snprintf(out, cap, "(operator detail refused: invalid UTF-8)");
}

bool alerts_operator_needed(char *detail_out, size_t detail_cap,
                            int64_t *since_unix_out)
{
    pthread_mutex_lock(&g_lock);
    bool active = atomic_load(&g_operator_needed);
    if (since_unix_out)
        *since_unix_out = atomic_load(&g_operator_needed_since_unix);
    operator_needed_copy(detail_out, detail_cap, g_operator_needed_detail);
    pthread_mutex_unlock(&g_lock);
    return active;
}

static bool operator_needed_is_chain_advance_recovery(const char *detail)
{
    if (!detail || !detail[0])
        return false;
    return strstr(detail, "chain_advance_local_recovery_gate") ||
           strstr(detail, "local_recovery_gate") ||
           strstr(detail, "local_header_refill");
}

bool alerts_operator_needed_clear_if_chain_advance_recovered(
    bool frontier_recovered,
    char *detail_out,
    size_t detail_cap,
    int64_t *since_unix_out)
{
    char detail[ALERT_OPERATOR_NEEDED_DETAIL_LEN] = {0};
    int64_t since = 0;

    if (!alerts_operator_needed(detail, sizeof(detail), &since))
        return false;
    operator_needed_copy(detail_out, detail_cap, detail);
    if (since_unix_out)
        *since_unix_out = since;

    if (!frontier_recovered ||
        !operator_needed_is_chain_advance_recovery(detail))
        return false;

    alerts_operator_needed_clear();
    return true;
}

void alerts_operator_needed_clear(void)
{
    pthread_mutex_lock(&g_lock);
    atomic_store(&g_operator_needed, false);
    atomic_store(&g_operator_needed_since_unix, 0);
    g_operator_needed_detail[0] = '\0';
    pthread_mutex_unlock(&g_lock);
}

/* ── Printf helper (same pattern as metrics.c) ──────────────── */

ZCL_PRINTF_LIKE(4, 5)
static size_t append(char *buf, size_t cap, size_t pos, const char *fmt, ...)
{
    if (pos >= cap) return pos;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + pos, cap - pos, fmt, ap);
    va_end(ap);
    if (n < 0) return pos;
    if ((size_t)n >= cap - pos) return cap - 1;
    return pos + (size_t)n;
}

size_t alerts_report_json(char *buf, size_t cap)
{
    if (!buf || cap == 0) return 0;
    pthread_mutex_lock(&g_lock);

    size_t pos = 0;
    pos = append(buf, cap, pos,
        "{\"webhook\":%s,\"rules\":[",
        g_webhook_enabled ? "true" : "false");

    for (size_t i = 0; i < g_num_rules; i++) {
        const struct rule_state *rs = &g_rules[i];
        pos = append(buf, cap, pos,
            "%s{\"name\":\"%s\",\"trigger\":\"%s\","
            "\"threshold\":%d,\"window_sec\":%d,"
            "\"cooldown_sec\":%d,\"enabled\":%s,"
            "\"fires\":%llu,\"count_in_window\":%d}",
            i == 0 ? "" : ",",
            rs->rule.name,
            event_type_name(rs->rule.trigger),
            rs->rule.threshold,
            rs->rule.window_sec,
            rs->rule.cooldown_sec,
            rs->rule.enabled ? "true" : "false",
            (unsigned long long)rs->total_fires,
            rs->count_in_window);
    }
    pos = append(buf, cap, pos, "],\"total_rules\":%zu}", g_num_rules);

    if (pos < cap) buf[pos] = '\0';
    pthread_mutex_unlock(&g_lock);
    return pos;
}
