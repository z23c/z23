/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Cheap process-resource telemetry for first-call AI/operator status. */

#include "controllers/agent_resources.h"

#include "json/json.h"
#include "platform/os_proc.h"

#include <stdio.h>
#include <string.h>

#define AGENT_RESOURCES_RSS_WARN_MB 4096
#define AGENT_RESOURCES_CGROUP_HIGH_WATCH_PCT 85
#define AGENT_RESOURCES_CGROUP_HIGH_WARN_PCT 95
#define AGENT_RESOURCES_CGROUP_MAX_WATCH_PCT 80
#define AGENT_RESOURCES_CGROUP_MAX_WARN_PCT 90

struct agent_resources_cgroup_stat {
    bool available;
    int64_t anon_bytes;
    int64_t file_bytes;
    int64_t kernel_bytes;
    int64_t kernel_stack_bytes;
    int64_t pagetables_bytes;
    int64_t sec_pagetables_bytes;
    int64_t percpu_bytes;
    int64_t sock_bytes;
    int64_t inactive_file_bytes;
    int64_t slab_reclaimable_bytes;
    int64_t slab_unreclaimable_bytes;
    int64_t slab_bytes;
};

static void agent_resources_trim_newline(char *s)
{
    if (!s)
        return;
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[len - 1] = '\0';
        len--;
    }
}

static int64_t agent_resources_cgroup_bytes(const char *dir, const char *name)
{
    if (!dir || !name)
        return -1; // raw-return-ok:optional-cgroup-unavailable

    char path[768];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path))
        return -1; // raw-return-ok:optional-cgroup-unavailable

    FILE *f = fopen(path, "r");
    if (!f)
        return -1; // raw-return-ok:optional-cgroup-unavailable

    char buf[64];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -1; // raw-return-ok:optional-cgroup-unavailable
    }
    fclose(f);
    agent_resources_trim_newline(buf);
    if (strcmp(buf, "max") == 0)
        return -1; // raw-return-ok:unlimited-cgroup-value

    long long value = -1;
    if (sscanf(buf, "%lld", &value) != 1 || value < 0)
        return -1; // raw-return-ok:optional-cgroup-unavailable
    return (int64_t)value;
}

static void agent_resources_cgroup_stat_init(
    struct agent_resources_cgroup_stat *st)
{
    if (!st)
        return;
    memset(st, 0, sizeof(*st));
    st->anon_bytes = -1;
    st->file_bytes = -1;
    st->kernel_bytes = -1;
    st->kernel_stack_bytes = -1;
    st->pagetables_bytes = -1;
    st->sec_pagetables_bytes = -1;
    st->percpu_bytes = -1;
    st->sock_bytes = -1;
    st->inactive_file_bytes = -1;
    st->slab_reclaimable_bytes = -1;
    st->slab_unreclaimable_bytes = -1;
    st->slab_bytes = -1;
}

static void agent_resources_stat_assign(struct agent_resources_cgroup_stat *st,
                                        const char *key,
                                        int64_t value)
{
    if (!st || !key || value < 0)
        return;
    st->available = true;
    if (strcmp(key, "anon") == 0)
        st->anon_bytes = value;
    else if (strcmp(key, "file") == 0)
        st->file_bytes = value;
    else if (strcmp(key, "kernel") == 0)
        st->kernel_bytes = value;
    else if (strcmp(key, "kernel_stack") == 0)
        st->kernel_stack_bytes = value;
    else if (strcmp(key, "pagetables") == 0)
        st->pagetables_bytes = value;
    else if (strcmp(key, "sec_pagetables") == 0)
        st->sec_pagetables_bytes = value;
    else if (strcmp(key, "percpu") == 0)
        st->percpu_bytes = value;
    else if (strcmp(key, "sock") == 0)
        st->sock_bytes = value;
    else if (strcmp(key, "inactive_file") == 0)
        st->inactive_file_bytes = value;
    else if (strcmp(key, "slab_reclaimable") == 0)
        st->slab_reclaimable_bytes = value;
    else if (strcmp(key, "slab_unreclaimable") == 0)
        st->slab_unreclaimable_bytes = value;
    else if (strcmp(key, "slab") == 0)
        st->slab_bytes = value;
}

static bool agent_resources_cgroup_stat_load(
    const char *dir,
    struct agent_resources_cgroup_stat *st)
{
    if (!dir || !st)
        return false; // raw-return-ok:optional-cgroup-unavailable

    agent_resources_cgroup_stat_init(st);
    char path[768];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, "memory.stat");
    if (n < 0 || (size_t)n >= sizeof(path))
        return false; // raw-return-ok:optional-cgroup-unavailable

    FILE *f = fopen(path, "r");
    if (!f)
        return false; // raw-return-ok:optional-cgroup-unavailable

    char key[64];
    long long value = -1;
    while (fscanf(f, "%63s %lld", key, &value) == 2)
        agent_resources_stat_assign(st, key, (int64_t)value);

    fclose(f);
    return st->available;
}

static int64_t agent_resources_sum_nonnegative(const int64_t *values,
                                               size_t count)
{
    int64_t total = 0;
    bool saw = false;
    for (size_t i = 0; i < count; i++) {
        if (values[i] < 0)
            continue;
        if (total > INT64_MAX - values[i])
            return -1; // raw-return-ok:sentinel
        total += values[i];
        saw = true;
    }
    return saw ? total : -1;
}

static int64_t agent_resources_bytes_to_mb(int64_t bytes)
{
    if (bytes < 0)
        return -1; // raw-return-ok:sentinel
    return bytes / (1024 * 1024);
}

static int64_t agent_resources_pct(int64_t current_mb, int64_t limit_mb)
{
    if (current_mb < 0 || limit_mb <= 0)
        return -1; // raw-return-ok:sentinel
    if (current_mb > INT64_MAX / 100)
        return -1; // raw-return-ok:sentinel
    return (current_mb * 100) / limit_mb;
}

static int64_t agent_resources_cgroup_kernel_bytes(
    const struct agent_resources_cgroup_stat *st)
{
    if (!st || !st->available)
        return -1; // raw-return-ok:sentinel
    if (st->kernel_bytes >= 0)
        return st->kernel_bytes;
    int64_t values[] = {
        st->kernel_stack_bytes,
        st->pagetables_bytes,
        st->sec_pagetables_bytes,
        st->percpu_bytes,
        st->sock_bytes,
        st->slab_bytes >= 0 ? st->slab_bytes : st->slab_unreclaimable_bytes,
    };
    return agent_resources_sum_nonnegative(values,
        sizeof(values) / sizeof(values[0]));
}

static void agent_resources_apply_cgroup_stat(
    struct agent_resource_snapshot *s,
    const struct agent_resources_cgroup_stat *st,
    int64_t current_bytes)
{
    if (!s || !st || !st->available)
        return;

    s->cgroup_memory_stat_available = true;
    s->cgroup_memory_anon_mb =
        agent_resources_bytes_to_mb(st->anon_bytes);
    s->cgroup_memory_file_mb =
        agent_resources_bytes_to_mb(st->file_bytes);
    s->cgroup_memory_kernel_mb =
        agent_resources_bytes_to_mb(agent_resources_cgroup_kernel_bytes(st));
    s->cgroup_memory_inactive_file_mb =
        agent_resources_bytes_to_mb(st->inactive_file_bytes);
    s->cgroup_memory_slab_reclaimable_mb =
        agent_resources_bytes_to_mb(st->slab_reclaimable_bytes);

    int64_t reclaimable_values[] = {
        st->inactive_file_bytes,
        st->slab_reclaimable_bytes,
    };
    int64_t reclaimable_bytes = agent_resources_sum_nonnegative(
        reclaimable_values, sizeof(reclaimable_values) /
        sizeof(reclaimable_values[0]));
    s->cgroup_memory_reclaimable_mb =
        agent_resources_bytes_to_mb(reclaimable_bytes);
    if (current_bytes >= 0 && reclaimable_bytes >= 0) {
        int64_t working_set = current_bytes > reclaimable_bytes
            ? current_bytes - reclaimable_bytes : 0;
        s->cgroup_memory_working_set_mb =
            agent_resources_bytes_to_mb(working_set);
        s->cgroup_memory_working_set_high_pct =
            agent_resources_pct(s->cgroup_memory_working_set_mb,
                                s->cgroup_memory_high_mb);
        s->cgroup_memory_working_set_max_pct =
            agent_resources_pct(s->cgroup_memory_working_set_mb,
                                s->cgroup_memory_max_mb);
        s->cgroup_memory_reclaimable_dominant =
            reclaimable_bytes > working_set;
    }
}

static void agent_resources_collect_cgroup(struct agent_resource_snapshot *s)
{
    char dir[768];
    if (!os_proc_cgroup_dir(dir, sizeof(dir)))
        return;

    int64_t current_bytes =
        agent_resources_cgroup_bytes(dir, "memory.current");
    if (current_bytes < 0)
        return;

    int64_t high_bytes = agent_resources_cgroup_bytes(dir, "memory.high");
    int64_t max_bytes = agent_resources_cgroup_bytes(dir, "memory.max");
    struct agent_resources_cgroup_stat st;
    bool stat_ok = agent_resources_cgroup_stat_load(dir, &st);
    s->cgroup_memory_available = true;
    s->cgroup_memory_current_mb =
        agent_resources_bytes_to_mb(current_bytes);
    s->cgroup_memory_high_mb = agent_resources_bytes_to_mb(high_bytes);
    s->cgroup_memory_max_mb = agent_resources_bytes_to_mb(max_bytes);
    s->cgroup_memory_high_pct =
        agent_resources_pct(s->cgroup_memory_current_mb,
                            s->cgroup_memory_high_mb);
    s->cgroup_memory_max_pct =
        agent_resources_pct(s->cgroup_memory_current_mb,
                            s->cgroup_memory_max_mb);
    if (stat_ok)
        agent_resources_apply_cgroup_stat(s, &st, current_bytes);

    bool working_high_near =
        s->cgroup_memory_working_set_high_pct < 0 ||
        s->cgroup_memory_working_set_high_pct >=
            AGENT_RESOURCES_CGROUP_HIGH_WATCH_PCT;
    bool working_max_near =
        s->cgroup_memory_working_set_max_pct < 0 ||
        s->cgroup_memory_working_set_max_pct >=
            AGENT_RESOURCES_CGROUP_MAX_WATCH_PCT;

    bool high_watch = s->cgroup_memory_high_pct >=
                      AGENT_RESOURCES_CGROUP_HIGH_WATCH_PCT;
    bool high_warn = s->cgroup_memory_high_pct >=
                     AGENT_RESOURCES_CGROUP_HIGH_WARN_PCT &&
                     working_high_near;
    bool max_watch = s->cgroup_memory_high_mb <= 0 &&
                     s->cgroup_memory_max_pct >=
                     AGENT_RESOURCES_CGROUP_MAX_WATCH_PCT;
    bool max_warn = s->cgroup_memory_max_mb > 0 &&
                    s->cgroup_memory_max_pct >=
                    AGENT_RESOURCES_CGROUP_MAX_WARN_PCT &&
                    working_max_near;
    s->cgroup_memory_warning = high_warn || max_warn;
    s->cgroup_memory_watch = high_watch || max_watch ||
                              s->cgroup_memory_warning;
}

static const char *agent_resources_pressure_detail(
    const struct agent_resource_snapshot *s)
{
    if (!s)
        return "unknown";
    if (s->cgroup_memory_available) {
        if (s->cgroup_memory_warning)
            return "cgroup_working_set_high";
        if (s->cgroup_memory_high_pct >=
                AGENT_RESOURCES_CGROUP_HIGH_WARN_PCT ||
            s->cgroup_memory_max_pct >=
                AGENT_RESOURCES_CGROUP_MAX_WARN_PCT)
            return "cgroup_reclaimable_cache_high";
        if (s->cgroup_memory_watch)
            return s->cgroup_memory_reclaimable_dominant
                ? "cgroup_cache_watch" : "cgroup_limit_watch";
        return "within_limits";
    }
    if (s->rss_mb < 0)
        return "unknown";
    return s->rss_warning ? "rss_over_threshold" : "within_limits";
}

static const char *agent_resources_pressure(
    const struct agent_resource_snapshot *s)
{
    if (!s)
        return "unknown";
    if (s->cgroup_memory_available) {
        if (s->cgroup_memory_warning)
            return "warn";
        if (s->cgroup_memory_watch)
            return "watch";
        return "ok";
    }
    if (s->rss_mb < 0)
        return "unknown";
    return s->rss_warning ? "warn" : "ok";
}

static const char *agent_resources_pressure_basis(
    const struct agent_resource_snapshot *s)
{
    if (!s)
        return "unknown";
    if (s->cgroup_memory_available) {
        if (s->cgroup_memory_high_mb > 0)
            return "cgroup_high";
        if (s->cgroup_memory_max_mb > 0)
            return "cgroup_max";
        return "cgroup";
    }
    if (s->rss_mb >= 0)
        return "rss";
    return "unknown";
}

void agent_resource_snapshot_collect(struct agent_resource_snapshot *snapshot)
{
    if (!snapshot)
        return;

    snapshot->rss_mb = -1;
    snapshot->rss_warn_threshold_mb = AGENT_RESOURCES_RSS_WARN_MB;
    snapshot->rss_warning = false;
    snapshot->cgroup_memory_available = false;
    snapshot->cgroup_memory_current_mb = -1;
    snapshot->cgroup_memory_high_mb = -1;
    snapshot->cgroup_memory_max_mb = -1;
    snapshot->cgroup_memory_high_pct = -1;
    snapshot->cgroup_memory_max_pct = -1;
    snapshot->cgroup_memory_stat_available = false;
    snapshot->cgroup_memory_anon_mb = -1;
    snapshot->cgroup_memory_file_mb = -1;
    snapshot->cgroup_memory_kernel_mb = -1;
    snapshot->cgroup_memory_inactive_file_mb = -1;
    snapshot->cgroup_memory_slab_reclaimable_mb = -1;
    snapshot->cgroup_memory_reclaimable_mb = -1;
    snapshot->cgroup_memory_working_set_mb = -1;
    snapshot->cgroup_memory_working_set_high_pct = -1;
    snapshot->cgroup_memory_working_set_max_pct = -1;
    snapshot->cgroup_memory_reclaimable_dominant = false;
    snapshot->cgroup_memory_watch = false;
    snapshot->cgroup_memory_warning = false;
    snapshot->uptime_seconds = -1;

    struct os_proc_mem mem;
    if (os_proc_mem_read(&mem) && mem.rss_bytes >= 0)
        snapshot->rss_mb = mem.rss_bytes / (1024 * 1024);
    snapshot->rss_warning =
        snapshot->rss_mb > snapshot->rss_warn_threshold_mb;
    agent_resources_collect_cgroup(snapshot);
    snapshot->uptime_seconds = os_proc_uptime_seconds();
}

void agent_push_resources_json(struct json_value *out, const char *key,
                               const struct agent_resource_snapshot *snapshot)
{
    struct agent_resource_snapshot live;
    if (!snapshot) {
        agent_resource_snapshot_collect(&live);
        snapshot = &live;
    }

    struct json_value resources = {0};
    json_set_object(&resources);
    json_push_kv_str(&resources, "schema", "zcl.node_resources.v1");
    json_push_kv_int(&resources, "schema_version", 1);
    json_push_kv_int(&resources, "rss_mb", snapshot->rss_mb);
    json_push_kv_int(&resources, "rss_warn_threshold_mb",
                     snapshot->rss_warn_threshold_mb);
    json_push_kv_bool(&resources, "rss_warning", snapshot->rss_warning);
    json_push_kv_bool(&resources, "cgroup_memory_available",
                      snapshot->cgroup_memory_available);
    json_push_kv_int(&resources, "cgroup_memory_current_mb",
                     snapshot->cgroup_memory_current_mb);
    json_push_kv_int(&resources, "cgroup_memory_high_mb",
                     snapshot->cgroup_memory_high_mb);
    json_push_kv_int(&resources, "cgroup_memory_max_mb",
                     snapshot->cgroup_memory_max_mb);
    json_push_kv_int(&resources, "cgroup_memory_high_pct",
                     snapshot->cgroup_memory_high_pct);
    json_push_kv_int(&resources, "cgroup_memory_max_pct",
                     snapshot->cgroup_memory_max_pct);
    json_push_kv_bool(&resources, "cgroup_memory_stat_available",
                      snapshot->cgroup_memory_stat_available);
    json_push_kv_int(&resources, "cgroup_memory_anon_mb",
                     snapshot->cgroup_memory_anon_mb);
    json_push_kv_int(&resources, "cgroup_memory_file_mb",
                     snapshot->cgroup_memory_file_mb);
    json_push_kv_int(&resources, "cgroup_memory_kernel_mb",
                     snapshot->cgroup_memory_kernel_mb);
    json_push_kv_int(&resources, "cgroup_memory_inactive_file_mb",
                     snapshot->cgroup_memory_inactive_file_mb);
    json_push_kv_int(&resources, "cgroup_memory_slab_reclaimable_mb",
                     snapshot->cgroup_memory_slab_reclaimable_mb);
    json_push_kv_int(&resources, "cgroup_memory_reclaimable_mb",
                     snapshot->cgroup_memory_reclaimable_mb);
    json_push_kv_int(&resources, "cgroup_memory_working_set_mb",
                     snapshot->cgroup_memory_working_set_mb);
    json_push_kv_int(&resources, "cgroup_memory_working_set_high_pct",
                     snapshot->cgroup_memory_working_set_high_pct);
    json_push_kv_int(&resources, "cgroup_memory_working_set_max_pct",
                     snapshot->cgroup_memory_working_set_max_pct);
    json_push_kv_bool(&resources, "cgroup_memory_reclaimable_dominant",
                      snapshot->cgroup_memory_reclaimable_dominant);
    json_push_kv_bool(&resources, "cgroup_memory_watch",
                      snapshot->cgroup_memory_watch);
    json_push_kv_bool(&resources, "cgroup_memory_warning",
                      snapshot->cgroup_memory_warning);
    json_push_kv_str(&resources, "memory_pressure",
                     agent_resources_pressure(snapshot));
    json_push_kv_str(&resources, "memory_pressure_detail",
                     agent_resources_pressure_detail(snapshot));
    json_push_kv_str(&resources, "pressure_basis",
                     agent_resources_pressure_basis(snapshot));
    json_push_kv_int(&resources, "uptime_seconds",
                     snapshot->uptime_seconds);
    json_push_kv_str(&resources, "source",
                     snapshot->cgroup_memory_stat_available
                     ? "proc_self+cgroup_v2+memory.stat" :
                     snapshot->cgroup_memory_available
                     ? "proc_self+cgroup_v2" : "proc_self");
    json_push_kv(out, key ? key : "resources", &resources);
    json_free(&resources);
}
