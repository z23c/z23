/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Host observers behind the node SLO monitors. Every call is bounded and
 * answers "unknown" rather than failing: a dark node, a missing unit or an
 * unreadable procfs entry is data for the ledger, never an abort. */

#define _XOPEN_SOURCE 700

#include "command/slo_monitor_io.h"

#include "controllers/rpc_client.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "rpc/legacy_rpc_client.h"
#include "util/spawn.h"

#include <ctype.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

enum {
    IO_DETAIL_MAX = 200,
    IO_SHOW_MAX = 4096,
    IO_CRED_MAX = 128,
    IO_DEFAULT_RPC_SEC = 8,
    IO_DEFAULT_SIDE_SEC = 5,
    IO_CANON_PORT = 18232,
    IO_DEV_PORT = 18252,
    IO_ORACLE_PORT = 8232
};

static const char k_live_default[] = "canonical,dev";

static long timeout_ms(const char *text, int64_t fallback_sec)
{
    int64_t sec = slo_parse_i64(text, fallback_sec);
    if (sec < 1 || sec > 600)
        sec = fallback_sec;
    return (long)(sec * 1000);
}

static long rpc_ms(void)
{
    return timeout_ms(getenv("ZCL_SLO_RPC_TIMEOUT_SEC"), IO_DEFAULT_RPC_SEC);
}

static long state_ms(void)
{
    return timeout_ms(getenv("ZCL_SLO_STATE_TIMEOUT_SEC"),
                      IO_DEFAULT_SIDE_SEC);
}

static long host_ms(void)
{
    return timeout_ms(getenv("ZCL_SLO_HOST_TIMEOUT_SEC"), IO_DEFAULT_SIDE_SEC);
}

static void fold_text(char *dst, size_t cap, const char *src, size_t limit)
{
    size_t n = 0;
    for (; src && src[n] && n < limit && n + 1 < cap; n++)
        dst[n] = (src[n] == '\n' || src[n] == '\r' || src[n] == '\t')
                     ? ' ' : src[n];
    if (cap)
        dst[n] = '\0';
}

static const struct json_value *state_of(const struct json_value *root)
{
    const struct json_value *st = json_get(root, "state");
    return st && st->type == JSON_OBJ ? st : root;
}

static bool int_field(const struct json_value *obj, const char *key,
                      struct slo_opt *out)
{
    const struct json_value *v = json_get(obj, key);
    if (!v || v->type != JSON_INT)
        return false;
    *out = (struct slo_opt){ true, json_get_int(v) };
    return true;
}

bool slo_io_chain_parse(const char *raw, struct slo_chain_answer *out)
{
    struct json_value root;
    json_init(&root);
    bool ok = raw && json_read(&root, raw, strlen(raw)) &&
              root.type == JSON_OBJ;
    if (ok) {
        const struct json_value *r = json_get(&root, "result");
        const struct json_value *info = r && r->type == JSON_OBJ ? r : &root;
        ok = int_field(info, "blocks", &out->served);
        (void)int_field(info, "headers", &out->header);
    }
    json_free(&root);
    return ok;
}

struct slo_opt slo_io_peer_count(const char *raw)
{
    struct json_value root;
    struct slo_opt n = { 0 };
    json_init(&root);
    if (raw && json_read(&root, raw, strlen(raw))) {
        const struct json_value *list = json_get(&root, "result");
        list = list ? list : &root;
        if (list->type == JSON_ARR) {
            n.has = true;
            for (size_t i = 0; i < json_size(list); i++)
                n.v += json_get(json_at(list, i), "addr") != NULL;
        }
    }
    json_free(&root);
    return n;
}

static bool legacy_creds(const char *datadir, char *user, char *pass)
{
    char path[SLO_PATH_MAX], line[2 * IO_CRED_MAX];
    snprintf(path, sizeof(path), "%s/.cookie", datadir);
    user[0] = pass[0] = '\0';
    FILE *f = fopen(path, "r");
    if (f) {
        const char *colon = fgets(line, sizeof(line), f)
                                ? strchr(line, ':') : NULL;
        if (colon && (size_t)(colon - line) < IO_CRED_MAX) {
            snprintf(user, IO_CRED_MAX, "%.*s", (int)(colon - line), line);
            fold_text(pass, IO_CRED_MAX, colon + 1, IO_CRED_MAX - 1);
            pass[strcspn(pass, " ")] = '\0';
        }
        fclose(f);
    }
    if (user[0] && pass[0])
        return true;
    snprintf(path, sizeof(path), "%s/zclassic.conf", datadir);
    f = fopen(path, "r");
    while (f && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "rpcuser=", 8) == 0)
            snprintf(user, IO_CRED_MAX, "%s", line + 8);
        else if (strncmp(line, "rpcpassword=", 12) == 0)
            snprintf(pass, IO_CRED_MAX, "%s", line + 12);
    }
    if (f)
        fclose(f);
    return user[0] && pass[0];
}

/* Raw JSON-RPC body from the legacy node, or a human-readable failure text. */
static char *legacy_raw(const struct slo_instance *at, const char *method)
{
    char user[IO_CRED_MAX], pass[IO_CRED_MAX], body[160], err[160];
    char *resp = NULL;
    if (!legacy_creds(at->datadir, user, pass))
        return strdup("no auth found (no cookie, no rpcuser/rpcpassword)");
    snprintf(body, sizeof(body),
             "{\"jsonrpc\":\"1.0\",\"id\":\"slo\",\"method\":\"%s\","
             "\"params\":[]}", method);
    if (!legacy_rpc_call_with_timeout("127.0.0.1", at->rpcport, user, pass,
                                      body, (uint32_t)rpc_ms(), &resp, err,
                                      sizeof(err)))
        return strdup(err[0] ? err : "legacy rpc call failed");
    const char *payload = legacy_rpc_http_body(resp);
    char *out = strdup(payload ? payload : resp);
    free(resp);
    return out;
}

static void io_chain(void *ctx, const struct slo_instance *at, bool oracle,
                     struct slo_chain_answer *out)
{
    (void)ctx;
    memset(out, 0, sizeof(*out));
    int64_t t0 = platform_time_monotonic_ms();
    long ms = rpc_ms();
    char *raw = oracle ? legacy_raw(at, "getblockchaininfo")
                       : node_rpc_call_at_deadline(at->datadir, at->rpcport,
                                                   "getblockchaininfo", NULL,
                                                   ms, ms);
    out->latency_ms = platform_time_monotonic_ms() - t0;
    if (!slo_io_chain_parse(raw, out)) {
        memset(&out->served, 0, sizeof(out->served));
        memset(&out->header, 0, sizeof(out->header));
        fold_text(out->detail, sizeof(out->detail), raw, IO_DETAIL_MAX);
        if (!out->detail[0])
            snprintf(out->detail, sizeof(out->detail), "empty_response");
    }
    free(raw);
}

static struct slo_opt io_peers(void *ctx, const struct slo_instance *at)
{
    (void)ctx;
    long ms = rpc_ms();
    char *raw = node_rpc_call_at_deadline(at->datadir, at->rpcport,
                                          "getpeerinfo", NULL, ms, ms);
    struct slo_opt n = slo_io_peer_count(raw);
    free(raw);
    return n;
}

static bool prop_value(const char *show, const char *key, char *out,
                       size_t cap)
{
    size_t klen = strlen(key);
    out[0] = '\0';
    for (const char *p = show; p && *p;) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            fold_text(out, cap, p + klen + 1, strcspn(p + klen + 1, "\n"));
            return true;
        }
        p = strchr(p, '\n');
        p = p ? p + 1 : NULL;
    }
    return false;
}

bool slo_io_epoch_parse(const char *text, int64_t *out)
{
    if (!text || !text[0] || strcmp(text, "n/a") == 0)
        return false;
    if (text[0] == '@') {
        char *end = NULL;
        long long v = strtoll(text + 1, &end, 10);
        if (end == text + 1 || *end != '\0')
            return false;
        *out = v;
        return true;
    }
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    if (!strptime(text, "%a %Y-%m-%d %H:%M:%S", &tm))
        return false;
    tm.tm_isdst = -1;
    time_t t = mktime(&tm);
    if (t == (time_t)-1)
        return false;
    *out = (int64_t)t;
    return true;
}

bool slo_io_rss_parse(const char *status_text, int64_t *out_kb)
{
    const char *p = status_text ? strstr(status_text, "VmRSS:") : NULL;
    if (!p)
        return false;
    char *end = NULL;
    long long v = strtoll(p + strlen("VmRSS:"), &end, 10);
    if (end == p + strlen("VmRSS:") || v < 0)
        return false;
    *out_kb = v;
    return true;
}

static void systemd_show(const char *unit, char *out, size_t cap)
{
    const char *with_unix[] = { "systemctl", "--user", "show", unit,
        "--timestamp=unix", "-p", "NRestarts", "-p", "ActiveEnterTimestamp",
        "-p", "ActiveState", "-p", "MainPID", NULL };
    const char *plain[] = { "systemctl", "--user", "show", unit, "-p",
        "NRestarts", "-p", "ActiveEnterTimestamp", "-p", "ActiveState", "-p",
        "MainPID", NULL };
    out[0] = '\0';
    zcl_spawn_capture(with_unix, out, cap, (int)host_ms());
    if (!out[0])
        zcl_spawn_capture(plain, out, cap, (int)host_ms());
}

static void read_rss(const char *pid_text, struct slo_host_facts *out)
{
    char path[48], text[IO_SHOW_MAX];
    if (!pid_text[0] || strspn(pid_text, "0123456789") != strlen(pid_text) ||
        strcmp(pid_text, "0") == 0)
        return;
    snprintf(path, sizeof(path), "/proc/%s/status", pid_text);
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    fclose(f);
    text[n] = '\0';
    out->rss_kb.has = slo_io_rss_parse(text, &out->rss_kb.v);
}

static int64_t g_du_sum;
static int64_t g_du_deadline;

static int du_visit(const char *path, const struct stat *st, int type,
                    struct FTW *ftw)
{
    (void)path;
    (void)ftw;
    if (type == FTW_NS)
        return 0;
    g_du_sum += (int64_t)st->st_size;
    return platform_time_monotonic_ms() > g_du_deadline ? 1 : 0;
}

static struct slo_opt dir_bytes(const char *dir)
{
    struct stat st;
    if (!dir[0] || stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
        return (struct slo_opt){ 0 };
    g_du_sum = 0;
    g_du_deadline = platform_time_monotonic_ms() + host_ms();
    int rc = nftw(dir, du_visit, 32, FTW_PHYS);
    return (struct slo_opt){ rc == 0, g_du_sum };
}

static void io_host(void *ctx, const struct slo_instance *at,
                    struct slo_host_facts *out)
{
    (void)ctx;
    char show[IO_SHOW_MAX], value[64];
    memset(out, 0, sizeof(*out));
    if (at->unit[0]) {
        systemd_show(at->unit, show, sizeof(show));
        if (prop_value(show, "NRestarts", value, sizeof(value)) && value[0] &&
            strspn(value, "0123456789") == strlen(value))
            out->nrestarts = (struct slo_opt){ true, atoll(value) };
        if (prop_value(show, "ActiveEnterTimestamp", value, sizeof(value)))
            out->active_enter_ts.has =
                slo_io_epoch_parse(value, &out->active_enter_ts.v);
        (void)prop_value(show, "ActiveState", out->active_state,
                         sizeof(out->active_state));
        if (prop_value(show, "MainPID", value, sizeof(value)))
            read_rss(value, out);
    }
    out->datadir_bytes = dir_bytes(at->datadir);
}

/* A node answer that carries a non-null "error" is not a state report. */
static bool dump_ok(const struct json_value *root)
{
    const struct json_value *err = json_get(root, "error");
    return root->type == JSON_OBJ && (!err || json_is_null(err));
}

static void parse_explorer(const struct json_value *root,
                           struct slo_self_report *out)
{
    const struct json_value *st = state_of(root);
    const struct json_value *on = json_get(st, "onion_enabled");
    const char *addr = json_get_str(json_get(st, "onion_address"));
    if (on && on->type == JSON_BOOL)
        out->onion_enabled = (struct slo_opt){ true, json_get_bool(on) };
    if (addr)
        snprintf(out->onion_address, sizeof(out->onion_address), "%s", addr);
}

static void parse_blocker(const struct json_value *root,
                          struct slo_self_report *out)
{
    const struct json_value *st = state_of(root);
    const struct json_value *list = json_get(st, "blockers");
    (void)int_field(st, "active_count", &out->blocker_count);
    if (list && list->type == JSON_ARR && json_size(list) > 0) {
        const char *id = json_get_str(json_get(json_at(list, 0), "id"));
        if (id)
            snprintf(out->blocker_primary, sizeof(out->blocker_primary), "%s",
                     id);
    }
}

void slo_io_self_parse(const char *explorer_raw, const char *blocker_raw,
                       struct slo_self_report *out)
{
    struct json_value ex, bl;
    json_init(&ex);
    json_init(&bl);
    bool have_ex = explorer_raw &&
                   json_read(&ex, explorer_raw, strlen(explorer_raw)) &&
                   dump_ok(&ex);
    bool have_bl = blocker_raw &&
                   json_read(&bl, blocker_raw, strlen(blocker_raw)) &&
                   dump_ok(&bl);
    if (have_ex)
        parse_explorer(&ex, out);
    if (have_bl)
        parse_blocker(&bl, out);
    out->state_ok = have_ex && have_bl;
    json_free(&ex);
    json_free(&bl);
}

static void io_self(void *ctx, const struct slo_instance *at,
                    struct slo_self_report *out)
{
    (void)ctx;
    long ms = state_ms();
    memset(out, 0, sizeof(*out));
    char *ex = node_rpc_call_at_deadline(at->datadir, at->rpcport, "dumpstate",
                                         "[\"explorer\"]", ms, ms);
    char *bl = node_rpc_call_at_deadline(at->datadir, at->rpcport, "dumpstate",
                                         "[\"blocker\"]", ms, ms);
    slo_io_self_parse(ex, bl, out);
    free(ex);
    free(bl);
}

static int64_t io_now(void *ctx)
{
    (void)ctx;
    return (int64_t)platform_time_wall_time_t();
}

static const struct slo_probe_io k_probe_io = {
    .now = io_now, .chain = io_chain, .peers = io_peers, .host = io_host,
    .self = io_self,
};

const struct slo_probe_io *slo_io_probe(void)
{
    return &k_probe_io;
}

static struct slo_instance g_canonical;

static size_t io_blocker(void *ctx, char *out, size_t cap)
{
    (void)ctx;
    long ms = timeout_ms(NULL, IO_DEFAULT_SIDE_SEC);
    out[0] = '\0';
    char *raw = node_rpc_call_at_deadline(g_canonical.datadir,
                                          g_canonical.rpcport, "dumpstate",
                                          "[\"blocker\"]", ms, ms);
    struct json_value root;
    json_init(&root);
    if (raw && json_read(&root, raw, strlen(raw)) && dump_ok(&root))
        fold_text(out, cap, raw, cap - 1);
    json_free(&root);
    free(raw);
    return strlen(out);
}

static void io_broadcast(void *ctx, const char *text)
{
    (void)ctx;
    char sink[64];
    const char *argv[] = { "wall", text, NULL };
    zcl_spawn_capture(argv, sink, sizeof(sink), 5000);
}

static const struct slo_page_io k_page_io = {
    .blocker = io_blocker, .broadcast = io_broadcast,
};

const struct slo_page_io *slo_io_page(const struct slo_instance *canonical)
{
    if (canonical)
        g_canonical = *canonical;
    return &k_page_io;
}

static int port_or(const char *text, int fallback)
{
    int64_t p = slo_parse_i64(text, 0);
    return (p >= 1 && p <= 65535) ? (int)p : fallback;
}

static void set_instance(struct slo_instance *at, const char *name, int port,
                         const char *datadir, const char *unit)
{
    memset(at, 0, sizeof(*at));
    snprintf(at->name, sizeof(at->name), "%s", name);
    at->rpcport = port;
    snprintf(at->datadir, sizeof(at->datadir), "%s", datadir);
    snprintf(at->unit, sizeof(at->unit), "%s", unit);
}

static void unit_exec_start(const char *unit, char *out, size_t cap)
{
    const char *argv[] = { "systemctl", "--user", "show", unit, "-p",
                           "ExecStart", NULL };
    out[0] = '\0';
    zcl_spawn_capture(argv, out, cap, (int)host_ms());
}

static void bind_canonical(struct slo_instance *at, const char *home)
{
    char fallback[SLO_PATH_MAX / 2], datadir[SLO_PATH_MAX / 2] = "";
    char port_text[16] = "", show[IO_SHOW_MAX];
    const char *env_dir = getenv("ZCL_SLO_CANON_DATADIR");
    const char *env_port = getenv("ZCL_SLO_CANON_RPCPORT");
    snprintf(fallback, sizeof(fallback), "%s/.zclassic-c23", home);
    if (env_dir && env_dir[0])
        snprintf(datadir, sizeof(datadir), "%s", env_dir);
    if (env_port && env_port[0])
        snprintf(port_text, sizeof(port_text), "%s", env_port);
    if (!datadir[0] || !port_text[0]) {
        unit_exec_start("zclassic23.service", show, sizeof(show));
        if (!datadir[0])
            (void)slo_unit_exec_arg(show, "datadir", datadir, sizeof(datadir));
        if (!port_text[0])
            (void)slo_unit_exec_arg(show, "rpcport", port_text,
                                    sizeof(port_text));
    }
    set_instance(at, "canonical", port_or(port_text, IO_CANON_PORT),
                 datadir[0] ? datadir : fallback, "zclassic23.service");
}

static int oracle_port(const char *datadir, const char *show,
                       const char *port_text)
{
    char conf[SLO_PATH_MAX], conf_arg[SLO_PATH_MAX / 2];
    int port = port_or(port_text, 0);
    if (port)
        return port;
    if (slo_unit_exec_arg(show, "rpcport", conf_arg, sizeof(conf_arg)))
        port = port_or(conf_arg, 0);
    if (port)
        return port;
    if (slo_unit_exec_arg(show, "conf", conf_arg, sizeof(conf_arg)))
        snprintf(conf, sizeof(conf), "%s%s%s",
                 conf_arg[0] == '/' ? "" : datadir,
                 conf_arg[0] == '/' ? "" : "/", conf_arg);
    else
        snprintf(conf, sizeof(conf), "%s/zclassic.conf", datadir);
    port = slo_conf_rpcport(conf);
    return port ? port : IO_ORACLE_PORT;
}

static void bind_oracle(struct slo_instance *at, const char *home)
{
    char datadir[SLO_PATH_MAX / 2] = "", show[IO_SHOW_MAX];
    const char *env_dir = getenv("ZCL_SLO_ORACLE_DATADIR");
    const char *env_port = getenv("ZCL_SLO_ORACLE_RPCPORT");
    if (env_dir && env_dir[0])
        snprintf(datadir, sizeof(datadir), "%s", env_dir);
    show[0] = '\0';
    if (!datadir[0] || !port_or(env_port, 0)) {
        unit_exec_start("zclassicd.service", show, sizeof(show));
        if (!datadir[0])
            (void)slo_unit_exec_arg(show, "datadir", datadir, sizeof(datadir));
    }
    if (!datadir[0])
        snprintf(datadir, sizeof(datadir), "%s/.zclassic", home);
    set_instance(at, "oracle", oracle_port(datadir, show, env_port), datadir,
                 "zclassicd.service");
}

bool slo_io_probe_config(struct slo_probe_config *cfg)
{
    const char *home = getenv("HOME");
    char dev_dir[SLO_PATH_MAX / 2];
    if (!cfg || !home || !home[0])
        return false;
    memset(cfg, 0, sizeof(*cfg));
    cfg->rotate_bytes =
        slo_parse_i64(getenv("ZCL_SLO_ROTATE_BYTES"), 50 * 1024 * 1024);
    cfg->blind_streak = slo_parse_i64(getenv("ZCL_SLO_BLIND_STREAK"), 10);
    bind_canonical(&cfg->inst[0], home);
    snprintf(dev_dir, sizeof(dev_dir), "%s/.zclassic-c23-dev", home);
    set_instance(&cfg->inst[1], "dev", IO_DEV_PORT, dev_dir,
                 "zcl23-dev.service");
    cfg->ninst = 2;
    bind_oracle(&cfg->oracle, home);
    return true;
}

static int64_t now_or_clock(void)
{
    return slo_parse_i64(getenv("ZCL_SLO_NOW"),
                         (int64_t)platform_time_wall_time_t());
}

void slo_io_page_config(struct slo_page_config *cfg)
{
    const char *live = getenv("ZCL_SLO_PAGE_LIVE_INSTANCES");
    const char *wall = getenv("ZCL_SLO_PAGE_WALL");
    memset(cfg, 0, sizeof(*cfg));
    cfg->now = now_or_clock();
    cfg->stale_sec = slo_parse_i64(getenv("ZCL_SLO_PAGE_STALE_SEC"), 300);
    cfg->unreach_sec = slo_parse_i64(getenv("ZCL_SLO_PAGE_UNREACH_SEC"), 600);
    cfg->advance_sec = slo_parse_i64(getenv("ZCL_SLO_PAGE_ADVANCE_SEC"), 7200);
    cfg->adv_min_trailing =
        slo_parse_i64(getenv("ZCL_SLO_PAGE_ADVANCE_MIN_TRAILING"), 2);
    cfg->cov_window_sec =
        slo_parse_i64(getenv("ZCL_SLO_PAGE_COVERAGE_WINDOW_SEC"), 3600);
    cfg->cov_cadence_sec =
        slo_parse_i64(getenv("ZCL_SLO_PAGE_COVERAGE_CADENCE_SEC"), 60);
    cfg->renotify_sec =
        slo_parse_i64(getenv("ZCL_SLO_PAGE_RENOTIFY_SEC"), 21600);
    cfg->cov_min_ratio =
        slo_parse_double(getenv("ZCL_SLO_PAGE_COVERAGE_MIN_RATIO"), 0.5);
    cfg->wall = !(wall && strcmp(wall, "0") == 0);
    snprintf(cfg->live, sizeof(cfg->live), "%s", live ? live : k_live_default);
}

void slo_io_hold_config(struct slo_hold_config *cfg)
{
    const char *inst = getenv("ZCL_SLO_INSTANCE");
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->instance, sizeof(cfg->instance), "%s",
             inst && inst[0] ? inst : "canonical");
    cfg->now = now_or_clock();
    cfg->window_hours = slo_parse_i64(getenv("ZCL_SLO_WINDOW_HOURS"), 72);
    cfg->gap_budget = slo_parse_i64(getenv("ZCL_SLO_GAP_BUDGET"), 3);
    cfg->max_unreach_sec =
        slo_parse_i64(getenv("ZCL_SLO_MAX_UNREACH_SEC"), 600);
    cfg->cadence_sec = slo_parse_i64(getenv("ZCL_SLO_CADENCE_SEC"), 60);
    cfg->max_age_sec = slo_parse_i64(getenv("ZCL_SLO_MAX_AGE_SEC"), 300);
    cfg->bucket_sec = slo_parse_i64(getenv("ZCL_SLO_BUCKET_SEC"), 900);
    cfg->reach_pct_min = slo_parse_double(getenv("ZCL_SLO_REACH_PCT"), 99.5);
    cfg->cov_pct_min = slo_parse_double(getenv("ZCL_SLO_COVERAGE_PCT"), 90);
}

bool slo_io_pages_path(char *out, size_t cap)
{
    const char *over = getenv("ZCL_SLO_PAGES_FILE");
    if (over && over[0]) {
        int n = snprintf(out, cap, "%s", over);
        return n > 0 && (size_t)n < cap;
    }
    return slo_monitor_file("pages.jsonl", out, cap);
}
