/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * External uptime prober. One cycle asks every instance and the legacy
 * oracle for its chain heights through injected observers and appends one
 * ledger row per instance. An unreachable node is recorded as data; the
 * cycle fails only when the ledger itself cannot be written. */
// one-result-type-ok:typed-report-struct — each entry point fills a report struct that names the failing condition; the bool only says whether the ledger I/O completed.

#include "services/slo_monitor.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct cycle {
    int64_t ts;
    struct slo_chain_answer oracle;
    struct slo_chain_answer ans[SLO_INSTANCE_MAX];
    struct slo_opt peers[SLO_INSTANCE_MAX];
    struct slo_opt max_height;
};

struct slo_row {
    int64_t ts;
    const struct slo_instance *at;
    bool reachable;
    int64_t streak;
    const struct slo_chain_answer *ans;
    struct slo_opt oracle;
    struct slo_opt max_height;
    struct slo_opt gap_max;
    struct slo_opt gap_oracle;
    struct slo_opt peers;
    const struct slo_host_facts *host;
    const struct slo_self_report *self; /* NULL when the node did not answer */
};

static void json_bool_opt(struct slo_text *t, struct slo_opt v)
{
    if (v.has)
        slo_text_addf(t, "%s", v.v ? "true" : "false");
    else
        slo_text_addf(t, "null");
}

static void format_self(struct slo_text *t, const struct slo_self_report *s)
{
    static const struct slo_self_report none;
    const struct slo_self_report *r = s ? s : &none;
    slo_text_addf(t, ",\"onion_enabled\":");
    json_bool_opt(t, r->onion_enabled);
    slo_text_addf(t, ",\"onion_address\":");
    slo_json_escape(t, r->onion_address);
    slo_text_addf(t, ",\"blocker_count\":");
    slo_json_opt(t, r->blocker_count);
    slo_text_addf(t, ",\"blocker_primary\":");
    slo_json_escape(t, r->blocker_primary);
    slo_text_addf(t, ",\"node_state_ok\":");
    if (s)
        slo_text_addf(t, "%s", s->state_ok ? "true" : "false");
    else
        slo_text_addf(t, "null");
}

static void format_head(struct slo_text *t, const struct slo_row *r)
{
    slo_text_addf(t, "{\"ts\":%lld,\"instance\":", (long long)r->ts);
    slo_json_escape(t, r->at->name);
    slo_text_addf(t, ",\"rpcport\":%d,\"datadir\":", r->at->rpcport);
    slo_json_escape(t, r->at->datadir);
    slo_text_addf(t, ",\"reachable\":%s,\"unreachable_streak\":%lld",
                  r->reachable ? "true" : "false", (long long)r->streak);
    slo_text_addf(t, ",\"served_height\":");
    slo_json_opt(t, r->ans->served);
    slo_text_addf(t, ",\"header_height\":");
    slo_json_opt(t, r->ans->header);
    slo_text_addf(t, ",\"latency_ms\":%lld", (long long)r->ans->latency_ms);
}

static void format_gaps(struct slo_text *t, const struct slo_row *r)
{
    slo_text_addf(t, ",\"oracle_height\":");
    slo_json_opt(t, r->oracle);
    slo_text_addf(t, ",\"max_height\":");
    slo_json_opt(t, r->max_height);
    slo_text_addf(t, ",\"gap_vs_max\":");
    slo_json_opt(t, r->gap_max);
    slo_text_addf(t, ",\"gap_vs_oracle\":");
    slo_json_opt(t, r->gap_oracle);
}

static void format_host(struct slo_text *t, const struct slo_row *r)
{
    slo_text_addf(t, ",\"peer_count\":");
    slo_json_opt(t, r->peers);
    slo_text_addf(t, ",\"rss_kb\":");
    slo_json_opt(t, r->host->rss_kb);
    slo_text_addf(t, ",\"datadir_bytes\":");
    slo_json_opt(t, r->host->datadir_bytes);
    slo_text_addf(t, ",\"nrestarts\":");
    slo_json_opt(t, r->host->nrestarts);
    slo_text_addf(t, ",\"active_enter_ts\":");
    slo_json_opt(t, r->host->active_enter_ts);
    slo_text_addf(t, ",\"unit_active_state\":");
    slo_json_escape(t, r->host->active_state);
}

static bool format_row(const struct slo_row *r, char *buf, size_t cap)
{
    struct slo_text t;
    slo_text_init(&t, buf, cap);
    format_head(&t, r);
    format_gaps(&t, r);
    format_host(&t, r);
    format_self(&t, r->self);
    slo_text_addf(&t, ",\"error_detail\":");
    slo_json_escape(&t, r->reachable ? "" : r->ans->detail);
    slo_text_addf(&t, "}");
    return !t.overflow;
}

static int64_t streak_next(const char *name, bool reachable)
{
    char path[SLO_PATH_MAX], text[32] = "";
    if (!reachable && slo_monitor_state_file("streak", name, false, path,
                                             sizeof(path)))
        (void)slo_monitor_read_line(path, text, sizeof(text));
    int64_t n = reachable ? 0 : slo_parse_i64(text, 0) + 1;
    if (n < 0)
        n = 0;
    if (slo_monitor_state_file("streak", name, true, path, sizeof(path))) {
        snprintf(text, sizeof(text), "%lld\n", (long long)n);
        (void)slo_monitor_write_atomic(path, text);
    }
    return n;
}

static void rotate_if_needed(struct slo_probe_result *out, int64_t limit)
{
    struct stat st;
    if (stat(out->ledger, &st) != 0 || (int64_t)st.st_size < limit)
        return;
    char older[SLO_PATH_MAX + 4], oldest[SLO_PATH_MAX + 4];
    snprintf(older, sizeof(older), "%s.1", out->ledger);
    snprintf(oldest, sizeof(oldest), "%s.2", out->ledger);
    (void)unlink(oldest);
    (void)rename(older, oldest);
    if (rename(out->ledger, older) == 0)
        SLO_NOTE(out, "rotated ledger (size=%lld bytes >= %lld)",
                 (long long)st.st_size, (long long)limit);
}

static void run_probes(const struct slo_probe_config *cfg,
                       const struct slo_probe_io *io, struct cycle *cy)
{
    memset(cy, 0, sizeof(*cy));
    cy->ts = io->now(io->ctx);
    io->chain(io->ctx, &cfg->oracle, true, &cy->oracle);
    cy->max_height = cy->oracle.served;
    for (size_t i = 0; i < cfg->ninst; i++) {
        io->chain(io->ctx, &cfg->inst[i], false, &cy->ans[i]);
        const struct slo_opt s = cy->ans[i].served;
        if (!s.has)
            continue;
        cy->peers[i] = io->peers(io->ctx, &cfg->inst[i]);
        if (!cy->max_height.has || s.v > cy->max_height.v)
            cy->max_height = s;
    }
}

static void note_unreachable(const struct slo_probe_config *cfg,
                             const struct slo_row *r,
                             struct slo_probe_result *out)
{
    const char *detail = r->ans->detail[0] ? r->ans->detail : "none";
    if (r->streak >= cfg->blind_streak)
        SLO_NOTE(out,
                 "BLIND instance=%s unreachable for %lld consecutive polls "
                 "(threshold %lld); fix the node or remove its row from the "
                 "instance table detail=%s",
                 r->at->name, (long long)r->streak,
                 (long long)cfg->blind_streak, detail);
    else
        SLO_NOTE(out, "WARN instance=%s unreachable streak=%lld detail=%s",
                 r->at->name, (long long)r->streak, detail);
}

static void fill_gaps(struct slo_row *r, const struct cycle *cy)
{
    r->oracle = cy->oracle.served;
    r->max_height = cy->max_height;
    if (r->ans->served.has && cy->max_height.has)
        r->gap_max = (struct slo_opt){ true,
                                       cy->max_height.v - r->ans->served.v };
    if (r->ans->served.has && cy->oracle.served.has)
        r->gap_oracle = (struct slo_opt){ true, cy->oracle.served.v -
                                                    r->ans->served.v };
}

static bool emit_one(const struct slo_probe_config *cfg,
                     const struct slo_probe_io *io, const struct cycle *cy,
                     size_t i, struct slo_probe_result *out)
{
    struct slo_host_facts host;
    struct slo_self_report self;
    memset(&host, 0, sizeof(host));
    memset(&self, 0, sizeof(self));
    struct slo_row row = { .ts = cy->ts, .at = &cfg->inst[i],
                           .ans = &cy->ans[i], .peers = cy->peers[i],
                           .reachable = cy->ans[i].served.has,
                           .host = &host };
    row.streak = streak_next(row.at->name, row.reachable);
    fill_gaps(&row, cy);
    io->host(io->ctx, row.at, &host);
    if (row.reachable) {
        io->self(io->ctx, row.at, &self);
        row.self = &self;
    }
    char line[SLO_LINE_MAX];
    if (!format_row(&row, line, sizeof(line)) ||
        !slo_monitor_append(out->ledger, line))
        return false;
    out->samples++;
    if (!row.reachable) {
        out->any_unreachable = true;
        out->any_blind = out->any_blind || row.streak >= cfg->blind_streak;
        note_unreachable(cfg, &row, out);
    }
    return true;
}

static bool probe_ready(const struct slo_probe_config *cfg,
                        const struct slo_probe_io *io)
{
    return cfg && io && io->now && io->chain && io->peers && io->host &&
           io->self && cfg->ninst > 0 && cfg->ninst <= SLO_INSTANCE_MAX;
}

bool slo_probe_collect(const struct slo_probe_config *cfg,
                       const struct slo_probe_io *io,
                       struct slo_probe_result *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    char dir[SLO_PATH_MAX];
    if (!probe_ready(cfg, io) || !slo_monitor_dir(dir, sizeof(dir)) ||
        !slo_monitor_mkdir_p(dir) ||
        !slo_monitor_file("uptime-ledger.jsonl", out->ledger,
                          sizeof(out->ledger)))
        return false;
    rotate_if_needed(out, cfg->rotate_bytes);
    struct cycle cy;
    run_probes(cfg, io, &cy);
    out->oracle_height = cy.oracle.served;
    out->max_height = cy.max_height;
    bool ok = true;
    for (size_t i = 0; i < cfg->ninst; i++)
        ok = emit_one(cfg, io, &cy, i, out) && ok;
    return ok;
}

static const char *last_argv_segment(const char *line, const char *eol)
{
    const char *seg = NULL;
    for (const char *p = strstr(line, "argv[]="); p && p < eol;
         p = strstr(p + 1, "argv[]="))
        seg = p + strlen("argv[]=");
    return seg;
}

static bool exec_key_valid(const char *key)
{
    if (!key || !key[0])
        return false;
    for (const char *p = key; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != '_' && *p != '-')
            return false; /* raw-return-ok:pure character-class predicate */
    return true;
}

/* Count the `-key=value` tokens of [seg, end); the value of the last one
 * lands in `out`. False when a value does not fit. */
static bool scan_exec_tokens(const char *seg, const char *end,
                             const char *prefix, char *out, size_t cap,
                             size_t *found)
{
    size_t plen = strlen(prefix);
    *found = 0;
    for (const char *p = seg; p < end;) {
        const char *sp = memchr(p, ' ', (size_t)(end - p));
        const char *tok_end = sp ? sp : end;
        if ((size_t)(tok_end - p) > plen && strncmp(p, prefix, plen) == 0) {
            size_t n = (size_t)(tok_end - p) - plen;
            if (n >= cap)
                return false;
            memcpy(out, p + plen, n);
            out[n] = '\0';
            (*found)++;
        }
        p = sp ? sp + 1 : end;
    }
    return true;
}

bool slo_unit_exec_arg(const char *show, const char *key, char *out,
                       size_t cap)
{
    if (!show || !out || cap == 0 || !exec_key_valid(key))
        return false;
    out[0] = '\0';
    const char *line = strstr(show, "ExecStart=");
    if (!line || (line != show && line[-1] != '\n'))
        return false;
    const char *eol = strchr(line, '\n');
    const char *seg = last_argv_segment(line, eol ? eol : line + strlen(line));
    const char *end = seg ? strchr(seg, ';') : NULL;
    char prefix[48];
    size_t found = 0;
    snprintf(prefix, sizeof(prefix), "-%s=", key);
    if (!end || !scan_exec_tokens(seg, end, prefix, out, cap, &found) ||
        found != 1) {
        out[0] = '\0';
        return false;
    }
    return true;
}

static const char *skip_blanks(const char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;
    return s;
}

static int conf_line_port(const char *line)
{
    line = skip_blanks(line);
    if (strncmp(line, "rpcport", 7) != 0)
        return 0;
    line = skip_blanks(line + 7);
    if (*line++ != '=')
        return 0;
    line = skip_blanks(line);
    char *end = NULL;
    long v = strtol(line, &end, 10);
    if (end == line)
        return 0;
    end = (char *)skip_blanks(end);
    while (*end == '\r' || *end == '\n')
        end++;
    return (*end == '\0' && v >= 1 && v <= 65535) ? (int)v : 0;
}

int slo_conf_rpcport(const char *conf_path)
{
    FILE *f = conf_path ? fopen(conf_path, "r") : NULL;
    if (!f)
        return 0;
    char line[256];
    int port = 0;
    while (fgets(line, sizeof(line), f)) {
        int p = conf_line_port(line);
        if (p)
            port = p;
        while (!strchr(line, '\n') && fgets(line, sizeof(line), f)) {
        }
    }
    fclose(f);
    return port;
}
