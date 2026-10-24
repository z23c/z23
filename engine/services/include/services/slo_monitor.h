/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Node SLO monitors: the external uptime prober, the stall pager and the
 * trailing-window hold judge. All three share one ledger directory
 * (ZCL_SLO_LEDGER_DIR, default ~/.local/state/zclassic23-slo) and keep the
 * on-disk JSONL formats of the shell instruments they replace, so recorded
 * history stays readable. The services are pure over injected observers:
 * network, systemd, procfs and wall(1) access live in the command layer. */

#ifndef ZCL_SERVICES_SLO_MONITOR_H
#define ZCL_SERVICES_SLO_MONITOR_H

#include "base/format_attribute.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SLO_PATH_MAX 1024u
#define SLO_NAME_MAX 32u
#define SLO_INSTANCE_MAX 4u
#define SLO_NOTE_MAX 6u
#define SLO_NOTE_LEN 288u
#define SLO_LINE_MAX 2048u

struct slo_opt {
    bool has;
    int64_t v;
};

/* Bounded printf sink; `overflow` latches when output would not fit. */
struct slo_text {
    char *buf;
    size_t cap;
    size_t len;
    bool overflow;
};

void slo_text_init(struct slo_text *t, char *buf, size_t cap);
void slo_text_addf(struct slo_text *t, const char *fmt, ...)
    ZCL_PRINTF_LIKE(2, 3);

/* Ledger rows sort by timestamp, then by position in the file. */
struct slo_stamp {
    int64_t ts;
    size_t seq;
};

/* qsort comparator for arrays whose elements begin with a struct slo_stamp. */
int slo_stamp_cmp(const void *a, const void *b);

/* Append one formatted note to a fixed-width note array while it has room. */
void slo_note_addf(char (*notes)[SLO_NOTE_LEN], size_t *count,
                   const char *fmt, ...) ZCL_PRINTF_LIKE(3, 4);

/* Note on a result that carries notes[] and nnotes. */
#define SLO_NOTE(result, ...) \
    slo_note_addf((result)->notes, &(result)->nnotes, __VA_ARGS__)

/* ---- shared plumbing (slo_monitor.c) ---- */

bool slo_monitor_dir(char *out, size_t cap);
bool slo_monitor_file(const char *name, char *out, size_t cap);
bool slo_monitor_mkdir_p(const char *dir);
/* <ledger dir>/<subdir>/<name>; the subdirectory is created when `make`. */
bool slo_monitor_state_file(const char *subdir, const char *name, bool make,
                            char *out, size_t cap);
/* First line of a small file without its newline; false when absent. */
bool slo_monitor_read_line(const char *path, char *out, size_t cap);
/* Append one line under an advisory lock, waiting at most 30 seconds. */
bool slo_monitor_append(const char *path, const char *line);
/* Replace a small state file through a same-directory rename. */
bool slo_monitor_write_atomic(const char *path, const char *text);
/* Strict whole-string parse; empty or malformed text yields the fallback. */
int64_t slo_parse_i64(const char *text, int64_t fallback);
double slo_parse_double(const char *text, double fallback);
void slo_json_escape(struct slo_text *out, const char *in);
void slo_json_opt(struct slo_text *out, struct slo_opt value);

/* ---- prober (slo_probe.c) ---- */

struct slo_instance {
    char name[SLO_NAME_MAX];
    int rpcport;
    char datadir[SLO_PATH_MAX / 2];
    char unit[64];
};

struct slo_chain_answer {
    struct slo_opt served;
    struct slo_opt header;
    int64_t latency_ms;
    char detail[208];
};

struct slo_host_facts {
    struct slo_opt nrestarts;
    struct slo_opt active_enter_ts;
    struct slo_opt rss_kb;
    struct slo_opt datadir_bytes;
    char active_state[32];
};

struct slo_self_report {
    struct slo_opt onion_enabled; /* v is 0 or 1 */
    struct slo_opt blocker_count;
    char onion_address[96];
    char blocker_primary[64];
    bool state_ok;
};

/* Observers behind the prober. `oracle` selects the legacy node's
 * credentials; the chain call must fill `detail` when nothing answered. */
struct slo_probe_io {
    void *ctx;
    int64_t (*now)(void *ctx);
    void (*chain)(void *ctx, const struct slo_instance *at, bool oracle,
                  struct slo_chain_answer *out);
    struct slo_opt (*peers)(void *ctx, const struct slo_instance *at);
    void (*host)(void *ctx, const struct slo_instance *at,
                 struct slo_host_facts *out);
    void (*self)(void *ctx, const struct slo_instance *at,
                 struct slo_self_report *out);
};

struct slo_probe_config {
    int64_t rotate_bytes;
    int64_t blind_streak;
    struct slo_instance oracle;
    struct slo_instance inst[SLO_INSTANCE_MAX];
    size_t ninst;
};

struct slo_probe_result {
    size_t samples;
    struct slo_opt oracle_height;
    struct slo_opt max_height;
    bool any_unreachable;
    bool any_blind;
    char ledger[SLO_PATH_MAX];
    char notes[SLO_NOTE_MAX][SLO_NOTE_LEN];
    size_t nnotes;
};

/* One probe-and-append cycle. False only when the ledger could not be
 * written; an unreachable node is data, never a failure. */
bool slo_probe_collect(const struct slo_probe_config *cfg,
                       const struct slo_probe_io *io,
                       struct slo_probe_result *out);

/* Value of the single `-key=value` token inside the argv[] segment of a
 * systemd ExecStart property; false when absent or duplicated. */
bool slo_unit_exec_arg(const char *show, const char *key, char *out,
                       size_t cap);

/* Last exact `rpcport = N` assignment of a config file, or 0. */
int slo_conf_rpcport(const char *conf_path);

/* ---- pager (slo_page.c) ---- */

#define SLO_PAGE_COND_MAX 4u

struct slo_page_config {
    int64_t now;
    int64_t stale_sec;
    int64_t unreach_sec;
    int64_t advance_sec;
    int64_t adv_min_trailing;
    int64_t cov_window_sec;
    int64_t cov_cadence_sec;
    int64_t renotify_sec;
    double cov_min_ratio;
    char live[96]; /* comma separated; empty ages every instance seen */
    bool wall;
};

struct slo_page_cond {
    char id[24];
    char detail[448];
    struct slo_opt served;
    struct slo_opt oracle;
    struct slo_opt gap;
};

struct slo_page_eval {
    struct slo_page_cond cond[SLO_PAGE_COND_MAX];
    size_t ncond;
    char summary[256];
};

struct slo_page_io {
    void *ctx;
    size_t (*blocker)(void *ctx, char *out, size_t cap);
    void (*broadcast)(void *ctx, const char *text);
};

struct slo_page_outcome {
    size_t announced;
    size_t deduped;
    char notes[SLO_NOTE_MAX][SLO_NOTE_LEN];
    size_t nnotes;
};

bool slo_page_evaluate(const char *ledger_path,
                       const struct slo_page_config *cfg,
                       struct slo_page_eval *out);
bool slo_page_announce(const struct slo_page_config *cfg,
                       const struct slo_page_io *io,
                       const struct slo_page_eval *eval,
                       struct slo_page_outcome *out);

/* ---- hold judge (slo_hold.c) ---- */

#define SLO_HOLD_LINES 10u
#define SLO_HOLD_LINE_LEN 400u

struct slo_hold_config {
    char instance[SLO_NAME_MAX];
    int64_t now;
    int64_t window_hours;
    int64_t gap_budget;
    int64_t max_unreach_sec;
    int64_t cadence_sec;
    int64_t max_age_sec;
    int64_t bucket_sec;
    double reach_pct_min;
    double cov_pct_min;
};

struct slo_hold_report {
    bool proven;
    int rc; /* 0 proven, 1 violated, 3 no samples, 4 no ledger */
    char verdict[16];
    char reason[24];
    char lines[SLO_HOLD_LINES][SLO_HOLD_LINE_LEN];
    size_t nlines;
};

bool slo_hold_instance_known(const char *name);
bool slo_hold_judge(const char *ledger_path, const char *pages_path,
                    const struct slo_hold_config *cfg,
                    struct slo_hold_report *out);
/* Append the verdict as one hold-ledger.jsonl line. */
bool slo_hold_record(const struct slo_hold_config *cfg,
                     const struct slo_hold_report *report);

#endif /* ZCL_SERVICES_SLO_MONITOR_H */
