/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The run-once trigger evaluator — resolves each source's path,
 * tracks a per-source byte cursor, reads new rows, matches them against
 * the closed registry, and performs the matched action. No daemon, no
 * network: one call reads what is new and returns. */

#include "command/native_fleet_triggers.h"

#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* tools/command is compiled for ZCL_TARGET=windows-x86_64 like every other
 * release translation unit, so <sys/utsname.h> cannot be reached
 * unconditionally. Same split, same reason, as tools/dev/fleet_enrol_facts.c. */
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/utsname.h>
#endif

/* platform_state_root() always returns "<base>/z23/dev" (see
 * platform/modules/platform/src/state_root.c: base is XDG_STATE_HOME or
 * ~/.local/state, then "/z23" then "/dev" are appended and each level is
 * created). Triggers' own state lives beside the interim fleet tools
 * (board.sh, exp.sh) under "<base>/zclassic23", so this strips the fixed
 * "/z23/dev" suffix to recover <base> without a second HOME/XDG read of
 * our own — one resolver, one seam, both trees derived from it. */
#define TRG_STATE_ROOT_SUFFIX "/z23/dev"

static bool trg_base_dir(char *out, size_t cap)
{
    char state[PATH_MAX];
    if (!platform_state_root(state, sizeof state))
        return false;
    size_t len = strlen(state);
    size_t suffix_len = strlen(TRG_STATE_ROOT_SUFFIX);
    if (len <= suffix_len ||
        strcmp(state + len - suffix_len, TRG_STATE_ROOT_SUFFIX) != 0)
        return false;
    size_t base_len = len - suffix_len;
    if (base_len >= cap)
        return false;
    memcpy(out, state, base_len);
    out[base_len] = 0;
    return true;
}

static bool trg_mkdir_p(const char *path)
{
    char copy[PATH_MAX];
    size_t length = path ? strlen(path) : 0;
    if (!length || length >= sizeof copy)
        return false;
    memcpy(copy, path, length + 1u);
    for (char *p = copy + (copy[0] == '/' ? 1 : 0); ; p++) {
        if (*p != '/' && *p != '\0')
            continue;
        char saved = *p;
        *p = '\0';
        if (copy[0] && !platform_directory_ensure(copy, 0700))
            return false;
        *p = saved;
        if (!saved)
            break;
    }
    return true;
}

bool zcl_trigger_landing_path(char *out, size_t cap)
{
    char state[PATH_MAX];
    if (!platform_state_root(state, sizeof state))
        return false;
    return (size_t)snprintf(out, cap, "%s/land/outcomes.jsonl", state) < cap;
}

/* This box's own short host name, the string board.sh puts in the board
 * filename. On POSIX that is uname()'s nodename rather than gethostname(2):
 * the same string from a call this tree already classifies CAP_HARMLESS
 * (see tools/dev/fleet_enrol_facts.c), so it costs no new external symbol.
 * The Windows arm reads the same fact through GetComputerNameA, exactly as
 * fleet_enrol_facts.c does. */
static bool trg_short_hostname(char *out, size_t cap)
{
#if defined(_WIN32)
    char name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD name_len = (DWORD)sizeof(name);
    if (!GetComputerNameA(name, &name_len))
        return false;
    if ((size_t)snprintf(out, cap, "%s", name) >= cap)
        return false;
#else
    struct utsname sys;
    if (uname(&sys) != 0)
        return false;
    if ((size_t)snprintf(out, cap, "%s", sys.nodename) >= cap)
        return false;
#endif
    char *dot = strchr(out, '.');
    if (dot)
        *dot = 0;
    return true;
}

bool zcl_trigger_board_path(char *out, size_t cap)
{
    char base[PATH_MAX];
    char host[256];
    if (!trg_base_dir(base, sizeof base) || !trg_short_hostname(host, sizeof host))
        return false;
    return (size_t)snprintf(out, cap, "%s/zclassic23/board/%s.jsonl", base,
                            host) < cap;
}

bool zcl_trigger_experiment_path(char *out, size_t cap)
{
    char base[PATH_MAX];
    if (!trg_base_dir(base, sizeof base))
        return false;
    return (size_t)snprintf(out, cap, "%s/zclassic23/experiments/rows.tsv",
                            base) < cap;
}

bool zcl_trigger_fired_ledger_path(char *out, size_t cap)
{
    char base[PATH_MAX];
    if (!trg_base_dir(base, sizeof base))
        return false;
    return (size_t)snprintf(out, cap, "%s/zclassic23/triggers/fired.jsonl",
                            base) < cap;
}

bool zcl_trigger_cursor_path(const char *source_name, char *out, size_t cap)
{
    char base[PATH_MAX];
    if (!trg_base_dir(base, sizeof base) || !source_name)
        return false;
    return (size_t)snprintf(out, cap, "%s/zclassic23/triggers/cursors/%s",
                            base, source_name) < cap;
}

/* ── per-source cursor: inode + size (identity/shrink check), byte
 * offset, and rows already counted ─────────────────────────────────── */

struct trg_cursor {
    uint64_t ino;
    uint64_t size;
    uint64_t offset;
    uint64_t row_count;
};

static bool trg_cursor_read(const char *source_name, struct trg_cursor *out)
{
    memset(out, 0, sizeof *out);
    char path[PATH_MAX];
    if (!zcl_trigger_cursor_path(source_name, path, sizeof path))
        return false;
    FILE *f = fopen(path, "rb");
    if (!f)
        return true; /* no cursor yet: starts at zero */
    unsigned long long a = 0, b = 0, c = 0, d = 0;
    int n = fscanf(f, "%llu %llu %llu %llu", &a, &b, &c, &d);
    fclose(f);
    if (n != 4)
        return true; /* malformed cursor: treat as fresh */
    out->ino = a;
    out->size = b;
    out->offset = c;
    out->row_count = d;
    return true;
}

static bool trg_cursor_write(const char *source_name,
                             const struct trg_cursor *c)
{
    char dir_path[PATH_MAX];
    char base[PATH_MAX];
    if (!trg_base_dir(base, sizeof base))
        return false;
    if ((size_t)snprintf(dir_path, sizeof dir_path,
                         "%s/zclassic23/triggers/cursors", base) >=
        sizeof dir_path ||
        !trg_mkdir_p(dir_path))
        return false;
    char path[PATH_MAX];
    if (!zcl_trigger_cursor_path(source_name, path, sizeof path))
        return false;
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fprintf(f, "%llu %llu %llu %llu\n",
                      (unsigned long long)c->ino, (unsigned long long)c->size,
                      (unsigned long long)c->offset,
                      (unsigned long long)c->row_count) > 0;
    fclose(f);
    return ok;
}

/* ── ISO-8601 "YYYY-MM-DDTHH:MM:SSZ" -> unix seconds. No libc TZ path is
 * used, so no environment is read for it (Howard Hinnant's civil-days
 * formula). Returns false on any shape it does not recognize. */
static bool trg_parse_iso8601(const char *s, int64_t *out)
{
    if (!s)
        return false;
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    if (sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2dZ", &y, &mo, &d, &h, &mi, &se) != 6)
        return false;
    int64_t yy = y - (mo <= 2 ? 1 : 0);
    int64_t era = (yy >= 0 ? yy : yy - 399) / 400;
    int64_t yoe = yy - era * 400;
    int64_t doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days = era * 146097 + doe - 719468;
    *out = days * 86400 + h * 3600 + mi * 60 + se;
    return true;
}

/* ── one row, either JSON-backed (landing_outcomes, board_rows) or
 * TSV-backed (experiment_rows) ──────────────────────────────────────── */

enum { TRG_TSV_MAX_COLS = 32, TRG_LINE_MAX = 8192 };

struct trg_row {
    bool is_json;
    struct json_value json;
    char tsv_copy[TRG_LINE_MAX];
    char *tsv_field[TRG_TSV_MAX_COLS];
    size_t tsv_count;
};

static void trg_row_free(struct trg_row *row)
{
    if (row->is_json)
        json_free(&row->json);
}

static bool trg_row_from_json_line(const char *line, size_t len,
                                   struct trg_row *row)
{
    memset(row, 0, sizeof *row);
    row->is_json = true;
    return json_read(&row->json, line, len) && row->json.type == JSON_OBJ;
}

static void trg_row_from_tsv_line(const char *line, size_t len,
                                  struct trg_row *row)
{
    memset(row, 0, sizeof *row);
    row->is_json = false;
    if (len >= sizeof row->tsv_copy)
        len = sizeof row->tsv_copy - 1;
    memcpy(row->tsv_copy, line, len);
    row->tsv_copy[len] = 0;
    char *p = row->tsv_copy;
    row->tsv_field[row->tsv_count++] = p;
    while (*p && row->tsv_count < TRG_TSV_MAX_COLS) {
        if (*p == '\t') {
            *p = 0;
            row->tsv_field[row->tsv_count++] = p + 1;
        }
        p++;
    }
}

/* field_ lookup against one row. Returns NULL for a field the row does not
 * carry (JSON key absent or not a string; TSV column name unknown to the
 * header this source opened with) — an absent field never matches any op,
 * "ne" included. */
static const char *trg_row_field(const struct trg_row *row,
                                 const char *const *header,
                                 size_t header_count, const char *field)
{
    if (row->is_json) {
        const struct json_value *v = json_get(&row->json, field);
        if (!v || v->type != JSON_STR)
            return NULL;
        return json_get_str(v);
    }
    for (size_t i = 0; i < header_count; i++) {
        if (strcmp(header[i], field) == 0)
            return i < row->tsv_count ? row->tsv_field[i] : NULL;
    }
    return NULL;
}

static const char *trg_row_ts(const struct trg_row *row,
                              const char *const *header, size_t header_count)
{
    return trg_row_field(row, header, header_count, "ts");
}

static bool trg_op_matches(enum zcl_trigger_op op, const char *actual,
                           const char *value)
{
    switch (op) {
    case ZCL_TRIGGER_OP_EQ:
        return strcmp(actual, value) == 0;
    case ZCL_TRIGGER_OP_NE:
        return strcmp(actual, value) != 0;
    case ZCL_TRIGGER_OP_PREFIX:
        return strncmp(actual, value, strlen(value)) == 0;
    case ZCL_TRIGGER_OP_CONTAINS:
        return strstr(actual, value) != NULL;
    }
    return false;
}

/* ── actions ──────────────────────────────────────────────────────────
 * print: one summary line on stdout. ledger: one appended JSON row under
 * <state>/zclassic23/triggers/fired.jsonl. */

static void trg_action_print(const struct zcl_trigger_row *trig,
                             const char *actual)
{
    printf("TRIGGER %s %s %s=%s\n", trig->id, trig->source_name, trig->field,
          actual);
}

static bool trg_action_ledger(const struct zcl_trigger_row *trig,
                              const char *actual, uint64_t seq)
{
    char path[PATH_MAX], dir[PATH_MAX], base[PATH_MAX];
    if (!trg_base_dir(base, sizeof base))
        return false;
    if ((size_t)snprintf(dir, sizeof dir, "%s/zclassic23/triggers", base) >=
            sizeof dir ||
        !trg_mkdir_p(dir) || !zcl_trigger_fired_ledger_path(path, sizeof path))
        return false;

    time_t now = platform_time_wall_time_t();
    struct tm tm_utc;
    char ts[32] = "";
    if (platform_time_utc_tm(now, &tm_utc))
        (void)strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

    char summary[512];
    (void)snprintf(summary, sizeof summary, "%s=%s", trig->field, actual);

    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "ts", ts);
    (void)json_push_kv_str(&row, "id", trig->id);
    (void)json_push_kv_str(&row, "source", trig->source_name);
    (void)json_push_kv_int(&row, "seq", (int64_t)seq);
    (void)json_push_kv_str(&row, "summary", summary);

    char line[1024];
    size_t n = json_write(&row, line, sizeof line);
    json_free(&row);
    if (n == 0 || n >= sizeof line)
        return false;

    FILE *f = fopen(path, "ab");
    if (!f)
        return false;
    bool ok = fprintf(f, "%s\n", line) > 0;
    fclose(f);
    return ok;
}

/* ── driving one source through the registry ─────────────────────────── */

struct trg_source_spec {
    enum zcl_trigger_source source;
    const char *name;
    bool has_header;
    bool (*path_fn)(char *out, size_t cap);
};

static const struct trg_source_spec k_source_specs[] = {
    { ZCL_TRIGGER_SOURCE_LANDING, "landing_outcomes", false,
     zcl_trigger_landing_path },
    { ZCL_TRIGGER_SOURCE_BOARD, "board_rows", false, zcl_trigger_board_path },
    { ZCL_TRIGGER_SOURCE_EXPERIMENT, "experiment_rows", true,
     zcl_trigger_experiment_path },
};

/* Read the header line of a TSV source (column names by index); a JSONL
 * source has none. header_storage is the caller's scratch buffer that
 * header[] points into. */
static void trg_read_header(FILE *f, bool has_header, char *header_storage,
                            size_t header_storage_cap, char **header,
                            size_t *header_count, long *header_bytes)
{
    *header_count = 0;
    *header_bytes = 0;
    if (!has_header)
        return;
    if (!fgets(header_storage, (int)header_storage_cap, f))
        return;
    *header_bytes = (long)strlen(header_storage);
    size_t len = strlen(header_storage);
    if (len && header_storage[len - 1] == '\n')
        header_storage[--len] = 0;
    char *p = header_storage;
    header[(*header_count)++] = p;
    while (*p && *header_count < TRG_TSV_MAX_COLS) {
        if (*p == '\t') {
            *p = 0;
            header[(*header_count)++] = p + 1;
        }
        p++;
    }
}

/* One matched-or-not verdict for a single trigger against a single row. */
static bool trg_fire_if_matched(const struct zcl_trigger_row *trig,
                                const struct trg_row *row,
                                const char *const *header,
                                size_t header_count, bool dry_run,
                                uint64_t seq, struct json_value *fired_ids)
{
    (void)dry_run;
    const char *actual = trg_row_field(row, header, header_count, trig->field);
    if (!actual || !trg_op_matches(trig->op, actual, trig->value))
        return false;
    if (trig->action == ZCL_TRIGGER_ACTION_PRINT) {
        trg_action_print(trig, actual);
    } else {
        (void)trg_action_ledger(trig, actual, seq);
    }
    if (fired_ids) {
        struct json_value idv;
        json_init(&idv);
        json_set_str(&idv, trig->id);
        (void)json_push_back(fired_ids, &idv);
        json_free(&idv);
    }
    return true;
}

/* Everything the per-line scan needs held together, so passing it around
 * stays one parameter instead of a growing argument list. */
struct trg_scan_ctx {
    const struct trg_source_spec *spec;
    const char *const *header;
    size_t header_count;
    bool dry_run;
    int64_t cutoff; /* 0 means "no since filter" */
    struct json_value *fired_ids;
};

static bool trg_row_too_old(const struct trg_scan_ctx *ctx,
                            const struct trg_row *row)
{
    if (ctx->cutoff == 0)
        return false;
    int64_t ts = 0;
    const char *raw = trg_row_ts(row, ctx->header, ctx->header_count);
    return trg_parse_iso8601(raw, &ts) && ts < ctx->cutoff;
}

/* Evaluate every registered trigger for this source against one row,
 * performing whichever actions match. Returns how many fired. */
static uint64_t trg_evaluate_row(const struct trg_scan_ctx *ctx,
                                 const struct trg_row *row, uint64_t seq)
{
    uint64_t fired_count = 0;
    for (size_t i = 0; i < zcl_trigger_count(); i++) {
        const struct zcl_trigger_row *trig = zcl_trigger_at(i);
        if (trig && trig->source == ctx->spec->source &&
            trg_fire_if_matched(trig, row, ctx->header, ctx->header_count,
                               ctx->dry_run, seq, ctx->fired_ids))
            fired_count++;
    }
    return fired_count;
}

/* Parse one complete (newline-stripped) line into a row and score it
 * against the registry. *checked counts every row this source's format
 * could parse, whether or not any trigger fired. */
static void trg_process_line(const struct trg_scan_ctx *ctx, char *line,
                             size_t len, uint64_t *row_count,
                             uint64_t *checked, uint64_t *fired)
{
    if (len == 0)
        return;
    struct trg_row row;
    bool have_row;
    if (ctx->spec->has_header) {
        trg_row_from_tsv_line(line, len, &row);
        have_row = true;
    } else {
        have_row = trg_row_from_json_line(line, len, &row);
    }
    if (!have_row)
        return;
    (*row_count)++;
    (*checked)++;
    if (!trg_row_too_old(ctx, &row))
        *fired += trg_evaluate_row(ctx, &row, *row_count);
    trg_row_free(&row);
}

/* Cursor identity/shrink check: a replaced or truncated file restarts at
 * byte zero rather than trusting a stale offset into different content. */
static void trg_cursor_rebase(struct trg_cursor *cursor, const struct stat *st)
{
    if ((uint64_t)st->st_ino != cursor->ino ||
        (uint64_t)st->st_size < cursor->size) {
        cursor->ino = (uint64_t)st->st_ino;
        cursor->offset = 0;
        cursor->row_count = 0;
    }
}

static void trg_process_source(const struct trg_source_spec *spec,
                               bool dry_run, int64_t since_s,
                               uint64_t *checked, uint64_t *fired,
                               struct json_value *fired_ids)
{
    char path[PATH_MAX];
    struct stat st;
    if (!spec->path_fn(path, sizeof path) || stat(path, &st) != 0)
        return; /* absent source contributes nothing; not an error */

    struct trg_cursor cursor;
    (void)trg_cursor_read(spec->name, &cursor);
    trg_cursor_rebase(&cursor, &st);

    FILE *f = fopen(path, "rb");
    if (!f)
        return;

    char header_storage[TRG_LINE_MAX];
    char *header[TRG_TSV_MAX_COLS];
    size_t header_count = 0;
    long header_bytes = 0;
    trg_read_header(f, spec->has_header, header_storage,
                    sizeof header_storage, header, &header_count,
                    &header_bytes);

    uint64_t start_offset = cursor.offset;
    if ((long)start_offset < header_bytes)
        start_offset = (uint64_t)header_bytes;
    if (fseek(f, (long)start_offset, SEEK_SET) != 0) {
        fclose(f);
        return;
    }

    struct trg_scan_ctx ctx = {
        .spec = spec,
        .header = (const char *const *)header,
        .header_count = header_count,
        .dry_run = dry_run,
        .cutoff = since_s > 0 ? (int64_t)platform_time_wall_unix() - since_s
                              : 0,
        .fired_ids = fired_ids,
    };
    uint64_t new_offset = start_offset;
    uint64_t new_row_count = cursor.row_count;
    char line[TRG_LINE_MAX];
    while (fgets(line, sizeof line, f)) {
        size_t len = strlen(line);
        if (len == 0 || line[len - 1] != '\n')
            break; /* partial trailing line: leave it for next time */
        new_offset += (uint64_t)len;
        line[--len] = 0; /* drop the newline for parsing */
        trg_process_line(&ctx, line, len, &new_row_count, checked, fired);
    }
    fclose(f);

    if (!dry_run) {
        cursor.size = (uint64_t)st.st_size;
        cursor.offset = new_offset;
        cursor.row_count = new_row_count;
        (void)trg_cursor_write(spec->name, &cursor);
    }
}

bool zcl_trigger_check_run(bool dry_run, int64_t since_s, uint64_t *out_checked,
                          uint64_t *out_fired, struct json_value *out_fired_ids,
                          char *out_why, size_t out_why_cap)
{
    if (!out_checked || !out_fired) {
        if (out_why)
            (void)snprintf(out_why, out_why_cap, "internal: no counters");
        return false;
    }
    *out_checked = 0;
    *out_fired = 0;
    for (size_t i = 0; i < sizeof k_source_specs / sizeof k_source_specs[0];
        i++)
        trg_process_source(&k_source_specs[i], dry_run, since_s, out_checked,
                          out_fired, out_fired_ids);
    return true;
}
