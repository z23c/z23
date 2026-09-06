/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.index per-format line parsing. See native_dev_index_parse.h.
 */

#include "command/native_dev_index_parse.h"

#include "json/json.h"

#include <stdio.h>
#include <string.h>

static void dev_index_copy(char *dst, size_t cap, const char *src)
{
    if (!src) {
        dst[0] = '\0';
        return;
    }
    (void)snprintf(dst, cap, "%s", src);
}

static void dev_index_kv_add(struct dev_index_fields *f, const char *key,
                             const char *value)
{
    if (!value || !value[0])
        return;
    size_t used = strlen(f->kv);
    if (used + 2 >= sizeof(f->kv))
        return;
    (void)snprintf(f->kv + used, sizeof(f->kv) - used, "%s%s:%s",
                  used ? " " : "", key, value);
}

/* Flattens every top-level string field of a parsed JSON object into
 * key:value kv terms — used by both jsonl kinds (board_rows,
 * landing_outcomes), whose schemas differ only in which named fields also
 * become ts/kind/a/b/c. */
static void dev_index_flatten_json_strings(const struct json_value *v,
                                           struct dev_index_fields *f)
{
    for (size_t i = 0; i < v->num_children; i++) {
        if (v->children[i].type != JSON_STR)
            continue;
        dev_index_kv_add(f, v->keys[i], json_get_str(&v->children[i]));
    }
}

static bool dev_index_parse_board(const char *line,
                                  struct dev_index_fields *f)
{
    struct json_value v;
    json_init(&v);
    if (!json_read(&v, line, strlen(line)) || v.type != JSON_OBJ) {
        json_free(&v);
        return false;
    }
    dev_index_copy(f->ts, sizeof(f->ts), json_get_str(json_get(&v, "ts")));
    dev_index_copy(f->kind, sizeof(f->kind),
                  json_get_str(json_get(&v, "kind")));
    dev_index_copy(f->a, sizeof(f->a), json_get_str(json_get(&v, "host")));
    dev_index_copy(f->b, sizeof(f->b), json_get_str(json_get(&v, "agent")));
    dev_index_copy(f->c, sizeof(f->c), json_get_str(json_get(&v, "ref")));
    dev_index_flatten_json_strings(&v, f);
    json_free(&v);
    return true;
}

static bool dev_index_parse_landing(const char *line,
                                    struct dev_index_fields *f)
{
    struct json_value v;
    json_init(&v);
    if (!json_read(&v, line, strlen(line)) || v.type != JSON_OBJ) {
        json_free(&v);
        return false;
    }
    dev_index_copy(f->ts, sizeof(f->ts), json_get_str(json_get(&v, "ts")));
    dev_index_copy(f->kind, sizeof(f->kind),
                  json_get_str(json_get(&v, "state")));
    dev_index_copy(f->a, sizeof(f->a),
                  json_get_str(json_get(&v, "worktree")));
    dev_index_copy(f->b, sizeof(f->b), json_get_str(json_get(&v, "note")));
    dev_index_copy(f->c, sizeof(f->c), json_get_str(json_get(&v, "phase")));
    dev_index_flatten_json_strings(&v, f);
    json_free(&v);
    return true;
}

/* Split `line` on '\t' in place (writes NULs into a caller-owned scratch
 * copy) and fill `out[i]` with a pointer into that copy for i < *n. */
#define DEV_INDEX_TSV_MAX_COLS 22u
static void dev_index_split_tsv(char *scratch, const char *out[], size_t *n)
{
    *n = 0;
    char *cur = scratch;
    out[(*n)++] = cur;
    while (*cur && *n < DEV_INDEX_TSV_MAX_COLS) {
        if (*cur == '\t') {
            *cur = '\0';
            out[(*n)++] = cur + 1;
        }
        cur++;
    }
}

static bool dev_index_parse_experiment(const char *line,
                                       struct dev_index_fields *f)
{
    if (strncmp(line, "ts\tkind\t", 8) == 0)
        return false; /* the header line, never indexed */
    char scratch[DEV_INDEX_LINE_MAX];
    dev_index_copy(scratch, sizeof(scratch), line);
    const char *cols[DEV_INDEX_TSV_MAX_COLS];
    size_t n = 0;
    dev_index_split_tsv(scratch, cols, &n);
    if (n < 18)
        return false;
    dev_index_copy(f->ts, sizeof(f->ts), cols[0]);
    dev_index_copy(f->kind, sizeof(f->kind), cols[1]);
    dev_index_copy(f->a, sizeof(f->a), cols[3]);  /* task_id */
    dev_index_copy(f->b, sizeof(f->b), cols[6]);  /* executor */
    dev_index_copy(f->c, sizeof(f->c), cols[17]); /* outcome */
    static const char *const enum_cols[] = {
        "ts", "kind", "box", "task_id", "task_class", "story",
        "executor", "harness", "model", "effort", "outcome",
    };
    static const size_t enum_idx[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 17};
    for (size_t i = 0; i < sizeof(enum_idx) / sizeof(enum_idx[0]); i++)
        if (enum_idx[i] < n)
            dev_index_kv_add(f, enum_cols[i], cols[enum_idx[i]]);
    return true;
}

/* A log line's leading token is a timestamp often enough to be worth
 * indexing, but plenty of lines start with anything else (a progress bar,
 * a bare word). Only trust it when it looks like "YYYY-MM-DDTHH:MM:SS" —
 * compared as a shape (digit positions collapse to 'D', position 10
 * accepts 'T' or ' ') instead of a long if/else chain over each position —
 * so a non-timestamp leading token leaves ts empty (searchable in `text`,
 * just not sortable) instead of polluting MAX(ts) with an arbitrary
 * string. */
static bool dev_index_looks_like_iso_ts(const char *tok, size_t len)
{
    static const char shape[19] = "DDDD-DD-DD?DD:DD:DD";
    if (len < sizeof(shape))
        return false;
    char got[sizeof(shape)];
    for (size_t i = 0; i < sizeof(shape); i++)
        got[i] = (tok[i] >= '0' && tok[i] <= '9') ? 'D' : tok[i];
    if (got[10] == 'T' || got[10] == ' ')
        got[10] = '?';
    return memcmp(got, shape, sizeof(shape)) == 0;
}

static bool dev_index_ident_start(char c)
{
    return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static bool dev_index_ident_char(char c)
{
    return dev_index_ident_start(c) || (c >= '0' && c <= '9');
}

/* Advance *p to the next `key=value` token (identifier key, non-space
 * value run) and fill key/val. Returns false once the line is exhausted.
 * Split out of dev_index_parse_log so that function stays one loop plus
 * one call instead of a nested scan. */
static bool dev_index_next_kv_token(const char **p, char *key, size_t key_cap,
                                    char *val, size_t val_cap)
{
    while (**p) {
        if (!dev_index_ident_start(**p)) {
            (*p)++;
            continue;
        }
        const char *key_start = *p;
        const char *eq = *p;
        while (dev_index_ident_char(*eq))
            eq++;
        if (*eq != '=') {
            *p = eq;
            continue;
        }
        const char *val_start = eq + 1;
        const char *val_end = val_start;
        while (*val_end && *val_end != ' ' && *val_end != '\t')
            val_end++;
        *p = val_end;
        size_t klen = (size_t)(eq - key_start);
        size_t vlen = (size_t)(val_end - val_start);
        if (vlen == 0 || klen >= key_cap || vlen >= val_cap)
            continue;
        memcpy(key, key_start, klen);
        key[klen] = '\0';
        memcpy(val, val_start, vlen);
        val[vlen] = '\0';
        return true;
    }
    return false;
}

static bool dev_index_parse_log(const char *line, struct dev_index_fields *f)
{
    const char *sp = strchr(line, ' ');
    size_t ts_len = sp ? (size_t)(sp - line) : 0;
    if (ts_len > 0 && ts_len < sizeof(f->ts) &&
       dev_index_looks_like_iso_ts(line, ts_len)) {
        memcpy(f->ts, line, ts_len);
        f->ts[ts_len] = '\0';
    }
    dev_index_copy(f->kind, sizeof(f->kind), "log");
    const char *p = line;
    char key[48], val[64];
    int found = 0;
    while (found < 16 &&
          dev_index_next_kv_token(&p, key, sizeof(key), val, sizeof(val))) {
        dev_index_kv_add(f, key, val);
        found++;
    }
    return true;
}

bool dev_index_parse_line(const struct dev_index_source *src,
                          const char *line, struct dev_index_fields *f)
{
    memset(f, 0, sizeof(*f));
    switch (src->kind) {
    case DEV_INDEX_KIND_BOARD_ROWS:
        return dev_index_parse_board(line, f);
    case DEV_INDEX_KIND_LANDING_OUTCOMES:
        return dev_index_parse_landing(line, f);
    case DEV_INDEX_KIND_EXPERIMENT_ROWS:
        return dev_index_parse_experiment(line, f);
    case DEV_INDEX_KIND_LOG_LINES:
        return dev_index_parse_log(line, f);
    }
    return false;
}
