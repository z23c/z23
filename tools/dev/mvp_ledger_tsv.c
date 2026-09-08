/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: measure the 144-loop MVP experiment — the bounded table
 *          lifetimes and the agents.tsv reader/writer. A row that is not
 *          exactly this build's header, or not exactly MVL_AGENT_COLUMNS
 *          cells, is refused by line number. See tools/dev/mvp_ledger.h. */
#define _POSIX_C_SOURCE 200809L
#include "mvp_ledger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "mvp_ledger_internal.h"

/* ── table lifetimes ──────────────────────────────────────────────────── */

bool mvl_agents_alloc(struct mvl_agents *agents)
{
    agents->rows = zcl_calloc(MVL_MAX_AGENTS, sizeof *agents->rows,
                              "mvl_agents");
    agents->count = 0;
    agents->cap = agents->rows ? MVL_MAX_AGENTS : 0;
    return agents->rows != NULL;
}

void mvl_agents_free(struct mvl_agents *agents)
{
    free(agents->rows);
    agents->rows = NULL;
    agents->count = 0;
    agents->cap = 0;
}

/* ── agents.tsv ───────────────────────────────────────────────────────── */

const char *mvl_agents_header(void)
{
    return "agent_id\tdescription\tlane\tkind\tmodel\tfirst_utc\tlast_utc\t"
           "wall_s\tturns\ttool_uses\ttokens_out\tthinking_tokens\t"
           "tokens_in\tinput_tokens\tcache_creation_tokens\t"
           "cache_read_tokens\toutcome";
}

static const char *mvl_or_dash(const char *s)
{
    return (s && s[0] != '\0') ? s : "-";
}

bool mvl_write_agents(const char *path, const struct mvl_agents *agents,
                      char *err, size_t err_cap)
{
    FILE *f = fopen(path, "w");

    if (!f) {
        mvl_err(err, err_cap, path, 0, "mvl_open: cannot write agents.tsv");
        return false;
    }
    fprintf(f, "%s\n", mvl_agents_header());
    for (size_t i = 0; i < agents->count; i++) {
        const struct mvl_agent *a = &agents->rows[i];

        fprintf(f,
                "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%lld\t%lld\t%lld\t%lld\t%lld"
                "\t%lld\t%lld\t%lld\t%lld\t%s\n",
                a->agent_id, mvl_or_dash(a->description), a->lane, a->kind,
                mvl_or_dash(a->model), mvl_or_dash(a->first_utc),
                mvl_or_dash(a->last_utc),
                (long long)(a->last_unix - a->first_unix),
                (long long)a->turns, (long long)a->tool_uses,
                (long long)a->tokens_out, (long long)a->thinking_tokens,
                (long long)a->tokens_in, (long long)a->tokens_input,
                (long long)a->tokens_cache_creation,
                (long long)a->tokens_cache_read, mvl_or_dash(a->outcome));
    }
    if (fclose(f) != 0) {
        mvl_err(err, err_cap, path, 0, "mvl_open: agents.tsv did not close");
        return false;
    }
    return true;
}

/* Splits `line` on tabs in place. Returns the number of cells written. */
static size_t mvl_split(char *line, char **cells, size_t cap)
{
    size_t n = 0;

    cells[n++] = line;
    for (char *p = line; *p; p++) {
        if (*p != '\t')
            continue;
        *p = '\0';
        if (n >= cap)
            return n + 1;
        cells[n++] = p + 1;
    }
    return n;
}

static void mvl_read_stamp(const char *cell, char *dst, size_t cap,
                           int64_t *unix_out)
{
    *unix_out = 0;
    mvl_copy(dst, cap, cell);
    if (strcmp(cell, "-") == 0) {
        dst[0] = '\0';
        return;
    }
    (void)mvl_parse_timestamp(cell, unix_out);
}

static void mvl_row_from_cells(char **c, struct mvl_agent *a)
{
    memset(a, 0, sizeof *a);
    mvl_copy(a->agent_id, sizeof a->agent_id, c[0]);
    mvl_copy(a->description, sizeof a->description, c[1]);
    mvl_copy(a->lane, sizeof a->lane, c[2]);
    mvl_copy(a->kind, sizeof a->kind, c[3]);
    mvl_copy(a->model, sizeof a->model, c[4]);
    mvl_read_stamp(c[5], a->first_utc, sizeof a->first_utc, &a->first_unix);
    mvl_read_stamp(c[6], a->last_utc, sizeof a->last_utc, &a->last_unix);
    a->turns = strtoll(c[8], NULL, 10);
    a->tool_uses = strtoll(c[9], NULL, 10);
    a->tokens_out = strtoll(c[10], NULL, 10);
    a->thinking_tokens = strtoll(c[11], NULL, 10);
    a->tokens_in = strtoll(c[12], NULL, 10);
    a->tokens_input = strtoll(c[13], NULL, 10);
    a->tokens_cache_creation = strtoll(c[14], NULL, 10);
    a->tokens_cache_read = strtoll(c[15], NULL, 10);
    mvl_copy(a->outcome, sizeof a->outcome, c[16]);
}

bool mvl_read_agents(const char *path, struct mvl_agents *out, char *err,
                     size_t err_cap)
{
    char *buf = zcl_malloc(MVL_LINE_CAP + 2, "mvl_tsv_line");
    char *cells[MVL_AGENT_COLUMNS];
    FILE *f;
    size_t line_no = 0;
    bool ok = true;

    if (!buf) {
        mvl_err(err, err_cap, path, 0, "mvl_overflow: no line buffer");
        return false;
    }
    f = fopen(path, "r");
    if (!f) {
        mvl_err(err, err_cap, path, 0, "mvl_open: cannot read agents.tsv");
        free(buf);
        return false;
    }
    while (ok) {
        int rc = mvl_read_line(f, buf, MVL_LINE_CAP + 2);
        struct mvl_agent *a;

        if (rc == 0)
            break;
        line_no++;
        if (rc < 0) {
            mvl_err(err, err_cap, path, line_no,
                    "mvl_line_too_long: line exceeds MVL_LINE_CAP bytes");
            ok = false;
            break;
        }
        if (line_no == 1) {
            if (strcmp(buf, mvl_agents_header()) != 0) {
                mvl_err(err, err_cap, path, line_no,
                        "mvl_tsv_header: not this build's agents.tsv header");
                ok = false;
            }
            continue;
        }
        if (buf[0] == '\0')
            continue;
        if (mvl_split(buf, cells, MVL_AGENT_COLUMNS) != MVL_AGENT_COLUMNS) {
            mvl_err(err, err_cap, path, line_no,
                    "mvl_tsv_fields: row is not 17 tab-separated cells");
            ok = false;
            break;
        }
        a = mvl_next_row(out, err, err_cap);
        if (!a) {
            ok = false;
            break;
        }
        mvl_row_from_cells(cells, a);
    }
    (void)fclose(f);
    free(buf);
    return ok;
}

bool mvl_plan_alloc(struct mvl_plan *plan)
{
    memset(plan, 0, sizeof *plan);
    plan->milestones = zcl_calloc(MVL_MAX_MILESTONES,
                                  sizeof *plan->milestones, "mvl_milestones");
    plan->loops = zcl_calloc(MVL_MAX_LOOPS, sizeof *plan->loops, "mvl_loops");
    if (plan->milestones && plan->loops)
        return true;
    mvl_plan_free(plan);
    return false;
}

void mvl_plan_free(struct mvl_plan *plan)
{
    free(plan->milestones);
    free(plan->loops);
    memset(plan, 0, sizeof *plan);
}

/* Refuses when `path` exists and its first line is not `want`: an append-only
 * ledger whose columns moved must never be appended to, because every earlier
 * row would then be read under the wrong names. An absent or empty file is
 * accepted — the caller writes the header. */
bool mvl_check_header(const char *path, const char *want, char *err,
                      size_t err_cap)
{
    char *buf = zcl_malloc(MVL_LINE_CAP + 2, "mvl_header_line");
    FILE *f = fopen(path, "r");
    bool ok = true;

    if (!buf) {
        mvl_err(err, err_cap, path, 0, "mvl_overflow: no line buffer");
        if (f)
            (void)fclose(f);
        return false;
    }
    if (!f) {
        free(buf);
        return true;
    }
    if (mvl_read_line(f, buf, MVL_LINE_CAP + 2) == 1
        && strcmp(buf, want) != 0) {
        mvl_err(err, err_cap, path, 1,
                "mvl_tsv_header: not this build's header for that ledger");
        ok = false;
    }
    (void)fclose(f);
    free(buf);
    return ok;
}

/* True when `path` has no first line yet (absent, or present and empty). */
bool mvl_ledger_is_fresh(const char *path)
{
    FILE *f = fopen(path, "r");
    int c;

    if (!f)
        return true;
    c = fgetc(f);
    (void)fclose(f);
    return c == EOF;
}
