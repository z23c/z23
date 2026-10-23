/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The tokens_per_landed_commit producer. Its numerator is the
 *          experiment ledger's `result` rows (rows.tsv, 22 tab-separated
 *          columns) with ts in the trailing 7 days, summing tokens_in plus
 *          tokens_out (tokens_cache is excluded: cache reads are not billed
 *          as fresh input). Its denominator is the landed rows of the land
 *          outcomes file in the same window, counted by their ts. The value
 *          is the quotient, rounded down.
 *
 * A malformed ledger line is skipped and counted, never guessed at. The
 * ledger is read with a bounded line reader, one line at a time.
 */

#include "native_fleet_objectives.h"

#include "json/json.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TPC_WINDOW_S ((int64_t)7 * 86400)
#define TPC_LINE_CAP 8192u
#define TPC_FIELDS 22u
#define TPC_TOKEN_DIGITS 18u

/* What one pass over the experiment ledger found in the window. */
struct tpc_ledger {
    int64_t start;
    int64_t end;
    int64_t tokens;
    int64_t result_rows;
    int64_t skipped;
    bool overflow;
};

/* What one pass over the outcomes file found in the window. */
struct tpc_landed {
    int64_t start;
    int64_t end;
    int64_t landed;
};

static int64_t tpc_now(const struct zcl_objectives_options *options)
{
    return options && options->now > 0 ? options->now
                                       : platform_time_wall_unix();
}

/* $XDG_STATE_HOME/zclassic23/experiments/rows.tsv, else the same path under
 * ~/.local/state. The state root of the rest of z23 is not this one. */
static bool tpc_default_ledger(char *out, size_t cap)
{
    const char *xdg = getenv("XDG_STATE_HOME");
    const char *home = getenv("HOME");
    int n;
    if (xdg && xdg[0])
        n = snprintf(out, cap, "%s/zclassic23/experiments/rows.tsv", xdg);
    else if (home && home[0])
        n = snprintf(out, cap,
                     "%s/.local/state/zclassic23/experiments/rows.tsv", home);
    else
        return false;
    return n > 0 && (size_t)n < cap;
}

static bool tpc_resolve_ledger(const struct zcl_objectives_options *options,
                               char *buf, size_t cap, const char **out)
{
    if (options && options->experiments) {
        *out = options->experiments;
        return true;
    }
    if (!tpc_default_ledger(buf, cap))
        return false;
    *out = buf;
    return true;
}

/* Reads one physical line into `buf` (NUL-terminated, at most cap - 1 bytes
 * kept). 1 = a line, 2 = a line that overflowed the cap (drained to its end),
 * 0 = end of file, -1 = a read error. */
static int tpc_read_line(FILE *f, char *buf, size_t cap, size_t *len)
{
    size_t n = 0;
    bool over = false;
    int ch = 0;
    while ((ch = fgetc(f)) != EOF && ch != '\n') {
        if (ch == 0 || n + 1u >= cap)
            over = true;
        else
            buf[n++] = (char)ch;
    }
    buf[n] = '\0';
    if (ferror(f))
        return -1;
    if (ch == EOF && n == 0 && !over)
        return 0;
    if (n > 0 && buf[n - 1] == '\r')
        buf[--n] = '\0';
    *len = n;
    return over ? 2 : 1;
}

static bool tpc_digits(const char *s, int64_t *out)
{
    int64_t v = 0;
    size_t len = strlen(s);
    if (len == 0 || len > TPC_TOKEN_DIGITS)
        return false;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + (s[i] - '0');
    }
    *out = v;
    return true;
}

/* Splits `line` on tabs into `fields`. Returns the field count, or
 * TPC_FIELDS + 1 when the line has more fields than that. */
static size_t tpc_split(char *line, char *fields[TPC_FIELDS])
{
    size_t n = 0;
    char *p = line;
    for (;;) {
        if (n == TPC_FIELDS)
            return n + 1u;
        fields[n++] = p;
        p = strchr(p, '\t');
        if (!p)
            return n;
        *p++ = '\0';
    }
}

static void tpc_account(struct tpc_ledger *acc, const char *kind, int64_t when,
                        int64_t tin, int64_t tout)
{
    if (strcmp(kind, "result") != 0 || when < acc->start || when > acc->end)
        return;
    acc->result_rows++;
    if (tin > INT64_MAX - tout || tin + tout > INT64_MAX - acc->tokens)
        acc->overflow = true;
    else
        acc->tokens += tin + tout;
}

/* Parses one ledger data line and folds it into `acc`. False when the line
 * is malformed: the wrong field count, an unparsable ts, an unknown kind, or
 * a token column that is not a plain decimal count. */
static bool tpc_row(char *line, struct tpc_ledger *acc)
{
    char *fields[TPC_FIELDS];
    int64_t when, tin, tout;
    const char *kind;
    if (tpc_split(line, fields) != TPC_FIELDS)
        return false;
    if (!zcl_objectives_parse_iso8601(fields[0], &when))
        return false;
    kind = fields[1];
    if (strcmp(kind, "predict") != 0 && strcmp(kind, "result") != 0)
        return false;
    if (!tpc_digits(fields[10], &tin) || !tpc_digits(fields[11], &tout))
        return false;
    tpc_account(acc, kind, when, tin, tout);
    return true;
}

static void tpc_note_line(struct tpc_ledger *acc, char *line, int status)
{
    if (status == 2 || !tpc_row(line, acc))
        acc->skipped++;
}

/* Walks the experiment ledger. False with `reason` set when the file is
 * missing or unreadable. The header line is not a row and is not counted. */
static bool tpc_scan_ledger(const char *path, struct tpc_ledger *acc,
                            char *reason, size_t cap)
{
    char line[TPC_LINE_CAP];
    size_t len = 0;
    size_t line_no = 0;
    int status;
    FILE *f = fopen(path, "rb");
    if (!f) {
        (void)snprintf(reason, cap, "missing experiment ledger %s", path);
        return false;
    }
    while ((status = tpc_read_line(f, line, sizeof(line), &len)) > 0) {
        line_no++;
        if (line_no > 1)
            tpc_note_line(acc, line, status);
    }
    if (fclose(f) != 0 || status < 0) {
        (void)snprintf(reason, cap, "unreadable experiment ledger %s", path);
        return false;
    }
    return true;
}

static void tpc_landed_row(const struct json_value *row, void *user)
{
    struct tpc_landed *l = user;
    const char *state = json_get_str(json_get(row, "state"));
    int64_t when;
    if (!state || strcmp(state, "landed") != 0)
        return;
    if (!zcl_objectives_parse_iso8601(json_get_str(json_get(row, "ts")),
                                      &when))
        return;
    if (when >= l->start && when <= l->end)
        l->landed++;
}

static bool tpc_scan_landed(const char *path, struct tpc_landed *l,
                            char *reason, size_t cap)
{
    return zcl_objectives_ledger_walk(path, tpc_landed_row, l, reason, cap);
}

/* Each unmeasured branch names its cause first: the status column is short,
 * so the cause must lead the reason. */
static struct zcl_objective_value tpc_unmeasured(struct zcl_objective_value v,
                                                const char *why)
{
    v.measured = false;
    (void)snprintf(v.reason, sizeof(v.reason), "%s", why);
    return v;
}

struct zcl_objective_value zcl_objectives_tokens_per_landed_commit(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v;
    struct tpc_ledger acc;
    struct tpc_landed landed;
    char ledger_buf[1024], outcomes_buf[1024];
    const char *ledger = NULL, *outcomes = NULL;
    int64_t now = tpc_now(options);

    memset(&v, 0, sizeof(v));
    memset(&acc, 0, sizeof(acc));
    memset(&landed, 0, sizeof(landed));
    acc.start = landed.start = now - TPC_WINDOW_S;
    acc.end = landed.end = now;

    if (!tpc_resolve_ledger(options, ledger_buf, sizeof(ledger_buf), &ledger))
        return tpc_unmeasured(v, "no experiment ledger path (no HOME)");
    if (!zcl_objectives_outcomes_path(options, outcomes_buf,
                                      sizeof(outcomes_buf), &outcomes))
        return tpc_unmeasured(v, "state root unavailable");
    if (!tpc_scan_ledger(ledger, &acc, v.reason, sizeof(v.reason)))
        return v;
    if (acc.result_rows == 0)
        return tpc_unmeasured(v,
                              "no experiment ledger result row in 7 days");
    if (acc.overflow)
        return tpc_unmeasured(v, "token sum overflows in 7 days");
    if (!tpc_scan_landed(outcomes, &landed, v.reason, sizeof(v.reason)))
        return v;
    if (landed.landed == 0)
        return tpc_unmeasured(v, "no landed row in 7 days");

    v.measured = true;
    v.value = acc.tokens / landed.landed;
    (void)snprintf(v.note, sizeof(v.note),
                   "%lld result rows, %lld landed, %lld malformed lines skipped",
                   (long long)acc.result_rows, (long long)landed.landed,
                   (long long)acc.skipped);
    return v;
}
