/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * kpi_floor — the committed ratchet over the scoreboard.
 *
 * The floor file holds one `metric value` row per ratcheted metric. A metric
 * passes while it is not worse than its floor in its declared direction;
 * equal passes. A floored metric that cannot be measured is a miss, because
 * a number nobody read proves nothing. NEUTRAL metrics have no direction and
 * cannot be floored.
 */

#include "kpi/kpi.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

enum { KPI_FLOOR_LINE = 512 };

static bool kpi_floor_value(const char *s, uint64_t *out)
{
    if (!isdigit((unsigned char)*s))
        return false;
    uint64_t v = 0;
    while (isdigit((unsigned char)*s)) {
        unsigned d = (unsigned)(*s++ - '0');
        if (v > (UINT64_MAX - d) / 10u)
            return false;
        v = v * 10u + d;
    }
    while (*s == ' ' || *s == '\t' || *s == '\r')
        s++;
    if (*s != '\0' && *s != '#')
        return false;
    *out = v;
    return true;
}

/* One non-blank, non-comment row into `fl`. */
static bool kpi_floor_row(const char *line, struct kpi_floor *fl)
{
    char id[KPI_ID_MAX];
    size_t n = strcspn(line, " \t");
    if (n == 0 || n >= sizeof id || line[n] == '\0')
        return false;
    memcpy(id, line, n);
    id[n] = '\0';

    const struct kpi_metric_def *def = kpi_metric_def_by_id(id);
    if (!def || def->direction == KPI_DIRECTION_NEUTRAL ||
        fl->count >= KPI_METRIC_MAX)
        return false;
    for (uint32_t i = 0; i < fl->count; i++)
        if (strcmp(fl->id[i], id) == 0)
            return false;

    const char *rest = line + n;
    while (*rest == ' ' || *rest == '\t')
        rest++;
    uint64_t v = 0;
    if (!kpi_floor_value(rest, &v))
        return false;
    memcpy(fl->id[fl->count], id, n + 1);
    fl->value[fl->count++] = v;
    return true;
}

static bool kpi_floor_blank(const char *s)
{
    return *s == '\0' || *s == '\n' || *s == '\r' || *s == '#';
}

/* Every row of `f` into `out`; `*lineno` ends on the first bad line. */
static bool kpi_floor_rows(FILE *f, struct kpi_floor *out, unsigned *lineno)
{
    char line[KPI_FLOOR_LINE];
    while (fgets(line, sizeof line, f)) {
        ++*lineno;
        const char *s = line + strspn(line, " \t");
        if (kpi_floor_blank(s))
            continue;
        line[strcspn(line, "\r\n")] = '\0';
        if (!kpi_floor_row(s, out))
            return false;
    }
    return ferror(f) == 0;
}

bool kpi_floor_load(const char *path, struct kpi_floor *out,
                    unsigned *bad_line)
{
    if (bad_line)
        *bad_line = 0;
    if (!path || !out)
        return false;
    memset(out, 0, sizeof *out);
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    unsigned lineno = 0;
    bool ok = kpi_floor_rows(f, out, &lineno);
    fclose(f);
    if (!ok && bad_line)
        *bad_line = lineno;
    return ok;
}

static bool kpi_floor_worse(enum kpi_direction d, uint64_t floor, uint64_t cur)
{
    return d == KPI_DIRECTION_HIGHER_IS_BETTER ? cur < floor : cur > floor;
}

size_t kpi_floor_check(const struct kpi_floor *fl, const struct kpi_frame *cur,
                       struct kpi_miss *miss, size_t cap)
{
    if (!fl || !cur)
        return 0;
    size_t n = 0;
    for (uint32_t i = 0; i < fl->count; i++) {
        const struct kpi_metric_def *def = kpi_metric_def_by_id(fl->id[i]);
        const struct kpi_entry *e = kpi_frame_find(cur, fl->id[i]);
        bool gone = !e || e->state != KPI_STATE_PRESENT;
        if (!def || (!gone && !kpi_floor_worse(def->direction, fl->value[i],
                                               e->value)))
            continue;
        if (miss && n < cap) {
            miss[n].def = def;
            miss[n].kind = gone ? KPI_MISS_UNAVAILABLE : KPI_MISS_WORSE;
            miss[n].floor = fl->value[i];
            miss[n].current = gone ? 0 : e->value;
        }
        n++;
    }
    return n;
}
