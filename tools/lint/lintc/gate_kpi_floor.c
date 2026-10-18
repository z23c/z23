/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-kpi-floor. The scoreboard behind `z23 code kpi`
 * may only improve: every metric named in tools/lint/kpi_floor.txt must be at
 * or better than its committed floor in its declared direction. The metrics
 * come from cognition/modules/kpi, the same code the leaf runs, over the
 * checkout; no node, index or ledger is read and nothing is written.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "kpi/kpi.h"
#include "lintc.h"

enum { KFG_MISS_MAX = KPI_METRIC_MAX };

static const char k_kfg_floor[] = "tools/lint/kpi_floor.txt";

/* One line per miss, then the rule. Returns how many metrics missed. */
static size_t kfg_report(const struct kpi_floor *fl,
                         const struct kpi_frame *cur, FILE *out)
{
    struct kpi_miss miss[KFG_MISS_MAX];
    size_t n = kpi_floor_check(fl, cur, miss, KFG_MISS_MAX);
    for (size_t i = 0; i < n && i < KFG_MISS_MAX; i++) {
        const struct kpi_miss *m = &miss[i];
        fprintf(out, "check-kpi-floor: FAIL %s: floor %" PRIu64 ", ",
                m->def->id, m->floor);
        if (m->kind == KPI_MISS_UNAVAILABLE)
            fputs("current UNAVAILABLE", out);
        else
            fprintf(out, "current %" PRIu64 " (%s)", m->current,
                    kpi_direction_label(m->def->direction));
        fprintf(out, "; rows: %s\n", m->def->drill);
    }
    if (n > 0)
        fprintf(out, "check-kpi-floor: scoreboard: z23 code kpi; fix the "
                     "regression, never lower %s\n", k_kfg_floor);
    return n;
}

int check_kpi_floor_run(int argc, char **argv)
{
    (void)argv;
    if (argc > 0)
        return die("check-kpi-floor: takes no arguments%s\n", "");
    char root[4096], path[4352];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, k_kfg_floor),
            sizeof path))
        return 2;

    struct kpi_floor fl;
    unsigned bad = 0;
    if (!kpi_floor_load(path, &fl, &bad)) {
        fprintf(stderr, "check-kpi-floor: cannot use %s (line %u)\n",
                k_kfg_floor, bad);
        return 2;
    }
    struct kpi_frame cur;
    kpi_collect_files(root, KPI_GROUP_ALL, &cur);
    if (kfg_report(&fl, &cur, stderr) > 0)
        return 1;
    printf("check-kpi-floor: clean — %u metrics at or better than their floor\n",
           fl.count);
    return 0;
}

/* ── selftest ─────────────────────────────────────────────────────────── */

static void kfg_frame(struct kpi_frame *f, const char *id, enum kpi_state s,
                      uint64_t v)
{
    memset(f, 0, sizeof *f);
    f->count = 1;
    snprintf(f->metric[0].id, sizeof f->metric[0].id, "%s", id);
    f->metric[0].state = s;
    f->metric[0].value = s == KPI_STATE_PRESENT ? v : 0;
}

static int kfg_case(const char *id, uint64_t floor, enum kpi_state s,
                    uint64_t cur, size_t want)
{
    struct kpi_floor fl;
    memset(&fl, 0, sizeof fl);
    fl.count = 1;
    snprintf(fl.id[0], sizeof fl.id[0], "%s", id);
    fl.value[0] = floor;
    struct kpi_frame f;
    kfg_frame(&f, id, s, cur);
    char *text = NULL;
    size_t len = 0;
    FILE *out = open_memstream(&text, &len);
    size_t got = out ? kfg_report(&fl, &f, out) : (size_t)-1;
    if (out)
        fclose(out);
    int ok = got == want && (want == 0 || (text && strstr(text, id) &&
                                           strstr(text, "rows: ")));
    if (!ok)
        fprintf(stderr, "check-kpi-floor selftest: %s floor %" PRIu64
                " current %" PRIu64 ": %zu misses, want %zu\n%s\n", id, floor,
                cur, got, want, text ? text : "");
    free(text);
    return ok ? 0 : 1;
}

int check_kpi_floor_selftest(void)
{
    int rc = 0;
    rc |= kfg_case("code.size_debt", 5, KPI_STATE_PRESENT, 5, 0);
    rc |= kfg_case("code.size_debt", 5, KPI_STATE_PRESENT, 4, 0);
    rc |= kfg_case("code.size_debt", 5, KPI_STATE_PRESENT, 6, 1);
    rc |= kfg_case("cmd.leaves", 700, KPI_STATE_PRESENT, 700, 0);
    rc |= kfg_case("cmd.leaves", 700, KPI_STATE_PRESENT, 701, 0);
    rc |= kfg_case("cmd.leaves", 700, KPI_STATE_PRESENT, 699, 1);
    rc |= kfg_case("cmd.leaves", 700, KPI_STATE_UNAVAILABLE, 0, 1);
    rc |= kfg_case("code.size_debt", 0, KPI_STATE_UNAVAILABLE, 0, 1);
    if (rc == 0)
        fputs("check-kpi-floor selftest: PASS — a metric at its floor passes in "
              "both directions; one step worse, or unavailable, refuses and "
              "names the rows\n", stdout);
    return rc;
}
