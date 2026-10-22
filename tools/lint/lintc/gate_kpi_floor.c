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

/* Whether `cur` is strictly better than `fl_value` in direction `d`. */
static bool kfg_better(enum kpi_direction d, uint64_t fl_value, uint64_t cur)
{
    return d == KPI_DIRECTION_HIGHER_IS_BETTER ? cur > fl_value
                                               : cur < fl_value;
}

/* Index of the floor row whose metric id opens `line`, or -1 for a blank,
 * comment or unknown line. */
static int kfg_row_index(const struct kpi_floor *fl, const char *line)
{
    size_t n = strcspn(line, " \t");
    for (uint32_t i = 0; n > 0 && i < fl->count; i++)
        if (strlen(fl->id[i]) == n && strncmp(fl->id[i], line, n) == 0)
            return (int)i;
    return -1;
}

/* Writes `line` with the value after its metric id replaced by `value`. The
 * spacing, any trailing comment and the newline are kept byte for byte. */
static bool kfg_put_row(FILE *out, const char *line, uint64_t value)
{
    const char *p = line + strcspn(line, " \t");
    while (*p == ' ' || *p == '\t')
        p++;
    const char *end = p + strspn(p, "0123456789");
    return fprintf(out, "%.*s%" PRIu64 "%s", (int)(p - line), line, value,
                   end) >= 0;
}

/* Copies the floor file through a sibling temp file: a row whose value differs
 * in `next` takes the new value and every other byte is copied as it is. The
 * temp file replaces `path` by rename only when the copy closed cleanly.
 * Returns 0 on success. */
static int kfg_copy_rows(const char *path, const struct kpi_floor *fl,
                         const struct kpi_floor *next)
{
    char tmp[4352], *line = NULL;
    size_t cap = 0;
    if (ovf(snprintf(tmp, sizeof tmp, "%s.tmp", path), sizeof tmp))
        return 2;
    FILE *in = fopen(path, "rb");
    FILE *out = in ? fopen(tmp, "wb") : NULL;
    if (!out) {
        if (in)
            (void)fclose(in);
        return 2;
    }
    int ok = 1;
    while (ok && getline(&line, &cap, in) >= 0) {
        int i = kfg_row_index(fl, line);
        if (i >= 0 && next->value[i] != fl->value[i])
            ok = kfg_put_row(out, line, next->value[i]);
        else
            ok = fputs(line, out) >= 0;
    }
    ok = ok && ferror(in) == 0;
    (void)fclose(in);
    free(line);
    if (fclose(out) != 0)
        ok = 0;
    if (ok && rename(tmp, path) == 0)
        return 0;
    (void)remove(tmp);
    return 2;
}

/* Copies `fl` into `next` with each floor moved to its current value where
 * that value is strictly better. Returns how many floors moved. */
static size_t kfg_improve(const struct kpi_floor *fl,
                          const struct kpi_frame *cur,
                          struct kpi_floor *next)
{
    size_t moved = 0;
    *next = *fl;
    for (uint32_t i = 0; i < fl->count; i++) {
        const struct kpi_metric_def *def = kpi_metric_def_by_id(fl->id[i]);
        const struct kpi_entry *e = kpi_frame_find(cur, fl->id[i]);
        if (!def || !e || e->state != KPI_STATE_PRESENT ||
            !kfg_better(def->direction, fl->value[i], e->value))
            continue;
        next->value[i] = e->value;
        moved++;
    }
    return moved;
}

/* One line per floor that moved: the metric, its old value, its new value. */
static void kfg_say_changes(const struct kpi_floor *fl,
                            const struct kpi_floor *next, FILE *out)
{
    for (uint32_t i = 0; i < fl->count; i++)
        if (next->value[i] != fl->value[i])
            fprintf(out, "check-kpi-floor: %s %" PRIu64 " -> %" PRIu64 "\n",
                    fl->id[i], fl->value[i], next->value[i]);
}

/* --tighten-baseline. Refuses, writing nothing, when any metric is worse than
 * its floor. Otherwise moves each strictly better floor to its current value
 * and rewrites only those rows. Returns 0, 1 on refusal or 2 on failure. */
static int kfg_tighten(const char *path, const struct kpi_floor *fl,
                       const struct kpi_frame *cur, FILE *out, FILE *err)
{
    if (kfg_report(fl, cur, err) > 0) {
        fprintf(err, "check-kpi-floor: refusing to tighten %s: a metric is "
                     "worse than its floor; nothing was written\n",
                k_kfg_floor);
        return 1;
    }
    struct kpi_floor next;
    size_t moved = kfg_improve(fl, cur, &next);
    if (moved == 0) {
        fprintf(out, "check-kpi-floor: nothing to tighten; all %u floors are "
                     "at their best\n", fl->count);
        return 0;
    }
    if (kfg_copy_rows(path, fl, &next) != 0) {
        fprintf(err, "check-kpi-floor: cannot rewrite %s\n", k_kfg_floor);
        return 2;
    }
    kfg_say_changes(fl, &next, out);
    fprintf(out, "check-kpi-floor: tightened %zu of %u floor(s) in %s\n",
            moved, fl->count, k_kfg_floor);
    return 0;
}

int check_kpi_floor_run(int argc, char **argv)
{
    int tighten = argc == 1 && strcmp(argv[0], "--tighten-baseline") == 0;
    if (argc > 0 && !tighten)
        return die("check-kpi-floor: takes no arguments or "
                   "--tighten-baseline%s\n", "");
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
    if (tighten)
        return kfg_tighten(path, &fl, &cur, stdout, stderr);
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

/* ── tighten selftest: fixtures in a private directory ─────────────────── */

static const char k_kfg_fixture[] =
    "# header comment kept\n"
    "\n"
    "cmd.tested 700\n"
    "# between rows\n"
    "code.shell_scripts 491   # trailing note kept\n";

static const char k_kfg_lowered[] =
    "# header comment kept\n"
    "\n"
    "cmd.tested 710\n"
    "# between rows\n"
    "code.shell_scripts 396   # trailing note kept\n";

static const char k_kfg_reordered[] =
    "# top comment\n"
    "code.shell_scripts 491 # note\n"
    "# middle\n"
    "cmd.tested 700\n";

static const char k_kfg_reordered_out[] =
    "# top comment\n"
    "code.shell_scripts 396 # note\n"
    "# middle\n"
    "cmd.tested 710\n";

static int kfg_check(const char *tag, int ok)
{
    if (ok)
        return 0;
    fprintf(stderr, "check-kpi-floor selftest: %s\n", tag);
    return 1;
}

/* A current frame for cmd.tested (higher is better) and code.shell_scripts
 * (lower is better). */
static void kfg_pair(struct kpi_frame *f, uint64_t tested, uint64_t shell)
{
    memset(f, 0, sizeof *f);
    f->count = 2;
    snprintf(f->metric[0].id, sizeof f->metric[0].id, "%s", "cmd.tested");
    f->metric[0].value = tested;
    snprintf(f->metric[1].id, sizeof f->metric[1].id, "%s",
             "code.shell_scripts");
    f->metric[1].value = shell;
}

/* 1 when the file at `path` holds exactly `want`, byte for byte. */
static int kfg_file_is(const char *path, const char *want)
{
    char buf[1024];
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    int whole = feof(f) != 0;
    (void)fclose(f);
    buf[n] = '\0';
    return whole && strcmp(buf, want) == 0;
}

static int kfg_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    (void)fclose(f);
    return 1;
}

static int kfg_sink_has(FILE *sink, const char *needle)
{
    char buf[2048];
    if (csr_slurp(sink, buf, sizeof buf) != 0)
        return 0;
    return strstr(buf, needle) != NULL;
}

static void kfg_close(FILE *f)
{
    if (f)
        (void)fclose(f);
}

/* Loads the floor file at `path` and tightens it against `cur`. -1 when the
 * fixture does not load. */
static int kfg_tighten_at(const char *path, const struct kpi_frame *cur,
                          FILE *out, FILE *err)
{
    struct kpi_floor fl;
    if (!kpi_floor_load(path, &fl, NULL))
        return -1;
    return kfg_tighten(path, &fl, cur, out, err);
}

/* (a) A better floor moves to its current value, lower or higher. */
static int kfg_case_better(const char *path)
{
    struct kpi_frame cur;
    kfg_pair(&cur, 710, 396);
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err || csr_write(path, k_kfg_fixture)) {
        kfg_close(out);
        kfg_close(err);
        return 1;
    }
    int bad = kfg_check("a better floor must tighten",
                        kfg_tighten_at(path, &cur, out, err) == 0);
    bad |= kfg_check("a better floor must move to its current value",
                     kfg_file_is(path, k_kfg_lowered));
    bad |= kfg_check("tighten must print each old -> new change",
                     kfg_sink_has(out, "check-kpi-floor: cmd.tested 700 -> 710")
                     && kfg_sink_has(out,
                         "check-kpi-floor: code.shell_scripts 491 -> 396"));
    kfg_close(out);
    kfg_close(err);
    return bad;
}

/* (b) One worse metric refuses; the file stays byte-identical, no temp file. */
static int kfg_case_worse(const char *path)
{
    struct kpi_frame cur;
    kfg_pair(&cur, 710, 500);
    char tmp[4352];
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err || csr_write(path, k_kfg_fixture)
        || ovf(snprintf(tmp, sizeof tmp, "%s.tmp", path), sizeof tmp)) {
        kfg_close(out);
        kfg_close(err);
        return 1;
    }
    int bad = kfg_check("a worse metric must refuse the tighten",
                        kfg_tighten_at(path, &cur, out, err) == 1);
    bad |= kfg_check("a refused tighten must leave the file byte-identical",
                     kfg_file_is(path, k_kfg_fixture));
    bad |= kfg_check("a refused tighten must write no temp file",
                     !kfg_exists(tmp));
    bad |= kfg_check("a refusal must name the worse metric",
                     kfg_sink_has(err, "FAIL code.shell_scripts"));
    kfg_close(out);
    kfg_close(err);
    return bad;
}

/* (c) Comments, blank lines, trailing notes and row order survive. */
static int kfg_case_order(const char *path)
{
    struct kpi_frame cur;
    kfg_pair(&cur, 710, 396);
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err || csr_write(path, k_kfg_reordered)) {
        kfg_close(out);
        kfg_close(err);
        return 1;
    }
    int bad = kfg_check("reordered floors must tighten",
                        kfg_tighten_at(path, &cur, out, err) == 0);
    bad |= kfg_check("comments and row order must survive the rewrite",
                     kfg_file_is(path, k_kfg_reordered_out));
    kfg_close(out);
    kfg_close(err);
    return bad;
}

/* (d) A second run over the tightened file is a no-op. */
static int kfg_case_twice(const char *path)
{
    struct kpi_frame cur;
    kfg_pair(&cur, 710, 396);
    FILE *out = tmpfile(), *err = tmpfile(), *again = tmpfile();
    if (!out || !err || !again || csr_write(path, k_kfg_fixture)) {
        kfg_close(out);
        kfg_close(err);
        kfg_close(again);
        return 1;
    }
    int bad = kfg_check("first tighten must succeed",
                        kfg_tighten_at(path, &cur, out, err) == 0);
    bad |= kfg_check("second tighten must succeed",
                     kfg_tighten_at(path, &cur, again, err) == 0);
    bad |= kfg_check("second tighten must leave the file byte-identical",
                     kfg_file_is(path, k_kfg_lowered));
    bad |= kfg_check("second tighten must report nothing to tighten",
                     kfg_sink_has(again, "nothing to tighten"));
    bad |= kfg_check("second tighten must print no change",
                     !kfg_sink_has(again, " -> "));
    kfg_close(out);
    kfg_close(err);
    kfg_close(again);
    return bad;
}

static int kfg_tighten_selftest(void)
{
    char dir[4096], path[4352];
    const char *root = env_or("TMPDIR", "test-tmp");
    if (ovf(snprintf(dir, sizeof dir, "%s/z23-kfg-XXXXXX", root), sizeof dir)
        || csr_mkdirs(root) || !mkdtemp(dir))
        return 1;
    int bad = 1;
    if (!ovf(snprintf(path, sizeof path, "%s/kpi_floor.txt", dir),
             sizeof path))
        bad = kfg_case_better(path) | kfg_case_worse(path)
            | kfg_case_order(path) | kfg_case_twice(path);
    rap_rm_rf(dir);
    return bad;
}

int check_kpi_floor_selftest(void)
{
    int rc = 0;
    rc |= kfg_case("code.size_debt", 5, KPI_STATE_PRESENT, 5, 0);
    rc |= kfg_case("code.size_debt", 5, KPI_STATE_PRESENT, 4, 0);
    rc |= kfg_case("code.size_debt", 5, KPI_STATE_PRESENT, 6, 1);
    rc |= kfg_case("cmd.tested", 700, KPI_STATE_PRESENT, 700, 0);
    rc |= kfg_case("cmd.tested", 700, KPI_STATE_PRESENT, 701, 0);
    rc |= kfg_case("cmd.tested", 700, KPI_STATE_PRESENT, 699, 1);
    rc |= kfg_case("cmd.tested", 700, KPI_STATE_UNAVAILABLE, 0, 1);
    rc |= kfg_case("code.size_debt", 0, KPI_STATE_UNAVAILABLE, 0, 1);
    rc |= kfg_tighten_selftest();
    if (rc == 0)
        fputs("check-kpi-floor selftest: PASS — a metric at its floor passes in "
              "both directions; one step worse, or unavailable, refuses and "
              "names the rows\n", stdout);
    return rc;
}
