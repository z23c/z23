/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-catalog-rooms. The native command rooms are
 * declared once, in engine/composition/commands/catalog.def. The runtime
 * metadata and handler tables (engine/composition/src/command_catalog.c) and
 * the describe-budget helper (tools/check_describe_budget.c) must expand that
 * one list and name no room directly, and the API reference generator
 * (tools/gen_api_reference.c) must include exactly the same rooms. A room the
 * generator omits ships live commands missing from the generated API_REFERENCE.md; a
 * room the budget helper omits ships leaves whose describe document is never
 * rendered. Both directions of the generator comparison refuse.
 *
 * The comparison runs over text streams, so the selftest plants omitted,
 * extra and directly-included rooms in memory without temporary files.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"

enum { CRM_ROOMS = 128, CRM_PATH = 96, CRM_FLOOR = 20 };

struct crm_set {
    char path[CRM_ROOMS][CRM_PATH];
    size_t n;
};

struct crm_scan {
    struct crm_set set;
    unsigned exact;
};

struct crm_files {
    FILE *catalog, *source, *budget, *generator;
};

static const char crm_source_line[] = "#include \"../commands/catalog.def\"";
static const char crm_budget_line[] = "#include \"commands/catalog.def\"";
static const char crm_gen_prefix[] = "../engine/composition/commands/";

static bool crm_has(const struct crm_set *s, const char *path)
{
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->path[i], path) == 0)
            return true;
    return false;
}

static int crm_add(struct crm_set *s, const char *path)
{
    if (crm_has(s, path))
        return 0;
    if (s->n >= CRM_ROOMS || strlen(path) >= CRM_PATH)
        return die("check-catalog-rooms: more rooms than the gate bounds: %s\n", path);
    memcpy(s->path[s->n], path, strlen(path) + 1);
    s->n++;
    return 0;
}

/* A line of the form `#include "<prefix><room>.def"` names <room>.def. */
static int crm_note(const char *line, const char *prefix, struct crm_scan *s)
{
    while (*line == ' ' || *line == '\t')
        line++;
    if (strncmp(line, "#include \"", 10) != 0)
        return 0;
    line += 10;
    size_t plen = strlen(prefix);
    if (strncmp(line, prefix, plen) != 0)
        return 0;
    line += plen;
    size_t len = strspn(line, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_/.");
    if (len < 5 || strcmp(line + len, "\"") != 0 || memcmp(line + len - 4, ".def", 4) != 0)
        return 0;
    char room[CRM_PATH];
    if (len >= sizeof room)
        return die("check-catalog-rooms: room path too long: %s\n", line);
    memcpy(room, line, len);
    room[len] = '\0';
    return crm_add(&s->set, room);
}

/* Reads every line of f, then closes it. */
static int crm_scan_stream(FILE *f, const char *label, const char *prefix,
                           const char *exact, struct crm_scan *s)
{
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    ssize_t n;
    while (rc == 0 && (n = getline(&line, &cap, f)) >= 0) {
        if (n > 0 && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (exact && strcmp(line, exact) == 0)
            s->exact++;
        rc = crm_note(line, prefix, s);
    }
    return fin(f, line, label, rc);
}

struct crm_report {
    FILE *out, *err;
    bool failed;
};

static void crm_head(struct crm_report *r)
{
    if (!r->failed)
        fputs("check-catalog-rooms: FAIL — command rooms disagree with "
              "catalog.def:\n", r->err);
    r->failed = true;
}

static void crm_report_diff(struct crm_report *r, const struct crm_set *a,
                            const struct crm_set *b, const char *heading)
{
    bool named = false;
    for (size_t i = 0; i < a->n; i++) {
        if (crm_has(b, a->path[i]))
            continue;
        crm_head(r);
        if (!named)
            fprintf(r->err, "  %s:\n", heading);
        fprintf(r->err, "    engine/composition/commands/%s\n", a->path[i]);
        named = true;
    }
}

static void crm_single_use(struct crm_report *r, const struct crm_scan *s,
                           unsigned uses, const char *file, const char *line)
{
    if (s->exact == uses && s->set.n == 1)
        return;
    crm_head(r);
    fprintf(r->err, "  %s must include %s exactly %u time(s) and name no "
                    "room directly\n", file, line, uses);
}

/* 0 clean, 1 refused, 2 fatal. Consumes the four streams. */
static int crm_check(const struct crm_files *in, size_t floor, FILE *out,
                     FILE *err)
{
    struct crm_scan rooms = { 0 }, src = { 0 }, bud = { 0 }, gen = { 0 };
    struct crm_report r = { out, err, false };
    int rc = crm_scan_stream(in->catalog, "catalog.def", "", NULL, &rooms);
    rc |= crm_scan_stream(in->source, "command_catalog.c", "../commands/",
                          crm_source_line, &src);
    rc |= crm_scan_stream(in->budget, "check_describe_budget.c", "commands/",
                          crm_budget_line, &bud);
    rc |= crm_scan_stream(in->generator, "gen_api_reference.c", crm_gen_prefix,
                          NULL, &gen);
    if (rc)
        return 2;
    if (rooms.set.n < floor) {
        fprintf(err, "check-catalog-rooms: FATAL — %zu rooms is below the "
                     "floor of %zu; a catalog that stopped parsing must never "
                     "read as clean\n", rooms.set.n, floor);
        return 2;
    }
    crm_single_use(&r, &src, 2, "command_catalog.c", crm_source_line);
    crm_single_use(&r, &bud, 1, "check_describe_budget.c", crm_budget_line);
    crm_report_diff(&r, &rooms.set, &gen.set, "Runtime rooms missing from generator");
    crm_report_diff(&r, &gen.set, &rooms.set, "Generator rooms absent from runtime");
    if (!r.failed)
        fprintf(out, "check-catalog-rooms: clean — %zu rooms; runtime tables, "
                     "describe budget and API reference generator agree\n",
                rooms.set.n);
    return r.failed ? 1 : 0;
}

static void crm_close_all(const struct crm_files *in)
{
    FILE *const all[] = { in->catalog, in->source, in->budget, in->generator };
    for (size_t i = 0; i < sizeof all / sizeof all[0]; i++)
        if (all[i])
            fclose(all[i]);
}

static FILE *crm_open_repo(const char *root, const char *rel)
{
    char path[4352];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return NULL;
    FILE *f = fopen(path, "r");
    if (!f)
        fprintf(stderr, "check-catalog-rooms: cannot read %s\n", path);
    return f;
}

static int crm_open_all(const char *root, struct crm_files *in)
{
    in->catalog = crm_open_repo(root, "engine/composition/commands/catalog.def");
    in->source = crm_open_repo(root, "engine/composition/src/command_catalog.c");
    in->budget = crm_open_repo(root, "tools/check_describe_budget.c");
    in->generator = crm_open_repo(root, "tools/gen_api_reference.c");
    if (in->catalog && in->source && in->budget && in->generator)
        return 0;
    crm_close_all(in);
    return 2;
}

int check_catalog_rooms_run(int argc, char **argv)
{
    (void)argv;
    if (argc > 0)
        return die("check-catalog-rooms: takes no arguments%s\n", "");
    char root[4096];
    struct crm_files in;
    if (cic_repo_root(root, sizeof root) || crm_open_all(root, &in))
        return 2;
    return crm_check(&in, CRM_FLOOR, stdout, stderr);
}

/* ── selftest ─────────────────────────────────────────────────────────── */

struct crm_case {
    const char *name;
    const char *catalog, *source, *budget, *generator;
    int want;
    const char *needle;
};

static const char crm_cat[] =
    "#include \"root.def\"\n#include \"fleet.def\"\n#include \"telemetry/root.def\"\n";
static const char crm_src[] =
    "static const struct spec t[] = {\n#include \"../commands/catalog.def\"\n};\n"
    "static const struct entry e[] = {\n#include \"../commands/catalog.def\"\n};\n";
static const char crm_bud[] =
    "static struct spec g_specs[] = {\n#include \"commands/catalog.def\"\n};\n";
static const char crm_gen[] =
    "#define ZCL_DEF_FILE \"engine/composition/commands/root.def\"\n"
    "#include \"../engine/composition/commands/root.def\"\n"
    "#include \"../engine/composition/commands/fleet.def\"\n"
    "#include \"../engine/composition/commands/telemetry/root.def\"\n";

enum { CRM_FIXTURE = 1024 };

/* A read stream over a private copy of a fixture; fmemopen needs a mutable
 * buffer. */
static FILE *crm_mem(const char *text, char copy[CRM_FIXTURE])
{
    size_t len = strlen(text);
    if (len >= CRM_FIXTURE)
        return NULL;
    memcpy(copy, text, len + 1);
    return fmemopen(copy, len, "r");
}

static int crm_run_case(const struct crm_case *c)
{
    char keep[4][CRM_FIXTURE], *report = NULL;
    size_t report_len = 0;
    struct crm_files in = {
        crm_mem(c->catalog, keep[0]), crm_mem(c->source, keep[1]),
        crm_mem(c->budget, keep[2]), crm_mem(c->generator, keep[3]) };
    FILE *out = open_memstream(&report, &report_len);
    int rc = -1;
    if (in.catalog && in.source && in.budget && in.generator && out)
        rc = crm_check(&in, 2, out, out);
    else
        crm_close_all(&in);
    if (out)
        fclose(out);
    int ok = rc == c->want && (!c->needle || (report && strstr(report, c->needle)));
    if (!ok)
        fprintf(stderr, "check-catalog-rooms selftest: %s: exit %d, want %d\n%s\n",
                c->name, rc, c->want, report ? report : "");
    free(report);
    return ok ? 0 : 1;
}

int check_catalog_rooms_selftest(void)
{
    static const char gen_no_fleet[] =
        "#include \"../engine/composition/commands/root.def\"\n"
        "#include \"../engine/composition/commands/telemetry/root.def\"\n";
    static const char gen_extra[] =
        "#include \"../engine/composition/commands/root.def\"\n"
        "#include \"../engine/composition/commands/fleet.def\"\n"
        "#include \"../engine/composition/commands/telemetry/root.def\"\n"
        "#include \"../engine/composition/commands/plugin.def\"\n";
    static const char src_direct[] =
        "#include \"../commands/catalog.def\"\n#include \"../commands/catalog.def\"\n"
        "#include \"../commands/fleet.def\"\n";
    static const char src_once[] = "#include \"../commands/catalog.def\"\n";
    static const char bud_direct[] = "#include \"commands/root.def\"\n";
    static const char cat_small[] = "#include \"root.def\"\n";
    const struct crm_case cases[] = {
        { "clean tree", crm_cat, crm_src, crm_bud, crm_gen, 0, NULL },
        { "generator omits a room", crm_cat, crm_src, crm_bud, gen_no_fleet, 1,
          "Runtime rooms missing from generator" },
        { "generator names an extra room", crm_cat, crm_src, crm_bud, gen_extra,
          1, "Generator rooms absent from runtime" },
        { "runtime names a room directly", crm_cat, src_direct, crm_bud, crm_gen,
          1, "command_catalog.c must include" },
        { "runtime expands the manifest once", crm_cat, src_once, crm_bud,
          crm_gen, 1, "exactly 2 time(s)" },
        { "budget helper names a room directly", crm_cat, crm_src, bud_direct,
          crm_gen, 1, "check_describe_budget.c must include" },
        { "catalog below the floor", cat_small, crm_src, crm_bud, crm_gen, 2,
          "below the floor" },
    };
    int rc = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        rc |= crm_run_case(&cases[i]);
    if (rc == 0)
        fputs("check-catalog-rooms selftest: PASS — a clean tree passes; an "
              "omitted room, an extra room, a directly included room and a "
              "catalog below the floor refuse\n", stdout);
    return rc;
}
