/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: C23 lint gate — check-remote-command-classes. Byte-parity port
 * of tools/lint/check_remote_command_classes.sh (at 89fca9905), which used
 * to reach through two standalone awk helper programs (now retired — see
 * gate_remote_command_classes_parse.c). Every command leaf in the typed
 * registry (every .def file under engine/composition/commands/) and the
 * flat agent-contract table (cognition/controllers/include/controllers/
 * agent_contracts.def) must carry exactly one row in
 * engine/composition/remote_command_classes.def, naming a known class
 * token, and (when the class permits remote reach) a non-empty reason.
 * There is no baseline: the tree is clean, and a shrink-only ratchet here
 * would only be a place to hide the next omission.
 *
 * Gates: check-remote-command-classes
 * Single-gate family (the port's _parse.c and _selftest.c siblings share
 * this subject and are not reused by any other gate).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_remote_command_classes_priv.h"

static const char k_gate[] = "check_remote_command_classes";
enum { RCC_TYPED_FLOOR = 500, RCC_AGENT_FLOOR = 25 };

struct rcc_ctx {
    const char *def_dir, *agent_def, *table;
    int typed_floor, agent_floor;
};

static int rcc_readable(const char *path)
{
    return access(path, R_OK) == 0;
}

/* Up-front FATAL guards: a missing table or agent-contract file must never
 * report a confident "clean" over nothing classified. */
static int rcc_prereq(const struct rcc_ctx *c, FILE *err)
{
    if (!rcc_readable(c->table)) {
        fprintf(err, "%s: FATAL — class table missing or unreadable: %s\n",
                k_gate, c->table);
        fputs("  Refusing to report 'clean' with nothing classified.\n", err);
        return 2;
    }
    if (!rcc_readable(c->agent_def)) {
        fprintf(err, "%s: FATAL — agent-contract table missing: %s\n",
                k_gate, c->agent_def);
        return 2;
    }
    return 0;
}

static int rcc_print_list(FILE *out, const struct rcc_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        if (fprintf(out, "    %s\n", l->v[i]) < 0)
            return die("z23-lint: write failed\n", "");
    return 0;
}

/* comm -23 registry classified — registry entries with no row (defect A). */
static int rcc_check_unclassified(const struct rcc_list *registry,
                                  const struct rcc_list *classified,
                                  const char *table, FILE *err, int *fail)
{
    struct rcc_list miss = { NULL, 0, 0 };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < registry->n; i++)
        if (!rcc_has(classified, registry->v[i]))
            rc = rcc_push(&miss, registry->v[i], strlen(registry->v[i]));
    if (rc == 0 && miss.n) {
        *fail = 1;
        fprintf(err, "%s: FAIL — command leaves with no remote class:\n",
                k_gate);
        rc = rcc_print_list(err, &miss);
        fprintf(err, "  Add one REMOTE_COMMAND_CLASS row per leaf to %s.\n",
                table);
        fputs("  A new command leaf is a new remote-authority decision; "
              "make it.\n", err);
    }
    rcc_free(&miss);
    return rc;
}

/* comm -13 registry classified — rows naming a leaf that does not exist
 * (defect B). */
static int rcc_check_orphans(const struct rcc_list *registry,
                             const struct rcc_list *classified,
                             const char *table, FILE *err, int *fail)
{
    struct rcc_list orph = { NULL, 0, 0 };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < classified->n; i++)
        if (!rcc_has(registry, classified->v[i]))
            rc = rcc_push(&orph, classified->v[i], strlen(classified->v[i]));
    if (rc == 0 && orph.n) {
        *fail = 1;
        fprintf(err, "%s: FAIL — class table names leaves the registry "
                "does not have:\n", k_gate);
        rc = rcc_print_list(err, &orph);
        fprintf(err, "  Delete the stale rows from %s (or fix the "
                "rename).\n", table);
        fputs("  A row with no leaf is a permission with no owner.\n", err);
    }
    rcc_free(&orph);
    return rc;
}

/* uniq -d on the sorted (non-deduped) classified leaves — a leaf row seen
 * more than once (defect: two rows is two decisions). */
static int rcc_check_dupes(const struct rcc_list *classified_all, FILE *err,
                           int *fail)
{
    struct rcc_list all = { NULL, 0, 0 };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < classified_all->n; i++)
        rc = rcc_push(&all, classified_all->v[i], strlen(classified_all->v[i]));
    if (rc)
        goto out;
    rcc_sort(&all);
    struct rcc_list dupes = { NULL, 0, 0 };
    for (size_t i = 0; rc == 0 && i + 1 < all.n; i++) {
        if (strcmp(all.v[i], all.v[i + 1]) == 0
            && (dupes.n == 0 || strcmp(dupes.v[dupes.n - 1], all.v[i]) != 0))
            rc = rcc_push(&dupes, all.v[i], strlen(all.v[i]));
    }
    if (rc == 0 && dupes.n) {
        *fail = 1;
        fprintf(err, "%s: FAIL — leaves classified more than once:\n",
                k_gate);
        rc = rcc_print_list(err, &dupes);
        fputs("  Exactly one row per leaf; two rows is two decisions.\n",
              err);
    }
    rcc_free(&dupes);
out:
    rcc_free(&all);
    return rc;
}

static int rcc_known_class(const char *cls)
{
    return strcmp(cls, "REMOTE_CLASS_NEVER") == 0
        || strcmp(cls, "REMOTE_CLASS_OWNER_CAPABILITY") == 0
        || strcmp(cls, "REMOTE_CLASS_READ_ONLY") == 0;
}

static int rcc_blank(const char *s)
{
    for (; *s; s++)
        if (!isspace((unsigned char)*s))
            return 0;
    return 1;
}

/* (4) unknown class token, and (5) a permitting class with no stated
 * reason. Both walk the rows in TABLE file order, matching the awk. */
static int rcc_permits(const char *cls)
{
    return strcmp(cls, "REMOTE_CLASS_OWNER_CAPABILITY") == 0
        || strcmp(cls, "REMOTE_CLASS_READ_ONLY") == 0;
}

/* (4) unknown class token. */
static int rcc_check_bad_class(const struct rcc_rows *rows, FILE *err,
                               int *fail)
{
    int any_bad = 0;
    for (size_t i = 0; i < rows->n; i++)
        if (!rcc_known_class(rows->v[i].cls))
            any_bad = 1;
    if (!any_bad)
        return 0;
    *fail = 1;
    fprintf(err, "%s: FAIL — rows with an unknown class token:\n", k_gate);
    for (size_t i = 0; i < rows->n; i++)
        if (!rcc_known_class(rows->v[i].cls)
            && fprintf(err, "    %s  (class: %s)\n", rows->v[i].leaf,
                      rows->v[i].cls) < 0)
            return die("z23-lint: write failed\n", "");
    fputs("  Use REMOTE_CLASS_NEVER, REMOTE_CLASS_OWNER_CAPABILITY or\n"
          "  REMOTE_CLASS_READ_ONLY.\n", err);
    return 0;
}

/* (5) a permitting class with no stated reason. */
static int rcc_check_no_reason(const struct rcc_rows *rows, FILE *err,
                               int *fail)
{
    int any_noreason = 0;
    for (size_t i = 0; i < rows->n; i++)
        if (rcc_permits(rows->v[i].cls) && rcc_blank(rows->v[i].reason))
            any_noreason = 1;
    if (!any_noreason)
        return 0;
    *fail = 1;
    fprintf(err, "%s: FAIL — remotable leaves with no stated reason:\n",
            k_gate);
    for (size_t i = 0; i < rows->n; i++)
        if (rcc_permits(rows->v[i].cls) && rcc_blank(rows->v[i].reason)
            && fprintf(err, "    %s  (%s)\n", rows->v[i].leaf,
                      rows->v[i].cls) < 0)
            return die("z23-lint: write failed\n", "");
    fputs("  Refusing needs no defence; permitting does. Say why.\n", err);
    return 0;
}

static int rcc_check_class_rows(const struct rcc_rows *rows, FILE *err,
                                int *fail)
{
    int rc = rcc_check_bad_class(rows, err, fail);
    if (rc == 0)
        rc = rcc_check_no_reason(rows, err, fail);
    return rc;
}

/* (6) a row that would not compile as two C string literals. */
static int rcc_check_malformed(const struct rcc_rows *rows, FILE *err,
                               int *fail)
{
    int any = 0;
    for (size_t i = 0; i < rows->n; i++)
        if (!rows->v[i].wellformed)
            any = 1;
    if (!any)
        return 0;
    *fail = 1;
    fprintf(err, "%s: FAIL — rows that are not two well-formed C string "
            "literals:\n", k_gate);
    for (size_t i = 0; i < rows->n; i++)
        if (!rows->v[i].wellformed
            && fprintf(err, "    %s\n", rows->v[i].leaf) < 0)
            return die("z23-lint: write failed\n", "");
    fputs("  A row is REMOTE_COMMAND_CLASS(\"leaf\", CLASS, \"reason\") and "
          "holds\n  exactly two string literals. Escape or remove quotes in "
          "the reason;\n  this table has to compile the day something "
          "includes it.\n", err);
    return 0;
}

struct rcc_data {
    struct rcc_list typed, agent, registry, classified_all, classified;
    struct rcc_rows rows;
};

static void rcc_data_free(struct rcc_data *d)
{
    rcc_free(&d->typed);
    rcc_free(&d->agent);
    rcc_free(&d->registry);
    rcc_free(&d->classified_all);
    rcc_free(&d->classified);
    rcc_rows_free(&d->rows);
}

/* Source A + B: gather the typed registry and the agent-contract table,
 * enforce their hollow-scan floors, and build the union registry. */
static int rcc_gather_registry(const struct rcc_ctx *c, struct rcc_data *d)
{
    int typed_files = 0;
    int rc = rcc_leaf_dir(c->def_dir, &d->typed, &typed_files);
    if (rc)
        return rc;
    char hint[256];
    snprintf(hint, sizeof hint, "no *.def under: %s", c->def_dir);
    rc = gate_require_scanned(typed_files, 1, k_gate, hint);
    if (rc)
        return rc;
    rc = gate_require_scanned((int)d->typed.n, c->typed_floor, k_gate,
        "typed leaf population collapsed under floor — parser or catalog "
        "broke");
    if (rc)
        return rc;
    rc = rcc_agent_defs(c->agent_def, &d->agent);
    if (rc)
        return rc;
    snprintf(hint, sizeof hint,
             "AGENT_CONTRACT population collapsed under floor: %s",
             c->agent_def);
    rc = gate_require_scanned((int)d->agent.n, c->agent_floor, k_gate, hint);
    if (rc)
        return rc;
    for (size_t i = 0; rc == 0 && i < d->typed.n; i++)
        rc = rcc_add_uniq(&d->registry, d->typed.v[i], strlen(d->typed.v[i]));
    for (size_t i = 0; rc == 0 && i < d->agent.n; i++)
        rc = rcc_add_uniq(&d->registry, d->agent.v[i], strlen(d->agent.v[i]));
    if (rc == 0)
        rcc_sort(&d->registry);
    return rc;
}

/* Source C: the class table, plus its hollow-scan floor and the two
 * derived leaf lists (all rows, and the deduped/sorted set). */
static int rcc_gather_table(const struct rcc_ctx *c, struct rcc_data *d)
{
    int rc = rcc_table_rows(c->table, &d->rows);
    if (rc)
        return rc;
    rc = gate_require_scanned((int)d->rows.n, 1, k_gate,
        "class table parsed to zero rows");
    if (rc)
        return rc;
    for (size_t i = 0; rc == 0 && i < d->rows.n; i++)
        rc = rcc_push(&d->classified_all, d->rows.v[i].leaf,
                      strlen(d->rows.v[i].leaf));
    for (size_t i = 0; rc == 0 && i < d->rows.n; i++)
        rc = rcc_add_uniq(&d->classified, d->rows.v[i].leaf,
                          strlen(d->rows.v[i].leaf));
    if (rc == 0)
        rcc_sort(&d->classified);
    return rc;
}

static int rcc_judge(const struct rcc_ctx *c, struct rcc_data *d, FILE *err,
                     int *fail)
{
    int rc = rcc_check_unclassified(&d->registry, &d->classified, c->table,
                                    err, fail);
    if (rc == 0)
        rc = rcc_check_orphans(&d->registry, &d->classified, c->table, err,
                               fail);
    if (rc == 0)
        rc = rcc_check_dupes(&d->classified_all, err, fail);
    if (rc == 0)
        rc = rcc_check_class_rows(&d->rows, err, fail);
    if (rc == 0)
        rc = rcc_check_malformed(&d->rows, err, fail);
    return rc;
}

static int rcc_run_gate(const struct rcc_ctx *c, FILE *out, FILE *err)
{
    int rc = rcc_prereq(c, err);
    if (rc)
        return rc;

    struct rcc_data d;
    memset(&d, 0, sizeof d);
    rc = rcc_gather_registry(c, &d);
    if (rc == 0)
        rc = rcc_gather_table(c, &d);

    int fail = 0;
    if (rc == 0)
        rc = rcc_judge(c, &d, err, &fail);

    if (rc == 0 && !fail) {
        if (fprintf(out, "%s: OK — %zu rows cover %zu command leaves "
                    "(%zu typed, %zu agent-contract).\n", k_gate, d.rows.n,
                    d.registry.n, d.typed.n, d.agent.n) < 0)
            rc = die("z23-lint: write failed\n", "");
    } else if (rc == 0) {
        rc = 1;
    }

    rcc_data_free(&d);
    return rc;
}

int check_remote_command_classes_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct rcc_ctx c = {
        .def_dir = env_or("ZCL_REMOTE_CLASS_DEF_DIR",
                          "engine/composition/commands"),
        .agent_def = env_or("ZCL_REMOTE_CLASS_AGENT_DEF",
                            "cognition/controllers/include/controllers/"
                            "agent_contracts.def"),
        .table = env_or("ZCL_REMOTE_CLASS_TABLE",
                        "engine/composition/remote_command_classes.def"),
        .typed_floor = RCC_TYPED_FLOOR,
        .agent_floor = RCC_AGENT_FLOOR,
    };
    return rcc_run_gate(&c, stdout, stderr);
}

/* Exposed for the _selftest.c sibling, which re-invokes the gate against
 * planted miniature fixtures. The shell selftest drops TYPED_FLOOR/
 * AGENT_FLOOR to 1 in-process before calling run_gate on its mini
 * registry; the port carries the same two floors through the ctx instead
 * of a compile-time constant so the selftest can do the same without
 * touching the production defaults. */
int rcc_run_gate_for_selftest(const char *def_dir, const char *agent_def,
                              const char *table, int typed_floor,
                              int agent_floor, FILE *out, FILE *err)
{
    struct rcc_ctx c = { .def_dir = def_dir, .agent_def = agent_def,
                         .table = table, .typed_floor = typed_floor,
                         .agent_floor = agent_floor };
    return rcc_run_gate(&c, out, err);
}
