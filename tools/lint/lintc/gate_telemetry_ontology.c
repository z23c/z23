/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-telemetry-ontology — every network telemetry field a
 * covered dump function emits must carry a MEANING row in the ontology.
 * Ported from tools/lint/check_telemetry_ontology.sh (deleted). This file
 * holds the entry point, the shared line-reader / violation-list helpers and
 * the top-level phase orchestration; the ontology/domain/paste parsing lives
 * in gate_telemetry_ontology_onto.c and the manifest/emission/table/fill
 * scanning in gate_telemetry_ontology_scan.c. Selftest:
 * gate_telemetry_ontology_selftest.c.
 *
 * The shell original required tools/lint/telemetry_scan_lib.awk to be
 * readable because that awk program WAS the emission slicer; the slicer is
 * now compiled C, so that one readability check has no equivalent here and
 * is deliberately dropped. Every other input, floor, message and exit code
 * is ported verbatim. Fail closed throughout: an unreadable input or a
 * function the slicer cannot find is exit 2, never a skip or a pass.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_telemetry_ontology_priv.h"

static struct to_state g_to;

/* getenv with the shell ${VAR-default} semantics: a set-but-EMPTY value is
 * honoured (it means "point the scan at nothing" and must fail loudly). */
static const char *to_dash(const char *v, const char *dflt)
{
    return v ? v : dflt;
}

int to_readable(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    fclose(f);
    return 1;
}

/* Reads path line by line (newline stripped; a final unterminated line is
 * delivered too), calling cb(ctx, line, len). Returns 0 ok, 1 unreadable,
 * 2 error (cb returned non-zero, read error, or a line over TO_LINE — a
 * truncated needle or key could turn a violation into a pass, so an
 * over-long line is a loud failure, never a silent cut). */
static int to_each_flush(char *buf, size_t n, int over, const char *path,
                         FILE *err, int (*cb)(void *, const char *, size_t),
                         void *ctx)
{
    if (over) {
        if (err)
            fprintf(err, "%s: line exceeds %d in %s\n", TO_GATE, TO_LINE,
                    path);
        return 2;
    }
    buf[n] = '\0';
    return cb(ctx, buf, n) ? 2 : 0;
}

int to_each_line(const char *path, FILE *err,
                 int (*cb)(void *, const char *, size_t), void *ctx)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 1;
    char buf[TO_LINE];
    size_t n = 0;
    int rc = 0, over = 0, c;
    while (rc == 0 && (c = fgetc(f)) != EOF) {
        if (c == '\n') {
            rc = to_each_flush(buf, n, over, path, err, cb, ctx);
            n = 0;
            over = 0;
        } else if (n + 1 < sizeof buf) {
            buf[n++] = (char)c;
        } else {
            over = 1;
        }
    }
    if (rc == 0 && (n > 0 || over))
        rc = to_each_flush(buf, n, over, path, err, cb, ctx);
    if (rc == 0 && ferror(f)) {
        if (err)
            fprintf(err, "%s: read error on %s\n", TO_GATE, path);
        rc = 2;
    }
    fclose(f);
    return rc;
}

int to_viol_add(struct to_viol *v, FILE *err, const char *fmt, ...)
{
    if (v->n >= TO_MAX_VIOL) {
        fprintf(err, "%s: violation list exceeds %d\n", TO_GATE, TO_MAX_VIOL);
        return 2;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(v->line[v->n], TO_VIOL, fmt, ap);
    va_end(ap);
    if (ovf(n, TO_VIOL)) {
        fprintf(err, "%s: violation line exceeds %d\n", TO_GATE, TO_VIOL);
        return 2;
    }
    v->n++;
    return 0;
}

int to_viol_has(const struct to_viol *v, const char *needle)
{
    for (int i = 0; i < v->n; i++)
        if (strstr(v->line[i], needle))
            return 1;
    return 0;
}

void to_viol_print(FILE *f, const struct to_viol *v)
{
    for (int i = 0; i < v->n; i++)
        fprintf(f, "%s\n", v->line[i]);
}

/* Required-input readability, matching the shell prologue. */
static int to_inputs(struct to_state *st)
{
    const char *req[3] = { st->manifest_path, st->onto_path,
                           st->domains_path };
    for (int i = 0; i < 3; i++)
        if (!to_readable(req[i])) {
            fprintf(st->err,
                    "%s: FATAL — required input missing or unreadable: %s\n",
                    TO_GATE, req[i]);
            return 2;
        }
    if (st->extra_path[0] && !to_readable(st->extra_path)) {
        fprintf(st->err,
                "%s: FATAL — ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST is set but\n"
                "  unreadable: %s\n",
                TO_GATE, st->extra_path);
        return 2;
    }
    return 0;
}

int to_check(FILE *out, FILE *err)
{
    struct to_state *st = &g_to;
    memset(st, 0, sizeof *st);
    st->out = out;
    st->err = err;
    st->manifest_path = to_dash(getenv("ZCL_TELEMETRY_SCAN_MANIFEST"),
                                    "tools/lint/telemetry_ontology_scan.txt");
    st->extra_path = getenv("ZCL_TELEMETRY_SCAN_EXTRA_MANIFEST");
    if (!st->extra_path)
        st->extra_path = "";
    st->onto_path = to_dash(
        getenv("ZCL_TELEMETRY_ONTOLOGY_DEF"),
        "platform/modules/util/include/util/telemetry_ontology.def");
    st->domains_path = to_dash(
        getenv("ZCL_TELEMETRY_DOMAINS_DEF"),
        "platform/modules/util/include/util/telemetry_domains.def");
    st->fields_dir = to_dash(
        getenv("ZCL_TELEMETRY_FIELDS_DIR"),
        "platform/modules/util/include/util/telemetry");
    st->tu_path = to_dash(
        getenv("ZCL_TELEMETRY_ONTOLOGY_TU"),
        "platform/modules/util/src/telemetry_ontology.c");
    st->fill_count_path = to_dash(getenv("ZCL_TELEMETRY_FILL_PROVIDER_COUNT"),
                                      "tools/lint/telemetry_fill_provider_count.txt");
    st->fill_roots =
        env_or("ZCL_TELEMETRY_FILL_SCAN_ROOTS", "core engine contexts cognition platform");
    st->mode = env_or("ZCL_LINT_MODE", "FAIL");
    int rc = to_inputs(st);
    if (!rc)
        rc = to_phase_onto(st);
    if (!rc)
        rc = to_phase_manifest(st);
    if (!rc)
        rc = to_phase_scan(st);
    if (!rc)
        rc = to_phase_tables(st);
    if (!rc)
        rc = to_verdict(st);
    return rc;
}

int check_telemetry_ontology_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return to_check(stdout, stderr);
}
