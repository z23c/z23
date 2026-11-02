/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-hidden-return-under-lock
 * (gate_hidden_return_under_lock.c). Writes one fixture file per case under
 * $HOME/.local/state/zclassic23/scratch (never /tmp) and checks how many
 * findings the scanner reports: a LOG_FAIL inside a locked span is found;
 * the same macro after the unlock, in the failure branch of the acquire,
 * after a trylock, or in a function that took no lock is not.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_hidden_return_under_lock_priv.h"

enum { HRLS_PATH = 1024 };

struct hrls_case {
    const char *name;
    const char *src;
    int want; /* expected findings */
};

static const struct hrls_case k_hrls_cases[] = {
    { "LOG_FAIL inside a locked span is found",
      "bool f(struct w *w)\n{\n    zcl_mutex_lock(&w->cs);\n"
      "    if (bad)\n        LOG_FAIL(\"x\", \"bad\");\n"
      "    zcl_mutex_unlock(&w->cs);\n    return true;\n}\n", 1 },
    { "GUARD_NOT_NULL under pthread rwlock is found",
      "int f(struct w *w)\n{\n    pthread_rwlock_rdlock(&w->rw);\n"
      "    GUARD_NOT_NULL(w->p, \"x\", \"p\");\n"
      "    pthread_rwlock_unlock(&w->rw);\n    return 0;\n}\n", 1 },
    { "LOG_RETURN with the lock taken in a nested block is found",
      "int f(struct w *w)\n{\n    if (w) {\n"
      "        pthread_mutex_lock(&w->m);\n"
      "        LOG_RETURN(-1, \"x\", \"bad\");\n    }\n    return 0;\n}\n", 1 },
    { "LOG_FAIL after the unlock is clean",
      "bool f(struct w *w)\n{\n    zcl_mutex_lock(&w->cs);\n    w->n++;\n"
      "    zcl_mutex_unlock(&w->cs);\n"
      "    if (bad)\n        LOG_FAIL(\"x\", \"bad\");\n    return true;\n}\n", 0 },
    { "LOG_FAIL in the lock-failure branch is clean",
      "bool f(struct w *w)\n{\n"
      "    if (pthread_mutex_lock(&w->m) != 0)\n"
      "        LOG_FAIL(\"x\", \"lock\");\n"
      "    pthread_mutex_unlock(&w->m);\n    return true;\n}\n", 0 },
    { "LOG_FAIL in a braced lock-failure branch is clean",
      "bool f(struct w *w)\n{\n"
      "    if (pthread_mutex_lock(&w->m) != 0) {\n"
      "        LOG_FAIL(\"x\", \"lock\");\n    }\n"
      "    pthread_mutex_unlock(&w->m);\n    return true;\n}\n", 0 },
    { "LOG_FAIL after a stored lock result test is clean",
      "bool f(struct w *w)\n{\n"
      "    int rc = pthread_mutex_lock(&w->m);\n"
      "    if (rc != 0)\n        LOG_FAIL(\"x\", \"lock\");\n"
      "    pthread_mutex_unlock(&w->m);\n    return true;\n}\n", 0 },
    { "LOG_FAIL after the success branch of the acquire is found",
      "bool f(struct w *w)\n{\n"
      "    if (pthread_mutex_lock(&w->m) != 0)\n        return false;\n"
      "    LOG_FAIL(\"x\", \"held\");\n"
      "    pthread_mutex_unlock(&w->m);\n    return true;\n}\n", 1 },
    { "LOG_FAIL after a trylock is clean",
      "bool f(struct w *w)\n{\n"
      "    if (pthread_mutex_trylock(&w->m) != 0)\n        return false;\n"
      "    LOG_FAIL(\"x\", \"try\");\n    return true;\n}\n", 0 },
    { "LOG_FAIL after a bounded lock is clean",
      "bool f(struct w *w)\n{\n    platform_mutex_lock_bounded_ns(&w->m, 5);\n"
      "    LOG_FAIL(\"x\", \"bounded\");\n    return true;\n}\n", 0 },
    { "a lock in a different function does not leak into the next",
      "void g(struct w *w)\n{\n    zcl_mutex_lock(&w->cs);\n"
      "    zcl_mutex_unlock(&w->cs);\n}\n\n"
      "bool f(struct w *w)\n{\n    LOG_FAIL(\"x\", \"nolock\");\n"
      "    return true;\n}\n", 0 },
    { "an unreleased lock in one function does not leak into the next",
      "void g(struct w *w)\n{\n    zcl_mutex_lock(&w->cs);\n}\n\n"
      "bool f(struct w *w)\n{\n    LOG_FAIL(\"x\", \"nolock\");\n"
      "    return true;\n}\n", 0 },
    { "LOG_FAIL named only in a comment or string is clean",
      "bool f(struct w *w)\n{\n    zcl_mutex_lock(&w->cs);\n"
      "    /* LOG_FAIL here would leak */\n"
      "    log_line(\"LOG_FAIL\");\n    zcl_mutex_unlock(&w->cs);\n"
      "    return true;\n}\n", 0 },
    { "LOG_ERROR under a lock is clean",
      "bool f(struct w *w)\n{\n    zcl_mutex_lock(&w->cs);\n"
      "    LOG_ERROR(\"x\", \"bad\");\n    zcl_mutex_unlock(&w->cs);\n"
      "    return false;\n}\n", 0 },
};

/* Runs one case; returns 0 when the scanner answered the way it expects. */
static int hrls_run_case(const char *root, const struct hrls_case *c)
{
    char path[HRLS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/case.c", root), sizeof path))
        return 2;
    int rc = csr_write(path, c->src);
    if (rc)
        return rc;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int found = 0;
    rc = hrl_scan_file(path, sink, &found);
    fclose(sink);
    if (rc || found != c->want) {
        fprintf(stderr, "check-hidden-return-under-lock selftest: %s: want "
                "%d finding(s) got %d (rc=%d)\n", c->name, c->want, found, rc);
        return 1;
    }
    printf("  selftest ok: %s (%d)\n", c->name, found);
    return 0;
}

/* A missing file must be an error, never a silent clean scan. */
static int hrls_missing_case(const char *root)
{
    char path[HRLS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/absent.c", root), sizeof path))
        return 2;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int found = 0;
    int rc = hrl_scan_file(path, sink, &found);
    fclose(sink);
    if (rc == 0) {
        fputs("check-hidden-return-under-lock selftest: missing file "
              "scanned clean\n", stderr);
        return 1;
    }
    puts("  selftest ok: a missing file is an error");
    return 0;
}

int check_hidden_return_under_lock_selftest(void)
{
    char root[HRLS_PATH];
    int rc = lct_scratch_dir(root, sizeof root, "hidden-return-under-lock");
    if (rc)
        return rc;
    int bad = 0;
    for (size_t i = 0; i < sizeof k_hrls_cases / sizeof k_hrls_cases[0]; i++)
        bad |= hrls_run_case(root, &k_hrls_cases[i]) != 0;
    bad |= hrls_missing_case(root) != 0;
    rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_hidden_return_under_lock selftest\n", stderr);
    return st_ok(bad, "check-hidden-return-under-lock selftest: OK\n");
}
