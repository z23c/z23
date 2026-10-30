/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-lib-module-order
 * (gate_lib_module_order.c). The shell script had no self-test mode, so
 * this proves one passing and several failing shapes against a fixture
 * tree under the lint scratch area: a cold tree reports NOT MEASURED
 * (exit 0); a forward edge passes; an unbaselined back edge fails; a
 * baselined back edge passes; an undeclared graph module fails; a .def
 * that disagrees with the tree fails; a baseline keyed to another tree
 * fails. The graph tool is a stub script driven through the
 * ZCL_LINKGRAPH_OBJ_DIR seam.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_lib_module_order_priv.h"

enum { LMOS_PATH = 1024, LMOS_TEXT = 2048 };

static const char k_lmos_stub[] =
    "#!/bin/sh\n"
    "[ \"$1\" = \"--summary\" ] || exit 3\n"
    "d=\"$3\"\n"
    "[ -f \"$d/edges.txt\" ] || exit 1\n"
    "cat \"$d/edges.txt\"\n"
    "exit 0\n";

struct lmos_case {
    const char *name;
    const char *extra_def; /* extra LIB_MODULE line, "" for none */
    const char *baseline;  /* baseline text; "# ..." headers honored */
    const char *edges;     /* edges.txt text; NULL means cold tree */
    int want;
    const char *want_text; /* substring the report must hold, or NULL */
};

static const struct lmos_case k_lmos_cases[] = {
    { "cold tree is NOT MEASURED (exit 0)", "", "", NULL, 0, NULL },
    { "forward edge passes", "", "",
      "lib/beta -> lib/alpha\t3\tsym\n", 0, NULL },
    { "unbaselined back edge fails", "", "",
      "lib/alpha -> lib/beta\t3\tsym\n", 1, NULL },
    { "baselined back edge passes", "",
      "# measured-from-tree: build/obj\nlib/alpha -> lib/beta\n",
      "lib/alpha -> lib/beta\t3\tsym\n", 0, NULL },
    { "undeclared graph module fails", "", "",
      "lib/gamma -> lib/alpha\t1\ts\n", 1, NULL },
    { "def disagreeing with the tree fails", "LIB_MODULE(\"delta\")\n", "",
      NULL, 1, NULL },
    { "baseline keyed to another tree fails", "",
      "# measured-from-tree: build/test-rel-obj\n", NULL, 1, NULL },
    { "stale baseline entry: ratchet can tighten", "",
      "lib/alpha -> lib/beta\n", "lib/beta -> lib/alpha\t3\tsym\n", 0,
      "ratchet can tighten" },
    { "indented baseline key never matches (still a violation)", "",
      "  lib/alpha -> lib/beta\n", "lib/alpha -> lib/beta\t3\tsym\n", 1,
      "NEW rank violation" },
    { "whitespace-only baseline line counts as a key", "", "   \n",
      "lib/beta -> lib/alpha\t3\tsym\n", 0, "1 baselined" },
    { "unterminated final baseline line is not a key", "",
      "lib/alpha -> lib/beta", "lib/alpha -> lib/beta\t3\tsym\n", 1,
      "NEW rank violation" },
    { "malformed lib edge line fails closed", "", "",
      "lib/alpha\t3\tsym\n", 2, NULL },
};

/* Writes the fixture .def (alpha, beta, plus any extra declaration). */
static int lmos_write_def(const char *root, const char *extra)
{
    char path[LMOS_PATH], text[LMOS_TEXT];
    if (ovf(snprintf(path, sizeof path,
                     "%s/engine/composition/lib_module_order.def", root),
             sizeof path))
        return 2;
    if (ovf(snprintf(text, sizeof text,
                     "/* fixture */\n"
                     "LIB_MODULE(\"alpha\")\n"
                     "LIB_MODULE(\"beta\")\n"
                     "%s", extra), sizeof text))
        return 2;
    return csr_write(path, text);
}

static int lmos_write_baseline(const char *root, const char *body)
{
    char path[LMOS_PATH];
    if (ovf(snprintf(path, sizeof path,
                     "%s/tools/scripts/lib_module_order_baseline.txt", root),
             sizeof path))
        return 2;
    return csr_write(path, body);
}

static int lmos_write_stub(const char *root)
{
    char path[LMOS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/tools/dev/module-linkgraph.sh",
             root), sizeof path))
        return 2;
    int rc = csr_write(path, k_lmos_stub);
    if (rc)
        return rc;
    if (chmod(path, 0755) != 0)
        return die("z23-lint: cannot chmod %s\n", path);
    return 0;
}

/* Lays down the static fixture: Makefile, module dirs, def, stub tool. */
/* Points the shared repo-shape reader at the fixture so the declared-set
 * check reads the fixture's module dirs, Makefile and .def, not the lane's. */
static int lmos_point_repo_shape(const char *root)
{
    char path[LMOS_PATH];
    if (setenv("ZCL_REPO_SHAPE_ROOT", root, 1) != 0)
        return 2;
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
        return 2;
    if (setenv("ZCL_REPO_SHAPE_MAKEFILE", path, 1) != 0)
        return 2;
    if (ovf(snprintf(path, sizeof path, "%s/engine/composition/"
                     "lib_module_order.def", root), sizeof path))
        return 2;
    return setenv("ZCL_REPO_SHAPE_MODULE_DEF", path, 1) != 0 ? 2 : 0;
}

static int lmos_fixture(const char *root)
{
    static const char *const dirs[] = {
        "core/fixture/modules/alpha", "core/fixture/modules/beta",
        "contexts/wallet",
        "build/obj",
    };
    char path[LMOS_PATH];
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        if (ovf(snprintf(path, sizeof path, "%s/%s", root, dirs[i]),
                 sizeof path))
            return 2;
        int rc = csr_mkdirs(path);
        if (rc)
            return rc;
    }
    if (ovf(snprintf(path, sizeof path, "%s/Makefile", root), sizeof path))
        return 2;
    int rc = csr_write(path, "PRODUCT_CONTEXTS = wallet\nAPP_DIRS = app\n");
    if (rc)
        return rc;
    rc = lmos_write_def(root, "");
    if (rc)
        return rc;
    rc = lmos_write_baseline(root, "");
    if (rc)
        return rc;
    rc = lmos_write_stub(root);
    return rc ? rc : lmos_point_repo_shape(root);
}

/* Arms or disarms the object tree and the env seam for one case. */
static int lmos_arm(const char *root, const struct lmos_case *c)
{
    char edges[LMOS_PATH];
    if (ovf(snprintf(edges, sizeof edges, "%s/build/obj/edges.txt", root),
             sizeof edges))
        return 2;
    if (c->edges) {
        int rc = csr_write(edges, c->edges);
        if (rc)
            return rc;
    } else {
        (void)unlink(edges);
    }
    char dir[LMOS_PATH];
    if (ovf(snprintf(dir, sizeof dir, "%s/build/obj", root), sizeof dir))
        return 2;
    return setenv("ZCL_LINKGRAPH_OBJ_DIR", dir, 1) != 0 ? 2 : 0;
}

static int lmos_run_case_in(const char *root, const struct lmos_case *c);

/* Runs one case from inside the fixture root: the gate reads its object
 * tree and tool relative to the working directory, as the shell did. */
static int lmos_run_case(const char *root, const struct lmos_case *c)
{
    char saved[LMOS_PATH];
    if (!getcwd(saved, sizeof saved) || chdir(root) != 0) {
        fputs("check_lib_module_order selftest: cannot enter fixture\n",
              stderr);
        return 2;
    }
    int rc = lmos_run_case_in(root, c);
    if (chdir(saved) != 0) {
        fputs("check_lib_module_order selftest: cannot leave fixture\n",
              stderr);
        return 2;
    }
    return rc;
}

/* Runs one case; returns 0 when the gate answered as expected. */
static int lmos_run_case_in(const char *root, const struct lmos_case *c)
{
    int rc = lmos_write_def(root, c->extra_def);
    if (rc == 0)
        rc = lmos_write_baseline(root, c->baseline);
    if (rc == 0)
        rc = lmos_arm(root, c);
    if (rc)
        return rc;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int got = lmo_check_root(root, sink);
    rewind(sink);
    char buf[LMOS_TEXT];
    size_t n = fread(buf, 1, sizeof buf - 1, sink);
    buf[n] = '\0';
    fclose(sink);
    if (got != c->want) {
        fprintf(stderr, "check_lib_module_order selftest: %s: want rc=%d "
                "got rc=%d\n", c->name, c->want, got);
        fputs(buf, stderr);
        return 1;
    }
    if (c->want_text && !strstr(buf, c->want_text)) {
        fprintf(stderr, "check_lib_module_order selftest: %s: report lacks "
                "\"%s\"\n", c->name, c->want_text);
        fputs(buf, stderr);
        return 1;
    }
    if (got == 0 && c->edges && !strstr(buf, "clean — ")) {
        fprintf(stderr, "check_lib_module_order selftest: %s: clean line "
                "missing from report\n", c->name);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", c->name, got);
    return 0;
}

int check_lib_module_order_selftest(void)
{
    char root[LMOS_PATH];
    int rc = lct_scratch_dir(root, sizeof root, "lib-module-order");
    if (rc)
        return rc;
    rc = lmos_fixture(root);
    int bad = 0;
    if (rc == 0)
        for (size_t i = 0; i < sizeof k_lmos_cases / sizeof k_lmos_cases[0];
             i++)
            bad |= lmos_run_case(root, &k_lmos_cases[i]) != 0;
    else
        bad = 1;
    (void)unsetenv("ZCL_LINKGRAPH_OBJ_DIR");
    rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_lib_module_order selftest\n", stderr);
    return st_ok(bad, "check-lib-module-order selftest: OK\n");
}
