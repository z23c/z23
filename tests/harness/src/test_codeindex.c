/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_codeindex — the cognition/modules/codeindex/ foundation gate.
 *
 * Coverage:
 *   1. build determinism           — same tree ⇒ byte-identical symbol dump.
 *   2. query correctness           — known sym / file / group / refs answers.
 *   3. rebuild-from-scratch identity — delete store, reopen, same dump.
 *   4. staleness ⇒ auto-rebuild    — edit a file, reopen, edit is reflected.
 *   5. verify-on-read              — a corrupted symbol row is rejected.
 *   6. group parity                — scanner module list == the lib/ tree
 *                                    on disk, and the eight app/ shapes.
 *   7. file counts + route parity  — recursive vs direct group file counts, and
 *                                    `code tests` route == `dev test plan`
 *                                    proof_group for the same single file.
 *   8. complete source roots       — physical authorities and conventional
 *                                    package workspaces are indexed, fixtures
 *                                    are pruned, and C23 stays distinct from .def.
 *   9. publication safety          — content freshness, old-reader retention,
 *                                    crash boundaries, and 32-way cold open.
 *
 * All scratch work happens under ./test-tmp/ (project no-/tmp convention). */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_context.h"
#include "codeindex/codeindex_merkle.h"
#include "platform/time_compat.h"
#include "test/test_timing_budget.h"

/* For the routing-link parity invariant (case 7): `code tests <path>`'s route
 * (tools/command/native_code_command.c) must equal `dev test plan`'s
 * proof_group (tools/dev/devloop_plan.c) for the same single changed file. */
#include "command/native_command.h"
#include "devloop.h"
#include "services/zcode_goal_context_service.h"
#include "base/hex.h"
#include "json/json.h"
#include "sha3/sha3.h"
#include "crypto/sha256.h"
#include "util/file_io.h"
#include "vcs/vcs_manifest.h"

#include <sqlite3.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/resource.h>
#endif
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <time.h>
#include <unistd.h>
#if !defined(_WIN32)

#define CI_CHECK(name, expr) do {                                     \
    if (expr) { printf("  codeindex: %s... OK\n", (name)); }          \
    else { printf("  codeindex: %s... FAIL\n", (name)); failures++; } \
} while (0)

#define FIX "test-tmp/ci_fix"
#define MET_FIX "test-tmp/ci_metrics"

/* The fixture mirrors the real object layout: every depfile the build writes
 * lands in a per-build compile epoch, `<object-root>/.current-epoch` names the
 * live one, and older generations stay on disk beside it. `build/obj` is an
 * epoch-managed root here; `build/test-obj` is a plain one. */
#define CUR_EPOCH \
    "1111111111111111111111111111111111111111111111111111111111111111"
#define RETAINED_EPOCH \
    "2222222222222222222222222222222222222222222222222222222222222222"
#define CUR_EPOCH_DEP "build/obj/epochs/" CUR_EPOCH "/foo.d"
#define RETAINED_EPOCH_DEP "build/obj/epochs/" RETAINED_EPOCH "/foo.d"

/* Write content to <dir>/<rel>, creating parent dirs. */
static bool mk_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    /* create every parent component, including the fixture root itself */
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    fclose(f);
    return true;
}

static const char *FOO_C =
    "/* net/foo.c — fixture translation unit for the code index test. */\n"
    "#include \"net/foo.h\"\n"
    "\n"
    "#define FOO_MAX 128\n"
    "\n"
    "/* A private accumulator helper. */\n"
    "static int helper_add(int a, int b)\n"
    "{\n"
    "    return a + b;\n"
    "}\n"
    "\n"
    "struct foo_state { int count; };\n"
    "\n"
    "typedef struct { int a; int b; } foo_pair;\n"
    "\n"
    "enum foo_color { FOO_RED, FOO_GREEN };\n"
    "\n"
    "/* Entry point that does a little work. */\n"
    "int foo_main(int x)\n"
    "{\n"
    "    int y = helper_add(x, 1);\n"
    "    int c = foo_checksum(0, 0);\n"
    "    return c + y;\n"
    "}\n"
    "\n"
    "#ifdef FOO_DEBUG\n"
    "void foo_debug(void)\n"
    "{\n"
    "    helper_add(1, 2);\n"
    "}\n"
    "#endif\n";

static const char *FOO_H =
    "/* net/foo.h — fixture header. */\n"
    "#ifndef NET_FOO_H\n"
    "#define NET_FOO_H\n"
    "\n"
    "#include <stddef.h>\n"
    "\n"
    "struct foo_state;\n"
    "\n"
    "/* Checksum over a data frame. */\n"
    "int foo_checksum(const unsigned char *data, size_t len);\n"
    "\n"
    "#endif\n";

static const char *BAR_H =
    "/* net/bar.h — alternate depfile fixture header. */\n"
    "#ifndef NET_BAR_H\n"
    "#define NET_BAR_H\n"
    "int bar_fixture(void);\n"
    "#endif\n";

/* Purpose-derivation fixtures (§1.1): stem-dashed header, explicit override,
 * and a file whose only comment is interior (no file-level purpose). */
static const char *PURPOSE_STEM_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * purpose_stem \xe2\x80\x94 derives its purpose from the stem header.\n"
    " */\n"
    "int purpose_stem_fn(void) { return 0; }\n";

static const char *PURPOSE_OVERRIDE_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * purpose: explicit override wins.\n"
    " */\n"
    "int purpose_override_fn(void) { return 0; }\n";

static const char *PURPOSE_NONE_C =
    "#include <stddef.h>\n"
    "\n"
    "/* interior helper doc, not a file-level purpose */\n"
    "int purpose_none_fn(void) { return 1; }\n";

static const char *PURPOSE_AFTER_LICENSE_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " * Distributed under the MIT software license, see the accompanying\n"
    " * file COPYING or http://www.opensource.org/licenses/mit-license.php.\n"
    " *\n"
    " * purpose_after_license — describes behavior after the license.\n"
    " */\n"
    "int purpose_after_license_fn(void) { return 0; }\n";

static const char *PURPOSE_LICENSE_ONLY_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " * Distributed under the MIT software license, see the accompanying\n"
    " * file COPYING or http://www.opensource.org/licenses/mit-license.php.\n"
    " */\n"
    "int purpose_license_only_fn(void) { return 0; }\n";

static const char *ROOT_MAIN_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * main — fixture top-level node entry.\n"
    " */\n"
    "int fixture_root_main(void) { return 0; }\n";

static const char *PACKAGE_APP_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " * package_parse_options — fixture package executable parser.\n"
    " */\n"
    "static int package_parse_options(void) { return 0; }\n";

static const char *PACKAGE_HEADER_H =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " * package_api — fixture package public interface.\n"
    " */\n"
    "int package_api(void);\n";

static const char *PACKAGE_TEST_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " * package_cli_test — fixture package executable test.\n"
    " */\n"
    "int package_cli_test(void) { return 0; }\n";

static const char *NESTED_PACKAGE_APP_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " * nested_package_parse_options — fixture repository package parser.\n"
    " */\n"
    "static int nested_package_parse_options(void) { return 0; }\n";

static const char *PORT_H =
    "/* SPDX-License-Identifier: Apache-2.0\n"
    " * Copyright 2026 Rhett Creighton\n"
    " *\n"
    " * fixture_port — fixture hexagonal interface.\n"
    " */\n"
    "int fixture_port_probe(void);\n";

static const char *TEST_SOURCE_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " *\n"
    " * test_fixture_indexed — fixture test translation unit.\n"
    " */\n"
    "int test_fixture_indexed(void) { return 0; }\n";

static const char *EXAMPLE_SOURCE_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " * example_fixture — fixture top-level example.\n"
    " */\n"
    "int example_fixture(void) { return 0; }\n";

static const char *MODULE_EXAMPLE_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " * module_example_fixture — fixture module-local example.\n"
    " */\n"
    "int module_example_fixture(void) { return 0; }\n";

static const char *MODULE_TEST_C =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    " * module_test_fixture — fixture module-local test.\n"
    " */\n"
    "int module_test_fixture(void) { return 0; }\n";

/* Seventeen literal matches prove the goal selector reports its sixteen-hit
 * per-token ceiling. The first sixteen answers remain ordered exactly as the
 * production selector already orders them; only completeness metadata is
 * under test. */
static const char *SATURATION_C =
    "/* core/modules/net/src/saturation.c — literal selection cap fixture. */\n"
    "int saturation_00(void) { return 0; }\n"
    "int saturation_01(void) { return 0; }\n"
    "int saturation_02(void) { return 0; }\n"
    "int saturation_03(void) { return 0; }\n"
    "int saturation_04(void) { return 0; }\n"
    "int saturation_05(void) { return 0; }\n"
    "int saturation_06(void) { return 0; }\n"
    "int saturation_07(void) { return 0; }\n"
    "int saturation_08(void) { return 0; }\n"
    "int saturation_09(void) { return 0; }\n"
    "int saturation_10(void) { return 0; }\n"
    "int saturation_11(void) { return 0; }\n"
    "int saturation_12(void) { return 0; }\n"
    "int saturation_13(void) { return 0; }\n"
    "int saturation_14(void) { return 0; }\n"
    "int saturation_15(void) { return 0; }\n"
    "int saturation_16(void) { return 0; }\n";

/* Call-graph fixture: two callers of one static helper and a call to an
 * external leaf. */
#define CG_FIX "test-tmp/ci_cg"

static const char *CG_C =
    "/* core/modules/net/src/cg.c — call-graph fixture translation unit. */\n"
    "#include \"net/cg.h\"\n"
    "\n"
    "static int cg_helper(int a)\n"
    "{\n"
    "    return a + 1;\n"
    "}\n"
    "\n"
    "int cg_main(int x)\n"
    "{\n"
    "    int y = cg_helper(x);\n"
    "    return cg_leaf(y);\n"
    "}\n"
    "\n"
    "int cg_other(void)\n"
    "{\n"
    "    return cg_helper(0);\n"
    "}\n";

static const char *CG_H =
    "/* core/modules/net/src/cg.h — call-graph fixture header. */\n"
    "#ifndef NET_CG_H\n"
    "#define NET_CG_H\n"
    "int cg_main(int x);\n"
    "int cg_other(void);\n"
    "int cg_leaf(int y);\n"
    "#endif\n";

static bool write_cg_fixture(void)
{
    return mk_write(CG_FIX, "core/modules/net/src/cg.c", CG_C) &&
           mk_write(CG_FIX, "core/modules/net/include/net/cg.h", CG_H) &&
           mk_write(CG_FIX, "build/obj/cg.d",
                    "build/obj/cg.o: core/modules/net/src/cg.c "
                    "core/modules/net/include/net/cg.h\n");
}

/* ── impact-closure fixture (F3) ────────────────────────────────────────
 * Three SEPARATE translation units forming a linear call chain across files:
 *   cl_a.c: cl_a() calls cl_b()   cl_b.c: cl_b() calls cl_c()   cl_c.c: cl_c()
 * so changing cl_c.c's file must impact cl_b.c (direct caller) AND cl_a.c
 * (caller-of-caller), plus cl_c.c itself. */
#define CL_FIX "test-tmp/ci_closure"

static const char *CL_A_C =
    "/* core/modules/net/src/cl_a.c — closure fixture A (top of the chain). */\n"
    "#include \"net/cl.h\"\n"
    "int cl_a(int x)\n"
    "{\n"
    "    return cl_b(x) + 1;\n"
    "}\n";

static const char *CL_B_C =
    "/* core/modules/net/src/cl_b.c — closure fixture B (middle of the chain). */\n"
    "#include \"net/cl.h\"\n"
    "int cl_b(int x)\n"
    "{\n"
    "    return cl_c(x) * 2;\n"
    "}\n";

static const char *CL_C_C =
    "/* core/modules/net/src/cl_c.c — closure fixture C (the changed leaf). */\n"
    "#include \"net/cl.h\"\n"
    "int cl_c(int x)\n"
    "{\n"
    "    return x + 7;\n"
    "}\n";

static const char *CL_H =
    "/* core/modules/net/src/cl.h — closure fixture header. */\n"
    "#ifndef NET_CL_H\n"
    "#define NET_CL_H\n"
    "int cl_a(int x);\n"
    "int cl_b(int x);\n"
    "int cl_c(int x);\n"
    "#endif\n";

static const char *CL_TEST_C =
    "/* terminal proof leaf: the harness calls this, but closure may stop here. */\n"
    "#include \"net/cl.h\"\n"
    "int test_cl(void)\n"
    "{\n"
    "    return cl_a(1);\n"
    "}\n";

static const char *CL_HARNESS_C =
    "int test_cl(void);\n"
    "int cl_harness(void)\n"
    "{\n"
    "    return test_cl();\n"
    "}\n";

static bool write_cl_fixture(void)
{
    return mk_write(CL_FIX, "core/modules/net/src/cl_a.c", CL_A_C) &&
           mk_write(CL_FIX, "core/modules/net/src/cl_b.c", CL_B_C) &&
           mk_write(CL_FIX, "core/modules/net/src/cl_c.c", CL_C_C) &&
           mk_write(CL_FIX, "tests/harness/src/test_cl.c", CL_TEST_C) &&
           mk_write(CL_FIX, "tests/harness/src/test.c", CL_HARNESS_C) &&
           mk_write(CL_FIX, "core/modules/net/include/net/cl.h", CL_H) &&
           mk_write(CL_FIX, "build/obj/cl_a.d",
                    "build/obj/cl_a.o: core/modules/net/src/cl_a.c "
                    "core/modules/net/include/net/cl.h\n") &&
           mk_write(CL_FIX, "build/obj/cl_b.d",
                    "build/obj/cl_b.o: core/modules/net/src/cl_b.c "
                    "core/modules/net/include/net/cl.h\n") &&
           mk_write(CL_FIX, "build/obj/cl_c.d",
                    "build/obj/cl_c.o: core/modules/net/src/cl_c.c "
                    "core/modules/net/include/net/cl.h\n");
}

static bool cl_test_tree_terminal(const char *path, void *user)
{
    (void)user;
    return path && strncmp(path, "tests/harness/src/", 13) == 0;
}

static bool write_fixture(void)
{
    return mk_write(FIX, "core/modules/net/src/foo.c", FOO_C) &&
           mk_write(FIX, "core/modules/net/include/net/foo.h", FOO_H) &&
           mk_write(FIX, "core/modules/net/include/net/bar.h", BAR_H) &&
           /* the live generation of the epoch-managed root */
           mk_write(FIX, "build/obj/.current-epoch", CUR_EPOCH "\n") &&
           mk_write(FIX, CUR_EPOCH_DEP,
                    "build/obj/foo.o: core/modules/net/src/foo.c "
                    "core/modules/net/include/net/foo.h\n") &&
           /* a pre-epoch leftover: no current compile wrote it */
           mk_write(FIX, "build/obj/foo.d",
                    "build/obj/foo.o: core/modules/net/src/foo.c "
                    "core/modules/net/include/net/bar.h\n") &&
           /* a retained generation of a tree that is no longer checked out */
           mk_write(FIX, RETAINED_EPOCH_DEP,
                    "build/obj/foo.o: core/modules/net/src/foo.c "
                    "core/modules/net/include/net/bar.h\n") &&
           /* a plain object root, with no generations at all */
           mk_write(FIX, "build/test-obj/foo.d",
                    "build/test-obj/foo.o: core/modules/net/src/foo.c "
                    "core/modules/net/include/net/foo.h\n") &&
           mk_write(FIX, "core/modules/net/src/purpose_stem.c", PURPOSE_STEM_C) &&
           mk_write(FIX, "core/modules/net/src/purpose_override.c", PURPOSE_OVERRIDE_C) &&
           mk_write(FIX, "core/modules/net/src/purpose_none.c", PURPOSE_NONE_C) &&
           mk_write(FIX, "core/modules/net/src/purpose_after_license.c",
                    PURPOSE_AFTER_LICENSE_C) &&
           mk_write(FIX, "core/modules/net/src/purpose_license_only.c",
                    PURPOSE_LICENSE_ONLY_C) &&
           mk_write(FIX, "app/main.c", PACKAGE_APP_C) &&
           mk_write(FIX, "engine/entry/main.c", ROOT_MAIN_C) &&
           mk_write(FIX, "packages/widget/app/main.c",
                    NESTED_PACKAGE_APP_C) &&
           mk_write(FIX, "packages/widget/include/package/api.h",
                    PACKAGE_HEADER_H) &&
           mk_write(FIX, "packages/widget/tests/test_package.c",
                    PACKAGE_TEST_C) &&
           mk_write(FIX, "platform/ports/include/ports/fixture_port.h", PORT_H) &&
           mk_write(FIX, "tests/harness/src/test_fixture_indexed.c", TEST_SOURCE_C) &&
           mk_write(FIX, "examples/example_fixture.c", EXAMPLE_SOURCE_C) &&
           mk_write(FIX, "docs/examples/documented_fixture.c", EXAMPLE_SOURCE_C) &&
           mk_write(FIX, "core/modules/net/examples/module_example_fixture.c",
                    MODULE_EXAMPLE_C) &&
           mk_write(FIX, "core/modules/net/tests/module_test_fixture.c",
                    MODULE_TEST_C) &&
           mk_write(FIX, "core/modules/net/fixtures/hidden_fixture.c",
                    "int hidden_fixture(void) { return 0; }\n") &&
           mk_write(FIX, "engine/composition/fixture_registry.def",
                    "FIXTURE_REGISTRY_ROW(value)\n") &&
           mk_write(FIX, "core/modules/net/src/saturation.c", SATURATION_C) &&
           mk_write(FIX, "tests/harness/include/test/build/generated_should_not_index.c",
                    "int generated_should_not_index(void) { return 0; }\n");
}

/* Canonical ordered dump of every symbol as one string (for identity tests). */
static char *dump_symbols(struct codeindex *ci)
{
    struct ci_symbol syms[256];
    int n = codeindex_find(ci, "", syms, 256);
    if (n < 0) return NULL;
    size_t cap = 64 * 1024, len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
    buf[0] = '\0';
    for (int i = 0; i < n; i++) {
        int w = snprintf(buf + len, cap - len,
                         "%s|%c|%s:%d|%s:%d|%s|%s|%d\n",
                         syms[i].name, syms[i].kind,
                         syms[i].def_path, syms[i].def_line,
                         syms[i].decl_path, syms[i].decl_line,
                         syms[i].signature, syms[i].guard,
                         syms[i].partial ? 1 : 0);
        if (w < 0 || (size_t)w >= cap - len) break;
        len += (size_t)w;
    }
    return buf;
}

/* Corrupt one symbol row's signature WITHOUT updating row_sha3, to exercise
 * verify-on-read. Returns true on success. */
static bool corrupt_symbol(const char *name)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(FIX "/.codeindex/index.kv", &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    char sql[512];
    snprintf(sql, sizeof(sql),
             "UPDATE symbols SET signature='CORRUPTED' WHERE name='%s'", name);
    int rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    sqlite3_close(db);
    return rc == SQLITE_OK;
}

/* Delete one meta key from the published index without going through a rebuild,
 * to exercise the ci_schema_version migration trigger. Returns true on success. */
static bool delete_meta_key(const char *index_path, const char *key)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(index_path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    char sql[256];
    snprintf(sql, sizeof(sql), "DELETE FROM meta WHERE k='%s'", key);
    int rc = sqlite3_exec(db, sql, NULL, NULL, NULL);
    sqlite3_close(db);
    return rc == SQLITE_OK;
}

/* Read a meta key directly from the published index (no lazy rebuild). Copies
 * the value text into buf and returns true when the key exists. */
static bool published_meta_get(const char *index_path, const char *key,
                               char *buf, size_t cap)
{
    if (buf && cap) buf[0] = '\0';
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(index_path, &db, SQLITE_OPEN_READONLY, NULL) !=
        SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    sqlite3_stmt *st = NULL;
    bool found = false;
    if (sqlite3_prepare_v2(db, "SELECT v FROM meta WHERE k=? LIMIT 1", -1, &st,
                           NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            found = true;
            if (buf && cap) {
                const void *b = sqlite3_column_blob(st, 0);
                int n = sqlite3_column_bytes(st, 0);
                size_t copy = (size_t)n < cap - 1 ? (size_t)n : cap - 1;
                if (b && copy) memcpy(buf, b, copy);
                buf[copy] = '\0';
            }
        }
    }
    if (st) sqlite3_finalize(st);
    sqlite3_close(db);
    return found;
}

/* Inspect the published generation directly, without triggering a lazy
 * rebuild. Used to distinguish the old/new winner at crash boundaries. */
static bool published_index_has_symbol(const char *name)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(FIX "/.codeindex/index.kv", &db,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    sqlite3_stmt *st = NULL;
    bool found = false;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM symbols WHERE name=? LIMIT 1", -1, &st, NULL) ==
        SQLITE_OK) {
        sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
        found = sqlite3_step(st) == SQLITE_ROW;
    }
    if (st) sqlite3_finalize(st);
    sqlite3_close(db);
    return found;
}

static bool no_staging_files(void)
{
    DIR *d = opendir(FIX "/.codeindex");
    if (!d) return false;
    bool clean = true;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, "index.kv.tmp.", 13) == 0) {
            clean = false;
            break;
        }
    }
    closedir(d);
    return clean;
}

static bool file_equals(const char *path, const char *expected)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    char buf[128];
    size_t n = fread(buf, 1, sizeof(buf), f);
    bool eof = feof(f) != 0;
    fclose(f);
    size_t expected_len = strlen(expected);
    return eof && n == expected_len &&
           memcmp(buf, expected, expected_len) == 0;
}

static uint64_t monotonic_us(void)
{
    int64_t now = platform_time_monotonic_us();
    return now > 0 ? (uint64_t)now : 0;
}

static bool crash_rebuild_at(enum codeindex_test_crash_point point)
{
    codeindex_test_set_crash_point(point);
    pid_t pid = fork();
    if (pid == 0) {
        struct codeindex *child = codeindex_open(FIX);
        if (child) codeindex_close(child);
        _exit(3);  /* reaching here means the required boundary did not fire */
    }
    codeindex_test_set_crash_point(CODEINDEX_TEST_CRASH_NONE);
    if (pid < 0) return false;
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return false;
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
}

static bool concurrent_open_32(const char *required_symbol)
{
    enum { CHILDREN = 32 };
    int gate[2];
    if (pipe(gate) != 0) return false;
    pid_t pids[CHILDREN];
    int started = 0;
    for (int i = 0; i < CHILDREN; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            close(gate[1]);
            char token = 0;
            if (read(gate[0], &token, 1) != 1) _exit(10);
            close(gate[0]);
            struct codeindex *child = codeindex_open(FIX);
            struct ci_symbol sym;
            bool found = false;
            bool ok = child &&
                      codeindex_symbol(child, required_symbol, &sym, &found) &&
                      found;
            if (child) codeindex_close(child);
            _exit(ok ? 0 : 11);
        }
        if (pid < 0) break;
        pids[started++] = pid;
    }
    close(gate[0]);
    bool ok = started == CHILDREN;
    for (int i = 0; i < started; i++) {
        char token = 'x';
        if (write(gate[1], &token, 1) != 1) ok = false;
    }
    close(gate[1]);
    for (int i = 0; i < started; i++) {
        int status = 0;
        if (waitpid(pids[i], &status, 0) != pids[i] ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            ok = false;
    }
    return ok;
}

/* Room for the declared module list in the disk-side fixture. The declared
 * list grows with every new module; a list longer than this is refused by
 * name instead of being cut short and reported as a set mismatch. */
#define CI_DISK_MODULES_MAX 256
#define CI_DISK_MODULE_NAME 64

/* Enumerate the physically owned module directories that exist. The
 * declared list is engine/composition/lib_module_order.def; this proves every
 * declared navigator module resolves to a real owner directory. Returns -1
 * when a module has no owner path and -2 when the declared list does not fit
 * the fixture. */
static int disk_lib_modules(char out[CI_DISK_MODULES_MAX][CI_DISK_MODULE_NAME])
{
    size_t declared = 0;
    const char *const *modules = ci_lib_modules(&declared);
    int count = 0;
    if (declared > CI_DISK_MODULES_MAX) return -2;
    for (size_t i = 0; i < declared; i++) {
        char path[64];
        if (!codeindex_module_group_path(modules[i], path)) return -1;
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        snprintf(out[count], CI_DISK_MODULE_NAME, "%s", modules[i]);
        count++;
    }
    return count;
}

/* True when the declared module list fit the disk-side fixture. */
static bool disk_lib_modules_fit(int disk_count)
{
    size_t declared = 0;
    (void)ci_lib_modules(&declared);
    return declared <= CI_DISK_MODULES_MAX && disk_count != -2;
}

static bool set_contains(char set[CI_DISK_MODULES_MAX][CI_DISK_MODULE_NAME], int n,
                         const char *s)
{
    for (int i = 0; i < n; i++) if (strcmp(set[i], s) == 0) return true;
    return false;
}

static int check_full_freshness_stale(struct codeindex *ci, const char *label)
{
    int failures = 0;
    bool stale = false;
    CI_CHECK(label, ci && codeindex_is_stale(ci, &stale) && stale);
    return failures;
}

static int check_existing_full_freshness_stale(const char *root,
                                                const char *label)
{
    struct codeindex *ci = codeindex_open_existing(root);
    int failures = check_full_freshness_stale(ci, label);
    if (ci) codeindex_close(ci);
    return failures;
}

static int test_codeindex_metrics_warm_view(int64_t files_indexed)
{
    int failures = 0;
    struct codeindex *idx = codeindex_open_existing(MET_FIX);
    bool current = false;
    int64_t nfiles = 0, nsymbols = 0, nrefs = 0, ngroups = 0;
    bool have_snap = false, unchanged = false;
    uint8_t digest[32];
    CI_CHECK("metrics fixture reopen for source-view", idx != NULL);
    CI_CHECK("source view is current after a sealed index",
             idx &&
             codeindex_source_view_is_current(idx, &current) &&
             current);
    bool full_stale = true;
    CI_CHECK("full view agrees with the sealed source-view generation",
             idx && codeindex_is_stale(idx, &full_stale) && !full_stale);
    CI_CHECK("cached table counts are present after rebuild",
             idx &&
             codeindex_table_counts(idx, &nfiles, &nsymbols,
                                    &nrefs, &ngroups) &&
             nfiles == files_indexed && ngroups > 0);
    CI_CHECK("sealed snapshot exists after the fixture index",
             ci_merkle_snapshot_inventory_current(
                 MET_FIX, &have_snap, &unchanged, digest) &&
             have_snap);
    CI_CHECK("new source inventory fixture writes",
             mk_write(MET_FIX, "core/modules/net/src/inventory_added.c",
                      "int inventory_added(void) { return 1; }\n"));
    full_stale = false;
    CI_CHECK("full view rejects an added source file",
             idx && codeindex_is_stale(idx, &full_stale) && full_stale);
    if (idx) codeindex_close(idx);
    return failures;
}

#define RECEIPT_FIX "test-tmp/ci_receipt_extent"

static bool receipt_extent_write(const char *key, const char *bytes, int len)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(RECEIPT_FIX "/.codeindex/index.kv", &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return false;
    }
    const char *defaults = "INSERT OR REPLACE INTO meta(k,v) VALUES"
        "('build_cold_ms','7'),('build_cold_files','7'),"
        "('build_seed_donor','0000000000000000000000000000007'),"
        "('build_seed_files','7')";
    sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_exec(db, defaults, NULL, NULL, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_prepare_v2(db, "UPDATE meta SET v=? WHERE k=?",
                                  -1, &stmt, NULL) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_blob(stmt, 1, bytes, len, SQLITE_TRANSIENT) == SQLITE_OK;
    if (ok) ok = sqlite3_bind_text(stmt, 2, key, -1, SQLITE_TRANSIENT) == SQLITE_OK;
    if (ok) ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    if (sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static int receipt_extent_check(const char *key, int len, bool fits, bool seed)
{
    int failures = 0;
    char bytes[256], kind[32];
    memset(bytes, '0', sizeof(bytes));
    bytes[len - 1] = '7';
    bool written = receipt_extent_write(key, bytes, len);
    CI_CHECK("write explicit receipt byte extent", written);
    if (!written) return failures;
    struct codeindex *ci = codeindex_open_existing(RECEIPT_FIX);
    CI_CHECK("open receipt extent fixture without rebuilding", ci != NULL);
    if (!ci) return failures;
    long long ms = -1, files = -1;
    memset(kind, 'X', sizeof(kind));
    bool ok;
    if (seed) {
        ok = codeindex_seed_receipt(ci, kind, &files);
        CI_CHECK("seed receipt extent refusal or exact fitting output", fits
            ? ok && files == 7 && strcmp(kind, "0000000000000000000000000000007") == 0
            : !ok && files == 0 && kind[0] == '\0');
    } else {
        ok = codeindex_build_cold_ms(ci, &ms, &files);
        CI_CHECK("cold receipt extent refusal or fitting values", fits
            ? ok && ms == 7 && files == 7
            : !ok && ms == 0 && files == 0);
    }
    codeindex_close(ci);
    return failures;
}

static int receipt_extent_tests(void)
{
    int failures = 0;
    bool cleaned = test_rm_rf_recursive(RECEIPT_FIX) == 0 || errno == ENOENT;
    CI_CHECK("receipt fixture cleanup", cleaned);
    if (!cleaned) return failures;
    bool written = mk_write(RECEIPT_FIX, "src/a.c", "int a;\n");
    CI_CHECK("receipt fixture source", written);
    if (!written) return failures;
    struct codeindex *ci = codeindex_open(RECEIPT_FIX);
    CI_CHECK("build isolated receipt fixture", ci != NULL);
    if (!ci) return failures;
    codeindex_close(ci);
    const char *keys[] = {"build_cold_ms", "build_cold_files",
                         "build_seed_donor", "build_seed_files"};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        int capacity = i == 2 ? 32 : 24;
        failures += receipt_extent_check(keys[i], capacity, false, i >= 2);
        failures += receipt_extent_check(keys[i], 256, false, i >= 2);
    }
    failures += receipt_extent_check(keys[0], 23, true, false);
    failures += receipt_extent_check(keys[1], 23, true, false);
    failures += receipt_extent_check(keys[2], 31, true, true);
    failures += receipt_extent_check(keys[3], 23, true, true);
    CI_CHECK("remove isolated receipt fixture", test_rm_rf_recursive(RECEIPT_FIX) == 0);
    return failures;
}

/* These goals reach the real resident selector over the ordinary fixture.
 * Twenty-two prose atoms precede the explicit target, beyond the calculator's
 * sixteen-token window. Expected names/paths are assertions, never overrides. */
static const char CI_SELECTOR_LATE_PROSE[] =
    "saturation amber birch cedar denim elm frost grove hazel indigo juniper "
    "kelp lemon maple nectar olive pine quartz river stone violet willow ";

static int ci_selector_late_targets(struct codeindex *index)
{
    int failures = 0;
    char query[1024];
    struct zcode_goal_selection selected = {0};
    int n = snprintf(query, sizeof(query), "%sfoo_main", CI_SELECTOR_LATE_PROSE);
    CI_CHECK("late explicit whole C symbol survives the prose token cap",
        n > 0 && (size_t)n < sizeof(query) &&
        zcode_goal_context_select_indexed(index, query, NULL, &selected).ok &&
        !strcmp(selected.selected.name, "foo_main"));
    n = snprintf(query, sizeof(query), "%sfoo.c", CI_SELECTOR_LATE_PROSE);
    CI_CHECK("late explicit source filename survives the prose token cap",
        n > 0 && (size_t)n < sizeof(query) &&
        zcode_goal_context_select_indexed(index, query, NULL, &selected).ok &&
        !strcmp(selected.selected.def_path, "core/modules/net/src/foo.c"));
    return failures;
}

static int ci_selector_identifier_boundaries(struct codeindex *index)
{
    int failures = 0;
    struct zcode_goal_selection baseline = {0}, selected = {0};
    bool baseline_ok = zcode_goal_context_select_indexed(index,
        "Repair the data frame checksum length", NULL, &baseline).ok &&
        !strcmp(baseline.selected.name, "foo_checksum");
    CI_CHECK("identifier boundary control retains the legitimate full-query selection", baseline_ok);
    const char *unknown[] = {"unrelated_nonexistent_identifier", "foo.cpp", "foo_main_extended"};
    const char *labels[] = {
        "unknown identifier does not displace legitimate full-query selection",
        "foo.cpp does not falsely qualify the foo.c filename component",
        "a longer unknown C identifier does not qualify its foo_main prefix"
    };
    for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++) {
        char query[256];
        int n = snprintf(query, sizeof(query), "Repair the data frame checksum length %s", unknown[i]);
        CI_CHECK(labels[i], baseline_ok && n > 0 && (size_t)n < sizeof(query) &&
            zcode_goal_context_select_indexed(index, query, NULL, &selected).ok &&
            !strcmp(selected.selected_symbol_id, baseline.selected_symbol_id));
    }
    return failures;
}

static int ci_selector_multiple_targets(struct codeindex *index)
{
    int failures = 0;
    struct zcode_goal_selection first = {0}, again = {0};
    const char *query = "Repair foo_main and foo_checksum";
    bool selected = zcode_goal_context_select_indexed(index, query, NULL, &first).ok;
    CI_CHECK("multiple explicit known symbols select an actual named target",
        selected && (!strcmp(first.selected.name, "foo_main") ||
                     !strcmp(first.selected.name, "foo_checksum")));
    CI_CHECK("multiple explicit target selection is deterministic",
        selected && zcode_goal_context_select_indexed(index, query, NULL, &again).ok &&
        !strcmp(first.selected_symbol_id, again.selected_symbol_id) &&
        first.candidate_count == again.candidate_count);
    return failures;
}

static int test_codeindex_platform_arm(void)
{
    int failures = 0;

    struct ci_context_assignment assignment;
    size_t context_count = 0;
    CI_CHECK("context taxonomy has exactly ten target contexts",
             codeindex_context_names(&context_count) != NULL &&
             context_count == 10);
    CI_CHECK("messaging file has one physical context and model shape",
             codeindex_context_classify("contexts/messaging/models/src/zmsg.c", &assignment) &&
             assignment.production && !assignment.overlap && !assignment.orphan &&
             strcmp(assignment.context, "messaging") == 0 &&
             strcmp(assignment.shape, "models") == 0);
    {
        uint8_t digest_a[32], digest_b[32], digest_again[32];
        struct ci_context_assignment changed = assignment;
        (void)snprintf(changed.matches[0], sizeof(changed.matches[0]),
                       "wallet");
        CI_CHECK("assignment digest is deterministic and binds competing matches",
                 codeindex_context_assignment_digest(
                     "contexts/messaging/models/src/zmsg.c", &assignment, digest_a) &&
                 codeindex_context_assignment_digest(
                     "contexts/messaging/models/src/zmsg.c", &assignment, digest_again) &&
                 codeindex_context_assignment_digest(
                     "contexts/messaging/models/src/zmsg.c", &changed, digest_b) &&
                 memcmp(digest_a, digest_again, sizeof(digest_a)) == 0 &&
                 memcmp(digest_a, digest_b, sizeof(digest_a)) != 0);
    }
    CI_CHECK("wallet service has one context and its physical service shape",
             codeindex_context_classify(
                 "contexts/wallet/services/src/wallet_backup_service.c", &assignment) &&
             assignment.production && !assignment.overlap &&
             strcmp(assignment.context, "wallet") == 0 &&
             strcmp(assignment.shape, "services") == 0);
    CI_CHECK("market controller has one physical owner",
             codeindex_context_classify(
                 "contexts/market/controllers/src/yardsale_site_controller.c",
                 &assignment) && assignment.production &&
             !assignment.overlap &&
             strcmp(assignment.context, "market") == 0 &&
             strcmp(assignment.shape, "controllers") == 0);
    CI_CHECK("unknown source root is an explicit orphan",
             codeindex_context_classify("unknown/src/mystery.c", &assignment) &&
             assignment.orphan && assignment.context[0] == '\0' &&
             strcmp(assignment.shape, "orphan") == 0);
    CI_CHECK("tests are excluded from the production context map",
             !codeindex_path_is_production("tests/harness/src/test_codeindex.c") &&
             !codeindex_path_is_production(
                 "contexts/commons/packages/zbuf/tests/test_zbuf.c") &&
             codeindex_path_is_production("cognition/modules/codeindex/src/codeindex.c"));

 TEST_DISCARD(system("rm -rf " FIX));
    if (!write_fixture()) {
        printf("  codeindex: write_fixture... FAIL\n");
        return failures + 1;
    }

    /* ── open (triggers first build) ── */
    struct codeindex *ci = codeindex_open(FIX);
    CI_CHECK("open builds index", ci != NULL);
    if (!ci) return failures + 1;

    {
        int total = codeindex_file_count(ci);
        struct ci_file files[256];
        int listed = codeindex_files_page(ci, 0, files, 256);
        bool covered = total > 0 && total < 256 && listed == total;
        for (int i = 0; covered && i < listed; i++) {
            if (!codeindex_path_is_production(files[i].path)) continue;
            bool physical =
                strncmp(files[i].path, "core/", 5) == 0 ||
                strncmp(files[i].path, "engine/", 7) == 0 ||
                strncmp(files[i].path, "contexts/", 9) == 0 ||
                strncmp(files[i].path, "cognition/", 10) == 0 ||
                strncmp(files[i].path, "platform/", 9) == 0 ||
                strncmp(files[i].path, "tools/", 6) == 0;
            if (!physical) continue; /* conventional external workspace */
            if (!codeindex_context_classify(files[i].path, &assignment) ||
                assignment.orphan || !assignment.context[0] ||
                !assignment.shape[0])
                covered = false;
        }
        CI_CHECK("every indexed Z23 production fixture has one context and shape",
                 covered);
    }

    /* ── 2: query correctness ── */
    struct ci_symbol s;
    bool found = false;

    codeindex_symbol(ci, "helper_add", &s, &found);
    CI_CHECK("helper_add is a static func", found && s.kind == 't' &&
             strstr(s.def_path, "core/modules/net/src/foo.c") != NULL);

    codeindex_symbol(ci, "foo_main", &s, &found);
    CI_CHECK("foo_main is a func", found && s.kind == 'T');

    codeindex_symbol(ci, "foo_state", &s, &found);
    CI_CHECK("foo_state is a struct (def wins)", found && s.kind == 'S' &&
             strstr(s.def_path, "src/foo.c") != NULL);

    codeindex_symbol(ci, "foo_pair", &s, &found);
    CI_CHECK("foo_pair is a typedef", found && s.kind == 'Y');

    codeindex_symbol(ci, "foo_color", &s, &found);
    CI_CHECK("foo_color is an enum", found && s.kind == 'E');

    codeindex_symbol(ci, "FOO_MAX", &s, &found);
    CI_CHECK("FOO_MAX is a macro", found && s.kind == 'M');

    codeindex_symbol(ci, "foo_debug", &s, &found);
    CI_CHECK("foo_debug carries #ifdef guard", found &&
             strcmp(s.guard, "FOO_DEBUG") == 0);

    codeindex_symbol(ci, "foo_checksum", &s, &found);
    CI_CHECK("foo_checksum is a header declaration", found &&
             s.def_path[0] == '\0' &&
             strstr(s.decl_path, "include/net/foo.h") != NULL);

    struct ci_search_hit text_hits[8];
    int ntext = codeindex_search_text(ci, "data frame", text_hits, 8);
    CI_CHECK("indexed doc text finds its symbol with an explained match",
             ntext >= 1 &&
             strcmp(text_hits[0].symbol.name, "foo_checksum") == 0 &&
             (text_hits[0].match_mask & CI_SEARCH_MATCH_DOC) != 0);
    ntext = codeindex_search_text(ci, "size_t len", text_hits, 8);
    CI_CHECK("indexed signature text finds its symbol before broad matches",
             ntext >= 1 &&
             strcmp(text_hits[0].symbol.name, "foo_checksum") == 0 &&
             (text_hits[0].match_mask & CI_SEARCH_MATCH_SIGNATURE) != 0);
    ntext = codeindex_search_text(ci, "foo.h", text_hits, 8);
    CI_CHECK("indexed path text finds declarations deterministically",
             ntext >= 1 &&
             (text_hits[0].match_mask & CI_SEARCH_MATCH_PATH) != 0);

    struct zcode_goal_selection selected, selected_again, selected_indexed;
    CI_CHECK("goal selector ranks the checksum symbol from plain language",
             zcode_goal_context_select(
                 FIX, "Repair the data frame checksum length", NULL,
                 &selected).ok &&
             strcmp(selected.selected.name, "foo_checksum") == 0 &&
             selected.token_count >= 3 && selected.candidate_count >= 1 &&
             selected.generation_us > 0 && selected.retrieval_us > 0 &&
             selected.retrieval_corpus_files > 0 &&
             selected.retrieval_ranked_files > 0 &&
             strstr(selected.why, "bm25_story_file") != NULL);
    bool indexed_ok = zcode_goal_context_select_indexed(
        ci, "Repair the data frame checksum length", NULL,
        &selected_indexed).ok;
    bool indexed_same = indexed_ok &&
        selected.token_count == selected_indexed.token_count &&
        selected.candidate_count == selected_indexed.candidate_count &&
        selected.total_matches == selected_indexed.total_matches &&
        selected.dropped_candidates == selected_indexed.dropped_candidates &&
        selected.budget_exhausted == selected_indexed.budget_exhausted &&
        selected.retrieval_corpus_files ==
            selected_indexed.retrieval_corpus_files &&
        selected.retrieval_ranked_files ==
            selected_indexed.retrieval_ranked_files &&
        selected.retrieval_truncated == selected_indexed.retrieval_truncated &&
        selected_indexed.retrieval_us > 0 &&
        selected.service_generation == selected_indexed.service_generation &&
        strcmp(selected.selected_symbol_id,
               selected_indexed.selected_symbol_id) == 0 &&
        strcmp(selected.why, selected_indexed.why) == 0 &&
        selected_indexed.generation_us > 0;
    for (size_t i = 0; indexed_same && i < selected.token_count; i++)
        indexed_same = strcmp(selected.tokens[i],
                              selected_indexed.tokens[i]) == 0;
    for (size_t i = 0; indexed_same && i < selected.candidate_count; i++) {
        indexed_same =
            strcmp(selected.candidates[i].symbol_id,
                   selected_indexed.candidates[i].symbol_id) == 0 &&
            strcmp(selected.candidates[i].matched_token,
                   selected_indexed.candidates[i].matched_token) == 0 &&
            strcmp(selected.candidates[i].why,
                   selected_indexed.candidates[i].why) == 0 &&
            selected.candidates[i].match_mask ==
                selected_indexed.candidates[i].match_mask &&
            selected.candidates[i].score == selected_indexed.candidates[i].score;
    }
    CI_CHECK("caller-owned index produces the identical literal ranking",
             indexed_same);
    CI_CHECK("goal selection is deterministic across repeated runs",
             zcode_goal_context_select(
                 FIX, "Repair the data frame checksum length", NULL,
                 &selected_again).ok &&
             strcmp(selected.selected_symbol_id,
                    selected_again.selected_symbol_id) == 0 &&
             selected.candidate_count == selected_again.candidate_count);
    CI_CHECK("exact symbol override remains available",
             zcode_goal_context_select(FIX, "ignored", "helper_add",
                                       &selected).ok &&
             strcmp(selected.selected.name, "helper_add") == 0 &&
             strcmp(selected.why, "exact_symbol_override") == 0);
    CI_CHECK("behavior-only goal gets an explicit project-entry fallback",
             zcode_goal_context_select(
                 FIX, "Eliminate the seeded oscillation", NULL,
                 &selected).ok &&
             selected.selected.name[0] != '\0' &&
             strcmp(selected.why, "project_entry_fallback") == 0);
    CI_CHECK("a saturated literal bucket reports incomplete ranking",
             zcode_goal_context_select(
                 FIX, "saturation", NULL, &selected).ok &&
             selected.candidate_count == ZCODE_GOAL_MAX_CANDIDATES &&
             selected.budget_exhausted);
    CI_CHECK("a selective story term survives an earlier saturated term",
             zcode_goal_context_select(
                 FIX, "saturation checksum", NULL, &selected).ok &&
             strcmp(selected.selected.name, "foo_checksum") == 0 &&
             selected.candidate_count == ZCODE_GOAL_MAX_CANDIDATES &&
             selected.budget_exhausted);
    CI_CHECK("the observational literal baseline preserves token-order loss",
             zcode_goal_context_select_literal_indexed(
                 ci, "saturation checksum", &selected_indexed).ok &&
             strcmp(selected_indexed.selected.name, "foo_checksum") != 0 &&
             selected_indexed.candidate_count == ZCODE_GOAL_MAX_CANDIDATES &&
             selected_indexed.budget_exhausted &&
             selected_indexed.retrieval_corpus_files == 0);

    failures += ci_selector_late_targets(ci);
    failures += ci_selector_identifier_boundaries(ci);
    failures += ci_selector_multiple_targets(ci);

    /* refs */
    struct ci_ref refs[32];
    int nref = codeindex_refs(ci, "helper_add", refs, 32);
    CI_CHECK("helper_add has call-site refs", nref >= 1);
    nref = codeindex_refs(ci, "foo_checksum", refs, 32);
    CI_CHECK("foo_checksum has one call-site ref", nref == 1);

    char includes[8][256];
    int nincludes = codeindex_includes_of_file(
        ci, "core/modules/net/src/foo.c", includes, 8);
    /* Only the live generation and the plain root are inputs, and both name
     * foo.h. The retained generation and the pre-epoch leftover both name
     * bar.h, so either one leaking in would show up here. */
    CI_CHECK("compiler depfile include edge is indexed",
             nincludes == 1 &&
             strcmp(includes[0], "core/modules/net/include/net/foo.h") == 0);

    /* Warm opens validate metadata cache keys only. Exact source/dep bytes are
     * sealed in the generation and reread only when inode/size/mtime/ctime
     * changes. Historical compile epochs are outside the active dep graph. */
    codeindex_close(ci);
    ci = NULL;
    CI_CHECK("historical epoch mutation fixture writes",
             mk_write(FIX, RETAINED_EPOCH_DEP,
                      "build/obj/foo.o: core/modules/net/src/foo.c "
                      "core/modules/net/include/net/foo.h\n"));
    codeindex_test_reset_exact_bytes_read();
    uint64_t warm_start_us = monotonic_us();
    uint64_t warm_cpu_start_us = test_thread_cpu_us();
    ci = codeindex_open(FIX);
    uint64_t warm_elapsed_us = monotonic_us() - warm_start_us;
    uint64_t warm_cpu_us = test_thread_cpu_us() - warm_cpu_start_us;
    struct test_budget warm_budget = test_budget_scale(UINT64_C(250000));
    uint64_t warm_exact_bytes = codeindex_test_exact_bytes_read();
    printf("  codeindex: warm-open elapsed_us=%llu cpu_us=%llu exact_bytes=%llu nominal_us=250000 effective_us=%llu load_factor=%.2f calib_us=%llu\n",
           (unsigned long long)warm_elapsed_us,
           (unsigned long long)warm_cpu_us,
           (unsigned long long)warm_exact_bytes,
           (unsigned long long)warm_budget.effective_us,
           warm_budget.factor,
           (unsigned long long)warm_budget.calib_med_us);
    CI_CHECK("warm open rereads zero exact-content bytes",
             ci && warm_exact_bytes == 0);
    CI_CHECK("fixture warm open stays below load-scaled 250 ms budget",
             ci && warm_elapsed_us > 0 &&
             warm_elapsed_us <= warm_budget.effective_us);
    memset(includes, 0, sizeof(includes));
    nincludes = ci ? codeindex_includes_of_file(
        ci, "core/modules/net/src/foo.c", includes, 8) : -1;
    CI_CHECK("historical epoch depfiles cannot change active include edges",
             ci && nincludes == 1 &&
             strcmp(includes[0], "core/modules/net/include/net/foo.h") == 0);

    /* Which generation is live is what .current-epoch says, not which one was
     * written last: repoint the root at the older one and its edges become the
     * graph. This is the whole mechanism — a build names the epoch it compiled
     * into, and the graph reads that name. */
    if (ci) { codeindex_close(ci); ci = NULL; }
    CI_CHECK("repoint the object root at its other generation",
             mk_write(FIX, RETAINED_EPOCH_DEP,
                      "build/obj/foo.o: core/modules/net/src/foo.c "
                      "core/modules/net/include/net/bar.h\n") &&
             mk_write(FIX, "build/obj/.current-epoch", RETAINED_EPOCH "\n"));
    ci = codeindex_open(FIX);
    memset(includes, 0, sizeof(includes));
    nincludes = ci ? codeindex_includes_of_file(
        ci, "core/modules/net/src/foo.c", includes, 8) : -1;
    CI_CHECK("the include graph follows the named generation",
             ci && nincludes == 2 &&
             strcmp(includes[0], "core/modules/net/include/net/bar.h") == 0 &&
             strcmp(includes[1], "core/modules/net/include/net/foo.h") == 0);

    if (ci) { codeindex_close(ci); ci = NULL; }
    CI_CHECK("restore the original live generation",
             mk_write(FIX, RETAINED_EPOCH_DEP,
                      "build/obj/foo.o: core/modules/net/src/foo.c "
                      "core/modules/net/include/net/foo.h\n") &&
             mk_write(FIX, "build/obj/.current-epoch", CUR_EPOCH "\n"));
    ci = codeindex_open(FIX);
    memset(includes, 0, sizeof(includes));
    nincludes = ci ? codeindex_includes_of_file(
        ci, "core/modules/net/src/foo.c", includes, 8) : -1;
    CI_CHECK("the retained generation is inert again",
             ci && nincludes == 1 &&
             strcmp(includes[0], "core/modules/net/include/net/foo.h") == 0);

    /* Four depfiles are on disk; two of them are the graph. Anyone who needs
     * that number (the test-result cache asks whether the graph exists at all)
     * gets it from the graph rather than from a second walk of build/. */
    {
        size_t dep_n = 0;
        int64_t dep_newest = 0;
        bool inventory = codeindex_depfile_graph(FIX, &dep_n, &dep_newest);
        CI_CHECK("depfile inventory counts the live generation only",
                 inventory && dep_n == 2 && dep_newest > 0);
    }

    /* Warm acceptance uses an owner-controlled directory capability. Mode
     * drift fails closed before SQLite can consume the canonical pathname. */
    if (ci) { codeindex_close(ci); ci = NULL; }
    CI_CHECK("make codeindex directory insecure for boundary test",
             chmod(FIX "/.codeindex", 0777) == 0);
    struct codeindex *insecure = codeindex_open(FIX);
    CI_CHECK("warm open rejects group/world-writable codeindex directory",
             insecure == NULL);
    if (insecure) codeindex_close(insecure);
    CI_CHECK("restore owner-controlled codeindex directory",
             chmod(FIX "/.codeindex", 0755) == 0);
    ci = codeindex_open(FIX);
    CI_CHECK("owner-controlled warm index reopens", ci != NULL);

    /* file → group */
    struct ci_file cf;
    codeindex_file(ci, "core/modules/net/src/foo.c", &cf, &found);
    CI_CHECK("foo.c maps to group core/modules/net", found &&
             strcmp(cf.group, "core/modules/net") == 0);

    /* file → purpose (§1.1): stem-dashed header, explicit override, none */
    codeindex_file(ci, "core/modules/net/src/purpose_stem.c", &cf, &found);
    CI_CHECK("stem-dashed header yields the bare description", found &&
             strcmp(cf.purpose, "derives its purpose from the stem header.") == 0);

    codeindex_file(ci, "core/modules/net/src/purpose_override.c", &cf, &found);
    CI_CHECK("explicit /* purpose: X */ override wins", found &&
             strcmp(cf.purpose, "explicit override wins.") == 0);

    codeindex_file(ci, "core/modules/net/src/purpose_none.c", &cf, &found);
    CI_CHECK("interior-only comment yields empty purpose", found &&
             cf.purpose[0] == '\0');

    codeindex_file(ci, "core/modules/net/src/purpose_after_license.c", &cf, &found);
    CI_CHECK("license lines are skipped before a real purpose", found &&
             strcmp(cf.purpose,
                    "describes behavior after the license.") == 0);

    codeindex_file(ci, "core/modules/net/src/purpose_license_only.c", &cf, &found);
    CI_CHECK("license-only header yields empty purpose", found &&
             cf.purpose[0] == '\0');

    /* ── 8: every developer-facing source root is indexed ── */
    codeindex_file(ci, "engine/entry/main.c", &cf, &found);
    CI_CHECK("engine/entry/main.c is indexed in its entry room", found &&
             strcmp(cf.group, "engine/entry") == 0 &&
             strcmp(cf.purpose, "fixture top-level node entry.") == 0);

    codeindex_symbol(ci, "package_parse_options", &s, &found);
    CI_CHECK("package app symbol is searchable", found && s.kind == 't' &&
             strcmp(s.def_path,
                    "app/main.c") == 0);
    codeindex_symbol(ci, "package_api", &s, &found);
    CI_CHECK("package public header is searchable", found && s.kind == 'T' &&
             strcmp(s.decl_path,
                    "packages/widget/include/package/api.h") == 0);
    codeindex_symbol(ci, "package_cli_test", &s, &found);
    CI_CHECK("package test symbol is searchable", found && s.kind == 'T' &&
             strcmp(s.def_path,
                    "packages/widget/tests/test_package.c") == 0);
    codeindex_symbol(ci, "nested_package_parse_options", &s, &found);
    CI_CHECK("repository package app symbol is searchable",
             found && s.kind == 't' &&
             strcmp(s.def_path, "packages/widget/app/main.c") == 0);

    codeindex_file(ci, "platform/ports/include/ports/fixture_port.h", &cf, &found);
    CI_CHECK("ports header is indexed in ports", found &&
             strcmp(cf.group, "platform/ports") == 0 &&
             strcmp(cf.purpose, "fixture hexagonal interface.") == 0);

    codeindex_file(ci, "tests/harness/src/test_fixture_indexed.c", &cf, &found);
    CI_CHECK("test source is indexed in tests", found &&
             strcmp(cf.group, "tests") == 0 &&
             strcmp(cf.purpose, "fixture test translation unit.") == 0);

    codeindex_file(ci, "examples/example_fixture.c", &cf, &found);
    CI_CHECK("top-level example is indexed in examples", found &&
             strcmp(cf.group, "examples") == 0);
    codeindex_file(ci, "docs/examples/documented_fixture.c", &cf, &found);
    CI_CHECK("documentation C23 example is indexed", found &&
             strcmp(cf.group, "docs") == 0);
    codeindex_file(ci, "core/modules/net/examples/module_example_fixture.c",
                   &cf, &found);
    CI_CHECK("module-local example is indexed with its module", found &&
             strcmp(cf.group, "core/modules/net") == 0);
    codeindex_file(ci, "core/modules/net/tests/module_test_fixture.c", &cf, &found);
    CI_CHECK("module-local test is indexed with its module", found &&
             strcmp(cf.group, "core/modules/net") == 0);
    codeindex_file(ci, "core/modules/net/fixtures/hidden_fixture.c", &cf, &found);
    CI_CHECK("fixture source remains indexed proof input", found &&
             strcmp(cf.group, "core/modules/net") == 0);
    codeindex_file(ci, "engine/composition/fixture_registry.def", &cf, &found);
    CI_CHECK("registry node is indexed for impact without C symbols", found &&
             strcmp(cf.group, "engine/composition") == 0);

    struct ci_source_file_counts source_counts;
    CI_CHECK("C23 and registry-node counts are exact and separate",
             codeindex_source_file_counts(ci, &source_counts) &&
             source_counts.c23_files == 21 &&
             source_counts.governed_c23_files == 20 &&
             source_counts.fixture_c23_files == 1 &&
             source_counts.registry_nodes == 1);

    codeindex_symbol(ci, "fixture_root_main", &s, &found);
    CI_CHECK("src symbol is searchable", found && s.kind == 'T');
    codeindex_symbol(ci, "fixture_port_probe", &s, &found);
    CI_CHECK("ports declaration is searchable", found && s.kind == 'T');
    codeindex_symbol(ci, "test_fixture_indexed", &s, &found);
    CI_CHECK("test symbol is searchable", found && s.kind == 'T');

    codeindex_file(ci, "tests/harness/include/test/build/generated_should_not_index.c",
                   &cf, &found);
    CI_CHECK("generated test build directory stays pruned", !found);

    /* group hierarchy follows the physical authorities and rooms. */
    struct ci_group groups[256];
    int ng = codeindex_groups(ci, groups, 256);
    bool has_libnet = false, has_appsvc = false, has_libtest = false;
    bool has_packages = false, has_examples = false, has_src = false;
    for (int i = 0; i < ng; i++) {
        if (strcmp(groups[i].path, "core/modules/net") == 0 &&
            strcmp(groups[i].parent, "core/modules") == 0) has_libnet = true;
        if (strcmp(groups[i].path, "engine/entry") == 0) has_appsvc = true;
        if (strcmp(groups[i].path, "tests") == 0 &&
            strcmp(groups[i].parent, "root") == 0) has_libtest = true;
        if (strcmp(groups[i].path, "packages") == 0 &&
            strcmp(groups[i].parent, "root") == 0) has_packages = true;
        if (strcmp(groups[i].path, "examples") == 0 &&
            strcmp(groups[i].parent, "root") == 0) has_examples = true;
        if (strcmp(groups[i].path, "app") == 0 &&
            strcmp(groups[i].parent, "root") == 0) has_src = true;
    }
    CI_CHECK("group hierarchy exposes physical and package-workspace roots",
             has_libnet && has_libtest && has_appsvc && has_packages &&
             has_examples && has_src);

    /* card render */
    char card[1024];
    int cl = codeindex_render_card(ci, "foo_main", card, sizeof(card));
    CI_CHECK("card renders foo_main", cl > 0 && strstr(card, "foo_main") &&
             strstr(card, "func"));

    /* ── 7a: file counts (ci_store_count_files_in_group via the public
     * wrapper). The fixture has a production core/modules/net module plus tests. */
    {
        struct ci_file fbuf[16];
        int listed = codeindex_files_in_group(ci, "core/modules/net", fbuf, 16);
        int direct = codeindex_count_files_in_group(ci, "core/modules/net", false);
        int direct_test = codeindex_count_files_in_group(ci, "tests", false);
        int recur_lib = codeindex_count_files_in_group(ci, "core/modules", true);
        int recur_self = codeindex_count_files_in_group(ci, "core/modules/net", true);
        int missing = codeindex_count_files_in_group(ci, "core/modules/nope", true);
        CI_CHECK("direct count equals the listed file count",
                 direct >= 2 && direct == listed);
        CI_CHECK("recursive count on core/modules includes the direct module",
                 direct_test >= 1 && recur_lib >= direct);
        CI_CHECK("recursive count on a leaf group equals its direct count",
                 recur_self == direct);
        CI_CHECK("unknown group counts zero (not an error)", missing == 0);
    }

    /* ── 7b: routing-link parity — `code tests <path>`'s route MUST equal
     * `dev test plan`'s proof_group for the same single changed file. Pure
     * path→route on both sides (no index/fixture dependency); the files need
     * not exist. Every case is a non-docs, non-hotswap single file, so devloop
     * takes the RELOAD path where proof_group is defined. This tripwire fails
     * the instant native_code_command.c's consensus/route logic drifts from
     * devloop_plan.c. */
    {
        static const char *const parity_paths[] = {
            "core/modules/net/src/download.c",             /* -> "download" */
            "core/consensus/src/pow.c",           /* -> "consensus_parity" */
            "core/math/src/arith_uint256.c",      /* sealed core -> consensus_parity */
            "engine/services/src/node_health_service.c", /* -> "node_health_service" */
            "cognition/modules/codeindex/include/codeindex/source_roots.def", /* -> "codeindex" */
            "core/modules/net/src/msg_blocks.c",           /* -> "msg_handlers" */
            "core/modules/bloom/src/zzz_unmapped_xyz.c",   /* no rule -> "make_lint_gates" */
        };
        bool all_agree = true;
        for (size_t i = 0; i < sizeof(parity_paths) / sizeof(parity_paths[0]); i++) {
            const char *files[1] = { parity_paths[i] };
            struct zcl_devloop_plan plan;
            bool ok = zcl_devloop_plan_files(files, 1, &plan);
            const char *my_route =
                zcl_native_code_route_for_path(parity_paths[i], NULL, NULL);
            if (!ok || plan.action != ZCL_DEVLOOP_RELOAD || !my_route ||
                !plan.proof_group || strcmp(my_route, plan.proof_group) != 0) {
                printf("    parity MISMATCH for %s: code=%s devloop=%s\n",
                       parity_paths[i], my_route ? my_route : "(null)",
                       ok ? plan.proof_group : "(plan failed)");
                all_agree = false;
            }
        }
        CI_CHECK("code tests route == dev test plan proof_group (all cases)",
                 all_agree);
    }

    /* ── 1: build determinism ── */
    char *dump1 = dump_symbols(ci);
    CI_CHECK("dump #1 non-empty", dump1 && dump1[0]);
    CI_CHECK("legacy WAL sidecar fixture writes",
             mk_write(FIX, ".codeindex/index.kv-wal", "legacy-wal-bytes") &&
             mk_write(FIX, ".codeindex/index.kv-shm", "legacy-shm-bytes"));
    CI_CHECK("forced rebuild publishes after legacy sidecars",
             codeindex_rebuild(ci));
    CI_CHECK("publication removes legacy WAL/SHM names",
             access(FIX "/.codeindex/index.kv-wal", F_OK) != 0 &&
             access(FIX "/.codeindex/index.kv-shm", F_OK) != 0);
    char *dump2 = dump_symbols(ci);
    CI_CHECK("rebuild is deterministic (dump identical)",
             dump1 && dump2 && strcmp(dump1, dump2) == 0);

    /* ── 3: rebuild-from-scratch identity ── */
    codeindex_close(ci);
 TEST_DISCARD(system("rm -rf " FIX "/.codeindex"));
    codeindex_test_reset_exact_bytes_read();
    ci = codeindex_open(FIX);
    uint64_t scratch_exact_bytes = codeindex_test_exact_bytes_read();
    printf("  codeindex: from-scratch rebuild exact_bytes=%llu\n",
           (unsigned long long)scratch_exact_bytes);
    /* Liveness proof for the byte counter the incremental check below relies
     * on: with the store deleted the open must rehash fixture content, so a
     * zero here would mean the counter is dead, not that no work happened. */
    CI_CHECK("from-scratch rebuild rehashes content (byte counter is alive)",
             ci && scratch_exact_bytes > 0);
    char *dump3 = ci ? dump_symbols(ci) : NULL;
    CI_CHECK("from-scratch rebuild matches",
             dump1 && dump3 && strcmp(dump1, dump3) == 0);

    /* ── 4: staleness ⇒ auto-rebuild ── */
    if (ci) codeindex_close(ci);
    {
        char appended[4096];
        snprintf(appended, sizeof(appended), "%s\nint foo_added(void){return 7;}\n",
                 FOO_C);
        mk_write(FIX, "core/modules/net/src/foo.c", appended);
    }
    codeindex_test_reset_exact_bytes_read();
    uint64_t incremental_start_us = monotonic_us();
    uint64_t incremental_cpu_start_us = test_thread_cpu_us();
    ci = codeindex_open(FIX);
    uint64_t incremental_elapsed_us = monotonic_us() - incremental_start_us;
    uint64_t incremental_cpu_us = test_thread_cpu_us() - incremental_cpu_start_us;
    uint64_t incremental_exact_bytes = codeindex_test_exact_bytes_read();
    struct test_budget incremental_budget =
        test_budget_scale(UINT64_C(300000));
    CI_CHECK("reopen after edit", ci != NULL);
    found = false;
    if (ci) codeindex_symbol(ci, "foo_added", &s, &found);
    CI_CHECK("staleness auto-rebuild reflects the edit",
             found && s.kind == 'T');
    uint8_t incremental_root[32], full_root[32];
    bool incremental_root_ok = ci &&
        codeindex_retrieval_projection_root_sha3(ci, incremental_root);
    bool full_rebuild_ok = ci && codeindex_rebuild(ci);
    bool full_root_ok = full_rebuild_ok &&
        codeindex_retrieval_projection_root_sha3(ci, full_root);
    /* Load-immune signal: a one-file edit rehashes strictly less content than
     * the from-scratch rebuild (relative bound); a redo-all fails it. */
    bool incremental_bytes_ok = ci &&
        incremental_exact_bytes < scratch_exact_bytes;
    bool incremental_cpu_ok = ci &&
        incremental_cpu_us <= UINT64_C(300000);
    bool incremental_wall_ok = ci && incremental_elapsed_us > 0 &&
        incremental_elapsed_us <= incremental_budget.effective_us;
    CI_CHECK("incremental reopen rehashes less than from-scratch, not the tree",
             incremental_bytes_ok);
    CI_CHECK("incremental reopen burns bounded CPU, not a full rebuild",
             incremental_cpu_ok);
    printf("INCREMENTAL_REOPEN_VERDICT=%s elapsed_us=%llu wall_ok=%d cpu_us=%llu exact_bytes=%llu scratch_bytes=%llu nominal_us=300000 budget_us=%llu load_factor=%.2f calib_us=%llu\n",
           incremental_wall_ok ||
           (incremental_bytes_ok && incremental_cpu_ok) ? "PASS" : "FAIL",
           (unsigned long long)incremental_elapsed_us,
           incremental_wall_ok ? 1 : 0,
           (unsigned long long)incremental_cpu_us,
           (unsigned long long)incremental_exact_bytes,
           (unsigned long long)scratch_exact_bytes,
           (unsigned long long)incremental_budget.effective_us,
           incremental_budget.factor,
           (unsigned long long)incremental_budget.calib_med_us);
    /* Fast under the load-scaled wall budget, or provably incremental
     * (bounded reread and CPU) when host IO stalls the wall clock. */
    CI_CHECK("one-file incremental reopen is fast or provably bounded (load-scaled 300 ms wall budget)",
             incremental_wall_ok ||
             (incremental_bytes_ok && incremental_cpu_ok));
    CI_CHECK("incremental and forced-full stores have identical logical roots",
             incremental_root_ok && full_root_ok &&
             memcmp(incremental_root, full_root, 32) == 0);

    /* Depfiles are consumed index inputs too. A same-size edit with the exact
     * previous mtime must invalidate include edges even when every C/H byte is
     * unchanged. */
    static const char dep_b[] =
        "build/obj/foo.o: core/modules/net/src/foo.c core/modules/net/include/net/bar.h\n";
    struct stat dep_st;
    bool dep_stat = stat(FIX "/" CUR_EPOCH_DEP, &dep_st) == 0;
    bool dep_write = mk_write(FIX, CUR_EPOCH_DEP, dep_b);
    struct timespec dep_times[2];
    if (dep_stat) {
        dep_times[0] = dep_st.st_atim;
        dep_times[1] = dep_st.st_mtim;
    }
    bool dep_mtime = dep_stat && dep_write &&
        utimensat(AT_FDCWD, FIX "/" CUR_EPOCH_DEP, dep_times, 0) == 0;
    CI_CHECK("same-size depfile edit restores exact previous mtime",
             dep_mtime);
    failures += check_full_freshness_stale(
        ci, "full freshness rejects same-size restored-mtime depfile edit");
    if (ci) { codeindex_close(ci); ci = NULL; }
    ci = codeindex_open_source_view(FIX);
    memset(includes, 0, sizeof(includes));
    nincludes = ci ? codeindex_includes_of_file(
        ci, "core/modules/net/src/foo.c", includes, 8) : -1;
    CI_CHECK("source-only view ignores depfile-only churn",
             ci && nincludes == 1 &&
             strcmp(includes[0], "core/modules/net/include/net/foo.h") == 0);
    if (ci) { codeindex_close(ci); ci = NULL; }
    ci = codeindex_open(FIX);
    memset(includes, 0, sizeof(includes));
    nincludes = ci ? codeindex_includes_of_file(
        ci, "core/modules/net/src/foo.c", includes, 8) : -1;
    /* Both release and test object-root aliases are active. Changing one
     * profile must rebuild the union while preserving the other profile's
     * still-current edge. */
    CI_CHECK("depfile digest rebuilds the include graph",
             ci && nincludes == 2 &&
             strcmp(includes[0], "core/modules/net/include/net/bar.h") == 0 &&
             strcmp(includes[1], "core/modules/net/include/net/foo.h") == 0);

    /* ── 9a: the freshness root is bytes, not (mtime,size). Preserve the
     * exact original mtime while changing a same-length symbol name. */
    if (ci) { codeindex_close(ci); ci = NULL; }
    char source_current[16384];
    snprintf(source_current, sizeof(source_current),
             "%s\nint ci_same_aaaa(void){return 1;}\n", FOO_C);
    CI_CHECK("content-freshness fixture A writes",
             mk_write(FIX, "core/modules/net/src/foo.c", source_current));
    ci = codeindex_open(FIX);
    found = false;
    if (ci) codeindex_symbol(ci, "ci_same_aaaa", &s, &found);
    CI_CHECK("content-freshness fixture A is indexed", ci && found);
    if (ci) { codeindex_close(ci); ci = NULL; }

    struct stat same_st;
    bool same_stat = stat(FIX "/core/modules/net/src/foo.c", &same_st) == 0;
    char *same_name = strstr(source_current, "ci_same_aaaa");
    if (same_name) memcpy(same_name, "ci_same_bbbb", strlen("ci_same_bbbb"));
    bool same_write = same_name &&
        mk_write(FIX, "core/modules/net/src/foo.c", source_current);
    struct timespec same_times[2];
    if (same_stat) {
        same_times[0] = same_st.st_atim;
        same_times[1] = same_st.st_mtim;
    }
    bool same_mtime = same_stat && same_write &&
        utimensat(AT_FDCWD, FIX "/core/modules/net/src/foo.c", same_times, 0) == 0;
    CI_CHECK("same-size edit restores the exact previous mtime", same_mtime);
    failures += check_existing_full_freshness_stale(
        FIX, "full freshness rejects same-size restored-mtime source edit");
    ci = codeindex_open_source_view(FIX);
    bool found_new = false, found_old = true;
    if (ci) {
        codeindex_symbol(ci, "ci_same_bbbb", &s, &found_new);
        codeindex_symbol(ci, "ci_same_aaaa", &s, &found_old);
    }
    CI_CHECK("source-only view rejects same-size/same-mtime stale index",
             ci && found_new && !found_old);

    /* ── 9b: publication is rename-over, not unlink-then-rename. A reader
     * already bound to generation A remains valid while B becomes canonical. */
    struct codeindex *old_reader = ci;
    size_t used = strlen(source_current);
    snprintf(source_current + used, sizeof(source_current) - used,
             "int ci_retained_new(void){return 2;}\n");
    CI_CHECK("old-reader replacement fixture writes",
             mk_write(FIX, "core/modules/net/src/foo.c", source_current));
    struct codeindex *new_reader = codeindex_open(FIX);
    bool old_known = false, old_new = true, new_new = false;
    if (old_reader) {
        codeindex_symbol(old_reader, "ci_same_bbbb", &s, &old_known);
        codeindex_symbol(old_reader, "ci_retained_new", &s, &old_new);
    }
    if (new_reader)
        codeindex_symbol(new_reader, "ci_retained_new", &s, &new_new);
    CI_CHECK("old reader retains complete prior generation",
             old_reader && old_known && !old_new);
    CI_CHECK("new reader sees atomically published generation",
             new_reader && new_new);
    if (old_reader) codeindex_close(old_reader);
    ci = new_reader;

    /* ── 9c: a substituted stage name never receives SQLite writes. The
     * retained O_EXCL descriptor becomes unlinked, identity verification
     * refuses publication, and both victim + prior canonical stay intact. */
    static const char victim_path[] = FIX "/stage-victim.bin";
    static const char victim_bytes[] = "stage-victim-must-not-change";
    CI_CHECK("stage-substitution victim fixture writes",
             mk_write(FIX, "stage-victim.bin", victim_bytes));
    used = strlen(source_current);
    snprintf(source_current + used, sizeof(source_current) - used,
             "int ci_stage_symlink(void){return 6;}\n");
    CI_CHECK("symlink-substitution source fixture writes",
             mk_write(FIX, "core/modules/net/src/foo.c", source_current));
    codeindex_test_set_stage_tamper(CODEINDEX_TEST_STAGE_TAMPER_SYMLINK,
                                    victim_path);
    CI_CHECK("symlink-substituted stage is rejected",
             ci && !codeindex_rebuild(ci));
    codeindex_test_set_stage_tamper(CODEINDEX_TEST_STAGE_TAMPER_NONE, NULL);
    CI_CHECK("symlink victim bytes remain unchanged",
             file_equals(victim_path, victim_bytes));
    CI_CHECK("symlink substitution preserves prior canonical generation",
             !published_index_has_symbol("ci_stage_symlink"));
    CI_CHECK("symlink substitution leaves no staging name",
             no_staging_files());

    used = strlen(source_current);
    snprintf(source_current + used, sizeof(source_current) - used,
             "int ci_stage_hardlink(void){return 7;}\n");
    CI_CHECK("hardlink-substitution source fixture writes",
             mk_write(FIX, "core/modules/net/src/foo.c", source_current));
    codeindex_test_set_stage_tamper(CODEINDEX_TEST_STAGE_TAMPER_HARDLINK,
                                    victim_path);
    CI_CHECK("hardlink-substituted stage is rejected",
             ci && !codeindex_rebuild(ci));
    codeindex_test_set_stage_tamper(CODEINDEX_TEST_STAGE_TAMPER_NONE, NULL);
    CI_CHECK("hardlink victim bytes remain unchanged",
             file_equals(victim_path, victim_bytes));
    CI_CHECK("hardlink substitution preserves prior canonical generation",
             !published_index_has_symbol("ci_stage_hardlink"));
    CI_CHECK("hardlink substitution leaves no staging name",
             no_staging_files());
    CI_CHECK("clean rebuild succeeds after stage substitutions",
             ci && codeindex_rebuild(ci));

    /* ── 9d: process death before rename leaves the old generation; a later
     * open removes the abandoned unique stage and publishes a complete new
     * generation. */
    if (ci) { codeindex_close(ci); ci = NULL; }
    used = strlen(source_current);
    snprintf(source_current + used, sizeof(source_current) - used,
             "int ci_crash_before(void){return 3;}\n");
    CI_CHECK("pre-rename crash fixture writes",
             mk_write(FIX, "core/modules/net/src/foo.c", source_current));
    CI_CHECK("SIGKILL fires immediately before publication rename",
             crash_rebuild_at(CODEINDEX_TEST_CRASH_BEFORE_RENAME));
    CI_CHECK("pre-rename crash preserves the prior canonical generation",
             !published_index_has_symbol("ci_crash_before"));
    ci = codeindex_open(FIX);
    found = false;
    if (ci) codeindex_symbol(ci, "ci_crash_before", &s, &found);
    CI_CHECK("next open rebuilds after pre-rename crash", ci && found);
    CI_CHECK("next opener removes abandoned staging files", no_staging_files());

    /* A kill after rename has exactly the other legal winner: the fully
     * committed new file. Directory fsync is a power-loss boundary; SIGKILL
     * cannot manufacture a hybrid SQLite generation. */
    if (ci) { codeindex_close(ci); ci = NULL; }
    used = strlen(source_current);
    snprintf(source_current + used, sizeof(source_current) - used,
             "int ci_crash_after(void){return 4;}\n");
    CI_CHECK("post-rename crash fixture writes",
             mk_write(FIX, "core/modules/net/src/foo.c", source_current));
    CI_CHECK("SIGKILL fires immediately after publication rename",
             crash_rebuild_at(CODEINDEX_TEST_CRASH_AFTER_RENAME));
    CI_CHECK("post-rename crash exposes one complete new generation",
             published_index_has_symbol("ci_crash_after"));
    ci = codeindex_open(FIX);
    found = false;
    if (ci) codeindex_symbol(ci, "ci_crash_after", &s, &found);
    CI_CHECK("post-rename generation reopens and verifies", ci && found);
    CI_CHECK("post-rename crash leaves no staging file", no_staging_files());

    /* A directory capability removed between validation and O_CREAT is
     * reacquired and revalidated (the ENOENT boundary of the 32-way case). */
    if (ci) { codeindex_close(ci); ci = NULL; }
    used = strlen(source_current);
    snprintf(source_current + used, sizeof(source_current) - used,
             "int ci_lock_dir_retry(void){return 8;}\n");
    CI_CHECK("lock-directory retry fixture writes",
             mk_write(FIX, "core/modules/net/src/foo.c", source_current));
    (void)test_rm_rf_recursive(FIX "/.codeindex");
    codeindex_test_remove_lock_directory_once();
    ci = codeindex_open(FIX);
    found = false;
    if (ci) codeindex_symbol(ci, "ci_lock_dir_retry", &s, &found);
    CI_CHECK("cold open reacquires a removed lock-directory capability",
             ci && found);

    /* ── 9e: 32 processes start with no index. Exactly one rebuilds; losers
     * wait, recheck the winner's content root, and adopt it. */
    if (ci) { codeindex_close(ci); ci = NULL; }
    used = strlen(source_current);
    snprintf(source_current + used, sizeof(source_current) - used,
             "int ci_concurrent_32(void){return 5;}\n");
    CI_CHECK("32-way cold-open fixture writes",
             mk_write(FIX, "core/modules/net/src/foo.c", source_current));
 TEST_DISCARD(system("rm -rf " FIX "/.codeindex"));
    CI_CHECK("32 concurrent cold opens all adopt one complete generation",
             concurrent_open_32("ci_concurrent_32"));
    CI_CHECK("32-way publication leaves no staging files", no_staging_files());
    ci = codeindex_open(FIX);
    found = false;
    if (ci) codeindex_symbol(ci, "ci_concurrent_32", &s, &found);
    CI_CHECK("32-way winner is the durable canonical index", ci && found);
    CI_CHECK("32 concurrent warm opens retain the durable generation",
             concurrent_open_32("ci_concurrent_32"));

    /* ── 5: verify-on-read rejects a corrupted row ── */
    if (ci) codeindex_close(ci);
    CI_CHECK("corrupt a symbol row", corrupt_symbol("foo_main"));
    ci = codeindex_open(FIX);
    found = true;
    if (ci) codeindex_symbol(ci, "foo_main", &s, &found);
    CI_CHECK("corrupted row is rejected on read", ci && found == false);
    if (ci) codeindex_close(ci);

    free(dump1); free(dump2); free(dump3);

    /* ── 6: group parity vs the lib/ tree + shapes ── */
    {
        static char mk[CI_DISK_MODULES_MAX][CI_DISK_MODULE_NAME];
        int mn = disk_lib_modules(mk);
        size_t cn = 0;
        const char *const *code = ci_lib_modules(&cn);
        CI_CHECK("module-list fixture has room for the declared module list",
                 disk_lib_modules_fit(mn));
        /* set equality (both directions) */
        bool all_mk_in_code = true, all_code_in_mk = true;
        for (int i = 0; i < mn; i++) {
            bool hit = false;
            for (size_t j = 0; j < cn; j++)
                if (strcmp(mk[i], code[j]) == 0) { hit = true; break; }
            if (!hit) all_mk_in_code = false;
        }
        for (size_t j = 0; j < cn; j++)
            if (!set_contains(mk, mn, code[j])) all_code_in_mk = false;
        CI_CHECK("module list resolves to the physical module tree",
                 mn > 0 && (size_t)mn == cn && all_mk_in_code && all_code_in_mk);

        bool modules_classified = true;
        for (size_t i = 0; i < cn; i++) {
            char path[128];
            if (!codeindex_module_group_path(code[i], path)) {
                modules_classified = false;
                break;
            }
            size_t used = strlen(path);
            if (used + sizeof("/src/x.c") > sizeof(path)) {
                modules_classified = false;
                break;
            }
            memcpy(path + used, "/src/x.c", sizeof("/src/x.c"));
            if (!codeindex_context_classify(path, &assignment) ||
                assignment.orphan || !assignment.context[0] ||
                strcmp(assignment.shape, "modules") != 0) {
                modules_classified = false;
                break;
            }
        }
        CI_CHECK("every canonical module has one context and module shape",
                 cn > 0 && modules_classified);

        size_t sn = 0;
        const char *const *shapes = ci_app_shapes(&sn);
        /* Seven physical app/ shape folders. Event (the eighth conceptual
         * shape, FRAMEWORK.md §3 row 7) has no app/ folder — it is
         * owned by engine/modules/event/ + engine/modules/storage/event_log.c. */
        const char *expect[] = { "conditions", "controllers", "jobs",
                                 "models", "services", "supervisors", "views" };
        bool shapes_ok = (sn == 7);
        for (size_t i = 0; shapes_ok && i < 7; i++) {
            bool hit = false;
            for (size_t j = 0; j < sn; j++)
                if (strcmp(expect[i], shapes[j]) == 0) { hit = true; break; }
            if (!hit) shapes_ok = false;
        }
        CI_CHECK("app shape list is the seven physical shape folders", shapes_ok);
    }

    /* ── 10: call graph (enclosing attribution, callers/callees, ids) ──
     * A dedicated clean fixture: the shared FIX foo.c has been mutated by the
     * staleness/crash cases above, so use CG_FIX for deterministic joins. */
    {
 TEST_DISCARD(system("rm -rf " CG_FIX));
        CI_CHECK("call-graph fixture writes", write_cg_fixture());
        struct codeindex *cg = codeindex_open(CG_FIX);
        CI_CHECK("call-graph fixture opens", cg != NULL);

        if (cg) {
            struct ci_ref refs[16];

            /* enclosing is populated on the reverse-ref path too. */
            int nr = codeindex_refs(cg, "cg_helper", refs, 16);
            CI_CHECK("cg_helper refs carry enclosing attribution",
                     nr == 2 &&
                     strcmp(refs[0].enclosing, "cg_main") == 0 &&
                     strcmp(refs[1].enclosing, "cg_other") == 0);

            /* callers(X): who references X, ordered (ref_file, ref_line). */
            int nc = codeindex_callers(cg, "cg_helper", refs, 16);
            CI_CHECK("callers(cg_helper) = its two call sites, in order",
                     nc == 2 &&
                     strcmp(refs[0].callee, "cg_helper") == 0 &&
                     strcmp(refs[0].enclosing, "cg_main") == 0 &&
                     strcmp(refs[1].enclosing, "cg_other") == 0 &&
                     refs[0].ref_line < refs[1].ref_line);

            /* callees(X): what X's body references, ordered (ref_file,line). */
            int ne = codeindex_callees(cg, "cg_main", refs, 16);
            CI_CHECK("callees(cg_main) = cg_helper then cg_leaf",
                     ne == 2 &&
                     strcmp(refs[0].callee, "cg_helper") == 0 &&
                     strcmp(refs[1].callee, "cg_leaf") == 0 &&
                     strcmp(refs[0].enclosing, "cg_main") == 0 &&
                     refs[0].ref_line < refs[1].ref_line);

            int ne2 = codeindex_callees(cg, "cg_other", refs, 16);
            CI_CHECK("callees(cg_other) = the single cg_helper call",
                     ne2 == 1 && strcmp(refs[0].callee, "cg_helper") == 0);

            /* A symbol nobody calls has no callers; a leaf body has no callees. */
            int nc0 = codeindex_callers(cg, "cg_main", refs, 16);
            int ne0 = codeindex_callees(cg, "cg_helper", refs, 16);
            CI_CHECK("cg_main has no callers, cg_helper has no callees",
                     nc0 == 0 && ne0 == 0);

            /* Linkage-aware ids: static functions are path-scoped, external
             * functions name-scoped, other kinds namespaced by kind. */
            char id[512];
            int il = codeindex_symbol_id(cg, "cg_helper", id, sizeof(id));
            CI_CHECK("symbol_id(static fn) is path-scoped",
                     il > 0 &&
                     strcmp(id, "fn:static:core/modules/net/src/cg.c:cg_helper") == 0);
            il = codeindex_symbol_id(cg, "cg_main", id, sizeof(id));
            CI_CHECK("symbol_id(external fn) is name-scoped",
                     il > 0 && strcmp(id, "fn:external:cg_main") == 0);
            il = codeindex_symbol_id(cg, "no_such_symbol_xyz", id, sizeof(id));
            CI_CHECK("symbol_id(missing) reports not-found", il == -1);

            codeindex_close(cg);
            cg = NULL;
        }

        /* ── 11: schema-version migration — a store missing ci_schema_version
         * is stale and fully rebuilds on the next open (recompute never repair). */
        /* The expected tag is READ from the fresh build, never spelled out
         * here. CI_SCHEMA_VERSION lives in codeindex_priv.h, which this TU
         * cannot see; a literal copy of it in the test is a second source of
         * truth that goes stale silently the moment the real one is bumped —
         * and bumping it is routine, since any derived-schema change is
         * required to. What is under test is the INVARIANT (a store that
         * lost the key rebuilds and gets stamped again with whatever the
         * current generation is), not the spelling of one generation. */
        char meta_val[64];
        char stamped[64];
        CI_CHECK("fresh index stamps ci_schema_version",
                 published_meta_get(CG_FIX "/.codeindex/index.kv",
                                    "ci_schema_version", stamped,
                                    sizeof(stamped)) &&
                 stamped[0] != '\0');
        CI_CHECK("drop the ci_schema_version key from the published index",
                 delete_meta_key(CG_FIX "/.codeindex/index.kv",
                                 "ci_schema_version"));
        CI_CHECK("key is genuinely absent after delete",
                 !published_meta_get(CG_FIX "/.codeindex/index.kv",
                                     "ci_schema_version", meta_val,
                                     sizeof(meta_val)));
        failures += check_existing_full_freshness_stale(
            CG_FIX, "full freshness rejects absent schema metadata");
        struct codeindex *migr = codeindex_open(CG_FIX);
        CI_CHECK("open with absent ci_schema_version rebuilds", migr != NULL);
        CI_CHECK("rebuild restamps ci_schema_version",
                 published_meta_get(CG_FIX "/.codeindex/index.kv",
                                    "ci_schema_version", meta_val,
                                    sizeof(meta_val)) &&
                 strcmp(meta_val, stamped) == 0);
        if (migr) {
            struct ci_ref refs[16];
            int ne = codeindex_callees(migr, "cg_main", refs, 16);
            CI_CHECK("call graph intact after migration rebuild", ne == 2);
            codeindex_close(migr);
        }
 TEST_DISCARD(system("rm -rf " CG_FIX));
    }

    /* ── 12: impact closure (F3, proof-DAG from symbol closure) ──
     * cl_a -> cl_b -> cl_c across three files; changing cl_c.c's file must
     * impact cl_b.c and cl_a.c too. Deterministic, depth-bounded, cap-honoured. */
    {
 TEST_DISCARD(system("rm -rf " CL_FIX));
        CI_CHECK("closure fixture writes", write_cl_fixture());
        struct codeindex *cl = codeindex_open(CL_FIX);
        CI_CHECK("closure fixture opens", cl != NULL);

        if (cl) {
            const char changed[1][256] = { "core/modules/net/src/cl_c.c" };
            char out[64][256];
            bool trunc = true;

            /* Full closure: cl_c.c seeds -> cl_b.c -> cl_a.c, sorted unique. */
            int n = codeindex_impact_closure(cl, changed, 1, 0, out, 64, &trunc);
            CI_CHECK("full closure walks through test leaf into harness",
                     n == 5 && !trunc &&
                     strcmp(out[0], "core/modules/net/src/cl_a.c") == 0 &&
                     strcmp(out[1], "core/modules/net/src/cl_b.c") == 0 &&
                     strcmp(out[2], "core/modules/net/src/cl_c.c") == 0 &&
                     strcmp(out[3], "tests/harness/src/test.c") == 0 &&
                     strcmp(out[4], "tests/harness/src/test_cl.c") == 0);

            char outt[64][256];
            bool trunct = true;
            int nt = codeindex_impact_closure_with_terminal(
                cl, changed, 1, 0, cl_test_tree_terminal, NULL,
                outt, 64, &trunct);
            CI_CHECK("terminal callback records test leaf but does not "
                     "walk into umbrella harness",
                     nt == 4 && !trunct &&
                     strcmp(outt[0], "core/modules/net/src/cl_a.c") == 0 &&
                     strcmp(outt[1], "core/modules/net/src/cl_b.c") == 0 &&
                     strcmp(outt[2], "core/modules/net/src/cl_c.c") == 0 &&
                     strcmp(outt[3], "tests/harness/src/test_cl.c") == 0);

            /* Deterministic: a second identical query yields the identical set. */
            char out2[64][256];
            bool trunc2 = true;
            int n2 = codeindex_impact_closure(cl, changed, 1, 0, out2, 64,
                                              &trunc2);
            bool same = (n2 == n && trunc2 == trunc);
            for (int i = 0; same && i < n; i++)
                if (strcmp(out[i], out2[i]) != 0) same = false;
            CI_CHECK("closure is deterministic across repeated queries", same);

            /* Depth bound: depth=1 reaches the direct caller only (cl_b.c), not
             * cl_a.c — depth exhaustion is a normal bound, NOT truncation. */
            char outd[64][256];
            bool truncd = true;
            int nd = codeindex_impact_closure(cl, changed, 1, 1, outd, 64,
                                              &truncd);
            CI_CHECK("closure depth=1 = {cl_b.c, cl_c.c}, not truncated",
                     nd == 2 && !truncd &&
                     strcmp(outd[0], "core/modules/net/src/cl_b.c") == 0 &&
                     strcmp(outd[1], "core/modules/net/src/cl_c.c") == 0);

            /* Cap honoured: a cap smaller than the closure sets truncated and
             * returns exactly `cap` rows (the sorted prefix). */
            char outc[1][256];
            bool truncc = false;
            int nc = codeindex_impact_closure(cl, changed, 1, 0, outc, 1,
                                              &truncc);
            CI_CHECK("closure honours cap: cap=1 -> 1 row + truncated flag",
                     nc == 1 && truncc &&
                     strcmp(outc[0], "core/modules/net/src/cl_a.c") == 0);

            /* A leaf change with no callers impacts only the changed file. */
            const char lone[1][256] = { "tests/harness/src/test.c" };
            char outl[64][256];
            bool truncl = true;
            int nl = codeindex_impact_closure(cl, lone, 1, 0, outl, 64, &truncl);
            CI_CHECK("closure(test.c) = itself only (no callers)",
                     nl == 1 && !truncl &&
                     strcmp(outl[0], "tests/harness/src/test.c") == 0);

            /* Bad args are rejected (not found is never an error). */
            bool tb = false;
            CI_CHECK("closure rejects null out / non-positive cap",
                     codeindex_impact_closure(cl, changed, 1, 0, NULL, 64,
                                              &tb) == -1 &&
                     codeindex_impact_closure(cl, changed, 1, 0, out, 0,
                                              &tb) == -1);

            codeindex_close(cl);
        }
 TEST_DISCARD(system("rm -rf " CL_FIX));
    }

    /* ── code.index.metrics: schema, receipt parity, stale without rebuild ── */
    {
 TEST_DISCARD(system("rm -rf " MET_FIX));
        CI_CHECK("metrics fixture writes",
                 mk_write(MET_FIX, "core/modules/net/src/metrics_fix.c",
                          "/* core/modules/net/src/metrics_fix.c — metrics "
                          "fixture. */\n"
                          "int metrics_fix(void)\n{\n    return 1;\n}\n"));
        struct codeindex *built = codeindex_open(MET_FIX);
        CI_CHECK("metrics fixture indexes", built != NULL);
        if (built) codeindex_close(built);

        struct zcl_command_context ctx = { .source_root = MET_FIX };
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        struct zcl_command_request request = {
            .input = &input, .context = &ctx, .view = "normal",
            .invoked_name = "code.index.metrics",
        };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.code_index_metrics.v1");
        zcl_native_handle_code_index_metrics(&request, &reply);
        int64_t cold_files =
            json_get_int(json_get(&reply.data, "build_cold_files"));
        int64_t files_indexed =
            json_get_int(json_get(&reply.data, "files_indexed"));
        int64_t cold_ms =
            json_get_int(json_get(&reply.data, "build_cold_ms"));
        CI_CHECK("metrics schema and fresh receipt match file count",
                 reply.status != ZCL_COMMAND_STATUS_FAILED &&
                 reply.data_schema &&
                 strcmp(reply.data_schema, "zcl.code_index_metrics.v1") == 0 &&
                 !json_get_bool(json_get(&reply.data, "stale")) &&
                 cold_files == files_indexed && cold_files > 0);
        zcl_command_reply_free(&reply);

        /* Warm source-view freshness must not rebuild the Merkle tree.
         * The sealed snapshot plus live inventory keys is enough to
         * keep code.index.metrics inside its 750 ms FOREGROUND bucket. */
        failures += test_codeindex_metrics_warm_view(files_indexed);

        CI_CHECK("metrics stale edit writes",
                 mk_write(MET_FIX, "core/modules/net/src/metrics_fix.c",
                          "/* core/modules/net/src/metrics_fix.c — metrics "
                          "fixture. */\n"
                          "int metrics_fix(void)\n{\n    return 1;\n}\n"
                          "int metrics_added(void)\n{\n    return 2;\n}\n"));
        zcl_command_reply_init(&reply, "zcl.code_index_metrics.v1");
        zcl_native_handle_code_index_metrics(&request, &reply);
        CI_CHECK("metrics reports stale without rewriting the cold receipt",
                 reply.status != ZCL_COMMAND_STATUS_FAILED &&
                 json_get_bool(json_get(&reply.data, "stale")) &&
                 json_get_int(json_get(&reply.data, "build_cold_ms")) ==
                     cold_ms);
        zcl_command_reply_free(&reply);
        json_free(&input);
 TEST_DISCARD(system("rm -rf " MET_FIX));
    }

    return failures;
}
#else  /* _WIN32 */
/* Windows has no fork()/waitpid process model; this group's forked crash-rebuild and multi-child concurrency lane
 * cannot run here. Skipped loudly rather than faked. */
static int test_codeindex_platform_arm(void)
{
    printf("codeindex: SKIP (Windows): forked crash-rebuild and multi-child concurrency lane\n");
    return 0;
}
#endif

/* Explicit observational mode, not a relevance evaluator or candidate author.
 * The corpus contains requests only: expected paths never enter the selector. */
static const struct json_value *ci_measure_unique(const struct json_value *v,
                                                 const char *key)
{
    if (!v || v->type != JSON_OBJ) return NULL;
    const struct json_value *found = NULL;
    for (size_t i = 0; i < v->num_children; i++) {
        if (strcmp(v->keys[i], key)) continue;
        if (found) return NULL;
        found = &v->children[i];
    }
    return found;
}

static bool ci_measure_manifest(const char *workspace, const uint8_t expected[32],
                                 size_t *files)
{
    struct vcs_manifest manifest = {0};
    uint8_t root[32];
    bool ok = vcs_manifest_build(workspace, NULL, &manifest) &&
        vcs_manifest_tree_hash(&manifest, root) && !memcmp(root, expected, 32);
    *files = manifest.count;
    vcs_manifest_free(&manifest);
    return ok;
}

static bool ci_measure_symbol(const struct ci_symbol *s, struct json_value *out)
{
    char kind[2] = {s->kind, 0};
    return json_push_kv_str(out, "name", s->name) &&
        json_push_kv_str(out, "kind", kind) &&
        json_push_kv_str(out, "def_path", s->def_path) &&
        json_push_kv_int(out, "def_line", s->def_line) &&
        json_push_kv_str(out, "decl_path", s->decl_path) &&
        json_push_kv_int(out, "decl_line", s->decl_line) &&
        json_push_kv_str(out, "signature", s->signature) &&
        json_push_kv_str(out, "documentation", s->doc) &&
        json_push_kv_str(out, "guard", s->guard) &&
        json_push_kv_str(out, "group", s->group) &&
        json_push_kv_bool(out, "partial", s->partial);
}

static bool ci_measure_candidate(const struct zcode_goal_candidate *candidate,
                                  struct json_value *out)
{
    json_set_object(out);
    return json_push_kv_str(out, "symbol_id", candidate->symbol_id) &&
        ci_measure_symbol(&candidate->symbol, out) &&
        json_push_kv_int(out, "score", candidate->score) &&
        json_push_kv_int(out, "match_mask", candidate->match_mask) &&
        json_push_kv_str(out, "matched_token", candidate->matched_token) &&
        json_push_kv_str(out, "why", candidate->why);
}

static bool ci_measure_request_valid(const struct json_value *id,
                                      const struct json_value *query)
{
    return id && id->type == JSON_STR && id->val.s[0] && strlen(id->val.s) <= 128 &&
        query && query->type == JSON_STR && query->val.s[0] && strlen(query->val.s) <= 4096;
}

static bool ci_measure_selection_arrays(const struct zcode_goal_selection *selected,
                                          struct json_value *tokens,
                                          struct json_value *candidates)
{
    json_set_array(tokens); json_set_array(candidates);
    bool ok = true;
    for (size_t i = 0; ok && i < selected->token_count; i++) {
        struct json_value token = {0};
        json_set_str(&token, selected->tokens[i]);
        ok = json_push_back(tokens, &token);
        json_free(&token);
    }
    for (size_t i = 0; ok && i < selected->candidate_count; i++) {
        struct json_value candidate = {0};
        ok = ci_measure_candidate(&selected->candidates[i], &candidate) &&
            json_push_back(candidates, &candidate);
        json_free(&candidate);
    }
    return ok;
}

static bool ci_measure_selection_identity(struct json_value *out,
                                            const struct zcode_goal_selection *s)
{
    return json_push_kv_str(out, "selected_symbol_id", s->selected_symbol_id) &&
        json_push_kv_str(out, "selected_name", s->selected.name) &&
        json_push_kv_str(out, "selected_def_path", s->selected.def_path) &&
        json_push_kv_str(out, "selected_decl_path", s->selected.decl_path) &&
        json_push_kv_str(out, "why", s->why);
}

static bool ci_measure_selection_metrics(struct json_value *out,
                                           const struct zcode_goal_selection *s)
{
    return json_push_kv_int(out, "token_count", (int64_t)s->token_count) &&
        json_push_kv_int(out, "candidate_count", (int64_t)s->candidate_count) &&
        json_push_kv_int(out, "total_matches", (int64_t)s->total_matches) &&
        json_push_kv_int(out, "dropped_candidates", (int64_t)s->dropped_candidates) &&
        json_push_kv_bool(out, "budget_exhausted", s->budget_exhausted) &&
        json_push_kv_int(out, "generation_us", (int64_t)s->generation_us) &&
        json_push_kv_int(out, "retrieval_us", (int64_t)s->retrieval_us) &&
        json_push_kv_int(out, "retrieval_corpus_files", (int64_t)s->retrieval_corpus_files) &&
        json_push_kv_int(out, "retrieval_ranked_files", (int64_t)s->retrieval_ranked_files) &&
        json_push_kv_bool(out, "retrieval_truncated", s->retrieval_truncated) &&
        json_push_kv_int(out, "service_generation", s->service_generation);
}

static bool ci_measure_request(struct codeindex *index,
                                const struct json_value *request,
                                struct json_value *out)
{
    const struct json_value *id = ci_measure_unique(request, "id");
    const struct json_value *query = ci_measure_unique(request, "query");
    if (!ci_measure_request_valid(id, query)) return false;
    struct zcode_goal_selection selected = {0};
    struct zcl_result result = zcode_goal_context_select_indexed(
        index, query->val.s, NULL, &selected);
    if (!result.ok) {
        fprintf(stderr, "codeindex baseline request %s failed: %s\n", id->val.s, result.message);
        return false;
    }
    struct json_value tokens = {0}, candidates = {0};
    json_set_object(out);
    bool ok = ci_measure_selection_arrays(&selected, &tokens, &candidates) &&
        json_push_kv_str(out, "request_id", id->val.s) &&
        json_push_kv_str(out, "query", query->val.s) &&
        json_push_kv_int(out, "query_bytes", (int64_t)strlen(query->val.s)) &&
        json_push_kv(out, "tokens", &tokens) && json_push_kv(out, "candidates", &candidates) &&
        ci_measure_selection_identity(out, &selected) && ci_measure_selection_metrics(out, &selected);
    json_free(&candidates); json_free(&tokens);
    return ok;
}

struct ci_measure_snapshot {
    uint8_t expected[32], index_root[32], projection[32];
    size_t source_files;
    int64_t indexed_files;
};

static bool ci_measure_corpus(const char *request_file, char **text, size_t *bytes,
                                struct json_value *corpus)
{
    if (!zcl_read_whole_file_text(request_file, 1024u * 1024u, text, bytes,
                                  "codeindex baseline corpus") ||
        memchr(*text, 0, *bytes) || !json_read(corpus, *text, *bytes)) return false;
    const struct json_value *schema = ci_measure_unique(corpus, "schema");
    const struct json_value *requests = ci_measure_unique(corpus, "requests");
    return schema && schema->type == JSON_STR &&
        !strcmp(schema->val.s, "experiment_request_evidence.v1") &&
        requests && requests->type == JSON_ARR && requests->num_children > 0 &&
        requests->num_children <= 64;
}

static bool ci_measure_capture_index(struct codeindex *index,
                                       struct ci_measure_snapshot *snapshot)
{
    int64_t symbols = 0, refs = 0, groups = 0;
    bool current = false;
    return index && codeindex_source_root_sha3(index, snapshot->index_root) &&
        codeindex_retrieval_projection_root_sha3(index, snapshot->projection) &&
        codeindex_source_view_is_current(index, &current) && current &&
        codeindex_table_counts(index, &snapshot->indexed_files, &symbols, &refs, &groups);
}

static bool ci_measure_rows(struct codeindex *index, const struct json_value *requests,
                              struct json_value *rows)
{
    json_set_array(rows);
    bool ok = true;
    for (size_t i = 0; ok && i < requests->num_children; i++) {
        struct json_value row = {0};
        ok = ci_measure_request(index, json_at(requests, i), &row) &&
            json_push_back(rows, &row);
        json_free(&row);
    }
    return ok;
}

static bool ci_measure_recheck_index(const char *workspace, struct codeindex *index,
                                       const struct ci_measure_snapshot *snapshot)
{
    size_t post_files = 0;
    uint8_t post_index[32], post_projection[32];
    bool current = false;
    return ci_measure_manifest(workspace, snapshot->expected, &post_files) &&
        post_files == snapshot->source_files &&
        codeindex_source_root_sha3(index, post_index) &&
        !memcmp(snapshot->index_root, post_index, 32) &&
        codeindex_retrieval_projection_root_sha3(index, post_projection) &&
        !memcmp(snapshot->projection, post_projection, 32) &&
        codeindex_source_view_is_current(index, &current) && current &&
        codeindex_retrieval_projection_is_current(index, &current) && current;
}

static bool ci_measure_recheck_corpus(const char *request_file,
                                        const char *text, size_t bytes)
{
    char *post_text = NULL;
    size_t post_bytes = 0;
    bool ok = zcl_read_whole_file_text(request_file, 1024u * 1024u, &post_text,
        &post_bytes, "codeindex baseline corpus recheck") &&
        bytes == post_bytes && !memcmp(text, post_text, bytes);
    free(post_text);
    return ok;
}

static bool ci_measure_render(struct json_value *output, const struct json_value *rows,
                                const struct ci_measure_snapshot *snapshot,
                                const char *expected_hex, const char *text, size_t bytes)
{
    uint8_t corpus_root[32];
    struct sha3_256_ctx sha;
    sha3_256_init(&sha); sha3_256_write(&sha, (const uint8_t *)text, bytes);
    sha3_256_finalize(&sha, corpus_root);
    char index_hex[65], projection_hex[65], corpus_hex[65];
    zcl_hex_encode(snapshot->index_root, 32, index_hex);
    zcl_hex_encode(snapshot->projection, 32, projection_hex);
    zcl_hex_encode(corpus_root, 32, corpus_hex);
    json_set_object(output);
    return json_push_kv_str(output, "schema", "zcl.goal_context_selector_observation.v1") &&
        json_push_kv_str(output, "phase", "isolated_selector_observation_no_service_activation") &&
        json_push_kv_str(output, "selector", "zcode_goal_context_select_indexed") &&
        json_push_kv_str(output, "source_manifest_root_sha3", expected_hex) &&
        json_push_kv_int(output, "source_manifest_files", (int64_t)snapshot->source_files) &&
        json_push_kv_str(output, "index_source_root_sha3", index_hex) &&
        json_push_kv_str(output, "index_projection_root_sha3", projection_hex) &&
        json_push_kv_int(output, "indexed_files", snapshot->indexed_files) &&
        json_push_kv_str(output, "request_file_sha3_256", corpus_hex) &&
        json_push_kv_int(output, "request_file_bytes", (int64_t)bytes) &&
        json_push_kv_bool(output, "pre_post_bindings_unchanged", true) &&
        json_push_kv(output, "requests", rows);
}

static bool ci_measure_write(const struct json_value *output)
{
    size_t length = json_write(output, NULL, 0);
    char *serialized = length ? malloc(length + 1) : NULL;
    bool ok = serialized && json_write(output, serialized, length + 1) == length;
    if (ok) ok = fwrite(serialized, 1, length, stdout) == length && putchar('\n') != EOF;
    free(serialized);
    return ok;
}

static bool ci_measure_baseline(const char *workspace, const char *request_file,
                                 const char *expected_hex)
{
    struct ci_measure_snapshot snapshot = {0};
    char *text = NULL;
    size_t bytes = 0;
    struct json_value corpus = {0}, output = {0}, rows = {0};
    struct codeindex *index = NULL;
    bool ok = zcl_hex_decode_lower(expected_hex, snapshot.expected, 32) &&
        ci_measure_manifest(workspace, snapshot.expected, &snapshot.source_files) &&
        ci_measure_corpus(request_file, &text, &bytes, &corpus);
    if (ok) index = codeindex_open(workspace);
    const struct json_value *requests = ci_measure_unique(&corpus, "requests");
    ok = ok && ci_measure_capture_index(index, &snapshot) &&
        ci_measure_rows(index, requests, &rows) &&
        ci_measure_recheck_index(workspace, index, &snapshot) &&
        ci_measure_recheck_corpus(request_file, text, bytes) &&
        ci_measure_render(&output, &rows, &snapshot, expected_hex, text, bytes) &&
        ci_measure_write(&output);
    if (index) codeindex_close(index);
    free(text);
    json_free(&rows); json_free(&output); json_free(&corpus);
    return ok;
}

/* Explicit one-shot test fixture. No watcher, service, fake plan or compiler.
 * Its source-build CAS and the frozen indexed workspace are distinct roots. */
#if defined(__linux__)
static bool ci_restart_hash(const char *path, char hex[65])
{
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    struct sha256_ctx sha;
    unsigned char bytes[16384], digest[32];
    sha256_init(&sha);
    size_t n;
    while ((n = fread(bytes, 1, sizeof(bytes), file))) sha256_write(&sha, bytes, n);
    bool ok = !ferror(file);
    if (fclose(file)) ok = false;
    sha256_finalize(&sha, digest);
    zcl_hex_encode(digest, 32, hex);
    return ok;
}

/* Save the entire environment by pointer, never overwrite its strings. Native
 * process calls are synchronous; no fixture opt-in reaches a recursive child.
 * Keep the EXACT inherited lock/session/build/admission entries: deleting the
 * checkout marker while inheriting its lock fd makes nested Make self-deadlock.
 * Never synthesize ownership. Only known fixture override namespaces disappear. */
static bool ci_restart_env_override(const char *entry)
{
    static const char *const prefixes[] = {
        "ZCL_CODEINDEX_BASELINE_", "ZCL_CODEINDEX_RESTART_", "ZCL_TEST_FORK_",
        "ZCL_TEST_CACHE", "ZCL_HOTSWAP_TEST_", "ZCL_DEVLOOP_TEST_",
        "ONLY=", "LD_PRELOAD=", "LD_LIBRARY_PATH="
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
        if (!strncmp(entry, prefixes[i], strlen(prefixes[i]))) return true;
    return false;
}

static char **ci_restart_environment(char **original, bool process_optin)
{
    size_t count = 0;
    while (original[count]) count++;
    /* Three measurement entries and the optional process opt-in fit even
     * when no input entry was filtered. Strings remain caller-owned. */
    char **clean = calloc(count + 5, sizeof(*clean));
    if (!clean) return NULL;
    size_t used = 0;
    for (size_t i = 0; i < count; i++) {
        if (ci_restart_env_override(original[i])) continue;
        clean[used++] = original[i];
    }
    if (process_optin) clean[used] = "ZCL_DEVLOOP_TEST_PROCESS=1";
    return clean;
}

static bool ci_restart_env_contains(char **env, const char *entry)
{
    for (size_t i = 0; env[i]; i++)
        if (!strcmp(env[i], entry)) return true;
    return false;
}

static int ci_restart_environment_tests(void)
{
    int failures = 0;
    char *fixture[] = {"ZCL_CHECKOUT_LOCK_HELD=fixture-marker-not-authority",
        "ZCL_SOURCE_IDENTITY_SESSION=fixture-session", "DEVBUILD_LANE=fixture-lane",
        "TEST_FAST_CFLAGS=fixture-build", "ZCL_VENDOR_OFFLINE=fixture-policy",
        "ZCL_CODEINDEX_RESTART_WORKSPACE=fixture", "ZCL_CODEINDEX_BASELINE_REQUESTS=fixture",
        "ZCL_TEST_CACHE=1", "ZCL_TEST_FORK_ROLE=fixture", "ZCL_DEVLOOP_TEST_PROCESS=0", NULL};
    char **clean = ci_restart_environment(fixture, true);
    CI_CHECK("restart environment filter allocates", clean != NULL);
    if (!clean) return failures;
    for (size_t i = 0; i < 5; i++)
        CI_CHECK("restart environment retains exact inherited ownership/build/admission",
                  ci_restart_env_contains(clean, fixture[i]));
    for (size_t i = 5; i < 10; i++)
        CI_CHECK("restart environment removes only fixture recursion/test overrides",
                  !ci_restart_env_contains(clean, fixture[i]));
    CI_CHECK("restart environment explicitly opts into test subprocesses",
              ci_restart_env_contains(clean, "ZCL_DEVLOOP_TEST_PROCESS=1"));
    extern char **environ;
    char **original = environ;
    environ = clean;
    bool installed = environ == clean;
    environ = original;
    CI_CHECK("restart temporary environment restores exact original pointer",
              installed && environ == original);
    free(clean);
    char *unowned[] = {"PATH=/usr/bin:/bin", NULL};
    clean = ci_restart_environment(unowned, false);
    CI_CHECK("cold child never invents ownership or subprocess opt-in",
              clean && !clean[1] && clean[0] == unowned[0]);
    free(clean);
    return failures;
}

static int ci_restart_child_output_tests(bool ran,
                                          const struct zcl_devloop_process_result *process)
{
    int failures = 0;
    CI_CHECK("test process parent opt-in admits a real bounded child",
        ran && process->exit_code == 0 && !process->term_signal &&
        !process->timed_out && !process->cancelled && !process->output_truncated);
    CI_CHECK("test process child does not inherit its parent's execution opt-in",
        ran && !strstr(process->output, "ZCL_DEVLOOP_TEST_PROCESS="));
    CI_CHECK("test process child retains unrelated and similarly prefixed entries",
        ran && strstr(process->output, "ZCL_CODEINDEX_CHILD_ENV_WITNESS=retained\n") &&
        strstr(process->output, "ZCL_DEVLOOP_TEST_PROCESS_EXTRA=retained\n"));
    return failures;
}

static int ci_restart_child_environment_tests(void)
{
    int failures = 0;
    extern char **environ;
    char **original = environ;
    char *fixture[] = {"PATH=/usr/bin:/bin", "ZCL_DEVLOOP_TEST_PROCESS=1",
        "ZCL_CODEINDEX_CHILD_ENV_WITNESS=retained",
        "ZCL_DEVLOOP_TEST_PROCESS_EXTRA=retained", NULL};
    const char *argv[] = {"/usr/bin/env", NULL};
    struct zcl_devloop_process_result process = {0};
    environ = fixture;
    bool ran = zcl_devloop_process_run_test(".", argv, 5000, &process);
    bool parent_unchanged = environ == fixture &&
        !strcmp(getenv("ZCL_DEVLOOP_TEST_PROCESS"), "1");
    environ = original;
    failures += ci_restart_child_output_tests(ran, &process);
    CI_CHECK("test process leaves parent environment and opt-in unchanged",
        parent_unchanged && environ == original);
    char *unowned[] = {"PATH=/usr/bin:/bin", NULL};
    environ = unowned;
    bool refused = !zcl_devloop_process_run_test(".", argv, 5000, &process);
    bool unowned_unchanged = environ == unowned && !getenv("ZCL_DEVLOOP_TEST_PROCESS");
    environ = original;
    CI_CHECK("test process without parent opt-in still refuses and restores environment",
        refused && unowned_unchanged && environ == original);
    return failures;
}

static bool ci_restart_execution_ok(const struct zcl_devloop_process_result *p)
{
    return !p->exit_code && !p->term_signal && !p->timed_out && !p->cancelled;
}

static bool ci_restart_process_ok(const struct zcl_devloop_process_result *p)
{
    return ci_restart_execution_ok(p) && !p->output_truncated;
}

static bool ci_restart_accounted(const struct zcl_devloop_restart_proof_receipt *p)
{
    return p->proof_complete && !p->groups_failed && !p->self_skips &&
        p->group_count > 0 && p->groups_selected == p->group_count &&
        p->groups_ran + p->groups_cached == p->group_count &&
        !p->deferred_group_count && !p->bounded_proof_deferred &&
        !p->integration_proof_deferred;
}

static bool ci_restart_proof_ok(const struct zcl_devloop_restart_build_receipt *b,
                                const struct zcl_devloop_restart_proof_receipt *p)
{
    return b->candidate_probe_passed && b->source_identity_overlay &&
        p->source_identity_overlay && !p->source_overlay_unresolved &&
        ci_restart_accounted(p) && b->source_cas_sha3[0] &&
        !strcmp(b->source_cas_sha3, p->source_cas_sha3);
}

/* The native API has already checked the canonical summary and exact groups.
 * Its diagnostic tail need not contain the whole transcript; structured cold
 * measurement and probe output retain the stricter completeness requirement. */
static bool ci_restart_native_proof_ok(bool native_succeeded,
                                        const struct zcl_devloop_restart_build_receipt *b,
                                        const struct zcl_devloop_restart_proof_receipt *p,
                                        const struct zcl_devloop_process_result *process)
{
    return native_succeeded && ci_restart_execution_ok(process) && ci_restart_proof_ok(b, p);
}

static int ci_restart_diagnostic_tail_tests(void)
{
    int failures = 0;
    struct zcl_devloop_restart_build_receipt build = {
        .candidate_probe_passed = true, .source_identity_overlay = true,
        .source_cas_sha3 = "fixture-same-source"};
    struct zcl_devloop_restart_proof_receipt proof = {
        .source_identity_overlay = true, .proof_complete = true,
        .group_count = 2, .groups_selected = 2, .groups_ran = 2,
        .source_cas_sha3 = "fixture-same-source"};
    struct zcl_devloop_process_result process = {.output_truncated = true};
    CI_CHECK("native successful complete typed proof accepts bounded diagnostic tail",
        ci_restart_native_proof_ok(true, &build, &proof, &process));
    CI_CHECK("bounded diagnostic tail cannot turn native refusal into success",
        !ci_restart_native_proof_ok(false, &build, &proof, &process));
    proof.proof_complete = false;
    CI_CHECK("bounded diagnostic tail cannot hide incomplete typed proof",
        !ci_restart_native_proof_ok(true, &build, &proof, &process));
    proof.proof_complete = true; proof.groups_failed = 1;
    CI_CHECK("bounded diagnostic tail cannot hide a failed group",
        !ci_restart_native_proof_ok(true, &build, &proof, &process));
    proof.groups_failed = 0; proof.groups_ran = 1;
    CI_CHECK("bounded diagnostic tail cannot hide missing group accounting",
        !ci_restart_native_proof_ok(true, &build, &proof, &process));
    proof.groups_ran = 2; build.source_cas_sha3[0] = 'x';
    CI_CHECK("bounded diagnostic tail cannot hide mismatched source identity",
        !ci_restart_native_proof_ok(true, &build, &proof, &process));
    build.source_cas_sha3[0] = 'f'; process.exit_code = 1;
    CI_CHECK("bounded diagnostic tail cannot hide failed execution",
        !ci_restart_native_proof_ok(true, &build, &proof, &process));
    process.exit_code = 0;
    CI_CHECK("cold structured data still refuses truncated capture",
        !ci_restart_process_ok(&process));
    process.output_truncated = false;
    CI_CHECK("complete successful structured capture remains eligible",
        ci_restart_process_ok(&process));
    return failures;
}

static bool ci_restart_json_string(const struct json_value *v, const char *key,
                                    const char *expected)
{
    const struct json_value *field = ci_measure_unique(v, key);
    return field && field->type == JSON_STR && !strcmp(field->val.s, expected);
}

static bool ci_restart_is_observation(const struct json_value *row)
{
    return ci_restart_json_string(row, "schema", "zcl.goal_context_selector_observation.v1") &&
        ci_restart_json_string(row, "phase", "isolated_selector_observation_no_service_activation") &&
        ci_restart_json_string(row, "selector", "zcode_goal_context_select_indexed");
}

/* Only a full JSON observation line is accepted, never a probe or PASS text.
 * Truncated runner output refuses rather than losing evidence silently. */
static bool ci_restart_find_observation(char *text, struct json_value *out)
{
    char *cursor = text;
    bool found = false;
    while (*cursor) {
        char *end = strchr(cursor, '\n');
        size_t length = end ? (size_t)(end - cursor) : strlen(cursor);
        if (length && cursor[0] == '{') {
            struct json_value row = {0};
            bool parsed = json_read(&row, cursor, length);
            if (parsed && ci_restart_is_observation(&row)) {
                if (found) { json_free(&row); return false; }
                *out = row; found = true;
            } else json_free(&row);
        }
        if (!end) break;
        cursor = end + 1;
    }
    return found;
}

static bool ci_restart_observation(char *text, const char *root,
                                    const char *request_file, struct json_value *out)
{
    char *requests = NULL;
    size_t bytes = 0;
    uint8_t digest[32];
    bool ok = ci_restart_find_observation(text, out) &&
        zcl_read_whole_file_text(request_file, 1024u * 1024u,
        &requests, &bytes, "restart request binding");
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    if (ok) sha3_256_write(&sha, (const uint8_t *)requests, bytes);
    sha3_256_finalize(&sha, digest);
    free(requests);
    char hex[65]; zcl_hex_encode(digest, 32, hex);
    const struct json_value *rows = ci_measure_unique(out, "requests");
    const struct json_value *bound = ci_measure_unique(out, "pre_post_bindings_unchanged");
    return ok && ci_restart_json_string(out, "source_manifest_root_sha3", root) &&
        ci_restart_json_string(out, "request_file_sha3_256", hex) &&
        rows && rows->type == JSON_ARR && rows->num_children == 2 &&
        bound && bound->type == JSON_BOOL && bound->val.b;
}

static bool ci_restart_cold_summary(const char *text)
{
    const char *line = strstr(text, "\nSUITE VERDICT mode=cold ");
    if (!line) return false;
    size_t total, ran, cached, gated;
    int failed, skips, unobserved, flaky;
    int fields = sscanf(line,
        "\nSUITE VERDICT mode=cold groups_total=%zu groups_ran=%zu groups_cached=%zu "
        "groups_gated=%zu groups_failed=%d self_skips=%d env_unobserved=%d load_flaky=%d",
        &total, &ran, &cached, &gated, &failed, &skips, &unobserved, &flaky);
    return fields == 8 && ran == 1 && !cached && total >= gated &&
        total - gated == ran &&
        !failed && !skips && !unobserved && !flaky;
}

static bool ci_restart_cold(const char *repo, const char *workspace,
                             const char *requests, const char *root,
                             const struct zcl_devloop_restart_proof_receipt *proof,
                             struct json_value *observation)
{
    char vars[3][8192];
    const char *keys[] = {"ZCL_CODEINDEX_BASELINE_WORKSPACE", "ZCL_CODEINDEX_BASELINE_REQUESTS",
                          "ZCL_CODEINDEX_BASELINE_SOURCE_ROOT"};
    const char *values[] = {workspace, requests, root};
    for (size_t i = 0; i < 3; i++) {
        int n = snprintf(vars[i], sizeof(vars[i]), "%s=%s", keys[i], values[i]);
        if (n < 0 || (size_t)n >= sizeof(vars[i])) return false;
    }
    extern char **environ;
    char **env = ci_restart_environment(environ, false);
    if (!env) return false;
    size_t used = 0;
    while (env[used]) used++;
    for (size_t i = 0; i < 3; i++) env[used++] = vars[i];
    const char *argv[] = {proof->artifact_path, "--exact=test_codeindex", "--no-cache", NULL};
    struct zcl_devloop_process_result process = {0};
    bool ok = zcl_devloop_process_run_env(repo, argv, (const char *const *)env, 300000, &process) &&
        ci_restart_process_ok(&process);
    free(env);
    /* Retain the actual child transcript even on refusal. */
    if (process.output_len) fwrite(process.output, 1, process.output_len, stdout);
    bool complete = ok && ci_restart_cold_summary(process.output) &&
        ci_restart_observation(process.output, root, requests, observation);
    if (!complete)
        fprintf(stderr, "codeindex cold data refused: exit=%d signal=%d timeout=%d cancelled=%d output_len=%zu truncated=%d\n",
            process.exit_code, process.term_signal, process.timed_out,
            process.cancelled, process.output_len, process.output_truncated);
    return complete;
}

static bool ci_restart_emit_identities(struct json_value *out,
                                        const struct zcl_devloop_restart_build_receipt *b,
                                        const struct zcl_devloop_restart_proof_receipt *p)
{
    return json_push_kv_str(out, "build_source_cas_sha3", b->source_cas_sha3) &&
        json_push_kv_str(out, "runtime_artifact", b->artifact_path) &&
        json_push_kv_str(out, "runtime_artifact_sha256", b->artifact_sha256) &&
        json_push_kv_str(out, "runtime_cache_key", b->artifact_cache_key) &&
        json_push_kv_str(out, "proof_artifact", p->artifact_path) &&
        json_push_kv_str(out, "proof_artifact_sha256", p->artifact_sha256) &&
        json_push_kv_str(out, "proof_cache_key", p->artifact_cache_key);
}

static bool ci_restart_artifacts_match(const struct zcl_devloop_restart_build_receipt *b,
                                        const struct zcl_devloop_restart_proof_receipt *p)
{
    char runtime[65], proof[65];
    struct stat st;
    return ci_restart_hash(b->artifact_path, runtime) && !strcmp(runtime, b->artifact_sha256) &&
        ci_restart_hash(p->artifact_path, proof) && !strcmp(proof, p->artifact_sha256) &&
        !stat(p->artifact_path, &st) && (uint64_t)st.st_dev == p->artifact_dev &&
        (uint64_t)st.st_ino == p->artifact_ino && (uint64_t)st.st_size == p->artifact_size &&
        (int64_t)st.st_ctime == p->artifact_ctime_sec;
}

static bool ci_restart_generation(struct json_value *out, const char *repo,
                                    const char *expected_source)
{
    struct dev_source_record after = {0};
    char path[8192], hash[65];
    int n = snprintf(path, sizeof(path), "%s/build/dev-loop/restart.env", repo);
    return n > 0 && (size_t)n < sizeof(path) && ci_restart_hash(path, hash) &&
        zcl_dev_source_cas_capture(repo, &after) && after.cas_present &&
        !strcmp(after.cas_root_sha3, expected_source) &&
        json_push_kv_str(out, "native_restart_plan_sha256", hash) &&
        json_push_kv_bool(out, "build_source_unchanged_after_cold_run", true);
}

static bool ci_restart_emit(const char *repo,
                             const struct zcl_devloop_restart_build_receipt *build,
                             const struct zcl_devloop_restart_proof_receipt *proof,
                             const struct json_value *observation)
{
    struct json_value out = {0};
    json_set_object(&out);
    bool ok = json_push_kv_str(&out, "schema", "zcl.goal_context_restart_observation.v1") &&
        json_push_kv_str(&out, "scope", "isolated_DEV_RESTART_no_service_activation") &&
        ci_restart_emit_identities(&out, build, proof) &&
        ci_restart_generation(&out, repo, build->source_cas_sha3) &&
        json_push_kv_str(&out, "proof_groups", proof->groups) &&
        json_push_kv_str(&out, "proof_groups_sha256", proof->groups_sha256) &&
        json_push_kv_int(&out, "proof_groups_ran", proof->groups_ran) &&
        json_push_kv_int(&out, "proof_groups_cached", proof->groups_cached) &&
        json_push_kv(&out, "cold_selector_observation", observation);
    size_t n = ok ? json_write(&out, NULL, 0) : 0;
    char *text = n ? malloc(n + 1) : NULL;
    ok = text && json_write(&out, text, n + 1) == n;
    if (ok) ok = fwrite(text, 1, n, stdout) == n && putchar('\n') != EOF;
    free(text); json_free(&out);
    return ok;
}

static bool ci_restart_stack_ready(void)
{
    struct rlimit stack;
    if (getrlimit(RLIMIT_STACK, &stack) || stack.rlim_cur != RLIM_INFINITY) {
        fprintf(stderr, "codeindex DEV_RESTART requires explicit unlimited test stack (ulimit -s unlimited)\n");
        return false;
    }
    return true;
}

static void ci_restart_refusal(const char *stage, const char *why,
                                 const struct zcl_devloop_process_result *process,
                                 const struct zcl_devloop_restart_proof_receipt *proof)
{
    fprintf(stderr, "codeindex DEV_RESTART diagnostic: stage=%s exit=%d signal=%d timeout=%d cancelled=%d output_len=%zu truncated=%d selected=%u ran=%u cached=%u failed=%u skips=%u complete=%d unresolved_overlay=%d\n",
        stage, process->exit_code, process->term_signal, process->timed_out,
        process->cancelled, process->output_len, process->output_truncated,
        proof->groups_selected, proof->groups_ran, proof->groups_cached,
        proof->groups_failed, proof->self_skips, proof->proof_complete,
        proof->source_overlay_unresolved);
    fprintf(stderr, "codeindex explicit DEV_RESTART refused: %s\n%s\n",
        why[0] ? why : "incomplete proof, changed identity or missing cold observation", process->output);
}

static bool ci_measure_restart(const char *repo, const char *workspace,
                                const char *requests, const char *root)
{
    /* Prerequisite: genuinely rebuild the baseline with the repaired process,
     * restart deadline and this fixture before applying the selector change.
     * This phase overlays/proves only that selector delta. The infrastructure
     * changes retain their separate complete native derived proof obligation;
     * this narrower source list does not qualify those changes. */
    const char *sources[] = {"cognition/services/src/zcode_goal_context_service.c"};
    if (!ci_restart_stack_ready()) return false;
    struct zcl_devloop_plan plan = {0};
    struct zcl_devloop_restart_build_receipt build = {0};
    struct zcl_devloop_restart_proof_receipt proof = {0};
    struct zcl_devloop_process_result process = {0};
    char why[512] = {0};
    struct json_value observation = {0};
    extern char **environ;
    char **original = environ, **clean = ci_restart_environment(original, true);
    if (!clean) return false;
    environ = clean;
    const char *stage = "plan_or_build";
    bool ok = zcl_devloop_plan_files(sources, 1, &plan) &&
        zcl_devloop_plan_add_closure(repo, sources, 1, &plan) &&
        zcl_devloop_plan_proof_admissible(&plan, NULL) &&
        zcl_devloop_restart_build(repo, sources, 1, &build, &process, why, sizeof(why));
    if (ok) {
        stage = "probe_or_native_proof";
        ok = ci_restart_process_ok(&process) &&
            zcl_devloop_restart_prove(repo, sources, 1, &plan, &proof, &process, why, sizeof(why));
    }
    if (ok) {
        stage = "typed_proof_and_artifact_identity";
        ok = ci_restart_native_proof_ok(ok, &build, &proof, &process) &&
            ci_restart_artifacts_match(&build, &proof);
    }
    if (ok) {
        stage = "cold_observation_and_final_bindings";
        ok = ci_restart_cold(repo, workspace, requests, root, &proof, &observation) &&
            ci_restart_artifacts_match(&build, &proof) && ci_restart_emit(repo, &build, &proof, &observation);
    }
    environ = original;
    free(clean); json_free(&observation);
    if (!ok) ci_restart_refusal(stage, why, &process, &proof);
    return ok;
}
#else
static bool ci_measure_restart(const char *repo, const char *workspace,
                                const char *requests, const char *root)
{
    (void)repo; (void)workspace; (void)requests; (void)root;
    fprintf(stderr, "codeindex explicit restart observation is supported only by the Linux test fixture\n");
    return false;
}
#endif

static bool ci_restart_inputs(const char *repo, const char *workspace,
                               const char *requests, const char *root)
{
    return repo[0] && workspace && workspace[0] && requests && requests[0] &&
        root && root[0] && ci_measure_restart(repo, workspace, requests, root);
}

int test_codeindex(void)
{
    int failures = test_codeindex_platform_arm();
#if defined(__linux__)
    failures += ci_restart_environment_tests();
    failures += ci_restart_child_environment_tests();
    failures += ci_restart_diagnostic_tail_tests();
#endif
#if !defined(_WIN32)
    failures += receipt_extent_tests();
#endif
    const char *workspace = getenv("ZCL_CODEINDEX_BASELINE_WORKSPACE");
    const char *requests = getenv("ZCL_CODEINDEX_BASELINE_REQUESTS");
    const char *root = getenv("ZCL_CODEINDEX_BASELINE_SOURCE_ROOT");
    const char *restart = getenv("ZCL_CODEINDEX_RESTART_WORKSPACE");
    if (restart) {
        if (!ci_restart_inputs(restart, workspace, requests, root)) failures++;
    } else if (workspace || requests || root) {
        bool complete = workspace && workspace[0] && requests && requests[0] &&
            root && root[0] && ci_measure_baseline(workspace, requests, root);
        if (!complete) {
            fprintf(stderr, "codeindex baseline measurement FAILED: all three explicit inputs and unchanged source/corpus/index bindings required\n");
            failures++;
        }
    } else printf("codeindex baseline measurement not requested; no observation produced\n");
    return failures;
}
