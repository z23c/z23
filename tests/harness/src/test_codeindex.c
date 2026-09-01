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
#include "platform/time_compat.h"

/* For the routing-link parity invariant (case 7): `code tests <path>`'s route
 * (tools/command/native_code_command.c) must equal `dev test plan`'s
 * proof_group (tools/dev/devloop_plan.c) for the same single changed file. */
#include "command/native_command.h"
#include "devloop.h"
#include "services/zcode_goal_context_service.h"

#include <sqlite3.h>

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

/* ── call-graph fixture (WF4 lane 4A) ──────────────────────────────────
 * A self-contained module with two callers of one static helper and a call to
 * an external leaf, so callers/callees/enclosing are all exercised. */
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

/* Enumerate the physically owned module directories that actually exist.
 *
 * This used to parse the Makefile's LIB_MODULES. That is no longer a list:
 * engine/composition/lib_module_order.def declares the modules and the Makefile derives
 * LIB_MODULES from it, so scraping the Makefile would read a $(shell ...) line,
 * and scraping the .def would compare the scanner's array against the very file
 * it is pasted from — a check that cannot fail no matter how wrong either is.
 *
 * The architecture-tree gate independently proves there are no undeclared
 * physical modules; this test proves every declared navigator module resolves
 * to a real owner directory. */
static int disk_lib_modules(char out[64][64])
{
    size_t declared = 0;
    const char *const *modules = ci_lib_modules(&declared);
    int count = 0;
    for (size_t i = 0; i < declared && count < 64; i++) {
        char path[64];
        if (!codeindex_module_group_path(modules[i], path)) return -1;
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        snprintf(out[count], 64, "%s", modules[i]);
        count++;
    }
    return count;
}

static bool set_contains(char set[64][64], int n, const char *s)
{
    for (int i = 0; i < n; i++) if (strcmp(set[i], s) == 0) return true;
    return false;
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

    system("rm -rf " FIX);
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
    ci = codeindex_open(FIX);
    uint64_t warm_elapsed_us = monotonic_us() - warm_start_us;
    uint64_t warm_exact_bytes = codeindex_test_exact_bytes_read();
    printf("  codeindex: warm-open elapsed_us=%llu exact_bytes=%llu\n",
           (unsigned long long)warm_elapsed_us,
           (unsigned long long)warm_exact_bytes);
    CI_CHECK("warm open rereads zero exact-content bytes",
             ci && warm_exact_bytes == 0);
    CI_CHECK("fixture warm open stays below 250 ms",
             ci && warm_elapsed_us > 0 && warm_elapsed_us <= UINT64_C(250000));
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
    codeindex_file(ci, "core/modules/net/examples/module_example_fixture.c",
                   &cf, &found);
    CI_CHECK("module-local example is indexed with its module", found &&
             strcmp(cf.group, "core/modules/net") == 0);
    codeindex_file(ci, "core/modules/net/tests/module_test_fixture.c", &cf, &found);
    CI_CHECK("module-local test is indexed with its module", found &&
             strcmp(cf.group, "core/modules/net") == 0);
    codeindex_file(ci, "core/modules/net/fixtures/hidden_fixture.c", &cf, &found);
    CI_CHECK("fixture source stays outside the maintained universe", !found);
    codeindex_file(ci, "engine/composition/fixture_registry.def", &cf, &found);
    CI_CHECK("registry node is indexed for impact without C symbols", found &&
             strcmp(cf.group, "engine/composition") == 0);

    struct ci_source_file_counts source_counts;
    CI_CHECK("C23 and registry-node counts are exact and separate",
             codeindex_source_file_counts(ci, &source_counts) &&
             source_counts.c23_files == 19 &&
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
    system("rm -rf " FIX "/.codeindex");
    ci = codeindex_open(FIX);
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
    ci = codeindex_open(FIX);
    CI_CHECK("reopen after edit", ci != NULL);
    found = false;
    if (ci) codeindex_symbol(ci, "foo_added", &s, &found);
    CI_CHECK("staleness auto-rebuild reflects the edit",
             found && s.kind == 'T');

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

    /* A removed directory capability between validation and O_CREAT is
     * reacquired and revalidated rather than turning into a sporadic cold
     * open failure. This is the exact ENOENT boundary stressed by the 32-way
     * case below. */
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
    system("rm -rf " FIX "/.codeindex");
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
        char mk[64][64];
        int mn = disk_lib_modules(mk);
        size_t cn = 0;
        const char *const *code = ci_lib_modules(&cn);
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
        system("rm -rf " CG_FIX);
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
        system("rm -rf " CG_FIX);
    }

    /* ── 12: impact closure (F3, proof-DAG from symbol closure) ──
     * cl_a -> cl_b -> cl_c across three files; changing cl_c.c's file must
     * impact cl_b.c and cl_a.c too. Deterministic, depth-bounded, cap-honoured. */
    {
        system("rm -rf " CL_FIX);
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
        system("rm -rf " CL_FIX);
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

int test_codeindex(void)
{
    return test_codeindex_platform_arm();
}
