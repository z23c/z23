/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-sem-replay, proved on a history whose answer is known.
 *
 * The replay is a reporting tool: it replays real commits through make's
 * test-fast object build, the semantic sensor and dev.change.plan, and
 * compares what make recompiled with what the facts plan would have
 * compiled. Its one hard verdict is exit 3 on a code false negative (too
 * narrow), an object whose code changed that the facts plan left out; it
 * also counts false-wide TUs a plan selected whose object bytes did not
 * move, which is an over-selection, not a build-breaking miss, so it never
 * stops the run. A replay that missed a false negative, or that miscounted
 * either direction, would report savings that are not there. So this group
 * runs the REAL built binary (build/bin/z23-sem-replay) as a subprocess
 * against a throwaway git repository it builds itself:
 *
 *   P   src/a.c, src/b.c (both include src/common.h) and src/c.c (main)
 *   C1  changes the body of src/a.c
 *   C2  changes the inline function in src/common.h that only a.c calls
 *
 * The fixture's Makefile has the shape the replay reads from the real one:
 * TEST_PARALLEL_FAST_CANDIDATE names the link, build/test-obj/.current-epoch
 * names the epoch directory, and each object is compiled by one recipe line
 * "<tool> dep OBJ SRC -- CC FLAGS" (a small compiled wrapper that writes the
 * depfile and publishes the object by rename, as the real epoch compiler
 * does). The sensor and the planner are small compiled stand-ins: the sensor
 * writes the --cc and --toolchain-id it was given, then the source, into its
 * --out manifest (the replay only hashes manifests), and the planner
 * prints a canned dev.change.plan reply read from files beside it, with the
 * facts reply chosen when --input names "facts".
 *
 *   step C1 with a facts reply that lists no TU: make rebuilt src/a.c and its
 *   code changed, so the step must exit SR_STEP_FALSE_NEGATIVE (3) and write
 *   the TU to MISSES.tsv and sets.tsv. `run` over the same commit, with the
 *   tool found on PATH by its bare name, re-executes itself for the step and
 *   stops with the same exit.
 *
 *   step C2 with a facts reply that narrows to src/a.c: make rebuilds a.o and
 *   b.o, only a.o's bytes change, the plain plan selects both TUs and two
 *   groups, the facts plan one TU and one group. Every count is exact, and
 *   the report headline says 1 compile and 1 group avoided, with false-wide
 *   vs plain 1 (b.o was recompiled byte-identical, so the plain set's b.c
 *   is a natural over-selection) and false-wide vs facts 0.
 *
 *   step C2 again with a facts reply that over-selects src/b.c (the planted
 *   false-wide): the step still exits 0 (over-selection never stops a run),
 *   and its false-wide counts are exact: facts 1, plain 1.
 *
 * Everything runs under test-tmp/. git and the replay run under `env -u`
 * for the make and git variables a surrounding `make` or hook exports, so
 * the fixture's make and git never see the outer build or checkout. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE /* realpath */
#endif

#include "test/test_core.h"

int test_sem_replay(void);

#if !defined(_WIN32)

#include "util/spawn.h"
#include "json/json.h"
#include "zutf8/zutf8.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SRT_EPOCH "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
/* The fixture build's toolchain identity, as make's BUILD_COMPILER_ID. */
#define SRT_TOOLCHAIN "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
#define SRT_TIMEOUT_MS 600000
#define SRT_EXIT_FALSE_NEGATIVE 3 /* SR_STEP_FALSE_NEGATIVE, sem_replay_step.h */

struct srt_fx {
    char root[PATH_MAX];  /* test-tmp/sem_replay_<pid>_fx */
    char repo[PATH_MAX];  /* the fixture git repository */
    char tools[PATH_MAX]; /* compiled fixture programs */
    char tool[PATH_MAX];  /* the real z23-sem-replay */
    char p[64], c1[64], c2[64];
    bool objcopy;
};

static char g_srt_out[1 << 16];

/* ── the fixture programs ────────────────────────────────────────────── */

/* "<tool> dep OBJ SRC -- CC FLAGS...": compile SRC to OBJ.tmp with its
 * depfile beside OBJ, then publish OBJ by rename. */
static const char k_epoch_object[] =
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "#include <sys/wait.h>\n"
    "#include <unistd.h>\n"
    "int main(int argc, char **argv)\n"
    "{\n"
    "    char tmp[4096], dep[4096], *av[256];\n"
    "    int n = 0, st = 0;\n"
    "    if (argc < 6 || argc > 200 || strcmp(argv[1], \"dep\") != 0 ||\n"
    "        strcmp(argv[4], \"--\") != 0)\n"
    "        return 2;\n"
    "    size_t ol = strlen(argv[2]);\n"
    "    if (ol < 3 || strcmp(argv[2] + ol - 2, \".o\") != 0)\n"
    "        return 2;\n"
    "    snprintf(tmp, sizeof tmp, \"%s.tmp\", argv[2]);\n"
    "    snprintf(dep, sizeof dep, \"%.*s.d\", (int)(ol - 2), argv[2]);\n"
    "    for (int i = 5; i < argc; i++)\n"
    "        av[n++] = argv[i];\n"
    "    const char *tail[] = {\"-c\", argv[3], \"-o\", tmp, \"-MMD\", \"-MP\",\n"
    "                          \"-MF\", dep, \"-MT\", argv[2]};\n"
    "    for (int i = 0; i < 10; i++)\n"
    "        av[n++] = (char *)tail[i];\n"
    "    av[n] = NULL;\n"
    "    pid_t pid = fork();\n"
    "    if (pid == 0) {\n"
    "        execvp(av[0], av);\n"
    "        _exit(127);\n"
    "    }\n"
    "    if (pid < 0 || waitpid(pid, &st, 0) < 0 || !WIFEXITED(st) ||\n"
    "        WEXITSTATUS(st) != 0)\n"
    "        return 1;\n"
    "    return rename(tmp, argv[2]) == 0 ? 0 : 1;\n"
    "}\n";

/* "emit --root R --source TU --out F --facts [--toolchain-id X] [--cc Y]
 * -- FLAGS": F gets "cc=Y toolchain=X" (a dash for one not given) on its
 * first line, then TU's bytes. */
static const char k_sensor[] =
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "int main(int argc, char **argv)\n"
    "{\n"
    "    const char *src = NULL, *out = NULL, *cc = \"-\", *tc = \"-\";\n"
    "    char buf[4096];\n"
    "    size_t n;\n"
    "    if (argc < 2 || strcmp(argv[1], \"emit\") != 0)\n"
    "        return 2;\n"
    "    for (int i = 2; i + 1 < argc && strcmp(argv[i], \"--\") != 0; i++) {\n"
    "        if (strcmp(argv[i], \"--source\") == 0)\n"
    "            src = argv[++i];\n"
    "        else if (strcmp(argv[i], \"--out\") == 0)\n"
    "            out = argv[++i];\n"
    "        else if (strcmp(argv[i], \"--cc\") == 0)\n"
    "            cc = argv[++i];\n"
    "        else if (strcmp(argv[i], \"--toolchain-id\") == 0)\n"
    "            tc = argv[++i];\n"
    "        else if (strcmp(argv[i], \"--root\") == 0)\n"
    "            i++;\n"
    "    }\n"
    "    FILE *in = src ? fopen(src, \"rb\") : NULL;\n"
    "    FILE *o = in && out ? fopen(out, \"wb\") : NULL;\n"
    "    if (o == NULL)\n"
    "        return 1;\n"
    "    fprintf(o, \"cc=%s toolchain=%s\\n\", cc, tc);\n"
    "    while ((n = fread(buf, 1, sizeof buf, in)) > 0)\n"
    "        fwrite(buf, 1, n, o);\n"
    "    fclose(in);\n"
    "    return fclose(o) == 0 ? 0 : 1;\n"
    "}\n";

/* "dev change plan --input=JSON": print <argv0>.facts.json when the request
 * names a facts directory, else <argv0>.plain.json. */
static const char k_planner[] =
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "int main(int argc, char **argv)\n"
    "{\n"
    "    char path[4096], buf[4096];\n"
    "    size_t n;\n"
    "    if (argc != 5 || strcmp(argv[1], \"dev\") != 0 ||\n"
    "        strcmp(argv[2], \"change\") != 0 || strcmp(argv[3], \"plan\") != 0 ||\n"
    "        strncmp(argv[4], \"--input={\\\"files\\\":[\", 18) != 0) {\n"
    "        fprintf(stderr, \"fixture planner: unexpected argv\\n\");\n"
    "        return 2;\n"
    "    }\n"
    "    snprintf(path, sizeof path, \"%s.%s.json\", argv[0],\n"
    "             strstr(argv[4], \",\\\"facts\\\":\\\"\") ? \"facts\" : \"plain\");\n"
    "    FILE *in = fopen(path, \"rb\");\n"
    "    if (in == NULL)\n"
    "        return 1;\n"
    "    while ((n = fread(buf, 1, sizeof buf, in)) > 0)\n"
    "        fwrite(buf, 1, n, stdout);\n"
    "    fclose(in);\n"
    "    return 0;\n"
    "}\n";

/* ── the canned dev.change.plan replies ──────────────────────────────── */

#define SRT_ENVELOPE                                                         \
    "{\"schema\":\"zcl.command_result.v1\",\"command\":\"dev.change.plan\","   \
    "\"ok\":true,\"status\":\"passed\",\"data_schema\":\"zcl.dev_change_plan.v1\"," \
    "\"data\":{\"closure_universal\":false,\"execution_selector\":\"exact\","

/* The plain plan: two groups. */
static const char k_plain_reply[] =
    SRT_ENVELOPE
    "\"execution_groups\":[\"test_fx_a\",\"test_fx_b\"],\"execution_groups_listed\":2,"
    "\"execution_groups_total\":2}}\n";

#define SRT_FACTS_HEAD                                                       \
    SRT_ENVELOPE                                                             \
    "\"execution_groups\":[\"test_fx_a\"],\"execution_groups_listed\":1,"     \
    "\"execution_groups_total\":1,\"facts\":{\"narrowed\":true,"

#define SRT_OBLIGATIONS                                                      \
    "\"obligations\":{\"reason\":\"fixture\",\"plain\":2,"                     \
    "\"plain_universal\":false,\"facts\":1,\"groups\":[{\"group\":"           \
    "\"test_fx_a\",\"reason\":\"fixture\"}],\"groups_listed\":1},"

/* A complete universe that lists no TU: the planted omission. */
static const char k_facts_omits[] =
    SRT_FACTS_HEAD
    "\"reason\":\"fixture-omits-the-changed-tu\",\"detail\":\"\",\"seeds\":[],"
    "\"seeds_total\":0,\"reached_files\":0,\"consumer\":\"fixture\","
    SRT_OBLIGATIONS
    "\"universe\":{\"applied\":true,\"complete\":true,\"reason\":\"\","
    "\"detail\":\"\",\"total\":0,\"affected\":0,\"offset\":0,\"listed\":0,"
    "\"next_offset\":null},\"tus\":[]}}}\n";

/* A complete universe that narrows to src/a.c. */
static const char k_facts_narrows[] =
    SRT_FACTS_HEAD
    "\"reason\":\"fixture-narrows\",\"detail\":\"\",\"seeds\":[\"fx_a_value\"],"
    "\"seeds_total\":1,\"reached_files\":1,\"consumer\":\"fixture\","
    SRT_OBLIGATIONS
    "\"universe\":{\"applied\":true,\"complete\":true,\"reason\":\"\","
    "\"detail\":\"\",\"total\":2,\"affected\":1,\"offset\":0,\"listed\":2,"
    "\"next_offset\":null},\"tus\":["
    "{\"path\":\"src/a.c\",\"affected\":true,\"broadened\":false,"
    "\"reason\":\"implementation-changed\",\"detail\":\"\"},"
    "{\"path\":\"src/b.c\",\"affected\":false,\"broadened\":false,"
    "\"reason\":\"unchanged\",\"detail\":\"\"}]}}}\n";

/* A complete universe that over-selects: both TUs affected, though only
 * src/a.c's object bytes actually change (the planted false-wide). */
static const char k_facts_overselects[] =
    SRT_FACTS_HEAD
    "\"reason\":\"fixture-overselects\",\"detail\":\"\",\"seeds\":[\"fx_a_value\"],"
    "\"seeds_total\":1,\"reached_files\":1,\"consumer\":\"fixture\","
    SRT_OBLIGATIONS
    "\"universe\":{\"applied\":true,\"complete\":true,\"reason\":\"\","
    "\"detail\":\"\",\"total\":2,\"affected\":2,\"offset\":0,\"listed\":2,"
    "\"next_offset\":null},\"tus\":["
    "{\"path\":\"src/a.c\",\"affected\":true,\"broadened\":false,"
    "\"reason\":\"implementation-changed\",\"detail\":\"\"},"
    "{\"path\":\"src/b.c\",\"affected\":true,\"broadened\":false,"
    "\"reason\":\"fixture-overselect\",\"detail\":\"\"}]}}}\n";

/* ── the fixture tree ────────────────────────────────────────────────── */

static const char k_header_p[] =
    "#ifndef FX_COMMON_H\n"
    "#define FX_COMMON_H\n"
    "static inline int fx_a_value(void) { return 1; }\n"
    "static inline int fx_b_value(void) { return 7; }\n"
    "#endif\n";

static const char k_header_c2[] =
    "#ifndef FX_COMMON_H\n"
    "#define FX_COMMON_H\n"
    "static inline int fx_a_value(void) { return 2; }\n"
    "static inline int fx_b_value(void) { return 7; }\n"
    "#endif\n";

static const char k_a_p[] =
    "#include \"common.h\"\n"
    "int fx_a(void);\n"
    "int fx_a(void) { return fx_a_value(); }\n";

static const char k_a_c1[] =
    "#include \"common.h\"\n"
    "int fx_a(void);\n"
    "int fx_a(void) { return fx_a_value() + 40; }\n";

static const char k_b[] =
    "#include \"common.h\"\n"
    "int fx_b(void);\n"
    "int fx_b(void) { return fx_b_value(); }\n";

static const char k_c[] =
    "int fx_a(void);\n"
    "int fx_b(void);\n"
    "int main(void) { return fx_a() + fx_b() > 0 ? 0 : 1; }\n";

/* Everything after the FX_TOOL line. */
static const char k_makefile_body[] =
    "FX_CC := cc\n"
    "FX_CFLAGS := -O1\n"
    "FX_EPOCH := " SRT_EPOCH "\n"
    "BUILD_COMPILER_ID := " SRT_TOOLCHAIN "\n"
    "FX_OBJ := build/test-obj/epochs/$(FX_EPOCH)\n"
    "FX_MARK := build/test-obj/.current-epoch\n"
    "TEST_PARALLEL_FAST_CANDIDATE := build/fixture-test\n"
    "FX_OBJS := $(patsubst %.c,$(FX_OBJ)/%.o,src/a.c src/b.c src/c.c)\n"
    "\n"
    "$(TEST_PARALLEL_FAST_CANDIDATE): $(FX_OBJS)\n"
    "\t$(FX_CC) -o $@ $(FX_OBJS)\n"
    "\n"
    "$(FX_MARK):\n"
    "\t@mkdir -p $(dir $@)\n"
    "\t@echo $(FX_EPOCH) > $@\n"
    "\n"
    "$(FX_OBJ)/%.o: %.c | $(FX_MARK)\n"
    "\t@mkdir -p $(dir $@)\n"
    "\t$(FX_TOOL) dep $@ $< -- $(FX_CC) $(FX_CFLAGS)\n"
    "\n"
    "-include $(FX_OBJS:.o=.d)\n";

/* ── process helpers ─────────────────────────────────────────────────── */

/* Variables a surrounding make or git hook exports that must not reach the
 * fixture's make and git. */
static const char *const k_env_clear[] = {
    "env", "-u", "MAKEFLAGS", "-u", "MFLAGS", "-u", "MAKELEVEL", "-u",
    "MAKEOVERRIDES", "-u", "GNUMAKEFLAGS", "-u", "GIT_DIR", "-u",
    "GIT_WORK_TREE", "-u", "GIT_INDEX_FILE", "-u", "GIT_COMMON_DIR", "-u",
    "GIT_OBJECT_DIRECTORY", "-u", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "-u",
    "GIT_PREFIX", NULL};

/* Run args (NULL-terminated) under k_env_clear; stdout and stderr land in
 * g_srt_out. Returns the exit status, or -1. */
static int srt_run(const char *const *args)
{
    const char *argv[64];
    size_t n = 0;
    bool timed_out = false;
    for (size_t i = 0; k_env_clear[i] && n < 62; i++)
        argv[n++] = k_env_clear[i];
    for (size_t i = 0; args[i] && n < 63; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    int rc = zcl_spawn_capture_merged_observed(argv, g_srt_out, sizeof g_srt_out,
                                               SRT_TIMEOUT_MS, &timed_out);
    return timed_out ? -1 : rc;
}

static int srt_git(const char *repo, const char *const *args)
{
    const char *argv[24] = {"git", "-C", repo};
    size_t n = 3;
    for (size_t i = 0; args[i] && n < 23; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    return srt_run(argv);
}

static bool srt_mkdir_p(const char *path)
{
    char buf[PATH_MAX];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof buf)
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

/* Write text to dir/rel, creating rel's directories. */
static bool srt_write(const char *dir, const char *rel, const char *text)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/%s", dir, rel) >= (int)sizeof path)
        return false;
    char *slash = strrchr(path, '/');
    *slash = '\0';
    bool ok = srt_mkdir_p(path);
    *slash = '/';
    FILE *f = ok ? fopen(path, "wb") : NULL;
    if (f == NULL)
        return false;
    size_t len = strlen(text);
    bool wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static bool srt_read(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return false;
    size_t n = fread(out, 1, cap - 1, f);
    out[n] = '\0';
    fclose(f);
    return n < cap - 1;
}

/* ── building the fixture ────────────────────────────────────────────── */

/* Compile tools/<name>.c (text) to tools/<name>. */
static bool srt_cc(const struct srt_fx *fx, const char *name, const char *text)
{
    char src[PATH_MAX + 8], bin[PATH_MAX];
    char rel[64];
    snprintf(rel, sizeof rel, "%s.c", name);
    if (!srt_write(fx->tools, rel, text) ||
        snprintf(src, sizeof src, "%s/%s.c", fx->tools, name) >= (int)sizeof src ||
        snprintf(bin, sizeof bin, "%s/%s", fx->tools, name) >= (int)sizeof bin)
        return false;
    const char *argv[] = {"cc", "-std=c23", "-O1", "-o", bin, src, NULL};
    int rc = srt_run(argv);
    if (rc != 0)
        printf("(cc %s exited %d: %s) ", name, rc, g_srt_out);
    return rc == 0;
}

/* A planner stand-in named name whose replies are plain and facts. */
static bool srt_planner(const struct srt_fx *fx, const char *name, const char *facts)
{
    char rel[128];
    snprintf(rel, sizeof rel, "%s.plain.json", name);
    bool ok = srt_cc(fx, name, k_planner) && srt_write(fx->tools, rel, k_plain_reply);
    snprintf(rel, sizeof rel, "%s.facts.json", name);
    return ok && srt_write(fx->tools, rel, facts);
}

/* Compile the production translation unit into a bounded probe. Dead-code
 * elimination keeps unrelated replay drivers out; no sanitizer is required.
 * The probes replace allocation fault selection, string duplication and the
 * sort observer. Checked strdup does not consult the allocation fault hook. */
static const char k_replay_probe_head[] =
    "#define _GNU_SOURCE\n"
    "#include <stdlib.h>\n"
    "#include <stdbool.h>\n"
    "#include <stddef.h>\n"
    "#include <string.h>\n"
    "#include \"base/safe_alloc.h\"\n"
    "static unsigned alloc_calls, dup_calls;\n"
    "static char *probe_strdup(const char *s, const char *label)\n"
    "{ (void)s; (void)label; dup_calls++; return NULL; }\n"
    "#undef zcl_strdup\n"
    "#define zcl_strdup(s, label) probe_strdup(s, label)\n"
    "static unsigned small_sorts;\n"
    "static void probe_sort(void *p, size_t n, size_t z,\n"
    "                       int (*cmp)(const void *, const void *))\n"
    "{ if (n < 2) small_sorts++; else qsort(p, n, z, cmp); }\n"
    "#define qsort probe_sort\n";

static const char k_replay_probe_fault[] =
    "bool zcl_alloc_fault_should_fail(const char *label)\n"
    "{ (void)label; alloc_calls++; return true; }\n"
    "void zcl_alloc_note_failure(void) {}\n";

static const char k_replay_probe_snap[] =
    "int main(int argc, char **argv)\n"
    "{\n"
    "    struct sr_snap s;\n"
    "    if (argc != 2 || !sr_snap_load(&s, argv[1])) return 1;\n"
    "    if (s.n != 0 || s.v != NULL || small_sorts != 0) return 2;\n"
    "    return strcmp(s.epoch, \"" SRT_EPOCH "\");\n"
    "}\n";

static const char k_replay_probe_cost[] =
    "static int probe_cost_overflow(size_t cap)\n"
    "{\n"
    "    struct cost_table t = {.n = cap, .cap = cap};\n"
    "    alloc_calls = dup_calls = 0;\n"
    "    if (cost_push(&t, \"overflow.c\", 3)) return 1;\n"
    "    if (t.n != cap || t.cap != cap || t.v != NULL) return 2;\n"
    "    return alloc_calls != 0 || dup_calls != 0;\n"
    "}\n"
    "static int probe_cost_retention(void)\n"
    "{\n"
    "    struct cost_row rows[2] = {{.tu = \"kept.c\", .cpu = 7},\n"
    "                               {.tu = \"sentinel.c\", .cpu = 9}};\n"
    "    struct cost_table t = {.v = rows, .n = 1, .cap = 2};\n"
    "    if (cost_push(&t, \"failed.c\", 3)) return 1;\n"
    "    if (t.n != 1 || t.cap != 2 || t.v != rows) return 2;\n"
    "    if (strcmp(rows[0].tu, \"kept.c\") || rows[0].cpu != 7) return 3;\n"
    "    if (strcmp(rows[1].tu, \"sentinel.c\") || rows[1].cpu != 9) return 4;\n"
    "    if (dup_calls != 1 || alloc_calls != 0) return 5;\n"
    "    return 0;\n"
    "}\n"
    "int main(void)\n"
    "{\n"
    "    int rc = probe_cost_retention();\n"
    "    if (rc) return rc;\n"
    "    if (probe_cost_overflow(SIZE_MAX)) return 6;\n"
    "    if (probe_cost_overflow(SIZE_MAX / sizeof(struct cost_row))) return 7;\n"
    "    return 0;\n"
    "}\n";

static const char k_replay_probe_price[] =
    "static int probe_price_overflow(size_t cap)\n"
    "{\n"
    "    struct prices p = {.n = cap, .cap = cap};\n"
    "    alloc_calls = dup_calls = 0;\n"
    "    if (price_push(&p, \"overflow.c\", 3)) return 1;\n"
    "    if (p.n != cap || p.cap != cap || p.v != NULL) return 2;\n"
    "    return alloc_calls != 0 || dup_calls != 0;\n"
    "}\n"
    "static int probe_price_retention(void)\n"
    "{\n"
    "    struct price_row rows[2] = {{.tu = \"kept.c\", .cpu = 7, .n = 1},\n"
    "                                {.tu = \"sentinel.c\", .cpu = 9, .n = 2}};\n"
    "    struct prices p = {.v = rows, .n = 1, .cap = 2};\n"
    "    if (price_push(&p, \"failed.c\", 3)) return 1;\n"
    "    if (p.n != 1 || p.cap != 2 || p.v != rows) return 2;\n"
    "    if (strcmp(rows[0].tu, \"kept.c\") || rows[0].cpu != 7 || rows[0].n != 1) return 3;\n"
    "    if (strcmp(rows[1].tu, \"sentinel.c\") || rows[1].cpu != 9 || rows[1].n != 2) return 4;\n"
    "    if (dup_calls != 1 || alloc_calls != 0) return 5;\n"
    "    return 0;\n"
    "}\n"
    "int main(void)\n"
    "{\n"
    "    int rc = probe_price_retention();\n"
    "    if (rc) return rc;\n"
    "    if (probe_price_overflow(SIZE_MAX)) return 6;\n"
    "    if (probe_price_overflow(SIZE_MAX / sizeof(struct price_row))) return 7;\n"
    "    return 0;\n"
    "}\n";

static bool srt_execute_row_probe(const struct srt_fx *fx, const char *name,
                                  const char *text)
{
    char src[PATH_MAX + 32], bin[PATH_MAX + 32];
    char snap[PATH_MAX + 32], rel[64];
    if (snprintf(rel, sizeof rel, "%s.c", name) >= (int)sizeof rel ||
        !srt_write(fx->tools, rel, text) ||
        snprintf(src, sizeof src, "%s/%s.c", fx->tools, name) >= (int)sizeof src ||
        snprintf(bin, sizeof bin, "%s/%s", fx->tools, name) >= (int)sizeof bin ||
        snprintf(snap, sizeof snap, "%s/epoch.snap", fx->tools) >= (int)sizeof snap)
        return false;
#ifdef __APPLE__
    const char *strip = "-Wl,-dead_strip";
#else
    const char *strip = "-Wl,--gc-sections";
#endif
    const char *cc[] = {"cc", "-std=c23", "-O1", "-ffunction-sections",
                        "-fdata-sections", strip, "-I.",
                        "-Iplatform/modules/base/include", "-o", bin, src, NULL};
    if (srt_run(cc) != 0) {
        printf("(replay probe compile %s: %s) ", name, g_srt_out);
        return false;
    }
    const char *run[] = {bin, snap, NULL};
    int rc = srt_run(run);
    if (rc != 0)
        printf("(replay probe %s exited %d: %s) ", name, rc, g_srt_out);
    return rc == 0;
}

static bool srt_compile_row_probe(const struct srt_fx *fx, const char *name,
                                  const char *source, const char *body)
{
    char text[8192];
    int len = snprintf(text, sizeof text, "%s#include \"tools/dev/%s\"\n%s%s",
                       k_replay_probe_head, source, k_replay_probe_fault, body);
    if (len < 0 || len >= (int)sizeof text)
        return false;
    return srt_execute_row_probe(fx, name, text);
}

/* Include each production reader; fixed buffers replace allocation only.
 * The fixture paths belong to the test_core.h-created replay directory. */
static const char k_replay_reader_head[] =
    "#define _GNU_SOURCE\n"
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <stdbool.h>\n"
    "#include <string.h>\n"
    "#include \"base/safe_alloc.h\"\n"
    "static bool read_fail, close_fail;\n"
    "static unsigned read_count;\n"
    "static int probe_getc(FILE *fp)\n"
    "{ if (read_fail && read_count++ == 6) return EOF; return fgetc(fp); }\n"
    "static int probe_error(FILE *fp)\n"
    "{ return read_fail || ferror(fp); }\n"
    "static int probe_close(FILE *fp)\n"
    "{ int rc = fclose(fp); return close_fail ? EOF : rc; }\n"
    "static union { max_align_t align; unsigned char bytes[512 * 1024]; } rows;\n"
    "static char tu_copy[4096];\n"
    "static void *probe_rows(void *p, size_t n, const char *label)\n"
    "{ (void)p; (void)label; return n <= sizeof rows.bytes ? rows.bytes : NULL; }\n"
    "static char *probe_tu(const char *s, const char *label)\n"
    "{ (void)label; size_t n = strlen(s); if (n >= sizeof tu_copy) return NULL;\n"
    "  memcpy(tu_copy, s, n + 1); return tu_copy; }\n"
    "#undef zcl_realloc\n"
    "#undef zcl_strdup\n"
    "#define zcl_realloc(p, n, label) probe_rows(p, n, label)\n"
    "#define zcl_strdup(s, label) probe_tu(s, label)\n"
    "#define fgetc probe_getc\n"
    "#define ferror probe_error\n"
    "#define fclose probe_close\n";

static const char k_replay_reader_body[] =
    "static int fixture(const char *path, const char *bytes, size_t n, bool want)\n"
    "{\n"
    "    FILE *fp = fopen(path, \"wb\");\n"
    "    if (!fp) return 1;\n"
    "    bool written = fwrite(bytes, 1, n, fp) == n;\n"
    "    int closed = probe_close(fp);\n"
    "    if (!written || (!close_fail && closed != 0)) return 2;\n"
    "    read_count = 0;\n"
    "    bool got = probe_load(path);\n"
    "    if (got != want) {\n"
    "        fprintf(stderr, \"reader accepted=%d expected=%d length=%zu\\n\", got, want, n);\n"
    "        return 3;\n"
    "    }\n"
    "    return 0;\n"
    "}\n"
    "static int malformed(const char *path)\n"
    "{\n"
    "    static const char nul[] = VALID_PREFIX \"\\0hidden\\n\";\n"
    "    static const char tail[] = VALID_PREFIX \"\\textra\\n\";\n"
    "    static const char junk[] = INVALID_RECORD;\n"
    "    static const char empty[] = \"\\t3\\n\";\n"
    "    char long_line[4608];\n"
    "    memset(long_line, 'x', sizeof long_line);\n"
    "    memcpy(long_line, VALID_PREFIX, sizeof(VALID_PREFIX) - 1);\n"
    "    long_line[sizeof long_line - 1] = '\\n';\n"
    "    if (fixture(path, nul, sizeof nul - 1, false)) return 1;\n"
    "    if (fixture(path, tail, sizeof tail - 1, false)) return 2;\n"
    "    if (fixture(path, junk, sizeof junk - 1, false)) return 3;\n"
    "    if (fixture(path, empty, sizeof empty - 1, false)) return 4;\n"
    "    return fixture(path, long_line, sizeof long_line, false);\n"
    "}\n"
    "static int io_failures(const char *path)\n"
    "{\n"
    "    read_fail = true;\n"
    "    int rc = fixture(path, VALID_RECORD, sizeof(VALID_RECORD) - 1, false);\n"
    "    read_fail = false;\n"
    "    if (rc) return 1;\n"
    "    close_fail = true;\n"
    "    rc = fixture(path, VALID_RECORD, sizeof(VALID_RECORD) - 1, false);\n"
    "    close_fail = false;\n"
    "    return rc;\n"
    "}\n"
    "int main(int argc, char **argv)\n"
    "{\n"
    "    if (argc != 2) return 1;\n"
    "    if (fixture(argv[1], VALID_RECORD, sizeof(VALID_RECORD) - 1, true)) return 2;\n"
    "    if (fixture(argv[1], VALID_PREFIX, sizeof(VALID_PREFIX) - 1, true)) return 3;\n"
    "    if (malformed(argv[1])) return 4;\n"
    "    if (io_failures(argv[1])) return 5;\n"
    "    return additional(argv[1]);\n"
    "}\n";

static const char k_replay_reader_snap[] =
    "#include \"tools/dev/sem_replay_build.c\"\n"
    "#define VALID_PREFIX \"epoch\\tok\"\n"
    "#define VALID_RECORD \"epoch\\tok\\n\"\n"
    "#define INVALID_RECORD \"epoch\\tok\\textra\\n\"\n"
    "static bool probe_load(const char *path)\n"
    "{ struct sr_snap s; return sr_snap_load(&s, path); }\n"
    "static int additional(const char *path);\n";

static const char k_replay_reader_cost[] =
    "#include \"tools/dev/sem_replay_step.c\"\n"
    "#define VALID_PREFIX \"src/a.c\\t3\"\n"
    "#define VALID_RECORD \"src/a.c\\t3\\t4\\t1\\n\"\n"
    "#define INVALID_RECORD \"src/a.c\\t3junk\\n\"\n"
    "static bool probe_load(const char *path)\n"
    "{ struct cost_table t = {0}; return cost_load(&t, path); }\n"
    "static int additional(const char *path);\n";

static const char k_replay_reader_price[] =
    "#include \"tools/dev/sem_replay_report.c\"\n"
    "#define VALID_PREFIX \"src/a.c\\t3\"\n"
    "#define VALID_RECORD \"src/a.c\\t3\\t4\\t1\\n\"\n"
    "#define INVALID_RECORD \"src/a.c\\t3junk\\n\"\n"
    "static bool probe_load(const char *path)\n"
    "{ struct prices p = {0}; return prices_load(&p, path); }\n"
    "static int additional(const char *path);\n";

static const char k_replay_reader_snap_extra[] =
    "static int additional(const char *path)\n"
    "{\n"
    "    static const char row[] = \"src/a.c\\t1\\t2\\t3\\t\"\n"
    "        \"0000000000000000000000000000000000000000000000000000000000000000\";\n"
    "    char tail[256];\n"
    "    if (fixture(path, row, sizeof row - 1, true)) return 1;\n"
    "    int n = snprintf(tail, sizeof tail, \"%sX\\n\", row);\n"
    "    if (n < 0 || n >= (int)sizeof tail) return 2;\n"
    "    if (fixture(path, tail, (size_t)n, false)) return 3;\n"
    "    n = snprintf(tail, sizeof tail, \"%s\\textra\\n\", row);\n"
    "    if (n < 0 || n >= (int)sizeof tail) return 4;\n"
    "    return fixture(path, tail, (size_t)n, false);\n"
    "}\n";

static const char k_replay_reader_cost_extra[] =
    "static int additional(const char *path)\n"
    "{\n"
    "    static const char extra[] = \"src/a.c\\t3\\t4\\t1\\textra\\n\";\n"
    "    static const char partial[] = \"src/a.c\\t3\\t4\\n\";\n"
    "    static const char bad_wall[] = \"src/a.c\\t3\\t4junk\\t1\\n\";\n"
    "    static const char bad_match[] = \"src/a.c\\t3\\t4\\t1junk\\n\";\n"
    "    if (fixture(path, extra, sizeof extra - 1, false)) return 1;\n"
    "    if (fixture(path, partial, sizeof partial - 1, false)) return 2;\n"
    "    if (fixture(path, bad_wall, sizeof bad_wall - 1, false)) return 3;\n"
    "    return fixture(path, bad_match, sizeof bad_match - 1, false);\n"
    "}\n";

static bool srt_compile_reader_probe(const struct srt_fx *fx, const char *name,
                                     const char *reader, const char *extra)
{
    char text[8192];
    int n = snprintf(text, sizeof text, "%s%s%s%s", k_replay_reader_head,
                     reader, k_replay_reader_body, extra);
    if (n < 0 || n >= (int)sizeof text)
        return false;
    return srt_execute_row_probe(fx, name, text);
}

static bool srt_replay_reader_cases(const struct srt_fx *fx)
{
    return srt_compile_reader_probe(fx, "snap-reader", k_replay_reader_snap,
                                    k_replay_reader_snap_extra) &&
           srt_compile_reader_probe(fx, "cost-reader", k_replay_reader_cost,
                                    k_replay_reader_cost_extra) &&
           srt_compile_reader_probe(fx, "price-reader", k_replay_reader_price,
                                    k_replay_reader_cost_extra);
}

static bool srt_replay_row_cases(const struct srt_fx *fx)
{
    return srt_write(fx->tools, "epoch.snap", "epoch\t" SRT_EPOCH "\n") &&
           srt_compile_row_probe(fx, "snap-probe", "sem_replay_build.c", k_replay_probe_snap) &&
           srt_compile_row_probe(fx, "cost-probe", "sem_replay_step.c", k_replay_probe_cost) &&
           srt_compile_row_probe(fx, "price-probe", "sem_replay_report.c", k_replay_probe_price);
}

static bool srt_tools(struct srt_fx *fx)
{
    return srt_replay_row_cases(fx) && srt_replay_reader_cases(fx) &&
           srt_cc(fx, "fx-epoch-object", k_epoch_object) && srt_cc(fx, "fx-sensor", k_sensor) &&
           srt_planner(fx, "fx-planner-omits", k_facts_omits) &&
           srt_planner(fx, "fx-planner-narrows", k_facts_narrows) &&
           srt_planner(fx, "fx-planner-overselects", k_facts_overselects);
}

/* Stage everything under the repo and commit it; out gets the commit. */
static bool srt_commit(const struct srt_fx *fx, const char *msg, char out[64])
{
    const char *add[] = {"add", "-A", NULL};
    const char *commit[] = {"-c", "user.name=sem-replay", "-c",
                            "user.email=sem-replay@z23.invalid", "commit", "--quiet",
                            "--no-verify", "--no-gpg-sign", "-m", msg, NULL};
    const char *head[] = {"rev-parse", "HEAD", NULL};
    if (srt_git(fx->repo, add) != 0 || srt_git(fx->repo, commit) != 0 ||
        srt_git(fx->repo, head) != 0)
        return false;
    g_srt_out[strcspn(g_srt_out, "\r\n")] = '\0';
    snprintf(out, 64, "%s", g_srt_out);
    return strlen(out) == 40;
}

static bool srt_tree_p(const struct srt_fx *fx)
{
    char mk[PATH_MAX + 32];
    snprintf(mk, sizeof mk, "FX_TOOL := %s/fx-epoch-object\n", fx->tools);
    char *body = malloc(strlen(mk) + sizeof k_makefile_body);
    if (body == NULL)
        return false;
    memcpy(body, mk, strlen(mk));
    memcpy(body + strlen(mk), k_makefile_body, sizeof k_makefile_body);
    bool ok = srt_write(fx->repo, "Makefile", body) &&
              srt_write(fx->repo, ".gitignore", "build/\n") &&
              srt_write(fx->repo, "src/common.h", k_header_p) &&
              srt_write(fx->repo, "src/a.c", k_a_p) && srt_write(fx->repo, "src/b.c", k_b) &&
              srt_write(fx->repo, "src/c.c", k_c);
    free(body);
    return ok;
}

/* The repository: P, then C1 (a.c's body), then C2 (common.h's fx_a_value). */
static bool srt_history(struct srt_fx *fx)
{
    const char *init[] = {"-c", "init.defaultBranch=main", "init", "--quiet", NULL};
    return srt_mkdir_p(fx->repo) && srt_git(fx->repo, init) == 0 && srt_tree_p(fx) &&
           srt_commit(fx, "P: three TUs and a header", fx->p) &&
           srt_write(fx->repo, "src/a.c", k_a_c1) &&
           srt_commit(fx, "C1: change the body of a.c", fx->c1) &&
           srt_write(fx->repo, "src/common.h", k_header_c2) &&
           srt_commit(fx, "C2: change the inline function only a.c calls", fx->c2);
}

static bool srt_find_tool(struct srt_fx *fx)
{
    const char *bin = getenv("ZCL_SEM_REPLAY_BIN");
    if (bin == NULL || bin[0] == '\0')
        bin = "build/bin/z23-sem-replay";
    if (realpath(bin, fx->tool) == NULL || access(fx->tool, X_OK) != 0) {
        printf("(%s is a required prerequisite: make sem-replay-bin) ", bin);
        return false;
    }
    return true;
}

/* Exercise the exact TU copy and failure flag through the owned callback. */
static int srt_tu_paths(const struct srt_fx *fx)
{
    const char *source =
        "/* Verify replay TU response path bounds. */\n"
        "#include \"tools/dev/sem_replay_plan.c\"\n"
        "bool sr_strv_push(struct sr_strv *s, const char *v)\n"
        "{ (void)v; s->n++; return true; }\n"
        "int main(void) {\n"
        " struct sr_plan p = {0}; struct pctx c = {.p = &p};\n"
        " char path[1025]; memset(path, 'a', 1024); path[1024] = 0;\n"
        " on_value(&c, \"data.facts.tus[].path\", path);\n"
        " on_value(&c, \"data.facts.tus[].affected\", \"true\");\n"
        " if (!c.failed || c.row_open || p.tus_affected.n) return 1;\n"
        " on_value(&c, \"data.facts.tus[].path\", \"src/ignored.c\");\n"
        " if (c.row_open || c.row_path[0] || p.tu_rows.n) return 5;\n"
        " c = (struct pctx){.p = &p}; path[1023] = 0;\n"
        " on_value(&c, \"data.facts.tus[].path\", path);\n"
        " if (c.failed || !c.row_open || strcmp(c.row_path, path)) return 2;\n"
        " on_value(&c, \"data.facts.tus[].affected\", \"true\");\n"
        " on_container_close(&c, \"data.facts.tus[]\");\n"
        " on_value(&c, \"data.facts.tus[].path\", \"src/a.c\");\n"
        " if (p.tus_affected.n != 1 || strcmp(c.row_path, \"src/a.c\")) return 3;\n"
        " return c.row_open ? 0 : 4;\n"
        "}\n";
    char src[PATH_MAX + 32], bin[PATH_MAX + 32];
    if (!srt_write(fx->tools, "tu-paths.c", source))
        return 1;
    snprintf(src, sizeof src, "%s/tu-paths.c", fx->tools);
    snprintf(bin, sizeof bin, "%s/tu-paths", fx->tools);
#if defined(__APPLE__)
    const char *discard = "-Wl,-dead_strip";
#else
    const char *discard = "-Wl,--gc-sections";
#endif
    const char *cc[] = {"cc", "-std=c23", "-O1", "-ffunction-sections",
                        "-fdata-sections", discard, "-I.",
                        "-Iplatform/modules/base/include",
                        "-Icontexts/commons/packages/zutf8/include",
                        "-o", bin, src, NULL};
    if (srt_run(cc) != 0) {
        printf("(TU path probe compile output: %s) ", g_srt_out);
        return 1;
    }
    const char *run[] = {bin, NULL};
    int rc = srt_run(run);
    if (rc != 0)
        printf("(TU path probe exit %d: %s) ", rc, g_srt_out);
    return rc != 0;
}

/* Run the public plan reader with real JSON flattening and a fixed clock. */
static bool srt_plan_probe(const struct srt_fx *fx)
{
    static const char source[] =
        "/* Observe exact replay TU fields and page refusal. */\n"
        "#include \"tools/dev/sem_replay_plan.c\"\n"
        "#include \"platform/clock.h\"\n"
        "int64_t clock_now_monotonic_ns(void) { return 0; }\n"
        "int main(int argc, char **argv) {\n"
        " struct sr_plan p; struct sr_strv files = {0};\n"
        " if (argc != 2 && argc != 3) return 2;\n"
        " if (argc == 3) zcl_alloc_fault_fail_nth(\"sem_replay_json_scratch\",\n"
        "     (unsigned)(argv[2][0] - '0'));\n"
        " bool ok = sr_plan_run(argv[1], NULL, &files, \"facts\", NULL, &p);\n"
        " printf(\"%d %d %zu %zu %s\\n\", ok, p.ok, p.tus_affected.n, p.tu_rows.n, p.error);\n"
        " for (size_t i = 0; i < p.tu_rows.n; i++) puts(p.tu_rows.v[i]);\n"
        " for (size_t i = 0; i < p.tus_affected.n; i++) puts(p.tus_affected.v[i]);\n"
        " sr_plan_free(&p); return 0;\n"
        "}\n";
    char src[PATH_MAX + 32], bin[PATH_MAX + 32];
    if (!srt_write(fx->tools, "plan-fields.c", source))
        return false;
    snprintf(src, sizeof src, "%s/plan-fields.c", fx->tools);
    snprintf(bin, sizeof bin, "%s/plan-fields", fx->tools);
    const char *cc[] = {"cc", "-std=c23", "-O1", "-D_DEFAULT_SOURCE",
        "-D_POSIX_C_SOURCE=200809L", "-I.", "-Iplatform/modules/base/include",
        "-Iplatform/modules/platform/include", "-Iplatform/modules/sha3/include",
        "-Icontexts/commons/packages/zjsonp/include", "-Icontexts/commons/packages/zutf8/include",
        "-o", bin, src, "tools/dev/sem_replay_util.c", "platform/modules/base/src/safe_alloc.c",
        "platform/modules/sha3/src/sha3.c", "contexts/commons/packages/zjsonp/src/zjsonp.c",
        "contexts/commons/packages/zutf8/src/zutf8.c", NULL};
    int rc = srt_run(cc);
    if (rc != 0)
        printf("(plan field probe compile exit %d: %s) ", rc, g_srt_out);
    return rc == 0;
}

static void srt_plan_expected(char expected[3600], const char *const v[4],
                              size_t field, bool fits)
{
    if (!fits) {
        snprintf(expected, 3600, "0 0 1 1 planner TU field overflow at offset 0\n"
            "src/keep.c\ttrue\tfalse\tkeep\nsrc/keep.c\n");
        return;
    }
    const char *first = "src/keep.c", *second = "src/next.c\n";
    if (field == 0) { first = v[0]; second = "src/keep.c\n"; }
    if (field == 1) second = "";
    snprintf(expected, 3600, "1 1 %d 2 \nsrc/keep.c\ttrue\tfalse\tkeep\n"
        "%s\t%s\t%s\t%s\n%s\n%s", field == 1 ? 1 : 2,
        v[0], v[1], v[2], v[3], first, second);
}

/* The first valid row survives refusal; the oversized row and later rows do not. */
static int srt_plan_field_case(const struct srt_fx *fx, size_t field, int length, bool fits)
{
    int failures = 0;
    char value[1025], reply[1800], expected[3600];
    char probe[PATH_MAX + 32], planner[PATH_MAX + 32];
    const char *v[] = {"src/next.c", "true", "false", "changed"};
    memset(value, 'a', (size_t)length);
    value[length] = '\0';
    v[field] = value;
    snprintf(probe, sizeof probe, "%s/plan-fields", fx->tools);
    snprintf(planner, sizeof planner, "%s/fx-fields", fx->tools);
    const char *later = fits ? "" : ",{\"path\":\"src/later.c\",\"affected\":true,"
        "\"broadened\":false,\"reason\":\"later\"}";
    snprintf(reply, sizeof reply, SRT_ENVELOPE
        "\"facts\":{\"tus\":[{\"path\":\"src/keep.c\",\"affected\":true,"
        "\"broadened\":false,\"reason\":\"keep\"},"
        "{\"path\":\"%s\",\"affected\":\"%s\",\"broadened\":\"%s\",\"reason\":\"%s\"}%s]}}}",
        v[0], v[1], v[2], v[3], later);
    srt_plan_expected(expected, v, field, fits);
    TEST("replay plan reader preserves fitting TU fields and refuses overflow") {
        printf("(field=%zu bytes=%d) ", field, length);
        ASSERT(srt_write(fx->tools, "fx-fields.facts.json", reply));
        const char *argv[] = {probe, planner, NULL};
        ASSERT_EQ(srt_run(argv), 0);
        const char *result = strstr(g_srt_out, expected);
        ASSERT(result != NULL);
        ASSERT_STR_EQ(result, expected);
        PASS();
    }
_test_next:;
    return failures;
}

/* Preserve a completed row, excluding the malformed row and its successor. */
static int srt_plan_decode_case(const struct srt_fx *fx, const char *key,
                                size_t field, const char *value)
{
    int failures = 0;
    char reply[1800], probe[PATH_MAX + 32], planner[PATH_MAX + 32];
    const char *v[] = {"src/next.c", "true", "false", "changed"};
    const char *keys[] = {"path", "affected", "broadened", "reason"};
    keys[field] = key;
    v[field] = value;
    snprintf(probe, sizeof probe, "%s/plan-fields", fx->tools);
    snprintf(planner, sizeof planner, "%s/fx-fields", fx->tools);
    snprintf(reply, sizeof reply, SRT_ENVELOPE
        "\"facts\":{\"tus\":[{\"path\":\"src/keep.c\",\"affected\":true,"
        "\"broadened\":false,\"reason\":\"keep\"},"
        "{\"%s\":\"%s\",\"%s\":\"%s\","
        "\"%s\":\"%s\",\"%s\":\"%s\"},"
        "{\"path\":\"src/later.c\",\"affected\":true,"
        "\"broadened\":false,\"reason\":\"later\"}]}}}",
        keys[0], v[0], keys[1], v[1], keys[2], v[2], keys[3], v[3]);
    TEST("replay plan reader refuses decoded NUL and invalid strings") {
        printf("(key=%s field=%zu) ", key, field);
        ASSERT(srt_write(fx->tools, "fx-fields.facts.json", reply));
        const char *argv[] = {probe, planner, NULL};
        ASSERT_EQ(srt_run(argv), 0);
        const char *expected = "0 0 1 1 planner exit 0 at offset 0\n"
            "src/keep.c\ttrue\tfalse\tkeep\nsrc/keep.c\n";
        const char *result = strstr(g_srt_out, expected);
        ASSERT(result != NULL);
        ASSERT_STR_EQ(result, expected);
        PASS();
    }
_test_next:;
    return failures;
}

/* Keep flushed evidence, but refuse the malformed row and every later row. */
static int srt_plan_nul_case(const struct srt_fx *fx, size_t field, int length,
                            bool key)
{
    int failures = 0;
    char suffix[1025], value[1040], reply[2000];
    char probe[PATH_MAX + 32], planner[PATH_MAX + 32];
    const char *names[] = {"path", "affected", "broadened", "reason"};
    const char *keys[] = {"path", "affected", "broadened", "reason"};
    const char *values[] = {"src/next.c", "true", "false", "changed"};
    memset(suffix, 'a', (size_t)length);
    suffix[length] = '\0';
    snprintf(value, sizeof value, "%s\\u0000%s", key ? names[field] : "ok", suffix);
    if (key)
        keys[field] = value;
    else
        values[field] = value;
    snprintf(probe, sizeof probe, "%s/plan-fields", fx->tools);
    snprintf(planner, sizeof planner, "%s/fx-fields", fx->tools);
    snprintf(reply, sizeof reply, SRT_ENVELOPE
        "\"facts\":{\"tus\":[{\"path\":\"src/keep.c\",\"affected\":true,"
        "\"broadened\":false,\"reason\":\"keep\"},"
        "{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":\"%s\"},"
        "{\"path\":\"src/later.c\",\"affected\":true,\"broadened\":false,"
        "\"reason\":\"later\"}]}}}", keys[0], values[0], keys[1], values[1],
        keys[2], values[2], keys[3], values[3]);
    TEST("replay plan reader refuses decoded NUL in TU fields and keys") {
        printf("(field=%zu suffix=%d key=%d) ", field, length, key);
        ASSERT(srt_write(fx->tools, "fx-fields.facts.json", reply));
        const char *argv[] = {probe, planner, NULL};
        ASSERT_EQ(srt_run(argv), 0);
        const char *expected = "0 0 1 1 planner exit 0 at offset 0\n"
            "src/keep.c\ttrue\tfalse\tkeep\nsrc/keep.c\n";
        const char *result = strstr(g_srt_out, expected);
        ASSERT(result != NULL);
        ASSERT_STR_EQ(result, expected);
        PASS();
    }
_test_next:;
    return failures;
}

/* Refuse scratch growth at a key, before callbacks or after a flushed TU. */
static int srt_plan_key_alloc_case(const struct srt_fx *fx, const char *reply,
                                  const char *nth, const char *expected)
{
    int failures = 0;
    char probe[PATH_MAX + 32], planner[PATH_MAX + 32];
    snprintf(probe, sizeof probe, "%s/plan-fields", fx->tools);
    snprintf(planner, sizeof planner, "%s/fx-fields", fx->tools);
    TEST("replay plan reader refuses key scratch allocation failure") {
        printf("(allocation=%s) ", nth);
        ASSERT(srt_write(fx->tools, "fx-fields.facts.json", reply));
        const char *argv[] = {probe, planner, nth, NULL};
        ASSERT_EQ(srt_run(argv), 0);
        const char *result = strstr(g_srt_out, expected);
        ASSERT(result != NULL);
        ASSERT_STR_EQ(result, expected);
        ASSERT(strstr(g_srt_out, "sem_replay_json_scratch") != NULL);
        PASS();
    }
_test_next:;
    return failures;
}

static int srt_plan_key_alloc(const struct srt_fx *fx)
{
    static const char reply[] =
        "{\"facts\":{\"tus\":[{\"path\":\"src/keep.c\",\"affected\":true,"
        "\"broadened\":false,\"reason\":\"keep\"},"
        "{\"path\":\"src/next.c\",\"affected\":true,\"broadened\":false,"
        "\"reason\":\"next\",\"unknown_key_needs_scratch\":true},"
        "{\"path\":\"src/later.c\",\"affected\":true,\"broadened\":false,"
        "\"reason\":\"later\"}]}}";
    int failures = srt_plan_key_alloc_case(fx, "{\"facts\":{\"tus\":[]}}", "1",
        "0 0 0 0 planner exit 0 at offset 0\n");
    failures += srt_plan_key_alloc_case(fx, reply, "3",
        "0 0 1 1 planner exit 0 at offset 0\n"
        "src/keep.c\ttrue\tfalse\tkeep\nsrc/keep.c\n");
    return failures;
}

static int srt_plan_fields(const struct srt_fx *fx)
{
    static const int caps[] = {1024, 8, 8, 128};
    static const char *names[] = {"path", "affected", "broadened", "reason"};
    if (!srt_plan_probe(fx) || !srt_cc(fx, "fx-fields", k_planner))
        return 1;
    int failures = srt_plan_key_alloc(fx);
    for (size_t i = 0; i < sizeof caps / sizeof caps[0]; i++) {
        failures += srt_plan_field_case(fx, i, caps[i], false);
        failures += srt_plan_field_case(fx, i, caps[i] - 1, true);
        char value[1033] = "ok\\u0000";
        memset(value + 8, 'a', (size_t)caps[i]);
        value[8 + caps[i]] = '\0';
        failures += srt_plan_decode_case(fx, names[i], i, value);
        char key[32];
        snprintf(key, sizeof key, "%s\\u0000suffix", names[i]);
        static const char *values[] = {"src/next.c", "true", "false", "changed"};
        failures += srt_plan_decode_case(fx, key, i, values[i]);
        failures += srt_plan_nul_case(fx, i, caps[i], false);
        failures += srt_plan_nul_case(fx, i, 1, false);
        failures += srt_plan_nul_case(fx, i, 1, true);
    }
    failures += srt_plan_decode_case(fx, "reason", 3, "ok\xff");
    failures += srt_plan_decode_case(fx, "reason", 3, "ok\\ud800");
    return failures;
}

/* Compile the real reader with deterministic read results and time. */
static bool srt_reader_fixture(const struct srt_fx *fx, char bin[PATH_MAX])
{
    static const char source[] =
        "#define _GNU_SOURCE\n#include <unistd.h>\n#include <errno.h>\n"
        "#include <string.h>\nstatic int mode, calls;\n"
        "static ssize_t injected(int fd, void *p, size_t n) {\n"
        "(void)fd; if(n<3)return -1; int c=calls++;\n"
        "if(c==0){errno=EINTR;return -1;}\n"
        "if(c==1){memcpy(p,\"x\\nx\",3);return 3;}\n"
        "if(mode){errno=EIO;return -1;}return 0;}\n"
        "#define read injected\n#include \"tools/dev/sem_replay_util.c\"\n"
        "#undef read\n#include \"tools/dev/sem_replay_report.c\"\n"
        "int64_t clock_now_monotonic_ns(void){return 0;}\n"
        "static int check(int capture, int error){\n"
        "char sentinel;char *p=&sentinel;size_t n=99;calls=0;mode=error;\n"
        "char *a[]={\"true\",NULL};\n"
        "int rc=capture?sr_capture(a,NULL,NULL,&p,&n):"
        "(sr_read_file(\"/dev/null\",&p,&n)?0:-1);\n"
        "if(error)return rc!=-1||p!=NULL||n!=0||calls!=3;\n"
        "if(rc||!p||n!=3||calls!=3)return 1;\n"
        "int bad=memcmp(p,\"x\\nx\",4)!=0;\n"
        "struct sr_strv s={.v=&p,.n=1};sr_strv_clear(&s);return bad;}\n"
        "int main(int argc,char **argv){\n"
        "if(argc==3){struct sr_cfg cfg={0};mode=argv[1][0]-'0';\n"
        "snprintf(cfg.state,sizeof cfg.state,\"%s\",argv[2]);\n"
        "return sr_report(&cfg);}\n"
        "if(argc!=2)return 9;\n"
        "int row=argv[1][0]-'0';return check(row/2,row%2);}\n";
    char src[PATH_MAX + 32];
    if (!srt_write(fx->tools, "reader.c", source))
        return false;
    snprintf(src, sizeof src, "%s/reader.c", fx->tools);
    snprintf(bin, PATH_MAX, "%s/reader", fx->tools);
#if defined(__APPLE__)
    const char *discard = "-Wl,-dead_strip";
#else
    const char *discard = "-Wl,--gc-sections";
#endif
    const char *argv[] = {"cc", "-std=c23", "-O1", "-D_DEFAULT_SOURCE",
        "-ffunction-sections", "-fdata-sections", discard, "-I.",
        "-Itools/dev", "-Iplatform/modules/util/include", "-Iplatform/modules/base/include",
        "-Iplatform/modules/platform/include", "-Iplatform/modules/sha3/include",
        "-Icontexts/commons/packages/zjsonp/include",
        "-Icontexts/commons/packages/zutf8/include", "-o", bin, src,
        "platform/modules/base/src/safe_alloc.c", NULL};
    int rc = srt_run(argv);
    if (rc != 0)
        printf("(reader probe compile output: %s) ", g_srt_out);
    return rc == 0;
}

static bool srt_reader_errors(const struct srt_fx *fx)
{
    char bin[PATH_MAX];
    if (!srt_reader_fixture(fx, bin))
        return false;
    bool ok = true;
    static const char *rows[] = {"0", "1", "2", "3"};
    for (size_t i = 0; i < 4; i++) {
        const char *argv[] = {bin, rows[i], NULL};
        int rc = srt_run(argv);
        if (rc != 0) {
            printf("(reader probe %s exit %d: %s) ", rows[i], rc, g_srt_out);
            ok = false;
        }
    }
    return ok;
}

static bool srt_setup(struct srt_fx *fx)
{
    const char *probe[] = {"objcopy", "--version", NULL};
    test_make_tmpdir(fx->root, sizeof fx->root, "sem_replay", "fx");
    if (snprintf(fx->repo, sizeof fx->repo, "%s/repo", fx->root) >= (int)sizeof fx->repo ||
        snprintf(fx->tools, sizeof fx->tools, "%s/tools", fx->root) >= (int)sizeof fx->tools)
        return false;
    /* Without objcopy the replay cannot split code from debug changes and
     * files a changed object as unknown, which it treats as code. */
    fx->objcopy = srt_run(probe) == 0;
    return srt_find_tool(fx) && srt_mkdir_p(fx->tools) && srt_reader_errors(fx) && srt_tu_paths(fx) == 0 &&
           srt_plan_fields(fx) == 0 && srt_tools(fx) && srt_history(fx);
}

/* ── running the replay ──────────────────────────────────────────────── */

/* z23-sem-replay step for commit at index; state becomes <root>/state-<index>. */
static int srt_step(const struct srt_fx *fx, const char *planner, const char *commit,
                    const char *index, char state[PATH_MAX])
{
    char sensor[PATH_MAX + 16], plan[PATH_MAX + 64];
    snprintf(state, PATH_MAX, "%s/state-%s", fx->root, index);
    snprintf(sensor, sizeof sensor, "%s/fx-sensor", fx->tools);
    snprintf(plan, sizeof plan, "%s/%s", fx->tools, planner);
    const char *argv[] = {fx->tool, "step",   "--repo",  fx->repo, "--state",
                          state,    "--sensor", sensor,  "--planner", plan,
                          "--jobs", "2",      "--index", index,    "--commit",
                          commit,   NULL};
    return srt_run(argv);
}

/* The value of column name in a two-line result.tsv; "" when absent. */
static bool srt_result(const char *state, const char *dir, const char *name,
                       char *val, size_t cap)
{
    static char text[8192];
    char path[PATH_MAX + 64];
    snprintf(path, sizeof path, "%s/run/%s/result.tsv", state, dir);
    val[0] = '\0';
    if (!srt_read(path, text, sizeof text))
        return false;
    char *row = strchr(text, '\n');
    if (row == NULL)
        return false;
    *row++ = '\0';
    char *hs = NULL, *rs = NULL;
    char *h = strtok_r(text, "\t", &hs), *v = strtok_r(row, "\t\n", &rs);
    for (; h && v; h = strtok_r(NULL, "\t", &hs), v = strtok_r(NULL, "\t\n", &rs)) {
        if (strcmp(h, name) == 0) {
            snprintf(val, cap, "%s", v);
            return true;
        }
    }
    return false;
}

/* Does column name of the step's result.tsv equal want? */
static bool srt_col_is(const char *state, const char *dir, const char *name,
                       const char *want)
{
    char got[256];
    bool ok = srt_result(state, dir, name, got, sizeof got) && strcmp(got, want) == 0;
    if (!ok)
        printf("(result.tsv %s = \"%s\", want \"%s\") ", name, got, want);
    return ok;
}

static bool srt_file_has(const char *path, const char *needle)
{
    static char text[1 << 16];
    return srt_read(path, text, sizeof text) && strstr(text, needle) != NULL;
}

/* run/<NNN>_<first ten hex of commit> */
static void srt_run_dir(char out[32], int index, const char *commit)
{
    snprintf(out, 32, "%03d_%.10s", index, commit);
}

/* z23-sem-replay run over one commit, the tool named by its bare name on
 * PATH: run re-executes itself for the step, so this also proves it finds
 * its own path without /proc. */
static int srt_replay_run(const struct srt_fx *fx, const char *commit)
{
    static char pathvar[8192];
    char state[PATH_MAX + 16], commits[PATH_MAX + 16], sensor[PATH_MAX + 16];
    char plan[PATH_MAX + 32], bindir[PATH_MAX], text[80];
    const char *old = getenv("PATH");
    snprintf(bindir, sizeof bindir, "%s", fx->tool);
    *strrchr(bindir, '/') = '\0';
    snprintf(pathvar, sizeof pathvar, "PATH=%s:%s", bindir, old ? old : "/usr/bin:/bin");
    snprintf(state, sizeof state, "%s/state-run", fx->root);
    snprintf(commits, sizeof commits, "%s/commits.txt", fx->root);
    snprintf(sensor, sizeof sensor, "%s/fx-sensor", fx->tools);
    snprintf(plan, sizeof plan, "%s/fx-planner-omits", fx->tools);
    snprintf(text, sizeof text, "%s\n", commit);
    if (!srt_write(fx->root, "commits.txt", text))
        return -1;
    const char *argv[] = {pathvar,   strrchr(fx->tool, '/') + 1, "run", "--repo", fx->repo,
                          "--state", state, "--sensor", sensor, "--planner", plan,
                          "--jobs",  "2",   "--commits", commits, NULL};
    return srt_run(argv);
}

/* Reject raw NUL anywhere in the list before dispatch, even past max_steps. */
static int srt_commit_records(const struct srt_fx *fx)
{
    int failures = 0;
    char state[PATH_MAX + 16], commits[PATH_MAX + 16], index[16];
    char sensor[PATH_MAX + 16], planner[PATH_MAX + 32];
    snprintf(sensor, sizeof sensor, "%s/fx-sensor", fx->tools);
    snprintf(planner, sizeof planner, "%s/fx-planner-omits", fx->tools);
    for (int kind = 0; kind < 3; kind++) {
        snprintf(index, sizeof index, "%d", 30 + kind);
        snprintf(state, sizeof state, "%s/list-%s", fx->root, index);
        snprintf(commits, sizeof commits, "%s/list-%s.txt", fx->root, index);
        TEST("commit lists reject hidden bytes before dispatch and retain comments/EOF") {
            FILE *f = fopen(commits, "wb");
            ASSERT(f != NULL);
            bool wrote = fwrite("#ignored", 1, 8, f) == 8;
            if (kind == 0) wrote &= fputc(0, f) != EOF;
            wrote &= fputc('\n', f) != EOF;
            wrote &= fwrite(fx->c1, 1, strlen(fx->c1), f) == strlen(fx->c1);
            if (kind == 1) wrote &= fwrite("\n#tail\0junk\n", 1, 12, f) == 12;
            bool closed = fclose(f) == 0;
            ASSERT(wrote && closed);
            const char *argv[] = {fx->tool, "run", "--repo", fx->repo, "--state", state,
                                  "--sensor", sensor, "--planner", planner,
                                  "--commits", commits, "--max-steps", "1", NULL};
            if (kind == 2) {
                ASSERT_EQ(srt_run(argv), SRT_EXIT_FALSE_NEGATIVE);
            } else {
                ASSERT_EQ(srt_run(argv), 2);
                ASSERT(strstr(g_srt_out, "malformed commit list") != NULL);
                ASSERT(strstr(g_srt_out, "sem-replay: step ") == NULL);
            }
            PASS();
        }
_test_next:;
    }
    return failures;
}

/* Build the real reader and capture path with a deterministic clock. */
static bool srt_replay_probe(const struct srt_fx *fx, const char *text)
{
    static const char *const dirs[] = {"tools/dev", "contexts/commons/packages/zjsonp/include",
        "contexts/commons/packages/zutf8/include", "platform/modules/sha3/include",
        "platform/modules/base/include", "platform/modules/platform/include"};
    static const char *const units[] = {"tools/dev/sem_replay_util.c",
        "contexts/commons/packages/zjsonp/src/zjsonp.c", "contexts/commons/packages/zutf8/src/zutf8.c",
        "platform/modules/sha3/src/sha3.c", "platform/modules/base/src/safe_alloc.c"};
    char root[PATH_MAX], source[PATH_MAX + 16], bin[PATH_MAX + 16];
    char paths[12][PATH_MAX + 96];
    if (!realpath(".", root) || !srt_write(fx->tools, "probe.c", text))
        { printf("(probe setup failed) "); return false; }
    snprintf(source, sizeof(source), "%s/probe.c", fx->tools);
    snprintf(bin, sizeof(bin), "%s/probe", fx->tools);
    const char *argv[24] = {"cc", "-std=c23", "-O1", "-D_DEFAULT_SOURCE",
        "-D_POSIX_C_SOURCE=200809L", "-o", bin, source};
    size_t n = 8;
    for (size_t i = 0; i < 6; i++) {
        snprintf(paths[i], sizeof(paths[i]), "-I%s/%s", root, dirs[i]);
        argv[n++] = paths[i];
    }
    for (size_t i = 0; i < 5; i++) {
        snprintf(paths[i + 6], sizeof(paths[i + 6]), "%s/%s", root, units[i]);
        argv[n++] = paths[i + 6];
    }
    argv[n] = NULL;
    int rc = srt_run(argv);
    if (rc != 0) printf("(probe build exited %d: %s) ", rc, g_srt_out);
    return rc == 0;
}

/* Observe feature selection as a child exit through the real sr_run caller.
 * The explicit wait4 prototype keeps a missing feature macro a runtime failure
 * on Darwin too, rather than using a compiler error as the mutation verdict.
 * These are macro-contract cases on the host libc, not a Darwin SDK emulation. */
static bool srt_darwin_probe(const struct srt_fx *fx, const char *selection)
{
    static const char driver[] =
        "#include <sys/types.h>\n#include <sys/resource.h>\n"
        "extern pid_t wait4(pid_t, int *, int, struct rusage *);\n"
        "extern int putenv(char *);\n"
        "%s\n"
        "#include \"tools/dev/sem_replay_util.c\"\n"
        "int64_t clock_now_monotonic_ns(void) { return 0; }\n"
        "static int feature_status(void) {\n"
        "#if defined(__APPLE__)\n"
        "#if !defined(_DARWIN_C_SOURCE)\n"
        " return 41;\n"
        "#elif _DARWIN_C_SOURCE != EXPECT_FEATURE\n"
        " return 42;\n"
        "#else\n return 0;\n#endif\n"
        "#elif defined(_DARWIN_C_SOURCE)\n return 43;\n"
        "#else\n return 0;\n#endif\n}\n"
        "int main(int argc, char **argv) {\n"
        " if (argc == 2) return feature_status();\n"
        " char *child[] = {argv[0], \"child\", NULL};\n"
        " struct sr_cost cost = {0};\n"
        " int rc = sr_run(child, NULL, NULL, NULL, &cost);\n"
        " printf(\"feature child exit=%%d wall=%%.0f\\n\", rc, cost.wall_s);\n"
        " return rc == 0 && cost.wall_s == 0 ? 0 : 1;\n}\n";
    char code[4096], source[PATH_MAX + 32], bin[PATH_MAX + 32];
    int n = snprintf(code, sizeof code, driver, selection);
    if (n < 0 || (size_t)n >= sizeof code ||
        !srt_write(fx->tools, "darwin-feature.c", code)) {
        printf("(Darwin feature fixture setup failed) ");
        return false;
    }
    snprintf(source, sizeof source, "%s/darwin-feature.c", fx->tools);
    snprintf(bin, sizeof bin, "%s/darwin-feature", fx->tools);
    const char *cc[] = {"cc", "-std=c23", "-O1", "-D_DEFAULT_SOURCE",
        "-D_POSIX_C_SOURCE=200809L", "-I.", "-Iplatform/modules/base/include",
        "-Iplatform/modules/platform/include", "-Iplatform/modules/sha3/include",
        "-Icontexts/commons/packages/zjsonp/include", "-Icontexts/commons/packages/zutf8/include",
        "-o", bin, source, "platform/modules/base/src/safe_alloc.c",
        "platform/modules/sha3/src/sha3.c", "contexts/commons/packages/zjsonp/src/zjsonp.c",
        "contexts/commons/packages/zutf8/src/zutf8.c", NULL};
    int rc = srt_run(cc);
    if (rc != 0)
        printf("(Darwin feature probe compile exit %d: %s) ", rc, g_srt_out);
    return rc == 0;
}

static int test_srt_darwin_feature(void)
{
    static const char *const selections[] = {
        "#undef __APPLE__\n#define __APPLE__ 1\n#undef _DARWIN_C_SOURCE\n#define EXPECT_FEATURE 1",
        "#undef __APPLE__\n#define __APPLE__ 1\n#undef _DARWIN_C_SOURCE\n#define _DARWIN_C_SOURCE 7\n#define EXPECT_FEATURE 7",
        "#undef __APPLE__\n#undef _DARWIN_C_SOURCE",
    };
    int failures = 0;
    struct srt_fx fx = {0};
    char probe[PATH_MAX + 32];
    test_make_tmpdir(fx.root, sizeof fx.root, "sem_replay", "darwin_feature");
    snprintf(fx.tools, sizeof fx.tools, "%s", fx.root);
    snprintf(probe, sizeof probe, "%s/darwin-feature", fx.root);
    const char *run[] = {probe, NULL};
    TEST("replay: Darwin feature default, caller selection and non-Apple scope") {
        for (size_t i = 0; i < sizeof selections / sizeof selections[0]; i++) {
            ASSERT(srt_darwin_probe(&fx, selections[i]));
            int rc = srt_run(run);
            if (rc != 0)
                printf("(feature case %zu: %s) ", i, g_srt_out);
            ASSERT_EQ(rc, 0);
            ASSERT_STR_EQ(g_srt_out, "feature child exit=0 wall=0\n");
        }
        PASS();
    }
_test_next:;
    if (test_rm_rf_recursive(fx.root) != 0) {
        printf("(Darwin feature fixture cleanup failed: %s) ", fx.root);
        failures++;
    }
    return failures;
}

static int test_srt_oid_extent(void)
{
    int failures = 0;
    struct srt_fx fx = {0};
    char path[PATH_MAX + 16], probe[PATH_MAX + 16], expected[48];
    static const char driver[] = "/* Purpose: observe exact replay object ID framing. */\n#include \"sem_replay_change.c\"\n"
        "#include \"platform/clock.h\"\n"
        "int64_t clock_now_monotonic_ns(void) { return 0; }\n"
        "int main(int argc, char **argv) { char out[64] = {0}; if (argc != 2) return 2;\n"
        "char *cmd[] = {\"cat\", argv[1], NULL}; memset(out, 'x', sizeof(out) - 1);\n"
        "bool ok = first_line(NULL, cmd, out); printf(\"%d:%s\\n\", ok, out); return 0; }\n";
    static const char oid[] = "0123456789abcdef0123456789abcdef01234567";
    static const struct { const char *bytes; size_t len; bool valid; } cases[] = {
        {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 64, false},
        {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", 65, false},
        {oid, 40, true},
        {"0123456789abcdef0123456789abcdef01234567\n", 41, true},
        {"0123456789abcdef0123456789abcdef01234567\r\n", 42, true},
        {"0123456789abcdef0123456789abcdef01234567\0junk\n", 46, false},
        {"0123456789abcdef0123456789abcdef01234567\nextra\n", 47, false},
        {"0123456789abcdef0123456789abcdef01234567x", 41, false},
        {oid, 39, false},
        {"g123456789abcdef0123456789abcdef01234567", 40, false},
    };
    test_make_tmpdir(fx.root, sizeof(fx.root), "sem_replay", "oid");
    snprintf(fx.tools, sizeof(fx.tools), "%s", fx.root);
    snprintf(path, sizeof(path), "%s/record", fx.root);
    snprintf(probe, sizeof(probe), "%s/probe", fx.root);
    const char *argv[] = {probe, path, NULL};
    snprintf(expected, sizeof(expected), "1:%s\n", oid);
    TEST("replay: an object ID is complete or refused, never shortened") {
        ASSERT(srt_replay_probe(&fx, driver));
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            FILE *f = fopen(path, "wb");
            ASSERT(f != NULL);
            size_t wrote = fwrite(cases[i].bytes, 1, cases[i].len, f);
            int closed = fclose(f);
            ASSERT_EQ(wrote, cases[i].len);
            ASSERT_EQ(closed, 0);
            ASSERT_EQ(srt_run(argv), 0);
            if (cases[i].valid)
                ASSERT_STR_EQ(g_srt_out, expected);
            else
                ASSERT_STR_EQ(g_srt_out,
                    "sem-replay: invalid or unsupported object ID response\n0:\n");
        }
        PASS();
    }
_test_next:;
    if (test_rm_rf_recursive(fx.root) != 0) {
        printf("(object ID fixture cleanup failed: %s) ", fx.root);
        failures++;
    }
    return failures + test_srt_darwin_feature();
}

/* Two fixed-width records; the final row deliberately has no LF. */
static void srt_table_columns(char body[600], size_t cols)
{
    size_t n = 0;
    for (size_t row = 0; row < 2; row++) {
        for (size_t c = 0; c < cols; c++) {
            body[n++] = 'x';
            if (c + 1 < cols)
                body[n++] = '\t';
        }
        if (row == 0)
            body[n++] = '\n';
    }
    body[n] = '\0';
}

static int srt_table_case(const struct srt_fx *fx, const char *body,
                          size_t len, int want, bool later)
{
    int failures = 0;
    char state[PATH_MAX + 32], path[PATH_MAX + 80];
    const char *rel = later ? "table-multi/run/b/result.tsv" :
                              "table-bounds/run/a/result.tsv";
    snprintf(state, sizeof state, "%s/%s", fx->root,
             later ? "table-multi" : "table-bounds");
    snprintf(path, sizeof path, "%s/%s", fx->root, rel);
    const char *argv[] = {fx->tool, "report", "--state", state, NULL};
    TEST("replay report validates each measured table and header") {
        ASSERT(srt_write(fx->root, rel, ""));
        FILE *fp = fopen(path, "wb");
        ASSERT(fp != NULL);
        bool wrote = fwrite(body, 1, len, fp) == len;
        int closed = fclose(fp);
        ASSERT(wrote);
        ASSERT_EQ(closed, 0);
        ASSERT_EQ(srt_run(argv), want);
        PASS();
    }
_test_next:;
    return failures;
}

static int srt_table_bounds(const struct srt_fx *fx)
{
    char body[600];
    int failures = 0;
    srt_table_columns(body, 128);
    failures += srt_table_case(fx, body, strlen(body), 0, false);
    srt_table_columns(body, 129);
    failures += srt_table_case(fx, body, strlen(body), 1, false);
    static const struct { const char *body; size_t len; int want; } cases[] = {
        {"x\nx\n\0junk\n", 10, 1}, {"x\nx\0y", 5, 1},
        {"x\nx\nx\n", 6, 1}, {"x\nx\n", 4, 0},
        {"x\ty\nx", 5, 1}, {"x\n", 2, 1}
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++)
        failures += srt_table_case(fx, cases[i].body, cases[i].len,
                                   cases[i].want, false);
    if (!srt_write(fx->root, "table-multi/run/a/result.tsv", "x\nx\n"))
        return failures + 1;
    failures += srt_table_case(fx, "x\ty\nx\n", 6, 1, true);
    char *row = strchr(body, '\n') + 1;
    memcpy(row, "x\n", 3); /* Only the later header exceeds the bound. */
    failures += srt_table_case(fx, body, strlen(body), 1, true);
    failures += srt_table_case(fx, "x\nx", 3, 0, true);
    failures += srt_table_case(fx, "x\nx\n", 4, 0, true);
    return failures;
}

static int srt_report_read_errors(const struct srt_fx *fx)
{
    int failures = 0;
    char state[PATH_MAX + 32], path[PATH_MAX + 80], bin[PATH_MAX];
    snprintf(state, sizeof state, "%s/table-read", fx->root);
    snprintf(path, sizeof path, "%s/run/a/result.tsv", state);
    const char *argv[] = {fx->tool, "report", "--state", state, NULL};
    TEST("replay report skips absent results and refuses read failures") {
        ASSERT(srt_mkdir_p(path)); /* Existing directory: open succeeds, read fails. */
        ASSERT_EQ(srt_run(argv), 1);
        ASSERT_EQ(rmdir(path), 0);
        ASSERT_EQ(srt_run(argv), 0); /* The unpublished result remains absent. */
        ASSERT(srt_write(fx->root, "table-read/run/a/result.tsv", "x\nx"));
        ASSERT(srt_reader_fixture(fx, bin));
        const char *good[] = {bin, "0", state, NULL};
        const char *bad[] = {bin, "1", state, NULL};
        ASSERT_EQ(srt_run(good), 0);
        ASSERT_EQ(srt_run(bad), 1); /* EINTR, valid-looking prefix, then EIO. */
        ASSERT(strstr(g_srt_out, "sem-replay: read:") != NULL);
        PASS();
    }
_test_next:;
    return failures;
}

static int srt_table_regressions(const struct srt_fx *fx)
{
    if (!fx->tool[0])
        return 0;
    return srt_table_bounds(fx) + srt_report_read_errors(fx);
}

/* An epoch-only last.snap (no object rows) is what a drifted or
 * partially-written snapshot looks like. sr_snap_load must not hand
 * qsort a NULL base (the parameter is declared nonnull — UBSan: "null
 * pointer passed as argument 1"), and the load must otherwise succeed.
 * The probe compiles the real sem_replay_build.c with
 * -fsanitize=undefined and loads the drifted snapshot in-process: the
 * spawned z23-sem-replay tool is not sanitizer-built, so the UB is only
 * observable where the harness instruments it. Red before the
 * empty-snapshot guard: UBSan runtime error and a nonzero probe exit.
 * Extracted from test_sem_replay so the group body stays under the
 * complexity cap. */
static int srt_drifted_snapshot_case(const struct srt_fx *fx)
{
    int failures = 0;
    char probe[PATH_MAX + 32], source[PATH_MAX + 32], snap[PATH_MAX + 32];
    TEST("an epoch-only snapshot loads with no qsort NULL-base UB") {
        ASSERT(srt_write(fx->root, "epoch-only.snap", "epoch\t" SRT_EPOCH "\n"));
        snprintf(snap, sizeof snap, "%s/epoch-only.snap", fx->root);
        const char *code =
            "#include \"tools/dev/sem_replay_build.c\"\n"
            "int main(int n,char **v){if(n!=2)return 1;struct sr_snap s;\n"
            "if(!sr_snap_load(&s,v[1]))return 2;\n"
            "int bad=s.n!=0 || s.cap!=0 || s.v!=NULL ||\n"
            "strcmp(s.epoch,\"" SRT_EPOCH "\")!=0;\n"
            "sr_snap_free(&s);return bad?3:0;}\n";
        ASSERT(srt_write(fx->tools, "fx_snap_load.c", code));
        snprintf(source, sizeof source, "%s/fx_snap_load.c", fx->tools);
        snprintf(probe, sizeof probe, "%s/fx-snap-load", fx->tools);
        const char *cc[] = {"cc", "-std=c23", "-O1", "-fsanitize=undefined",
            "-fno-sanitize-recover=undefined",
            "-D_POSIX_C_SOURCE=200809L", "-D_DARWIN_C_SOURCE",
            "-I.", "-Iplatform/modules/util/include",
            "-Iplatform/modules/base/include", "-Iplatform/modules/platform/include",
            "-Iplatform/modules/sha3/include",
            "-Icontexts/commons/packages/zjsonp/include",
            "-Icontexts/commons/packages/zutf8/include",
            "-o", probe, source,
            "tools/dev/sem_replay_util.c",
            "contexts/commons/packages/zjsonp/src/zjsonp.c",
            "contexts/commons/packages/zutf8/src/zutf8.c",
            "platform/modules/base/src/safe_alloc.c",
            "platform/modules/platform/src/clock.c",
            "platform/modules/sha3/src/sha3.c", NULL};
        int compiled = srt_run(cc); if (compiled) printf("%s", g_srt_out);
        ASSERT_EQ(compiled, 0);
        const char *argv[] = {probe, snap, NULL};
        ASSERT_EQ(srt_run(argv), 0);
        ASSERT(strstr(g_srt_out, "runtime error") == NULL);
        PASS();
    }
_test_next:;
    return failures;
}

#endif /* !_WIN32 */

int test_sem_replay(void)
{
#if defined(_WIN32)
    printf("sem_replay: UNAVAILABLE on native Windows "
           "(the replay forks git, make and a compiler)\n");
    return 1;
#else
    int failures = 0;
    failures += test_srt_oid_extent();
    struct srt_fx fx = {0};
    char state_a[PATH_MAX] = "", state_b[PATH_MAX] = "", state_c[PATH_MAX] = "";
    char dir_a[32], dir_b[32], dir_c[32];
    char path[PATH_MAX + 64], want[512];

    TEST("the fixture history builds: P, C1 (a.c body), C2 (common.h)") {
        ASSERT(srt_setup(&fx));
        failures += srt_commit_records(&fx);
        srt_run_dir(dir_a, 1, fx.c1);
        srt_run_dir(dir_b, 2, fx.c2);
        srt_run_dir(dir_c, 3, fx.c2);
        PASS();
    }

    TEST("request encoding preserves direct and quoted name-status entries") {
        char probe[PATH_MAX], source[PATH_MAX], quoted[PATH_MAX];
        ASSERT(srt_write(fx.repo, "a\"b.c", "/* fixture */\n"));
        const char *git[] = {"git", "-C", fx.repo, "-c", "core.quotePath=true",
                            "diff", "--no-index", "--name-status", "--", "/dev/null", "a\"b.c", NULL};
        ASSERT_EQ(srt_run(git), 1);
        char *field = strchr(g_srt_out, '\t');
        ASSERT(field != NULL);
        snprintf(quoted, sizeof quoted, "%s", field + 1);
        quoted[strcspn(quoted, "\r\n")] = '\0';
        snprintf(source, sizeof source, "%s/a\"b.c", fx.repo);
        ASSERT(remove(source) == 0);
        const char *code = "#include \"tools/dev/sem_replay_plan.c\"\n"
            "int main(int n,char **v){struct sr_strv f={.v=v+1,.n=(size_t)(n-1)};char *s=request_json(&f,NULL,0);if(!s)return 3;puts(s+8);return 0;}\n";
        ASSERT(srt_write(fx.tools, "fx_request.c", code));
        snprintf(source, sizeof source, "%s/fx_request.c", fx.tools);
        snprintf(probe, sizeof probe, "%s/fx_request", fx.tools);
        const char *cc[] = {"cc", "-std=c23", "-O1", "-D_POSIX_C_SOURCE=200809L", "-D_DEFAULT_SOURCE", "-I.", "-Iplatform/modules/util/include",
            "-Iplatform/modules/base/include", "-Iplatform/modules/platform/include",
            "-Iplatform/modules/sha3/include", "-Icontexts/commons/packages/zjsonp/include",
            "-Icontexts/commons/packages/zutf8/include", "-o", probe, source,
            "tools/dev/sem_replay_util.c", "platform/modules/base/src/safe_alloc.c",
            "platform/modules/platform/src/clock.c", "platform/modules/sha3/src/sha3.c",
            "contexts/commons/packages/zjsonp/src/zjsonp.c", "contexts/commons/packages/zutf8/src/zutf8.c", NULL};
        int compiled = srt_run(cc); if (compiled) printf("%s", g_srt_out);
        ASSERT_EQ(compiled, 0);
        const char *args[] = {probe, "a\"b.c", quoted, "a\\n\001\xc3\xa9.c", NULL};
        ASSERT_EQ(srt_run(args), 0);
        ASSERT(zutf8_validate(g_srt_out));
        struct json_value decoded;
        json_init(&decoded);
        ASSERT(json_read(&decoded, g_srt_out, strlen(g_srt_out)));
        const struct json_value *files = json_get(&decoded, "files");
        ASSERT(files && files->type == JSON_ARR && files->num_children == 3);
        for (size_t i = 0; i < 3; i++)
            ASSERT_STR_EQ(json_get_str(json_at(files, i)), args[i + 1]);
        json_free(&decoded);
        const char *bad[] = {probe, "a\xff.c", NULL};
        ASSERT_EQ(srt_run(bad), 3);
        PASS();
    }
    TEST("a facts plan that leaves out the changed TU exits 3 (false negative)") {
        int rc = srt_step(&fx, "fx-planner-omits", fx.c1, "1", state_a);
        if (rc != SRT_EXIT_FALSE_NEGATIVE)
            printf("(step output: %s) ", g_srt_out);
        ASSERT_EQ(rc, SRT_EXIT_FALSE_NEGATIVE);
        snprintf(want, sizeof want, "FALSE NEGATIVE (code): commit %s TU src/a.c", fx.c1);
        ASSERT(strstr(g_srt_out, want) != NULL);
        PASS();
    }

    failures += srt_drifted_snapshot_case(&fx);

    TEST("MISSES.tsv names src/a.c as the code false negative, exactly") {
        char text[4096];
        snprintf(path, sizeof path, "%s/MISSES.tsv", state_a);
        ASSERT(srt_read(path, text, sizeof text));
        snprintf(want, sizeof want,
                 "%s\tsrc/a.c\tFALSE NEGATIVE (code)\tprecise\tfixture-omits-the-changed-tu\n",
                 fx.c1);
        ASSERT_STR_EQ(text, want);
        snprintf(path, sizeof path, "%s/run/%s/sets.tsv", state_a, dir_a);
        ASSERT(srt_file_has(path, "\nfn_code\tsrc/a.c\n"));
        PASS();
    }

    TEST("run over the same commit re-executes itself and stops with exit 3") {
        int rc = srt_replay_run(&fx, fx.c1);
        if (rc != SRT_EXIT_FALSE_NEGATIVE)
            printf("(run output: %s) ", g_srt_out);
        ASSERT_EQ(rc, SRT_EXIT_FALSE_NEGATIVE);
        ASSERT(strstr(g_srt_out, "stopped at a code false negative") != NULL);
        PASS();
    }

    TEST("the omitting step counts make 1, changed 1, plain 1, facts 0, fn_code 1") {
        ASSERT(srt_col_is(state_a, dir_a, "kind", "body-only"));
        ASSERT(srt_col_is(state_a, dir_a, "make", "1"));
        ASSERT(srt_col_is(state_a, dir_a, "changed", "1"));
        ASSERT(srt_col_is(state_a, dir_a, "plain", "1"));
        ASSERT(srt_col_is(state_a, dir_a, "facts", "0"));
        ASSERT(srt_col_is(state_a, dir_a, "facts_mode", "precise"));
        ASSERT(srt_col_is(state_a, dir_a, "fn", "1"));
        ASSERT(srt_col_is(state_a, dir_a, "fn_code", "1"));
        ASSERT(srt_col_is(state_a, dir_a, "build_failed", "0"));
        PASS();
    }

    TEST("a facts plan that narrows to the changed TU exits 0") {
        int rc = srt_step(&fx, "fx-planner-narrows", fx.c2, "2", state_b);
        if (rc != 0)
            printf("(step output: %s) ", g_srt_out);
        ASSERT_EQ(rc, 0);
        PASS();
    }

    TEST("both sides' manifests name the object compiler and the toolchain identity, "
        "as make clang-facts senses them") {
        const char *sides[] = {"before", "after"};
        for (size_t s = 0; s < 2; s++) {
            snprintf(path, sizeof path, "%s/build/sem-replay/facts/src/a.c.%s.zsm", fx.repo,
                     sides[s]);
            if (!srt_file_has(path, "cc=cc toolchain=" SRT_TOOLCHAIN "\n"))
                printf("(%s manifest lacks --cc cc --toolchain-id) ", sides[s]);
            ASSERT(srt_file_has(path, "cc=cc toolchain=" SRT_TOOLCHAIN "\n"));
        }
        PASS();
    }

    TEST("the narrowing step's compile counts are exact: make 2, changed 1, plain 2, facts 1") {
        ASSERT(srt_col_is(state_b, dir_b, "kind", "header"));
        ASSERT(srt_col_is(state_b, dir_b, "files", "1"));
        ASSERT(srt_col_is(state_b, dir_b, "h", "1"));
        ASSERT(srt_col_is(state_b, dir_b, "make", "2"));
        ASSERT(srt_col_is(state_b, dir_b, "changed", "1"));
        ASSERT(srt_col_is(state_b, dir_b, "code_changed", fx.objcopy ? "1" : "0"));
        ASSERT(srt_col_is(state_b, dir_b, "unknown_changed", fx.objcopy ? "0" : "1"));
        ASSERT(srt_col_is(state_b, dir_b, "debug_changed", "0"));
        ASSERT(srt_col_is(state_b, dir_b, "plain", "2"));
        ASSERT(srt_col_is(state_b, dir_b, "facts", "1"));
        ASSERT(srt_col_is(state_b, dir_b, "facts_mode", "precise"));
        ASSERT(srt_col_is(state_b, dir_b, "fn", "0"));
        ASSERT(srt_col_is(state_b, dir_b, "plain_fn", "0"));
        ASSERT(srt_col_is(state_b, dir_b, "drift", "0"));
        ASSERT(srt_col_is(state_b, dir_b, "cold_checked", "2"));
        ASSERT(srt_col_is(state_b, dir_b, "cold_mismatch", "0"));
        ASSERT(srt_col_is(state_b, dir_b, "build_failed", "0"));
        PASS();
    }

    TEST("the narrowing step's group counts are exact: plain 2, facts 1") {
        ASSERT(srt_col_is(state_b, dir_b, "groups_plain", "2"));
        ASSERT(srt_col_is(state_b, dir_b, "groups_facts", "1"));
        ASSERT(srt_col_is(state_b, dir_b, "obl_plain", "2"));
        ASSERT(srt_col_is(state_b, dir_b, "obl_facts", "1"));
        ASSERT(srt_col_is(state_b, dir_b, "narrowed", "1"));
        ASSERT(srt_col_is(state_b, dir_b, "uni_complete", "1"));
        ASSERT(srt_col_is(state_b, dir_b, "uni_total", "2"));
        ASSERT(srt_col_is(state_b, dir_b, "uni_affected", "1"));
        PASS();
    }

    TEST("the narrowing step's sets name the exact TUs") {
        snprintf(path, sizeof path, "%s/run/%s/sets.tsv", state_b, dir_b);
        ASSERT(srt_file_has(path, "\nmake\tsrc/a.c\nmake\tsrc/b.c\nchanged\tsrc/a.c\nplain\t"));
        ASSERT(srt_file_has(path, "\nplain\tsrc/a.c\nplain\tsrc/b.c\nfacts\tsrc/a.c\ntu\tsrc/a.c\t"));
        ASSERT(!srt_file_has(path, "\nfn_code\t"));
        snprintf(path, sizeof path, "%s/MISSES.tsv", state_b);
        ASSERT(access(path, F_OK) != 0);
        PASS();
    }

    TEST("the report headline counts 1 compile and 1 test group avoided, "
        "false-narrow 0, false-wide facts 0, false-wide plain 1") {
        const char *argv[] = {fx.tool, "report", "--state", state_b, NULL};
        ASSERT_EQ(srt_run(argv), 0);
        ASSERT(strstr(g_srt_out, "Compiler executions avoided vs make: 1 (make compiled 2 "
                                 "TUs, the facts plan 1).\n") != NULL);
        ASSERT(strstr(g_srt_out, "Test-group executions avoided vs plain: 1 (plain "
                                 "selected 2 groups, the facts plan 1).\n") != NULL);
        ASSERT(strstr(g_srt_out, "False-narrow (a changed object the facts plan left out; "
                                 "must be 0, fails the run): 0.\n") != NULL);
        ASSERT(strstr(g_srt_out, "False-wide vs facts (a TU the facts plan compiled whose "
                                 "object bytes did not change): 0.\n") != NULL);
        ASSERT(strstr(g_srt_out, "False-wide vs plain (a TU the plain plan compiled whose "
                                 "object bytes did not change): 1.\n") != NULL);
        PASS();
    }

    TEST("the report puts catalog groups and plan tokens in separate columns, each "
        "plain / facts") {
        const char *argv[] = {fx.tool, "report", "--state", state_b, NULL};
        ASSERT_EQ(srt_run(argv), 0);
        ASSERT(strstr(g_srt_out, "| groups plain / facts | tokens plain / facts |") != NULL);
        ASSERT(strstr(g_srt_out, "| 0/0/0 | 2 / 1 | 2 / 1 | narrowed |") != NULL);
        PASS();
    }

    TEST("a facts plan that over-selects the unaffected TU exits 0 (not a false negative)") {
        int rc = srt_step(&fx, "fx-planner-overselects", fx.c2, "3", state_c);
        if (rc != 0)
            printf("(step output: %s) ", g_srt_out);
        ASSERT_EQ(rc, 0);
        PASS();
    }

    TEST("the over-selecting step's counts are exact: false-narrow 0, false-wide facts 1, "
        "false-wide plain 1") {
        ASSERT(srt_col_is(state_c, dir_c, "fn_code", "0"));
        ASSERT(srt_col_is(state_c, dir_c, "fw_facts", "1"));
        ASSERT(srt_col_is(state_c, dir_c, "fw_plain", "1"));
        snprintf(path, sizeof path, "%s/run/%s/sets.tsv", state_c, dir_c);
        ASSERT(srt_file_has(path, "\nfw_facts\tsrc/b.c\n"));
        ASSERT(srt_file_has(path, "\nfw_plain\tsrc/b.c\n"));
        PASS();
    }

_test_next:;
    failures += srt_table_regressions(&fx);
    if (fx.root[0])
        (void)test_rm_rf_recursive(fx.root);
    if (failures == 0)
        printf("test_sem_replay: all passed\n");
    else
        printf("test_sem_replay: %d FAILED\n", failures);
    return failures;
#endif
}
