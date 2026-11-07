/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the whole app journey with ONE owner key in ONE ISO week, every
 * step a `z23 app` front-door verb as a person types it, on a STUB in-repo
 * app (a fixture checkout whose apps/tinyapp has app.mk, one C file that
 * prints a line and waits for a signal). Two HOMEs and datadirs:
 *   A, in the checkout: copy tinyapp (no release yet, so app.seed publishes
 *      one signed by A's key), edit src/main.c, save, build, open (the stub
 *      child through resident_launch), share, which writes
 *      tinyapp-1.z23share and publishes again with the same key;
 *   B, in B's HOME: open tinyapp-1.z23share with the confirm injected, which
 *      receives, builds and opens.
 * Asserted: no step is refused (seed then share used to be refused
 * PUBLISH_FREQUENCY_LIMIT, the 1-per-week new-user allowance); A's key has
 * both publishes recorded in this ISO week; B's image_sha3 equals A's for
 * the shared version; MCP refuses app.copy, app.share and app.receive. The
 * commands A and B typed are printed. */

#include "test/test_core.h"
#include "test/app_seed_fixture.h"

#include "chain/chainparams.h"

#if defined(_WIN32)
int test_app_journey(void);
int test_app_journey(void)
{
    printf("app journey... SKIP (the copy open spawns through "
           "resident_launch, which refuses on Windows)\n");
    return 0;
}
#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AJ_PATH 900

static const char k_app_mk[] =
    ".PHONY: app print-app-closure\n"
    "print-app-closure:\n"
    "\t@printf '%s\\n' Makefile include/tiny.h src/main.c\n"
    "app:\n"
    "\tcc -std=c2x -O2 -Iinclude -MD -MF $(APP_OUT)/main.d -c src/main.c "
    "-o $(APP_OUT)/main.o\n"
    "\tcc -o $(APP_OUT)/app $(APP_OUT)/main.o\n";

static const char k_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"stub/tinyapp\",\n"
    "  \"semver\": \"0.1.0\",\n  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n";

/* Prints one line, then waits for a signal: a pid that stays put. */
static const char k_main[] =
    "#include <stdio.h>\n#include <unistd.h>\n#include \"tiny.h\"\n"
    "int main(void) { puts(TINY_NAME \" ready boost=1\"); fflush(stdout);\n"
    "    pause(); return 0; }\n";

struct aj_world {
    char root[512];
    char repo[600];
    char saved_home[1024], saved_cwd[1024];
    char license[4096];
    struct asf_journey j;
};

static bool aj_mkdirs(const char *base, const char *const *rels, size_t n)
{
    char path[AJ_PATH];
    for (size_t i = 0; i < n; i++)
        if (snprintf(path, sizeof(path), "%s/%s", base, rels[i]) >=
                (int)sizeof(path) ||
            mkdir(path, 0700) != 0)
            return false;
    return true;
}

/* The stub carries the same Apache-2.0 text the skycombat package does;
 * read before any step changes the working directory. */
static bool aj_license(struct aj_world *w)
{
    FILE *f = fopen("apps/skycombat/LICENSE", "rb");
    if (!f)
        return false;
    size_t n = fread(w->license, 1, sizeof(w->license) - 1u, f);
    (void)fclose(f);
    w->license[n] = '\0';
    return n > 0;
}

/* A z23 checkout as app.seed finds it from its working directory (the
 * three marker files) with one in-repo app, apps/tinyapp. */
static bool aj_checkout(struct aj_world *w)
{
    static const char *const dirs[] = {
        "engine", "engine/composition", "engine/composition/commands",
        "tools", "tools/dev", "apps", "apps/tinyapp",
        "apps/tinyapp/include", "apps/tinyapp/src"};
    char app[AJ_PATH];
    (void)snprintf(app, sizeof(app), "%s/apps/tinyapp", w->repo);
    return mkdir(w->repo, 0700) == 0 &&
           aj_mkdirs(w->repo, dirs, sizeof(dirs) / sizeof(dirs[0])) &&
           asf_put(w->repo, "Makefile", "# fixture checkout\n") &&
           asf_put(w->repo, "engine/composition/commands/root.def", "\n") &&
           asf_put(w->repo, "tools/dev/test_group_catalog.def", "\n") &&
           asf_put(app, "LICENSE", w->license) &&
           asf_put(app, "zcode-package.json", k_meta) &&
           asf_put(app, "include/tiny.h", "#define TINY_NAME \"tinyapp\"\n") &&
           asf_put(app, "src/main.c", k_main) &&
           asf_put(app, "app.mk", k_app_mk);
}

static bool aj_world_init(struct aj_world *w)
{
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    if (!getcwd(w->saved_cwd, sizeof(w->saved_cwd)) || !aj_license(w) ||
        !test_mkdtemp(w->root, sizeof(w->root), "app_journey"))
        return false;
    (void)snprintf(w->repo, sizeof(w->repo), "%s/repo", w->root);
    return aj_checkout(w) &&
           asf_journey_init(&w->j, "tinyapp", w->repo, w->root);
}

static int aj_mcp_authority(void)
{
    int failures = 0;
    TEST("app journey: MCP refuses app.copy, app.share and app.receive") {
        ASSERT(asf_mcp_refuses_owner("app.copy", "app", "tinyapp"));
        ASSERT(asf_mcp_refuses_owner("app.share", "copy", "tinyapp-1"));
        ASSERT(asf_mcp_refuses_owner("app.receive", "file", "x.z23share"));
        PASS();
    } _test_next:;
    return failures;
}

/* The first copy plan in an empty HOME seeds, and the seed plan makes the
 * owner's key (package_root and plan_id derive from it): the front door
 * must say so instead of claiming nothing changed. */
static int aj_first_plan(struct aj_world *w)
{
    int failures = 0;
    TEST("app journey: the first copy plan in an empty HOME says it made "
         "the signing key") {
        static struct asf_door run;
        char key[AJ_PATH], want[AJ_PATH + 96];
        struct stat st;
        (void)snprintf(key, sizeof(key), "%s/.z23/zcode_publisher.key",
                       w->j.a_home);
        ASSERT(stat(key, &st) != 0);
        asf_door_run(w->j.a_home, w->j.source, w->j.a_datadir, "copy",
                     w->j.app, ZCL_CLI_CONFIRM_PLAN_ONLY, &run);
        ASSERT_EQ(run.rc, 0);
        ASSERT(stat(key, &st) == 0 && S_ISREG(st.st_mode));
        (void)snprintf(want, sizeof(want), "made your signing key at %s "
                       "(first use); nothing else changed", key);
        ASSERT(strstr(run.text, want) != NULL);
        ASSERT(strstr(run.text, "nothing changed") == NULL);
        /* the key exists now, so the second plan changes nothing at all */
        asf_door_run(w->j.a_home, w->j.source, w->j.a_datadir, "copy",
                     w->j.app, ZCL_CLI_CONFIRM_PLAN_ONLY, &run);
        ASSERT_EQ(run.rc, 0);
        ASSERT(strstr(run.text, "made your signing key") == NULL);
        ASSERT(strstr(run.text, "nothing changed") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int aj_a(struct aj_world *w)
{
    int failures = 0;
    TEST("app journey A: copy seeds with the owner key, edit, save, build, "
         "open, share; nothing refused") {
        ASSERT(asf_journey_copy(&w->j));
        ASSERT(asf_replace(w->j.a_copy, "src/main.c", "boost=1", "boost=2"));
        ASSERT(asf_journey_save_build_open(&w->j));
        ASSERT(asf_journey_share(&w->j));
        PASS();
    } _test_next:;
    return failures;
}

static int aj_b(struct aj_world *w)
{
    int failures = 0;
    TEST("app journey B: open the share file receives, builds A's image and "
         "opens it") {
        ASSERT(asf_journey_receive(&w->j));
        PASS();
    } _test_next:;
    return failures;
}

/* "A sends an update": A edits, saves and shares v2 in the same ISO week,
 * and B (whose book already counts A's v1 publish) opens it. The receive is
 * the friend's deliberate step on a file, so the weekly allowance does not
 * refuse it; B ends with A's v2 image. */
static int aj_update(struct aj_world *w)
{
    int failures = 0;
    TEST("app journey update: A shares v2 in the same week and B opens it") {
        char v1[sizeof(w->j.share) + 8];
        /* a share file is never overwritten: A moves the v1 file aside */
        (void)snprintf(v1, sizeof(v1), "%s.v1", w->j.share);
        ASSERT(rename(w->j.share, v1) == 0);
        ASSERT(asf_replace(w->j.a_copy, "src/main.c", "boost=2", "boost=3"));
        ASSERT(asf_journey_save_build_open(&w->j));
        ASSERT(asf_journey_share(&w->j));
        ASSERT(strcmp(w->j.image_shared, w->j.image_b) != 0);
        ASSERT(asf_journey_receive(&w->j));
        PASS();
    } _test_next:;
    return failures;
}

int test_app_journey(void);
int test_app_journey(void)
{
    int failures = 0;
    struct aj_world w;
    chain_params_select(CHAIN_MAIN);
    failures += aj_mcp_authority();
    TEST("app journey: a fixture checkout with a stub in-repo app, two HOMEs "
         "and datadirs") {
        ASSERT(aj_world_init(&w));
        PASS();
    } _test_next:;
    if (!failures)
        failures += aj_first_plan(&w) + aj_a(&w);
    if (!failures)
        failures += aj_b(&w);
    printf("app journey: A typed %d commands (copy, save, build, open, "
           "share), B typed %d (open FILE.z23share); 0 hex pastes, 0 JSON "
           "inputs\n", w.j.commands_a, w.j.commands_b);
    if (!failures)
        failures += aj_update(&w);
    if (w.saved_cwd[0] && chdir(w.saved_cwd) != 0)
        printf("  [could not return to %s]\n", w.saved_cwd);
    if (w.saved_home[0])
        (void)setenv("HOME", w.saved_home, 1);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}
#endif /* !_WIN32 */
