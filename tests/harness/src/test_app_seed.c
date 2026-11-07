/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.seed on a fixture checkout with a tiny stub app. Asserted:
 *   - staging the app into two different directories gives byte-identical
 *     trees with the same package root: app.mk becomes the Makefile, the
 *     repo file zcode-seed.def maps comes along and the app's root-level
 *     build/ store, app.mk and zcode-seed.def stay out;
 *   - app.seed (plan, then confirm) publishes a release whose package root
 *     is that root; seeding again returns the same release and writes
 *     nothing; a second owner (other HOME key, other datadir) seeds the same
 *     package root under a different release;
 *   - the seeded release adopts into a copy that app.build builds, so the
 *     copy holds every input its build reads;
 *   - a '..', absolute or symlinked entry in zcode-seed.def, a collision
 *     with an app file and an app without app.mk are refused by name;
 *   - app.seed is owner authority: MCP refuses it, plan or confirm. */

#include "test/test_core.h"
#include "test/app_seed_fixture.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/app_seed.h"
#include "config/command_catalog.h"
#include "mcp/mcp_policy.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "vcs/package_prepare.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ASD_PATH 900

struct asd_world {
    char root[512];
    char repo[600];
    char home1[600], datadir1[600];
    char home2[600], datadir2[600];
    char saved_home[1024];
    char package_root[65];
    char release1[65];
};

static const char k_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"stub/tiny\",\n"
    "  \"semver\": \"0.1.0\",\n  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n";

static const char k_app_mk[] =
    "APP_CFLAGS = -std=c2x -O2 -Iinclude -Ihost\n"
    ".PHONY: app print-app-closure\n"
    "print-app-closure:\n"
    "\t@printf '%s\\n' Makefile include/boost.h host/shared/extra.h "
    "src/main.c\n"
    "app:\n"
    "\tcc $(APP_CFLAGS) -MD -MF $(APP_OUT)/main.d -c src/main.c "
    "-o $(APP_OUT)/main.o\n"
    "\tcc -o $(APP_OUT)/app $(APP_OUT)/main.o\n";

/* "../include/boost.h" lands in the depfile as src/../include/boost.h,
 * the spelling raylib's platform layer uses ("../external/RGFW/RGFW.h"). */
static const char k_main[] =
    "#include \"../include/boost.h\"\n#include \"shared/extra.h\"\n"
    "int main(void) { return BOOST + EXTRA - 2; }\n";

static bool asd_mkdirs(const char *base, const char *const *rels, size_t n)
{
    char path[ASD_PATH];
    for (size_t i = 0; i < n; i++) {
        if (snprintf(path, sizeof(path), "%s/%s", base, rels[i]) >=
                (int)sizeof(path) ||
            mkdir(path, 0700) != 0)
            return false;
    }
    return true;
}

/* The stub carries the same Apache-2.0 text the skycombat package does. */
static bool asd_license(const char *dir)
{
    char text[4096];
    FILE *f = fopen("apps/skycombat/LICENSE", "rb");
    if (!f)
        return false;
    size_t n = fread(text, 1, sizeof(text) - 1u, f);
    (void)fclose(f);
    text[n] = '\0';
    return n > 0 && asf_put(dir, "LICENSE", text);
}

/* One fixture app under repo/apps/<name> with the stub's files; def is its
 * zcode-seed.def text, NULL for none; with_mk adds app.mk. */
static bool asd_app(const struct asd_world *w, const char *name,
                    const char *def, bool with_mk)
{
    char dir[ASD_PATH], sub[ASD_PATH];
    (void)snprintf(dir, sizeof(dir), "%s/apps/%s", w->repo, name);
    const char *const dirs[] = {"include", "src", "build"};
    bool ok = mkdir(dir, 0700) == 0 && asd_mkdirs(dir, dirs, 3) &&
              asd_license(dir) && asf_put(dir, "zcode-package.json", k_meta) &&
              asf_put(dir, "include/boost.h", "#define BOOST 1\n") &&
              asf_put(dir, "src/main.c", k_main) &&
              asf_put(dir, "build/junk.o", "not package input\n") &&
              (!with_mk || asf_put(dir, APP_SEED_FRAGMENT, k_app_mk)) &&
              (!def || asf_put(dir, APP_SEED_DEF, def));
    (void)snprintf(sub, sizeof(sub), "%s/include/boost.h", dir);
    return ok && chmod(sub, 0640) == 0;
}

static bool asd_repo(struct asd_world *w)
{
    char outside[ASD_PATH], link[ASD_PATH];
    const char *const dirs[] = {"apps", "lib", "lib/shared"};
    (void)snprintf(outside, sizeof(outside), "%s/outside", w->root);
    bool ok = mkdir(w->repo, 0700) == 0 && asd_mkdirs(w->repo, dirs, 3) &&
              mkdir(outside, 0700) == 0 &&
              asf_put(outside, "secret.h", "#define SECRET 1\n") &&
              asf_put(w->repo, "lib/shared/extra.h", "#define EXTRA 1\n");
    (void)snprintf(link, sizeof(link), "%s/lib/link.h", w->repo);
    ok = ok && symlink("../../outside/secret.h", link) == 0;
    (void)snprintf(link, sizeof(link), "%s/linkdir", w->repo);
    ok = ok && symlink("../outside", link) == 0;
    const char *good = "# host files the build reads\n\n"
                       "lib/shared/extra.h host/shared/extra.h\n";
    return ok && asd_app(w, "tiny", good, true) &&
           asd_app(w, "dotdot", "../outside/secret.h host/s.h\n", true) &&
           asd_app(w, "treedots", "lib/shared/extra.h ../s.h\n", true) &&
           asd_app(w, "absolute", "/etc/hostname host/h\n", true) &&
           asd_app(w, "linkfile", "lib/link.h host/link.h\n", true) &&
           asd_app(w, "linkdir", "linkdir/secret.h host/s.h\n", true) &&
           asd_app(w, "collide", "lib/shared/extra.h src/main.c\n", true) &&
           asd_app(w, "nomk", good, false);
}

static bool asd_world_init(struct asd_world *w)
{
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    if (!test_mkdtemp(w->root, sizeof(w->root), "app_seed"))
        return false;
    (void)snprintf(w->repo, sizeof(w->repo), "%s/repo", w->root);
    (void)snprintf(w->home1, sizeof(w->home1), "%s/owner1", w->root);
    (void)snprintf(w->datadir1, sizeof(w->datadir1), "%s/owner1/datadir",
                   w->root);
    (void)snprintf(w->home2, sizeof(w->home2), "%s/owner2", w->root);
    (void)snprintf(w->datadir2, sizeof(w->datadir2), "%s/owner2/datadir",
                   w->root);
    return asd_repo(w) && mkdir(w->home1, 0700) == 0 &&
           mkdir(w->datadir1, 0700) == 0 && mkdir(w->home2, 0700) == 0 &&
           mkdir(w->datadir2, 0700) == 0 && setenv("HOME", w->home1, 1) == 0;
}

/* ── staging ─────────────────────────────────────────────────────────── */

static bool asd_same_file(const char *a, const char *b)
{
    char x[4096], y[4096];
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    size_t na = fa ? fread(x, 1, sizeof(x), fa) : 0;
    size_t nb = fb ? fread(y, 1, sizeof(y), fb) : 0;
    if (fa)
        (void)fclose(fa);
    if (fb)
        (void)fclose(fb);
    return fa && fb && na > 0 && na == nb && memcmp(x, y, na) == 0;
}

static bool asd_prepare_root(const char *dir, char out[65])
{
    char key[ASD_PATH], pubhex[PLUGIN_HEX_PUBLIC_KEY + 1], detail[256] = "";
    struct plugin_dist_published why;
    struct vcs_package_prepare_options o = {
        .dir = dir, .publisher_sequence = 1, .reward_address = "",
        .chain_id = "zclassic-main",
    };
    struct vcs_package_prepared p;
    (void)snprintf(key, sizeof(key), "%s.key", dir);
    if (plugin_keygen(key, pubhex) != PLUGIN_OK ||
        plugin_dist_release_key_sign(key, NULL, o.publisher_pubkey, NULL,
                                     &why) != PLUGIN_DIST_OK)
        return false;
    bool ok = vcs_package_prepare(&o, &p, detail, sizeof(detail)) ==
              VCS_PACKAGE_PREPARE_OK;
    if (ok)
        zcl_hex_encode(p.package_root, 32, out);
    else
        printf("  [prepare %s: %s]\n", dir, detail);
    vcs_package_prepared_free(&p);
    return ok;
}

static bool asd_stage(const struct asd_world *w, const char *dest,
                      struct app_seed_stage *s)
{
    if (mkdir(dest, 0700) != 0)
        return false;
    bool ok = app_seed_stage(w->repo, "tiny", dest, s);
    if (!ok)
        printf("  [stage %s: %s %s]\n", dest, s->code, s->why);
    return ok;
}

static int asd_staging_deterministic(struct asd_world *w)
{
    int failures = 0;
    TEST("app.seed: two staging directories give the same tree and root") {
        char a[ASD_PATH], b[ASD_PATH], fa[ASD_PATH], fb[ASD_PATH];
        char deep[ASD_PATH], root_b[65];
        struct app_seed_stage sa, sb;
        struct stat st;
        (void)snprintf(a, sizeof(a), "%s/stage-a", w->root);
        (void)snprintf(deep, sizeof(deep), "%s/elsewhere", w->root);
        (void)snprintf(b, sizeof(b), "%s/elsewhere/stage-b", w->root);
        ASSERT(mkdir(deep, 0700) == 0);
        ASSERT(asd_stage(w, a, &sa) && asd_stage(w, b, &sb));
        ASSERT(sa.mapped == 1u && sb.mapped == 1u);
        (void)snprintf(fa, sizeof(fa), "%s/Makefile", a);
        (void)snprintf(fb, sizeof(fb), "%s/apps/tiny/app.mk", w->repo);
        ASSERT(asd_same_file(fa, fb));
        (void)snprintf(fa, sizeof(fa), "%s/host/shared/extra.h", a);
        (void)snprintf(fb, sizeof(fb), "%s/host/shared/extra.h", b);
        ASSERT(asd_same_file(fa, fb));
        (void)snprintf(fa, sizeof(fa), "%s/include/boost.h", a);
        (void)snprintf(fb, sizeof(fb), "%s/apps/tiny/include/boost.h",
                       w->repo);
        ASSERT(asd_same_file(fa, fb));
        (void)snprintf(fa, sizeof(fa), "%s/build", a);
        ASSERT(stat(fa, &st) != 0);
        (void)snprintf(fa, sizeof(fa), "%s/app.mk", a);
        ASSERT(stat(fa, &st) != 0);
        (void)snprintf(fa, sizeof(fa), "%s/" APP_SEED_DEF, a);
        ASSERT(stat(fa, &st) != 0);
        ASSERT(asd_prepare_root(a, w->package_root));
        ASSERT(asd_prepare_root(b, root_b));
        ASSERT(strcmp(w->package_root, root_b) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the leaf ────────────────────────────────────────────────────────── */

static int asd_mcp_refuses(void)
{
    int failures = 0;
    TEST("app.seed: owner authority, refused to MCP at plan and confirm") {
        const struct zcl_command_spec *spec = asf_spec("app.seed");
        struct mcp_refusal why = {0};
        struct json_value in;
        ASSERT(spec && spec->authority == ZCL_COMMAND_AUTH_OWNER);
        ASSERT(spec->confirmation == ZCL_COMMAND_CONFIRM_PLAN_COMMIT);
        json_init(&in);
        json_set_object(&in);
        (void)json_push_kv_str(&in, "app", "skycombat");
        bool plan_refused =
            !mcp_policy_allows(spec, zcl_command_catalog(), &in, &why);
        (void)json_push_kv_str(&in, "plan_id", "00000000000000000000000000000"
                               "00000000000000000000000000000000000");
        (void)json_push_kv_bool(&in, "confirm", true);
        bool confirm_refused =
            !mcp_policy_allows(spec, zcl_command_catalog(), &in, &why);
        json_free(&in);
        ASSERT(plan_refused && confirm_refused);
        PASS();
    } _test_next:;
    return failures;
}

static int asd_seeds_and_reseeds(struct asd_world *w)
{
    int failures = 0;
    TEST("app.seed: publishes the staged root; seeding again is the same "
         "release and writes nothing") {
        struct asf_leaf l;
        ASSERT(asf_seed(&l, "tiny", w->repo, w->datadir1));
        ASSERT(strcmp(asf_get(&l, "package_root"), w->package_root) == 0);
        ASSERT(strlen(asf_get(&l, "release_id")) == 64);
        ASSERT(json_get_int(json_get(&l.out.data, "file_count")) == 6);
        ASSERT(!asf_flag(&l, "existing") && l.out.error.mutated);
        (void)snprintf(w->release1, sizeof(w->release1), "%s",
                       asf_get(&l, "release_id"));
        asf_close(&l);
        ASSERT(asf_seed(&l, "tiny", w->repo, w->datadir1));
        ASSERT(strcmp(asf_get(&l, "release_id"), w->release1) == 0);
        ASSERT(strcmp(asf_get(&l, "package_root"), w->package_root) == 0);
        ASSERT(asf_flag(&l, "existing") && !l.out.error.mutated);
        asf_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

static int asd_second_owner(const struct asd_world *w)
{
    int failures = 0;
    TEST("app.seed: another owner seeds the same package root under its own "
         "release") {
        struct asf_leaf l;
        ASSERT(setenv("HOME", w->home2, 1) == 0);
        bool ok = asf_seed(&l, "tiny", w->repo, w->datadir2);
        ASSERT(setenv("HOME", w->home1, 1) == 0);
        ASSERT(ok);
        ASSERT(strcmp(asf_get(&l, "package_root"), w->package_root) == 0);
        ASSERT(strcmp(asf_get(&l, "release_id"), w->release1) != 0);
        asf_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

static int asd_copy_builds(const struct asd_world *w)
{
    int failures = 0;
    TEST("app.seed: the seeded release adopts into a copy app.build builds") {
        struct asf_leaf l;
        char copy[ASD_PATH], host[ASD_PATH + 32];
        struct stat st;
        ASSERT(asf_adopt(w->release1, w->datadir1, copy, sizeof(copy)));
        (void)snprintf(host, sizeof(host), "%s/host/shared/extra.h", copy);
        ASSERT(stat(host, &st) == 0 && S_ISREG(st.st_mode));
        ASSERT(asf_build(&l, copy, w->datadir1));
        ASSERT(strlen(asf_get(&l, "image_sha3")) == 64);
        ASSERT(strcmp(asf_get(&l, "package_root"), w->package_root) == 0);
        asf_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

static bool asd_refused(const struct asd_world *w, const char *app,
                        const char *code)
{
    struct asf_leaf l;
    asf_open(&l);
    (void)json_push_kv_str(&l.in, "app", app);
    (void)json_push_kv_str(&l.in, "source", w->repo);
    (void)json_push_kv_str(&l.in, "datadir", w->datadir1);
    bool ok = asf_exec("app.seed", &l) && asf_refusal(&l, code) &&
              !l.out.error.mutated;
    asf_close(&l);
    return ok;
}

static int asd_refusals(const struct asd_world *w)
{
    int failures = 0;
    TEST("app.seed: '..', absolute and symlinked entries are refused") {
        ASSERT(asd_refused(w, "dotdot", "SEED_PATH_ESCAPE"));
        ASSERT(asd_refused(w, "treedots", "SEED_PATH_ESCAPE"));
        ASSERT(asd_refused(w, "absolute", "SEED_PATH_ESCAPE"));
        ASSERT(asd_refused(w, "linkfile", "SEED_NOT_REGULAR"));
        ASSERT(asd_refused(w, "linkdir", "SEED_NOT_REGULAR"));
        PASS();
    } _test_next:;
    return failures;
}

static int asd_refusals_app(const struct asd_world *w)
{
    int failures = 0;
    TEST("app.seed: a collision, a missing app.mk and an unknown app are "
         "refused") {
        ASSERT(asd_refused(w, "collide", "SEED_COLLISION"));
        ASSERT(asd_refused(w, "nomk", "NO_MAKE_FRAGMENT"));
        ASSERT(asd_refused(w, "nosuchapp", "APP_UNKNOWN"));
        ASSERT(asd_refused(w, "../tiny", "BAD_APP"));
        PASS();
    } _test_next:;
    return failures;
}

int test_app_seed(void);
int test_app_seed(void)
{
    int failures = 0;
    struct asd_world w;
    chain_params_select(CHAIN_MAIN);
    TEST("app.seed: a fixture checkout with a stub app") {
        ASSERT(asd_world_init(&w));
        PASS();
    } _test_next:;
    failures += asd_mcp_refuses();
    if (!failures)
        failures += asd_staging_deterministic(&w);
    if (!failures)
        failures += asd_seeds_and_reseeds(&w);
    if (!failures)
        failures += asd_second_owner(&w);
    if (!failures)
        failures += asd_copy_builds(&w);
    if (!failures)
        failures += asd_refusals(&w) + asd_refusals_app(&w);
    if (w.saved_home[0])
        (void)setenv("HOME", w.saved_home, 1);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}
