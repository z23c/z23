/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.seed on a fixture checkout with a tiny stub app. Asserted:
 *   - staging the app into two different directories gives byte-identical
 *     trees with the same package root: the app's own Makefile is staged
 *     as its package entrypoint, the repo file zcode-seed.def maps comes
 *     along and the app's root-level build/ store and zcode-seed.def stay
 *     out; the staged tree's print-app-closure names its four inputs;
 *   - app.seed (plan, then confirm) publishes a release whose package root
 *     is that root; seeding again returns the same release and writes
 *     nothing; a second owner (other HOME key, other datadir) seeds the same
 *     package root under a different release;
 *   - the seeded release adopts into a copy that app.build builds, so the
 *     copy holds every input its build reads;
 *   - a '..', absolute or symlinked entry in zcode-seed.def, a collision
 *     with an app file, an app without a Makefile, a Makefile without
 *     print-app-closure and one naming an input the tree does not hold are
 *     refused by name;
 *   - app.seed is owner authority: MCP refuses it, plan or confirm. */

#include "test/test_core.h"
#include "test/app_seed_fixture.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/app_build_make.h"
#include "command/app_installed_source.h"
#include "command/native_app_seed_installed.h"
#include "command/native_app_personalize_command.h"
#include "command/native_app_adopt.h"
#include "command/native_app_receive_preview.h"
#include "command/native_app_installed_copy.h"
#include "base/safe_alloc.h"
#include "platform/time_compat.h"
#if defined(ZCL_TESTING) && !defined(_WIN32)
#include <pthread.h>
#include <time.h>
#endif
#include "command/native_zcode_package_copy.h"
#include "command/app_seed.h"
#include "config/command_catalog.h"
#include "mcp/mcp_policy.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "sha3/sha3.h"
#include "vcs/package_prepare.h"
#include "util/file_tree_ops.h"

#include <stdio.h>
#include <errno.h>
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

/* The stub's package entrypoint. */
static const char k_makefile[] =
    "APP_CFLAGS = -std=c2x -O2 -Iinclude -Ihost\n"
    ".PHONY: app print-app-closure\n"
    "print-app-closure:\n"
    "\t@printf '%s\\n' Makefile include/boost.h host/shared/extra.h "
    "src/main.c\n"
    "app:\n"
    "\tcc $(APP_CFLAGS) -MD -MF $(APP_OUT)/main.d -c src/main.c "
    "-o $(APP_OUT)/main.o\n"
    "\tcc -o $(APP_OUT)/app $(APP_OUT)/main.o\n";

/* A Makefile with no package targets, and one whose closure names a file
 * the staged tree does not hold. */
static const char k_makefile_no_targets[] = "all:\n\t@true\n";
static const char k_makefile_absent_input[] =
    ".PHONY: app print-app-closure\n"
    "print-app-closure:\n"
    "\t@printf '%s\\n' Makefile src/main.c host/absent.h\n"
    "app:\n\t@true\n";

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
 * zcode-seed.def text and mk its Makefile, NULL for none. */
static bool asd_app(const struct asd_world *w, const char *name,
                    const char *def, const char *mk)
{
    char dir[ASD_PATH], sub[ASD_PATH];
    (void)snprintf(dir, sizeof(dir), "%s/apps/%s", w->repo, name);
    const char *const dirs[] = {"include", "src", "build"};
    bool ok = mkdir(dir, 0700) == 0 && asd_mkdirs(dir, dirs, 3) &&
              asd_license(dir) && asf_put(dir, "zcode-package.json", k_meta) &&
              asf_put(dir, "include/boost.h", "#define BOOST 1\n") &&
              asf_put(dir, "src/main.c", k_main) &&
              asf_put(dir, "build/junk.o", "not package input\n") &&
              (!mk || asf_put(dir, APP_SEED_MAKEFILE, mk)) &&
              (!def || asf_put(dir, APP_SEED_DEF, def));
    (void)snprintf(sub, sizeof(sub), "%s/include/boost.h", dir);
    return ok && chmod(sub, 0640) == 0;
}

/* The good stub and one fixture app per refusal. */
static bool asd_apps(const struct asd_world *w)
{
    const char *good = "# host files the build reads\n\n"
                       "lib/shared/extra.h host/shared/extra.h\n";
    const char *mk = k_makefile;
    return asd_app(w, "tiny", good, mk) &&
           asd_app(w, "dotdot", "../outside/secret.h host/s.h\n", mk) &&
           asd_app(w, "treedots", "lib/shared/extra.h ../s.h\n", mk) &&
           asd_app(w, "absolute", "/etc/hostname host/h\n", mk) &&
           asd_app(w, "linkfile", "lib/link.h host/link.h\n", mk) &&
           asd_app(w, "linkdir", "linkdir/secret.h host/s.h\n", mk) &&
           asd_app(w, "collide", "lib/shared/extra.h src/main.c\n", mk) &&
           asd_app(w, "nomk", good, NULL) &&
           asd_app(w, "notargets", good, k_makefile_no_targets) &&
           asd_app(w, "absentinput", good, k_makefile_absent_input);
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
    return ok && asd_apps(w);
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
        ASSERT(sa.closure == 4u && sb.closure == 4u);
        (void)snprintf(fa, sizeof(fa), "%s/Makefile", a);
        (void)snprintf(fb, sizeof(fb), "%s/apps/tiny/Makefile", w->repo);
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
        ASSERT(strcmp(asf_get(&l, "confinement"),
                      app_build_make_confinable() ? "landlock"
                                                  : "unconfined") == 0);
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

static bool asd_export_input(struct asf_leaf *out, const struct asf_leaf *built,
                             const struct asd_world *w, const char *copy,
                             const char *destination)
{
    static const char *const keys[] = {
        "version", "env_root", "dependency_root", "record_id"
    };
    asf_open(out);
    bool ok = json_push_kv_str(&out->in, "app", "tiny") &&
        json_push_kv_str(&out->in, "copy", copy) &&
        json_push_kv_str(&out->in, "datadir", w->datadir1) &&
        json_push_kv_str(&out->in, "artifact_dir", destination);
    for (size_t i = 0; ok && i < sizeof(keys) / sizeof(keys[0]); ++i)
        ok = json_push_kv_str(&out->in, keys[i], asf_get(built, keys[i]));
    return ok;
}

static bool asd_export_identity(const char *copy, const struct asf_leaf *built,
                                 const struct app_installed_source *source)
{
    struct asf_leaf probe; asf_open(&probe);
    struct zcl_package_copy history = {0};
    uint8_t package[32], record[32];
    bool ok = zcl_hex_decode_lower(asf_get(built, "package_root"), package, 32) &&
        zcl_hex_decode_lower(asf_get(built, "record_id"), record, 32) &&
        zcl_package_copy_open_selected_as(copy, ZCL_PACKAGE_COPY_READ, &history,
            &probe.out, "app.source.export", asf_get(built, "version"));
    if (ok) ok = !memcmp(source->tree_root, history.selected_tree, 32) &&
        !memcmp(source->package_root, package, 32) && !memcmp(source->record_id, record, 32);
    zcl_package_copy_close(&history);
    asf_close(&probe);
    return ok;
}

static bool asd_export_rejects_record(const char *destination, const char *pin,
                                       const char *image, struct app_installed_source *source)
{
    char why[256];
    return asf_put(destination, APP_INSTALLED_SOURCE_RECORD, "tampered record") &&
        !app_installed_source_load(destination, pin, image, source, why, sizeof(why)) &&
        !source->bundle.bytes && !source->projection.bytes && !source->record.bytes;
}

static bool asd_verify_leaf(const char *destination, const struct asf_leaf *built,
                             const struct asf_leaf *exported, const char *app)
{
    struct asf_leaf check; asf_open(&check);
    bool ok = json_push_kv_str(&check.in, "app", app) &&
        json_push_kv_str(&check.in, "artifact_dir", destination) &&
        json_push_kv_str(&check.in, "projection_sha3", asf_get(exported, "projection_sha3")) &&
        json_push_kv_str(&check.in, "image_file", asf_get(built, "image_path")) &&
        asf_exec("app.source.verify", &check);
    if (ok && !strcmp(app, "tiny"))
        ok = check.out.status == ZCL_COMMAND_STATUS_PASSED &&
            asf_flag(&check, "artifact_consistent") &&
            json_get(&check.out.data, "source_package_checked") &&
            json_get(&check.out.data, "source_package_checked")->type == JSON_BOOL &&
            !asf_flag(&check, "source_package_checked");
    else if (ok) ok = asf_refusal(&check, "APP_MISMATCH") && !check.out.error.mutated;
    asf_close(&check);
    return ok;
}

static bool asd_retained_stage(struct app_installed_source *source, bool expected)
{
    char scratch[512], staged[600], why[256], path[640], bytes[sizeof(k_main)] = {0};
    bool staged_ok = app_installed_source_stage(source, scratch, sizeof(scratch),
        staged, sizeof(staged), why, sizeof(why));
    bool ok = staged_ok == expected && scratch[0];
    if (ok && expected) {
        int n = snprintf(path, sizeof(path), "%s/src/main.c", staged);
        FILE *f = n > 0 && (size_t)n < sizeof(path) ? fopen(path, "rb") : NULL;
        ok = f && fread(bytes, 1, sizeof(bytes), f) == sizeof(k_main) - 1 &&
            !ferror(f) && feof(f) && !memcmp(bytes, k_main, sizeof(k_main) - 1);
        if (f && fclose(f) != 0) ok = false;
    } else if (ok) ok = !staged[0];
    if (scratch[0] && !zcl_tree_remove(scratch).ok) ok = false;
    return ok;
}

static bool asd_retained_derives(struct app_installed_source *source)
{
    bool ok = asd_retained_stage(source, true);
    /* A valid source bundle is insufficient: a claimed different package or
     * altered canonical recipe must fail before a key or make is needed. */
    source->package_root[0] ^= 1;
    bool rejects_package = asd_retained_stage(source, false);
    source->package_root[0] ^= 1;
    if (!source->recipe.length) return false;
    source->recipe.bytes[0] ^= 1;
    bool rejects_recipe = asd_retained_stage(source, false);
    source->recipe.bytes[0] ^= 1;
    return ok && rejects_package && rejects_recipe;
}

static bool asd_installed_seed_call(const struct app_installed_source *source,
    const char *datadir, struct asf_leaf *leaf, bool stale_owner)
{
    asf_open(leaf);
    if (!json_push_kv_str(&leaf->in, "app", source->app) ||
        !json_push_kv_str(&leaf->in, "datadir", datadir)) return false;
    char path[4400], publisher[67]; bool exists;
    if (!app_personalize_key_probe(&leaf->out, path, sizeof(path), publisher, &exists)) return false;
    if (stale_owner && exists) publisher[0] = 0;
    const struct app_seed_installed_owner owner = {
        .key_path = path, .publisher = publisher, .exists = stale_owner ? !exists : exists,
    };
    struct zcl_command_request request = {.input = &leaf->in};
    app_seed_installed_commit(&request, &leaf->out, source, &owner);
    return true;
}

static bool asd_adopted_plan(struct app_receive_preview *preview,
    const struct json_value *adopted, const uint8_t original_package[32])
{
    struct asf_leaf build; asf_open(&build);
    json_free(&build.in);
    bool ok = app_receive_preview_build_input(preview, &build.in) && asf_pass("app.build", &build);
    char original[65]; zcl_hex_encode(original_package, 32, original);
    if (ok) ok = strcmp(asf_get(&build, "package_root"), original) &&
        !strcmp(asf_get(&build, "version"), json_get_str(json_get(adopted, "version")));
    struct json_value wire, confirm; json_init(&wire); json_set_object(&wire); json_init(&confirm);
    ok = ok && json_push_kv_str(&wire, "command", "app.build") &&
        json_push_kv_str(&wire, "status", "passed") && json_push_kv_bool(&wire, "ok", true) &&
        json_push_kv(&wire, "data", &build.out.data) &&
        app_receive_preview_confirm_input(preview, &wire, &confirm, &build.out);
    json_free(&wire); json_free(&confirm); asf_close(&build);
    return ok;
}

static bool asd_unsaved_unchanged(const char *source);

static bool asd_received_publisher(struct json_value *in, const char *datadir,
    const char *release)
{
    struct vcs_package_release persisted; uint8_t root[32], id[32]; char publisher[67];
    if (!zcl_hex_decode_lower(release, root, 32) ||
        zcl_package_copy_find_release(datadir, root, &persisted, id) != ZCL_PACKAGE_COPY_FOUND ||
        memcmp(root, id, 32)) return false;
    zcl_hex_encode(persisted.publisher_pubkey, sizeof(persisted.publisher_pubkey), publisher);
    return json_push_kv_str(in, "publisher_fingerprint", publisher);
}

static bool asd_adopted_not_received(const struct asf_leaf *adopted, const char *datadir)
{
    struct asf_leaf received; asf_open(&received);
    bool ok = json_push_kv_str(&received.in, "destination", asf_get(adopted, "copy")) &&
        json_push_kv_str(&received.in, "stage", "commit") &&
        json_push_kv_bool(&received.in, "executed", false) &&
        json_push_kv_str(&received.in, "version", asf_get(adopted, "version")) &&
        json_push_kv_str(&received.in, "release_id", asf_get(adopted, "release_root")) &&
        json_push_kv_str(&received.in, "package_root", asf_get(adopted, "package_root")) &&
        asd_received_publisher(&received.in, datadir, asf_get(adopted, "release_root"));
    struct app_receive_preview *preview = NULL;
    if (ok) ok = !app_receive_preview_create(&received.in, datadir, &preview, &received.out) &&
        !preview && asf_refusal(&received, "PREVIEW_COPY_REFUSED");
    app_receive_preview_close(preview);
    asf_close(&received);
    return ok;
}

static bool asd_adopted_unsaved(const struct asf_leaf *adopted)
{
    char path[ASD_PATH + 32];
    int n = snprintf(path, sizeof(path), "%s/src/main.c", asf_get(adopted, "copy"));
    return n > 0 && (size_t)n < sizeof(path) && asd_unsaved_unchanged(path);
}

static bool asd_copies_absent(const char *datadir)
{
    char path[ASD_PATH + 32]; struct stat st;
    int n = snprintf(path, sizeof(path), "%s/copies", datadir);
    return n > 0 && (size_t)n < sizeof(path) && lstat(path, &st) != 0 && errno == ENOENT;
}

static bool asd_adopt_identity_refused(const struct asf_leaf *seed, const char *datadir,
    const uint8_t package[32], bool wrong_key)
{
    struct asf_leaf adopted; asf_open(&adopted);
    char publisher[67], key[4408];
    int k = snprintf(key, sizeof(key), "%s.changed", asf_get(seed, "key_path"));
    const char *pub = asf_get(seed, "publisher");
    bool ok = k > 0 && (size_t)k < sizeof(key) &&
        strlen(pub) == 66 && asd_copies_absent(datadir);
    if (ok) {
        memcpy(publisher, pub, sizeof(publisher));
        publisher[65] = publisher[65] == '0' ? '1' : '0';
        ok = json_push_kv_str(&adopted.in, "release_root", asf_get(seed, "release_id")) &&
            json_push_kv_str(&adopted.in, "datadir", datadir);
    }
    if (ok) {
        struct zcl_command_request request = {.input = &adopted.in};
        app_adopt_installed_confirmed(&request, &adopted.out, package,
            wrong_key ? key : asf_get(seed, "key_path"), wrong_key ? pub : publisher);
        ok = asf_refusal(&adopted, "PUBLISHER_CHANGED") && !adopted.out.error.mutated;
    }
    if (ok) ok = asd_copies_absent(datadir);
    asf_close(&adopted);
    return ok;
}

static bool asd_adopted_preview(const char *datadir, const struct asf_leaf *seed,
    const uint8_t original_package[32])
{
    struct asf_leaf adopted; asf_open(&adopted);
    bool ok = json_push_kv_str(&adopted.in, "release_root", asf_get(seed, "release_id")) &&
        json_push_kv_str(&adopted.in, "datadir", datadir);
    struct zcl_command_request request = {.input = &adopted.in};
    if (ok) app_adopt_installed_confirmed(&request, &adopted.out, original_package,
        asf_get(seed, "key_path"), asf_get(seed, "publisher"));
    ok = ok && adopted.out.status == ZCL_COMMAND_STATUS_PASSED &&
        strcmp(asf_get(&adopted, "root_commit"), asf_get(&adopted, "version")) &&
        asf_put(asf_get(&adopted, "copy"), "src/main.c", "unsaved edits must survive export\n");
    struct app_receive_preview *preview = NULL;
    ok = ok && app_receive_preview_create_adopted(&adopted.out.data, datadir, &preview, &adopted.out) &&
        asd_adopted_plan(preview, &adopted.out.data, original_package);
    app_receive_preview_close(preview);
    /* Reach the trust check with valid received locations and roots. */
    if (ok) ok = asd_adopted_not_received(&adopted, datadir);
    if (ok) ok = asd_adopted_unsaved(&adopted);
    asf_close(&adopted);
    return ok;
}

static bool asd_installed_seed_invalid(struct app_installed_source *source,
    const char *datadir, const char *home)
{
    struct asf_leaf leaf;
    char key[900];
    (void)snprintf(key, sizeof(key), "%s/.z23/zcode_publisher.key", home);
    source->package_root[0] ^= 1;
    bool ok = asd_installed_seed_call(source, datadir, &leaf, false) &&
        asf_refusal(&leaf, "INSTALLED_SOURCE_INVALID") && !leaf.out.error.mutated &&
        access(key, F_OK) != 0;
    source->package_root[0] ^= 1;
    asf_close(&leaf);
    return ok;
}

static bool asd_installed_seed_repeated(const struct app_installed_source *source,
    const char *datadir, const char *release)
{
    struct asf_leaf leaf;
    bool ok = asd_installed_seed_call(source, datadir, &leaf, false) &&
        leaf.out.status == ZCL_COMMAND_STATUS_PASSED && asf_flag(&leaf, "existing") &&
        !asf_flag(&leaf, "key_created") && !leaf.out.error.mutated &&
        !strcmp(asf_get(&leaf, "release_id"), release);
    asf_close(&leaf);
    if (!ok) return false;
    /* A key appearing after consent must refuse before signing. */
    ok = asd_installed_seed_call(source, datadir, &leaf, true) &&
        asf_refusal(&leaf, "PUBLISHER_CHANGED") && !leaf.out.error.mutated;
    asf_close(&leaf);
    return ok;
}

static bool asd_installed_seed_checks(struct app_installed_source *source,
    const char *datadir, const char *home)
{
    if (!asd_installed_seed_invalid(source, datadir, home)) return false;
    struct asf_leaf leaf;
    char release[65], package[65];
    zcl_hex_encode(source->package_root, 32, package);
    bool ok = asd_installed_seed_call(source, datadir, &leaf, false) &&
        leaf.out.status == ZCL_COMMAND_STATUS_PASSED && asf_flag(&leaf, "key_created") &&
        !strcmp(asf_get(&leaf, "package_root"), package) && strlen(asf_get(&leaf, "release_id")) == 64;
    (void)snprintf(release, sizeof(release), "%s", asf_get(&leaf, "release_id"));
    if (ok) ok = asd_installed_seed_repeated(source, datadir, release) &&
        asd_adopt_identity_refused(&leaf, datadir, source->package_root, true) &&
        asd_adopt_identity_refused(&leaf, datadir, source->package_root, false) &&
        asd_adopted_preview(datadir, &leaf, source->package_root);
    asf_close(&leaf);
    return ok;
}

static bool asd_installed_seed(struct app_installed_source *source)
{
    char home[512], old_home[1024], datadir[600];
    const char *old = getenv("HOME");
    if (!old || strlen(old) >= sizeof(old_home)) return false;
    memcpy(old_home, old, strlen(old) + 1);
    if (!test_mkdtemp(home, sizeof(home), "installed_seed")) return false;
    (void)snprintf(datadir, sizeof(datadir), "%s/data", home);
    bool ok = mkdir(datadir, 0700) == 0 && setenv("HOME", home, 1) == 0 &&
        asd_installed_seed_checks(source, datadir, home);
    if (setenv("HOME", old_home, 1) != 0) ok = false;
    if (!zcl_tree_remove(home).ok) ok = false;
    return ok;
}

static bool asd_export_verifies(const char *destination, const char *copy,
                                 const struct asf_leaf *built, const struct asf_leaf *exported)
{
    const char *pin = asf_get(exported, "projection_sha3");
    const char *image = asf_get(built, "image_path");
    if (strlen(pin) != 64 || !image[0]) return false;
    char wrong[65], why[256];
    memcpy(wrong, pin, sizeof(wrong));
    wrong[0] = wrong[0] == '0' ? '1' : '0';
    struct app_installed_source source;
    app_installed_source_init(&source);
    bool ok = app_installed_source_load(destination, pin, image, &source, why, sizeof(why)) &&
        !strcmp(source.app, "tiny") && source.bundle.length > 0 &&
        asd_export_identity(copy, built, &source) &&
        !app_installed_source_load(destination, wrong, image, &source, why, sizeof(why)) &&
        !source.bundle.bytes && !source.projection.bytes &&
        app_installed_source_load(destination, pin, image, &source, why, sizeof(why));
    if (ok) ok = asd_retained_derives(&source) && asd_installed_seed(&source) &&
        asd_export_rejects_record(destination, pin, image, &source);
    app_installed_source_free(&source);
    return ok;
}

static bool asd_export_no_overwrite(const struct asd_world *w, const char *copy,
                                    const char *destination, const struct asf_leaf *built,
                                    const struct asf_leaf *exported)
{
    struct asf_leaf repeated;
    bool ok = asd_export_input(&repeated, built, w, copy, destination) &&
        asf_exec("app.source.export", &repeated) &&
        asf_refusal(&repeated, "OUTPUT_EXISTS") && !repeated.out.error.mutated;
    asf_close(&repeated);
    struct app_installed_source preserved; app_installed_source_init(&preserved);
    char why[256];
    /* The unchanged independently captured projection pin rechecks every
     * retained member's exact bytes, not just whether its path still exists. */
    if (ok) ok = app_installed_source_load(destination, asf_get(exported, "projection_sha3"),
        asf_get(built, "image_path"), &preserved, why, sizeof(why));
    app_installed_source_free(&preserved);
    return ok;
}

static bool asd_unsaved_unchanged(const char *source)
{
    char text[64] = {0};
    FILE *f = fopen(source, "rb");
    bool same = f && fgets(text, sizeof(text), f) &&
        !strcmp(text, "unsaved edits must survive export\n") &&
        fgetc(f) == EOF && !ferror(f);
    if (f && fclose(f) != 0) same = false;
    return same;
}

static bool asd_export_saved(const struct asd_world *w, const char *copy,
                              const struct asf_leaf *built)
{
    char destination[ASD_PATH], source[ASD_PATH + 32];
    if (snprintf(destination, sizeof(destination), "%s/installed-source", w->root)
            >= (int)sizeof(destination) ||
        snprintf(source, sizeof(source), "%s/src/main.c", copy) >= (int)sizeof(source))
        return false;
    if (!asf_put(copy, "src/main.c", "unsaved edits must survive export\n")) return false;
    struct asf_leaf exported;
    bool ok = asd_export_input(&exported, built, w, copy, destination) &&
        asf_pass("app.source.export", &exported) &&
        asd_export_no_overwrite(w, copy, destination, built, &exported) &&
        asd_verify_leaf(destination, built, &exported, "tiny") &&
        asd_verify_leaf(destination, built, &exported, "different-app") &&
        asd_export_verifies(destination, copy, built, &exported);
    asf_close(&exported);
    return ok && asd_unsaved_unchanged(source);
}

/* sha3 of the owner key file under home; the key bytes are never shown. */
static bool asd_key_digest(const char *home, uint8_t out[32])
{
    char path[ASD_PATH];
    uint8_t buf[256];
    (void)snprintf(path, sizeof(path), "%s/.z23/zcode_publisher.key", home);
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(buf, 1, sizeof(buf), f);
    (void)fclose(f);
    if (n == 0 || n == sizeof(buf))
        return false;
    zcl_sha3_256(buf, n, out);
    return true;
}

static int asd_plan_writes_nothing(const struct asd_world *w)
{
    int failures = 0;
    TEST("app.seed: the plan half writes no owner key; confirm makes it "
         "0600 and a later seed reuses the same key") {
        char home[ASD_PATH], dd1[ASD_PATH], dd2[ASD_PATH], dot[ASD_PATH + 8];
        char plan[65];
        uint8_t first[32], again[32];
        struct stat st;
        struct asf_leaf l;
        (void)snprintf(home, sizeof(home), "%s/owner3", w->root);
        (void)snprintf(dd1, sizeof(dd1), "%s/datadir", home);
        (void)snprintf(dd2, sizeof(dd2), "%s/datadir2", home);
        (void)snprintf(dot, sizeof(dot), "%s/.z23", home);
        ASSERT(mkdir(home, 0700) == 0 && mkdir(dd1, 0700) == 0 &&
               mkdir(dd2, 0700) == 0 && setenv("HOME", home, 1) == 0);
        asf_open(&l);
        (void)json_push_kv_str(&l.in, "app", "tiny");
        (void)json_push_kv_str(&l.in, "source", w->repo);
        (void)json_push_kv_str(&l.in, "datadir", dd1);
        bool planned = asf_pass("app.seed", &l);
        bool wrote = lstat(dot, &st) == 0;
        (void)snprintf(plan, sizeof(plan), "%s", asf_get(&l, "plan_id"));
        bool created = asf_flag(&l, "key_created");
        asf_close(&l);
        ASSERT(setenv("HOME", w->home1, 1) == 0);
        ASSERT(planned && !wrote && !created && strlen(plan) == 64);
        ASSERT(setenv("HOME", home, 1) == 0);
        asf_open(&l);
        (void)json_push_kv_str(&l.in, "app", "tiny");
        (void)json_push_kv_str(&l.in, "source", w->repo);
        (void)json_push_kv_str(&l.in, "datadir", dd1);
        (void)json_push_kv_str(&l.in, "plan_id", plan);
        (void)json_push_kv_bool(&l.in, "confirm", true);
        bool confirmed = asf_pass("app.seed", &l);
        asf_close(&l);
        char keyp[ASD_PATH + 32];
        (void)snprintf(keyp, sizeof(keyp), "%s/zcode_publisher.key", dot);
        bool mode_ok = stat(keyp, &st) == 0 && (st.st_mode & 0777) == 0600;
        bool d1 = asd_key_digest(home, first);
        bool seeded = asf_seed(&l, "tiny", w->repo, dd2);
        asf_close(&l);
        bool d2 = asd_key_digest(home, again);
        ASSERT(setenv("HOME", w->home1, 1) == 0);
        ASSERT(confirmed && mode_ok && d1 && seeded && d2);
        ASSERT(memcmp(first, again, sizeof(first)) == 0);
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
        ASSERT(asd_export_saved(w, copy, &l));
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
    TEST("app.seed: a collision, a missing Makefile, one without package "
         "targets, an undelivered input and an unknown app are refused") {
        ASSERT(asd_refused(w, "collide", "SEED_COLLISION"));
        ASSERT(asd_refused(w, "nomk", "NO_PACKAGE_ENTRYPOINT"));
        ASSERT(asd_refused(w, "notargets", "NO_PACKAGE_TARGETS"));
        ASSERT(asd_refused(w, "absentinput", "NO_PACKAGE_TARGETS"));
        ASSERT(asd_refused(w, "nosuchapp", "APP_UNKNOWN"));
        ASSERT(asd_refused(w, "../tiny", "BAD_APP"));
        struct app_seed_stage ws;
        char wdest[512];
        snprintf(wdest, sizeof(wdest), "%s/webapp-stage", w->datadir1);
        ASSERT(mkdir(wdest, 0700) == 0);
        ASSERT(!app_seed_stage(w->repo, "blog", wdest, &ws));
        ASSERT_STR_EQ(ws.code, "APP_UNKNOWN");
        ASSERT(strstr(ws.why, "web app your node serves at /blog") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

#if defined(ZCL_TESTING) && !defined(_WIN32)
enum asd_progress_case { ASD_PROGRESS_NORMAL, ASD_PROGRESS_CLOSE, ASD_PROGRESS_UI_FAIL, ASD_PROGRESS_PARTIAL,
    ASD_PROGRESS_ALLOC, ASD_PROGRESS_MAIN_ALLOC, ASD_PROGRESS_START, ASD_PROGRESS_PREPARE };
struct asd_progress_fixture {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool entered, released, finished, observed, waited;
    unsigned calls;
    enum asd_progress_case mode;
};
/* real-clock: condition deadline contains a native worker lifecycle fixture;
 * no sleep constitutes acceptance, and every path releases the worker. */
static bool asd_progress_wait(struct asd_progress_fixture *f, const bool *flag)
{
    struct timespec end;
    if (clock_gettime(CLOCK_REALTIME, &end) != 0) return false;
    end.tv_sec += 5;
    while (!*flag) {
        int rc = pthread_cond_timedwait(&f->cond, &f->mutex, &end);
        if (rc != 0) return false;
    }
    return true;
}
static void asd_progress_worker(void *context, const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    struct asd_progress_fixture *f = context;
    pthread_mutex_lock(&f->mutex);
    ++f->calls; f->entered = true; pthread_cond_broadcast(&f->cond);
    f->waited = asd_progress_wait(f, &f->released);
    pthread_mutex_unlock(&f->mutex);
    void *allocation = zcl_calloc(1, 1, "installed-copy-fixture");
    free(allocation); /* Deliberately leave PASSED: worker counter must catch failure. */
    if (!json_push_kv_str(&reply->data, "copy", "/fixture/saved-copy") ||
        !json_push_kv_str(&reply->data, "version", zcl_package_copy_str(request->input, "version")))
        zcl_package_copy_fail(reply, "OUT_OF_MEMORY", true, "fixture receipt allocation", "progress fixture");
    reply->error.mutated = true;
    if (f->mode == ASD_PROGRESS_PARTIAL)
        zcl_package_copy_fail(reply, "FIXTURE_PARTIAL", true, "saved before controlled failure", "progress fixture");
    pthread_mutex_lock(&f->mutex); f->finished = true;
    pthread_cond_broadcast(&f->cond); pthread_mutex_unlock(&f->mutex);
}
static size_t asd_progress_pixels(const struct zcl_present_window_v1 *page)
{
    /* Bounded before multiplication: maximum 12 MiB RGB8 fixture raster. */
    if (!page->pixels || page->pixel_format != ZCL_PRESENT_RGB8 ||
        !page->width || !page->height || page->width > 2048 || page->height > 2048) return 0;
    return (size_t)page->width * (size_t)page->height * 3u;
}
static bool asd_progress_close_pixels(const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live)
{
    const struct zcl_present_window_v1 *page = &pages->pages[0];
    size_t size = asd_progress_pixels(page);
    void *before = size ? zcl_malloc(size, "installed-copy/pixel-fixture") : NULL;
    if (!before) return false;
    memcpy(before, page->pixels, size);
    uint32_t width = page->width, height = page->height;
    bool redraw = false, close = true;
    live->owner.update(live->owner.context, NULL, true, &redraw, &close);
    bool ok = !close && redraw && page->width == width && page->height == height &&
        asd_progress_pixels(page) == size && memcmp(before, page->pixels, size) != 0 &&
        !strcmp(model->summary, "Finishing your copy");
    free(before);
    return ok;
}
static bool asd_progress_completed(struct asd_progress_fixture *f,
    const struct zcl_present_window_live_view_v1 *live)
{
    pthread_mutex_lock(&f->mutex);
    bool finished = asd_progress_wait(f, &f->finished);
    pthread_mutex_unlock(&f->mutex);
    if (!finished) return false;
    int64_t end = platform_time_monotonic_ms() + 5000;
    bool redraw = false, close = false;
    do {
        live->owner.update(live->owner.context, NULL, false, &redraw, &close);
        if (close) return !redraw;
        platform_sleep_ms(1); /* real-clock: poll native worker's release/acquire completion */
    } while (platform_time_monotonic_ms() < end);
    return false;
}
static bool asd_progress_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    (void)why; (void)cap;
    struct asd_progress_fixture *f = context;
    pthread_mutex_lock(&f->mutex);
    bool entered = asd_progress_wait(f, &f->entered);
    pthread_mutex_unlock(&f->mutex);
    bool ok = entered && !strcmp(model->title, "Making your copy") && pages->page_count == 1;
    if (f->mode != ASD_PROGRESS_UI_FAIL && f->mode != ASD_PROGRESS_NORMAL)
        ok = ok && asd_progress_close_pixels(model, pages, live);
    pthread_mutex_lock(&f->mutex);
    f->observed = ok; f->released = true; pthread_cond_broadcast(&f->cond);
    pthread_mutex_unlock(&f->mutex);
    if (f->mode == ASD_PROGRESS_NORMAL) ok = ok && asd_progress_completed(f, live);
    /* Return immediately, including failure: production must still join.
     * This is lifecycle coverage, not a real-window or owner-consent proof. */
    return ok && f->mode != ASD_PROGRESS_UI_FAIL;
}
static bool asd_progress_saved(const struct asd_progress_fixture *f, const struct asf_leaf *leaf)
{
    return !strcmp(asf_get(leaf, "copy"), "/fixture/saved-copy") &&
        !strcmp(asf_get(leaf, "version"), "fixture-version") && leaf->out.error.mutated &&
        f->calls == 1 && f->finished && f->waited && f->observed;
}
static bool asd_progress_normal(const struct asd_progress_fixture *f,
    const struct asf_leaf *leaf, bool offer)
{
    return offer && asd_progress_saved(f, leaf) && leaf->out.status == ZCL_COMMAND_STATUS_PASSED &&
        !json_get(&leaf->out.data, "continuation");
}
static bool asd_progress_result(const struct asd_progress_fixture *f,
    const struct asf_leaf *leaf, bool offer)
{
    if (f->mode == ASD_PROGRESS_NORMAL)
        return asd_progress_normal(f, leaf, offer);
    if (offer) return false;
    if (f->mode == ASD_PROGRESS_START || f->mode == ASD_PROGRESS_PREPARE)
        return f->calls == 0 && !leaf->out.error.mutated &&
            leaf->out.status != ZCL_COMMAND_STATUS_PASSED && !json_get(&leaf->out.data, "copy");
    if (!asd_progress_saved(f, leaf)) return false;
    if (f->mode == ASD_PROGRESS_PARTIAL) return asf_refusal(leaf, "FIXTURE_PARTIAL");
    if (f->mode == ASD_PROGRESS_ALLOC) return asf_refusal(leaf, "OUT_OF_MEMORY");
    return leaf->out.status == ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(asf_get(leaf, "continuation"), "adopted") &&
        !asf_flag(leaf, "continuation_executed") &&
        asf_flag(leaf, "copy_progress_ui_failed") == (f->mode == ASD_PROGRESS_UI_FAIL);
}
static bool asd_progress_main_fault(void)
{
    uint64_t before = zcl_alloc_failure_count();
    zcl_alloc_fault_fail_next("installed-copy/main-fixture");
    void *allocation = zcl_calloc(1, 1, "installed-copy/main-fixture");
    bool ok = !allocation && zcl_alloc_failure_count() == before + 1;
    free(allocation);
    zcl_alloc_fault_clear();
    return ok;
}
static bool asd_progress_case(enum asd_progress_case mode)
{
    struct asd_progress_fixture f = {.mode = mode};
    if (pthread_mutex_init(&f.mutex, NULL) != 0) return false;
    if (pthread_cond_init(&f.cond, NULL) != 0) { pthread_mutex_destroy(&f.mutex); return false; }
    struct asf_leaf leaf; asf_open(&leaf);
    bool ok = json_push_kv_str(&leaf.in, "version", "fixture-version");
    struct zcl_command_request request = {.input = &leaf.in};
    const struct app_installed_copy_test_hooks hooks = {
        .commit = asd_progress_worker, .context = &f,
        .worker_alloc_label = mode == ASD_PROGRESS_ALLOC ? "installed-copy-fixture" : NULL,
        .refuse_start = mode == ASD_PROGRESS_START,
    };
    if (mode == ASD_PROGRESS_PREPARE) zcl_alloc_fault_fail_next("installed-copy/progress");
    if (mode == ASD_PROGRESS_MAIN_ALLOC) ok = ok && asd_progress_main_fault();
    bool offer = ok && zcl_test_app_installed_copy_progress(&request, &leaf.out,
        asd_progress_present, &f, &hooks);
    zcl_alloc_fault_clear();
    ok = ok && asd_progress_result(&f, &leaf, offer);
    asf_close(&leaf);
    if (pthread_cond_destroy(&f.cond) != 0) ok = false;
    if (pthread_mutex_destroy(&f.mutex) != 0) ok = false;
    return ok;
}
static int asd_progress_cases(void)
{
    int failures = 0;
    TEST("installed copy progress: close, UI failure, partial receipt, worker TLS and prestart failures") {
        for (int i = ASD_PROGRESS_NORMAL; i <= ASD_PROGRESS_PREPARE; ++i)
            ASSERT(asd_progress_case((enum asd_progress_case)i));
        PASS();
    } _test_next:;
    return failures;
}
#endif
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
#if defined(ZCL_TESTING) && !defined(_WIN32)
    if (!failures) failures += asd_progress_cases();
#endif
    if (!failures)
        failures += asd_staging_deterministic(&w);
    if (!failures)
        failures += asd_seeds_and_reseeds(&w);
    if (!failures)
        failures += asd_second_owner(&w);
    if (!failures)
        failures += asd_plan_writes_nothing(&w);
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
