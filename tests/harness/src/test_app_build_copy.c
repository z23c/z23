/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.build on a personal copy, end to end on local fixtures. A
 * tiny stub app package (one C file, one header, a make fragment that
 * counts its own runs) is published, adopted, built, edited, saved,
 * rebuilt, shared by file and built again by a friend. Asserted:
 *   - MCP runs app.build plan-first (not owner authority);
 *   - a plain fork that was never adopted is refused NOT_ADOPTED;
 *   - a caller's wrong dependency root is refused DEPENDENCY_MISMATCH;
 *   - a saved edit gives a new image_sha3 and a new zcl.app_build.v1 record;
 *   - the friend's received, owner-trusted copy builds the same image, and
 *     the same copy without its trust record is refused NOT_ADOPTED;
 *   - restoring v1 is a cache_hit at plan and confirm, and make never ran
 *     (the make fragment's run counter is unchanged);
 *   - a dirty tree is refused UNSAVED_CHANGES;
 *   - an explicit saved version builds exact CAS source despite poisoned live
 *     recipe/metadata/source, preserving HEAD, history and dirty bytes;
 *   - a build that reads an input its declared closure omits is refused
 *     CLOSURE_DRIFT, a compile error is BUILD_FAILED with a bounded tail;
 *   - where Landlock confines the build, a make fragment that writes outside
 *     the copy and build directories fails; elsewhere skipped with a reason.
 * Leaves run as the CLI and MCP run them: input contract, handler, budget. */

#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/app_image.h"
#include "command/app_build_make.h"
#include "command/app_toolchain.h"
#include "command/lab_exec.h"
#include "command/native_command.h"
#include "command/native_zcode_package_bundle.h"
#include "command/native_zcode_package_copy.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "mcp/mcp_policy.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "sha3/sha3.h"
#include "util/spawn.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include "vcs/vcs.h"

#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define ABC_DAY 20400
#define ABC_PATH 900

struct abc_world {
    char root[512];
    char src[600];
    char alice_home[600], alice_datadir[600];
    char bob_home[600], bob_datadir[600], bob_copy[600];
    char share_file[700];
    char copy[ABC_PATH];
    char origin_release[65];
    char v1[65], v2[65];
    char image_v1[65], image_v2[65];
    char build_dir[ABC_PATH];
    char saved_home[1024];
};

struct abc_leaf {
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply out;
};

static void abc_open(struct abc_leaf *l)
{
    memset(l, 0, sizeof(*l));
    json_init(&l->in);
    json_set_object(&l->in);
    zcl_command_reply_init(&l->out, "zcl.test.app_build_copy.v1");
}

static void abc_close(struct abc_leaf *l)
{
    zcl_command_reply_free(&l->out);
    json_free(&l->in);
}

static const struct zcl_command_spec *abc_spec(const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t i = 0; reg && i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

/* The registry contract, then the handler; the reply must fit the budget. */
static bool abc_exec(const char *path, struct abc_leaf *l)
{
    char why[256] = "no such leaf";
    const struct zcl_command_spec *spec = abc_spec(path);
    if (!spec || !spec->handler ||
        !zcl_command_registry_input_validate(spec, &l->in, why, sizeof(why))) {
        printf("  [%s not runnable: %s]\n", path, why);
        return false;
    }
    l->req.spec = spec;
    l->req.input = &l->in;
    l->req.invoked_name = spec->path;
    spec->handler(&l->req, &l->out);
    size_t bytes = json_write(&l->out.data, NULL, 0) + 1024u;
    if (spec->budget_bytes && bytes > (size_t)spec->budget_bytes) {
        printf("  [%s reply %zu bytes over its budget]\n", path, bytes);
        return false;
    }
    return true;
}

static bool abc_pass(const char *path, struct abc_leaf *l)
{
    if (!abc_exec(path, l))
        return false;
    if (l->out.status != ZCL_COMMAND_STATUS_PASSED)
        printf("  [%s refused %s: %s]\n", path, l->out.error.code,
               l->out.error.message);
    return l->out.status == ZCL_COMMAND_STATUS_PASSED;
}

static bool abc_refusal(const struct abc_leaf *l, const char *code)
{
    if (l->out.status != ZCL_COMMAND_STATUS_PASSED &&
        strcmp(l->out.error.code, code) == 0)
        return true;
    printf("  [expected %s; status=%d code=%s: %s]\n", code,
           (int)l->out.status, l->out.error.code, l->out.error.message);
    return false;
}

static const char *abc_get(const struct abc_leaf *l, const char *key)
{
    const char *s = json_get_str(json_get(&l->out.data, key));
    return s ? s : "";
}

static bool abc_flag(const struct abc_leaf *l, const char *key)
{
    const struct json_value *v = json_get(&l->out.data, key);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

/* Repeat the leaf with the returned plan_id and confirm:true. */
static bool abc_confirm(const char *path, struct abc_leaf *l)
{
    char plan[65];
    if (strlen(abc_get(l, "plan_id")) != 64)
        return false;
    (void)snprintf(plan, sizeof(plan), "%s", abc_get(l, "plan_id"));
    zcl_command_reply_free(&l->out);
    zcl_command_reply_init(&l->out, "zcl.test.app_build_copy.v1");
    (void)json_push_kv_str(&l->in, "plan_id", plan);
    (void)json_push_kv_bool(&l->in, "confirm", true);
    return abc_exec(path, l);
}

static bool abc_plan_confirm(const char *path, struct abc_leaf *l)
{
    bool ok = abc_pass(path, l) && abc_confirm(path, l);
    if (ok && l->out.status != ZCL_COMMAND_STATUS_PASSED)
        printf("  [%s confirm refused %s: %s]\n", path, l->out.error.code,
               l->out.error.message);
    return ok && l->out.status == ZCL_COMMAND_STATUS_PASSED;
}

static bool abc_put(const char *dir, const char *rel, const char *text)
{
    char path[ABC_PATH];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "wb");
    bool ok = f && fputs(text, f) >= 0;
    return f ? fclose(f) == 0 && ok : false;
}

static bool abc_as(const char *home)
{
    return setenv("HOME", home, 1) == 0;
}

/* The make fragment of the stub app: it declares its closure, counts its
 * own runs one directory above APP_OUT (inside the copy's build directory)
 * and builds out of tree with -MD. */
static const char k_makefile[] =
    "APP_CFLAGS = -std=c2x -O2 -Iinclude\n"
    ".PHONY: app print-app-closure\n"
    "print-app-closure:\n"
    "\t@printf '%s\\n' Makefile include/boost.h src/main.c\n"
    "app:\n"
    "\t@echo run >> $(APP_OUT)/../make-runs\n"
    "\tcc $(APP_CFLAGS) -MD -MF $(APP_OUT)/main.d -c src/main.c "
    "-o $(APP_OUT)/main.o\n"
    "\tcc -o $(APP_OUT)/app $(APP_OUT)/main.o\n";

static const char k_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"stub/tinyapp\",\n"
    "  \"semver\": \"0.1.0\",\n  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n";

/* The same stub published under the skycombat release name, so the build
 * reaches the compiled-in skycombat preview row. */
static const char k_sky_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"skycombat/skycombat\",\n"
    "  \"semver\": \"0.1.0\",\n  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n";
static const char *abc_stub_meta = k_meta;

static const char k_alice_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"alice/tinyapp\",\n"
    "  \"semver\": \"0.2.0\",\n  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n";

static const char k_main[] =
    "#include \"boost.h\"\nint main(void) { return BOOST - 1; }\n";

/* The stub carries the same Apache-2.0 text the skycombat package does. */
static bool abc_license(const char *dir)
{
    char text[4096];
    FILE *f = fopen("apps/skycombat/LICENSE", "rb");
    if (!f)
        return false;
    size_t n = fread(text, 1, sizeof(text) - 1u, f);
    (void)fclose(f);
    text[n] = '\0';
    return n > 0 && abc_put(dir, "LICENSE", text);
}

static bool abc_stub_source(struct abc_world *w)
{
    char dir[ABC_PATH];
    bool ok = mkdir(w->src, 0700) == 0 && abc_license(w->src);
    (void)snprintf(dir, sizeof(dir), "%s/include", w->src);
    ok = ok && mkdir(dir, 0700) == 0;
    (void)snprintf(dir, sizeof(dir), "%s/src", w->src);
    ok = ok && mkdir(dir, 0700) == 0;
    return ok && abc_put(w->src, "zcode-package.json", abc_stub_meta) &&
           abc_put(w->src, "Makefile", k_makefile) &&
           abc_put(w->src, "include/boost.h", "#define BOOST 1\n") &&
           abc_put(w->src, "src/main.c", k_main);
}

/* The original publisher signs the stub with its own release key. */
static bool abc_publish_origin(struct abc_world *w)
{
    char key[700], pubhex[PLUGIN_HEX_PUBLIC_KEY + 1];
    struct plugin_dist_published why;
    struct vcs_package_prepare_options o = {
        .dir = w->src, .publisher_sequence = 1, .reward_address = "",
        .chain_id = "zclassic-main",
    };
    struct vcs_package_prepared p;
    char detail[256] = {0};
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    (void)snprintf(key, sizeof(key), "%s/origin.key", w->root);
    if (plugin_keygen(key, pubhex) != PLUGIN_OK ||
        plugin_dist_release_key_sign(key, NULL, o.publisher_pubkey, NULL,
                                     &why) != PLUGIN_DIST_OK ||
        vcs_package_prepare(&o, &p, detail, sizeof(detail)) !=
            VCS_PACKAGE_PREPARE_OK) {
        printf("  [stub publish setup: %s]\n", detail);
        return false;
    }
    bool ok = plugin_dist_release_key_sign(key, p.signing_digest,
                                           o.publisher_pubkey,
                                           p.release.signature,
                                           &why) == PLUGIN_DIST_OK &&
              vcs_package_release_serialize(&p.release, &wire, &wire_len) ==
                  VCS_PACKAGE_RELEASE_OK;
    struct zcl_command_reply r;
    zcl_command_reply_init(&r, "zcl.test.app_build_copy.v1");
    const struct zcl_native_local_publication pub = {
        .datadir = w->alice_datadir, .source_directory = w->src,
        .release_wire = wire, .release_wire_len = wire_len,
        .manifest_wire = p.manifest_wire,
        .manifest_wire_len = p.manifest_wire_len,
        .recipe_wire = p.recipe_wire, .recipe_wire_len = p.recipe_wire_len,
        .has_day = true, .day = ABC_DAY,
    };
    if (ok)
        zcl_native_zcode_local_publication_commit(&pub, &r);
    ok = ok && r.status == ZCL_COMMAND_STATUS_PASSED;
    if (!ok)
        printf("  [stub publish: %s %s]\n", r.error.code, r.error.message);
    zcl_hex_encode(p.signing_digest, 32, w->origin_release);
    zcl_command_reply_free(&r);
    free(wire);
    vcs_package_prepared_free(&p);
    return ok;
}

static bool abc_adopt(struct abc_world *w)
{
    struct abc_leaf l;
    abc_open(&l);
    (void)json_push_kv_str(&l.in, "root", w->origin_release);
    (void)json_push_kv_str(&l.in, "datadir", w->alice_datadir);
    bool ok = abc_plan_confirm("zcode.package.adopt", &l);
    (void)snprintf(w->copy, sizeof(w->copy), "%s", abc_get(&l, "copy"));
    abc_close(&l);
    return ok && w->copy[0] == '/';
}

static bool abc_world_init_named(struct abc_world *w, const char *alice)
{
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    if (!test_mkdtemp(w->root, sizeof(w->root), "app_build_copy"))
        return false;
    (void)snprintf(w->src, sizeof(w->src), "%s/stub-src", w->root);
    (void)snprintf(w->alice_home, sizeof(w->alice_home), "%s/%s", w->root, alice);
    (void)snprintf(w->alice_datadir, sizeof(w->alice_datadir),
                   "%s/%s/datadir", w->root, alice);
    (void)snprintf(w->bob_home, sizeof(w->bob_home), "%s/bob", w->root);
    (void)snprintf(w->bob_datadir, sizeof(w->bob_datadir), "%s/bob/datadir",
                   w->root);
    (void)snprintf(w->bob_copy, sizeof(w->bob_copy), "%s/bob/tinyapp-from-alice",
                   w->root);
    (void)snprintf(w->share_file, sizeof(w->share_file),
                   "%s/%s/tinyapp.z23share", w->root, alice);
    return abc_stub_source(w) && mkdir(w->alice_home, 0700) == 0 &&
           mkdir(w->alice_datadir, 0700) == 0 &&
           mkdir(w->bob_home, 0700) == 0 && abc_as(w->alice_home) &&
           abc_publish_origin(w) && abc_adopt(w);
}

static bool abc_world_init(struct abc_world *w)
{
    return abc_world_init_named(w, "alice");
}

/* ── app.build helpers ──────────────────────────────────────────────── */

static void abc_build_input(struct abc_leaf *l, const char *copy,
                            const char *datadir)
{
    abc_open(l);
    (void)json_push_kv_str(&l->in, "copy", copy);
    (void)json_push_kv_str(&l->in, "datadir", datadir);
}

/* Plan and confirm one build; the confirm reply stays in `l` for reading. */
static bool abc_build(struct abc_leaf *l, const char *copy,
                      const char *datadir)
{
    abc_build_input(l, copy, datadir);
    bool ok = abc_plan_confirm("app.build", l);
    if (!ok && l->out.status != ZCL_COMMAND_STATUS_PASSED)
        printf("  [app.build refused %s: %s]\n", l->out.error.code,
               l->out.error.message);
    return ok;
}

/* The make fragment's run count in the copy's build directory. */
static int abc_make_runs(const char *build_dir)
{
    char path[ABC_PATH + 16], line[16];
    int runs = 0;
    (void)snprintf(path, sizeof(path), "%s/make-runs", build_dir);
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f))
        runs++;
    (void)fclose(f);
    return runs;
}

static bool abc_save(const char *dir, char version[65])
{
    struct abc_leaf l;
    abc_open(&l);
    (void)json_push_kv_str(&l.in, "dir", dir);
    bool ok = abc_plan_confirm("zcode.package.version.save", &l);
    if (ok && version)
        (void)snprintf(version, 65, "%s", abc_get(&l, "version"));
    abc_close(&l);
    return ok;
}

static bool abc_restore(const char *dir, const char *version)
{
    struct abc_leaf l;
    abc_open(&l);
    (void)json_push_kv_str(&l.in, "dir", dir);
    (void)json_push_kv_str(&l.in, "version", version);
    bool ok = abc_plan_confirm("zcode.package.version.restore", &l);
    abc_close(&l);
    return ok;
}

/* The build record on disk for the reply's roots decodes to the reply. */
static bool abc_record_matches(const struct abc_leaf *l, const char *datadir)
{
    uint8_t package[32], env[32], deps[32], image[32];
    char store[ABC_PATH];
    struct app_image_build rec;
    bool hit = false;
    (void)snprintf(store, sizeof(store), "%s", abc_get(l, "record_store"));
    return zcl_hex_decode(abc_get(l, "package_root"), package, 32) &&
           zcl_hex_decode(abc_get(l, "env_root"), env, 32) &&
           zcl_hex_decode(abc_get(l, "dependency_root"), deps, 32) &&
           zcl_hex_decode(abc_get(l, "image_sha3"), image, 32) &&
           strncmp(store, datadir, strlen(datadir)) == 0 &&
           app_image_build_load(store, package, env, deps, &rec, &hit).ok &&
           hit && memcmp(rec.image_sha3, image, 32) == 0;
}

/* ── cases ──────────────────────────────────────────────────────────── */

static int abc_mcp_plan_first(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: MCP runs it plan-first and it is not owner authority") {
        const struct zcl_command_spec *spec = abc_spec("app.build");
        struct mcp_refusal why = {0};
        struct json_value in;
        ASSERT(spec && spec->confirmation == ZCL_COMMAND_CONFIRM_PLAN_COMMIT);
        ASSERT(spec->authority != ZCL_COMMAND_AUTH_OWNER);
        json_init(&in);
        json_set_object(&in);
        (void)json_push_kv_str(&in, "copy", w->copy);
        ASSERT(mcp_policy_allows(spec, zcl_command_catalog(), &in, &why));
        (void)json_push_kv_bool(&in, "confirm", true);
        bool refused = !mcp_policy_allows(spec, zcl_command_catalog(), &in,
                                          &why);
        ASSERT(refused && why.code &&
               strcmp(why.code, "PLAN_ID_REQUIRED") == 0);
        (void)json_push_kv_str(&in, "plan_id", w->origin_release);
        ASSERT(mcp_policy_allows(spec, zcl_command_catalog(), &in, &why));
        json_free(&in);
        PASS();
    } _test_next:;
    return failures;
}

static int abc_refuses_unadopted(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: a plain fork that was never adopted is refused") {
        struct abc_leaf l;
        char plain[ABC_PATH];
        struct stat st;
        (void)snprintf(plain, sizeof(plain), "%s/plain-fork", w->root);
        abc_open(&l);
        (void)json_push_kv_str(&l.in, "root", w->origin_release);
        (void)json_push_kv_str(&l.in, "destination", plain);
        (void)json_push_kv_str(&l.in, "datadir", w->alice_datadir);
        ASSERT(abc_plan_confirm("zcode.package.fork", &l));
        char plain_version[65];
        (void)snprintf(plain_version, sizeof(plain_version), "%s", abc_get(&l, "version"));
        abc_close(&l);
        abc_build_input(&l, plain, w->alice_datadir);
        ASSERT(abc_exec("app.build", &l));
        ASSERT(abc_refusal(&l, "NOT_ADOPTED"));
        abc_close(&l);
        abc_build_input(&l, plain, w->alice_datadir);
        (void)json_push_kv_str(&l.in, "version", plain_version);
        ASSERT(abc_exec("app.build", &l));
        ASSERT(abc_refusal(&l, "NOT_ADOPTED"));
        abc_close(&l);
        char images[ABC_PATH + 32];
        (void)snprintf(images, sizeof(images), "%s/app_build",
                       w->alice_datadir);
        ASSERT(stat(images, &st) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int abc_refuses_wrong_deps(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: a dependency root other than the declared set is "
         "refused before anything builds") {
        struct abc_leaf l;
        abc_build_input(&l, w->copy, w->alice_datadir);
        (void)json_push_kv_str(&l.in, "dependency_root",
            "1111111111111111111111111111111111111111111111111111111111111111");
        ASSERT(abc_exec("app.build", &l));
        ASSERT(abc_refusal(&l, "DEPENDENCY_MISMATCH"));
        abc_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

static int abc_builds_v1_then_v2(struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: v1 builds an image and a record; a saved edit builds "
         "a new image_sha3") {
        struct abc_leaf l;
        struct stat st;
        abc_build_input(&l, w->copy, w->alice_datadir);
        ASSERT(abc_pass("app.build", &l));
        ASSERT(strcmp(abc_get(&l, "stage"), "plan") == 0);
        ASSERT(!abc_flag(&l, "cache_hit"));
        ASSERT(strcmp(abc_get(&l, "authorization"), "adopted") == 0);
        ASSERT(strlen(abc_get(&l, "closure_root")) == 64);
        ASSERT(strlen(abc_get(&l, "env_root")) == 64);
        ASSERT(strlen(abc_get(&l, "dependency_root")) == 64);
        char store[ABC_PATH + 32];
        (void)snprintf(store, sizeof(store), "%s/app_build", w->alice_datadir);
        ASSERT(stat(store, &st) != 0);
        ASSERT(abc_confirm("app.build", &l));
        ASSERT(l.out.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(abc_get(&l, "stage"), "commit") == 0);
        ASSERT(!abc_flag(&l, "cache_hit") && abc_flag(&l, "make_ran"));
        ASSERT(abc_record_matches(&l, w->alice_datadir));
        (void)snprintf(w->image_v1, 65, "%s", abc_get(&l, "image_sha3"));
        (void)snprintf(w->build_dir, sizeof(w->build_dir), "%s",
                       abc_get(&l, "build_dir"));
        ASSERT(stat(abc_get(&l, "image_path"), &st) == 0 &&
               S_ISREG(st.st_mode));
        ASSERT(strstr(abc_get(&l, "image_path"), w->image_v1) != NULL);
        /* tinyapp has no preview row: no preview hint at all */
        ASSERT(!json_get(&l.out.data, "preview_argv") &&
               !json_get(&l.out.data, "preview"));
        abc_close(&l);
        ASSERT_EQ(abc_make_runs(w->build_dir), 1);

        /* The copy itself was not written: it is still clean. */
        ASSERT(abc_save(w->copy, NULL) == false);

        /* v2: a stronger boost, under Alice's own name (the stub's name is
         * bound to the original publisher's key). */
        ASSERT(abc_put(w->copy, "include/boost.h", "#define BOOST 2\n"));
        ASSERT(abc_put(w->copy, "zcode-package.json", k_alice_meta));
        ASSERT(abc_save(w->copy, w->v2));
        ASSERT(abc_build(&l, w->copy, w->alice_datadir));
        (void)snprintf(w->image_v2, 65, "%s", abc_get(&l, "image_sha3"));
        ASSERT(strlen(w->image_v2) == 64 &&
               strcmp(w->image_v1, w->image_v2) != 0);
        ASSERT(abc_record_matches(&l, w->alice_datadir));
        abc_close(&l);
        ASSERT_EQ(abc_make_runs(w->build_dir), 2);
        PASS();
    } _test_next:;
    return failures;
}

static bool abc_alice_shares(struct abc_world *w, char package[65],
                             char fingerprint[67])
{
    struct abc_leaf l;
    if (!abc_as(w->alice_home))
        return false;
    abc_open(&l);
    (void)json_push_kv_str(&l.in, "dir", w->copy);
    (void)json_push_kv_str(&l.in, "datadir", w->alice_datadir);
    (void)json_push_kv_str(&l.in, "output", w->share_file);
    (void)json_push_kv_int(&l.in, "day", ABC_DAY);
    bool ok = abc_plan_confirm("zcode.package.bundle.sign", &l);
    (void)snprintf(package, 65, "%s", abc_get(&l, "package_root"));
    (void)snprintf(fingerprint, 67, "%s", abc_get(&l, "publisher_fingerprint"));
    abc_close(&l);
    return ok && strlen(package) == 64 && strlen(fingerprint) == 66;
}

static bool abc_bob_receives(struct abc_world *w, const char *package,
                             const char *fingerprint, char trust[ABC_PATH])
{
    struct abc_leaf l;
    if (!abc_as(w->bob_home))
        return false;
    abc_open(&l);
    (void)json_push_kv_str(&l.in, "file", w->share_file);
    (void)json_push_kv_str(&l.in, "destination", w->bob_copy);
    (void)json_push_kv_str(&l.in, "datadir", w->bob_datadir);
    (void)json_push_kv_int(&l.in, "day", ABC_DAY);
    (void)json_push_kv_str(&l.in, "trust_publisher", fingerprint);
    (void)json_push_kv_str(&l.in, "trust_root", package);
    bool ok = abc_plan_confirm("zcode.package.bundle.receive", &l);
    (void)snprintf(trust, ABC_PATH, "%s", abc_get(&l, "trust_record"));
    abc_close(&l);
    return ok && trust[0] == '/';
}

static int abc_friend_builds(struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: a friend's received, owner-trusted copy builds the same "
         "image; without its trust record it is refused") {
        char package[65], fingerprint[67], trust[ABC_PATH];
        struct abc_leaf l;
        ASSERT(abc_alice_shares(w, package, fingerprint));
        ASSERT(abc_bob_receives(w, package, fingerprint, trust));
        abc_build_input(&l, w->bob_copy, w->bob_datadir);
        ASSERT(abc_pass("app.build", &l));
        ASSERT(strcmp(abc_get(&l, "authorization"), "received_trusted") == 0);
        ASSERT(abc_confirm("app.build", &l));
        ASSERT(l.out.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(abc_record_matches(&l, w->bob_datadir));
        /* Same source, same toolchain: the friend gets Alice's v2 bytes. */
        ASSERT(strcmp(abc_get(&l, "image_sha3"), w->image_v2) == 0);
        abc_close(&l);

        ASSERT(strstr(trust, ZCL_PACKAGE_RECEIVE_TRUST_DIR) != NULL);
        ASSERT(unlink(trust) == 0);
        abc_build_input(&l, w->bob_copy, w->bob_datadir);
        ASSERT(abc_exec("app.build", &l));
        ASSERT(abc_refusal(&l, "NOT_ADOPTED"));
        abc_close(&l);
        ASSERT(abc_as(w->alice_home));
        PASS();
    } _test_next:;
    return failures;
}

static int abc_restore_is_cache_hit(struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: restoring v1 is a cache_hit and make never runs") {
        struct abc_leaf l;
        char fork[65];
        abc_open(&l);
        (void)json_push_kv_str(&l.in, "dir", w->copy);
        ASSERT(abc_pass("zcode.package.version.list", &l));
        const struct json_value *rows = json_get(&l.out.data, "versions");
        size_t n = rows ? json_size(rows) : 0;
        ASSERT(n >= 2);
        const char *oldest = json_get_str(json_get(json_at(rows, n - 1u),
                                                   "version"));
        ASSERT(oldest && strlen(oldest) == 64);
        (void)snprintf(fork, sizeof(fork), "%s", oldest);
        abc_close(&l);
        ASSERT(abc_restore(w->copy, fork));

        abc_build_input(&l, w->copy, w->alice_datadir);
        ASSERT(abc_pass("app.build", &l));
        ASSERT(abc_flag(&l, "cache_hit"));
        ASSERT(abc_confirm("app.build", &l));
        ASSERT(l.out.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(abc_flag(&l, "cache_hit") && !abc_flag(&l, "make_ran"));
        ASSERT(strcmp(abc_get(&l, "image_sha3"), w->image_v1) == 0);
        abc_close(&l);
        ASSERT_EQ(abc_make_runs(w->build_dir), 2);
        PASS();
    } _test_next:;
    return failures;
}

static int abc_refuses_dirty(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: an unsaved edit is refused UNSAVED_CHANGES") {
        struct abc_leaf l;
        ASSERT(abc_put(w->copy, "src/main.c",
                       "#include \"boost.h\"\nint main(void) { return 0; }\n"));
        abc_build_input(&l, w->copy, w->alice_datadir);
        ASSERT(abc_exec("app.build", &l));
        ASSERT(abc_refusal(&l, "UNSAVED_CHANGES"));
        abc_close(&l);
        ASSERT(abc_put(w->copy, "src/main.c", k_main));
        PASS();
    } _test_next:;
    return failures;
}

/* Save `rel` as `text`, then plan and confirm a build that must fail. */
static bool abc_build_refused(const struct abc_world *w, const char *rel,
                              const char *text, const char *code,
                              struct abc_leaf *l)
{
    if (!abc_put(w->copy, rel, text) || !abc_save(w->copy, NULL))
        return false;
    abc_build_input(l, w->copy, w->alice_datadir);
    return abc_pass("app.build", l) && abc_confirm("app.build", l) &&
           abc_refusal(l, code);
}

/* Failure data is private unless explicitly admitted as failure_facts. */
static const char *abc_failure_get(const struct abc_leaf *l, const char *key)
{
    const struct json_value *facts = json_get(&l->out.data, "failure_facts");
    const char *value = json_get_str(json_get(facts, key));
    return value ? value : "";
}

static bool abc_failure_tail_bytes(const char *tail)
{
    for (const unsigned char *p = (const unsigned char *)tail; *p; ++p)
        if (*p != '\n' && *p != '\t' && (*p < 32 || *p >= 127)) return false;
    return true;
}

static bool abc_failure_tail(const struct json_value *facts, const char *marker,
                              bool truncated)
{
    const char *tail = json_get_str(json_get(facts, "log_tail"));
    const char *mode = json_get_str(json_get(facts, "confinement"));
    const struct json_value *cut = json_get(facts, "log_tail_truncated");
    if (!tail || !mode || !cut || cut->type != JSON_BOOL) return false;
    if (strlen(tail) > 768 || !strstr(tail, marker) || json_get_bool(cut) != truncated) return false;
    if (truncated && (!strstr(tail, "APP_BUILD_TAIL_END") || strstr(tail, "DISCARDED_PREFIX"))) return false;
    if (strcmp(mode, lab_sandbox_available() ? "landlock" : "unconfined")) return false;
    return abc_failure_tail_bytes(tail);
}

static bool abc_failure_envelope(const struct json_value *doc, const char *marker,
                                  bool truncated)
{
    const struct json_value *error = json_get(doc, "error");
    const struct json_value *ok = json_get(doc, "ok"), *mutated = json_get(error, "mutated");
    const char *status = json_get_str(json_get(doc, "status"));
    const char *code = json_get_str(json_get(error, "code"));
    const char *evidence = json_get_str(json_get(error, "evidence"));
    if (!ok || ok->type != JSON_BOOL || json_get_bool(ok)) return false;
    if (!mutated || mutated->type != JSON_BOOL || !json_get_bool(mutated)) return false;
    if (!status || strcmp(status, "failed") || !code || strcmp(code, "BUILD_FAILED")) return false;
    return evidence && !strcmp(evidence, "app.build") && !json_get(doc, "data") &&
        abc_failure_tail(json_get(error, "facts"), marker, truncated);
}

/* Exercise the real producer, then plant ordinary private reply data before
 * the real serializer. This must never become a blanket data export. */
static void abc_failure_private_probe(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply)
{
    zcl_native_handle_app_build(request, reply);
    if (!json_push_kv_str(&reply->data, "fixture_private", "APP_BUILD_PRIVATE_SHOULD_NOT_ESCAPE"))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "FIXTURE_FAILURE", "fixture", false, reply->error.mutated,
            "could not insert private serializer probe", "app.build");
}

static bool abc_failure_wire(const struct abc_world *w, const char *marker, bool truncated)
{
    struct abc_leaf l;
    abc_build_input(&l, w->copy, w->alice_datadir);
    bool ok = abc_pass("app.build", &l);
    char plan[65];
    const char *id = abc_get(&l, "plan_id");
    ok = ok && strlen(id) == 64;
    if (ok) memcpy(plan, id, sizeof(plan));
    ok = ok && json_push_kv_str(&l.in, "plan_id", plan) && json_push_kv_bool(&l.in, "confirm", true);
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *declared = abc_spec("app.build");
    struct zcl_command_spec spec = {0};
    if (declared) spec = *declared;
    spec.handler = abc_failure_private_probe;
    struct zcl_command_registry local = {.commands = &spec, .count = 1};
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER, .dev_build = true};
    char wire[ZCL_COMMAND_ERROR_BUDGET + 1]; enum zcl_command_exit code;
    size_t n = ok && declared ? zcl_command_registry_execute_json(&local, &spec, &ctx, &l.in,
        false, spec.path, "normal", 0, 0, NULL, wire, sizeof(wire), &code) : 0;
    struct json_value doc; json_init(&doc);
    ok = n > 0 && n <= ZCL_COMMAND_ERROR_BUDGET && code == ZCL_COMMAND_EXIT_INVALID &&
        json_read(&doc, wire, n) && abc_failure_envelope(&doc, marker, truncated) &&
        !strstr(wire, "APP_BUILD_PRIVATE_SHOULD_NOT_ESCAPE") && !strstr(wire, "fixture_private");
    printf("app.build failure wire: bytes=%zu truncated=%d valid=%d\n", n, truncated, ok);
    json_free(&doc); abc_close(&l);
    return ok;
}

static int abc_failure_serialization(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: actual compiler sentinel survives the failure envelope") {
        ASSERT(abc_put(w->copy, "Makefile", k_makefile));
        ASSERT(abc_put(w->copy, "src/main.c", "#error APP_BUILD_WIRE_SENTINEL\n"));
        ASSERT(abc_save(w->copy, NULL));
        ASSERT(abc_failure_wire(w, "APP_BUILD_WIRE_SENTINEL", false));
        PASS();
    } _test_next:;
    return failures;
}

static int abc_failure_escaped(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: long escaped build output stays valid bounded JSON with explicit truncation") {
        const char recipe[] =
            ".PHONY: app print-app-closure\nprint-app-closure:\n"
            "\t@printf '%s\\n' Makefile include/boost.h src/main.c\napp:\n"
            "\t@exec 1>&2; printf 'DISCARDED_PREFIX\\n'; i=0; while [ $$i -lt 600 ]; do "
            "printf '\"\\\\\\t\\001\\377'; i=$$((i+1)); done; "
            "printf '\\nAPP_BUILD_TAIL_END\\n'; exit 2\n";
        ASSERT(abc_put(w->copy, "Makefile", recipe));
        ASSERT(abc_save(w->copy, NULL));
        /* Quotes, literal backslashes and tabs survive; hostile bytes become '?'. */
        ASSERT(abc_failure_wire(w, "\"\\\t??", true));
        PASS();
    } _test_next:;
    return failures;
}

static int abc_refuses_bad_builds(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: an undeclared input is CLOSURE_DRIFT; a compile error "
         "is BUILD_FAILED with a bounded log tail") {
        struct abc_leaf l;
        ASSERT(abc_put(w->copy, "include/extra.h", "#define EXTRA 0\n"));
        ASSERT(abc_build_refused(w, "src/main.c",
            "#include \"boost.h\"\n#include \"extra.h\"\n"
            "int main(void) { return EXTRA; }\n", "CLOSURE_DRIFT", &l));
        abc_close(&l);
        ASSERT(abc_build_refused(w, "src/main.c",
                                 "int main(void) { return }\n",
                                 "BUILD_FAILED", &l));
        const char *tail = abc_failure_get(&l, "log_tail");
        ASSERT(strstr(tail, "error") != NULL);
        ASSERT(strlen(tail) <= 2048u);
        abc_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

static int abc_landlock_contains(const struct abc_world *w)
{
    int failures = 0;
    if (!lab_sandbox_available()) {
        printf("app.build: Landlock containment... SKIP (this host cannot "
               "apply Landlock and seccomp to a child; builds run unconfined "
               "and say so)\n");
        return 0;
    }
    TEST("app.build: under Landlock a make fragment that writes outside the "
         "copy and build directories fails") {
        struct abc_leaf l;
        char escape[ABC_PATH], makefile[ABC_PATH * 2];
        struct stat st;
        (void)snprintf(escape, sizeof(escape), "%s/escaped", w->root);
        (void)snprintf(makefile, sizeof(makefile),
                       ".PHONY: app print-app-closure\n"
                       "print-app-closure:\n"
                       "\t@printf '%%s\\n' Makefile src/main.c\n"
                       "app:\n"
                       "\techo out > %s\n"
                       "\tcc -MD -MF $(APP_OUT)/main.d -c src/main.c "
                       "-o $(APP_OUT)/main.o\n"
                       "\tcc -o $(APP_OUT)/app $(APP_OUT)/main.o\n",
                       escape);
        ASSERT(abc_put(w->copy, "src/main.c", "int main(void) { return 0; }\n"));
        ASSERT(abc_build_refused(w, "Makefile", makefile, "BUILD_FAILED", &l));
        ASSERT(strcmp(abc_failure_get(&l, "confinement"), "landlock") == 0);
        ASSERT(strstr(abc_failure_get(&l, "log_tail"), "denied") != NULL);
        abc_close(&l);
        ASSERT(stat(escape, &st) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static bool abc_dep_verdict(const struct app_build_make *make, const char *out,
    const struct app_build_closure *closure, const char *token, bool expected)
{
    char wire[2048], why[320];
    int n = snprintf(wire, sizeof(wire), "main.o: %s\n", token);
    if (n <= 0 || (size_t)n >= sizeof(wire) || !abc_put(out, "main.d", wire))
        return false;
    return app_build_depfiles_declared(make, out, closure, why, sizeof(why)) == expected;
}

static int abc_dep_alias_controls(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: depfile aliases stay inside declared source; escapes refuse") {
        char copy[ABC_PATH], include[ABC_PATH], out[ABC_PATH];
        char outside[ABC_PATH], link[ABC_PATH], absolute[2048];
        (void)snprintf(copy, sizeof(copy), "%s/dep-copy", w->root);
        (void)snprintf(include, sizeof(include), "%s/dep-copy/include", w->root);
        (void)snprintf(out, sizeof(out), "%s/dep-out", w->root);
        (void)snprintf(outside, sizeof(outside), "%s/outside.h", w->root);
        (void)snprintf(link, sizeof(link), "%s/dep-copy/include/link.h", w->root);
        ASSERT(mkdir(copy, 0700) == 0);
        ASSERT(mkdir(include, 0700) == 0);
        ASSERT(mkdir(out, 0700) == 0);
        ASSERT(abc_put(copy, "include/boost.h", "#define BOOST 2\n"));
        ASSERT(abc_put(copy, "include/extra.h", "#define EXTRA 1\n"));
        ASSERT(abc_put(w->root, "outside.h", "#define OUTSIDE 1\n"));
        ASSERT(symlink(outside, link) == 0);
        char *paths[] = {"include/boost.h", "include/link.h"};
        const struct app_build_closure closure = {.paths = paths, .count = 2};
        const struct app_build_make make = {.copy_dir = copy, .work_dir = out};
        ASSERT(abc_dep_verdict(&make, out, &closure, "include/boost.h", true));
        ASSERT(abc_dep_verdict(&make, out, &closure, "./include/../include/boost.h", true));
        (void)snprintf(absolute, sizeof(absolute), "%s/include/../include/boost.h", copy);
        ASSERT(abc_dep_verdict(&make, out, &closure, absolute, true));
        (void)snprintf(absolute, sizeof(absolute), "%s/./dep-copy/include/boost.h", w->root);
        ASSERT(abc_dep_verdict(&make, out, &closure, absolute, true));
        (void)snprintf(absolute, sizeof(absolute), "%s/./dep-copy/include/extra.h", w->root);
        ASSERT(abc_dep_verdict(&make, out, &closure, absolute, false));
        struct vcs_entry compiler = {.path = "rootfs/usr/include/kit.h"};
        struct app_toolchain kit = {.selected = true,
            .manifest = {.entries = &compiler, .count = 1}};
        struct app_build_make sealed = make; sealed.kit = &kit;
        ASSERT(abc_dep_verdict(&sealed, out, &closure, "/source/include/boost.h", true));
        ASSERT(abc_dep_verdict(&sealed, out, &closure, "/source/include/extra.h", false));
        ASSERT(abc_dep_verdict(&sealed, out, &closure, "/source/include/link.h", false));
        ASSERT(abc_dep_verdict(&sealed, out, &closure, "/source/../usr/include/kit.h", false));
        ASSERT(abc_dep_verdict(&sealed, out, &closure, "/usr/include/kit.h", true));
        ASSERT(abc_dep_verdict(&sealed, out, &closure, "/usr/bin/../include/kit.h", true));
        ASSERT(abc_dep_verdict(&sealed, out, &closure, "/usr/include/stdio.h", false));
        ASSERT(abc_dep_verdict(&sealed, out, &closure, outside, false));
        (void)snprintf(absolute, sizeof(absolute), "%s/./dep-copy/../outside.h", w->root);
        ASSERT(abc_dep_verdict(&make, out, &closure, absolute, false));
        ASSERT(abc_dep_verdict(&make, out, &closure, "include/../include/extra.h", false));
        ASSERT(abc_dep_verdict(&make, out, &closure, "../outside.h", false));
        (void)snprintf(absolute, sizeof(absolute), "%s/../outside.h", copy);
        ASSERT(abc_dep_verdict(&make, out, &closure, absolute, false));
        ASSERT(abc_dep_verdict(&make, out, &closure, "include/link.h", false));
        /* Existing external-absolute policy is a separate unresolved gap. */
        ASSERT(abc_dep_verdict(&make, out, &closure, outside, true));
        (void)snprintf(absolute, sizeof(absolute), "%s/external-link.h", w->root);
        ASSERT(symlink(outside, absolute) == 0);
        ASSERT(abc_dep_verdict(&make, out, &closure, absolute, true));
        ASSERT(unlink(absolute) == 0);
        (void)snprintf(link, sizeof(link), "%s/include/extra.h", copy);
        ASSERT(symlink(link, absolute) == 0);
        ASSERT(abc_dep_verdict(&make, out, &closure, absolute, false));
        PASS();
    } _test_next:;
    return failures;
}

static int abc_dep_store_controls(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: depfiles cannot traverse excluded root stores") {
        char copy[ABC_PATH], out[ABC_PATH], path[ABC_PATH + 32], alias[ABC_PATH + 32], token[2048];
        (void)snprintf(copy, sizeof(copy), "%s/dep-copy", w->root);
        (void)snprintf(out, sizeof(out), "%s/dep-out", w->root);
        const char *stores[] = {"build", ".zvcs", ".codeindex"};
        for (size_t i = 0; i < sizeof(stores) / sizeof(stores[0]); ++i) {
            int n = snprintf(path, sizeof(path), "%s/%s", copy, stores[i]);
            ASSERT(n > 0 && (size_t)n < sizeof(path));
            ASSERT(mkdir(path, 0700) == 0);
        }
        (void)snprintf(path, sizeof(path), "%s/src", copy);
        ASSERT(mkdir(path, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/src/build", copy);
        ASSERT(mkdir(path, 0700) == 0);
        ASSERT(abc_put(copy, "src/build/nested.h", "#define NESTED 1\n"));
        (void)snprintf(alias, sizeof(alias), "%s/dep-root-alias", w->root);
        ASSERT(symlink(copy, alias) == 0);
        char *paths[] = {"include/boost.h", "src/build/nested.h"};
        const struct app_build_closure closure = {.paths = paths, .count = 2};
        const struct app_build_make make = {.copy_dir = copy, .work_dir = out};
        ASSERT(abc_dep_verdict(&make, out, &closure, "src/../include/boost.h", true));
        ASSERT(abc_dep_verdict(&make, out, &closure, "src/build/nested.h", true));
        for (size_t i = 0; i < sizeof(stores) / sizeof(stores[0]); ++i) {
            int n = snprintf(token, sizeof(token), "%s/../include/boost.h", stores[i]);
            ASSERT(n > 0 && (size_t)n < sizeof(token));
            ASSERT(abc_dep_verdict(&make, out, &closure, token, false));
            n = snprintf(token, sizeof(token), "%s/%s/../include/boost.h", alias, stores[i]);
            ASSERT(n > 0 && (size_t)n < sizeof(token));
            ASSERT(abc_dep_verdict(&make, out, &closure, token, false));
        }
        ASSERT(unlink(alias) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int abc_builds_alias_include(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: real compiler depfile alias resolves to declared saved header") {
        struct abc_leaf l;
        ASSERT(abc_put(w->copy, "Makefile", k_makefile));
        ASSERT(abc_put(w->copy, "src/main.c",
            "#include \"../include/../include/boost.h\"\n"
            "int main(void) { return BOOST - 1; }\n"));
        ASSERT(abc_save(w->copy, NULL));
        bool built = abc_build(&l, w->copy, w->alice_datadir);
        bool recorded = built && abc_record_matches(&l, w->alice_datadir);
        abc_close(&l);
        ASSERT(built);
        ASSERT(recorded);
        PASS();
    } _test_next:;
    return failures;
}

static const char k_saved_main[] = "int main(void) { return 23; }\n";
static const char k_live_main[] = "int main(void) { return 24; }\n";

/* The editor is outside make's confinement. A FIFO handshake, not elapsed
 * time, orders the live edit before make reads its compilation input. */
static int abc_edit_on_ready(const struct abc_world *w, int ready, int go)
{
    struct pollfd event = {.fd = ready, .events = POLLIN};
    char byte;
    bool ok = poll(&event, 1, 30000) == 1 && read(ready, &byte, 1) == 1 &&
              abc_put(w->copy, "src/main.c", k_live_main);
    bool released = write(go, "go\n", 3) == 3;
    return ok && released ? 0 : 1;
}

static bool abc_build_with_live_edit(const struct abc_world *w,
                                     struct abc_leaf *l)
{
    char ready_path[ABC_PATH + 32], go_path[ABC_PATH + 32];
    (void)snprintf(ready_path, sizeof(ready_path), "%s/edit-ready", w->build_dir);
    (void)snprintf(go_path, sizeof(go_path), "%s/edit-go", w->build_dir);
    bool setup = mkfifo(ready_path, 0600) == 0 && mkfifo(go_path, 0600) == 0;
    int ready = setup ? open(ready_path, O_RDWR | O_NONBLOCK | O_CLOEXEC) : -1;
    int go = setup ? open(go_path, O_RDWR | O_NONBLOCK | O_CLOEXEC) : -1;
    pid_t child = ready >= 0 && go >= 0 ? fork() : -1;
    if (child == 0)
        _exit(abc_edit_on_ready(w, ready, go));
    bool built = false;
    int status = -1;
    if (child > 0) {
        built = abc_build(l, w->copy, w->alice_datadir);
        if (waitpid(child, &status, 0) != child) status = -1;
    }
    if (ready >= 0) (void)close(ready);
    if (go >= 0) (void)close(go);
    (void)unlink(ready_path);
    (void)unlink(go_path);
    return built && status == 0;
}

static bool abc_saved_image(const char *path)
{
    const char *argv[] = {path, NULL};
    char output[256];
    bool timed_out = false;
    int status = zcl_spawn_capture_merged_in_dir_observed(
        argv, "/", output, sizeof(output), 10000, &timed_out);
    return !timed_out && status == 23;
}

static bool abc_live_edit_preserved(const struct abc_world *w)
{
    char path[ABC_PATH + 32], bytes[sizeof(k_live_main)];
    (void)snprintf(path, sizeof(path), "%s/src/main.c", w->copy);
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    size_t count = fread(bytes, 1, sizeof(bytes), file);
    bool ok = !ferror(file) && feof(file) && count == sizeof(k_live_main) - 1 &&
              memcmp(bytes, k_live_main, count) == 0;
    return fclose(file) == 0 && ok;
}

static int abc_builds_saved_snapshot(const struct abc_world *w)
{
    int failures = 0;
    TEST("app.build: editing the live copy during make preserves saved input and live edit") {
        struct abc_leaf l;
        char makefile[2048];
        (void)snprintf(makefile, sizeof(makefile), "%s"
            ".PHONY: before\napp: before\nbefore:\n"
            "\t@printf ready > $(APP_OUT)/../edit-ready\n"
            "\t@read ack < $(APP_OUT)/../edit-go\n", k_makefile);
        ASSERT(abc_put(w->copy, "Makefile", makefile));
        ASSERT(abc_put(w->copy, "src/main.c", k_saved_main));
        ASSERT(abc_save(w->copy, NULL));
        ASSERT(abc_build_with_live_edit(w, &l));
        bool saved = abc_saved_image(abc_get(&l, "image_path"));
        bool recorded = abc_record_matches(&l, w->alice_datadir);
        abc_close(&l);
        ASSERT(abc_live_edit_preserved(w));
        ASSERT(saved);
        ASSERT(recorded);
        PASS();
    } _test_next:;
    return failures;
}

static const char *const abc_selected_keys[] = {
    "version", "package_root", "closure_root", "env_root", "dependency_root", "image_sha3"
};
struct abc_selected {
    char n[65], newer[65];
    char roots[6][65];
    uint8_t preserved[5][32];
};

static void abc_selected_input(struct abc_leaf *l, const struct abc_world *w,
                                const char *version)
{
    abc_build_input(l, w->copy, w->alice_datadir);
    (void)json_push_kv_str(&l->in, "version", version);
}

static bool abc_file_digest(const char *dir, const char *rel, uint8_t hash[32])
{
    char path[ABC_PATH + 128];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, rel);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    struct sha3_256_ctx sha; sha3_256_init(&sha);
    uint8_t buf[4096]; size_t got;
    while ((got = fread(buf, 1, sizeof(buf), file)) != 0)
        sha3_256_write(&sha, buf, got);
    bool ok = !ferror(file);
    ok = fclose(file) == 0 && ok;
    sha3_256_finalize(&sha, hash);
    return ok;
}

static bool abc_selected_bytes(const struct abc_world *w,
                                struct abc_selected *s, bool compare)
{
    static const char *const paths[] = {"src/main.c", "include/boost.h",
        "Makefile", "zcode-package.json", ".zvcs/commits.log"};
    for (size_t i = 0; i < 5; ++i) {
        uint8_t digest[32];
        if (!abc_file_digest(w->copy, paths[i], digest)) return false;
        if (compare && memcmp(digest, s->preserved[i], 32)) return false;
        if (!compare) memcpy(s->preserved[i], digest, 32);
    }
    return true;
}

static bool abc_selected_record(const struct abc_world *w,
                                 struct abc_selected *s, const struct abc_leaf *l)
{
    for (size_t i = 0; i < 6; ++i) {
        const char *value = abc_get(l, abc_selected_keys[i]);
        if (strlen(value) != 64) return false;
        (void)snprintf(s->roots[i], 65, "%s", value);
    }
    /* Force a real rebuild after poisoning live files, not only a cache hit. */
    return abc_saved_image(abc_get(l, "image_path")) &&
        abc_record_matches(l, w->alice_datadir) && unlink(abc_get(l, "image_path")) == 0;
}

static bool abc_selected_seed(const struct abc_world *w, struct abc_selected *s)
{
    if (!abc_put(w->copy, "Makefile", k_makefile) ||
        !abc_put(w->copy, "zcode-package.json", k_alice_meta) ||
        !abc_put(w->copy, "src/main.c", k_saved_main) || !abc_save(w->copy, s->n))
        return false;
    struct abc_leaf l;
    abc_selected_input(&l, w, s->n);
    bool ok = abc_pass("app.build", &l);
    char store[ABC_PATH + 32]; struct stat st;
    (void)snprintf(store, sizeof(store), "%s/app_build", w->alice_datadir);
    ok = ok && stat(store, &st) != 0; /* explicit plan retains no build state */
    ok = ok && abc_confirm("app.build", &l) && l.out.status == ZCL_COMMAND_STATUS_PASSED;
    if (ok) ok = abc_selected_record(w, s, &l);
    abc_close(&l);
    return ok;
}

static bool abc_selected_poison(const struct abc_world *w, struct abc_selected *s)
{
    return abc_put(w->copy, "src/main.c", "int main(void) { return 24; }\n") &&
        abc_save(w->copy, s->newer) &&
        abc_put(w->copy, "src/main.c", "#error dirty source must not compile\n") &&
        abc_put(w->copy, "include/boost.h", "#error dirty header\n") &&
        abc_put(w->copy, "Makefile", "$(error LIVE MAKEFILE MUST NOT RUN)\n") &&
        abc_put(w->copy, "zcode-package.json", "not valid JSON\n") &&
        abc_selected_bytes(w, s, false);
}

static bool abc_selected_rebuild(const struct abc_world *w, struct abc_selected *s)
{
    struct abc_leaf l;
    abc_selected_input(&l, w, s->n);
    bool ok = abc_plan_confirm("app.build", &l);
    for (size_t i = 0; ok && i < 6; ++i)
        ok = !strcmp(s->roots[i], abc_get(&l, abc_selected_keys[i]));
    ok = ok && abc_flag(&l, "make_ran") && abc_saved_image(abc_get(&l, "image_path")) &&
        abc_record_matches(&l, w->alice_datadir);
    abc_close(&l);
    if (!ok || !abc_selected_bytes(w, s, true)) return false;
    abc_open(&l); (void)json_push_kv_str(&l.in, "dir", w->copy);
    ok = abc_pass("zcode.package.version.list", &l) &&
        !strcmp(abc_get(&l, "head_version"), s->newer);
    abc_close(&l);
    return ok;
}

static bool abc_selected_error(const struct abc_world *w, const char *version,
                                const char *error)
{
    struct abc_leaf l;
    abc_selected_input(&l, w, version);
    bool ok = abc_exec("app.build", &l) && abc_refusal(&l, error);
    abc_close(&l);
    return ok;
}

static bool abc_selected_stale(const struct abc_world *w, const struct abc_selected *s)
{
    struct abc_leaf l;
    abc_selected_input(&l, w, s->n);
    bool ok = abc_pass("app.build", &l) && strlen(abc_get(&l, "plan_id")) == 64;
    char plan[65];
    (void)snprintf(plan, sizeof(plan), "%s", abc_get(&l, "plan_id"));
    abc_close(&l);
    abc_selected_input(&l, w, s->newer);
    (void)json_push_kv_str(&l.in, "plan_id", plan);
    (void)json_push_kv_bool(&l.in, "confirm", true);
    ok = ok && abc_exec("app.build", &l) && abc_refusal(&l, "PLAN_MISMATCH");
    abc_close(&l);
    return ok;
}

static bool abc_selected_default_dirty(const struct abc_world *w)
{
    struct abc_leaf l;
    abc_build_input(&l, w->copy, w->alice_datadir);
    bool ok = abc_exec("app.build", &l) && abc_refusal(&l, "UNSAVED_CHANGES");
    abc_close(&l);
    return ok;
}

static bool abc_selected_empty_version(const struct abc_world *w)
{
    struct abc_leaf l;
    abc_selected_input(&l, w, "");
    const struct zcl_command_spec *spec = abc_spec("app.build");
    char why[256] = "";
    bool rejected = spec &&
        !zcl_command_registry_input_validate(spec, &l.in, why, sizeof(why));
    l.req.spec = spec;
    l.req.input = &l.in;
    l.req.invoked_name = "app.build";
    zcl_native_handle_app_build(&l.req, &l.out);
    bool ok = rejected && abc_refusal(&l, "BAD_VERSION");
    abc_close(&l);
    return ok;
}

static bool abc_selected_types(const struct abc_world *w)
{
    struct abc_leaf l;
    abc_build_input(&l, w->copy, w->alice_datadir);
    (void)json_push_kv_int(&l.in, "version", 1);
    /* Direct boundary remains required even when registry types reject first. */
    l.req.spec = abc_spec("app.build"); l.req.input = &l.in;
    l.req.invoked_name = "app.build";
    zcl_native_handle_app_build(&l.req, &l.out);
    bool ok = abc_refusal(&l, "BAD_VERSION");
    abc_close(&l);
    return ok && abc_selected_empty_version(w) &&
        abc_selected_error(w, "typo", "BAD_VERSION") &&
        abc_selected_error(w, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                            "VERSION_UNKNOWN");
}

static bool abc_selected_cas_refusal(const struct abc_world *w, const struct abc_selected *s)
{
    struct zcl_package_copy copy;
    struct abc_leaf l; abc_open(&l);
    bool opened = zcl_package_copy_open_selected(w->copy, &copy, &l.out, "fixture", s->n);
    char hex[65];
    if (opened) { zcl_hex_encode(copy.selected_tree, 32, hex); zcl_package_copy_close(&copy); }
    abc_close(&l);
    if (!opened) return false;
    char path[ABC_PATH + 128], saved[ABC_PATH + 128];
    (void)snprintf(path, sizeof(path), "%s/.zvcs/objects/%.2s/%s", w->copy, hex, hex + 2);
    (void)snprintf(saved, sizeof(saved), "%s/saved-manifest", w->root);
    if (rename(path, saved) != 0) return false;
    bool missing = abc_selected_error(w, s->n, "SNAPSHOT_MATERIALIZE_FAILED");
    FILE *file = fopen(path, "wb");
    bool wrote = false;
    if (file) { wrote = fwrite("bad", 1, 3, file) == 3; wrote = fclose(file) == 0 && wrote; }
    bool corrupt = wrote && abc_selected_error(w, s->n, "SNAPSHOT_MATERIALIZE_FAILED");
    (void)unlink(path);
    bool restored = rename(saved, path) == 0;
    return missing && corrupt && restored;
}

static bool abc_selected_foreign(const struct abc_world *w, const struct abc_selected *s)
{
    struct vcs_repo *repo = vcs_open(w->copy);
    if (!repo) return false;
    struct vcs_snapshot_meta meta = {.phase = "foreign"}; uint8_t id[32];
    bool saved = vcs_snapshot(repo, &meta, id) == VCS_OK;
    vcs_close(repo);
    return saved && abc_selected_error(w, s->n, "NOT_ADOPTED");
}

static bool abc_selected_head(const struct abc_world *w, const struct abc_selected *s)
{
    uint8_t want[32], head[32]; bool found = false;
    if (!zcl_hex_decode_lower(s->newer, want, 32)) return false;
    struct vcs_repo *repo = vcs_open(w->copy);
    if (!repo) return false;
    bool ok = vcs_index_ref_get(vcs_repo_index(repo), "HEAD", head, &found) &&
        found && !memcmp(head, want, 32);
    vcs_close(repo);
    return ok;
}

static int abc_explicit_saved_version(void)
{
    int failures = 0;
    struct abc_world w = {0}; struct abc_selected s = {0};
    TEST("app.build: explicit N ignores poisoned newer/dirty files, binds plan and preserves history") {
        ASSERT(abc_world_init(&w));
        ASSERT(abc_selected_seed(&w, &s));
        ASSERT(abc_selected_poison(&w, &s));
        ASSERT(abc_selected_default_dirty(&w));
        ASSERT(abc_selected_rebuild(&w, &s));
        ASSERT(abc_selected_stale(&w, &s));
        ASSERT(abc_selected_types(&w));
        ASSERT(abc_selected_cas_refusal(&w, &s));
        ASSERT(abc_selected_bytes(&w, &s, true));
        ASSERT(abc_selected_head(&w, &s));
        ASSERT(abc_selected_foreign(&w, &s));
        PASS();
    } _test_next:;
    if (w.saved_home[0]) (void)setenv("HOME", w.saved_home, 1);
    if (!failures) (void)test_rm_rf_recursive(w.root);
    return failures;
}

/* A successful build of a skycombat copy offers ONE preview run: the built
 * image, --qa-frames=120 and a --capture in the build store, outside the copy. */
static int abc_preview_skycombat(void)
{
    int failures = 0;
    struct abc_world w = {0};
    TEST("app.build: a skycombat copy's reply carries the image + --qa-frames "
         "+ --capture=<datadir>/app_build/previews preview run") {
        abc_stub_meta = k_sky_meta;
        bool ready = abc_world_init(&w);
        abc_stub_meta = k_meta;
        ASSERT(ready);
        struct abc_leaf l;
        ASSERT(abc_build(&l, w.copy, w.alice_datadir));
        const struct json_value *argv = json_get(&l.out.data, "preview_argv");
        char want[ABC_PATH * 2 + 32], line[5 * ABC_PATH];
        ASSERT(argv && argv->type == JSON_ARR && argv->num_children == 3);
        ASSERT(strcmp(json_get_str(&argv->children[0]),
                      abc_get(&l, "image_path")) == 0);
        ASSERT(strcmp(json_get_str(&argv->children[1]),
                      "--qa-frames=120") == 0);
        char cap[ABC_PATH * 2];
        const char *img = strrchr(abc_get(&l, "image_path"), '/');
        ASSERT(img != NULL);
        (void)snprintf(cap, sizeof(cap), "%s/app_build/previews/%s.png",
                       w.alice_datadir, img + 1);
        (void)snprintf(want, sizeof(want), "--capture=%s", cap);
        ASSERT(strcmp(json_get_str(&argv->children[2]), want) == 0);
        (void)snprintf(line, sizeof(line),
                       "Preview: run %s --qa-frames=120 --capture=%s "
                       "to save %s", abc_get(&l, "image_path"), cap, cap);
        ASSERT(strcmp(abc_get(&l, "preview"), line) == 0);
        abc_close(&l);
        PASS();
    } _test_next:;
    if (w.saved_home[0]) (void)setenv("HOME", w.saved_home, 1);
    if (!failures) (void)test_rm_rf_recursive(w.root);
    return failures;
}

/* The hinted capture must never land in the copy: the game writes it, and a
 * file inside the tracked tree is an unsaved change that blocks build/share. */
static int abc_preview_outside_copy(void)
{
    int failures = 0;
    struct abc_world w = {0};
    TEST("app.build: the hinted preview capture is outside the copy and "
         "writing it leaves the copy with 0 unsaved changes") {
        abc_stub_meta = k_sky_meta;
        bool ready = abc_world_init(&w);
        abc_stub_meta = k_meta;
        ASSERT(ready);
        struct abc_leaf l;
        ASSERT(abc_build(&l, w.copy, w.alice_datadir));
        const struct json_value *argv = json_get(&l.out.data, "preview_argv");
        ASSERT(argv && argv->type == JSON_ARR && argv->num_children == 3);
        const char *arg = json_get_str(&argv->children[2]);
        ASSERT(arg && strncmp(arg, "--capture=", 10) == 0);
        char cap[ABC_PATH * 2];
        (void)snprintf(cap, sizeof(cap), "%s", arg + 10);
        abc_close(&l);
        size_t clen = strlen(w.copy);
        ASSERT(!(strncmp(cap, w.copy, clen) == 0 &&
                 (cap[clen] == '/' || cap[clen] == '\0')));
        FILE *fp = fopen(cap, "wb"); /* as the game would */
        ASSERT(fp != NULL);
        ASSERT(fputs("png", fp) >= 0);
        ASSERT(fclose(fp) == 0);
        struct zcl_package_copy copy;
        abc_open(&l);
        ASSERT(zcl_package_copy_open(w.copy, &copy, &l.out, "fixture"));
        size_t changes = 99;
        bool counted = zcl_package_copy_unsaved(&copy, &changes);
        zcl_package_copy_close(&copy);
        abc_close(&l);
        ASSERT(counted && changes == 0);
        PASS();
    } _test_next:;
    if (w.saved_home[0]) (void)setenv("HOME", w.saved_home, 1);
    if (!failures) (void)test_rm_rf_recursive(w.root);
    return failures;
}

/* A spaced personal HOME is valid; only make's execution spelling needs a
 * syntax-safe workspace. Keep this independent of the old counter/FIFO case. */
static bool abc_workspace_empty(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool empty = true;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) empty = false;
    }
    bool ok = errno == 0;
    return closedir(dir) == 0 && ok && empty;
}

static bool abc_workspace_prepare(const struct abc_world *w, struct abc_selected *s)
{
    char recipe[sizeof(k_makefile) + 350];
    int n = snprintf(recipe, sizeof(recipe), "%s"
        "APP_CFLAGS += -ffile-prefix-map=$(CURDIR)=/fixture\n%s", k_makefile,
        lab_sandbox_available() ?
        ".PHONY: readonlycheck\napp: readonlycheck\nreadonlycheck:\n"
        "\t@if printf forbidden > src/main.c; then exit 89; fi\n" : "");
    return n > 0 && (size_t)n < sizeof(recipe) &&
        abc_put(w->copy, "Makefile", recipe) &&
        abc_put(w->copy, "src/main.c", k_saved_main) && abc_save(w->copy, s->n);
}

static bool abc_workspace_result(const struct abc_world *w, const struct abc_leaf *l,
                                  int runs)
{
    const char *build = abc_get(l, "build_dir");
    size_t len = strlen(w->alice_datadir);
    return abc_flag(l, "make_ran") && !abc_flag(l, "executed") &&
        !strncmp(build, w->alice_datadir, len) && build[len] == '/' &&
        abc_make_runs(build) == runs && abc_saved_image(abc_get(l, "image_path")) &&
        abc_record_matches(l, w->alice_datadir) &&
        !strcmp(abc_get(l, "confinement"), lab_sandbox_available() ? "landlock" : "unconfined");
}

static bool abc_workspace_head(const struct abc_world *w, struct abc_selected *s)
{
    struct abc_leaf l;
    bool ok = abc_build(&l, w->copy, w->alice_datadir);
    ok = ok && abc_workspace_result(w, &l, 1);
    (void)snprintf(s->roots[0], sizeof(s->roots[0]), "%s", s->n);
    for (size_t i = 1; ok && i < 6; ++i) {
        const char *value = abc_get(&l, abc_selected_keys[i]);
        ok = strlen(value) == 64;
        if (ok) memcpy(s->roots[i], value, 65);
    }
    /* Force selected-version compilation, not an old image cache hit. */
    if (ok) ok = unlink(abc_get(&l, "image_path")) == 0;
    abc_close(&l);
    return ok;
}

static bool abc_workspace_selected(const struct abc_world *w, struct abc_selected *s)
{
    struct abc_leaf l;
    abc_selected_input(&l, w, s->n);
    bool ok = abc_plan_confirm("app.build", &l) && abc_workspace_result(w, &l, 2);
    for (size_t i = 0; ok && i < 6; ++i)
        ok = !strcmp(s->roots[i], abc_get(&l, abc_selected_keys[i]));
    abc_close(&l);
    return ok && abc_selected_bytes(w, s, true) && abc_selected_head(w, s);
}

static bool abc_workspace_refused(const struct abc_world *w, const char *version)
{
    struct abc_leaf l;
    abc_build_input(&l, w->copy, w->alice_datadir);
    bool ran;
    if (version) {
        (void)json_push_kv_str(&l.in, "version", version);
        ran = abc_exec("app.build", &l);
    } else {
        /* A head plan may query its declared closure, but no compiler runs. */
        ran = abc_pass("app.build", &l) && abc_confirm("app.build", &l);
    }
    bool ok = ran && abc_refusal(&l, "BUILD_WORKSPACE_PATH_UNSUPPORTED") &&
        strstr(l.out.error.message, "TMPDIR") != NULL &&
        l.out.error.mutated == (version == NULL) &&
        !abc_flag(&l, "make_ran") && !abc_flag(&l, "executed") &&
        !abc_get(&l, "image_path")[0] && !abc_get(&l, "record_path")[0];
    abc_close(&l);
    return ok;
}

static bool abc_workspace_no_images(const struct abc_world *w)
{
    char path[ABC_PATH];
    const char *const stores[] = {"images", "records"};
    for (size_t i = 0; i < 2; ++i) {
        int n = snprintf(path, sizeof(path), "%s/app_build/%s", w->alice_datadir, stores[i]);
        if (n < 0 || (size_t)n >= sizeof(path)) return false;
        struct stat st;
        if (lstat(path, &st) != 0) {
            if (errno == ENOENT) continue;
            return false;
        }
        if (!S_ISDIR(st.st_mode) || !abc_workspace_empty(path)) return false;
    }
    return true;
}

static bool abc_workspace_dirs(const struct abc_world *w, char safe[ABC_PATH],
                                char unsafe[ABC_PATH])
{
    int a = snprintf(safe, ABC_PATH, "%s/workspace-temp", w->root);
    int b = snprintf(unsafe, ABC_PATH, "%s/workspace temp", w->root);
    return a > 0 && a < ABC_PATH && b > 0 && b < ABC_PATH &&
        mkdir(safe, 0700) == 0 && mkdir(unsafe, 0700) == 0;
}

static bool abc_workspace_alias_refused(const struct abc_world *w,
                                         const struct abc_selected *s, const char *safe)
{
    char alias[ABC_PATH];
    int n = snprintf(alias, sizeof(alias), "%s/spaced link", w->root);
    return n > 0 && (size_t)n < sizeof(alias) && symlink(safe, alias) == 0 &&
        setenv("TMPDIR", alias, 1) == 0 &&
        abc_workspace_refused(w, NULL) && abc_workspace_empty(safe) &&
        abc_workspace_refused(w, s->n) && abc_workspace_empty(safe);
}

static int abc_spaced_workspace(void)
{
    int failures = 0;
    struct abc_world w = {0}; struct abc_selected s = {0};
    const char *old = getenv("TMPDIR");
    char *saved = old ? strdup(old) : NULL;
    bool env_ready = !old || saved != NULL;
    bool had_home = getenv("HOME") != NULL;
    char safe[ABC_PATH] = "", unsafe[ABC_PATH] = "";
    TEST("app.build: spaced HOME/datadir uses private safe workspace, retains persistent counters and selected source") {
        ASSERT(env_ready);
        ASSERT(abc_world_init_named(&w, "alice home"));
        ASSERT(abc_workspace_dirs(&w, safe, unsafe));
        ASSERT(abc_workspace_prepare(&w, &s));
        ASSERT(abc_selected_bytes(&w, &s, false));
        ASSERT(setenv("TMPDIR", unsafe, 1) == 0);
        ASSERT(abc_workspace_refused(&w, NULL));
        ASSERT(abc_workspace_empty(unsafe));
        ASSERT(abc_workspace_refused(&w, s.n));
        ASSERT(abc_workspace_empty(unsafe));
        ASSERT(abc_workspace_alias_refused(&w, &s, safe));
        ASSERT(abc_workspace_no_images(&w));
        ASSERT(abc_selected_bytes(&w, &s, true));
        ASSERT(setenv("TMPDIR", safe, 1) == 0);
        ASSERT(abc_workspace_head(&w, &s));
        ASSERT(abc_workspace_empty(safe));
        ASSERT(abc_selected_poison(&w, &s));
        ASSERT(abc_workspace_selected(&w, &s));
        ASSERT(abc_workspace_empty(safe));
        PASS();
    } _test_next:;
    if (env_ready && (saved ? setenv("TMPDIR", saved, 1) : unsetenv("TMPDIR")) != 0) ++failures;
    free(saved);
    if (w.saved_home[0] && setenv("HOME", w.saved_home, 1) != 0) ++failures;
    if (!had_home && unsetenv("HOME") != 0) ++failures;
    if (!failures && test_rm_rf_recursive(w.root) != 0) ++failures;
    return failures;
}

/* The lexical datadir is unsafe, but its target and TMPDIR are syntax-safe.
 * A temporary alias or source inside writable work is nevertheless forbidden. */
static bool abc_workspace_counter_only(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) return false;
    bool ok = true; unsigned count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        ++count;
        if (strcmp(entry->d_name, "make-runs")) ok = false;
    }
    ok = ok && errno == 0 && count == 1;
    return closedir(dir) == 0 && ok && abc_make_runs(path) == 1;
}

static bool abc_workspace_initial_run(struct abc_world *w)
{
    struct abc_leaf l;
    bool ok = abc_build(&l, w->copy, w->alice_datadir);
    const char *work = abc_get(&l, "build_dir");
    int n = snprintf(w->build_dir, sizeof(w->build_dir), "%s", work);
    ok = ok && n > 0 && (size_t)n < sizeof(w->build_dir) && abc_flag(&l, "make_ran") &&
        abc_saved_image(abc_get(&l, "image_path")) && abc_record_matches(&l, w->alice_datadir);
    if (ok) ok = unlink(abc_get(&l, "image_path")) == 0;
    abc_close(&l);
    return ok && abc_workspace_counter_only(w->build_dir);
}

static bool abc_workspace_nested_refused(const struct abc_world *w, const char *version)
{
    struct abc_leaf l;
    abc_build_input(&l, w->copy, w->alice_datadir);
    if (version) (void)json_push_kv_str(&l.in, "version", version);
    bool ok = abc_pass("app.build", &l) && abc_confirm("app.build", &l) &&
        abc_refusal(&l, "SNAPSHOT_NOT_ISOLATED") &&
        !abc_flag(&l, "make_ran") && !abc_flag(&l, "executed");
    abc_close(&l);
    return ok && abc_workspace_counter_only(w->build_dir);
}

static bool abc_workspace_datadir_alias(struct abc_world *w)
{
    char target[sizeof(w->alice_datadir)];
    memcpy(target, w->alice_datadir, sizeof(target));
    int n = snprintf(w->alice_datadir, sizeof(w->alice_datadir), "%s/datadir alias", w->root);
    return n > 0 && (size_t)n < sizeof(w->alice_datadir) &&
        symlink(target, w->alice_datadir) == 0 && setenv("TMPDIR", w->build_dir, 1) == 0;
}

static int abc_workspace_nested(void)
{
    int failures = 0;
    struct abc_world w = {0}; struct abc_selected s = {0};
    const char *old = getenv("TMPDIR");
    char *saved = old ? strdup(old) : NULL;
    bool ready = !old || saved != NULL, had_home = getenv("HOME") != NULL;
    struct stat before, after; uint8_t digest[32], current[32];
    TEST("app.build: safe-canonical TMPDIR inside persistent work refuses spaced datadir alias and preserves work") {
        ASSERT(ready);
        ASSERT(abc_world_init(&w));
        ASSERT(abc_workspace_prepare(&w, &s));
        ASSERT(abc_selected_bytes(&w, &s, false));
        ASSERT(abc_workspace_initial_run(&w));
        ASSERT(stat(w.build_dir, &before) == 0);
        ASSERT(abc_file_digest(w.build_dir, "make-runs", digest));
        ASSERT(setenv("TMPDIR", w.build_dir, 1) == 0);
        ASSERT(abc_workspace_nested_refused(&w, s.n));
        ASSERT(abc_workspace_datadir_alias(&w));
        ASSERT(abc_workspace_nested_refused(&w, NULL));
        ASSERT(abc_workspace_nested_refused(&w, s.n));
        ASSERT(stat(w.build_dir, &after) == 0);
        ASSERT(before.st_dev == after.st_dev && before.st_ino == after.st_ino);
        ASSERT(abc_file_digest(w.build_dir, "make-runs", current));
        ASSERT(memcmp(digest, current, sizeof(digest)) == 0);
        ASSERT(abc_selected_bytes(&w, &s, true));
        PASS();
    } _test_next:;
    if (ready && (saved ? setenv("TMPDIR", saved, 1) : unsetenv("TMPDIR")) != 0) ++failures;
    free(saved);
    if (w.saved_home[0] && setenv("HOME", w.saved_home, 1) != 0) ++failures;
    if (!had_home && unsetenv("HOME") != 0) ++failures;
    if (!failures && test_rm_rf_recursive(w.root) != 0) ++failures;
    return failures;
}

int test_app_build_copy(void)
{
    int failures = 0;
    struct abc_world w;
    chain_params_select(CHAIN_MAIN);
    TEST("app.build: publish and adopt a one-file stub app") {
        ASSERT(abc_world_init(&w));
        PASS();
    } _test_next:;
    if (!failures) {
        failures += abc_mcp_plan_first(&w);
        failures += abc_refuses_unadopted(&w);
        failures += abc_refuses_wrong_deps(&w);
        failures += abc_builds_v1_then_v2(&w);
    }
    if (!failures)
        failures += abc_friend_builds(&w);
    if (!failures) {
        failures += abc_restore_is_cache_hit(&w);
        failures += abc_refuses_dirty(&w);
        failures += abc_refuses_bad_builds(&w);
        if (!failures) failures += abc_failure_serialization(&w);
        if (!failures) failures += abc_failure_escaped(&w);
        failures += abc_landlock_contains(&w);
    }
    if (!failures) {
        failures += abc_dep_alias_controls(&w);
        failures += abc_dep_store_controls(&w);
        failures += abc_builds_alias_include(&w);
    }
    if (!failures)
        failures += abc_builds_saved_snapshot(&w);
    if (w.saved_home[0])
        (void)setenv("HOME", w.saved_home, 1);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    if (!failures)
        failures += abc_explicit_saved_version();
    if (!failures)
        failures += abc_preview_skycombat();
    if (!failures)
        failures += abc_preview_outside_copy();
    if (!failures)
        failures += abc_spaced_workspace();
    if (!failures)
        failures += abc_workspace_nested();
    return failures;
}
