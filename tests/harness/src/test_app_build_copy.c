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
 *   - a build that reads an input its declared closure omits is refused
 *     CLOSURE_DRIFT, a compile error is BUILD_FAILED with a bounded tail;
 *   - where Landlock confines the build, a make fragment that writes outside
 *     the copy and build directories fails; elsewhere skipped with a reason.
 * Leaves run as the CLI and MCP run them: input contract, handler, budget. */

#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/app_image.h"
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
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
    return abc_pass(path, l) && abc_confirm(path, l) &&
           l->out.status == ZCL_COMMAND_STATUS_PASSED;
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
    return ok && abc_put(w->src, "zcode-package.json", k_meta) &&
           abc_put(w->src, "Makefile", k_makefile) &&
           abc_put(w->src, "include/boost.h", "#define BOOST 1\n") &&
           abc_put(w->src, "src/main.c", k_main);
}

/* Alice publishes the stub with her own publisher key (the key file the
 * owner's sign leaf uses later), so her shared edit keeps the name. */
static bool abc_publish_origin(struct abc_world *w)
{
    char key[700], z23[700], pubhex[PLUGIN_HEX_PUBLIC_KEY + 1];
    struct plugin_dist_published why;
    struct vcs_package_prepare_options o = {
        .dir = w->src, .publisher_sequence = 1, .reward_address = "",
        .chain_id = "zclassic-main",
    };
    struct vcs_package_prepared p;
    char detail[256] = {0};
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    (void)snprintf(z23, sizeof(z23), "%s/.z23", w->alice_home);
    (void)snprintf(key, sizeof(key), "%s/zcode_publisher.key", z23);
    if (mkdir(z23, 0700) != 0 || plugin_keygen(key, pubhex) != PLUGIN_OK ||
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

static bool abc_world_init(struct abc_world *w)
{
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    if (!test_mkdtemp(w->root, sizeof(w->root), "app_build_copy"))
        return false;
    (void)snprintf(w->src, sizeof(w->src), "%s/stub-src", w->root);
    (void)snprintf(w->alice_home, sizeof(w->alice_home), "%s/alice", w->root);
    (void)snprintf(w->alice_datadir, sizeof(w->alice_datadir),
                   "%s/alice/datadir", w->root);
    (void)snprintf(w->bob_home, sizeof(w->bob_home), "%s/bob", w->root);
    (void)snprintf(w->bob_datadir, sizeof(w->bob_datadir), "%s/bob/datadir",
                   w->root);
    (void)snprintf(w->bob_copy, sizeof(w->bob_copy), "%s/bob/tinyapp-from-alice",
                   w->root);
    (void)snprintf(w->share_file, sizeof(w->share_file),
                   "%s/alice/tinyapp.z23share", w->root);
    return abc_stub_source(w) && mkdir(w->alice_home, 0700) == 0 &&
           mkdir(w->alice_datadir, 0700) == 0 &&
           mkdir(w->bob_home, 0700) == 0 && abc_as(w->alice_home) &&
           abc_publish_origin(w) && abc_adopt(w);
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
        abc_close(&l);
        abc_build_input(&l, plain, w->alice_datadir);
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
        abc_close(&l);
        ASSERT_EQ(abc_make_runs(w->build_dir), 1);

        /* The copy itself was not written: it is still clean. */
        ASSERT(abc_save(w->copy, NULL) == false);

        ASSERT(abc_put(w->copy, "include/boost.h", "#define BOOST 2\n"));
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
        const char *tail = abc_get(&l, "log_tail");
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
        ASSERT(strcmp(abc_get(&l, "confinement"), "landlock") == 0);
        abc_close(&l);
        ASSERT(stat(escape, &st) != 0);
        PASS();
    } _test_next:;
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
        failures += abc_landlock_contains(&w);
    }
    if (w.saved_home[0])
        (void)setenv("HOME", w.saved_home, 1);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}
