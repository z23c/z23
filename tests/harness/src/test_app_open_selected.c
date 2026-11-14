/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
#if !defined(_WIN32)
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/app_image.h"
#include "command/native_app_launch.h"
#include "command/native_app_confirm.h"
#include "command/app_selection.h"
#include "command/native_app_receive_command.h"
#include "command/native_app_receive_preview.h"
#include "command/native_app_share_command.h"
#include "command/native_app_library_command.h"
#include "command/native_app_personalize_command.h"
#include "command/native_app_personalize_view.h"
#include "vcs/vcs.h"
#include "vcs/vcs_manifest.h"
#include <signal.h>
#include <errno.h>
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
#include "util/spawn.h"
#include "util/file_io.h"
#include "sha3/sha3.h"
#include "platform/time_compat.h"
#include "platform/directory_compat.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
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

static const char *abc_get(const struct abc_leaf *l, const char *key)
{
    const char *s = json_get_str(json_get(&l->out.data, key));
    return s ? s : "";
}

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

static const char k_main[] =
    "#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n#include \"boost.h\"\n"
    "int main(int n,char **v){if(n!=2)return 8;"
    "if(!strcmp(v[1],\"exit\")){sleep(1);return 3;}"
    "if(!strcmp(v[1],\"ready\")){printf(\"BOOST=%d\\n\",BOOST);puts(\"READY-N\");fflush(stdout);}"
    "for(;;) pause();}\n";

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


/* DISPLAY is synthetic: this child has no windows and proves no GUI behavior. */
struct aso_env { const char *key; char *saved; };
struct aso_build { char version[65], package[65], env[65], deps[65], image[65], record[65], image_path[ABC_PATH]; bool long_label; };
struct aso_live { long pid; uint64_t token; char exe[APP_LAUNCH_PATH_MAX]; };
static struct aso_live aso_live[8];
static unsigned aso_nlive;

static void aso_env_restore(struct aso_env *env, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (env[i].saved) { (void)setenv(env[i].key, env[i].saved, 1); free(env[i].saved); }
        else (void)unsetenv(env[i].key);
    }
}
static bool aso_config(struct abc_world *w, const struct aso_build *b)
{
    char config[ABC_PATH], z23[ABC_PATH], catalog[ABC_PATH], text[ABC_PATH * 4];
    (void)snprintf(config, sizeof(config), "%s/config", w->root);
    (void)snprintf(z23, sizeof(z23), "%s/config/z23", w->root);
    if (mkdir(config, 0700) || mkdir(z23, 0700)) return false;
    int n = snprintf(text, sizeof(text),
        "tiny-ready\t-\t%s\tREADY-N\t-\tready\n"
        "tiny-exit\t-\t%s\tREADY-N\t-\texit\n"
        "tiny-silent\t-\t%s\tREADY-N\t-\tsilent\n",
        b->image_path, b->image_path, b->image_path);
    int path_n = snprintf(catalog, sizeof(catalog), "%s/apps.tsv", z23);
    return n > 0 && (size_t)n < sizeof(text) && path_n > 0 &&
        (size_t)path_n < sizeof(catalog) && abc_put(z23, "apps.tsv", text) &&
        chmod(catalog, 0600) == 0;
}
static bool aso_tuple(struct abc_leaf *l, struct aso_build *b)
{
    const char *keys[] = {"version", "package_root", "env_root", "dependency_root", "image_sha3", "record_id"};
    char *slots[] = {b->version, b->package, b->env, b->deps, b->image, b->record};
    for (size_t i = 0; i < 6; ++i) {
        const char *v = abc_get(l, keys[i]);
        if (strlen(v) != 64) return false;
        memcpy(slots[i], v, 65);
    }
    const char *path = abc_get(l, "image_path");
    if (strlen(path) >= sizeof(b->image_path)) return false;
    strcpy(b->image_path, path);
    return true;
}
static bool aso_execute(const struct abc_world *w, const struct aso_build *b,
                        const char *name, bool consent, const char *record,
                        const char *image, struct json_value *root)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = abc_spec("app.open");
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
                                      .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    struct json_value input;
    json_init(&input); json_set_object(&input);
    (void)json_push_kv_str(&input, "name", name);
    (void)json_push_kv_str(&input, "copy", w->copy);
    (void)json_push_kv_str(&input, "datadir", w->alice_datadir);
    (void)json_push_kv_str(&input, "version", b->version);
    (void)json_push_kv_str(&input, "env_root", b->env);
    (void)json_push_kv_str(&input, "dependency_root", b->deps);
    (void)json_push_kv_str(&input, "image_sha3", image ? image : b->image);
    (void)json_push_kv_str(&input, "record_id", record ? record : b->record);
    if (consent) (void)json_push_kv_bool(&input, "accept_execution", true);
    char wire[32768]; enum zcl_command_exit exit_code;
    size_t n = spec ? zcl_command_registry_execute_json(reg, spec, &ctx, &input,
        false, spec->path, "normal", 0, 0, NULL, wire, sizeof(wire), &exit_code) : 0;
    json_free(&input);
    json_init(root);
    if (!n || n >= sizeof(wire) || !json_read(root, wire, n)) return false;
    return true;
}
static const char *aso_string(const struct json_value *v, const char *key)
{
    const char *s = json_get_str(json_get(v, key));
    return s ? s : "";
}
static bool aso_build_facts_match(const struct json_value *f, const struct aso_build *b)
{
    return !strcmp(aso_string(f, "version"), b->version) &&
        !strcmp(aso_string(f, "package_root"), b->package) &&
        !strcmp(aso_string(f, "record_id"), b->record) &&
        !strcmp(aso_string(f, "image_sha3"), b->image) &&
        !strcmp(aso_string(f, "env_root"), b->env) &&
        !strcmp(aso_string(f, "dependency_root"), b->deps);
}
static bool aso_facts(const struct json_value *doc, const struct aso_build *b,
                      const char *error_code, bool alive)
{
    const struct json_value *err = json_get(doc, "error");
    const struct json_value *f = json_get(err, "facts");
    const struct json_value *pid = json_get(f, "pid");
    if (!f || !pid || pid->type != JSON_INT) return false;
    long value = (long)json_get_int(pid);
    const char *token = aso_string(f, "start_token");
    if (alive && value > 1 && aso_nlive < 8) {
        aso_live[aso_nlive].pid = value;
        aso_live[aso_nlive].token = strtoull(token, NULL, 10);
        (void)snprintf(aso_live[aso_nlive].exe, sizeof(aso_live[aso_nlive].exe), "%s", b->image_path);
        ++aso_nlive;
    }
    return strcmp(aso_string(err, "code"), error_code) == 0 && value > 1 &&
        strtoull(token, NULL, 10) > 0 && aso_string(f, "mapped_proof")[0] &&
        aso_string(f, "log")[0] && aso_build_facts_match(f, b);
}
static bool aso_same_process(const struct aso_live *child)
{
    char exe[APP_LAUNCH_PATH_MAX]; uint64_t token = 0;
    return app_proc_identity(child->pid, exe, &token) && token == child->token &&
           strcmp(exe, child->exe) == 0;
}

static bool aso_wait_child_exit(const struct aso_live *child)
{
    int64_t deadline = platform_time_monotonic_ms() + 5000;
    int status;
    while (aso_same_process(child)) {
        (void)waitpid((pid_t)child->pid, &status, WNOHANG);
        if (!aso_same_process(child)) break;
        if (platform_time_monotonic_ms() >= deadline) return false;
        platform_sleep_ms(10); /* real-clock: wait for the owned process to exit */
    }
    (void)waitpid((pid_t)child->pid, &status, WNOHANG);
    return true;
}

static bool aso_cleanup_child(const struct aso_live *child)
{
    if (!aso_same_process(child)) {
        int status;
        (void)waitpid((pid_t)child->pid, &status, WNOHANG);
        return true;
    }
    bool signaled = kill((pid_t)child->pid, SIGKILL) == 0 || errno == ESRCH;
    return aso_wait_child_exit(child) && signaled;
}

static bool aso_cleanup_children(void)
{
    bool ok = true;
    for (unsigned i = 0; i < aso_nlive; ++i)
        ok = aso_cleanup_child(&aso_live[i]) && ok;
    aso_nlive = 0;
    return ok;
}

static void aso_track_ready(const struct json_value *d, const struct aso_build *b)
{
    const struct json_value *pid = json_get(d, "pid");
    if (!pid || pid->type != JSON_INT || aso_nlive >= 8) return;
    aso_live[aso_nlive].pid = (long)json_get_int(pid);
    aso_live[aso_nlive].token = strtoull(aso_string(d, "start_token"), NULL, 10);
    (void)snprintf(aso_live[aso_nlive].exe, sizeof(aso_live[aso_nlive].exe), "%s", b->image_path);
    ++aso_nlive;
}
static bool aso_head_and_dirty(const struct abc_world *w, const char *version)
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.app_open_selected.v1");
    bool opened = zcl_package_copy_open_as(w->copy, ZCL_PACKAGE_COPY_READ, &copy, &reply, "test");
    char actual[65] = {0};
    if (opened) zcl_hex_encode(copy.head_version, 32, actual);
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply);
    char path[ABC_PATH]; (void)snprintf(path, sizeof(path), "%s/include/boost.h", w->copy);
    FILE *file = fopen(path, "rb");
    char bytes[64] = {0}; size_t n = file ? fread(bytes, 1, sizeof(bytes) - 1, file) : 0;
    if (file) fclose(file);
    return opened && !strcmp(actual, version) && n == strlen("#define BOOST 4\n") &&
        !strcmp(bytes, "#define BOOST 4\n");
}
static int aso_success(const struct abc_world *w, const struct aso_build *b, const char *head)
{
    int failures = 0;
    struct json_value doc; json_init(&doc);
    TEST("selected app opens saved N while N+1 and dirty bytes remain") {
        ASSERT(aso_execute(w, b, "tiny-ready", true, NULL, NULL, &doc));
        const struct json_value *d = json_get(&doc, "data");
        aso_track_ready(d, b);
        ASSERT(d && !strcmp(aso_string(d, "status"), "opened"));
        ASSERT(!strcmp(aso_string(d, "version"), b->version));
        ASSERT(!strcmp(aso_string(d, "package_root"), b->package));
        ASSERT(!strcmp(aso_string(d, "record_id"), b->record));
        ASSERT(!strcmp(aso_string(d, "image_sha3"), b->image));
        ASSERT(aso_string(d, "mapped_proof")[0] && strtoull(aso_string(d, "start_token"), NULL, 10));
        ASSERT(aso_head_and_dirty(w, head));
        PASS();
    } _test_next:;
    json_free(&doc);
    return failures;
}
static int aso_refusals(const struct abc_world *w, const struct aso_build *b)
{
    int failures = 0;
    struct json_value doc; json_init(&doc);
    const char *wrong = "0000000000000000000000000000000000000000000000000000000000000000";
    TEST("app keep without a preview says it is the agent step and names app save") {
        struct abc_leaf leaf;
        abc_open(&leaf);
        ASSERT(json_push_kv_str(&leaf.in, "name", "tiny-ready"));
        ASSERT(json_push_kv_str(&leaf.in, "copy", w->copy));
        ASSERT(json_push_kv_str(&leaf.in, "datadir", w->alice_datadir));
        ASSERT(abc_exec("app.keep", &leaf));
        ASSERT(!strcmp(leaf.out.error.code, "EXECUTION_CONFIRMATION_REQUIRED"));
        ASSERT(strstr(leaf.out.error.message, "after an app open preview") != NULL);
        ASSERT(strstr(leaf.out.error.message, "app save ") != NULL);
        abc_close(&leaf);
        PASS();
    } TEST("selected app requires explicit execution consent") {
        ASSERT(aso_execute(w, b, "tiny-ready", false, NULL, NULL, &doc));
        ASSERT(!strcmp(aso_string(json_get(&doc, "error"), "code"), "EXECUTION_CONFIRMATION_REQUIRED"));
        json_free(&doc);
        ASSERT(aso_execute(w, b, "tiny-ready", true, wrong, NULL, &doc));
        ASSERT(!strcmp(aso_string(json_get(&doc, "error"), "code"), "BUILD_IDENTITY_MISMATCH"));
        json_free(&doc);
        ASSERT(aso_execute(w, b, "tiny-ready", true, NULL, wrong, &doc));
        ASSERT(!strcmp(aso_string(json_get(&doc, "error"), "code"), "BUILD_IDENTITY_MISMATCH"));
        PASS();
    } _test_next:;
    json_free(&doc);
    return failures;
}
static int aso_failure_cases(const struct abc_world *w, const struct aso_build *b)
{
    int failures = 0;
    struct json_value doc; json_init(&doc);
    TEST("early exit and live timeout serialize exact process and build facts") {
        ASSERT(aso_execute(w, b, "tiny-exit", true, NULL, NULL, &doc));
        ASSERT(aso_facts(&doc, b, "EXITED_EARLY", false));
        json_free(&doc);
        ASSERT(aso_execute(w, b, "tiny-silent", true, NULL, NULL, &doc));
        ASSERT(aso_facts(&doc, b, "NOT_READY", true));
        PASS();
    } _test_next:;
    json_free(&doc);
    return failures;
}
static int aso_mutation_open(const char *path)
{
    int64_t deadline = platform_time_monotonic_ms() + 5000;
    bool observed_busy = false;
    for (;;) {
        int fd = open(path, O_WRONLY | O_APPEND);
        if (fd >= 0) return fd;
        int error = errno;
        if (error != ETXTBSY || platform_time_monotonic_ms() >= deadline) {
            printf("image mutation open failed errno=%d: %s\n", error, strerror(error));
            errno = error;
            return -1;
        }
        if (!observed_busy) {
            printf("image mutation awaiting executable release errno=%d: %s\n", error, strerror(error));
            observed_busy = true;
        }
        platform_sleep_ms(10); /* real-clock: await kernel executable release */
    }
}
static int aso_mutation(const struct abc_world *w, const struct aso_build *b)
{
    int failures = 0; struct json_value doc; json_init(&doc);
    TEST("mutated built image is refused before launch") {
        int fd = aso_mutation_open(b->image_path);
        ASSERT(fd >= 0 && write(fd, "x", 1) == 1 && close(fd) == 0);
        ASSERT(aso_execute(w, b, "tiny-ready", true, NULL, NULL, &doc));
        ASSERT(!strcmp(aso_string(json_get(&doc, "error"), "code"), "IMAGE_REFUSED"));
        PASS();
    } _test_next:;
    json_free(&doc); return failures;
}

/* A short-lived MCP server over private pipes; DISPLAY is synthetic and the
 * fixture never opens a window. No service remains running after this test. */
struct aso_mcp { pid_t pid; int input, output; char line[65536]; };
static bool aso_mcp_spawn_args(struct aso_mcp *m, const char *bin,
                               const char *arg0, const char *arg1, const char *arg2)
{
    int in[2], out[2];
    m->pid = -1; m->input = m->output = -1;
    if (pipe(in) != 0) return false;
    if (pipe(out) != 0) { close(in[0]); close(in[1]); return false; }
    m->pid = fork();
    if (m->pid == 0) {
        int nullfd = open("/dev/null", O_WRONLY);
        if (dup2(in[0], 0) < 0 || dup2(out[1], 1) < 0 || nullfd < 0 || dup2(nullfd, 2) < 0) _exit(126);
        close(in[0]); close(in[1]); close(out[0]); close(out[1]); close(nullfd);
        if (setenv("ZCL_CLI_TEST_NO_SERVICE_LOOKUP", "1", 1) != 0) _exit(126);
        execl(bin, bin, arg0, arg1, arg2, (char *)NULL);
        _exit(127);
    }
    close(in[0]); close(out[1]);
    if (m->pid < 0) { close(in[1]); close(out[0]); return false; }
    m->input = in[1]; m->output = out[0];
    return true;
}
static bool aso_mcp_spawn(struct aso_mcp *m)
{
    char bin[PATH_MAX];
    m->pid = -1; m->input = m->output = -1;
    return realpath("build/bin/z23-dev", bin) &&
        aso_mcp_spawn_args(m, bin, "mcp", "serve", NULL);
}
static bool aso_mcp_reap(pid_t pid, int timeout_ms)
{
    int64_t deadline = platform_time_monotonic_ms() + timeout_ms;
    for (;;) {
        pid_t done = waitpid(pid, NULL, WNOHANG);
        if (done == pid || (done < 0 && errno == ECHILD)) return true;
        if (done < 0 && errno != EINTR) return false;
        if (platform_time_monotonic_ms() >= deadline) return false;
        platform_sleep_ms(10); /* real-clock: bound waiting for the owned MCP child */
    }
}
static bool aso_mcp_close(struct aso_mcp *m)
{
    if (m->input >= 0) close(m->input);
    if (m->output >= 0) close(m->output);
    m->input = m->output = -1;
    if (m->pid <= 0) return true;
    pid_t pid = m->pid;
    (void)kill(pid, SIGTERM);
    bool reaped = aso_mcp_reap(pid, 2000);
    if (!reaped) {
        (void)kill(pid, SIGKILL);
        reaped = aso_mcp_reap(pid, 2000);
    }
    if (reaped) m->pid = -1;
    return reaped;
}
static bool aso_mcp_send(struct aso_mcp *m, const char *line, bool response)
{
    size_t n = strlen(line), used = 0;
    if (write(m->input, line, n) != (ssize_t)n || write(m->input, "\n", 1) != 1) return false;
    if (!response) return true;
    for (;;) {
        struct pollfd p = {.fd = m->output, .events = POLLIN}; char c;
        if (poll(&p, 1, 30000) <= 0 || read(m->output, &c, 1) != 1) {
            printf("MCP response interrupted errno=%d after %zu bytes\n", errno, used);
            return false;
        }
        if (c == '\n') { m->line[used] = 0; return true; }
        if (used + 1 >= sizeof(m->line)) return false;
        m->line[used++] = c;
    }
}
static bool aso_mcp_init(struct aso_mcp *m)
{
    const char *init = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"selected-test\",\"version\":\"1\"}}}";
    const char *ready = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
    return aso_mcp_send(m, init, true) && strstr(m->line, "serverInfo") && aso_mcp_send(m, ready, false);
}
static bool aso_mcp_request(struct json_value *req, struct json_value *params,
                            struct json_value *args, const struct abc_world *w,
                            const struct aso_build *b, const char *tool, int64_t revision)
{
    const char *keys[] = {"name", "copy", "datadir", "version", "env_root",
                          "dependency_root", "image_sha3", "record_id"};
    const struct aso_build empty = {0};
    const struct aso_build *value = b ? b : &empty;
    const char *values[] = {"tiny-ready", w->copy, w->alice_datadir, value->version,
                            value->env, value->deps, value->image, value->record};
    bool ok = true;
    size_t count = b ? sizeof(keys) / sizeof(keys[0]) : 1;
    for (size_t i = 0; i < count; ++i)
        if (!json_push_kv_str(args, keys[i], values[i])) ok = false;
    if (b) ok = ok && json_push_kv_bool(args, "accept_execution", true);
    if (revision >= 0) ok = ok && json_push_kv_int(args, "expected_revision", revision);
    ok = ok && json_push_kv_str(params, "name", tool) && json_push_kv(params, "arguments", args) &&
        json_push_kv_str(req, "jsonrpc", "2.0") && json_push_kv_int(req, "id", 2) &&
        json_push_kv_str(req, "method", "tools/call") && json_push_kv(req, "params", params);
    return ok;
}
static bool aso_mcp_call(struct aso_mcp *m, const struct abc_world *w,
                         const struct aso_build *b, const char *tool, int64_t revision,
                         struct json_value *doc, bool *is_error)
{
    struct json_value req, params, args, result;
    json_init(&req); json_init(&params); json_init(&args); json_init(&result);
    json_set_object(&req); json_set_object(&params); json_set_object(&args);
    bool ok = aso_mcp_request(&req, &params, &args, w, b, tool, revision);
    char wire[8192]; size_t n = ok ? json_write(&req, wire, sizeof(wire)) : 0;
    ok = n && n < sizeof(wire) && aso_mcp_send(m, wire, true) &&
         json_read(&result, m->line, strlen(m->line));
    const struct json_value *r = json_get(&result, "result");
    const struct json_value *iserr = json_get(r, "isError");
    const struct json_value *part = json_at(json_get(r, "content"), 0);
    const char *text = json_get_str(json_get(part, "text"));
    if (!iserr || iserr->type != JSON_BOOL || !text) ok = false;
    if (ok) { *is_error = json_get_bool(iserr); ok = json_read(doc, text, strlen(text)); }
    if (!ok) printf("MCP %s response invalid: %.1024s\n", tool, m->line);
    json_free(&result); json_free(&args); json_free(&params); json_free(&req);
    return ok;
}
static bool aso_mcp_tool(struct aso_mcp *m, const struct abc_world *w,
                         const struct aso_build *b, struct json_value *doc, bool *is_error)
{
    return aso_mcp_call(m, w, b, "apps_open", -1, doc, is_error);
}
static bool aso_revision_is(const struct json_value *data, int64_t revision)
{
    const struct json_value *v = json_get(data, "selection_revision");
    return v && v->type == JSON_INT && json_get_int(v) == revision;
}
static bool aso_code_is(const struct json_value *doc, const char *code)
{
    return !strcmp(aso_string(json_get(doc, "error"), "code"), code);
}
static void aso_doc_clear(struct json_value *doc) { json_free(doc); json_init(doc); }

static bool aj_receive_action(const struct zcl_present_window_live_view_v1 *live,
    unsigned index, bool *close, bool *redraw);
static bool aj_receive_field(const struct zcl_present_model_v1 *m, const char *label, const char *expected);
struct aso_keep_view {
    const struct aso_build *build;
    char current[65];
    unsigned mode; /* 0 approve; 1 cancel; 2 close; 3 presenter failure. */
    bool observed;
};
static bool aso_keep_race(void)
{
    struct app_launch_env env; struct app_selection old, saved; char why[256];
    return app_launch_env_from_process(&env, why, sizeof(why)) &&
        app_selection_load(env.state_dir, "tiny-ready", &old) == APP_SELECTION_OK &&
        app_selection_save(env.state_dir, old.revision, &old, &saved) == APP_SELECTION_OK;
}
static bool aso_keep_fields_match(struct aso_keep_view *v, const struct zcl_present_model_v1 *model)
{
    const char *label = v->build->long_label ?
        "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk" : "tinyapp";
    bool current = v->current[0] ? aj_receive_field(model, "Currently kept: ", v->current) : true;
    if (!v->current[0])
        for (uint32_t i = 0; i < model->item_count; ++i)
            if (strstr(model->items[i].value, "Currently kept: ")) current = false;
    return current && aj_receive_field(model, "App: ", label) &&
        aj_receive_field(model, "Saved app: ", "tiny-ready") &&
        aj_receive_field(model, "Version to keep: ", v->build->version) &&
        aj_receive_field(model, "Exact app image: ", v->build->image);
}
static bool aso_keep_mutate(struct aso_keep_view *v)
{
    if (v->mode == 3) return false;
    if (v->mode == 4 && !aso_keep_race()) return false;
    if (v->mode == 5) {
        int fd = open(v->build->image_path, O_WRONLY | O_APPEND);
        if (fd < 0) return false;
        bool changed = write(fd, "!", 1) == 1;
        if (close(fd) || !changed) return false;
    }
    return true;
}
/* Confirm before the last page refuses approval and guides to page one. */
static bool aj_receive_early_guided(const struct zcl_present_window_live_view_v1 *live)
{
    bool close = false, redraw = false;
    if (!aj_receive_action(live, 3, &close, &redraw) || close || !redraw) return false;
    const struct app_confirm *view = live->owner.context;
    return !view->confirmed && view->page_index == 1 && (view->visited & 3u) == 3u;
}
static bool aso_keep_choose(const struct zcl_present_window_live_view_v1 *live,
    unsigned mode, uint32_t count)
{
    bool close = false, redraw = false;
    if (mode == 1) return aj_receive_action(live, 0, &close, &redraw) && close;
    if (mode == 2) {
        struct zcl_present_window_event_v1 event = {0};
        live->owner.update(live->owner.context, &event, true, &redraw, &close);
        return close;
    }
    if (count > 1 && !aj_receive_early_guided(live)) return false;
    for (uint32_t i = 2; i < count; ++i)
        if (!aj_receive_action(live, 2, &close, &redraw) || close || !redraw) return false;
    return aj_receive_action(live, 3, &close, &redraw) && close;
}
static bool aso_keep_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct aso_keep_view *v = context;
    uint32_t count = 0;
    if (!pages || !pages->pages[0].pixels || strcmp(model->request_id, "keep-app") ||
        !zcl_present_model_page_count_v1(model, &count, why, cap) || count != 1 ||
        !aso_keep_fields_match(v, model)) return false;
    v->observed = true;
    return aso_keep_mutate(v) && aso_keep_choose(live, v->mode, count);
}

/* Native per-invocation presenter, not a JSON approval or a GUI claim. */
static bool aso_keep_current(struct aso_keep_view *view)
{
    struct app_launch_env env; struct app_selection kept; char why[256];
    if (!app_launch_env_from_process(&env, why, sizeof(why))) return false;
    enum app_selection_result r = app_selection_load(env.state_dir, "tiny-ready", &kept);
    if (r == APP_SELECTION_OK) zcl_hex_encode(kept.version, 32, view->current);
    return r == APP_SELECTION_OK || r == APP_SELECTION_ABSENT || view->mode == 6;
}
static bool aso_owner_keep(const struct abc_world *w, const struct aso_build *b,
    int64_t revision, unsigned mode, struct json_value *doc, bool *error)
{
    struct json_value req, params, args, result;
    json_init(&req); json_init(&params); json_init(&args); json_init(&result);
    json_set_object(&req); json_set_object(&params); json_set_object(&args); json_set_object(&result);
    bool ok = aso_mcp_request(&req, &params, &args, w, b, "apps_keep", revision);
    const struct json_value *input = json_get(json_get(&req, "params"), "arguments");
    struct zcl_command_context ctx = {.plan_first = true};
    struct zcl_command_request request = {.input = input, .context = &ctx};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_keep.v1");
    struct aso_keep_view view = {.build = b, .mode = mode};
    ok = ok && aso_keep_current(&view);
    if (ok) zcl_native_app_keep_present(&request, &reply, aso_keep_present, &view);
    *error = reply.status != ZCL_COMMAND_STATUS_PASSED;
    struct json_value failure; json_init(&failure); json_set_object(&failure);
    ok = ok && view.observed == (mode != 6) && json_push_kv_str(&failure, "code", reply.error.code) &&
        json_push_kv(&result, "error", &failure) && json_push_kv(&result, "data", &reply.data);
    char wire[8192]; size_t size = ok ? json_write(&result, wire, sizeof(wire)) : 0;
    ok = size && size < sizeof(wire) && json_read(doc, wire, size);
    zcl_command_reply_free(&reply); json_free(&failure); json_free(&result);
    json_free(&args); json_free(&params); json_free(&req);
    return ok;
}

static int aso_keep_readonly(const struct abc_world *w, const struct aso_build *b)
{
    int failures = 0; bool moved = false, error = false;
    char index[ABC_PATH + 32], saved[ABC_PATH + 40], wal[ABC_PATH + 40];
    (void)snprintf(index, sizeof(index), "%s/.zvcs/index.kv", w->copy);
    (void)snprintf(saved, sizeof(saved), "%s.keep-test", index);
    (void)snprintf(wal, sizeof(wal), "%s-wal", index);
    struct json_value doc; json_init(&doc);
    TEST("Cancel validates saved history without creating a missing copy index") {
        ASSERT(access(wal, F_OK) != 0 && errno == ENOENT);
        ASSERT(rename(index, saved) == 0); moved = true;
        ASSERT(aso_owner_keep(w, b, 0, 1, &doc, &error));
        ASSERT(!error && !strcmp(aso_string(json_get(&doc, "data"), "status"), "canceled"));
        ASSERT(access(index, F_OK) != 0 && errno == ENOENT);
        ASSERT(access(wal, F_OK) != 0 && errno == ENOENT);
        PASS();
    } _test_next:;
    if (moved && rename(saved, index)) failures++;
    json_free(&doc); return failures;
}
static bool aso_blob_path(const struct abc_world *w, const struct aso_build *b, char path[ABC_PATH + 100])
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.keep.v1");
    struct vcs_manifest manifest; vcs_manifest_init(&manifest);
    bool ok = zcl_package_copy_open_selected_as(w->copy, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "test", b->version) &&
        vcs_tree_load_readonly_bounded(w->copy, copy.selected_tree, 1024 * 1024, 1024, &manifest) && manifest.count;
    if (ok) {
        char hex[65]; zcl_hex_encode(manifest.entries[0].blob, 32, hex);
        (void)snprintf(path, ABC_PATH + 100, "%s/.zvcs/objects/%c%c/%s", w->copy, hex[0], hex[1], hex + 2);
    }
    vcs_manifest_free(&manifest); zcl_package_copy_close(&copy); zcl_command_reply_free(&reply);
    return ok;
}
static int aso_keep_missing_alias(const struct abc_world *w, const struct aso_build *b)
{
    int failures = 0; bool moved = false, error = false;
    char canonical[ABC_PATH + 100], alias[ABC_PATH + 100];
    (void)snprintf(alias, sizeof(alias), "%s/.zvcs/objects/tmp/.put.keep-missing", w->copy);
    struct json_value doc; json_init(&doc);
    TEST("owner Keep refuses a missing canonical blob without repairing its alias") {
        ASSERT(aso_blob_path(w, b, canonical));
        ASSERT(rename(canonical, alias) == 0); moved = true;
        ASSERT(aso_owner_keep(w, b, 0, 6, &doc, &error));
        ASSERT(error && aso_code_is(&doc, "SNAPSHOT_MATERIALIZE_FAILED"));
        struct stat st;
        ASSERT(lstat(canonical, &st) != 0 && errno == ENOENT);
        ASSERT(lstat(alias, &st) == 0 && S_ISREG(st.st_mode));
        PASS();
    } _test_next:;
    if (moved && rename(alias, canonical)) failures++;
    json_free(&doc); return failures;
}

static bool aso_plain_fork(const struct abc_world *w, struct abc_world *plain,
                           struct aso_build *selected)
{
    *plain = *w;
    (void)snprintf(plain->copy, sizeof(plain->copy), "%s/plain-fork", w->root);
    struct abc_leaf leaf; abc_open(&leaf);
    (void)json_push_kv_str(&leaf.in, "root", w->origin_release);
    (void)json_push_kv_str(&leaf.in, "destination", plain->copy);
    (void)json_push_kv_str(&leaf.in, "datadir", w->alice_datadir);
    bool ok = abc_plan_confirm("zcode.package.fork", &leaf);
    const char *version = abc_get(&leaf, "version");
    if (ok && strlen(version) == 64) memcpy(selected->version, version, 65);
    else ok = false;
    abc_close(&leaf);
    return ok;
}
static bool aso_foreign_commit(const struct abc_world *w)
{
    const struct vcs_snapshot_meta meta = {.phase = "merge", .task_ref = "zcode.merge:friend"};
    struct vcs_repo *repo = vcs_open(w->copy); uint8_t version[32];
    bool ok = repo && vcs_snapshot(repo, &meta, version) == VCS_OK;
    if (repo) vcs_close(repo);
    return ok;
}
static int aso_mcp_acceptance(const struct abc_world *w, const struct aso_build *b,
                              const char *head)
{
    int failures = 0; struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    struct json_value doc; json_init(&doc); bool is_error = false;
    struct abc_world plain; struct aso_build plain_build = *b;
    TEST("MCP apps_open runs saved version under adopted copy authority") {
        ASSERT(aso_mcp_spawn(&m) && aso_mcp_init(&m));
        ASSERT(aso_mcp_tool(&m, w, b, &doc, &is_error));
        const struct json_value *data = json_get(&doc, "data");
        aso_track_ready(data, b);
        ASSERT(!is_error && data && !strcmp(aso_string(data, "status"), "opened"));
        ASSERT(aso_build_facts_match(data, b));
        ASSERT(aso_string(data, "mapped_proof")[0] && strtoull(aso_string(data, "start_token"), NULL, 10));
        ASSERT(aso_head_and_dirty(w, head));
        json_free(&doc); json_init(&doc);
        ASSERT(aso_plain_fork(w, &plain, &plain_build));
        ASSERT(aso_mcp_tool(&m, &plain, &plain_build, &doc, &is_error));
        ASSERT(is_error && !strcmp(aso_string(json_get(&doc, "error"), "code"), "NOT_ADOPTED"));
        PASS();
    } _test_next:;
    if (!aso_mcp_close(&m)) failures++;
    json_free(&doc);
    return failures;
}

/* MCP preview is real stdio; Keep approval uses a per-invocation presenter.
 * Invalid DISPLAY is a Linux-only wire failure; Cocoa ignores DISPLAY. */
static int aso_keep_commit(const struct abc_world *w, const struct aso_build *b,
                           const struct aso_build *next, const char *head)
{
    int failures = 0; struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    struct json_value doc; json_init(&doc); bool error = false;
    TEST("MCP cannot keep without native owner approval; later preview preserves N") {
        ASSERT(aso_mcp_spawn(&m) && aso_mcp_init(&m));
        ASSERT(aso_mcp_tool(&m, w, b, &doc, &error));
        const struct json_value *data = json_get(&doc, "data");
        aso_track_ready(data, b);
        ASSERT(!error && aso_build_facts_match(data, b) && aso_revision_is(data, 0));
        int64_t expected = json_get_int(json_get(data, "selection_revision"));
        aso_doc_clear(&doc);
#if defined(__linux__)
        ASSERT(aso_mcp_call(&m, w, b, "apps_keep", expected, &doc, &error));
        ASSERT(error && aso_code_is(&doc, "KEEP_CONFIRMATION_UNAVAILABLE"));
        aso_doc_clear(&doc);
#endif
        for (unsigned mode = 1; mode <= 3; ++mode) {
            ASSERT(aso_owner_keep(w, b, expected, mode, &doc, &error));
            ASSERT(mode == 3 ? error && aso_code_is(&doc, "KEEP_CONFIRMATION_UNAVAILABLE") :
                !error && !strcmp(aso_string(json_get(&doc, "data"), "status"), "canceled"));
            struct app_launch_env env; struct app_selection kept; char why[256];
            ASSERT(app_launch_env_from_process(&env, why, sizeof(why)));
            ASSERT(app_selection_load(env.state_dir, "tiny-ready", &kept) == APP_SELECTION_ABSENT);
            aso_doc_clear(&doc);
        }
        ASSERT(aso_owner_keep(w, b, expected, 0, &doc, &error));
        data = json_get(&doc, "data");
        ASSERT(!error && !strcmp(aso_string(data, "status"), "kept"));
        ASSERT(aso_build_facts_match(data, b) && aso_revision_is(data, 1));
        aso_doc_clear(&doc);
        ASSERT(aso_mcp_call(&m, w, b, "apps_keep", expected, &doc, &error));
        ASSERT(error && aso_code_is(&doc, "SELECTION_STALE"));
        aso_doc_clear(&doc);
        ASSERT(aso_mcp_tool(&m, w, next, &doc, &error));
        data = json_get(&doc, "data");
        aso_track_ready(data, next);
        ASSERT(!error && aso_build_facts_match(data, next) && aso_revision_is(data, 1));
        ASSERT(aso_head_and_dirty(w, head));
        PASS();
    } _test_next:;
    if (!aso_mcp_close(&m)) failures++;
    json_free(&doc); return failures;
}
static int aso_keep_restart(const struct abc_world *w, const struct aso_build *b,
                            const char *head)
{
    int failures = 0; struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    struct json_value doc; json_init(&doc); bool error = false;
    TEST("fresh MCP server reopens the exact kept N without touching newer source") {
        ASSERT(aso_mcp_spawn(&m) && aso_mcp_init(&m));
        ASSERT(aso_mcp_call(&m, w, NULL, "apps_open", -1, &doc, &error));
        const struct json_value *data = json_get(&doc, "data");
        aso_track_ready(data, b);
        ASSERT(!error && !strcmp(aso_string(data, "status"), "opened"));
        ASSERT(aso_build_facts_match(data, b) && aso_revision_is(data, 1));
        ASSERT(aso_string(data, "mapped_proof")[0] && strtoull(aso_string(data, "start_token"), NULL, 10));
        ASSERT(aso_head_and_dirty(w, head));
        PASS();
    } _test_next:;
    if (!aso_mcp_close(&m)) failures++;
    json_free(&doc); return failures;
}
static int aso_owner_keep_races(const struct abc_world *w, const struct aso_build *next)
{
    int failures = 0;
    struct json_value doc; json_init(&doc); bool error = false;
    struct app_launch_env env; struct app_selection before, after; char why[256];
    struct stat original = {0}; bool restore = false;
    TEST("owner Keep rechecks selection CAS and image after the dialog") {
        ASSERT(app_launch_env_from_process(&env, why, sizeof(why)));
        ASSERT(app_selection_load(env.state_dir, "tiny-ready", &before) == APP_SELECTION_OK);
        ASSERT(aso_owner_keep(w, next, (int64_t)before.revision, 4, &doc, &error));
        ASSERT(error && aso_code_is(&doc, "SELECTION_STALE")); aso_doc_clear(&doc);
        ASSERT(app_selection_load(env.state_dir, "tiny-ready", &after) == APP_SELECTION_OK);
        ASSERT(after.revision == before.revision + 1 && !memcmp(after.version, before.version, 32));
        ASSERT(stat(next->image_path, &original) == 0); restore = true;
        ASSERT(aso_owner_keep(w, next, (int64_t)after.revision, 5, &doc, &error));
        ASSERT(error && aso_code_is(&doc, "IMAGE_REFUSED"));
        struct app_selection unchanged;
        ASSERT(app_selection_load(env.state_dir, "tiny-ready", &unchanged) == APP_SELECTION_OK);
        ASSERT(unchanged.revision == after.revision && !memcmp(unchanged.version, before.version, 32));
        PASS();
    } _test_next:;
    if (restore && truncate(next->image_path, original.st_size)) failures++;
    json_free(&doc); return failures;
}
static int aso_owner_keep_preserves(const struct abc_world *w, const struct aso_build *next)
{
    int failures = 0;
    struct app_launch_env env; struct app_selection before, after; char why[256];
    struct json_value doc; json_init(&doc); bool error = false;
    TEST("Cancel close and presenter failure preserve the complete existing Keep") {
        ASSERT(app_launch_env_from_process(&env, why, sizeof(why)));
        ASSERT(app_selection_load(env.state_dir, "tiny-ready", &before) == APP_SELECTION_OK);
        for (unsigned mode = 1; mode <= 3; ++mode) {
            ASSERT(aso_owner_keep(w, next, (int64_t)before.revision, mode, &doc, &error));
            ASSERT(mode == 3 ? error && aso_code_is(&doc, "KEEP_CONFIRMATION_UNAVAILABLE") :
                !error && !strcmp(aso_string(json_get(&doc, "data"), "status"), "canceled"));
            ASSERT(app_selection_load(env.state_dir, "tiny-ready", &after) == APP_SELECTION_OK);
            ASSERT(!memcmp(&before, &after, sizeof(before)));
            aso_doc_clear(&doc);
        }
        PASS();
    } _test_next:;
    json_free(&doc); return failures;
}
static bool aso_kept_catalog_refused(void)
{
    struct json_value input; json_init(&input); json_set_object(&input);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.catalog.v1");
    struct zcl_command_request request = {.input = &input};
    bool ok = json_push_kv_str(&input, "name", "tiny-ready") &&
        zcl_native_app_open_kept(&request, &reply) && reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, "CONFIG_REFUSED");
    zcl_command_reply_free(&reply); json_free(&input); return ok;
}
static int aso_bad_catalog(const struct abc_world *w, const struct aso_build *b)
{
    int failures = 0, fd = -1; off_t original = -1;
    char path[ABC_PATH];
    struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    struct json_value doc; json_init(&doc); bool error = false;
    (void)snprintf(path, sizeof(path), "%s/config/z23/apps.tsv", w->root);
    TEST("malformed catalog refuses explicit and kept selected opens") {
        fd = open(path, O_RDWR | O_APPEND);
        ASSERT(fd >= 0);
        original = lseek(fd, 0, SEEK_END);
        const char bad[] = "broken-row\n";
        ASSERT(original >= 0 && write(fd, bad, sizeof(bad) - 1) == (ssize_t)(sizeof(bad) - 1));
        ASSERT(aso_execute(w, b, "skycombat", true, NULL, NULL, &doc));
        ASSERT(aso_code_is(&doc, "CONFIG_REFUSED")); aso_doc_clear(&doc);
        ASSERT(aso_kept_catalog_refused());
        ASSERT(aso_mcp_spawn(&m) && aso_mcp_init(&m));
        ASSERT(aso_mcp_call(&m, w, NULL, "apps_open", -1, &doc, &error));
        ASSERT(error && aso_code_is(&doc, "CONFIG_REFUSED"));
        PASS();
    } _test_next:;
    if (!aso_mcp_close(&m)) failures++;
    if (fd >= 0) {
        if (original >= 0 && ftruncate(fd, original) != 0) failures++;
        if (close(fd) != 0) failures++;
    }
    json_free(&doc); return failures;
}

static int aso_keep_corruption(const struct abc_world *w)
{
    int failures = 0, fd = -1; bool changed = false;
    char path[ABC_PATH], original = 0;
    struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    struct json_value doc; json_init(&doc); bool error = false;
    (void)snprintf(path, sizeof(path), "%s/state/z23/apps/tiny-ready.selection", w->root);
    TEST("corrupt kept selection refuses name-only open instead of fallback") {
        fd = open(path, O_RDWR);
        ASSERT(fd >= 0 && pread(fd, &original, 1, 0) == 1);
        char bad = (char)(original ^ 0x40);
        ASSERT(pwrite(fd, &bad, 1, 0) == 1); changed = true;
        ASSERT(aso_mcp_spawn(&m) && aso_mcp_init(&m));
        ASSERT(aso_mcp_call(&m, w, NULL, "apps_open", -1, &doc, &error));
        ASSERT(error && aso_code_is(&doc, "SELECTION_UNREADABLE"));
        PASS();
    } _test_next:;
    if (!aso_mcp_close(&m)) failures++;
    if (changed && pwrite(fd, &original, 1, 0) != 1) failures++;
    if (fd >= 0) close(fd);
    json_free(&doc); return failures;
}

static int aso_kept_image_refusal(const struct abc_world *w)
{
    int failures = 0; struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    struct json_value doc; json_init(&doc); bool error = false;
    TEST("name-only open refuses a mutated kept image without builtin fallback") {
        ASSERT(aso_mcp_spawn(&m) && aso_mcp_init(&m));
        ASSERT(aso_mcp_call(&m, w, NULL, "apps_open", -1, &doc, &error));
        ASSERT(error && aso_code_is(&doc, "IMAGE_REFUSED"));
        PASS();
    } _test_next:;
    if (!aso_mcp_close(&m)) failures++;
    json_free(&doc); return failures;
}

static int aso_mcp_foreign(const struct abc_world *w, const struct aso_build *b)
{
    int failures = 0; struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    struct json_value doc; json_init(&doc); bool is_error = false;
    TEST("MCP apps_open refuses a copy with foreign history") {
        ASSERT(aso_foreign_commit(w));
        ASSERT(aso_mcp_spawn(&m) && aso_mcp_init(&m));
        ASSERT(aso_mcp_tool(&m, w, b, &doc, &is_error));
        ASSERT(is_error && !strcmp(aso_string(json_get(&doc, "error"), "code"), "NOT_ADOPTED"));
        aso_doc_clear(&doc);
        ASSERT(aso_mcp_call(&m, w, NULL, "apps_open", -1, &doc, &is_error));
        ASSERT(is_error && aso_code_is(&doc, "NOT_ADOPTED"));
        PASS();
    } _test_next:;
    if (!aso_mcp_close(&m)) failures++;
    json_free(&doc);
    return failures;
}

static int aso_fixture_setup(struct abc_world *w, struct aso_build *b,
                             struct aso_build *next, char head[65], bool long_label)
{
    int failures = 0; struct abc_leaf l;
    char config[ABC_PATH], state[ABC_PATH];
    TEST("selected app fixture publishes, adopts and builds a real saved version") {
        ASSERT(abc_world_init(w));
        ASSERT(abc_put(w->copy, "include/boost.h", "#define BOOST 2\n"));
        ASSERT(abc_save(w->copy, NULL));
        ASSERT(abc_build(&l, w->copy, w->alice_datadir));
        bool tuple = aso_tuple(&l, b); abc_close(&l); ASSERT(tuple);
        ASSERT(aso_config(w, b));
        (void)snprintf(config, sizeof(config), "%s/config", w->root);
        (void)snprintf(state, sizeof(state), "%s/state", w->root);
        ASSERT(setenv("XDG_CONFIG_HOME", config, 1) == 0 && setenv("XDG_STATE_HOME", state, 1) == 0);
        ASSERT(setenv("DISPLAY", ":synthetic-nonvisual", 1) == 0 && unsetenv("WAYLAND_DISPLAY") == 0);
        ASSERT(abc_put(w->copy, "include/boost.h", "#define BOOST 3\n"));
        if (long_label) {
            const char *tail = strstr(k_meta, "\",\n  \"semver\"");
            char meta[1024];
            ASSERT(tail);
            int n = snprintf(meta, sizeof(meta), "{\"schema\":1,\"name\":\"stub/%s%s",
                "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk", tail);
            ASSERT(n > 0 && (size_t)n < sizeof(meta) && abc_put(w->copy, "zcode-package.json", meta));
            next->long_label = true;
        }
        ASSERT(abc_save(w->copy, head));
        ASSERT(abc_build(&l, w->copy, w->alice_datadir));
        bool next_tuple = aso_tuple(&l, next); abc_close(&l); ASSERT(next_tuple);
        ASSERT(strcmp(next->version, b->version) != 0);
        ASSERT(abc_put(w->copy, "include/boost.h", "#define BOOST 4\n"));
        PASS();
    } _test_next:;
    return failures;
}

static int aso_before_keep(const struct abc_world *w, const struct aso_build *b, const char *head)
{
    int failures = 0;
    if (!failures) failures += aso_success(w, b, head);
    if (!failures) failures += aso_refusals(w, b);
    if (!failures) failures += aso_failure_cases(w, b);
    if (!failures) failures += aso_mcp_acceptance(w, b, head);
    if (!failures) failures += aso_keep_readonly(w, b);
    if (!failures) failures += aso_keep_missing_alias(w, b);
    return failures;
}
static int aso_journey(const struct abc_world *w, const struct aso_build *b,
                       const struct aso_build *next, const char *head)
{
    int failures = aso_before_keep(w, b, head);
    if (!failures) failures += aso_keep_commit(w, b, next, head);
    if (!failures) failures += aso_keep_restart(w, b, head);
    if (!failures) failures += aso_bad_catalog(w, b);
    if (!failures) failures += aso_owner_keep_preserves(w, next);
    if (!aso_cleanup_children()) failures++;
    if (!failures) failures += aso_owner_keep_races(w, next);
    if (!failures) failures += aso_keep_corruption(w);
    if (!aso_cleanup_children()) failures++;
    if (!failures) failures += aso_mutation(w, b);
    if (!failures) failures += aso_kept_image_refusal(w);
    if (!failures) failures += aso_mcp_foreign(w, b);
    return failures;
}

static int ak_routes(void);
int test_app_open_selected(void)
{
    int failures = 0;
    struct aso_env env[] = {{"HOME", NULL}, {"XDG_CONFIG_HOME", NULL}, {"XDG_STATE_HOME", NULL},
                            {"DISPLAY", NULL}, {"WAYLAND_DISPLAY", NULL}};
    size_t saved = 0;
    for (; saved < sizeof(env) / sizeof(env[0]); ++saved) {
        const char *v = getenv(env[saved].key);
        env[saved].saved = v ? strdup(v) : NULL;
        if (v && !env[saved].saved) { failures++; break; }
    }
    struct abc_world w = {0}; struct aso_build b = {0}, next = {0};
    char head[65] = {0};
    chain_params_select(CHAIN_MAIN);
    if (!failures) failures += aso_fixture_setup(&w, &b, &next, head, true);
    if (!failures) failures += aso_journey(&w, &b, &next, head);
    aso_env_restore(env, saved);
    if (w.root[0]) (void)test_rm_rf_recursive(w.root);
    failures += ak_routes();
    return failures;
}

/* Synthetic nonvisual process journey: no graphical or public-link claim. */
static bool aj_mcp_result(const struct json_value *result, struct json_value *doc, bool *is_error)
{
    const struct json_value *r = json_get(result, "result");
    const struct json_value *part = json_at(json_get(r, "content"), 0);
    const char *text = json_get_str(json_get(part, "text"));
    const struct json_value *flag = json_get(r, "isError");
    if (!flag || flag->type != JSON_BOOL || !text || !json_read(doc, text, strlen(text))) return false;
    *is_error = json_get_bool(flag); return true;
}
static bool aj_mcp_run_result(struct aso_mcp *m, const char *path,
    const struct json_value *input, struct json_value *doc, bool *is_error)
{
    struct json_value req, params, args, result;
    json_init(&req); json_init(&params); json_init(&args); json_init(&result);
    json_set_object(&req); json_set_object(&params); json_set_object(&args);
    bool ok = json_push_kv_str(&args, "path", path) && json_push_kv(&args, "input", input) &&
        json_push_kv_str(&params, "name", "z23_run") && json_push_kv(&params, "arguments", &args) &&
        json_push_kv_str(&req, "jsonrpc", "2.0") && json_push_kv_int(&req, "id", 8) &&
        json_push_kv_str(&req, "method", "tools/call") && json_push_kv(&req, "params", &params);
    char wire[8192]; size_t n = ok ? json_write(&req, wire, sizeof(wire)) : 0;
    ok = n && n < sizeof(wire) && aso_mcp_send(m, wire, true) &&
        json_read(&result, m->line, strlen(m->line));
    ok = ok && aj_mcp_result(&result, doc, is_error);
    json_free(&result); json_free(&args); json_free(&params); json_free(&req);
    return ok;
}
static bool aj_mcp_run(struct aso_mcp *m, const char *path,
                       const struct json_value *input, struct json_value *doc)
{
    bool is_error = false;
    return aj_mcp_run_result(m, path, input, doc, &is_error) && !is_error;
}

static bool aj_edit_input(struct json_value *in, const char *head, const char *blob)
{
    json_init(in); json_set_object(in);
    return json_push_kv_str(in, "name", "tiny-ready") &&
        json_push_kv_int(in, "expected_revision", 1) && json_push_kv_str(in, "expected_head", head) &&
        json_push_kv_str(in, "path", "include/boost.h") && json_push_kv_str(in, "expected_blob", blob) &&
        json_push_kv_str(in, "content", "#define BOOST 9\n");
}
static bool aj_edit(struct aso_mcp *m, const char *head, char version[65])
{
    struct json_value in, doc; json_init(&in); json_init(&doc); json_set_object(&in);
    bool ok = json_push_kv_str(&in, "name", "tiny-ready") && json_push_kv_int(&in, "expected_revision", 1) &&
        json_push_kv_str(&in, "path", "include/boost.h") && aj_mcp_run(m, "app.customize", &in, &doc);
    const struct json_value *data = json_get(&doc, "data");
    const struct json_value *file = json_get(data, "file");
    char blob[65]; snprintf(blob, sizeof(blob), "%s", aso_string(file, "blob"));
    ok = ok && !strcmp(aso_string(data, "content"), "#define BOOST 2\n") && strlen(blob) == 64;
    json_free(&in); aso_doc_clear(&doc);
    if (ok) ok = aj_edit_input(&in, head, blob) && aj_mcp_run(m, "app.edit", &in, &doc);
    char plan[65]; snprintf(plan, sizeof(plan), "%s", aso_string(json_get(&doc, "data"), "plan_id"));
    ok = ok && strlen(plan) == 64;
    aso_doc_clear(&doc);
    if (ok) ok = json_push_kv_str(&in, "plan_id", plan) && json_push_kv_bool(&in, "confirm", true) &&
        aj_mcp_run(m, "app.edit", &in, &doc);
    snprintf(version, 65, "%s", aso_string(json_get(&doc, "data"), "version"));
    ok = ok && strlen(version) == 64;
    json_free(&in); json_free(&doc); return ok;
}
static bool aj_make_ran(const struct json_value *data)
{
    const struct json_value *made = json_get(data, "make_ran");
    return made && made->type == JSON_BOOL && json_get_bool(made);
}
static bool aj_build(struct aso_mcp *m, const struct abc_world *w, const char *version, struct aso_build *out)
{
    struct json_value in, doc; json_init(&in); json_init(&doc); json_set_object(&in);
    bool ok = json_push_kv_str(&in, "copy", w->copy) && json_push_kv_str(&in, "datadir", w->alice_datadir) &&
        json_push_kv_str(&in, "version", version) && aj_mcp_run(m, "app.build", &in, &doc);
    char plan[65]; snprintf(plan, sizeof(plan), "%s", aso_string(json_get(&doc, "data"), "plan_id"));
    ok = ok && strlen(plan) == 64; aso_doc_clear(&doc);
    if (ok) ok = json_push_kv_str(&in, "plan_id", plan) && json_push_kv_bool(&in, "confirm", true) &&
        aj_mcp_run(m, "app.build", &in, &doc);
    const struct json_value *data = json_get(&doc, "data");
    ok = ok && aj_make_ran(data);
    const char *keys[] = {"version", "package_root", "env_root", "dependency_root", "image_sha3", "record_id"};
    char *values[] = {out->version, out->package, out->env, out->deps, out->image, out->record};
    for (size_t i = 0; ok && i < 6; ++i) {
        const char *v = aso_string(data, keys[i]);
        ok = strlen(v) == 64;
        if (ok) memcpy(values[i], v, 65);
    }
    const char *path = aso_string(data, "image_path");
    if (ok) ok = strlen(path) < sizeof(out->image_path) && !strcmp(out->version, version);
    if (ok) strcpy(out->image_path, path);
    json_free(&in); json_free(&doc); return ok;
}

struct aj_parent_check { uint8_t child[32], parent[32]; bool found; };
static bool aj_parent_visit(const struct vcs_commit *commit, const uint8_t id[32], void *arg)
{
    struct aj_parent_check *check = arg;
    if (!memcmp(id, check->child, 32)) {
        check->found = !memcmp(commit->parent, check->parent, 32);
        return false;
    }
    return true;
}
static bool aj_parent_is(const struct abc_world *w, const char *child, const char *parent)
{
    struct aj_parent_check check = {0};
    if (!zcl_hex_decode_lower(child, check.child, 32) ||
        !zcl_hex_decode_lower(parent, check.parent, 32)) return false;
    struct vcs_repo *repo = vcs_open_readonly(w->copy);
    if (!repo) return false;
    bool ok = vcs_log(repo, 0, aj_parent_visit, &check) == VCS_OK && check.found;
    vcs_close(repo); return ok;
}
static bool aj_personalize(struct abc_world *w, const char *edited, char personalized[65])
{
    struct abc_leaf l; abc_open(&l);
    bool ok = json_push_kv_str(&l.in, "copy", w->copy) &&
        json_push_kv_str(&l.in, "datadir", w->alice_datadir) &&
        json_push_kv_str(&l.in, "version", edited) &&
        json_push_kv_str(&l.in, "expected_head", edited) &&
        abc_plan_confirm("app.personalize", &l);
    snprintf(personalized, 65, "%s", abc_get(&l, "version"));
    const struct json_value *created = json_get(&l.out.data, "key_created");
    ok = ok && strlen(personalized) == 64 && strcmp(personalized, edited) &&
        abc_get(&l, "namespace")[0] && created && created->type == JSON_BOOL;
    abc_close(&l); return ok;
}

/* Backend setup only for the independent pre-Keep received-route fixture. */
static bool ak_share_backend(struct abc_world *w, const struct aso_build *draft, char fingerprint[67], char release[65])
{
    struct abc_leaf l; abc_open(&l);
    bool ok = json_push_kv_str(&l.in, "dir", w->copy) && json_push_kv_str(&l.in, "datadir", w->alice_datadir) &&
        json_push_kv_str(&l.in, "output", w->share_file) && json_push_kv_str(&l.in, "version", draft->version) &&
        json_push_kv_int(&l.in, "day", ABC_DAY + 7) && abc_plan_confirm("zcode.package.bundle.sign", &l);
    if (ok) {
        snprintf(fingerprint, 67, "%s", abc_get(&l, "publisher_fingerprint"));
        snprintf(release, 65, "%s", abc_get(&l, "release_id"));
        ok = strlen(fingerprint) == 66 && strlen(release) == 64 &&
            !strcmp(abc_get(&l, "version"), draft->version) && !strcmp(abc_get(&l, "package_root"), draft->package);
    }
    abc_close(&l); return ok;
}
static bool aj_received_lineage(struct abc_world *w, const char *release)
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.journey.v1");
    bool opened = zcl_package_copy_open_selected_as(w->bob_copy, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "journey", NULL);
    uint8_t expected[32];
    bool ok = opened && zcl_hex_decode_lower(release, expected, 32) && !memcmp(copy.parent_release, expected, 32);
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply); return ok;
}
static bool aj_receive_plan(struct abc_leaf *l, const struct abc_world *w,
    const char *fingerprint, const char *root, const char *release)
{
    return abc_as(w->bob_home) && json_push_kv_str(&l->in, "file", w->share_file) &&
        json_push_kv_str(&l->in, "datadir", w->bob_datadir) &&
        json_push_kv_str(&l->in, "destination", w->bob_copy) &&
        json_push_kv_int(&l->in, "day", ABC_DAY + 7) &&
        abc_pass("zcode.package.bundle.receive", l) &&
        !strcmp(abc_get(l, "package_root"), root) &&
        !strcmp(abc_get(l, "release_id"), release) &&
        !strcmp(abc_get(l, "publisher_fingerprint"), fingerprint);
}
static bool aj_receive_action(const struct zcl_present_window_live_view_v1 *live,
    unsigned index, bool *close, bool *redraw)
{
    struct zcl_present_input_v1 input = {.key = ZCL_PRESENT_INPUT_TEXT, .character = '1' + index};
    uint32_t focus = UINT32_MAX, action = UINT32_MAX;
    if (!live->input(live->owner.context, &input, &focus, &action) || action != index) return false;
    struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = action};
    live->owner.update(live->owner.context, &event, true, redraw, close);
    return true;
}
static bool aj_receive_field(const struct zcl_present_model_v1 *m, const char *label, const char *expected)
{
    char actual[4400] = {0};
    size_t used = 0;
    bool found = false;
    for (uint32_t i = 0; i < m->item_count; ++i) {
        const char *text = m->items[i].value;
        if (!found) {
            if (strncmp(text, label, strlen(label))) continue;
            text += strlen(label); found = true;
        } else {
            if (strncmp(text, "  ", 2)) break;
            text += 2;
        }
        size_t len = strlen(text);
        if (len >= sizeof(actual) - used) return false;
        memcpy(actual + used, text, len + 1); used += len;
    }
    return found && !strcmp(actual, expected);
}
struct aj_receive_view {
    const char *publisher, *package, *release, *destination;
    char parent[65];
    bool observed, visited, confirmed;
};
static bool aj_receive_fields(const struct zcl_present_model_v1 *model,
    const struct aj_receive_view *view)
{
    const char *labels[] = {"Publisher: ", "Package: ", "Release: ", "Destination: "};
    const char *values[] = {view->publisher, view->package, view->release, view->destination};
    for (size_t i = 0; i < 4; ++i)
        if (!aj_receive_field(model, labels[i], values[i])) return false;
    const char *parent = view->parent[0] ? view->parent : "None (first release)";
    return aj_receive_field(model, "Parent release: ", parent);
}
/* real-clock: observe the already-consented native worker without changing
 * the joined fixture's verified confirmation fields or authorizing new work. */
static bool aj_receive_progress(const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live)
{
    if (strcmp(model->title, "Receiving your copy") || pages->page_count != 1 || !pages->pages[0].pixels) return false;
    int64_t end = platform_time_monotonic_ms() + 5000;
    do {
        bool redraw = false, close = false;
        live->owner.update(live->owner.context, NULL, false, &redraw, &close);
        if (close) return true;
        platform_sleep_ms(1); /* real-clock: poll native commit completion */
    } while (platform_time_monotonic_ms() < end);
    return false;
}
static bool aj_receive_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    if (!strcmp(model->request_id, "receive-copy")) return aj_receive_progress(model, pages, live);
    struct aj_receive_view *view = context;
    uint32_t count = 0;
    view->observed = pages && pages->page_count == 1 && pages->pages->pixels &&
        zcl_present_model_page_count_v1(model, &count, why, cap) && count > 1 &&
        aj_receive_fields(model, view);
    if (!view->observed) return false;
    bool close = false, redraw = false;
    if (!aj_receive_early_guided(live)) return false;
    for (uint32_t i = 2; i < count; ++i)
        if (!aj_receive_action(live, 2, &close, &redraw) || close || !redraw) return false;
    view->visited = true;
    view->confirmed = aj_receive_action(live, 3, &close, &redraw) && close;
    return view->confirmed;
}
static bool aj_receive_parent(const struct json_value *data, struct aj_receive_view *view)
{
    const struct json_value *parent = json_get(data, "parent_release_root");
    if (!parent) return true;
    const char *text = parent->type == JSON_STR ? json_get_str(parent) : NULL;
    uint8_t root[32];
    if (!text || strlen(text) != 64 || !zcl_hex_decode_lower(text, root, 32)) return false;
    memcpy(view->parent, text, 65);
    return true;
}
static bool aj_receive_frontdoor(struct abc_leaf *leaf, struct aj_receive_view *view)
{
    const struct zcl_command_spec *spec = abc_spec("app.receive");
    char why[256] = "app.receive unavailable";
    if (!spec || !zcl_command_registry_input_validate(spec, &leaf->in, why, sizeof(why))) {
        printf("  [joined app.receive input refused: %s]\n", why);
        return false;
    }
    leaf->req.spec = spec;
    leaf->req.input = &leaf->in;
    leaf->req.invoked_name = spec->path;
    zcl_command_reply_free(&leaf->out);
    zcl_command_reply_init(&leaf->out, "zcl.app_receive.v1");
    zcl_test_app_receive_run(&leaf->req, &leaf->out, aj_receive_present, view);
    size_t bytes = json_write(&leaf->out.data, NULL, 0) + 1024u;
    bool fits = !spec->budget_bytes || bytes <= (size_t)spec->budget_bytes;
    bool ok = fits && leaf->out.status == ZCL_COMMAND_STATUS_PASSED && leaf->out.exit_code == 0 &&
        !strcmp(abc_get(leaf, "stage"), "commit") && view->observed && view->visited && view->confirmed;
    if (!ok)
        printf("  [joined app.receive status=%d exit=%d outcome=%s code=%s reason=%s observed=%d visited=%d confirmed=%d]\n",
            (int)leaf->out.status, leaf->out.exit_code, abc_get(leaf, "stage"),
            leaf->out.error.code, leaf->out.error.message, view->observed, view->visited, view->confirmed);
    return ok;
}
static bool aj_receive(struct abc_world *w, const char *fingerprint, const char *root, const char *release)
{
    struct abc_leaf leaf; abc_open(&leaf);
    struct aj_receive_view view = {
        .publisher = fingerprint, .package = root, .release = release, .destination = w->bob_copy,
    };
    /* Read-only verified plan supplies the optional actual parent; only the
     * per-invocation native presenter authorizes the subsequent receive. */
    bool ok = aj_receive_plan(&leaf, w, fingerprint, root, release) &&
        aj_receive_parent(&leaf.out.data, &view) && aj_receive_frontdoor(&leaf, &view);
    abc_close(&leaf);
    return ok && aj_received_lineage(w, release);
}
struct aj_share_view {
    const struct aso_build *draft;
    const char *output;
    char publisher[67], release[65], plan[65];
    bool observed, visited, confirmed;
};
static bool aj_share_expected(struct abc_world *w, struct aj_share_view *view)
{
    struct abc_leaf leaf; abc_open(&leaf);
    char key[4400]; bool exists = false;
    bool ok = app_personalize_key_probe(&leaf.out, key, sizeof(key), view->publisher, &exists) &&
        exists && strlen(view->publisher) == 66;
    ok = ok && json_push_kv_str(&leaf.in, "dir", w->copy) &&
        json_push_kv_str(&leaf.in, "datadir", w->alice_datadir) &&
        json_push_kv_str(&leaf.in, "version", view->draft->version) &&
        json_push_kv_str(&leaf.in, "publisher_pubkey", view->publisher) &&
        json_push_kv_str(&leaf.in, "output", view->output) && abc_pass("zcode.package.share", &leaf);
    if (ok) {
        (void)snprintf(view->release, sizeof(view->release), "%s", abc_get(&leaf, "signing_digest"));
        (void)snprintf(view->plan, sizeof(view->plan), "%s", abc_get(&leaf, "plan_id"));
        ok = strlen(view->release) == 64 && strlen(view->plan) == 64 &&
            !strcmp(abc_get(&leaf, "version"), view->draft->version) &&
            !strcmp(abc_get(&leaf, "package_root"), view->draft->package);
    }
    abc_close(&leaf);
    return ok;
}
static bool aj_share_fields(const struct zcl_present_model_v1 *model, const struct aj_share_view *view)
{
    const char *labels[] = {"Saved version: ", "Package: ", "Publisher: ", "Release: ", "Output: "};
    const char *values[] = {view->draft->version, view->draft->package, view->publisher, view->release, view->output};
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); ++i)
        if (!aj_receive_field(model, labels[i], values[i])) return false;
    char request_id[32];
    (void)snprintf(request_id, sizeof(request_id), "share-%.12s", view->plan);
    return !model->exact_root[0] && !strcmp(model->request_id, request_id);
}
static bool aj_share_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct aj_share_view *view = context;
    uint32_t count = 0;
    view->observed = pages && pages->page_count == 1 && pages->pages->pixels &&
        zcl_present_model_page_count_v1(model, &count, why, cap) && count > 1 &&
        aj_share_fields(model, view);
    if (!view->observed) return false;
    bool close = false, redraw = false;
    if (!aj_receive_early_guided(live)) return false;
    for (uint32_t i = 2; i < count; ++i)
        if (!aj_receive_action(live, 2, &close, &redraw) || close || !redraw) return false;
    view->visited = true;
    view->confirmed = aj_receive_action(live, 3, &close, &redraw) && close;
    return view->confirmed;
}
static bool aj_share_result(struct abc_leaf *leaf, const struct aj_share_view *view)
{
    return leaf->out.status == ZCL_COMMAND_STATUS_PASSED && leaf->out.exit_code == 0 &&
        view->observed && view->visited && view->confirmed &&
        !strcmp(abc_get(leaf, "version"), view->draft->version) &&
        !strcmp(abc_get(leaf, "package_root"), view->draft->package) &&
        !strcmp(abc_get(leaf, "publisher_fingerprint"), view->publisher) &&
        !strcmp(abc_get(leaf, "release_id"), view->release) &&
        !strcmp(abc_get(leaf, "share_file"), view->output);
}
static bool aj_share_run(struct abc_leaf *leaf, struct aj_share_view *view)
{
    const struct zcl_command_spec *spec = abc_spec("app.share");
    char why[256] = "app.share unavailable";
    if (!spec || !zcl_command_registry_input_validate(spec, &leaf->in, why, sizeof(why))) {
        printf("  [joined app.share input refused: %s]\n", why);
        return false;
    }
    leaf->req.spec = spec; leaf->req.input = &leaf->in; leaf->req.invoked_name = spec->path;
    zcl_test_app_share_run(&leaf->req, &leaf->out, aj_share_present, view);
    size_t bytes = json_write(&leaf->out.data, NULL, 0) + 1024u;
    bool fits = !spec->budget_bytes || bytes <= (size_t)spec->budget_bytes;
    bool ok = fits && aj_share_result(leaf, view);
    if (!ok)
        printf("  [joined app.share status=%d exit=%d code=%s reason=%s observed=%d visited=%d confirmed=%d]\n",
            (int)leaf->out.status, leaf->out.exit_code, leaf->out.error.code, leaf->out.error.message,
            view->observed, view->visited, view->confirmed);
    return ok;
}
static bool aj_share(struct abc_world *w, const struct aso_build *draft, char fingerprint[67], char release[65])
{
    struct aj_share_view view = {.draft = draft, .output = w->share_file};
    if (!aj_share_expected(w, &view)) return false;
    struct abc_leaf leaf; abc_open(&leaf);
    bool ok = json_push_kv_str(&leaf.in, "name", "tiny-ready") &&
        json_push_kv_str(&leaf.in, "output", w->share_file) && aj_share_run(&leaf, &view);
    if (ok) { memcpy(fingerprint, view.publisher, 67); memcpy(release, view.release, 65); }
    abc_close(&leaf);
    return ok;
}

static bool aj_bob_source(const struct abc_world *w)
{
    char path[ABC_PATH], *text = NULL; size_t size = 0;
    int n = snprintf(path, sizeof(path), "%s/include/boost.h", w->bob_copy);
    bool ok = n > 0 && (size_t)n < sizeof(path) &&
        zcl_read_whole_file_text(path, 512, &text, &size, "journey bob source") &&
        size == strlen("#define BOOST 9\n") && !memcmp(text, "#define BOOST 9\n", size);
    free(text); return ok;
}
static bool aj_history_preserved(const struct abc_world *w, const char *previous, const char *candidate)
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.journey.v1");
    bool ok = zcl_package_copy_open_selected_as(w->copy, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "journey", previous);
    char actual[65] = {0};
    if (ok) zcl_hex_encode(copy.head_version, 32, actual);
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply);
    return ok && !strcmp(actual, candidate) && aso_head_and_dirty(w, candidate);
}
static bool aj_exact_line(const char *text, const char *expected)
{
    size_t n = strlen(expected);
    for (const char *line = text; *line;) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        if (len == n && !memcmp(line, expected, n)) return true;
        if (!end) break;
        line = end + 1;
    }
    return false;
}
static bool aj_log_has(const struct json_value *data, const char *expected)
{
    const char *path = aso_string(data, "log");
    char *text = NULL; size_t size = 0;
    bool ok = path[0] && zcl_read_whole_file_text(path, 65536, &text, &size, "journey log") &&
        aj_exact_line(text, expected);
    free(text); return ok;
}
static bool aj_start_token(const struct json_value *data, uint64_t *token)
{
    const char *text = aso_string(data, "start_token");
    if (!text[0] || text[0] < '0' || text[0] > '9') return false;
    char *end = NULL; errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !end || *end || !value) return false;
    *token = (uint64_t)value; return true;
}
static bool aj_live_identity(const struct json_value *data, const struct aso_build *build)
{
    const struct json_value *pid = json_get(data, "pid"); uint64_t expected = 0;
    if (!pid || pid->type != JSON_INT || json_get_int(pid) <= 1 ||
        json_get_int(pid) > LONG_MAX || !aj_start_token(data, &expected)) return false;
    char exe[APP_LAUNCH_PATH_MAX]; uint64_t actual = 0;
    return app_proc_identity((long)json_get_int(pid), exe, &actual) &&
        actual == expected && !strcmp(exe, build->image_path);
}
static bool aj_ready(const struct json_value *data, const struct aso_build *build)
{
    const struct json_value *ready = json_get(data, "ready");
    return ready && ready->type == JSON_BOOL && json_get_bool(ready) &&
        !strcmp(aso_string(data, "status"), "opened") &&
        !strcmp(aso_string(data, "ready_basis"), "marker") &&
        aso_string(data, "mapped_proof")[0] && aso_build_facts_match(data, build) &&
        aj_live_identity(data, build);
}
static bool aj_image_digest(const struct aso_build *build)
{
    uint8_t *bytes = NULL; size_t size = 0; uint8_t digest[32]; char hex[65];
    bool ok = zcl_read_whole_file(build->image_path, 64u * 1024u * 1024u,
                                  &bytes, &size, "journey image");
    if (ok) { sha3_256(bytes, size, digest); zcl_hex_encode(digest, 32, hex); ok = !strcmp(hex, build->image); }
    free(bytes); return ok;
}
static bool aj_distinct_images(const struct aso_build *a, const struct aso_build *b)
{
    struct stat left, right;
    return strcmp(a->image_path, b->image_path) && stat(a->image_path, &left) == 0 &&
        stat(b->image_path, &right) == 0 &&
        (left.st_dev != right.st_dev || left.st_ino != right.st_ino) &&
        aj_image_digest(a) && aj_image_digest(b);
}
static bool aj_bob_open(struct abc_world *w, const struct aso_build *draft,
    struct aso_mcp *m, struct json_value *doc, bool *error)
{
    struct abc_leaf l; struct aso_build bob_build = {0};
    if (!abc_build(&l, w->bob_copy, w->bob_datadir)) { abc_close(&l); return false; }
    bool tuple = aso_tuple(&l, &bob_build);
    const struct json_value *made = json_get(&l.out.data, "make_ran");
    bool built = made && made->type == JSON_BOOL && json_get_bool(made);
    abc_close(&l);
    if (!tuple || !built || strcmp(bob_build.package, draft->package) ||
        !aj_distinct_images(draft, &bob_build)) return false;
    struct abc_world bob = *w;
    snprintf(bob.copy, sizeof(bob.copy), "%s", w->bob_copy);
    snprintf(bob.alice_datadir, sizeof(bob.alice_datadir), "%s", w->bob_datadir);
    if (!aso_mcp_close(m)) return false;
    char state[ABC_PATH]; snprintf(state, sizeof(state), "%s/state", w->bob_home);
    if (setenv("XDG_STATE_HOME", state, 1) != 0 || !aso_mcp_spawn(m) || !aso_mcp_init(m)) return false;
    if (!aso_mcp_tool(m, &bob, &bob_build, doc, error)) return false;
    aso_track_ready(json_get(doc, "data"), &bob_build);
    return !*error && aj_ready(json_get(doc, "data"), &bob_build) &&
        aj_log_has(json_get(doc, "data"), "BOOST=9");
}
static bool aj_alice_reopen(struct abc_world *w, const struct aso_build *draft,
    const char *head, struct aso_mcp *m, struct json_value *doc, bool *error)
{
    if (!aso_mcp_close(m) || !abc_as(w->alice_home)) return false;
    char state[ABC_PATH]; snprintf(state, sizeof(state), "%s/state", w->root);
    if (setenv("XDG_STATE_HOME", state, 1) != 0 || !aso_mcp_spawn(m) || !aso_mcp_init(m)) return false;
    aso_doc_clear(doc);
    if (!aso_mcp_call(m, w, NULL, "apps_open", -1, doc, error)) return false;
    aso_track_ready(json_get(doc, "data"), draft);
    return !*error && aj_ready(json_get(doc, "data"), draft) &&
        aso_revision_is(json_get(doc, "data"), 2) && aj_log_has(json_get(doc, "data"), "BOOST=9") &&
        aj_history_preserved(w, head, draft->version);
}
static bool aj_owner_keep(struct aso_mcp *m, const struct abc_world *w,
    const struct aso_build *build, int64_t revision, struct json_value *doc, bool *error)
{
#if defined(__linux__)
    if (!aso_mcp_call(m, w, build, "apps_keep", revision, doc, error) ||
        !*error || !aso_code_is(doc, "KEEP_CONFIRMATION_UNAVAILABLE")) return false;
    aso_doc_clear(doc);
#else
    (void)m; /* Native presenter acceptance below is portable; DISPLAY is not. */
#endif
    return aso_owner_keep(w, build, revision, 0, doc, error) && !*error &&
        aso_revision_is(json_get(doc, "data"), revision + 1);
}
static int aj_steps(struct abc_world *w, const struct aso_build *old, const char *head)
{
    int failures = 0; struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    struct json_value doc; json_init(&doc); bool error = false;
    struct aso_build draft = {0}; char candidate[65], personal[65], fp[67], release[65];
    TEST("MCP pinned edit, preview, Keep, share and independent recipient") {
        ASSERT(aso_mcp_spawn(&m) && aso_mcp_init(&m));
        ASSERT(aso_mcp_tool(&m, w, old, &doc, &error));
        aso_track_ready(json_get(&doc, "data"), old);
        ASSERT(!error && aso_build_facts_match(json_get(&doc, "data"), old)); aso_doc_clear(&doc);
        ASSERT(aj_owner_keep(&m, w, old, 0, &doc, &error)); aso_doc_clear(&doc);
        ASSERT(aj_edit(&m, head, candidate));
        ASSERT(aj_history_preserved(w, head, candidate) && aj_parent_is(w, candidate, head));
        ASSERT(aj_personalize(w, candidate, personal));
        ASSERT(aj_history_preserved(w, candidate, personal) && aj_parent_is(w, personal, candidate));
        ASSERT(aso_mcp_call(&m, w, NULL, "apps_open", -1, &doc, &error));
        aso_track_ready(json_get(&doc, "data"), old);
        ASSERT(!error && aso_build_facts_match(json_get(&doc, "data"), old)); aso_doc_clear(&doc);
        ASSERT(aj_build(&m, w, personal, &draft));
        ASSERT(aso_mcp_tool(&m, w, &draft, &doc, &error));
        aso_track_ready(json_get(&doc, "data"), &draft);
        ASSERT(!error && aj_ready(json_get(&doc, "data"), &draft) &&
            aj_log_has(json_get(&doc, "data"), "BOOST=9")); aso_doc_clear(&doc);
        ASSERT(aso_mcp_call(&m, w, NULL, "apps_open", -1, &doc, &error));
        aso_track_ready(json_get(&doc, "data"), old);
        ASSERT(!error && aso_build_facts_match(json_get(&doc, "data"), old) &&
            aj_log_has(json_get(&doc, "data"), "BOOST=2")); aso_doc_clear(&doc);
        ASSERT(aj_owner_keep(&m, w, &draft, 1, &doc, &error)); aso_doc_clear(&doc);
        ASSERT(aso_cleanup_children());
        ASSERT(aj_share(w, &draft, fp, release));
        ASSERT(aj_receive(w, fp, draft.package, release) && aj_bob_source(w));
        ASSERT(aj_bob_open(w, &draft, &m, &doc, &error));
        ASSERT(aj_alice_reopen(w, &draft, head, &m, &doc, &error));
        PASS();
    } _test_next:;
    if (!aso_mcp_close(&m)) failures++;
    json_free(&doc);
    if (!aso_cleanup_children()) failures++;
    return failures;
}
/* Independent no-catalog receive/build/Keep fixture; synthetic DISPLAY, no GUI claim. */
#define AK_ROUTE "kept:received"
struct ak_fixture {
    struct abc_world world;
    struct aso_build build;
    struct app_launch_env env;
    char release[65], trust[APP_SELECTION_PATH_MAX];
};
static bool ak_build_tuple(const char *copy, const char *datadir, struct aso_build *build)
{
    struct abc_leaf leaf;
    bool ok = abc_build(&leaf, copy, datadir) && aso_tuple(&leaf, build);
    abc_close(&leaf);
    return ok;
}
static bool ak_build_saved_tuple(const struct abc_world *w, const char *version,
    struct aso_build *build)
{
    struct abc_leaf leaf;
    abc_build_input(&leaf, w->copy, w->alice_datadir);
    bool ok = json_push_kv_str(&leaf.in, "version", version) &&
        abc_plan_confirm("app.build", &leaf) && aso_tuple(&leaf, build);
    ok = ok && !strcmp(build->version, version);
    abc_close(&leaf);
    return ok;
}
static bool ak_received_source(struct ak_fixture *fixture, const char *source)
{
    struct abc_world *w = &fixture->world;
    char version[65], personal[65], publisher[67]; struct aso_build sender;
    if (!abc_world_init(w) || !abc_put(w->copy, "src/main.c", source) ||
        !abc_save(w->copy, version) || !aj_personalize(w, version, personal) ||
        !ak_build_saved_tuple(w, personal, &sender)) return false;
    if (!ak_share_backend(w, &sender, publisher, fixture->release) ||
        !aj_receive(w, publisher, sender.package, fixture->release) ||
        !ak_build_tuple(w->bob_copy, w->bob_datadir, &fixture->build)) return false;
    int n = snprintf(fixture->trust, sizeof(fixture->trust), "%s/zcode/received/%s.%s.trust",
        w->bob_datadir, fixture->build.version, fixture->release);
    return n > 0 && (size_t)n < sizeof(fixture->trust);
}
static bool ak_received(struct ak_fixture *fixture)
{
    const char *source = "#include <stdio.h>\n#include <unistd.h>\n"
        "int main(int argc,char **argv){(void)argv;if(argc!=1)return 7;"
        "puts(\"NO-ARGS\");fflush(stdout);for(;;)pause();}\n";
    return ak_received_source(fixture, source);
}
static bool ak_environment(struct ak_fixture *fixture)
{
    char config[ABC_PATH], state[ABC_PATH], why[256];
    (void)snprintf(config, sizeof(config), "%s/config", fixture->world.bob_home);
    (void)snprintf(state, sizeof(state), "%s/state", fixture->world.bob_home);
    if (setenv("XDG_CONFIG_HOME", config, 1) || setenv("XDG_STATE_HOME", state, 1) ||
        setenv("DISPLAY", ":synthetic-kept-route", 1) || unsetenv("WAYLAND_DISPLAY")) return false;
    if (!app_launch_env_from_process(&fixture->env, why, sizeof(why))) return false;
    struct stat st;
    return lstat(fixture->env.config_path, &st) != 0 && errno == ENOENT;
}
static bool ak_request(struct abc_leaf *leaf, const struct ak_fixture *f, bool selected)
{
    abc_open(leaf);
    if (!json_push_kv_str(&leaf->in, "name", AK_ROUTE)) return false;
    if (!selected) return true;
    const char *keys[] = {"copy", "datadir", "version", "env_root", "dependency_root", "image_sha3", "record_id"};
    const char *values[] = {f->world.bob_copy, f->world.bob_datadir, f->build.version,
        f->build.env, f->build.deps, f->build.image, f->build.record};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
        if (!json_push_kv_str(&leaf->in, keys[i], values[i])) return false;
    return json_push_kv_bool(&leaf->in, "accept_execution", true);
}
static bool ak_opened(struct abc_leaf *leaf, const struct ak_fixture *f)
{
    aso_track_ready(&leaf->out.data, &f->build);
    return leaf->out.status == ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(abc_get(leaf, "name"), AK_ROUTE) && !strcmp(abc_get(leaf, "status"), "opened") &&
        !strcmp(abc_get(leaf, "ready_basis"), "alive") &&
        aso_build_facts_match(&leaf->out.data, &f->build) && aj_live_identity(&leaf->out.data, &f->build);
}
static bool ak_preview_keep(struct ak_fixture *f)
{
    struct abc_leaf leaf;
    bool ok = ak_request(&leaf, f, true) && abc_exec("app.open", &leaf) && ak_opened(&leaf, f);
    abc_close(&leaf);
    if (!aso_cleanup_children() || !ok) return false;
    ok = ak_request(&leaf, f, true) && json_push_kv_int(&leaf.in, "expected_revision", 0) &&
        abc_pass("app.keep", &leaf) && aso_revision_is(&leaf.out.data, 1);
    abc_close(&leaf);
    if (!ok) return false;
    ok = ak_request(&leaf, f, true) && json_push_kv_int(&leaf.in, "expected_revision", 0) &&
        abc_exec("app.keep", &leaf) && !strcmp(leaf.out.error.code, "SELECTION_STALE");
    abc_close(&leaf);
    return ok;
}
/* Exercise the emitted input through the catalog executor and serializer. */
static bool ak_discovery_wire(const char *command, const struct json_value *input,
    struct json_value *doc, enum zcl_command_exit *code)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = abc_spec(command);
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    char wire[ZCL_COMMAND_LIST_BUDGET + 1];
    if (!spec) return false;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, input, false,
        spec->path, "normal", 0, 0, NULL, wire, sizeof(wire), code);
    return n && n <= ZCL_COMMAND_LIST_BUDGET &&
        (!spec->budget_bytes || (spec->budget_bytes > 0 && n <= (size_t)spec->budget_bytes)) &&
        json_read(doc, wire, n);
}
static bool ak_discovery_state(const struct ak_fixture *f, uint8_t hashes[6][32])
{
    const char *relative[] = {".zvcs/commits.log", ".zvcs/index.kv", "src/main.c", "include/boost.h"};
    for (size_t i = 0; i < 6; ++i) {
        char path[APP_SELECTION_PATH_MAX + 64];
        int n;
        if (i < 4) n = snprintf(path, sizeof(path), "%s/%s", f->world.bob_copy, relative[i]);
        else if (i == 4) n = snprintf(path, sizeof(path), "%s/@kept-received.selection", f->env.state_dir);
        else n = snprintf(path, sizeof(path), "%s", f->trust);
        uint8_t *bytes = NULL; size_t size = 0;
        if (n <= 0 || (size_t)n >= sizeof(path) ||
            !zcl_read_whole_file(path, 8u << 20, &bytes, &size, "kept discovery state")) return false;
        sha3_256(bytes, size, hashes[i]); free(bytes);
    }
    return true;
}
static bool ak_discovery_identity(const struct ak_fixture *f, const struct json_value *data)
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.kept_discovery.v1");
    bool ok = zcl_package_copy_open_selected_as(f->world.bob_copy, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "app.customize", f->build.version);
    char tree[65]; zcl_hex_encode(copy.selected_tree, 32, tree);
    ok = ok && !strcmp(aso_string(data, "name"), AK_ROUTE) && aso_revision_is(data, 1) &&
        !strcmp(aso_string(data, "version"), f->build.version) &&
        !strcmp(aso_string(data, "source_root"), tree) &&
        !strcmp(aso_string(data, "authority"), "read-only-selected-source");
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply); return ok;
}
static bool ak_discovery_hint(const struct ak_fixture *f, const struct json_value *entry)
{
    const struct json_value *hint = json_get(entry, "customize"), *input = json_get(hint, "input");
    struct json_value doc; json_init(&doc); enum zcl_command_exit code;
    bool ok = !strcmp(aso_string(hint, "command"), "app.customize") &&
        !strcmp(aso_string(hint, "validation"), "required-on-read") &&
        input && input->type == JSON_OBJ && input->num_children == 1 &&
        !strcmp(aso_string(input, "name"), AK_ROUTE) &&
        ak_discovery_wire("app.customize", input, &doc, &code) && code == ZCL_COMMAND_EXIT_OK &&
        ak_discovery_identity(f, json_get(&doc, "data"));
    json_free(&doc); return ok;
}
static bool ak_discovery_builtin(void)
{
    struct json_value input, doc; json_init(&input); json_init(&doc); json_set_object(&input);
    enum zcl_command_exit code;
    bool ok = json_push_kv_str(&input, "name", "skycombat") &&
        ak_discovery_wire("app.customize", &input, &doc, &code) && code != ZCL_COMMAND_EXIT_OK;
    const struct json_value *error = json_get(&doc, "error"), *mutated = json_get(error, "mutated");
    ok = ok && !strcmp(aso_string(error, "code"), "SELECTION_REQUIRED") &&
        mutated && mutated->type == JSON_BOOL && !json_get_bool(mutated);
    json_free(&input); json_free(&doc); return ok;
}
static bool ak_discovery_next(const struct json_value *doc)
{
    const struct json_value *next = json_get(doc, "next");
    size_t count = 0; bool opened = false;
    for (size_t i = 0; i < json_size(next); ++i) {
        const struct json_value *row = json_at(next, i), *input = json_get(row, "input");
        if (!strcmp(aso_string(row, "command"), "app.open")) opened = true;
        if (strcmp(aso_string(row, "command"), "app.customize")) continue;
        if (strcmp(aso_string(input, "name"), AK_ROUTE)) return false;
        ++count;
    }
    return opened && count == 1;
}
static bool ak_discovery_rows(const struct ak_fixture *f, const struct json_value *doc)
{
    const struct json_value *list = json_get(json_get(doc, "data"), "launchable");
    if (!list || list->type != JSON_ARR) return false;
    bool found = false, builtin = false;
    for (size_t i = 0; i < json_size(list); ++i) {
        const struct json_value *entry = json_at(list, i);
        if (!strcmp(aso_string(entry, "id"), "skycombat")) builtin = true;
        if (strcmp(aso_string(entry, "id"), AK_ROUTE)) continue;
        found = !strcmp(aso_string(entry, "source"), "kept") &&
            !strcmp(aso_string(entry, "validation"), "required-on-open") &&
            !json_get(entry, "installed") && strstr(aso_string(entry, "open"), " app open " AK_ROUTE) &&
            ak_discovery_hint(f, entry);
    }
    return builtin && found;
}
static bool ak_listed(struct ak_fixture *f)
{
    uint8_t before[6][32], after[6][32];
    struct json_value input, doc; json_init(&input); json_init(&doc); json_set_object(&input);
    enum zcl_command_exit code;
    bool ok = ak_discovery_state(f, before) &&
        ak_discovery_wire("app.list", &input, &doc, &code) && code == ZCL_COMMAND_EXIT_OK &&
        strstr(aso_string(json_get(&doc, "data"), "summary"), "exact kept: ID") &&
        ak_discovery_rows(f, &doc) && ak_discovery_next(&doc) && ak_discovery_builtin();
    ok = ok && ak_discovery_state(f, after) && !memcmp(before, after, sizeof(before));
    json_free(&input); json_free(&doc); return ok;
}
static bool ak_mcp_open(struct aso_mcp *server, struct json_value *doc)
{
    const char *request = "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\","
        "\"params\":{\"name\":\"apps_open\",\"arguments\":{\"name\":\"" AK_ROUTE "\"}}}";
    struct json_value result; json_init(&result);
    bool ok = aso_mcp_send(server, request, true) && json_read(&result, server->line, strlen(server->line));
    const struct json_value *reply = json_get(&result, "result");
    const struct json_value *part = json_at(json_get(reply, "content"), 0);
    const char *text = json_get_str(json_get(part, "text"));
    ok = ok && !json_get_bool(json_get(reply, "isError")) && text && json_read(doc, text, strlen(text));
    json_free(&result);
    return ok;
}
static bool ak_restart(struct ak_fixture *f)
{
    struct aso_mcp server = {.pid = -1, .input = -1, .output = -1};
    struct json_value doc; json_init(&doc);
    bool ok = aso_mcp_spawn(&server) && aso_mcp_init(&server) && ak_mcp_open(&server, &doc);
    const struct json_value *data = json_get(&doc, "data");
    aso_track_ready(data, &f->build);
    ok = ok && !strcmp(aso_string(data, "name"), AK_ROUTE) &&
        !strcmp(aso_string(data, "status"), "opened") && !strcmp(aso_string(data, "ready_basis"), "alive") &&
        aso_build_facts_match(data, &f->build) && aj_live_identity(data, &f->build);
    bool closed = aso_mcp_close(&server);
    bool cleaned = aso_cleanup_children();
    json_free(&doc);
    return ok && closed && cleaned;
}
static bool ak_read_source(struct ak_fixture *f, char blob[65])
{
    struct abc_leaf leaf;
    bool ok = ak_request(&leaf, f, false) && json_push_kv_int(&leaf.in, "expected_revision", 1) &&
        json_push_kv_str(&leaf.in, "path", "include/boost.h") && abc_pass("app.customize", &leaf);
    if (ok) {
        const struct json_value *file = json_get(&leaf.out.data, "file");
        (void)snprintf(blob, 65, "%s", aso_string(file, "blob"));
        ok = strlen(blob) == 64 && !strcmp(abc_get(&leaf, "version"), f->build.version) &&
            !strcmp(abc_get(&leaf, "content"), "#define BOOST 1\n");
    }
    abc_close(&leaf);
    return ok;
}
static bool ak_edit_source(struct ak_fixture *f, const char *blob)
{
    struct abc_leaf leaf;
    bool ok = ak_request(&leaf, f, false) && json_push_kv_int(&leaf.in, "expected_revision", 1) &&
        json_push_kv_str(&leaf.in, "expected_head", f->build.version) &&
        json_push_kv_str(&leaf.in, "path", "include/boost.h") &&
        json_push_kv_str(&leaf.in, "expected_blob", blob) &&
        json_push_kv_str(&leaf.in, "content", "#define BOOST 8\n") && abc_plan_confirm("app.edit", &leaf);
    ok = ok && strlen(abc_get(&leaf, "version")) == 64 && strcmp(abc_get(&leaf, "version"), f->build.version);
    abc_close(&leaf);
    struct app_selection selection;
    uint8_t version[32];
    return ok && zcl_hex_decode_lower(f->build.version, version, 32) &&
        app_selection_load(f->env.state_dir, AK_ROUTE, &selection) == APP_SELECTION_OK &&
        selection.revision == 1 && !memcmp(selection.version, version, 32);
}
struct ak_draft_view { bool valid, prompted, returned, share_menu; unsigned calls; char head[65]; };
static bool ak_draft_library(void *context, const struct zcl_present_model_v1 *model,
    const char *copy_text, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    (void)copy_text; (void)why; (void)cap;
    struct ak_draft_view *v = context;
    if (++v->calls > 10) return false;
    if (v->prompted) {
        event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
        if (!v->returned) {
            v->returned = model->action_count && !strcmp(model->actions[0].id, "open");
            for (unsigned i = 0; v->returned && i < model->action_count; ++i)
                if (!strcmp(model->actions[i].id, "share")) {
                    event->outcome = ZCL_PRESENT_WINDOW_ACTION; event->action_index = i; return true;
                }
            return false;
        }
        v->share_menu = !strcmp(model->request_id, "library-share-options");
        event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return v->share_menu;
    }
    const char *id = !strcmp(model->request_id, "library-home") ? "myapps" :
        model->action_count && !strcmp(model->actions[0].id, "choose") ? "choose" :
        model->action_count && !strcmp(model->actions[0].id, "draft") ? "draft" : "change-options";
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    for (unsigned i = 0; i < model->action_count; ++i)
        if (!strcmp(model->actions[i].id, id)) { event->action_index = i; return true; }
    v->valid = false; return false;
}
static bool ak_draft_cancel_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    (void)why; (void)cap;
    struct ak_draft_view *v = context; bool close = false, redraw = false;
    v->prompted = pages && pages->page_count == 1 &&
        !strcmp(model->title, "Review unkept changes") && aj_receive_field(model, "Draft version: ", v->head);
    return v->prompted && aj_receive_action(live, 0, &close, &redraw) && close;
}
static bool ak_draft_cancel_reply(const struct ak_draft_view *view, const struct zcl_command_reply *reply)
{
    return view->valid && view->prompted && view->returned && view->share_menu &&
        reply->status == ZCL_COMMAND_STATUS_PASSED && !reply->error.mutated &&
        !strcmp(aso_string(&reply->data, "status"), "canceled") &&
        !json_get(&reply->data, "version") && !json_get(&reply->data, "continuation");
}
static bool ak_draft_cancel(struct ak_fixture *f)
{
    struct app_selection kept; uint8_t head[32] = {0}, before[6][32], after[6][32];
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    bool ok = app_selection_load(f->env.state_dir, AK_ROUTE, &kept) == APP_SELECTION_OK &&
        app_saved_draft_available(&kept) && app_saved_draft_head(&kept, head, &reply) && ak_discovery_state(f, before);
    struct ak_draft_view view = {.valid = true}; zcl_hex_encode(head, 32, view.head);
    if (ok) zcl_test_app_library_native_at(&f->env, NULL, f->world.bob_datadir, &reply,
        ak_draft_library, &view, ak_draft_cancel_present);
    ok = ok && ak_draft_cancel_reply(&view, &reply) &&
        ak_discovery_state(f, after) && !memcmp(before, after, sizeof(before));
    zcl_command_reply_free(&reply); return ok;
}
static bool arpt_head(const struct ak_fixture *f, const char *newer, const char *pinned,
    struct zcl_command_reply *failure);
struct ak_draft_flow_view {
    struct ak_draft_view nav;
    struct ak_fixture *fixture;
    bool keep, prompted_keep, advanced, kept_card, share_menu, history, capped, share_failed, preview_stopped;
    bool share_cancel, share_called, prep_cancel, prep_cancel_menu, failure_notice, next_action, next_canceled, review_seen, consent_returned;
    struct zcl_command_reply *active_reply;
    unsigned preparations;
    uint64_t prior_revision;
    char newer[65];
};
static bool ak_draft_kept_card(struct ak_draft_flow_view *v,
    const struct zcl_present_model_v1 *model)
{
    struct app_selection saved; uint8_t expected[32];
    const char *base = strrchr(v->fixture->world.bob_copy, '/');
    return base && base[1] && strstr(model->summary, base + 1) &&
        zcl_hex_decode_lower(v->nav.head, expected, sizeof(expected)) &&
        app_selection_load(v->fixture->env.state_dir, AK_ROUTE, &saved) == APP_SELECTION_OK &&
        saved.revision == v->prior_revision + 1 && !memcmp(saved.version, expected, sizeof(expected)) &&
        !strcmp(saved.copy, v->fixture->world.bob_copy);
}
static const char *ak_draft_prior_action(const struct ak_draft_flow_view *v,
    const struct zcl_present_model_v1 *model)
{
    if (!v->history || v->prompted_keep) return NULL;
    if (!strcmp(model->request_id, "library-help")) return "back";
    if (!v->preparations && model->action_count && !strcmp(model->actions[0].id, "draft")) return "help";
    return NULL;
}
static bool ak_draft_press(const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event, const char *action)
{
    for (unsigned i = 0; i < model->action_count; ++i) if (!strcmp(model->actions[i].id, action)) {
        event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
        event->outcome = ZCL_PRESENT_WINDOW_ACTION; event->action_index = i; return true;
    }
    return false;
}
static bool ak_draft_stop_preview(struct ak_fixture *f, const struct zcl_command_reply *reply);
static bool ak_draft_share_return(struct ak_draft_flow_view *v, const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event)
{
    if (!v->review_seen || strcmp(model->request_id, "library-share-options")) return false;
    v->consent_returned = true; event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true;
}
static bool ak_draft_unkept_card(struct ak_draft_flow_view *v, const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event)
{
    if (!v->nav.returned) {
        v->nav.returned = model->action_count && !strcmp(model->actions[0].id, "open");
        if (!v->nav.returned) return false;
        if (v->next_action) {
            v->preview_stopped = ak_draft_stop_preview(v->fixture, v->active_reply);
            return v->preview_stopped && ak_draft_press(model, event, "share");
        }
    }
    if (v->next_action && !v->share_menu) {
        v->share_menu = !strcmp(model->request_id, "library-share-options");
        return v->share_menu && ak_draft_press(model, event, "share-file");
    }
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return v->nav.returned;
}
static bool ak_draft_kept_navigation(struct ak_draft_flow_view *v, const struct zcl_present_model_v1 *model,
    struct zcl_present_window_event_v1 *event)
{
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    if (!v->history && v->share_menu) return ak_draft_share_return(v, model, event);
    if (!v->kept_card) {
        if (!ak_draft_kept_card(v, model)) return false;
        for (unsigned i = 0; i < model->action_count; ++i) {
            if (strcmp(model->actions[i].id, "share")) continue;
            v->kept_card = true; event->outcome = ZCL_PRESENT_WINDOW_ACTION;
            event->action_index = i; return true;
        }
        return false;
    }
    v->share_menu = !strcmp(model->request_id, "library-share-options");
    if (!v->share_menu) return false;
    if (!v->history) {
        v->preview_stopped = ak_draft_stop_preview(v->fixture, v->active_reply);
        return v->preview_stopped && ak_draft_press(model, event, "share-file");
    }
    if (v->prep_cancel && v->preparations == 2) {
        v->prep_cancel_menu = true;
        event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true;
    }
    if (v->share_cancel && v->share_called) {
        event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true;
    }
    if (v->history) return ak_draft_press(model, event, "share-file");
    event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true;
}
static bool ak_draft_flow_library(void *context, const struct zcl_present_model_v1 *model,
    const char *copy_text, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    struct ak_draft_flow_view *v = context;
    if (!strcmp(model->request_id, "library-error")) {
        event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
        event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true;
    }
    const char *prior_action = ak_draft_prior_action(v, model);
    if (prior_action) return ak_draft_press(model, event, prior_action);
    if (!v->keep && v->prompted_keep) return ak_draft_unkept_card(v, model, event);
    if (!v->keep || !v->prompted_keep)
        return ak_draft_library(context, model, copy_text, event, why, cap);
    return ak_draft_kept_navigation(v, model, event);
}
static bool ak_draft_wait_worker(const struct zcl_present_window_live_view_v1 *live)
{
    bool close = false, redraw = false;
    int64_t end = platform_time_monotonic_ms() + 60000;
    do {
        live->owner.update(live->owner.context, NULL, false, &redraw, &close);
        if (close) return true;
        platform_sleep_ms(1); /* real-clock: wait for this owned worker */
    } while (platform_time_monotonic_ms() < end);
    return false;
}
static bool ak_draft_confirm_pages(struct ak_draft_flow_view *v, bool keep_view,
    const struct zcl_present_model_v1 *model, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    bool close = false, redraw = false; uint32_t count = 0;
    if (!zcl_present_model_page_count_v1(model, &count, why, cap)) return false;
    for (uint32_t i = 1; i < count; ++i)
        if (!aj_receive_action(live, 2, &close, &redraw) || close) return false;
    if (keep_view && v->keep && !v->history) {
        v->advanced = abc_put(v->fixture->world.bob_copy, "include/boost.h", "#define BOOST 9\n") &&
            abc_save(v->fixture->world.bob_copy, v->newer);
        if (!v->advanced) return false;
    }
    return aj_receive_action(live, 3, &close, &redraw) && close;
}
static bool ak_draft_cancel_consent(struct ak_draft_flow_view *v,
    const struct zcl_present_model_v1 *model, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    bool close = false, redraw = false; char revision[32]; uint32_t count = 0;
    (void)snprintf(revision, sizeof(revision), "%llu", (unsigned long long)(v->prior_revision + 1));
    if (strcmp(model->summary, "Review every page before confirming.") ||
        !aj_receive_field(model, "Kept app: ", AK_ROUTE) ||
        !aj_receive_field(model, "Kept revision: ", revision) ||
        !aj_receive_field(model, "Saved version: ", v->nav.head) ||
        !aj_receive_field(model, "Current HEAD: ", v->newer) ||
        !aj_receive_field(model, "Copy: ", v->fixture->world.bob_copy) ||
        !zcl_present_model_page_count_v1(model, &count, why, cap)) return false;
    for (uint32_t i = 1; i < count; ++i)
        if (!aj_receive_action(live, 2, &close, &redraw) || close) return false;
    v->review_seen = true;
    return aj_receive_action(live, 0, &close, &redraw) && close;
}
static bool ak_draft_expected_title(const struct zcl_present_model_v1 *model, bool keep_view)
{
    if (keep_view || !strcmp(model->title, "Review unkept changes")) return true;
    fprintf(stderr, "draft presenter: unexpected title=%s summary=%s\n", model->title, model->summary);
    return false;
}
static bool ak_draft_flow_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct ak_draft_flow_view *v = context; bool close = false, redraw = false;
    if (!pages || !live) return false;
    if (!strcmp(model->title, "The next step did not finish")) {
        v->failure_notice = !strcmp(model->summary, "Your unkept draft is retained. Nothing is retried automatically.") &&
            aj_receive_field(model, "Draft version: ", v->nav.head);
        return v->failure_notice && aj_receive_action(live, 0, &close, &redraw) && close;
    }
    if (!model->action_count) return ak_draft_wait_worker(live);
    if (!strcmp(model->title, "Prepare a personal copy?"))
        return ak_draft_cancel_consent(v, model, live, why, cap);
    bool keep_view = !strcmp(model->title, "Preview opened");
    if (!ak_draft_expected_title(model, keep_view)) return false;
    if (!aj_receive_field(model, "Draft version: ", v->nav.head)) return false;
    if (keep_view) v->prompted_keep = true;
    if (keep_view && !v->keep) return aj_receive_action(live, 0, &close, &redraw) && close;
    return ak_draft_confirm_pages(v, keep_view, model, live, why, cap);
}
static bool ak_draft_stop_preview(struct ak_fixture *f, const struct zcl_command_reply *reply)
{
    const struct json_value *data = &reply->data;
    if (!json_get(data, "operations")) data = json_get(json_get(data, "failure_facts"), "historical_keep");
    const struct json_value *open = json_at(json_get(data, "operations"), 2);
    const struct json_value *pid = json_get(open, "pid");
    const char *image = aso_string(open, "image_sha3"); uint8_t digest[32];
    uint64_t expected = 0, actual = 0; char path[APP_LAUNCH_PATH_MAX];
    if (!pid || pid->type != JSON_INT || json_get_int(pid) <= 1 || json_get_int(pid) > LONG_MAX ||
        !aj_start_token(open, &expected) || !zcl_hex_decode_lower(image, digest, sizeof(digest))) return false;
    int n = snprintf(f->build.image_path, sizeof(f->build.image_path), "%s/app_build/images/%s",
                     f->world.bob_datadir, image);
    if (n <= 0 || (size_t)n >= sizeof(f->build.image_path) ||
        !app_proc_identity((long)json_get_int(pid), path, &actual) || actual != expected ||
        strcmp(path, f->build.image_path)) return false;
    aso_track_ready(open, &f->build);
    return aso_cleanup_children();
}
static bool ak_draft_selection_result(struct ak_fixture *f, bool keep, const struct app_selection *before,
    const uint8_t head[32], struct ak_draft_flow_view *view, struct zcl_command_reply *reply)
{
    struct app_selection after;
    if (app_selection_load(f->env.state_dir, AK_ROUTE, &after) != APP_SELECTION_OK) return false;
    if (keep && view->history) return after.revision == before->revision + 1 && !memcmp(after.version, head, 32);
    if (keep) return view->advanced && after.revision == before->revision + 1 &&
        !memcmp(after.version, head, 32) && arpt_head(f, view->newer, view->nav.head, reply);
    return after.revision == before->revision && !memcmp(after.version, before->version, 32) &&
        !strcmp(aso_string(&reply->data, "continuation"), "previewed");
}
static void ak_draft_preparer(void *context, const struct app_selection *selection,
    struct zcl_command_reply *reply)
{
    struct ak_draft_flow_view *v = context; uint8_t version[32]; char hex[65];
    ++v->preparations;
    if (v->prep_cancel && v->preparations == 2) {
        if (!json_push_kv_str(&reply->data, "status", "canceled"))
            zcl_package_copy_fail(reply, "FIXTURE_FAILED", false, "Cannot describe cancellation.", "fixture");
        return;
    }
    bool changed = v->preparations == 1;
    if (changed) {
        if (!app_saved_draft_head(selection, version, reply)) return;
    } else memcpy(version, selection->version, sizeof(version));
    zcl_hex_encode(version, sizeof(version), hex);
    bool ok = json_push_kv_str(&reply->data, "version", hex) &&
        json_push_kv_str(&reply->data, "copy", selection->copy) &&
        json_push_kv_str(&reply->data, "datadir", selection->datadir) &&
        json_push_kv_bool(&reply->data, "key_created", changed) &&
        json_push_kv_bool(&reply->data, "changed", changed);
    if (!ok) zcl_package_copy_fail(reply, "FIXTURE_FAILED", false, "Cannot prepare fixture receipt.", "fixture");
    else reply->error.mutated = changed;
}
static void ak_draft_next_cancel(void *context, const struct app_selection *selection,
    struct zcl_command_reply *reply)
{
    struct ak_draft_flow_view *v = context;
    if (v->history && !v->preparations) {
        ak_draft_preparer(context, selection, reply);
        return;
    }
    struct app_selection saved;
    if (v->history) {
        v->next_canceled = selection && selection->revision == v->prior_revision &&
            app_selection_load(v->fixture->env.state_dir, AK_ROUTE, &saved) == APP_SELECTION_OK &&
            !memcmp(saved.version, selection->version, sizeof(saved.version));
        zcl_package_copy_fail(reply, "FIXTURE_PREPARE_FAILED", false, "Later preparation failed.", "fixture");
        return;
    }
    v->next_canceled = selection && selection->revision == v->prior_revision &&
        app_selection_load(v->fixture->env.state_dir, AK_ROUTE, &saved) == APP_SELECTION_OK &&
        !memcmp(saved.version, selection->version, sizeof(saved.version)) &&
        json_push_kv_str(&reply->data, "status", "canceled");
}
static void ak_draft_share_failure(void *context, const struct app_selection *selection,
    const char *path, struct zcl_command_reply *reply)
{
    struct ak_draft_flow_view *v = context; uint8_t expected[32];
    v->preview_stopped = ak_draft_stop_preview(v->fixture, reply);
    v->share_called = true;
    v->share_failed = zcl_hex_decode_lower(v->nav.head, expected, sizeof(expected)) &&
        !memcmp(selection->version, expected, sizeof(expected)) &&
        selection->revision == v->prior_revision + 1 && path && path[0] == '/';
    zcl_command_reply_free(reply); zcl_command_reply_init(reply, "zcl.app_open.v1");
    if (v->share_cancel) {
        if (!json_push_kv_str(&reply->data, "status", "canceled"))
            zcl_package_copy_fail(reply, "FIXTURE_FAILED", false, "Cannot describe cancellation.", "fixture");
        return;
    }
    zcl_package_copy_fail(reply, "FIXTURE_SHARE_FAILED", false, "Later share failed.", "fixture");
}
static void ak_draft_share_sentinel(void *context, const struct app_selection *selection,
    const char *path, struct zcl_command_reply *reply)
{
    (void)selection; (void)path;
    struct ak_draft_flow_view *v = context; v->share_called = true;
    zcl_package_copy_fail(reply, "FIXTURE_UNEXPECTED_SIGN", false, "Unexpected signing attempt.", "fixture");
}
static bool ak_draft_history_identity(const struct json_value *kept,
    const struct ak_draft_flow_view *view)
{
    struct app_selection saved; char image[65], record[65];
    if (app_selection_load(view->fixture->env.state_dir, AK_ROUTE, &saved) != APP_SELECTION_OK) return false;
    zcl_hex_encode(saved.image, 32, image); zcl_hex_encode(saved.record, 32, record);
    const struct json_value *revision = json_get(kept, "selection_revision");
    return !strcmp(aso_string(kept, "name"), AK_ROUTE) && revision && revision->type == JSON_INT &&
        json_get_int(revision) == (int64_t)(view->prior_revision + 1) &&
        !strcmp(aso_string(kept, "version"), view->nav.head) &&
        !strcmp(aso_string(kept, "image_sha3"), image) && !strcmp(aso_string(kept, "record_id"), record);
}
static bool ak_draft_history_preparation(const struct json_value *facts,
    const struct ak_draft_flow_view *view)
{
    const struct json_value *p = json_get(facts, "library_preparation");
    if (!p) p = facts;
    const struct json_value *changed = json_get(p, "changed");
    return !strcmp(aso_string(p, "version"), view->nav.head) &&
        !strcmp(aso_string(p, "copy"), view->fixture->world.bob_copy) &&
        !strcmp(aso_string(p, "datadir"), view->fixture->world.bob_datadir) &&
        changed && changed->type == JSON_BOOL && json_get_bool(changed);
}
static bool ak_draft_history_facts(const struct json_value *facts,
    const struct ak_draft_flow_view *view)
{
    const struct json_value *kept = json_get(facts, "historical_keep");
    const struct json_value *operations = json_get(kept, "operations");
    if (!ak_draft_history_identity(kept, view) || !ak_draft_history_preparation(facts, view)) return false;
    if (!operations) return json_get_bool(json_get(facts, "details_unavailable"));
    const struct json_value *pid = json_get(json_at(operations, 2), "pid");
    return !strcmp(aso_string(kept, "continuation"), "kept") && pid && pid->type == JSON_INT && json_get_int(pid) > 0;
}
static bool ak_draft_history_wire(struct zcl_command_reply *reply, const struct ak_draft_flow_view *view)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", NULL);
    char wire[ZCL_COMMAND_ERROR_BUDGET + 1];
    size_t n = spec ? zcl_command_registry_test_reply_wire(reg, spec, reply, wire, sizeof(wire)) : 0;
    struct json_value doc; json_init(&doc);
    bool ok = n && n < sizeof(wire) && json_read(&doc, wire, n);
    const struct json_value *error = json_get(&doc, "error");
    ok = ok && !strcmp(aso_string(error, "code"), "FIXTURE_SHARE_FAILED") &&
        json_get_bool(json_get(error, "mutated")) && ak_draft_history_facts(json_get(error, "facts"), view);
    json_free(&doc); return ok;
}
static bool ak_draft_history_result(const struct ak_draft_flow_view *view,
    struct zcl_command_reply *reply)
{
    return view->preparations == 2 && view->share_failed && reply->error.mutated &&
        reply->status != ZCL_COMMAND_STATUS_PASSED && !strcmp(reply->error.code, "FIXTURE_SHARE_FAILED") &&
        ak_draft_history_facts(json_get(&reply->data, "failure_facts"), view) && ak_draft_history_wire(reply, view);
}
static bool ak_draft_success_facts(const struct json_value *data, const struct ak_draft_flow_view *view)
{
    const struct json_value *kept = json_get(data, "historical_keep");
    const struct json_value *preparation = json_get(data, "preparation");
    const struct json_value *pid = json_get(json_at(json_get(kept, "operations"), 2), "pid");
    return ak_draft_history_identity(kept, view) &&
        !strcmp(aso_string(kept, "continuation"), "kept") && pid && pid->type == JSON_INT &&
        json_get_int(pid) > 0 && json_get_bool(json_get(preparation, "changed")) &&
        !strcmp(aso_string(preparation, "version"), view->nav.head);
}
static bool ak_draft_success_wire(struct zcl_command_reply *reply, const struct ak_draft_flow_view *view)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", NULL);
    char wire[32768u + 1u]; /* app.library's complete success envelope. */
    struct zcl_command_budget_fixture budget = {.budget_bytes = spec ? (size_t)spec->budget_bytes : 0};
    size_t n = spec ? zcl_command_registry_test_reply_wire_fixture(reg, spec, reply, &budget, wire, sizeof(wire)) : 0;
    struct json_value doc; json_init(&doc);
    bool ok = n && n < sizeof(wire) && json_read(&doc, wire, n) &&
        !strcmp(aso_string(&doc, "status"), "passed") && ak_draft_success_facts(json_get(&doc, "data"), view);
    json_free(&doc); return ok;
}
static bool ak_draft_current_facts(const struct json_value *data,
                                   const struct ak_draft_flow_view *view)
{
    const struct json_value *kept = json_get(data, "kept");
    const struct json_value *prep = json_get(data, "preparation");
    const struct json_value *pid = json_get(json_at(json_get(data, "operations"), 2), "pid");
    return ak_draft_history_identity(kept, view) &&
        !strcmp(aso_string(data, "continuation"), "kept") && pid && pid->type == JSON_INT &&
        json_get_int(pid) > 0 && json_get_bool(json_get(prep, "changed")) &&
        !strcmp(aso_string(prep, "version"), view->nav.head);
}
static bool ak_draft_current_wire(struct zcl_command_reply *reply,
                                  const struct ak_draft_flow_view *view)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", NULL);
    char wire[32768u + 1u];
    struct zcl_command_budget_fixture budget = {.budget_bytes = spec ? (size_t)spec->budget_bytes : 0};
    size_t n = spec ? zcl_command_registry_test_reply_wire_fixture(reg, spec, reply, &budget, wire, sizeof(wire)) : 0;
    struct json_value doc; json_init(&doc);
    bool ok = n && n < sizeof(wire) && json_read(&doc, wire, n) &&
        !strcmp(aso_string(&doc, "status"), "passed") && ak_draft_current_facts(json_get(&doc, "data"), view);
    json_free(&doc); return ok;
}
static bool ak_draft_cap_facts(const struct json_value *facts, const char *head)
{
    if (json_get_bool(json_get(facts, "details_unavailable"))) return true;
    const struct json_value *kept = json_get(facts, "kept");
    const struct json_value *preparation = json_get(facts, "library_preparation");
    return !strcmp(aso_string(kept, "version"), head) && json_get_bool(json_get(preparation, "changed"));
}
static bool ak_draft_cap_wire(struct zcl_command_reply *reply, const char *head)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", NULL);
    char wire[ZCL_COMMAND_ERROR_BUDGET + 1];
    size_t n = spec ? zcl_command_registry_test_reply_wire(reg, spec, reply, wire, sizeof(wire)) : 0;
    struct json_value doc; json_init(&doc);
    bool ok = n && n < sizeof(wire) && json_read(&doc, wire, n);
    const struct json_value *error = json_get(&doc, "error");
    ok = ok && !strcmp(aso_string(error, "code"), "RESULT_TOO_LARGE") &&
        json_get_bool(json_get(error, "mutated")) && ak_draft_cap_facts(json_get(error, "facts"), head);
    json_free(&doc); return ok;
}
static bool ak_draft_cap_result(struct ak_fixture *f, bool keep, bool stopped,
    const struct app_selection *before, const uint8_t head[32],
    struct ak_draft_flow_view *view, struct zcl_command_reply *reply)
{
    return stopped && view->nav.valid && view->prompted_keep &&
        !view->kept_card && !view->share_menu && view->preparations == 1 && !view->share_failed &&
        reply->status != ZCL_COMMAND_STATUS_PASSED && reply->error.mutated &&
        ak_draft_cap_wire(reply, view->nav.head) &&
        ak_draft_selection_result(f, keep, before, head, view, reply);
}
static bool ak_draft_success_result(struct ak_fixture *f, bool keep, bool stopped,
    const struct app_selection *before, const uint8_t head[32],
    struct ak_draft_flow_view *view, struct zcl_command_reply *reply)
{
    return stopped && view->nav.valid && view->prompted_keep &&
        view->kept_card && view->share_menu && view->preparations == 2 && view->share_failed &&
        reply->status == ZCL_COMMAND_STATUS_PASSED && reply->error.mutated &&
        ak_draft_success_facts(&reply->data, view) && ak_draft_success_wire(reply, view) &&
        ak_draft_selection_result(f, keep, before, head, view, reply);
}
static bool ak_draft_prep_cancel_result(struct ak_fixture *f, bool keep, bool stopped,
    const struct app_selection *before, const uint8_t head[32],
    struct ak_draft_flow_view *view, struct zcl_command_reply *reply)
{
    return stopped && view->nav.valid && view->prompted_keep &&
        view->kept_card && view->share_menu && view->prep_cancel_menu && view->preparations == 2 &&
        !view->share_called && reply->status == ZCL_COMMAND_STATUS_PASSED && reply->error.mutated &&
        ak_draft_current_facts(&reply->data, view) && ak_draft_current_wire(reply, view) &&
        ak_draft_selection_result(f, keep, before, head, view, reply);
}
static bool ak_draft_unkept_result(const struct ak_draft_flow_view *view, const struct zcl_command_reply *reply)
{
    return view->nav.returned && !view->kept_card && !view->share_menu &&
        json_get_bool(json_get(&reply->data, "preview_opened")) &&
        json_get_bool(json_get(&reply->data, "continuation_executed")) &&
        !json_get(&reply->data, "status");
}
static bool ak_draft_kept_result(const struct ak_draft_flow_view *view, bool history)
{
    return view->kept_card && view->share_menu &&
        (history || (view->review_seen && view->consent_returned && !view->share_called));
}
static bool ak_draft_flow_result(struct ak_fixture *f, bool keep, bool history, bool stopped,
    const struct app_selection *before, const uint8_t head[32],
    struct ak_draft_flow_view *view, struct zcl_command_reply *reply)
{
    if (view->capped) return ak_draft_cap_result(f, keep, stopped, before, head, view, reply);
    if (view->prep_cancel) return ak_draft_prep_cancel_result(f, keep, stopped, before, head, view, reply);
    if (view->share_cancel) return ak_draft_success_result(f, keep, stopped, before, head, view, reply);
    return stopped && view->nav.valid && view->prompted_keep &&
        (keep ? ak_draft_kept_result(view, history) : ak_draft_unkept_result(view, reply)) &&
        (history ? ak_draft_history_result(view, reply) : reply->status == ZCL_COMMAND_STATUS_PASSED) &&
        ak_draft_selection_result(f, keep, before, head, view, reply);
}
static bool ak_draft_next_result(struct ak_fixture *f, const struct app_selection *before,
    struct ak_draft_flow_view *view, const struct zcl_command_reply *reply, bool stopped, bool history)
{
    struct app_selection after;
    const struct json_value *facts = json_get(&reply->data, "failure_facts");
    bool outcome = history ? reply->status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply->error.code, "FIXTURE_PREPARE_FAILED") && view->preparations == 1 &&
        ak_draft_history_preparation(facts, view) : reply->status == ZCL_COMMAND_STATUS_PASSED;
    return stopped && view->nav.returned && view->share_menu && view->next_canceled && outcome &&
        reply->error.mutated && !json_get(&reply->data, "version") && !json_get(&reply->data, "continuation") &&
        app_selection_load(f->env.state_dir, AK_ROUTE, &after) == APP_SELECTION_OK &&
        after.revision == before->revision && !memcmp(after.version, before->version, 32);
}
static void ak_draft_run_library(struct ak_fixture *f, struct ak_draft_flow_view *view,
    struct zcl_command_reply *reply, const char *worker)
{
    if (view->next_action) zcl_test_app_library_discover_worker_share(&f->env, f->world.bob_datadir, reply,
        ak_draft_flow_library, ak_draft_flow_present, view, worker, ak_draft_next_cancel, ak_draft_share_failure);
    else if (view->capped) zcl_test_app_library_discover_worker_share_cap(&f->env, f->world.bob_datadir, reply,
        ak_draft_flow_library, ak_draft_flow_present, view, worker, ak_draft_preparer, ak_draft_share_failure, 1500);
    else if (view->history) zcl_test_app_library_discover_worker_share(&f->env, f->world.bob_datadir, reply,
        ak_draft_flow_library, ak_draft_flow_present, view, worker, ak_draft_preparer, ak_draft_share_failure);
    else if (view->keep) zcl_test_app_library_discover_worker_share(&f->env, f->world.bob_datadir, reply,
        ak_draft_flow_library, ak_draft_flow_present, view, worker, NULL, ak_draft_share_sentinel);
    else zcl_test_app_library_discover_worker(&f->env, f->world.bob_datadir, reply,
        ak_draft_flow_library, ak_draft_flow_present, view, worker);
}
static bool ak_draft_preview_keep_variant(struct ak_fixture *f, bool keep, bool history, bool capped, bool share_cancel, bool prep_cancel, bool next_action)
{
    struct app_selection before = {0}; uint8_t head[32] = {0}; char worker[PATH_MAX];
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    bool ok = app_selection_load(f->env.state_dir, AK_ROUTE, &before) == APP_SELECTION_OK &&
        app_saved_draft_head(&before, head, &reply) && realpath("build/bin/z23-dev", worker);
    struct ak_draft_flow_view view = {.nav = {.valid = true}, .fixture = f, .keep = keep, .history = history,
        .capped = capped, .share_cancel = share_cancel, .prep_cancel = prep_cancel, .next_action = next_action, .active_reply = &reply};
    view.prior_revision = before.revision;
    zcl_hex_encode(head, 32, view.nav.head);
    zcl_native_bridge_ensure_rpc();
    char old_dir[512];
    (void)snprintf(old_dir, sizeof(old_dir), "%s", zcl_native_command_datadir());
    int old_port = zcl_native_command_rpc_port();
    zcl_native_bridge_bind_rpc(f->world.bob_datadir, 39461);
    if (ok) ak_draft_run_library(f, &view, &reply, worker);
    zcl_native_bridge_bind_rpc(old_dir, old_port);
    bool stopped = view.preview_stopped || ak_draft_stop_preview(f, &reply);
    printf("  draft Keep: keep=%d card=%d share=%d review=%d signer=%d stopped=%d status=%d\n",
        keep, view.kept_card, view.share_menu, view.review_seen, view.share_called, stopped, reply.status);
    if (reply.status != ZCL_COMMAND_STATUS_PASSED)
        fprintf(stderr, "draft reply: code=%s message=%s\n", reply.error.code, reply.error.message);
    if (history) {
        char data[2048]; size_t n = json_write(&reply.data, data, sizeof(data));
        printf("  draft history: cap=%d preparations=%u share_failed=%d code=%s data_bytes=%zu data=%.*s\n",
            capped, view.preparations, view.share_failed, reply.error.code, n,
            (int)(n < sizeof(data) ? n : sizeof(data) - 1), data);
    }
    if (next_action) ok = ok && ak_draft_next_result(f, &before, &view, &reply, stopped, history);
    else ok = ok && ak_draft_flow_result(f, keep, history, stopped, &before, head, &view, &reply);
    zcl_command_reply_free(&reply); return ok;
}
static bool ak_draft_preview_keep(struct ak_fixture *f, bool keep)
{
    return ak_draft_preview_keep_variant(f, keep, false, false, false, false, false);
}
static bool ak_draft_failure_reply(const struct zcl_command_reply *reply, bool notice, int old_port)
{
    const struct json_value *failure = json_get(&reply->data, "continuation_error");
    const struct json_value *operation = json_at(json_get(&reply->data, "operations"), 0);
    const struct json_value *exit_code = json_get(operation, "exit_code");
    bool worker_exit = exit_code && exit_code->type == JSON_INT && json_get_int(exit_code) != 0;
    bool outcome = reply->status == ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(aso_string(&reply->data, "continuation"), "failed") &&
        !strcmp(aso_string(failure, "code"), "PREVIEW_WORKER_FAILED");
    if (!notice || !outcome || !worker_exit)
        fprintf(stderr, "draft failure reply: notice=%d status=%d continuation=%s code=%s operation=%d exit_type=%d exit=%lld old_rpc=%d\n",
            notice, reply->status, aso_string(&reply->data, "continuation"), aso_string(failure, "code"),
            operation != NULL, exit_code ? (int)exit_code->type : -1,
            exit_code && exit_code->type == JSON_INT ? (long long)json_get_int(exit_code) : -1LL, old_port);
    return notice && outcome && worker_exit;
}
static bool ak_draft_failure_state(struct ak_fixture *f, const uint8_t before[6][32])
{
    uint8_t after[6][32];
    bool observed = ak_discovery_state(f, after);
    bool same = observed && !memcmp(before, after, sizeof(after));
    if (!same) fprintf(stderr, "draft failure state: observed=%d unchanged=%d\n", observed, same);
    return same;
}
/* A failed draft worker reports the retained draft and does not change Keep. */
static bool ak_draft_failure_notice(struct ak_fixture *f)
{
    struct app_selection selection; uint8_t head[32], before[6][32];
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    bool ok = app_selection_load(f->env.state_dir, AK_ROUTE, &selection) == APP_SELECTION_OK &&
        app_saved_draft_head(&selection, head, &reply) && ak_discovery_state(f, before);
    struct ak_draft_flow_view view = {.nav = {.valid = true}, .fixture = f};
    zcl_native_bridge_ensure_rpc();
    char old_dir[512]; (void)snprintf(old_dir, sizeof(old_dir), "%s", zcl_native_command_datadir());
    int old_port = zcl_native_command_rpc_port();
    zcl_native_bridge_bind_rpc(f->world.bob_datadir, 39461);
    if (ok) {
        zcl_hex_encode(head, sizeof(head), view.nav.head);
        app_saved_draft_flow_run(&selection, &reply, ak_draft_flow_present, &view, "/bin/false");
    }
    zcl_native_bridge_bind_rpc(old_dir, old_port);
    bool outcome = ak_draft_failure_reply(&reply, view.failure_notice, old_port);
    bool same = ok && ak_draft_failure_state(f, before);
    if (!ok) fprintf(stderr, "draft failure setup failed; old_rpc=%d\n", old_port);
    ok = ok && outcome && same;
    zcl_command_reply_free(&reply); return ok;
}
static bool ak_draft_stale_controls(struct ak_fixture *f)
{
    struct app_selection kept, advanced; uint8_t head[32]; char newer[65];
    struct app_receive_preview *p = NULL;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.preview.v1");
    bool ok = app_selection_load(f->env.state_dir, AK_ROUTE, &kept) == APP_SELECTION_OK &&
        app_saved_draft_head(&kept, head, &reply) &&
        app_saved_draft_preview_create(&kept, head, &p, &reply) &&
        app_receive_preview_current(p, &reply) &&
        abc_put(f->world.bob_copy, "include/boost.h", "#define BOOST 10\n") &&
        abc_save(f->world.bob_copy, newer) && !app_receive_preview_current(p, &reply) &&
        !strcmp(reply.error.code, "DRAFT_STALE");
    app_receive_preview_close(p); p = NULL;
    zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.test.preview.v1");
    if (ok) ok = app_saved_draft_head(&kept, head, &reply) &&
        app_saved_draft_preview_create(&kept, head, &p, &reply) &&
        app_selection_save(f->env.state_dir, kept.revision, &kept, &advanced) == APP_SELECTION_OK &&
        !app_receive_preview_current(p, &reply) && !strcmp(reply.error.code, "SELECTION_STALE");
    app_receive_preview_close(p); zcl_command_reply_free(&reply); return ok;
}
static bool ak_refused(struct ak_fixture *f, const char *code)
{
    struct abc_leaf leaf;
    bool ok = ak_request(&leaf, f, false) && abc_exec("app.open", &leaf);
    ok = ok && leaf.out.status != ZCL_COMMAND_STATUS_PASSED && !strcmp(leaf.out.error.code, code);
    if (!ok) printf("kept route expected=%s actual=%s %s\n", code, leaf.out.error.code, leaf.out.error.message);
    abc_close(&leaf);
    return ok;
}
static bool ak_revoked(struct ak_fixture *f)
{
    char saved[APP_SELECTION_PATH_MAX + 8];
    (void)snprintf(saved, sizeof(saved), "%s.saved", f->trust);
    if (rename(f->trust, saved)) return false;
    bool ok = ak_refused(f, "NOT_ADOPTED");
    bool restored = rename(saved, f->trust) == 0;
    return ok && restored;
}
static bool ak_collision(struct ak_fixture *f)
{
    char config[ABC_PATH], z23[ABC_PATH], text[APP_LAUNCH_PATH_MAX + 128];
    (void)snprintf(config, sizeof(config), "%s/config", f->world.bob_home);
    (void)snprintf(z23, sizeof(z23), "%s/config/z23", f->world.bob_home);
    int n = snprintf(text, sizeof(text), AK_ROUTE "\t-\t%s\t-\tsigusr1\tUNTRUSTED\n", f->build.image_path);
    if (n <= 0 || (size_t)n >= sizeof(text) || mkdir(config, 0700) || mkdir(z23, 0700)) return false;
    return abc_put(z23, "apps.tsv", text) && chmod(f->env.config_path, 0600) == 0;
}
static bool ak_deleted(struct ak_fixture *f)
{
    char path[APP_SELECTION_PATH_MAX + 64], saved[APP_SELECTION_PATH_MAX + 72];
    (void)snprintf(path, sizeof(path), "%s/@kept-received.selection", f->env.state_dir);
    (void)snprintf(saved, sizeof(saved), "%s.saved", path);
    if (rename(path, saved)) return false;
    bool ok = ak_refused(f, "SELECTION_REQUIRED");
    bool restored = rename(saved, path) == 0;
    return ok && restored;
}
static bool ak_corrupted(struct ak_fixture *f)
{
    char path[APP_SELECTION_PATH_MAX + 64];
    (void)snprintf(path, sizeof(path), "%s/@kept-received.selection", f->env.state_dir);
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) return false;
    bool wrote = write(fd, "bad", 3) == 3;
    bool closed = close(fd) == 0;
    if (!wrote || !closed || !ak_refused(f, "SELECTION_UNREADABLE")) return false;
    struct abc_leaf leaf; abc_open(&leaf);
    bool ok = abc_exec("app.list", &leaf) && leaf.out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(leaf.out.error.code, "KEPT_LIST_REFUSED");
    abc_close(&leaf);
    return ok;
}
static bool ak_replaced(struct ak_fixture *f)
{
    char saved[ABC_PATH + 8];
    (void)snprintf(saved, sizeof(saved), "%s.saved", f->build.image_path);
    if (rename(f->build.image_path, saved)) return false;
    FILE *file = fopen(f->build.image_path, "wb");
    bool created = file && fputs("not an executable", file) >= 0;
    if (file && fclose(file)) created = false;
    bool ok = created && ak_refused(f, "IMAGE_REFUSED");
    bool restored = rename(saved, f->build.image_path) == 0;
    return ok && restored;
}
static int ak_acceptance(struct ak_fixture *f)
{
    int failures = 0; char blob[65];
    TEST("received app previews Keeps lists and reopens without a catalog; source stays editable") {
        ASSERT(ak_received(f) && ak_environment(f));
        ASSERT(ak_refused(f, "SELECTION_REQUIRED"));
        ASSERT(ak_preview_keep(f));
        ASSERT(ak_listed(f) && ak_restart(f));
        ASSERT(ak_read_source(f, blob));
        ASSERT(ak_revoked(f) && ak_replaced(f));
        ASSERT(ak_edit_source(f, blob));
        ASSERT(ak_draft_cancel(f));
        ASSERT(ak_collision(f));
        ASSERT(ak_restart(f));
        ASSERT(ak_deleted(f) && ak_corrupted(f));
        PASS();
    } _test_next:;
    return failures;
}
/* Actual receive/build/open replies drive the private continuation helper.
 * Synthetic DISPLAY exercises native alive readiness, not a visual window. */
static bool arpt_wire(const struct abc_leaf *leaf, const char *command, struct json_value *wire)
{
    json_init(wire); json_set_object(wire);
    bool passed = leaf->out.status == ZCL_COMMAND_STATUS_PASSED && leaf->out.exit_code == 0;
    return json_push_kv_str(wire, "command", command) && json_push_kv_bool(wire, "ok", passed) &&
        json_push_kv_str(wire, "status", passed ? "passed" : "failed") && json_push_kv(wire, "data", &leaf->out.data);
}
static bool arpt_received(struct ak_fixture *f, struct app_receive_preview **preview,
    struct zcl_command_reply *failure)
{
    struct abc_world *w = &f->world; struct aso_build sender;
    char version[65], personal[65], publisher[67];
    const char *source = "#include <stdio.h>\n#include <unistd.h>\n"
        "int main(void){puts(\"RECEIVED-PIN\");fflush(stdout);for(;;)pause();}\n";
    if (!abc_world_init(w) || !abc_put(w->copy, "src/main.c", source) || !abc_save(w->copy, version) ||
        !aj_personalize(w, version, personal) || !ak_build_saved_tuple(w, personal, &sender) ||
        !ak_share_backend(w, &sender, publisher, f->release)) return false;
    struct abc_leaf leaf; abc_open(&leaf);
    struct aj_receive_view view = {.publisher = publisher, .package = sender.package,
        .release = f->release, .destination = w->bob_copy};
    bool ok = aj_receive_plan(&leaf, w, publisher, sender.package, f->release) &&
        aj_receive_parent(&leaf.out.data, &view) && aj_receive_frontdoor(&leaf, &view) && ak_environment(f);
    if (ok) {
        (void)snprintf(f->build.version, sizeof(f->build.version), "%s", abc_get(&leaf, "version"));
        ok = app_receive_preview_create(&leaf.out.data, w->bob_datadir, preview, failure);
    }
    abc_close(&leaf); return ok;
}
static bool arpt_bad_plan(struct app_receive_preview *p, const struct json_value *wire,
    struct zcl_command_reply *failure)
{
    struct json_value bad, input; json_init(&bad); json_init(&input);
    bool ok = json_copy_checked(&bad, wire);
    struct json_value *data = (struct json_value *)json_get(&bad, "data");
    if (ok) json_set_str((struct json_value *)json_get(data, "copy"), "/different-copy");
    ok = ok && !app_receive_preview_confirm_input(p, &bad, &input, failure) &&
        !strcmp(failure->error.code, "PREVIEW_PLAN_MISMATCH");
    json_free(&input); json_free(&bad); return ok;
}
static bool arpt_bad_build(struct app_receive_preview *p, const struct json_value *wire,
    struct zcl_command_reply *failure)
{
    struct json_value bad, input; json_init(&bad); json_init(&input);
    bool ok = json_copy_checked(&bad, wire);
    struct json_value *data = (struct json_value *)json_get(&bad, "data");
    if (ok) json_set_str((struct json_value *)json_get(data, "record_id"), "invalid");
    ok = ok && !app_receive_preview_bind_build(p, &bad, failure) &&
        !app_receive_preview_open_input(p, &input);
    json_free(&input); json_free(&bad); return ok;
}
static bool arpt_build_commit(struct ak_fixture *f, struct app_receive_preview *p,
    const char *pinned, struct json_value *confirm, struct zcl_command_reply *failure)
{
    struct abc_leaf leaf; abc_open(&leaf); json_free(&leaf.in);
    leaf.in = *confirm; json_init(confirm);
    struct json_value wire; json_init(&wire);
    bool ok = abc_pass("app.build", &leaf) && aso_tuple(&leaf, &f->build) &&
        !strcmp(f->build.version, pinned) && arpt_wire(&leaf, "app.build", &wire) &&
        arpt_bad_build(p, &wire, failure) && app_receive_preview_bind_build(p, &wire, failure);
    json_free(&wire); abc_close(&leaf); return ok;
}
static bool arpt_head(const struct ak_fixture *f, const char *newer, const char *pinned,
    struct zcl_command_reply *failure)
{
    struct zcl_package_copy copy = {0};
    bool ok = zcl_package_copy_open_selected_as(f->world.bob_copy, ZCL_PACKAGE_COPY_READ,
        &copy, failure, "preview-test", newer);
    if (ok) {
        char actual[65]; zcl_hex_encode(copy.head_version, 32, actual);
        ok = !strcmp(actual, newer) && strcmp(actual, pinned);
    }
    zcl_package_copy_close(&copy); return ok;
}
static bool arpt_build(struct ak_fixture *f, struct app_receive_preview *p,
    struct zcl_command_reply *failure)
{
    char newer[65], pinned[65];
    (void)snprintf(pinned, sizeof(pinned), "%s", f->build.version);
    if (!abc_put(f->world.bob_copy, "src/main.c", "poison live source: never compile me\n") ||
        !abc_save(f->world.bob_copy, newer) || !strcmp(newer, f->build.version)) return false;
    struct abc_leaf leaf; abc_open(&leaf); json_free(&leaf.in);
    struct json_value wire, confirm; json_init(&wire); json_init(&confirm);
    bool ok = app_receive_preview_build_input(p, &leaf.in) &&
        !strcmp(aso_string(&leaf.in, "version"), f->build.version) && abc_pass("app.build", &leaf) &&
        arpt_wire(&leaf, "app.build", &wire) && arpt_bad_plan(p, &wire, failure) &&
        app_receive_preview_confirm_input(p, &wire, &confirm, failure);
    if (ok) ok = arpt_build_commit(f, p, pinned, &confirm, failure);
    if (ok) ok = arpt_head(f, newer, pinned, failure);
    json_free(&wire); json_free(&confirm); abc_close(&leaf); return ok;
}
static bool arpt_failed_open(struct ak_fixture *f, struct app_receive_preview *p,
    struct zcl_command_reply *failure)
{
    char saved[ABC_PATH + 16];
    int n = snprintf(saved, sizeof(saved), "%s.saved", f->build.image_path);
    if (n <= 0 || (size_t)n >= sizeof(saved) || rename(f->build.image_path, saved)) return false;
    struct abc_leaf leaf; abc_open(&leaf); json_free(&leaf.in);
    struct json_value wire, keep; json_init(&wire); json_init(&keep);
    bool ok = app_receive_preview_open_input(p, &leaf.in) && abc_exec("app.open", &leaf) &&
        !strcmp(leaf.out.error.code, "IMAGE_REFUSED") && arpt_wire(&leaf, "app.open", &wire) &&
        !app_receive_preview_bind_preview(p, &wire, failure) &&
        app_receive_preview_keep_input(p, &keep, failure) == APP_RECEIVE_PREVIEW_KEEP_REFUSED;
    bool restored = rename(saved, f->build.image_path) == 0;
    json_free(&wire); json_free(&keep); abc_close(&leaf); return ok && restored;
}
static bool arpt_preview(struct ak_fixture *f, struct app_receive_preview *p,
    struct zcl_command_reply *failure)
{
    struct abc_leaf leaf; abc_open(&leaf); json_free(&leaf.in);
    struct json_value wire, keep; json_init(&wire); json_init(&keep);
    bool ok = app_receive_preview_keep_input(p, &keep, failure) == APP_RECEIVE_PREVIEW_KEEP_REFUSED &&
        !strcmp(failure->error.code, "PREVIEW_REQUIRED");
    json_free(&keep);
    ok = ok && arpt_failed_open(f, p, failure) && app_receive_preview_open_input(p, &leaf.in) &&
        abc_pass("app.open", &leaf) && arpt_wire(&leaf, "app.open", &wire);
    aso_track_ready(&leaf.out.data, &f->build);
    ok = ok && aj_live_identity(&leaf.out.data, &f->build) &&
        app_receive_preview_bind_preview(p, &wire, failure);
    json_free(&wire); abc_close(&leaf);
    bool cleaned = aso_cleanup_children(); return ok && cleaned;
}
static bool arpt_keep(struct ak_fixture *f, struct app_receive_preview *p,
    struct zcl_command_reply *failure, char route[33])
{
    struct abc_leaf leaf; abc_open(&leaf); json_free(&leaf.in);
    struct json_value stale, same; json_init(&stale); json_init(&same);
    bool ok = app_receive_preview_keep_input(p, &leaf.in, failure) == APP_RECEIVE_PREVIEW_KEEP_NEW &&
        json_get_int(json_get(&leaf.in, "expected_revision")) == 0 && json_copy_checked(&stale, &leaf.in);
    if (ok) {
        (void)snprintf(route, 33, "%s", aso_string(&leaf.in, "name"));
        ok = strlen(route) == 32 && !strncmp(route, "kept:received-", 14) && abc_pass("app.keep", &leaf);
    }
    if (ok) ok = app_receive_preview_keep_input(p, &same, failure) == APP_RECEIVE_PREVIEW_KEEP_SAME && same.type == JSON_NULL;
    if (ok) {
        abc_close(&leaf); abc_open(&leaf); json_free(&leaf.in); leaf.in = stale; json_init(&stale);
        ok = abc_exec("app.keep", &leaf) && !strcmp(leaf.out.error.code, "SELECTION_STALE");
    }
    struct app_selection selected;
    ok = ok && app_selection_load(f->env.state_dir, route, &selected) == APP_SELECTION_OK && selected.revision == 1;
    json_free(&stale); json_free(&same); abc_close(&leaf); return ok;
}
static bool arpt_collision(struct ak_fixture *f, struct app_receive_preview *p,
    struct zcl_command_reply *failure, const char *route)
{
    struct app_selection original, other, saved;
    if (app_selection_load(f->env.state_dir, route, &original) != APP_SELECTION_OK) return false;
    struct zcl_package_copy copy = {0};
    bool opened = zcl_package_copy_open_selected_as(f->world.bob_copy, ZCL_PACKAGE_COPY_READ,
        &copy, failure, "preview-test", NULL);
    other = original;
    if (opened) memcpy(other.version, copy.head_version, 32);
    zcl_package_copy_close(&copy);
    if (!opened || !memcmp(other.version, original.version, 32)) return false;
    if (app_selection_save(f->env.state_dir, original.revision, &other, &saved) != APP_SELECTION_OK) return false;
    struct app_launch_entry displayed;
    struct zcl_command_reply stale_reply; zcl_command_reply_init(&stale_reply, "zcl.app_open.v1");
    bool stale_ok = app_launch_kept_entry(route, &displayed);
    if (stale_ok) zcl_native_app_open_snapshot(&f->env, &displayed, &original, &stale_reply);
    stale_ok = stale_ok && !strcmp(stale_reply.error.code, "SELECTION_STALE") &&
        !json_get(&stale_reply.data, "pid");
    zcl_command_reply_free(&stale_reply);
    if (!stale_ok) return false;
    struct json_value input; json_init(&input);
    bool ok = app_receive_preview_keep_input(p, &input, failure) == APP_RECEIVE_PREVIEW_KEEP_REFUSED &&
        !strcmp(failure->error.code, "PREVIEW_ROUTE_COLLISION");
    struct app_selection after;
    ok = ok && app_selection_load(f->env.state_dir, route, &after) == APP_SELECTION_OK &&
        after.revision == saved.revision && !memcmp(after.version, other.version, 32);
    json_free(&input); return ok;
}
static bool arpt_corrupt(struct ak_fixture *f, struct app_receive_preview *p,
    struct zcl_command_reply *failure, const char *route)
{
    char path[APP_SELECTION_PATH_MAX + 64];
    int n = snprintf(path, sizeof(path), "%s/@kept-%s.selection", f->env.state_dir, route + 5);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) return false;
    bool wrote = write(fd, "bad", 3) == 3; bool closed = close(fd) == 0;
    struct json_value input; json_init(&input);
    bool ok = wrote && closed && app_receive_preview_keep_input(p, &input, failure) == APP_RECEIVE_PREVIEW_KEEP_REFUSED &&
        !strcmp(failure->error.code, "SELECTION_UNREADABLE");
    json_free(&input); return ok;
}
static int arpt_acceptance(struct ak_fixture *f)
{
    int failures = 0; struct app_receive_preview *p = NULL; char route[33] = {0};
    struct zcl_command_reply failure; zcl_command_reply_init(&failure, "zcl.test.preview.v1");
    /* A later helper refusal must preserve the already committed receipt. */
    bool seeded = json_push_kv_str(&failure.data, "receipt_marker", "received");
    failure.error.mutated = true;
    TEST("received preview pins saved source, rejects failed replies and never overwrites Keep") {
        ASSERT(seeded && arpt_received(f, &p, &failure));
        ASSERT(arpt_build(f, p, &failure));
        ASSERT(arpt_preview(f, p, &failure));
        ASSERT(arpt_keep(f, p, &failure, route));
        ASSERT(arpt_collision(f, p, &failure, route));
        ASSERT(arpt_corrupt(f, p, &failure, route));
        ASSERT(failure.error.mutated && !strcmp(aso_string(&failure.data, "receipt_marker"), "received"));
        PASS();
    } _test_next:;
    app_receive_preview_close(p); zcl_command_reply_free(&failure); return failures;
}

static int ak_draft_acceptance(struct ak_fixture *f)
{
    int failures = 0; char blob[65];
    TEST("My Apps reviews an unkept draft and keeps the exact preview despite a newer edit") {
        ASSERT(ak_received(f) && ak_environment(f) && ak_preview_keep(f));
        ASSERT(ak_read_source(f, blob) && ak_edit_source(f, blob));
        ASSERT(ak_draft_failure_notice(f));
        ASSERT(ak_draft_preview_keep(f, false));
        ASSERT(ak_draft_preview_keep_variant(f, false, false, false, false, false, true));
        ASSERT(ak_draft_preview_keep_variant(f, false, true, false, false, false, true));
        ASSERT(ak_draft_preview_keep(f, true));
        ASSERT(ak_draft_stale_controls(f));
        PASS();
    } _test_next:;
    return failures;
}
static int ak_draft_history_acceptance(struct ak_fixture *f, bool capped, bool share_cancel, bool prep_cancel)
{
    int failures = 0; char blob[65];
    TEST("My Apps retains prior preparation and kept preview after a later share failure") {
        ASSERT(ak_received(f) && ak_environment(f) && ak_preview_keep(f));
        ASSERT(ak_read_source(f, blob) && ak_edit_source(f, blob));
        ASSERT(ak_draft_preview_keep_variant(f, true, true, capped, share_cancel, prep_cancel, false));
        PASS();
    } _test_next:;
    return failures;
}
static int ak_draft_history_one(bool capped, bool share_cancel, bool prep_cancel)
{
    struct ak_fixture history = {0};
    int failures = ak_draft_history_acceptance(&history, capped, share_cancel, prep_cancel);
    if (!aso_cleanup_children()) failures++;
    if (history.world.root[0]) (void)test_rm_rf_recursive(history.world.root);
    return failures;
}
static int ak_draft_history_run(void)
{
    int failures = ak_draft_history_one(false, false, false);
    failures += ak_draft_history_one(true, false, false);
    failures += ak_draft_history_one(false, true, false);
    failures += ak_draft_history_one(false, false, true);
    return failures;
}

struct ak_recovery_view { struct ak_fixture *fixture; bool fail_trust, build, keep, observed, changed, previewed, cautious_notice; char backup[APP_SELECTION_PATH_MAX]; };
bool zcl_test_library_recovery_failure(const struct json_value *expected, const struct json_value *prior,
                                       struct zcl_command_reply *reply);
static bool ak_recovery_room(void *context, const struct zcl_present_model_v1 *model,
    const char *copy_text, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    (void)context; (void)copy_text; (void)why; (void)cap;
    const char *wanted = !strcmp(model->request_id, "library-home") ? "discover" :
        !strcmp(model->request_id, "library-discover-options") ? "recover-copies" :
        !strcmp(model->request_id, "library-recovered-copies") ? "recover-select" : NULL;
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    if (!wanted) { event->outcome = ZCL_PRESENT_WINDOW_DISMISSED; return true; }
    for (uint32_t i = 0; i < model->action_count; ++i) if (!strcmp(model->actions[i].id, wanted)) {
        event->outcome = ZCL_PRESENT_WINDOW_ACTION; event->action_index = i; return true;
    }
    return false;
}
static bool ak_recovery_preview_choice(struct ak_recovery_view *v, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    bool close = false, redraw = false; uint32_t count = 0;
    v->previewed = true;
    if (!v->keep) return aj_receive_action(live, 0, &close, &redraw) && close;
    if (!zcl_present_model_page_count_v1(model, &count, why, cap)) return false;
    for (uint32_t i = 1; i < count; ++i)
        if (!aj_receive_action(live, 2, &close, &redraw) || close) return false;
    return aj_receive_action(live, 3, &close, &redraw) && close;
}
static bool ak_recovery_ready(struct ak_recovery_view *v, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    bool close = false, redraw = false; uint32_t count = 0;
    v->observed = aj_receive_field(model, "Saved version: ", v->fixture->build.version) &&
        aj_receive_field(model, "Copy location: ", v->fixture->world.bob_copy);
    if (!v->observed) return false;
    if (!v->fail_trust && !v->build) return aj_receive_action(live, 0, &close, &redraw) && close;
    if (!zcl_present_model_page_count_v1(model, &count, why, cap)) return false;
    for (uint32_t i = 1; i < count; ++i)
        if (!aj_receive_action(live, 2, &close, &redraw) || close) return false;
    if (v->fail_trust) v->changed = rename(v->fixture->trust, v->backup) == 0;
    return (!v->fail_trust || v->changed) && aj_receive_action(live, 3, &close, &redraw) && close;
}
static bool ak_recovery_notice(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    struct ak_recovery_view *v = context; bool close = false, redraw = false;
    if (!pages || !live) return false;
    if (!model->action_count) return ak_draft_wait_worker(live);
    if (!strcmp(model->title, "Preview opened")) return ak_recovery_preview_choice(v, model, live, why, cap);
    if (!strcmp(model->title, "The next step did not finish"))
        v->cautious_notice = !strcmp(model->summary, "Review the received copy before continuing. Nothing is retried automatically.") &&
            !strstr(model->summary, "is retained");
    if (strcmp(model->title, "Your copy is ready"))
        return aj_receive_action(live, 0, &close, &redraw) && close;
    return ak_recovery_ready(v, model, live, why, cap);
}
static bool ak_recovery_expected_matches(const struct json_value *expected, const struct ak_fixture *f)
{
    return !strcmp(aso_string(expected, "destination"), f->world.bob_copy) &&
        !strcmp(aso_string(expected, "version"), f->build.version) &&
        !strcmp(aso_string(expected, "release_id"), f->release) &&
        !strcmp(aso_string(expected, "package_root"), f->build.package);
}
static bool ak_recovery_wire(struct zcl_command_reply *reply, const struct ak_fixture *f)
{
    const struct zcl_command_registry *reg = zcl_command_catalog(); bool alias = false;
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", &alias);
    char wire[ZCL_COMMAND_ERROR_BUDGET + 1];
    size_t n = spec ? zcl_command_registry_test_reply_wire(reg, spec, reply, wire, sizeof(wire)) : 0;
    struct json_value doc; json_init(&doc);
    bool ok = n && n <= ZCL_COMMAND_ERROR_BUDGET && json_read(&doc, wire, n);
    const struct json_value *facts = json_get(json_get(&doc, "error"), "facts");
    const struct json_value *expected = json_get(facts, "recovery_expected");
    const struct json_value *executed = json_get(facts, "continuation_executed");
    const struct json_value *selected = json_get(facts, "selection_changed");
    ok = ok && ak_recovery_expected_matches(expected, f) &&
        executed && executed->type == JSON_BOOL && !json_get_bool(executed) &&
        selected && selected->type == JSON_BOOL && !json_get_bool(selected) &&
        json_get_bool(json_get(facts, "details_unavailable"));
    json_free(&doc); return ok;
}
static bool ak_recovery_move(struct ak_fixture *f)
{
    char directory[ABC_PATH], destination[ABC_PATH];
    int n = snprintf(directory, sizeof(directory), "%s/copies", f->world.bob_datadir);
    int m = snprintf(destination, sizeof(destination), "%s/original", directory);
    if (n <= 0 || (size_t)n >= sizeof(directory) || m <= 0 || (size_t)m >= sizeof(destination) ||
        mkdir(directory, 0700) || rename(f->world.bob_copy, destination)) return false;
    return snprintf(f->world.bob_copy, sizeof(f->world.bob_copy), "%s", destination) > 0;
}
static bool ak_recovery_prior(const struct ak_fixture *f, struct json_value *prior, size_t length)
{
    char path[APP_SELECTION_PATH_MAX];
    if (!length || length >= sizeof(path)) return false;
    memset(path, 'a', length); path[0] = '/'; path[length] = 0;
    json_init(prior); json_set_object(prior);
    return json_push_kv_str(prior, "destination", path) &&
        json_push_kv_str(prior, "version", f->build.version) &&
        json_push_kv_str(prior, "release_id", f->release) &&
        json_push_kv_str(prior, "package_root", f->build.package) &&
        json_push_kv_str(prior, "publisher_fingerprint", "021111111111111111111111111111111111111111111111111111111111111111");
}
static bool ak_recovery_projection_fits(const struct json_value *expected, const struct json_value *prior)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    zcl_package_copy_fail(&reply, "PREVIEW_WORKER_FAILED", true, "The worker stopped.", "fixture");
    bool fits = zcl_test_library_recovery_failure(expected, prior, &reply);
    zcl_command_reply_free(&reply); return fits;
}
static bool ak_recovery_history_matches(const struct ak_fixture *f, const struct json_value *prior,
                                        const struct json_value *facts)
{
    const struct json_value *history = json_get(facts, "historical_receive");
    const struct json_value *selection = json_get(facts, "selection_changed");
    return !strcmp(aso_string(history, "destination"), aso_string(prior, "destination")) &&
        !strcmp(aso_string(history, "version"), f->build.version) &&
        !strcmp(aso_string(history, "release_id"), f->release) &&
        !strcmp(aso_string(history, "package_root"), f->build.package) &&
        !strcmp(aso_string(history, "publisher_fingerprint"), aso_string(prior, "publisher_fingerprint")) &&
        selection && selection->type == JSON_NULL &&
        !strcmp(aso_string(json_get(facts, "recovery_expected"), "version"), f->build.version);
}
static bool ak_recovery_projection_wire(const struct ak_fixture *f, const struct json_value *expected,
                                        const struct json_value *prior)
{
    struct json_value null_value, doc; json_init(&null_value); json_init(&doc);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    bool ok = json_push_kv_str(&reply.data, "name", "stale-current") &&
        json_push_kv(&reply.data, "continuation_executed", &null_value) &&
        json_push_kv(&reply.data, "selection_changed", &null_value);
    zcl_package_copy_fail(&reply, "PREVIEW_WORKER_FAILED", true, "The worker stopped.", "fixture");
    memset(reply.error.code, 'A', sizeof(reply.error.code) - 1); reply.error.code[sizeof(reply.error.code) - 1] = 0;
    memset(reply.error.message, '"', 160); reply.error.message[160] = 0;
    ok = ok && zcl_test_library_recovery_failure(expected, prior, &reply);
    const struct zcl_command_registry *reg = zcl_command_catalog(); bool alias = false;
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", &alias);
    char wire[ZCL_COMMAND_ERROR_BUDGET + 1];
    size_t n = ok && spec ? zcl_command_registry_test_reply_wire(reg, spec, &reply, wire, sizeof(wire)) : 0;
    ok = ok && n && n <= ZCL_COMMAND_ERROR_BUDGET && json_read(&doc, wire, n);
    const struct json_value *facts = json_get(json_get(&doc, "error"), "facts");
    ok = ok && !json_get(facts, "name") && ak_recovery_history_matches(f, prior, facts);
    json_free(&doc); json_free(&null_value);
    zcl_command_reply_free(&reply); return ok;
}
static bool ak_recovery_projection_test(const struct ak_fixture *f)
{
    struct json_value expected; json_init(&expected); json_set_object(&expected);
    bool ok = json_push_kv_str(&expected, "destination", f->world.bob_copy) &&
        json_push_kv_str(&expected, "version", f->build.version) &&
        json_push_kv_str(&expected, "release_id", f->release) &&
        json_push_kv_str(&expected, "package_root", f->build.package);
    size_t low = 1, high = APP_SELECTION_PATH_MAX - 1;
    while (ok && low < high) {
        size_t mid = low + (high - low + 1) / 2;
        struct json_value prior;
        ok = ak_recovery_prior(f, &prior, mid);
        bool fits = ok && ak_recovery_projection_fits(&expected, &prior);
        json_free(&prior);
        if (fits) low = mid; else high = mid - 1;
    }
    struct json_value prior; json_init(&prior);
    ok = ok && low < APP_SELECTION_PATH_MAX - 1 && ak_recovery_prior(f, &prior, low) &&
        ak_recovery_projection_wire(f, &expected, &prior);
    json_free(&prior); json_init(&prior);
    ok = ok && ak_recovery_prior(f, &prior, low + 1) && !ak_recovery_projection_fits(&expected, &prior);
    json_free(&prior); json_free(&expected); return ok;
}
static bool ak_recovery_success_wire(struct zcl_command_reply *reply, const struct ak_fixture *f, bool keep)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = zcl_command_registry_find(reg, "app.library", NULL);
    char wire[32769];
    struct zcl_command_budget_fixture budget = {.budget_bytes = spec ? (size_t)spec->budget_bytes : 0};
    size_t n = spec ? zcl_command_registry_test_reply_wire_fixture(reg, spec, reply, &budget, wire, sizeof(wire)) : 0;
    struct json_value doc; json_init(&doc);
    bool ok = n && n < sizeof(wire) && json_read(&doc, wire, n) && !strcmp(aso_string(&doc, "status"), "passed");
    const struct json_value *data = json_get(&doc, "data"), *kept = json_get(data, "kept");
    ok = ok && !strcmp(aso_string(data, "destination"), f->world.bob_copy) &&
        !strcmp(aso_string(data, "version"), f->build.version) &&
        !strcmp(aso_string(data, "release_id"), f->release) &&
        !strcmp(aso_string(data, "package_root"), f->build.package) &&
        (!keep ? !kept : kept && !strcmp(aso_string(kept, "version"), f->build.version));
    json_free(&doc); return ok;
}
static bool ak_recovery_selection(struct ak_fixture *f, const struct zcl_command_reply *reply, bool keep)
{
    if (!keep) return !json_get(&reply->data, "kept");
    struct app_selection selected; const char *name = aso_string(json_get(&reply->data, "kept"), "name");
    uint8_t version[32];
    return zcl_hex_decode_lower(f->build.version, version, sizeof(version)) &&
        app_selection_load(f->env.state_dir, name, &selected) == APP_SELECTION_OK &&
        !memcmp(selected.version, version, sizeof(version));
}
static bool ak_recovery_build(struct ak_fixture *f, bool keep)
{
    char worker[PATH_MAX], old_dir[PATH_MAX];
    if (!realpath("build/bin/z23-dev", worker)) return false;
    zcl_native_bridge_ensure_rpc();
    (void)snprintf(old_dir, sizeof(old_dir), "%s", zcl_native_command_datadir());
    int old_port = zcl_native_command_rpc_port();
    zcl_native_bridge_bind_rpc(f->world.bob_datadir, 39461);
    struct ak_recovery_view view = {.fixture = f, .build = true, .keep = keep};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    zcl_test_app_library_discover_worker(&f->env, f->world.bob_datadir, &reply,
        ak_recovery_room, ak_recovery_notice, &view, worker);
    zcl_native_bridge_bind_rpc(old_dir, old_port);
    const struct json_value *changed = json_get(&reply.data, "selection_changed");
    bool ok = view.observed && view.previewed && reply.status == ZCL_COMMAND_STATUS_PASSED &&
        reply.error.mutated && !strcmp(aso_string(&reply.data, "version"), f->build.version) &&
        !strcmp(aso_string(&reply.data, "continuation"), keep ? "kept" : "previewed") &&
        changed && changed->type == JSON_BOOL && json_get_bool(changed) == keep &&
        json_get_bool(json_get(&reply.data, "continuation_executed"));
    ok = ok && ak_recovery_selection(f, &reply, keep);
    ok = ok && ak_recovery_success_wire(&reply, f, keep);
    bool stopped = ak_draft_stop_preview(f, &reply);
    zcl_command_reply_free(&reply); return ok && stopped;
}
static bool ak_recovery_link_refused(const struct ak_fixture *f)
{
    char link[ABC_PATH];
    int n = snprintf(link, sizeof(link), "%s/copies/link", f->world.bob_datadir);
    if (n <= 0 || (size_t)n >= sizeof(link) || symlink(f->world.bob_copy, link)) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    struct app_receive_preview *preview = NULL;
    bool refused = !app_receive_preview_create_recovered(link, f->world.bob_datadir, NULL, &preview, &reply) &&
        !reply.error.mutated && !preview;
    app_receive_preview_close(preview); zcl_command_reply_free(&reply);
    return unlink(link) == 0 && refused;
}
static bool ak_recovery_state(const struct ak_fixture *f, const char *head, uint8_t digest[32])
{
    uint8_t *bytes = NULL, version[32]; size_t size = 0;
    bool ok = zcl_read_whole_file(f->trust, 65536, &bytes, &size, "received trust snapshot") &&
        zcl_hex_decode_lower(head, version, sizeof(version));
    if (ok) sha3_256(bytes, size, digest);
    free(bytes);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.recovery_state.v1");
    struct zcl_package_copy copy = {0};
    ok = ok && zcl_package_copy_open_as(f->world.bob_copy, ZCL_PACKAGE_COPY_READ, &copy, &reply, "recovery-state") &&
        !memcmp(copy.head_version, version, sizeof(version));
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply);
    char directory[ABC_PATH];
    int n = snprintf(directory, sizeof(directory), "%s/copies", f->world.bob_datadir);
    struct platform_directory_list list = {0};
    ok = ok && n > 0 && (size_t)n < sizeof(directory) && platform_directory_list_real_sorted(directory, &list) &&
        list.count == 1 && !strcmp(list.entries[0].name, "original");
    platform_directory_list_free(&list); return ok;
}
static bool ak_recovery_unchanged(const struct ak_fixture *f, const char *head, const uint8_t before[32])
{
    uint8_t after[32];
    return ak_recovery_state(f, head, after) && !memcmp(before, after, sizeof(after));
}
static bool ak_recovery_cancel(struct ak_fixture *f)
{
    struct ak_recovery_view view = {.fixture = f};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    zcl_test_app_library_discover_worker(&f->env, f->world.bob_datadir, &reply,
        ak_recovery_room, ak_recovery_notice, &view, NULL);
    bool ok = view.observed && reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated &&
        !strcmp(aso_string(&reply.data, "stage"), "recovery") &&
        !strcmp(aso_string(&reply.data, "version"), f->build.version);
    zcl_command_reply_free(&reply); return ok;
}
static bool ak_recovery_trust_failure(struct ak_fixture *f)
{
    struct ak_recovery_view view = {.fixture = f, .fail_trust = true};
    int n = snprintf(view.backup, sizeof(view.backup), "%s.saved", f->trust);
    if (n <= 0 || (size_t)n >= sizeof(view.backup)) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_open.v1");
    zcl_test_app_library_discover_worker(&f->env, f->world.bob_datadir, &reply,
        ak_recovery_room, ak_recovery_notice, &view, NULL);
    bool failed = view.observed && view.changed && view.cautious_notice && reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !reply.error.mutated && ak_recovery_wire(&reply, f);
    bool restored = !view.changed || rename(view.backup, f->trust) == 0;
    zcl_command_reply_free(&reply); return failed && restored;
}
static int ak_recovery_acceptance(struct ak_fixture *f)
{
    int failures = 0; char head[65]; uint8_t trust[32];
    TEST("My Apps recovers the received fork after restart and refuses changed trust") {
        ASSERT(ak_received(f) && ak_recovery_move(f) && ak_environment(f));
        ASSERT(ak_recovery_link_refused(f));
        ASSERT(ak_recovery_projection_test(f));
        ASSERT(abc_put(f->world.bob_copy, "include/boost.h", "#define BOOST 9\n") &&
            abc_save(f->world.bob_copy, head) && strcmp(head, f->build.version));
        ASSERT(ak_recovery_state(f, head, trust));
        ASSERT(ak_recovery_cancel(f));
        ASSERT(ak_recovery_unchanged(f, head, trust));
        ASSERT(ak_recovery_trust_failure(f));
        ASSERT(ak_recovery_unchanged(f, head, trust));
        ASSERT(ak_recovery_build(f, false));
        ASSERT(ak_recovery_unchanged(f, head, trust));
        ASSERT(ak_recovery_build(f, true));
        ASSERT(ak_recovery_unchanged(f, head, trust));
        PASS();
    } _test_next:;
    return failures;
}

static int ak_recovery_run(bool run)
{
    struct ak_fixture recovery = {0};
    int failures = run ? ak_recovery_acceptance(&recovery) : 0;
    if (!aso_cleanup_children()) failures++;
    if (recovery.world.root[0]) (void)test_rm_rf_recursive(recovery.world.root);
    return failures;
}
static int ak_routes(void)
{
    struct aso_env env[] = {{"HOME", NULL}, {"XDG_CONFIG_HOME", NULL}, {"XDG_STATE_HOME", NULL},
                            {"DISPLAY", NULL}, {"WAYLAND_DISPLAY", NULL}};
    size_t saved = 0; int failures = 0;
    for (; saved < sizeof(env) / sizeof(env[0]); ++saved) {
        const char *value = getenv(env[saved].key);
        env[saved].saved = value ? strdup(value) : NULL;
        if (value && !env[saved].saved) { failures++; break; }
    }
    struct ak_fixture fixture = {0};
    if (!failures) failures += ak_acceptance(&fixture);
    if (!aso_cleanup_children()) failures++;
    struct ak_fixture continuation = {0};
    if (!failures) failures += arpt_acceptance(&continuation);
    if (!aso_cleanup_children()) failures++;
    if (continuation.world.root[0]) (void)test_rm_rf_recursive(continuation.world.root);
    struct ak_fixture draft = {0};
    if (!failures) failures += ak_draft_acceptance(&draft);
    if (!aso_cleanup_children()) failures++;
    if (draft.world.root[0]) (void)test_rm_rf_recursive(draft.world.root);
    if (!failures) failures += ak_draft_history_run();
    failures += ak_recovery_run(!failures);
    aso_env_restore(env, saved);
    if (fixture.world.root[0]) (void)test_rm_rf_recursive(fixture.world.root);
    return failures;
}
/* Three people, ordinary native authorities. Presenter callbacks exercise local
 * consent, not a human/window; the no-args child proves image identity only. */
struct rr_cycle {
    struct ak_fixture bob, carol;
    struct abc_world owner;
    char head[65], personal[65], edited[65], publisher[67], space[64];
    char mcp_setup[8192];
    uint8_t keep[32];
};
static bool rr_text(const char *copy, const char *path, const char *expected)
{
    char full[ABC_PATH]; char *text = NULL; size_t size = 0;
    int n = snprintf(full, sizeof(full), "%s/%s", copy, path);
    bool ok = n > 0 && (size_t)n < sizeof(full) &&
        zcl_read_whole_file_text(full, 65536, &text, &size, "recipient cycle source") &&
        size == strlen(expected) && !memcmp(text, expected, size);
    free(text); return ok;
}
static bool rr_keep_hash(const struct ak_fixture *f, uint8_t hash[32])
{
    char path[APP_SELECTION_PATH_MAX + 64]; uint8_t *bytes = NULL; size_t size = 0;
    int n = snprintf(path, sizeof(path), "%s/@kept-received.selection", f->env.state_dir);
    bool ok = n > 0 && (size_t)n < sizeof(path) &&
        zcl_read_whole_file(path, 65536, &bytes, &size, "recipient cycle Keep");
    if (ok) sha3_256(bytes, size, hash);
    free(bytes); return ok;
}
static bool rr_preserved(const struct rr_cycle *r, const char *head)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.recipient.v1");
    struct zcl_package_copy copy = {0}; uint8_t expected[32], keep[32];
    bool ok = zcl_hex_decode_lower(head, expected, 32) &&
        zcl_package_copy_open_selected_as(r->owner.copy, ZCL_PACKAGE_COPY_READ,
            &copy, &reply, "recipient-cycle", head) && !memcmp(copy.head_version, expected, 32);
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply);
    return ok && rr_text(r->owner.copy, "include/boost.h", "#define BOOST 4\n") &&
        rr_keep_hash(&r->bob, keep) && !memcmp(keep, r->keep, sizeof(keep));
}
static bool rr_newer_dirty(struct rr_cycle *r, const char *saved)
{
    return abc_put(r->owner.copy, "include/boost.h", saved) &&
        abc_save(r->owner.copy, r->head) &&
        strcmp(r->head, r->bob.build.version) &&
        abc_put(r->owner.copy, "include/boost.h", "#define BOOST 4\n") &&
        rr_preserved(r, r->head);
}
static bool rr_trusted(const struct ak_fixture *f)
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.recipient.v1");
    bool ok = zcl_package_copy_open_selected_as(f->world.bob_copy, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "recipient-cycle", NULL) &&
        zcl_package_copy_adopted(f->world.bob_datadir, &copy, NULL) == ZCL_PACKAGE_COPY_RECEIVED_TRUSTED;
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply); return ok;
}
static bool rr_start(struct rr_cycle *r)
{
    const char *source = "#include <stdio.h>\n#include <unistd.h>\n#include \"boost.h\"\n"
        "int main(int n,char **v){(void)v;if(n!=1)return 7;"
        "printf(\"BOOST=%d\\n\",BOOST);fflush(stdout);for(;;)pause();}\n";
    if (!ak_received_source(&r->bob, source) || !ak_environment(&r->bob) ||
        !rr_trusted(&r->bob) || !ak_preview_keep(&r->bob) || !ak_restart(&r->bob)) return false;
    r->owner = r->bob.world;
    (void)snprintf(r->owner.copy, sizeof(r->owner.copy), "%s", r->bob.world.bob_copy);
    (void)snprintf(r->owner.alice_datadir, sizeof(r->owner.alice_datadir), "%s", r->bob.world.bob_datadir);
    (void)snprintf(r->owner.alice_home, sizeof(r->owner.alice_home), "%s", r->bob.world.bob_home);
    return rr_keep_hash(&r->bob, r->keep) && rr_newer_dirty(r, "#define BOOST 3\n");
}
struct rr_consent { const struct rr_cycle *cycle; bool confirmed, cancel; unsigned calls; char setup[8192]; };
static bool rr_personal_fields(const struct zcl_present_model_v1 *model, const struct rr_cycle *r)
{
    return aj_receive_field(model, "Kept app: ", AK_ROUTE) &&
        aj_receive_field(model, "Kept revision: ", "1") &&
        aj_receive_field(model, "Copy: ", r->owner.copy) &&
        aj_receive_field(model, "Datadir: ", r->owner.alice_datadir) &&
        aj_receive_field(model, "Saved version: ", r->bob.build.version) &&
        aj_receive_field(model, "Current HEAD: ", r->head) &&
        aj_receive_field(model, "Identity: ",
            "Create a local publishing key after confirmation; personal namespace is pending.");
}
static bool rr_consent_pages(struct rr_consent *view,
    const struct zcl_present_window_live_view_v1 *live, uint32_t count)
{
    bool close = false, redraw = false;
    if (view->cancel) return aj_receive_action(live, 0, &close, &redraw) && close;
    if (!aj_receive_early_guided(live)) return false;
    for (uint32_t i = 2; i < count; ++i)
        if (!aj_receive_action(live, 2, &close, &redraw) || close || !redraw) return false;
    view->confirmed = aj_receive_action(live, 3, &close, &redraw) && close;
    return view->confirmed;
}
static bool rr_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct rr_consent *view = context; uint32_t count = 0;
    if (!pages || pages->page_count != 1 || !pages->pages->pixels ||
        !rr_personal_fields(model, view->cycle) ||
        !zcl_present_model_page_count_v1(model, &count, why, cap) || count < 2) return false;
    return rr_consent_pages(view, live, count);
}
static const char *rr_library_target(const struct zcl_present_model_v1 *model, const char *copy_text)
{
    const char *wanted = !strcmp(model->request_id, "library-home") ? "myapps" :
        copy_text ? "cancel" :
        model->action_count && !strcmp(model->actions[0].id, "choose") ? "choose" : "help";
    if (!strcmp(wanted, "help"))
        for (unsigned i = 0; i < model->action_count; ++i)
            if (!strcmp(model->actions[i].id, "change-options")) wanted = "change-options";
    return wanted;
}
static bool rr_library_present(void *context, const struct zcl_present_model_v1 *model,
    const char *copy_text, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    (void)why; (void)cap;
    struct rr_consent *view = context;
    if (++view->calls > 12) return false;
    const char *wanted = rr_library_target(model, copy_text);
    if (!strcmp(wanted, "choose")) {
        char short_version[13]; memcpy(short_version, view->cycle->bob.build.version, 12); short_version[12] = 0;
        const char *base = strrchr(view->cycle->owner.copy, '/');
        if (!model->item_count || !strstr(model->items[0].value, "Saved version ") ||
            !strstr(model->items[0].value, short_version) || !base || !strstr(model->summary, base + 1)) wanted = "next";
    }
    if (copy_text) (void)snprintf(view->setup, sizeof(view->setup), "%s", copy_text);
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    for (unsigned i = 0; i < model->action_count; ++i)
        if (!strcmp(model->actions[i].id, wanted)) { event->action_index = i; return true; }
    return false;
}
static bool rr_cancel_personalize(struct rr_cycle *r)
{
    struct rr_consent view = {.cycle = r, .cancel = true}; struct zcl_command_reply reply;
    char key[4400]; bool exists = false;
    zcl_command_reply_init(&reply, "zcl.app_library.v1");
    zcl_test_app_library_native_at(&r->bob.env, NULL, r->owner.alice_datadir, &reply,
        rr_library_present, &view, rr_present);
    bool canceled = reply.status == ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(aso_string(&reply.data, "status"), "canceled") && !reply.error.mutated &&
        app_personalize_key_probe(&reply, key, sizeof(key), r->publisher, &exists) && !exists &&
        rr_preserved(r, r->head);
    zcl_command_reply_free(&reply);
    return canceled;
}
static bool rr_setup_guide(const struct json_value *setup)
{
    const char *request = aso_string(setup, "request");
    return strstr(request, "expected_head from head_version") && strstr(request, "expected_blob from file.blob") &&
        strstr(request, "plan_id and confirm=true") && strstr(request, "re-read before another edit") &&
        strstr(request, "explicit Keep and Share choices");
}
static bool rr_setup_identity(struct rr_cycle *r, const struct rr_consent *view,
    struct zcl_command_reply *reply, struct json_value *setup)
{
    char key[4400]; bool exists = false;
    bool ok = reply->status == ZCL_COMMAND_STATUS_PASSED && view->confirmed &&
        json_read(setup, view->setup, strlen(view->setup)) && rr_setup_guide(setup) &&
        !strcmp(aso_string(setup, "name"), AK_ROUTE) &&
        json_get(setup, "revision") && json_get(setup, "revision")->type == JSON_INT &&
        json_get_int(json_get(setup, "revision")) == 1 &&
        !strcmp(aso_string(setup, "version"), r->bob.build.version);
    (void)snprintf(r->personal, sizeof(r->personal), "%s", aso_string(setup, "source_version"));
    return ok && strlen(r->personal) == 64 && strcmp(r->personal, r->head) &&
        app_personalize_key_probe(reply, key, sizeof(key), r->publisher, &exists) && exists &&
        app_personalize_namespace(r->publisher, r->space, sizeof(r->space));
}
static bool rr_preparation_identity(struct rr_cycle *r, const struct zcl_command_reply *reply)
{
    const struct json_value *prepared = json_get(&reply->data, "preparation");
    const struct json_value *created = json_get(prepared, "key_created");
    char name[128]; int n = snprintf(name, sizeof(name), "%s/tinyapp", r->space);
    return n > 0 && (size_t)n < sizeof(name) &&
        !strcmp(aso_string(prepared, "version"), r->personal) &&
        !strcmp(aso_string(prepared, "namespace"), r->space) &&
        !strcmp(aso_string(prepared, "name"), name) && created &&
        created->type == JSON_BOOL && json_get_bool(created);
}
static bool rr_library_budget(struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec = abc_spec("app.library");
    char wire[ZCL_COMMAND_LIST_BUDGET + 1];
    struct zcl_command_budget_fixture fixture = {0}; size_t usable = 0, bytes = 0;
    return spec && zcl_command_registry_test_success_budget(spec, reply, &fixture,
        &usable, wire, sizeof(wire), &bytes) && bytes > 0;
}
static bool rr_setup_mcp_read(struct aso_mcp *m, const struct json_value *setup, int revision,
                              bool expect_stale)
{
    struct json_value input = {0}, doc = {0}; bool is_error = false;
    json_set_object(&input);
    bool ok = json_push_kv_str(&input, "name", aso_string(setup, "name")) &&
        json_push_kv_int(&input, "expected_revision", revision) &&
        json_push_kv_str(&input, "source_version", aso_string(setup, "source_version")) &&
        json_push_kv_str(&input, "path", "include/boost.h") &&
        aj_mcp_run_result(m, "app.customize", &input, &doc, &is_error);
    const struct json_value *data = json_get(&doc, "data");
    if (expect_stale)
        ok = ok && is_error && aso_code_is(&doc, "SELECTION_STALE");
    else
        ok = ok && !is_error && !strcmp(aso_string(data, "version"), aso_string(setup, "version")) &&
            !strcmp(aso_string(data, "source_version"), aso_string(setup, "source_version")) &&
            !strcmp(aso_string(data, "content"), "#define BOOST 1\n");
    if (!ok) printf("copied setup MCP stale=%d is_error=%d code=%s version=%s source=%s content=%s\n",
        expect_stale, is_error, aso_string(json_get(&doc, "error"), "code"),
        aso_string(data, "version"), aso_string(data, "source_version"), aso_string(data, "content"));
    json_free(&doc); json_free(&input); return ok;
}
static bool rr_setup_args(const struct json_value *setup, const char *expected_exe,
                          const char *datadir, const char **a, const char **b, const char **c)
{
    const struct json_value *args = json_get(setup, "args"); char profile[APP_SELECTION_PATH_MAX + 16];
    int n = snprintf(profile, sizeof(profile), "--datadir=%s", datadir);
    if (n <= 0 || (size_t)n >= sizeof(profile) || strcmp(aso_string(setup, "command"), expected_exe) ||
        !args || args->type != JSON_ARR || json_size(args) != 3) return false;
    *a = json_get_str(json_at(args, 0)); *b = json_get_str(json_at(args, 1)); *c = json_get_str(json_at(args, 2));
    return *a && *b && *c && !strcmp(*a, "mcp") && !strcmp(*b, "serve") && !strcmp(*c, profile);
}
static bool rr_setup_mcp(const struct json_value *setup, const char *expected_exe, const char *datadir)
{
    const char *a, *b, *c;
    if (!rr_setup_args(setup, expected_exe, datadir, &a, &b, &c)) return false;
    struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    bool ok = aso_mcp_spawn_args(&m, expected_exe, a, b, c) && aso_mcp_init(&m);
    if (!ok) printf("copied setup MCP spawn/init failed: %.200s\n", m.line);
    if (ok) ok = rr_setup_mcp_read(&m, setup, 1, false) && rr_setup_mcp_read(&m, setup, 2, true);
    return aso_mcp_close(&m) && ok;
}
static bool rr_personalize(struct rr_cycle *r)
{
    if (!rr_cancel_personalize(r)) return false;
    struct rr_consent view = {.cycle = r}; struct zcl_command_reply reply;
    struct json_value setup = {0};
    zcl_command_reply_init(&reply, "zcl.app_library.v1");
    char exe[PATH_MAX];
    if (!realpath("build/bin/z23-dev", exe)) { zcl_command_reply_free(&reply); return false; }
    zcl_test_app_library_native_at(&r->bob.env, exe, r->owner.alice_datadir, &reply,
        rr_library_present, &view, rr_present);
    bool ok = rr_setup_identity(r, &view, &reply, &setup) &&
        rr_preparation_identity(r, &reply) && rr_library_budget(&reply) &&
        rr_setup_mcp(&setup, exe, r->owner.alice_datadir);
    if (ok) {
        int n = snprintf(r->mcp_setup, sizeof(r->mcp_setup), "%s", view.setup);
        ok = n > 0 && (size_t)n < sizeof(r->mcp_setup);
    }
    if (!ok) printf("recipient library prepare: %s %s calls=%u confirmed=%d setup=%zu prepared=%d\n",
        reply.error.code, reply.error.message, view.calls, view.confirmed, strlen(view.setup),
        json_get(&reply.data, "preparation") != NULL);
    json_free(&setup); zcl_command_reply_free(&reply);
    return ok && aj_parent_is(&r->owner, r->personal, r->head) && rr_preserved(r, r->personal);
}
/* Use the exported literal MCP setup for each short-lived tool session. */
static bool rr_mcp_start(struct rr_cycle *r, struct aso_mcp *m)
{
    struct json_value setup = {0}; char exe[PATH_MAX]; const char *a, *b, *c;
    bool ok = json_read(&setup, r->mcp_setup, strlen(r->mcp_setup)) &&
        realpath("build/bin/z23-dev", exe) &&
        rr_setup_args(&setup, exe, r->owner.alice_datadir, &a, &b, &c) &&
        aso_mcp_spawn_args(m, exe, a, b, c) && aso_mcp_init(m);
    json_free(&setup); return ok;
}
static bool rr_mcp_tool(struct aso_mcp *m, const char *tool,
                        const struct json_value *input, struct json_value *doc, bool *error)
{
    struct json_value req = {0}, params = {0}, result = {0};
    json_set_object(&req); json_set_object(&params);
    bool ok = json_push_kv_str(&params, "name", tool) && json_push_kv(&params, "arguments", input) &&
        json_push_kv_str(&req, "jsonrpc", "2.0") && json_push_kv_int(&req, "id", 9) &&
        json_push_kv_str(&req, "method", "tools/call") && json_push_kv(&req, "params", &params);
    char wire[8192]; size_t n = ok ? json_write(&req, wire, sizeof(wire)) : 0;
    ok = n && n < sizeof(wire) && aso_mcp_send(m, wire, true) &&
        json_read(&result, m->line, strlen(m->line)) && aj_mcp_result(&result, doc, error);
    json_free(&result); json_free(&params); json_free(&req); return ok;
}
static bool rr_preview_open(struct rr_cycle *r, struct aso_mcp *m)
{
    struct json_value doc = {0}; bool error = false;
    struct abc_leaf leaf; bool opened = ak_request(&leaf, &r->bob, true);
    bool ok = opened && rr_mcp_tool(m, "apps_open", &leaf.in, &doc, &error) && !error;
    const struct json_value *data = json_get(&doc, "data");
    if (ok) {
        aso_track_ready(data, &r->bob.build);
        ok = !strcmp(aso_string(data, "name"), AK_ROUTE) &&
            !strcmp(aso_string(data, "status"), "opened") &&
            !strcmp(aso_string(data, "ready_basis"), "alive") &&
            aso_build_facts_match(data, &r->bob.build) && aj_live_identity(data, &r->bob.build);
    }
    abc_close(&leaf); json_free(&doc); return ok;
}
static bool rr_preview(struct rr_cycle *r, const char *version)
{
    struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    struct aso_build built = {0};
    bool ok = rr_mcp_start(r, &m) && aj_build(&m, &r->owner, version, &built) && rr_preserved(r, version);
    if (ok && !strcmp(version, r->edited) && !strcmp(built.image, r->bob.build.image)) ok = false;
    if (ok) { r->bob.build = built; ok = rr_preview_open(r, &m); }
    bool closed = aso_mcp_close(&m), clean = aso_cleanup_children();
    return ok && closed && clean && rr_preserved(r, version);
}
struct rr_keep_view { const struct rr_cycle *cycle; char current[65]; bool cancel, observed; };
static bool rr_keep_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages,
    const struct zcl_present_window_live_view_v1 *live, char *why, size_t cap)
{
    struct rr_keep_view *v = context; uint32_t count = 0;
    if (!pages || !pages->pages[0].pixels || strcmp(model->request_id, "keep-app") ||
        !zcl_present_model_page_count_v1(model, &count, why, cap) ||
        !aj_receive_field(model, "Currently kept: ", v->current) ||
        !aj_receive_field(model, "Saved app: ", AK_ROUTE) ||
        !aj_receive_field(model, "Version to keep: ", v->cycle->bob.build.version) ||
        !aj_receive_field(model, "Exact app image: ", v->cycle->bob.build.image)) return false;
    v->observed = true;
    return aso_keep_choose(live, v->cancel ? 1u : 0u, count);
}
static bool rr_keep_choice(struct rr_cycle *r, int64_t revision, bool cancel)
{
    struct abc_leaf leaf; bool ok = ak_request(&leaf, &r->bob, true) &&
        json_push_kv_int(&leaf.in, "expected_revision", revision);
    struct zcl_command_context ctx = {.plan_first = true};
    struct zcl_command_request request = {.input = &leaf.in, .context = &ctx};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_keep.v1");
    struct rr_keep_view view = {.cycle = r, .cancel = cancel};
    struct app_selection before;
    ok = ok && app_selection_load(r->bob.env.state_dir, AK_ROUTE, &before) == APP_SELECTION_OK &&
        before.revision == (uint64_t)revision;
    if (ok) zcl_hex_encode(before.version, 32, view.current);
    if (ok) zcl_native_app_keep_present(&request, &reply, rr_keep_present, &view);
    ok = ok && view.observed && reply.status == ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(aso_string(&reply.data, "status"), cancel ? "canceled" : "kept") &&
        (cancel || aso_revision_is(&reply.data, revision + 1));
    zcl_command_reply_free(&reply); abc_close(&leaf); return ok;
}
/* A stale wire request must fail before presenting any owner dialog. */
static bool rr_keep_stale_wire(struct rr_cycle *r, int64_t revision)
{
    struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    struct abc_leaf leaf; struct json_value doc = {0}; bool error = false;
    bool input = ak_request(&leaf, &r->bob, true) &&
        json_push_kv_int(&leaf.in, "expected_revision", revision);
    bool ok = input && rr_mcp_start(r, &m) &&
        rr_mcp_tool(&m, "apps_keep", &leaf.in, &doc, &error) && error &&
        aso_code_is(&doc, "SELECTION_STALE") && rr_preserved(r, r->bob.build.version);
    json_free(&doc); abc_close(&leaf);
    bool closed = aso_mcp_close(&m); return ok && closed;
}
static bool rr_keep(struct rr_cycle *r, int64_t revision)
{
    bool ok = rr_keep_choice(r, revision, true) && rr_preserved(r, r->bob.build.version) &&
        rr_keep_choice(r, revision, false);
    return ok && rr_keep_hash(&r->bob, r->keep) && rr_keep_stale_wire(r, revision) &&
        ak_restart(&r->bob) && rr_preserved(r, r->bob.build.version);
}
static bool rr_read(struct rr_cycle *r, int64_t revision, const char *content, char blob[65])
{
    struct abc_leaf leaf;
    bool ok = ak_request(&leaf, &r->bob, false) && json_push_kv_int(&leaf.in, "expected_revision", revision) &&
        json_push_kv_str(&leaf.in, "path", "include/boost.h") && abc_pass("app.customize", &leaf);
    if (ok) {
        (void)snprintf(blob, 65, "%s", aso_string(json_get(&leaf.out.data, "file"), "blob"));
        ok = strlen(blob) == 64 && !strcmp(abc_get(&leaf, "version"), r->bob.build.version) &&
            !strcmp(abc_get(&leaf, "content"), content);
    }
    abc_close(&leaf); return ok;
}
static bool rr_stale_change(struct rr_cycle *r)
{
    struct abc_leaf leaf;
    bool ok = ak_request(&leaf, &r->bob, false) &&
        json_push_kv_int(&leaf.in, "expected_revision", 1) &&
        abc_exec("app.customize", &leaf) && leaf.out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(leaf.out.error.code, "SELECTION_STALE") && !leaf.out.error.mutated;
    abc_close(&leaf);
    return ok && rr_preserved(r, r->personal);
}
static bool rr_edit_input(struct json_value *input, const struct json_value *setup,
                          const char *head, const char *blob)
{
    json_init(input); json_set_object(input);
    const struct json_value *revision = json_get(setup, "revision");
    return json_push_kv_str(input, "name", aso_string(setup, "name")) &&
        revision && revision->type == JSON_INT && json_push_kv(input, "expected_revision", revision) &&
        json_push_kv_str(input, "source_version", aso_string(setup, "source_version")) &&
        json_push_kv_str(input, "expected_head", head) &&
        json_push_kv_str(input, "path", "include/boost.h") &&
        json_push_kv_str(input, "expected_blob", blob) &&
        json_push_kv_str(input, "content", "#define BOOST 8\n");
}
static bool rr_edit_bindings(const struct json_value *data, const struct rr_cycle *r,
                             const struct json_value *setup)
{
    const struct json_value *revision = json_get(data, "source_selection_revision");
    const struct json_value *expected = json_get(setup, "revision");
    return revision && revision->type == JSON_INT && expected && expected->type == JSON_INT &&
        json_get_int(revision) == json_get_int(expected) &&
        !strcmp(aso_string(data, "kept_version"), r->bob.build.version) &&
        !strcmp(aso_string(data, "source_version"), aso_string(setup, "source_version"));
}
static bool rr_edit_transaction(struct aso_mcp *m, struct rr_cycle *r,
                                const struct json_value *setup, const char *head, const char *blob)
{
    struct json_value input, doc; json_init(&doc);
    bool ok = rr_edit_input(&input, setup, head, blob) && aj_mcp_run(m, "app.edit", &input, &doc);
    char plan[65]; const char *id = aso_string(json_get(&doc, "data"), "plan_id");
    ok = ok && strlen(id) == 64 && rr_edit_bindings(json_get(&doc, "data"), r, setup);
    if (ok) (void)snprintf(plan, sizeof(plan), "%s", id);
    json_free(&doc); json_init(&doc);
    if (ok) ok = json_push_kv_str(&input, "plan_id", plan) && json_push_kv_bool(&input, "confirm", true) &&
        aj_mcp_run(m, "app.edit", &input, &doc);
    const char *version = aso_string(json_get(&doc, "data"), "version");
    ok = ok && strlen(version) == 64 && rr_edit_bindings(json_get(&doc, "data"), r, setup);
    if (ok) (void)snprintf(r->edited, sizeof(r->edited), "%s", version);
    json_free(&doc); json_free(&input); return ok;
}
static bool rr_edit_read_input(const struct json_value *setup, struct json_value *input)
{
    const struct json_value *revision = json_get(setup, "revision");
    json_set_object(input);
    return json_push_kv_str(input, "name", aso_string(setup, "name")) &&
        revision && revision->type == JSON_INT && json_get_int(revision) == 2 &&
        json_push_kv(input, "expected_revision", revision) &&
        json_push_kv_str(input, "source_version", aso_string(setup, "source_version")) &&
        json_push_kv_str(input, "path", "include/boost.h");
}
static bool rr_edit_read_result(const struct json_value *data, const struct rr_cycle *r,
                                const struct json_value *setup, char head[65], char blob[65])
{
    const struct json_value *revision = json_get(setup, "revision");
    const char *observed_head = aso_string(data, "head_version");
    const char *observed_blob = aso_string(json_get(data, "file"), "blob");
    const struct json_value *observed_revision = json_get(data, "selection_revision");
    bool ok = strlen(observed_head) == 64 && strlen(observed_blob) == 64 && revision &&
        observed_revision && observed_revision->type == JSON_INT && json_get_int(observed_revision) == json_get_int(revision) &&
        !strcmp(observed_head, r->head) && strcmp(observed_head, aso_string(setup, "source_version")) &&
        !strcmp(aso_string(data, "source_version"), aso_string(setup, "source_version")) &&
        !strcmp(aso_string(data, "version"), r->bob.build.version) &&
        !strcmp(aso_string(data, "content"), "#define BOOST 1\n");
    if (ok) { memcpy(head, observed_head, 65); memcpy(blob, observed_blob, 65); }
    return ok;
}
static bool rr_edit_read(struct aso_mcp *m, const struct rr_cycle *r, const struct json_value *setup,
                         char head[65], char blob[65])
{
    struct json_value input = {0}, doc = {0};
    bool ok = rr_edit_read_input(setup, &input) && aj_mcp_run(m, "app.customize", &input, &doc) &&
        rr_edit_read_result(json_get(&doc, "data"), r, setup, head, blob);
    json_free(&doc); json_free(&input); return ok;
}
static bool rr_refresh_setup(struct rr_cycle *r)
{
    struct rr_consent view = {.cycle = r}; struct zcl_command_reply reply;
    struct json_value setup = {0}; char exe[PATH_MAX];
    zcl_command_reply_init(&reply, "zcl.app_library.v1");
    bool ok = realpath("build/bin/z23-dev", exe) != NULL;
    if (ok) zcl_test_app_library_native_at(&r->bob.env, exe, r->owner.alice_datadir, &reply,
        rr_library_present, &view, rr_present);
    const struct json_value *revision = NULL;
    ok = ok && reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated &&
        json_read(&setup, view.setup, strlen(view.setup));
    if (ok) revision = json_get(&setup, "revision");
    ok = ok && revision && revision->type == JSON_INT && json_get_int(revision) == 2 &&
        !strcmp(aso_string(&setup, "version"), r->bob.build.version) &&
        !strcmp(aso_string(&setup, "source_version"), r->personal) && rr_setup_guide(&setup);
    if (ok) { int n = snprintf(r->mcp_setup, sizeof(r->mcp_setup), "%s", view.setup); ok = n > 0 && (size_t)n < sizeof(r->mcp_setup); }
    json_free(&setup); zcl_command_reply_free(&reply); return ok;
}
static bool rr_edit(struct rr_cycle *r)
{
    char head[65], blob[65];
    if (!rr_refresh_setup(r) || !rr_newer_dirty(r, "#define BOOST 6\n")) return false;
    struct json_value setup; json_init(&setup);
    char exe[PATH_MAX]; const char *a, *b, *c;
    struct aso_mcp m = {.pid = -1, .input = -1, .output = -1};
    bool ok = json_read(&setup, r->mcp_setup, strlen(r->mcp_setup)) &&
        realpath("build/bin/z23-dev", exe) && rr_setup_args(&setup, exe, r->owner.alice_datadir, &a, &b, &c) &&
        aso_mcp_spawn_args(&m, exe, a, b, c) && aso_mcp_init(&m) &&
        rr_edit_read(&m, r, &setup, head, blob) && rr_edit_transaction(&m, r, &setup, head, blob);
    bool closed = aso_mcp_close(&m); json_free(&setup); ok = ok && closed;
    return ok && strlen(r->edited) == 64 && strcmp(r->edited, r->personal) &&
        aj_parent_is(&r->owner, r->edited, r->head) && rr_preserved(r, r->edited);
}
static bool rr_share(struct rr_cycle *r)
{
    int n = snprintf(r->owner.share_file, sizeof(r->owner.share_file), "%s/bob/from-bob.z23share", r->owner.root);
    if (n <= 0 || (size_t)n >= sizeof(r->owner.share_file)) return false;
    struct aj_share_view view = {.draft = &r->bob.build, .output = r->owner.share_file};
    if (!aj_share_expected(&r->owner, &view) || strcmp(view.publisher, r->publisher)) return false;
    struct abc_leaf leaf; abc_open(&leaf);
    bool ok = json_push_kv_str(&leaf.in, "name", AK_ROUTE) &&
        json_push_kv_str(&leaf.in, "output", r->owner.share_file) && aj_share_run(&leaf, &view);
    if (ok) memcpy(r->carol.release, view.release, sizeof(r->carol.release));
    abc_close(&leaf); return ok && rr_preserved(r, r->edited);
}
static bool rr_carol_paths(struct rr_cycle *r)
{
    struct abc_world *w = &r->carol.world;
    (void)snprintf(w->bob_home, sizeof(w->bob_home), "%s/carol", r->owner.root);
    (void)snprintf(w->bob_datadir, sizeof(w->bob_datadir), "%s/carol/datadir", r->owner.root);
    (void)snprintf(w->bob_copy, sizeof(w->bob_copy), "%s/carol/from-bob", r->owner.root);
    (void)snprintf(w->share_file, sizeof(w->share_file), "%s", r->owner.share_file);
    return mkdir(w->bob_home, 0700) == 0 && abc_as(w->bob_home) && ak_environment(&r->carol);
}
static bool rr_carol_release(const struct rr_cycle *r)
{
    struct vcs_package_release release; uint8_t id[32], got[32], parent[32], publisher[33], package[32];
    if (!zcl_hex_decode_lower(r->carol.release, id, 32) ||
        !zcl_hex_decode_lower(r->bob.release, parent, 32) ||
        !zcl_hex_decode_lower(r->publisher, publisher, 33) ||
        !zcl_hex_decode_lower(r->bob.build.package, package, 32)) return false;
    if (zcl_package_copy_find_release(r->carol.world.bob_datadir, id, &release, got) != ZCL_PACKAGE_COPY_FOUND)
        return false;
    char name[128]; int n = snprintf(name, sizeof(name), "%s/tinyapp", r->space);
    return n > 0 && (size_t)n < sizeof(name) && !strcmp(release.name, name) &&
        !memcmp(got, id, 32) && release.has_parent && !memcmp(release.parent_root, parent, 32) &&
        !memcmp(release.publisher_pubkey, publisher, 33) && !memcmp(release.package_root, package, 32);
}
static bool rr_carol_source(const struct rr_cycle *r)
{
    struct vcs_package_prepared p; vcs_package_prepared_init(&p); char why[256]; uint8_t expected[32];
    /* Full canonical manifest binds every received path/byte/mode, not only the edited header. */
    bool ok = vcs_package_prepare_content(r->carol.world.bob_copy, &p, why, sizeof(why)) == VCS_PACKAGE_PREPARE_OK &&
        zcl_hex_decode_lower(r->bob.build.package, expected, 32) && !memcmp(p.package_root, expected, 32) &&
        rr_text(r->carol.world.bob_copy, "include/boost.h", "#define BOOST 8\n");
    vcs_package_prepared_free(&p); return ok;
}
static bool rr_carol_build_open(struct rr_cycle *r)
{
    struct ak_fixture *c = &r->carol;
    if (!ak_build_tuple(c->world.bob_copy, c->world.bob_datadir, &c->build) ||
        strcmp(c->build.package, r->bob.build.package) || strcmp(c->build.image, r->bob.build.image) ||
        !aj_distinct_images(&r->bob.build, &c->build)) return false;
    struct abc_leaf leaf;
    bool ok = ak_request(&leaf, c, true) && abc_exec("app.open", &leaf) && ak_opened(&leaf, c);
    abc_close(&leaf); bool clean = aso_cleanup_children();
    return ok && clean && rr_carol_source(r);
}
static bool rr_carol(struct rr_cycle *r)
{
    if (!rr_carol_paths(r) || !aj_receive(&r->carol.world, r->publisher, r->bob.build.package, r->carol.release) ||
        !rr_trusted(&r->carol) || !rr_carol_release(r) || !rr_carol_source(r) || !rr_carol_build_open(r)) return false;
    /* Bob's exact name still reopens the chosen edited image after Carol's independent build. */
    return abc_as(r->owner.alice_home) && ak_environment(&r->bob) && ak_restart(&r->bob) &&
        rr_preserved(r, r->edited);
}
static int rr_acceptance(struct rr_cycle *r)
{
    int failures = 0;
    TEST("trusted Bob personalizes, edits and Keeps before native reshare to fresh Carol") {
        ASSERT(rr_start(r));
        ASSERT(rr_personalize(r));
        ASSERT(rr_preview(r, r->personal));
        ASSERT(rr_keep(r, 1));
        ASSERT(rr_stale_change(r));
        ASSERT(rr_edit(r));
        ASSERT(rr_preview(r, r->edited));
        ASSERT(rr_keep(r, 2));
        char blob[65]; ASSERT(rr_read(r, 3, "#define BOOST 8\n", blob));
        ASSERT(rr_share(r));
        ASSERT(rr_carol(r));
        PASS();
    } _test_next:;
    if (!aso_cleanup_children()) failures++;
    if (r->bob.world.root[0] && test_rm_rf_recursive(r->bob.world.root) != 0) failures++;
    return failures;
}

int test_app_kept_journey(void)
{
    int failures = 0;
    struct aso_env env[] = {{"HOME", NULL}, {"XDG_CONFIG_HOME", NULL}, {"XDG_STATE_HOME", NULL},
                            {"DISPLAY", NULL}, {"WAYLAND_DISPLAY", NULL}};
    size_t saved = 0;
    for (; saved < sizeof(env) / sizeof(env[0]); ++saved) {
        const char *v = getenv(env[saved].key);
        env[saved].saved = v ? strdup(v) : NULL;
        if (v && !env[saved].saved) { failures++; break; }
    }
    struct abc_world w = {0}; struct aso_build old = {0}, next = {0}; char head[65] = {0};
    chain_params_select(CHAIN_MAIN);
    if (!failures) failures += aso_fixture_setup(&w, &old, &next, head, false);
    if (!failures) failures += aj_steps(&w, &old, head);
    struct rr_cycle recipient = {0};
    if (!failures) failures += rr_acceptance(&recipient);
    aso_env_restore(env, saved);
    if (w.root[0]) (void)test_rm_rf_recursive(w.root);
    return failures;
}
#else
int test_app_open_selected(void) { return 0; }
int test_app_kept_journey(void) { return 0; }
#endif
