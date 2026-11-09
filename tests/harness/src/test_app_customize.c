/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 */
#if !defined(_WIN32)
#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/native_app_launch.h"
#include "command/native_app_personalize_command.h"
#if defined(ZCL_TESTING)
#include "command/native_app_personalize_view.h"
#endif
#include "command/native_app_share_command.h"
#include "command/native_app_publish_command.h"
#include "command/native_app_offer.h"
#include "command/native_app_library_command.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/vcs_seal.h"
#include <signal.h>
#include <errno.h>
#include "command/native_command.h"
#include "command/native_zcode_package_bundle.h"
#include "command/native_zcode_package_copy.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "platform/time_compat.h"
#include "vcs/package_prepare.h"
#include "vcs/package_store.h"
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
    "#include <stdio.h>\n#include <string.h>\n#include <unistd.h>\n"
    "int main(int n,char **v){if(n!=2)return 8;"
    "if(!strcmp(v[1],\"exit\")){sleep(1);return 3;}"
    "if(!strcmp(v[1],\"ready\")){puts(\"READY-N\");fflush(stdout);}"
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

/* Source-only fixture: the publish/adopt helpers above are reused from
 * app_open_selected. No image is built or launched. Nonzero build identities
 * below are selection-store fixture data, not a claimed build qualification. */
#include "command/app_selection.h"
#include "util/file_io.h"
#include "sha3/sha3.h"

struct ac_fixture {
    struct abc_world world;
    struct app_launch_env env;
    struct app_selection kept;
    uint8_t tree[32], blob[32], head[32];
    char *config_before, *state_before, *home_before;
    bool env_touched;
    uint8_t log_hash[32], index_hash[32], selection_hash[32];
};

static bool act_hash(const char *dir, const char *rel, uint8_t hash[32])
{
    char path[1600]; uint8_t *data = NULL; size_t size = 0;
    int n = snprintf(path, sizeof(path), "%s/%s", dir, rel);
    if (n < 0 || (size_t)n >= sizeof(path) ||
        !zcl_read_whole_file(path, 16u * 1024u * 1024u, &data, &size, "app-customize-test")) return false;
    struct sha3_256_ctx sha; sha3_256_init(&sha); sha3_256_write(&sha, data, size); sha3_256_finalize(&sha, hash);
    free(data); return true;
}

static bool act_snapshot(struct ac_fixture *f, const char *phase, uint8_t version[32])
{
    struct vcs_repo *repo = vcs_open(f->world.copy);
    if (!repo) return false;
    struct vcs_snapshot_meta meta = {.phase = phase, .task_ref = "customize fixture"};
    bool ok = vcs_snapshot(repo, &meta, version) == VCS_OK;
    vcs_close(repo); return ok;
}

static bool act_keep(struct ac_fixture *f)
{
    struct zcl_package_copy copy;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.customize.v1");
    bool ok = zcl_package_copy_open_as(f->world.copy, ZCL_PACKAGE_COPY_READ, &copy, &reply, "fixture");
    if (ok) {
        struct zcl_package_adopt_record adoption;
        ok = zcl_package_copy_adopted(f->world.alice_datadir, &copy, &adoption) == ZCL_PACKAGE_COPY_ADOPTED;
        (void)snprintf(f->kept.app, sizeof(f->kept.app), "skycombat");
        (void)snprintf(f->kept.copy, sizeof(f->kept.copy), "%s", f->world.copy);
        (void)snprintf(f->kept.datadir, sizeof(f->kept.datadir), "%s", f->world.alice_datadir);
        memcpy(f->kept.fork, copy.fork_version, 32); memcpy(f->kept.parent, copy.parent_release, 32);
        memcpy(f->kept.version, copy.head_version, 32); memcpy(f->tree, copy.head_tree, 32);
        if (ok) memcpy(f->kept.package, adoption.package_root, 32);
        memset(f->kept.env, 1, 32); memset(f->kept.dependencies, 2, 32);
        memset(f->kept.image, 3, 32); memset(f->kept.record, 4, 32);
        zcl_package_copy_close(&copy);
    }
    zcl_command_reply_free(&reply);
    return ok && app_selection_save(f->env.state_dir, 0, &f->kept, &f->kept) == APP_SELECTION_OK;
}

static bool act_binary(struct ac_fixture *f)
{
    char path[1000];
    (void)snprintf(path, sizeof(path), "%s/include/binary.dat", f->world.copy);
    FILE *file = fopen(path, "wb");
    const unsigned char bytes[] = {0, 0xff, 'A'};
    bool ok = file && fwrite(bytes, 1, sizeof(bytes), file) == sizeof(bytes);
    return file ? fclose(file) == 0 && ok : false;
}

static void act_quote_path(char path[241])
{
    memset(path, '"', 240); path[240] = 0;
}

static bool act_quote_source(struct ac_fixture *f)
{
    char path[241], text[601];
    act_quote_path(path);
    memset(text, 'Q', 600); text[600] = 0;
    return abc_put(f->world.copy, path, text) &&
        abc_put(f->world.copy, "src/sky_combat_multiplayer_ultimate.c", text);
}

static bool act_save_environment(struct ac_fixture *f)
{
    memset(f, 0, sizeof(*f));
    const char *s = getenv("XDG_CONFIG_HOME"), *t = getenv("XDG_STATE_HOME");
    const char *h = getenv("HOME");
    f->home_before = h ? strdup(h) : NULL;
    f->config_before = s ? strdup(s) : NULL; f->state_before = t ? strdup(t) : NULL;
    if ((s && !f->config_before) || (t && !f->state_before) || (h && !f->home_before)) return false;
    f->env_touched = true;
    return true;
}

static bool act_configure_environment(struct ac_fixture *f)
{
    char cfg[900], state[900], why[256];
    (void)snprintf(cfg, sizeof(cfg), "%s/config", f->world.root);
    (void)snprintf(state, sizeof(state), "%s/state", f->world.root);
    if (setenv("XDG_CONFIG_HOME", cfg, 1) || setenv("XDG_STATE_HOME", state, 1) ||
        !app_launch_env_from_process(&f->env, why, sizeof(why))) return false;
    if (!app_launch_state_dir_ready(f->env.state_dir)) return false;
    return true;
}

static bool act_find_kept_blob(struct ac_fixture *f)
{
    struct vcs_manifest manifest;
    if (!vcs_tree_load(f->world.copy, f->tree, &manifest)) return false;
    bool found = false;
    for (size_t i = 0; i < manifest.count; ++i)
        if (!strcmp(manifest.entries[i].path, "include/boost.h")) {
            memcpy(f->blob, manifest.entries[i].blob, 32); found = true;
        }
    vcs_manifest_free(&manifest);
    return found;
}

static bool act_setup(struct ac_fixture *f, bool escaped_source)
{
    if (!act_save_environment(f) || !abc_world_init(&f->world) ||
        !act_configure_environment(f)) return false;
    /* Escaped names exercise read-only JSON output, but are deliberately
     * outside the portable package paths required for editable app trees. */
    if (!act_binary(f) || (escaped_source && !act_quote_source(f)) || !abc_put(f->world.copy, "include/boost.h", "#define BOOST 2\n") ||
        !act_snapshot(f, "save", f->head) || !act_keep(f)) return false;
    return act_find_kept_blob(f) && abc_put(f->world.copy, "include/boost.h", "#define BOOST 3\n") &&
        act_snapshot(f, "save", f->head) && abc_put(f->world.copy, "include/boost.h", "#define BOOST 4\n");
}

static bool act_call(struct abc_leaf *l, const char *path, bool pinned)
{
    abc_open(l);
    if (!json_push_kv_str(&l->in, "name", "skycombat")) return false;
    if (path && !json_push_kv_str(&l->in, "path", path)) return false;
    return !pinned || json_push_kv_int(&l->in, "expected_revision", 1);
}

static bool act_result(struct abc_leaf *l, const char *error)
{
    bool ok = abc_exec("app.customize", l);
    if (ok) ok = error ? l->out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(l->out.error.code, error) : l->out.status == ZCL_COMMAND_STATUS_PASSED;
    if (!ok) printf("customize expected=%s actual=%s %s\n", error ? error : "PASS", l->out.error.code, l->out.error.message);
    return ok;
}

static bool act_preserved(struct ac_fixture *f, bool capture)
{
    uint8_t log[32], index[32], selection[32];
    if (!act_hash(f->world.copy, ".zvcs/commits.log", log) ||
        !act_hash(f->world.copy, ".zvcs/index.kv", index) ||
        !act_hash(f->env.state_dir, "skycombat.selection", selection)) return false;
    if (capture) {
        memcpy(f->log_hash, log, 32); memcpy(f->index_hash, index, 32);
        memcpy(f->selection_hash, selection, 32); return true;
    }
    char path[1000], *text = NULL; size_t size = 0;
    (void)snprintf(path, sizeof(path), "%s/include/boost.h", f->world.copy);
    bool ok = zcl_read_whole_file_text(path, 512, &text, &size, "customize dirty") &&
        size == strlen("#define BOOST 4\n") && !memcmp(text, "#define BOOST 4\n", size) &&
        !memcmp(log, f->log_hash, 32) && !memcmp(index, f->index_hash, 32) &&
        !memcmp(selection, f->selection_hash, 32);
    free(text); return ok;
}

static bool act_read_identity(struct ac_fixture *f, struct abc_leaf *l)
{
    bool ok = json_push_kv_str(&l->in, "change", "Make the plane green") && act_result(l, NULL);
    char tree[65], version[65];
    zcl_hex_encode(f->tree, 32, tree); zcl_hex_encode(f->kept.version, 32, version);
    ok = ok && !strcmp(abc_get(l, "source_root"), tree) && !strcmp(abc_get(l, "version"), version) &&
        json_get_int(json_get(&l->out.data, "selection_revision")) == 1;
    return ok;
}

static bool act_read_files(struct ac_fixture *f, bool ok)
{
    char blob[65]; zcl_hex_encode(f->blob, 32, blob);
    struct abc_leaf l;
    if (!act_call(&l, "include/boost.h", true)) return false;
    ok = act_result(&l, NULL) && ok && !strcmp(abc_get(&l, "content"), "#define BOOST 2\n") &&
        !strcmp(abc_get(&l, "encoding"), "utf8") &&
        !strcmp(json_get_str(json_get(json_get(&l.out.data, "file"), "blob")), blob);
    abc_close(&l);
    if (!act_call(&l, "include/binary.dat", true)) return false;
    ok = act_result(&l, NULL) && ok && !strcmp(abc_get(&l, "content"), "AP9B") &&
        !strcmp(abc_get(&l, "encoding"), "base64");
    abc_close(&l);
    return ok && act_preserved(f, false);
}

static bool act_reads(struct ac_fixture *f)
{
    struct abc_leaf l;
    bool ok = act_preserved(f, true) && act_call(&l, NULL, false);
    if (!ok) return false;
    ok = act_read_identity(f, &l);
    abc_close(&l);
    return act_read_files(f, ok);
}

static bool act_refusals(void)
{
    const char *const paths[] = {"../include/boost.h", "include/../include/boost.h", "/include/boost.h", "missing.h"};
    bool ok = true;
    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); ++i) {
        struct abc_leaf l;
        if (!act_call(&l, paths[i], true)) return false;
        ok = act_result(&l, "PATH_UNKNOWN") && ok; abc_close(&l);
    }
    struct abc_leaf l;
    if (!act_call(&l, "include/boost.h", false)) return false;
    ok = act_result(&l, "REVISION_REQUIRED") && ok; abc_close(&l);
    if (!act_call(&l, "include/boost.h", false)) return false;
    ok = json_push_kv_int(&l.in, "expected_revision", 2) &&
        act_result(&l, "SELECTION_STALE") && ok; abc_close(&l);
    return ok;
}

static bool act_escaped_listing(const char *path, struct abc_leaf *l)
{
    bool ok = act_result(l, NULL);
    const struct json_value *row = json_at(json_get(&l->out.data, "files"), 0);
    const char *listed = json_get_str(json_get(row, "path"));
    ok = listed && !strcmp(listed, path) && ok;
    return ok;
}

static bool act_escaped_first(struct abc_leaf *l, bool ok)
{
    ok = act_result(l, NULL) && ok && strlen(abc_get(l, "content")) == 512 &&
        strspn(abc_get(l, "content"), "Q") == 512 &&
        json_get_int(json_get(&l->out.data, "next_offset")) == 512 &&
        !json_get_bool(json_get(&l->out.data, "complete")) && l->out.next_count == 0;
    return ok;
}

static bool act_escaped_last(struct abc_leaf *l, bool ok)
{
    (void)json_push_kv_int(&l->in, "offset", 512);
    ok = act_result(l, NULL) && ok && strlen(abc_get(l, "content")) == 88 &&
        strspn(abc_get(l, "content"), "Q") == 88 &&
        json_get_int(json_get(&l->out.data, "next_offset")) == 600 &&
        json_get_bool(json_get(&l->out.data, "complete")) && l->out.next_count == 0;
    return ok;
}

static bool act_escaped_reads(void)
{
    char path[241]; act_quote_path(path);
    struct abc_leaf l;
    if (!act_call(&l, NULL, false)) return false;
    bool ok = act_escaped_listing(path, &l);
    abc_close(&l);
    if (!act_call(&l, path, true)) return false;
    ok = act_escaped_first(&l, ok);
    abc_close(&l);
    if (!act_call(&l, path, true)) return false;
    ok = act_escaped_last(&l, ok);
    abc_close(&l); return ok;
}

/* Exercise registry admission and defensive handler validation independently. */
static bool act_bad_input_boundaries(struct abc_leaf *l)
{
    const struct zcl_command_spec *spec = abc_spec("app.customize");
    if (!spec || !spec->handler) return false;
    char why[256] = {0};
    bool rejected = !zcl_command_registry_input_validate(
        spec, &l->in, why, sizeof(why));
    l->req.spec = spec;
    l->req.input = &l->in;
    l->req.invoked_name = spec->path;
    spec->handler(&l->req, &l->out);
    bool bad_input = l->out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(l->out.error.code, "BAD_INPUT");
    if (!rejected || !bad_input)
        printf("customize registry_rejected=%d reason=%s handler=%s %s\n",
               rejected, why, l->out.error.code, l->out.error.message);
    size_t bytes = json_write(&l->out.data, NULL, 0) + 1024u;
    bool fits = !spec->budget_bytes || bytes <= (size_t)spec->budget_bytes;
    return rejected && bad_input && fits;
}

static bool act_bounds(void)
{
    const char *const fields[] = {"offset", "limit", "page", "expected_revision"};
    bool ok = true;
    for (size_t i = 0; i < sizeof(fields)/sizeof(fields[0]); ++i) {
        struct abc_leaf l;
        if (!act_call(&l, "include/boost.h", strcmp(fields[i], "expected_revision") != 0)) return false;
        ok = json_push_kv_str(&l.in, fields[i], "1") &&
            act_bad_input_boundaries(&l) && ok; abc_close(&l);
    }
    struct abc_leaf l;
    if (!act_call(&l, "include/boost.h", true)) return false;
    (void)json_push_kv_int(&l.in, "limit", 2049);
    ok = act_bad_input_boundaries(&l) && ok; abc_close(&l);
    if (!act_call(&l, "include/boost.h", true)) return false;
    (void)json_push_kv_int(&l.in, "offset", 999);
    ok = act_result(&l, "BLOB_RANGE") && ok; abc_close(&l);
    return ok;
}

static bool act_object_path(struct ac_fixture *f, const uint8_t root[32], char path[1600])
{
    char blob[65]; zcl_hex_encode(root, 32, blob);
    int n = snprintf(path, 1600, "%s/.zvcs/objects/%.2s/%s", f->world.copy, blob, blob + 2);
    return n > 0 && n < 1600;
}

static bool act_corrupt_blob_refusal(const char *path, bool ok)
{
    struct abc_leaf l;
    FILE *file = fopen(path, "wb");
    bool written = file && fputs("corrupt", file) >= 0;
    if (file && fclose(file)) written = false;
    if (written && act_call(&l, "include/boost.h", true)) {
        ok = act_result(&l, "BLOB_UNREADABLE") && ok; abc_close(&l);
    } else ok = false;
    if (unlink(path)) ok = false;
    return ok;
}

static bool act_symlink_blob_refusal(const char *path, const char *saved, bool ok)
{
    struct abc_leaf l;
    if (symlink(saved, path) == 0) {
        if (act_call(&l, "include/boost.h", true)) {
            ok = act_result(&l, "BLOB_UNREADABLE") && ok; abc_close(&l);
        } else ok = false;
        if (unlink(path)) ok = false;
    } else ok = false;
    if (rename(saved, path)) ok = false;
    return ok;
}

static bool act_blob_refusal(struct ac_fixture *f)
{
    char path[1600], saved[1620];
    if (!act_object_path(f, f->blob, path)) return false;
    (void)snprintf(saved, sizeof(saved), "%s.saved", path);
    if (rename(path, saved)) return false;
    struct abc_leaf l;
    bool ok = act_call(&l, "include/boost.h", true);
    if (ok) { ok = act_result(&l, "BLOB_UNREADABLE"); abc_close(&l); }
    ok = act_corrupt_blob_refusal(path, ok);
    return act_symlink_blob_refusal(path, saved, ok);
}

static bool act_alias_refusal(struct ac_fixture *f, bool manifest)
{
    char path[1600], alias[1600];
    if (!act_object_path(f, manifest ? f->tree : f->blob, path)) return false;
    (void)snprintf(alias, sizeof(alias), "%s/.zvcs/objects/tmp/.put.customize-alias", f->world.copy);
    if (link(path, alias)) return false;
    struct abc_leaf l;
    bool ok = act_call(&l, "include/boost.h", true);
    if (ok) { ok = act_result(&l, manifest ? "SOURCE_UNREADABLE" : "BLOB_UNREADABLE"); abc_close(&l); }
    struct stat st;
    ok = lstat(alias, &st) == 0 && st.st_nlink == 2 && ok;
    if (unlink(alias)) ok = false;
    return ok;
}

static bool act_reader_bounds(struct ac_fixture *f)
{
    uint8_t *bytes = NULL; size_t size = 99;
    int rc = vcs_object_get_readonly_bounded(f->world.copy, f->blob,
        VCS_TAG_BLOB, 1, &bytes, &size);
    bool ok = rc == -2 && bytes == NULL && size == 0;
    free(bytes); bytes = NULL;
    rc = vcs_object_get_readonly_bounded(f->world.copy, f->blob,
        VCS_TAG_COMMIT, 512, &bytes, &size);
    ok = rc == -1 && bytes == NULL && size == 0 && ok;
    free(bytes); bytes = NULL;
    rc = vcs_object_get_readonly_bounded(f->world.copy, f->blob,
        VCS_TAG_BLOB, strlen("#define BOOST 2\n"), &bytes, &size);
    ok = rc == 0 && size == strlen("#define BOOST 2\n") &&
        !memcmp(bytes, "#define BOOST 2\n", size) && ok;
    free(bytes);
    struct vcs_manifest tree = {0};
    bool loaded = vcs_tree_load_readonly_bounded(f->world.copy, f->tree, 1, 16384, &tree);
    ok = !loaded && tree.entries == NULL && tree.count == 0 && ok;
    vcs_manifest_free(&tree);
    return ok;
}

static bool act_selection_refusal(struct ac_fixture *f)
{
    char path[1600], saved[1620];
    (void)snprintf(path, sizeof(path), "%s/skycombat.selection", f->env.state_dir);
    (void)snprintf(saved, sizeof(saved), "%s.saved", path);
    if (rename(path, saved)) return false;
    struct abc_leaf l;
    bool ok = act_call(&l, NULL, false);
    if (ok) {
        ok = act_result(&l, "SELECTION_REQUIRED");
        if (ok && (!strstr(l.out.error.message, "app copy skycombat --yes") ||
                   !strstr(l.out.error.message, "app save"))) {
            printf("selection refusal does not name the commands: %s\n", l.out.error.message);
            ok = false;
        }
        abc_close(&l);
    }
    FILE *file = fopen(path, "wb");
    bool wrote = file && fputs("corrupt selection", file) >= 0;
    if (file && fclose(file)) wrote = false;
    if (wrote && act_call(&l, NULL, false)) {
        ok = act_result(&l, "SELECTION_UNREADABLE") && ok; abc_close(&l);
    } else ok = false;
    if (unlink(path) || rename(saved, path)) ok = false;
    return ok;
}

static bool act_no_grant(struct ac_fixture *f)
{
    char path[1600], saved[1620];
    (void)snprintf(path, sizeof(path), "%s/zcode/adopted", f->world.alice_datadir);
    (void)snprintf(saved, sizeof(saved), "%s.saved", path);
    if (rename(path, saved)) return false;
    struct abc_leaf l;
    bool ok = act_call(&l, NULL, false);
    if (ok) { ok = act_result(&l, "NOT_ADOPTED"); abc_close(&l); }
    if (rename(saved, path)) ok = false;
    return ok;
}

static bool act_unknown_version(struct ac_fixture *f)
{
    struct app_selection invalid = f->kept, out;
    memset(invalid.version, 0x71, sizeof(invalid.version));
    if (app_selection_save(f->env.state_dir, 1, &invalid, &out) != APP_SELECTION_OK) return false;
    struct abc_leaf l;
    bool ok = act_call(&l, NULL, false);
    if (ok) { ok = act_result(&l, "VERSION_UNKNOWN"); abc_close(&l); }
    if (app_selection_save(f->env.state_dir, 2, &f->kept, &out) != APP_SELECTION_OK) return false;
    f->kept = out;
    return ok;
}

static bool act_foreign_history(struct ac_fixture *f)
{
    if (!abc_put(f->world.copy, "include/boost.h", "#define BOOST 5\n") ||
        !act_snapshot(f, "foreign", f->head)) return false;
    struct abc_leaf l;
    bool ok = act_call(&l, NULL, false);
    if (ok) { ok = act_result(&l, "NOT_ADOPTED"); abc_close(&l); }
    return ok;
}

static void act_cleanup(struct ac_fixture *f)
{
    if (f->env_touched) {
        if (f->home_before) (void)setenv("HOME", f->home_before, 1);
        else (void)unsetenv("HOME");
        if (f->config_before) (void)setenv("XDG_CONFIG_HOME", f->config_before, 1);
        else (void)unsetenv("XDG_CONFIG_HOME");
        if (f->state_before) (void)setenv("XDG_STATE_HOME", f->state_before, 1);
        else (void)unsetenv("XDG_STATE_HOME");
    }
    free(f->config_before); free(f->state_before); free(f->home_before);
    if (f->world.root[0]) test_rm_rf(f->world.root);
}

/* Use the real catalog executor and envelope serializer, not the direct
 * handler shortcut used by the older content-only fixture assertions. */
static bool act_wire(const struct json_value *input, struct json_value *doc)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = abc_spec("app.customize");
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    char wire[ZCL_COMMAND_LIST_BUDGET + 1]; enum zcl_command_exit code;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, input, false,
        spec->path, "normal", 0, 0, NULL, wire, sizeof(wire), &code);
    json_free(doc); json_init(doc);
    bool ok = n && n <= ZCL_COMMAND_LIST_BUDGET && code == ZCL_COMMAND_EXIT_OK && json_read(doc, wire, n);
    const char *status = json_get_str(json_get(doc, "status"));
    return ok && status && !strcmp(status, "passed");
}
static const struct json_value *act_wire_next(const struct json_value *doc, const char *key)
{
    const struct json_value *next = json_get(doc, "next");
    for (size_t i = 0; i < json_size(next); ++i) {
        const struct json_value *row = json_at(next, i), *input = json_get(row, "input");
        const char *command = json_get_str(json_get(row, "command"));
        if (command && !strcmp(command, "app.customize") && json_get(input, key)) return input;
    }
    return NULL;
}
static bool act_wire_identity(const struct json_value *doc, const struct ac_fixture *f)
{
    const struct json_value *data = json_get(doc, "data"); char version[65], tree[65];
    zcl_hex_encode(f->kept.version, 32, version); zcl_hex_encode(f->tree, 32, tree);
    const char *v = json_get_str(json_get(data, "version")), *t = json_get_str(json_get(data, "source_root"));
    return v && t && !strcmp(v, version) && !strcmp(t, tree) &&
        json_get_int(json_get(data, "selection_revision")) == 1;
}
static bool act_wire_qbytes(const struct json_value *doc, size_t count)
{
    const char *text = json_get_str(json_get(json_get(doc, "data"), "content"));
    return text && strlen(text) == count && strspn(text, "Q") == count;
}
static bool act_wire_same_blob(const struct json_value *first, const struct json_value *last)
{
    const struct json_value *a = json_get(json_get(first, "data"), "file");
    const struct json_value *b = json_get(json_get(last, "data"), "file");
    const char *ah = json_get_str(json_get(a, "blob")), *bh = json_get_str(json_get(b, "blob"));
    return ah && bh && strlen(ah) == 64 && !strcmp(ah, bh) &&
        json_get_int(json_get(a, "size")) == 600 && json_get_int(json_get(b, "size")) == 600;
}
static bool act_wire_file(struct ac_fixture *f)
{
    struct abc_leaf l; bool ok = act_call(&l, "src/sky_combat_multiplayer_ultimate.c", true);
    struct json_value first, last; json_init(&first); json_init(&last);
    ok = ok && json_push_kv_int(&l.in, "limit", 512) && act_wire(&l.in, &first);
    const struct json_value *next = act_wire_next(&first, "offset");
    ok = ok && act_wire_identity(&first, f) && act_wire_qbytes(&first, 512) &&
        next && json_get_int(json_get(next, "offset")) == 512 && act_wire(next, &last);
    ok = ok && act_wire_identity(&last, f) && act_wire_qbytes(&last, 88) && act_wire_same_blob(&first, &last) &&
        json_get_bool(json_get(json_get(&last, "data"), "complete")) && !act_wire_next(&last, "offset");
    json_free(&first); json_free(&last); abc_close(&l); return ok;
}
static bool act_wire_pages(struct ac_fixture *f)
{
    struct abc_leaf l; bool ok = act_call(&l, NULL, true);
    struct json_value doc, next_doc; json_init(&doc); json_init(&next_doc);
    size_t seen = 0, pages = 0; bool finished = false, opened_file = false;
    ok = ok && act_wire(&l.in, &doc);
    while (ok && pages++ < 64) {
        const struct json_value *d = json_get(&doc, "data"), *files = json_get(d, "files");
        seen += json_size(files); ok = act_wire_identity(&doc, f);
        const struct json_value *file = act_wire_next(&doc, "path");
        if (file) { ok = ok && act_wire(file, &next_doc) && act_wire_identity(&next_doc, f); opened_file = true; }
        if (json_get_bool(json_get(d, "complete"))) {
            finished = seen == (size_t)json_get_int(json_get(d, "file_count")); break;
        }
        const struct json_value *next = act_wire_next(&doc, "page");
        ok = ok && next && json_get_int(json_get(next, "page")) == (int64_t)seen && act_wire(next, &next_doc);
        if (ok) { json_free(&doc); doc = next_doc; json_init(&next_doc); }
    }
    json_free(&doc); json_free(&next_doc); abc_close(&l);
    return ok && finished && pages > 1 && opened_file;
}
/* Real serializer with deliberately invalid handler-provided next links. No
 * handler override, global state mutation, or test-only production entrypoint. */
static bool act_next_case(const char *path, const char *data, const char *input, bool expected)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = abc_spec(path);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, spec->output_schema);
    bool ok = json_read(&reply.data, data, strlen(data)) &&
        zcl_command_reply_add_next(&reply, path, input, "fixture continuation");
    char wire[ZCL_COMMAND_LIST_BUDGET + 1];
    size_t n = ok ? zcl_command_registry_test_reply_wire(reg, spec, &reply, wire, sizeof(wire)) : 0;
    /* This existing synthetic seam imposes ERROR_BUDGET, stricter than this
     * leaf's success budget. Neither buffer capacity nor n>0 alone establishes
     * success-budget acceptance; the real executor cases above use production
     * budget selection and remain the positive pagination coverage. */
    size_t success_cap = spec->budget_bytes > 0 ? (size_t)spec->budget_bytes : ZCL_COMMAND_RESULT_BUDGET;
    ok = ok && (expected ? (n > 0 && n <= success_cap) : n == 0);
    zcl_command_reply_free(&reply); return ok;
}
static bool act_next_refusals(void)
{
    static const char data[] = "{\"name\":\"skycombat\",\"selection_revision\":1,\"complete\":false,\"file\":{\"path\":\"include/boost.h\"},\"next_offset\":512}";
    const char *bad[] = {
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"path\":\"include/boost.h\",\"offset\":0}",
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"path\":\"include/boost.h\",\"offset\":511}",
        "{\"name\":\"skycombat\",\"expected_revision\":2,\"path\":\"include/boost.h\",\"offset\":512}",
        "{\"name\":\"other\",\"expected_revision\":1,\"path\":\"include/boost.h\",\"offset\":512}",
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"path\":\"other.h\",\"offset\":512}",
        "{\"name\":\"skycombat\",\"path\":\"include/boost.h\",\"offset\":512}",
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"path\":\"include/boost.h\",\"offset\":\"512\"}",
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"path\":\"include/boost.h\",\"offset\":512,\"limit\":2049}"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i)
        if (!act_next_case("app.customize", data, bad[i], false)) return false;
    return act_next_case("app.customize", data,
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"path\":\"include/boost.h\",\"offset\":512}", true) &&
        act_next_case("app.list", "{}", "{}", false);
}
static bool act_next_manifest(void)
{
    static const char data[] = "{\"name\":\"skycombat\",\"selection_revision\":1,\"complete\":true,\"files\":[{\"path\":\"include/boost.h\"}],\"next_page\":1}";
    return act_next_case("app.customize", data,
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"path\":\"include/boost.h\"}", true) &&
        act_next_case("app.customize", data,
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"path\":\"other.h\"}", false) &&
        act_next_case("app.customize", data,
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"page\":1}", false);
}
static bool act_next_page_refusals(void)
{
    static const char data[] = "{\"name\":\"skycombat\",\"selection_revision\":1,\"complete\":false,\"files\":[],\"next_page\":4}";
    const char *bad[] = {"{\"name\":\"skycombat\",\"expected_revision\":1,\"page\":0}",
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"page\":3}",
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"page\":\"4\"}",
        "{\"name\":\"skycombat\",\"expected_revision\":2,\"page\":4}"};
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i)
        if (!act_next_case("app.customize", data, bad[i], false)) return false;
    return act_next_case("app.customize", data,
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"page\":4}", true);
}
static bool act_serialized_navigation(struct ac_fixture *f)
{
    return act_wire_file(f) && act_wire_pages(f) && act_next_refusals() && act_next_manifest() &&
        act_next_page_refusals() && act_preserved(f, false);
}

static bool act_search_row(const struct json_value *row, struct ac_fixture *f,
                           const char *query, size_t seen[2])
{
    const char *path = json_get_str(json_get(row, "path"));
    const char *content = json_get_str(json_get(row, "content"));
    if (!path || !content || !strstr(content, query)) return false;
    int64_t offset = json_get_int(json_get(row, "offset"));
    if (!strcmp(query, "BOOST 2")) {
        char blob[65]; zcl_hex_encode(f->blob, 32, blob);
        const char *got = json_get_str(json_get(row, "blob"));
        ++seen[0];
        return !strcmp(path, "include/boost.h") && offset == 8 && got && !strcmp(got, blob);
    }
    if (query[0] != 'Q') return false; /* A newer/dirty-only match is a failure. */
    size_t file = path[0] == '"' ? 0u : 1u;
    char quoted[241]; act_quote_path(quoted);
    if (!file && strcmp(path, quoted)) return false;
    if (file && strcmp(path, "src/sky_combat_multiplayer_ultimate.c")) return false;
    bool ok = offset == (int64_t)(seen[file] * 64u);
    ++seen[file];
    return ok;
}

static bool act_search_rows(const struct json_value *rows, struct ac_fixture *f,
                            const char *query, size_t seen[2])
{
    if (!rows || rows->type != JSON_ARR || json_size(rows) > 2u) return false;
    for (size_t i = 0; i < json_size(rows); ++i)
        if (!act_search_row(json_at(rows, i), f, query, seen)) return false;
    return true;
}

static bool act_search_count(const char *query, const size_t seen[2], size_t want)
{
    if (query[0] == 'Q' && (seen[0] != 9u || seen[1] != 9u)) return false;
    return seen[0] + seen[1] == want;
}

static bool act_search_input(struct json_value *input, const char *query, const char *source)
{
    return json_push_kv_str(input, "query", query) &&
        (!source || json_push_kv_str(input, "source_version", source));
}
static bool act_search_continue(const struct json_value *next, const char *source,
    struct json_value *doc)
{
    const char *pin = json_get_str(json_get(next, "source_version"));
    return next && (!source || (pin && !strcmp(pin, source))) && act_wire(next, doc);
}
static bool act_search_all(struct ac_fixture *f, const char *query, size_t want, const char *source)
{
    struct abc_leaf l; bool ok = act_call(&l, NULL, true);
    struct json_value doc, next_doc; json_init(&doc); json_init(&next_doc);
    size_t seen[2] = {0}, pages = 0; bool complete = false;
    ok = ok && act_search_input(&l.in, query, source) && act_wire(&l.in, &doc);
    while (ok && pages++ < 32u) {
        const struct json_value *d = json_get(&doc, "data");
        const struct json_value *rows = json_get(d, "matches");
        ok = act_wire_identity(&doc, f) && act_search_rows(rows, f, query, seen);
        if (json_get_bool(json_get(d, "complete"))) { complete = true; break; }
        const struct json_value *next = act_wire_next(&doc, "query");
        ok = ok && act_search_continue(next, source, &next_doc);
        if (ok) { json_free(&doc); doc = next_doc; json_init(&next_doc); }
    }
    json_free(&doc); json_free(&next_doc); abc_close(&l);
    return ok && complete && act_search_count(query, seen, want) && act_preserved(f, false);
}

static bool act_search_refusal(const char *query, int revision, const char *error)
{
    struct abc_leaf l; bool ok = act_call(&l, NULL, false);
    ok = ok && json_push_kv_str(&l.in, "query", query);
    if (revision >= 0) ok = ok && json_push_kv_int(&l.in, "expected_revision", revision);
    ok = ok && (!strcmp(error, "BAD_INPUT") ? act_bad_input_boundaries(&l) :
                act_result(&l, error));
    abc_close(&l); return ok;
}

static bool act_search_next_refusals(void)
{
    static const char data[] = "{\"name\":\"skycombat\",\"selection_revision\":1,\"query\":\"BOOST\",\"page\":0,\"offset\":0,\"matches\":[],\"complete\":false,\"next_page\":0,\"next_offset\":128}";
    const char *bad[] = {
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"query\":\"OTHER\",\"page\":0,\"offset\":128}",
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"query\":\"BOOST\",\"page\":0,\"offset\":127}",
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"query\":\"BOOST\",\"page\":1,\"offset\":128}",
        "{\"name\":\"skycombat\",\"expected_revision\":2,\"query\":\"BOOST\",\"page\":0,\"offset\":128}",
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"page\":0,\"offset\":128}"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i)
        if (!act_next_case("app.customize", data, bad[i], false)) return false;
    return act_next_case("app.customize", data,
        "{\"name\":\"skycombat\",\"expected_revision\":1,\"query\":\"BOOST\",\"page\":0,\"offset\":128}", true);
}

static bool act_pinned_next_identity(struct json_value *data, struct json_value *input,
    const char *kept, const char *draft)
{
    return json_push_kv_str(data, "name", "skycombat") && json_push_kv_int(data, "selection_revision", 1) &&
        json_push_kv_str(data, "version", kept) && json_push_kv_str(data, "source_version", draft) &&
        json_push_kv_str(input, "name", "skycombat") && json_push_kv_int(input, "expected_revision", 1);
}
static bool act_pinned_next_case(const char *shape, const char *cursor, unsigned kind)
{
    struct json_value data = {0}, input = {0}; char kept[65], draft[65];
    memset(kept, '1', 64); kept[64] = 0;
    memset(draft, '2', 64); draft[64] = 0;
    bool ok = json_read(&data, shape, strlen(shape)) && json_read(&input, cursor, strlen(cursor)) &&
        act_pinned_next_identity(&data, &input, kept, draft);
    if (kind == 3) ok = ok && json_push_kv_int(&input, "source_version", 2);
    else if (kind) ok = ok && json_push_kv_str(&input, "source_version", kind == 2 ? kept : draft);
    if (kind == 4) ok = ok && json_push_kv_str(&input, "unexpected", "no");
    char data_wire[2048], input_wire[1024];
    ok = ok && json_write(&data, data_wire, sizeof(data_wire)) &&
        json_write(&input, input_wire, sizeof(input_wire)) &&
        act_next_case("app.customize", data_wire, input_wire, kind == 1);
    json_free(&data); json_free(&input); return ok;
}
static bool act_pinned_next_cases(void)
{
    static const struct { const char *data, *input; } cases[] = {
        {"{\"query\":\"BOOST\",\"page\":0,\"offset\":0,\"matches\":[],\"complete\":false,\"next_page\":0,\"next_offset\":128}",
         "{\"query\":\"BOOST\",\"page\":0,\"offset\":128}"},
        {"{\"file\":{\"path\":\"include/boost.h\"},\"complete\":false,\"next_offset\":512}",
         "{\"path\":\"include/boost.h\",\"offset\":512}"},
        {"{\"files\":[],\"complete\":false,\"next_page\":4}", "{\"page\":4}"}
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i)
        for (unsigned kind = 0; kind < 5; ++kind)
            if (!act_pinned_next_case(cases[i].data, cases[i].input, kind)) return false;
    return true;
}

static bool act_searches(struct ac_fixture *f)
{
    char repeated[65]; memset(repeated, 'Q', 64); repeated[64] = 0;
    return act_search_all(f, "BOOST 2", 1, NULL) && act_search_all(f, "BOOST 3", 0, NULL) &&
        act_search_all(f, "BOOST 4", 0, NULL) && act_search_all(f, repeated, 18, NULL) &&
        act_search_refusal("BOOST", -1, "REVISION_REQUIRED") &&
        act_search_refusal("BOOST", 2, "SELECTION_STALE") &&
        act_search_refusal("", 1, "BAD_INPUT") && act_search_next_refusals();
}
static int act_pinned_search_case(void)
{
    int failures = 0; struct ac_fixture f = {0};
    TEST("serialized pinned search advances without losing its source and refuses altered draft continuations") {
        ASSERT(act_setup(&f, true));
        ASSERT(act_preserved(&f, true));
        char source[65], repeated[65]; zcl_hex_encode(f.kept.version, 32, source);
        memset(repeated, 'Q', 64); repeated[64] = 0;
        ASSERT(act_search_all(&f, "PLAYER1", 0, source));
        ASSERT(act_search_all(&f, "BOOST 2", 1, source));
        ASSERT(act_search_all(&f, repeated, 18, source));
        ASSERT(act_pinned_next_cases());
        PASS();
    } _test_next:;
    act_cleanup(&f); return failures;
}

/* Search-only edge fixtures retain real saved CAS and a readable live file. */
static bool acs_file(struct ac_fixture *f, const char *name,
                     const unsigned char *bytes, size_t count, size_t repeats)
{
    char path[1000];
    int n = snprintf(path, sizeof(path), "%s/%s", f->world.copy, name);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool ok = true;
    for (size_t i = 0; ok && i < repeats; ++i)
        ok = fwrite(bytes, 1, count, file) == count;
    return fclose(file) == 0 && ok;
}

static bool acs_setup(struct ac_fixture *f)
{
    if (!act_save_environment(f) || !abc_world_init(&f->world) ||
        !act_configure_environment(f)) return false;
    unsigned char block[4097]; memset(block, 'Z', sizeof(block));
    const unsigned char binary[] = {'A', 0, 0xff, 'B'};
    /* 4097 * 256 = 1MiB + 256: deliberately over the per-file ceiling. */
    return acs_file(f, "acs-large", block, sizeof(block), 256) &&
        acs_file(f, "acs-binary", binary, sizeof(binary), 1) &&
        act_snapshot(f, "save", f->head) && act_keep(f);
}

static bool acs_request(struct abc_leaf *l, const char *query, size_t page, size_t offset)
{
    return act_call(l, NULL, true) && json_push_kv_str(&l->in, "query", query) &&
        json_push_kv_int(&l->in, "page", (int64_t)page) &&
        json_push_kv_int(&l->in, "offset", (int64_t)offset);
}

static bool acs_string(const struct json_value *row, const char *key, const char *expected)
{
    const char *value = json_get_str(json_get(row, key));
    return value && !strcmp(value, expected);
}

static bool acs_skip_row(const struct json_value *data, size_t page)
{
    const struct json_value *rows = json_get(data, "skipped");
    const struct json_value *row = json_at(rows, 0);
    return json_size(rows) == 1 &&
        json_get_int(json_get(row, "page")) == (int64_t)page &&
        json_get_int(json_get(row, "size")) == 4097 * 256 &&
        acs_string(row, "reason", "file_exceeds_1MiB");
}

static bool acs_skipped(size_t page, size_t end)
{
    struct abc_leaf l; struct json_value doc; json_init(&doc);
    bool ok = acs_request(&l, "ZZZ", page, 0) && act_wire(&l.in, &doc);
    const struct json_value *data = json_get(&doc, "data");
    ok = ok && acs_skip_row(data, page) &&
        json_get_int(json_get(data, "unsearched_files")) == 1;
    abc_close(&l); json_free(&doc); json_init(&doc);
    bool last = acs_request(&l, "ZZZ", end, 0) && act_wire(&l.in, &doc);
    data = json_get(&doc, "data");
    last = last && json_get_bool(json_get(data, "complete")) &&
        json_get_int(json_get(data, "unsearched_files")) == 1 &&
        json_get_int(json_get(data, "scanned_files")) == 0 &&
        json_size(json_get(data, "matches")) == 0 &&
        json_size(json_get(data, "skipped")) == 0;
    abc_close(&l); json_free(&doc); return ok && last;
}

static bool acs_binary_row(const struct json_value *row, const uint8_t blob[32])
{
    char hex[65]; zcl_hex_encode(blob, 32, hex);
    return acs_string(row, "path", "acs-binary") && acs_string(row, "blob", hex) &&
        acs_string(row, "encoding", "base64") && acs_string(row, "content", "QQD/Qg==") &&
        json_get_int(json_get(row, "offset")) == 0 &&
        json_get_int(json_get(row, "bytes")) == 4;
}

static bool acs_binary(size_t page, const uint8_t blob[32])
{
    struct abc_leaf l; struct json_value doc; json_init(&doc);
    bool ok = acs_request(&l, "A", page, 0) && act_wire(&l.in, &doc);
    const struct json_value *matches = json_get(json_get(&doc, "data"), "matches");
    ok = ok && json_size(matches) >= 1 && acs_binary_row(json_at(matches, 0), blob);
    abc_close(&l); json_free(&doc); return ok;
}

static bool acs_refused(size_t page, size_t offset, const char *error)
{
    struct abc_leaf l;
    bool ok = acs_request(&l, "A", page, offset) && act_result(&l, error);
    abc_close(&l); return ok;
}

static bool acs_query_bound(const char *query)
{
    struct abc_leaf l;
    bool ok = acs_request(&l, query, 0, 0) && act_bad_input_boundaries(&l);
    abc_close(&l); return ok;
}

static bool acs_bounds(size_t binary, size_t end)
{
    char query[66]; memset(query, 'A', 65); query[65] = 0;
    return acs_refused(end + 1, 0, "BAD_INPUT") &&
        acs_refused(end, 1, "BAD_INPUT") && acs_refused(binary, 5, "BLOB_RANGE") &&
        acs_query_bound(query) && acs_query_bound("");
}

static bool acs_live_binary(struct ac_fixture *f)
{
    char path[1000]; uint8_t *bytes = NULL; size_t size = 0;
    const unsigned char expected[] = {'A', 0, 0xff, 'B'};
    int n = snprintf(path, sizeof(path), "%s/acs-binary", f->world.copy);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    bool ok = zcl_read_whole_file(path, 8, &bytes, &size, "search live fallback control") &&
        size == sizeof(expected) && !memcmp(bytes, expected, sizeof(expected));
    free(bytes); return ok;
}

static bool acs_missing_corrupt(struct ac_fixture *f, size_t page, const uint8_t blob[32])
{
    char path[1600], saved[1620];
    if (!act_object_path(f, blob, path)) return false;
    int n = snprintf(saved, sizeof(saved), "%s.acs-saved", path);
    if (n < 0 || (size_t)n >= sizeof(saved) || rename(path, saved)) return false;
    bool ok = acs_live_binary(f) && acs_refused(page, 0, "BLOB_UNREADABLE");
    FILE *file = fopen(path, "wb");
    bool written = file && fwrite("corrupt", 1, 7, file) == 7;
    if (file && fclose(file)) written = false;
    bool corrupt = written && acs_live_binary(f) && acs_refused(page, 0, "BLOB_UNREADABLE");
    bool removed = unlink(path) == 0;
    bool restored = rename(saved, path) == 0;
    return ok && corrupt && removed && restored && acs_binary(page, blob);
}

static bool acs_manifest(struct ac_fixture *f)
{
    struct vcs_manifest manifest;
    if (!vcs_tree_load(f->world.copy, f->tree, &manifest)) return false;
    size_t binary = manifest.count, large = manifest.count;
    for (size_t i = 0; i < manifest.count; ++i) {
        if (!strcmp(manifest.entries[i].path, "acs-binary")) binary = i;
        if (!strcmp(manifest.entries[i].path, "acs-large")) large = i;
    }
    bool ok = binary < manifest.count && large < manifest.count;
    if (ok) ok = acs_skipped(large, manifest.count) &&
        acs_binary(binary, manifest.entries[binary].blob) && acs_bounds(binary, manifest.count) &&
        acs_missing_corrupt(f, binary, manifest.entries[binary].blob);
    vcs_manifest_free(&manifest); return ok;
}

static int acs_edges(void)
{
    int failures = 0; struct ac_fixture f = {0};
    TEST("selected source search reports omissions, validates cursors and refuses damaged CAS") {
        ASSERT(acs_setup(&f));
        ASSERT(acs_manifest(&f));
        PASS();
    } _test_next:;
    act_cleanup(&f); return failures;
}

/* Explicit large slices use the same verified CAS and production serializer.
 * No fixture changes the default limit or the existing reply budgets. */
static bool acl_setup(struct ac_fixture *f)
{
    if (!act_save_environment(f) || !abc_world_init(&f->world) ||
        !act_configure_environment(f)) return false;
    unsigned char bytes[4097]; char quoted[241]; act_quote_path(quoted);
    memset(bytes, 'Q', sizeof(bytes));
    if (!acs_file(f, "slice-text", bytes, sizeof(bytes), 1)) return false;
    memset(bytes, 0, 2048);
    if (!acs_file(f, "slice-binary", bytes, 2048, 1)) return false;
    memset(bytes, 1, 2048); /* Each byte needs six bytes in JSON: \u0001. */
    return acs_file(f, quoted, bytes, 2048, 1) &&
        act_snapshot(f, "save", f->head) && act_keep(f);
}

static bool acl_request(struct abc_leaf *l, const char *path, int limit)
{
    return act_call(l, path, true) &&
        (limit == 0 || json_push_kv_int(&l->in, "limit", limit));
}

static bool acl_budget(const struct json_value *doc)
{
    const struct json_value *data = json_get(doc, "data");
    return json_write(doc, NULL, 0) <= 8192u &&
        (!data || json_write(data, NULL, 0) <= 6144u);
}

static bool acl_default(void)
{
    struct abc_leaf l; struct json_value doc; json_init(&doc);
    bool ok = acl_request(&l, "slice-text", 0) && act_wire(&l.in, &doc);
    const struct json_value *d = json_get(&doc, "data");
    ok = ok && acl_budget(&doc) && act_wire_qbytes(&doc, 512) &&
        json_get_int(json_get(d, "bytes")) == 512 &&
        json_get_int(json_get(d, "next_offset")) == 512 &&
        !json_get_bool(json_get(d, "complete"));
    abc_close(&l); json_free(&doc); return ok;
}

static bool acl_text_page(const struct json_value *doc, size_t page)
{
    size_t offset = page * 2048u, count = page == 2 ? 1u : 2048u;
    const struct json_value *d = json_get(doc, "data");
    return acl_budget(doc) && act_wire_qbytes(doc, count) &&
        acs_string(d, "encoding", "utf8") &&
        json_get_int(json_get(d, "bytes")) == (int64_t)count &&
        json_get_int(json_get(d, "offset")) == (int64_t)offset &&
        json_get_int(json_get(d, "next_offset")) == (int64_t)(offset + count) &&
        json_get_bool(json_get(d, "complete")) == (page == 2);
}

static bool acl_next(const struct json_value *doc, struct json_value *next, size_t page)
{
    const struct json_value *input = act_wire_next(doc, "offset");
    return input && acs_string(input, "name", "skycombat") &&
        acs_string(input, "path", "slice-text") &&
        json_get_int(json_get(input, "expected_revision")) == 1 &&
        json_get_int(json_get(input, "offset")) == (int64_t)((page + 1u) * 2048u) &&
        json_get_int(json_get(input, "limit")) == 2048 && act_wire(input, next);
}

static bool acl_pages(struct ac_fixture *f)
{
    struct abc_leaf l; struct json_value doc, next;
    json_init(&doc); json_init(&next);
    bool ok = acl_request(&l, "slice-text", 2048) && act_wire(&l.in, &doc);
    for (size_t page = 0; ok && page < 3; ++page) {
        ok = act_wire_identity(&doc, f) && acl_text_page(&doc, page);
        if (page == 2) { ok = ok && !act_wire_next(&doc, "offset"); break; }
        ok = ok && acl_next(&doc, &next, page);
        if (ok) { json_free(&doc); doc = next; json_init(&next); }
    }
    abc_close(&l); json_free(&doc); json_free(&next); return ok;
}

static bool acl_binary(void)
{
    struct abc_leaf l; struct json_value doc; json_init(&doc);
    bool ok = acl_request(&l, "slice-binary", 2048) && act_wire(&l.in, &doc);
    const struct json_value *d = json_get(&doc, "data");
    const char *text = json_get_str(json_get(d, "content"));
    /* Exactly 2048 zero bytes: 2731 'A' characters and one padding '='. */
    ok = ok && acl_budget(&doc) && acs_string(d, "encoding", "base64") &&
        text && strlen(text) == 2732 && strspn(text, "A") == 2731 && text[2731] == '=' &&
        json_get_int(json_get(d, "bytes")) == 2048 &&
        json_get_int(json_get(d, "next_offset")) == 2048 &&
        json_get_bool(json_get(d, "complete"));
    abc_close(&l); json_free(&doc); return ok;
}

static bool acl_refusal_wire(struct abc_leaf *l)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = abc_spec("app.customize");
    struct zcl_command_context ctx = {.registry = reg, .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER};
    char wire[8193]; enum zcl_command_exit code;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &l->in, false,
        spec->path, "normal", 0, 0, NULL, wire, sizeof(wire), &code);
    struct json_value doc; json_init(&doc);
    bool ok = n > 0 && n <= 8192u && code != ZCL_COMMAND_EXIT_OK && json_read(&doc, wire, n);
    const struct json_value *error = json_get(&doc, "error");
    const struct json_value *mutated = json_get(error, "mutated");
    ok = ok && acl_budget(&doc) && acs_string(error, "code", "CONTEXT_REFUSED") &&
        mutated && mutated->type == JSON_BOOL && !json_get_bool(mutated) &&
        !json_get(json_get(&doc, "data"), "content") && !act_wire_next(&doc, "offset");
    json_free(&doc); return ok;
}

static bool acl_escaped_small(const char *path)
{
    struct abc_leaf l; struct json_value doc; json_init(&doc);
    bool ok = acl_request(&l, path, 512) && act_wire(&l.in, &doc);
    const struct json_value *d = json_get(&doc, "data");
    const char *text = json_get_str(json_get(d, "content"));
    ok = ok && acl_budget(&doc) && text && strlen(text) == 512;
    for (size_t i = 0; ok && i < 512; ++i) ok = (unsigned char)text[i] == 1;
    ok = ok && acs_string(d, "encoding", "utf8") &&
        json_get_int(json_get(d, "next_offset")) == 512 &&
        !json_get_bool(json_get(d, "complete"));
    abc_close(&l); json_free(&doc); return ok;
}

static bool acl_escaped(void)
{
    char path[241]; act_quote_path(path);
    struct abc_leaf l;
    bool ok = acl_request(&l, path, 2048) && acl_refusal_wire(&l);
    abc_close(&l);
    return acl_escaped_small(path) && ok;
}

static int acl_slices(void)
{
    int failures = 0; struct ac_fixture f = {0};
    TEST("explicit 2048-byte source slices preserve default, continuation and wire budgets") {
        ASSERT(acl_setup(&f));
        ASSERT(acl_default());
        ASSERT(acl_pages(&f));
        ASSERT(acl_binary());
        ASSERT(acl_escaped());
        PASS();
    } _test_next:;
    act_cleanup(&f); return failures;
}

int test_app_customize(void)
{
    int failures = 0;
    struct ac_fixture f;
    TEST("customize reads selected N while HEAD and working files advance without mutation") {
        ASSERT(act_setup(&f, true));
        ASSERT(act_reads(&f));
        ASSERT(act_escaped_reads());
        ASSERT(act_serialized_navigation(&f));
        ASSERT(act_searches(&f));
        ASSERT(act_refusals());
        ASSERT(act_bounds());
        ASSERT(act_blob_refusal(&f));
        ASSERT(act_selection_refusal(&f));
        ASSERT(act_no_grant(&f));
        ASSERT(act_reader_bounds(&f));
        ASSERT(act_alias_refusal(&f, false));
        ASSERT(act_alias_refusal(&f, true));
        ASSERT(act_preserved(&f, false));
        ASSERT(act_unknown_version(&f));
        ASSERT(act_foreign_history(&f));
        PASS();
    } _test_next:;
    act_cleanup(&f);
    failures += acs_edges();
    failures += acl_slices();
    failures += act_pinned_search_case();
    return failures;
}

static bool ae_request(struct abc_leaf *l, struct ac_fixture *f, const char *path,
                       const char *content, const char *head, const char *blob,
                       int revision, const char *plan)
{
    abc_open(l);
    bool ok = json_push_kv_str(&l->in, "name", "skycombat") &&
        json_push_kv_int(&l->in, "expected_revision", revision) &&
        json_push_kv_str(&l->in, "expected_head", head) &&
        json_push_kv_str(&l->in, "path", path) &&
        json_push_kv_str(&l->in, "expected_blob", blob) &&
        json_push_kv_str(&l->in, "content", content);
    (void)f;
    return ok && (!plan || (json_push_kv_str(&l->in, "plan_id", plan) &&
                             json_push_kv_bool(&l->in, "confirm", true)));
}

static bool ae_refusal(struct ac_fixture *f, const char *head, const char *blob,
                       int revision, const char *path, const char *error)
{
    struct abc_leaf l;
    if (!ae_request(&l, f, path, "#define BOOST 9\n", head, blob, revision, NULL)) return false;
    bool ok = abc_exec("app.edit", &l) && l.out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(l.out.error.code, error);
    abc_close(&l);
    return ok;
}

static bool ae_noop(struct ac_fixture *f, const char *head, const char *blob)
{
    struct abc_leaf l;
    if (!ae_request(&l, f, "include/boost.h", "#define BOOST 2\n", head, blob, 1, NULL)) return false;
    bool ok = abc_pass("app.edit", &l);
    char plan[65]; snprintf(plan, sizeof(plan), "%s", abc_get(&l, "plan_id"));
    abc_close(&l);
    if (!ok || !ae_request(&l, f, "include/boost.h", "#define BOOST 2\n", head, blob, 1, plan)) return false;
    ok = abc_exec("app.edit", &l) && l.out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(l.out.error.code, "NO_CHANGES");
    abc_close(&l);
    return ok;
}

static bool ae_contents(struct ac_fixture *f, const uint8_t root[32])
{
    struct vcs_manifest manifest = {0};
    if (!vcs_tree_load_readonly_bounded(f->world.copy, root, 8u * 1024u * 1024u, 16384u, &manifest)) return false;
    bool ok = false;
    for (size_t i = 0; i < manifest.count; ++i) {
        if (strcmp(manifest.entries[i].path, "include/boost.h")) continue;
        uint8_t *data = NULL; size_t size = 0;
        ok = vcs_object_get_readonly_bounded(f->world.copy, manifest.entries[i].blob,
            VCS_TAG_BLOB, 1024, &data, &size) == 0 && size == strlen("#define BOOST 9\n") &&
            !memcmp(data, "#define BOOST 9\n", size);
        free(data);
        break;
    }
    vcs_manifest_free(&manifest);
    return ok;
}

static bool ae_bad_text(struct ac_fixture *f, const char *head, const char *blob)
{
    char *large = malloc(1024u * 1024u + 2u);
    if (!large) return false;
    memset(large, 'x', 1024u * 1024u + 1u); large[1024u * 1024u + 1u] = 0;
    const char invalid[] = {(char)0xc0, (char)0xaf, 0};
    const char *const cases[] = {invalid, large};
    bool ok = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        struct abc_leaf l;
        if (!ae_request(&l, f, "include/boost.h", cases[i], head, blob, 1, NULL)) { ok = false; break; }
        const struct zcl_command_spec *spec = abc_spec("app.edit");
        if (!spec || !spec->handler) { abc_close(&l); ok = false; break; }
        l.req.spec = spec; l.req.input = &l.in; l.req.invoked_name = spec->path;
        spec->handler(&l.req, &l.out);
        ok = ok && l.out.status != ZCL_COMMAND_STATUS_PASSED && !strcmp(l.out.error.code, "BAD_INPUT");
        abc_close(&l);
    }
    free(large); return ok;
}

/* The fixture already has a seal pin; authorize only this setup sealset. */
static bool ae_pin_seal(struct ac_fixture *f)
{
    struct vcs_repo *repo = vcs_open(f->world.copy);
    if (!repo) return false;
    struct vcs_manifest manifest = {0}; char **globs = NULL; size_t count = 0;
    uint8_t seal[32], version[32];
    bool ok = vcs_manifest_build(vcs_repo_root(repo), vcs_repo_index(repo), &manifest) &&
        vcs_seal_load_globs(vcs_repo_root(repo), &globs, &count) &&
        vcs_sealset_hash(&manifest, globs, count, seal) &&
        vcs_seal_grant_unseal(vcs_repo_index(repo), seal);
    struct vcs_snapshot_meta meta = {.phase = "save"};
    if (ok) ok = vcs_snapshot(repo, &meta, version) == VCS_OK;
    if (ok) memcpy(f->head, version, 32);
    vcs_seal_free_globs(globs, count); vcs_manifest_free(&manifest); vcs_close(repo);
    return ok;
}

static bool ae_sealed(struct ac_fixture *f)
{
    if (!abc_put(f->world.copy, ".zvcs/sealed_paths", "include/boost.h\n") ||
        !ae_pin_seal(f)) return false;
    if (!act_preserved(f, true)) return false;
    char head[65], blob[65];
    zcl_hex_encode(f->head, 32, head); zcl_hex_encode(f->blob, 32, blob);
    struct abc_leaf l;
    if (!ae_request(&l, f, "include/boost.h", "#define BOOST 9\n", head, blob, 1, NULL)) return false;
    bool ok = abc_pass("app.edit", &l);
    char plan[65]; snprintf(plan, sizeof(plan), "%s", abc_get(&l, "plan_id"));
    abc_close(&l);
    if (!ok || !ae_request(&l, f, "include/boost.h", "#define BOOST 9\n", head, blob, 1, plan)) return false;
    ok = abc_exec("app.edit", &l) && l.out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(l.out.error.code, "SNAPSHOT_REFUSED") && l.out.error.mutated;
    abc_close(&l); return ok && act_preserved(f, false);
}

static bool ae_stale_commit(struct ac_fixture *f)
{
    char head[65], blob[65];
    zcl_hex_encode(f->head, 32, head); zcl_hex_encode(f->blob, 32, blob);
    struct abc_leaf l;
    if (!ae_request(&l, f, "include/boost.h", "#define BOOST 9\n", head, blob, 1, NULL)) return false;
    bool ok = abc_pass("app.edit", &l);
    char plan[65]; snprintf(plan, sizeof(plan), "%s", abc_get(&l, "plan_id"));
    abc_close(&l);
    uint8_t advanced[32];
    if (!ok || !act_snapshot(f, "save", advanced) ||
        !ae_request(&l, f, "include/boost.h", "#define BOOST 9\n", head, blob, 1, plan)) return false;
    ok = abc_exec("app.edit", &l) && l.out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(l.out.error.code, "HEAD_STALE");
    abc_close(&l); return ok;
}

static bool ae_verify_draft(struct ac_fixture *f, const char *version, const char *root)
{
    struct app_selection selection;
    uint8_t selection_hash[32];
    bool ok = app_selection_load(f->env.state_dir, "skycombat", &selection) == APP_SELECTION_OK &&
        selection.revision == 1 && !memcmp(selection.version, f->kept.version, 32) &&
        act_hash(f->env.state_dir, "skycombat.selection", selection_hash) &&
        !memcmp(selection_hash, f->selection_hash, 32);
    char file[1000], *text = NULL; size_t size = 0;
    snprintf(file, sizeof(file), "%s/include/boost.h", f->world.copy);
    ok = ok && zcl_read_whole_file_text(file, 512, &text, &size, "draft dirty") &&
        size == strlen("#define BOOST 4\n") && !memcmp(text, "#define BOOST 4\n", size);
    free(text);
    struct zcl_package_copy copy; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.edit.v1");
    bool opened = zcl_package_copy_open_selected_as(f->world.copy, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "test", version);
    uint8_t wanted[32];
    ok = ok && opened && zcl_hex_decode_lower(root, wanted, 32) &&
        !memcmp(copy.selected_tree, wanted, 32) && !memcmp(copy.head_version, copy.selected_version, 32) &&
        ae_contents(f, wanted);
    if (opened) zcl_package_copy_close(&copy);
    zcl_command_reply_free(&reply);
    return ok;
}
static bool ae_initial_refusals(struct ac_fixture *f, const char *head, const char *blob, const char *wrong)
{
    return ae_refusal(f, head, blob, 2, "include/boost.h", "SELECTION_STALE") &&
        ae_refusal(f, wrong, blob, 1, "include/boost.h", "HEAD_STALE") &&
        ae_refusal(f, head, wrong, 1, "include/boost.h", "BLOB_STALE") &&
        ae_refusal(f, head, blob, 1, "missing.h", "PATH_UNKNOWN");
}
static bool ae_prepare_draft(struct ac_fixture *f, const char *head, const char *blob, char plan[65])
{
    struct abc_leaf l;
    if (!act_preserved(f, true) || !ae_bad_text(f, head, blob) || !ae_noop(f, head, blob) ||
        !act_preserved(f, false) ||
        !ae_request(&l, f, "include/boost.h", "#define BOOST 9\n", head, blob, 1, NULL)) return false;
    bool ok = abc_pass("app.edit", &l);
    snprintf(plan, 65, "%s", abc_get(&l, "plan_id"));
    abc_close(&l);
    return ok && strlen(plan) == 64 && act_preserved(f, false);
}
static bool ae_draft(struct ac_fixture *f)
{
    char head[65], blob[65], wrong[65];
    zcl_hex_encode(f->head, 32, head); zcl_hex_encode(f->blob, 32, blob);
    memset(wrong, 'a', 64); wrong[64] = 0;
    if (!ae_initial_refusals(f, head, blob, wrong)) return false;
    char plan[65]; struct abc_leaf l;
    if (!ae_prepare_draft(f, head, blob, plan) ||
        !ae_request(&l, f, "include/boost.h", "#define BOOST 9\n", head, blob, 1, plan)) return false;
    bool ok = abc_pass("app.edit", &l);
    char version[65], root[65];
    snprintf(version, sizeof(version), "%s", abc_get(&l, "version"));
    snprintf(root, sizeof(root), "%s", abc_get(&l, "source_root"));
    ok = ok && strlen(version) == 64 && strlen(root) == 64 && l.out.next_count &&
        !strcmp(l.out.next[0].command, "app.build") && strstr(l.out.next[0].input_json, version);
    abc_close(&l);
    return ok && ae_verify_draft(f, version, root);
}

static int ae_stale_case(void)
{
    int failures = 0;
    struct ac_fixture f;
    TEST("app.edit refuses a plan whose head advanced before confirmation") {
        ASSERT(act_setup(&f, false));
        ASSERT(ae_stale_commit(&f));
        PASS();
    } _test_next:;
    act_cleanup(&f);
    return failures;
}

static int ae_sealed_case(void)
{
    int failures = 0;
    struct ac_fixture f;
    TEST("app.edit refuses a sealed replacement") {
        ASSERT(act_setup(&f, false));
        ASSERT(ae_sealed(&f));
        PASS();
    } _test_next:;
    act_cleanup(&f);
    return failures;
}

/* Real catalog bounds, independent of the direct-handler fixture shortcut. */
static bool ae_catalog_content(const struct zcl_command_spec *spec,
    const struct json_value *value, bool expected)
{
    struct json_value in; json_init(&in); json_set_object(&in);
    char why[256];
    bool ok = spec && json_push_kv(&in, "content", value);
    if (ok) ok = zcl_command_registry_input_validate(spec, &in, why, sizeof(why)) == expected;
    if (ok && !expected && !strcmp(spec->path, "app.edit"))
        ok = strstr(why, "UTF-8 string") && strstr(why, "1048576 bytes") &&
            strstr(why, "empty is allowed") && !strstr(why, "4096");
    json_free(&in); return ok;
}
static bool ae_catalog_text(const struct zcl_command_spec *spec, const char *text, bool expected)
{
    struct json_value value; json_init(&value);
    json_set_str(&value, text);
    bool ok = value.type == JSON_STR && json_get_str(&value) &&
        !strcmp(json_get_str(&value), text) && ae_catalog_content(spec, &value, expected);
    json_free(&value); return ok;
}
static bool ae_catalog_types(const struct zcl_command_spec *spec)
{
    struct json_value value; json_init(&value);
    json_set_null(&value); bool ok = ae_catalog_content(spec, &value, false);
    json_set_int(&value, 1); ok = ae_catalog_content(spec, &value, false) && ok;
    json_set_bool(&value, true); ok = ae_catalog_content(spec, &value, false) && ok;
    json_set_array(&value); ok = ae_catalog_content(spec, &value, false) && ok;
    json_set_object(&value); ok = ae_catalog_content(spec, &value, false) && ok;
    json_free(&value);
    const char invalid[] = {(char)0xc0, (char)0xaf, 0};
    return ok && ae_catalog_text(spec, invalid, false) &&
        ae_catalog_text(spec, "", true) && ae_catalog_text(spec, "\xc3\xa9", true);
}
static bool ae_catalog_boundaries(const struct zcl_command_spec *spec, char *text)
{
    size_t cap = ZCL_COMMAND_APP_EDIT_CONTENT_MAX;
    memset(text, 'Q', cap + 1); text[cap + 1] = 0;
    bool ok = ae_catalog_text(spec, text, false);
    text[cap] = 0; ok = ae_catalog_text(spec, text, true) && ok;
    text[cap - 1] = 0; ok = ae_catalog_text(spec, text, true) && ok;
    /* Same declared content field under another leaf must keep its generic
     * bound. Synthetic spec tests isolation; no synthetic handler executes. */
    struct zcl_command_spec other = *spec; other.path = "fixture.other";
    text[4097] = 0; ok = ae_catalog_text(&other, text, false) && ok;
    text[4096] = 0;
    return ae_catalog_text(&other, text, true) && ok &&
        zcl_command_registry_input_str_max("content") == ZCL_COMMAND_INPUT_STR_MAX;
}
static bool ae_catalog_escaped_frame(const struct zcl_command_spec *spec, char *text)
{
    memset(text, 1, ZCL_COMMAND_APP_EDIT_CONTENT_MAX);
    text[ZCL_COMMAND_APP_EDIT_CONTENT_MAX] = 0;
    struct json_value in; json_init(&in); json_set_object(&in);
    bool ok = json_push_kv_str(&in, "content", text);
    size_t encoded = ok ? json_write(&in, NULL, 0) : 0;
    ok = ok && encoded > 6u * ZCL_COMMAND_APP_EDIT_CONTENT_MAX &&
        encoded + 1 <= zcl_command_registry_input_budget_bytes(spec);
    json_free(&in); return ok;
}
static bool ae_catalog_bounds(void)
{
    const struct zcl_command_spec *spec = abc_spec("app.edit");
    struct zcl_command_input_descriptor d;
    if (!spec || !zcl_command_registry_input_descriptor(spec, "content", &d) ||
        d.type != JSON_STR || d.max_bytes != ZCL_COMMAND_APP_EDIT_CONTENT_MAX || !d.required) return false;
    char *text = malloc(ZCL_COMMAND_APP_EDIT_CONTENT_MAX + 2u);
    if (!text) return false;
    bool ok = ae_catalog_types(spec) && ae_catalog_boundaries(spec, text) &&
        ae_catalog_escaped_frame(spec, text);
    free(text); return ok;
}
static bool ae_bound_mismatch(struct abc_leaf *l)
{
    return abc_exec("app.edit", l) && l->out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(l->out.error.code, "PLAN_MISMATCH") && !l->out.error.mutated;
}
static bool ae_bound_plan(struct ac_fixture *f, const char *text, const char *plan,
    char saved[65])
{
    char head[65], blob[65]; zcl_hex_encode(f->head, 32, head); zcl_hex_encode(f->blob, 32, blob);
    struct abc_leaf l;
    bool ok = ae_request(&l, f, "include/boost.h", text, head, blob, 1, plan);
    if (ok) ok = plan ? ae_bound_mismatch(&l) :
        abc_pass("app.edit", &l);
    if (ok && !plan) {
        const char *p = abc_get(&l, "plan_id");
        ok = strlen(p) == 64;
        if (ok) memcpy(saved, p, 65);
    }
    abc_close(&l); return ok;
}
static bool ae_bound_plans(struct ac_fixture *f)
{
    char *text = malloc(36400); char plan[65], empty[65];
    if (!text) return false;
    memset(text, 'Q', 36399); text[36399] = 0;
    bool ok = act_preserved(f, true) && ae_bound_plan(f, text, NULL, plan);
    text[36398] = 'R';
    ok = ok && ae_bound_plan(f, text, plan, NULL) && ae_bound_plan(f, "", NULL, empty) &&
        act_preserved(f, false);
    free(text); return ok;
}

#if defined(ZCL_TESTING)
static int asb_cases(void);
#endif
int test_app_edit(void)
{
    int failures = 0;
    struct ac_fixture f;
    TEST("app.edit saves pinned N while preserving Keep and dirty working files") {
        ASSERT(act_setup(&f, false));
        ASSERT(ae_catalog_bounds());
        ASSERT(ae_bound_plans(&f));
        ASSERT(ae_draft(&f));
        PASS();
    } _test_next:;
    act_cleanup(&f);
    failures += ae_stale_case();
    failures += ae_sealed_case();
#if defined(ZCL_TESTING)
    failures += asb_cases();
#endif
    return failures;
}
/* Source-only owner fixture; it creates no host key outside the isolated HOME. */
static bool apt_input(struct abc_leaf *l, struct ac_fixture *f, const uint8_t version[32], const uint8_t head[32])
{
    char v[65], h[65]; zcl_hex_encode(version, 32, v); zcl_hex_encode(head, 32, h);
    abc_open(l);
    return json_push_kv_str(&l->in, "copy", f->world.copy) &&
        json_push_kv_str(&l->in, "datadir", f->world.alice_datadir) &&
        json_push_kv_str(&l->in, "version", v) && json_push_kv_str(&l->in, "expected_head", h);
}
static bool apt_key_path(struct ac_fixture *f, char key[900])
{
    int n = snprintf(key, 900, "%s/.z23/zcode_publisher.key", f->world.alice_home);
    return n > 0 && n < 900;
}
static bool apt_key_absent(struct ac_fixture *f)
{
    char key[900]; struct stat st;
    return apt_key_path(f, key) && lstat(key, &st) < 0 && errno == ENOENT;
}
static bool apt_external_key(struct ac_fixture *f)
{
    char dir[900], key[900], public_hex[PLUGIN_HEX_PUBLIC_KEY + 1];
    int n = snprintf(dir, sizeof(dir), "%s/.z23", f->world.alice_home);
    return n > 0 && (size_t)n < sizeof(dir) && (mkdir(dir, 0700) == 0 || errno == EEXIST) &&
        apt_key_path(f, key) && plugin_keygen(key, public_hex) == PLUGIN_OK;
}
static bool apt_plan_absent(struct ac_fixture *f)
{
    struct abc_leaf l;
    if (!apt_key_absent(f) || !act_preserved(f, true) ||
        !apt_input(&l, f, f->kept.version, f->head)) return false;
    bool ok = abc_pass("app.personalize", &l) &&
        !json_get_bool(json_get(&l.out.data, "key_exists")) &&
        json_get_bool(json_get(&l.out.data, "namespace_pending")) &&
        strlen(abc_get(&l, "plan_id")) == 64 && !abc_get(&l, "namespace")[0];
    abc_close(&l); return ok && apt_key_absent(f) && act_preserved(f, false);
}
static bool apt_key_race(struct ac_fixture *f)
{
    struct abc_leaf l;
    if (!apt_key_absent(f) || !act_preserved(f, true) ||
        !apt_input(&l, f, f->kept.version, f->head)) return false;
    bool ok = abc_pass("app.personalize", &l) && apt_external_key(f) &&
        abc_confirm("app.personalize", &l) && l.out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(l.out.error.code, "PLAN_MISMATCH") && !l.out.error.mutated;
    abc_close(&l); return ok && act_preserved(f, false);
}
static bool apt_current_head(struct ac_fixture *f, const uint8_t expected[32])
{
    struct zcl_package_copy copy = {0}; struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.app_personalize.v1");
    bool ok = zcl_package_copy_open_as(f->world.copy, ZCL_PACKAGE_COPY_READ,
        &copy, &reply, "test") && !memcmp(copy.head_version, expected, 32);
    zcl_package_copy_close(&copy); zcl_command_reply_free(&reply); return ok;
}
static bool apt_head_race(struct ac_fixture *f)
{
    struct abc_leaf l; uint8_t newer[32];
    if (!apt_input(&l, f, f->kept.version, f->head)) return false;
    bool ok = abc_pass("app.personalize", &l) && act_snapshot(f, "save", newer) &&
        act_preserved(f, true) &&
        abc_confirm("app.personalize", &l) && l.out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(l.out.error.code, "HEAD_STALE") && !l.out.error.mutated;
    abc_close(&l);
    return ok && apt_key_absent(f) && apt_current_head(f, newer) && act_preserved(f, false);
}
static bool apt_bad_metadata(struct ac_fixture *f, const char *metadata)
{
    uint8_t version[32]; struct abc_leaf l;
    if (!abc_put(f->world.copy, "zcode-package.json", metadata) ||
        !act_snapshot(f, "save", version) || !apt_key_absent(f) ||
        !act_preserved(f, true) || !apt_input(&l, f, version, version)) return false;
    bool ok = abc_exec("app.personalize", &l) && l.out.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(l.out.error.code, "METADATA_INVALID") && !l.out.error.mutated;
    abc_close(&l); return ok && apt_key_absent(f) && act_preserved(f, false);
}

struct apt_tip { uint8_t parent[32], id[32]; bool found; };
static bool apt_tip_visit(const struct vcs_commit *commit, const uint8_t id[32], void *context)
{
    struct apt_tip *tip = context;
    memcpy(tip->parent, commit->parent, 32); memcpy(tip->id, id, 32); tip->found = true;
    return false;
}
static bool apt_metadata_blob(struct ac_fixture *f, const struct vcs_entry *entry, struct json_value *out)
{
    uint8_t *bytes = NULL; size_t size = 0;
    bool ok = vcs_object_get_readonly_bounded(f->world.copy, entry->blob, VCS_TAG_BLOB,
        1024u * 1024u, &bytes, &size) == 0 && size == entry->size && json_read(out, (const char *)bytes, size);
    free(bytes); return ok;
}
static bool apt_metadata_equal(struct ac_fixture *f, const struct vcs_entry *before,
    const struct vcs_entry *after, const char *name)
{
    struct json_value a, b; json_init(&a); json_init(&b);
    bool ok = apt_metadata_blob(f, before, &a) && apt_metadata_blob(f, after, &b) &&
        a.type == JSON_OBJ && b.type == JSON_OBJ && a.num_children == b.num_children;
    const char *actual = json_get_str(json_get(&b, "name"));
    ok = ok && actual && !strcmp(actual, name);
    for (size_t i = 0; ok && i < a.num_children; ++i) {
        if (!strcmp(a.keys[i], "name")) continue;
        const struct json_value *other = json_get(&b, a.keys[i]);
        char left[4096], right[4096];
        size_t n = json_write(&a.children[i], left, sizeof(left));
        size_t m = other ? json_write(other, right, sizeof(right)) : 0;
        ok = n && n < sizeof(left) && n == m && !memcmp(left, right, n);
    }
    json_free(&a); json_free(&b); return ok;
}
static bool apt_trees_equal(struct ac_fixture *f, const uint8_t root[32], const char *name)
{
    struct vcs_manifest before = {0}, after = {0};
    bool ok = vcs_tree_load_readonly_bounded(f->world.copy, f->tree, 8u * 1024u * 1024u, 16384u, &before) &&
        vcs_tree_load_readonly_bounded(f->world.copy, root, 8u * 1024u * 1024u, 16384u, &after) &&
        before.count == after.count;
    bool metadata = false;
    for (size_t i = 0; ok && i < before.count; ++i) {
        const struct vcs_entry *a = &before.entries[i], *b = &after.entries[i];
        ok = !strcmp(a->path, b->path) && a->mode == b->mode;
        if (!ok) break;
        if (!strcmp(a->path, "zcode-package.json")) {
            metadata = true; ok = apt_metadata_equal(f, a, b, name);
        } else ok = a->size == b->size && !memcmp(a->blob, b->blob, 32);
    }
    vcs_manifest_free(&before); vcs_manifest_free(&after); return ok && metadata;
}
static bool apt_head_and_keep(struct ac_fixture *f, const uint8_t version[32])
{
    struct vcs_repo *repo = vcs_open_readonly(f->world.copy); struct apt_tip tip = {0};
    bool ok = repo && vcs_log(repo, 1, apt_tip_visit, &tip) == VCS_OK && tip.found &&
        !memcmp(tip.parent, f->head, 32) && !memcmp(tip.id, version, 32);
    if (repo) vcs_close(repo);
    struct app_selection selection; uint8_t hash[32];
    ok = ok && app_selection_load(f->env.state_dir, "skycombat", &selection) == APP_SELECTION_OK &&
        selection.revision == 1 && !memcmp(selection.version, f->kept.version, 32) &&
        act_hash(f->env.state_dir, "skycombat.selection", hash) && !memcmp(hash, f->selection_hash, 32);
    char path[1000], *text = NULL; size_t size = 0;
    (void)snprintf(path, sizeof(path), "%s/include/boost.h", f->world.copy);
    ok = ok && zcl_read_whole_file_text(path, 512, &text, &size, "personalize dirty") &&
        size == strlen("#define BOOST 4\n") && !memcmp(text, "#define BOOST 4\n", size);
    free(text); return ok;
}
static bool apt_success_verify(struct ac_fixture *f, const uint8_t key_before[32],
    const uint8_t root[32], const uint8_t version[32], const char *name)
{
    uint8_t key_after[32];
    return act_hash(f->world.alice_home, ".z23/zcode_publisher.key", key_after) &&
        !memcmp(key_before, key_after, 32) && apt_trees_equal(f, root, name) && apt_head_and_keep(f, version);
}
static bool apt_plan_visible(struct abc_leaf *l)
{
    return abc_pass("app.personalize", l) && json_get_bool(json_get(&l->out.data, "key_exists")) &&
        !json_get_bool(json_get(&l->out.data, "namespace_pending")) &&
        !strcmp(abc_get(l, "short_name"), "tinyapp") && strlen(abc_get(l, "namespace")) == 62;
}
static bool apt_existing_success(struct ac_fixture *f, uint8_t output_version[32], uint8_t output_root[32])
{
    struct abc_leaf l; uint8_t key_before[32], version[32], root[32];
    if (!apt_external_key(f) || !act_preserved(f, true) ||
        !act_hash(f->world.alice_home, ".z23/zcode_publisher.key", key_before) ||
        !apt_input(&l, f, f->kept.version, f->head)) return false;
    bool ok = apt_plan_visible(&l);
    char expected_name[128], expected_namespace[64];
    snprintf(expected_name, sizeof(expected_name), "%s", abc_get(&l, "name"));
    snprintf(expected_namespace, sizeof(expected_namespace), "%s", abc_get(&l, "namespace"));
    ok = ok && act_preserved(f, false) && abc_confirm("app.personalize", &l) &&
        l.out.status == ZCL_COMMAND_STATUS_PASSED && !json_get_bool(json_get(&l.out.data, "key_created")) &&
        !strcmp(abc_get(&l, "name"), expected_name) && !strcmp(abc_get(&l, "namespace"), expected_namespace) &&
        zcl_hex_decode_lower(abc_get(&l, "version"), version, 32) &&
        zcl_hex_decode_lower(abc_get(&l, "source_root"), root, 32);
    abc_close(&l);
    ok = ok && apt_success_verify(f, key_before, root, version, expected_name);
    if (ok) { memcpy(output_version, version, 32); memcpy(output_root, root, 32); }
    return ok;
}
static bool apt_same_roots(struct abc_leaf *l, const uint8_t version[32], const uint8_t root[32])
{
    uint8_t result_version[32], result_root[32];
    return zcl_hex_decode_lower(abc_get(l, "version"), result_version, 32) &&
        zcl_hex_decode_lower(abc_get(l, "source_root"), result_root, 32) &&
        !memcmp(version, result_version, 32) && !memcmp(root, result_root, 32);
}
static bool apt_missing_index(const char *index)
{
    struct stat st;
    return lstat(index, &st) != 0 && errno == ENOENT;
}
static bool apt_no_index_command(struct ac_fixture *f, const uint8_t version[32],
                                 const uint8_t root[32], const char *index)
{
    struct abc_leaf l;
    if (!apt_input(&l, f, version, version)) return false;
    bool ok = abc_pass("app.personalize", &l) && apt_missing_index(index) &&
        json_get_bool(json_get(&l.out.data, "already_personalized")) &&
        !json_get_bool(json_get(&l.out.data, "namespace_pending"));
    ok = ok && abc_confirm("app.personalize", &l) && l.out.status == ZCL_COMMAND_STATUS_PASSED &&
        !json_get_bool(json_get(&l.out.data, "changed")) && !l.out.error.mutated &&
        !json_get_bool(json_get(&l.out.data, "key_created")) && apt_missing_index(index);
    ok = ok && apt_same_roots(&l, version, root);
    abc_close(&l); return ok;
}
static bool apt_idempotent(struct ac_fixture *f)
{
    uint8_t version[32], root[32];
    if (!apt_existing_success(f, version, root) || !act_preserved(f, true)) return false;
    char index[1000], saved[1000];
    int a = snprintf(index, sizeof(index), "%s/.zvcs/index.kv", f->world.copy);
    int b = snprintf(saved, sizeof(saved), "%s/.zvcs/index.test-saved", f->world.copy);
    if (a <= 0 || (size_t)a >= sizeof(index) || b <= 0 || (size_t)b >= sizeof(saved) ||
        rename(index, saved) != 0) return false;
    bool ok = apt_no_index_command(f, version, root, index);
    bool missing = apt_missing_index(index);
    bool restored = rename(saved, index) == 0;
    return ok && missing && restored && act_preserved(f, false);
}

static bool apt_key_replaced(struct ac_fixture *f)
{
    struct abc_leaf l; char key[900];
    if (!apt_external_key(f) || !act_preserved(f, true) ||
        !apt_input(&l, f, f->kept.version, f->head)) return false;
    bool ok = abc_pass("app.personalize", &l) && apt_key_path(f, key) && unlink(key) == 0 &&
        apt_external_key(f) && abc_confirm("app.personalize", &l) &&
        l.out.status != ZCL_COMMAND_STATUS_PASSED && !strcmp(l.out.error.code, "PLAN_MISMATCH") &&
        !l.out.error.mutated;
    abc_close(&l); return ok && act_preserved(f, false);
}
enum apt_kind { APT_PLAN, APT_KEY_CREATED, APT_KEY_REPLACED, APT_HEAD,
                APT_BAD_NAME, APT_DUPLICATE, APT_EXISTING };
static bool apt_one(enum apt_kind kind)
{
    struct ac_fixture f;
    bool ok = act_setup(&f, false);
    if (ok) {
        switch (kind) {
        case APT_PLAN: ok = apt_plan_absent(&f); break;
        case APT_KEY_CREATED: ok = apt_key_race(&f); break;
        case APT_KEY_REPLACED: ok = apt_key_replaced(&f); break;
        case APT_HEAD: ok = apt_head_race(&f); break;
        case APT_BAD_NAME: ok = apt_bad_metadata(&f, "{\"name\":\"stub/bad_name\"}\n"); break;
        case APT_DUPLICATE: ok = apt_bad_metadata(&f, "{\"name\":\"stub/a\",\"name\":\"stub/b\"}\n"); break;
        case APT_EXISTING: ok = apt_idempotent(&f); break;
        }
    }
    act_cleanup(&f); return ok;
}
#if defined(ZCL_TESTING)
static int apbt_cases(void);
#endif
int test_app_personalize(void)
{
    int failures = 0;
    TEST("personalize owner plans, stale identities and metadata-only successor") {
        ASSERT(apt_one(APT_PLAN));
        ASSERT(apt_one(APT_KEY_CREATED));
        ASSERT(apt_one(APT_KEY_REPLACED));
        ASSERT(apt_one(APT_HEAD));
        ASSERT(apt_one(APT_BAD_NAME));
        ASSERT(apt_one(APT_DUPLICATE));
        ASSERT(apt_one(APT_EXISTING));
        PASS();
    } _test_next:;
#if defined(ZCL_TESTING)
    failures += apbt_cases();
#endif
    return failures;
}


#if defined(ZCL_TESTING)
enum ast_change { AST_UNCHANGED, AST_KEEP_CHANGED, AST_KEY_REMOVED, AST_OUTPUT_PARENT_REMOVED };
struct ast_present {
    bool confirm, fail, observed, injected;
    const char *version, *output, *route, *publisher, *package;
    struct ac_fixture *fixture;
    enum ast_change change;
    char key[900], backup[900];
};
static bool ast_field(const struct zcl_present_model_v1 *m, const char *label, const char *expected)
{
    char text[4400] = {0}; size_t used = 0; bool found = false;
    for (uint32_t i = 0; i < m->item_count; ++i) {
        const char *part = m->items[i].value;
        if (!found) { if (strncmp(part, label, strlen(label))) continue; part += strlen(label); found = true; }
        else { if (strncmp(part, "  ", 2)) break; part += 2; }
        size_t n = strlen(part); if (n >= sizeof(text) - used) return false;
        memcpy(text + used, part, n + 1); used += n;
    }
    return found && !strcmp(text, expected);
}
static bool ast_action(const struct zcl_present_window_live_view_v1 *live, uint32_t action, bool *close, bool *redraw)
{
    struct zcl_present_window_event_v1 event = {.outcome = ZCL_PRESENT_WINDOW_ACTION, .action_index = action};
    live->owner.update(live->owner.context, &event, true, redraw, close); return true;
}
static bool ast_inject(struct ast_present *p)
{
    if (p->change == AST_KEEP_CHANGED) {
        struct app_selection saved;
        if (app_selection_save(p->fixture->env.state_dir, p->fixture->kept.revision,
                               &p->fixture->kept, &saved) != APP_SELECTION_OK) return false;
        p->fixture->kept = saved; p->injected = true;
    } else if (p->change == AST_KEY_REMOVED) {
        if (!apt_key_path(p->fixture, p->key)) return false;
        int n = snprintf(p->backup, sizeof(p->backup), "%s.share-test", p->key);
        if (n <= 0 || (size_t)n >= sizeof(p->backup) || rename(p->key, p->backup)) return false;
        p->injected = true;
    } else if (p->change == AST_OUTPUT_PARENT_REMOVED) {
        if (!p->backup[0] || rmdir(p->backup)) return false;
        p->injected = true;
    }
    return true;
}
static bool ast_observe(struct ast_present *p, const struct zcl_present_model_v1 *model,
                         uint32_t *count, char *why, size_t cap)
{
    return !model->exact_root[0] &&
        ast_field(model, "Sharing: ", "Signs this saved version and creates a local share file. Nothing is sent over the network.") &&
        ast_field(model, "Saved version: ", p->version) && ast_field(model, "Output: ", p->output) &&
        (!p->publisher || ast_field(model, "Publisher: ", p->publisher)) &&
        (!p->package || ast_field(model, "Package: ", p->package)) &&
        zcl_present_model_page_count_v1(model, count, why, cap);
}
static bool ast_presenter(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    (void)pages; struct ast_present *p = context; uint32_t count = 0;
    p->observed = ast_observe(p, model, &count, why, cap);
    if (!p->observed || p->fail) return false;
    bool close = false, redraw = false;
    if (!p->confirm) return ast_action(live, 0, &close, &redraw) && close;
    if (count > 1 && (!ast_action(live, 3, &close, &redraw) || close)) return false;
    for (uint32_t i = 1; i < count; ++i)
        if (!ast_action(live, 2, &close, &redraw) || close || !redraw) return false;
    return ast_inject(p) && ast_action(live, 3, &close, &redraw) && close;
}
/* Native kept-name personalization; synthetic presenter tests authority and
 * exact saved-source composition, not a physical dialog or executable image. */
enum apbt_mode { APBT_CANCEL, APBT_HEADLESS, APBT_EARLY, APBT_CANCEL_LATE,
    APBT_PAINT_FAIL, APBT_SELECTION, APBT_HEAD, APBT_KEY, APBT_CONFIRM, APBT_EXISTING };
struct apbt_present {
    struct ac_fixture *f;
    enum apbt_mode mode;
    bool invoked, observed, visited, injected;
    uint8_t key_hash[32];
};
static bool apbt_bool(const struct json_value *d, const char *key, bool expected)
{
    const struct json_value *v = json_get(d, key);
    return v && v->type == JSON_BOOL && json_get_bool(v) == expected;
}
static bool apbt_fields(struct apbt_present *p, const struct zcl_present_model_v1 *m)
{
    char version[65], source[65], head[65], revision[32];
    zcl_hex_encode(p->f->kept.version, 32, version); zcl_hex_encode(p->f->tree, 32, source);
    zcl_hex_encode(p->f->head, 32, head);
    snprintf(revision, sizeof(revision), "%llu", (unsigned long long)p->f->kept.revision);
    return !strcmp(m->title, "Personalize this saved version?") &&
        ast_field(m, "Kept app: ", "skycombat") && ast_field(m, "Kept revision: ", revision) &&
        ast_field(m, "Copy: ", p->f->world.copy) && ast_field(m, "Datadir: ", p->f->world.alice_datadir) &&
        ast_field(m, "Saved version: ", version) && ast_field(m, "Source: ", source) &&
        ast_field(m, "Current HEAD: ", head);
}
static bool apbt_identity(struct apbt_present *p, const struct zcl_present_model_v1 *m)
{
    if (p->mode != APBT_EXISTING)
        return apt_key_absent(p->f) && ast_field(m, "Identity: ",
            "Create a local publishing key after confirmation; personal namespace is pending.");
    struct zcl_command_reply r; zcl_command_reply_init(&r, "zcl.test.personalize-view.v1");
    char path[4400], pub[67], ns[64]; bool exists = false;
    bool ok = app_personalize_key_probe(&r, path, sizeof(path), pub, &exists) && exists &&
        app_personalize_namespace(pub, ns, sizeof(ns)) &&
        ast_field(m, "Publisher: ", pub) && ast_field(m, "Personal namespace: ", ns);
    zcl_command_reply_free(&r); return ok;
}
static bool apbt_inject(struct apbt_present *p)
{
    if (p->mode == APBT_SELECTION) {
        struct app_selection saved;
        if (app_selection_save(p->f->env.state_dir, p->f->kept.revision, &p->f->kept, &saved) != APP_SELECTION_OK) return false;
        p->f->kept = saved;
    } else if (p->mode == APBT_HEAD) {
        if (!act_snapshot(p->f, "save", p->f->head)) return false;
    } else if (p->mode == APBT_KEY) {
        if (!apt_external_key(p->f) || !act_hash(p->f->world.alice_home, ".z23/zcode_publisher.key", p->key_hash)) return false;
    } else return true;
    p->injected = true;
    return act_preserved(p->f, true); /* Preserve the concurrent writer's new state. */
}
static bool apbt_visit(const struct zcl_present_window_live_view_v1 *live, uint32_t count)
{
    bool close = false, redraw = false;
    for (uint32_t i = 1; i < count; ++i)
        if (!ast_action(live, 2, &close, &redraw) || close || !redraw) return false;
    return true;
}
static bool apbt_confirm_after_pages(struct apbt_present *p,
    const struct zcl_present_window_live_view_v1 *live, bool *close, bool *redraw)
{
    p->visited = true;
    if (!apbt_inject(p) || !ast_action(live, 3, close, redraw) || !*close) return false;
    if (p->mode == APBT_PAINT_FAIL) return false;
    if (p->mode == APBT_CANCEL_LATE) return ast_action(live, 0, close, redraw) && *close;
    return true;
}
static bool apbt_presenter(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    (void)pages; struct apbt_present *p = context; uint32_t count = 0;
    p->invoked = true;
    p->observed = apbt_fields(p, model) && apbt_identity(p, model) &&
        zcl_present_model_page_count_v1(model, &count, why, cap) && count > 1;
    if (!p->observed || p->mode == APBT_HEADLESS) return false;
    bool close = false, redraw = false;
    if (p->mode == APBT_CANCEL) return ast_action(live, 0, &close, &redraw) && close;
    if (!ast_action(live, 3, &close, &redraw) || close) return false;
    if (p->mode == APBT_EARLY) return true;
    if (!apbt_visit(live, count)) return false;
    return apbt_confirm_after_pages(p, live, &close, &redraw);
}
static bool apbt_run(struct apbt_present *p, struct json_value *input, struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec = abc_spec("app.personalize");
    if (!spec) return false;
    struct zcl_command_request request = {.spec = spec, .input = input, .invoked_name = "app.personalize"};
    zcl_test_app_personalize_view_run(&request, reply, apbt_presenter, p);
    return true;
}
static bool apbt_reply_paths(struct apbt_present *p, const struct zcl_command_reply *r)
{
    const char *copy = zcl_package_copy_str(&r->data, "copy");
    const char *datadir = zcl_package_copy_str(&r->data, "datadir");
    return copy && datadir && !strcmp(copy, p->f->world.copy) &&
        !strcmp(datadir, p->f->world.alice_datadir);
}
static bool apbt_reply_identity(const struct zcl_command_reply *r, const char *name,
    uint8_t version[32], uint8_t root[32])
{
    const char *v = zcl_package_copy_str(&r->data, "version"), *tree = zcl_package_copy_str(&r->data, "source_root");
    if (!name || !v || !tree || !zcl_hex_decode_lower(v, version, 32) || !zcl_hex_decode_lower(tree, root, 32)) return false;
    return true;
}
static bool apbt_success(struct apbt_present *p, struct zcl_command_reply *r)
{
    uint8_t version[32], root[32], key[32];
    const char *name = zcl_package_copy_str(&r->data, "name");
    if (!apbt_reply_identity(r, name, version, root)) return false;
    bool key_ok = act_hash(p->f->world.alice_home, ".z23/zcode_publisher.key", key);
    if (p->mode == APBT_EXISTING) key_ok = key_ok && !memcmp(key, p->key_hash, 32);
    return apbt_reply_paths(p, r) && key_ok && p->visited && r->status == ZCL_COMMAND_STATUS_PASSED && r->error.mutated &&
        apbt_bool(&r->data, "changed", true) && apbt_bool(&r->data, "key_created", p->mode != APBT_EXISTING) &&
        apt_trees_equal(p->f, root, name) && apt_head_and_keep(p->f, version);
}
static bool apbt_refusal(struct apbt_present *p, struct zcl_command_reply *r)
{
    const char *code = NULL;
    switch (p->mode) {
    case APBT_HEADLESS: case APBT_PAINT_FAIL: code = "CONFIRMATION_UNAVAILABLE"; break;
    case APBT_SELECTION: code = "SELECTION_STALE"; break;
    case APBT_HEAD: code = "HEAD_STALE"; break;
    case APBT_KEY: code = "PLAN_MISMATCH"; break;
    default: break;
    }
    if (code) {
        if (r->status == ZCL_COMMAND_STATUS_PASSED || strcmp(r->error.code, code)) return false;
    } else {
        const char *status = zcl_package_copy_str(&r->data, "status");
        if (r->status != ZCL_COMMAND_STATUS_PASSED || !status || strcmp(status, "canceled")) return false;
    }
    return !r->error.mutated && act_preserved(p->f, false);
}
static bool apbt_key_preserved(struct apbt_present *p)
{
    if (p->mode != APBT_KEY) return apt_key_absent(p->f);
    uint8_t key[32];
    return p->injected && act_hash(p->f->world.alice_home, ".z23/zcode_publisher.key", key) &&
        !memcmp(key, p->key_hash, 32);
}
static bool apbt_one(enum apbt_mode mode)
{
    struct ac_fixture f; bool ok = act_setup(&f, false);
    struct apbt_present p = {.f = &f, .mode = mode};
    struct json_value input; json_init(&input); json_set_object(&input);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_personalize.v1");
    if (ok && mode == APBT_EXISTING) ok = apt_external_key(&f) &&
        act_hash(f.world.alice_home, ".z23/zcode_publisher.key", p.key_hash);
    ok = ok && act_preserved(&f, true) && json_push_kv_str(&input, "name", "skycombat") &&
        json_push_kv_int(&input, "expected_revision", 1) && apbt_run(&p, &input, &reply) && p.observed;
    if (ok && (mode == APBT_CONFIRM || mode == APBT_EXISTING)) ok = apbt_success(&p, &reply);
    else if (ok) ok = apbt_refusal(&p, &reply) && apbt_key_preserved(&p);
    if (!ok) fprintf(stderr, "personalize view mode=%d observed=%d visited=%d error=%s message=%s\n",
        mode, p.observed, p.visited, reply.error.code, reply.error.message);
    zcl_command_reply_free(&reply); json_free(&input); act_cleanup(&f); return ok;
}
static bool apbt_bad_input(unsigned kind, struct json_value *input)
{
    json_set_object(input);
    if (!json_push_kv_str(input, "name", kind == 0 ? "" : "skycombat")) return false;
    switch (kind) {
    case 0: return json_push_kv_int(input, "expected_revision", 1);
    case 1: return json_push_kv_str(input, "expected_revision", "1");
    case 2: return json_push_kv_int(input, "expected_revision", 0);
    case 3: return json_push_kv_int(input, "expected_revision", -1);
    case 4: return json_push_kv_str(input, "name", "skycombat");
    case 5: return json_push_kv_bool(input, "confirm", true);
    case 6: return json_push_kv_str(input, "copy", "/not-an-authorized-copy");
    default: return false;
    }
}
static bool apbt_strict_one(struct ac_fixture *f, unsigned kind)
{
    struct apbt_present p = {.f = f, .mode = APBT_CONFIRM};
    struct json_value input; json_init(&input);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.app_personalize.v1");
    bool ok = apbt_bad_input(kind, &input) && apbt_run(&p, &input, &reply) &&
        !p.invoked && reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, "BAD_INPUT") && !reply.error.mutated &&
        apt_key_absent(f) && act_preserved(f, false);
    zcl_command_reply_free(&reply); json_free(&input); return ok;
}
static bool apbt_strict(void)
{
    struct ac_fixture f; bool ok = act_setup(&f, false);
    ok = ok && act_preserved(&f, true);
    for (unsigned i = 0; ok && i < 7; ++i) ok = apbt_strict_one(&f, i);
    act_cleanup(&f); return ok;
}
static int apbt_cases(void)
{
    int failures = 0;
    TEST("kept personalization native consent preserves saved selection and dirty work") {
        ASSERT(apbt_one(APBT_CANCEL)); ASSERT(apbt_one(APBT_HEADLESS));
        ASSERT(apbt_one(APBT_EARLY)); ASSERT(apbt_one(APBT_CANCEL_LATE));
        ASSERT(apbt_one(APBT_PAINT_FAIL)); ASSERT(apbt_one(APBT_SELECTION));
        ASSERT(apbt_one(APBT_HEAD)); ASSERT(apbt_one(APBT_KEY));
        ASSERT(apbt_strict());
        ASSERT(apbt_one(APBT_CONFIRM)); ASSERT(apbt_one(APBT_EXISTING));
        PASS();
    } _test_next:;
    return failures;
}

/* Real owner preparation followed by source-bound edit. The presenter drives
 * the maintained consent state machine; no rendering/build claim is made. */
struct asb_present { struct ac_fixture *f; bool confirm, called; };
struct asb_source { uint8_t version[32], tree[32]; char version_hex[65]; };
static bool asb_presenter(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    (void)pages; struct asb_present *p = context; uint32_t count = 0;
    p->called = true;
    char kept[65]; zcl_hex_encode(p->f->kept.version, 32, kept);
    if (strcmp(model->title, "Prepare your copy for changes?") ||
        !ast_field(model, "Saved version: ", kept) ||
        !zcl_present_model_page_count_v1(model, &count, why, cap)) return false;
    bool close = false, redraw = false;
    if (!p->confirm) return ast_action(live, 0, &close, &redraw) && close;
    return apbt_visit(live, count) && ast_action(live, 3, &close, &redraw) && close;
}
static bool asb_prepared(struct ac_fixture *f, struct abc_leaf *l, bool expect_view, struct asb_source *source)
{
    snprintf(source->version_hex, sizeof(source->version_hex), "%s", abc_get(l, "version"));
    if (!zcl_hex_decode_lower(source->version_hex, source->version, 32)) return false;
    if (!expect_view) return !l->out.error.mutated;
    return zcl_hex_decode_lower(abc_get(l, "source_root"), source->tree, 32) &&
        apt_trees_equal(f, source->tree, abc_get(l, "name")) && apt_head_and_keep(f, source->version);
}
static bool asb_prepare(struct ac_fixture *f, bool confirm, bool expect_view, struct asb_source *source)
{
    struct abc_leaf l; abc_open(&l);
    const struct zcl_command_spec *spec = abc_spec("app.personalize");
    bool ok = spec && json_push_kv_str(&l.in, "name", "skycombat") &&
        json_push_kv_int(&l.in, "expected_revision", (int64_t)f->kept.revision);
    struct asb_present p = {.f = f, .confirm = confirm};
    l.req.spec = spec; l.req.input = &l.in; l.req.invoked_name = "app.personalize";
    if (ok) zcl_test_app_personalize_prepare(&l.req, &l.out, asb_presenter, &p);
    ok = ok && p.called == expect_view && l.out.status == ZCL_COMMAND_STATUS_PASSED;
    if (ok && !confirm) ok = !strcmp(abc_get(&l, "status"), "canceled") && !l.out.error.mutated;
    if (ok && confirm) ok = asb_prepared(f, &l, expect_view, source);
    abc_close(&l); return ok;
}
static bool asb_read(struct ac_fixture *f, const char *source, const char *error, int revision)
{
    struct abc_leaf l; abc_open(&l); char kept[65]; zcl_hex_encode(f->kept.version, 32, kept);
    bool ok = json_push_kv_str(&l.in, "name", "skycombat") &&
        json_push_kv_int(&l.in, "expected_revision", revision) &&
        json_push_kv_str(&l.in, "source_version", source) &&
        json_push_kv_str(&l.in, "path", "include/boost.h") && act_result(&l, error);
    if (ok && !error) ok = !strcmp(abc_get(&l, "version"), kept) &&
        !strcmp(abc_get(&l, "source_version"), source) &&
        !strcmp(abc_get(&l, "content"), "#define BOOST 2\n");
    if (error) ok = ok && !l.out.error.mutated;
    abc_close(&l); return ok;
}
static bool asb_navigation(struct ac_fixture *f, const struct asb_source *source)
{
    struct abc_leaf l; struct json_value doc; json_init(&doc);
    bool ok = act_call(&l, "zcode-package.json", true) &&
        json_push_kv_str(&l.in, "source_version", source->version_hex) &&
        json_push_kv_int(&l.in, "limit", 16) && act_wire(&l.in, &doc);
    const struct json_value *next = act_wire_next(&doc, "offset");
    ok = ok && next && acs_string(next, "source_version", source->version_hex);
    json_free(&doc); abc_close(&l);
    return ok && act_preserved(f, false);
}
static bool asb_edit_request(struct abc_leaf *l, struct ac_fixture *f,
    const char *source, const char *plan)
{
    char head[65], blob[65]; zcl_hex_encode(f->head, 32, head); zcl_hex_encode(f->blob, 32, blob);
    return ae_request(l, f, "include/boost.h", "#define BOOST 9\n", head, blob, 1, plan) &&
        json_push_kv_str(&l->in, "source_version", source);
}
static bool asb_plan(struct ac_fixture *f, const struct asb_source *source, char plan[65])
{
    struct abc_leaf l; char kept[65]; zcl_hex_encode(f->kept.version, 32, kept);
    bool ok = asb_edit_request(&l, f, source->version_hex, NULL) && abc_pass("app.edit", &l) &&
        !strcmp(abc_get(&l, "kept_version"), kept) && !strcmp(abc_get(&l, "source_version"), source->version_hex);
    snprintf(plan, 65, "%s", abc_get(&l, "plan_id"));
    ok = ok && strlen(plan) == 64;
    abc_close(&l); return ok && act_preserved(f, false);
}
static bool asb_reject_edit(struct ac_fixture *f, const char *source, const char *plan, const char *error)
{
    struct abc_leaf l;
    bool ok = asb_edit_request(&l, f, source, plan) && abc_exec("app.edit", &l) &&
        l.out.status != ZCL_COMMAND_STATUS_PASSED && !strcmp(l.out.error.code, error) && !l.out.error.mutated;
    abc_close(&l); return ok && act_preserved(f, false);
}
static bool asb_same_tree_successor(struct ac_fixture *f, const struct asb_source *source, uint8_t version[32])
{
    struct vcs_repo *repo = vcs_open(f->world.copy);
    if (!repo) return false;
    const struct vcs_snapshot_meta meta = {.phase = "save", .task_ref = "same tree source identity control"};
    const struct vcs_snapshot_tree_limits limits = {8u * 1024u * 1024u, 16384u,
        VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES, VCS_PACKAGE_STORE_MAX_PACKAGE_BYTES};
    bool ok = vcs_snapshot_from_tree(repo, source->tree, source->version, &meta, &limits, version) == VCS_OK;
    vcs_close(repo); return ok && memcmp(version, source->version, 32);
}
static bool asb_metadata_preserved(struct ac_fixture *f, const uint8_t prepared[32], const uint8_t edited[32])
{
    struct vcs_manifest a = {0}, b = {0};
    bool ok = vcs_tree_load_readonly_bounded(f->world.copy, prepared, 8u * 1024u * 1024u, 16384u, &a) &&
        vcs_tree_load_readonly_bounded(f->world.copy, edited, 8u * 1024u * 1024u, 16384u, &b) && a.count == b.count;
    size_t changed = 0;
    for (size_t i = 0; ok && i < a.count; ++i) {
        ok = !strcmp(a.entries[i].path, b.entries[i].path) && a.entries[i].mode == b.entries[i].mode;
        if (!strcmp(a.entries[i].path, "include/boost.h")) {
            ++changed; ok = ok && memcmp(a.entries[i].blob, b.entries[i].blob, 32);
        } else ok = ok && a.entries[i].size == b.entries[i].size && !memcmp(a.entries[i].blob, b.entries[i].blob, 32);
    }
    vcs_manifest_free(&a); vcs_manifest_free(&b);
    return ok && changed == 1 && ae_contents(f, edited);
}
static bool asb_commit(struct ac_fixture *f, const struct asb_source *source, const char *plan)
{
    struct abc_leaf l; uint8_t version[32], tree[32];
    bool ok = asb_edit_request(&l, f, source->version_hex, plan) && abc_pass("app.edit", &l) &&
        zcl_hex_decode_lower(abc_get(&l, "version"), version, 32) &&
        zcl_hex_decode_lower(abc_get(&l, "source_root"), tree, 32) &&
        !strcmp(abc_get(&l, "source_version"), source->version_hex);
    abc_close(&l);
    return ok && apt_head_and_keep(f, version) && asb_metadata_preserved(f, source->tree, tree);
}
static bool asb_plan_controls(struct ac_fixture *f, const struct asb_source *source)
{
    char plan[65], newer_hex[65]; uint8_t newer[32];
    if (!asb_plan(f, source, plan) || !asb_same_tree_successor(f, source, newer) ||
        !act_preserved(f, true) || !asb_reject_edit(f, source->version_hex, plan, "HEAD_STALE")) return false;
    memcpy(f->head, newer, 32); zcl_hex_encode(newer, 32, newer_hex);
    return asb_plan(f, source, plan) &&
        asb_reject_edit(f, newer_hex, plan, "PLAN_MISMATCH") && asb_commit(f, source, plan);
}
static bool asb_foreign(struct ac_fixture *f, const struct asb_source *source)
{
    uint8_t foreign[32];
    return act_snapshot(f, "foreign", foreign) && act_preserved(f, true) &&
        asb_read(f, source->version_hex, "NOT_ADOPTED", 1) && act_preserved(f, false);
}
static bool asb_cancel_then_prepare(struct ac_fixture *f, struct asb_source *source)
{
    return act_preserved(f, true) && apt_key_absent(f) && asb_prepare(f, false, true, NULL) &&
        apt_key_absent(f) && act_preserved(f, false) && asb_prepare(f, true, true, source);
}
static bool asb_bridge(struct ac_fixture *f)
{
    struct asb_source source = {0};
    if (!asb_cancel_then_prepare(f, &source)) return false;
    memcpy(f->head, source.version, 32);
    if (!act_preserved(f, true) || !asb_read(f, source.version_hex, NULL, 1) || !asb_navigation(f, &source)) return false;
    char unknown[65]; memset(unknown, 'a', 64); unknown[64] = 0;
    return asb_read(f, source.version_hex, "SELECTION_STALE", 2) &&
        asb_read(f, unknown, "VERSION_UNKNOWN", 1) &&
        asb_reject_edit(f, unknown, NULL, "VERSION_UNKNOWN") &&
        asb_plan_controls(f, &source) && asb_foreign(f, &source);
}
static bool asb_already_owned(struct ac_fixture *f)
{
    struct asb_source source = {0}, repeated = {0};
    if (!act_preserved(f, true) || !asb_prepare(f, true, true, &source)) return false;
    struct app_selection next = f->kept;
    memcpy(next.version, source.version, 32);
    if (app_selection_save(f->env.state_dir, 1, &next, &f->kept) != APP_SELECTION_OK ||
        !act_preserved(f, true)) return false;
    uint8_t key_before[32], key_after[32];
    return act_hash(f->world.alice_home, ".z23/zcode_publisher.key", key_before) &&
        asb_prepare(f, true, false, &repeated) && !memcmp(source.version, repeated.version, 32) &&
        act_hash(f->world.alice_home, ".z23/zcode_publisher.key", key_after) &&
        !memcmp(key_before, key_after, 32) && act_preserved(f, false);
}
static int asb_bridge_case(void)
{
    int failures = 0; struct ac_fixture f = {0};
    TEST("prepared P source edits preserve Keep N and bind exact source independently of tree and head") {
        ASSERT(act_setup(&f, false)); ASSERT(asb_bridge(&f)); PASS();
    } _test_next:;
    act_cleanup(&f); return failures;
}
static bool asb_draft_blob(struct ac_fixture *f, const struct asb_source *source,
    const char *expected, char blob[65])
{
    struct vcs_manifest manifest = {0};
    if (!vcs_tree_load_readonly_bounded(f->world.copy, source->tree,
        8u * 1024u * 1024u, 16384u, &manifest)) return false;
    bool ok = false;
    for (size_t i = 0; i < manifest.count; ++i) {
        const struct vcs_entry *entry = &manifest.entries[i];
        if (strcmp(entry->path, "include/boost.h")) continue;
        uint8_t *bytes = NULL; size_t size = 0;
        ok = vcs_object_get_readonly_bounded(f->world.copy, entry->blob, VCS_TAG_BLOB,
            1024, &bytes, &size) == 0 && size == strlen(expected) &&
            !memcmp(bytes, expected, size) && entry->size == size;
        if (ok) zcl_hex_encode(entry->blob, 32, blob);
        free(bytes); break;
    }
    vcs_manifest_free(&manifest); return ok;
}
static bool asb_draft_reply(struct ac_fixture *f, struct abc_leaf *l,
    const struct asb_source *source, struct asb_source *next)
{
    char kept[65]; zcl_hex_encode(f->kept.version, 32, kept);
    snprintf(next->version_hex, sizeof(next->version_hex), "%s", abc_get(l, "version"));
    return !strcmp(abc_get(l, "source_version"), source->version_hex) &&
        !strcmp(abc_get(l, "kept_version"), kept) &&
        zcl_hex_decode_lower(next->version_hex, next->version, 32) &&
        zcl_hex_decode_lower(abc_get(l, "source_root"), next->tree, 32) &&
        memcmp(next->version, source->version, 32) && apt_head_and_keep(f, next->version);
}
static bool asb_draft_step(struct ac_fixture *f, const struct asb_source *source,
    const char *before, const char *after, struct asb_source *next)
{
    char blob[65], head[65], plan[65]; struct abc_leaf l;
    if (!asb_draft_blob(f, source, before, blob) || !act_preserved(f, true)) return false;
    zcl_hex_encode(f->head, 32, head);
    bool ok = ae_request(&l, f, "include/boost.h", after, head, blob, 1, NULL) &&
        json_push_kv_str(&l.in, "source_version", source->version_hex) && abc_pass("app.edit", &l);
    snprintf(plan, sizeof(plan), "%s", abc_get(&l, "plan_id"));
    abc_close(&l);
    if (!ok || strlen(plan) != 64 || !act_preserved(f, false)) return false;
    ok = ae_request(&l, f, "include/boost.h", after, head, blob, 1, plan) &&
        json_push_kv_str(&l.in, "source_version", source->version_hex) && abc_pass("app.edit", &l) &&
        asb_draft_reply(f, &l, source, next);
    abc_close(&l); return ok;
}
static bool asb_draft_other_files(struct ac_fixture *f,
    const struct asb_source *prepared, const struct asb_source *last)
{
    struct vcs_manifest a = {0}, b = {0}; bool metadata = false;
    bool ok = vcs_tree_load_readonly_bounded(f->world.copy, prepared->tree, 8u * 1024u * 1024u, 16384u, &a) &&
        vcs_tree_load_readonly_bounded(f->world.copy, last->tree, 8u * 1024u * 1024u, 16384u, &b) && a.count == b.count;
    for (size_t i = 0; ok && i < a.count; ++i) {
        const struct vcs_entry *x = &a.entries[i], *y = &b.entries[i];
        ok = !strcmp(x->path, y->path) && x->mode == y->mode;
        if (!strcmp(x->path, "include/boost.h")) continue;
        ok = ok && x->size == y->size && !memcmp(x->blob, y->blob, 32);
        if (!strcmp(x->path, "zcode-package.json")) metadata = true;
    }
    vcs_manifest_free(&a); vcs_manifest_free(&b); return ok && metadata;
}
static bool asb_chained_drafts(struct ac_fixture *f)
{
    struct asb_source prepared = {0}, first = {0}, second = {0}; char blob[65];
    if (!act_preserved(f, true) || !asb_prepare(f, true, true, &prepared)) return false;
    memcpy(f->head, prepared.version, 32);
    if (!asb_draft_step(f, &prepared, "#define BOOST 2\n", "#define BOOST 9\n", &first)) return false;
    memcpy(f->head, first.version, 32);
    const char *both = "#define BOOST 9\n#define SECOND_EDIT 1\n";
    return asb_draft_step(f, &first, "#define BOOST 9\n", both, &second) &&
        asb_draft_blob(f, &second, both, blob) && asb_draft_other_files(f, &prepared, &second);
}
static int asb_chain_case(void)
{
    int failures = 0; struct ac_fixture f = {0};
    TEST("prepared P to E1 to E2 uses returned source and preserves first edit, namespace and Keep N") {
        ASSERT(act_setup(&f, false)); ASSERT(asb_chained_drafts(&f)); PASS();
    } _test_next:;
    act_cleanup(&f); return failures;
}
static int asb_cases(void)
{
    int failures = asb_bridge_case() + asb_chain_case(); struct ac_fixture f = {0};
    TEST("already personal kept source preparation is read-only and never invokes presenter") {
        ASSERT(act_setup(&f, false)); ASSERT(asb_already_owned(&f)); PASS();
    } _test_next:;
    act_cleanup(&f); return failures;
}

static bool ast_selection_plan(struct ac_fixture *f, const char *version, char *publisher, const char *output, struct abc_leaf *leaf)
{
    struct abc_leaf l; bool ok;
    char path[4400]; bool exists = false; struct zcl_command_reply probe;
    zcl_command_reply_init(&probe, "zcl.test.share.v1");
    ok = app_personalize_key_probe(&probe, path, sizeof(path), publisher, &exists) && exists;
    zcl_command_reply_free(&probe);
    abc_open(&l);
    ok = ok && json_push_kv_str(&l.in, "dir", f->world.copy) && json_push_kv_str(&l.in, "datadir", f->world.alice_datadir) &&
        json_push_kv_str(&l.in, "version", version) && json_push_kv_str(&l.in, "publisher_pubkey", publisher) &&
        json_push_kv_str(&l.in, "output", output) && abc_pass("zcode.package.share", &l);
    *leaf = l; return ok;
}
static bool ast_prepare_selection(struct ac_fixture *f, char version[65], char publisher[67], const char *output)
{
    struct abc_leaf l;
    if (!apt_input(&l, f, f->kept.version, f->head)) return false;
    bool ok = abc_plan_confirm("app.personalize", &l);
    snprintf(version, 65, "%s", abc_get(&l, "version")); abc_close(&l);
    if (!ok || strlen(version) != 64) return false;
    ok = ast_selection_plan(f, version, publisher, output, &l);
    uint8_t selected[32], package[32];
    ok = ok && zcl_hex_decode_lower(version, selected, 32) && zcl_hex_decode_lower(abc_get(&l, "package_root"), package, 32);
    abc_close(&l);
    if (!ok) return false;
    struct app_selection next = f->kept, saved;
    memcpy(next.version, selected, 32); memcpy(next.package, package, 32);
    ok = app_selection_save(f->env.state_dir, 1, &next, &saved) == APP_SELECTION_OK;
    if (ok) f->kept = saved;
    return ok && abc_put(f->world.copy, "include/boost.h", "#define BOOST 3\n") &&
        act_snapshot(f, "save", f->head) && abc_put(f->world.copy, "include/boost.h", "#define BOOST 4\n");
}
static bool ast_run(struct ast_present *present, struct zcl_command_reply *reply)
{
    struct json_value input; json_init(&input); json_set_object(&input);
    bool ok = json_push_kv_str(&input, "name", present->route ? present->route : "skycombat") &&
        json_push_kv_str(&input, "output", present->output);
    const struct zcl_command_spec *spec = abc_spec("app.share");
    struct zcl_command_request req = {.spec = spec, .input = &input, .invoked_name = "app.share"};
    if (ok && spec) zcl_test_app_share_run(&req, reply, ast_presenter, present);
    else ok = false;
    json_free(&input); return ok;
}
static bool ast_reply_is(const struct zcl_command_reply *reply, const char *key, const char *expected)
{
    const char *actual = json_get_str(json_get(&reply->data, key));
    return actual && !strcmp(actual, expected);
}
static bool ast_cancel_no_index(struct ac_fixture *f, struct ast_present *present)
{
    char index[1000], saved[1000];
    int a = snprintf(index, sizeof(index), "%s/.zvcs/index.kv", f->world.copy);
    int b = snprintf(saved, sizeof(saved), "%s/.zvcs/index.share-test", f->world.copy);
    if (a <= 0 || (size_t)a >= sizeof(index) || b <= 0 || (size_t)b >= sizeof(saved) || rename(index, saved)) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    bool ok = ast_run(present, &reply) && present->observed && reply.status == ZCL_COMMAND_STATUS_PASSED &&
        ast_reply_is(&reply, "status", "canceled") && !reply.error.mutated;
    struct stat st;
    ok = ok && lstat(index, &st) != 0 && errno == ENOENT;
    zcl_command_reply_free(&reply);
    bool restored = rename(saved, index) == 0;
    return ok && restored && act_preserved(f, false);
}
static bool ast_alias_paths(struct ac_fixture *f, char canonical[1000], char alias[1000], const char *suffix)
{
    char hex[65]; zcl_hex_encode(f->blob, 32, hex);
    int a = snprintf(canonical, 1000, "%s/.zvcs/objects/%c%c/%s", f->world.copy, hex[0], hex[1], hex + 2);
    int b = snprintf(alias, 1000, "%s/.zvcs/objects/tmp/%s", f->world.copy, suffix);
    return a > 0 && a < 1000 && b > 0 && b < 1000;
}
static bool ast_alias_refusal(struct ac_fixture *f, struct ast_present *present)
{
    char canonical[1000], alias[1000];
    if (!ast_alias_paths(f, canonical, alias, ".put.share-test") || link(canonical, alias)) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    present->observed = false;
    bool ok = ast_run(present, &reply) && !present->observed && reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !reply.error.mutated;
    struct stat before, after;
    ok = ok && stat(canonical, &before) == 0 && stat(alias, &after) == 0 && before.st_nlink == 2 &&
        before.st_ino == after.st_ino && before.st_dev == after.st_dev;
    zcl_command_reply_free(&reply);
    bool removed = unlink(alias) == 0;
    return ok && removed && act_preserved(f, false);
}
static bool ast_reserved_distinct(struct ac_fixture *f, const char *version, const char *output)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    struct ast_present p = {.version = version, .output = output, .route = "kept:skycombat"};
    bool ok = ast_run(&p, &reply) && !p.observed && reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, "SELECTION_UNAVAILABLE") && !reply.error.mutated;
    zcl_command_reply_free(&reply); return ok && act_preserved(f, false);
}
static bool ast_failed_display(struct ac_fixture *f, struct ast_present *present)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    present->fail = true; present->observed = false;
    bool ok = ast_run(present, &reply) && present->observed &&
        reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, "CONFIRMATION_UNAVAILABLE") && !reply.error.mutated;
    present->fail = false;
    zcl_command_reply_free(&reply);
    return ok && act_preserved(f, false);
}
static bool ast_missing_canonical(struct ac_fixture *f, struct ast_present *present)
{
    char hex[65], canonical[1000], alias[1000]; zcl_hex_encode(f->blob, 32, hex);
    int a = snprintf(canonical, sizeof(canonical), "%s/.zvcs/objects/%c%c/%s", f->world.copy, hex[0], hex[1], hex + 2);
    int b = snprintf(alias, sizeof(alias), "%s/.zvcs/objects/tmp/.put.share-missing", f->world.copy);
    if (a <= 0 || (size_t)a >= sizeof(canonical) || b <= 0 || (size_t)b >= sizeof(alias) || rename(canonical, alias)) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    present->observed = false;
    bool ok = ast_run(present, &reply) && !present->observed && reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !reply.error.mutated;
    struct stat st;
    ok = ok && lstat(canonical, &st) != 0 && errno == ENOENT && lstat(alias, &st) == 0;
    zcl_command_reply_free(&reply);
    bool restored = rename(alias, canonical) == 0;
    return ok && restored && act_preserved(f, false);
}
static bool ast_expected_key_command(struct abc_leaf *l, struct ac_fixture *f, const char *version, const char *output, const char *publisher)
{
    bool ok = json_push_kv_str(&l->in, "dir", f->world.copy) && json_push_kv_str(&l->in, "datadir", f->world.alice_datadir) &&
        json_push_kv_str(&l->in, "version", version) && json_push_kv_str(&l->in, "output", output) &&
        json_push_kv_str(&l->in, "expected_publisher_pubkey", publisher) &&
        json_push_kv_str(&l->in, "plan_id", "0000000000000000000000000000000000000000000000000000000000000000") &&
        json_push_kv_bool(&l->in, "confirm", true) && abc_exec("zcode.package.bundle.sign", l) &&
        l->out.status != ZCL_COMMAND_STATUS_PASSED && !strcmp(l->out.error.code, "PUBLISHER_KEY_CHANGED") && !l->out.error.mutated;
    return ok;
}
static bool ast_expected_key_refused(struct ac_fixture *f, const char *version,
    const char *output, const char *publisher)
{
    char index[1000], saved[1000];
    int a = snprintf(index, sizeof(index), "%s/.zvcs/index.kv", f->world.copy);
    int b = snprintf(saved, sizeof(saved), "%s/.zvcs/index.share-key-test", f->world.copy);
    if (a <= 0 || (size_t)a >= sizeof(index) || b <= 0 || (size_t)b >= sizeof(saved) || rename(index, saved)) return false;
    struct abc_leaf l; abc_open(&l);
    bool ok = ast_expected_key_command(&l, f, version, output, publisher);
    struct stat st; ok = ok && lstat(index, &st) != 0 && errno == ENOENT;
    abc_close(&l);
    bool restored = rename(saved, index) == 0;
    return ok && restored;
}
static bool ast_receive_plan(struct abc_leaf *l, struct ac_fixture *f, const char *output)
{
    bool ok = abc_as(f->world.bob_home) && json_push_kv_str(&l->in, "file", output) &&
        json_push_kv_str(&l->in, "datadir", f->world.bob_datadir) &&
        json_push_kv_str(&l->in, "destination", f->world.bob_copy) && abc_pass("zcode.package.bundle.receive", l);
    return ok;
}
static bool ast_receive_command(struct abc_leaf *l, struct ac_fixture *f, const char *output, const char *publisher, const char *package)
{
    bool ok = ast_receive_plan(l, f, output);
    char plan[65]; snprintf(plan, sizeof(plan), "%s", abc_get(l, "plan_id"));
    ok = ok && strlen(plan) == 64 && !strcmp(abc_get(l, "package_root"), package) &&
        !strcmp(abc_get(l, "publisher_fingerprint"), publisher);
    zcl_command_reply_free(&l->out); zcl_command_reply_init(&l->out, "zcl.test.share.v1");
    ok = ok && json_push_kv_str(&l->in, "plan_id", plan) && json_push_kv_bool(&l->in, "confirm", true) &&
        json_push_kv_str(&l->in, "trust_root", package) && json_push_kv_str(&l->in, "trust_publisher", publisher) &&
        abc_pass("zcode.package.bundle.receive", l);
    return ok;
}
static bool ast_receive(struct ac_fixture *f, const char *output, const char *publisher, const char *package)
{
    struct abc_leaf l; abc_open(&l);
    bool ok = ast_receive_command(&l, f, output, publisher, package);
    abc_close(&l);
    char path[1000], *text = NULL; size_t size = 0;
    (void)snprintf(path, sizeof(path), "%s/include/boost.h", f->world.bob_copy);
    ok = ok && zcl_read_whole_file_text(path, 512, &text, &size, "shared saved source") &&
        size == strlen("#define BOOST 2\n") && !memcmp(text, "#define BOOST 2\n", size);
    free(text);
    return abc_as(f->world.alice_home) && ok;
}
static bool ast_missing_key(struct ac_fixture *f, const char *version, const char *output, const char *publisher)
{
    char key[900], backup[900];
    if (!apt_key_path(f, key)) return false;
    int n = snprintf(backup, sizeof(backup), "%s.missing-test", key);
    if (n <= 0 || (size_t)n >= sizeof(backup) || rename(key, backup)) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    struct ast_present p = {.version = version, .output = output};
    bool ok = ast_run(&p, &reply) && !p.observed && reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, "SIGNING_KEY_REQUIRED") && !reply.error.mutated;
    zcl_command_reply_free(&reply);
    ok = ok && ast_expected_key_refused(f, version, output, publisher);
    bool restored = rename(backup, key) == 0;
    return ok && restored;
}
static bool ast_existing_output(struct ac_fixture *f, const char *version, const char *existing)
{
    uint8_t before[32], after[32];
    if (!act_hash(f->world.root, "share.z23share", before)) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    struct ast_present p = {.version = version, .output = existing};
    bool ok = ast_run(&p, &reply) && !p.observed && reply.status != ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(reply.error.code, "OUTPUT_EXISTS") && !reply.error.mutated;
    zcl_command_reply_free(&reply);
    ok = ok && act_hash(f->world.root, "share.z23share", after) && !memcmp(before, after, 32);
    return ok;
}
static bool ast_key_race(struct ac_fixture *f, const char *version, const char *missing)
{
    bool ok = true; struct zcl_command_reply reply; struct ast_present p;
    p = (struct ast_present){.version = version, .output = missing, .fixture = f, .confirm = true, .change = AST_KEY_REMOVED};
    zcl_command_reply_init(&reply, "zcl.test.share.v1");
    ok = ok && ast_run(&p, &reply) && p.observed && p.injected &&
        reply.status != ZCL_COMMAND_STATUS_PASSED && !strcmp(reply.error.code, "PUBLISHER_CHANGED") && !reply.error.mutated;
    zcl_command_reply_free(&reply);
    if (p.injected && rename(p.backup, p.key)) ok = false;
    return ok;
}
static bool ast_dialog_races(struct ac_fixture *f, const char *version, const char *missing)
{
    bool ok = ast_key_race(f, version, missing);
    struct zcl_command_reply reply; struct ast_present p;
    p = (struct ast_present){.version = version, .output = missing, .fixture = f, .confirm = true, .change = AST_KEEP_CHANGED};
    zcl_command_reply_init(&reply, "zcl.test.share.v1");
    ok = ok && ast_run(&p, &reply) && p.observed && p.injected &&
        reply.status != ZCL_COMMAND_STATUS_PASSED && !strcmp(reply.error.code, "SELECTION_STALE") && !reply.error.mutated;
    zcl_command_reply_free(&reply);
    return ok;
}
static bool ast_refusals(struct ac_fixture *f, const char *version, const char *existing, const char *publisher)
{
    bool ok = ast_existing_output(f, version, existing);
    char missing[900]; snprintf(missing, sizeof(missing), "%s/missing.z23share", f->world.root);
    ok = ok && ast_missing_key(f, version, missing, publisher);
    ok = ok && ast_dialog_races(f, version, missing);
    return ok && access(missing, F_OK) != 0 && errno == ENOENT;
}
static bool ast_confirm_share(struct ast_present *p, const char *version, const char *output, const char *publisher)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    p->confirm = true; p->observed = false;
    bool ok = ast_run(p, &reply) && p->observed && reply.status == ZCL_COMMAND_STATUS_PASSED && reply.error.mutated &&
        ast_reply_is(&reply, "version", version) && ast_reply_is(&reply, "share_file", output) &&
        ast_reply_is(&reply, "publisher_fingerprint", publisher);
    zcl_command_reply_free(&reply);
    return ok;
}
static bool ast_verify_bundle(struct ac_fixture *f, const char *output, const char *publisher, char package[65])
{
    struct abc_leaf verify; abc_open(&verify);
    zcl_hex_encode(f->kept.package, 32, package);
    bool ok = json_push_kv_str(&verify.in, "file", output) && abc_pass("zcode.package.bundle.verify", &verify) &&
        !strcmp(abc_get(&verify, "publisher_fingerprint"), publisher) && !strcmp(abc_get(&verify, "package_root"), package);
    abc_close(&verify);
    return ok;
}
static bool ast_preconsent(struct ac_fixture *f, struct ast_present *p, const char *version, const char *output)
{
    bool ok = ast_reserved_distinct(f, version, output) && ast_failed_display(f, p) && ast_alias_refusal(f, p) &&
        ast_missing_canonical(f, p) && ast_cancel_no_index(f, p) &&
        access(output, F_OK) != 0 && errno == ENOENT;
    return ok;
}
static bool ast_journey(struct ac_fixture *f)
{
    char output[900], version[65], publisher[67], key[900];
    snprintf(output, sizeof(output), "%s/share.z23share", f->world.root);
    if (!ast_prepare_selection(f, version, publisher, output) || !act_preserved(f, true) || !apt_key_path(f, key)) return false;
    uint8_t key_hash[32], after[32];
    if (!act_hash(f->world.alice_home, ".z23/zcode_publisher.key", key_hash)) return false;
    char expected_package[65]; zcl_hex_encode(f->kept.package, 32, expected_package);
    struct ast_present p = {.version = version, .output = output,
                            .publisher = publisher, .package = expected_package};
    bool ok = ast_preconsent(f, &p, version, output);
    ok = ok && ast_confirm_share(&p, version, output, publisher);
    ok = ok && act_preserved(f, false) && act_hash(f->world.alice_home, ".z23/zcode_publisher.key", after) &&
        !memcmp(key_hash, after, 32);
    char package[65];
    ok = ok && ast_verify_bundle(f, output, publisher, package);
    return ok && ast_receive(f, output, publisher, package) && ast_refusals(f, version, output, publisher);
}
static bool ast_snapshot_commit_after_change(struct ac_fixture *f, const char *output,
    const char *version, const char *publisher, char package[65])
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    struct zcl_app_share_session *s = zcl_app_share_prepare("skycombat", output, &f->kept, &reply);
    if (!s) { zcl_command_reply_free(&reply); return false; }
    struct app_selection updated;
    if (app_selection_save(f->env.state_dir, f->kept.revision, &f->kept, &updated) != APP_SELECTION_OK) {
        zcl_app_share_dispose(s); zcl_command_reply_free(&reply); return false;
    }
    zcl_app_share_commit(s, &reply); zcl_app_share_dispose(s);
    bool ok = reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated &&
        !strcmp(reply.error.code, "SELECTION_STALE") && access(output, F_OK) != 0;
    f->kept = updated;
    zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.test.share.v1");
    s = zcl_app_share_prepare("skycombat", output, &f->kept, &reply);
    if (!s) { zcl_command_reply_free(&reply); return false; }
    zcl_app_share_commit(s, &reply); zcl_app_share_dispose(s);
    ok = ok && reply.status == ZCL_COMMAND_STATUS_PASSED && reply.error.mutated &&
        ast_reply_is(&reply, "version", version) && ast_verify_bundle(f, output, publisher, package);
    zcl_command_reply_free(&reply); return ok;
}
static bool ast_snapshot_session(struct ac_fixture *f)
{
    char output[900], version[65], publisher[67], package[65];
    snprintf(output, sizeof(output), "%s/snapshot-session.z23share", f->world.root);
    if (!ast_prepare_selection(f, version, publisher, output) || !act_preserved(f, true)) return false;
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    struct app_selection wrong = f->kept; wrong.version[0] ^= 1;
    struct zcl_app_share_session *s = zcl_app_share_prepare("skycombat", output, &wrong, &reply);
    bool ok = !s && !reply.error.mutated && !strcmp(reply.error.code, "SELECTION_STALE");
    zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.test.share.v1");
    s = zcl_app_share_prepare("skycombat", output, &f->kept, &reply);
    if (!s) { zcl_command_reply_free(&reply); return false; }
    struct zcl_app_share_identity id; zcl_app_share_identity(s, &id);
    zcl_hex_encode(f->kept.package, 32, package);
    ok = ok && !strcmp(id.version, version) && !strcmp(id.package, package) && !strcmp(id.publisher, publisher);
    zcl_app_share_dispose(s);
    ok = ok && access(output, F_OK) != 0 && errno == ENOENT && act_preserved(f, false);
    zcl_command_reply_free(&reply);
    return ok && ast_snapshot_commit_after_change(f, output, version, publisher, package);
}
struct ast_publish_view { struct ac_fixture *f; bool confirm, stale, observed; const char *version; };
static int ast_publish_offers, ast_publish_posts;
static bool ast_publish_fail_offer, ast_publish_fail_post, ast_publish_identity_ok;
static char ast_publish_package[65], ast_publish_publisher[67], ast_publish_name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
static bool ast_publish_transport(const char *path, const struct json_value *input, struct zcl_command_reply *out)
{
    (void)input; zcl_command_reply_init(out, "zcl.test.publish.v1");
    if (!strcmp(path, "core.network.onion.status")) {
        const char *wire = "{\"bootstrap_state\":\"ready\",\"tor_ready\":true,\"onion_service_ready\":true,\"p2p_publish_ready\":true,\"onion_address\":\"abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion\",\"port_mapping\":{\"routes\":[{\"name\":\"p2p_tcp\",\"installed\":true,\"virtual_port\":28133}]}}";
        return json_read(&out->data, wire, strlen(wire));
    }
    if (!strcmp(path, ZCL_APP_OFFER_BUNDLE_OFFER)) {
        ast_publish_offers++;
        if (ast_publish_fail_offer) {
            zcl_command_reply_fail(out, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "OFFER_FAILED", "execute", false, true, "fixture offer failure", path);
            return false;
        }
        return json_push_kv_str(&out->data, "root", "1111111111111111111111111111111111111111111111111111111111111111") &&
            json_push_kv_str(&out->data, "sha256", "2222222222222222222222222222222222222222222222222222222222222222") &&
            json_push_kv_int(&out->data, "size", 123);
    }
    if (!strcmp(path, ZCL_APP_OFFER_BOARD_POST)) {
        ast_publish_posts++;
        const char *text = json_get_str(json_get(input, "text")); struct zcl_app_offer offer;
        ast_publish_identity_ok = text && zcl_app_offer_parse(text, strlen(text), &offer) &&
            !strcmp(offer.root, ast_publish_package) && !strcmp(offer.publisher, ast_publish_publisher);
        if (ast_publish_identity_ok) (void)snprintf(ast_publish_name, sizeof(ast_publish_name), "%s", offer.name);
        if (ast_publish_fail_post) {
            zcl_command_reply_fail(out, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "POST_UNKNOWN", "execute", true, true, "fixture response lost", path);
            return false;
        }
        return json_push_kv_str(&out->data, "id", "3333333333333333333333333333333333333333333333333333333333333333");
    }
    return false;
}
static bool ast_publish_present(void *context, const struct zcl_present_model_v1 *model,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    (void)pages; struct ast_publish_view *p = context; uint32_t count = 0;
    p->observed = ast_field(model, "Saved version: ", p->version) &&
        ast_field(model, "Public: ", "Sign and pin this saved version; post an offer to the public apps board for 24 hours.") &&
        zcl_present_model_page_count_v1(model, &count, why, cap);
    if (!p->observed) return false;
    bool close = false, redraw = false;
    if (!p->confirm) return ast_action(live, 0, &close, &redraw) && close;
    for (uint32_t i = 1; i < count; ++i)
        if (!ast_action(live, 2, &close, &redraw) || close || !redraw) return false;
    if (p->stale) {
        struct app_selection saved;
        if (app_selection_save(p->f->env.state_dir, p->f->kept.revision, &p->f->kept, &saved) != APP_SELECTION_OK) return false;
        p->f->kept = saved;
    }
    return ast_action(live, 3, &close, &redraw) && close;
}
static bool ast_fact_is(const struct json_value *facts, const char *key, const char *expected)
{
    const char *v = zcl_package_copy_str(facts, key);
    return v && !strcmp(v, expected);
}
static bool ast_publish_failures(struct ac_fixture *f, struct ast_publish_view *view,
    const char *version, const char *publisher)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.publish.v1");
    ast_publish_fail_offer = true;
    zcl_native_app_publish_snapshot("kept:skycombat", &f->kept, &reply, ast_publish_present, view);
    const struct json_value *facts = json_get(&reply.data, "failure_facts");
    bool ok = reply.status != ZCL_COMMAND_STATUS_PASSED && reply.error.mutated &&
        !strcmp(reply.error.code, "OFFER_FAILED") && ast_publish_posts == 1 && facts &&
        ast_fact_is(facts, "version", version) && ast_fact_is(facts, "package_root", ast_publish_package) &&
        ast_fact_is(facts, "publisher_fingerprint", publisher) && ast_fact_is(facts, "board_status", "not_attempted");
    zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.test.publish.v1");
    ast_publish_fail_offer = false; ast_publish_fail_post = true;
    zcl_native_app_publish_snapshot("kept:skycombat", &f->kept, &reply, ast_publish_present, view);
    facts = json_get(&reply.data, "failure_facts");
    ok = ok && reply.status != ZCL_COMMAND_STATUS_PASSED && reply.error.mutated && facts &&
        !strcmp(reply.error.code, "POST_UNKNOWN") && ast_fact_is(facts, "board_status", "unknown") &&
        ast_fact_is(facts, "version", version);
    zcl_command_reply_free(&reply); return ok;
}
static bool ast_publish_preconsent(struct ac_fixture *f, struct ast_publish_view *view)
{
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.publish.v1");
    zcl_native_app_publish_snapshot("kept:skycombat", &f->kept, &reply, ast_publish_present, view);
    bool ok = view->observed && reply.status == ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated &&
        ast_reply_is(&reply, "status", "canceled") && !ast_publish_offers && !ast_publish_posts;
    zcl_command_reply_free(&reply); zcl_command_reply_init(&reply, "zcl.test.publish.v1");
    view->confirm = true; view->stale = true;
    zcl_native_app_publish_snapshot("kept:skycombat", &f->kept, &reply, ast_publish_present, view);
    ok = ok && reply.status != ZCL_COMMAND_STATUS_PASSED && !reply.error.mutated &&
        !strcmp(reply.error.code, "SELECTION_STALE") && !ast_publish_offers && !ast_publish_posts;
    zcl_command_reply_free(&reply); view->stale = false; return ok;
}
struct ast_publish_library_view { struct ast_publish_view publish; unsigned menus, notices; };
static bool ast_publish_library_present(void *context, const struct zcl_present_model_v1 *m,
    const char *copy, struct zcl_present_window_event_v1 *event, char *why, size_t cap)
{
    (void)context; (void)copy;
    if (!zcl_present_model_validate_v1(m, why, cap)) return false;
    const char *wanted = "choose";
    if (!strcmp(m->request_id, "library-home")) wanted = "myapps";
    else if (!strcmp(m->request_id, "library-share-options")) wanted = "publish";
    else {
        for (uint32_t i = 0; i < m->action_count; ++i)
            if (!strcmp(m->actions[i].id, "share")) wanted = "share";
        unsigned index = 0, count = 0;
        if (!strcmp(wanted, "choose") && sscanf(m->summary, "App %u of %u", &index, &count) == 2 && index < count)
            wanted = "next";
    }
    event->struct_size = sizeof(*event); event->abi_version = ZCL_PRESENT_ABI_V1;
    event->outcome = ZCL_PRESENT_WINDOW_ACTION;
    for (uint32_t i = 0; i < m->action_count; ++i)
        if (!strcmp(m->actions[i].id, wanted)) { event->action_index = i; return true; }
    return false;
}
static bool ast_publish_library_notice(void *context, const struct zcl_present_model_v1 *m,
    const struct zcl_present_window_pages_v1 *pages, const struct zcl_present_window_live_view_v1 *live,
    char *why, size_t cap)
{
    struct ast_publish_library_view *v = context;
    if (!strcmp(m->request_id, "library-publish-result")) {
        bool close = false, redraw = false; v->notices++;
        char expected[512];
        int n = snprintf(expected, sizeof(expected), "z23 app get %s --root=%s --publisher=%s --offer=%s",
            ast_publish_name, ast_publish_package, ast_publish_publisher,
            "3333333333333333333333333333333333333333333333333333333333333333");
        return n > 0 && (size_t)n < sizeof(expected) && pages && pages->page_count == 1 &&
            pages->pages && pages->pages[0].copy_text && !strcmp(pages->pages[0].copy_text, expected) &&
            !strcmp(m->summary, "Posted on this node for up to 24 hours. Other people can discover it after their nodes receive the offer. Press C to copy a command for the recipient.") &&
            ast_action(live, 0, &close, &redraw) && close;
    }
    v->publish.confirm = v->menus++ != 0;
    return ast_publish_present(&v->publish, m, pages, live, why, cap);
}
static bool ast_publish_library(struct ac_fixture *f, const char *version)
{
    struct ast_publish_library_view view = {.publish = {.f = f, .version = version}};
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.library.v1");
    int posts = ast_publish_posts;
    zcl_test_app_library_native_at(&f->env, "/fixture/z23", f->world.alice_datadir,
        &reply, ast_publish_library_present, &view, ast_publish_library_notice);
    bool ok = reply.status == ZCL_COMMAND_STATUS_PASSED && view.menus == 2 && view.notices == 1 &&
        ast_publish_posts == posts + 1 && ast_publish_identity_ok && json_get(&reply.data, "post_id") &&
        !json_get(&reply.data, "status");
    zcl_command_reply_free(&reply); return ok;
}
static bool ast_publish_snapshot(struct ac_fixture *f)
{
    char output[900], version[65], publisher[67];
    snprintf(output, sizeof(output), "%s/unused.z23share", f->world.root);
    if (!ast_prepare_selection(f, version, publisher, output) || !act_preserved(f, true)) return false;
    struct app_selection route = f->kept, saved;
    snprintf(route.app, sizeof(route.app), "kept:skycombat");
    if (app_selection_save(f->env.state_dir, 0, &route, &saved) != APP_SELECTION_OK) return false;
    f->kept = saved;
    zcl_app_offer_set_call(ast_publish_transport); ast_publish_offers = ast_publish_posts = 0;
    zcl_hex_encode(f->kept.package, 32, ast_publish_package);
    snprintf(ast_publish_publisher, sizeof(ast_publish_publisher), "%s", publisher);
    ast_publish_fail_offer = ast_publish_fail_post = ast_publish_identity_ok = false;
    struct ast_publish_view view = {.f = f, .version = version};
    bool ok = ast_publish_preconsent(f, &view);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.publish.v1");
    zcl_native_app_publish_snapshot("kept:skycombat", &f->kept, &reply, ast_publish_present, &view);
    ok = ok && reply.status == ZCL_COMMAND_STATUS_PASSED && ast_publish_offers == 1 && ast_publish_posts == 1 && ast_publish_identity_ok &&
        ast_reply_is(&reply, "publisher_fingerprint", publisher);
    zcl_command_reply_free(&reply);
    ok = ok && ast_publish_library(f, version);
    /* The direct failure probes start after the separate UI publication. */
    ast_publish_posts = 1;
    ok = ok && ast_publish_failures(f, &view, version, publisher);
    zcl_app_offer_set_call(NULL); return ok;
}
static bool ast_publication_recorded(struct ac_fixture *f, const struct zcl_command_reply *reply)
{
    const char *id = json_get_str(json_get(&reply->data, "release_id"));
    uint8_t root[32], actual[32]; struct vcs_package_release release;
    return id && strlen(id) == 64 && zcl_hex_decode_lower(id, root, 32) &&
        zcl_package_copy_find_release(f->world.alice_datadir, root, &release, actual) == ZCL_PACKAGE_COPY_FOUND &&
        !memcmp(root, actual, 32);
}
static bool ast_partial_wire(struct ac_fixture *f, struct zcl_command_reply *reply,
                             const char *version, const char *output)
{
    const struct zcl_command_spec *spec = abc_spec("app.share");
    char wire[ZCL_COMMAND_ERROR_BUDGET + 1], package[65]; size_t bytes = 0;
    zcl_hex_encode(f->kept.package, 32, package);
    if (!spec) return false;
    bytes = zcl_command_registry_test_reply_wire(zcl_command_catalog(), spec, reply, wire, sizeof(wire));
    if (!bytes || bytes >= sizeof(wire)) {
        printf("  [share failure serialization returned %zu bytes]\n", bytes); return false;
    }
    struct json_value doc; json_init(&doc);
    bool ok = json_read(&doc, wire, bytes);
    const struct json_value *facts = json_get(json_get(&doc, "error"), "facts");
    const char *release = zcl_package_copy_str(&reply->data, "release_id");
    const char *got_release = zcl_package_copy_str(facts, "release_id");
    const char *got_package = zcl_package_copy_str(facts, "package_root");
    const char *got_version = zcl_package_copy_str(facts, "version");
    const char *got_output = zcl_package_copy_str(facts, "output");
    ok = ok && release && got_release && got_package && got_version && got_output &&
        !strcmp(release, got_release) && !strcmp(package, got_package) &&
        !strcmp(version, got_version) && !strcmp(output, got_output);
    json_free(&doc); return ok;
}
static bool ast_partial_setup(struct ac_fixture *f, char dir[900], char output[900], char version[65], char publisher[67])
{
    int n = snprintf(dir, 900, "%s/share-output", f->world.root);
    if (n <= 0 || (size_t)n >= 900 || mkdir(dir, 0700)) return false;
    n = snprintf(output, 900, "%s/share.z23share", dir);
    if (n <= 0 || (size_t)n >= 900 || !ast_prepare_selection(f, version, publisher, output) ||
        !act_preserved(f, true)) return false;
    return true;
}
static bool ast_partial_failure(struct ac_fixture *f)
{
    char output[900], version[65], publisher[67], dir[900];
    if (!ast_partial_setup(f, dir, output, version, publisher)) return false;
    struct ast_present p = {.version = version, .output = output, .fixture = f,
        .confirm = true, .change = AST_OUTPUT_PARENT_REMOVED};
    (void)snprintf(p.backup, sizeof(p.backup), "%s", dir);
    struct zcl_command_reply reply; zcl_command_reply_init(&reply, "zcl.test.share.v1");
    bool ok = ast_run(&p, &reply) && p.observed && p.injected &&
        reply.status != ZCL_COMMAND_STATUS_PASSED && !strcmp(reply.error.code, "SHARE_FILE_WRITE") &&
        reply.error.mutated && ast_publication_recorded(f, &reply) &&
        ast_partial_wire(f, &reply, version, output);
    zcl_command_reply_free(&reply);
    return ok && access(output, F_OK) != 0 && errno == ENOENT && act_preserved(f, false);
}
static int ast_partial_case(void)
{
    int failures = 0; struct ac_fixture f;
    TEST("native share reports release persisted when output creation fails") {
        ASSERT(act_setup(&f, false)); ASSERT(ast_partial_failure(&f)); PASS();
    } _test_next:;
    act_cleanup(&f); return failures;
}
static bool ast_kept_route(struct ac_fixture *f)
{
    char output[900], version[65], publisher[67], package[65];
    int n = snprintf(output, sizeof(output), "%s/kept-share.z23share", f->world.root);
    if (n <= 0 || (size_t)n >= sizeof(output) ||
        !ast_prepare_selection(f, version, publisher, output) || !act_preserved(f, true)) return false;
    struct app_selection selected = f->kept, saved;
    snprintf(selected.app, sizeof(selected.app), "kept:skycombat");
    if (app_selection_save(f->env.state_dir, 0, &selected, &saved) != APP_SELECTION_OK ||
        saved.revision != 1) return false;
    struct ast_present p = {.version = version, .output = output, .route = "kept:skycombat"};
    return ast_confirm_share(&p, version, output, publisher) && act_preserved(f, false) &&
        ast_verify_bundle(f, output, publisher, package) && ast_receive(f, output, publisher, package);
}
static int ast_kept_case(void)
{
    int failures = 0; struct ac_fixture f;
    TEST("native share sends the exact kept route to an independent recipient") {
        ASSERT(act_setup(&f, false)); ASSERT(ast_kept_route(&f)); PASS();
    } _test_next:;
    act_cleanup(&f); return failures;
}
static int ast_snapshot_case(void)
{
    int failures = 0; struct ac_fixture f;
    TEST("snapshot session signs the saved version despite a changed working copy") {
        ASSERT(act_setup(&f, false)); ASSERT(ast_snapshot_session(&f)); PASS();
    } _test_next:;
    act_cleanup(&f); return failures;
}
static int ast_publish_case(void)
{
    int failures = 0; struct ac_fixture f;
    TEST("snapshot publish confirms exact saved version and refuses stale selection") {
        ASSERT(act_setup(&f, false)); ASSERT(ast_publish_snapshot(&f)); PASS();
    } _test_next:;
    zcl_app_offer_set_call(NULL); act_cleanup(&f); return failures;
}
int test_app_share(void)
{
    int failures = 0; struct ac_fixture f;
    TEST("native share confirms the exact Keep and cancel does not mutate it") {
        ASSERT(act_setup(&f, false)); ASSERT(ast_journey(&f)); PASS();
    } _test_next:;
    act_cleanup(&f); failures += ast_snapshot_case(); failures += ast_publish_case(); failures += ast_partial_case(); failures += ast_kept_case(); return failures;
}
#else
int test_app_share(void) { return 0; }
#endif

#else
int test_app_customize(void) { return 0; }
int test_app_edit(void) { return 0; }
int test_app_personalize(void) { return 0; }
int test_app_share(void) { return 0; }
#endif
