/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the `z23 app` front door, end to end on local fixtures with a
 * STUB app package (one C file plus a Makefile meeting the app_build_make
 * contract) and two HOMEs and datadirs, A and B. No display is needed: the
 * stub prints one line and waits for a signal.
 *   A: copy (a release is pre-seeded in A's datadir), edit, save, build,
 *      open the copy (the stub child, spawned through resident_launch),
 *      then share, which writes NAME.z23share with a short fingerprint.
 *   B: open FILE.z23share with the confirm injected: verify, receive with
 *      trust taken from the file, build the SAME image_sha3 as A, open.
 * Refusals:
 *   - MCP refuses app.copy, app.share and app.receive (owner authority) and
 *     runs app.save and app.run.copy plan-first;
 *   - an absent or failing app.seed refuses and writes nothing;
 *   - a tampered share file writes nothing; the public app.open never
 *     receives a share file;
 *   - open of an unbuilt, unsaved or stale copy, or with another image
 *     hash, is refused;
 *   - with no terminal and no --yes the front door plans and mutates nothing
 *     (HOME and datadir snapshots are byte-for-byte unchanged).
 * The journey's command and hex-paste counts are printed at the end. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "test/test_core.h"
#include "test/app_seed_fixture.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "command/cli_confirm.h"
#include "command/app_copy_build.h"
#include "command/app_selection.h"
#include "command/native_app_launch.h"
#include "command/native_app_front_door.h"
#include "command/native_command.h"
#include "command/native_zcode_package_bundle.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "mcp/mcp_policy.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "vcs/package_prepare.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/vcs.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "core/uint256.h"
#include "sha3/sha3.h"

#if defined(_WIN32)
int test_app_front_door(void);
int test_app_front_door(void)
{
    printf("app front door... SKIP (the copy open spawns through "
           "resident_launch, which refuses on Windows)\n");
    return 0;
}
#else

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "base/log_level.h"

#define AFD_PATH 900
#define AFD_SNAP (64u * 1024u)

struct afd_world {
    char root[512];
    char src[600];
    char a_home[600], a_datadir[600];
    char b_home[600], b_datadir[600];
    char a_copy[AFD_PATH];
    char share[AFD_PATH];
    char image_a[65];
    char hint[1024];        /* the no-TTY plan's pasted next: command */
    char b_root[65];        /* A's package_root, from bundle.verify */
    char b_fp[67]; /* A's full fingerprint, same */
    char told_root[65];     /* the version root share told A to pass on */
    char told_fp[96];       /* the full fingerprint share told A, same */
    char saved_home[1024];
    char saved_cwd[1024];
    int commands_a, commands_b, hex_a, hex_b;
};

struct afd_leaf {
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply out;
};

static void afd_open_leaf(struct afd_leaf *l)
{
    memset(l, 0, sizeof(*l));
    json_init(&l->in);
    json_set_object(&l->in);
    zcl_command_reply_init(&l->out, "zcl.test.app_front_door.v1");
}

static void afd_close_leaf(struct afd_leaf *l)
{
    zcl_command_reply_free(&l->out);
    json_free(&l->in);
}

static const struct zcl_command_spec *afd_spec(const char *path)
{
    return zcl_command_registry_find(zcl_command_catalog(), path, NULL);
}

/* The registry contract, then the handler, as the CLI runs a leaf. */
static bool afd_exec(const char *path, struct afd_leaf *l)
{
    char why[256] = "no such leaf";
    const struct zcl_command_spec *spec = afd_spec(path);
    if (!spec || !spec->handler ||
        !zcl_command_registry_input_validate(spec, &l->in, why, sizeof(why))) {
        printf("  [%s not runnable: %s]\n", path, why);
        return false;
    }
    l->req.spec = spec;
    l->req.input = &l->in;
    l->req.invoked_name = spec->path;
    spec->handler(&l->req, &l->out);
    return true;
}

static const char *afd_get(const struct afd_leaf *l, const char *key)
{
    const char *s = json_get_str(json_get(&l->out.data, key));
    return s ? s : "";
}

static bool afd_refused(const struct afd_leaf *l, const char *code)
{
    if (l->out.status != ZCL_COMMAND_STATUS_PASSED &&
        strcmp(l->out.error.code, code) == 0)
        return true;
    printf("  [expected %s; status=%d code=%s: %s]\n", code,
           (int)l->out.status, l->out.error.code, l->out.error.message);
    return false;
}

static bool afd_put(const char *dir, const char *rel, const char *text)
{
    char path[AFD_PATH];
    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) >= (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "wb");
    bool ok = f && fputs(text, f) >= 0;
    return f ? fclose(f) == 0 && ok : false;
}

/* ── the stub app ───────────────────────────────────────────────────── */

static const char k_makefile[] =
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
    "  \"source_dir\": \"src\",\n"
    "  \"dependencies\": []\n}\n";

/* The package shape needs an include directory; the one C file is main.c. */
static const char k_header[] = "#define TINY_NAME \"tinyapp\"\n";

/* Prints one line, then waits for a signal: a pid that stays put. */
static const char k_main_v1[] =
    "#include <stdio.h>\n#include <unistd.h>\n#include \"tiny.h\"\n"
    "int main(void) { puts(TINY_NAME \" ready boost=1\"); fflush(stdout);\n"
    "    pause(); return 0; }\n";

static const char k_main_v2[] =
    "#include <stdio.h>\n#include <unistd.h>\n#include \"tiny.h\"\n"
    "int main(void) { puts(TINY_NAME \" ready boost=2\"); fflush(stdout);\n"
    "    pause(); return 0; }\n";

static bool afd_license(const char *dir)
{
    char text[4096];
    FILE *f = fopen("apps/skycombat/LICENSE", "rb");
    if (!f)
        return false;
    size_t n = fread(text, 1, sizeof(text) - 1u, f);
    (void)fclose(f);
    text[n] = '\0';
    return n > 0 && afd_put(dir, "LICENSE", text);
}

static bool afd_stub_source(struct afd_world *w)
{
    char dir[AFD_PATH];
    bool ok = mkdir(w->src, 0700) == 0 && afd_license(w->src);
    (void)snprintf(dir, sizeof(dir), "%s/src", w->src);
    ok = ok && mkdir(dir, 0700) == 0;
    (void)snprintf(dir, sizeof(dir), "%s/include", w->src);
    return ok && mkdir(dir, 0700) == 0 &&
           afd_put(w->src, "include/tiny.h", k_header) &&
           afd_put(w->src, "zcode-package.json", k_meta) &&
           afd_put(w->src, "Makefile", k_makefile) &&
           afd_put(w->src, "src/main.c", k_main_v1);
}

/* The pre-seeded release in A's datadir, signed by an origin key. */
static bool afd_seed_a(struct afd_world *w)
{
    char key[700], pubhex[PLUGIN_HEX_PUBLIC_KEY + 1], detail[256] = {0};
    struct plugin_dist_published why;
    struct vcs_package_prepare_options o = {
        .dir = w->src, .publisher_sequence = 1, .reward_address = "",
        .chain_id = "zclassic-main",
    };
    struct vcs_package_prepared p;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    (void)snprintf(key, sizeof(key), "%s/origin.key", w->root);
    if (plugin_keygen(key, pubhex) != PLUGIN_OK ||
        plugin_dist_release_key_sign(key, NULL, o.publisher_pubkey, NULL,
                                     &why) != PLUGIN_DIST_OK ||
        vcs_package_prepare(&o, &p, detail, sizeof(detail)) !=
            VCS_PACKAGE_PREPARE_OK) {
        printf("  [stub seed setup: %s]\n", detail);
        return false;
    }
    bool ok = plugin_dist_release_key_sign(key, p.signing_digest,
                                           o.publisher_pubkey,
                                           p.release.signature,
                                           &why) == PLUGIN_DIST_OK &&
              vcs_package_release_serialize(&p.release, &wire, &wire_len) ==
                  VCS_PACKAGE_RELEASE_OK;
    struct zcl_command_reply r;
    zcl_command_reply_init(&r, "zcl.test.app_front_door.v1");
    const struct zcl_native_local_publication pub = {
        .datadir = w->a_datadir, .source_directory = w->src,
        .release_wire = wire, .release_wire_len = wire_len,
        .manifest_wire = p.manifest_wire,
        .manifest_wire_len = p.manifest_wire_len,
        .recipe_wire = p.recipe_wire, .recipe_wire_len = p.recipe_wire_len,
    };
    if (ok)
        zcl_native_zcode_local_publication_commit(&pub, &r);
    ok = ok && r.status == ZCL_COMMAND_STATUS_PASSED;
    if (!ok)
        printf("  [stub seed: %s %s]\n", r.error.code, r.error.message);
    zcl_command_reply_free(&r);
    free(wire);
    vcs_package_prepared_free(&p);
    return ok;
}

static bool afd_world_init(struct afd_world *w)
{
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    if (!getcwd(w->saved_cwd, sizeof(w->saved_cwd)) ||
        !test_mkdtemp(w->root, sizeof(w->root), "app_front_door"))
        return false;
    (void)snprintf(w->src, sizeof(w->src), "%s/stub-src", w->root);
    (void)snprintf(w->a_home, sizeof(w->a_home), "%s/a", w->root);
    (void)snprintf(w->a_datadir, sizeof(w->a_datadir), "%s/a/datadir",
                   w->root);
    (void)snprintf(w->b_home, sizeof(w->b_home), "%s/b", w->root);
    (void)snprintf(w->b_datadir, sizeof(w->b_datadir), "%s/b/datadir",
                   w->root);
    (void)snprintf(w->a_copy, sizeof(w->a_copy), "%s/copies/tinyapp-1",
                   w->a_datadir);
    (void)snprintf(w->share, sizeof(w->share), "%s/tinyapp-1.z23share",
                   w->a_home);
    return afd_stub_source(w) && mkdir(w->a_home, 0700) == 0 &&
           mkdir(w->a_datadir, 0700) == 0 && mkdir(w->b_home, 0700) == 0 &&
           mkdir(w->b_datadir, 0700) == 0 && afd_seed_a(w);
}

/* ── snapshots: nothing mutated means byte-for-byte the same listing ── */

static void afd_snap_dir(const char *dir, char *buf, size_t cap, size_t *at)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    if (!d)
        return;
    while ((e = readdir(d)) != NULL) {
        char path[AFD_PATH];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0 ||
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >=
                (int)sizeof(path) ||
            lstat(path, &st) != 0)
            continue;
        int n = snprintf(buf + *at, cap - *at, "%s %lld %lld %o\n", path,
                         (long long)st.st_size, (long long)st.st_mtime,
                         (unsigned)st.st_mode);
        if (n > 0 && (size_t)n < cap - *at)
            *at += (size_t)n;
        if (S_ISDIR(st.st_mode))
            afd_snap_dir(path, buf, cap, at);
    }
    (void)closedir(d);
}

static char *afd_snapshot(const char *home)
{
    char *buf = calloc(1, AFD_SNAP);
    size_t at = 0;
    if (buf)
        afd_snap_dir(home, buf, AFD_SNAP, &at);
    return buf;
}

static bool afd_same(const char *before, const char *home)
{
    char *after = afd_snapshot(home);
    bool same = before && after && strcmp(before, after) == 0;
    if (!same)
        printf("  [the tree under %s changed]\n", home);
    free(after);
    return same;
}

/* ── the front door ─────────────────────────────────────────────────── */

/* The person runs each verb from their HOME. */
static void afd_door(const char *home, const char *datadir, const char *verb,
                     const char *target, enum zcl_cli_confirm_mode mode,
                     struct asf_door *run)
{
    asf_door_run(home, home, datadir, verb, target, mode, run);
}

/* The command a "next:" line pastes, up to the end of its line. */
static bool afd_hint_of(const char *text, char *out, size_t cap)
{
    const char *at = strstr(text, "next: z23 ");
    size_t n;
    if (!at)
        return false;
    at += strlen("next: ");
    n = strcspn(at, "\n");
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, at, n);
    out[n] = '\0';
    return true;
}

/* The hint as a person pastes it: split on spaces into
 * z23 -datadir=DIR app VERB TARGET [--yes], then run in `home`. The datadir
 * comes from the pasted words, never from the world. */
static bool afd_run_hint(const char *hint, const char *home,
                         struct asf_door *run)
{
    char buf[1024], *word[8];
    size_t n = 0;
    char *save = NULL;
    (void)snprintf(buf, sizeof(buf), "%s", hint);
    for (char *w = strtok_r(buf, " ", &save); w && n < 8;
         w = strtok_r(NULL, " ", &save))
        word[n++] = w;
    if (n != 6 || strcmp(word[0], "z23") != 0 ||
        strncmp(word[1], "-datadir=", 9) != 0 ||
        strcmp(word[2], "app") != 0 || strcmp(word[5], "--yes") != 0)
        return false;
    afd_door(home, word[1] + 9, word[3], word[4], ZCL_CLI_CONFIRM_YES, run);
    return run->rc == 0;
}

/* The "  next: ..." line of a finished verb, equal to `want`. */
static bool afd_next_is(const struct asf_door *run, const char *want)
{
    char line[1024];
    (void)asf_door_line(run, "next", line, sizeof(line));
    if (strcmp(line, want) == 0)
        return true;
    printf("  [next was \"%s\", wanted \"%s\"]\n", line, want);
    return false;
}

/* app.run.copy plan on a copy: the build record's image_sha3. */
static bool afd_open_plan(const char *datadir, const char *copy,
                          struct afd_leaf *l)
{
    afd_open_leaf(l);
    (void)json_push_kv_str(&l->in, "copy", copy);
    (void)json_push_kv_str(&l->in, "datadir", datadir);
    return afd_exec("app.run.copy", l);
}

/* ── cases ──────────────────────────────────────────────────────────── */

static bool afd_mcp_plan_first(const char *path)
{
    const struct zcl_command_spec *spec = afd_spec(path);
    struct mcp_refusal why = {0};
    struct json_value in;
    if (!spec || spec->authority == ZCL_COMMAND_AUTH_OWNER ||
        spec->confirmation != ZCL_COMMAND_CONFIRM_PLAN_COMMIT)
        return false;
    json_init(&in);
    json_set_object(&in);
    (void)json_push_kv_str(&in, "copy", "tinyapp-1");
    bool plan = mcp_policy_allows(spec, zcl_command_catalog(), &in, &why);
    (void)json_push_kv_bool(&in, "confirm", true);
    bool bare = !mcp_policy_allows(spec, zcl_command_catalog(), &in, &why);
    json_free(&in);
    return plan && bare;
}

static int afd_mcp_authority(void)
{
    int failures = 0;
    TEST("app front door: MCP refuses copy, share and receive as owner "
         "authority; save and open-copy run plan-first") {
        ASSERT(asf_mcp_refuses_owner("app.copy", "app", "tinyapp"));
        ASSERT(asf_mcp_refuses_owner("app.share", "copy", "tinyapp-1"));
        ASSERT(asf_mcp_refuses_owner("app.receive", "file", "x.z23share"));
        ASSERT(asf_mcp_refuses_owner("app.share-copy", "copy", "tinyapp-1"));
        ASSERT(asf_mcp_refuses_owner("app.receive-copy", "file", "x.z23share"));
        ASSERT(afd_mcp_plan_first("app.save"));
        ASSERT(afd_mcp_plan_first("app.run.copy"));
        PASS();
    } _test_next:;
    return failures;
}

static int afd_seed_absent(const struct afd_world *w)
{
    int failures = 0;
    TEST("app.copy: with no release and no working seed it refuses and "
         "writes nothing") {
        struct afd_leaf l;
        char *before = afd_snapshot(w->b_home);
        ASSERT(before != NULL);
        ASSERT(setenv("HOME", w->b_home, 1) == 0);
        afd_open_leaf(&l);
        (void)json_push_kv_str(&l.in, "app", "tinyapp");
        (void)json_push_kv_str(&l.in, "datadir", w->b_datadir);
        ASSERT(afd_exec("app.copy", &l));
        ASSERT(l.out.status != ZCL_COMMAND_STATUS_PASSED);
        if (!afd_spec("app.seed"))
            ASSERT(afd_refused(&l, "SEED_UNAVAILABLE"));
        ASSERT(strstr(l.out.error.next_action, "z23share") != NULL ||
               strstr(l.out.error.message, "seed") != NULL);
        afd_close_leaf(&l);
        ASSERT(afd_same(before, w->b_home));
        free(before);
        PASS();
    } _test_next:;
    return failures;
}

static int afd_plan_only(struct afd_world *w)
{
    int failures = 0;
    TEST("app front door: no terminal and no --yes plans and mutates "
         "nothing") {
        struct asf_door run;
        char *before = afd_snapshot(w->a_home);
        ASSERT(before != NULL);
        afd_door(w->a_home, w->a_datadir, "copy", "tinyapp",
                 ZCL_CLI_CONFIRM_PLAN_ONLY, &run);
        ASSERT_EQ(run.rc, 0);
        ASSERT(strstr(run.text, "tinyapp-1") != NULL);
        ASSERT(strstr(run.text, "--yes") != NULL);
        ASSERT(afd_same(before, w->a_home));
        free(before);
        /* The hint names the datadir, so it works pasted from any shell. */
        char want[AFD_PATH + 64];
        ASSERT(afd_hint_of(run.text, w->hint, sizeof(w->hint)));
        (void)snprintf(want, sizeof(want),
                       "z23 -datadir=%s app copy tinyapp --yes",
                       w->a_datadir);
        ASSERT_STR_EQ(w->hint, want);
        PASS();
    } _test_next:;
    return failures;
}

static int afd_a_copies_and_saves(struct afd_world *w)
{
    int failures = 0;
    TEST("A: copy adopts the pre-seeded release, open refuses NOT_BUILT, "
         "edit and save") {
        struct asf_door run;
        struct afd_leaf l;
        struct stat st;
        struct json_value data;
        char want[AFD_PATH + 128];
        /* the pasted hint from the plan-only run, verbatim */
        ASSERT(afd_run_hint(w->hint, w->a_home, &run));
        w->commands_a++;
        ASSERT(stat(w->a_copy, &st) == 0 && S_ISDIR(st.st_mode));
        (void)snprintf(want, sizeof(want),
                       "edit the files in %s, then: z23 -datadir=%s app "
                       "save tinyapp-1", w->a_copy, w->a_datadir);
        ASSERT(afd_next_is(&run, want));
        json_init(&data);
        json_set_object(&data);
        zcl_app_list_copies(w->a_datadir, &data);
        const struct json_value *rows = json_get(&data, "copies");
        ASSERT(rows && json_size(rows) == 1);
        ASSERT(strcmp(json_get_str(json_get(json_at(rows, 0), "name")),
                      "tinyapp-1") == 0);
        ASSERT(strcmp(json_get_str(json_get(json_at(rows, 0), "status")),
                      "adopted") == 0);
        json_free(&data);

        ASSERT(afd_open_plan(w->a_datadir, "tinyapp-1", &l));
        ASSERT(afd_refused(&l, "NOT_BUILT"));
        afd_close_leaf(&l);

        ASSERT(afd_put(w->a_copy, "src/main.c", k_main_v2));
        afd_door(w->a_home, w->a_datadir, "save", "tinyapp-1",
                 ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        w->commands_a++;
        PASS();
    } _test_next:;
    return failures;
}

static bool afd_route_try(const char *leaf, const char *name, const char *datadir)
{
    const struct zcl_command_spec *spec = afd_spec(leaf);
    const char *words[] = {name}; int rc = -1;
    return spec && zcl_app_front_door_try(spec, words, 1, 0, datadir, &rc);
}
static bool afd_route_selection(const struct afd_world *w, const char *state)
{
    struct app_selection selection = {0}, saved;
    (void)snprintf(selection.app, sizeof(selection.app), "skycombat");
    char *copy = realpath(w->a_copy, NULL), *datadir = realpath(w->a_datadir, NULL);
    bool paths = copy && datadir && strlen(copy) < sizeof(selection.copy) &&
                 strlen(datadir) < sizeof(selection.datadir);
    if (paths) { (void)snprintf(selection.copy, sizeof(selection.copy), "%s", copy);
                 (void)snprintf(selection.datadir, sizeof(selection.datadir), "%s", datadir); }
    free(copy); free(datadir);
    if (!paths) return false;
    uint8_t *roots[] = {selection.fork, selection.parent, selection.version, selection.package,
                        selection.env, selection.dependencies, selection.record, selection.image};
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); ++i) roots[i][0] = 1;
    return app_selection_save(state, 0, &selection, &saved) == APP_SELECTION_OK;
}
static bool afd_route_env_restore(const char *key, const char *value)
{
    return value ? setenv(key, value, 1) == 0 : unsetenv(key) == 0;
}
static bool afd_route_env_capture(const char *key, char **saved)
{
    const char *value = getenv(key);
    *saved = value ? strdup(value) : NULL;
    return !value || *saved != NULL;
}
static int afd_kept_routing(const struct afd_world *w)
{
    int failures = 0;
    char *home = NULL, *state_old = NULL, *config_old = NULL;
    bool captured = afd_route_env_capture("HOME", &home) &&
        afd_route_env_capture("XDG_STATE_HOME", &state_old) &&
        afd_route_env_capture("XDG_CONFIG_HOME", &config_old);
    if (!captured) { free(home); free(state_old); free(config_old); return 1; }
    TEST("app.open preserves kept selection priority over the CLI copy shortcut") {
        char base[AFD_PATH], z23[AFD_PATH], state[AFD_PATH], path[AFD_PATH + 32];
        (void)snprintf(base, sizeof(base), "%s/route-state", w->root);
        (void)snprintf(z23, sizeof(z23), "%s/route-state/z23", w->root);
        (void)snprintf(state, sizeof(state), "%s/route-state/z23/apps", w->root);
        ASSERT(mkdir(base, 0700) == 0 && mkdir(z23, 0700) == 0 && mkdir(state, 0700) == 0);
        ASSERT(setenv("HOME", w->a_home, 1) == 0 && setenv("XDG_STATE_HOME", base, 1) == 0 &&
               setenv("XDG_CONFIG_HOME", base, 1) == 0);
        (void)snprintf(path, sizeof(path), "%s/copies/skycombat", w->a_datadir);
        ASSERT(mkdir(path, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/copies/sky", w->a_datadir);
        ASSERT(mkdir(path, 0700) == 0);
        ASSERT(afd_route_try("app.open", "skycombat", w->a_datadir));
        ASSERT(afd_route_try("app.open", "sky", w->a_datadir));
        ASSERT(!afd_route_try("app.open", "kept:skycombat", w->a_datadir));
        PASS();
    } TEST("app.open uses the saved catalog choice and aliases") {
        char state[AFD_PATH];
        (void)snprintf(state, sizeof(state), "%s/route-state/z23/apps", w->root);
        ASSERT(afd_route_selection(w, state));
        ASSERT(!afd_route_try("app.open", "skycombat", w->a_datadir));
        ASSERT(!afd_route_try("app.open", "sky", w->a_datadir));
        ASSERT(afd_route_try("app.run.copy", "skycombat", w->a_datadir));
        ASSERT(afd_put(state, "skycombat.selection", "bad"));
        ASSERT(!afd_route_try("app.open", "skycombat", w->a_datadir));
        ASSERT(!afd_route_try("app.open", "sky", w->a_datadir));
        PASS();
    } _test_next:;
    bool restored = afd_route_env_restore("HOME", home);
    restored = afd_route_env_restore("XDG_STATE_HOME", state_old) && restored;
    restored = afd_route_env_restore("XDG_CONFIG_HOME", config_old) && restored;
    free(home); free(state_old); free(config_old);
    if (!restored) failures++;
    return failures;
}

static int afd_a_builds_and_opens(struct afd_world *w)
{
    int failures = 0;
    TEST("A: build, then open the copy through resident_launch; a wrong "
         "image hash is refused") {
        struct asf_door run;
        struct afd_leaf l;
        char want[AFD_PATH + 64];
        afd_door(w->a_home, w->a_datadir, "build", "tinyapp-1",
                 ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        w->commands_a++;
        (void)snprintf(want, sizeof(want),
                       "z23 -datadir=%s app open tinyapp-1", w->a_datadir);
        ASSERT(afd_next_is(&run, want));
        ASSERT(strstr(run.text, "accept_execution") == NULL);
        ASSERT(afd_open_plan(w->a_datadir, "tinyapp-1", &l));
        ASSERT(l.out.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strlen(afd_get(&l, "image_sha3")) == 64);
        (void)snprintf(w->image_a, sizeof(w->image_a), "%s",
                       afd_get(&l, "image_sha3"));
        char plan[65];
        (void)snprintf(plan, sizeof(plan), "%s", afd_get(&l, "plan_id"));
        afd_close_leaf(&l);

        ASSERT(afd_open_plan(w->a_datadir, "tinyapp-1", &l));
        (void)json_push_kv_str(&l.in, "plan_id", plan);
        (void)json_push_kv_bool(&l.in, "confirm", true);
        (void)json_push_kv_bool(&l.in, "accept_execution", true);
        (void)json_push_kv_str(&l.in, "image_sha3",
                               "00000000000000000000000000000000"
                               "00000000000000000000000000000000");
        zcl_command_reply_free(&l.out);
        zcl_command_reply_init(&l.out, "zcl.test.app_front_door.v1");
        ASSERT(afd_exec("app.run.copy", &l));
        ASSERT(afd_refused(&l, "IMAGE_HASH_MISMATCH"));
        afd_close_leaf(&l);

        afd_door(w->a_home, w->a_datadir, "open", "tinyapp-1",
                 ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        w->commands_a++;
        ASSERT(strstr(run.text, w->image_a) != NULL ||
               strstr(run.text, "opened") != NULL);
        ASSERT(asf_alive_then_stop(asf_door_pid(run.text)));
        PASS();
    } _test_next:;
    return failures;
}

static int afd_a_stale(struct afd_world *w)
{
    int failures = 0;
    TEST("A: an unsaved edit, or a saved one not yet built, is a stale "
         "build") {
        struct afd_leaf l;
        struct asf_door run;
        ASSERT(afd_put(w->a_copy, "src/main.c", k_main_v1));
        ASSERT(afd_open_plan(w->a_datadir, "tinyapp-1", &l));
        ASSERT(afd_refused(&l, "STALE_BUILD"));
        afd_close_leaf(&l);
        afd_door(w->a_home, w->a_datadir, "save", "tinyapp-1",
                 ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        ASSERT(afd_open_plan(w->a_datadir, "tinyapp-1", &l));
        ASSERT(afd_refused(&l, "STALE_BUILD"));
        afd_close_leaf(&l);
        /* Back to v2, which is built: a cache hit, and it opens again. */
        ASSERT(afd_put(w->a_copy, "src/main.c", k_main_v2));
        afd_door(w->a_home, w->a_datadir, "save", "tinyapp-1",
                 ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        ASSERT(afd_open_plan(w->a_datadir, "tinyapp-1", &l));
        ASSERT(l.out.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(afd_get(&l, "image_sha3"), w->image_a) == 0);
        afd_close_leaf(&l);
        PASS();
    } _test_next:;
    return failures;
}

static int afd_a_shares(struct afd_world *w)
{
    int failures = 0;
    TEST("A: share writes NAME.z23share, tells A the fingerprint, version "
         "root and install the friend needs, and A's copy still opens") {
        struct asf_door run;
        struct afd_leaf l;
        struct stat st;
        afd_door(w->a_home, w->a_datadir, "share", "tinyapp-1",
                 ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        w->commands_a++;
        ASSERT(stat(w->share, &st) == 0 && S_ISREG(st.st_mode));
        ASSERT(strstr(run.text, "tinyapp-1.z23share") != NULL);
        ASSERT(asf_short_fingerprint(run.text));
        ASSERT(asf_share_told(run.text, w->told_fp, sizeof(w->told_fp),
                              w->told_root));
        ASSERT(strstr(run.text, "Tell them these another way") != NULL);
        char line[1024];
        (void)asf_door_line(&run, "next", line, sizeof(line));
        ASSERT(strstr(line, "your friend runs: z23 app open "
                            "tinyapp-1.z23share") != NULL);
        ASSERT(strstr(line, "a C compiler") != NULL);
        ASSERT(strstr(line, "app build") == NULL);
        /* Renamed under A's key, yet the build A made before share still
         * opens: the rename touches no build input. */
        ASSERT(afd_open_plan(w->a_datadir, "tinyapp-1", &l));
        ASSERT(l.out.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(afd_get(&l, "image_sha3"), w->image_a) == 0);
        afd_close_leaf(&l);
        afd_door(w->a_home, w->a_datadir, "open", "tinyapp-1",
                 ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        w->commands_a++;
        ASSERT(asf_alive_then_stop(asf_door_pid(run.text)));
        PASS();
    } _test_next:;
    return failures;
}

/* A flipped byte in the middle of the shared tree. */
static bool afd_tamper(const char *from, const char *to)
{
    uint8_t *bytes = NULL;
    size_t len = 0;
    FILE *f = fopen(from, "rb");
    if (!f)
        return false;
    if (fseek(f, 0, SEEK_END) == 0 && ftell(f) > 64) {
        len = (size_t)ftell(f);
        bytes = malloc(len);
        rewind(f);
    }
    bool ok = bytes && fread(bytes, 1, len, f) == len;
    (void)fclose(f);
    if (ok) {
        bytes[len - 40u] ^= 0x5a;
        f = fopen(to, "wb");
        ok = f && fwrite(bytes, 1, len, f) == len;
        ok = f ? fclose(f) == 0 && ok : false;
    }
    free(bytes);
    return ok;
}

static int afd_b_refusals(struct afd_world *w)
{
    int failures = 0;
    TEST("B: a tampered share file writes nothing; the public app.open never "
         "receives a share file") {
        struct asf_door run;
        struct afd_leaf l;
        char tampered[AFD_PATH];
        (void)snprintf(tampered, sizeof(tampered), "%s/tampered.z23share",
                       w->b_home);
        ASSERT(afd_tamper(w->share, tampered));
        char *before = afd_snapshot(w->b_datadir);
        ASSERT(before != NULL);
        afd_door(w->b_home, w->b_datadir, "open", tampered,
                 ZCL_CLI_CONFIRM_YES, &run);
        ASSERT(run.rc != 0);
        ASSERT(afd_same(before, w->b_datadir));

        afd_open_leaf(&l);
        (void)json_push_kv_str(&l.in, "name", w->share);
        ASSERT(afd_exec("app.open", &l));
        ASSERT(l.out.status != ZCL_COMMAND_STATUS_PASSED);
        afd_close_leaf(&l);
        ASSERT(afd_same(before, w->b_datadir));
        free(before);
        PASS();
    } _test_next:;
    return failures;
}

/* What A's share file says its root and publisher are, read by the verify
 * leaf directly: the expectation for what B must be shown, never taken from
 * B's own front-door reply. */
static int afd_b_plan_shows_root(struct afd_world *w)
{
    int failures = 0;
    TEST("B: the open plan of a share file shows A's full fingerprint and "
         "exact package root, and a hint that pastes") {
        struct asf_door run;
        struct afd_leaf v;
        char want[AFD_PATH + 64], line[96];
        afd_open_leaf(&v);
        (void)json_push_kv_str(&v.in, "file", w->share);
        ASSERT(afd_exec("zcode.package.bundle.verify", &v));
        ASSERT_EQ((int)v.out.status, (int)ZCL_COMMAND_STATUS_PASSED);
        (void)snprintf(w->b_root, sizeof(w->b_root), "%s",
                       afd_get(&v, "package_root"));
        (void)snprintf(w->b_fp, sizeof(w->b_fp), "%s",
                       afd_get(&v, "publisher_fingerprint"));
        afd_close_leaf(&v);
        ASSERT_EQ((int)strlen(w->b_root), 64);
        ASSERT_EQ((int)strlen(w->b_fp), 66);
        /* what share told A is what the file carries */
        ASSERT_STR_EQ(w->told_root, w->b_root);
        ASSERT_STR_EQ(w->told_fp, w->b_fp);

        afd_door(w->b_home, w->b_datadir, "open", w->share,
                 ZCL_CLI_CONFIRM_PLAN_ONLY, &run);
        ASSERT_EQ(run.rc, 0);
        (void)asf_door_line(&run, "package_root", line, sizeof(line));
        ASSERT_STR_EQ(line, w->b_root);
        (void)asf_door_line(&run, "publisher_fingerprint", line,
                            sizeof(line));
        ASSERT_STR_EQ(line, w->b_fp);
        ASSERT(afd_hint_of(run.text, w->hint, sizeof(w->hint)));
        (void)snprintf(want, sizeof(want),
                       "z23 -datadir=%s app open %s --yes", w->b_datadir,
                       w->share);
        ASSERT_STR_EQ(w->hint, want);
        PASS();
    } _test_next:;
    return failures;
}

static int afd_b_receives(struct afd_world *w)
{
    int failures = 0;
    TEST("B: open FILE.z23share verifies, asks once, receives, builds the "
         "same image as A and opens it") {
        struct asf_door run;
        struct afd_leaf l;
        afd_door(w->b_home, w->b_datadir, "open", w->share,
                 ZCL_CLI_CONFIRM_ASK, &run);
        ASSERT_EQ(run.rc, 0);
        w->commands_b++;
        ASSERT(run.asked);
        ASSERT(asf_short_fingerprint(run.question));
        ASSERT(strstr(run.question, w->b_fp) != NULL);
        ASSERT(strstr(run.question, w->b_root) != NULL);
        ASSERT(asf_alive_then_stop(asf_door_pid(run.text)));
        ASSERT(afd_open_plan(w->b_datadir, "tinyapp-1", &l));
        ASSERT(l.out.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(strcmp(afd_get(&l, "image_sha3"), w->image_a) == 0);
        afd_close_leaf(&l);
        PASS();
    } _test_next:;
    return failures;
}

#if defined(ZCL_TESTING)
struct afd_share_fault { unsigned nth; bool reached, tampered; };
static void afd_share_after_sign(void *context, struct zcl_command_reply *inner)
{
    struct afd_share_fault *f = context;
    f->reached = true;
    if (f->nth && f->nth < 100) zcl_alloc_fault_fail_nth("json_push_kv_key", f->nth);
    if (f->nth < 100 || f->nth == 102) return;
    for (size_t i = 0; i < inner->data.num_children; ++i) {
        if (strcmp(inner->data.keys[i], "share_file")) continue;
        if (f->nth == 100) json_set_null(&inner->data.children[i]);
        else json_set_str(&inner->data.children[i], "/fixture/wrong-output");
        f->tampered = true; return;
    }
}
static bool afd_share_verify(const char *path, const struct afd_world *w)
{
    struct afd_leaf l; afd_open_leaf(&l);
    bool ok = json_push_kv_str(&l.in, "file", path) &&
        afd_exec("zcode.package.bundle.verify", &l) && l.out.status == ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(afd_get(&l, "package_root"), w->told_root) &&
        !strcmp(afd_get(&l, "publisher_fingerprint"), w->told_fp);
    afd_close_leaf(&l); return ok;
}
static bool afd_share_plan(struct afd_leaf *l, const struct afd_world *w, const char *path)
{
    afd_open_leaf(l);
    return json_push_kv_str(&l->in, "copy", "tinyapp-1") &&
        json_push_kv_str(&l->in, "datadir", w->a_datadir) && json_push_kv_str(&l->in, "output", path) &&
        afd_exec("app.share-copy", l) && l->out.status == ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(afd_get(l, "output"), path) && strlen(afd_get(l, "plan_id")) == 64;
}
static bool afd_share_confirm(struct afd_leaf *l, struct afd_share_fault *fault)
{
    char plan[65]; (void)snprintf(plan, sizeof(plan), "%s", afd_get(l, "plan_id"));
    zcl_command_reply_free(&l->out); zcl_command_reply_init(&l->out, "zcl.test.app_front_door.v1");
    if (!json_push_kv_str(&l->in, "plan_id", plan) || !json_push_kv_bool(&l->in, "confirm", true)) return false;
    if (fault->nth == 102) {
        l->req.success_data_budget_provided = true;
        l->req.success_data_budget = 64;
    }
    zcl_test_app_share_copy(&l->req, &l->out, afd_share_after_sign, fault);
    return true;
}
static bool afd_share_recovery_identity(const struct json_value *facts, const struct afd_world *w)
{
    const char *name = json_get_str(json_get(facts, "name"));
    const char *release = json_get_str(json_get(facts, "release_id"));
    const char *version = json_get_str(json_get(facts, "version"));
    const char *root = json_get_str(json_get(facts, "package_root"));
    const char *publisher = json_get_str(json_get(facts, "publisher_fingerprint"));
    return name && *name && release && strlen(release) == 64 &&
        version && strlen(version) == 64 && root && !strcmp(root, w->told_root) &&
        publisher && !strcmp(publisher, w->told_fp);
}
static bool afd_share_optional_string(const struct json_value *value)
{
    return !value || value->type == JSON_STR;
}
static bool afd_share_compact_facts(const struct json_value *facts, const char *path)
{
    const struct json_value *requested = json_get(facts, "requested_output");
    return requested && !strcmp(json_get_str(requested), path) && !json_get(facts, "share_file") &&
        json_get_bool(json_get(facts, "details_unavailable")) && !json_get(facts, "package_root");
}
static bool afd_share_recovery_fields(const struct json_value *facts, const struct afd_world *w,
    const char *path, unsigned nth, bool escaped)
{
    const struct json_value *requested_value = json_get(facts, "requested_output");
    const struct json_value *file_value = json_get(facts, "share_file");
    if (!afd_share_optional_string(requested_value) || !afd_share_optional_string(file_value)) return false;
    bool omitted = json_get_bool(json_get(facts, "details_unavailable"));
    size_t len = strlen(path);
    if (escaped) return !requested_value && !file_value && omitted;
    if (len > 600) return afd_share_compact_facts(facts, path);
    if (!requested_value || strcmp(json_get_str(requested_value), path)) return false;
    if (!afd_share_recovery_identity(facts, w)) return false;
    if (nth == 100 || nth == 101) return !file_value && omitted;
    return file_value && !strcmp(json_get_str(file_value), path) && !omitted;
}
static bool afd_share_error_fields(const struct json_value *error, const struct afd_world *w,
    const char *path, unsigned nth, bool escaped)
{
    const char *code = json_get_str(json_get(error, "code"));
    const char *action = json_get_str(json_get(error, "next_action"));
    const struct json_value *retryable = json_get(error, "retryable");
    return code && !strcmp(code, nth == 102 ? "OBSERVATION_TOO_LARGE" : "REPLY_FAILED") && action &&
        !strcmp(action, "Inspect the exact output from the share plan before retrying.") &&
        json_get_bool(json_get(error, "mutated")) && retryable && retryable->type == JSON_BOOL &&
        !json_get_bool(retryable) && afd_share_recovery_fields(json_get(error, "facts"), w, path, nth, escaped);
}
static bool afd_share_error_wire(struct afd_leaf *l, const struct afd_world *w, const char *path, unsigned nth, bool escaped)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = afd_spec("app.share-copy");
    char wire[ZCL_COMMAND_ERROR_BUDGET + 1];
    size_t n = spec ? zcl_command_registry_test_reply_wire(reg, spec, &l->out, wire, sizeof(wire)) : 0;
    struct json_value doc; json_init(&doc);
    bool ok = n && json_read(&doc, wire, n) &&
        afd_share_error_fields(json_get(&doc, "error"), w, path, nth, escaped);
    if (!ok) printf("  share wire mismatch nth=%u pathlen=%zu wirelen=%zu wire=%.*s\n",
        nth, strlen(path), n, (int)(n < sizeof(wire) ? n : sizeof(wire) - 1), wire);
    json_free(&doc); return ok;
}
static bool afd_share_response(const struct afd_leaf *l, const struct afd_world *w,
    const char *path, unsigned nth)
{
    if (nth) return l->out.status != ZCL_COMMAND_STATUS_PASSED && l->out.error.mutated &&
        !strcmp(l->out.error.code, nth == 102 ? "OBSERVATION_TOO_LARGE" : "REPLY_FAILED") && !l->out.error.retryable &&
        !strcmp(l->out.error.next_action, "Inspect the exact output from the share plan before retrying.");
    return l->out.status == ZCL_COMMAND_STATUS_PASSED && !strcmp(afd_get(l, "package_root"), w->told_root) &&
        l->out.error.mutated && !strcmp(afd_get(l, "share_file"), path) &&
        !strcmp(afd_get(l, "publisher_fingerprint"), w->told_fp) &&
        afd_get(l, "publisher")[0] && afd_get(l, "next")[0];
}
static bool afd_share_full_response(struct afd_leaf *l, const struct afd_world *w,
    const char *path, unsigned nth, bool escaped)
{
    if (!afd_share_response(l, w, path, nth)) return false;
    if (!nth) return true;
    return afd_share_error_wire(l, w, path, nth, escaped) &&
        (strlen(path) >= sizeof(l->out.error.evidence) || !strcmp(l->out.error.evidence, path));
}
static bool afd_share_reply_one(const struct afd_world *w, unsigned nth, const char *output_dir, bool escaped)
{
    char path[APP_COPY_BUILD_PATH]; struct stat st; struct afd_leaf l; struct afd_share_fault fault = {.nth = nth};
    int n = snprintf(path, sizeof(path), "%s/reply-fault-%u.z23share", output_dir, nth);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    bool plan = afd_share_plan(&l, w, path);
    bool ran = plan && afd_share_confirm(&l, &fault);
    bool consumed = fault.reached && (nth == 102 ? true : nth >= 100 ? fault.tampered :
        (!nth || !zcl_alloc_fault_armed_label()));
    zcl_alloc_fault_clear();
    bool exists = stat(path, &st) == 0 && S_ISREG(st.st_mode);
    bool valid = exists && afd_share_verify(path, w);
    bool response = afd_share_full_response(&l, w, path, nth, escaped);
    printf("  share reply nth=%u pathlen=%zu plan=%d ran=%d reached=%d consumed=%d file=%d verified=%d response=%d status=%d mutated=%d code=%s evidence=%s\n",
        nth, strlen(path), plan, ran, fault.reached, consumed, exists, valid, response, l.out.status, l.out.error.mutated,
        l.out.error.code, l.out.error.evidence);
    afd_close_leaf(&l); return plan && ran && consumed && valid && response;
}
static bool afd_share_long_dir(const struct afd_world *w, char out[APP_COPY_BUILD_PATH], bool wide)
{
    char component[201]; size_t len = wide ? 200u : 110u;
    for (size_t i = 0; i < len; ++i)
        component[i] = wide ? (i % 3 == 0 ? '\1' : i % 3 == 1 ? '"' : '\\') : 'x';
    component[len] = 0;
    int n = snprintf(out, APP_COPY_BUILD_PATH, "%s", w->root);
    if (n < 0 || n >= APP_COPY_BUILD_PATH) return false;
    const int wide_parts = 4; /* Escaped output exceeds the facts budget within PATH_MAX. */
    for (int i = 0; i < (wide ? wide_parts : 3); ++i) {
        size_t used = strlen(out);
        n = snprintf(out + used, APP_COPY_BUILD_PATH - used, "/%s", component);
        if (n < 0 || (size_t)n >= APP_COPY_BUILD_PATH - used || mkdir(out, 0700)) return false;
    }
    return strlen(out) > (wide ? (size_t)wide_parts * 200u : 255u);
}
static bool afd_share_medium_dir(const struct afd_world *w, char out[APP_COPY_BUILD_PATH])
{
    char component[201]; memset(component, 'm', 200); component[200] = 0;
    int n = snprintf(out, APP_COPY_BUILD_PATH, "%s", w->root);
    if (n < 0 || n >= APP_COPY_BUILD_PATH) return false;
    for (int i = 0; i < 4; ++i) {
        size_t used = strlen(out);
        n = snprintf(out + used, APP_COPY_BUILD_PATH - used, "/%s", component);
        if (n < 0 || (size_t)n >= APP_COPY_BUILD_PATH - used || mkdir(out, 0700)) return false;
    }
    return strlen(out) > 600 && strlen(out) < 950;
}
/* The harness cleanup has a shorter path buffer than these deliberate long
 * names. Remove only this known output and the directories we created. */
static bool afd_share_remove_long(const struct afd_world *w, char dir[APP_COPY_BUILD_PATH])
{
    size_t root_len = strlen(w->root);
    if (strncmp(dir, w->root, root_len) || dir[root_len] != '/') return false;
    char path[APP_COPY_BUILD_PATH];
    int n = snprintf(path, sizeof(path), "%s/reply-fault-1.z23share", dir);
    if (n < 0 || (size_t)n >= sizeof(path) || unlink(path) != 0) return false;
    while (strlen(dir) > root_len) {
        if (rmdir(dir) != 0) return false;
        char *slash = strrchr(dir, '/');
        if (!slash || (size_t)(slash - dir) < root_len) return false;
        *slash = 0;
    }
    return !strcmp(dir, w->root);
}
static bool afd_share_long_case(const struct afd_world *w, unsigned kind)
{
    char dir[APP_COPY_BUILD_PATH] = {0};
    bool made = kind == 1 ? afd_share_medium_dir(w, dir) : afd_share_long_dir(w, dir, kind == 2);
    bool passed = made && afd_share_reply_one(w, 1, dir, kind == 2);
    if (!passed) {
        printf("  long share case %u failed; fixture retained at %s\n", kind, dir);
        return false;
    }
    if (!afd_share_remove_long(w, dir)) {
        printf("  long share case %u cleanup failed at %s: %s\n", kind, dir, strerror(errno));
        return false;
    }
    return true;
}
static bool afd_share_default_plan(const struct afd_world *w, const char *moved, const char *name)
{
    struct afd_leaf l; afd_open_leaf(&l);
    bool ran = json_push_kv_str(&l.in, "copy", moved) &&
        json_push_kv_str(&l.in, "datadir", w->a_datadir) && afd_exec("app.share-copy", &l);
    char truncated[AFD_PATH];
    int n = snprintf(truncated, sizeof(truncated), "%s/%.95s", w->root, name);
    struct stat st;
    bool absent = n > 0 && (size_t)n < sizeof(truncated) && stat(truncated, &st) != 0 && errno == ENOENT;
    bool ok = ran && l.out.status != ZCL_COMMAND_STATUS_PASSED && !l.out.error.mutated &&
        !strcmp(l.out.error.code, "BAD_OUTPUT") && absent;
    if (!ok) printf("  default leaf ran=%d status=%d mutated=%d code=%s absent=%d\n",
        ran, l.out.status, l.out.error.mutated, l.out.error.code, absent);
    afd_close_leaf(&l); return ok;
}
static bool afd_share_default_leaf_refusal(const struct afd_world *w)
{
    char name[121], moved[AFD_PATH], cwd[AFD_PATH];
    memset(name, 'y', 120); name[120] = 0;
    int n = snprintf(moved, sizeof(moved), "%s/copies/%s", w->a_datadir, name);
    if (n < 0 || (size_t)n >= sizeof(moved) || !getcwd(cwd, sizeof(cwd)) || rename(w->a_copy, moved)) return false;
    bool changed_dir = chdir(w->root) == 0;
    bool ok = changed_dir && afd_share_default_plan(w, moved, name);
    bool restored = rename(moved, w->a_copy) == 0;
    if (changed_dir && chdir(cwd) != 0) restored = false;
    if (!ok || !restored) printf("  default leaf changed_dir=%d ok=%d restored=%d\n", changed_dir, ok, restored);
    return ok && restored;
}
static int afd_share_reply_faults(const struct afd_world *w)
{
    int failures = 0; char *old = NULL; bool captured = false;
    TEST("signed share reply allocation failure retains a verifiable file and recovery path") {
        captured = afd_route_env_capture("HOME", &old); ASSERT(captured);
        ASSERT(setenv("HOME", w->a_home, 1) == 0);
        bool ok = true; const unsigned cases[] = {0, 1, 8, 9, 10, 100, 101, 102};
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
            if (!afd_share_reply_one(w, cases[i], w->root, false)) ok = false;
        for (unsigned kind = 0; kind < 3; ++kind)
            if (!afd_share_long_case(w, kind)) ok = false;
        if (!afd_share_default_leaf_refusal(w)) ok = false;
        ASSERT(ok); PASS();
    } _test_next:;
    zcl_alloc_fault_clear();
    if (captured && !afd_route_env_restore("HOME", old)) ++failures;
    free(old); return failures;
}
#endif

static int afd_changed_dependencies(struct afd_world *w)
{
    int failures = 0;
    TEST("a cached build cannot be carried to another dependency identity") {
        struct afd_leaf l;
        struct app_copy_build_keys from, to;
        struct zcl_package_copy copy;
        uint8_t fork[32];
        afd_open_leaf(&l);
        ASSERT(app_copy_build_keys(w->a_datadir, w->a_copy, &from, &l.out));
        ASSERT(from.hit);
        ASSERT(zcl_package_copy_open(w->a_copy, &copy, &l.out, "app.share-copy"));
        memcpy(fork, copy.fork_version, sizeof(fork));
        zcl_package_copy_close(&copy);
        to = from;
        to.package_root[0] ^= 1;
        to.dependency_root[0] ^= 1;
        char *before = afd_snapshot(w->a_datadir);
        ASSERT(before != NULL);
        bool carried = app_copy_build_carry(w->a_datadir, fork, &from, &to, &l.out);
        bool unchanged = afd_same(before, w->a_datadir);
        free(before);
        ASSERT(!carried);
        ASSERT_STR_EQ(l.out.error.code, "NOT_CARRIED");
        ASSERT(unchanged);
        afd_close_leaf(&l);
        PASS();
    } _test_next:;
    return failures;
}

/* The confirm half makes the owner's signing key on first use; the front
 * door tells the person once, with the path, and not on the next copy. */
/* ── tasks copy carry: a datadir tasks release flows through the front door ──
 * The tasks journey rides the same copy carry as skycombat: with a tasks
 * release already in the datadir (published through the same wire formats the
 * zcode lifecycle uses), `app copy tasks` adopts it into an editable copy —
 * no seeding, no apps/ member, no installed-source gate. */
static const struct { const char *path; const char *body; } aftp_files[] = {
    {"LICENSE", "Apache-2.0\n"},
    {"app/main.c", "int main(void) { return 0; }\n"},
    {"include/tasks.h", "#pragma once\n"},
    {"src/tasks.c", "#include \"tasks.h\"\n"},
    {"tests/test_tasks.c", "int main(void) { return 0; }\n"},
};
static bool aftp_put(const char *base, const char *rel, const void *bytes, size_t len)
{
    char path[AFD_PATH + 128];
    int n = snprintf(path, sizeof(path), "%s/%s", base, rel);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    return fwrite(bytes, 1, len, f) == len && fclose(f) == 0;
}
static bool aftp_mkdirs(const char *zcode)
{
    static const char *const subs[] = {"manifests", "releases", "staging",
                                       "pins", "cas", "cas/sha3", "recipes"};
    char dir[AFD_PATH + 64];
    if (mkdir(zcode, 0700) != 0) {
        printf("  [tasks fixture: mkdir %s failed: %s]\n", zcode, strerror(errno));
        return false;
    }
    for (size_t i = 0; i < sizeof(subs) / sizeof(subs[0]); ++i) {
        int n = snprintf(dir, sizeof(dir), "%s/%s", zcode, subs[i]);
        if (n <= 0 || (size_t)n >= sizeof(dir) || mkdir(dir, 0700) != 0) {
            printf("  [tasks fixture: mkdir %s failed: %s]\n", dir, strerror(errno));
            return false;
        }
    }
    return true;
}
/* Add every fixture member to the manifest and its bytes to the CAS shard. */
static bool aftp_members(const char *zcode, struct vcs_package_manifest *m)
{
    char hex[65], shard[AFD_PATH + 96], path[AFD_PATH + 96];
    for (size_t i = 0; i < sizeof(aftp_files) / sizeof(aftp_files[0]); ++i) {
        uint8_t hash[32];
        struct sha3_256_ctx c;
        size_t len = strlen(aftp_files[i].body);
        sha3_256_init(&c);
        sha3_256_write(&c, (const uint8_t *)aftp_files[i].body, len);
        sha3_256_finalize(&c, hash);
        zcl_hex_encode(hash, 32, hex);
        bool added = vcs_package_manifest_add(m, aftp_files[i].path,
                                              VCS_PACKAGE_MODE_FILE, len, hash, 1) &&
            (int)snprintf(shard, sizeof(shard), "%s/cas/sha3/%.2s", zcode, hex) <
                (int)sizeof(shard) &&
            (int)snprintf(path, sizeof(path), "cas/sha3/%.2s/%s", hex, hex) <
                (int)sizeof(path);
        int made = added ? mkdir(shard, 0700) : -1;
        if (!added || (made != 0 && errno != EEXIST) ||
            !aftp_put(zcode, path, aftp_files[i].body, len)) {
            printf("  [tasks fixture: member %s refused]\n", aftp_files[i].path);
            return false;
        }
    }
    return true;
}
/* The recipe rows of the tasks package, then the signed release wire. */
static bool aftp_recipe_wires(struct vcs_package_recipe *r,
                              struct vcs_package_manifest *m,
                              uint8_t recipe_root[32], uint8_t root_out[32],
                              uint8_t **rwire, size_t *rlen,
                              uint8_t **mwire, size_t *mlen)
{
    bool ok = vcs_package_recipe_add_header(r, "include/tasks.h", NULL) &&
        vcs_package_recipe_add_source(r, "src/tasks.c", NULL) &&
        vcs_package_recipe_add_test_source(r, "tests/test_tasks.c", NULL) &&
        vcs_package_recipe_add_include_dir(r, "include", NULL) &&
        vcs_package_recipe_add_library(r, VCS_PACKAGE_RECIPE_LIB_LIBC, NULL) &&
        vcs_package_recipe_add_program(r, "app/main.c", NULL);
    vcs_package_recipe_set_test_limits(r, 0, 60, UINT64_C(64) * 1024 * 1024);
    ok = ok && vcs_package_recipe_root(r, recipe_root) == VCS_PACKAGE_RECIPE_OK &&
        vcs_package_recipe_serialize(r, rwire, rlen) == VCS_PACKAGE_RECIPE_OK &&
        vcs_package_manifest_root(m, root_out) &&
        vcs_package_manifest_serialize(m, mwire, mlen);
    if (!ok)
        printf("  [tasks fixture: recipe or manifest wires refused]\n");
    return ok;
}
static bool aftp_release_wire(const struct privkey *sk, const struct pubkey *pk,
                              const uint8_t root_out[32],
                              const uint8_t recipe_root[32], uint8_t id[32],
                              char release_hex[65], uint8_t **relwire,
                              size_t *relen)
{
    struct vcs_package_release rel;
    struct uint256 h;
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    memset(&rel, 0, sizeof(rel));
    rel.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    (void)snprintf(rel.name, sizeof(rel.name), "ztasks/tasks");
    (void)snprintf(rel.semver, sizeof(rel.semver), "0.1.0");
    memcpy(rel.package_root, root_out, 32);
    memcpy(rel.publisher_pubkey, pk->vch, COMPRESSED_PUBLIC_KEY_SIZE);
    rel.publisher_sequence = 1;
    /* empty = no reward address; the store refuses non-chain addresses */
    rel.reward_address[0] = 0;
    (void)snprintf(rel.license, sizeof(rel.license), "Apache-2.0");
    memcpy(rel.recipe_root, recipe_root, 32);
    (void)snprintf(rel.chain_id, sizeof(rel.chain_id), "zclassic-main");
    bool ok = vcs_package_release_id(&rel, id) == VCS_PACKAGE_RELEASE_OK &&
        privkey_sign_compact(sk, (memcpy(h.data, id, 32), &h), compact) &&
        (memcpy(rel.signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES),
         vcs_package_release_serialize(&rel, relwire, relen) ==
             VCS_PACKAGE_RELEASE_OK);
    if (ok) zcl_hex_encode(id, 32, release_hex);
    return ok;
}
static bool aftp_store(const char *zcode, const uint8_t root_out[32],
                       const uint8_t recipe_root[32], const char *release_hex,
                       const uint8_t *mwire, size_t mlen,
                       const uint8_t *rwire, size_t rlen,
                       const uint8_t *relwire, size_t relen)
{
    char root_hex[65], recipe_hex[65], path[AFD_PATH + 96];
    zcl_hex_encode(root_out, 32, root_hex);
    zcl_hex_encode(recipe_root, 32, recipe_hex);
    return (int)snprintf(path, sizeof(path), "manifests/%s", root_hex) <
            (int)sizeof(path) && aftp_put(zcode, path, mwire, mlen) &&
        (int)snprintf(path, sizeof(path), "recipes/%s", recipe_hex) <
            (int)sizeof(path) && aftp_put(zcode, path, rwire, rlen) &&
        (int)snprintf(path, sizeof(path), "releases/%s", release_hex) <
            (int)sizeof(path) && aftp_put(zcode, path, relwire, relen);
}
static bool aftp_publish(const char *datadir, uint8_t root_out[32],
                         char release_hex[65])
{
    char zcode[AFD_PATH];
    struct vcs_package_manifest m; vcs_package_manifest_init(&m);
    struct vcs_package_recipe r; vcs_package_recipe_init(&r);
    struct privkey sk; struct pubkey pk;
    uint8_t *mwire = NULL, *rwire = NULL, *relwire = NULL;
    size_t mlen = 0, rlen = 0, relen = 0;
    uint8_t recipe_root[32], id[32];
    privkey_init(&sk);
    memset(sk.vch, 0x11, 32); sk.fValid = true; sk.fCompressed = true;
    bool ok = (int)snprintf(zcode, sizeof(zcode), "%s/zcode", datadir) <
            (int)sizeof(zcode) && aftp_mkdirs(zcode) && ecc_start_once() &&
        privkey_get_pubkey(&sk, &pk);
    ok = ok && aftp_members(zcode, &m) && aftp_recipe_wires(&r, &m,
        recipe_root, root_out, &rwire, &rlen, &mwire, &mlen);
    ok = ok && aftp_release_wire(&sk, &pk, root_out, recipe_root, id,
                                 release_hex, &relwire, &relen);
    ok = ok && aftp_store(zcode, root_out, recipe_root, release_hex,
                          mwire, mlen, rwire, rlen, relwire, relen);
    free(mwire); free(rwire); free(relwire);
    vcs_package_manifest_free(&m); vcs_package_recipe_free(&r);
    return ok;
}
static int afd_tasks_carry(struct afd_world *w)
{
    int failures = 0;
    TEST("app front door: a datadir tasks release carries into an editable copy") {
        char datadir[AFD_PATH], home[AFD_PATH], copy[AFD_PATH + 32], release[65];
        struct asf_door run;
        struct stat st;
        uint8_t root[32];
        (void)snprintf(datadir, sizeof(datadir), "%s/tasks-data", w->root);
        (void)snprintf(home, sizeof(home), "%s/tasks-home", w->root);
        ASSERT(mkdir(datadir, 0700) == 0 && mkdir(home, 0700) == 0);
        ASSERT(aftp_publish(datadir, root, release));
        asf_door_run(home, w->saved_cwd, datadir, "copy", "tasks",
                     ZCL_CLI_CONFIRM_YES, &run);
        ASSERT_EQ(run.rc, 0);
        (void)snprintf(copy, sizeof(copy), "%s/copies/tasks-1", datadir);
        ASSERT(stat(copy, &st) == 0 && S_ISDIR(st.st_mode));
        PASS();
    } _test_next:;
    return failures;
}
/* The checkout member, not a datadir release: running from this checkout the
 * first `app copy tasks` seeds apps/tasks (the wrapper Makefile plus the
 * ztasks package files zcode-seed.def maps), signs it and adopts the copy.
 * Without an apps/tasks member the seed refuses APP_UNKNOWN and nothing is
 * written. */
static int afd_tasks_checkout(struct afd_world *w)
{
    int failures = 0;
    TEST("app front door: `app copy tasks` from this checkout seeds the "
         "checkout member") {
        char datadir[AFD_PATH], home[AFD_PATH], copy[AFD_PATH + 32];
        struct asf_door run;
        struct stat st;
        (void)snprintf(datadir, sizeof(datadir), "%s/tasks-checkout-data", w->root);
        (void)snprintf(home, sizeof(home), "%s/tasks-checkout-home", w->root);
        ASSERT(mkdir(datadir, 0700) == 0 && mkdir(home, 0700) == 0);
        asf_door_run(home, w->saved_cwd, datadir, "copy", "tasks",
                     ZCL_CLI_CONFIRM_YES, &run);
        if (run.rc != 0)
            printf("  [copy tasks refused: %.400s]\n", run.text);
        ASSERT_EQ(run.rc, 0);
        (void)snprintf(copy, sizeof(copy), "%s/copies/tasks-1", datadir);
        ASSERT(stat(copy, &st) == 0 && S_ISDIR(st.st_mode));
        PASS();
    } _test_next:;
    return failures;
}
static int afd_key_note_after_confirm(const struct afd_world *w)
{
    int failures = 0;
    TEST("app front door: the confirm reports a first-use signing key once") {
        struct asf_door first, second;
        char want[AFD_PATH + 64], home[AFD_PATH], datadir[AFD_PATH];
        (void)snprintf(home, sizeof(home), "%s/keyhome", w->root);
        (void)snprintf(datadir, sizeof(datadir), "%s/keydata", w->root);
        ASSERT(mkdir(home, 0700) == 0 && mkdir(datadir, 0700) == 0);
        /* run from this checkout, so the first copy seeds apps/skycombat */
        asf_door_run(home, w->saved_cwd, datadir, "copy", "skycombat",
                     ZCL_CLI_CONFIRM_YES, &first);
        ASSERT_EQ(first.rc, 0);
        (void)snprintf(want, sizeof(want), "made your signing key at %s/"
                       ".z23/zcode_publisher.key", home);
        ASSERT(strstr(first.text, want) != NULL);
        asf_door_run(home, w->saved_cwd, datadir, "copy", "skycombat",
                     ZCL_CLI_CONFIRM_YES, &second);
        ASSERT(strstr(second.text, "made your signing key") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* Run `copy skycombat` twice with fd 2 pointed at a file; the second open
 * of the store is the one that finds a receipt. Returns the captured text. */
static char *afd_capture_stderr_copies(const struct afd_world *w, int *rcs)
{
    char home[AFD_PATH], datadir[AFD_PATH];
    struct asf_door run;
    (void)snprintf(home, sizeof(home), "%s/quiethome", w->root);
    (void)snprintf(datadir, sizeof(datadir), "%s/quietdata", w->root);
    if (mkdir(home, 0700) != 0 || mkdir(datadir, 0700) != 0) return NULL;
    FILE *cap = tmpfile();
    if (!cap) return NULL;
    (void)fflush(stderr);
    const int saved = dup(STDERR_FILENO);
    if (saved < 0 || dup2(fileno(cap), STDERR_FILENO) < 0) {
        (void)fclose(cap);
        return NULL;
    }
    for (int i = 0; i < 2; i++) {
        asf_door_run(home, w->saved_cwd, datadir, "copy", "skycombat",
                     ZCL_CLI_CONFIRM_YES, &run);
        rcs[i] = run.rc;
    }
    (void)fflush(stderr);
    (void)dup2(saved, STDERR_FILENO);
    (void)close(saved);
    char *text = calloc(1, 65536);
    if (text) {
        rewind(cap);
        TEST_DISCARD(fread(text, 1, 65535, cap));
    }
    (void)fclose(cap);
    return text;
}

static int afd_quiet_logs(const struct afd_world *w)
{
    int failures = 0;
    TEST("app front door: no INFO log or event_log receipt line reaches the "
         "terminal") {
        int rcs[2] = {-1, -1};
        const enum zcl_log_level prior = zcl_log_level_get();
        zcl_log_level_set(ZCL_LOG_ALL);
        char *text = afd_capture_stderr_copies(w, rcs);
        zcl_log_level_set(prior);
        ASSERT(text != NULL);
        ASSERT_EQ(rcs[0], 0);
        ASSERT_EQ(rcs[1], 0);
        ASSERT(strstr(text, " INFO [") == NULL);
        ASSERT(strstr(text, "[event_log]") == NULL);
        free(text);
        PASS();
    } _test_next:;
    return failures;
}

/* A person who runs `receive` on a file that is not there is told so under
 * the verb they typed, with what to give it. */
static int afd_receive_missing(const struct afd_world *w)
{
    int failures = 0;
    TEST("app front door: receive of a missing file says app receive and what to give") {
        struct asf_door run;
        afd_door(w->b_home, w->b_datadir, "receive", "nothing-here.z23share",
                 ZCL_CLI_CONFIRM_YES, &run);
        ASSERT(run.rc != 0);
        ASSERT(strstr(run.text, "z23 app receive: no such file: nothing-here.z23share") != NULL);
        ASSERT(strstr(run.text, "z23share file you were sent") != NULL);
        ASSERT(strstr(run.text, "z23 app open") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* `app list` runs with every log line on; the event_log receipt of each
 * copy's history must not reach the terminal. */
static int afd_list_quiet(const struct afd_world *w)
{
    int failures = 0;
    TEST("app list: no [event_log] line reaches the terminal") {
        struct afd_leaf l;
        char *text = calloc(1, 65536);
        char prior_dir[512];
        const int prior_port = zcl_native_command_rpc_port();
        (void)snprintf(prior_dir, sizeof(prior_dir), "%s", zcl_native_command_datadir());
        ASSERT(text != NULL);
        FILE *cap = tmpfile();
        ASSERT(cap != NULL);
        (void)fflush(stderr);
        const int saved = dup(STDERR_FILENO);
        ASSERT(saved >= 0 && dup2(fileno(cap), STDERR_FILENO) >= 0);
        const enum zcl_log_level prior = zcl_log_level_get();
        zcl_log_level_set(ZCL_LOG_ALL);
        zcl_native_bridge_bind_rpc(w->a_datadir, prior_port);
        afd_open_leaf(&l);
        bool ran = afd_exec("app.list", &l);
        afd_close_leaf(&l);
        zcl_native_bridge_bind_rpc(prior_dir, prior_port);
        zcl_log_level_set(prior);
        (void)fflush(stderr);
        (void)dup2(saved, STDERR_FILENO);
        (void)close(saved);
        rewind(cap);
        TEST_DISCARD(fread(text, 1, 65535, cap));
        (void)fclose(cap);
        ASSERT(ran);
        ASSERT(strstr(text, "[event_log]") == NULL);
        free(text);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the recipe form: a headless program share opens to a preview offer ── */

/* One headless program package: the main() prints and exits, so a
 * spawn-and-wait open can never see it as a usable window. */
static const char k_prog_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"stub/tinyprog\",\n"
    "  \"semver\": \"0.1.0\",  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",  \"dependencies\": [],\n"
    "  \"programs\": [\"app/main.c\"]\n}\n";
static const char k_prog_library[] = "int tinyprog_value(void) { return 7; }\n";
static const char k_prog_main[] =
    "#include <stdio.h>\nint main(void) { puts(\"tinyprog ready\"); "
    "return 0; }\n";

static bool afd_recipe_source(const struct afd_world *w, char *src,
                              size_t cap)
{
    static const char *const dirs[] = {"include", "src", "app"};
    char dir[AFD_PATH], saved[AFD_PATH];
    (void)snprintf(src, cap, "%s/prog-src", w->root);
    /* afd_license reads the checkout's LICENSE by a relative path; earlier
     * cases may have left the process in another directory. */
    bool ok = getcwd(saved, sizeof(saved)) != NULL &&
              chdir(w->saved_cwd) == 0 && mkdir(src, 0700) == 0 &&
              afd_license(src) && chdir(saved) == 0;
    if (!ok && chdir(saved) != 0)
        printf("  [recipe source: could not return to %s]\n", saved);
    for (size_t i = 0; ok && i < sizeof(dirs) / sizeof(dirs[0]); ++i) {
        int n = snprintf(dir, sizeof(dir), "%s/%s", src, dirs[i]);
        ok = n > 0 && (size_t)n < sizeof(dir) && mkdir(dir, 0700) == 0;
    }
    return ok && afd_put(src, "include/boost.h", "#define BOOST 1\n") &&
           afd_put(src, "zcode-package.json", k_prog_meta) &&
           afd_put(src, "src/main.c", k_prog_library) &&
           afd_put(src, "app/main.c", k_prog_main);
}

static bool afd_recipe_share(const struct afd_world *w, const char *src,
                             char *path, size_t cap)
{
    char key[AFD_PATH + 16], publisher[PLUGIN_HEX_PUBLIC_KEY + 1];
    char detail[256] = {0};
    struct plugin_dist_published why;
    struct vcs_package_prepare_options o = {
        .dir = src, .publisher_sequence = 1, .reward_address = "",
        .chain_id = "zclassic-main",
    };
    struct vcs_package_prepared p;
    struct zcl_command_reply r;
    struct zcl_package_bundle_wires wires;
    uint8_t tree[32];
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    vcs_package_prepared_init(&p);
    (void)snprintf(key, sizeof(key), "%s/prog.key", w->root);
    (void)snprintf(path, cap, "%s/tinyprog-1.z23share", w->root);
    bool ok = plugin_keygen(key, publisher) == PLUGIN_OK &&
              plugin_dist_release_key_sign(key, NULL, o.publisher_pubkey,
                                           NULL, &why) == PLUGIN_DIST_OK &&
              vcs_package_prepare(&o, &p, detail, sizeof(detail)) ==
                  VCS_PACKAGE_PREPARE_OK &&
              plugin_dist_release_key_sign(key, p.signing_digest,
                                           o.publisher_pubkey,
                                           p.release.signature,
                                           &why) == PLUGIN_DIST_OK &&
              vcs_package_release_serialize(&p.release, &wire, &wire_len) ==
                  VCS_PACKAGE_RELEASE_OK &&
              vcs_tree_capture_path(src, tree) == VCS_OK;
    zcl_command_reply_init(&r, "zcl.test.app_front_door.v1");
    memset(&wires, 0, sizeof(wires));
    wires.release = wire;
    wires.release_len = wire_len;
    wires.manifest = p.manifest_wire;
    wires.manifest_len = p.manifest_wire_len;
    wires.recipe = p.recipe_wire;
    wires.recipe_len = p.recipe_wire_len;
    if (ok)
        ok = zcl_package_bundle_write(path, src, tree, &wires, &r) &&
             r.status == ZCL_COMMAND_STATUS_PASSED;
    if (!ok)
        printf("  [prog share: %s %s]\n", r.error.code, r.error.message);
    zcl_command_reply_free(&r);
    free(wire);
    vcs_package_prepared_free(&p);
    return ok;
}

static bool afd_recipe_local_release_needed(const char *datadir, const char *copy)
{
    struct afd_leaf l; afd_open_leaf(&l);
    bool ok = json_push_kv_str(&l.in, "copy", copy) && json_push_kv_str(&l.in, "datadir", datadir) &&
        afd_exec("app.build", &l) && afd_refused(&l, "RECIPE_RELEASE_REQUIRED") && !l.out.error.mutated &&
        l.out.next_count == 1 && !strcmp(l.out.next[0].command, "app.share-copy") &&
        strstr(l.out.next[0].input_json, datadir) && strstr(l.out.next[0].input_json, copy) &&
        strstr(l.out.error.next_action, "signing identity");
    afd_close_leaf(&l); return ok;
}
static bool afd_recipe_incomplete_inventory(const char *datadir, const char *copy)
{
    char path[AFD_PATH];
    int n = snprintf(path, sizeof(path), "%s/zcode/releases/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", datadir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *file = fopen(path, "wx");
    if (!file) return false;
    bool ok = fputs("invalid release", file) >= 0;
    if (fclose(file) != 0) ok = false;
    struct afd_leaf l; afd_open_leaf(&l);
    ok = ok && json_push_kv_str(&l.in, "copy", copy) && json_push_kv_str(&l.in, "datadir", datadir) &&
        afd_exec("app.build", &l) && l.out.status == ZCL_COMMAND_STATUS_PASSED && !l.out.error.mutated;
    afd_close_leaf(&l);
    if (unlink(path) != 0) ok = false;
    return ok;
}
static bool afd_recipe_refusal(const struct afd_world *w, const char *home,
    const char *datadir, const char *copy)
{
    struct asf_door refused;
    char *before_home = afd_snapshot(home), *before_data = afd_snapshot(datadir);
    bool ok = before_home && before_data && afd_recipe_local_release_needed(datadir, copy);
    asf_door_run(home, w->saved_cwd, datadir, "build", "tinyprog-1", ZCL_CLI_CONFIRM_PLAN_ONLY, &refused);
    ok = ok && refused.rc && strstr(refused.text, "RECIPE_RELEASE_REQUIRED") &&
        strstr(refused.text, "app share") && strstr(refused.text, datadir) &&
        strstr(refused.text, "tinyprog-1") && !strstr(refused.text, "--yes") &&
        afd_same(before_home, home) && afd_same(before_data, datadir);
    free(before_home); free(before_data); return ok;
}
static bool afd_head_version(const char *copy_path, char version[65])
{
    struct afd_leaf l; afd_open_leaf(&l);
    struct zcl_package_copy copy = {0};
    bool ok = zcl_package_copy_open_as(copy_path, ZCL_PACKAGE_COPY_READ, &copy, &l.out, "test");
    if (ok) zcl_hex_encode(copy.head_version, 32, version);
    zcl_package_copy_close(&copy); afd_close_leaf(&l); return ok;
}
static bool afd_pinned_refusal(const struct afd_leaf *l)
{
    return afd_refused(l, "RECIPE_RELEASE_REQUIRED") && !l->out.error.mutated &&
        l->out.next_count == 0 && strstr(l->out.error.next_action, "release") &&
        strstr(l->out.error.next_action, "signed") &&
        strstr(l->out.error.message, "Import that release") && strstr(l->out.error.message, "signed version");
}
static bool afd_recipe_pinned(const char *datadir, const char *copy, const char *version, bool signed_release)
{
    struct afd_leaf l; afd_open_leaf(&l);
    bool ok = json_push_kv_str(&l.in, "copy", copy) && json_push_kv_str(&l.in, "datadir", datadir) &&
        json_push_kv_str(&l.in, "version", version) && afd_exec("app.build", &l);
    if (!signed_release && ok && l.out.status == ZCL_COMMAND_STATUS_PASSED)
        printf("  [pinned missing-release plan incorrectly passed]\n");
    if (signed_release) ok = ok && l.out.status == ZCL_COMMAND_STATUS_PASSED && !l.out.error.mutated;
    else ok = ok && afd_pinned_refusal(&l);
    afd_close_leaf(&l); return ok;
}
static bool afd_recipe_after_share(const char *datadir, const char *copy,
                                   const char *old_version, const char *signed_old)
{
    char new_version[65] = {0};
    return afd_head_version(copy, new_version) && strcmp(old_version, new_version) &&
        afd_recipe_pinned(datadir, copy, old_version, false) &&
        afd_recipe_pinned(datadir, copy, signed_old, true) &&
        afd_recipe_pinned(datadir, copy, new_version, true);
}
static bool afd_recipe_edited(const struct afd_world *w, const char *home, const char *datadir)
{
    char copy[AFD_PATH], signed_old[65] = {0};
    int n = snprintf(copy, sizeof(copy), "%s/copies/tinyprog-1", datadir);
    if (n <= 0 || (size_t)n >= sizeof(copy) || !afd_head_version(copy, signed_old) ||
        !afd_recipe_pinned(datadir, copy, signed_old, true) ||
        !afd_put(copy, "src/main.c", "int tinyprog_value(void) { return 8; }\n")) return false;
    struct asf_door save, share, build;
    asf_door_run(home, w->saved_cwd, datadir, "save", "tinyprog-1", ZCL_CLI_CONFIRM_YES, &save);
    char old_version[65] = {0};
    if (save.rc || !afd_head_version(copy, old_version) ||
        !afd_recipe_pinned(datadir, copy, old_version, false) ||
        !afd_recipe_incomplete_inventory(datadir, copy) ||
        !afd_recipe_refusal(w, home, datadir, copy)) return false;
    asf_door_run(home, home, datadir, "share", "tinyprog-1", ZCL_CLI_CONFIRM_YES, &share);
    if (share.rc || !afd_recipe_after_share(datadir, copy, old_version, signed_old)) return false;
    asf_door_run(home, w->saved_cwd, datadir, "build", "tinyprog-1", ZCL_CLI_CONFIRM_PLAN_ONLY, &build);
    return build.rc == 0 && strstr(build.text, "package_root:");
}
static int afd_recipe_open(const struct afd_world *w)
{
    int failures = 0;
    TEST("app front door: open of a recipe-form share completes to its "
         "preview without a spawn") {
        char src[AFD_PATH], share[AFD_PATH], home[AFD_PATH], datadir[AFD_PATH];
        struct asf_door run;
        ASSERT(afd_recipe_source(w, src, sizeof(src)));
        ASSERT(afd_recipe_share(w, src, share, sizeof(share)));
        (void)snprintf(home, sizeof(home), "%s/prog-home", w->root);
        (void)snprintf(datadir, sizeof(datadir), "%s/prog-data", w->root);
        ASSERT(mkdir(home, 0700) == 0 && mkdir(datadir, 0700) == 0);
        /* The checkout as the working directory, like the tasks carry: the
         * recipe install resolves the package verifier beside build/bin. */
        asf_door_run(home, w->saved_cwd, datadir, "open", share,
                     ZCL_CLI_CONFIRM_YES, &run);
        if (run.rc != 0)
            printf("  [recipe open rc=%d text=%s]\n", run.rc, run.text);
        ASSERT_EQ(run.rc, 0);
        ASSERT(strstr(run.text, "copy: tinyprog-1") != NULL);
        /* Nothing was spawned: the reported pid is 0, never a live child.
         * (The door prints "opened tinyprog-1 pid 0"; the receive-copy
         * leaf copies the inner pid verbatim.) */
        ASSERT(asf_door_pid(run.text) == 0);
        ASSERT(strstr(run.text, "next:") != NULL);
        ASSERT(strstr(run.text, "app invoke package") != NULL);
        ASSERT(strstr(run.text, "bin/tinyprog") != NULL);
        ASSERT(strstr(run.text, "--accept_execution=true") != NULL);
        ASSERT(afd_recipe_edited(w, home, datadir));
        PASS();
    } _test_next:;
    return failures;
}

static bool afd_verify_share_file(const char *path)
{
    struct afd_leaf l; afd_open_leaf(&l);
    bool ok = json_push_kv_str(&l.in, "file", path) && afd_exec("zcode.package.bundle.verify", &l) &&
        l.out.status == ZCL_COMMAND_STATUS_PASSED;
    afd_close_leaf(&l); return ok;
}
static bool afd_repeat_plan(struct afd_leaf *l, const struct afd_world *w, const char *output)
{
    afd_open_leaf(l);
    return json_push_kv_str(&l->in, "copy", "tinyapp-1") &&
        json_push_kv_str(&l->in, "datadir", w->a_datadir) &&
        (!output || json_push_kv_str(&l->in, "output", output)) && afd_exec("app.share-copy", l);
}
static bool afd_repeat_collision(const struct afd_world *w, const char *path)
{
    struct afd_leaf l;
    bool ok = afd_repeat_plan(&l, w, path) && afd_refused(&l, "OUTPUT_EXISTS") && !l.out.error.mutated;
    afd_close_leaf(&l); return ok;
}
static bool afd_repeat_race(const struct afd_world *w, const char *third)
{
    struct afd_leaf l;
    bool ok = afd_repeat_plan(&l, w, NULL) && l.out.status == ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(afd_get(&l, "output"), third);
    const char *plan_value = afd_get(&l, "plan_id");
    char plan[65];
    ok = ok && strlen(plan_value) == 64;
    (void)snprintf(plan, sizeof(plan), "%s", plan_value);
    bool made = ok && symlink("missing-target", third) == 0;
    ok = ok && made;
    if (ok) {
        zcl_command_reply_free(&l.out); zcl_command_reply_init(&l.out, "zcl.test.app_front_door.v1");
        ok = json_push_kv_str(&l.in, "plan_id", plan) && json_push_kv_bool(&l.in, "confirm", true) &&
            afd_exec("app.share-copy", &l) && afd_refused(&l, "PLAN_MISMATCH") && !l.out.error.mutated;
    }
    struct stat st;
    ok = ok && lstat(third, &st) == 0 && S_ISLNK(st.st_mode);
    if (made && unlink(third) != 0) ok = false;
    afd_close_leaf(&l); return ok;
}
static bool afd_repeat_shapes(const struct afd_world *w, const char *third)
{
    char fourth[AFD_PATH], fifth[AFD_PATH];
    int a = snprintf(fourth, sizeof(fourth), "%s/tinyapp-1-4.z23share", w->a_home);
    int b = snprintf(fifth, sizeof(fifth), "%s/tinyapp-1-5.z23share", w->a_home);
    if (a <= 0 || (size_t)a >= sizeof(fourth) || b <= 0 || (size_t)b >= sizeof(fifth)) return false;
    if (symlink("missing-target", third) != 0) return false;
    bool made = mkdir(fourth, 0700) == 0;
    struct afd_leaf l;
    bool planned = afd_repeat_plan(&l, w, NULL);
    bool ok = made && planned && l.out.status == ZCL_COMMAND_STATUS_PASSED &&
        !strcmp(afd_get(&l, "output"), fifth);
    afd_close_leaf(&l);
    ok = afd_repeat_collision(w, third) && ok;
    if (unlink(third) != 0) ok = false;
    if (made && rmdir(fourth) != 0) ok = false;
    return ok;
}
static bool afd_repeat_preflight(const struct afd_world *w, const char *third)
{
    char cwd[AFD_PATH];
    const char *home = getenv("HOME"); char *saved = home ? strdup(home) : NULL;
    if ((home && !saved) || !getcwd(cwd, sizeof(cwd))) { free(saved); return false; }
    bool changed = chdir(w->a_home) == 0;
    bool bound = changed && setenv("HOME", w->a_home, 1) == 0;
    bool ok = bound && afd_repeat_collision(w, w->share) && afd_repeat_race(w, third) && afd_repeat_shapes(w, third);
    if (changed && chdir(cwd) != 0) ok = false;
    if (saved ? setenv("HOME", saved, 1) != 0 : unsetenv("HOME") != 0) ok = false;
    free(saved); return ok;
}
static int afd_repeat_share(struct afd_world *w)
{
    int failures = 0; uint8_t *before = NULL, *after = NULL;
    TEST("repeated implicit share preserves the old file and binds the next free name") {
        size_t before_len = 0, after_len = 0;
        before = zcl_native_source_bundle_read(w->share, &before_len);
        ASSERT(before && afd_verify_share_file(w->share));
        ASSERT(afd_put(w->a_copy, "src/main.c", k_main_v1));
        struct asf_door run; afd_door(w->a_home, w->a_datadir, "share", "tinyapp-1", ZCL_CLI_CONFIRM_YES, &run);
        char second[AFD_PATH], third[AFD_PATH];
        int a = snprintf(second, sizeof(second), "%s/tinyapp-1-2.z23share", w->a_home);
        int b = snprintf(third, sizeof(third), "%s/tinyapp-1-3.z23share", w->a_home);
        ASSERT(a > 0 && (size_t)a < sizeof(second) && b > 0 && (size_t)b < sizeof(third));
        ASSERT(run.rc == 0 && strstr(run.text, "tinyapp-1-2.z23share") && afd_verify_share_file(second));
        after = zcl_native_source_bundle_read(w->share, &after_len);
        ASSERT(after && before_len == after_len && !memcmp(before, after, before_len));
        ASSERT(afd_repeat_preflight(w, third));
        PASS();
    } _test_next:;
    free(before); free(after); return failures;
}

static bool afd_zip_dispatch(const char *datadir, const char *target, bool yes,
    char *out, size_t cap, bool *handled, int *rc)
{
    const struct zcl_command_spec *spec = afd_spec("app.open");
    const char *words[] = {target, "--yes"};
    if (!spec) return false;
    FILE *capture = tmpfile();
    if (!capture) return false;
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    if (saved < 0 || dup2(fileno(capture), STDOUT_FILENO) < 0) {
        if (saved >= 0) close(saved);
        fclose(capture); return false;
    }
    *rc = -1;
    *handled = zcl_app_front_door_try(spec, words, yes ? 2 : 1, 0, datadir, rc);
    fflush(stdout);
    bool ok = dup2(saved, STDOUT_FILENO) >= 0;
    close(saved); rewind(capture);
    size_t n = fread(out, 1, cap - 1, capture); out[n] = 0;
    if (fclose(capture) != 0) ok = false;
    return ok;
}
static bool afd_zip_valid(const struct afd_world *w, const char *zip)
{
    char output[1024]; bool handled = false; int rc = 0;
    char *home = afd_snapshot(w->a_home), *data = afd_snapshot(w->a_datadir);
    bool ok = home && data && afd_zip_dispatch(w->a_datadir, zip, true, output, sizeof(output), &handled, &rc) &&
        handled && rc != 0 && strstr(output, "Extract") && strstr(output, ".z23share") &&
        !strstr(output, "verified") && afd_same(home, w->a_home) && afd_same(data, w->a_datadir);
    free(home); free(data); return ok;
}
static bool afd_zip_other_routes(const struct afd_world *w, const char *near)
{
    char output[1024]; bool handled = false; int rc = 0;
    bool ok = afd_zip_dispatch(w->a_datadir, near, false, output, sizeof(output), &handled, &rc) && !handled;
    bool dispatched = afd_zip_dispatch(w->a_datadir, "missing.zip", false, output, sizeof(output), &handled, &rc);
    ok = ok && dispatched && !handled;
    dispatched = afd_zip_dispatch(w->a_datadir, "collision.zip", false, output, sizeof(output), &handled, &rc);
    return ok && dispatched && handled && !strstr(output, "Extract the ZIP");
}
static bool afd_zip_cleanup(const char *zip, const char *near, const char *copy)
{
    bool ok = true;
    if (rmdir(copy) != 0) ok = false;
    if (unlink(zip) != 0) ok = false;
    if (unlink(near) != 0) ok = false;
    if (unlink("Other Tasks.zip") != 0) ok = false;
    if (unlink("collision.zip") != 0) ok = false;
    return ok;
}
static bool afd_zip_checks(const struct afd_world *w)
{
    char zip[AFD_PATH], near[AFD_PATH], copy[AFD_PATH];
    if (snprintf(zip, sizeof(zip), "%s/My Tasks.ZIP", w->a_home) >= (int)sizeof(zip) ||
        snprintf(near, sizeof(near), "%s/My Tasks.zip.bak", w->a_home) >= (int)sizeof(near) ||
        snprintf(copy, sizeof(copy), "%s/copies/collision.zip", w->a_datadir) >= (int)sizeof(copy)) return false;
    if (!afd_put(w->a_home, "My Tasks.ZIP", "not an archive") ||
        !afd_put(w->a_home, "Other Tasks.zip", "not an archive") ||
        !afd_put(w->a_home, "My Tasks.zip.bak", "near miss") ||
        !afd_put(w->a_home, "collision.zip", "not an archive") || mkdir(copy, 0700)) return false;
    bool ok = afd_zip_valid(w, zip) && afd_zip_valid(w, "Other Tasks.zip") && afd_zip_other_routes(w, near);
    bool cleaned = afd_zip_cleanup(zip, near, copy);
    return ok && cleaned;
}
static int afd_zip_case(const struct afd_world *w)
{
    int failures = 0; char cwd[AFD_PATH], *home = NULL;
    bool captured = afd_route_env_capture("HOME", &home) && getcwd(cwd, sizeof(cwd));
    if (!captured) { free(home); return 1; }
    TEST("app open guides ZIP extraction without changing a profile or displacing copy routing") {
        ASSERT(setenv("HOME", w->a_home, 1) == 0 && chdir(w->a_home) == 0);
        ASSERT(afd_zip_checks(w));
        PASS();
    } _test_next:;
    if (chdir(cwd) != 0) ++failures;
    if (!afd_route_env_restore("HOME", home)) ++failures;
    free(home); return failures;
}

int test_app_front_door(void);
int test_app_front_door(void)
{
    int failures = 0;
    struct afd_world w;
    memset(&w, 0, sizeof(w));
    chain_params_select(CHAIN_MAIN);
    failures += afd_mcp_authority();
    TEST("app front door: a stub app release pre-seeded in A's datadir") {
        ASSERT(afd_world_init(&w));
        PASS();
    } _test_next:;
    if (!failures) {
        failures += afd_seed_absent(&w);
        failures += afd_plan_only(&w);
        failures += afd_a_copies_and_saves(&w);
        failures += afd_kept_routing(&w);
    }
    if (!failures) {
        failures += afd_a_builds_and_opens(&w);
        failures += afd_a_stale(&w);
        failures += afd_a_shares(&w);
    }
    if (!failures)
        failures += afd_changed_dependencies(&w);
#if defined(ZCL_TESTING)
    if (!failures)
        failures += afd_share_reply_faults(&w);
#endif
    if (!failures) {
        failures += afd_b_refusals(&w);
        failures += afd_b_plan_shows_root(&w);
        failures += afd_b_receives(&w);
        failures += afd_recipe_open(&w);
    }
    if (!failures)
        failures += afd_key_note_after_confirm(&w);
    if (!failures)
        failures += afd_tasks_carry(&w);
    if (!failures)
        failures += afd_tasks_checkout(&w);
    if (!failures)
        failures += afd_quiet_logs(&w);
    if (!failures) {
        failures += afd_receive_missing(&w);
        failures += afd_list_quiet(&w);
        failures += afd_zip_case(&w);
        failures += afd_repeat_share(&w);
    }
    printf("app front door journey: A %d commands, %d hex pastes; B %d "
           "commands, %d hex pastes (baseline 45 commands, 15 JSON inputs, "
           "3 hex pastes)\n", w.commands_a, w.hex_a, w.commands_b, w.hex_b);
    if (w.saved_cwd[0] && chdir(w.saved_cwd) != 0)
        printf("  [could not return to %s]\n", w.saved_cwd);
    if (w.saved_home[0])
        (void)setenv("HOME", w.saved_home, 1);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}
#endif /* !_WIN32 */
