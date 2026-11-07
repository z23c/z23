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
#include "chain/chainparams.h"
#include "command/cli_confirm.h"
#include "command/app_copy_build.h"
#include "command/app_selection.h"
#include "command/native_app_launch.h"
#include "command/native_app_front_door.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "mcp/mcp_policy.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"

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
    if (!failures) {
        failures += afd_b_refusals(&w);
        failures += afd_b_plan_shows_root(&w);
        failures += afd_b_receives(&w);
    }
    if (!failures)
        failures += afd_key_note_after_confirm(&w);
    if (!failures)
        failures += afd_quiet_logs(&w);
    if (!failures) {
        failures += afd_receive_missing(&w);
        failures += afd_list_quiet(&w);
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
