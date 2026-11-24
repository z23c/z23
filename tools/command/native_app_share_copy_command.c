/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: app.share-copy, `z23 app share skycombat-1` (see
 * command/native_app_front_door.h). AUTH_OWNER: it runs the owner leaf
 * zcode.package.bundle.sign as an inner call, which skips MCP policy.
 *
 * A copy keeps its release's name ("skycombat/skycombat"), whose publisher
 * half is bound to the origin's key; the Commons refuses another key's
 * release under it (publisher-namespace-conflict). So share publishes the
 * copy under the namespace the owner's own key owns: "k" and 16 hex of the
 * key's fingerprint digest (zcl_app_publisher_namespace), rewriting only
 * the name value of zcode-package.json.
 *
 * Plan: only plan halves. It reads the owner's key when it exists (never
 * makes one: the sign plan would), names the target name, runs the save
 * plan for unsaved edits or, for a clean copy already under the owner's
 * namespace, the sign plan. The plan_id binds the copy's head, those plan
 * ids, the target name (or "no-key") and the output path.
 *
 * Confirm: makes the key if missing, renames the package if needed, saves
 * once when there are edits or a rename, then signs and writes
 * NAME.z23share. A rename changes the package root the copy's build record
 * is keyed by, though no build input changes; so for a clean copy built
 * before the share, the record is carried to the renamed tree when app.build's
 * plan shows the same closure and env roots (app_copy_build_carry), and the
 * copy opens again without a rebuild. Otherwise the reply says to build.
 *
 * A copy with no regular root Makefile is the recipe form: app open opens
 * its kept install, not a build record, and nothing carries across roots.
 * The share then answers opens_now as app open's own read-only checks do
 * for the tree it just signed (adoption, the package roots, the filed
 * receipt, one bin/ program and that program verified against the
 * receipt); when it does not open, build_note names the first refusal and
 * the build hint names the datadir the share ran in.
 *
 * The reply tells the owner what the friend will be asked to confirm (the
 * short and full publisher fingerprint and the exact package root of the
 * shared release, the values the friend's `z23 app open FILE.z23share`
 * shows), to pass on another way, and what the friend must install. */

#include "command/native_command.h"

#include "command/app_copy_build.h"
#include "command/native_app_compose.h"
#include "command/native_app_front_door.h"
#include "command/native_zcode_package_bundle.h"
#include "command/native_zcode_package_copy.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/file_metadata.h"
#include "services/package_lifecycle.h"
#include "services/package_resident.h"
#include "util/authority_receipt.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "util/file_io.h"
#include "util/file_tree_ops.h"
#include "util/path_util.h"
#include "vcs/package_release.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZSH_COMMAND "app.share-copy"
#define ZSH_DOMAIN "zcl.app_share.plan.v1"
#define ZSH_SAVE_LEAF "zcode.package.version.save"
#define ZSH_SIGN_LEAF "zcode.package.bundle.sign"
#define ZSH_META "zcode-package.json"
#define ZSH_META_MAX (64u << 10)
#define ZSH_NAME_MAX (VCS_PACKAGE_RELEASE_NAME_MAX + 1u)

struct zsh {
    const struct json_value *input;
    struct zcl_command_reply *reply;
    const char *datadir;
    const char *name;
    size_t result_cap;
    char dir[APP_COPY_BUILD_PATH];
    char output[APP_COPY_BUILD_PATH];
    char store[APP_COPY_BUILD_PATH];    /* ~/.z23 */
    char key_path[APP_COPY_BUILD_PATH]; /* ~/.z23/zcode_publisher.key */
    char head[65];
    uint8_t fork[32];
    struct app_copy_build_keys before; /* the build keys before a rename */
    bool carry;                        /* before holds them */
    bool opens_now;                    /* the copy opens without a build */
    char build_why[256];               /* why not, when known */
    bool dirty;
    bool have_key;
    uint8_t pubkey[VCS_PACKAGE_RELEASE_PUBKEY_BYTES];
    char old_name[ZSH_NAME_MAX];
    char new_name[ZSH_NAME_MAX]; /* "" until the key is known */
    bool rename;
    char inner_plan[65];
    uint8_t plan_id[32];
#if defined(ZCL_TESTING)
    void (*after_sign)(void *, struct zcl_command_reply *);
    void *test_context;
#endif
};

/* ── the copy, the key and the name ──────────────────────────────────── */

/* The copy, its head and whether it has unsaved edits; the copy is closed
 * again before any inner leaf opens it. */
static bool zsh_state(struct zsh *z)
{
    struct zcl_package_copy copy;
    size_t changes = 0;
    if (!app_copy_build_dir(z->datadir, z->name, z->dir, sizeof(z->dir),
                            z->reply) ||
        !zcl_package_copy_open_as(z->dir, ZCL_PACKAGE_COPY_READ, &copy, z->reply, ZSH_COMMAND))
        return false;
    bool ok = zcl_package_copy_unsaved_readonly(&copy, &changes);
    zcl_hex_encode(copy.head_version, 32, z->head);
    memcpy(z->fork, copy.fork_version, 32);
    zcl_package_copy_close(&copy);
    if (!ok)
        zcl_package_copy_fail(z->reply, "STATUS_FAILED", false,
                              "the copy's status scan failed", z->dir);
    z->dirty = changes > 0;
    return ok;
}

static bool zsh_output_shape(struct zsh *z, bool *available)
{
    enum platform_file_shape shape = platform_file_shape_read(z->output);
    *available = shape == PLATFORM_FILE_SHAPE_MISSING;
    if (shape != PLATFORM_FILE_SHAPE_UNREADABLE) return true;
    zcl_package_copy_fail(z->reply, "OUTPUT_UNAVAILABLE", false,
                          "Cannot inspect the share destination.", z->output);
    return false;
}
static bool zsh_implicit_output(struct zsh *z)
{
    char cwd[APP_COPY_BUILD_PATH], leaf[96];
    const char *base = strrchr(z->dir, '/');
    base = base ? base + 1 : z->dir;
    if (!getcwd(cwd, sizeof(cwd)) || cwd[0] != '/') return false;
    for (unsigned i = 1; i <= 1000; ++i) {
        int n = i == 1 ? snprintf(leaf, sizeof(leaf), "%s%s", base, ZCL_PACKAGE_BUNDLE_SUFFIX) :
            snprintf(leaf, sizeof(leaf), "%s-%u%s", base, i, ZCL_PACKAGE_BUNDLE_SUFFIX);
        if (n <= 0 || (size_t)n >= sizeof(leaf) || !zcl_path_join(z->output, sizeof(z->output), cwd, leaf)) return false;
        bool available;
        if (!zsh_output_shape(z, &available)) return false;
        if (available) return true;
    }
    zcl_package_copy_fail(z->reply, "OUTPUT_UNAVAILABLE", false,
                          "No free share filename is available.", "app.share-copy");
    return false;
}
static bool zsh_output(struct zsh *z)
{
    const char *given = zcl_package_copy_str(z->input, "output");
    if (!given) {
        if (zsh_implicit_output(z)) return true;
        if (z->reply->status != ZCL_COMMAND_STATUS_PASSED) return false;
    } else {
        int n = snprintf(z->output, sizeof(z->output), "%s", given);
        if (n > 0 && (size_t)n < sizeof(z->output) && z->output[0] == '/') {
            bool available;
            if (!zsh_output_shape(z, &available)) return false;
            if (available) return true;
            zcl_package_copy_fail(z->reply, "OUTPUT_EXISTS", false,
                "a share file is never overwritten; move it or name another output", z->output);
            return false;
        }
    }
    const char *evidence = given && strlen(given) < sizeof(z->reply->error.evidence)
        ? given : "output path unavailable or too long";
    zcl_package_copy_fail(z->reply, "BAD_OUTPUT", false,
                          "output must be an absolute bounded path", evidence);
    return false;
}

/* The key bundle.sign uses; its public half when the file exists. Reading
 * never makes a key. */
static bool zsh_key_read(struct zsh *z)
{
    const char *home = getenv("HOME");
    struct plugin_dist_published why;
    struct stat st;
    if (!home || home[0] != '/' ||
        !zcl_path_join(z->store, sizeof(z->store), home, ".z23") ||
        !zcl_path_join(z->key_path, sizeof(z->key_path), z->store,
                       "zcode_publisher.key")) {
        zcl_package_copy_fail(z->reply, "PUBLISHER_KEY_UNAVAILABLE", false,
                              "HOME must be an absolute directory where "
                              "~/.z23 can hold the owner's key", ZSH_COMMAND);
        return false;
    }
    z->have_key = stat(z->key_path, &st) == 0 &&
                  plugin_dist_release_key_sign(z->key_path, NULL, z->pubkey,
                                               NULL, &why) == PLUGIN_DIST_OK;
    return true;
}

static bool zsh_meta_path(const struct zsh *z, char *out, size_t cap)
{
    return zcl_path_join(out, cap, z->dir, ZSH_META);
}

/* The package name now, and the one it publishes under. */
static bool zsh_names(struct zsh *z)
{
    char path[APP_COPY_BUILD_PATH], ns[ZCL_APP_NAMESPACE_LEN];
    char *text = NULL;
    size_t len = 0;
    struct json_value meta;
    json_init(&meta);
    bool ok = zsh_meta_path(z, path, sizeof(path)) &&
              zcl_read_whole_file_text(path, ZSH_META_MAX, &text, &len,
                                       ZSH_COMMAND) &&
              json_read(&meta, text, len);
    const struct json_value *v = ok ? json_get(&meta, "name") : NULL;
    const char *name = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    const char *slash = name ? strchr(name, '/') : NULL;
    ok = slash && strlen(name) < sizeof(z->old_name);
    if (ok)
        (void)snprintf(z->old_name, sizeof(z->old_name), "%s", name);
    if (ok && z->have_key && zcl_app_publisher_namespace(z->pubkey, ns))
        (void)snprintf(z->new_name, sizeof(z->new_name), "%s%s", ns, slash);
    json_free(&meta);
    free(text);
    if (!ok)
        zcl_package_copy_fail(z->reply, "PACKAGE_INVALID", false, "the "
                              "copy's zcode-package.json has no package "
                              "name", z->dir);
    z->rename = !z->new_name[0] || strcmp(z->new_name, z->old_name) != 0;
    return ok;
}

/* Rewrite only the name value: the first "<old>" after the "name" key. */
static bool zsh_rename(struct zsh *z)
{
    char path[APP_COPY_BUILD_PATH], quoted[ZSH_NAME_MAX + 2u];
    char *text = NULL, *out = NULL;
    size_t len = 0;
    (void)snprintf(quoted, sizeof(quoted), "\"%s\"", z->old_name);
    bool ok = zsh_meta_path(z, path, sizeof(path)) &&
              zcl_read_whole_file_text(path, ZSH_META_MAX, &text, &len,
                                       ZSH_COMMAND);
    char *key = ok ? strstr(text, "\"name\"") : NULL;
    char *at = key ? strstr(key, quoted) : NULL;
    size_t old_len = strlen(quoted), new_len = strlen(z->new_name) + 2u;
    if (at)
        out = zcl_malloc(len - old_len + new_len + 1u, "app.share.meta");
    if (out) {
        size_t head = (size_t)(at - text);
        memcpy(out, text, head);
        (void)snprintf(out + head, new_len + 1u, "\"%s\"", z->new_name);
        memcpy(out + head + new_len, at + old_len, len - head - old_len + 1u);
        ok = authority_receipt_write_atomic(z->dir, ZSH_META,
                                            (const uint8_t *)out,
                                            len - old_len + new_len, NULL, 0);
    }
    ok = ok && out;
    free(out);
    free(text);
    if (!ok)
        zcl_package_copy_fail(z->reply, "RENAME_FAILED", false, "the package "
                              "name in zcode-package.json could not be "
                              "rewritten", path);
    return ok;
}

/* ── plan ────────────────────────────────────────────────────────────── */

static bool zsh_leaf_input(struct zsh *z, bool sign, struct json_value *in)
{
    const char *kv[] = {"dir", z->dir, "datadir", sign ? z->datadir : NULL,
                        "output", sign ? z->output : NULL};
    return zcl_app_input(in, kv, 6) && (!sign || zcl_app_input_day(z->input, in));
}

/* The plan half the copy allows now: the save plan for unsaved edits, or
 * the sign plan for a clean copy already under the owner's namespace. */
static bool zsh_plan(struct zsh *z, struct zcl_command_reply *inner)
{
    struct json_value in;
    bool save = z->dirty, sign = !z->dirty && z->have_key && !z->rename;
    const char *leaf = save ? ZSH_SAVE_LEAF : ZSH_SIGN_LEAF;
    z->inner_plan[0] = '\0';
    if (!save && !sign) {
        zcl_command_reply_init(inner, "zcl.app_share.inner.v1");
    } else if (!zcl_app_inner_call_built(leaf, &in,
                                         zsh_leaf_input(z, sign, &in),
                                         inner)) {
        zcl_app_inner_fail(z->reply, inner, false);
        zcl_command_reply_free(inner);
        return false;
    } else if (zcl_app_inner_str(inner, "plan_id")) {
        (void)snprintf(z->inner_plan, sizeof(z->inner_plan), "%s",
                       zcl_app_inner_str(inner, "plan_id"));
    }
    const char *parts[] = {z->dir, z->head, z->output, z->inner_plan,
                           z->new_name[0] ? z->new_name : "no-key"};
    zcl_app_plan_id(ZSH_DOMAIN, parts, 5, z->plan_id);
    return true;
}

static void zsh_plan_reply(struct zsh *z, const struct zcl_command_reply *in)
{
    struct json_value *d = &z->reply->data;
    char next[APP_COPY_BUILD_PATH + 160], as[ZSH_NAME_MAX + 32];
    const char *slash = strchr(z->old_name, '/');
    (void)snprintf(as, sizeof(as), "%s%s",
                   z->new_name[0] ? z->new_name : "<your new key>",
                   z->new_name[0] ? "" : slash);
    (void)json_push_kv_str(d, "stage", "plan");
    (void)json_push_kv_str(d, "copy", z->name);
    (void)json_push_kv_str(d, "output", z->output);
    (void)json_push_kv_str(d, "name", z->old_name);
    (void)json_push_kv_str(d, "publishes_as", as);
    (void)json_push_kv_bool(d, "saves_first", z->dirty || z->rename);
    (void)json_push_kv_bool(d, "makes_key", !z->have_key);
    zcl_app_push_publisher(d, zcl_app_inner_str(in, "publisher_fingerprint"));
    zcl_package_copy_push_root(d, "plan_id", z->plan_id);
    (void)json_push_kv_bool(d, "executed", false);
    if (zcl_app_hint(next, sizeof(next),
                     zcl_package_copy_str(z->input, "datadir"),
                     "share %s --yes", z->name))
        (void)json_push_kv_str(d, "next", next);
}

/* ── confirm ─────────────────────────────────────────────────────────── */

/* Make the key bundle.sign would make on first use, then read it. */
static bool zsh_key_make(struct zsh *z)
{
    char made[PLUGIN_HEX_PUBLIC_KEY + 1];
    if (z->have_key)
        return true;
    if (zcl_mkdir_p(z->store, 0700).ok)
        (void)plugin_keygen(z->key_path, made);
    if (!zsh_key_read(z))
        return false;
    if (!z->have_key)
        zcl_package_copy_fail(z->reply, "PUBLISHER_KEY_REFUSED", false,
                              "the owner's publisher key must be a private "
                              "(0600) 32-byte key file", z->key_path);
    return z->have_key;
}

/* ── the recipe form: what app open's read-only checks answer ───────── */

#if !defined(_WIN32)
/* The build-form rule app.build and app open route by: a regular root
 * Makefile is the make form, where the share stays as it was. */
static bool zsh_recipe_form(const struct zsh *z)
{
    char path[APP_COPY_BUILD_PATH];
    struct stat st;
    return zcl_path_join(path, sizeof(path), z->dir, "Makefile") &&
           !(lstat(path, &st) == 0 && S_ISREG(st.st_mode));
}

/* The adoption app open requires, refused as it refuses it. */
static bool zsh_adopted(struct zsh *z, const struct zcl_package_copy *copy,
                        struct zcl_command_reply *why)
{
    enum zcl_package_copy_adoption a =
        zcl_package_copy_adopted(z->datadir, copy, NULL);
    if (a == ZCL_PACKAGE_COPY_ADOPTED || a == ZCL_PACKAGE_COPY_RECEIVED_TRUSTED)
        return true;
    zcl_package_copy_fail(why, "NOT_ADOPTED", false, "only an adopted copy, "
                          "or a received copy whose publisher and root the "
                          "owner confirmed, opens",
                          zcl_package_copy_adoption_name(a));
    return false;
}

/* The kept install of this exact package, as app open inspects it: the
 * filed and revalidated receipt, one bin/ program, and that program
 * verified against the receipt. 1 when it opens, 0 when nothing is
 * installed for this root, -1 with the refusal in why. */
static int zsh_recipe_kept(struct zsh *z, const uint8_t package_root[32],
                           struct zcl_command_reply *why)
{
    struct package_lifecycle_step step;
    struct package_lifecycle_programs programs;
    struct package_resident_artifact installed;
    bool here = false;
    struct zcl_result r = package_lifecycle_installed_inspect(z->datadir,
        package_root, &step, &here);
    if (!r.ok) {
        zcl_package_copy_fail(why, "RECIPE_OPEN_REFUSED", false,
                              "the kept install could not be inspected",
                              r.message);
        return -1;
    }
    if (!here)
        return 0;
    if (!step.has_receipt) {
        zcl_package_copy_fail(why, "RECIPE_OPEN_REFUSED", false,
                              "the kept install has no build receipt", z->dir);
        return -1;
    }
    r = package_lifecycle_installed_programs(z->datadir, package_root,
                                             &programs);
    if (!r.ok || programs.count == 0 ||
        strncmp(programs.output[0], "bin/", 4) != 0) {
        zcl_package_copy_fail(why, "RECIPE_OPEN_REFUSED", false,
                              "the kept install names no bin/ program",
                              r.ok ? z->dir : r.message);
        return -1;
    }
    r = package_resident_artifact_read(z->datadir, package_root,
                                       step.receipt_id, programs.output[0],
                                       &installed);
    if (!r.ok) {
        zcl_package_copy_fail(why, "RECIPE_OPEN_REFUSED", false,
                              "the installed program did not verify against "
                              "its receipt", r.message);
        return -1;
    }
    return 1;
}

/* What app open says of a saved tree with no kept install: this version
 * was never built. The fork is the saved copy's own. The store path names
 * why when even that is refused. */
static void zsh_recipe_unbuilt(struct zsh *z, const uint8_t fork[32],
                               struct zcl_command_reply *why)
{
    struct app_copy_build_store store;
    struct stat st;
    if (!app_copy_build_store(z->datadir, fork, &store, why))
        return;
    if (stat(store.work, &st) == 0)
        zcl_package_copy_fail(why, "STALE_BUILD", false, "this saved version "
                              "(or toolchain) is not built yet; run z23 app "
                              "build first", z->name);
    else
        zcl_package_copy_fail(why, "NOT_BUILT", false, "this copy has not "
                              "been built; run z23 app build first", z->name);
}

/* Whether the recipe-form copy just signed opens now, read as app open
 * reads it and never failing the share: the reply names the first check
 * that says it does not. */
static void zsh_recipe_ready(struct zsh *z)
{
    struct zcl_command_reply why;
    struct zcl_package_copy copy;
    uint8_t package_root[32], dependency_root[32];
    int kept = -1;
    zcl_command_reply_init(&why, "zcl.app_share.inner.v1");
    if (zcl_package_copy_open_as(z->dir, ZCL_PACKAGE_COPY_READ, &copy, &why,
                                 ZSH_COMMAND)) {
        if (zsh_adopted(z, &copy, &why) &&
            app_copy_build_roots(z->datadir, z->dir, &copy, package_root,
                                 dependency_root, &why))
            kept = zsh_recipe_kept(z, package_root, &why);
        if (kept == 0)
            zsh_recipe_unbuilt(z, copy.fork_version, &why);
        zcl_package_copy_close(&copy);
    }
    z->opens_now = kept > 0;
    if (!z->opens_now && why.error.code[0])
        (void)snprintf(z->build_why, sizeof(z->build_why), "%s: %s",
                       why.error.code, why.error.message);
    zcl_command_reply_free(&why);
}
#endif

/* Whether the copy opens now with no rebuild: its build is current, or the
 * build from before the rename is carried to the renamed tree. A recipe
 * form copy has no build record; app open's own checks answer for it.
 * Never fails the share: a copy that does not open is told to build. */
static void zsh_keep_build(struct zsh *z)
{
    struct app_copy_build_keys now;
    struct zcl_command_reply why;
#if !defined(_WIN32)
    if (zsh_recipe_form(z)) {
        zsh_recipe_ready(z);
        return;
    }
#endif
    zcl_command_reply_init(&why, "zcl.app_share.inner.v1");
    bool keys = app_copy_build_keys(z->datadir, z->dir, &now, &why);
    z->opens_now = keys && now.hit;
    if (keys && !now.hit && z->carry)
        z->opens_now = app_copy_build_carry(z->datadir, z->fork, &z->before,
                                            &now, &why);
    if (!z->opens_now && why.error.code[0])
        (void)snprintf(z->build_why, sizeof(z->build_why), "%s: %s",
                       why.error.code, why.error.message);
    zcl_command_reply_free(&why);
}

/* The build keys before the rename, for zsh_keep_build. Only a clean copy
 * carries: with edits, the saved version is a new build. */
static void zsh_take_build(struct zsh *z)
{
    struct zcl_command_reply why;
    if (z->dirty || !z->rename)
        return;
    zcl_command_reply_init(&why, "zcl.app_share.inner.v1");
    z->carry = app_copy_build_keys(z->datadir, z->dir, &z->before, &why) &&
               z->before.hit;
    zcl_command_reply_free(&why);
}

#define ZSH_FRIEND_NEEDS \
    "Z23 (install instructions: https://z23.sh), a C compiler, make and any app-specific build dependencies"

/* The friend opens the file in their own datadir, so that command carries
 * none; it names the file as written. */
static bool zsh_commit_next(const struct zsh *z, char *next, size_t cap)
{
    char friend_cmd[APP_COPY_BUILD_PATH + 32];
    char build[APP_COPY_BUILD_PATH + 64];
    const char *base = strrchr(z->output, '/');
    if (!zcl_app_hint_neutral(friend_cmd, sizeof(friend_cmd), NULL, "open %s",
                              base ? base + 1 : z->output)) return false;
    int n = snprintf(next, cap, "send the file; your friend needs %s; your "
                     "friend runs: %s", ZSH_FRIEND_NEEDS, friend_cmd);
    if (n <= 0 || (size_t)n >= cap) return false;
    if (z->opens_now) return true;
    if (!zcl_app_hint(build, sizeof(build), z->datadir,
                      "build %s", z->name)) return false;
    int appended = snprintf(next + n, cap - (size_t)n, "; run %s before opening your copy again", build);
    return appended > 0 && (size_t)appended < cap - (size_t)n;
}

/* One line saying what the friend is asked to confirm, to pass on another
 * way: the shared release's own fingerprint and package root. */
static bool zsh_share_line(const struct zsh *z,
                           const struct zcl_command_reply *s, char *line,
                           size_t cap)
{
    char brief[ZCL_APP_SHORT_FINGERPRINT_LEN];
    const char *full = zcl_app_inner_str(s, "publisher_fingerprint");
    const char *root = zcl_app_inner_str(s, "package_root");
    const char *semver = zcl_app_inner_str(s, "semver");
    if (!full || !root || !zcl_app_short_fingerprint(full, brief)) return false;
    int n = snprintf(line, cap, "share %s%s%s file %s. Your friend will be "
                   "asked to confirm: fingerprint %s (full %s), version root "
                   "%s. Tell them these another way so they can check.",
                   z->new_name, semver ? " " : "", semver ? semver : "",
                   z->output, brief, full ? full : "?", root ? root : "?");
    return n > 0 && (size_t)n < cap;
}

static bool zsh_copy_identity(struct zsh *z, const struct zcl_command_reply *s)
{
    struct json_value *d = &z->reply->data;
    const char *keys[] = {"name", "release_id", "package_root",
                          "version", "share_file"};
    const char *output = zcl_app_inner_str(s, "share_file");
    const char *publisher = zcl_app_inner_str(s, "publisher_fingerprint");
    char brief[ZCL_APP_SHORT_FINGERPRINT_LEN];
    if (!output || strcmp(output, z->output) || !publisher ||
        !zcl_app_short_fingerprint(publisher, brief) ||
        !json_push_kv_str(d, "stage", "commit") || !json_push_kv_str(d, "copy", z->name)) return false;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *value = zcl_app_inner_str(s, keys[i]);
        if (!value || !json_push_kv_str(d, keys[i], value)) return false;
    }
    const char *semver = zcl_app_inner_str(s, "semver");
    if (semver && !json_push_kv_str(d, "semver", semver)) return false;
    return json_push_kv_str(d, "publisher_fingerprint", publisher) &&
        json_push_kv_str(d, "publisher", brief);
}

static bool zsh_commit_reply(struct zsh *z, const struct zcl_command_reply *s)
{
    struct json_value *d = &z->reply->data;
    char line[APP_COPY_BUILD_PATH + 512];
    char next[2 * APP_COPY_BUILD_PATH + 512];
    if (!zsh_copy_identity(z, s) || !json_push_kv_bool(d, "renamed", z->rename) ||
        !json_push_kv_bool(d, "opens_now", z->opens_now)) return false;
    if (!z->opens_now && z->build_why[0])
        if (!json_push_kv_str(d, "build_note", z->build_why)) return false;
    return json_push_kv_str(d, "friend_needs", ZSH_FRIEND_NEEDS) &&
        zsh_share_line(z, s, line, sizeof(line)) && json_push_kv_str(d, "share_line", line) &&
        zsh_commit_next(z, next, sizeof(next)) && json_push_kv_str(d, "next", next) &&
        json_push_kv_bool(d, "executed", false);
}

/* Match the library's conservative error-envelope reserve, but use the
 * actual JSON-escaped error field lengths instead of a fixed facts cap. */
static size_t zsh_error_facts_cap(const struct zcl_command_reply *reply)
{
    const struct zcl_command_error *e = &reply->error;
    const char *fields[] = {e->code, e->code, e->message, e->phase, e->current_state,
                            e->next_action, e->evidence, e->failure_id};
    size_t reserve = 1000u + 50u;
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        struct json_value v; json_init(&v); json_set_str(&v, fields[i]);
        size_t n = v.type == JSON_STR ? json_write(&v, NULL, 0) : 0;
        json_free(&v);
        if (!n || n > ZCL_COMMAND_ERROR_BUDGET - reserve) return 0;
        reserve += n;
    }
    return ZCL_COMMAND_ERROR_BUDGET - reserve;
}

static bool zsh_store_facts(struct zsh *z, struct json_value *facts, size_t cap)
{
    size_t n = json_write(facts, NULL, 0);
    return n && n <= cap && json_push_kv(&z->reply->data, "failure_facts", facts);
}

static bool zsh_full_facts(struct zsh *z, const struct zcl_command_reply *inner,
                           struct json_value *facts, bool *omitted)
{
    const char *keys[] = {"name", "release_id", "package_root", "version", "publisher_fingerprint"};
    bool ok = json_push_kv_str(facts, "requested_output", z->output);
    const char *file = zcl_app_inner_str(inner, "share_file");
    *omitted = !file || strcmp(file, z->output);
    if (ok && file && !strcmp(file, z->output)) ok = json_push_kv_str(facts, "share_file", file);
    for (size_t i = 0; ok && i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const char *value = zcl_app_inner_str(inner, keys[i]);
        if (value) ok = json_push_kv_str(facts, keys[i], value);
        else *omitted = true;
    }
    const char *semver = zcl_app_inner_str(inner, "semver");
    if (ok && semver) ok = json_push_kv_str(facts, "semver", semver);
    return ok && (!*omitted || json_push_kv_bool(facts, "details_unavailable", true));
}

/* After failure, prefer full identity; if it cannot fit, retain the exact
 * requested output alone and explicitly report the omitted details. */
static bool zsh_failure_facts(struct zsh *z, const struct zcl_command_reply *inner)
{
    struct json_value facts; json_init(&facts); json_set_object(&facts);
    bool omitted = false;
    bool ok = zsh_full_facts(z, inner, &facts, &omitted);
    size_t cap = zsh_error_facts_cap(z->reply);
    bool stored = ok && zsh_store_facts(z, &facts, cap);
    if (!stored) {
        json_free(&facts); json_init(&facts); json_set_object(&facts);
        ok = json_push_kv_str(&facts, "requested_output", z->output) &&
            json_push_kv_bool(&facts, "details_unavailable", true);
        stored = ok && zsh_store_facts(z, &facts, cap);
        if (!stored) {
            json_free(&facts); json_init(&facts); json_set_object(&facts);
            if (json_push_kv_bool(&facts, "details_unavailable", true))
                (void)zsh_store_facts(z, &facts, cap);
        }
    }
    json_free(&facts);
    return stored && !omitted;
}

static void zsh_commit_unreported(struct zsh *z, const struct zcl_command_reply *inner, const char *code)
{
    const char *evidence = strlen(z->output) < sizeof(z->reply->error.evidence) ? z->output :
        "Output path omitted; consult the original share plan.";
    json_free(&z->reply->data); json_init(&z->reply->data); json_set_object(&z->reply->data);
    zcl_package_copy_fail(z->reply, code, true,
        "Share publication or file creation may have completed; inspect the output before retrying. Recovery details are unavailable.", evidence);
    (void)snprintf(z->reply->error.next_action, sizeof(z->reply->error.next_action),
        "Inspect the exact output from the share plan before retrying.");
    if (zsh_failure_facts(z, inner))
        (void)snprintf(z->reply->error.message, sizeof(z->reply->error.message),
            "Share publication or file creation may have completed; inspect the output before retrying.");
}

/* One save of the edits and the rename together. */
static bool zsh_save(struct zsh *z, struct zcl_command_reply *inner)
{
    struct json_value in;
    bool ok = false;
    if (zsh_leaf_input(z, false, &in)) {
        ok = zcl_app_inner_plan_confirm(ZSH_SAVE_LEAF, &in, inner);
    } else {
        zcl_command_reply_init(inner, "zcl.app_share.inner.v1");
        zcl_package_copy_fail(inner, "ALLOC", false, "inner input",
                              ZSH_SAVE_LEAF);
    }
    json_free(&in);
    return ok;
}

static bool zsh_prepare_name(struct zsh *z)
{
    bool made = !z->have_key;
    if (!zsh_key_make(z) || !zsh_names(z) || (z->rename && !zsh_rename(z))) {
        z->reply->error.mutated = made && z->have_key;
        return false;
    }
    return true;
}

static void zsh_commit(struct zsh *z)
{
    struct json_value in;
    struct zcl_command_reply inner;
    if (!zcl_package_copy_plan_matches(z->input, z->plan_id, z->reply,
                                       ZSH_COMMAND))
        return;
    zsh_take_build(z);
    if (!zsh_prepare_name(z))
        return;
    bool mutated = z->rename;
    if (z->dirty || z->rename) {
        if (!zsh_save(z, &inner)) {
            zcl_app_inner_fail(z->reply, &inner, mutated);
            zcl_command_reply_free(&inner);
            return;
        }
        zcl_command_reply_free(&inner);
        mutated = true;
    }
    bool ok = false;
    if (zsh_leaf_input(z, true, &in)) {
        ok = zcl_app_inner_plan_confirm(ZSH_SIGN_LEAF, &in, &inner);
    } else {
        zcl_command_reply_init(&inner, "zcl.app_share.inner.v1");
        zcl_package_copy_fail(&inner, "ALLOC", false, "inner input",
                              ZSH_SIGN_LEAF);
    }
    json_free(&in);
    if (ok) {
        z->reply->error.mutated = true;
        zsh_keep_build(z);
#if defined(ZCL_TESTING)
        if (z->after_sign) z->after_sign(z->test_context, &inner);
#endif
        if (!zsh_commit_reply(z, &inner)) zsh_commit_unreported(z, &inner, "REPLY_FAILED");
        else if (z->reply->status == ZCL_COMMAND_STATUS_PASSED) {
            size_t n = json_write(&z->reply->data, NULL, 0);
            if (!n || n > z->result_cap) zsh_commit_unreported(z, &inner, "OBSERVATION_TOO_LARGE");
        }
    } else {
        zcl_app_inner_fail(z->reply, &inner, mutated);
    }
    zcl_command_reply_free(&inner);
}

static void zsh_handle(const struct zcl_command_request *request,
                       struct zcl_command_reply *reply,
                       void (*after_sign)(void *, struct zcl_command_reply *), void *context)
{
    struct zcl_command_reply inner;
    struct zsh *z = request && reply
                        ? zcl_calloc(1, sizeof(*z), "app.share.state")
                        : NULL;
    if (!z) {
        if (reply)
            zcl_package_copy_fail(reply, "ALLOC", false, "app.share state",
                                  ZSH_COMMAND);
        return;
    }
    z->input = request->input;
    z->reply = reply;
    z->result_cap = request->success_data_budget_provided ? request->success_data_budget : ZCL_COMMAND_RESULT_BUDGET;
#if defined(ZCL_TESTING)
    z->after_sign = after_sign; z->test_context = context;
#else
    (void)after_sign; (void)context;
#endif
    z->name = zcl_package_copy_str(request->input, "copy");
    z->datadir = zcl_package_copy_datadir(request->input, reply, ZSH_COMMAND);
    if (z->datadir && zsh_state(z) && zsh_output(z) && zsh_key_read(z) &&
        zsh_names(z) && zsh_plan(z, &inner)) {
        if (zcl_package_copy_confirmed(request->input))
            zsh_commit(z);
        else
            zsh_plan_reply(z, &inner);
        zcl_command_reply_free(&inner);
    }
    free(z);
}

void zcl_native_handle_app_share_copy(const struct zcl_command_request *request,
                                     struct zcl_command_reply *reply)
{
    zsh_handle(request, reply, NULL, NULL);
}

#if defined(ZCL_TESTING)
void zcl_test_app_share_copy(const struct zcl_command_request *request,
    struct zcl_command_reply *reply, void (*after_sign)(void *, struct zcl_command_reply *), void *context)
{
    zsh_handle(request, reply, after_sign, context);
}
#endif
