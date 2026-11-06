/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the skycombat remix journey on local fixtures — fork a published
 * package, save and restore versions, share a release that names its parent,
 * and see the parent in zcode.commons.lineage. Refusals: an unknown root, a
 * share without changes, unsaved changes, a forged fork record and a broken
 * commit log. Every leaf runs the way the CLI and MCP run it: the registry
 * input contract first, then the bound handler. */

#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "core/uint256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "mcp/mcp_policy.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include "vcs/vcs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZPF_SOURCE "apps/skycombat"
#define ZPF_EDITED "src/philosophical_test.c"
#define ZPF_DAY 20400
#define ZPF_ORIGIN_SEED 0x31
#define ZPF_PLAYER_SEED 0x52
#define ZPF_ENVELOPE_MARGIN 1024u

struct zpf_world {
    char root[512];
    char datadir[600];
    char workspace[600];
    char copy[600];
    uint8_t origin_release[32];
    uint8_t origin_package[32];
    char origin_release_hex[65];
    char origin_package_hex[65];
};

struct zpf_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static const struct zcl_command_spec *zpf_leaf(const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t i = 0; reg && i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

static void zpf_begin(struct zpf_call *c)
{
    memset(c, 0, sizeof(*c));
    json_init(&c->input);
    json_set_object(&c->input);
    zcl_command_reply_init(&c->reply, "zcl.test.zcode_package_fork.v1");
}

static void zpf_end(struct zpf_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Validate against the leaf's declared input contract, then run the handler
 * the leaf binds. False when the leaf is missing or the contract refuses. */
static bool zpf_run(const char *path, struct zpf_call *c)
{
    const struct zcl_command_spec *spec = zpf_leaf(path);
    char why[256];
    if (!spec || !spec->handler ||
        !zcl_command_registry_input_validate(spec, &c->input, why,
                                             sizeof(why))) {
        printf("  [%s refused by contract: %s]\n", path,
               spec ? why : "no leaf");
        return false;
    }
    c->request.input = &c->input;
    c->request.spec = spec;
    c->request.invoked_name = spec->path;
    spec->handler(&c->request, &c->reply);
    /* The CLI and MCP serialize the reply under the leaf's budget; keep a
     * margin for the result envelope around `data`. */
    size_t data_bytes = json_write(&c->reply.data, NULL, 0);
    size_t budget = (size_t)spec->budget_bytes;
    if (budget && data_bytes + ZPF_ENVELOPE_MARGIN > budget) {
        printf("  [%s reply %zu bytes over budget %zu]\n", path, data_bytes,
               (size_t)spec->budget_bytes);
        return false;
    }
    return true;
}

static bool zpf_passed(const struct zpf_call *c)
{
    if (c->reply.status == ZCL_COMMAND_STATUS_PASSED)
        return true;
    printf("  [refused %s: %s]\n", c->reply.error.code,
           c->reply.error.message);
    return false;
}

static bool zpf_refused(const struct zpf_call *c, const char *code)
{
    bool ok = c->reply.status != ZCL_COMMAND_STATUS_PASSED &&
              strcmp(c->reply.error.code, code) == 0;
    if (!ok)
        printf("  [wanted %s, got status=%d code=%s: %s]\n", code,
               (int)c->reply.status, c->reply.error.code,
               c->reply.error.message);
    return ok;
}

static const char *zpf_data_str(const struct zpf_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    const char *s = v ? json_get_str(v) : NULL;
    return s ? s : "";
}

static bool zpf_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool zpf_sign(uint8_t seed, const uint8_t digest[32],
                     uint8_t signature[64])
{
    struct privkey sk;
    struct pubkey pk;
    struct uint256 hash;
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    memcpy(hash.data, digest, 32);
    if (!zpf_keypair(seed, &sk, &pk) ||
        !privkey_sign_compact(&sk, &hash, compact))
        return false;
    memcpy(signature, compact + 1, 64);
    return true;
}

static bool zpf_pubkey_hex(uint8_t seed, char out[67])
{
    struct privkey sk;
    struct pubkey pk;
    if (!zpf_keypair(seed, &sk, &pk))
        return false;
    zcl_hex_encode(pk.vch, pk.size, out);
    return true;
}

static bool zpf_append(const char *dir, const char *rel, const char *text)
{
    char path[900];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, "ab");
    bool ok = f && fputs(text, f) >= 0;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

static bool zpf_write(const char *dir, const char *rel, const char *text)
{
    char path[900];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, "wb");
    bool ok = f && fputs(text, f) >= 0;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

/* Byte equality of one copy file against the original package source. */
static bool zpf_same_as_source(const char *dir, const char *rel)
{
    char a[900], b[900];
    (void)snprintf(a, sizeof(a), "%s/%s", dir, rel);
    (void)snprintf(b, sizeof(b), "%s/%s", ZPF_SOURCE, rel);
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    bool same = fa && fb;
    while (same) {
        int ca = fgetc(fa), cb = fgetc(fb);
        same = ca == cb;
        if (ca == EOF || cb == EOF)
            break;
    }
    if (fa)
        fclose(fa);
    if (fb)
        fclose(fb);
    return same;
}

/* Publish the untouched skycombat tree as publisher A's first release, the
 * same way a maintainer would: prepare, sign offline, local commit. */
static bool zpf_publish_origin(struct zpf_world *w)
{
    struct privkey sk;
    struct pubkey pk;
    struct vcs_package_prepare_options options = {
        .dir = ZPF_SOURCE, .publisher_sequence = 1,
        .reward_address = "", .chain_id = "zclassic-main",
    };
    struct vcs_package_prepared prepared;
    char detail[256] = {0};
    if (!zpf_keypair(ZPF_ORIGIN_SEED, &sk, &pk))
        return false;
    memcpy(options.publisher_pubkey, pk.vch, 33);
    if (vcs_package_prepare(&options, &prepared, detail, sizeof(detail)) !=
        VCS_PACKAGE_PREPARE_OK) {
        printf("  [prepare skycombat: %s]\n", detail);
        return false;
    }
    struct vcs_package_release release = prepared.release;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = zpf_sign(ZPF_ORIGIN_SEED, prepared.signing_digest,
                       release.signature) &&
              vcs_package_release_serialize(&release, &wire, &wire_len) ==
                  VCS_PACKAGE_RELEASE_OK;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.zcode_package_fork.v1");
    if (ok) {
        const struct zcl_native_local_publication publication = {
            .datadir = w->datadir, .source_directory = ZPF_SOURCE,
            .release_wire = wire, .release_wire_len = wire_len,
            .manifest_wire = prepared.manifest_wire,
            .manifest_wire_len = prepared.manifest_wire_len,
            .recipe_wire = prepared.recipe_wire,
            .recipe_wire_len = prepared.recipe_wire_len,
            .has_day = true, .day = ZPF_DAY,
        };
        zcl_native_zcode_local_publication_commit(&publication, &reply);
        ok = reply.status == ZCL_COMMAND_STATUS_PASSED;
        if (!ok)
            printf("  [origin publish: %s %s]\n", reply.error.code,
                   reply.error.message);
    }
    memcpy(w->origin_release, prepared.signing_digest, 32);
    memcpy(w->origin_package, prepared.package_root, 32);
    zcl_hex_encode(w->origin_release, 32, w->origin_release_hex);
    zcl_hex_encode(w->origin_package, 32, w->origin_package_hex);
    zcl_command_reply_free(&reply);
    free(wire);
    vcs_package_prepared_free(&prepared);
    return ok;
}

static bool zpf_world_init(struct zpf_world *w)
{
    memset(w, 0, sizeof(*w));
    if (!test_mkdtemp(w->root, sizeof(w->root), "zcode_package_fork"))
        return false;
    (void)snprintf(w->datadir, sizeof(w->datadir), "%s/datadir", w->root);
    (void)snprintf(w->workspace, sizeof(w->workspace), "%s/ws", w->root);
    (void)snprintf(w->copy, sizeof(w->copy), "%s/my-skycombat", w->root);
    return mkdir(w->datadir, 0700) == 0 && mkdir(w->workspace, 0700) == 0 &&
           zpf_publish_origin(w);
}

/* One fork call; plan_id NULL means the plan half. */
static void zpf_fork_input(struct zpf_call *c, const struct zpf_world *w,
                           const char *root, const char *destination,
                           const char *plan_id)
{
    zpf_begin(c);
    (void)json_push_kv_str(&c->input, "root", root);
    (void)json_push_kv_str(&c->input, "destination", destination);
    (void)json_push_kv_str(&c->input, "datadir", w->datadir);
    if (plan_id) {
        (void)json_push_kv_str(&c->input, "plan_id", plan_id);
        (void)json_push_kv_bool(&c->input, "confirm", true);
    }
}

/* Plan then commit one mutating leaf whose input `c` already holds. */
static bool zpf_plan_commit(const char *path, struct zpf_call *c,
                            char plan_id[65])
{
    if (!zpf_run(path, c) || !zpf_passed(c))
        return false;
    (void)snprintf(plan_id, 65, "%s", zpf_data_str(c, "plan_id"));
    if (strlen(plan_id) != 64)
        return false;
    zcl_command_reply_free(&c->reply);
    zcl_command_reply_init(&c->reply, "zcl.test.zcode_package_fork.v1");
    (void)json_push_kv_str(&c->input, "plan_id", plan_id);
    (void)json_push_kv_bool(&c->input, "confirm", true);
    return zpf_run(path, c) && zpf_passed(c);
}

static bool zpf_fork(const struct zpf_world *w, const char *root,
                     const char *destination, char version[65])
{
    struct zpf_call c;
    char plan_id[65] = {0};
    zpf_fork_input(&c, w, root, destination, NULL);
    bool ok = zpf_plan_commit("zcode.package.fork", &c, plan_id);
    if (ok && version)
        (void)snprintf(version, 65, "%s", zpf_data_str(&c, "version"));
    zpf_end(&c);
    return ok;
}

static bool zpf_save(const char *dir, char version[65])
{
    struct zpf_call c;
    char plan_id[65] = {0};
    zpf_begin(&c);
    (void)json_push_kv_str(&c.input, "dir", dir);
    bool ok = zpf_plan_commit("zcode.package.version.save", &c, plan_id);
    if (ok && version)
        (void)snprintf(version, 65, "%s", zpf_data_str(&c, "version"));
    zpf_end(&c);
    return ok;
}

static bool zpf_restore(const char *dir, const char *version)
{
    struct zpf_call c;
    char plan_id[65] = {0};
    zpf_begin(&c);
    (void)json_push_kv_str(&c.input, "dir", dir);
    (void)json_push_kv_str(&c.input, "version", version);
    bool ok = zpf_plan_commit("zcode.package.version.restore", &c, plan_id);
    zpf_end(&c);
    return ok;
}

static void zpf_share_input(struct zpf_call *c, const struct zpf_world *w,
                            const char *dir)
{
    char pubkey[67];
    zpf_begin(c);
    (void)zpf_pubkey_hex(ZPF_PLAYER_SEED, pubkey);
    (void)json_push_kv_str(&c->input, "dir", dir);
    (void)json_push_kv_str(&c->input, "datadir", w->datadir);
    (void)json_push_kv_str(&c->input, "publisher_pubkey", pubkey);
    (void)json_push_kv_int(&c->input, "day", ZPF_DAY);
}

/* Share plan only; returns the refusal-or-pass reply in `c`. */
static bool zpf_share_plan(struct zpf_call *c, const struct zpf_world *w,
                           const char *dir)
{
    zpf_share_input(c, w, dir);
    return zpf_run("zcode.package.share", c);
}

static int zpf_refusal_unknown_root(const struct zpf_world *w)
{
    int failures = 0;
    TEST("zcode package fork: an unknown root is refused and creates nothing") {
        struct zpf_call c;
        char other[700];
        (void)snprintf(other, sizeof(other), "%s/never", w->root);
        zpf_fork_input(&c, w, "abababababababababababababababababababababababababababababababab",
                       other, NULL);
        ASSERT(zpf_run("zcode.package.fork", &c));
        ASSERT(zpf_refused(&c, "FORK_ROOT_UNKNOWN"));
        struct stat st;
        ASSERT(stat(other, &st) != 0);
        zpf_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int zpf_mcp_confirmation(const struct zpf_world *w)
{
    int failures = 0;
    TEST("zcode package fork/version/share: MCP runs them plan-first") {
        static const char *const leaves[] = {
            "zcode.package.fork", "zcode.package.version.save",
            "zcode.package.version.restore", "zcode.package.share",
        };
        for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++) {
            const struct zcl_command_spec *spec = zpf_leaf(leaves[i]);
            struct mcp_refusal why = {0};
            struct json_value in;
            ASSERT(spec && spec->confirmation ==
                               ZCL_COMMAND_CONFIRM_PLAN_COMMIT);
            json_init(&in); json_set_object(&in);
            (void)json_push_kv_str(&in, "dir", w->copy);
            ASSERT(mcp_policy_allows(spec, zcl_command_catalog(), &in, &why));
            (void)json_push_kv_bool(&in, "confirm", true);
            bool refused = !mcp_policy_allows(spec, zcl_command_catalog(),
                                              &in, &why);
            ASSERT(refused && why.code &&
                   strcmp(why.code, "PLAN_ID_REQUIRED") == 0);
            (void)json_push_kv_str(&in, "plan_id", w->origin_release_hex);
            ASSERT(mcp_policy_allows(spec, zcl_command_catalog(), &in, &why));
            json_free(&in);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int zpf_fork_records_parent(const struct zpf_world *w,
                                   char fork_version[65])
{
    int failures = 0;
    TEST("zcode package fork: the copy records the parent release") {
        struct zpf_call c;
        zpf_fork_input(&c, w, w->origin_package_hex, w->copy, NULL);
        ASSERT(zpf_run("zcode.package.fork", &c) && zpf_passed(&c));
        ASSERT(strcmp(zpf_data_str(&c, "stage"), "plan") == 0);
        ASSERT(strcmp(zpf_data_str(&c, "parent_release_root"),
                      w->origin_release_hex) == 0);
        struct stat st;
        ASSERT(stat(w->copy, &st) != 0);
        zpf_end(&c);
        ASSERT(zpf_fork(w, w->origin_package_hex, w->copy, fork_version));
        ASSERT(strlen(fork_version) == 64);
        ASSERT(zpf_same_as_source(w->copy, ZPF_EDITED));
        ASSERT(zpf_same_as_source(w->copy, "zcode-package.json"));

        zpf_begin(&c);
        (void)json_push_kv_str(&c.input, "dir", w->copy);
        ASSERT(zpf_run("zcode.package.version.list", &c) && zpf_passed(&c));
        ASSERT(json_get_int(json_get(&c.reply.data, "count")) == 1);
        ASSERT(strcmp(zpf_data_str(&c, "parent_release_root"),
                      w->origin_release_hex) == 0);
        ASSERT(strcmp(zpf_data_str(&c, "fork_version"), fork_version) == 0);
        zpf_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int zpf_no_change_refusals(const struct zpf_world *w)
{
    int failures = 0;
    TEST("zcode package version save/share: an unchanged copy is refused") {
        struct zpf_call c;
        zpf_begin(&c);
        (void)json_push_kv_str(&c.input, "dir", w->copy);
        ASSERT(zpf_run("zcode.package.version.save", &c));
        ASSERT(zpf_refused(&c, "VERSION_NO_CHANGES"));
        zpf_end(&c);
        ASSERT(zpf_share_plan(&c, w, w->copy));
        ASSERT(zpf_refused(&c, "SHARE_NO_CHANGES"));
        zpf_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int zpf_save_and_restore(const struct zpf_world *w,
                                const char *fork_version)
{
    int failures = 0;
    TEST("zcode package version: save a change, then restore the fork") {
        char saved[65] = {0};
        struct zpf_call c;
        ASSERT(zpf_append(w->copy, ZPF_EDITED, "/* player edit one */\n"));
        ASSERT(!zpf_same_as_source(w->copy, ZPF_EDITED));
        zpf_begin(&c);
        (void)json_push_kv_str(&c.input, "dir", w->copy);
        (void)json_push_kv_str(&c.input, "plan_id", w->origin_release_hex);
        (void)json_push_kv_bool(&c.input, "confirm", true);
        ASSERT(zpf_run("zcode.package.version.save", &c));
        ASSERT(zpf_refused(&c, "PLAN_MISMATCH"));
        zpf_end(&c);
        ASSERT(zpf_save(w->copy, saved));
        ASSERT(strlen(saved) == 64 && strcmp(saved, fork_version) != 0);

        zpf_begin(&c);
        (void)json_push_kv_str(&c.input, "dir", w->copy);
        ASSERT(zpf_run("zcode.package.version.list", &c) && zpf_passed(&c));
        ASSERT(json_get_int(json_get(&c.reply.data, "count")) == 2);
        zpf_end(&c);

        ASSERT(zpf_restore(w->copy, fork_version));
        ASSERT(zpf_same_as_source(w->copy, ZPF_EDITED));
        PASS();
    } _test_next:;
    return failures;
}

static int zpf_unsaved_refusal(const struct zpf_world *w)
{
    int failures = 0;
    TEST("zcode package share/restore: unsaved changes are refused") {
        struct zpf_call c;
        ASSERT(zpf_append(w->copy, ZPF_EDITED, "/* player edit two */\n"));
        ASSERT(zpf_share_plan(&c, w, w->copy));
        ASSERT(zpf_refused(&c, "SHARE_UNSAVED_CHANGES"));
        zpf_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

static const char k_player_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"player/skycombat\",\n"
    "  \"semver\": \"0.1.0\",\n  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n";

/* Plan, sign the returned digest as the player, then commit. */
static bool zpf_share(const struct zpf_world *w, struct zpf_call *c)
{
    uint8_t digest[32], signature[64];
    char signature_hex[129], plan_id[65];
    if (!zpf_share_plan(c, w, w->copy) || !zpf_passed(c))
        return false;
    (void)snprintf(plan_id, sizeof(plan_id), "%s",
                   zpf_data_str(c, "plan_id"));
    if (strcmp(zpf_data_str(c, "parent_release_root"),
               w->origin_release_hex) != 0 ||
        !zcl_hex_decode(zpf_data_str(c, "signing_digest"), digest, 32) ||
        !zpf_sign(ZPF_PLAYER_SEED, digest, signature))
        return false;
    zcl_hex_encode(signature, 64, signature_hex);
    zcl_command_reply_free(&c->reply);
    zcl_command_reply_init(&c->reply, "zcl.test.zcode_package_fork.v1");
    (void)json_push_kv_str(&c->input, "plan_id", plan_id);
    (void)json_push_kv_str(&c->input, "signature_hex", signature_hex);
    (void)json_push_kv_bool(&c->input, "confirm", true);
    return zpf_run("zcode.package.share", c) && zpf_passed(c);
}

/* The persisted envelope is the authority, not the reply. */
static bool zpf_release_parent(const struct zpf_world *w,
                               const char *release_hex, uint8_t parent[32],
                               uint8_t package[32])
{
    char path[900];
    uint8_t wire[VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES];
    struct vcs_package_release release;
    (void)snprintf(path, sizeof(path), "%s/zcode/releases/%s", w->datadir,
                   release_hex);
    FILE *f = fopen(path, "rb");
    size_t len = f ? fread(wire, 1, sizeof(wire), f) : 0;
    if (f)
        fclose(f);
    bool ok = len > 0 &&
              vcs_package_release_parse(wire, len, &release) ==
                  VCS_PACKAGE_RELEASE_OK &&
              vcs_package_release_verify(&release) ==
                  VCS_PACKAGE_RELEASE_OK &&
              vcs_package_release_parent(&release, parent);
    memcpy(package, release.package_root, 32);
    return ok;
}

static bool zpf_lineage_names_parent(const struct zpf_world *w,
                                     const char *package_hex)
{
    struct zpf_call c;
    zpf_begin(&c);
    (void)json_push_kv_str(&c.input, "workspace", w->workspace);
    (void)json_push_kv_str(&c.input, "package_root", package_hex);
    (void)json_push_kv_str(&c.input, "datadir", w->datadir);
    bool ok = zpf_run("zcode.commons.lineage", &c) && zpf_passed(&c);
    const struct json_value *rows = json_get(&c.reply.data, "releases");
    const struct json_value *row = rows ? json_at(rows, 0) : NULL;
    const struct json_value *parent =
        row ? json_get(row, "parent_release_root") : NULL;
    const struct json_value *parent_package =
        row ? json_get(row, "parent_package_root") : NULL;
    ok = ok && json_size(rows) == 1 && parent && parent_package &&
         strcmp(json_get_str(parent), w->origin_release_hex) == 0 &&
         strcmp(json_get_str(parent_package), w->origin_package_hex) == 0;
    zpf_end(&c);
    return ok;
}

static int zpf_share_names_parent(const struct zpf_world *w,
                                  char shared_release[65])
{
    int failures = 0;
    TEST("zcode package share: the new release's parent is the forked release") {
        struct zpf_call c;
        ASSERT(zpf_write(w->copy, "zcode-package.json", k_player_meta));
        ASSERT(zpf_save(w->copy, NULL));
        ASSERT(zpf_share(w, &c));
        (void)snprintf(shared_release, 65, "%s",
                       zpf_data_str(&c, "release_id"));
        char package_hex[65];
        (void)snprintf(package_hex, sizeof(package_hex), "%s",
                       zpf_data_str(&c, "package_root"));
        zpf_end(&c);
        uint8_t parent[32], package[32];
        ASSERT(zpf_release_parent(w, shared_release, parent, package));
        ASSERT(memcmp(parent, w->origin_release, 32) == 0);
        ASSERT(memcmp(package, w->origin_package, 32) != 0);
        ASSERT(zpf_lineage_names_parent(w, package_hex));
        PASS();
    } _test_next:;
    return failures;
}

/* A copy of the original package whose first commit claims a different,
 * valid parent: the recorded tree no longer prepares to that parent. */
static bool zpf_forge_copy(const struct zpf_world *w, const char *dir,
                           const char *claimed_parent_hex)
{
    struct zpf_call c;
    zpf_begin(&c);
    (void)json_push_kv_str(&c.input, "root", w->origin_package_hex);
    (void)json_push_kv_str(&c.input, "destination", dir);
    (void)json_push_kv_str(&c.input, "datadir", w->datadir);
    bool ok = zpf_run("zcode.package.checkout", &c) && zpf_passed(&c);
    zpf_end(&c);
    char task_ref[96];
    uint8_t version[32];
    (void)snprintf(task_ref, sizeof(task_ref), "zcode.fork:%s",
                   claimed_parent_hex);
    const struct vcs_snapshot_meta meta = {.phase = "fork",
                                           .task_ref = task_ref};
    struct vcs_repo *repo = ok ? vcs_open(dir) : NULL;
    ok = repo && vcs_snapshot(repo, &meta, version) == VCS_OK;
    vcs_close(repo);
    return ok && zpf_append(dir, ZPF_EDITED, "/* forged */\n") &&
           zpf_save(dir, NULL);
}

static int zpf_tamper_refusals(const struct zpf_world *w,
                               const char *shared_release)
{
    int failures = 0;
    TEST("zcode package share: forged or broken copy history is refused") {
        char forged[700], broken[700], log[800];
        struct zpf_call c;
        (void)snprintf(forged, sizeof(forged), "%s/forged", w->root);
        ASSERT(zpf_forge_copy(w, forged, shared_release));
        ASSERT(zpf_share_plan(&c, w, forged));
        ASSERT(zpf_refused(&c, "COPY_TAMPERED"));
        zpf_end(&c);

        (void)snprintf(broken, sizeof(broken), "%s/broken", w->root);
        ASSERT(zpf_fork(w, w->origin_release_hex, broken, NULL));
        (void)snprintf(log, sizeof(log), "%s/.zvcs/commits.log", broken);
        FILE *f = fopen(log, "r+b");
        ASSERT(f != NULL);
        ASSERT(fseek(f, -40, SEEK_END) == 0);
        int byte = fgetc(f);
        ASSERT(fseek(f, -40, SEEK_END) == 0);
        ASSERT(fputc(byte ^ 0x5a, f) != EOF);
        ASSERT(fclose(f) == 0);
        ASSERT(zpf_share_plan(&c, w, broken));
        ASSERT(zpf_refused(&c, "COPY_HISTORY_INVALID"));
        zpf_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_package_fork(void)
{
    int failures = 0;
    struct zpf_world w;
    char fork_version[65] = {0}, shared_release[65] = {0};
    chain_params_select(CHAIN_MAIN);
    TEST("zcode package fork: skycombat publishes as a source package") {
        ASSERT(zpf_world_init(&w));
        PASS();
    } _test_next:;
    if (failures)
        return failures;
    failures += zpf_refusal_unknown_root(&w);
    failures += zpf_mcp_confirmation(&w);
    failures += zpf_fork_records_parent(&w, fork_version);
    failures += zpf_no_change_refusals(&w);
    failures += zpf_save_and_restore(&w, fork_version);
    failures += zpf_unsaved_refusal(&w);
    failures += zpf_share_names_parent(&w, shared_release);
    failures += zpf_tamper_refusals(&w, shared_release);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}
