/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the skycombat remix journey on local fixtures — fork a published
 * package, save and restore versions, share a release that names its parent,
 * and see the parent in zcode.commons.lineage. Refusals: an unknown root, a
 * share without changes, unsaved changes, a forged fork record and a broken
 * commit log. Read leaves and plan halves leave a torn copy byte-identical.
 * Adopt keeps an owner-approved copy under <datadir>/copies with a datadir
 * record: refused over MCP, numbered per adopt, kept across local saves,
 * lost to a foreign commit, never granted by a copied commit log. Every leaf
 * runs the way the CLI and MCP run it: the registry input contract first,
 * then the bound handler. */

#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/native_command.h"
#include "command/native_zcode_package_copy.h"
#include "config/command_catalog.h"
#include "core/uint256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "mcp/mcp_policy.h"
#include "platform/directory_compat.h"
#include "platform/file_metadata.h"
#include "sha3/sha3.h"
#include "storage/event_log.h"
#include "vcs/package_prepare.h"
#include "vcs/package_checkout.h"
#include "vcs/package_release.h"
#include "vcs/vcs.h"
#include "vcs/vcs_index.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#ifdef ZCL_TESTING
void zcl_package_copy_test_restore_partial(bool enabled);
#endif

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

static void zpf_share_input_at_day(struct zpf_call *c, const struct zpf_world *w,
                                   const char *dir, int day)
{
    char pubkey[67];
    zpf_begin(c);
    (void)zpf_pubkey_hex(ZPF_PLAYER_SEED, pubkey);
    (void)json_push_kv_str(&c->input, "dir", dir);
    (void)json_push_kv_str(&c->input, "datadir", w->datadir);
    (void)json_push_kv_str(&c->input, "publisher_pubkey", pubkey);
    (void)json_push_kv_int(&c->input, "day", day);
}

static void zpf_share_input(struct zpf_call *c, const struct zpf_world *w,
                            const char *dir)
{
    zpf_share_input_at_day(c, w, dir, ZPF_DAY);
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

static bool zpf_mismatch_index(const char *dir, bool missing)
{
    char path[1400];
    if (missing) {
        int n = snprintf(path, sizeof path, "%s/.zvcs/index.kv", dir);
        if (n <= 0 || (size_t)n >= sizeof path || unlink(path) != 0) return false;
    }
    struct vcs_index *idx = vcs_index_open(dir);
    if (!idx) return false;
    uint8_t other[32] = {1};
    bool ok = missing || (vcs_index_begin(idx) &&
        vcs_index_ref_set_in_tx(idx, "HEAD", other) && vcs_index_commit(idx));
    vcs_index_close(idx);
    return ok;
}

static int zpf_index_head_refusal(const struct zpf_world *w)
{
    int failures = 0;
    for (int missing = 0; missing < 2; ++missing) {
        TEST("zcode package version save: inconsistent index HEAD refuses") {
            char dir[700], plan[65]; struct zpf_call c;
            (void)snprintf(dir, sizeof dir, "%s/index-head-%d", w->root, missing);
            ASSERT(zpf_fork(w, w->origin_release_hex, dir, NULL));
            ASSERT(zpf_append(dir, ZPF_EDITED, "/* dirty */\n"));
            zpf_begin(&c);
            ASSERT(json_push_kv_str(&c.input, "dir", dir));
            ASSERT(zpf_run("zcode.package.version.save", &c) && zpf_passed(&c));
            (void)snprintf(plan, sizeof plan, "%s", zpf_data_str(&c, "plan_id"));
            ASSERT(zpf_mismatch_index(dir, missing));
            ASSERT(json_push_kv_str(&c.input, "plan_id", plan));
            ASSERT(json_push_kv_bool(&c.input, "confirm", true));
            zcl_command_reply_free(&c.reply);
            zcl_command_reply_init(&c.reply, "zcl.test.zcode_package_fork.v1");
            ASSERT(zpf_run("zcode.package.version.save", &c));
            ASSERT(zpf_refused(&c, "COPY_HEAD_MISMATCH"));
            ASSERT(!c.reply.error.mutated);
            zpf_end(&c);
            PASS();
        } _test_next:;
    }
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
#ifdef ZCL_TESTING
        ASSERT(zpf_append(w->copy, ZPF_EDITED, "/* partial fixture */\n"));
        ASSERT(zpf_save(w->copy, saved));
        zpf_begin(&c);
        (void)json_push_kv_str(&c.input, "dir", w->copy);
        (void)json_push_kv_str(&c.input, "version", fork_version);
        ASSERT(zpf_run("zcode.package.version.restore", &c) && zpf_passed(&c));
        char plan[65];
        (void)snprintf(plan, sizeof(plan), "%s", zpf_data_str(&c, "plan_id"));
        zcl_command_reply_free(&c.reply);
        zcl_command_reply_init(&c.reply, "zcl.test.zcode_package_fork.v1");
        (void)json_push_kv_str(&c.input, "plan_id", plan);
        (void)json_push_kv_bool(&c.input, "confirm", true);
        zcl_package_copy_test_restore_partial(true);
        bool ran = zpf_run("zcode.package.version.restore", &c);
        zcl_package_copy_test_restore_partial(false);
        ASSERT(ran);
        ASSERT(zpf_refused(&c, "VERSION_RESTORE_FAILED"));
        ASSERT(c.reply.error.mutated && zpf_same_as_source(w->copy, ZPF_EDITED));
        zpf_end(&c);
#endif
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
    if (ok)
        memcpy(package, release.package_root, 32);
    else
        memset(package, 0, 32);
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

static bool zpf_head(const char *dir, char version[65])
{
    struct zpf_call c;
    zpf_begin(&c);
    (void)json_push_kv_str(&c.input, "dir", dir);
    bool ok = zpf_run("zcode.package.version.list", &c) && zpf_passed(&c);
    if (ok) (void)snprintf(version, 65, "%s", zpf_data_str(&c, "head_version"));
    zpf_end(&c);
    return ok;
}

static bool zpf_file_digest(const char *dir, uint8_t digest[32])
{
    char path[900]; unsigned char buf[4096];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, ZPF_EDITED);
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    struct sha3_256_ctx ctx; sha3_256_init(&ctx);
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) != 0) sha3_256_write(&ctx, buf, n);
    bool ok = !ferror(file);
    if (fclose(file) != 0) ok = false;
    if (ok) sha3_256_finalize(&ctx, digest);
    return ok;
}

struct zpf_log_injection {
    event_log_t *destination;
    bool ok;
    size_t count;
};

static bool zpf_inject_event(uint64_t offset, enum event_log_type type,
                             const void *payload, size_t len, void *user)
{
    (void)offset;
    struct zpf_log_injection *injection = user;
    injection->ok = type == EV_VCS_COMMIT &&
        event_log_append(injection->destination, type, payload, len) != UINT64_MAX;
    if (injection->ok) injection->count++;
    return injection->ok;
}

static bool zpf_inject_log(const char *source, const char *destination)
{
    char from[900], to[900];
    (void)snprintf(from, sizeof(from), "%s/.zvcs/commits.log", source);
    (void)snprintf(to, sizeof(to), "%s/.zvcs/commits.log", destination);
    /* Reframe each foreign record at its destination offset. Raw concatenation
     * preserves old sentinel offsets and is recovered as a torn append before
     * the version-chain validator can observe the disconnected commits. */
    event_log_t *in = event_log_open(from), *out = event_log_open(to);
    struct zpf_log_injection injection = {.destination = out, .ok = true};
    bool ok = in && out &&
        event_log_stream(in, 0, zpf_inject_event, &injection) == 0 &&
        injection.ok && injection.count > 0;
    if (in) event_log_close(in);
    if (out) event_log_close(out);
    return ok;
}

static bool zpf_selected_plan(struct zpf_call *c, const struct zpf_world *w,
                              const char *version)
{
    /* The initial head share already used this publisher's weekly allowance. */
    zpf_share_input_at_day(c, w, w->copy, ZPF_DAY + 7);
    (void)json_push_kv_str(&c->input, "version", version);
    return zpf_run("zcode.package.share", c);
}

static int zpf_selected_plan_identity(const struct zpf_world *w, char n[65],
                                       char root[65])
{
    int failures = 0;
    TEST("zcode package share: same-tree versions require distinct plans") {
        struct zpf_call c;
        char same[65], old_plan[65];
        uint8_t same_id[32];
        ASSERT(zpf_append(w->copy, ZPF_EDITED, "/* selected N */\n"));
        ASSERT(zpf_save(w->copy, n));
        ASSERT(zpf_selected_plan(&c, w, n) && zpf_passed(&c));
        (void)snprintf(root, 65, "%s", zpf_data_str(&c, "package_root"));
        (void)snprintf(old_plan, sizeof(old_plan), "%s", zpf_data_str(&c, "plan_id"));
        zpf_end(&c);
        struct vcs_repo *repo = vcs_open(w->copy);
        const struct vcs_snapshot_meta meta = { .phase = "same-tree" };
        bool snapped = repo && vcs_snapshot(repo, &meta, same_id) == VCS_OK;
        vcs_close(repo);
        ASSERT(snapped);
        zcl_hex_encode(same_id, 32, same);
        ASSERT(strcmp(same, n) != 0);
        ASSERT(zpf_selected_plan(&c, w, same) && zpf_passed(&c));
        ASSERT(strcmp(zpf_data_str(&c, "package_root"), root) == 0 &&
               strcmp(zpf_data_str(&c, "plan_id"), old_plan) != 0);
        zcl_command_reply_free(&c.reply);
        zcl_command_reply_init(&c.reply, "zcl.test.zcode_package_fork.v1");
        (void)json_push_kv_str(&c.input, "plan_id", old_plan);
        (void)json_push_kv_bool(&c.input, "confirm", true);
        ASSERT(zpf_run("zcode.package.share", &c) && zpf_refused(&c, "PLAN_MISMATCH"));
        zpf_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int zpf_selected_share(const struct zpf_world *w, const char *fork_version)
{
    int failures = 0;
    TEST("zcode package share: select saved version without touching newer dirty work") {
        struct zpf_call c;
        char n[65], n1[65], head[65], root[65], plan[65], signature_hex[129];
        char other_dir[700], other_version[65], broken_dir[700];
        uint8_t before[32], after[32], digest[32], signature[64], parent[32], package[32];
        failures += zpf_selected_plan_identity(w, n, root);
        if (failures) goto _test_next;
        ASSERT(zpf_append(w->copy, ZPF_EDITED, "/* newer N+1 */\n"));
        ASSERT(zpf_save(w->copy, n1));
        ASSERT(zpf_append(w->copy, ZPF_EDITED, "/* unsaved working edit */\n"));
        ASSERT(zpf_file_digest(w->copy, before));
        ASSERT(zpf_share_plan(&c, w, w->copy) && zpf_refused(&c, "SHARE_UNSAVED_CHANGES"));
        zpf_end(&c);
        ASSERT(zpf_selected_plan(&c, w, "bad") && zpf_refused(&c, "VERSION_UNKNOWN"));
        zpf_end(&c);
        (void)snprintf(other_dir, sizeof(other_dir), "%s/other-copy", w->root);
        ASSERT(zpf_fork(w, w->origin_package_hex, other_dir, NULL));
        ASSERT(zpf_append(other_dir, ZPF_EDITED, "/* unrelated copy */\n"));
        ASSERT(zpf_save(other_dir, other_version));
        (void)snprintf(broken_dir, sizeof(broken_dir), "%s/injected-copy", w->root);
        ASSERT(zpf_fork(w, w->origin_package_hex, broken_dir, NULL));
        ASSERT(zpf_inject_log(other_dir, broken_dir));
        zpf_share_input(&c, w, broken_dir);
        (void)json_push_kv_str(&c.input, "version", other_version);
        ASSERT(zpf_run("zcode.package.share", &c) && zpf_refused(&c, "COPY_HISTORY_INVALID"));
        zpf_end(&c);
        ASSERT(zpf_selected_plan(&c, w, other_version) && zpf_refused(&c, "VERSION_UNKNOWN"));
        zpf_end(&c);
        ASSERT(zpf_selected_plan(&c, w, fork_version) && zpf_refused(&c, "SHARE_NO_CHANGES"));
        zpf_end(&c);
        ASSERT(zpf_selected_plan(&c, w, n) && zpf_passed(&c));
        ASSERT(strcmp(zpf_data_str(&c, "version"), n) == 0 && strcmp(zpf_data_str(&c, "package_root"), root) == 0);
        (void)snprintf(plan, sizeof(plan), "%s", zpf_data_str(&c, "plan_id"));
        ASSERT(zcl_hex_decode(zpf_data_str(&c, "signing_digest"), digest, 32) && zpf_sign(ZPF_PLAYER_SEED, digest, signature));
        zcl_hex_encode(signature, 64, signature_hex);
        zcl_command_reply_free(&c.reply);
        zcl_command_reply_init(&c.reply, "zcl.test.zcode_package_fork.v1");
        (void)json_push_kv_str(&c.input, "plan_id", plan);
        (void)json_push_kv_str(&c.input, "signature_hex", signature_hex);
        (void)json_push_kv_bool(&c.input, "confirm", true);
        ASSERT(zpf_run("zcode.package.share", &c) && zpf_passed(&c));
        ASSERT(strcmp(zpf_data_str(&c, "version"), n) == 0 && strcmp(zpf_data_str(&c, "package_root"), root) == 0);
        ASSERT(zpf_release_parent(w, zpf_data_str(&c, "release_id"), parent, package));
        ASSERT(zcl_hex_decode(root, digest, 32) && memcmp(package, digest, 32) == 0);
        zpf_end(&c);
        ASSERT(zpf_head(w->copy, head) && strcmp(head, n1) == 0);
        ASSERT(zpf_file_digest(w->copy, after) && memcmp(before, after, 32) == 0);
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

/* ── read leaves never repair: a torn copy stays byte-for-byte as it was ── */

static void zpf_mix(uint8_t acc[32], const char *rel, FILE *f)
{
    struct sha3_256_ctx ctx;
    unsigned char buf[4096];
    uint8_t h[32];
    size_t got;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)rel, strlen(rel) + 1u);
    while (f && (got = fread(buf, 1, sizeof(buf), f)) > 0)
        sha3_256_write(&ctx, buf, got);
    sha3_256_finalize(&ctx, h);
    for (size_t i = 0; i < 32; i++)
        acc[i] ^= h[i];
}

/* Order-free digest of every name and every file's bytes beneath dir. */
static bool zpf_tree_digest(const char *dir, const char *rel, uint8_t acc[32],
                            size_t *entries)
{
    char path[1400];
    (void)snprintf(path, sizeof(path), "%s%s%s", dir, rel[0] ? "/" : "", rel);
    DIR *d = opendir(path);
    struct dirent *e;
    bool ok = d != NULL;
    while (ok && (e = readdir(d)) != NULL) {
        char child_rel[1200], child[2700];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        (void)snprintf(child_rel, sizeof(child_rel), "%s%s%s", rel,
                       rel[0] ? "/" : "", e->d_name);
        (void)snprintf(child, sizeof(child), "%s/%s", dir, child_rel);
        ok = lstat(child, &st) == 0;
        (*entries)++;
        if (ok && S_ISDIR(st.st_mode)) {
            zpf_mix(acc, child_rel, NULL);
            ok = zpf_tree_digest(dir, child_rel, acc, entries);
        } else if (ok) {
            FILE *f = fopen(child, "rb");
            ok = f != NULL;
            zpf_mix(acc, child_rel, f);
            if (f)
                ok = fclose(f) == 0 && ok;
        }
    }
    if (d)
        closedir(d);
    return ok;
}

static bool zpf_same_tree(const char *dir, const uint8_t want[32],
                          size_t want_entries)
{
    uint8_t got[32] = {0};
    size_t entries = 0;
    bool ok = zpf_tree_digest(dir, "", got, &entries) &&
              entries == want_entries && memcmp(got, want, 32) == 0;
    if (!ok)
        printf("  [copy bytes changed: %zu entries, want %zu]\n", entries,
               want_entries);
    return ok;
}

static bool zpf_dir_refused(const char *path, const char *dir,
                            const char *extra_key, const char *extra)
{
    struct zpf_call c;
    zpf_begin(&c);
    (void)json_push_kv_str(&c.input, "dir", dir);
    if (extra_key)
        (void)json_push_kv_str(&c.input, extra_key, extra);
    bool ok = zpf_run(path, &c) && zpf_refused(&c, "COPY_HISTORY_INVALID");
    zpf_end(&c);
    return ok;
}

static int zpf_torn_copy_reads(const struct zpf_world *w)
{
    int failures = 0;
    TEST("zcode package version list and plans: a torn copy is refused and "
         "left byte-for-byte untouched") {
        char torn[700], log[800], plan_id[65];
        uint8_t digest[32] = {0};
        size_t entries = 0;
        struct zpf_call c;
        (void)snprintf(torn, sizeof(torn), "%s/torn", w->root);
        ASSERT(zpf_fork(w, w->origin_release_hex, torn, NULL));
        ASSERT(zpf_append(torn, ZPF_EDITED, "/* before the tear */\n"));
        zpf_begin(&c);
        (void)json_push_kv_str(&c.input, "dir", torn);
        ASSERT(zpf_run("zcode.package.version.save", &c) && zpf_passed(&c));
        (void)snprintf(plan_id, sizeof(plan_id), "%s",
                       zpf_data_str(&c, "plan_id"));
        zpf_end(&c);

        /* A clean read writes nothing either. */
        ASSERT(zpf_tree_digest(torn, "", digest, &entries));
        zpf_begin(&c);
        (void)json_push_kv_str(&c.input, "dir", torn);
        ASSERT(zpf_run("zcode.package.version.list", &c) && zpf_passed(&c));
        zpf_end(&c);
        ASSERT(zpf_same_tree(torn, digest, entries));

        (void)snprintf(log, sizeof(log), "torn/.zvcs/commits.log");
        ASSERT(zpf_append(w->root, log, "a torn half-record"));
        memset(digest, 0, sizeof(digest));
        entries = 0;
        ASSERT(zpf_tree_digest(torn, "", digest, &entries));
        ASSERT(zpf_dir_refused("zcode.package.version.list", torn, NULL, NULL));
        ASSERT(zpf_dir_refused("zcode.package.version.save", torn, NULL, NULL));
        ASSERT(zpf_dir_refused("zcode.package.version.restore", torn,
                               "version", w->origin_release_hex));
        ASSERT(zpf_share_plan(&c, w, torn));
        ASSERT(zpf_refused(&c, "COPY_HISTORY_INVALID"));
        zpf_end(&c);
        ASSERT(zpf_same_tree(torn, digest, entries));

        /* A confirmed save keeps the recovering open: the plan bound before
         * the tear still matches once the torn tail is dropped. */
        zpf_begin(&c);
        (void)json_push_kv_str(&c.input, "dir", torn);
        (void)json_push_kv_str(&c.input, "plan_id", plan_id);
        (void)json_push_kv_bool(&c.input, "confirm", true);
        ASSERT(zpf_run("zcode.package.version.save", &c) && zpf_passed(&c));
        zpf_end(&c);
        zpf_begin(&c);
        (void)json_push_kv_str(&c.input, "dir", torn);
        ASSERT(zpf_run("zcode.package.version.list", &c) && zpf_passed(&c));
        ASSERT(json_get_int(json_get(&c.reply.data, "count")) == 2);
        zpf_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

/* ── adopt: the owner keeps a runnable copy ─────────────────────────── */

static void zpf_adopt_input(struct zpf_call *c, const struct zpf_world *w,
                            const char *root)
{
    zpf_begin(c);
    (void)json_push_kv_str(&c->input, "root", root);
    (void)json_push_kv_str(&c->input, "datadir", w->datadir);
}

static bool zpf_adopt(const struct zpf_world *w, const char *root,
                      char name[40], char copy[700])
{
    struct zpf_call c;
    char plan_id[65] = {0};
    zpf_adopt_input(&c, w, root);
    bool ok = zpf_plan_commit("zcode.package.adopt", &c, plan_id);
    const struct json_value *adopted = json_get(&c.reply.data, "adopted");
    ok = ok && adopted && json_get_bool(adopted);
    (void)snprintf(name, 40, "%s", zpf_data_str(&c, "copy_name"));
    (void)snprintf(copy, 700, "%s", zpf_data_str(&c, "copy"));
    zpf_end(&c);
    return ok;
}

static enum zcl_package_copy_adoption zpf_adoption(const struct zpf_world *w,
                                                   const char *dir)
{
    struct zcl_package_copy copy;
    struct zcl_command_reply reply;
    enum zcl_package_copy_adoption a = ZCL_PACKAGE_COPY_ADOPTION_UNREADABLE;
    zcl_command_reply_init(&reply, "zcl.test.zcode_package_fork.v1");
    if (zcl_package_copy_open_as(dir, ZCL_PACKAGE_COPY_READ, &copy, &reply,
                                 "test")) {
        a = zcl_package_copy_adopted(w->datadir, &copy, NULL);
        zcl_package_copy_close(&copy);
    }
    zcl_command_reply_free(&reply);
    return a;
}

/* The copies list row for `name`: its status, or "" when absent. */
static bool zpf_copies_status(const struct zpf_world *w, const char *name,
                              char status[32], int64_t *count)
{
    struct zpf_call c;
    zpf_begin(&c);
    (void)json_push_kv_str(&c.input, "datadir", w->datadir);
    bool ok = zpf_run("zcode.copies", &c) && zpf_passed(&c);
    const struct json_value *rows = json_get(&c.reply.data, "copies");
    status[0] = '\0';
    *count = ok ? json_get_int(json_get(&c.reply.data, "count")) : -1;
    for (size_t i = 0; ok && i < json_size(rows); i++) {
        const struct json_value *row = json_at(rows, i);
        const char *n = json_get_str(json_get(row, "name"));
        const char *s = json_get_str(json_get(row, "status"));
        if (n && s && strcmp(n, name) == 0)
            (void)snprintf(status, 32, "%s", s);
    }
    zpf_end(&c);
    return ok;
}

static int zpf_adopt_mcp(const struct zpf_world *w)
{
    int failures = 0;
    TEST("zcode package adopt: MCP refuses adopt and still allows fork") {
        const struct zcl_command_spec *adopt = zpf_leaf("zcode.package.adopt");
        const struct zcl_command_spec *fork = zpf_leaf("zcode.package.fork");
        const struct zcl_command_spec *copies = zpf_leaf("zcode.copies");
        struct mcp_refusal why = {0};
        struct json_value in;
        ASSERT(adopt && fork && copies);
        ASSERT(adopt->authority == ZCL_COMMAND_AUTH_OWNER &&
               adopt->confirmation == ZCL_COMMAND_CONFIRM_PLAN_COMMIT);
        json_init(&in); json_set_object(&in);
        (void)json_push_kv_str(&in, "root", w->origin_release_hex);
        ASSERT(!mcp_policy_allows(adopt, zcl_command_catalog(), &in, &why));
        ASSERT(why.code &&
               strcmp(why.code, "MUTATION_REFUSED_OWNER_AUTHORITY") == 0);
        (void)json_push_kv_str(&in, "plan_id", w->origin_release_hex);
        (void)json_push_kv_bool(&in, "confirm", true);
        ASSERT(!mcp_policy_allows(adopt, zcl_command_catalog(), &in, &why));
        ASSERT(mcp_policy_allows(fork, zcl_command_catalog(), &in, &why));
        ASSERT(mcp_policy_allows(copies, zcl_command_catalog(), &in, &why));
        json_free(&in);
        PASS();
    } _test_next:;
    return failures;
}

static int zpf_adopt_two_copies(const struct zpf_world *w, char first[700],
                                char second[700])
{
    int failures = 0;
    TEST("zcode package adopt: the plan names the publisher and two adopts "
         "make skycombat-1 and skycombat-2") {
        char pubkey[67], name[40], status[32];
        int64_t count = 0;
        struct zpf_call c;
        struct stat st;
        ASSERT(zpf_pubkey_hex(ZPF_ORIGIN_SEED, pubkey));
        zpf_adopt_input(&c, w, w->origin_release_hex);
        ASSERT(zpf_run("zcode.package.adopt", &c) && zpf_passed(&c));
        ASSERT(strcmp(zpf_data_str(&c, "stage"), "plan") == 0);
        ASSERT(strcmp(zpf_data_str(&c, "publisher"), pubkey) == 0);
        ASSERT(strcmp(zpf_data_str(&c, "release_root"),
                      w->origin_release_hex) == 0);
        ASSERT(strcmp(zpf_data_str(&c, "package_root"),
                      w->origin_package_hex) == 0);
        ASSERT(strcmp(zpf_data_str(&c, "copy_name"), "skycombat-1") == 0);
        ASSERT(!json_get_bool(json_get(&c.reply.data, "has_parent")));
        ASSERT(stat(zpf_data_str(&c, "copy"), &st) != 0);
        zpf_end(&c);

        ASSERT(zpf_adopt(w, w->origin_release_hex, name, first));
        ASSERT(strcmp(name, "skycombat-1") == 0);
        ASSERT(strstr(first, "/copies/skycombat-1") != NULL);
        ASSERT(zpf_adopt(w, w->origin_package_hex, name, second));
        ASSERT(strcmp(name, "skycombat-2") == 0);
        ASSERT(zpf_same_as_source(first, ZPF_EDITED));
        ASSERT(zpf_adoption(w, first) == ZCL_PACKAGE_COPY_ADOPTED);
        ASSERT(zpf_adoption(w, second) == ZCL_PACKAGE_COPY_ADOPTED);
        ASSERT(zpf_copies_status(w, "skycombat-2", status, &count));
        ASSERT(count == 2 && strcmp(status, "adopted") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int zpf_adopt_local_and_foreign(const struct zpf_world *w,
                                       const char *first, const char *second)
{
    int failures = 0;
    TEST("zcode package adopt: a local save stays adopted; a merged commit "
         "is foreign") {
        char status[32];
        int64_t count = 0;
        uint8_t version[32];
        char boosted[65] = {0};
        ASSERT(zpf_append(first, ZPF_EDITED, "/* my own boost */\n"));
        ASSERT(zpf_save(first, boosted));
        ASSERT(zpf_adoption(w, first) == ZCL_PACKAGE_COPY_ADOPTED);
        ASSERT(zpf_append(first, ZPF_EDITED, "/* a second boost */\n"));
        ASSERT(zpf_save(first, NULL));
        ASSERT(zpf_restore(first, boosted));
        ASSERT(zpf_adoption(w, first) == ZCL_PACKAGE_COPY_ADOPTED);

        ASSERT(zpf_append(second, ZPF_EDITED, "/* someone else's code */\n"));
        const struct vcs_snapshot_meta meta = {
            .phase = "merge", .task_ref = "zcode.merge:friend",
        };
        struct vcs_repo *repo = vcs_open(second);
        ASSERT(repo && vcs_snapshot(repo, &meta, version) == VCS_OK);
        vcs_close(repo);
        ASSERT(zpf_adoption(w, second) == ZCL_PACKAGE_COPY_FOREIGN_COMMITS);
        ASSERT(zpf_copies_status(w, "skycombat-2", status, &count));
        ASSERT(strcmp(status, "foreign_commits") == 0);
        ASSERT(zpf_copies_status(w, "skycombat-1", status, &count));
        ASSERT(strcmp(status, "adopted") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static bool zpf_copy_file(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb"), *out = fopen(to, "wb");
    unsigned char buf[4096];
    size_t got;
    bool ok = in && out;
    while (ok && (got = fread(buf, 1, sizeof(buf), in)) > 0)
        ok = fwrite(buf, 1, got, out) == got;
    if (in)
        fclose(in);
    if (out)
        ok = fclose(out) == 0 && ok;
    return ok;
}

static int zpf_adopt_hand_edit(const struct zpf_world *w, const char *first)
{
    int failures = 0;
    TEST("zcode package adopt: a hand-edited commit log is not adoption") {
        char plain[700], from[800], to[800];
        (void)snprintf(plain, sizeof(plain), "%s/plain-fork", w->root);
        ASSERT(zpf_fork(w, w->origin_release_hex, plain, NULL));
        ASSERT(zpf_adoption(w, plain) == ZCL_PACKAGE_COPY_NOT_ADOPTED);
        /* The adopted copy's whole history, root commit and all. */
        (void)snprintf(from, sizeof(from), "%s/.zvcs/commits.log", first);
        (void)snprintf(to, sizeof(to), "%s/.zvcs/commits.log", plain);
        ASSERT(zpf_copy_file(from, to));
        ASSERT(zpf_adoption(w, plain) == ZCL_PACKAGE_COPY_NOT_ADOPTED);
        PASS();
    } _test_next:;
    return failures;
}

static bool zpf_has_change(const struct zpf_call *c, const char *path)
{
    const struct json_value *rows = json_get(&c->reply.data, "changed_paths");
    for (size_t i = 0; i < json_size(rows); i++) {
        const char *p = json_get_str(json_get(json_at(rows, i), "path"));
        if (p && strcmp(p, path) == 0)
            return true;
    }
    return false;
}

static int zpf_adopt_remix_plan(const struct zpf_world *w,
                                const char *shared_release)
{
    int failures = 0;
    TEST("zcode package adopt: a remix's plan shows its parent and the files "
         "it changed") {
        char pubkey[67];
        struct zpf_call c;
        ASSERT(zpf_pubkey_hex(ZPF_PLAYER_SEED, pubkey));
        zpf_adopt_input(&c, w, shared_release);
        ASSERT(zpf_run("zcode.package.adopt", &c) && zpf_passed(&c));
        ASSERT(strcmp(zpf_data_str(&c, "publisher"), pubkey) == 0);
        ASSERT(json_get_bool(json_get(&c.reply.data, "has_parent")));
        ASSERT(strcmp(zpf_data_str(&c, "parent_release_root"),
                      w->origin_release_hex) == 0);
        ASSERT(strcmp(zpf_data_str(&c, "parent_package_root"),
                      w->origin_package_hex) == 0);
        ASSERT(json_get_int(json_get(&c.reply.data, "changes")) == 2);
        ASSERT(zpf_has_change(&c, "zcode-package.json"));
        ASSERT(zpf_has_change(&c, ZPF_EDITED));
        zpf_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

static bool zpf_name_pick(const char *root, const char *expected)
{
    char name[ZCL_PACKAGE_ADOPT_NAME_MAX + 1u], path[4400];
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.copy_name.v1");
    bool ok = zcl_package_copy_pick_name(root, "Game", name, path, sizeof(path), &reply);
    bool result = expected ? ok && strcmp(name, expected) == 0 :
        !ok && strcmp(reply.error.code, "COPY_NAME_UNREADABLE") == 0;
    zcl_command_reply_free(&reply);
    return result;
}

static bool zpf_name_file(const char *path)
{
    FILE *f = fopen(path, "wb");
    return f && fclose(f) == 0;
}

static int zpf_name_occupied(void)
{
    int failures = 0;
    char root[512] = {0}, copies[600], one[650], two[650];
    TEST("copy names: missing copies is advisory; files and directories occupy suffixes") {
        ASSERT(test_mkdtemp(root, sizeof(root), "copy_names"));
        (void)snprintf(copies, sizeof(copies), "%s/copies", root);
        ASSERT(zpf_name_pick(root, "game-1"));
        ASSERT(platform_file_shape_read(copies) == PLATFORM_FILE_SHAPE_MISSING);
        ASSERT(platform_directory_create(copies, 0700) == 0);
        (void)snprintf(one, sizeof(one), "%s/game-1", copies);
        (void)snprintf(two, sizeof(two), "%s/game-2", copies);
        ASSERT(zpf_name_file(one));
        ASSERT(platform_directory_create(two, 0700) == 0);
        ASSERT(zpf_name_pick(root, "game-3"));
        PASS();
    } _test_next:;
    if (root[0]) (void)test_rm_rf_recursive(root);
    return failures;
}

static int zpf_name_missing_ancestors(void)
{
    int failures = 0;
    char root[512] = {0}, absent[600], nested[650];
    TEST("copy names: first-use absent datadir and multiple ancestors stay absent") {
        ASSERT(test_mkdtemp(root, sizeof(root), "copy_names_missing"));
        (void)snprintf(absent, sizeof(absent), "%s/absent", root);
        (void)snprintf(nested, sizeof(nested), "%s/one/two", absent);
        ASSERT(zpf_name_pick(absent, "game-1"));
        ASSERT(zpf_name_pick(nested, "game-1"));
        ASSERT(platform_file_shape_read(absent) == PLATFORM_FILE_SHAPE_MISSING);
        ASSERT(platform_file_shape_read(nested) == PLATFORM_FILE_SHAPE_MISSING);
        PASS();
    } _test_next:;
    if (root[0]) (void)test_rm_rf_recursive(root);
    return failures;
}

#if !defined(_WIN32)
static bool zpf_name_advisory_or_refused(const char *root)
{
    char name[ZCL_PACKAGE_ADOPT_NAME_MAX + 1u], path[4400], expected[4400];
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.test.copy_name.v1");
    int n = snprintf(expected, sizeof(expected), "%s/copies/game-1", root);
    bool picked = zcl_package_copy_pick_name(root, "Game", name, path, sizeof(path), &reply);
    bool ok = picked ? n > 0 && (size_t)n < sizeof(expected) &&
        !strcmp(name, "game-1") && !strcmp(path, expected) :
        reply.status != ZCL_COMMAND_STATUS_PASSED && reply.error.code[0] &&
        reply.error.message[0] && !reply.error.mutated;
    zcl_command_reply_free(&reply);
    return ok;
}
static bool zpf_name_blocker_unchanged(const char *path)
{
    static const char marker[] = "copy-name blocker must survive\n";
    char bytes[sizeof(marker)];
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(bytes, 1, sizeof(bytes), f);
    bool ok = n == sizeof(marker) - 1 && !memcmp(bytes, marker, n) &&
        feof(f) && !ferror(f);
    if (fclose(f) != 0) ok = false;
    return ok;
}
static bool zpf_name_checkout_refused(const struct zpf_world *w, const char *root)
{
    char destination[4400];
    int n = snprintf(destination, sizeof(destination), "%s/copies/game-1", root);
    if (n <= 0 || (size_t)n >= sizeof(destination)) return false;
    struct vcs_package_store *store = vcs_package_store_open(w->datadir, vcs_package_store_quota_bytes());
    if (!store) return false;
    struct vcs_package_checkout_metrics metrics;
    enum vcs_package_checkout_result rc = vcs_package_checkout(
        store, w->origin_package, destination, &metrics);
    vcs_package_store_close(store);
    return rc == VCS_PACKAGE_CHECKOUT_DESTINATION;
}
#endif

/* Name selection may stay advisory or improve to an early refusal. The
 * actual checkout must reject invalid parents without replacing their bytes. */
static int zpf_name_invalid_parent_advisory(const struct zpf_world *w)
{
    int failures = 0;
#if !defined(_WIN32)
    char root[512] = {0}, copies[600], nested[650];
    TEST("copy names: invalid parent never becomes an admitted checkout") {
        ASSERT(test_mkdtemp(root, sizeof(root), "copy_names_notdir"));
        (void)snprintf(copies, sizeof(copies), "%s/copies", root);
        ASSERT(zpf_write(root, "copies", "copy-name blocker must survive\n"));
        (void)snprintf(nested, sizeof(nested), "%s/child", copies);
        ASSERT(zpf_name_advisory_or_refused(root));
        ASSERT(zpf_name_advisory_or_refused(nested));
        ASSERT(zpf_name_blocker_unchanged(copies));
        ASSERT(zpf_name_checkout_refused(w, root));
        ASSERT(zpf_name_checkout_refused(w, nested));
        ASSERT(zpf_name_blocker_unchanged(copies));
        ASSERT(platform_file_shape_read(copies) == PLATFORM_FILE_SHAPE_REGULAR);
        PASS();
    } _test_next:;
    if (root[0]) (void)test_rm_rf_recursive(root);
#else
    (void)w;
    puts("SKIP (native package checkout is not qualified on Windows)");
#endif
    return failures;
}

static int zpf_name_links(void)
{
    int failures = 0;
#if !defined(_WIN32)
    char root[512] = {0}, copies[600], one[650];
    TEST("copy names: dangling leaf occupies suffix without following it") {
        ASSERT(test_mkdtemp(root, sizeof(root), "copy_names_links"));
        (void)snprintf(copies, sizeof(copies), "%s/copies", root);
        ASSERT(platform_directory_create(copies, 0700) == 0);
        (void)snprintf(one, sizeof(one), "%s/game-1", copies);
        ASSERT(symlink("missing-target", one) == 0);
        ASSERT(zpf_name_pick(root, "game-2"));
        ASSERT(platform_file_shape_read(one) == PLATFORM_FILE_SHAPE_SYMLINK);
        PASS();
    } _test_next:;
    if (root[0]) (void)test_rm_rf_recursive(root);
#else
    puts("SKIP (copy-name symlink controls require POSIX symlink fixtures)");
#endif
    return failures;
}

static int zpf_name_unreadable(void)
{
    int failures = 0;
#if !defined(_WIN32)
    char root[512] = {0}, copies[600] = {0};
    TEST("copy names: unsearchable copies refuses instead of selecting suffix") {
        ASSERT(test_mkdtemp(root, sizeof(root), "copy_names_denied"));
        (void)snprintf(copies, sizeof(copies), "%s/copies", root);
        ASSERT(platform_directory_create(copies, 0700) == 0);
        ASSERT(chmod(copies, 0000) == 0);
        char leaf[650];
        (void)snprintf(leaf, sizeof(leaf), "%s/game-1", copies);
        if (platform_file_shape_read(leaf) != PLATFORM_FILE_SHAPE_UNREADABLE) {
            puts("SKIP (host credentials bypass directory permission refusal)");
        } else {
            ASSERT(zpf_name_pick(root, NULL));
        }
        PASS();
    } _test_next:;
    if (copies[0]) (void)chmod(copies, 0700);
    if (root[0]) (void)test_rm_rf_recursive(root);
#else
    puts("SKIP (copy-name permission control requires POSIX permission fixtures)");
#endif
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
    failures += zpf_name_occupied();
    failures += zpf_name_missing_ancestors();
    failures += zpf_name_invalid_parent_advisory(&w);
    failures += zpf_name_links();
    failures += zpf_name_unreadable();
    failures += zpf_mcp_confirmation(&w);
    failures += zpf_fork_records_parent(&w, fork_version);
    failures += zpf_no_change_refusals(&w);
    failures += zpf_index_head_refusal(&w);
    failures += zpf_save_and_restore(&w, fork_version);
    failures += zpf_unsaved_refusal(&w);
    failures += zpf_share_names_parent(&w, shared_release);
    failures += zpf_selected_share(&w, fork_version);
    failures += zpf_tamper_refusals(&w, shared_release);
    failures += zpf_torn_copy_reads(&w);
    char first[700] = {0}, second[700] = {0};
    failures += zpf_adopt_mcp(&w);
    failures += zpf_adopt_two_copies(&w, first, second);
    failures += zpf_adopt_local_and_foreign(&w, first, second);
    failures += zpf_adopt_hand_edit(&w, first);
    failures += zpf_adopt_remix_plan(&w, shared_release);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}
