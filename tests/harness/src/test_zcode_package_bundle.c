/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: share a personal package copy with a friend by one file, with no
 * account and no node. Alice forks skycombat, saves an edit and signs the
 * share with her own local publisher key (zcode.package.bundle.sign, created 0600 on
 * first use, owner-only); the confirm writes one .z23share file and prints one
 * share line. Bob, in a second HOME with no node, verifies the file, must name
 * Alice's publisher fingerprint and the package root before anything is
 * written, and gets a copy whose fork record names Alice's release and whose
 * lineage names Alice's parent. A flipped byte, a missing or wrong trust and
 * MCP signing or receiving are refused. Leaves run the way the CLI and MCP run
 * them: the registry input contract first, then the bound handler. */

#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "command/native_command.h"
#include "command/native_zcode_package_bundle.h"
#include "command/native_zcode_package_copy.h"
#include "config/command_catalog.h"
#include "config/boot_app_host.h"
#include "crypto/sha256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "mcp/mcp_policy.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include "vcs/bundle_carry.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZPB_SOURCE "apps/skycombat"
#define ZPB_DAY 20400

struct zpb_world {
    char root[512];
    char alice_home[600], alice_datadir[600], alice_copy[600];
    char bob_home[600], bob_datadir[600], bob_copy[600];
    char share_file[700];
    char origin_release[65], origin_package[65];
    char fingerprint[67], shared_release[65], shared_package[65];
    char saved_home[1024];
};

struct zpb_leaf {
    struct json_value in;
    struct zcl_command_request req;
    struct zcl_command_reply out;
};

static void zpb_open(struct zpb_leaf *l)
{
    memset(l, 0, sizeof(*l));
    json_init(&l->in);
    json_set_object(&l->in);
    zcl_command_reply_init(&l->out, "zcl.test.zcode_package_bundle.v1");
}

static void zpb_close(struct zpb_leaf *l)
{
    zcl_command_reply_free(&l->out);
    json_free(&l->in);
}

static const struct zcl_command_spec *zpb_spec(const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    for (size_t i = 0; reg && i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

/* The registry contract, then the handler; the reply must fit the budget. */
static bool zpb_exec(const char *path, struct zpb_leaf *l)
{
    char why[256] = "no such leaf";
    const struct zcl_command_spec *spec = zpb_spec(path);
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
        printf("  [%s reply over its budget]\n", path);
        return false;
    }
    return true;
}

/* Run and require a pass. */
static bool zpb_pass(const char *path, struct zpb_leaf *l)
{
    if (!zpb_exec(path, l))
        return false;
    if (l->out.status != ZCL_COMMAND_STATUS_PASSED)
        printf("  [%s refused %s: %s]\n", path, l->out.error.code,
               l->out.error.message);
    return l->out.status == ZCL_COMMAND_STATUS_PASSED;
}

static bool zpb_refusal(const struct zpb_leaf *l, const char *code)
{
    if (l->out.status != ZCL_COMMAND_STATUS_PASSED &&
        strcmp(l->out.error.code, code) == 0)
        return true;
    printf("  [expected %s; status=%d code=%s]\n", code, (int)l->out.status,
           l->out.error.code);
    return false;
}

static const char *zpb_get(const struct zpb_leaf *l, const char *key)
{
    const char *s = json_get_str(json_get(&l->out.data, key));
    return s ? s : "";
}

/* Plan, then repeat with the returned plan_id and confirm:true. */
static bool zpb_plan_confirm(const char *path, struct zpb_leaf *l)
{
    char plan[65];
    if (!zpb_pass(path, l) || strlen(zpb_get(l, "plan_id")) != 64)
        return false;
    (void)snprintf(plan, sizeof(plan), "%s", zpb_get(l, "plan_id"));
    zcl_command_reply_free(&l->out);
    zcl_command_reply_init(&l->out, "zcl.test.zcode_package_bundle.v1");
    (void)json_push_kv_str(&l->in, "plan_id", plan);
    (void)json_push_kv_bool(&l->in, "confirm", true);
    return zpb_pass(path, l);
}

static bool zpb_put_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && fputs(text, f) >= 0;
    return f ? fclose(f) == 0 && ok : false;
}

static bool zpb_as(const char *home)
{
    return setenv("HOME", home, 1) == 0;
}

/* The original publisher signs skycombat with a release key made by
 * plugin_keygen, through the same key glue the sign leaf uses. */
static bool zpb_publish_origin(struct zpb_world *w)
{
    char key[700], pubhex[PLUGIN_HEX_PUBLIC_KEY + 1];
    struct plugin_dist_published why;
    struct vcs_package_prepare_options o = {
        .dir = ZPB_SOURCE, .publisher_sequence = 1, .reward_address = "",
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
            VCS_PACKAGE_PREPARE_OK)
        return false;
    bool ok = plugin_dist_release_key_sign(key, p.signing_digest,
                                           o.publisher_pubkey,
                                           p.release.signature,
                                           &why) == PLUGIN_DIST_OK &&
              vcs_package_release_serialize(&p.release, &wire, &wire_len) ==
                  VCS_PACKAGE_RELEASE_OK;
    struct zcl_command_reply r;
    zcl_command_reply_init(&r, "zcl.test.zcode_package_bundle.v1");
    const struct zcl_native_local_publication pub = {
        .datadir = w->alice_datadir, .source_directory = ZPB_SOURCE,
        .release_wire = wire, .release_wire_len = wire_len,
        .manifest_wire = p.manifest_wire,
        .manifest_wire_len = p.manifest_wire_len,
        .recipe_wire = p.recipe_wire, .recipe_wire_len = p.recipe_wire_len,
        .has_day = true, .day = ZPB_DAY,
    };
    if (ok)
        zcl_native_zcode_local_publication_commit(&pub, &r);
    ok = ok && r.status == ZCL_COMMAND_STATUS_PASSED;
    zcl_hex_encode(p.signing_digest, 32, w->origin_release);
    zcl_hex_encode(p.package_root, 32, w->origin_package);
    zcl_command_reply_free(&r);
    free(wire);
    vcs_package_prepared_free(&p);
    return ok;
}

/* Alice forks, renames the namespace (it is bound to the original key),
 * edits a source file and saves the version she will share. */
static bool zpb_alice_copy(const struct zpb_world *w)
{
    static const char meta[] =
        "{\n  \"schema\": 1,\n  \"name\": \"alice/skycombat\",\n"
        "  \"semver\": \"0.2.0\",\n  \"language\": \"c23\",\n"
        "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
        "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n";
    struct zpb_leaf fork, save;
    char path[800];
    zpb_open(&fork);
    (void)json_push_kv_str(&fork.in, "root", w->origin_release);
    (void)json_push_kv_str(&fork.in, "destination", w->alice_copy);
    (void)json_push_kv_str(&fork.in, "datadir", w->alice_datadir);
    bool ok = zpb_plan_confirm("zcode.package.fork", &fork);
    zpb_close(&fork);
    (void)snprintf(path, sizeof(path), "%s/zcode-package.json", w->alice_copy);
    ok = ok && zpb_put_file(path, meta);
    (void)snprintf(path, sizeof(path), "%s/src/zpb_boost.c", w->alice_copy);
    ok = ok && zpb_put_file(path, "/* Alice's boost: twice the speed. */\n"
                                  "int zpb_boost(void) { return 2; }\n");
    zpb_open(&save);
    (void)json_push_kv_str(&save.in, "dir", w->alice_copy);
    ok = ok && zpb_plan_confirm("zcode.package.version.save", &save);
    zpb_close(&save);
    return ok;
}

static bool zpb_world_init(struct zpb_world *w)
{
    memset(w, 0, sizeof(*w));
    const char *home = getenv("HOME");
    (void)snprintf(w->saved_home, sizeof(w->saved_home), "%s",
                   home ? home : "");
    if (!test_mkdtemp(w->root, sizeof(w->root), "zcode_package_bundle"))
        return false;
    (void)snprintf(w->alice_home, sizeof(w->alice_home), "%s/alice", w->root);
    (void)snprintf(w->alice_datadir, sizeof(w->alice_datadir),
                   "%s/alice/datadir", w->root);
    (void)snprintf(w->alice_copy, sizeof(w->alice_copy),
                   "%s/alice/my-skycombat", w->root);
    (void)snprintf(w->bob_home, sizeof(w->bob_home), "%s/bob", w->root);
    (void)snprintf(w->bob_datadir, sizeof(w->bob_datadir),
                   "%s/bob/datadir", w->root);
    (void)snprintf(w->bob_copy, sizeof(w->bob_copy),
                   "%s/bob/skycombat-from-alice", w->root);
    (void)snprintf(w->share_file, sizeof(w->share_file),
                   "%s/alice/skycombat.z23share", w->root);
    return mkdir(w->alice_home, 0700) == 0 &&
           mkdir(w->alice_datadir, 0700) == 0 &&
           mkdir(w->bob_home, 0700) == 0 && zpb_as(w->alice_home) &&
           zpb_publish_origin(w) && zpb_alice_copy(w);
}

static int zpb_agents_never_sign(const struct zpb_world *w)
{
    int failures = 0;
    TEST("zcode package bundle sign/bundle receive: MCP is refused; the plan names "
         "the owner's command") {
        static const char *const owner_only[] = {
            "zcode.package.bundle.sign", "zcode.package.bundle.receive",
        };
        for (size_t i = 0; i < 2; i++) {
            const struct zcl_command_spec *spec = zpb_spec(owner_only[i]);
            struct mcp_refusal why = {0};
            struct json_value in;
            ASSERT(spec != NULL);
            ASSERT(spec->authority == ZCL_COMMAND_AUTH_OWNER);
            json_init(&in);
            json_set_object(&in);
            (void)json_push_kv_str(&in, "dir", w->alice_copy);
            bool allowed = mcp_policy_allows(spec, zcl_command_catalog(), &in,
                                             &why);
            json_free(&in);
            ASSERT(!allowed && why.code &&
                   strcmp(why.code, "MUTATION_REFUSED_OWNER_AUTHORITY") == 0);
        }
        const struct zcl_command_spec *verify =
            zpb_spec("zcode.package.bundle.verify");
        struct mcp_refusal why = {0};
        struct json_value in;
        json_init(&in);
        json_set_object(&in);
        ASSERT(verify && mcp_policy_allows(verify, zcl_command_catalog(), &in,
                                           &why));
        json_free(&in);
        /* An agent's share plan tells the human the one command to run. */
        struct zpb_leaf share;
        zpb_open(&share);
        (void)json_push_kv_str(&share.in, "dir", w->alice_copy);
        (void)json_push_kv_str(&share.in, "datadir", w->alice_datadir);
        (void)json_push_kv_str(&share.in, "publisher_pubkey",
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        ASSERT(zpb_pass("zcode.package.share", &share));
        ASSERT(strstr(zpb_get(&share, "next"), "z23 zcode package bundle sign") !=
               NULL);
        zpb_close(&share);
        PASS();
    } _test_next:;
    return failures;
}

static bool zpb_sign_input(struct zpb_leaf *l, const struct zpb_world *w)
{
    zpb_open(l);
    return json_push_kv_str(&l->in, "dir", w->alice_copy) &&
           json_push_kv_str(&l->in, "datadir", w->alice_datadir) &&
           json_push_kv_str(&l->in, "output", w->share_file) &&
           json_push_kv_int(&l->in, "day", ZPB_DAY);
}

static int zpb_alice_signs(struct zpb_world *w)
{
    int failures = 0;
    TEST("zcode package bundle sign: the owner key is made 0600 once, shown by "
         "fingerprint, and the confirm writes one share file") {
        struct zpb_leaf l;
        struct stat st;
        char key[700];
        ASSERT(zpb_as(w->alice_home));
        ASSERT(zpb_sign_input(&l, w));
        ASSERT(zpb_pass("zcode.package.bundle.sign", &l));
        (void)snprintf(key, sizeof(key), "%s/.z23/zcode_publisher.key",
                       w->alice_home);
        ASSERT(stat(key, &st) == 0 && (st.st_mode & 0777) == 0600);
        ASSERT(strcmp(zpb_get(&l, "key_path"), key) == 0);
        ASSERT(json_get_bool(json_get(&l.out.data, "key_created")));
        (void)snprintf(w->fingerprint, sizeof(w->fingerprint), "%s",
                       zpb_get(&l, "publisher_fingerprint"));
        ASSERT(strlen(w->fingerprint) == 66);
        ASSERT(stat(w->share_file, &st) != 0);
        char plan[65];
        (void)snprintf(plan, sizeof(plan), "%s", zpb_get(&l, "plan_id"));
        ASSERT(stat(key, &st) == 0);
        ino_t key_inode = st.st_ino;
        zpb_close(&l);

        /* The confirm reuses the same key file: same fingerprint, same file. */
        ASSERT(zpb_sign_input(&l, w));
        (void)json_push_kv_str(&l.in, "plan_id", plan);
        (void)json_push_kv_bool(&l.in, "confirm", true);
        ASSERT(zpb_pass("zcode.package.bundle.sign", &l));
        ASSERT(stat(key, &st) == 0 && st.st_ino == key_inode &&
               (st.st_mode & 0777) == 0600);
        ASSERT(strcmp(zpb_get(&l, "publisher_fingerprint"), w->fingerprint) ==
               0);
        (void)snprintf(w->shared_release, 65, "%s", zpb_get(&l, "release_id"));
        (void)snprintf(w->shared_package, 65, "%s",
                       zpb_get(&l, "package_root"));
        ASSERT(strlen(w->shared_release) == 64);
        ASSERT(strcmp(zpb_get(&l, "parent_release_root"),
                      w->origin_release) == 0);
        const char *line = zpb_get(&l, "share_line");
        ASSERT(strstr(line, "alice/skycombat") && strstr(line, w->fingerprint));
        ASSERT(strstr(line, w->shared_package) && strstr(line, w->share_file));
        ASSERT(stat(w->share_file, &st) == 0 && S_ISREG(st.st_mode));
        zpb_close(&l);
        PASS();
    } _test_next:;
    return failures;
}

static bool zpb_fixture_offer(const uint8_t *bytes, size_t len, struct zcl_app_offer *offer)
{
    struct vcs_package_share share = {0}; const char *reason = NULL;
    uint8_t carrier[32], digest[32]; struct sha256_ctx hash;
    bool ok = vcs_bundle_root_of(bytes, len, carrier) == VCS_BUNDLE_OK &&
         vcs_package_share_load(&share, bytes, len, &reason) &&
         vcs_package_share_check_source(&share, &reason);
    if (ok) {
        memset(offer, 0, sizeof(*offer));
        sha256_init(&hash); sha256_write(&hash, bytes, len); sha256_finalize(&hash, digest);
        zcl_hex_encode(carrier, 32, offer->carrier); zcl_hex_encode(digest, 32, offer->sha256);
        (void)snprintf(offer->name, sizeof(offer->name), "%s", share.release.name);
        zcl_hex_encode(share.release.package_root, 32, offer->root);
        zcl_hex_encode(share.release.publisher_pubkey, 33, offer->publisher);
        (void)snprintf(offer->onion, sizeof(offer->onion), "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion");
        offer->size = (int64_t)len;
    }
    vcs_package_share_cleanup(&share);
    return ok;
}

/* Reuse the real saved-copy/signing journey for isolated host lifecycle tests.
 * On success the caller owns fixture_root and removes it after use. */
bool test_app_host_fixture_create(char *fixture_root, size_t root_cap,
                                  char *share_path, size_t share_cap,
                                  struct zcl_app_offer *offer)
{
    struct zpb_world w = {0};
    size_t len = 0;
    uint8_t *bytes = NULL;
    chain_params_select(CHAIN_MAIN);
    bool ok = fixture_root && share_path && offer && zpb_world_init(&w) &&
              zpb_alice_signs(&w) == 0 && strlen(w.root) < root_cap &&
              strlen(w.share_file) < share_cap;
    if (ok) bytes = zcl_native_source_bundle_read(w.share_file, &len);
    ok = ok && bytes && zpb_fixture_offer(bytes, len, offer);
    if (ok) {
        (void)snprintf(fixture_root, root_cap, "%s", w.root);
        (void)snprintf(share_path, share_cap, "%s", w.share_file);
    }
    free(bytes);
    if (w.saved_home[0]) (void)setenv("HOME", w.saved_home, 1);
    if (!ok && w.root[0]) (void)test_rm_rf_recursive(w.root);
    return ok;
}

static void zpb_receive_input_at_day(struct zpb_leaf *l, const char *file,
    const char *datadir, const char *destination, int day)
{
    zpb_open(l);
    (void)json_push_kv_str(&l->in, "file", file);
    (void)json_push_kv_str(&l->in, "destination", destination);
    (void)json_push_kv_str(&l->in, "datadir", datadir);
    (void)json_push_kv_int(&l->in, "day", day);
}

static void zpb_receive_input(struct zpb_leaf *l, const char *file,
                              const char *datadir, const char *destination)
{
    zpb_receive_input_at_day(l, file, datadir, destination, ZPB_DAY);
}

/* Confirm one receive of Bob's plan with the given trust (NULL leaves it
 * out). */
static bool zpb_receive_at_day(struct zpb_leaf *l, const struct zpb_world *w,
                        const char *plan, const char *publisher,
                        const char *root, int day)
{
    zpb_receive_input_at_day(l, w->share_file, w->bob_datadir, w->bob_copy, day);
    (void)json_push_kv_str(&l->in, "plan_id", plan);
    (void)json_push_kv_bool(&l->in, "confirm", true);
    if (publisher)
        (void)json_push_kv_str(&l->in, "trust_publisher", publisher);
    if (root)
        (void)json_push_kv_str(&l->in, "trust_root", root);
    return zpb_exec("zcode.package.bundle.receive", l);
}

static bool zpb_receive(struct zpb_leaf *l, const struct zpb_world *w,
                        const char *plan, const char *publisher,
                        const char *root)
{
    return zpb_receive_at_day(l, w, plan, publisher, root, ZPB_DAY);
}

static bool zpb_lineage_names(const struct zpb_world *w)
{
    struct zpb_leaf l;
    char workspace[700];
    (void)snprintf(workspace, sizeof(workspace), "%s/ws", w->bob_home);
    if (mkdir(workspace, 0700) != 0)
        return false;
    zpb_open(&l);
    (void)json_push_kv_str(&l.in, "workspace", workspace);
    (void)json_push_kv_str(&l.in, "package_root", w->shared_package);
    (void)json_push_kv_str(&l.in, "datadir", w->bob_datadir);
    bool ok = zpb_pass("zcode.commons.lineage", &l);
    const struct json_value *row = json_at(json_get(&l.out.data, "releases"),
                                           0);
    const char *release = row ? json_get_str(json_get(row, "release_root"))
                              : NULL;
    const char *parent =
        row ? json_get_str(json_get(row, "parent_release_root")) : NULL;
    ok = ok && release && parent &&
         strcmp(release, w->shared_release) == 0 &&
         strcmp(parent, w->origin_release) == 0;
    zpb_close(&l);
    return ok;
}

/* The copy's fork record names the shared release, and its fork commit is the
 * copy_root the trust record is keyed by: the adopt check reads both from
 * zcl_package_copy_open (fork_version, parent_release) after any later edit. */
static bool zpb_copy_names_release(const struct zpb_world *w,
                                   const char *copy_root_hex)
{
    struct zcl_package_copy copy;
    struct zcl_command_reply r;
    char hex[65], fork[65];
    zcl_command_reply_init(&r, "zcl.test.zcode_package_bundle.v1");
    bool ok = zcl_package_copy_open(w->bob_copy, &copy, &r,
                                    "zcode.package.bundle.receive");
    if (ok) {
        zcl_hex_encode(copy.parent_release, 32, hex);
        zcl_hex_encode(copy.fork_version, 32, fork);
    }
    ok = ok && strcmp(hex, w->shared_release) == 0 &&
         strcmp(fork, copy_root_hex) == 0;
    zcl_package_copy_close(&copy);
    zcl_command_reply_free(&r);
    return ok;
}

static bool zpb_trust_recorded(const struct zpb_world *w,
                               const char *copy_root_hex)
{
    uint8_t copy_root[32], release[32], publisher[33], package[32];
    struct zcl_package_receive_trust trust;
    return zcl_hex_decode(copy_root_hex, copy_root, 32) &&
           zcl_hex_decode(w->shared_release, release, 32) &&
           zcl_hex_decode(w->fingerprint, publisher, 33) &&
           zcl_hex_decode(w->shared_package, package, 32) &&
           zcl_package_receive_trust_read(w->bob_datadir, copy_root, release,
                                          &trust) &&
           memcmp(trust.publisher, publisher, 33) == 0 &&
           memcmp(trust.package_root, package, 32) == 0;
}

/* The reusable verifier must agree with the command on the signed identity
 * and must refuse a forged publisher even if the rest of the file is intact. */
static bool zpb_shared_equivalence(const struct zpb_world *w)
{
    size_t len = 0;
    uint8_t *bytes = zcl_native_source_bundle_read(w->share_file, &len);
    struct vcs_package_share share = {0};
    const char *reason = NULL;
    char publisher[67], root[65], release[65];
    memset(&share, 0xa5, sizeof(share));
    bool ok = !vcs_package_share_load(&share, NULL, 0, NULL);
    vcs_package_share_cleanup(&share);
    ok = ok && bytes && vcs_package_share_load(&share, bytes, len, &reason) &&
         vcs_package_share_check_source(&share, &reason) &&
         !vcs_package_share_check_source(&share, &reason);
    if (ok) {
        zcl_hex_encode(share.release.publisher_pubkey, 33, publisher);
        zcl_hex_encode(share.release.package_root, 32, root);
        zcl_hex_encode(share.release_id, 32, release);
        ok = strcmp(publisher, w->fingerprint) == 0 &&
             strcmp(root, w->shared_package) == 0 &&
             strcmp(release, w->shared_release) == 0;
    }
    size_t at = 0, manifest_at = 0;
    if (ok) {
        manifest_at = (size_t)(share.wires.manifest - bytes);
        for (; at + 33 <= len; at++)
            if (memcmp(bytes + at, share.release.publisher_pubkey, 33) == 0) break;
        ok = at + 33 <= len;
    }
    vcs_package_share_cleanup(&share);
    if (ok) {
        uint8_t original = bytes[manifest_at];
        bytes[manifest_at] ^= 0xffu;
        ok = !vcs_package_share_load(&share, bytes, len, &reason) &&
             !vcs_package_share_check_source(&share, &reason);
        vcs_package_share_cleanup(&share);
        bytes[manifest_at] = original;
    }
    if (ok) {
        bytes[at + 1] ^= 1u;
        ok = !vcs_package_share_load(&share, bytes, len, &reason);
        vcs_package_share_cleanup(&share);
    }
    free(bytes);
    return ok;
}

static bool zpb_host_negatives(struct vcs_package_store *store, struct zcl_app_offer *offer,
                               const uint8_t carrier[32], const char *publisher)
{
    uint64_t generation = 0;
    bool ok = boot_app_host_verify_carrier(store, offer, &generation) && generation != 0;
    char original = offer->sha256[0];
    offer->sha256[0] = original == '0' ? '1' : '0';
    ok = ok && !boot_app_host_verify_carrier(store, offer, &generation);
    offer->sha256[0] = original;
    original = offer->root[0];
    offer->root[0] = original == '0' ? '1' : '0';
    ok = ok && !boot_app_host_verify_carrier(store, offer, &generation);
    offer->root[0] = original;
    offer->publisher[3] = offer->publisher[3] == '0' ? '1' : '0';
    ok = ok && !boot_app_host_verify_carrier(store, offer, &generation);
    (void)snprintf(offer->publisher, sizeof(offer->publisher), "%s", publisher);
    return ok && vcs_package_store_pin(store, carrier, false) == VCS_PACKAGE_STORE_OK &&
           !boot_app_host_verify_carrier(store, offer, &generation);
}

static bool zpb_host_carrier(const struct zpb_world *w)
{
    char datadir[800];
    (void)snprintf(datadir, sizeof(datadir), "%s/host-store", w->root);
    struct vcs_package_store *store = vcs_package_store_open(datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    size_t len = 0;
    uint8_t *bytes = zcl_native_source_bundle_read(w->share_file, &len);
    uint8_t carrier[32], digest[32];
    struct zcl_app_offer offer = {0}; struct sha256_ctx hash;
    struct vcs_package_share share = {0}; const char *reason = NULL;
    bool ok = store && bytes && vcs_bundle_put_to_no_evict(store, bytes, len, carrier) == VCS_BUNDLE_OK &&
              vcs_package_store_pin(store, carrier, true) == VCS_PACKAGE_STORE_OK &&
              vcs_package_share_load(&share, bytes, len, &reason);
    if (ok) {
        sha256_init(&hash); sha256_write(&hash, bytes, len); sha256_finalize(&hash, digest);
        zcl_hex_encode(carrier, 32, offer.carrier); zcl_hex_encode(digest, 32, offer.sha256);
        (void)snprintf(offer.name, sizeof(offer.name), "%s", share.release.name);
        (void)snprintf(offer.root, sizeof(offer.root), "%s", w->shared_package);
        (void)snprintf(offer.publisher, sizeof(offer.publisher), "%s", w->fingerprint);
        (void)snprintf(offer.onion, sizeof(offer.onion), "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion");
        offer.size = (int64_t)len;
        ok = zpb_host_negatives(store, &offer, carrier, w->fingerprint);
    }
    vcs_package_share_cleanup(&share);
    if (store) vcs_package_store_close(store);
    free(bytes);
    return ok;
}

static int zpb_bob_receives(const struct zpb_world *w)
{
    int failures = 0;
    TEST("zcode package bundle: a second HOME with no node verifies, must "
         "trust the fingerprint and root, and gets the lineage") {
        struct zpb_leaf l;
        struct stat st;
        ASSERT(zpb_as(w->bob_home));
        ASSERT(zpb_shared_equivalence(w));
        ASSERT(zpb_host_carrier(w));
        zpb_open(&l);
        (void)json_push_kv_str(&l.in, "file", w->share_file);
        ASSERT(zpb_pass("zcode.package.bundle.verify", &l));
        ASSERT(strcmp(zpb_get(&l, "publisher_fingerprint"), w->fingerprint) ==
               0);
        ASSERT(strcmp(zpb_get(&l, "package_root"), w->shared_package) == 0);
        ASSERT(strcmp(zpb_get(&l, "release_id"), w->shared_release) == 0);
        ASSERT(strcmp(zpb_get(&l, "parent_release_root"), w->origin_release) ==
               0);
        ASSERT(strstr(zpb_get(&l, "next"), w->fingerprint) != NULL);
        zpb_close(&l);

        /* The owner's plan shows the same publisher and names the confirm. */
        char plan[65];
        zpb_receive_input(&l, w->share_file, w->bob_datadir, w->bob_copy);
        ASSERT(zpb_pass("zcode.package.bundle.receive", &l));
        ASSERT(strcmp(zpb_get(&l, "publisher_fingerprint"), w->fingerprint) ==
               0);
        ASSERT(strstr(zpb_get(&l, "next"), "trust_publisher") != NULL);
        (void)snprintf(plan, sizeof(plan), "%s", zpb_get(&l, "plan_id"));
        ASSERT(strlen(plan) == 64);
        zpb_close(&l);

        ASSERT(zpb_receive(&l, w, plan, NULL, NULL));
        ASSERT(zpb_refusal(&l, "TRUST_REQUIRED"));
        ASSERT(stat(w->bob_copy, &st) != 0);
        zpb_close(&l);
        ASSERT(zpb_receive(&l, w, plan,
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            w->shared_package));
        ASSERT(zpb_refusal(&l, "TRUST_MISMATCH"));
        zpb_close(&l);
        ASSERT(zpb_receive(&l, w, plan, w->fingerprint, w->origin_package));
        ASSERT(zpb_refusal(&l, "TRUST_MISMATCH"));
        ASSERT(stat(w->bob_copy, &st) != 0);
        ASSERT(stat(w->bob_datadir, &st) != 0);
        zpb_close(&l);

        ASSERT(zpb_receive(&l, w, plan, w->fingerprint, w->shared_package));
        ASSERT(l.out.status == ZCL_COMMAND_STATUS_PASSED);
        char copy_root[65];
        (void)snprintf(copy_root, sizeof(copy_root), "%s",
                       zpb_get(&l, "version"));
        ASSERT(strcmp(zpb_get(&l, "parent_release_root"), w->origin_release) ==
               0);
        zpb_close(&l);
        ASSERT(zpb_copy_names_release(w, copy_root));
        ASSERT(zpb_lineage_names(w));
        ASSERT(zpb_trust_recorded(w, copy_root));
        PASS();
    } _test_next:;
    return failures;
}

/* Flip one byte at offset (from the end when negative) of a copy. */
static bool zpb_flipped_copy(const char *from, const char *to, long offset)
{
    FILE *in = fopen(from, "rb"), *out = fopen(to, "wb");
    bool ok = in && out;
    long at = 0, size = 0;
    if (ok && fseek(in, 0, SEEK_END) == 0)
        size = ftell(in);
    ok = ok && size > 0 && fseek(in, 0, SEEK_SET) == 0;
    long target = offset < 0 ? size + offset : offset;
    for (int c; ok && (c = fgetc(in)) != EOF; at++)
        ok = fputc(at == target ? (c ^ 0x01) : c, out) != EOF;
    if (in)
        fclose(in);
    if (out)
        ok = fclose(out) == 0 && ok;
    return ok;
}

static int zpb_flipped_refused(const struct zpb_world *w)
{
    int failures = 0;
    TEST("zcode package bundle: a flipped byte is refused and writes nothing") {
        static const long offsets[] = {64, 200, -5};
        char bad[800], datadir[800], copy[800];
        struct stat st;
        for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
            struct zpb_leaf l;
            (void)snprintf(bad, sizeof(bad), "%s/bob/flipped-%zu.z23share",
                           w->root, i);
            (void)snprintf(datadir, sizeof(datadir), "%s/bob/clean-%zu",
                           w->root, i);
            ASSERT(zpb_flipped_copy(w->share_file, bad, offsets[i]));
            ASSERT(mkdir(datadir, 0700) == 0);
            zpb_open(&l);
            (void)json_push_kv_str(&l.in, "file", bad);
            ASSERT(zpb_exec("zcode.package.bundle.verify", &l));
            ASSERT(zpb_refusal(&l, "BUNDLE_REFUSED"));
            zpb_close(&l);
            (void)snprintf(copy, sizeof(copy), "%s/bob/never-%zu", w->root, i);
            zpb_receive_input(&l, bad, datadir, copy);
            (void)json_push_kv_str(&l.in, "trust_publisher", w->fingerprint);
            (void)json_push_kv_str(&l.in, "trust_root", w->shared_package);
            ASSERT(zpb_exec("zcode.package.bundle.receive", &l));
            ASSERT(zpb_refusal(&l, "BUNDLE_REFUSED"));
            zpb_close(&l);
            (void)snprintf(bad, sizeof(bad), "%s/zcode", datadir);
            ASSERT(stat(bad, &st) != 0 && stat(copy, &st) != 0);
        }
        PASS();
    } _test_next:;
    return failures;
}

static bool zpb_source_is_two(const char *copy)
{
    char path[800], bytes[80];
    static const char expected[] = "/* Alice's boost: twice the speed. */\n"
                                   "int zpb_boost(void) { return 2; }\n";
    (void)snprintf(path, sizeof(path), "%s/src/zpb_boost.c", copy);
    FILE *file = fopen(path, "rb");
    if (!file) return false;
    size_t count = fread(bytes, 1, sizeof(bytes), file);
    bool ok = !ferror(file) && feof(file) && count == sizeof(expected) - 1 &&
              memcmp(bytes, expected, sizeof(expected) - 1) == 0;
    return fclose(file) == 0 && ok;
}

static int zpb_selected_recipient(const struct zpb_world *w, const char *file,
    const char *root, const char *release, int day)
{
    int failures = 0;
    struct zpb_world bob = *w;
    (void)snprintf(bob.bob_home, sizeof(bob.bob_home), "%s/selected-bob", w->root);
    (void)snprintf(bob.bob_datadir, sizeof(bob.bob_datadir), "%s/selected-bob/data", w->root);
    (void)snprintf(bob.bob_copy, sizeof(bob.bob_copy), "%s/selected-bob/copy", w->root);
    (void)snprintf(bob.share_file, sizeof(bob.share_file), "%s", file);
    (void)snprintf(bob.shared_package, sizeof(bob.shared_package), "%s", root);
    (void)snprintf(bob.shared_release, sizeof(bob.shared_release), "%s", release);
    TEST("zcode package bundle: fresh recipient materializes selected N, not later edits") {
        struct zpb_leaf l;
        char plan[65], copy_root[65];
        ASSERT(mkdir(bob.bob_home, 0700) == 0);
        ASSERT(zpb_as(bob.bob_home));
        zpb_receive_input_at_day(&l, bob.share_file, bob.bob_datadir, bob.bob_copy, day);
        ASSERT(zpb_pass("zcode.package.bundle.receive", &l));
        ASSERT(strcmp(zpb_get(&l, "package_root"), root) == 0);
        ASSERT(strcmp(zpb_get(&l, "release_id"), release) == 0);
        (void)snprintf(plan, sizeof(plan), "%s", zpb_get(&l, "plan_id"));
        zpb_close(&l);
        ASSERT(zpb_receive_at_day(&l, &bob, plan, bob.fingerprint, root, day));
        ASSERT(l.out.status == ZCL_COMMAND_STATUS_PASSED);
        (void)snprintf(copy_root, sizeof(copy_root), "%s", zpb_get(&l, "version"));
        zpb_close(&l);
        ASSERT(zpb_copy_names_release(&bob, copy_root));
        ASSERT(zpb_lineage_names(&bob));
        ASSERT(zpb_trust_recorded(&bob, copy_root));
        ASSERT(zpb_source_is_two(bob.bob_copy));
        PASS();
    } _test_next:;
    if (!zpb_as(w->alice_home)) failures++;
    return failures;
}

/* Deliberately bypass registry type validation to preserve the handler's
 * malformed-value refusal and its version-before-key validation order. */
static bool zpb_expected_type_refused(const struct zpb_world *w,
    const char *selected, const char *file)
{
    const struct zcl_command_spec *spec = zpb_spec("zcode.package.bundle.sign");
    if (!spec || !spec->handler) return false;
    for (unsigned i = 0; i < 2; ++i) {
        struct zpb_leaf l; zpb_open(&l);
        bool ok = json_push_kv_str(&l.in, "dir", w->alice_copy) &&
            json_push_kv_str(&l.in, "datadir", w->alice_datadir) &&
            json_push_kv_str(&l.in, "output", file) &&
            json_push_kv_bool(&l.in, "expected_publisher_pubkey", false);
        if (i) ok = ok && json_push_kv_str(&l.in, "version", selected);
        if (ok) {
            l.req.spec = spec; l.req.input = &l.in; l.req.invoked_name = spec->path;
            spec->handler(&l.req, &l.out);
            ok = zpb_refusal(&l, i ? "PUBLISHER_KEY_CHANGED" : "VERSION_REQUIRED") &&
                !l.out.error.mutated;
        }
        zpb_close(&l);
        if (!ok) return false;
    }
    return true;
}

static int zpb_selected_bundle(const struct zpb_world *w)
{
    int failures = 0;
    /* Alice already published in ZPB_DAY's week. Exercise another share in
     * the following week without bypassing the publisher's tier allowance. */
    const int selected_day = ZPB_DAY + 7;
    TEST("zcode package bundle: owner signs selected N after head and worktree advance") {
        struct zpb_leaf l;
        char selected[65], head[65], plan[65], root[65], file[800], source[800], release[65];
        ASSERT(zpb_as(w->alice_home));
        zpb_open(&l);
        (void)json_push_kv_str(&l.in, "dir", w->alice_copy);
        ASSERT(zpb_pass("zcode.package.version.list", &l));
        (void)snprintf(selected, sizeof(selected), "%s", zpb_get(&l, "head_version"));
        zpb_close(&l);
        (void)snprintf(file, sizeof(file), "%s/alice/selected.z23share", w->root);
        ASSERT(zpb_expected_type_refused(w, selected, file));
        zpb_open(&l);
        (void)json_push_kv_str(&l.in, "dir", w->alice_copy);
        (void)json_push_kv_str(&l.in, "datadir", w->alice_datadir);
        (void)json_push_kv_str(&l.in, "output", file);
        (void)json_push_kv_str(&l.in, "version", selected);
        (void)json_push_kv_int(&l.in, "day", selected_day);
        ASSERT(zpb_pass("zcode.package.bundle.sign", &l));
        ASSERT(strcmp(zpb_get(&l, "version"), selected) == 0 && strstr(zpb_get(&l, "next"), selected));
        (void)snprintf(plan, sizeof(plan), "%s", zpb_get(&l, "plan_id"));
        (void)snprintf(root, sizeof(root), "%s", zpb_get(&l, "package_root"));
        zpb_close(&l);
        (void)snprintf(source, sizeof(source), "%s/src/zpb_boost.c", w->alice_copy);
        ASSERT(zpb_put_file(source, "int zpb_boost(void) { return 3; }\n"));
        zpb_open(&l); (void)json_push_kv_str(&l.in, "dir", w->alice_copy);
        ASSERT(zpb_plan_confirm("zcode.package.version.save", &l));
        (void)snprintf(head, sizeof(head), "%s", zpb_get(&l, "version"));
        zpb_close(&l);
        ASSERT(strcmp(head, selected) != 0 && zpb_put_file(source, "int zpb_boost(void) { return 4; }\n"));
        zpb_open(&l);
        (void)json_push_kv_str(&l.in, "dir", w->alice_copy);
        (void)json_push_kv_str(&l.in, "datadir", w->alice_datadir);
        (void)json_push_kv_str(&l.in, "output", file);
        (void)json_push_kv_str(&l.in, "version", selected);
        (void)json_push_kv_int(&l.in, "day", selected_day);
        (void)json_push_kv_str(&l.in, "plan_id", plan);
        (void)json_push_kv_bool(&l.in, "confirm", true);
        ASSERT(zpb_pass("zcode.package.bundle.sign", &l));
        ASSERT(strcmp(zpb_get(&l, "version"), selected) == 0 && strcmp(zpb_get(&l, "package_root"), root) == 0);
        (void)snprintf(release, sizeof(release), "%s", zpb_get(&l, "release_id"));
        zpb_close(&l);
        zpb_open(&l); (void)json_push_kv_str(&l.in, "file", file);
        ASSERT(zpb_pass("zcode.package.bundle.verify", &l));
        ASSERT(strcmp(zpb_get(&l, "package_root"), root) == 0);
        zpb_close(&l);
        failures += zpb_selected_recipient(w, file, root, release, selected_day);
        if (failures) goto _test_next;
        zpb_open(&l); (void)json_push_kv_str(&l.in, "dir", w->alice_copy);
        ASSERT(zpb_pass("zcode.package.version.list", &l) && strcmp(zpb_get(&l, "head_version"), head) == 0);
        zpb_close(&l);
        FILE *f = fopen(source, "rb"); char bytes[80] = {0};
        ASSERT(f != NULL); size_t n = fread(bytes, 1, sizeof(bytes) - 1, f);
        ASSERT(fclose(f) == 0 && n > 0 && strcmp(bytes, "int zpb_boost(void) { return 4; }\n") == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_package_bundle(void)
{
    int failures = 0;
    struct zpb_world w;
    chain_params_select(CHAIN_MAIN);
    TEST("zcode package bundle: alice forks skycombat and saves an edit") {
        ASSERT(zpb_world_init(&w));
        PASS();
    } _test_next:;
    if (!failures) {
        failures += zpb_agents_never_sign(&w);
        failures += zpb_alice_signs(&w);
    }
    if (!failures) {
        failures += zpb_bob_receives(&w);
        failures += zpb_flipped_refused(&w);
        failures += zpb_selected_bundle(&w);
    }
    if (w.saved_home[0])
        (void)setenv("HOME", w.saved_home, 1);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}
