/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the receive half of the skycombat remix journey. Datadir A forks
 * the published Sky Combat source package, saves a change and shares it with
 * its parent. Datadir B, with nothing in common, receives that exact signed
 * carrier from A over the real swarm engines (two in-process engines wired
 * frame to frame; the same code a network peer reaches), admits it with
 * `zcode package admit` and checks it out. Proven: B's tree has A's head
 * package root and A's head bytes; B's lineage row names the parent release;
 * and one corrupted chunk during receive writes nothing to B: no tree, no
 * release, no lineage row. A fresh C also receives the same shared version
 * after A edits its working copy without saving or sharing again. */

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
#include "vcs/package_prepare.h"
#include "vcs/package_release.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"
#include "vcs/service_receipt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZPR_SOURCE "apps/skycombat"
#define ZPR_EDITED "src/philosophical_test.c"
#define ZPR_DAY 20400
#define ZPR_ORIGIN_SEED 0x31
#define ZPR_PLAYER_SEED 0x52
#define ZPR_PEER_A 1u
#define ZPR_PEER_B 2u
#define ZPR_ROUNDS 600
#define ZPR_SCHEMA "zcl.test.zcode_package_receive.v1"

static const char k_player_meta[] =
    "{\n  \"schema\": 1,\n  \"name\": \"player/skycombat\",\n"
    "  \"semver\": \"0.1.0\",\n  \"language\": \"c23\",\n"
    "  \"license\": \"Apache-2.0\",\n  \"include_dir\": \"include\",\n"
    "  \"source_dir\": \"src\",\n  \"dependencies\": []\n}\n";

struct zpr_world {
    char root[512];
    char a_dir[600], b_dir[600], a_copy[600], b_tree[600], workspace[600];
    char origin_release_hex[65], origin_package_hex[65];
    char shared_release_hex[65], shared_package_hex[65];
    char transport_hex[65];
};

struct zpr_node {
    struct vcs_package_store *store;
    struct vcs_service_book *book;
    struct vcs_swarm_engine *engine;
};

struct zpr_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

/* ── command plumbing: registry contract first, then the bound handler ── */

static void zpr_begin(struct zpr_call *c)
{
    memset(c, 0, sizeof(*c));
    json_init(&c->input);
    json_set_object(&c->input);
    zcl_command_reply_init(&c->reply, ZPR_SCHEMA);
}

static void zpr_end(struct zpr_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static bool zpr_run(const char *path, struct zpr_call *c)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec =
        reg ? zcl_command_registry_find(reg, path, NULL) : NULL;
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
    return true;
}

static bool zpr_passed(const struct zpr_call *c)
{
    if (c->reply.status == ZCL_COMMAND_STATUS_PASSED)
        return true;
    printf("  [refused %s: %s]\n", c->reply.error.code,
           c->reply.error.message);
    return false;
}

static bool zpr_refused(const struct zpr_call *c)
{
    return c->reply.status != ZCL_COMMAND_STATUS_PASSED;
}

static const char *zpr_str(const struct zpr_call *c, const char *key)
{
    const struct json_value *v = json_get(&c->reply.data, key);
    const char *s = v ? json_get_str(v) : NULL;
    return s ? s : "";
}

/* Plan then commit one mutating leaf whose input `c` already holds. */
static bool zpr_plan_commit(const char *path, struct zpr_call *c)
{
    char plan_id[65];
    if (!zpr_run(path, c) || !zpr_passed(c))
        return false;
    (void)snprintf(plan_id, sizeof(plan_id), "%s", zpr_str(c, "plan_id"));
    if (strlen(plan_id) != 64)
        return false;
    zcl_command_reply_free(&c->reply);
    zcl_command_reply_init(&c->reply, ZPR_SCHEMA);
    (void)json_push_kv_str(&c->input, "plan_id", plan_id);
    (void)json_push_kv_bool(&c->input, "confirm", true);
    return zpr_run(path, c) && zpr_passed(c);
}

/* ── keys and files ───────────────────────────────────────────────────── */

static bool zpr_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool zpr_sign(uint8_t seed, const uint8_t digest[32],
                     uint8_t signature[64])
{
    struct privkey sk;
    struct pubkey pk;
    struct uint256 hash;
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    memcpy(hash.data, digest, 32);
    if (!zpr_keypair(seed, &sk, &pk) ||
        !privkey_sign_compact(&sk, &hash, compact))
        return false;
    memcpy(signature, compact + 1, 64);
    return true;
}

static bool zpr_write(const char *dir, const char *rel, const char *text,
                      const char *mode)
{
    char path[900];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, mode);
    bool ok = f && fputs(text, f) >= 0;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

/* Whole-file read; the caller frees. */
static uint8_t *zpr_slurp(const char *dir, const char *rel, size_t *len)
{
    char path[900];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, rel);
    FILE *f = fopen(path, "rb");
    uint8_t *buf = NULL;
    size_t cap = 0, used = 0;
    *len = 0;
    while (f) {
        if (used == cap) {
            cap = cap ? cap * 2u : 65536u;
            uint8_t *grown = realloc(buf, cap);
            if (!grown) {
                free(buf);
                buf = NULL;
                break;
            }
            buf = grown;
        }
        size_t got = fread(buf + used, 1, cap - used, f);
        used += got;
        if (got == 0)
            break;
    }
    if (f)
        fclose(f);
    *len = used;
    return buf;
}

static bool zpr_same_bytes(const char *dir_a, const char *dir_b,
                           const char *rel)
{
    size_t la = 0, lb = 0;
    uint8_t *a = zpr_slurp(dir_a, rel, &la);
    uint8_t *b = zpr_slurp(dir_b, rel, &lb);
    bool same = a && b && la == lb && (la == 0 || memcmp(a, b, la) == 0);
    free(a);
    free(b);
    return same;
}

/* Prepare `dir` the way share does and return its package root. */
static bool zpr_tree_root(const char *dir, uint8_t root[32],
                          struct vcs_package_manifest *manifest)
{
    struct privkey sk;
    struct pubkey pk;
    struct vcs_package_prepare_options options = {
        .dir = dir, .publisher_sequence = 1, .reward_address = "",
        .chain_id = "zclassic-main",
    };
    struct vcs_package_prepared prepared;
    char detail[256] = {0};
    if (manifest)
        vcs_package_manifest_init(manifest);
    if (!zpr_keypair(ZPR_PLAYER_SEED, &sk, &pk))
        return false;
    memcpy(options.publisher_pubkey, pk.vch, 33);
    if (vcs_package_prepare(&options, &prepared, detail, sizeof(detail)) !=
        VCS_PACKAGE_PREPARE_OK)
        return false;
    memcpy(root, prepared.package_root, 32);
    bool ok = !manifest ||
        vcs_package_manifest_parse(
            prepared.manifest_wire,
            prepared.manifest_wire_len, manifest);
    vcs_package_prepared_free(&prepared);
    return ok;
}

/* ── publisher A: origin release, fork, change, share ─────────────────── */

static bool zpr_publish_origin(struct zpr_world *w)
{
    struct privkey sk;
    struct pubkey pk;
    struct vcs_package_prepare_options options = {
        .dir = ZPR_SOURCE, .publisher_sequence = 1, .reward_address = "",
        .chain_id = "zclassic-main",
    };
    struct vcs_package_prepared prepared;
    char detail[256] = {0};
    if (!zpr_keypair(ZPR_ORIGIN_SEED, &sk, &pk))
        return false;
    memcpy(options.publisher_pubkey, pk.vch, 33);
    if (vcs_package_prepare(&options, &prepared, detail, sizeof(detail)) !=
        VCS_PACKAGE_PREPARE_OK)
        return false;
    struct vcs_package_release release = prepared.release;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    bool ok = zpr_sign(ZPR_ORIGIN_SEED, prepared.signing_digest,
                       release.signature) &&
              vcs_package_release_serialize(&release, &wire, &wire_len) ==
                  VCS_PACKAGE_RELEASE_OK;
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, ZPR_SCHEMA);
    if (ok) {
        const struct zcl_native_local_publication publication = {
            .datadir = w->a_dir, .source_directory = ZPR_SOURCE,
            .release_wire = wire, .release_wire_len = wire_len,
            .manifest_wire = prepared.manifest_wire,
            .manifest_wire_len = prepared.manifest_wire_len,
            .recipe_wire = prepared.recipe_wire,
            .recipe_wire_len = prepared.recipe_wire_len,
            .has_day = true, .day = ZPR_DAY,
        };
        zcl_native_zcode_local_publication_commit(&publication, &reply);
        ok = reply.status == ZCL_COMMAND_STATUS_PASSED;
    }
    zcl_hex_encode(prepared.signing_digest, 32, w->origin_release_hex);
    zcl_hex_encode(prepared.package_root, 32, w->origin_package_hex);
    zcl_command_reply_free(&reply);
    free(wire);
    vcs_package_prepared_free(&prepared);
    return ok;
}

static bool zpr_fork_and_save(const struct zpr_world *w)
{
    struct zpr_call c;
    zpr_begin(&c);
    (void)json_push_kv_str(&c.input, "root", w->origin_package_hex);
    (void)json_push_kv_str(&c.input, "destination", w->a_copy);
    (void)json_push_kv_str(&c.input, "datadir", w->a_dir);
    bool ok = zpr_plan_commit("zcode.package.fork", &c);
    zpr_end(&c);
    ok = ok && zpr_write(w->a_copy, ZPR_EDITED, "/* player edit one */\n",
                         "ab") &&
         zpr_write(w->a_copy, "zcode-package.json", k_player_meta, "wb");
    zpr_begin(&c);
    (void)json_push_kv_str(&c.input, "dir", w->a_copy);
    ok = ok && zpr_plan_commit("zcode.package.version.save", &c);
    zpr_end(&c);
    return ok;
}

/* Plan, sign the returned digest as the player, commit. Fills the shared
 * release, package and transport roots from the commit reply. */
static bool zpr_share(struct zpr_world *w)
{
    struct zpr_call c;
    uint8_t digest[32], signature[64];
    char sig_hex[129], plan_id[65], pubkey[67];
    struct privkey sk;
    struct pubkey pk;
    zpr_begin(&c);
    bool ok = zpr_keypair(ZPR_PLAYER_SEED, &sk, &pk);
    if (ok)
        zcl_hex_encode(pk.vch, pk.size, pubkey);
    (void)json_push_kv_str(&c.input, "dir", w->a_copy);
    (void)json_push_kv_str(&c.input, "datadir", w->a_dir);
    (void)json_push_kv_str(&c.input, "publisher_pubkey", pubkey);
    (void)json_push_kv_int(&c.input, "day", ZPR_DAY);
    ok = ok && zpr_run("zcode.package.share", &c) && zpr_passed(&c) &&
         strcmp(zpr_str(&c, "parent_release_root"),
                w->origin_release_hex) == 0 &&
         zcl_hex_decode(zpr_str(&c, "signing_digest"), digest, 32) &&
         zpr_sign(ZPR_PLAYER_SEED, digest, signature);
    if (ok) {
        zcl_hex_encode(signature, 64, sig_hex);
        (void)snprintf(plan_id, sizeof(plan_id), "%s",
                       zpr_str(&c, "plan_id"));
        zcl_command_reply_free(&c.reply);
        zcl_command_reply_init(&c.reply, ZPR_SCHEMA);
        (void)json_push_kv_str(&c.input, "plan_id", plan_id);
        (void)json_push_kv_str(&c.input, "signature_hex", sig_hex);
        (void)json_push_kv_bool(&c.input, "confirm", true);
        ok = zpr_run("zcode.package.share", &c) && zpr_passed(&c);
    }
    if (ok) {
        (void)snprintf(w->shared_release_hex, 65, "%s",
                       zpr_str(&c, "release_id"));
        (void)snprintf(w->shared_package_hex, 65, "%s",
                       zpr_str(&c, "package_root"));
        (void)snprintf(w->transport_hex, 65, "%s",
                       zpr_str(&c, "transport_root"));
    }
    zpr_end(&c);
    return ok && strlen(w->transport_hex) == 64;
}

/* ── two swarm engines wired frame to frame ───────────────────────────── */

static bool zpr_node_open(struct zpr_node *n, const char *datadir)
{
    char zcode_dir[700];
    memset(n, 0, sizeof(*n));
    (void)snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    n->store = vcs_package_store_open(
        datadir, VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    n->book = vcs_service_book_load(zcode_dir);
    n->engine = vcs_swarm_engine_create(n->store, n->book, zcode_dir, NULL,
                                        NULL);
    return n->store && n->book && n->engine;
}

static void zpr_node_close(struct zpr_node *n)
{
    vcs_swarm_engine_free(n->engine);
    vcs_service_book_free(n->book);
    vcs_package_store_close(n->store);
    memset(n, 0, sizeof(*n));
}

static void zpr_key(uint8_t seed, uint8_t out[33])
{
    memset(out, seed, 33);
    out[0] = 0x02;
}

/* Flip the last payload byte of a chunk DATA frame; manifests pass. */
static bool zpr_corrupt_chunk(uint8_t *frame, size_t len)
{
    struct vcs_package_swarm_message msg;
    if (!vcs_package_swarm_parse(frame, len, &msg) ||
        msg.type != VCS_PACKAGE_SWARM_DATA ||
        msg.body.data.object.object_kind != VCS_PACKAGE_SWARM_OBJECT_CHUNK ||
        len == 0)
        return false;
    frame[len - 1] ^= 0xa5;
    return true;
}

struct zpr_pump {
    uint32_t invalid_data;
    uint32_t corrupted;
};

/* Answer one frame B queued for A, and hand A's DATA reply back to B. */
static void zpr_exchange(struct zpr_node *a, struct zpr_node *b,
                         const uint8_t *frame, size_t len, bool corrupt,
                         uint64_t now, struct zpr_pump *stats)
{
    struct vcs_swarm_frame_result answer =
        vcs_swarm_engine_handle_frame(a->engine, ZPR_PEER_B, frame, len,
                                      ZPR_DAY, now);
    if (answer.reply) {
        if (corrupt && zpr_corrupt_chunk(answer.reply, answer.reply_len))
            stats->corrupted++;
        struct vcs_swarm_frame_result got = vcs_swarm_engine_handle_frame(
            b->engine, ZPR_PEER_A, answer.reply, answer.reply_len, ZPR_DAY,
            now);
        if (got.penalty == VCS_SWARM_PENALTY_INVALID_DATA)
            stats->invalid_data++;
        free(got.reply);
    }
    free(answer.reply);
}

/* B fetches the carrier from A. Returns whether B's download completed. */
static bool zpr_receive(struct zpr_node *a, struct zpr_node *b,
                        const uint8_t transport[32], bool corrupt,
                        struct zpr_pump *stats)
{
    uint8_t key_a[33], key_b[33], frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    uint64_t target = 0;
    size_t len = 0;
    zpr_key(0x61, key_a);
    zpr_key(0x62, key_b);
    memset(stats, 0, sizeof(*stats));
    if (!vcs_swarm_engine_peer_add(a->engine, ZPR_PEER_B, key_b) ||
        !vcs_swarm_engine_peer_add(b->engine, ZPR_PEER_A, key_a) ||
        vcs_swarm_engine_announce_to(a->engine, ZPR_PEER_B) == 0)
        return false;
    while (vcs_swarm_engine_next_outbound(a->engine, ZPR_PEER_B, &target,
                                          frame, &len))
        free(vcs_swarm_engine_handle_frame(b->engine, ZPR_PEER_A, frame,
                                           len, ZPR_DAY, 1).reply);
    if (vcs_swarm_engine_fetch(b->engine, transport, ZPR_DAY, 1) !=
        VCS_SWARM_FETCH_OK)
        return false;
    for (int round = 0; round < ZPR_ROUNDS; round++) {
        struct vcs_swarm_download_status st;
        uint64_t now = (uint64_t)round + 2u;
        vcs_swarm_engine_tick(b->engine, ZPR_DAY, now);
        while (vcs_swarm_engine_next_outbound(b->engine, ZPR_PEER_A, &target,
                                              frame, &len))
            zpr_exchange(a, b, frame, len, corrupt, now, stats);
        if (!vcs_swarm_engine_download_status(b->engine, transport, &st) ||
            st.state == VCS_SWARM_DL_COMPLETE ||
            st.state == VCS_SWARM_DL_FAILED)
            return st.state == VCS_SWARM_DL_COMPLETE;
    }
    return false;
}

/* Run the receive with both engines on their datadirs, then close them so
 * the commands below open the stores themselves. */
static bool zpr_transfer(const struct zpr_world *w, bool corrupt,
                         struct zpr_pump *stats)
{
    struct zpr_node a, b;
    uint8_t transport[32];
    bool ok = zcl_hex_decode(w->transport_hex, transport, 32) &&
              zpr_node_open(&a, w->a_dir);
    if (ok && !zpr_node_open(&b, w->b_dir)) {
        zpr_node_close(&a);
        return false;
    }
    if (!ok)
        return false;
    ok = zpr_receive(&a, &b, transport, corrupt, stats);
    zpr_node_close(&b);
    zpr_node_close(&a);
    return ok;
}

/* ── B's side: admit, checkout, lineage ───────────────────────────────── */

static bool zpr_admit(const struct zpr_world *w, struct zpr_call *c)
{
    zpr_begin(c);
    (void)json_push_kv_str(&c->input, "transport_root", w->transport_hex);
    (void)json_push_kv_str(&c->input, "datadir", w->b_dir);
    return zpr_run("zcode.package.admit", c);
}

static bool zpr_checkout(const struct zpr_world *w, struct zpr_call *c)
{
    zpr_begin(c);
    (void)json_push_kv_str(&c->input, "root", w->shared_package_hex);
    (void)json_push_kv_str(&c->input, "destination", w->b_tree);
    (void)json_push_kv_str(&c->input, "datadir", w->b_dir);
    return zpr_run("zcode.package.checkout", c);
}

/* Lineage rows of B's datadir for the shared package root. */
static bool zpr_lineage(const struct zpr_world *w, struct zpr_call *c)
{
    zpr_begin(c);
    (void)json_push_kv_str(&c->input, "workspace", w->workspace);
    (void)json_push_kv_str(&c->input, "package_root", w->shared_package_hex);
    (void)json_push_kv_str(&c->input, "datadir", w->b_dir);
    return zpr_run("zcode.commons.lineage", c);
}

static bool zpr_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool zpr_b_has_release(const struct zpr_world *w, const char *hex)
{
    char path[900];
    (void)snprintf(path, sizeof(path), "%s/zcode/releases/%s", w->b_dir,
                   hex);
    return zpr_exists(path);
}

/* ── the cases ────────────────────────────────────────────────────────── */

static bool zpr_world_init(struct zpr_world *w)
{
    memset(w, 0, sizeof(*w));
    if (!test_mkdtemp(w->root, sizeof(w->root), "zcode_package_receive"))
        return false;
    (void)snprintf(w->a_dir, sizeof(w->a_dir), "%s/a", w->root);
    (void)snprintf(w->b_dir, sizeof(w->b_dir), "%s/b", w->root);
    (void)snprintf(w->a_copy, sizeof(w->a_copy), "%s/a-copy", w->root);
    (void)snprintf(w->b_tree, sizeof(w->b_tree), "%s/b-tree", w->root);
    (void)snprintf(w->workspace, sizeof(w->workspace), "%s/ws", w->root);
    return mkdir(w->a_dir, 0700) == 0 && mkdir(w->b_dir, 0700) == 0 &&
           mkdir(w->workspace, 0700) == 0 && zpr_publish_origin(w) &&
           zpr_fork_and_save(w) && zpr_share(w);
}

/* A corrupted chunk: nothing lands in B. Runs first, on an empty B, so a
 * later honest receive proves the refusal left B clean enough to succeed. */
static int zpr_corrupt_chunk_writes_nothing(const struct zpr_world *w)
{
    int failures = 0;
    TEST("zcode package receive: a corrupted chunk writes nothing to B") {
        struct zpr_pump stats;
        struct zpr_call c;
        ASSERT(!zpr_transfer(w, true, &stats));
        ASSERT(stats.corrupted > 0 && stats.invalid_data > 0);
        ASSERT(zpr_admit(w, &c) && zpr_refused(&c));
        zpr_end(&c);
        ASSERT(zpr_checkout(w, &c) && zpr_refused(&c));
        zpr_end(&c);
        ASSERT(!zpr_exists(w->b_tree));
        ASSERT(!zpr_b_has_release(w, w->shared_release_hex));
        ASSERT(zpr_lineage(w, &c));
        ASSERT(zpr_refused(&c) ||
               json_size(json_get(&c.reply.data, "releases")) == 0);
        zpr_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

static int zpr_tree_equals_head(const struct zpr_world *w)
{
    int failures = 0;
    TEST("zcode package receive: B's tree equals A's head") {
        struct zpr_pump stats;
        struct zpr_call c;
        uint8_t a_root[32], b_root[32], shared[32];
        struct vcs_package_manifest manifest;
        ASSERT(zpr_transfer(w, false, &stats));
        ASSERT(zpr_admit(w, &c) && zpr_passed(&c));
        ASSERT(strcmp(zpr_str(&c, "release_id"), w->shared_release_hex) == 0);
        ASSERT(strcmp(zpr_str(&c, "package_root"),
                      w->shared_package_hex) == 0);
        zpr_end(&c);
        ASSERT(zpr_checkout(w, &c) && zpr_passed(&c));
        zpr_end(&c);
        ASSERT(zcl_hex_decode(w->shared_package_hex, shared, 32));
        ASSERT(zpr_tree_root(w->a_copy, a_root, NULL));
        ASSERT(zpr_tree_root(w->b_tree, b_root, &manifest));
        ASSERT(memcmp(a_root, b_root, 32) == 0);
        ASSERT(memcmp(b_root, shared, 32) == 0);
        ASSERT(manifest.count > 1);
        for (size_t i = 0; i < manifest.count; i++)
            ASSERT(zpr_same_bytes(w->a_copy, w->b_tree,
                                  manifest.files[i].path));
        ASSERT(!zpr_same_bytes(ZPR_SOURCE, w->b_tree, ZPR_EDITED));
        vcs_package_manifest_free(&manifest);
        PASS();
    } _test_next:;
    return failures;
}

static int zpr_shared_version_survives_edits(const struct zpr_world *w)
{
    int failures = 0;
    struct zpr_world recipient = *w;
    struct vcs_package_manifest manifest = {0};
    struct zpr_call c;
    bool call_open = false;
    (void)snprintf(recipient.b_dir, sizeof(recipient.b_dir), "%s/c", w->root);
    (void)snprintf(recipient.b_tree, sizeof(recipient.b_tree), "%s/c-tree", w->root);
    TEST("zcode package receive: unpublished A edits cannot change C's selected share") {
        uint8_t shared[32], changed[32], received[32];
        struct zpr_pump stats = {0};
        ASSERT(!zpr_exists(recipient.b_dir) && !zpr_exists(recipient.b_tree));
        ASSERT(mkdir(recipient.b_dir, 0700) == 0);
        ASSERT(zpr_write(w->a_copy, ZPR_EDITED,
                          "\n/* later unpublished publisher edit */\n", "ab"));
        ASSERT(zcl_hex_decode(w->shared_package_hex, shared, 32));
        ASSERT(zpr_tree_root(w->a_copy, changed, NULL));
        ASSERT(memcmp(changed, shared, 32) != 0);
        ASSERT(zpr_transfer(&recipient, false, &stats));
        call_open = true;
        ASSERT(zpr_admit(&recipient, &c) && zpr_passed(&c));
        ASSERT(strcmp(zpr_str(&c, "release_id"), w->shared_release_hex) == 0);
        ASSERT(strcmp(zpr_str(&c, "package_root"), w->shared_package_hex) == 0);
        ASSERT(strcmp(zpr_str(&c, "transport_root"), w->transport_hex) == 0);
        zpr_end(&c);
        ASSERT(zpr_checkout(&recipient, &c) && zpr_passed(&c));
        zpr_end(&c);
        call_open = false;
        ASSERT(zpr_tree_root(recipient.b_tree, received, &manifest));
        ASSERT(memcmp(received, shared, 32) == 0);
        ASSERT(memcmp(received, changed, 32) != 0);
        ASSERT(manifest.count > 1);
        for (size_t i = 0; i < manifest.count; i++)
            ASSERT(zpr_same_bytes(w->b_tree, recipient.b_tree,
                                  manifest.files[i].path));
        ASSERT(!zpr_same_bytes(w->a_copy, recipient.b_tree, ZPR_EDITED));
        PASS();
    } _test_next:;
    if (call_open)
        zpr_end(&c);
    vcs_package_manifest_free(&manifest);
    return failures;
}

static int zpr_lineage_names_parent(const struct zpr_world *w)
{
    int failures = 0;
    TEST("zcode package receive: B's lineage names A's release as parent") {
        struct zpr_call c;
        ASSERT(zpr_b_has_release(w, w->shared_release_hex));
        ASSERT(zpr_lineage(w, &c) && zpr_passed(&c));
        const struct json_value *rows = json_get(&c.reply.data, "releases");
        const struct json_value *row = rows ? json_at(rows, 0) : NULL;
        ASSERT(json_size(rows) == 1 && row);
        const char *release = json_get_str(json_get(row, "release_root"));
        const char *parent = json_get_str(json_get(row, "parent_release_root"));
        ASSERT(release && strcmp(release, w->shared_release_hex) == 0);
        ASSERT(json_get_bool(json_get(row, "has_parent")));
        ASSERT(parent && strcmp(parent, w->origin_release_hex) == 0);
        zpr_end(&c);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_package_receive(void)
{
    int failures = 0;
    struct zpr_world w;
    chain_params_select(CHAIN_MAIN);
    TEST("zcode package receive: A forks, changes and shares skycombat") {
        ASSERT(zpr_world_init(&w));
        PASS();
    } _test_next:;
    if (failures)
        return failures;
    failures += zpr_corrupt_chunk_writes_nothing(&w);
    failures += zpr_tree_equals_head(&w);
    failures += zpr_lineage_names_parent(&w);
    if (!failures)
        failures += zpr_shared_version_survives_edits(&w);
    if (!failures)
        (void)test_rm_rf_recursive(w.root);
    return failures;
}
