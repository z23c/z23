/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * The plugin software-anywhere journey through the real commands. The
 * publisher keygens, packs and `plugin publish`es a signed plugin; the
 * package is then serveable through the closed public-shape gate as
 * VCS_PACKAGE_PUBLIC_PLUGIN and crosses the authenticated swarm; the
 * receiver `plugin fetch`es it (inert: verifies, reports, never installs),
 * is refused install until its owner pins the publisher key, then installs,
 * switches, calls, independently attests the verified generation with its own
 * builder key and checks the listing, upgrades, preserves state across a
 * rollback, and rolls back. Sibling cases prove publisher disappearance (a joiner fetches the
 * replica from the receiver), corrupt bytes (refused in transit, repaired
 * at the receiver) and the publish/fetch refusal names. A Linux-only case
 * closes the loop from source: the test writes a tiny C23 capability,
 * lab.promote proves its cases and signs it, and after swarm transfer the
 * receiver's plugin call returns the cases' output. A second Linux case
 * lets source and cases ride in the package and has the receiver re-run
 * the whole promote pipeline under its own key: the release image comes
 * out bit-identical to the signed manifest's sha3_512 before the owner's
 * pin lets it activate. A resident case crosses the same swarm with an
 * interface 1 pack: the public-shape gate admits it, the owner-pin gate
 * holds, and the receiver's resident supervisor runs the fetched
 * generation to a healthy ping. A platform-neutral case pins fetch resilience: a
 * fetch started before the root is served waits in want-manifest, survives
 * a receiver node restart through its persisted record, and completes when
 * a provider appears. Two more pin refusal honesty at the table's limits:
 * a full download table refuses the seventeenth fetch by name until an
 * operator cancel frees a slot, and a downloads path that cannot persist
 * refuses record-io with no partial state, recovering once the path is
 * repaired. A sibling case pins the activation-lane refusal boundary:
 * rollback before any recorded last-good, switch to an uninstalled
 * generation and rollback of a never-installed plugin each refuse by name
 * and change nothing on disk. An announce case pins the publish opt-in:
 * POINTER and PROVIDER records naming the fresh root go to the plugin DHT
 * namespace through the standard publication helper, and an unreachable
 * overlay is a named refusal that leaves the publish standing. A fetch-route
 * case pins the receiver half: a one-shot fetch given the plugin namespace
 * routes the exact root through the node's provider discovery, and both a
 * provider-less root and a routed refusal are named, never silent. A stop
 * case pins the supervisor registry: a live registration makes uninstall
 * refuse busy, stop signals exactly the registered process after its start
 * token matches, a stale record is cleared without a signal, and the run
 * command registers and unregisters itself. Peer
 * handles are fixture inputs; this is not network-authentication evidence. */

#include "test/test_core.h"
#include "test/test_zcode_swarm_priv.h"
#include "test/public_shape_fixture.h"

#include "command/native_command.h"
#include "command/native_zcode_discovery.h"
#include "base/hex.h"
#include "json/json.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"
#include "plugin/plugin_run.h"
#include "plugin/plugin_store.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <signal.h>
#include <sys/wait.h>
#endif

#define PJ_CAP (4u * VCS_PACKAGE_CHUNK_BYTES)
#define PJ_NAME "upper"

struct pj_fixture {
    struct sw_node pub, recv;
    char base[1024], home[1100], plugins[1200], key[1200], dist[1200];
    char exe[1200], old_home[1024];
    char pub_hex[65];
};

static bool pj_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

static bool pj_write(const char *path, const uint8_t *bytes, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(bytes, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool pj_slurp(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(out, 1, cap - 1, f);
    fclose(f);
    out[n] = '\0';
    return true;
}

static bool pj_call(void (*handler)(const struct zcl_command_request *,
                                    struct zcl_command_reply *),
                    const char *input_json, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input, .view = "normal" };
    zcl_command_reply_init(reply, "zcl.plugin_journey_test.v1");
    if (ok)
        handler(&request, reply);
    json_free(&input);
    return ok;
}

static const char *pj_str(const struct zcl_command_reply *reply,
                          const char *key)
{
    return json_get_str(json_get(&reply->data, key));
}

static bool pj_bool(const struct zcl_command_reply *reply, const char *key)
{
    const struct json_value *v = json_get(&reply->data, key);
    return v && json_get_bool(v);
}

/* Lay out the fake HOME the receiver's publisher key file lives under. */
static bool pj_mkdirs(struct pj_fixture *f)
{
    char dot[1200];
    const char *home = getenv("HOME");
    snprintf(f->old_home, sizeof(f->old_home), "%s", home ? home : "");
    return test_mkdtemp(f->base, sizeof(f->base), "plugin_journey") &&
           pj_join(f->home, sizeof(f->home), f->base, "home") &&
           mkdir(f->home, 0700) == 0 &&
           pj_join(dot, sizeof(dot), f->home, ".z23") && mkdir(dot, 0700) == 0 &&
           pj_join(f->plugins, sizeof(f->plugins), dot, "plugins") &&
           mkdir(f->plugins, 0700) == 0 &&
           pj_join(f->dist, sizeof(f->dist), f->base, "dist") &&
           pj_join(f->key, sizeof(f->key), f->base, "publisher.key") &&
           pj_join(f->exe, sizeof(f->exe), f->base, "image") &&
           setenv("HOME", f->home, 1) == 0;
}

/* The signed sha3_512 of the executable member, read from a manifest. */
static bool pj_manifest_sha(const char *path, char out[129])
{
    uint8_t text[8192];
    FILE *f = fopen(path, "rb");
    size_t len = f ? fread(text, 1, sizeof(text) - 1, f) : 0;
    bool ok = f && !ferror(f) && len > 0;
    if (f)
        ok = fclose(f) == 0 && ok;
    if (!ok)
        return false;
    text[len] = '\0';
    struct json_value v;
    json_init(&v);
    ok = json_read(&v, (const char *)text, len);
    const char *sha = ok ? json_get_str(json_get(&v, "sha3_512")) : NULL;
    ok = sha && strlen(sha) == 128 &&
         snprintf(out, 129, "%s", sha) == 128;
    json_free(&v);
    return ok;
}

static bool pj_keygen_to(const char *path, char pub_hex[65])
{
    char in[1400];
    struct zcl_command_reply r;
    int n = snprintf(in, sizeof(in), "{\"key\":\"%s\"}", path);
    if (n <= 0 || (size_t)n >= sizeof(in) ||
        !pj_call(zcl_native_handle_plugin_keygen, in, &r))
        return false;
    bool ok = r.status == ZCL_COMMAND_STATUS_PASSED;
    const char *pub = ok ? pj_str(&r, "public_key") : NULL;
    if (pub_hex)
        ok = pub && strlen(pub) == 64 && snprintf(pub_hex, 65, "%s", pub) == 64;
    zcl_command_reply_free(&r);
    return ok;
}

/* Generate the publisher signing key through the real command. */
static bool pj_keygen(struct pj_fixture *f)
{
    return pj_keygen_to(f->key, f->pub_hex);
}

/* One fake HOME (the receiver's ~/.z23/plugins), one publisher key, and the
 * two store+engine nodes the packages travel between. */
static bool pj_open(struct pj_fixture *f)
{
    memset(f, 0, sizeof(*f));
    if (!pj_mkdirs(f) || !pj_keygen(f))
        return false;
    return sw_node_open(&f->pub, "plugin-journey-publisher", sw_score_contributor) &&
           sw_node_open(&f->recv, "plugin-journey-receiver", sw_score_contributor);
}

static void pj_close(struct pj_fixture *f)
{
    vcs_swarm_engine_set_global(NULL);
    if (f->recv.engine)
        sw_node_close(&f->recv);
    if (f->pub.engine)
        sw_node_close(&f->pub);
    if (f->recv.datadir[0])
        (void)test_rm_rf_recursive(f->recv.datadir);
    if (f->pub.datadir[0])
        (void)test_rm_rf_recursive(f->pub.datadir);
    if (f->old_home[0])
        (void)setenv("HOME", f->old_home, 1);
    if (f->base[0])
        (void)test_rm_rf_recursive(f->base);
}

/* On Linux the image is the real one-shot fixture padded past one package
 * chunk so the transfer is multi-chunk; elsewhere it is inert padded bytes
 * and the call assertions are compiled out. Version shifts the tail so two
 * versions never share a chunk hash. */
static bool pj_write_image(const char *path, unsigned version)
{
    uint8_t *bytes = calloc(1, PJ_CAP);
    if (!bytes)
        return false;
    size_t length = 0;
    bool ok = true;
#if defined(__linux__)
    FILE *f = fopen("build/fixtures/plugin_call_upper", "rb");
    ok = f != NULL;
    if (ok) {
        length = fread(bytes, 1, PJ_CAP, f);
        ok = !ferror(f) && length > 0 && length < PJ_CAP;
        ok = fclose(f) == 0 && ok;
    }
    if (length <= VCS_PACKAGE_CHUNK_BYTES)
        length = VCS_PACKAGE_CHUNK_BYTES + version;
    memset(bytes + VCS_PACKAGE_CHUNK_BYTES, (int)('A' + version % 26u),
           length - VCS_PACKAGE_CHUNK_BYTES);
#else
    length = VCS_PACKAGE_CHUNK_BYTES + version;
    for (size_t i = 0; i < length; i++)
        bytes[i] = (uint8_t)(i * 31u + version);
#endif
    ok = ok && pj_write(path, bytes, length) && chmod(path, 0755) == 0;
    free(bytes);
    return ok;
}

/* The verbatim allowlisted MIT text beside the pack makes the root publicly
 * serveable; adding it is the publishing owner's explicit step. */
static bool pj_write_license(const char *dir)
{
    char license[1400];
    return pj_join(license, sizeof(license), dir, "LICENSE") &&
           pj_write(license, (const uint8_t *)TEST_LICENSE_TEXT_MIT,
                    strlen(TEST_LICENSE_TEXT_MIT));
}

/* Write the versioned image and pack it through the real command. */
static bool pj_pack(struct pj_fixture *f, unsigned version)
{
    char in[4 * 1200];
    struct zcl_command_reply r;
    if (!pj_write_image(f->exe, version))
        return false;
    int n = snprintf(in, sizeof(in),
                     "{\"exe\":\"%s\",\"name\":\"%s\",\"version\":\"%u.0.0\","
                     "\"key\":\"%s\",\"dir\":\"%s\",\"interface\":2}",
                     f->exe, PJ_NAME, version, f->key, f->dist);
    if (n <= 0 || (size_t)n >= sizeof(in) ||
        !pj_call(zcl_native_handle_plugin_pack, in, &r))
        return false;
    bool ok = r.status == ZCL_COMMAND_STATUS_PASSED;
    zcl_command_reply_free(&r);
    return ok && pj_write_license(f->dist);
}

/* Publish one already-packed directory through the real command. */
static bool pj_publish(struct pj_fixture *f, char root_hex[65])
{
    char in[4 * 1200];
    struct zcl_command_reply r;
    int n = snprintf(in, sizeof(in), "{\"dir\":\"%s\",\"datadir\":\"%s\"}",
                     f->dist, f->pub.datadir);
    if (n <= 0 || (size_t)n >= sizeof(in) ||
        !pj_call(zcl_native_handle_plugin_publish, in, &r))
        return false;
    bool ok = r.status == ZCL_COMMAND_STATUS_PASSED && pj_str(&r, "package_root") &&
              strlen(pj_str(&r, "package_root")) == 64 && pj_bool(&r, "pinned");
    if (ok)
        snprintf(root_hex, 65, "%s", pj_str(&r, "package_root"));
    zcl_command_reply_free(&r);
    /* The handler admitted through its own handle; refresh the fixture
     * handle the serving engine reads so its catalog sees the new root,
     * exactly as the node's own refresh gates do after a cross-handle
     * admission. */
    return ok && vcs_package_store_refresh(f->pub.store);
}

/* Pack version `version`, then publish it. */
static bool pj_pack_publish(struct pj_fixture *f, unsigned version,
                            char root_hex[65])
{
    return pj_pack(f, version) && pj_publish(f, root_hex);
}

/* Deliver every queued outbound frame of `from` to `to`, and any DATA reply
 * straight back. Each fixture engine has exactly one peer per direction, so
 * the handle naming is unambiguous. */
static bool pj_pump(struct vcs_swarm_engine *from, uint64_t from_peer,
                    struct vcs_swarm_engine *to, uint64_t to_peer, uint64_t now)
{
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    uint64_t target = 0;
    size_t length = 0;
    unsigned frames = 0;
    while (vcs_swarm_engine_next_outbound(from, from_peer, &target, frame,
                                          &length)) {
        if (++frames > 64)
            return false;
        struct vcs_swarm_frame_result served = vcs_swarm_engine_handle_frame(
            to, to_peer, frame, length, SW_DAY, now);
        if (served.reply && served.reply_len) {
            struct vcs_swarm_frame_result got = vcs_swarm_engine_handle_frame(
                from, from_peer, served.reply, served.reply_len, SW_DAY, now);
            free(got.reply);
        }
        free(served.reply);
    }
    return true;
}

static bool pj_fetch_call(const char *datadir, const char *root_hex,
                          const char *dir, struct zcl_command_reply *reply)
{
    char in[3 * 1200];
    int n = snprintf(in, sizeof(in),
                     "{\"root\":\"%s\",\"dir\":\"%s\",\"datadir\":\"%s\","
                     "\"day\":%d}",
                     root_hex, dir, datadir, SW_DAY);
    return n > 0 && (size_t)n < sizeof(in) &&
           pj_call(zcl_native_handle_plugin_fetch, in, reply);
}

/* Poll plugin fetch while pumping frames between the two engines on the
 * wall-clock tick domain the handler registers with. The serving node first
 * announces its serveable roots to the receiver, as the production
 * transport glue does on every membership sync. */
static bool pj_fetch_drive(struct sw_node *recv_node, uint64_t recv_handle,
                           struct sw_node *serve_node, uint64_t serve_handle,
                           const char *datadir, const char *root_hex,
                           const char *dir, struct zcl_command_reply *done_out)
{
    uint64_t base = (uint64_t)platform_time_wall_unix();
    (void)vcs_swarm_engine_announce_to(serve_node->engine, serve_handle);
    if (!pj_pump(serve_node->engine, serve_handle, recv_node->engine,
                 recv_handle, base))
        return false;
    for (uint64_t i = 0; i < 48; i++) {
        uint64_t now = base + i;
        vcs_swarm_engine_tick(recv_node->engine, SW_DAY, now);
        if (!pj_pump(recv_node->engine, recv_handle, serve_node->engine,
                     serve_handle, now) ||
            !pj_pump(serve_node->engine, serve_handle, recv_node->engine,
                     recv_handle, now))
            return false;
        struct zcl_command_reply r;
        if (!pj_fetch_call(datadir, root_hex, dir, &r))
            return false;
        bool ok = r.status == ZCL_COMMAND_STATUS_PASSED;
        bool complete = ok && pj_bool(&r, "complete");
        if (ok && complete) {
            if (done_out)
                *done_out = r;
            else
                zcl_command_reply_free(&r);
            return true;
        }
        zcl_command_reply_free(&r);
        if (!ok)
            return false;
    }
    return false;
}

/* The CAS path of chunk 0 of the executable member. */
static bool pj_chunk0_path(const struct sw_node *node, const char *image,
                           char path[1500])
{
    uint8_t *bytes = malloc(VCS_PACKAGE_CHUNK_BYTES);
    if (!bytes)
        return false;
    FILE *f = fopen(image, "rb");
    size_t length = f ? fread(bytes, 1, VCS_PACKAGE_CHUNK_BYTES, f) : 0;
    bool ok = f && !ferror(f) && length == VCS_PACKAGE_CHUNK_BYTES;
    if (f)
        ok = fclose(f) == 0 && ok;
    uint8_t digest[32];
    char hex[65];
    ok = ok && vcs_package_chunk_hash(bytes, length, digest);
    free(bytes);
    if (!ok)
        return false;
    for (size_t i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    int n = snprintf(path, 1500, "%s/cas/sha3/%.2s/%s", node->zcode_dir, hex,
                     hex);
    return n > 0 && n < 1500;
}

static bool pj_flip_byte0(const char *path)
{
    FILE *f = fopen(path, "rb");
    int c = f ? fgetc(f) : EOF;
    if (f && fclose(f) != 0)
        return false;
    if (c == EOF)
        return false;
    (void)chmod(path, 0644);
    uint8_t b = (uint8_t)(c ^ 0x01);
    f = fopen(path, "r+b");
    bool ok = f && fseek(f, 0, SEEK_SET) == 0 && fwrite(&b, 1, 1, f) == 1;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok;
}

static bool pj_absent(const char *path)
{
    errno = 0;
    return access(path, F_OK) != 0 && errno == ENOENT;
}

static bool pj_pin(struct pj_fixture *f)
{
    char in[160];
    struct zcl_command_reply r;
    int n = snprintf(in, sizeof(in), "{\"key\":\"%s\"}", f->pub_hex);
    if (n <= 0 || (size_t)n >= sizeof(in) ||
        !pj_call(zcl_native_handle_plugin_publisher, in, &r))
        return false;
    bool ok = r.status == ZCL_COMMAND_STATUS_PASSED;
    zcl_command_reply_free(&r);
    return ok;
}

static bool pj_install(const char *manifest, char generation[129],
                       bool expect_ok)
{
    char in[1600];
    struct zcl_command_reply r;
    int n = snprintf(in, sizeof(in), "{\"manifest\":\"%s\"}", manifest);
    if (n <= 0 || (size_t)n >= sizeof(in) ||
        !pj_call(zcl_native_handle_plugin_install, in, &r))
        return false;
    bool ok = r.status == ZCL_COMMAND_STATUS_PASSED;
    if (ok && expect_ok && pj_str(&r, "generation"))
        snprintf(generation, 129, "%s", pj_str(&r, "generation"));
    zcl_command_reply_free(&r);
    return ok == expect_ok;
}

static bool pj_switch(const char *generation)
{
    char in[240];
    struct zcl_command_reply r;
    int n = snprintf(in, sizeof(in), "{\"name\":\"%s\",\"generation\":\"%s\"}",
                     PJ_NAME, generation);
    if (n <= 0 || (size_t)n >= sizeof(in) ||
        !pj_call(zcl_native_handle_plugin_switch, in, &r))
        return false;
    bool ok = r.status == ZCL_COMMAND_STATUS_PASSED;
    zcl_command_reply_free(&r);
    return ok;
}

static bool pj_current(char generation[129])
{
    char in[128];
    struct zcl_command_reply r;
    int n = snprintf(in, sizeof(in), "{\"name\":\"%s\"}", PJ_NAME);
    if (n <= 0 || (size_t)n >= sizeof(in) ||
        !pj_call(zcl_native_handle_plugin_status, in, &r))
        return false;
    bool ok = r.status == ZCL_COMMAND_STATUS_PASSED &&
              pj_str(&r, "current") != NULL;
    if (ok)
        snprintf(generation, 129, "%s", pj_str(&r, "current"));
    zcl_command_reply_free(&r);
    return ok;
}

#if defined(__linux__)
static bool pj_call_upper(const char *expect_version)
{
    struct zcl_command_reply r;
    if (!pj_call(zcl_native_handle_plugin_call,
                 "{\"name\":\"upper\",\"stdin\":\"abc\\n\"}", &r))
        return false;
    const struct json_value *run = json_get(&r.data, "run");
    bool ok = r.status == ZCL_COMMAND_STATUS_PASSED && run &&
              strcmp(json_get_str(json_get(run, "stdout")), "ABC\n") == 0 &&
              json_get_str(json_get(&r.data, "version")) &&
              strcmp(json_get_str(json_get(&r.data, "version")),
                     expect_version) == 0;
    zcl_command_reply_free(&r);
    return ok;
}
#endif

/* The full journey: publish, peer transfer, inert fetch, refused authority,
 * owner pin, install, switch, call, upgrade, state preservation, rollback. */
static int pj_t_journey(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: publish, peer fetch, owner-authority install, upgrade, state, rollback") {
        char root1[65], root2[65], gen1[129], gen2[129], cur[129];
        char dir1[1400], dir2[1400], manifest[1600], state[1600];
        uint8_t root_bin[32];
        ASSERT(ready);
        ASSERT(pj_pack_publish(&f, 1, root1));
        ASSERT(zcl_hex_decode(root1, root_bin, 32));
        struct vcs_package_public_verdict verdict;
        ASSERT_EQ(vcs_package_public_shape_classify(f.pub.store, root_bin,
                                                    &verdict),
                  VCS_PACKAGE_PUBLIC_PLUGIN);
        uint8_t publisher_key[33], receiver_key[33];
        sw_key(81, publisher_key);
        sw_key(82, receiver_key);
        ASSERT(vcs_swarm_engine_peer_add(f.recv.engine, 11, publisher_key));
        ASSERT(vcs_swarm_engine_peer_add(f.pub.engine, 13, receiver_key));
        vcs_swarm_engine_set_global(f.recv.engine);
        ASSERT(pj_join(dir1, sizeof(dir1), f.base, "received-one"));
        struct zcl_command_reply r;
        ASSERT(pj_fetch_call(f.recv.datadir, root1, dir1, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!pj_bool(&r, "complete"));
        ASSERT(pj_bool(&r, "live"));
        zcl_command_reply_free(&r);
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root1,
                              dir1, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(pj_bool(&r, "complete"));
        ASSERT_STR_EQ(pj_str(&r, "publisher_status"), "unknown");
        ASSERT_STR_EQ(pj_str(&r, "publisher"), f.pub_hex);
        ASSERT_STR_EQ(pj_str(&r, "name"), PJ_NAME);
        ASSERT_STR_EQ(pj_str(&r, "version"), "1.0.0");
        ASSERT(r.next_count == 1 && strcmp(r.next[0].command,
                                           "plugin.install") == 0);
        zcl_command_reply_free(&r);
        /* Fetch is inert: nothing installed yet. */
        ASSERT(!pj_current(cur));
        ASSERT(pj_join(manifest, sizeof(manifest), dir1, "upper.plugin.json"));
        /* Refused authority: the receiver has not listed the publisher. */
        {
            char in[1600];
            struct zcl_command_reply refused;
            ASSERT(snprintf(in, sizeof(in), "{\"manifest\":\"%s\"}",
                            manifest) > 0);
            ASSERT(pj_call(zcl_native_handle_plugin_install, in, &refused));
            ASSERT(refused.status != ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(refused.error.code, "PLUGIN_NO_KEYS");
            zcl_command_reply_free(&refused);
        }
        /* The receiving owner pins the publisher key; only then install. */
        ASSERT(pj_pin(&f));
        /* A repeated fetch refuses to overwrite the verified checkout. */
        ASSERT(pj_fetch_call(f.recv.datadir, root1, dir1, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_FETCH_DESTINATION");
        zcl_command_reply_free(&r);
        ASSERT(pj_install(manifest, gen1, true));
        ASSERT(pj_switch(gen1));
        ASSERT(pj_current(cur) && strcmp(cur, gen1) == 0);
#if defined(__linux__)
        ASSERT(pj_call_upper("1.0.0"));
#endif
        /* The receiving owner independently attests the fetched image:
         * its builder key signs the image hash for this package root, and
         * plugin.attest_verify accepts that one pinned builder. */
        {
            char bkey[1200], bpub[65], pins[1200], attest_dir[1200], image[1200];
            char in[4096], pin_line[80];
            struct zcl_command_reply att;
            ASSERT(pj_join(bkey, sizeof(bkey), f.base, "builder.key"));
            ASSERT(pj_keygen_to(bkey, bpub));
            ASSERT(pj_join(attest_dir, sizeof(attest_dir), f.base, "attestations"));
            ASSERT(mkdir(attest_dir, 0700) == 0);
            ASSERT(pj_join(pins, sizeof(pins), f.base, "builders.pin"));
            ASSERT(snprintf(pin_line, sizeof(pin_line), "%s\n", bpub) == 65);
            ASSERT(pj_write(pins, (const uint8_t *)pin_line, 65));
            ASSERT(chmod(pins, 0600) == 0);
            ASSERT(pj_join(image, sizeof(image), dir1, PJ_NAME));
            ASSERT(snprintf(in, sizeof(in),
                            "{\"image\":\"%s\",\"key\":\"%s\",\"name\":\"%s\","
                            "\"version\":\"1.0.0\",\"source-root\":\"%s\","
                            "\"toolchain\":\"fixture-toolchain\",\"dir\":\"%s\"}",
                            image, bkey, PJ_NAME, root1, attest_dir) > 0);
            ASSERT(pj_call(zcl_native_handle_plugin_attest, in, &att));
            ASSERT(att.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(pj_str(&att, "schema"), "zcl.plugin_attest.v1");
            ASSERT_STR_EQ(pj_str(&att, "builder_key"), bpub);
            ASSERT_STR_EQ(pj_str(&att, "name"), PJ_NAME);
            ASSERT_STR_EQ(pj_str(&att, "source_root"), root1);
            zcl_command_reply_free(&att);
            ASSERT(snprintf(in, sizeof(in),
                            "{\"manifest\":\"%s\",\"attestations\":\"%s\","
                            "\"builders\":\"%s\",\"threshold\":1,"
                            "\"source-root\":\"%s\"}",
                            manifest, attest_dir, pins, root1) > 0);
            ASSERT(pj_call(zcl_native_handle_plugin_attest_verify, in, &att));
            ASSERT(att.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(pj_str(&att, "schema"), "zcl.plugin_attest_verify.v1");
            ASSERT(pj_bool(&att, "accepted"));
            ASSERT_STR_EQ(pj_str(&att, "source_root"), root1);
            const struct json_value *attested = json_get(&att.data, "attested");
            ASSERT(attested && json_get_int(attested) >= 1);
            const struct json_value *builders = json_get(&att.data, "builders");
            ASSERT_STR_EQ(json_get_str(json_at(builders, 0)), bpub);
            zcl_command_reply_free(&att);
        }
        /* Upgrade: v2 crosses the swarm the same way and becomes current. */
        ASSERT(pj_pack_publish(&f, 2, root2));
        ASSERT(strcmp(root1, root2) != 0);
        ASSERT(pj_join(dir2, sizeof(dir2), f.base, "received-two"));
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root2,
                              dir2, NULL));
        ASSERT(pj_join(manifest, sizeof(manifest), dir2, "upper.plugin.json"));
        ASSERT(pj_install(manifest, gen2, true));
        ASSERT(strcmp(gen1, gen2) != 0);
        ASSERT(pj_switch(gen2));
        ASSERT(pj_current(cur) && strcmp(cur, gen2) == 0);
#if defined(__linux__)
        ASSERT(pj_call_upper("2.0.0"));
#endif
        /* Plugin state lives outside the generations; rollback preserves it. */
        char data_dir[1600];
        ASSERT(snprintf(data_dir, sizeof(data_dir), "%s/upper/data",
                        f.plugins) > 0 &&
               (mkdir(data_dir, 0700) == 0 || errno == EEXIST));
        ASSERT(pj_join(state, sizeof(state), data_dir, "state.txt"));
        ASSERT(pj_write(state, (const uint8_t *)"fleet-state-v2\n", 15));
        {
            char in[128];
            struct zcl_command_reply rolled;
            ASSERT(snprintf(in, sizeof(in), "{\"name\":\"%s\"}", PJ_NAME) > 0);
            ASSERT(pj_call(zcl_native_handle_plugin_rollback, in, &rolled));
            ASSERT(rolled.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(pj_str(&rolled, "current"), gen1);
            zcl_command_reply_free(&rolled);
        }
        ASSERT(pj_current(cur) && strcmp(cur, gen1) == 0);
        {
            uint8_t back[16];
            FILE *sf = fopen(state, "rb");
            ASSERT(sf != NULL);
            size_t got = fread(back, 1, sizeof(back), sf);
            ASSERT_EQ(fclose(sf), 0);
            ASSERT(got == 15 && memcmp(back, "fleet-state-v2\n", 15) == 0);
        }
        /* Both generations remain on disk; the rollback target runs. */
        {
            char slot[1700];
            ASSERT(snprintf(slot, sizeof(slot), "%s/upper/generations/%s",
                            f.plugins, gen1) > 0 && access(slot, F_OK) == 0);
            ASSERT(snprintf(slot, sizeof(slot), "%s/upper/generations/%s",
                            f.plugins, gen2) > 0 && access(slot, F_OK) == 0);
        }
#if defined(__linux__)
        ASSERT(pj_call_upper("1.0.0"));
#endif
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* The publisher disappears; a joiner that never met it fetches the replica
 * from the receiver, which advertises the root through the serving gate. */
static int pj_t_disappearance(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct sw_node join;
    memset(&join, 0, sizeof(join));
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: publisher disappears, joiner fetches the replica") {
        char root1[65], dir1[1400], dirj[1400], manifest[1600], gen[129];
        uint8_t root_bin[32];
        ASSERT(ready);
        ASSERT(pj_pack_publish(&f, 1, root1));
        ASSERT(zcl_hex_decode(root1, root_bin, 32));
        uint8_t publisher_key[33], receiver_key[33], joiner_key[33];
        sw_key(81, publisher_key);
        sw_key(82, receiver_key);
        sw_key(83, joiner_key);
        ASSERT(vcs_swarm_engine_peer_add(f.recv.engine, 11, publisher_key));
        ASSERT(vcs_swarm_engine_peer_add(f.pub.engine, 13, receiver_key));
        vcs_swarm_engine_set_global(f.recv.engine);
        ASSERT(pj_join(dir1, sizeof(dir1), f.base, "first-receiver"));
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root1,
                              dir1, NULL));
        /* The publisher vanishes: engine, store and datadir all gone. */
        vcs_swarm_engine_set_global(NULL);
        sw_node_close(&f.pub);
        memset(&f.pub, 0, sizeof(f.pub));
        ASSERT(sw_node_open(&join, "plugin-journey-joiner",
                            sw_score_contributor));
        ASSERT(vcs_swarm_engine_peer_add(join.engine, 21, receiver_key));
        ASSERT(vcs_swarm_engine_peer_add(f.recv.engine, 23, joiner_key));
        ASSERT(vcs_swarm_engine_announce_to(f.recv.engine, 23) > 0);
        uint64_t now = (uint64_t)platform_time_wall_unix();
        ASSERT(pj_pump(f.recv.engine, 23, join.engine, 21, now));
        struct vcs_swarm_peer_info infos[4];
        ASSERT_EQ(vcs_swarm_engine_peers_for(join.engine, root_bin, infos, 4),
                  1u);
        /* The joiner fetches from the only remaining copy and runs it. */
        vcs_swarm_engine_set_global(join.engine);
        ASSERT(pj_join(dirj, sizeof(dirj), f.base, "joiner-received"));
        ASSERT(pj_fetch_drive(&join, 21, &f.recv, 23, join.datadir, root1,
                              dirj, NULL));
        ASSERT(pj_join(manifest, sizeof(manifest), dirj, "upper.plugin.json"));
        ASSERT(pj_pin(&f));
        /* With the publisher key listed, a re-fetch to a fresh destination
         * reports the key pinned; the store already holds every chunk, so no
         * transfer is needed. */
        {
            char dirp[1400];
            struct zcl_command_reply pinned;
            ASSERT(pj_join(dirp, sizeof(dirp), f.base, "joiner-pinned"));
            ASSERT(pj_fetch_call(join.datadir, root1, dirp, &pinned));
            ASSERT(pinned.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT(pj_bool(&pinned, "complete"));
            ASSERT_STR_EQ(pj_str(&pinned, "publisher_status"), "pinned");
            zcl_command_reply_free(&pinned);
        }
        ASSERT(pj_install(manifest, gen, true));
        ASSERT(pj_switch(gen));
#if defined(__linux__)
        ASSERT(pj_call_upper("1.0.0"));
#endif
        PASS();
    } _test_next:;
    vcs_swarm_engine_set_global(NULL);
    if (join.engine) {
        char dd[1024];
        snprintf(dd, sizeof(dd), "%s", join.datadir);
        sw_node_close(&join);
        (void)test_rm_rf_recursive(dd);
    }
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* Corrupt bytes: the publisher's CAS object rots, the transfer never
 * completes and nothing bad is stored; restored bytes complete it. Then the
 * receiver's own stored copy rots and the next fetch quarantines it,
 * re-downloads and completes. */
static int pj_t_corrupt(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: corrupt bytes refuse in transit and repair") {
        char root1[65], dir1[1400], dir2[1400], pub_cas[1500], recv_cas[1500];
        char manifest[1600], gen[129];
        uint8_t root_bin[32];
        ASSERT(ready);
        ASSERT(pj_pack_publish(&f, 1, root1));
        ASSERT(zcl_hex_decode(root1, root_bin, 32));
        uint8_t publisher_key[33], receiver_key[33];
        sw_key(81, publisher_key);
        sw_key(82, receiver_key);
        ASSERT(vcs_swarm_engine_peer_add(f.recv.engine, 11, publisher_key));
        ASSERT(vcs_swarm_engine_peer_add(f.pub.engine, 13, receiver_key));
        vcs_swarm_engine_set_global(f.recv.engine);
        ASSERT(pj_chunk0_path(&f.pub, f.exe, pub_cas));
        ASSERT(pj_chunk0_path(&f.recv, f.exe, recv_cas));
        ASSERT(pj_flip_byte0(pub_cas));
        /* The receiver never completes against the corrupt serving copy. */
        ASSERT(pj_join(dir1, sizeof(dir1), f.base, "corrupt-received"));
        (void)vcs_swarm_engine_announce_to(f.pub.engine, 13);
        uint64_t base = (uint64_t)platform_time_wall_unix();
        for (uint64_t i = 0; i < 12; i++) {
            uint64_t now = base + i;
            vcs_swarm_engine_tick(f.recv.engine, SW_DAY, now);
            ASSERT(pj_pump(f.recv.engine, 11, f.pub.engine, 13, now));
            ASSERT(pj_pump(f.pub.engine, 13, f.recv.engine, 11, now));
            struct zcl_command_reply r;
            ASSERT(pj_fetch_call(f.recv.datadir, root1, dir1, &r));
            ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT(!pj_bool(&r, "complete"));
            zcl_command_reply_free(&r);
        }
        /* The bad object never entered the receiver's store. */
        ASSERT(pj_absent(recv_cas));
        /* The publisher quarantined its rotten object on the failed verified
         * read; the store admits the correct chunk again and the stalled
         * download completes once restarted. */
        {
            uint8_t *saved = malloc(VCS_PACKAGE_CHUNK_BYTES);
            ASSERT(saved != NULL);
            FILE *image = fopen(f.exe, "rb");
            ASSERT(image != NULL);
            size_t got = fread(saved, 1, VCS_PACKAGE_CHUNK_BYTES, image);
            ASSERT_EQ(fclose(image), 0);
            ASSERT(got == VCS_PACKAGE_CHUNK_BYTES);
            ASSERT_EQ(vcs_package_store_put_chunk(f.pub.store, root_bin,
                                                  PJ_NAME, 0, saved, got),
                      VCS_PACKAGE_STORE_OK);
            free(saved);
        }
        (void)vcs_swarm_engine_cancel(f.recv.engine, root_bin, base + 100);
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root1,
                              dir1, NULL));
        /* Receiver-side rot: the next fetch's possession proof quarantines
         * the bad object and repairs from the publisher. */
        ASSERT(pj_flip_byte0(recv_cas));
        {
            struct zcl_command_reply r;
            ASSERT(pj_fetch_call(f.recv.datadir, root1, dir1, &r));
            ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT(!pj_bool(&r, "complete"));
            zcl_command_reply_free(&r);
        }
        ASSERT(pj_absent(recv_cas));
        /* Repair completes; the fresh checkout names a new destination —
         * re-running fetch against the existing verified checkout refuses
         * PLUGIN_FETCH_DESTINATION, as the journey case pins. */
        ASSERT(pj_join(dir2, sizeof(dir2), f.base, "corrupt-repaired"));
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root1,
                              dir2, NULL));
        /* The repaired copy verifies, installs under the pinned key and runs. */
        ASSERT(pj_join(manifest, sizeof(manifest), dir2, "upper.plugin.json"));
        ASSERT(pj_pin(&f));
        ASSERT(pj_install(manifest, gen, true));
        ASSERT(pj_switch(gen));
#if defined(__linux__)
        ASSERT(pj_call_upper("1.0.0"));
#endif
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* Named refusals: layout, unservable license, broken signature, missing
 * directory, malformed root. */
static int pj_t_refusals(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: publish and fetch refusals name their rule") {
        char in[3 * 1200], license[1400], mpath[1400];
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pj_write_image(f.exe, 1));
        int n = snprintf(in, sizeof(in),
                         "{\"exe\":\"%s\",\"name\":\"%s\",\"version\":\"1.0.0\","
                         "\"key\":\"%s\",\"dir\":\"%s\",\"interface\":2}",
                         f.exe, PJ_NAME, f.key, f.dist);
        ASSERT(n > 0 && (size_t)n < sizeof(in));
        ASSERT(pj_call(zcl_native_handle_plugin_pack, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&r);
        ASSERT(pj_join(license, sizeof(license), f.dist, "LICENSE"));
        /* No LICENSE at all. */
        n = snprintf(in, sizeof(in), "{\"dir\":\"%s\",\"datadir\":\"%s\"}",
                     f.dist, f.pub.datadir);
        ASSERT(n > 0 && (size_t)n < sizeof(in));
        ASSERT(pj_call(zcl_native_handle_plugin_publish, in, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_PUBLISH_LAYOUT");
        zcl_command_reply_free(&r);
        /* A proprietary license may install by hand but may not be served. */
        ASSERT(pj_write(license, (const uint8_t *)"Proprietary.\n", 13));
        ASSERT(pj_call(zcl_native_handle_plugin_publish, in, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_PUBLISH_LICENSE");
        zcl_command_reply_free(&r);
        /* The allowlisted text, then a manifest byte flipped after packing:
         * the signature no longer covers the manifest. */
        ASSERT(pj_write(license, (const uint8_t *)TEST_LICENSE_TEXT_MIT,
                        strlen(TEST_LICENSE_TEXT_MIT)));
        ASSERT(pj_join(mpath, sizeof(mpath), f.dist, "upper.plugin.json"));
        {
            uint8_t text[4096];
            FILE *mf = fopen(mpath, "rb");
            ASSERT(mf != NULL);
            size_t len = fread(text, 1, sizeof(text), mf);
            ASSERT_EQ(fclose(mf), 0);
            ASSERT(len > 0 && len < sizeof(text));
            char *v = strstr((char *)text, "1.0.0");
            ASSERT(v != NULL);
            v[4] = '9';
            ASSERT(pj_write(mpath, text, len));
        }
        ASSERT(pj_call(zcl_native_handle_plugin_publish, in, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_SIG_BAD");
        zcl_command_reply_free(&r);
        /* A directory that does not exist. */
        ASSERT(pj_call(zcl_native_handle_plugin_publish,
                       "{\"dir\":\"/nonexistent-pj\",\"datadir\":\"x\"}", &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_PUBLISH_LAYOUT");
        zcl_command_reply_free(&r);
        /* A malformed root never reaches the store or the engine. */
        char nowhere[1200];
        ASSERT(pj_join(nowhere, sizeof(nowhere), f.base, "nowhere"));
        ASSERT(pj_fetch_call(f.recv.datadir, "zz", nowhere, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_FETCH_BAD_ROOT");
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* An extra member rides in the package and stays inert end to end: the
 * fetch delivers it into the checkout, install stores only what the signed
 * manifest names, and call runs the signed executable only. Matters
 * because the reproduce journey encourages extra members (source, cases). */
static int pj_t_extra_inert(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: an extra member is inert end to end") {
        char root1[65], dir1[1400], manifest[1600], gen1[129];
        ASSERT(ready);
        ASSERT(pj_pack(&f, 1));
        /* A second, executable-looking file the manifest never names. */
        static const char HELPER[] = "#!/bin/sh\necho PWNED\n";
        char helper[1400];
        ASSERT(pj_join(helper, sizeof(helper), f.dist, "helper"));
        ASSERT(pj_write(helper, (const uint8_t *)HELPER, sizeof(HELPER) - 1));
        ASSERT(chmod(helper, 0755) == 0);
        ASSERT(pj_publish(&f, root1));
        uint8_t root_bin[32];
        ASSERT(zcl_hex_decode(root1, root_bin, 32));
        struct vcs_package_public_verdict verdict;
        ASSERT_EQ(vcs_package_public_shape_classify(f.pub.store, root_bin,
                                                    &verdict),
                  VCS_PACKAGE_PUBLIC_PLUGIN);
        uint8_t publisher_key[33], receiver_key[33];
        sw_key(81, publisher_key);
        sw_key(82, receiver_key);
        ASSERT(vcs_swarm_engine_peer_add(f.recv.engine, 11, publisher_key));
        ASSERT(vcs_swarm_engine_peer_add(f.pub.engine, 13, receiver_key));
        vcs_swarm_engine_set_global(f.recv.engine);
        ASSERT(pj_join(dir1, sizeof(dir1), f.base, "extras-received"));
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root1,
                              dir1, NULL));
        /* The extra travelled, inert, into the checkout. */
        char got_helper[1600];
        ASSERT(pj_join(got_helper, sizeof(got_helper), dir1, "helper"));
        ASSERT(access(got_helper, R_OK) == 0);
        ASSERT(pj_join(manifest, sizeof(manifest), dir1, "upper.plugin.json"));
        ASSERT(pj_pin(&f));
        ASSERT(pj_install(manifest, gen1, true));
        ASSERT(pj_switch(gen1));
        /* The store holds no helper: not as a plugin, not inside the
         * installed generation. */
        char under[1700];
        ASSERT(snprintf(under, sizeof(under), "%s/helper", f.plugins) > 0 &&
               pj_absent(under));
        ASSERT(snprintf(under, sizeof(under), "%s/upper/generations/%s",
                        f.plugins, gen1) > 0 && access(under, F_OK) == 0);
        ASSERT(snprintf(under, sizeof(under),
                        "%s/upper/generations/%s/helper", f.plugins, gen1) > 0 &&
               pj_absent(under));
#if defined(__linux__)
        ASSERT(pj_call_upper("1.0.0"));
#endif
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* Reopen a fixture node on its existing datadir, keeping every byte — the
 * production "restart the node" move; sw_node_open would wipe it. */
static bool pj_node_reopen(struct sw_node *n)
{
    n->store = vcs_package_store_open(n->datadir,
                                      VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
    n->book = vcs_service_book_load(n->zcode_dir);
    if (!n->store || !n->book)
        return false;
    n->engine = vcs_swarm_engine_create(n->store, n->book, n->zcode_dir,
                                        sw_score_contributor, NULL);
    return n->engine != NULL;
}

/* A fetch started before the root is served anywhere waits honestly —
 * complete:false, live:true, nothing stored — survives a receiver node
 * restart through its persisted record, and completes once a provider
 * appears. */
static int pj_t_fetch_before_serve(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: fetch before serve, receiver restart, provider appears") {
        char root1[65], dir1[1400], manifest[1600], gen1[129], cas0[1500];
        ASSERT(ready);
        ASSERT(pj_pack_publish(&f, 1, root1));
        ASSERT(pj_join(dir1, sizeof(dir1), f.base, "early-received"));
        /* No peering yet: the root is not served anywhere the receiver can
         * reach. */
        vcs_swarm_engine_set_global(f.recv.engine);
        struct zcl_command_reply r;
        ASSERT(pj_fetch_call(f.recv.datadir, root1, dir1, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!pj_bool(&r, "complete"));
        ASSERT(pj_bool(&r, "live"));
        ASSERT_STR_EQ(pj_str(&r, "state"), "want-manifest");
        zcl_command_reply_free(&r);
        ASSERT(pj_chunk0_path(&f.recv, f.exe, cas0));
        uint64_t base = (uint64_t)platform_time_wall_unix();
        for (uint64_t i = 0; i < 4; i++) {
            vcs_swarm_engine_tick(f.recv.engine, SW_DAY, base + i);
            ASSERT(pj_fetch_call(f.recv.datadir, root1, dir1, &r));
            ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT(!pj_bool(&r, "complete"));
            zcl_command_reply_free(&r);
        }
        ASSERT(pj_absent(cas0));
        /* Restart the receiver node: engine, book and store reopen on the
         * same datadir; the persisted download record survives. */
        sw_node_close(&f.recv);
        ASSERT(pj_node_reopen(&f.recv));
        vcs_swarm_engine_set_global(f.recv.engine);
        ASSERT(pj_fetch_call(f.recv.datadir, root1, dir1, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!pj_bool(&r, "complete"));
        ASSERT(pj_bool(&r, "live"));
        zcl_command_reply_free(&r);
        /* A provider appears; the same fetch completes. */
        uint8_t publisher_key[33], receiver_key[33];
        sw_key(81, publisher_key);
        sw_key(82, receiver_key);
        ASSERT(vcs_swarm_engine_peer_add(f.recv.engine, 11, publisher_key));
        ASSERT(vcs_swarm_engine_peer_add(f.pub.engine, 13, receiver_key));
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root1,
                              dir1, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(pj_bool(&r, "complete"));
        zcl_command_reply_free(&r);
        ASSERT(pj_join(manifest, sizeof(manifest), dir1, "upper.plugin.json"));
        ASSERT(pj_pin(&f));
        ASSERT(pj_install(manifest, gen1, true));
        ASSERT(pj_switch(gen1));
#if defined(__linux__)
        ASSERT(pj_call_upper("1.0.0"));
#endif
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

#if defined(__linux__)
/* The capability this journey creates from source: uppercase stdin to
 * stdout, the contract pj_call_upper pins. */
static const char PJ_CAP_SOURCE[] =
    "/* Copyright 2026 Rhett Creighton - Apache License 2.0 */\n"
    "#include <ctype.h>\n"
    "#include <stdio.h>\n"
    "\n"
    "int main(void)\n"
    "{\n"
    "    int c;\n"
    "    while ((c = getchar()) != EOF)\n"
    "        putchar(toupper(c));\n"
    "    return 0;\n"
    "}\n";

#define PJ_CAP_CASES \
    "[{\"name\":\"lower\",\"stdin\":\"abc\\n\",\"expect_stdout\":\"ABC\\n\"}," \
    "{\"name\":\"mixed\",\"stdin\":\"Hello, z23\\n\",\"expect_stdout\":\"HELLO, Z23\\n\"}]"

/* Create the capability from source: lab.promote runs the cases against a
 * sanitized build, builds the release image, re-proves the cases on it and
 * signs the pack into f->dist; the owner then adds the LICENSE. */
static bool pj_promote_source(struct pj_fixture *f)
{
    char cap[1200], src[1400], in[4 * 1200];
    struct zcl_command_reply r;
    if (!pj_join(cap, sizeof(cap), f->base, "cap") || mkdir(cap, 0700) != 0 ||
        !pj_join(src, sizeof(src), cap, "upper.c") ||
        !pj_write(src, (const uint8_t *)PJ_CAP_SOURCE, sizeof(PJ_CAP_SOURCE) - 1))
        return false;
    int n = snprintf(in, sizeof(in),
                     "{\"file\":\"%s\",\"cases\":%s,\"name\":\"%s\","
                     "\"version\":\"1.0.0\",\"key\":\"%s\",\"dir\":\"%s\"}",
                     src, PJ_CAP_CASES, PJ_NAME, f->key, f->dist);
    if (n <= 0 || (size_t)n >= sizeof(in) ||
        !pj_call(zcl_native_handle_lab_promote, in, &r))
        return false;
    bool ok = r.exit_code == ZCL_COMMAND_EXIT_OK &&
              json_get_int(json_get(&r.data, "cases_passed")) == 2;
    zcl_command_reply_free(&r);
    return ok && pj_write_license(f->dist);
}

/* Source to peer: the publisher creates a tiny C23 capability, lab.promote
 * proves and signs it, the owner adds a LICENSE and publishes, the package
 * crosses the swarm, the receiver's inert fetch verifies it, and only the
 * receiving owner's key pin lets install proceed; plugin call on the
 * receiver then returns the cases' output. */
static int pj_t_source_to_peer(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: C23 source to a peer's plugin call") {
        char root1[65], dir1[1400], manifest[1600], gen1[129], cur[129];
        ASSERT(ready);
        ASSERT(pj_promote_source(&f));
        ASSERT(pj_publish(&f, root1));
        uint8_t publisher_key[33], receiver_key[33];
        sw_key(81, publisher_key);
        sw_key(82, receiver_key);
        ASSERT(vcs_swarm_engine_peer_add(f.recv.engine, 11, publisher_key));
        ASSERT(vcs_swarm_engine_peer_add(f.pub.engine, 13, receiver_key));
        vcs_swarm_engine_set_global(f.recv.engine);
        ASSERT(pj_join(dir1, sizeof(dir1), f.base, "source-received"));
        struct zcl_command_reply r;
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root1,
                              dir1, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(pj_bool(&r, "complete"));
        ASSERT_STR_EQ(pj_str(&r, "publisher_status"), "unknown");
        ASSERT_STR_EQ(pj_str(&r, "publisher"), f.pub_hex);
        ASSERT_STR_EQ(pj_str(&r, "name"), PJ_NAME);
        ASSERT_STR_EQ(pj_str(&r, "version"), "1.0.0");
        zcl_command_reply_free(&r);
        /* Fetch is inert and the receiver has not pinned the publisher. */
        ASSERT(!pj_current(cur));
        ASSERT(pj_join(manifest, sizeof(manifest), dir1, "upper.plugin.json"));
        {
            char in[1600];
            struct zcl_command_reply refused;
            ASSERT(snprintf(in, sizeof(in), "{\"manifest\":\"%s\"}",
                            manifest) > 0);
            ASSERT(pj_call(zcl_native_handle_plugin_install, in, &refused));
            ASSERT(refused.status != ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(refused.error.code, "PLUGIN_NO_KEYS");
            zcl_command_reply_free(&refused);
        }
        /* The receiving owner pins the publisher key; only then install. */
        ASSERT(pj_pin(&f));
        ASSERT(pj_install(manifest, gen1, true));
        ASSERT(pj_switch(gen1));
        ASSERT(pj_current(cur) && strcmp(cur, gen1) == 0);
        ASSERT(pj_call_upper("1.0.0"));
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}
/* Re-run the promote pipeline on a fetched source under the receiver's own
 * key; the out-params take the release hash and the signing key the receipt
 * names, so the caller can prove the pipeline really re-ran. */
static bool pj_reproduce(const char *src, const char *cases, const char *key,
                         const char *dir, char release_sha[129],
                         char pub_hex[65])
{
    char in[4 * 1200];
    struct zcl_command_reply r;
    int n = snprintf(in, sizeof(in),
                     "{\"file\":\"%s\",\"cases\":\"%s\",\"name\":\"%s\","
                     "\"version\":\"1.0.0\",\"key\":\"%s\",\"dir\":\"%s\"}",
                     src, cases, PJ_NAME, key, dir);
    if (n <= 0 || (size_t)n >= sizeof(in) ||
        !pj_call(zcl_native_handle_lab_promote, in, &r))
        return false;
    bool ok = r.exit_code == ZCL_COMMAND_EXIT_OK &&
              json_get_int(json_get(&r.data, "cases_passed")) == 2;
    const char *sha = ok ? pj_str(&r, "release_sha3_512") : NULL;
    const char *pub = ok ? pj_str(&r, "public_key") : NULL;
    ok = sha && strlen(sha) == 128 && pub && strlen(pub) == 64;
    if (ok) {
        snprintf(release_sha, 129, "%s", sha);
        snprintf(pub_hex, 65, "%s", pub);
    }
    zcl_command_reply_free(&r);
    return ok;
}

/* Independent reproduction: source and cases ride in the package as extra
 * flat members; the receiver re-runs the whole promote pipeline on the
 * fetched source under its own key and the release image comes out
 * bit-identical to the signed manifest's sha3_512 — before install is even
 * possible. Authority is unchanged: only the receiving owner's pin lets the
 * reproduced plugin activate. */
static int pj_t_reproduce(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: receiver independently reproduces the signed bytes") {
        char root1[65], dir1[1400], manifest[1600], gen1[129];
        ASSERT(ready);
        ASSERT(pj_promote_source(&f));
        /* The owner lets the source and cases ride with the signed pack. */
        {
            char dst_src[1400], dst_cases[1400];
            ASSERT(pj_join(dst_src, sizeof(dst_src), f.dist, "upper.c"));
            ASSERT(pj_write(dst_src, (const uint8_t *)PJ_CAP_SOURCE,
                            sizeof(PJ_CAP_SOURCE) - 1));
            ASSERT(pj_join(dst_cases, sizeof(dst_cases), f.dist, "cases.json"));
            ASSERT(pj_write(dst_cases, (const uint8_t *)PJ_CAP_CASES,
                            strlen(PJ_CAP_CASES)));
        }
        ASSERT(pj_publish(&f, root1));
        uint8_t root_bin[32];
        ASSERT(zcl_hex_decode(root1, root_bin, 32));
        struct vcs_package_public_verdict verdict;
        ASSERT_EQ(vcs_package_public_shape_classify(f.pub.store, root_bin,
                                                    &verdict),
                  VCS_PACKAGE_PUBLIC_PLUGIN);
        uint8_t publisher_key[33], receiver_key[33];
        sw_key(81, publisher_key);
        sw_key(82, receiver_key);
        ASSERT(vcs_swarm_engine_peer_add(f.recv.engine, 11, publisher_key));
        ASSERT(vcs_swarm_engine_peer_add(f.pub.engine, 13, receiver_key));
        vcs_swarm_engine_set_global(f.recv.engine);
        ASSERT(pj_join(dir1, sizeof(dir1), f.base, "repro-received"));
        struct zcl_command_reply r;
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root1,
                              dir1, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(pj_bool(&r, "complete"));
        ASSERT_STR_EQ(pj_str(&r, "publisher_status"), "unknown");
        zcl_command_reply_free(&r);
        /* The fetched checkout carries the source, the cases and the
         * signed manifest. */
        char got_src[1600], got_cases[1600], got_sha[129];
        ASSERT(pj_join(got_src, sizeof(got_src), dir1, "upper.c"));
        ASSERT(pj_join(got_cases, sizeof(got_cases), dir1, "cases.json"));
        ASSERT(pj_join(manifest, sizeof(manifest), dir1, "upper.plugin.json"));
        ASSERT(access(got_src, R_OK) == 0 && access(got_cases, R_OK) == 0);
        ASSERT(pj_manifest_sha(manifest, got_sha));
        /* The receiver re-runs the pipeline under its own key: the same
         * cases pass, the release image is bit-identical to the signed
         * sha3_512, and the receipt names the receiver's own signing key —
         * a real re-run, not a replay of the publisher's receipt. */
        char rkey[1200], rdist[1200], rsha[129], rpub[65], rpub_self[65];
        ASSERT(pj_join(rkey, sizeof(rkey), f.base, "receiver.key"));
        ASSERT(pj_keygen_to(rkey, rpub_self));
        ASSERT(pj_join(rdist, sizeof(rdist), f.base, "repro-dist"));
        ASSERT(pj_reproduce(got_src, got_cases, rkey, rdist, rsha, rpub));
        ASSERT_STR_EQ(rsha, got_sha);
        ASSERT_STR_EQ(rpub, rpub_self);
        ASSERT(strcmp(rpub, f.pub_hex) != 0);
        /* Authority is unchanged: no install until the receiver's owner
         * pins the publisher key. */
        {
            char in[1600];
            struct zcl_command_reply refused;
            ASSERT(snprintf(in, sizeof(in), "{\"manifest\":\"%s\"}",
                            manifest) > 0);
            ASSERT(pj_call(zcl_native_handle_plugin_install, in, &refused));
            ASSERT(refused.status != ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(refused.error.code, "PLUGIN_NO_KEYS");
            zcl_command_reply_free(&refused);
        }
        ASSERT(pj_pin(&f));
        ASSERT(pj_install(manifest, gen1, true));
        ASSERT(pj_switch(gen1));
        ASSERT(pj_call_upper("1.0.0"));
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

static uint8_t *pj_find(uint8_t *img, size_t size, const char *marker)
{
    size_t m = strlen(marker);
    for (size_t i = 0; i + m <= size; i++)
        if (memcmp(img + i, marker, m) == 0)
            return img + i;
    return NULL;
}

/* The resident fixture image with its behaviour field set to mode "normal"
 * and the tag "rj", padded past one package chunk so the transfer stays
 * multi-chunk; the patched field makes this lane a distinct generation. */
static bool pj_write_resident_image(const char *path)
{
    uint8_t *bytes = calloc(1, PJ_CAP);
    if (!bytes)
        return false;
    FILE *f = fopen("build/fixtures/plugin_run_child", "rb");
    size_t length = f ? fread(bytes, 1, PJ_CAP, f) : 0;
    bool ok = f && !ferror(f) && length > 0 && length < PJ_CAP;
    if (f)
        ok = fclose(f) == 0 && ok;
    uint8_t *at = ok ? pj_find(bytes, length, "PRC-VARIANT:") : NULL;
    if (!at) {
        free(bytes);
        return false;
    }
    at += strlen("PRC-VARIANT:");
    memset(at, ' ', 16);
    memcpy(at, "normal", 6);
    memcpy(at + 14, "rj", 2);
    if (length <= VCS_PACKAGE_CHUNK_BYTES)
        length = VCS_PACKAGE_CHUNK_BYTES + 7;
    memset(bytes + VCS_PACKAGE_CHUNK_BYTES, 'R',
           length - VCS_PACKAGE_CHUNK_BYTES);
    ok = pj_write(path, bytes, length) && chmod(path, 0755) == 0;
    free(bytes);
    return ok;
}

/* Pack the resident fixture as interface 1. Its "normal" mode writes
 * data.dir/report.txt and answers supervisor pings. */
static bool pj_pack_resident(struct pj_fixture *f, unsigned version)
{
    char in[4 * 1200];
    struct zcl_command_reply r;
    if (!pj_write_resident_image(f->exe))
        return false;
    int n = snprintf(in, sizeof(in),
                     "{\"exe\":\"%s\",\"name\":\"%s\",\"version\":\"%u.0.0\","
                     "\"key\":\"%s\",\"dir\":\"%s\",\"interface\":1,"
                     "\"cap\":[\"fs.write\",\"clock\",\"state\"]}",
                     f->exe, PJ_NAME, version, f->key, f->dist);
    if (n <= 0 || (size_t)n >= sizeof(in) ||
        !pj_call(zcl_native_handle_plugin_pack, in, &r))
        return false;
    bool ok = r.status == ZCL_COMMAND_STATUS_PASSED;
    zcl_command_reply_free(&r);
    return ok && pj_write_license(f->dist);
}

/* Poll until the supervised child is running and has answered one ping. */
static bool pj_run_healthy(struct plugin_run *run, unsigned timeout_ms)
{
    struct plugin_run_info info;
    for (unsigned elapsed = 0; elapsed < timeout_ms; elapsed += 5) {
        (void)plugin_run_poll(run);
        plugin_run_info_get(run, &info);
        if (info.state == PLUGIN_RUN_STATE_RUNNING && info.pings_ok >= 1)
            return true;
        if (info.state == PLUGIN_RUN_STATE_FAILED)
            return false;
        struct timespec nap = {0, 5 * 1000 * 1000};
        nanosleep(&nap, NULL);
    }
    return false;
}

/* The resident lane end to end: an interface 1 plugin is packed, signed and
 * published, crosses the swarm, and only the receiving owner's key pin lets
 * install proceed; the resident supervisor then runs the fetched generation
 * to a healthy ping, both through the supervisor API and through the real
 * plugin run command handle. */
static int pj_t_resident(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: interface 1 resident crosses the swarm and runs supervised") {
        char root1[65], dir1[1400], manifest[1600], gen1[129], cur[129];
        ASSERT(ready);
        ASSERT(pj_pack_resident(&f, 1));
        ASSERT(pj_publish(&f, root1));
        uint8_t root_bin[32];
        ASSERT(zcl_hex_decode(root1, root_bin, 32));
        struct vcs_package_public_verdict verdict;
        ASSERT_EQ(vcs_package_public_shape_classify(f.pub.store, root_bin,
                                                    &verdict),
                  VCS_PACKAGE_PUBLIC_PLUGIN);
        uint8_t publisher_key[33], receiver_key[33];
        sw_key(81, publisher_key);
        sw_key(82, receiver_key);
        ASSERT(vcs_swarm_engine_peer_add(f.recv.engine, 11, publisher_key));
        ASSERT(vcs_swarm_engine_peer_add(f.pub.engine, 13, receiver_key));
        vcs_swarm_engine_set_global(f.recv.engine);
        ASSERT(pj_join(dir1, sizeof(dir1), f.base, "resident-received"));
        struct zcl_command_reply r;
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root1,
                              dir1, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(pj_bool(&r, "complete"));
        ASSERT_STR_EQ(pj_str(&r, "publisher_status"), "unknown");
        ASSERT_STR_EQ(pj_str(&r, "publisher"), f.pub_hex);
        zcl_command_reply_free(&r);
        /* Fetch is inert and the receiver has not pinned the publisher. */
        ASSERT(!pj_current(cur));
        ASSERT(pj_join(manifest, sizeof(manifest), dir1, "upper.plugin.json"));
        {
            char in[1600];
            struct zcl_command_reply refused;
            ASSERT(snprintf(in, sizeof(in), "{\"manifest\":\"%s\"}",
                            manifest) > 0);
            ASSERT(pj_call(zcl_native_handle_plugin_install, in, &refused));
            ASSERT(refused.status != ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(refused.error.code, "PLUGIN_NO_KEYS");
            zcl_command_reply_free(&refused);
        }
        /* The receiving owner pins the publisher key; only then install. */
        ASSERT(pj_pin(&f));
        ASSERT(pj_install(manifest, gen1, true));
        ASSERT(pj_switch(gen1));
        ASSERT(pj_current(cur) && strcmp(cur, gen1) == 0);
        /* The supervisor runs the fetched generation; the run is closed
         * before any assertion can leave the child behind. */
        struct plugin_run_options options = {
            .root = f.plugins, .name = PJ_NAME,
            .ping_interval_ms = 40, .ping_deadline_ms = 500,
            .ping_miss_limit = 2, .backoff_initial_ms = 20,
            .backoff_max_ms = 2000, .stable_ms = 60000,
        };
        struct plugin_run *run = NULL;
        ASSERT_EQ(plugin_run_open(&options, &run, NULL), PLUGIN_RUN_OK);
        bool healthy = run && pj_run_healthy(run, 10000);
        struct plugin_run_info info;
        memset(&info, 0, sizeof(info));
        if (run) {
            plugin_run_info_get(run, &info);
            plugin_run_close(run);
        }
        ASSERT(healthy);
        ASSERT_STR_EQ(info.generation, gen1);
        /* Mode "normal" writes the confinement report into data.dir. */
        char report[1600], report_body[640];
        ASSERT(snprintf(report, sizeof(report), "%s/upper/data/report.txt",
                        f.plugins) > 0 && access(report, R_OK) == 0);
        ASSERT(pj_slurp(report, report_body, sizeof(report_body)));
        ASSERT(strstr(report_body, "fds=") != NULL);
        ASSERT(strstr(report_body, "stdio_null=") != NULL);
        /* The production activation surface: the same fetched generation
         * runs through the real plugin run command handle. */
        {
            struct zcl_command_reply ran;
            ASSERT(pj_call(zcl_native_handle_plugin_run,
                           "{\"name\":\"upper\",\"seconds\":3}", &ran));
            ASSERT(ran.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(pj_str(&ran, "schema"), "zcl.plugin_run.v1");
            ASSERT_STR_EQ(pj_str(&ran, "generation"), gen1);
            ASSERT(pj_bool(&ran, "stopped"));
            ASSERT(!pj_bool(&ran, "fell_back"));
            const struct json_value *pings = json_get(&ran.data, "pings_ok");
            ASSERT(pings && json_get_int(pings) >= 1);
            zcl_command_reply_free(&ran);
        }
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}
#endif

/* Capacity honesty: sixteen live downloads fill the receiver's table; the
 * seventeenth fetch is refused by name with no record, no checkout and no
 * in-memory state. Re-running an active fetch is idempotent even with the
 * table full, and an operator cancel tombstones a slot the refused fetch
 * then reuses. */
static int pj_t_slots_full(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: full download table refuses by name until a cancel "
         "frees a slot") {
        ASSERT(ready);
        vcs_swarm_engine_set_global(f.recv.engine);
        char dir[1400];
        ASSERT(pj_join(dir, sizeof(dir), f.base, "slots-received"));
        char roots[VCS_SWARM_MAX_DOWNLOADS + 1u][65];
        for (size_t i = 0; i <= VCS_SWARM_MAX_DOWNLOADS; i++) {
            uint8_t root_bin[32];
            memset(root_bin, (int)(i + 1u), sizeof(root_bin));
            zcl_hex_encode(root_bin, sizeof(root_bin), roots[i]);
        }
        /* None of the roots is served: each fetch registers live in
         * want-manifest and holds its slot. */
        for (size_t i = 0; i < VCS_SWARM_MAX_DOWNLOADS; i++) {
            struct zcl_command_reply r;
            ASSERT(pj_fetch_call(f.recv.datadir, roots[i], dir, &r));
            ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT(!pj_bool(&r, "complete"));
            ASSERT(pj_bool(&r, "live"));
            ASSERT_STR_EQ(pj_str(&r, "state"), "want-manifest");
            zcl_command_reply_free(&r);
        }
        char rec[1600];
        int rn = snprintf(rec, sizeof(rec), "%s/downloads/%s",
                          f.recv.zcode_dir,
                          roots[VCS_SWARM_MAX_DOWNLOADS]);
        ASSERT(rn > 0 && (size_t)rn < sizeof(rec));
        struct zcl_command_reply refused;
        ASSERT(pj_fetch_call(f.recv.datadir, roots[VCS_SWARM_MAX_DOWNLOADS],
                             dir, &refused));
        ASSERT(refused.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(refused.error.code, "PLUGIN_FETCH_SLOTS_FULL");
        ASSERT(strstr(refused.error.evidence, "download-table-full") != NULL);
        ASSERT(refused.error.human_action_required);
        zcl_command_reply_free(&refused);
        /* The refusal left nothing: no record, no checkout, and the root
         * reports inactive with zero chunks tracked. */
        ASSERT(pj_absent(rec));
        ASSERT(pj_absent(dir));
        uint8_t refused_bin[32];
        ASSERT(zcl_hex_decode(roots[VCS_SWARM_MAX_DOWNLOADS], refused_bin,
                              32));
        struct vcs_swarm_download_status st;
        memset(&st, 0, sizeof(st));
        ASSERT(vcs_swarm_engine_download_status(f.recv.engine, refused_bin,
                                                &st));
        ASSERT(st.state == VCS_SWARM_DL_INACTIVE);
        ASSERT(st.present_chunks == 0 && st.total_chunks == 0);
        /* A re-run of an active fetch never needs a new slot. */
        {
            struct zcl_command_reply again;
            ASSERT(pj_fetch_call(f.recv.datadir, roots[3], dir, &again));
            ASSERT(again.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT(pj_bool(&again, "live"));
            ASSERT_STR_EQ(pj_str(&again, "state"), "want-manifest");
            zcl_command_reply_free(&again);
        }
        /* The operator cancels a stale download; the tombstoned slot is
         * reused, so the refused root now registers and persists. */
        uint8_t cancel_bin[32];
        ASSERT(zcl_hex_decode(roots[0], cancel_bin, 32));
        ASSERT(vcs_swarm_engine_cancel(f.recv.engine, cancel_bin,
                                       (uint64_t)platform_time_wall_unix()));
        struct zcl_command_reply r;
        ASSERT(pj_fetch_call(f.recv.datadir, roots[VCS_SWARM_MAX_DOWNLOADS],
                             dir, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!pj_bool(&r, "complete"));
        ASSERT(pj_bool(&r, "live"));
        ASSERT_STR_EQ(pj_str(&r, "state"), "want-manifest");
        zcl_command_reply_free(&r);
        ASSERT(access(rec, F_OK) == 0);
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* Record-I/O honesty: when the resumable record cannot persist, the fetch
 * is refused by name and leaves nothing behind; once the path is repaired
 * the same fetch registers live and its record is on disk. The blocker is
 * a regular file where downloads/ must be a directory, so the refusal does
 * not depend on the test's uid. */
static int pj_t_record_io(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: unpersistable record refuses by name, then "
         "recovers once the path is repaired") {
        ASSERT(ready);
        vcs_swarm_engine_set_global(f.recv.engine);
        char dir[1400], dl_path[1500], rec[1600], root_hex[65];
        ASSERT(pj_join(dir, sizeof(dir), f.base, "io-received"));
        uint8_t root_bin[32];
        memset(root_bin, 0x2a, sizeof(root_bin));
        zcl_hex_encode(root_bin, sizeof(root_bin), root_hex);
        int rn = snprintf(dl_path, sizeof(dl_path), "%s/downloads",
                          f.recv.zcode_dir);
        ASSERT(rn > 0 && (size_t)rn < sizeof(dl_path));
        rn = snprintf(rec, sizeof(rec), "%s/%s", dl_path, root_hex);
        ASSERT(rn > 0 && (size_t)rn < sizeof(rec));
        ASSERT(pj_write(dl_path, (const uint8_t *)"x", 1));
        struct zcl_command_reply refused;
        bool called = pj_fetch_call(f.recv.datadir, root_hex, dir, &refused);
        ASSERT(unlink(dl_path) == 0);
        ASSERT(called);
        ASSERT(refused.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(refused.error.code, "PLUGIN_FETCH_RECORD_IO");
        ASSERT(strstr(refused.error.evidence, "record-io") != NULL);
        ASSERT(refused.error.human_action_required);
        zcl_command_reply_free(&refused);
        /* No partial state: no record, no checkout, and the root reports
         * inactive with zero chunks tracked. */
        ASSERT(pj_absent(rec));
        ASSERT(pj_absent(dir));
        struct vcs_swarm_download_status st;
        memset(&st, 0, sizeof(st));
        ASSERT(vcs_swarm_engine_download_status(f.recv.engine, root_bin,
                                                &st));
        ASSERT(st.state == VCS_SWARM_DL_INACTIVE);
        ASSERT(st.present_chunks == 0 && st.total_chunks == 0);
        /* Repaired: the same fetch registers live and persists its record. */
        struct zcl_command_reply r;
        ASSERT(pj_fetch_call(f.recv.datadir, root_hex, dir, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!pj_bool(&r, "complete"));
        ASSERT(pj_bool(&r, "live"));
        ASSERT_STR_EQ(pj_str(&r, "state"), "want-manifest");
        zcl_command_reply_free(&r);
        ASSERT(access(rec, F_OK) == 0);
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* The activation-lane refusal boundary: rollback before any upgrade
 * recorded a last-good refuses PLUGIN_NO_LAST_GOOD (even after the first
 * switch, which has no previous current to record), switching to a
 * generation that was never installed refuses PLUGIN_NO_GENERATION, and
 * rolling back a plugin that was never installed refuses
 * PLUGIN_NOT_INSTALLED. Every refusal names its rule and changes nothing
 * on disk; the working generation survives them all. */
static int pj_t_activation_refusals(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: activation refusals name their rule and change "
         "nothing") {
        char root1[65], dir1[1400], manifest[1600], gen1[129], cur[129];
        ASSERT(ready);
        ASSERT(pj_pack_publish(&f, 1, root1));
        uint8_t publisher_key[33], receiver_key[33];
        sw_key(81, publisher_key);
        sw_key(82, receiver_key);
        ASSERT(vcs_swarm_engine_peer_add(f.recv.engine, 11, publisher_key));
        ASSERT(vcs_swarm_engine_peer_add(f.pub.engine, 13, receiver_key));
        vcs_swarm_engine_set_global(f.recv.engine);
        ASSERT(pj_join(dir1, sizeof(dir1), f.base, "act-received"));
        ASSERT(pj_fetch_drive(&f.recv, 11, &f.pub, 13, f.recv.datadir, root1,
                              dir1, NULL));
        ASSERT(pj_join(manifest, sizeof(manifest), dir1, "upper.plugin.json"));
        ASSERT(pj_pin(&f));
        ASSERT(pj_install(manifest, gen1, true));
        char current_link[1700], last_good_link[1700];
        ASSERT(snprintf(current_link, sizeof(current_link),
                        "%s/upper/current", f.plugins) > 0);
        ASSERT(snprintf(last_good_link, sizeof(last_good_link),
                        "%s/upper/last-good", f.plugins) > 0);
        /* Install stages the generation but selects nothing: current
         * reports empty and neither link exists yet. */
        ASSERT(pj_current(cur) && cur[0] == '\0');
        ASSERT(pj_absent(current_link) && pj_absent(last_good_link));
        /* Rollback with nothing recorded refuses and changes nothing. */
        {
            struct zcl_command_reply refused;
            ASSERT(pj_call(zcl_native_handle_plugin_rollback,
                           "{\"name\":\"upper\"}", &refused));
            ASSERT(refused.status != ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(refused.error.code, "PLUGIN_NO_LAST_GOOD");
            ASSERT(strstr(refused.error.next_action, "switch") != NULL);
            zcl_command_reply_free(&refused);
        }
        ASSERT(pj_current(cur) && cur[0] == '\0');
        ASSERT(pj_absent(current_link) && pj_absent(last_good_link));
        /* Switching to a generation that was never installed refuses. */
        {
            char in[240], bogus[129];
            memset(bogus, 'a', 128);
            bogus[128] = '\0';
            struct zcl_command_reply refused;
            ASSERT(snprintf(in, sizeof(in),
                            "{\"name\":\"upper\",\"generation\":\"%s\"}",
                            bogus) > 0);
            ASSERT(pj_call(zcl_native_handle_plugin_switch, in, &refused));
            ASSERT(refused.status != ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(refused.error.code, "PLUGIN_NO_GENERATION");
            zcl_command_reply_free(&refused);
        }
        /* Rolling back a plugin that was never installed refuses. */
        {
            struct zcl_command_reply refused;
            ASSERT(pj_call(zcl_native_handle_plugin_rollback,
                           "{\"name\":\"ghost\"}", &refused));
            ASSERT(refused.status != ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(refused.error.code, "PLUGIN_NOT_INSTALLED");
            zcl_command_reply_free(&refused);
        }
        ASSERT(pj_absent(current_link) && pj_absent(last_good_link));
        /* The first switch has no previous current to record, so rollback
         * still refuses — and the working generation survives it all. */
        ASSERT(pj_switch(gen1));
        ASSERT(pj_current(cur) && strcmp(cur, gen1) == 0);
        {
            struct zcl_command_reply refused;
            ASSERT(pj_call(zcl_native_handle_plugin_rollback,
                           "{\"name\":\"upper\"}", &refused));
            ASSERT(refused.status != ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(refused.error.code, "PLUGIN_NO_LAST_GOOD");
            zcl_command_reply_free(&refused);
        }
        ASSERT(pj_current(cur) && strcmp(cur, gen1) == 0);
        ASSERT(pj_absent(last_good_link));
#if defined(__linux__)
        ASSERT(pj_call_upper("1.0.0"));
#endif
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* Announce-lane capture for the publish announce opt-in. */
static struct {
    char kind[12];
    char ns[24];
    char semantic[65];
    char transport[65];
    bool has_semantic;
} pj_ann[4];
static size_t pj_ann_count;

static bool pj_ann_capture(const char *kind, const char *ns,
                           const char *semantic, const char *transport)
{
    if (pj_ann_count >= 4)
        return false;
    snprintf(pj_ann[pj_ann_count].kind, 12, "%s", kind);
    snprintf(pj_ann[pj_ann_count].ns, 24, "%s", ns);
    pj_ann[pj_ann_count].has_semantic = semantic != NULL;
    if (semantic)
        snprintf(pj_ann[pj_ann_count].semantic, 65, "%s", semantic);
    snprintf(pj_ann[pj_ann_count].transport, 65, "%s", transport);
    pj_ann_count++;
    return true;
}

static bool pj_ann_refuse(const char *kind, const char *ns,
                          const char *semantic, const char *transport)
{
    (void)kind;
    (void)ns;
    (void)semantic;
    (void)transport;
    return false;
}

/* The announce opt-in: plugin publish with announce:true emits the POINTER
 * and PROVIDER records naming the fresh root into the plugin namespace
 * through the standard DHT publication helper; when the overlay cannot
 * commit them the publish stands and the refusal names the incomplete
 * announcement. */
static int pj_t_announce(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    pj_ann_count = 0;
    zcl_native_zcode_publish_test_backend(pj_ann_capture);
    TEST("plugin journey: publish announce emits POINTER and PROVIDER for the root") {
        char root1[65], in[4 * 1200];
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(pj_pack(&f, 1));
        ASSERT(snprintf(in, sizeof(in),
                        "{\"dir\":\"%s\",\"datadir\":\"%s\",\"announce\":true}",
                        f.dist, f.pub.datadir) > 0);
        ASSERT(pj_call(zcl_native_handle_plugin_publish, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(pj_bool(&r, "pointer_announced"));
        ASSERT(pj_bool(&r, "provider_announced"));
        ASSERT(pj_str(&r, "package_root"));
        snprintf(root1, sizeof(root1), "%s", pj_str(&r, "package_root"));
        zcl_command_reply_free(&r);
        ASSERT(pj_ann_count == 2);
        ASSERT_STR_EQ(pj_ann[0].kind, "pointer");
        ASSERT_STR_EQ(pj_ann[0].ns, "zclassic23.plugin");
        ASSERT(pj_ann[0].has_semantic);
        ASSERT_STR_EQ(pj_ann[0].semantic, root1);
        ASSERT_STR_EQ(pj_ann[0].transport, root1);
        ASSERT_STR_EQ(pj_ann[1].kind, "provider");
        ASSERT_STR_EQ(pj_ann[1].ns, "zclassic23.plugin");
        ASSERT(!pj_ann[1].has_semantic);
        ASSERT_STR_EQ(pj_ann[1].transport, root1);
        /* Overlay unreachable: the publish stands, the refusal is named. */
        pj_ann_count = 0;
        zcl_native_zcode_publish_test_backend(pj_ann_refuse);
        ASSERT(pj_pack(&f, 2));
        ASSERT(snprintf(in, sizeof(in),
                        "{\"dir\":\"%s\",\"datadir\":\"%s\",\"announce\":true}",
                        f.dist, f.pub.datadir) > 0);
        ASSERT(pj_call(zcl_native_handle_plugin_publish, in, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_ANNOUNCE_INCOMPLETE");
        ASSERT(r.error.mutated);
        ASSERT(pj_str(&r, "package_root") != NULL);
        ASSERT(pj_bool(&r, "pinned"));
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    zcl_native_zcode_publish_test_backend(NULL);
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* Fetch-route lane capture for the provider-discovery opt-in. */
static char pj_disc_kind[12];
static char pj_disc_ns[24];
static char pj_disc_root[65];
static int64_t pj_disc_records; /* count the discover seam reports */
static bool pj_route_refuse;    /* route seam fails with a refusal code */

static bool pj_disc_capture(struct json_value *selector,
                            struct json_value *result)
{
    const char *kind = json_get_str(json_get(selector, "kind"));
    const char *ns = json_get_str(json_get(selector, "namespace"));
    const char *tr = json_get_str(json_get(selector, "transport_root"));
    snprintf(pj_disc_kind, sizeof(pj_disc_kind), "%s", kind ? kind : "");
    snprintf(pj_disc_ns, sizeof(pj_disc_ns), "%s", ns ? ns : "");
    snprintf(pj_disc_root, sizeof(pj_disc_root), "%s", tr ? tr : "");
    json_set_object(result);
    (void)json_push_kv_int(result, "count", pj_disc_records);
    return true;
}

static bool pj_route_capture(struct json_value *selector,
                             struct json_value *result)
{
    (void)selector;
    json_set_object(result);
    if (pj_route_refuse) {
        (void)json_push_kv_str(result, "code", "FETCH_REFUSED");
        (void)json_push_kv_str(result, "error", "store quota");
        (void)json_push_kv_str(result, "fetch_result", "refused");
        return false;
    }
    (void)json_push_kv_bool(result, "ok", true);
    (void)json_push_kv_int(result, "authenticated_providers", 2);
    return true;
}

/* The fetch route opt-in: a one-shot plugin fetch given the plugin namespace
 * sends the exact root through the running node's provider discovery and
 * reports the route instead of a local download. A provider-less root is a
 * named transient refusal; a refusal after a successful route keeps the
 * node's own code. No store is opened and nothing downloads. */
static int pj_t_fetch_route(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    pj_disc_records = 2;
    pj_route_refuse = false;
    zcl_native_zcode_discovery_test_backend(pj_disc_capture,
                                            pj_route_capture);
    TEST("plugin journey: fetch with namespace routes the root through node discovery") {
        char in[4 * 1200];
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(snprintf(in, sizeof(in),
                        "{\"root\":\"%s\",\"dir\":\"%s/routed\","
                        "\"datadir\":\"%s\",\"namespace\":\"zclassic23.plugin\"}",
                        f.pub_hex, f.base, f.recv.datadir) > 0);
        ASSERT(pj_call(zcl_native_handle_plugin_fetch, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(pj_bool(&r, "routed"));
        ASSERT(pj_bool(&r, "live"));
        ASSERT_STR_EQ(pj_str(&r, "root"), f.pub_hex);
        ASSERT_STR_EQ(pj_str(&r, "schema"), "zcl.plugin_fetch.v1");
        const struct json_value *pr = json_get(&r.data, "provider_records");
        ASSERT(pr && json_get_int(pr) == 2);
        zcl_command_reply_free(&r);
        ASSERT_STR_EQ(pj_disc_kind, "provider");
        ASSERT_STR_EQ(pj_disc_ns, "zclassic23.plugin");
        ASSERT_STR_EQ(pj_disc_root, f.pub_hex);
        /* No provider announced: a named transient refusal, nothing local. */
        pj_disc_records = 0;
        ASSERT(pj_call(zcl_native_handle_plugin_fetch, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_PROVIDER_DISCOVERY_FAILED");
        zcl_command_reply_free(&r);
        /* The node routed, then refused under its own name: pass it through. */
        pj_disc_records = 2;
        pj_route_refuse = true;
        ASSERT(pj_call(zcl_native_handle_plugin_fetch, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(r.error.code, "FETCH_REFUSED");
        zcl_command_reply_free(&r);
        PASS();
    } _test_next:;
    zcl_native_zcode_discovery_test_backend(NULL, NULL);
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* Uninstall closes the lifecycle: one generation leaves only when neither
 * pointer names it, and whole-plugin removal deletes exactly the store-owned
 * files — a foreign byte anywhere refuses everything before anything moves,
 * and the plugin's data directory survives by design. */
static int pj_t_uninstall(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: uninstall removes exact owned files and preserves state") {
        char manifest[1600], gen1[129], gen2[129], gen3[129], cur[129];
        char in[2400];
        struct zcl_command_reply r;
        const struct json_value *gr;
        struct stat st;
        ASSERT(ready);
        ASSERT(pj_pin(&f));
        ASSERT(pj_pack(&f, 1));
        ASSERT(pj_join(manifest, sizeof(manifest), f.dist, "upper.plugin.json"));
        ASSERT(pj_install(manifest, gen1, true));
        ASSERT(pj_switch(gen1));
        ASSERT(pj_pack(&f, 2));
        ASSERT(pj_install(manifest, gen2, true));
        ASSERT(pj_switch(gen2)); /* current gen2, last-good gen1 */
        ASSERT(pj_pack(&f, 3));
        ASSERT(pj_install(manifest, gen3, true)); /* no pointer names gen3 */
        /* Refused authority over live bytes: both pointer-named generations
         * stay until the operator moves the pointers. */
        ASSERT(snprintf(in, sizeof(in),
                        "{\"name\":\"%s\",\"generation\":\"%s\"}", PJ_NAME,
                        gen2) > 0);
        ASSERT(pj_call(zcl_native_handle_plugin_uninstall, in, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_UNINSTALL_ACTIVE");
        zcl_command_reply_free(&r);
        ASSERT(snprintf(in, sizeof(in),
                        "{\"name\":\"%s\",\"generation\":\"%s\"}", PJ_NAME,
                        gen1) > 0);
        ASSERT(pj_call(zcl_native_handle_plugin_uninstall, in, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_UNINSTALL_ACTIVE");
        zcl_command_reply_free(&r);
        /* The unreferenced generation goes; both pointers stay valid. */
        ASSERT(snprintf(in, sizeof(in),
                        "{\"name\":\"%s\",\"generation\":\"%s\"}", PJ_NAME,
                        gen3) > 0);
        ASSERT(pj_call(zcl_native_handle_plugin_uninstall, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(pj_str(&r, "schema"), "zcl.plugin_uninstall.v1");
        gr = json_get(&r.data, "generations_removed");
        ASSERT(gr && json_get_int(gr) == 1);
        ASSERT(!pj_bool(&r, "current_cleared"));
        zcl_command_reply_free(&r);
        ASSERT(pj_current(cur) && strcmp(cur, gen2) == 0);
        /* The same generation again is a named refusal, not a no-op. */
        ASSERT(pj_call(zcl_native_handle_plugin_uninstall, in, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_NO_GENERATION");
        zcl_command_reply_free(&r);
        /* A stranger's file inside a generation refuses the whole uninstall
         * before anything moves. */
        char gendir[1600], sentinel[1700];
        ASSERT(snprintf(gendir, sizeof(gendir), "%s/%s/generations/%s",
                        f.plugins, PJ_NAME, gen2) > 0);
        ASSERT(pj_join(sentinel, sizeof(sentinel), gendir, "notes.txt"));
        ASSERT(pj_write(sentinel, (const uint8_t *)"keep", 4));
        ASSERT(snprintf(in, sizeof(in), "{\"name\":\"%s\"}", PJ_NAME) > 0);
        ASSERT(pj_call(zcl_native_handle_plugin_uninstall, in, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_UNINSTALL_LAYOUT");
        zcl_command_reply_free(&r);
        ASSERT(pj_current(cur) && strcmp(cur, gen2) == 0);
        ASSERT(stat(sentinel, &st) == 0);
        ASSERT(unlink(sentinel) == 0);
        /* Whole plugin: both pointers and all generations go; the state
         * directory is preserved and reported. */
        char state_dir[1600], state[1700];
        ASSERT(snprintf(state_dir, sizeof(state_dir), "%s/%s/data",
                        f.plugins, PJ_NAME) > 0 &&
               mkdir(state_dir, 0700) == 0);
        ASSERT(pj_join(state, sizeof(state), state_dir, "state.txt"));
        ASSERT(pj_write(state, (const uint8_t *)"7", 1));
        ASSERT(pj_call(zcl_native_handle_plugin_uninstall, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(pj_bool(&r, "current_cleared"));
        ASSERT(pj_bool(&r, "last_good_cleared"));
        ASSERT(pj_bool(&r, "state_preserved"));
        gr = json_get(&r.data, "generations_removed");
        ASSERT(gr && json_get_int(gr) == 2);
        zcl_command_reply_free(&r);
        ASSERT(stat(state, &st) == 0);   /* state intact */
        ASSERT(stat(gendir, &st) != 0);  /* generations gone */
        /* Nothing is current now: status reports the empty slot by name. */
        {
            struct zcl_command_reply st_r;
            char st_in[128];
            ASSERT(snprintf(st_in, sizeof(st_in), "{\"name\":\"%s\"}",
                            PJ_NAME) > 0);
            ASSERT(pj_call(zcl_native_handle_plugin_status, st_in, &st_r));
            ASSERT(st_r.status == ZCL_COMMAND_STATUS_PASSED);
            ASSERT_STR_EQ(pj_str(&st_r, "current"), "");
            ASSERT_STR_EQ(pj_str(&st_r, "current_state"), "missing");
            const struct json_value *gc = json_get(&st_r.data, "generations");
            ASSERT(gc && json_get_int(gc) == 0);
            zcl_command_reply_free(&st_r);
        }
        /* Idempotent: the repeat removes nothing and still passes. */
        ASSERT(pj_call(zcl_native_handle_plugin_uninstall, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        gr = json_get(&r.data, "generations_removed");
        ASSERT(gr && json_get_int(gr) == 0);
        ASSERT(pj_bool(&r, "state_preserved"));
        zcl_command_reply_free(&r);
        /* The publisher keys live outside the plugin directory: untouched. */
        char keys[1600];
        ASSERT(pj_join(keys, sizeof(keys), f.plugins, "publisher_keys"));
        ASSERT(stat(keys, &st) == 0);
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

#if defined(__linux__)
/* Double-fork so the supervised stand-in is orphaned and init reaps it: a
 * zombie child of this test process would still answer kill(pid, 0), which
 * is not how a real supervisor's death looks. The grandchild's pid comes
 * back over the pipe. */
static pid_t pj_orphan_pause(int *ready)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t child = fork();
    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (child == 0) {
        close(fds[0]);
        signal(SIGTERM, SIG_DFL); /* before the grandchild inherits it */
        pid_t grand = fork();
        if (grand == 0) {
            close(fds[1]);
            for (;;)
                pause();
            _exit(0);
        }
        int64_t gp = grand;
        TEST_DISCARD(write(fds[1], &gp, sizeof(gp)));
        _exit(0);
    }
    close(fds[1]);
    int64_t grand = -1;
    *ready = read(fds[0], &grand, sizeof(grand)) == (ssize_t)sizeof(grand) &&
             grand > 0;
    close(fds[0]);
    int status = 0;
    (void)waitpid(child, &status, 0);
    return *ready ? (pid_t)grand : -1;
}

static int pj_t_stop(void)
{
    int failures = 0;
    struct pj_fixture f;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    bool ready = pj_open(&f);
    TEST("plugin journey: stop signals only the registered live supervisor and clears stale records") {
        char manifest[1600], gen1[129], in[1600], run_file[1600];
        struct zcl_command_reply r;
        struct stat st;
        ASSERT(ready);
        ASSERT(pj_pin(&f));
        ASSERT(pj_pack_resident(&f, 1));
        ASSERT(pj_join(manifest, sizeof(manifest), f.dist, "upper.plugin.json"));
        ASSERT(pj_install(manifest, gen1, true));
        ASSERT(pj_switch(gen1));
        ASSERT(snprintf(run_file, sizeof(run_file), "%s/%s/run", f.plugins,
                        PJ_NAME) > 0);
        /* Nothing registered: an idempotent success; an unknown name refuses. */
        ASSERT(snprintf(in, sizeof(in), "{\"name\":\"%s\"}", PJ_NAME) > 0);
        ASSERT(pj_call(zcl_native_handle_plugin_stop, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(pj_str(&r, "schema"), "zcl.plugin_stop.v1");
        ASSERT(!pj_bool(&r, "stopped"));
        zcl_command_reply_free(&r);
        ASSERT(pj_call(zcl_native_handle_plugin_stop, "{\"name\":\"ghost\"}", &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_NOT_INSTALLED");
        zcl_command_reply_free(&r);
        /* A live registered supervisor: uninstall refuses busy until stop. */
        int spawned = 0;
        pid_t grand = pj_orphan_pause(&spawned);
        ASSERT(spawned && grand > 0);
        uint64_t token = 0;
        ASSERT(os_proc_pid_start_token((uint64_t)grand, &token));
        ASSERT_EQ(plugin_store_run_register(f.plugins, PJ_NAME, (uint64_t)grand,
                                            token, gen1),
                  PLUGIN_OK);
        ASSERT(pj_call(zcl_native_handle_plugin_uninstall, in, &r));
        ASSERT(r.status != ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(r.error.code, "PLUGIN_BUSY");
        zcl_command_reply_free(&r);
        /* Stop signals exactly that process; its record goes with it. */
        ASSERT(pj_call(zcl_native_handle_plugin_stop, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(pj_bool(&r, "stopped"));
        const struct json_value *pidv = json_get(&r.data, "pid");
        ASSERT(pidv && json_get_int(pidv) == (int64_t)grand);
        ASSERT_STR_EQ(pj_str(&r, "generation"), gen1);
        zcl_command_reply_free(&r);
        ASSERT_EQ(os_proc_pid_liveness((uint64_t)grand), OS_PROC_LIVENESS_DEAD);
        ASSERT(stat(run_file, &st) != 0);
        /* The repeat finds nothing and is the same success. */
        ASSERT(pj_call(zcl_native_handle_plugin_stop, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!pj_bool(&r, "stopped"));
        zcl_command_reply_free(&r);
        /* A stale record (dead pid) is cleared without a signal. */
        ASSERT_EQ(plugin_store_run_register(f.plugins, PJ_NAME, (uint64_t)grand,
                                            1, gen1),
                  PLUGIN_OK);
        ASSERT(pj_call(zcl_native_handle_plugin_stop, in, &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(!pj_bool(&r, "stopped"));
        zcl_command_reply_free(&r);
        ASSERT(stat(run_file, &st) != 0);
        /* The real run handler registers on entry and unregisters on exit. */
        ASSERT(pj_call(zcl_native_handle_plugin_run,
                       "{\"name\":\"upper\",\"seconds\":2}", &r));
        ASSERT(r.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(pj_bool(&r, "stopped"));
        zcl_command_reply_free(&r);
        ASSERT(stat(run_file, &st) != 0);
        PASS();
    } _test_next:;
    pj_close(&f);
    vcs_swarm_engine_set_global(prev);
    return failures;
}
#endif

int test_plugin_journey(void)
{
    int failures = 0;
    failures += pj_t_journey();
    failures += pj_t_disappearance();
    failures += pj_t_corrupt();
    failures += pj_t_refusals();
    failures += pj_t_extra_inert();
    failures += pj_t_fetch_before_serve();
    failures += pj_t_slots_full();
    failures += pj_t_record_io();
    failures += pj_t_activation_refusals();
    failures += pj_t_announce();
    failures += pj_t_fetch_route();
    failures += pj_t_uninstall();
#if defined(__linux__)
    failures += pj_t_source_to_peer();
    failures += pj_t_reproduce();
    failures += pj_t_resident();
    failures += pj_t_stop();
#endif
    return failures;
}
