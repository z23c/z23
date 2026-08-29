/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The serve side of identity-free source transport:
 * zcode.workspace.source.bundle.publish, the `sourcebundle_publish` RPC under
 * it, and app/services/src/source_bundle_publish.c under that.
 *
 * WHAT THIS FILE IS FOR. `create` already proved a bundle can be written.
 * Nothing proved a bundle could be FETCHED FROM THIS NODE, and those are
 * different claims: a file in the right directory that the running node's
 * artifact registry has never heard of is not an offer, and neither is a
 * registry entry on a node with no listening file service. So the central case
 * here is the whole loop over the real serve path — publish on one datadir,
 * then fetch and check out on a second one using nothing but the printed
 * 64-hex root — and the tree that comes out the far end is proved identical by
 * re-capturing it and comparing ZVCS roots, not by eyeballing a byte count.
 *
 * THE TRAP THIS FILE PINS. rom_seed's directory sweep stops after
 * ROM_SEED_SCAN_ENTRY_CAP entries, so a bundle published into a crowded
 * directory can sit past the cap and never be offered, silently. Case (e)
 * fills the seeded directory past that cap, resets the registry to empty, and
 * requires publish to serve the bundle anyway — which only a by-name
 * registration can do — while reporting `rescan_guaranteed` false so the
 * operator is told the sweep is no longer a promise.
 *
 * Everything runs over the REAL serve path (fs_server_start on a fixture
 * datadir) against 127.0.0.1 — no mock transport, no real datadir. The one
 * stub is the RPC SOCKET (node_rpc_client_set_test_hook), and it is mandatory
 * rather than convenient: without it the leaf would dial whatever node this
 * host is actually running and publish into its live datadir. The hook routes
 * the call into the same registered RPC handler the daemon serves, so the leaf
 * -> RPC -> service -> registry chain is exercised end to end.
 *
 * Every assertion is about an OUTCOME or a RELATIONSHIP; none is about wall-
 * clock duration. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "controllers/file_market_controller.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "net/file_service.h"
#include "net/rom_peer_scoring.h"
#include "net/rom_seed.h"
#include "platform/time_compat.h"
#include "rpc/server.h"
#include "services/source_bundle_publish.h"
#include "util/util.h"
#include "vcs/source_bundle.h"
#include "vcs/vcs.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ── Fixtures ───────────────────────────────────────────────────────── */

static bool sbp_write(const char *dir, const char *name, const void *bytes,
                      size_t len)
{
    char path[1200];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t off = 0;
    const uint8_t *p = bytes;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w <= 0) { close(fd); return false; }
        off += (size_t)w;
    }
    return close(fd) == 0;
}

/* A small C23 source tree. `flavor` selects one differing byte so two trees
 * can be built that capture to different roots while every other path, mode
 * and length is identical. */
static bool sbp_make_tree(const char *dir, char flavor)
{
    char body[600];
    for (size_t i = 0; i < sizeof(body); i++)
        body[i] = (char)('a' + (int)(i % 26));
    body[11] = flavor;
    return sbp_write(dir, "main.c", body, sizeof(body)) &&
           sbp_write(dir, "unit.h", "#pragma once\n", 13) &&
           sbp_write(dir, "NOTES", "z23 identity-free source\n", 25);
}

/* Read a whole file into a heap buffer. NULL on any failure. */
static uint8_t *sbp_slurp(const char *path, size_t *len_out)
{
    *len_out = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0 || st.st_size > (off_t)(1 << 26)) {
        close(fd);
        return NULL;
    }
    size_t len = (size_t)st.st_size;
    uint8_t *buf = malloc(len);
    if (!buf) { close(fd); return NULL; }
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, buf + off, len - off);
        if (r <= 0) { free(buf); close(fd); return NULL; }
        off += (size_t)r;
    }
    close(fd);
    *len_out = len;
    return buf;
}

/* True when `left/name` and `right/name` hold the same bytes. */
static bool sbp_same_file(const char *left, const char *right, const char *name)
{
    char lp[1200], rp[1200];
    snprintf(lp, sizeof(lp), "%s/%s", left, name);
    snprintf(rp, sizeof(rp), "%s/%s", right, name);
    size_t ln = 0, rn = 0;
    uint8_t *lb = sbp_slurp(lp, &ln);
    uint8_t *rb = sbp_slurp(rp, &rn);
    bool same = lb && rb && ln == rn && memcmp(lb, rb, ln) == 0;
    free(lb);
    free(rb);
    return same;
}

/* Count non-dot entries directly under `dir` (-1 when it cannot be read). */
static int sbp_count_entries(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            n++;
    closedir(d);
    return n;
}

/* Remove a fixture directory and everything under it, to a fixed depth. The
 * shared test_cleanup_tmpdir() is one level deep, and these fixtures are not:
 * a datadir grows a bundles/ subdirectory (with thousands of padding entries
 * in the scan-cap case) and a workspace grows its .zvcs/ CAS. Depth-bounded
 * rather than unbounded — a fixture that needed more than this is a fixture
 * that got away from the test. */
static void sbp_rm_tree(const char *path, int depth)
{
    if (!path || depth < 0) return;
    DIR *d = opendir(path);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            char child[1400];
            snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
            if (unlink(child) == 0)
                continue;
            sbp_rm_tree(child, depth - 1);
        }
        closedir(d);
    }
    rmdir(path);
}

/* Start the real file service on `datadir` and return its OS-assigned port
 * (0 on failure). Port 0 everywhere: a fixed port would collide with a second
 * copy of this suite, or with anything else on the box. */
static uint16_t sbp_serve(const char *datadir)
{
    fs_server_start(datadir, 0);
    for (int w = 0; w < 40 && !fs_server_is_running(); w++)
        platform_sleep_ms(50);
    return fs_server_is_running() ? fs_server_get_port() : 0;
}

/* Raise the free-tier byte-rate windows so a multi-case suite is not throttled
 * by its own previous case; rom_seed_reset() restores the defaults. */
static void sbp_open_caps(void)
{
    rom_seed_reset();
    rom_peer_scoring_test_reset();
    rom_seed_set_enabled(true);
    rom_seed_set_peer_bps_cap(1ull << 30);
    rom_seed_set_global_bps_cap(1ull << 30);
}

static void sbp_hex32(const uint8_t v[32], char out[65])
{
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2] = d[v[i] >> 4];
        out[i * 2 + 1] = d[v[i] & 0x0F];
    }
    out[64] = '\0';
}

/* ── The RPC socket stand-in ────────────────────────────────────────── */

/* Route node_rpc_call() into the SAME registered handler the daemon serves,
 * in this process, instead of onto a socket. Mandatory, not convenient: the
 * unhooked client would resolve this host's real node cookie and publish into
 * a live datadir. */
static struct rpc_table g_sbp_table;

static char *sbp_rpc_hook(const char *method, const char *params_json)
{
    struct json_value params, result;
    json_init(&params);
    json_init(&result);
    if (params_json && !json_read(&params, params_json, strlen(params_json)))
        json_set_array(&params);
    (void)rpc_table_execute(&g_sbp_table, method, &params, &result);
    size_t need = json_write(&result, NULL, 0);
    char *out = malloc(need + 1);
    if (out) {
        json_write(&result, out, need + 1);
        out[need] = '\0';
    }
    json_free(&params);
    json_free(&result);
    return out;
}

static void sbp_hook_install(void)
{
    rpc_table_init(&g_sbp_table);
    register_source_bundle_rpc_commands(&g_sbp_table);
    set_rpc_warmup_finished();
    node_rpc_client_set_test_hook(sbp_rpc_hook);
}

/* Drive the publish leaf exactly as the CLI would. */
static void sbp_run_leaf(const char *workspace, const char *pin_hex,
                         struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "workspace", workspace);
    if (pin_hex)
        (void)json_push_kv_str(&input, "source_root", pin_hex);
    struct zcl_command_request request = { .input = &input };
    zcl_command_reply_init(reply, "zcl.zcode_source_bundle_publish.v1");
    zcl_native_handle_zcode_source_bundle_publish(&request, reply);
    json_free(&input);
}

/* Drive the fetch leaf — the OTHER machine's half of the loop. */
static void sbp_run_fetch(const char *root_hex, const char *out_path,
                          const char *peers, struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "source_root", root_hex);
    (void)json_push_kv_str(&input, "output", out_path);
    (void)json_push_kv_str(&input, "peers", peers);
    struct zcl_command_request request = { .input = &input };
    zcl_command_reply_init(reply, "zcl.zcode_source_bundle_fetch.v1");
    zcl_native_handle_zcode_source_bundle_fetch(&request, reply);
    json_free(&input);
}

/* Drive the checkout leaf — materializing what arrived. */
static void sbp_run_checkout(const char *bundle, const char *root_hex,
                             const char *cas, const char *destination,
                             struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "bundle", bundle);
    (void)json_push_kv_str(&input, "source_root", root_hex);
    (void)json_push_kv_str(&input, "workspace", cas);
    (void)json_push_kv_str(&input, "destination", destination);
    struct zcl_command_request request = { .input = &input };
    zcl_command_reply_init(reply, "zcl.zcode_source_bundle_checkout.v1");
    zcl_native_handle_zcode_source_bundle_checkout(&request, reply);
    json_free(&input);
}

/* The string value of one reply key, or NULL. */
static const char *sbp_reply_str(const struct zcl_command_reply *reply,
                                 const char *key)
{
    const struct json_value *v = json_get(&reply->data, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static const struct zcl_command_spec *sbp_publish_spec(void)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    for (size_t i = 0; registry && i < registry->count; i++) {
        if (strcmp(registry->commands[i].path,
                   "zcode.workspace.source.bundle.publish") == 0)
            return &registry->commands[i];
    }
    return NULL;
}

/* ── (a) The loop: publish here, fetch and check out over there ──────── */

static int test_publish_then_fetch_elsewhere(void)
{
    int failures = 0;
    TEST("publish offers a workspace by its content root, and a second "
         "datadir reconstructs the identical tree from that root alone") {
        sbp_open_caps();
        char aroot[] = "/tmp/zcl_sbpub_nodeA_XXXXXX";
        char wroot[] = "/tmp/zcl_sbpub_work_XXXXXX";
        char broot[] = "/tmp/zcl_sbpub_nodeB_XXXXXX";
        char croot[] = "/tmp/zcl_sbpub_cas_XXXXXX";
        char droot[] = "/tmp/zcl_sbpub_dest_XXXXXX";
        char *adir = mkdtemp(aroot), *wdir = mkdtemp(wroot);
        char *bdir = mkdtemp(broot), *cdir = mkdtemp(croot);
        char *ddir = mkdtemp(droot);
        ASSERT(adir && wdir && bdir && cdir && ddir);
        ASSERT(sbp_make_tree(wdir, 'A'));

        /* NODE A: its own datadir, its own port, serving. */
        uint16_t port = sbp_serve(adir);
        ASSERT(port != 0);

        struct source_bundle_publish_report report;
        ASSERT(source_bundle_publish(wdir, adir, NULL, &report) ==
               SOURCE_BUNDLE_PUBLISH_OK);
        ASSERT(report.file_service_port == port);
        ASSERT(report.wire_bytes > 0 && report.num_chunks >= 1);
        ASSERT(!report.republished);
        /* It is being OFFERED, which is a stronger claim than "the file is in
         * the right directory": the registry answers for it by root. */
        struct rom_artifact offered;
        ASSERT(rom_seed_find_by_root(report.artifact_root, &offered));
        ASSERT(offered.kind == ROM_ARTIFACT_SOURCE_BUNDLE);
        ASSERT(offered.has_source_root);
        ASSERT(memcmp(offered.source_root, report.source_root, 32) == 0);
        /* The name is derived from the content root and lives under the ONE
         * subdirectory the seeder reaches into. */
        char root_hex[65];
        sbp_hex32(report.source_root, root_hex);
        char expect_name[160];
        snprintf(expect_name, sizeof(expect_name), "%s/%s%s",
                 ROM_SEED_BUNDLES_SUBDIR, root_hex,
                 ROM_SEED_SOURCE_BUNDLE_SUFFIX);
        ASSERT(strcmp(report.filename, expect_name) == 0);
        ASSERT(access(report.path, F_OK) == 0);

        /* NODE B: a different datadir, holding nothing, knowing only the
         * 64-hex root and one address. */
        char out_path[1200], peers[64];
        snprintf(out_path, sizeof(out_path), "%s/pulled.zvsb", bdir);
        snprintf(peers, sizeof(peers), "127.0.0.1:%u", (unsigned)port);
        struct zcl_command_reply reply;
        sbp_run_fetch(root_hex, out_path, peers, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        zcl_command_reply_free(&reply);
        ASSERT(access(out_path, F_OK) == 0);

        sbp_run_checkout(out_path, root_hex, cdir, ddir, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        zcl_command_reply_free(&reply);

        /* THE property: the tree that came out the far end IS the tree that
         * went in. Proved by the same content authority that named it — a
         * fresh capture of the destination must produce the published root —
         * and cross-checked byte for byte on every file. */
        uint8_t back[32];
        ASSERT(vcs_tree_capture_path(ddir, back) == VCS_OK);
        ASSERT(memcmp(back, report.source_root, 32) == 0);
        ASSERT(sbp_same_file(wdir, ddir, "main.c"));
        ASSERT(sbp_same_file(wdir, ddir, "unit.h"));
        ASSERT(sbp_same_file(wdir, ddir, "NOTES"));

        fs_server_stop();
        sbp_rm_tree(ddir, 6);
        sbp_rm_tree(cdir, 6);
        sbp_rm_tree(bdir, 6);
        sbp_rm_tree(wdir, 6);
        sbp_rm_tree(adir, 6);
        sbp_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (b) Publishing the same tree twice is a no-op ───────────────────── */

static int test_republish_is_idempotent(void)
{
    int failures = 0;
    TEST("republishing an unchanged workspace re-offers the same artifact "
         "instead of writing a second copy") {
        sbp_open_caps();
        char aroot[] = "/tmp/zcl_sbpub_again_dd_XXXXXX";
        char wroot[] = "/tmp/zcl_sbpub_again_ws_XXXXXX";
        char *adir = mkdtemp(aroot), *wdir = mkdtemp(wroot);
        ASSERT(adir && wdir);
        ASSERT(sbp_make_tree(wdir, 'A'));
        ASSERT(sbp_serve(adir) != 0);

        struct source_bundle_publish_report first, second;
        ASSERT(source_bundle_publish(wdir, adir, NULL, &first) ==
               SOURCE_BUNDLE_PUBLISH_OK);
        ASSERT(!first.republished);
        ASSERT(source_bundle_publish(wdir, adir, NULL, &second) ==
               SOURCE_BUNDLE_PUBLISH_OK);
        ASSERT(second.republished);
        ASSERT(memcmp(first.source_root, second.source_root, 32) == 0);
        ASSERT(memcmp(first.artifact_root, second.artifact_root, 32) == 0);
        ASSERT(strcmp(first.path, second.path) == 0);

        /* One bundle on disk, one entry in the registry — not two of either. */
        char seed_dir[1200];
        snprintf(seed_dir, sizeof(seed_dir), "%s/%s", adir,
                 ROM_SEED_BUNDLES_SUBDIR);
        ASSERT(sbp_count_entries(seed_dir) == 1);
        ASSERT(rom_seed_count() == 1);

        fs_server_stop();
        sbp_rm_tree(wdir, 6);
        sbp_rm_tree(adir, 6);
        sbp_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (c) A malformed object at the content address is never replaced ── */

static int test_malformed_existing_bundle_is_preserved(void)
{
    int failures = 0;
    TEST("publishing refuses and preserves a malformed existing bundle at "
         "the captured tree's content address") {
        sbp_open_caps();
        char aroot[] = "/tmp/zcl_sbpub_malformed_dd_XXXXXX";
        char wroot[] = "/tmp/zcl_sbpub_malformed_ws_XXXXXX";
        char *adir = mkdtemp(aroot), *wdir = mkdtemp(wroot);
        ASSERT(adir && wdir);
        ASSERT(sbp_make_tree(wdir, 'A'));
        ASSERT(sbp_serve(adir) != 0);

        uint8_t root[32];
        ASSERT(vcs_tree_capture_path(wdir, root) == VCS_OK);
        char root_hex[65], seed_dir[1200], leaf[96], path[1400];
        sbp_hex32(root, root_hex);
        snprintf(seed_dir, sizeof(seed_dir), "%s/%s", adir,
                 ROM_SEED_BUNDLES_SUBDIR);
        ASSERT(mkdir(seed_dir, 0700) == 0 || errno == EEXIST);
        snprintf(leaf, sizeof(leaf), "%s%s", root_hex,
                 ROM_SEED_SOURCE_BUNDLE_SUFFIX);
        snprintf(path, sizeof(path), "%s/%s", seed_dir, leaf);

        /* Empty is not a valid bundle. It is still an existing object, not
         * permission to replace bytes at a content-addressed name. */
        ASSERT(sbp_write(seed_dir, leaf, "", 0));
        struct stat before;
        ASSERT(stat(path, &before) == 0);
        ASSERT(before.st_size == 0);

        struct source_bundle_publish_report report;
        ASSERT(source_bundle_publish(wdir, adir, NULL, &report) ==
               SOURCE_BUNDLE_PUBLISH_ERR_STORE);

        struct stat after;
        ASSERT(stat(path, &after) == 0);
        ASSERT(after.st_size == before.st_size);
        ASSERT(rom_seed_count() == 0);

        fs_server_stop();
        sbp_rm_tree(wdir, 6);
        sbp_rm_tree(adir, 6);
        sbp_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (d) The pin refuses a tree the caller did not mean ──────────────── */

static int test_root_pin_refuses(void)
{
    int failures = 0;
    TEST("a source_root pin refuses a workspace that captures to a different "
         "tree, and offers nothing") {
        sbp_open_caps();
        char aroot[] = "/tmp/zcl_sbpub_pin_dd_XXXXXX";
        char hroot[] = "/tmp/zcl_sbpub_pin_honest_XXXXXX";
        char eroot[] = "/tmp/zcl_sbpub_pin_other_XXXXXX";
        char *adir = mkdtemp(aroot), *hdir = mkdtemp(hroot);
        char *edir = mkdtemp(eroot);
        ASSERT(adir && hdir && edir);
        ASSERT(sbp_make_tree(hdir, 'A'));
        ASSERT(sbp_make_tree(edir, 'B'));
        ASSERT(sbp_serve(adir) != 0);

        uint8_t honest[32];
        ASSERT(vcs_tree_capture_path(hdir, honest) == VCS_OK);

        /* The OTHER tree, published under the honest tree's root. */
        struct source_bundle_publish_report report;
        ASSERT(source_bundle_publish(edir, adir, honest, &report) ==
               SOURCE_BUNDLE_PUBLISH_ERR_ROOT_PIN);
        ASSERT(rom_seed_count() == 0);
        char seed_dir[1200];
        snprintf(seed_dir, sizeof(seed_dir), "%s/%s", adir,
                 ROM_SEED_BUNDLES_SUBDIR);
        ASSERT(sbp_count_entries(seed_dir) <= 0);

        /* The same pin on the tree it names is accepted. */
        ASSERT(source_bundle_publish(hdir, adir, honest, &report) ==
               SOURCE_BUNDLE_PUBLISH_OK);
        ASSERT(memcmp(report.source_root, honest, 32) == 0);

        fs_server_stop();
        sbp_rm_tree(edir, 6);
        sbp_rm_tree(hdir, 6);
        sbp_rm_tree(adir, 6);
        sbp_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (e) The bounded directory sweep cannot hide a published bundle ──── */

static int test_immune_to_scan_cap(void)
{
    int failures = 0;
    TEST("a seeded directory crowded past ROM_SEED_SCAN_ENTRY_CAP still "
         "serves a freshly published bundle, and says the sweep is no longer "
         "a promise") {
        sbp_open_caps();
        char aroot[] = "/tmp/zcl_sbpub_cap_dd_XXXXXX";
        char wroot[] = "/tmp/zcl_sbpub_cap_ws_XXXXXX";
        char *adir = mkdtemp(aroot), *wdir = mkdtemp(wroot);
        ASSERT(adir && wdir);
        ASSERT(sbp_make_tree(wdir, 'A'));
        ASSERT(sbp_serve(adir) != 0);

        /* Crowd the seeded directory past the sweep's ceiling. The padding is
         * deliberately NOT artifact-shaped: it costs the walk its budget
         * without competing for a registry slot, which is exactly the shape a
         * real busy datadir has. */
        char seed_dir[1200];
        snprintf(seed_dir, sizeof(seed_dir), "%s/%s", adir,
                 ROM_SEED_BUNDLES_SUBDIR);
        ASSERT(mkdir(seed_dir, 0700) == 0 || errno == EEXIST);
        for (unsigned i = 0; i < ROM_SEED_SCAN_ENTRY_CAP + 8u; i++) {
            char name[64];
            snprintf(name, sizeof(name), "pad-%06u.bin", i);
            ASSERT(sbp_write(seed_dir, name, "x", 1));
        }

        /* An EMPTY registry, so nothing can be inherited from an earlier
         * case: whatever ends up offered was put there by this publish. */
        rom_seed_reset();
        rom_seed_set_enabled(true);
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);
        ASSERT(rom_seed_count() == 0);

        struct source_bundle_publish_report report;
        ASSERT(source_bundle_publish(wdir, adir, NULL, &report) ==
               SOURCE_BUNDLE_PUBLISH_OK);
        /* Immunity: the artifact is offered although the walk that would have
         * had to find it cannot promise it reached that far. */
        ASSERT(rom_seed_find_by_root(report.artifact_root, NULL));
        ASSERT(report.seed_directory_entries > ROM_SEED_SCAN_ENTRY_CAP);
        ASSERT(!report.rescan_guaranteed);

        /* And the same call on an uncrowded directory reports the sweep as
         * still dependable — so the flag tracks the directory, not the code
         * path. */
        char broot[] = "/tmp/zcl_sbpub_cap_dd2_XXXXXX";
        char *bdir = mkdtemp(broot);
        ASSERT(bdir);
        struct source_bundle_publish_report clean;
        ASSERT(source_bundle_publish(wdir, bdir, NULL, &clean) ==
               SOURCE_BUNDLE_PUBLISH_OK);
        ASSERT(clean.rescan_guaranteed);
        ASSERT(memcmp(clean.source_root, report.source_root, 32) == 0);

        fs_server_stop();
        sbp_rm_tree(bdir, 6);
        sbp_rm_tree(wdir, 6);
        sbp_rm_tree(adir, 6);
        sbp_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (f) Never "published" when nothing could serve it ───────────────── */

static int test_unservable_is_refused(void)
{
    int failures = 0;
    TEST("publish refuses, with the reason, when there is no file service or "
         "seeding is switched off — it never reports an offer it cannot make") {
        sbp_open_caps();
        char aroot[] = "/tmp/zcl_sbpub_off_dd_XXXXXX";
        char wroot[] = "/tmp/zcl_sbpub_off_ws_XXXXXX";
        char *adir = mkdtemp(aroot), *wdir = mkdtemp(wroot);
        ASSERT(adir && wdir);
        ASSERT(sbp_make_tree(wdir, 'A'));

        /* No file service: nobody could dial this node for the bytes. */
        ASSERT(!fs_server_is_running());
        struct source_bundle_publish_report report;
        ASSERT(source_bundle_publish(wdir, adir, NULL, &report) ==
               SOURCE_BUNDLE_PUBLISH_ERR_NO_SERVICE);
        ASSERT(rom_seed_count() == 0);

        /* Serving, but seeding disabled: registered artifacts are not served,
         * so this is refused too — and with its OWN reason, because "turn
         * seeding on" and "start the file service" are different fixes. */
        ASSERT(sbp_serve(adir) != 0);
        rom_seed_set_enabled(false);
        ASSERT(source_bundle_publish(wdir, adir, NULL, &report) ==
               SOURCE_BUNDLE_PUBLISH_ERR_SEEDING_OFF);
        ASSERT(rom_seed_count() == 0);
        rom_seed_set_enabled(true);

        /* Nothing was written on either refusal. */
        char seed_dir[1200];
        snprintf(seed_dir, sizeof(seed_dir), "%s/%s", adir,
                 ROM_SEED_BUNDLES_SUBDIR);
        ASSERT(sbp_count_entries(seed_dir) <= 0);

        /* With both in place, the same call succeeds — proving the two
         * refusals above were about posture, not about the workspace. */
        ASSERT(source_bundle_publish(wdir, adir, NULL, &report) ==
               SOURCE_BUNDLE_PUBLISH_OK);

        fs_server_stop();
        sbp_rm_tree(wdir, 6);
        sbp_rm_tree(adir, 6);
        sbp_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

/* ── (g) The leaf: through the RPC the daemon actually serves ────────── */

static int test_leaf_through_rpc(void)
{
    int failures = 0;
    TEST("zcode.workspace.source.bundle.publish reports the root and the port "
         "a peer needs, and fails loudly rather than half-publishing") {
        sbp_open_caps();
        char aroot[] = "/tmp/zcl_sbpub_leaf_dd_XXXXXX";
        char wroot[] = "/tmp/zcl_sbpub_leaf_ws_XXXXXX";
        char *adir = mkdtemp(aroot), *wdir = mkdtemp(wroot);
        ASSERT(adir && wdir);
        ASSERT(sbp_make_tree(wdir, 'A'));

        /* The RPC handler resolves the NODE'S datadir, never a caller
         * argument, so the fixture datadir is pinned before the hook is
         * installed. */
        ASSERT(SetDataDir(adir));
        char nodedir[1024];
        GetDataDir(true, nodedir, sizeof(nodedir));
        ASSERT(nodedir[0] != '\0');
        uint16_t port = sbp_serve(nodedir);
        ASSERT(port != 0);
        sbp_hook_install();

        struct zcl_command_reply reply;
        sbp_run_leaf(wdir, NULL, &reply);
        ASSERT(reply.status != ZCL_COMMAND_STATUS_FAILED);
        const char *root_hex = sbp_reply_str(&reply, "source_root");
        ASSERT(root_hex != NULL && strlen(root_hex) == 64);
        const struct json_value *offered = json_get(&reply.data, "offered");
        ASSERT(offered && offered->type == JSON_BOOL && json_get_bool(offered));
        const struct json_value *pv =
            json_get(&reply.data, "file_service_port");
        ASSERT(pv && pv->type == JSON_INT && json_get_int(pv) == (int64_t)port);
        /* The printed root is the one the registry is answering for. */
        uint8_t captured[32];
        ASSERT(vcs_tree_capture_path(wdir, captured) == VCS_OK);
        char captured_hex[65];
        sbp_hex32(captured, captured_hex);
        ASSERT(strcmp(root_hex, captured_hex) == 0);
        zcl_command_reply_free(&reply);

        /* Drive the catalog boundary too. A direct handler call cannot catch
         * an optional key omitted from input_keys: normalization would reject
         * it before this file's handler fixture ever ran. The pin must be an
         * allowed JSON key while only workspace maps positionally, and a full
         * registry dispatch with the pin must reach the RPC and succeed. */
        const struct zcl_command_registry *registry = zcl_command_catalog();
        const struct zcl_command_spec *spec = sbp_publish_spec();
        ASSERT(registry && spec);
        ASSERT(strcmp(spec->input_keys, "workspace,source_root") == 0);
        ASSERT(strcmp(spec->positional_keys, "workspace") == 0);
        struct json_value catalog_input;
        json_init(&catalog_input);
        json_set_object(&catalog_input);
        ASSERT(json_push_kv_str(&catalog_input, "workspace", wdir));
        ASSERT(json_push_kv_str(&catalog_input, "source_root", captured_hex));
        char why[160];
        ASSERT(zcl_command_registry_input_validate(
            spec, &catalog_input, why, sizeof(why)));
        struct zcl_command_context context = {
            .registry = registry,
            .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        };
        char envelope[ZCL_COMMAND_RESULT_BUDGET + 1];
        enum zcl_command_exit exit_code = ZCL_COMMAND_EXIT_INTERNAL;
        size_t envelope_len = zcl_command_registry_execute_json(
            registry, spec, &context, &catalog_input, false, spec->path,
            "normal", 0, 0, NULL, envelope, sizeof(envelope), &exit_code);
        ASSERT(envelope_len > 0);
        ASSERT(exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(strstr(envelope, captured_hex) != NULL);
        json_free(&catalog_input);

        /* A pin naming a tree this workspace is not is refused at the leaf
         * with the service's own reason, not a generic failure. */
        char wrong_hex[65];
        uint8_t wrong[32];
        memcpy(wrong, captured, 32);
        wrong[0] = (uint8_t)(wrong[0] ^ 0xFFu);
        sbp_hex32(wrong, wrong_hex);
        sbp_run_leaf(wdir, wrong_hex, &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "SOURCE_BUNDLE_PUBLISH_REFUSED") == 0);
        ASSERT(strstr(reply.error.message, "source-root-pin") != NULL);
        zcl_command_reply_free(&reply);

        /* A malformed pin never reaches the node at all. */
        sbp_run_leaf(wdir, "not-hex", &reply);
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT(strcmp(reply.error.code, "BAD_SOURCE_BUNDLE_PUBLISH_INPUT") == 0);
        zcl_command_reply_free(&reply);

        node_rpc_client_set_test_hook(NULL);
        fs_server_stop();
        sbp_rm_tree(wdir, 6);
        sbp_rm_tree(adir, 6);
        sbp_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

int test_source_bundle_publish(void)
{
    int failures = 0;
    failures += test_publish_then_fetch_elsewhere();
    failures += test_republish_is_idempotent();
    failures += test_malformed_existing_bundle_is_preserved();
    failures += test_root_pin_refuses();
    failures += test_immune_to_scan_cap();
    failures += test_unservable_is_refused();
    failures += test_leaf_through_rpc();
    return failures;
}
