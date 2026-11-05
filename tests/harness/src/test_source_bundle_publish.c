/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The serve side of identity-free source transport:
 * zcode.workspace.source.bundle.publish, the `sourcebundle_publish` RPC under
 * it, and engine/services/src/source_bundle_publish.c under that.
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
#include "base/safe_alloc.h"
#include "config/command_catalog.h"
#include "controllers/file_market_controller.h"
#include "controllers/rpc_client.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "net/file_market.h"
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
 * rather than unbounded -- a fixture that needed more than this is a fixture
 * that got away from the test.
 *
 * The argument is normalized by test_cleanup_path() (trailing separators
 * stripped) and the top and every visited entry are classified with
 * platform_file_shape_read() before use. A link is removed as a link and is
 * never enumerated; on a reparse-point platform it is left alone. A child path
 * that would be truncated is skipped, never acted on. Child paths are rebuilt
 * by name, so ancestor and concurrent swaps are NOT covered. */
static void sbp_rm_entry(const char *norm, int depth);

static void sbp_rm_children(DIR *d, const char *norm, int depth)
{
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char child[768];
        int n = snprintf(child, sizeof(child), "%s/%s", norm, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(child))
            continue;
        sbp_rm_entry(child, depth - 1);
    }
}

static void sbp_rm_entry(const char *norm, int depth)
{
    if (depth < 0) return;
    enum platform_file_shape shape = platform_file_shape_read(norm);
    if (shape == PLATFORM_FILE_SHAPE_MISSING ||
        shape == PLATFORM_FILE_SHAPE_UNREADABLE)
        return;
    if (shape == PLATFORM_FILE_SHAPE_SYMLINK) {
#if !defined(_WIN32)
        (void)unlink(norm);
#endif
        return;
    }
    if (shape == PLATFORM_FILE_SHAPE_REGULAR) {
        (void)unlink(norm);
        return;
    }
    DIR *d = opendir(norm);
    if (!d) {
        (void)unlink(norm);
        return;
    }
    sbp_rm_children(d, norm, depth);
    closedir(d);
    (void)rmdir(norm);
}

static void sbp_rm_tree(const char *path, int depth)
{
    char norm[768];
    if (!path || depth < 0 || !test_cleanup_path(path, norm)) return;
    sbp_rm_entry(norm, depth);
}

/* Start the real file service on `datadir` and return its OS-assigned port
 * (0 on failure). Port 0 everywhere: a fixed port would collide with a second
 * copy of this suite, or with anything else on the box. */
static uint16_t sbp_serve(const char *datadir)
{
    fs_server_start(datadir, 0, NULL);
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
        char aroot[PATH_MAX];
        char wroot[PATH_MAX];
        char broot[PATH_MAX];
        char croot[PATH_MAX];
        char droot[PATH_MAX];
        char *adir = test_mkdtemp(aroot, sizeof aroot, "zcl_sbpub_nodeA"), *wdir = test_mkdtemp(wroot, sizeof wroot, "zcl_sbpub_work");
        char *bdir = test_mkdtemp(broot, sizeof broot, "zcl_sbpub_nodeB"), *cdir = test_mkdtemp(croot, sizeof croot, "zcl_sbpub_cas");
        char *ddir = test_mkdtemp(droot, sizeof droot, "zcl_sbpub_dest");
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
        char aroot[PATH_MAX];
        char wroot[PATH_MAX];
        char *adir = test_mkdtemp(aroot, sizeof aroot, "zcl_sbpub_again_dd"), *wdir = test_mkdtemp(wroot, sizeof wroot, "zcl_sbpub_again_ws");
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
        char aroot[PATH_MAX];
        char wroot[PATH_MAX];
        char *adir = test_mkdtemp(aroot, sizeof aroot, "zcl_sbpub_malformed_dd"), *wdir = test_mkdtemp(wroot, sizeof wroot, "zcl_sbpub_malformed_ws");
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
        char aroot[PATH_MAX];
        char hroot[PATH_MAX];
        char eroot[PATH_MAX];
        char *adir = test_mkdtemp(aroot, sizeof aroot, "zcl_sbpub_pin_dd"), *hdir = test_mkdtemp(hroot, sizeof hroot, "zcl_sbpub_pin_honest");
        char *edir = test_mkdtemp(eroot, sizeof eroot, "zcl_sbpub_pin_other");
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
        char aroot[PATH_MAX];
        char wroot[PATH_MAX];
        char *adir = test_mkdtemp(aroot, sizeof aroot, "zcl_sbpub_cap_dd"), *wdir = test_mkdtemp(wroot, sizeof wroot, "zcl_sbpub_cap_ws");
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
        ASSERT(report.entries_beyond_cap > 0);
        ASSERT(!report.rescan_guaranteed);

        /* And the same call on an uncrowded directory reports the sweep as
         * still dependable — so the flag tracks the directory, not the code
         * path. */
        char broot[PATH_MAX];
        char *bdir = test_mkdtemp(broot, sizeof broot, "zcl_sbpub_cap_dd2");
        ASSERT(bdir);
        struct source_bundle_publish_report clean;
        ASSERT(source_bundle_publish(wdir, bdir, NULL, &clean) ==
               SOURCE_BUNDLE_PUBLISH_OK);
        ASSERT(clean.rescan_guaranteed);
        ASSERT(clean.entries_beyond_cap == 0);
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
        char aroot[PATH_MAX];
        char wroot[PATH_MAX];
        char *adir = test_mkdtemp(aroot, sizeof aroot, "zcl_sbpub_off_dd"), *wdir = test_mkdtemp(wroot, sizeof wroot, "zcl_sbpub_off_ws");
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
        char aroot[PATH_MAX];
        char wroot[PATH_MAX];
        char *adir = test_mkdtemp(aroot, sizeof aroot, "zcl_sbpub_leaf_dd"), *wdir = test_mkdtemp(wroot, sizeof wroot, "zcl_sbpub_leaf_ws");
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

/* ── (g) The OTHER cap: registry slots, not walked entries ───────────── */

/* ADVERSARIAL. Case (d) proves publish survives a directory crowded past
 * ROM_SEED_SCAN_ENTRY_CAP, and its padding is deliberately not artifact-shaped
 * so nothing there "competes for a registry slot". That leaves the competition
 * itself untested, and it is the cap that actually binds: the registry is
 * ROM_SEED_MAX_ARTIFACTS = 8 slots, three orders of magnitude below the 4096
 * entry cap, and rom_seed_scan_datadir() fills them in arbitrary readdir order
 * and then `break`s. So a seeded directory nowhere near the entry cap can still
 * lose bundles on the next sweep — and `rescan_guaranteed`, computed against
 * the entry cap alone, told the operator the opposite.
 *
 * The fixture is the ordinary shape of a synced node that publishes: one
 * header seed in the datadir root (the exactly-named artifact every sweep
 * registers FIRST, by name) plus a full set of published source bundles. No
 * padding, no tampering, no hostile input — every file here is one this node
 * put there itself and was told would survive a restart. */
static int test_registry_cap_breaks_rescan_promise(void)
{
    int failures = 0;
    TEST("publish must not promise a boot-time sweep it cannot keep: the "
         "registry holds ROM_SEED_MAX_ARTIFACTS entries, so a seeded directory "
         "far under the entry cap still loses bundles on the next sweep") {
        sbp_open_caps();
        char aroot[PATH_MAX];
        char *adir = test_mkdtemp(aroot, sizeof aroot, "zcl_sbpub_slots_dd");
        ASSERT(adir != NULL);
        ASSERT(sbp_serve(adir) != 0);

        /* A synced node's header seed. It is not padding: it classifies as a
         * real artifact, it is looked up BY NAME before any walk, and it
         * therefore takes one of the eight slots on every future sweep. */
        uint8_t seed_bytes[ROM_SEED_MIN_ARTIFACT_BYTES];
        memset(seed_bytes, 0, sizeof(seed_bytes));
        ASSERT(sbp_write(adir, "block_index.bin", seed_bytes,
                         sizeof(seed_bytes)));

        /* Publish a full registry's worth of distinct trees. Each call is
         * told, in its own report, whether a future sweep will reach the
         * bundle it just landed. */
        uint8_t artifact_roots[ROM_SEED_MAX_ARTIFACTS][32];
        struct source_bundle_publish_report report;
        memset(&report, 0, sizeof(report));
        for (unsigned i = 0; i < ROM_SEED_MAX_ARTIFACTS; i++) {
            char wroot[PATH_MAX];
            char *wdir = test_mkdtemp(wroot, sizeof wroot, "zcl_sbpub_slots_ws");
            ASSERT(wdir != NULL);
            ASSERT(sbp_make_tree(wdir, (char)('A' + (int)i)));
            ASSERT(source_bundle_publish(wdir, adir, NULL, &report) ==
                   SOURCE_BUNDLE_PUBLISH_OK);
            memcpy(artifact_roots[i], report.artifact_root, 32);
            sbp_rm_tree(wdir, 6);
        }

        /* The seeded directory is three orders of magnitude under the entry
         * cap, so nothing the walk-length rule measures is in play here. */
        char seed_dir[1200];
        snprintf(seed_dir, sizeof(seed_dir), "%s/%s", adir,
                 ROM_SEED_BUNDLES_SUBDIR);
        ASSERT(sbp_count_entries(seed_dir) == (int)ROM_SEED_MAX_ARTIFACTS);
        ASSERT(report.seed_directory_entries < ROM_SEED_SCAN_ENTRY_CAP);
        ASSERT(rom_seed_count() == (int)ROM_SEED_MAX_ARTIFACTS);

        /* THE RESTART. An empty registry, then the same bounded sweep a boot
         * runs — the only thing that re-offers these bundles afterwards. */
        rom_seed_reset();
        rom_seed_set_enabled(true);
        rom_seed_set_peer_bps_cap(1ull << 30);
        rom_seed_set_global_bps_cap(1ull << 30);
        ASSERT(rom_seed_count() == 0);
        ASSERT(rom_seed_scan_datadir(adir) == (int)ROM_SEED_MAX_ARTIFACTS);

        /* Ground truth, independent of any flag: the header seed took a slot,
         * so the sweep provably could not re-offer every published bundle.
         * WHICH ones survive is readdir order; that at least one does not is
         * arithmetic. */
        unsigned still_offered = 0;
        for (unsigned i = 0; i < ROM_SEED_MAX_ARTIFACTS; i++)
            if (rom_seed_find_by_root(artifact_roots[i], NULL))
                still_offered++;
        ASSERT(still_offered < ROM_SEED_MAX_ARTIFACTS);

        /* So the promise made at publish time must not have been made.
         * `rescan_guaranteed` is a claim about the NEXT sweep, and a sweep
         * bounded by eight slots cannot honour it for nine artifacts —
         * whatever the entry count says. */
        ASSERT(!report.rescan_guaranteed);

        fs_server_stop();
        sbp_rm_tree(adir, 6);
        sbp_open_caps();
        PASS();
    } _test_next:;
    return failures;
}

static const char *g_sbp_observed_body;

static char *sbp_malformed_rpc(const char *method, const char *params_json)
{
    (void)method;
    (void)params_json;
    return zcl_strdup(g_sbp_observed_body, "source_bundle_publish.test_reply");
}

static int sbp_refuses_malformed_reply(const char *label, const char *body)
{
    int failures = 0;
    TEST(label) {
        char workspace[1200];
        ASSERT(test_mkdtemp(workspace, sizeof(workspace), "sbpub_reply"));
        struct zcl_command_reply reply;
        g_sbp_observed_body = body;
        node_rpc_client_set_test_hook(sbp_malformed_rpc);
        sbp_run_leaf(workspace, NULL, &reply);
        node_rpc_client_set_test_hook(NULL);
        g_sbp_observed_body = NULL;
        test_cleanup_tmpdir(workspace);
        bool failed = reply.status == ZCL_COMMAND_STATUS_FAILED;
        bool malformed = strcmp(reply.error.code,
                                "SOURCE_BUNDLE_PUBLISH_MALFORMED_REPLY") == 0;
        bool mutated = reply.error.mutated;
        bool offered = json_get(&reply.data, "offered") != NULL;
        bool root = json_get(&reply.data, "source_root") != NULL;
        bool next = json_get(&reply.data, "next") != NULL;
        zcl_command_reply_free(&reply);
        ASSERT(access(workspace, F_OK) != 0);
        ASSERT(failed);
        ASSERT(malformed);
        ASSERT(!mutated);
        ASSERT(!offered);
        ASSERT(!root);
        ASSERT(!next);
        PASS();
    } _test_next:;
    return failures;
}

static int test_malformed_published_reply(void)
{
    static const char root[] =
        "{\"status\":\"published\",\"source_root\":\"a\\\"b\"}";
    static const char filename[] =
        "{\"status\":\"published\",\"source_root\":\""
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "\",\"filename\":\"\xff\"}";
    static const char error[] = "{\"error\":{\"message\":\"\xff\"}}";
    static const char result[] = "{\"status\":\"refused\",\"result\":\"\xff\"}";
    int failures = 0;
    failures += sbp_refuses_malformed_reply(
        "published RPC observation refuses a quote-bearing source root", root);
    failures += sbp_refuses_malformed_reply(
        "published RPC observation refuses invalid UTF-8 filename", filename);
    failures += sbp_refuses_malformed_reply(
        "publish RPC observation refuses invalid UTF-8 error message", error);
    failures += sbp_refuses_malformed_reply(
        "publish RPC observation refuses invalid UTF-8 result text", result);
    return failures;
}

#if !defined(_WIN32)
/* Checked, non-recursive cleanup of the symlink fixture: the link first. */
static bool nofollow_cleanup(const char *root, const char *target,
                             const char *sentinel, const char *link)
{
    (void)unlink(link);
    bool clean = true;
    if (unlink(sentinel) != 0 && errno != ENOENT) clean = false;
    if (rmdir(target) != 0 && errno != ENOENT) clean = false;
    if (rmdir(root) != 0 && errno != ENOENT) clean = false;
    return clean;
}

/* The remover must unlink a symbolic link at its top, never walk through it.
 * The link points (relative) at a sibling directory this test creates and
 * fills with one sentinel; cleanup is checked unlink/rmdir only, and the link
 * is unlinked before anything else runs. */
static int test_rm_tree_does_not_follow_symlink(void)
{
    int failures = 0;
    printf("test_rm_tree_does_not_follow_symlink: ");

    char root[512], target[640], sentinel[704], link[640];
    test_make_tmpdir(root, sizeof(root), "sbpub", "nofollow");
    snprintf(target, sizeof(target), "%s/target", root);
    snprintf(sentinel, sizeof(sentinel), "%s/keep", target);
    snprintf(link, sizeof(link), "%s/link", root);

    bool built = mkdir(target, 0700) == 0;
    int sfd = built ? open(sentinel, O_WRONLY | O_CREAT | O_EXCL, 0600) : -1;
    if (sfd >= 0) close(sfd);
    bool linked = sfd >= 0 && symlink("target", link) == 0;
    if (linked) sbp_rm_tree(link, 6);

    struct stat st;
    bool link_gone = linked && lstat(link, &st) != 0 && errno == ENOENT;
    bool kept = linked && stat(sentinel, &st) == 0;

    bool clean = nofollow_cleanup(root, target, sentinel, link);

    if (link_gone && kept && clean) {
        printf("OK\n");
    } else {
        printf("FAIL (linked=%d link_gone=%d kept=%d clean=%d)\n",
               linked, link_gone, kept, clean);
        failures++;
    }
    return failures;
}

/* Trailing-separator control: "root/link/" must not resolve the link's
 * referent. The link points (relative) at a sibling directory this case
 * creates and fills with one sentinel. The shared normalizer strips the
 * separator, so the link is removed as a link and the sentinel and target
 * directory survive. Cleanup is checked unlink/rmdir only, link first, and
 * runs before any assertion. */
static int test_rm_tree_trailing_separator_keeps_target(void)
{
    int failures = 0;
    printf("test_rm_tree_trailing_separator_keeps_target: ");

    char root[512], target[640], sentinel[704], link[640], slashed[648];
    test_make_tmpdir(root, sizeof(root), "sbpub", "nofollow_slash");
    snprintf(target, sizeof(target), "%s/target", root);
    snprintf(sentinel, sizeof(sentinel), "%s/keep", target);
    snprintf(link, sizeof(link), "%s/link", root);
    snprintf(slashed, sizeof(slashed), "%s/", link);

    bool built = mkdir(target, 0700) == 0;
    int sfd = built ? open(sentinel, O_WRONLY | O_CREAT | O_EXCL, 0600) : -1;
    if (sfd >= 0) close(sfd);
    bool linked = sfd >= 0 && symlink("target", link) == 0;
    if (linked) sbp_rm_tree(slashed, 6);

    struct stat st;
    bool link_gone = linked && lstat(link, &st) != 0 && errno == ENOENT;
    bool kept = linked && stat(sentinel, &st) == 0;
    bool target_kept = linked && stat(target, &st) == 0;

    bool clean = nofollow_cleanup(root, target, sentinel, link);

    if (link_gone && kept && target_kept && clean) {
        printf("OK\n");
    } else {
        printf("FAIL (linked=%d link_gone=%d kept=%d target_kept=%d clean=%d)\n",
               linked, link_gone, kept, target_kept, clean);
        failures++;
    }
    return failures;
}
#endif

/* ── Mutation-measured gaps: names, arguments, refusals, announce, caps ──
 *
 * Helpers return false on the first unmet requirement (printing the line) so
 * the TEST wrapper can always run its teardown. */

#define SBP_REQ(cond) do { \
    if (!(cond)) { \
        printf("\n    sbp requirement failed at line %d: %s\n", __LINE__, \
               #cond); \
        return false; \
    } \
} while (0)

/* readdir() reports "." and ".."; the service's bounded walk counts them. */
#define SBP_DOT_ENTRIES 2u

/* A datadir with a running file service and one workspace. Zero-initialised
 * so a close after a failed open removes only what exists. */
struct sbp_fx {
    char aroot[PATH_MAX];
    char wroot[PATH_MAX];
    char *adir;
    char *wdir;
};

static bool sbp_fx_open(struct sbp_fx *fx, const char *tag, char flavor)
{
    memset(fx, 0, sizeof(*fx));
    sbp_open_caps();
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "zcl_sbpx_%s_d", tag);
    fx->adir = test_mkdtemp(fx->aroot, sizeof(fx->aroot), prefix);
    snprintf(prefix, sizeof(prefix), "zcl_sbpx_%s_w", tag);
    fx->wdir = test_mkdtemp(fx->wroot, sizeof(fx->wroot), prefix);
    return fx->adir && fx->wdir && sbp_make_tree(fx->wdir, flavor) &&
           sbp_serve(fx->adir) != 0;
}

static void sbp_fx_close(struct sbp_fx *fx)
{
    fs_server_stop();
    if (fx->wdir) sbp_rm_tree(fx->wdir, 6);
    if (fx->adir) sbp_rm_tree(fx->adir, 6);
    memset(fx, 0, sizeof(*fx));
    sbp_open_caps();
}

/* The content address of the workspace: seeded directory (created), leaf name
 * and the captured root. */
static bool sbp_address(const struct sbp_fx *fx, uint8_t root[32],
                        char seed_dir[1200], char leaf[96])
{
    char root_hex[65];
    if (vcs_tree_capture_path(fx->wdir, root) != VCS_OK)
        return false;
    sbp_hex32(root, root_hex);
    snprintf(seed_dir, 1200, "%s/%s", fx->adir, ROM_SEED_BUNDLES_SUBDIR);
    snprintf(leaf, 96, "%s%s", root_hex, ROM_SEED_SOURCE_BUNDLE_SUFFIX);
    return mkdir(seed_dir, 0700) == 0 || errno == EEXIST;
}

static int test_publish_result_strings(void)
{
    int failures = 0;
    TEST("source_bundle_publish: every result has its own stable name and an "
         "unknown value is named unknown") {
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_OK), "ok") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_ERR_ARGS), "arguments") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_ERR_WORKSPACE),
                   "workspace-capture") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_ERR_ROOT_PIN),
                   "source-root-pin") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_ERR_BUNDLE), "bundle-create") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_ERR_STORE),
                   "seed-directory-write") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_ERR_SEEDING_OFF),
                   "seeding-disabled") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_ERR_NO_SERVICE),
                   "no-file-service") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_ERR_REGISTRY_FULL),
                   "registry-full") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_ERR_REGISTER),
                   "registration-refused") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   SOURCE_BUNDLE_PUBLISH_ERR_NOT_OFFERED),
                   "not-offered") == 0);
        ASSERT(strcmp(source_bundle_publish_result_string(
                   (enum source_bundle_publish_result)99), "unknown") == 0);
        PASS();
    } _test_next:;
    return failures;
}

static bool sbp_report_is_zero(const struct source_bundle_publish_report *r)
{
    static const uint8_t zero[32] = {0};
    return memcmp(r->source_root, zero, 32) == 0 &&
           memcmp(r->artifact_root, zero, 32) == 0 && r->filename[0] == '\0' &&
           r->path[0] == '\0' && r->wire_bytes == 0 && r->num_chunks == 0 &&
           r->file_service_port == 0 && !r->republished &&
           r->seed_directory_entries == 0 && r->entries_beyond_cap == 0 &&
           !r->rescan_guaranteed;
}

/* Argument checks come first, whatever the node's posture; a refusal never
 * leaves stale report bytes behind; a one-character name is a name. */
static bool sbp_args_contract(void)
{
    struct source_bundle_publish_report r;
    SBP_REQ(!fs_server_is_running());
    SBP_REQ(source_bundle_publish("w", "d", NULL, NULL) ==
            SOURCE_BUNDLE_PUBLISH_ERR_ARGS);

    memset(&r, 0xFF, sizeof(r));
    SBP_REQ(source_bundle_publish("", "d", NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_ARGS);
    SBP_REQ(sbp_report_is_zero(&r));
    memset(&r, 0xFF, sizeof(r));
    SBP_REQ(source_bundle_publish("w", "", NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_ARGS);
    SBP_REQ(sbp_report_is_zero(&r));
    SBP_REQ(source_bundle_publish(NULL, "d", NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_ARGS);
    SBP_REQ(source_bundle_publish("w", NULL, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_ARGS);

    memset(&r, 0xFF, sizeof(r));
    SBP_REQ(source_bundle_publish("w", "d", NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_NO_SERVICE);
    SBP_REQ(sbp_report_is_zero(&r));
    rom_seed_set_enabled(false);
    SBP_REQ(source_bundle_publish("w", "d", NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_SEEDING_OFF);
    rom_seed_set_enabled(true);
    return true;
}

static int test_publish_argument_contract(void)
{
    int failures = 0;
    TEST("source_bundle_publish: null report, empty and one-character "
         "arguments, and a refusal that leaves the report zeroed") {
        sbp_open_caps();
        bool ok = sbp_args_contract();
        sbp_open_caps();
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

static bool sbp_refuse_missing_workspace(const struct sbp_fx *fx)
{
    char gone[PATH_MAX + 16];
    snprintf(gone, sizeof(gone), "%s/absent", fx->wdir);
    struct source_bundle_publish_report r;
    SBP_REQ(source_bundle_publish(gone, fx->adir, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_WORKSPACE);
    SBP_REQ(rom_seed_count() == 0);
    return true;
}

/* A pin that differs from the captured root only in its LAST byte is still a
 * different root. */
static bool sbp_refuse_pin_last_byte(const struct sbp_fx *fx)
{
    uint8_t root[32], pin[32];
    SBP_REQ(vcs_tree_capture_path(fx->wdir, root) == VCS_OK);
    memcpy(pin, root, 32);
    pin[31] ^= 0x01u;
    struct source_bundle_publish_report r;
    SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, pin, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_ROOT_PIN);
    SBP_REQ(rom_seed_count() == 0);
    SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, root, &r) ==
            SOURCE_BUNDLE_PUBLISH_OK);
    return true;
}

/* Different, non-empty bytes already sitting at the content address are
 * preserved, not replaced. */
static bool sbp_refuse_foreign_bytes(const struct sbp_fx *fx)
{
    uint8_t root[32];
    char seed_dir[1200], leaf[96], path[1400];
    SBP_REQ(sbp_address(fx, root, seed_dir, leaf));
    snprintf(path, sizeof(path), "%s/%s", seed_dir, leaf);
    SBP_REQ(sbp_write(seed_dir, leaf, "garbage", 7));
    struct source_bundle_publish_report r;
    SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_STORE);
    size_t len = 0;
    uint8_t *kept = sbp_slurp(path, &len);
    bool same = kept && len == 7 && memcmp(kept, "garbage", 7) == 0;
    free(kept);
    SBP_REQ(same);
    SBP_REQ(rom_seed_count() == 0);
    return true;
}

/* A datadir that cannot hold a bundles/ directory (it is a file) is a store
 * failure. */
static bool sbp_refuse_datadir_is_file(const struct sbp_fx *fx)
{
    char file[PATH_MAX + 16];
    snprintf(file, sizeof(file), "%s/not-a-dir", fx->adir);
    SBP_REQ(sbp_write(fx->adir, "not-a-dir", "x", 1));
    struct source_bundle_publish_report r;
    SBP_REQ(source_bundle_publish(fx->wdir, file, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_STORE);
    SBP_REQ(rom_seed_count() == 0);
    return true;
}

/* A staging path that cannot be opened is a store failure that leaves nothing
 * under the final name, and the same publish works once it is cleared. */
static bool sbp_refuse_staging_blocked(const struct sbp_fx *fx)
{
    uint8_t root[32];
    char seed_dir[1200], leaf[96], path[1400], block[1500];
    SBP_REQ(sbp_address(fx, root, seed_dir, leaf));
    snprintf(path, sizeof(path), "%s/%s", seed_dir, leaf);
    snprintf(block, sizeof(block), "%s/%s.part", seed_dir, leaf);
    SBP_REQ(mkdir(block, 0700) == 0);
    struct source_bundle_publish_report r;
    SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_STORE);
    SBP_REQ(access(path, F_OK) != 0);
    SBP_REQ(rom_seed_count() == 0);
    sbp_rm_tree(block, 2);
    SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_OK);
    return true;
}

static int test_publish_refusal_paths(void)
{
    int failures = 0;
    TEST("source_bundle_publish: missing workspace, last-byte pin, foreign "
         "bytes, file-as-datadir and blocked staging are each refused with "
         "their own code and offer nothing") {
        struct sbp_fx fx;
        bool ok = sbp_fx_open(&fx, "refuse", 'A');
        ok = ok && sbp_refuse_missing_workspace(&fx);
        ok = ok && sbp_refuse_pin_last_byte(&fx);
        sbp_fx_close(&fx);
        ok = ok && sbp_fx_open(&fx, "refuse2", 'A');
        ok = ok && sbp_refuse_foreign_bytes(&fx);
        ok = ok && sbp_refuse_datadir_is_file(&fx);
        sbp_fx_close(&fx);
        ok = ok && sbp_fx_open(&fx, "refuse3", 'A');
        ok = ok && sbp_refuse_staging_blocked(&fx);
        sbp_fx_close(&fx);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* A full registry is its own refusal, not a generic registration failure. */
static bool sbp_registry_full(const struct sbp_fx *fx)
{
    struct source_bundle_publish_report r;
    for (unsigned i = 0; i < ROM_SEED_MAX_ARTIFACTS; i++) {
        SBP_REQ(sbp_make_tree(fx->wdir, (char)('B' + (int)i)));
        SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, NULL, &r) ==
                SOURCE_BUNDLE_PUBLISH_OK);
    }
    SBP_REQ(rom_seed_count() == (int)ROM_SEED_MAX_ARTIFACTS);
    SBP_REQ(sbp_make_tree(fx->wdir, 'Z'));
    SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_ERR_REGISTRY_FULL);
    SBP_REQ(rom_seed_count() == (int)ROM_SEED_MAX_ARTIFACTS);
    return true;
}

static int test_publish_registry_full(void)
{
    int failures = 0;
    TEST("source_bundle_publish: the ninth bundle is refused as registry-full") {
        struct sbp_fx fx;
        bool ok = sbp_fx_open(&fx, "full", 'A');
        ok = ok && sbp_registry_full(&fx);
        sbp_fx_close(&fx);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* The price-0 offer reaches the market with the dialable port, and the report
 * names the file it wrote. */
static bool sbp_announces_to_market(const struct sbp_fx *fx)
{
    SBP_REQ(sbp_make_tree(fx->wdir, 'Q'));
    struct source_bundle_publish_report r;
    struct file_offer offer;
    uint8_t root[32];
    char seed_dir[1200], leaf[96], want[160];
    SBP_REQ(sbp_address(fx, root, seed_dir, leaf));
    SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_OK);
    SBP_REQ(file_market_find_offer(r.artifact_root, &offer));
    SBP_REQ(offer.peer_port == r.file_service_port && offer.price_per_mb == 0 &&
            offer.num_chunks == r.num_chunks && offer.size_bytes == r.wire_bytes);
    snprintf(want, sizeof(want), "%s/%s", ROM_SEED_BUNDLES_SUBDIR, leaf);
    SBP_REQ(strcmp(r.filename, want) == 0);
    SBP_REQ(memcmp(r.source_root, root, 32) == 0);
    /* The bounded walk counts "." and ".." like the seeder's own sweep. */
    SBP_REQ(r.seed_directory_entries ==
            (unsigned)sbp_count_entries(seed_dir) + SBP_DOT_ENTRIES);
    SBP_REQ(r.entries_beyond_cap == 0 && r.rescan_guaranteed);
    return true;
}

static int test_publish_announces_to_market(void)
{
    int failures = 0;
    TEST("source_bundle_publish: a published bundle is announced to the "
         "market and counted exactly in the report") {
        struct sbp_fx fx;
        bool ok = sbp_fx_open(&fx, "market", 'A');
        ok = ok && sbp_announces_to_market(&fx);
        sbp_fx_close(&fx);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

/* Add non-artifact files to `dir` until it holds exactly `target` entries. */
static bool sbp_pad_to(const char *dir, int target, const char *prefix)
{
    int count = sbp_count_entries(dir);
    while (count >= 0 && count < target) {
        char name[64];
        snprintf(name, sizeof(name), "%s-%06d.bin", prefix, count);
        if (!sbp_write(dir, name, "x", 1))
            return false;
        count++;
    }
    return count == target;
}

/* One directory holding exactly ROM_SEED_SCAN_ENTRY_CAP entries is still
 * fully walked; one more is not. `seed_side` picks bundles/ or the root. */
static bool sbp_entry_cap_edge(const struct sbp_fx *fx, bool seed_side)
{
    struct source_bundle_publish_report r;
    char seed_dir[1200];
    SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_OK);
    snprintf(seed_dir, sizeof(seed_dir), "%s/%s", fx->adir,
             ROM_SEED_BUNDLES_SUBDIR);
    const char *dir = seed_side ? seed_dir : fx->adir;
    /* The walk counts "." and ".." too, so a directory the walk sees as
     * exactly ROM_SEED_SCAN_ENTRY_CAP entries holds two fewer real ones. */
    const int cap = (int)ROM_SEED_SCAN_ENTRY_CAP - (int)SBP_DOT_ENTRIES;

    SBP_REQ(sbp_pad_to(dir, cap, "edge"));
    SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_OK);
    SBP_REQ(r.republished && r.rescan_guaranteed);
    SBP_REQ(r.entries_beyond_cap == 0);
    if (seed_side)
        SBP_REQ(r.seed_directory_entries == ROM_SEED_SCAN_ENTRY_CAP);

    SBP_REQ(sbp_pad_to(dir, cap + 1, "edge"));
    SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, NULL, &r) ==
            SOURCE_BUNDLE_PUBLISH_OK);
    SBP_REQ(!r.rescan_guaranteed);
    SBP_REQ(r.entries_beyond_cap == 0);
    return true;
}

/* A header seed plus seven bundles fill the eight registry slots exactly, so
 * the promise is still keepable; only non-artifact padding adds nothing. */
static bool sbp_artifact_cap_edge(const struct sbp_fx *fx)
{
    uint8_t seed_bytes[ROM_SEED_MIN_ARTIFACT_BYTES];
    memset(seed_bytes, 0, sizeof(seed_bytes));
    SBP_REQ(sbp_write(fx->adir, "block_index.bin", seed_bytes,
                      sizeof(seed_bytes)));
    struct source_bundle_publish_report r;
    memset(&r, 0, sizeof(r));
    for (unsigned i = 0; i + 1u < ROM_SEED_MAX_ARTIFACTS; i++) {
        SBP_REQ(sbp_make_tree(fx->wdir, (char)('B' + (int)i)));
        SBP_REQ(source_bundle_publish(fx->wdir, fx->adir, NULL, &r) ==
                SOURCE_BUNDLE_PUBLISH_OK);
    }
    SBP_REQ(r.rescan_guaranteed);
    SBP_REQ(r.entries_beyond_cap == 0);
    return true;
}

static int test_publish_sweep_boundaries(void)
{
    int failures = 0;
    TEST("source_bundle_publish: the rescan promise holds at exactly the "
         "entry cap in either directory and at exactly eight artifacts, and "
         "breaks one past") {
        struct sbp_fx fx;
        bool ok = sbp_fx_open(&fx, "edge_seed", 'A');
        ok = ok && sbp_entry_cap_edge(&fx, true);
        sbp_fx_close(&fx);
        ok = ok && sbp_fx_open(&fx, "edge_root", 'A');
        ok = ok && sbp_entry_cap_edge(&fx, false);
        sbp_fx_close(&fx);
        ok = ok && sbp_fx_open(&fx, "edge_art", 'A');
        ok = ok && sbp_artifact_cap_edge(&fx);
        sbp_fx_close(&fx);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

int test_source_bundle_publish(void)
{
    int failures = 0;
    failures += test_publish_result_strings();
    failures += test_publish_argument_contract();
    failures += test_publish_refusal_paths();
    failures += test_publish_registry_full();
    failures += test_publish_announces_to_market();
    failures += test_publish_sweep_boundaries();
#if !defined(_WIN32)
    failures += test_rm_tree_does_not_follow_symlink();
    failures += test_rm_tree_trailing_separator_keeps_target();
#endif
    failures += test_malformed_published_reply();
    failures += test_publish_then_fetch_elsewhere();
    failures += test_republish_is_idempotent();
    failures += test_malformed_existing_bundle_is_preserved();
    failures += test_root_pin_refuses();
    failures += test_immune_to_scan_cap();
    failures += test_unservable_is_refused();
    failures += test_leaf_through_rpc();
    failures += test_registry_cap_breaks_rescan_promise();
    return failures;
}
