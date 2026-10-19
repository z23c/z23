/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Verify inert plugin distribution through two real content stores. Peer
 * handles are fixture inputs; this is not network-authentication evidence. */
#include "test/test_core.h"
#include "test/test_zcode_swarm_priv.h"
#include "test/public_shape_fixture.h"
#include "plugin/plugin_pack.h"
#include "plugin/plugin_store.h"
#include "plugin/plugin_run.h"
#include "vcs/package_checkout.h"
#include "vcs/package_public_shape.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#define PP_CAP (4u * VCS_PACKAGE_CHUNK_BYTES)

struct pp_fixture {
    struct sw_node publisher, receiver;
    char base[1024], source[1200], signing[1200], executable[1200];
    char plugins[1200], checkout[1200], manifest[1400], current[1400];
    struct plugin_pack_result packed;
    uint8_t root[32];
    unsigned capabilities;
};

static bool pp_path(char *out, size_t cap, const char *base, const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", base, leaf);
    return n > 0 && (size_t)n < cap;
}

static bool pp_write(const char *path, const char *bytes, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(bytes, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

static bool pp_keys(const char *directory, const char *key)
{
    char path[1400], line[66];
    int n = snprintf(line, sizeof(line), "%s\n", key);
    return n == 65 && pp_path(path, sizeof(path), directory, "publisher_keys") &&
           pp_write(path, line, (size_t)n) && chmod(path, 0600) == 0;
}

static bool pp_open(struct pp_fixture *f)
{
    char public_key[65];
    return test_mkdtemp(f->base, sizeof(f->base), "plugin_package") &&
        pp_path(f->source, sizeof(f->source), f->base, "packed") &&
        pp_path(f->signing, sizeof(f->signing), f->base, "publisher-signing") &&
        pp_path(f->executable, sizeof(f->executable), f->base, "inert-image") &&
        pp_path(f->plugins, sizeof(f->plugins), f->base, "receiver-plugins") &&
        mkdir(f->plugins, 0700) == 0 &&
        pp_path(f->current, sizeof(f->current), f->plugins, "demo/current") &&
        pp_write(f->executable, "inert plugin image\n", 19) &&
        plugin_keygen(f->signing, public_key) == PLUGIN_OK &&
        sw_node_open(&f->publisher, "plugin-package-publisher", sw_score_contributor) &&
        sw_node_open(&f->receiver, "plugin-package-receiver", sw_score_contributor);
}

static void pp_close(struct pp_fixture *f)
{
    sw_node_close(&f->receiver);
    sw_node_close(&f->publisher);
    if (f->receiver.datadir[0])
        (void)test_rm_rf_recursive(f->receiver.datadir);
    if (f->publisher.datadir[0])
        (void)test_rm_rf_recursive(f->publisher.datadir);
    if (f->base[0])
        (void)test_rm_rf_recursive(f->base);
}

static bool pp_add_file(struct vcs_package_manifest *m, const char *directory,
                        const char *leaf, uint8_t **bytes, size_t *length)
{
    char path[1400];
    if (!pp_path(path, sizeof(path), directory, leaf))
        return false;
    FILE *file = fopen(path, "rb");
    if (!file)
        return false;
    *bytes = malloc(PP_CAP);
    if (!*bytes) {
        (void)fclose(file);
        return false;
    }
    *length = fread(*bytes, 1, PP_CAP, file);
    bool ok = !ferror(file) && *length > 0 && *length < PP_CAP;
    ok = fclose(file) == 0 && ok;
    uint8_t digests[4 * 32];
    uint32_t chunks = (uint32_t)((*length + VCS_PACKAGE_CHUNK_BYTES - 1) /
                                  VCS_PACKAGE_CHUNK_BYTES);
    for (uint32_t i = 0; i < chunks && ok; i++) {
        size_t offset = (size_t)i * VCS_PACKAGE_CHUNK_BYTES;
        size_t chunk_length = *length - offset;
        if (chunk_length > VCS_PACKAGE_CHUNK_BYTES)
            chunk_length = VCS_PACKAGE_CHUNK_BYTES;
        ok = vcs_package_chunk_hash(*bytes + offset, chunk_length, digests + i * 32);
    }
    uint32_t mode = strcmp(leaf, "demo") == 0
        ? VCS_PACKAGE_MODE_EXECUTABLE : VCS_PACKAGE_MODE_FILE;
    return ok && vcs_package_manifest_add(m, leaf, mode, *length, digests, chunks);
}

static bool pp_store_file_chunks(struct pp_fixture *f, const char *leaf,
                                 const uint8_t *bytes, size_t length)
{
    for (size_t offset = 0; offset < length; offset += VCS_PACKAGE_CHUNK_BYTES) {
        size_t chunk_length = length - offset;
        if (chunk_length > VCS_PACKAGE_CHUNK_BYTES)
            chunk_length = VCS_PACKAGE_CHUNK_BYTES;
        if (vcs_package_store_put_chunk(f->publisher.store, f->root, leaf,
                (uint32_t)(offset / VCS_PACKAGE_CHUNK_BYTES), bytes + offset,
                chunk_length) != VCS_PACKAGE_STORE_OK)
            return false;
    }
    return true;
}

static const char *const pp_versions[] = {"1.0.0", "2.0.0", "3.0.0"};
static const char *const pp_releases[] = {"one/plugin", "two/plugin", "three/plugin"};

static bool pp_publish(struct pp_fixture *f, unsigned version)
{
    struct plugin_pack_request request = {
        .exe_path = f->executable, .name = "demo",
        .version = pp_versions[version - 1],
        .key_path = f->signing, .out_dir = f->source,
        .capabilities = f->capabilities
    };
    if (plugin_pack(&request, &f->packed) != PLUGIN_OK)
        return false;
    char license[1400];
    if (!pp_path(license, sizeof(license), f->source, "LICENSE") ||
        !pp_write(license, TEST_LICENSE_TEXT_MIT, strlen(TEST_LICENSE_TEXT_MIT)))
        return false;
    static const char *const leaves[] = {
        "LICENSE", "demo", "demo.plugin.json", "demo.plugin.sig"
    };
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    uint8_t *bytes[4] = {0};
    size_t lengths[4] = {0};
    bool ok = true;
    for (size_t i = 0; i < 4 && ok; i++)
        ok = pp_add_file(&manifest, f->source, leaves[i], &bytes[i], &lengths[i]);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ok = ok && vcs_package_manifest_serialize(&manifest, &wire, &wire_len) &&
        vcs_package_store_put_manifest(f->publisher.store, wire, wire_len,
                                        f->root) == VCS_PACKAGE_STORE_OK;
    for (size_t i = 0; i < 4 && ok; i++)
        ok = pp_store_file_chunks(f, leaves[i], bytes[i], lengths[i]);
    for (size_t i = 0; i < 4; i++) free(bytes[i]);
    free(wire);
    vcs_package_manifest_free(&manifest);
    return ok && sw_publish_release(f->publisher.store, f->root,
                                     (uint8_t)(90 + version), pp_releases[version - 1]);
}

static bool pp_exchange(struct pp_fixture *f, uint64_t now)
{
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    uint64_t target = 0;
    size_t length = 0;
    unsigned frames = 0;
    while (vcs_swarm_engine_next_outbound(f->receiver.engine, 11, &target,
                                          frame, &length)) {
        if (++frames > 64)
            return false;
        struct vcs_swarm_frame_result served = vcs_swarm_engine_handle_frame(
            f->publisher.engine, 13, frame, length, SW_DAY, now);
        if (served.reply && served.reply_len) {
            struct vcs_swarm_frame_result received = vcs_swarm_engine_handle_frame(
                f->receiver.engine, 11, served.reply, served.reply_len, SW_DAY, now);
            free(received.reply);
        }
        free(served.reply);
    }
    return true;
}

static bool pp_fetch(struct pp_fixture *f)
{
    uint8_t publisher_key[33], receiver_key[33];
    sw_key(81, publisher_key);
    sw_key(82, receiver_key);
    if (!vcs_swarm_engine_peer_add(f->receiver.engine, 11, publisher_key) ||
        !vcs_swarm_engine_peer_add(f->publisher.engine, 13, receiver_key))
        return false;
    const uint64_t provider = 11;
    if (vcs_swarm_engine_fetch_from_bounded(f->receiver.engine, f->root,
            SW_DAY, 1, &provider, 1, 4u * PP_CAP) != VCS_SWARM_FETCH_OK)
        return false;
    for (uint64_t now = 2; now < 34; now++) {
        vcs_swarm_engine_tick(f->receiver.engine, SW_DAY, now);
        if (!pp_exchange(f, now))
            return false;
        struct vcs_swarm_download_status status;
        if (vcs_swarm_engine_download_status(f->receiver.engine, f->root, &status) &&
            status.state == VCS_SWARM_DL_COMPLETE)
            return status.fetched_bytes > 0;
    }
    return false;
}

static bool pp_selection(const struct pp_fixture *f, const char *generation)
{
    char target[160];
    errno = 0;
    ssize_t n = readlink(f->current, target, sizeof(target));
    if (!generation)
        return n < 0 && errno == ENOENT;
    return n == 12 + PLUGIN_HEX_SHA3_512 &&
        memcmp(target, "generations/", 12) == 0 &&
        memcmp(target + 12, generation, PLUGIN_HEX_SHA3_512) == 0;
}

static int pp_round(struct pp_fixture *f, unsigned version, char first[129])
{
    int failures = 0;
    TEST("plugin package: real transfer, local publisher key, inert install") {
        ASSERT(pp_publish(f, version));
        struct vcs_package_public_verdict public_shape;
        vcs_package_public_shape_classify(f->publisher.store, f->root, &public_shape);
        ASSERT(public_shape.shape != VCS_PACKAGE_PUBLIC_REFUSED);
        ASSERT(pp_fetch(f));
        ASSERT(pp_path(f->checkout, sizeof(f->checkout), f->base,
                        version == 1 ? "received-one" : "received-two"));
        struct vcs_package_checkout_metrics metrics;
        ASSERT_EQ(vcs_package_checkout(f->receiver.store, f->root,
                                        f->checkout, &metrics), VCS_PACKAGE_CHECKOUT_OK);
        ASSERT_EQ(metrics.files, 4u);
        ASSERT_EQ(vcs_package_checkout(f->receiver.store, f->root,
                        f->checkout, &metrics), VCS_PACKAGE_CHECKOUT_DESTINATION);
        ASSERT(pp_path(f->manifest, sizeof(f->manifest), f->checkout, "demo.plugin.json"));
        struct plugin_manifest installed;
        int present = -1;
        if (version == 1) {
            ASSERT(pp_keys(f->source, f->packed.public_key));
            ASSERT_EQ(plugin_store_install(f->plugins, f->manifest, &installed,
                                           &present), PLUGIN_ERR_NO_KEYS);
            ASSERT(pp_selection(f, NULL));
            ASSERT(pp_keys(f->plugins, f->packed.public_key));
        }
        ASSERT_EQ(plugin_store_install(f->plugins, f->manifest, &installed,
                                       &present), PLUGIN_OK);
        ASSERT_EQ(present, 0);
        ASSERT(strcmp(installed.generation, f->packed.generation) == 0);
        char exe[1400], digest[129];
        ASSERT(pp_path(exe, sizeof(exe), f->checkout, "demo"));
        ASSERT_EQ(plugin_hash_file(exe, digest), PLUGIN_OK);
        ASSERT(strcmp(installed.exe_sha3, digest) == 0);
        ASSERT(pp_selection(f, version == 1 ? NULL : first));
        ASSERT_EQ(plugin_store_install(f->plugins, f->manifest, &installed,
                                       &present), PLUGIN_OK);
        ASSERT_EQ(present, 1);
        ASSERT(pp_selection(f, version == 1 ? NULL : first));
        if (version == 1) {
            memcpy(first, installed.generation, 129);
            ASSERT_EQ(plugin_store_switch(f->plugins, "demo", first), PLUGIN_OK);
            ASSERT(pp_selection(f, first));
        }
        ASSERT(pp_write(exe, "changed", 7));
        ASSERT_EQ(plugin_store_install(f->plugins, f->manifest, &installed,
                                       &present), PLUGIN_ERR_EXE_HASH);
        ASSERT(pp_selection(f, first));
        PASS();
    } _test_next:;
    return failures;
}

#if defined(__linux__)
/* Patch the existing protocol-speaking executable, retaining a bounded trailing
 * pad so this journey exercises more than one canonical package chunk. */
static bool pp_runtime_image(struct pp_fixture *f, const char *mode)
{
    if (!mode || strlen(mode) > 16) return false;
    FILE *image = fopen("build/fixtures/plugin_run_child", "rb");
    if (!image) return false;
    uint8_t *bytes = calloc(1, PP_CAP);
    if (!bytes) {
        (void)fclose(image);
        return false;
    }
    size_t length = fread(bytes, 1, PP_CAP, image);
    bool ok = !ferror(image) && length > 0 && length < PP_CAP;
    ok = fclose(image) == 0 && ok;
    static const char marker[] = "PRC-VARIANT:";
    bool patched = false;
    for (size_t i = 0; ok && i + sizeof(marker) - 1 + 16 <= length; i++) {
        if (memcmp(bytes + i, marker, sizeof(marker) - 1) == 0) {
            uint8_t *field = bytes + i + sizeof(marker) - 1;
            memset(field, ' ', 16);
            memcpy(field, mode, strlen(mode));
            patched = true;
            break;
        }
    }
    if (length <= VCS_PACKAGE_CHUNK_BYTES) length = VCS_PACKAGE_CHUNK_BYTES + 1;
    ok = ok && patched && pp_write(f->executable, (const char *)bytes, length);
    free(bytes);
    return ok;
}

static bool pp_runtime_verify_executable(const struct pp_fixture *f,
                                         const struct plugin_manifest *installed)
{
    char exe[1400], digest[129];
    struct stat image_stat;
    return pp_path(exe, sizeof(exe), f->checkout, "demo") &&
        stat(exe, &image_stat) == 0 && S_ISREG(image_stat.st_mode) &&
        (image_stat.st_mode & 0111) != 0 &&
        image_stat.st_size > VCS_PACKAGE_CHUNK_BYTES &&
        plugin_hash_file(exe, digest) == PLUGIN_OK &&
        strcmp(installed->exe_sha3, digest) == 0;
}

static bool pp_runtime_receive(struct pp_fixture *f, unsigned version,
                               char generation[129])
{
    if (!pp_publish(f, version) || !pp_fetch(f) ||
        !pp_path(f->checkout, sizeof(f->checkout), f->base,
                 version == 1 ? "runtime-good" : "runtime-bad"))
        return false;
    struct vcs_package_checkout_metrics metrics;
    if (vcs_package_checkout(f->receiver.store, f->root, f->checkout, &metrics) !=
            VCS_PACKAGE_CHECKOUT_OK || metrics.files != 4 ||
        !pp_path(f->manifest, sizeof(f->manifest), f->checkout, "demo.plugin.json") ||
        !pp_keys(f->plugins, f->packed.public_key))
        return false;
    struct plugin_manifest installed;
    int present = -1;
    if (plugin_store_install(f->plugins, f->manifest, &installed, &present) != PLUGIN_OK ||
        present != 0 || strcmp(installed.generation, f->packed.generation) != 0)
        return false;
    if (!pp_runtime_verify_executable(f, &installed))
        return false;
    memcpy(generation, installed.generation, 129);
    return true;
}

static bool pp_runtime_healthy(struct plugin_run *run, const char *generation,
                               bool fallback)
{
    struct timespec start;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return false;
    for (;;) {
        if (plugin_run_poll(run) != PLUGIN_RUN_OK) return false;
        struct plugin_run_info info;
        plugin_run_info_get(run, &info);
        if (info.state == PLUGIN_RUN_STATE_RUNNING && info.pings_ok > 0 &&
            info.fell_back == fallback && strcmp(info.generation, generation) == 0)
            return true;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
            now.tv_sec - start.tv_sec >= 20)
            return false;
        struct timespec tick = {.tv_nsec = 5000000L};
        (void)nanosleep(&tick, NULL);
    }
}

static int pp_runtime_journey(void)
{
    int failures = 0;
    struct pp_fixture f = {0};
    struct plugin_run *run = NULL;
    bool ready = pp_open(&f);
    TEST("plugin package: received executable runs healthy and automatically restores healthy last-good") {
        char good[129], bad[129], last_good[1400], target[160];
        ASSERT(ready);
        ASSERT(plugin_capability_add("fs.write", 8, &f.capabilities));
        ASSERT(plugin_capability_add("clock", 5, &f.capabilities));
        ASSERT(pp_runtime_image(&f, "normal"));
        ASSERT(pp_runtime_receive(&f, 1, good));
        ASSERT(pp_selection(&f, NULL));
        ASSERT_EQ(plugin_store_switch(f.plugins, "demo", good), PLUGIN_OK);
        struct plugin_run_options options = {
            .root = f.plugins, .name = "demo", .ping_interval_ms = 40,
            .ping_deadline_ms = 500, .ping_miss_limit = 2,
            .backoff_initial_ms = 20, .backoff_max_ms = 2000,
            .stable_ms = 60000, .crash_limit = 3
        };
        ASSERT_EQ(plugin_run_open(&options, &run, NULL), PLUGIN_RUN_OK);
        ASSERT(pp_runtime_healthy(run, good, false));
        plugin_run_close(run);
        run = NULL;
        ASSERT(pp_runtime_image(&f, "crash"));
        ASSERT(pp_runtime_receive(&f, 2, bad));
        ASSERT(strcmp(good, bad) != 0);
        ASSERT(pp_selection(&f, good));
        ASSERT_EQ(plugin_store_switch(f.plugins, "demo", bad), PLUGIN_OK);
        ASSERT(pp_selection(&f, bad));
        ASSERT(pp_path(last_good, sizeof(last_good), f.plugins, "demo/last-good"));
        ssize_t n = readlink(last_good, target, sizeof(target));
        ASSERT_EQ(n, 12 + PLUGIN_HEX_SHA3_512);
        ASSERT(memcmp(target, "generations/", 12) == 0);
        ASSERT(memcmp(target + 12, good, PLUGIN_HEX_SHA3_512) == 0);
        ASSERT_EQ(plugin_run_open(&options, &run, NULL), PLUGIN_RUN_OK);
        ASSERT(pp_runtime_healthy(run, good, true));
        ASSERT(pp_selection(&f, good));
        PASS();
    } _test_next:;
    plugin_run_close(run);
    pp_close(&f);
    return failures;
}
#endif


/* ── refusal cases: wrong pin, corrupt transit, altered stored generation ── */

static bool pp_read_link(const struct pp_fixture *f, const char *leaf,
                         char target[160])
{
    char dir[1500], path[1500];
    if (!pp_path(dir, sizeof(dir), f->plugins, "demo") ||
        !pp_path(path, sizeof(path), dir, leaf))
        return false;
    ssize_t n = readlink(path, target, 159);
    if (n < 0)
        return false;
    target[n] = '\0';
    return true;
}

static int pp_generation_entries(const struct pp_fixture *f)
{
    char dir[1500];
    if (!pp_path(dir, sizeof(dir), f->plugins, "demo/generations"))
        return -1;
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    int count = 0;
    for (struct dirent *e = readdir(d); e; e = readdir(d))
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
            count++;
    (void)closedir(d);
    return count;
}

static bool pp_generation_absent(const struct pp_fixture *f, const char *generation)
{
    char path[1700], leaf[200];
    struct stat st;
    return snprintf(leaf, sizeof(leaf), "demo/generations/%s", generation) > 0 &&
        pp_path(path, sizeof(path), f->plugins, leaf) &&
        lstat(path, &st) != 0 && errno == ENOENT;
}

/* Receive version 1 then 2 over the swarm and install both under the pinned
 * publisher key: current names the second generation, last-good the first. */
static bool pp_stage_two(struct pp_fixture *f, char first[129], char second[129])
{
    for (unsigned version = 1; version <= 2; version++) {
        if (!pp_publish(f, version) || !pp_fetch(f) ||
            !pp_keys(f->plugins, f->packed.public_key) ||
            !pp_path(f->checkout, sizeof(f->checkout), f->base,
                     version == 1 ? "stage-one" : "stage-two"))
            return false;
        struct vcs_package_checkout_metrics metrics;
        struct plugin_manifest installed;
        int present = -1;
        if (vcs_package_checkout(f->receiver.store, f->root, f->checkout,
                                 &metrics) != VCS_PACKAGE_CHECKOUT_OK ||
            !pp_path(f->manifest, sizeof(f->manifest), f->checkout,
                     "demo.plugin.json") ||
            plugin_store_install(f->plugins, f->manifest, &installed, &present) !=
                PLUGIN_OK ||
            plugin_store_switch(f->plugins, "demo", installed.generation) != PLUGIN_OK)
            return false;
        memcpy(version == 1 ? first : second, installed.generation, 129);
    }
    return true;
}

static int pp_refusal_wrong_pin(void)
{
    int failures = 0;
    struct pp_fixture f = {0};
    bool ready = pp_open(&f);
    TEST("plugin package: valid signature by an unpinned key refuses and keeps state") {
        char first[129], second[129], cur[160], lg[160], cur2[160], lg2[160];
        char other_key[1400], other_out[1400], other_pub[65];
        ASSERT(ready);
        ASSERT(pp_stage_two(&f, first, second));
        ASSERT(pp_read_link(&f, "current", cur) && pp_read_link(&f, "last-good", lg));
        ASSERT(strcmp(cur + 12, second) == 0 && strcmp(lg + 12, first) == 0);
        int before = pp_generation_entries(&f);
        ASSERT_EQ(before, 2);
        /* The signer is a second, genuine key; the receiver still pins only the first. */
        ASSERT(pp_path(other_key, sizeof(other_key), f.base, "other-signing"));
        ASSERT(pp_path(other_out, sizeof(other_out), f.base, "other-packed"));
        ASSERT_EQ(plugin_keygen(other_key, other_pub), PLUGIN_OK);
        ASSERT(strcmp(other_pub, f.packed.public_key) != 0);
        struct plugin_pack_request request = {
            .exe_path = f.executable, .name = "demo", .version = "9.0.0",
            .key_path = other_key, .out_dir = other_out
        };
        struct plugin_pack_result other;
        ASSERT_EQ(plugin_pack(&request, &other), PLUGIN_OK);
        struct plugin_manifest installed;
        int present = -1;
        ASSERT_EQ(plugin_store_install(f.plugins, other.manifest_path, &installed,
                                       &present), PLUGIN_ERR_KEY_UNKNOWN);
        ASSERT_EQ(pp_generation_entries(&f), before);
        ASSERT(pp_generation_absent(&f, other.generation));
        ASSERT(pp_read_link(&f, "current", cur2) && pp_read_link(&f, "last-good", lg2));
        ASSERT(strcmp(cur, cur2) == 0 && strcmp(lg, lg2) == 0);
        PASS();
    } _test_next:;
    pp_close(&f);
    return failures;
}

/* Flip one byte of the CAS object holding the bytes whose chunk hash is given;
 * the original is kept so the caller can put it back. */
static bool pp_cas_object(const struct sw_node *node, const uint8_t *bytes,
                          size_t length, char path[1500])
{
    uint8_t digest[32];
    char hex[65];
    if (!vcs_package_chunk_hash(bytes, length, digest))
        return false;
    for (size_t i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", digest[i]);
    int n = snprintf(path, 1500, "%s/cas/sha3/%.2s/%s", node->zcode_dir, hex, hex);
    return n > 0 && n < 1500;
}

static bool pp_cas_swap(const char *path, uint8_t *saved, size_t length, bool corrupt)
{
    uint8_t bytes[64];
    if (length > sizeof(bytes))
        return false;
    if (!corrupt) {
        /* The store may have discarded the bad object; recreate it from the saved bytes. */
        (void)chmod(path, 0644);
        return pp_write(path, (const char *)saved, length);
    }
    FILE *file = fopen(path, "rb");
    if (!file)
        return false;
    bool ok = fread(saved, 1, length, file) == length;
    ok = fclose(file) == 0 && ok;
    memcpy(bytes, saved, length);
    bytes[0] ^= 0x01;
    (void)chmod(path, 0644);
    return ok && pp_write(path, (const char *)bytes, length);
}

/* A second download of the same root after the first stalled. Peers are
 * already registered; this only reissues the fetch and drives ticks. */
static bool pp_fetch_again(struct pp_fixture *f, uint64_t first_tick)
{
    const uint64_t provider = 11;
    (void)vcs_swarm_engine_cancel(f->receiver.engine, f->root, first_tick);
    if (vcs_swarm_engine_fetch_from_bounded(f->receiver.engine, f->root,
            SW_DAY, first_tick, &provider, 1, 4u * PP_CAP) != VCS_SWARM_FETCH_OK)
        return false;
    for (uint64_t now = first_tick + 1; now < first_tick + 33; now++) {
        vcs_swarm_engine_tick(f->receiver.engine, SW_DAY, now);
        if (!pp_exchange(f, now))
            return false;
        struct vcs_swarm_download_status status;
        if (vcs_swarm_engine_download_status(f->receiver.engine, f->root, &status) &&
            status.state == VCS_SWARM_DL_COMPLETE)
            return true;
    }
    return false;
}

static int pp_refusal_transit(void)
{
    static const char image[] = "inert plugin image, transit variant\n";
    int failures = 0;
    struct pp_fixture f = {0};
    bool ready = pp_open(&f);
    TEST("plugin package: corrupt exe chunk is refused in transit and recovery installs") {
        char first[129], second[129], cur[160], lg[160], cur2[160], lg2[160];
        char publisher_cas[1500], receiver_cas[1500];
        uint8_t saved[64];
        ASSERT(ready);
        ASSERT(pp_stage_two(&f, first, second));
        ASSERT(pp_read_link(&f, "current", cur) && pp_read_link(&f, "last-good", lg));
        int before = pp_generation_entries(&f);
        ASSERT_EQ(before, 2);
        /* Version 3 carries an image no earlier version did, so its executable
         * chunk must cross the wire; flip one byte of it at the publisher. */
        ASSERT(pp_write(f.executable, image, sizeof(image) - 1));
        ASSERT(pp_publish(&f, 3));
        ASSERT(pp_cas_object(&f.publisher, (const uint8_t *)image, sizeof(image) - 1,
                             publisher_cas));
        ASSERT(pp_cas_object(&f.receiver, (const uint8_t *)image, sizeof(image) - 1,
                             receiver_cas));
        ASSERT(pp_cas_swap(publisher_cas, saved, sizeof(image) - 1, true));
        ASSERT(!pp_fetch_again(&f, 100));
        struct vcs_swarm_download_status status;
        ASSERT(!vcs_swarm_engine_download_status(f.receiver.engine, f.root, &status) ||
               status.state != VCS_SWARM_DL_COMPLETE);
        ASSERT(access(receiver_cas, F_OK) != 0 && errno == ENOENT);
        ASSERT(pp_path(f.checkout, sizeof(f.checkout), f.base, "transit-bad"));
        struct vcs_package_checkout_metrics metrics;
        ASSERT_EQ(vcs_package_checkout(f.receiver.store, f.root, f.checkout, &metrics),
                  VCS_PACKAGE_CHECKOUT_INCOMPLETE);
        ASSERT(access(f.checkout, F_OK) != 0 && errno == ENOENT);
        ASSERT_EQ(pp_generation_entries(&f), before);
        ASSERT(pp_read_link(&f, "current", cur2) && pp_read_link(&f, "last-good", lg2));
        ASSERT(strcmp(cur, cur2) == 0 && strcmp(lg, lg2) == 0);
        /* The correct bytes arrive: nothing from the refusal blocks recovery. */
        /* The publisher quarantined the bad object and reports the package
         * incomplete; supplying the correct chunk through its store completes it. */
        ASSERT_EQ(vcs_package_store_put_chunk(f.publisher.store, f.root, "demo", 0,
                      (const uint8_t *)image, sizeof(image) - 1), VCS_PACKAGE_STORE_OK);
        ASSERT(pp_fetch_again(&f, 200));
        ASSERT(pp_path(f.checkout, sizeof(f.checkout), f.base, "transit-good"));
        ASSERT_EQ(vcs_package_checkout(f.receiver.store, f.root, f.checkout, &metrics),
                  VCS_PACKAGE_CHECKOUT_OK);
        /* Receiver-side rot between fetch and checkout is refused the same way. */
        char rotten[1400];
        ASSERT(pp_cas_swap(receiver_cas, saved, sizeof(image) - 1, true));
        ASSERT(pp_path(rotten, sizeof(rotten), f.base, "transit-rotten"));
        ASSERT_EQ(vcs_package_checkout(f.receiver.store, f.root, rotten, &metrics),
                  VCS_PACKAGE_CHECKOUT_CHUNK);
        ASSERT(access(rotten, F_OK) != 0 && errno == ENOENT);
        /* Checkout quarantined the rotten object, so the package is incomplete
         * until the correct chunk is admitted again. */
        ASSERT_EQ(vcs_package_checkout(f.receiver.store, f.root, rotten, &metrics),
                  VCS_PACKAGE_CHECKOUT_INCOMPLETE);
        ASSERT(access(rotten, F_OK) != 0 && errno == ENOENT);
        ASSERT_EQ(vcs_package_store_put_chunk(f.receiver.store, f.root, "demo", 0,
                      (const uint8_t *)image, sizeof(image) - 1), VCS_PACKAGE_STORE_OK);
        ASSERT_EQ(vcs_package_checkout(f.receiver.store, f.root, rotten, &metrics),
                  VCS_PACKAGE_CHECKOUT_OK);
        ASSERT(pp_path(f.manifest, sizeof(f.manifest), rotten, "demo.plugin.json"));
        struct plugin_manifest installed;
        int present = -1;
        ASSERT_EQ(plugin_store_install(f.plugins, f.manifest, &installed, &present),
                  PLUGIN_OK);
        ASSERT_EQ(present, 0);
        ASSERT_EQ(pp_generation_entries(&f), before + 1);
        ASSERT(pp_read_link(&f, "current", cur2) && pp_read_link(&f, "last-good", lg2));
        ASSERT(strcmp(cur, cur2) == 0 && strcmp(lg, lg2) == 0);
        PASS();
    } _test_next:;
    pp_close(&f);
    return failures;
}

static int pp_refusal_switch(void)
{
    int failures = 0;
    struct pp_fixture f = {0};
    bool ready = pp_open(&f);
    TEST("plugin package: switch to an altered stored generation refuses and keeps state") {
        char first[129], second[129], cur[160], lg[160], cur2[160], lg2[160];
        char stored[1700], leaf[200];
        ASSERT(ready);
        ASSERT(pp_stage_two(&f, first, second));
        /* Install a third generation without selecting it, then alter its stored image. */
        ASSERT(pp_write(f.executable, "third plugin image\n", 19));
        ASSERT(pp_publish(&f, 3));
        struct plugin_manifest installed;
        int present = -1;
        ASSERT_EQ(plugin_store_install(f.plugins, f.packed.manifest_path, &installed,
                                       &present), PLUGIN_OK);
        ASSERT(pp_read_link(&f, "current", cur) && pp_read_link(&f, "last-good", lg));
        ASSERT(strcmp(cur + 12, second) == 0 && strcmp(lg + 12, first) == 0);
        ASSERT(snprintf(leaf, sizeof(leaf), "demo/generations/%s/demo",
                        installed.generation) > 0);
        ASSERT(pp_path(stored, sizeof(stored), f.plugins, leaf));
        ASSERT_EQ(chmod(stored, 0644), 0);
        ASSERT(pp_write(stored, "tampered after install", 22));
        ASSERT_EQ(plugin_store_switch(f.plugins, "demo", installed.generation),
                  PLUGIN_ERR_EXE_HASH);
        ASSERT(pp_read_link(&f, "current", cur2) && pp_read_link(&f, "last-good", lg2));
        ASSERT(strcmp(cur, cur2) == 0 && strcmp(lg, lg2) == 0);
        PASS();
    } _test_next:;
    pp_close(&f);
    return failures;
}

int test_plugin_package(void)
{
    struct pp_fixture fixture = {0};
    if (!pp_open(&fixture)) {
        fprintf(stderr, "plugin_package: fixture initialization failed\n");
        pp_close(&fixture);
        return 1;
    }
    char first[129] = {0};
    int failures = pp_round(&fixture, 1, first);
    if (!failures)
        failures += pp_round(&fixture, 2, first);
    pp_close(&fixture);
    failures += pp_refusal_wrong_pin();
    failures += pp_refusal_transit();
    failures += pp_refusal_switch();
#if defined(__linux__)
    failures += pp_runtime_journey();
#endif
    return failures;
}
