/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared fixture for the plugin distribution tests: two isolated
 *          swarm nodes, a packed demo plugin, a publish and a pumped transfer.
 *          Peer handles are fixture inputs; images are inert. */
#include "test/plugin_dist_fixture.h"

#include "test/public_shape_fixture.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool pd_path(char *out, size_t cap, const char *base, const char *leaf)
{
    int n = snprintf(out, cap, "%s/%s", base, leaf);
    return n > 0 && (size_t)n < cap;
}

bool pd_write(const char *path, const char *bytes, size_t len, mode_t mode)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(bytes, 1, len, f) == len;
    return fclose(f) == 0 && ok && chmod(path, mode) == 0;
}

bool pd_keys(const char *dir, const char *key)
{
    char path[1400], line[66];
    int n = snprintf(line, sizeof(line), "%s\n", key);
    return n == 65 && pd_path(path, sizeof(path), dir, "publisher_keys") &&
           pd_write(path, line, (size_t)n, 0600);
}

bool pd_open(struct pd_fixture *f)
{
    char seed[32];
    memset(seed, 0x61, sizeof(seed));
    f->ready = test_mkdtemp(f->base, sizeof(f->base), "plugin_dist") &&
        pd_path(f->signing, sizeof(f->signing), f->base, "publisher-signing") &&
        pd_path(f->release_key, sizeof(f->release_key), f->base, "release.key") &&
        pd_path(f->license, sizeof(f->license), f->base, "LICENSE") &&
        pd_path(f->plugins, sizeof(f->plugins), f->base, "receiver-plugins") &&
        pd_path(f->pub_plugins, sizeof(f->pub_plugins), f->base, "publisher-plugins") &&
        pd_path(f->scratch, sizeof(f->scratch), f->base, "scratch") &&
        mkdir(f->plugins, 0700) == 0 && mkdir(f->pub_plugins, 0700) == 0 &&
        mkdir(f->scratch, 0700) == 0 &&
        pd_write(f->release_key, seed, sizeof(seed), 0600) &&
        pd_write(f->license, TEST_LICENSE_TEXT_MIT, strlen(TEST_LICENSE_TEXT_MIT), 0644) &&
        plugin_keygen(f->signing, f->public_key) == PLUGIN_OK &&
        sw_node_open(&f->publisher, "plugin-dist-publisher", sw_score_contributor) &&
        sw_node_open(&f->receiver, "plugin-dist-receiver", sw_score_contributor);
    return f->ready;
}

void pd_close(struct pd_fixture *f)
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

/* Pack plugin "demo" at a version into <base>/<leaf>; the image differs per version. */
bool pd_pack(struct pd_fixture *f, const char *leaf, const char *version,
                    struct plugin_pack_result *packed)
{
    char dir[1400], exe[1400], image[96];
    int n = snprintf(image, sizeof(image), "inert plugin image %s\n", version);
    if (!pd_path(dir, sizeof(dir), f->base, leaf) ||
        !pd_path(exe, sizeof(exe), f->base, "image") || n <= 0)
        return false;
    struct plugin_pack_request rq = {
        .exe_path = exe, .name = "demo", .version = version,
        .key_path = f->signing, .out_dir = dir, .capabilities = 0
    };
    return pd_write(exe, image, (size_t)n, 0644) && plugin_pack(&rq, packed) == PLUGIN_OK;
}

enum plugin_dist_status pd_publish(struct pd_fixture *f, const char *leaf,
                                          uint64_t sequence,
                                          struct plugin_dist_published *out)
{
    char dir[1400];
    if (!pd_path(dir, sizeof(dir), f->base, leaf))
        return PLUGIN_DIST_ERR_ARGUMENT;
    struct plugin_dist_publish_request rq = {
        .name = "demo", .src_dir = dir, .license_file = f->license, .spdx = "MIT",
        .release_key = f->release_key, .sequence = sequence
    };
    return plugin_dist_publish(f->publisher.store, &rq, out);
}

/* One receiver tick: deliver each queued WANT to the publisher engine and its
 * DATA back. Returns false on a runaway queue; *replies counts DATA frames and
 * a nonzero limit stops the tick early with *stopped set. */
bool pd_pump_tick(struct pd_fixture *f, uint64_t now, unsigned limit,
                         unsigned *replies, bool *stopped)
{
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    uint64_t target = 0;
    size_t length = 0;
    unsigned frames = 0;
    vcs_swarm_engine_tick(f->receiver.engine, SW_DAY, now);
    while (vcs_swarm_engine_next_outbound(f->receiver.engine, 11, &target, frame, &length)) {
        if (++frames > 64)
            return false;
        struct vcs_swarm_frame_result served = vcs_swarm_engine_handle_frame(
            f->publisher.engine, 13, frame, length, SW_DAY, now);
        if (served.reply && served.reply_len) {
            struct vcs_swarm_frame_result got = vcs_swarm_engine_handle_frame(
                f->receiver.engine, 11, served.reply, served.reply_len, SW_DAY, now);
            free(got.reply);
            (*replies)++;
        }
        free(served.reply);
        if (limit && *replies >= limit) {
            *stopped = true;
            return true;
        }
    }
    return true;
}

bool pd_peers(struct pd_fixture *f)
{
    uint8_t pk[33], rk[33];
    sw_key(81, pk);
    sw_key(82, rk);
    return vcs_swarm_engine_peer_add(f->receiver.engine, 11, pk) &&
           vcs_swarm_engine_peer_add(f->publisher.engine, 13, rk);
}

bool pd_transfer_start(struct pd_fixture *f, const uint8_t root[32])
{
    const uint64_t provider = 11;
    return pd_peers(f) &&
           vcs_swarm_engine_fetch_from_bounded(f->receiver.engine, root, SW_DAY, 1,
               &provider, 1, 4u * PD_CAP) == VCS_SWARM_FETCH_OK;
}

/* Drive the real engines until the receiver has `limit` replies (0 = until
 * complete). Returns true when the stop condition was reached. */
bool pd_transfer(struct pd_fixture *f, const uint8_t root[32],
                        unsigned limit, bool first)
{
    if (first && !pd_transfer_start(f, root))
        return false;
    unsigned replies = 0;
    bool stopped = false;
    for (uint64_t now = first ? 2 : 40; now < (first ? 34 : 80); now++) {
        if (!pd_pump_tick(f, now, limit, &replies, &stopped))
            return false;
        if (stopped)
            return true;
        struct vcs_swarm_download_status st;
        if (vcs_swarm_engine_download_status(f->receiver.engine, root, &st) &&
            st.state == VCS_SWARM_DL_COMPLETE)
            return limit == 0;
    }
    return false;
}

bool pd_selection(const struct pd_fixture *f, const char *generation)
{
    char path[1400], target[160];
    if (!pd_path(path, sizeof(path), f->plugins, "demo/current"))
        return false;
    errno = 0;
    ssize_t n = readlink(path, target, sizeof(target));
    if (!generation)
        return n < 0 && errno == ENOENT;
    return n == 12 + PLUGIN_HEX_SHA3_512 && memcmp(target + 12, generation, 128) == 0;
}

bool pd_generation_stored(const struct pd_fixture *f, const char *generation)
{
    char path[1400], rel[256];
    snprintf(rel, sizeof(rel), "demo/generations/%s", generation);
    struct stat st;
    return pd_path(path, sizeof(path), f->plugins, rel) && stat(path, &st) == 0;
}

enum plugin_dist_status pd_receive(struct pd_fixture *f, const uint8_t root[32],
                                          const uint8_t *delivered, bool allow,
                                          struct plugin_dist_received *out)
{
    struct plugin_dist_receive_request rq = {
        .store = f->receiver.store, .delivered_root = delivered, .name = "demo",
        .plugins_dir = f->plugins, .scratch_dir = f->scratch, .allow_downgrade = allow
    };
    memcpy(rq.requested_root, root, 32);
    return plugin_dist_receive(&rq, out);
}

bool pd_scratch_empty(const struct pd_fixture *f)
{
    DIR *d = opendir(f->scratch);
    if (!d)
        return false;
    struct dirent *e;
    bool empty = true;
    while ((e = readdir(d)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, ".."))
            empty = false;
    closedir(d);
    return empty;
}
