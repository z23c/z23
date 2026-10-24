/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The in-node core of `fleet bundle offer` and `fleet bundle fetch`.
 *          See native_fleet_bundle.h. The carrier is the package store plus
 *          the swarm (vcs/bundle_carry.h); the land identity is the file's
 *          sha256, which the fetching side recomputes. */

#include "command/native_fleet_bundle.h"

#include "base/safe_alloc.h"
#include "crypto/sha256.h"
#include "vcs/blob_store.h"
#include "vcs/bundle_carry.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#define ZFB_ONION_LABEL 56u

static enum zcl_fleet_bundle_status zfb_refuse(
    struct zcl_fleet_bundle_outcome *out, const char *code,
    const char *message, bool retryable, bool mutated)
{
    out->status = ZCL_FLEET_BUNDLE_REFUSED;
    (void)snprintf(out->code, sizeof(out->code), "%s", code);
    (void)snprintf(out->message, sizeof(out->message), "%s", message);
    out->retryable = retryable;
    out->mutated = mutated;
    return ZCL_FLEET_BUNDLE_REFUSED;
}

static void zfb_sha256(const uint8_t *bytes, size_t len, uint8_t out[32])
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_write(&ctx, bytes, len);
    sha256_finalize(&ctx, out);
}

static bool zfb_onion_label(const char *peer)
{
    for (size_t i = 0; i < ZFB_ONION_LABEL; i++) {
        char c = peer[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')))
            return false;
    }
    return strncmp(peer + ZFB_ONION_LABEL, ".onion", 6) == 0;
}

static bool zfb_onion_port(const char *port)
{
    if (*port == '\0')
        return true;
    if (*port != ':' || port[1] == '\0' || strlen(port + 1) > 5u)
        return false;
    uint32_t value = 0;
    for (const char *p = port + 1; *p; p++) {
        if (*p < '0' || *p > '9')
            return false;
        value = value * 10u + (uint32_t)(*p - '0');
    }
    return value >= 1u && value <= 65535u;
}

bool zcl_fleet_bundle_peer_is_onion(const char *peer)
{
    if (!peer || strlen(peer) < ZFB_ONION_LABEL + 6u)
        return false;
    return zfb_onion_label(peer) &&
           zfb_onion_port(peer + ZFB_ONION_LABEL + 6);
}

/* ── offer ───────────────────────────────────────────────────────── */

/* Read the whole regular file into a heap buffer, refusing a symlink, a
 * non-regular file, an empty one and one over the cap before reading. */
static enum zcl_fleet_bundle_status zfb_read_file(
    const char *path, uint8_t **buf, size_t *len,
    struct zcl_fleet_bundle_outcome *out)
{
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return zfb_refuse(out, "FILE_UNREADABLE",
                          "the file cannot be opened (missing, a symlink, "
                          "or not readable)", false, false);
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return zfb_refuse(out, "FILE_NOT_REGULAR",
                          "the path is not a regular file", false, false);
    }
    if (st.st_size <= 0) {
        close(fd);
        return zfb_refuse(out, "FILE_EMPTY", "the file is empty", false,
                          false);
    }
    if ((uint64_t)st.st_size > (uint64_t)VCS_BUNDLE_MAX_BYTES) {
        close(fd);
        return zfb_refuse(out, "FILE_TOO_LARGE",
                          "the file is over the 5 MiB bundle cap", false,
                          false);
    }
    size_t want = (size_t)st.st_size;
    uint8_t *data = zcl_malloc(want, "fleet-bundle-offer");
    if (!data) {
        close(fd);
        return zfb_refuse(out, "NO_MEMORY", "allocation failed", true,
                          false);
    }
    size_t got = 0;
    while (got < want) {
        ssize_t n = read(fd, data + got, want - got);
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    close(fd);
    if (got != want) {
        free(data);
        return zfb_refuse(out, "FILE_UNREADABLE",
                          "the file changed or could not be read in full",
                          true, false);
    }
    *buf = data;
    *len = want;
    return ZCL_FLEET_BUNDLE_DONE;
}

static enum zcl_fleet_bundle_status zfb_put_refused(
    struct zcl_fleet_bundle_outcome *out, enum vcs_bundle_result vr)
{
    if (vr == VCS_BUNDLE_ERR_STORE)
        return zfb_refuse(out, "STORE_REFUSED",
                          "the package store refused the bundle (quota or "
                          "eviction pressure; nothing was evicted)", true,
                          true);
    if (vr == VCS_BUNDLE_ERR_NO_STORE)
        return zfb_refuse(out, "HOSTING_DISABLED",
                          "package hosting is disabled on this node "
                          "(start it with -packagehost=1)", false, false);
    return zfb_refuse(out, "BUNDLE_REFUSED", vcs_bundle_result_string(vr),
                      false, false);
}

enum zcl_fleet_bundle_status zcl_fleet_bundle_offer(
    struct vcs_package_store *store, struct vcs_swarm_engine *engine,
    const char *path, struct zcl_fleet_bundle_outcome *out)
{
    memset(out, 0, sizeof(*out));
    if (!store)
        return zfb_put_refused(out, VCS_BUNDLE_ERR_NO_STORE);
    if (!path || path[0] != '/')
        return zfb_refuse(out, "BAD_FILE", "file must be an absolute path",
                          false, false);
    uint8_t *buf = NULL;
    size_t len = 0;
    if (zfb_read_file(path, &buf, &len, out) != ZCL_FLEET_BUNDLE_DONE)
        return ZCL_FLEET_BUNDLE_REFUSED;
    zfb_sha256(buf, len, out->sha256);
    enum vcs_bundle_result vr =
        vcs_bundle_put_to_no_evict(store, buf, len, out->root);
    free(buf);
    if (vr != VCS_BUNDLE_OK)
        return zfb_put_refused(out, vr);
    out->size = len;
    if (vcs_package_store_pin(store, out->root, true) !=
        VCS_PACKAGE_STORE_OK)
        return zfb_refuse(out, "PIN_REFUSED",
                          "the bundle is stored but the pins pool has no "
                          "room to keep it from eviction", true, true);
    if (engine)
        out->announced = vcs_blob_announce_via(engine);
    out->status = ZCL_FLEET_BUNDLE_DONE;
    return ZCL_FLEET_BUNDLE_DONE;
}

/* ── fetch ───────────────────────────────────────────────────────── */

/* Create out_path exclusively with 0600 and write the verified bytes. */
static enum zcl_fleet_bundle_status zfb_write_out(
    const char *path, const uint8_t *bytes, size_t len,
    struct zcl_fleet_bundle_outcome *out)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                  0600);
    if (fd < 0)
        return zfb_refuse(out, errno == EEXIST ? "OUT_EXISTS" : "OUT_UNWRITABLE",
                          "the output file could not be created exclusively",
                          false, false);
    size_t done = 0;
    while (done < len) {
        ssize_t n = write(fd, bytes + done, len - done);
        if (n <= 0)
            break;
        done += (size_t)n;
    }
    bool closed = close(fd) == 0;
    if (done != len || !closed) {
        (void)unlink(path);
        return zfb_refuse(out, "OUT_UNWRITABLE",
                          "the output file could not be written in full",
                          true, false);
    }
    return ZCL_FLEET_BUNDLE_DONE;
}

/* The package is complete in the store: shape, size, sha256, then write. */
static enum zcl_fleet_bundle_status zfb_finish(
    struct vcs_package_store *store,
    const struct zcl_fleet_bundle_fetch_args *args,
    struct zcl_fleet_bundle_outcome *out)
{
    size_t size = 0;
    enum vcs_bundle_result vr = vcs_bundle_size_of(store, args->root, &size);
    if (vr != VCS_BUNDLE_OK)
        return zfb_refuse(out, "NOT_A_BUNDLE",
                          "the root is not a one-file bundle package", false,
                          false);
    if ((uint64_t)size != args->size)
        return zfb_refuse(out, "SIZE_MISMATCH",
                          "the bundle size differs from the size named",
                          false, false);
    uint8_t *buf = zcl_malloc(size, "fleet-bundle-fetch");
    if (!buf)
        return zfb_refuse(out, "NO_MEMORY", "allocation failed", true,
                          false);
    size_t got = 0;
    vr = vcs_bundle_get_from(store, args->root, buf, size, &got);
    if (vr != VCS_BUNDLE_OK || got != size) {
        free(buf);
        return zfb_refuse(out, "BUNDLE_UNREADABLE",
                          vcs_bundle_result_string(vr), true, false);
    }
    uint8_t digest[32];
    zfb_sha256(buf, size, digest);
    enum zcl_fleet_bundle_status st = ZCL_FLEET_BUNDLE_DONE;
    if (memcmp(digest, args->sha256, 32) != 0)
        st = zfb_refuse(out, "SHA256_MISMATCH",
                        "the bundle sha256 differs from the one named; "
                        "nothing was written", false, false);
    else
        st = zfb_write_out(args->out_path, buf, size, out);
    free(buf);
    if (st != ZCL_FLEET_BUNDLE_DONE)
        return st;
    memcpy(out->root, args->root, 32);
    memcpy(out->sha256, digest, 32);
    out->size = size;
    out->status = ZCL_FLEET_BUNDLE_DONE;
    return ZCL_FLEET_BUNDLE_DONE;
}

static bool zfb_store_complete(struct vcs_package_store *store,
                               const uint8_t root[32])
{
    struct vcs_package_store_status ps;
    return vcs_package_store_package_status(store, root, &ps) && ps.tracked &&
           ps.complete;
}

static const char *zfb_fetch_code(enum vcs_swarm_fetch_result r)
{
    switch (r) {
    case VCS_SWARM_FETCH_NO_STORE:  return "NO_STORE";
    case VCS_SWARM_FETCH_FULL:      return "DOWNLOAD_SLOTS_FULL";
    case VCS_SWARM_FETCH_RECORD_IO: return "RECORD_IO";
    case VCS_SWARM_FETCH_BAD_INPUT: return "BAD_ROOT";
    default:                        return "FETCH_REFUSED";
    }
}

/* Start or continue the download. DONE: complete in the store. PENDING:
 * still arriving. REFUSED: a rule failed (a lying size cancels the work). */
static enum zcl_fleet_bundle_status zfb_progress(
    struct vcs_package_store *store, struct vcs_swarm_engine *engine,
    const struct zcl_fleet_bundle_fetch_args *args,
    struct zcl_fleet_bundle_outcome *out)
{
    if (zfb_store_complete(store, args->root))
        return ZCL_FLEET_BUNDLE_DONE;
    if (!engine)
        return zfb_refuse(out, "NO_ENGINE",
                          "no swarm engine is running (package hosting "
                          "disabled)", false, false);
    enum vcs_swarm_fetch_result r =
        vcs_swarm_engine_fetch(engine, args->root, args->day, args->now);
    if (r != VCS_SWARM_FETCH_OK && r != VCS_SWARM_FETCH_ALREADY_COMPLETE)
        return zfb_refuse(out, zfb_fetch_code(r),
                          vcs_swarm_fetch_result_string(r), true, false);
    if (zfb_store_complete(store, args->root))
        return ZCL_FLEET_BUNDLE_DONE;
    struct vcs_swarm_download_status ds;
    memset(&ds, 0, sizeof(ds));
    (void)vcs_swarm_engine_download_status(engine, args->root, &ds);
    if (ds.state == VCS_SWARM_DL_FAILED)
        return zfb_refuse(out, "DOWNLOAD_FAILED",
                          ds.rule ? ds.rule : "the swarm download failed",
                          false, true);
    if (ds.total_bytes != 0 && ds.total_bytes != args->size) {
        (void)vcs_swarm_engine_cancel(engine, args->root, args->now);
        return zfb_refuse(out, "SIZE_MISMATCH",
                          "the root's manifest size differs from the size "
                          "named; the download was cancelled", false, true);
    }
    out->present_chunks = ds.present_chunks;
    out->total_chunks = ds.total_chunks;
    out->status = ZCL_FLEET_BUNDLE_PENDING;
    return ZCL_FLEET_BUNDLE_PENDING;
}

enum zcl_fleet_bundle_status zcl_fleet_bundle_fetch_step(
    struct vcs_package_store *store, struct vcs_swarm_engine *engine,
    const struct zcl_fleet_bundle_fetch_args *args,
    struct zcl_fleet_bundle_outcome *out)
{
    memset(out, 0, sizeof(*out));
    if (!store)
        return zfb_put_refused(out, VCS_BUNDLE_ERR_NO_STORE);
    if (!args || !args->out_path || args->out_path[0] != '/')
        return zfb_refuse(out, "BAD_OUT", "out must be an absolute path",
                          false, false);
    if (args->size < 1u || args->size > (uint64_t)VCS_BUNDLE_MAX_BYTES)
        return zfb_refuse(out, "BAD_SIZE",
                          "size must be 1 to 5242880 bytes", false, false);
    struct stat st;
    if (lstat(args->out_path, &st) == 0 || errno != ENOENT)
        return zfb_refuse(out, "OUT_EXISTS",
                          "out already exists (or cannot be checked); pick "
                          "a path that does not exist", false, false);
    enum zcl_fleet_bundle_status s = zfb_progress(store, engine, args, out);
    if (s != ZCL_FLEET_BUNDLE_DONE)
        return s;
    return zfb_finish(store, args, out);
}
