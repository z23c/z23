/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the zcl.app_build.v1 build record of one app copy image
 *          (see command/app_image.h). */

#include "command/app_image.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "platform/positioned_file.h"
#include "sha3/sha3.h"
#include "util/authority_receipt.h"
#include "vcs/build_action.h"
#include "vcs/package_prepare.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int aib_root_compare(const void *a, const void *b)
{
    return memcmp(a, b, 32);
}

void app_image_dependency_root(const struct vcs_package_lock *lock, uint8_t out[32])
{
    static const char domain[] = "zcl.app_build.dependency_set.v1";
    uint8_t roots[VCS_PACKAGE_LOCK_MAX_NODES][32];
    size_t n = 0;
    for (size_t i = 0; i + 1u < lock->count && n < VCS_PACKAGE_LOCK_MAX_NODES; ++i)
        memcpy(roots[n++], lock->nodes[i].root, 32);
    qsort(roots, n, 32, aib_root_compare);
    uint8_t count[4] = {(uint8_t)n, (uint8_t)(n >> 8), 0, 0};
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, count, sizeof(count));
    for (size_t i = 0; i < n; ++i) sha3_256_write(&sha, roots[i], 32);
    sha3_256_finalize(&sha, out);
}

#define AIB_OFF_PACKAGE   APP_IMAGE_BUILD_DOMAIN_BYTES
#define AIB_OFF_CLOSURE   (AIB_OFF_PACKAGE + 32u)
#define AIB_OFF_ENV       (AIB_OFF_CLOSURE + 32u)
#define AIB_OFF_DEPS      (AIB_OFF_ENV + 32u)
#define AIB_OFF_IMAGE     (AIB_OFF_DEPS + 32u)
#define AIB_OFF_VOLUME    (AIB_OFF_IMAGE + 32u)
#define AIB_OFF_LOW       (AIB_OFF_VOLUME + 8u)
#define AIB_OFF_HIGH      (AIB_OFF_LOW + 8u)
#define AIB_OFF_SIZE      (AIB_OFF_HIGH + 8u)

static_assert(AIB_OFF_SIZE + 8u == APP_IMAGE_BUILD_BODY_BYTES,
              "app build record body layout");
static_assert(APP_IMAGE_BUILD_BODY_BYTES + 32u == APP_IMAGE_BUILD_WIRE_BYTES,
              "app build record wire layout");
static_assert(sizeof(APP_IMAGE_BUILD_DOMAIN) - 1u ==
                  APP_IMAGE_BUILD_DOMAIN_BYTES,
              "app build record domain width");

static bool aib_zero(const uint8_t root[32])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++)
        any |= root[i];
    return any == 0;
}

struct zcl_result app_image_env_root(uint8_t out[32])
{
    struct vcs_toolchain_capsule_v1 capsule;
    if (!out)
        return ZCL_ERR(-1, "app build record: env root needs an output");
    if (!vcs_toolchain_capsule_v1_capture(&capsule))
        return ZCL_ERR(-1, "app build record: the toolchain capsule cannot "
                           "be captured on this host");
    if (!vcs_toolchain_capsule_v1_root(&capsule, out))
        return ZCL_ERR(-1, "app build record: the captured toolchain "
                           "capsule has no root");
    return ZCL_OK;
}

/* ---- image identity -------------------------------------------------- */

static bool aib_hash_handle(const struct platform_positioned_file *file,
                            uint64_t size, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    uint8_t chunk[16384];
    uint64_t offset = 0;
    sha3_256_init(&sha);
    while (offset < size) {
        size_t want = size - offset < sizeof(chunk)
            ? (size_t)(size - offset) : sizeof(chunk);
        int64_t got = platform_positioned_file_read(file, chunk, want, offset);
        if (got <= 0)
            return false;
        sha3_256_write(&sha, chunk, (size_t)got);
        offset += (uint64_t)got;
    }
    sha3_256_finalize(&sha, out);
    return true;
}

struct zcl_result app_image_capture(const char *image_path,
                                    struct app_image_build *rec)
{
    if (!image_path || !image_path[0] || !rec)
        return ZCL_ERR(-1, "app build record: capture needs an image path");
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, image_path))
        return ZCL_ERR(-1, "app build record: cannot open image %s: %s",
                       image_path, strerror(errno));
    bool ok = platform_positioned_file_snapshot(&file, &before) &&
              before.size > 0 &&
              aib_hash_handle(&file, before.size, rec->image_sha3) &&
              platform_positioned_file_snapshot(&file, &after) &&
              platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok)
        return ZCL_ERR(-1, "app build record: image %s is empty, unreadable "
                           "or changed while it was hashed", image_path);
    rec->image_volume = before.volume;
    rec->image_low = before.file_low;
    rec->image_high = before.file_high;
    rec->image_size = before.size;
    return ZCL_OK;
}

void app_image_build_accepted(const struct app_image_build *rec,
                              struct resident_launch_accepted *out)
{
    memset(out, 0, sizeof(*out));
    zcl_hex_encode(rec->image_sha3, 32, out->image_sha3_hex);
    out->image_volume = rec->image_volume;
    out->image_low = rec->image_low;
    out->image_high = rec->image_high;
    out->image_size = rec->image_size;
}

/* ---- codec ----------------------------------------------------------- */

struct zcl_result app_image_build_validate(const struct app_image_build *rec)
{
    if (!rec)
        return ZCL_ERR(-1, "app build record: no record");
    const struct { const char *name; const uint8_t *root; } roots[] = {
        { "package_root", rec->package_root },
        { "closure_root", rec->closure_root },
        { "env_root", rec->env_root },
        { "dependency_root", rec->dependency_root },
        { "image_sha3", rec->image_sha3 },
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (aib_zero(roots[i].root))
            return ZCL_ERR(-1, "app build record: %s is zero", roots[i].name);
    if (rec->image_size == 0)
        return ZCL_ERR(-1, "app build record: image_size is zero");
    return ZCL_OK;
}

static void aib_record_id(const uint8_t body[APP_IMAGE_BUILD_BODY_BYTES],
                          uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)APP_IMAGE_BUILD_DOMAIN,
                   sizeof(APP_IMAGE_BUILD_DOMAIN)); /* domain plus its NUL */
    sha3_256_write(&sha, body, APP_IMAGE_BUILD_BODY_BYTES);
    sha3_256_finalize(&sha, out);
}

struct zcl_result app_image_build_encode(
    const struct app_image_build *rec,
    uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES])
{
    struct zcl_result valid = app_image_build_validate(rec);
    if (!valid.ok)
        return valid;
    if (!wire)
        return ZCL_ERR(-1, "app build record: encode needs an output");
    memcpy(wire, APP_IMAGE_BUILD_DOMAIN, APP_IMAGE_BUILD_DOMAIN_BYTES);
    memcpy(wire + AIB_OFF_PACKAGE, rec->package_root, 32);
    memcpy(wire + AIB_OFF_CLOSURE, rec->closure_root, 32);
    memcpy(wire + AIB_OFF_ENV, rec->env_root, 32);
    memcpy(wire + AIB_OFF_DEPS, rec->dependency_root, 32);
    memcpy(wire + AIB_OFF_IMAGE, rec->image_sha3, 32);
    zcl_write_u64_le(wire + AIB_OFF_VOLUME, rec->image_volume);
    zcl_write_u64_le(wire + AIB_OFF_LOW, rec->image_low);
    zcl_write_u64_le(wire + AIB_OFF_HIGH, rec->image_high);
    zcl_write_u64_le(wire + AIB_OFF_SIZE, rec->image_size);
    aib_record_id(wire, wire + APP_IMAGE_BUILD_BODY_BYTES);
    return ZCL_OK;
}

static struct zcl_result aib_frame_check(const uint8_t *wire, size_t len)
{
    if (!wire && len)
        return ZCL_ERR(-1, "app build record: no bytes");
    if (len < APP_IMAGE_BUILD_WIRE_BYTES)
        return ZCL_ERR(-1, "app build record: truncated, %zu of %u bytes",
                       len, APP_IMAGE_BUILD_WIRE_BYTES);
    if (len > APP_IMAGE_BUILD_WIRE_BYTES)
        return ZCL_ERR(-1, "app build record: %zu trailing bytes after the "
                           "%u-byte record", len - APP_IMAGE_BUILD_WIRE_BYTES,
                       APP_IMAGE_BUILD_WIRE_BYTES);
    if (memcmp(wire, APP_IMAGE_BUILD_DOMAIN, APP_IMAGE_BUILD_DOMAIN_BYTES))
        return ZCL_ERR(-1, "app build record: foreign domain, not "
                           APP_IMAGE_BUILD_DOMAIN);
    uint8_t id[32];
    aib_record_id(wire, id);
    if (memcmp(id, wire + APP_IMAGE_BUILD_BODY_BYTES, 32))
        return ZCL_ERR(-1, "app build record: record id does not match its "
                           "bytes");
    return ZCL_OK;
}

struct zcl_result app_image_build_decode(const uint8_t *wire, size_t len,
                                         struct app_image_build *out)
{
    if (!out)
        return ZCL_ERR(-1, "app build record: decode needs an output");
    memset(out, 0, sizeof(*out));
    struct zcl_result framed = aib_frame_check(wire, len);
    if (!framed.ok)
        return framed;
    memcpy(out->package_root, wire + AIB_OFF_PACKAGE, 32);
    memcpy(out->closure_root, wire + AIB_OFF_CLOSURE, 32);
    memcpy(out->env_root, wire + AIB_OFF_ENV, 32);
    memcpy(out->dependency_root, wire + AIB_OFF_DEPS, 32);
    memcpy(out->image_sha3, wire + AIB_OFF_IMAGE, 32);
    out->image_volume = zcl_read_u64_le(wire + AIB_OFF_VOLUME);
    out->image_low = zcl_read_u64_le(wire + AIB_OFF_LOW);
    out->image_high = zcl_read_u64_le(wire + AIB_OFF_HIGH);
    out->image_size = zcl_read_u64_le(wire + AIB_OFF_SIZE);
    struct zcl_result valid = app_image_build_validate(out);
    if (!valid.ok)
        memset(out, 0, sizeof(*out));
    return valid;
}

struct zcl_result app_image_build_id(const struct app_image_build *rec,
                                     uint8_t out[32])
{
    uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES];
    if (!out)
        return ZCL_ERR(-1, "app build record: id needs an output");
    struct zcl_result encoded = app_image_build_encode(rec, wire);
    if (encoded.ok)
        memcpy(out, wire + APP_IMAGE_BUILD_BODY_BYTES, 32);
    return encoded;
}

/* ---- store ----------------------------------------------------------- */

void app_image_build_key(const uint8_t package_root[32],
                         const uint8_t env_root[32],
                         const uint8_t dependency_root[32], uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)APP_IMAGE_BUILD_KEY_DOMAIN,
                   sizeof(APP_IMAGE_BUILD_KEY_DOMAIN)); /* domain plus its NUL */
    sha3_256_write(&sha, package_root, 32);
    sha3_256_write(&sha, env_root, 32);
    sha3_256_write(&sha, dependency_root, 32);
    sha3_256_finalize(&sha, out);
}

static void aib_file_name(const uint8_t package_root[32],
                          const uint8_t env_root[32],
                          const uint8_t dependency_root[32], char name[80])
{
    uint8_t key[32];
    char hex[65];
    app_image_build_key(package_root, env_root, dependency_root, key);
    zcl_hex_encode(key, sizeof(key), hex);
    (void)snprintf(name, 80, "%s%s", hex, APP_IMAGE_BUILD_FILE_SUFFIX);
}

struct zcl_result app_image_build_save(const char *store_dir,
                                       const struct app_image_build *rec,
                                       char *path_out, size_t path_cap)
{
    uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES];
    char name[80];
    if (!store_dir || !store_dir[0])
        return ZCL_ERR(-1, "app build record: save needs a store directory");
    struct zcl_result encoded = app_image_build_encode(rec, wire);
    if (!encoded.ok)
        return encoded;
    aib_file_name(rec->package_root, rec->env_root, rec->dependency_root,
                  name);
    if (!authority_receipt_write_atomic(store_dir, name, wire, sizeof(wire),
                                        path_out, path_cap))
        return ZCL_ERR(-1, "app build record: durable write of %s/%s failed",
                       store_dir, name);
    return ZCL_OK;
}

/* Read the whole stored record, one byte past the wire so an over-long
 * file is seen. ENOENT is reported as *missing, not as an error. */
static struct zcl_result aib_read_stored(const char *path, uint8_t *buf,
                                         size_t cap, size_t *len,
                                         bool *missing)
{
    struct platform_positioned_file file;
    *len = 0;
    *missing = false;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path)) {
        *missing = errno == ENOENT;
        return *missing ? ZCL_OK
                        : ZCL_ERR(-1, "app build record %s: cannot open: %s",
                                  path, strerror(errno));
    }
    int64_t got = platform_positioned_file_read(&file, buf, cap, 0);
    platform_positioned_file_close(&file);
    if (got < 0)
        return ZCL_ERR(-1, "app build record %s: read failed: %s", path,
                       strerror(errno));
    *len = (size_t)got;
    return ZCL_OK;
}

static bool aib_names_inputs(const struct app_image_build *rec,
                             const uint8_t package_root[32],
                             const uint8_t env_root[32],
                             const uint8_t dependency_root[32])
{
    return memcmp(rec->package_root, package_root, 32) == 0 &&
           memcmp(rec->env_root, env_root, 32) == 0 &&
           memcmp(rec->dependency_root, dependency_root, 32) == 0;
}

struct zcl_result app_image_build_load(const char *store_dir,
                                       const uint8_t package_root[32],
                                       const uint8_t env_root[32],
                                       const uint8_t dependency_root[32],
                                       struct app_image_build *out, bool *hit)
{
    if (!store_dir || !package_root || !env_root || !dependency_root ||
        !out || !hit)
        return ZCL_ERR(-1, "app build record: load needs a store, the three "
                           "input roots and outputs");
    *hit = false;
    memset(out, 0, sizeof(*out));
    char name[80], path[4096 + 96];
    aib_file_name(package_root, env_root, dependency_root, name);
    int n = snprintf(path, sizeof(path), "%s/%s", store_dir, name);
    if (n < 0 || (size_t)n >= sizeof(path))
        return ZCL_ERR(-1, "app build record: store path too long");
    uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES + 1u];
    size_t len = 0;
    bool missing = false;
    struct zcl_result read = aib_read_stored(path, wire, sizeof(wire), &len,
                                             &missing);
    if (!read.ok || missing)
        return read;
    struct zcl_result decoded = app_image_build_decode(wire, len, out);
    if (!decoded.ok)
        return ZCL_ERR(-1, "%s (stored at %s)", decoded.message, path);
    if (!aib_names_inputs(out, package_root, env_root, dependency_root)) {
        memset(out, 0, sizeof(*out));
        return ZCL_ERR(-1, "app build record %s names other inputs than its "
                           "key", path);
    }
    *hit = true;
    return ZCL_OK;
}

struct zcl_result app_image_build_prepare(const struct app_image_build *rec,
                                          const char *image_path,
                                          struct resident_launch *launch)
{
    struct zcl_result valid = app_image_build_validate(rec);
    if (!valid.ok)
        return valid;
    if (!image_path || !image_path[0] || !launch)
        return ZCL_ERR(-1, "app build record: prepare needs an image path "
                           "and a launch");
    struct resident_launch_accepted accepted;
    char error[RESIDENT_LAUNCH_ERROR_MAX] = "";
    app_image_build_accepted(rec, &accepted);
    if (!resident_launch_prepare(launch, image_path, &accepted, error,
                                 sizeof(error)))
        return ZCL_ERR(-1, "app build record: image %s is not the recorded "
                           "build: %s", image_path, error);
    return ZCL_OK;
}
