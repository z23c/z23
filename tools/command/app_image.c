/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the zcl.app_build.v1 build record of one app copy image
 *          (see command/app_image.h). */

#include "command/app_image.h"

struct zcl_result app_image_closure_root(
    const struct zcl_action_root_request *actions, size_t count,
    uint8_t out[32])
{
    (void)actions; (void)count; (void)out;
    return ZCL_ERR(-1, "app build record: not implemented");
}

struct zcl_result app_image_env_root(uint8_t out[32])
{
    (void)out;
    return ZCL_ERR(-1, "app build record: not implemented");
}

struct zcl_result app_image_capture(const char *image_path,
                                    struct app_image_build *rec)
{
    (void)image_path; (void)rec;
    return ZCL_ERR(-1, "app build record: not implemented");
}

struct zcl_result app_image_build_validate(const struct app_image_build *rec)
{
    (void)rec;
    return ZCL_ERR(-1, "app build record: not implemented");
}

struct zcl_result app_image_build_encode(
    const struct app_image_build *rec,
    uint8_t wire[APP_IMAGE_BUILD_WIRE_BYTES])
{
    (void)rec; (void)wire;
    return ZCL_ERR(-1, "app build record: not implemented");
}

struct zcl_result app_image_build_decode(const uint8_t *wire, size_t len,
                                         struct app_image_build *out)
{
    (void)wire; (void)len; (void)out;
    return ZCL_OK;
}

struct zcl_result app_image_build_id(const struct app_image_build *rec,
                                     uint8_t out[32])
{
    (void)rec; (void)out;
    return ZCL_ERR(-1, "app build record: not implemented");
}

void app_image_build_key(const uint8_t package_root[32],
                         const uint8_t env_root[32],
                         const uint8_t dependency_root[32], uint8_t out[32])
{
    (void)package_root; (void)env_root; (void)dependency_root; (void)out;
}

void app_image_build_accepted(const struct app_image_build *rec,
                              struct resident_launch_accepted *out)
{
    (void)rec; (void)out;
}

struct zcl_result app_image_build_save(const char *store_dir,
                                       const struct app_image_build *rec,
                                       char *path_out, size_t path_cap)
{
    (void)store_dir; (void)rec; (void)path_out; (void)path_cap;
    return ZCL_ERR(-1, "app build record: not implemented");
}

struct zcl_result app_image_build_load(const char *store_dir,
                                       const uint8_t package_root[32],
                                       const uint8_t env_root[32],
                                       const uint8_t dependency_root[32],
                                       struct app_image_build *out, bool *hit)
{
    (void)store_dir; (void)package_root; (void)env_root;
    (void)dependency_root; (void)out;
    if (hit) *hit = false;
    return ZCL_OK;
}

struct zcl_result app_image_build_prepare(const struct app_image_build *rec,
                                          const char *image_path,
                                          struct resident_launch *launch)
{
    (void)rec; (void)image_path; (void)launch;
    return ZCL_OK;
}
