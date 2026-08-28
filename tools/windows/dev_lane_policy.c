/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "dev_lane_policy.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wchar.h>

#define ZCL_WIN_DEV_PATH_CAP 32768u

static bool resolve_path(const wchar_t *input,
                         wchar_t output[ZCL_WIN_DEV_PATH_CAP])
{
    if (!input || !input[0])
        return false;
    DWORD length = GetFullPathNameW(input, ZCL_WIN_DEV_PATH_CAP, output, NULL);
    if (length == 0 || length >= ZCL_WIN_DEV_PATH_CAP)
        return false;
    while (length > 3 && (output[length - 1] == L'\\' ||
                          output[length - 1] == L'/'))
        output[--length] = L'\0';
    return true;
}

static bool path_equal(const wchar_t *left, const wchar_t *right)
{
    return CompareStringOrdinal(left, -1, right, -1, TRUE) == CSTR_EQUAL;
}

static bool path_below(const wchar_t *path, const wchar_t *root)
{
    size_t root_len = wcslen(root);
    if (_wcsnicmp(path, root, root_len) != 0)
        return false;
    return path[root_len] == L'\\' || path[root_len] == L'/';
}

static bool has_component(const wchar_t *path, const wchar_t *component)
{
    const wchar_t *cursor = path;
    size_t wanted = wcslen(component);
    while (*cursor) {
        while (*cursor == L'\\' || *cursor == L'/')
            cursor++;
        const wchar_t *end = cursor;
        while (*end && *end != L'\\' && *end != L'/')
            end++;
        if ((size_t)(end - cursor) == wanted &&
            _wcsnicmp(cursor, component, wanted) == 0)
            return true;
        cursor = end;
    }
    return false;
}

enum zcl_win_dev_lane_result zcl_win_dev_lane_validate(
    const struct zcl_win_dev_lane_config *config)
{
    wchar_t local[ZCL_WIN_DEV_PATH_CAP];
    wchar_t datadir[ZCL_WIN_DEV_PATH_CAP];
    wchar_t generations[ZCL_WIN_DEV_PATH_CAP];

    if (!config || !config->service_identity)
        return ZCL_WIN_DEV_LANE_INVALID_ARGUMENT;
    if (!resolve_path(config->local_app_data, local) ||
        !resolve_path(config->datadir, datadir) ||
        !resolve_path(config->generation_root, generations))
        return ZCL_WIN_DEV_LANE_PATH_RESOLUTION_FAILED;

    if (!path_below(datadir, local) || !path_below(generations, local))
        return ZCL_WIN_DEV_LANE_OUTSIDE_LOCAL_ROOT;
    if (has_component(datadir, L".zclassic") ||
        has_component(datadir, L".zclassic-c23") ||
        has_component(generations, L".zclassic") ||
        has_component(generations, L".zclassic-c23"))
        return ZCL_WIN_DEV_LANE_CANONICAL_PATH;
    if (path_equal(datadir, generations) || path_below(datadir, generations) ||
        path_below(generations, datadir))
        return ZCL_WIN_DEV_LANE_PATH_COLLISION;
    if (config->p2p_port != 8053u || config->rpc_port != 18252u)
        return ZCL_WIN_DEV_LANE_WRONG_PORT;
    if (_wcsicmp(config->service_identity, L"Z23 Dev Node") != 0)
        return ZCL_WIN_DEV_LANE_WRONG_IDENTITY;
    return ZCL_WIN_DEV_LANE_OK;
}

const char *zcl_win_dev_lane_result_name(enum zcl_win_dev_lane_result result)
{
    switch (result) {
    case ZCL_WIN_DEV_LANE_OK: return "ok";
    case ZCL_WIN_DEV_LANE_INVALID_ARGUMENT: return "invalid_argument";
    case ZCL_WIN_DEV_LANE_PATH_RESOLUTION_FAILED:
        return "path_resolution_failed";
    case ZCL_WIN_DEV_LANE_OUTSIDE_LOCAL_ROOT: return "outside_local_root";
    case ZCL_WIN_DEV_LANE_CANONICAL_PATH: return "canonical_path";
    case ZCL_WIN_DEV_LANE_PATH_COLLISION: return "path_collision";
    case ZCL_WIN_DEV_LANE_WRONG_PORT: return "wrong_port";
    case ZCL_WIN_DEV_LANE_WRONG_IDENTITY: return "wrong_identity";
    }
    return "unknown";
}
#endif
