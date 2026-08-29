/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Windows acceptance for the node datadir's owner-private boundary. */
#include "chain/chainparamsbase.h"
#include "platform/private_directory.h"
#include "util/util.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <stdio.h>
#include <string.h>
#include <windows.h>

static bool path_concat(char *out, size_t out_size, const char *left,
                        const char *right)
{
    size_t left_size = strlen(left);
    size_t right_size = strlen(right);
    if (left_size >= out_size || right_size >= out_size - left_size)
        return false;
    memcpy(out, left, left_size);
    memcpy(out + left_size, right, right_size + 1u);
    return true;
}

static int fail(const char *message)
{
    fprintf(stderr, "datadir_privacy_acceptance: %s\n", message);
    return 1;
}

int main(void)
{
    char temp[MAX_PATH], root[MAX_PATH], permissive[MAX_PATH];
    char private_path[MAX_PATH], network[MAX_PATH], leaf[64];
    DWORD temp_size = GetTempPathA(sizeof(temp), temp);
    int leaf_size = snprintf(leaf, sizeof(leaf), "z23-datadir-%lu-%llu",
                             (unsigned long)GetCurrentProcessId(),
                             (unsigned long long)GetTickCount64());
    if (!temp_size || temp_size >= sizeof(temp) || leaf_size <= 0 ||
        (size_t)leaf_size >= sizeof(leaf) ||
        !path_concat(root, sizeof(root), temp, leaf) ||
        !path_concat(permissive, sizeof(permissive), root, "\\permissive") ||
        !path_concat(private_path, sizeof(private_path), root, "\\private") ||
        !path_concat(network, sizeof(network), private_path, "\\testnet3") ||
        !CreateDirectoryA(root, NULL))
        return fail("fixture creation failed");

    SelectBaseParams(CHAIN_TESTNET);
    if (!CreateDirectoryA(permissive, NULL) || SetDataDir(permissive))
        return fail("SetDataDir accepted an inherited broad ACL");
    if (!platform_private_directory_create(private_path)) {
        RemoveDirectoryA(permissive);
        RemoveDirectoryA(root);
        fputs("datadir_privacy_acceptance: REFUSE: runtime cannot prove "
              "native SID/DACL semantics\n", stderr);
        return 77;
    }
    if (!platform_private_directory_ensure(private_path))
        return fail("private fixture revalidation failed");
    if (!SetDataDir(private_path))
        return fail("SetDataDir refused a private directory");

    SetDataDir("");
    ClearDataDirCache();
    if (!RemoveDirectoryA(network) || !RemoveDirectoryA(private_path) ||
        !RemoveDirectoryA(permissive) || !RemoveDirectoryA(root))
        return fail("fixture cleanup failed");
    puts("datadir_privacy_acceptance: PASS");
    return 0;
}
