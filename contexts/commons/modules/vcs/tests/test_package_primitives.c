#include "vcs/package_manifest.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    static const uint8_t bytes[] = "c23 commons";
    uint8_t chunk[32], first[32], second[32];
    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    if (!vcs_package_chunk_hash(bytes, sizeof(bytes) - 1u, chunk) ||
        !vcs_package_manifest_add(&manifest, "src/commons.c",
            VCS_PACKAGE_MODE_FILE, sizeof(bytes) - 1u, chunk, 1) ||
        !vcs_package_manifest_root(&manifest, first)) {
        vcs_package_manifest_free(&manifest);
        return 1;
    }
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    struct vcs_package_manifest parsed;
    if (!vcs_package_manifest_serialize(&manifest, &wire, &wire_len) ||
        !vcs_package_manifest_parse(wire, wire_len, &parsed) ||
        !vcs_package_manifest_root(&parsed, second)) {
        free(wire);
        vcs_package_manifest_free(&manifest);
        return 2;
    }
    bool equal = memcmp(first, second, sizeof(first)) == 0;
    vcs_package_manifest_free(&parsed);
    vcs_package_manifest_free(&manifest);
    free(wire);
    return equal ? 0 : 3;
}
