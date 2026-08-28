/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Windows acceptance that consensus_export_descriptor_digest()
 * and consensus_export_seal_readonly() refuse without writing through the
 * caller output binding, stat buffer or digest -- each is poisoned
 * beforehand so a refusal that left caller garbage is caught, not read as
 * clean. */
#include "consensus_state_snapshot_export_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct consensus_export_output_binding output;
    memset(&output, 0x5a, sizeof(output));
    struct consensus_export_output_binding before = output;
    struct stat sealed;
    memset(&sealed, 0xa5, sizeof(sealed));
    struct stat sealed_before = sealed;
    uint8_t digest[32], digest_before[32];
    memset(digest, 0x3c, sizeof(digest));
    memcpy(digest_before, digest, sizeof(digest));

    if (consensus_export_descriptor_digest(7, digest) ||
        memcmp(digest, digest_before, sizeof(digest)) != 0 ||
        consensus_export_seal_readonly(&output, &sealed) ||
        memcmp(&output, &before, sizeof(output)) != 0 ||
        memcmp(&sealed, &sealed_before, sizeof(sealed)) != 0)
        return 1;
    puts("consensus_export_output_seal_refusal_acceptance: PASS");
    return 0;
}
