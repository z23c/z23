/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "services/build_fabric_worker.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    uint8_t secret[32] = {0};
    uint8_t public_key[32] = {0};
    struct db_build_receipt receipt;
    struct build_fabric_worker_feedback feedback;
    memset(&receipt, 0xa5, sizeof(receipt));
    memset(&feedback, 0xa5, sizeof(feedback));

    struct zcl_result result = build_fabric_worker_execute(
        (struct node_db *)(uintptr_t)1, "workspace", "datadir", "action",
        "lease", secret, public_key, &receipt, &feedback);
    if (result.ok ||
        !strstr(result.message, "windows-build-fabric-execution-refused") ||
        !strstr(result.message, "restricted-token Job Object") ||
        !strstr(result.message, "network-denial")) {
        fputs("build_fabric_worker_refusal_acceptance: bad refusal\n", stderr);
        return 1;
    }

    const unsigned char *receipt_bytes = (const unsigned char *)&receipt;
    const unsigned char *feedback_bytes = (const unsigned char *)&feedback;
    for (size_t i = 0; i < sizeof(receipt); ++i)
        if (receipt_bytes[i] != 0) return 2;
    for (size_t i = 0; i < sizeof(feedback); ++i)
        if (feedback_bytes[i] != 0) return 3;

    puts("build_fabric_worker_refusal_acceptance: PASS");
    return 0;
}
