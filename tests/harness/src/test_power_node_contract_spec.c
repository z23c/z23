/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * doc-contract test for the power-node architecture spec.
 * The spec is the contract; this test keeps the required surfaces
 * discoverable for RAG and future native tooling work. */

#include "test/test_core.h"

#include <errno.h>

#define POWER_NODE_SPEC_PATH "docs/spec/power-node-contract.md"

static int read_file(const char *path, char *buf, size_t bufsz)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    size_t n = fread(buf, 1, bufsz - 1, fp);
    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }
    buf[n] = '\0';
    fclose(fp);
    return 0;
}

static int test_doc_exists_and_names_contracts(void)
{
    int failures = 0;
    char body[32768];

    TEST("power-node contract spec: exists and names required surfaces") {
        if (read_file(POWER_NODE_SPEC_PATH, body, sizeof(body)) != 0) {
            printf("FAIL (%s: %s)\n", POWER_NODE_SPEC_PATH, strerror(errno));
            failures++; goto _test_next;
        }

        ASSERT(strstr(body, "node_state_api") != NULL);
        ASSERT(strstr(body, "service_registry") != NULL);
        ASSERT(strstr(body, "onion gateway") != NULL);
        ASSERT(strstr(body, "ZClassicDNS") != NULL);
        ASSERT(strstr(body, "native command surfaces") != NULL);
        ASSERT(strstr(body, "permissions") != NULL);
        ASSERT(strstr(body, "event expectations") != NULL);
        PASS();
    } _test_next:;

    return failures;
}

int test_power_node_contract_spec(void)
{
    int failures = 0;

    printf("\n=== Power Node Contract Spec Tests ===\n");
    failures += test_doc_exists_and_names_contracts();

    return failures;
}
