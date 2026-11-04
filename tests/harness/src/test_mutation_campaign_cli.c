#include "mutation_harness.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int campaign_option(const char *option, bool accepted)
{
    char *arguments[] = {
        "build/bin/mutation-campaign",
        "--file=tools/agent/gate_receipt.c", "--list", (char *)option, NULL,
    };
    char *output = NULL;
    size_t length = 0;
    int status = zcl_mut_spawn(NULL, arguments, 10000, &output, &length);
    bool correct = accepted ? status == 0 :
        status == 2 && output && strstr(output, "mutation-campaign:") != NULL;
    printf("  mutation_campaign_cli: %s status=%d expected=%d... %s\n",
           option, status, accepted ? 0 : 2, correct ? "OK" : "FAIL");
    free(output);
    return correct ? 0 : 1;
}

int test_mutation_campaign_cli(void)
{
    int failures = 0;
    static const char *const invalid[] = {
        "--limit=typo", "--limit=", "--limit=3junk", "--limit=-1",
        "--limit=+1", "--limit= 1", "--limit=1 ", "--limit=0x10",
        "--limit=18446744073709551616",
        "--build-timeout=typo", "--build-timeout=", "--build-timeout=-1",
        "--build-timeout=1.5", "--build-timeout=1s", "--build-timeout=+1",
        "--test-timeout=typo", "--test-timeout=", "--test-timeout=-1",
        "--test-timeout=1.5", "--test-timeout=1s", "--test-timeout= 1",
        "--test-timeout=9223372036854775807",
        "--build-timeout=184467440737095516160",
    };
    static const char *const valid[] = {
        "--limit=0", "--limit=1", "--limit=0002",
        "--build-timeout=0", "--build-timeout=1", "--build-timeout=900",
        "--test-timeout=0", "--test-timeout=1", "--test-timeout=300",
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
        failures += campaign_option(invalid[i], false);
    for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++)
        failures += campaign_option(valid[i], true);
    char option[96];
    (void)snprintf(option, sizeof(option), "--limit=%zu", SIZE_MAX);
    failures += campaign_option(option, true);
    (void)snprintf(option, sizeof(option), "--limit=%zu0", SIZE_MAX);
    failures += campaign_option(option, false);
    const char *timeouts[] = {"--build-timeout=", "--test-timeout="};
    for (size_t i = 0; i < 2; i++) {
        (void)snprintf(option, sizeof(option), "%s%d", timeouts[i], INT_MAX / 1000);
        failures += campaign_option(option, true);
        (void)snprintf(option, sizeof(option), "%s%d", timeouts[i], INT_MAX / 1000 + 1);
        failures += campaign_option(option, false);
    }
    return failures;
}
