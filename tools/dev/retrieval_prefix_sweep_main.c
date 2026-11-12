/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the retrieval prefix sweep. */

#include "dev_script_dir.h"
#include "retrieval_prefix_sweep.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct rx_slot {
    char *buf;
    size_t cap;
    const char *env;
    const char *rel;
};

static int rx_fill(const char *root, struct rx_slot *slot, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        const char *env = slot[i].env == NULL ? NULL : getenv(slot[i].env);
        int n;
        if (env != NULL && env[0] != '\0')
            n = snprintf(slot[i].buf, slot[i].cap, "%s", env);
        else
            n = snprintf(slot[i].buf, slot[i].cap, "%s/%s", root, slot[i].rel);
        if (n < 0 || (size_t)n >= slot[i].cap)
            return -1;
    }
    return 0;
}

static void rx_main_fail(const char *msg)
{
    fprintf(stderr, "retrieval-prefix-sweep: FAIL \xe2\x80\x94 %s\n", msg);
}

int main(int argc, char **argv)
{
    char root[PATH_MAX];
    char checker[PATH_MAX];
    char evaluator[PATH_MAX];
    char jsonq[PATH_MAX];
    char sha3[PATH_MAX];
    char receipt[PATH_MAX];
    char source[PATH_MAX];
    struct rx_slot slot[6];
    struct zcl_rx_tools tools;
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        rx_main_fail("checkout root is unavailable");
        return 1;
    }
    slot[0] = (struct rx_slot){checker, sizeof checker, NULL,
        "tools/dev/retrieval-gold-identifier-graph-receipt-check.sh"};
    slot[1] = (struct rx_slot){receipt, sizeof receipt, NULL,
        "docs/work/retrieval-gold-evidence/retrieval-gold-benchmark-25fe3e353288.jsonl"};
    slot[2] = (struct rx_slot){source, sizeof source, NULL,
        "tools/dev/retrieval_prefix_sweep.c"};
    slot[3] = (struct rx_slot){evaluator, sizeof evaluator, "ZCL_RETRIEVAL_EVAL",
        "build/bin/retrieval-eval"};
    slot[4] = (struct rx_slot){jsonq, sizeof jsonq, "ZCL_JSONQ", "build/bin/jsonq"};
    slot[5] = (struct rx_slot){sha3, sizeof sha3, "ZCL_AGENT_SHA3", "build/bin/agent_sha3"};
    if (rx_fill(root, slot, 6) != 0) {
        rx_main_fail("tool path does not fit");
        return 1;
    }
    tools.checker = checker;
    tools.evaluator = evaluator;
    tools.jsonq = jsonq;
    tools.sha3 = sha3;
    tools.receipt = receipt;
    tools.sweep_source = source;
    return zcl_retrieval_prefix_sweep(argv[0], argc, argv, &tools);
}
