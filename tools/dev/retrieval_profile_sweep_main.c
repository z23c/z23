/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Host entry for the retrieval profile sweep. */

#include "dev_script_dir.h"
#include "retrieval_profile_sweep.h"

#include <stdio.h>
#include <stdlib.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static int rps_copy(char *out, size_t cap, const char *envname, const char *root,
                    const char *rel)
{
    const char *env = getenv(envname);
    int n;
    if (env != NULL && env[0] != '\0')
        n = snprintf(out, cap, "%s", env);
    else
        n = snprintf(out, cap, "%s/%s", root, rel);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static int rps_under(char *out, size_t cap, const char *root, const char *rel)
{
    int n = snprintf(out, cap, "%s/%s", root, rel);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static void rps_main_fail(const char *msg)
{
    fprintf(stderr, "retrieval-profile-sweep: FAIL \xe2\x80\x94 %s\n", msg);
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
    struct zcl_rps_tools tools;
    if (zcl_dev_checkout_root(root, sizeof root) != 0) {
        rps_main_fail("checkout root is unavailable");
        return 1;
    }
    if (rps_under(checker, sizeof checker, root,
                  "tools/dev/retrieval-gold-identifier-graph-receipt-check.sh") != 0 ||
        rps_under(receipt, sizeof receipt, root,
                  "docs/work/retrieval-gold-evidence/"
                  "retrieval-gold-benchmark-25fe3e353288.jsonl") != 0 ||
        rps_under(source, sizeof source, root,
                  "tools/dev/retrieval_profile_sweep.c") != 0 ||
        rps_copy(evaluator, sizeof evaluator, "ZCL_RETRIEVAL_EVAL", root,
                 "build/bin/retrieval-eval") != 0 ||
        rps_copy(jsonq, sizeof jsonq, "ZCL_JSONQ", root, "build/bin/jsonq") != 0 ||
        rps_copy(sha3, sizeof sha3, "ZCL_AGENT_SHA3", root,
                 "build/bin/agent_sha3") != 0) {
        rps_main_fail("tool path does not fit");
        return 1;
    }
    tools.checker = checker;
    tools.evaluator = evaluator;
    tools.jsonq = jsonq;
    tools.sha3 = sha3;
    tools.receipt = receipt;
    tools.sweep_source = source;
    return zcl_retrieval_profile_sweep(argv[0], argc, argv, &tools);
}
