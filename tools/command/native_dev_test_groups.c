/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.test-groups, the leaf form of the former
 *          tools/dev/test-group-list.sh and test-registry-report.sh. It runs
 *          the one body (tools/dev/test_group_list.c) the standalone
 *          build/bin/test-group-list host tool runs, so the two cannot
 *          disagree. The result is the tool's own lines on stdout; the
 *          envelope follows on stderr. Exit 1 is no match or a refusal, exit
 *          2 a missing proof source or a bad mode. */

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "command/native_command.h"
#include "test_group_list.h"

#include <stdlib.h>
#include <string.h>

#define TG_MODE_MAX 32
#define TG_ARGS_MAX 64

/* The string option `key`, or "" when absent. */
static const char *tg_opt(const struct json_value *in, const char *key)
{
    const char *v = json_get_str(json_get(in, key));
    return v ? v : "";
}

/* argv = ["--mode" | "list", operand...]; operands split on blanks. */
static int tg_build_args(const char *mode, const char *operands,
                         char *store, size_t store_cap, const char **argv)
{
    int argc = 0;
    size_t used = 0;
    if (strlen(mode) >= TG_MODE_MAX)
        return -1;
    if (!mode[0] || strcmp(mode, "list") == 0)
        argv[argc++] = "list";
    else {
        used = (size_t)snprintf(store, store_cap, "--%s", mode) + 1;
        argv[argc++] = store;
    }
    for (const char *p = operands; *p;) {
        size_t len;
        while (*p == ' ' || *p == '\t' || *p == '\n')
            p++;
        len = strcspn(p, " \t\n");
        if (!len)
            break;
        if (argc >= TG_ARGS_MAX || used + len + 1 > store_cap)
            return -1;
        memcpy(store + used, p, len);
        store[used + len] = '\0';
        argv[argc++] = store + used;
        used += len + 1;
        p += len;
    }
    return argc;
}

static void tg_fail(struct zcl_command_reply *reply, int rc)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        rc == 2 ? ZCL_COMMAND_EXIT_INVALID : ZCL_COMMAND_EXIT_FAILED,
        rc == 2 ? "TEST_GROUPS_USAGE" : "TEST_GROUPS_REFUSED", "run", false,
        false, rc == 2 ? "missing proof source or bad mode"
                       : "no match, or the selection was refused",
        "z23-dev dev test-groups --mode=list");
}

void zcl_native_handle_dev_test_groups(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply)
{
    const struct json_value *in = request ? request->input : NULL;
    const char *argv[TG_ARGS_MAX + 1];
    char store[4096];
    struct tgl_sources src;
    int argc, rc;
    if (!reply)
        return;
    zcl_native_envelope_to_stderr();
    argc = tg_build_args(tg_opt(in, "mode"), tg_opt(in, "args"), store,
                         sizeof(store), argv);
    if (argc < 0) {
        tg_fail(reply, 2);
        return;
    }
    tgl_sources_from_env(&src);
    rc = tgl_run(&src, argc, argv, stdout, stderr);
    (void)fflush(stdout);
    if (rc != 0) {
        tg_fail(reply, rc);
        return;
    }
    (void)json_push_kv_str(&reply->data, "leaf", "dev.test-groups");
}
