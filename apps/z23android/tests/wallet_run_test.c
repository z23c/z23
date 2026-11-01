/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "operations.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TXID "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

/* Run with arguments, this program stands in for the node's command line: it prints what it was asked. */
static int fake_node(int argc, char **argv)
{
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--input=-")) continue;
        char body[256] = "";
        size_t got = fread(body, 1, sizeof(body) - 1, stdin);
        body[got] = 0;
        if (strstr(body, "SLEEP")) sleep(2);
        printf("{\"ok\":true,\"data\":{\"argv\":\"");
        for (int j = 1; j < argc; ++j) printf("%s%s", j > 1 ? " " : "", argv[j]);
        printf("\",\"stdin\":\"%s\"}}\n", body);
        return 0;
    }
    printf("{\"ok\":true,\"data\":{\"argv\":\"");
    for (int i = 1; i < argc; ++i) printf("%s%s", i > 1 ? " " : "", argv[i]);
    printf("\"}}\n");
    return 0;
}

static void expect_args(struct zapp_runtime *r, const char *op, const char *arg, const char *want)
{
    char out[512], needle[256];
    snprintf(needle, sizeof(needle), "\"argv\":\"%s -datadir=", want);
    assert(zapp_wallet_run(r, op, arg, out, sizeof(out)));
    assert(strstr(out, needle));
}
static void expect_refused(struct zapp_runtime *r, const char *op, const char *arg, const char *why)
{
    char out[512];
    assert(!zapp_wallet_run(r, op, arg, out, sizeof(out)));
    assert(strstr(out, why) && !strstr(out, "argv"));
}

/* A send's commands: the payment goes on standard input, never on the command line. */
static void send_commands_run(struct zapp_runtime *r)
{
    char got[512];
    assert(zapp_wallet_send_run(r, "plan", "{\"to\":\"X\"}", 60000, got, sizeof(got)));
    assert(strstr(got, "\"argv\":\"core wallet shielded send -datadir=") && strstr(got, "--input=-"));
    assert(strstr(got, "\"stdin\":\"{\"to\":\"X\"}\""));
    assert(zapp_wallet_send_run(r, "unlock", "{}", 60000, got, sizeof(got)) && strstr(got, "core wallet security unlock"));
    assert(zapp_wallet_send_run(r, "lock", NULL, 60000, got, sizeof(got)) && strstr(got, "core wallet security lock"));
    assert(!strstr(got, "--input"));
    assert(zapp_wallet_send_run(r, "summary", NULL, 60000, got, sizeof(got)) && strstr(got, "core wallet summary"));
    assert(zapp_wallet_send_run(r, "fleet", NULL, 60000, got, sizeof(got)) && strstr(got, "core wallet fleet status"));
    assert(zapp_wallet_send_run(r, "latest", NULL, 60000, got, sizeof(got)) && strstr(got, "core wallet shielded latest"));
}
/* Input where none is taken, none where it is required, no time, too much time, and any other command: refused. */
static void send_refusals_run(struct zapp_runtime *r)
{
    char got[512];
    assert(!zapp_wallet_send_run(r, "lock", "{}", 60000, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "plan", NULL, 60000, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "commit", "{}", 0, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "commit", "{}", ZAPP_WALLET_SEND_TIMEOUT_MAX_MS + 1, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "summary", "{}", 60000, got, sizeof(got)));
    static const char *const other[] = {"export", "create", "restore", "send", "address", "history", "", "Plan"};
    for (size_t i = 0; i < sizeof(other) / sizeof(other[0]); ++i) {
        assert(!zapp_wallet_send_run(r, other[i], "{}", 60000, got, sizeof(got)));
        assert(strstr(got, "not available") && !strstr(got, "argv"));
    }
    assert(!zapp_wallet_send_run(r, "plan", "{}", 60000, got, 8) && !zapp_wallet_send_run(r, NULL, NULL, 1, got, sizeof(got)));
}
/* A step is killed at its own limit; a commit never sooner than its floor, so one second of work is not cut by a 1 ms limit. */
static void send_timeouts_run(struct zapp_runtime *r)
{
    char got[512];
    assert(!zapp_wallet_send_run(r, "plan", "SLEEP", 300, got, sizeof(got)) && strstr(got, "timed out"));
    assert(zapp_wallet_send_run(r, "commit", "SLEEP", 1, got, sizeof(got)) && strstr(got, "\"stdin\":\"SLEEP\""));
    assert(ZAPP_WALLET_COMMIT_MIN_MS >= 300000u);
}

/* The scratch directory comes from the caller: the test makes no path of its own. */
int main(int argc, char **argv)
{
    if (argc > 1) return fake_node(argc, argv);
    const char *root = getenv("ZAPP_TEST_DIR");
    char out[256], dir[400];
    struct zapp_runtime r = {0};
    assert(root && root[0] == '/');
    assert(pthread_mutex_init(&r.mutex, NULL) == 0);
    snprintf(r.executable, sizeof(r.executable), "%s", argv[0]);
    snprintf(r.directory, sizeof(r.directory), "%s", root);
    snprintf(r.state_root, sizeof(r.state_root), "%s/state", root);
    snprintf(r.temporary_root, sizeof(r.temporary_root), "%s/tmp", root);
    assert(mkdir(r.state_root, 0700) == 0 && mkdir(r.temporary_root, 0700) == 0);

    expect_args(&r, "summary", "", "core wallet summary");
    expect_args(&r, "fleet", "", "core wallet fleet status");
    expect_args(&r, "latest", "", "core wallet shielded latest");
    expect_args(&r, "receive", "", "core wallet shielded receive");
    expect_args(&r, "history", "", "core wallet history --limit=10");
    expect_args(&r, "history", "3000000:" TXID, "core wallet history --limit=10 --cursor=3000000:" TXID);
    expect_args(&r, "history", "p:" TXID, "core wallet history --limit=10 --cursor=p:" TXID);
    expect_args(&r, "detail", TXID, "core wallet history --txid=" TXID);

    /* An argument becomes a command-line argument, so only the exact forms pass. */
    static const char *const bad_cursor[] = {"x", "3000000", "3000000:", ("3000000:" TXID " --offer"), ("3000000: " TXID), ("-1:" TXID), ("q:" TXID),
        ("12345678901:" TXID), (":" TXID), ("3000000:" "ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"), ("3000000:" TXID "\n"),
        "--limit=1", ("3000000:" "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde")};
    for (size_t i = 0; i < sizeof(bad_cursor) / sizeof(bad_cursor[0]); ++i) expect_refused(&r, "history", bad_cursor[i], "not a history cursor");
    static const char *const bad_txid[] = {"", "x", (TXID "0"), "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef", (TXID " -x"),
        ("--txid=" TXID), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde;"};
    for (size_t i = 0; i < sizeof(bad_txid) / sizeof(bad_txid[0]); ++i) expect_refused(&r, "detail", bad_txid[i], "not a transaction id");
    expect_refused(&r, "summary", "--all", "takes no argument");
    expect_refused(&r, "receive", TXID, "takes no argument");

    /* Only the read commands and the diversified receive command exist here: nothing that spends, unlocks or mints a spending key, `address` included. */
    static const char *const refused[] = {"send", "unlock", "lock", "create", "restore", "export", "address", "", "summary ", "History"};
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); ++i) {
        assert(!zapp_wallet_run(&r, refused[i], "", out, sizeof(out)));
        assert(strstr(out, "not available"));
    }
    assert(!zapp_wallet_run(&r, NULL, "", out, sizeof(out)) && !zapp_wallet_run(&r, "summary", NULL, out, sizeof(out)));
    assert(!zapp_wallet_run(&r, "summary", "", out, 8));

    send_commands_run(&r);
    send_refusals_run(&r);
    send_timeouts_run(&r);

    r.preview = true;
    assert(!zapp_wallet_run(&r, "summary", "", out, sizeof(out)) && strstr(out, "no wallet"));
    r.preview = false;
    pthread_mutex_lock(&r.mutex); r.stopping = true; pthread_mutex_unlock(&r.mutex);
    assert(!zapp_wallet_run(&r, "summary", "", out, sizeof(out)) && strstr(out, "Unable to run native Z23"));

    snprintf(dir, sizeof(dir), "%s/state", root); assert(rmdir(dir) == 0);
    snprintf(dir, sizeof(dir), "%s/tmp", root); assert(rmdir(dir) == 0);
    pthread_mutex_destroy(&r.mutex);
    puts("wallet_run_test: ok");
    return 0;
}
