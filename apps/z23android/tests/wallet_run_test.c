/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "operations.h"
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <errno.h>
#include <spawn.h>

#define TXID "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

static int spawn_error;   /* when set, the next posix_spawn fails with it */
int __real_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions, const posix_spawnattr_t *attr,
                       char *const argv[], char *const envp[]);
int __wrap_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions, const posix_spawnattr_t *attr,
                       char *const argv[], char *const envp[])
{
    return spawn_error ? spawn_error : __real_posix_spawn(pid, path, actions, attr, argv, envp);
}

/* Run with arguments, this program stands in for the node's command line: it prints what it was asked. */
static int fake_node(int argc, char **argv)
{
    static const char *const wallet_variables[] = {"ZCL_WALLET_PASSPHRASE", "ZCL_ALLOW_PLAINTEXT_WALLET", "ZCL_RECOVERY_PHRASE",
                                                   "ZCL_WALLET_NO_PHRASE_BACKUP"};
    for (size_t i = 0; i < sizeof(wallet_variables) / sizeof(wallet_variables[0]); ++i)
        if (getenv(wallet_variables[i])) return 9;
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
    /* The move of public funds into the private balance: its plan and its commit go to the shield command, input on stdin. */
    assert(zapp_wallet_send_run(r, "shieldplan", "{\"wallet_scope\":\"prod\"}", 60000, got, sizeof(got)));
    assert(strstr(got, "\"argv\":\"core wallet shielded shield -datadir=") && strstr(got, "--input=-"));
    assert(strstr(got, "\"stdin\":\"{\"wallet_scope\":\"prod\"}\"") && !strstr(got, "shielded send"));
    assert(zapp_wallet_send_run(r, "shieldcommit", "{\"confirm\":true}", 60000, got, sizeof(got)));
    assert(strstr(got, "core wallet shielded shield -datadir=") && strstr(got, "\"stdin\":\"{\"confirm\":true}\""));
    assert(zapp_wallet_send_run(r, "unlock", "{}", 60000, got, sizeof(got)) && strstr(got, "core wallet security unlock"));
    assert(zapp_wallet_send_run(r, "lock", NULL, 60000, got, sizeof(got)) && strstr(got, "core wallet security lock"));
    assert(!strstr(got, "--input"));
    assert(zapp_wallet_send_run(r, "summary", NULL, 60000, got, sizeof(got)) && strstr(got, "core wallet summary"));
    assert(zapp_wallet_send_run(r, "fleet", NULL, 60000, got, sizeof(got)) && strstr(got, "core wallet fleet status"));
    assert(zapp_wallet_send_run(r, "latest", NULL, 60000, got, sizeof(got)) && strstr(got, "core wallet shielded latest"));
    assert(zapp_wallet_send_run(r, "broadcast", NULL, 60000, got, sizeof(got)) && strstr(got, "core wallet broadcast status"));
}
/* Input where none is taken, none where it is required, no time, too much time, and any other command: refused. */
static void send_refusals_run(struct zapp_runtime *r)
{
    char got[512];
    assert(!zapp_wallet_send_run(r, "lock", "{}", 60000, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "plan", NULL, 60000, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "commit", "{}", 0, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "shieldplan", NULL, 60000, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "shieldcommit", "{}", 0, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "shieldcommit", "{}", ZAPP_WALLET_SEND_TIMEOUT_MAX_MS + 1, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "commit", "{}", ZAPP_WALLET_SEND_TIMEOUT_MAX_MS + 1, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_send_run(r, "summary", "{}", 60000, got, sizeof(got)));
    assert(!zapp_wallet_send_run(r, "broadcast", "{}", 60000, got, sizeof(got)));
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
    assert(zapp_wallet_send_run(r, "shieldcommit", "SLEEP", 1, got, sizeof(got)) && strstr(got, "\"stdin\":\"SLEEP\""));
    assert(!zapp_wallet_send_run(r, "shieldplan", "SLEEP", 300, got, sizeof(got)) && strstr(got, "timed out"));
    assert(ZAPP_WALLET_COMMIT_MIN_MS >= 300000u);
}

#define SECRET "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

/* Everything before the standard-input field of a fake node reply: the command line the node was given. */
static bool command_line_holds(const char *reply, const char *text)
{
    const char *end = strstr(reply, "\",\"stdin\"");
    const char *at = strstr(reply, text);
    return at && (!end || at < end);
}
static void setup_commands_run(struct zapp_runtime *r)
{
    char got[512];
    char request[200];
    snprintf(request, sizeof(request), "{\"passphrase\":\"%s\",\"phrase\":\"words\"}", SECRET);
    assert(zapp_wallet_setup_run(r, "create", request, 60000, got, sizeof(got)));
    assert(command_line_holds(got, "core wallet create -datadir=") && command_line_holds(got, "--input=-"));
    assert(!command_line_holds(got, SECRET) && !command_line_holds(got, "words") && strstr(got, SECRET));
    assert(zapp_wallet_setup_run(r, "restore", request, 60000, got, sizeof(got)));
    assert(command_line_holds(got, "core wallet recovery restore -datadir=") && !command_line_holds(got, SECRET) && strstr(got, SECRET));
    /* The new phrase needs no wallet files: it is asked for with nothing on standard input but an empty request. */
    assert(zapp_wallet_setup_run(r, "newphrase", "{}", 60000, got, sizeof(got)) && command_line_holds(got, "core wallet recovery new -datadir="));
}
/* Arguments the command does not take, and every other command, are refused without running anything. */
static void setup_refusals_run(struct zapp_runtime *r)
{
    char got[512];
    assert(!zapp_wallet_setup_run(r, "create", "{}", 0, got, sizeof(got)) && !strstr(got, "argv") && strstr(got, "\"code\":\"NOT_RUN\""));
    assert(!zapp_wallet_setup_run(r, "create", "{}", ZAPP_WALLET_SETUP_TIMEOUT_MAX_MS + 1, got, sizeof(got)) && !strstr(got, "argv"));
    assert(!zapp_wallet_setup_run(r, "create", NULL, 60000, got, sizeof(got)) && !zapp_wallet_setup_run(r, NULL, "{}", 60000, got, sizeof(got)));
    static const char *const other[] = {"unlock", "export", "send", "address", "", "Create", "blockhash "};
    for (size_t i = 0; i < sizeof(other) / sizeof(other[0]); ++i) {
        assert(!zapp_wallet_setup_run(r, other[i], "{}", 60000, got, sizeof(got)) && !strstr(got, "argv"));
        assert(strstr(got, "not available") || strstr(got, "did not answer") || strstr(got, "request"));
    }
    /* A command that was never started says so in a typed code, so the app can tell it from one that may have written. */
    spawn_error = EAGAIN;
    assert(!zapp_wallet_setup_run(r, "create", "{}", 60000, got, sizeof(got)) && strstr(got, "\"code\":\"NOT_RUN\"") && !atomic_load(&r->setup_running));
    assert(!zapp_wallet_setup_run(r, "restore", "{}", 60000, got, sizeof(got)) && strstr(got, "\"code\":\"NOT_RUN\""));
    spawn_error = 0;
    assert(zapp_wallet_setup_run(r, "status", "{\"datadir\":\"x\"}", 0, got, sizeof(got)) && command_line_holds(got, "core wallet recovery status -datadir="));
    assert(!zapp_wallet_setup_run(r, "blockhash", "[1]", 60000, got, sizeof(got)) && !strstr(got, "argv"));
}
/* Setup changes the files a node holds, so it refuses while a node runs. */
static void setup_node_running_run(struct zapp_runtime *r)
{
    char got[512];
    pid_t sleeper = fork();
    assert(sleeper >= 0);
    if (sleeper == 0) { sleep(30); _exit(0); }
    r->node = sleeper;
    assert(!zapp_wallet_setup_run(r, "create", "{}", 60000, got, sizeof(got)) && strstr(got, "Stop the node first") && !strstr(got, "argv"));
    assert(strstr(got, "\"code\":\"NOT_RUN\""));
    assert(zapp_wallet_setup_run(r, "status", "{}", 0, got, sizeof(got)) && command_line_holds(got, "core wallet recovery status"));
    assert(!zapp_wallet_setup_run(r, "restore", "{}", 60000, got, sizeof(got)) && strstr(got, "Stop the node first") && !strstr(got, "argv"));
    assert(zapp_wallet_setup_run(r, "newphrase", "{}", 60000, got, sizeof(got)) && command_line_holds(got, "core wallet recovery new") && !atomic_load(&r->setup_running));
    assert(kill(sleeper, SIGKILL) == 0 && waitpid(sleeper, NULL, 0) == sleeper);
    r->node = 0;
    assert(!atomic_load(&r->setup_running));
}
static void *setup_slowly(void *arg)
{
    char got[512];
    (void)zapp_wallet_setup_run(arg, "create", "SLEEP", 60000, got, sizeof(got));
    return NULL;
}
/* While a setup command runs the node cannot start, and a second setup command is refused. */
static void setup_exclusion_run(struct zapp_runtime *r)
{
    char got[512];
    pthread_t worker;
    assert(pthread_create(&worker, NULL, setup_slowly, r) == 0);
    for (int i = 0; i < 200 && !atomic_load(&r->setup_running); ++i) usleep(5000);
    assert(atomic_load(&r->setup_running));
    assert(!zapp_node_start(r, got, sizeof(got)) && strstr(got, "Wallet setup is running") && r->node == 0);
    assert(!zapp_wallet_setup_run(r, "restore", "{}", 60000, got, sizeof(got)) && strstr(got, "already running"));
    assert(pthread_join(worker, NULL) == 0 && !atomic_load(&r->setup_running));
}

/* No address is shown before setup is confirmed: the blob alone, an interrupted setup, does not open Receive. */
static void touch_in(const char *root, const char *name)
{
    char path[500];
    snprintf(path, sizeof(path), "%s/%s", root, name);
    FILE *f = fopen(path, "w");
    assert(f && fclose(f) == 0);
}
static void receive_gate_run(struct zapp_runtime *r, const char *root)
{
    char got[512], path[500];
    assert(!zapp_wallet_run(r, "receive", "", got, sizeof(got)) && strstr(got, "Finish wallet setup") && !strstr(got, "argv"));
    touch_in(root, "wallet_key.blob");
    assert(!zapp_wallet_run(r, "receive", "", got, sizeof(got)) && strstr(got, "Finish wallet setup") && !strstr(got, "argv"));
    assert(zapp_wallet_run(r, "summary", "", got, sizeof(got)));
    touch_in(root, "wallet_setup_done");
    assert(zapp_wallet_run(r, "receive", "", got, sizeof(got)) && strstr(got, "core wallet shielded receive"));
    snprintf(path, sizeof(path), "%s/wallet_key.blob", root); assert(unlink(path) == 0);
    assert(!zapp_wallet_run(r, "receive", "", got, sizeof(got)) && strstr(got, "Finish wallet setup"));
    touch_in(root, "wallet_key.blob");
}

/* The scratch directory comes from the caller: the test makes no path of its own. */
int main(int argc, char **argv)
{
    if (argc > 1) return fake_node(argc, argv);
    const char *root = getenv("ZAPP_TEST_DIR");
    char out[256], dir[400];
    struct zapp_runtime r = {0};
    assert(root && root[0] == '/');
    assert(setenv("ZCL_WALLET_PASSPHRASE", "decoy", 1) == 0 && setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1) == 0);
    assert(setenv("ZCL_RECOVERY_PHRASE", "decoy words", 1) == 0 && setenv("ZCL_WALLET_NO_PHRASE_BACKUP", "1", 1) == 0);
    assert(pthread_mutex_init(&r.mutex, NULL) == 0);
    snprintf(r.executable, sizeof(r.executable), "%s", argv[0]);
    snprintf(r.directory, sizeof(r.directory), "%s", root);
    snprintf(r.state_root, sizeof(r.state_root), "%s/state", root);
    snprintf(r.temporary_root, sizeof(r.temporary_root), "%s/tmp", root);
    assert(mkdir(r.state_root, 0700) == 0 && mkdir(r.temporary_root, 0700) == 0);

    snprintf(r.files, sizeof(r.files), "%s", root);
    receive_gate_run(&r, root);
    expect_args(&r, "summary", "", "core wallet summary");
    expect_args(&r, "fleet", "", "core wallet fleet status");
    expect_args(&r, "latest", "", "core wallet shielded latest");
    expect_args(&r, "broadcast", "", "core wallet broadcast status");
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
    setup_commands_run(&r);
    setup_refusals_run(&r);
    setup_node_running_run(&r);
    setup_exclusion_run(&r);

    r.preview = true;
    assert(!zapp_wallet_setup_run(&r, "create", "{}", 60000, out, sizeof(out)) && strstr(out, "\"code\":\"NOT_RUN\""));
    assert(!zapp_wallet_run(&r, "summary", "", out, sizeof(out)) && strstr(out, "no wallet"));
    r.preview = false;
    pthread_mutex_lock(&r.mutex); r.stopping = true; pthread_mutex_unlock(&r.mutex);
    assert(!zapp_wallet_run(&r, "summary", "", out, sizeof(out)) && strstr(out, "Unable to run native Z23"));

    snprintf(dir, sizeof(dir), "%s/wallet_key.blob", root); assert(unlink(dir) == 0);
    snprintf(dir, sizeof(dir), "%s/wallet_setup_done", root); assert(unlink(dir) == 0);
    snprintf(dir, sizeof(dir), "%s/state", root); assert(rmdir(dir) == 0);
    snprintf(dir, sizeof(dir), "%s/tmp", root); assert(rmdir(dir) == 0);
    pthread_mutex_destroy(&r.mutex);
    puts("wallet_run_test: ok");
    return 0;
}
