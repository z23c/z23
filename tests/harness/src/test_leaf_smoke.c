/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registry-driven smoke contract. Every READY read leaf that needs no
 * network, process, wallet or long-lived capability is run with empty input
 * as a CLI call against an empty scratch datadir with no node, so a leaf with
 * a required input must refuse it with a typed result rather than crash. Each
 * call runs in a forked child with a SIGALRM bound so a crash or hang fails
 * the leaf instead of the harness. Required of every such leaf: exit by
 * return (no signal), exactly one zcl.result.v1 document on stdout, and a
 * zcl.command_schema.v1 document on --help. Scope is selected from spec
 * fields; the named deny list holds leaves that by design wait for a node or
 * answer with a document other than zcl.result.v1. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SMOKE_CALL_BOUND_S 60U
/* Largest per-leaf response budget (65536) plus envelope slack. */
#define SMOKE_WIRE_CAP (65536U + 8192U)
#define SMOKE_NOT_SMOKED_CAPS \
    (ZCL_COMMAND_CAP_APP_SIMULATE | ZCL_COMMAND_CAP_PROCESS_EXEC | \
     ZCL_COMMAND_CAP_TEST_RUN | ZCL_COMMAND_CAP_COMPILER | \
     ZCL_COMMAND_CAP_HOTSWAP | ZCL_COMMAND_CAP_DEV_ACTIVATE | \
     ZCL_COMMAND_CAP_WALLET_REQUEST | ZCL_COMMAND_CAP_WEB | \
     ZCL_COMMAND_CAP_ONION | ZCL_COMMAND_CAP_P2P_TOPIC)

struct smoke_deny {
    const char *path;
    const char *reason;
};

static const struct smoke_deny smoke_deny_list[] = {
    { "core.node.bootwait", "waits its full 60 s default for a node boot by design" },
    { "discover.help", "by design prints the root zcl.command_menu.v1 document" },
};

enum smoke_scope {
    SMOKE_IN,
    SMOKE_NOT_READY_READ,
    SMOKE_NOT_SYNC,
    SMOKE_SLOW_LATENCY,
    SMOKE_EXTERNAL_CAP,
    SMOKE_DENIED,
    SMOKE_REASONS
};

static const char *const smoke_reason_names[SMOKE_REASONS] = {
    "in scope", "not READY read", "not a synchronous leaf",
    "background/persistent/maintenance latency",
    "network, process or wallet capability", "named deny list",
};

static enum smoke_scope smoke_classify(const struct zcl_command_spec *s)
{
    if (s->availability != ZCL_COMMAND_READY || !s->handler ||
        s->effect != ZCL_COMMAND_EFFECT_READ ||
        s->risk != ZCL_COMMAND_RISK_READ)
        return SMOKE_NOT_READY_READ;
    if (s->mode != ZCL_COMMAND_MODE_SYNC)
        return SMOKE_NOT_SYNC;
    if (s->latency >= ZCL_COMMAND_LATENCY_BACKGROUND)
        return SMOKE_SLOW_LATENCY;
    if (s->required_capabilities & SMOKE_NOT_SMOKED_CAPS)
        return SMOKE_EXTERNAL_CAP;
    for (size_t i = 0; i < sizeof(smoke_deny_list) / sizeof(smoke_deny_list[0]); i++)
        if (strcmp(s->path, smoke_deny_list[i].path) == 0)
            return SMOKE_DENIED;
    return SMOKE_IN;
}

/* The scratch datadir lives under the checkout's test-tmp, so an unconfined git
 * (dev.agent.triage) discovers the enclosing repository and triages every lane
 * branch with several git calls each: 41 s idle, past SMOKE_CALL_BOUND_S under
 * load. The leaf must meet an empty, repository-less directory: stop git's
 * upward discovery at the datadir's parent and drop any inherited repo pins. */
static bool smoke_confine_git(const char *datadir)
{
    char ceiling[PATH_MAX];
    int n = snprintf(ceiling, sizeof(ceiling), "%s", datadir);
    if (n < 0 || (size_t)n >= sizeof(ceiling))
        return false;
    char *slash = strrchr(ceiling, '/');
    if (slash && slash != ceiling)
        *slash = 0;
    return setenv("GIT_CEILING_DIRECTORIES", ceiling, 1) == 0 &&
           unsetenv("GIT_DIR") == 0 && unsetenv("GIT_WORK_TREE") == 0;
}

/* Child: stdout to `out`, stdin and stderr to /dev/null, HOME and cwd to the scratch
 * directory, one CLI call, then _exit with the CLI status. */
static void smoke_child(const struct zcl_command_spec *s, const char *datadir,
                        const char *out, bool help)
{
    const char *args[2];
    int n = 0;
    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int nul = open("/dev/null", O_RDWR);
    if (fd < 0 || nul < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
        dup2(nul, STDIN_FILENO) < 0 || dup2(nul, STDERR_FILENO) < 0)
        _exit(125);
    (void)setenv("HOME", datadir, 1);
    if (!smoke_confine_git(datadir) || chdir(datadir) != 0)
        _exit(125);
    if (help)
        args[n++] = "--help";
    else if (s->traits & ZCL_COMMAND_TRAIT_PROSE)
        args[n++] = "--format=json";
    (void)alarm(SMOKE_CALL_BOUND_S);
    int rc = zcl_native_command_main(s->path, args, n, datadir, 0, CHAIN_MAIN,
                                     false);
    fflush(stdout);
    _exit(rc & 0x7f);
}

static bool smoke_read(const char *path, char *wire, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    size_t n = fread(wire, 1, cap - 1, f);
    bool ok = !ferror(f) && n < cap - 1;
    wire[n] = 0;
    fclose(f);
    return ok;
}

/* Runs one call; false when the child died on a signal or output is unread. */
static bool smoke_run(const struct zcl_command_spec *s, const char *datadir,
                      bool help, char *wire, size_t cap)
{
    char out[PATH_MAX];
    int status = 0;
    snprintf(out, sizeof(out), "%s/out.json", datadir);
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0)
        smoke_child(s, datadir, out, help);
    if (pid < 0 || waitpid(pid, &status, 0) != pid)
        return false;
    if (WIFSIGNALED(status))
        printf("  %s: terminated by signal %d\n", s->path, WTERMSIG(status));
    bool read = WIFEXITED(status) && smoke_read(out, wire, cap);
    if (!read && WIFEXITED(status))
        printf("  %s: exit %d, output unreadable\n", s->path, WEXITSTATUS(status));
    return read;
}

static bool smoke_help_ok(const struct zcl_command_spec *s, const char *wire)
{
    return wire[0] == '{' && strstr(wire, s->path) != NULL &&
           strstr(wire, "zcl.command_schema.v1") != NULL;
}

static bool smoke_datadir_kept(const struct zcl_command_spec *s, const char *dir)
{
    if (access(dir, F_OK) == 0)
        return true;
    printf("  %s: removed the scratch datadir\n", s->path);
    (void)mkdir(dir, 0700);
    return false;
}

static bool smoke_leaf_ok(const struct zcl_command_spec *s, const char *dir,
                          char *wire, size_t cap)
{
    if (!smoke_run(s, dir, true, wire, cap)) {
        printf("  %s: --help did not complete\n", s->path);
        return false;
    }
    if (!smoke_help_ok(s, wire)) {
        printf("  %s: --help is not a zcl.command_schema.v1 document\n", s->path);
        return false;
    }
    bool ran = smoke_run(s, dir, false, wire, cap);
    if (!smoke_datadir_kept(s, dir))
        return false;
    if (!ran) {
        printf("  %s: run did not complete\n", s->path);
        return false;
    }
    if (!native_contract_single_result(wire)) {
        printf("  %s: run is not one zcl.result.v1 document: %.60s\n", s->path, wire);
        return false;
    }
    return true;
}

/* Mutating leaves outside the read smoke above. Every row must resolve in the
 * registry and render a zcl.command_schema.v1 document on --help. A row with
 * refuse set is also called with empty input in the scratch datadir, which
 * must answer one zcl.result.v1 refusal (ok=false, non-empty error.code) and
 * leave the datadir empty. Rows without it are the leaves where an empty call
 * would act or be handed to a live node or wallet (bind a socket, take the
 * node singleton, lock the wallet, sweep the real worktree pools, sample the
 * host, write a seed or KPI record, or settle or arm a spend through a node
 * RPC that does not refuse locally); those are checked for resolution and
 * schema only. */
struct contract_row {
    const char *path;
    bool refuse;
};

static const struct contract_row contract_rows[] = {
    { "lab.promote", true }, { "lab.test", true },
    { "plugin.call", true }, { "code.kpi", false },
    { "dev.fleet.mind.serve", false },
    { "dev.fleet.tunnel.allow", true }, { "dev.fleet.tunnel.close", true },
    { "dev.fleet.tunnel.deny", true }, { "dev.fleet.tunnel.open", true },
    { "ops.debug.rom_seed.disable", false },
    { "ops.debug.rom_seed.enable", false },
    { "ops.debug.rom_seed.publish", false },
    { "ops.host.gc", false }, { "ops.mesh.device.init", true },
    { "fleet.experiment.result", true }, { "fleet.join", true },
    { "fleet.link.probe", false }, { "fleet.steer.deliver", true },
    { "fleet.steer.drop", true }, { "fleet.vitals.sample", false },
    { "core.epoch.anchor", true }, { "core.wallet.address.label", true },
    { "core.wallet.recovery.restore", true },
    { "core.wallet.security.encrypt", true },
    { "core.wallet.security.lock", false }, { "vault.intent.cancel", false },
    { "vault.intent.commit", false }, { "vault.intent.issue", true },
    { "vault.send-token", false }, { "vault.swap.redeem", true },
    { "vault.swap.refund", true }, { "yardsale.buy", false },
    { "yardsale.seller.arm", false }, { "yardsale.seller.disarm", false },
};

static bool contract_refusal(const char *wire)
{
    size_t n = strlen(wire);
    struct json_value doc;
    if (!native_contract_single_result(wire) || !json_read(&doc, wire, n - 1))
        return false;
    bool ok = strcmp(json_get_str_or(&doc, "schema", ""), "zcl.result.v1") == 0 &&
              !json_get_bool(json_get(&doc, "ok")) &&
              json_get_str(json_get(json_get(&doc, "error"), "code"))[0] != 0;
    json_free(&doc);
    return ok;
}

/* True when `dir` holds nothing but the captured stdout file. */
static bool contract_dir_untouched(const char *dir)
{
    DIR *d = opendir(dir);
    size_t extra = 0;
    if (!d)
        return false;
    for (const struct dirent *e = readdir(d); e; e = readdir(d))
        extra += strcmp(e->d_name, ".") && strcmp(e->d_name, "..") &&
                 strcmp(e->d_name, "out.json");
    closedir(d);
    return extra == 0;
}

static bool contract_row_ok(const struct contract_row *r, const char *dir,
                            char *wire, size_t cap)
{
    const struct zcl_command_spec *s =
        zcl_command_registry_find(zcl_command_catalog(), r->path, NULL);
    if (!s || s->availability != ZCL_COMMAND_READY || !s->handler) {
        printf("  %s: not a READY leaf in the registry\n", r->path);
        return false;
    }
    if (!smoke_run(s, dir, true, wire, cap) || !smoke_help_ok(s, wire)) {
        printf("  %s: --help is not a zcl.command_schema.v1 document\n", r->path);
        return false;
    }
    if (!r->refuse)
        return true;
    if (!smoke_run(s, dir, false, wire, cap) || !contract_refusal(wire)) {
        printf("  %s: empty input is not a typed refusal: %.80s\n", r->path, wire);
        return false;
    }
    if (!contract_dir_untouched(dir)) {
        printf("  %s: refusal wrote into the scratch datadir\n", r->path);
        return false;
    }
    return true;
}

static int test_leaf_contract_rows(char *wire)
{
    int failures = 0;
    TEST_CASE("mutating leaves resolve, render schema and refuse empty input without writing") {
        char dir[PATH_MAX];
        size_t bad = 0;
        ASSERT(wire != NULL);
        test_make_tmpdir(dir, sizeof(dir), "leaf_smoke", "contract");
        for (size_t i = 0; i < sizeof(contract_rows) / sizeof(contract_rows[0]); i++)
            bad += !contract_row_ok(&contract_rows[i], dir, wire, SMOKE_WIRE_CAP);
        ASSERT_EQ(bad, (size_t)0);
        (void)test_rm_rf_recursive(dir);
    } TEST_END
    return failures;
}

int test_leaf_smoke(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    char *wire = malloc(SMOKE_WIRE_CAP);
    TEST_CASE("every READY no-input read leaf survives a no-node run and answers --help") {
        size_t counts[SMOKE_REASONS] = {0}, bad = 0;
        char dir[PATH_MAX];
        ASSERT(wire != NULL);
        test_make_tmpdir(dir, sizeof(dir), "leaf_smoke", "datadir");
        for (size_t i = 0; i < reg->count; i++) {
            const struct zcl_command_spec *s = &reg->commands[i];
            if (s->mode == ZCL_COMMAND_MODE_BRANCH)
                continue;
            enum smoke_scope scope = smoke_classify(s);
            counts[scope]++;
            if (scope == SMOKE_IN)
                bad += !smoke_leaf_ok(s, dir, wire, SMOKE_WIRE_CAP);
        }
        for (int r = 0; r < SMOKE_REASONS; r++)
            printf("  leaf smoke: %-42s %zu\n", smoke_reason_names[r], counts[r]);
        ASSERT(counts[SMOKE_IN] > 0);
        ASSERT_EQ(bad, (size_t)0);
        (void)test_rm_rf_recursive(dir);
    } TEST_END
    failures += test_leaf_contract_rows(wire);
    free(wire);
    return failures;
}

#else

int test_leaf_smoke(void)
{
    return 0;
}

#endif
