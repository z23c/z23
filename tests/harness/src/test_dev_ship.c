/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Acceptance for dev.ship phase 1 (tools/command/native_dev_ship.c) and its
 * parity with `tools/ship.sh --dry-run`.
 *
 * Every case runs against one throwaway git repository with a local bare
 * origin under the test tmpdir. The repository carries committed copies of
 * tools/ship.sh, the four libraries it sources and tools/dev/source-identity.sh,
 * because ship.sh only ever acts on the checkout it lives in. Both programs
 * see the same fixture state and must agree on the refusal class, the
 * persistent-schema one-way verdict, whether the gate is banked, the target
 * names and the source id.
 *
 * ship.sh runs with an explicit environment: HOME, ZCL_SCRATCH_DIR and
 * TMPDIR inside the tmpdir, and PATH led by generated stand-ins for ssh and
 * systemctl, so its dry run reaches no host and no service. The ssh
 * stand-in logs every call; the last case proves it was only ever asked
 * about the two fixture aliases. HEAD ahead of origin/main is the one
 * deliberate difference: ship.sh pushes first, dev.ship refuses. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(__APPLE__)
int test_dev_ship(void);
int test_dev_ship(void)
{
    printf("test_dev_ship: skipped (ship.sh needs bash 4 and Linux)\n");
    return 0;
}
#else
#include <sys/stat.h>

#define DSX_PATH 768
#define DSX_HOSTS "shipfix-a shipfix-p shipfix-b"
#define DSX_PROOF "shipfix-p"
#define DSX_SCHEMA_FILE "engine/models/src/database_fixture.c"

static const char *const dsx_copied[] = {
    "tools/ship.sh",
    "tools/scripts/source_identity_lib.sh",
    "tools/scripts/tor_stamp_lib.sh",
    "tools/scripts/tor_provenance_lib.sh",
    "tools/scripts/ship_progress_lib.sh",
    "tools/dev/source-identity.sh",
};

static const char *const dsx_tor_archives[] = {
    "vendor/tor/libtor.a",
    "vendor/tor/src/ext/ed25519/donna/libed25519_donna.a",
    "vendor/tor/src/ext/ed25519/ref10/libed25519_ref10.a",
    "vendor/tor/src/ext/keccak-tiny/libkeccak-tiny.a",
};

/* ssh stand-in: answers the preflight probes and the dry-run executable
 * read; every other remote command (the fleet status read) fails. */
static const char dsx_ssh_shim[] =
    "#!/bin/sh\n"
    "printf '%s\\n' \"$*\" >> \"$SHIP_FIXTURE_SSH_LOG\"\n"
    "case \"$*\" in\n"
    "  *cpuinfo*) printf '%s||2.99\\n' \"$(uname -m)\"; exit 0 ;;\n"
    "  *readlink*) printf '/opt/shipfix/zclassic23\\n'; exit 0 ;;\n"
    "  *' true') exit 0 ;;\n"
    "esac\n"
    "exit 1\n";

struct dsx {
    char base[512];
    char repo[DSX_PATH], origin[DSX_PATH], home[DSX_PATH];
    char scratch[DSX_PATH], tmp[DSX_PATH], shim[DSX_PATH];
    char ssh_log[DSX_PATH];
    char *saved_home, *saved_tmp;
};

struct dsx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

/* What one `ship.sh --dry-run` printed, reduced to the compared facts. */
struct dsx_sh {
    int rc;
    char cls[40];
    bool banked;
    bool pushing_first;
    bool forward_only;
    char hosts[256];
    char source16[17];
    char text[65536];
};

/* ── fixture plumbing ───────────────────────────────────────────────────── */

static void dsx_die(const char *what, const char *path)
{
    fprintf(stderr, "dev_ship fixture: %s %s\n", what, path);
    abort();
}

static void dsx_mkdirs(const char *path)
{
    char buf[DSX_PATH];
    (void)snprintf(buf, sizeof(buf), "%s", path);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        (void)mkdir(buf, 0700);
        *p = '/';
    }
    (void)mkdir(buf, 0700);
}

static void dsx_write(const char *path, const char *text, mode_t mode)
{
    char dir[DSX_PATH];
    (void)snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash)
        *slash = '\0';
    dsx_mkdirs(dir);
    FILE *fp = fopen(path, "w");
    if (!fp)
        dsx_die("cannot write", path);
    (void)fputs(text, fp);
    (void)fclose(fp);
    (void)chmod(path, mode);
}

static char *dsx_slurp(const char *path)
{
    FILE *fp = fopen(path, "rb");
    char *buf;
    long n;
    if (!fp)
        dsx_die("cannot read", path);
    (void)fseek(fp, 0, SEEK_END);
    n = ftell(fp);
    (void)fseek(fp, 0, SEEK_SET);
    buf = calloc(1, (size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, fp) != (size_t)n)
        dsx_die("cannot load", path);
    (void)fclose(fp);
    return buf;
}

static void dsx_copy_into_repo(const struct dsx *fx, const char *rel)
{
    char dst[DSX_PATH + 128];
    char *text = dsx_slurp(rel);
    (void)snprintf(dst, sizeof(dst), "%s/%s", fx->repo, rel);
    dsx_write(dst, text, 0755);
    free(text);
}

static int dsx_run(const char *cwd, const char *const argv[], char *out,
                   size_t cap)
{
    char sink[256];
    bool timed_out = false;
    int rc = zcl_spawn_capture_in_dir_observed(argv, cwd, out ? out : sink,
                                               out ? cap : sizeof(sink),
                                               120000, &timed_out);
    return timed_out ? -1 : rc;
}

/* git in the fixture checkout; argv after "git -C <repo>". */
static void dsx_git(const struct dsx *fx, const char *const args[])
{
    const char *argv[16] = { "git", "-C", fx->repo };
    size_t n = 3;
    for (size_t i = 0; args[i] && n < 15; i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    if (dsx_run(fx->base, argv, NULL, 0) != 0)
        dsx_die("git failed:", args[0]);
}

static void dsx_commit(const struct dsx *fx, const char *msg)
{
    dsx_git(fx, (const char *const[]){ "add", "-A", NULL });
    dsx_git(fx, (const char *const[]){ "commit", "-q", "-m", msg, NULL });
}

static void dsx_repo_config(const struct dsx *fx)
{
    char hooks[DSX_PATH + 16];
    (void)snprintf(hooks, sizeof(hooks), "%s/nohooks", fx->base);
    dsx_git(fx, (const char *const[]){ "config", "user.email",
                                       "fixture@ship.example", NULL });
    dsx_git(fx, (const char *const[]){ "config", "user.name", "fixture", NULL });
    dsx_git(fx, (const char *const[]){ "config", "commit.gpgsign", "false",
                                       NULL });
    dsx_git(fx, (const char *const[]){ "config", "core.hooksPath", hooks,
                                       NULL });
}

/* Ignored build/ and vendor/ outputs ship.sh's tor preflight reads: the four
 * archives and a provenance stand-in that accepts them. */
static void dsx_tor_outputs(const struct dsx *fx)
{
    char path[DSX_PATH + 128];
    for (size_t i = 0; i < sizeof(dsx_tor_archives) / sizeof(*dsx_tor_archives);
         i++) {
        (void)snprintf(path, sizeof(path), "%s/%s", fx->repo,
                       dsx_tor_archives[i]);
        dsx_write(path, "fixture archive\n", 0644);
    }
    (void)snprintf(path, sizeof(path), "%s/build/bin/z23-tor-provenance",
                   fx->repo);
    dsx_write(path, "#!/bin/sh\nexit 0\n", 0755);
}

static void dsx_shims(const struct dsx *fx)
{
    char path[DSX_PATH + 32];
    (void)snprintf(path, sizeof(path), "%s/ssh", fx->shim);
    dsx_write(path, dsx_ssh_shim, 0755);
    (void)snprintf(path, sizeof(path), "%s/systemctl", fx->shim);
    dsx_write(path, "#!/bin/sh\nexit 1\n", 0755);
    (void)snprintf(path, sizeof(path), "%s/hardlink", fx->shim);
    dsx_write(path, "#!/bin/sh\necho 0\n", 0755);
}

static void dsx_paths(struct dsx *fx)
{
    test_make_tmpdir(fx->base, sizeof(fx->base), "dev_ship", "t");
    (void)snprintf(fx->repo, sizeof(fx->repo), "%s/repo", fx->base);
    (void)snprintf(fx->origin, sizeof(fx->origin), "%s/origin.git", fx->base);
    (void)snprintf(fx->home, sizeof(fx->home), "%s/home", fx->base);
    (void)snprintf(fx->scratch, sizeof(fx->scratch), "%s/scratch", fx->base);
    (void)snprintf(fx->tmp, sizeof(fx->tmp), "%s/tmp", fx->base);
    (void)snprintf(fx->shim, sizeof(fx->shim), "%s/shim", fx->base);
    (void)snprintf(fx->ssh_log, sizeof(fx->ssh_log), "%s/ssh.log", fx->base);
    dsx_mkdirs(fx->home);
    dsx_mkdirs(fx->scratch);
    dsx_mkdirs(fx->tmp);
    dsx_mkdirs(fx->repo);
}

static void dsx_fixture(struct dsx *fx)
{
    char path[DSX_PATH + 32];
    const char *bare[] = { "git", "init", "-q", "--bare", "-b", "main",
                           fx->origin, NULL };
    const char *init[] = { "git", "init", "-q", "-b", "main", fx->repo, NULL };
    if (dsx_run(fx->base, bare, NULL, 0) != 0 ||
        dsx_run(fx->base, init, NULL, 0) != 0)
        dsx_die("git init failed in", fx->base);
    dsx_repo_config(fx);
    for (size_t i = 0; i < sizeof(dsx_copied) / sizeof(*dsx_copied); i++)
        dsx_copy_into_repo(fx, dsx_copied[i]);
    (void)snprintf(path, sizeof(path), "%s/.gitignore", fx->repo);
    dsx_write(path, "/build/\n/vendor/\n", 0644);
    (void)snprintf(path, sizeof(path), "%s/README", fx->repo);
    dsx_write(path, "ship fixture v1\n", 0644);
    dsx_commit(fx, "base");
    dsx_git(fx, (const char *const[]){ "remote", "add", "origin", fx->origin,
                                       NULL });
    dsx_git(fx, (const char *const[]){ "push", "-q", "origin", "HEAD:main",
                                       NULL });
    dsx_git(fx, (const char *const[]){ "fetch", "-q", "origin", NULL });
    dsx_tor_outputs(fx);
    dsx_shims(fx);
}

static char *dsx_save_env(const char *name)
{
    const char *v = getenv(name);
    return v ? strdup(v) : NULL;
}

static void dsx_restore_env(const char *name, char *saved)
{
    if (saved)
        (void)setenv(name, saved, 1);
    else
        (void)unsetenv(name);
    free(saved);
}

/* The in-process leaf sees the same HOME and TMPDIR ship.sh is given. */
static void dsx_env_enter(struct dsx *fx)
{
    fx->saved_home = dsx_save_env("HOME");
    fx->saved_tmp = dsx_save_env("TMPDIR");
    (void)setenv("HOME", fx->home, 1);
    (void)setenv("TMPDIR", fx->tmp, 1);
}

static void dsx_env_leave(struct dsx *fx)
{
    dsx_restore_env("HOME", fx->saved_home);
    dsx_restore_env("TMPDIR", fx->saved_tmp);
    (void)unsetenv("ZCL_SHIP_HOSTS");
    (void)unsetenv("ZCL_SHIP_REMOTE");
    (void)unsetenv("ZCL_SHIP_PROOF_SERVER");
    (void)unsetenv("ZCL_SHIP_ALLOW_PROOF_SERVER");
}

static void dsx_set_or_unset(const char *name, const char *value)
{
    if (value)
        (void)setenv(name, value, 1);
    else
        (void)unsetenv(name);
}

static void dsx_hosts(const char *hosts, const char *proof)
{
    (void)unsetenv("ZCL_SHIP_REMOTE");
    (void)unsetenv("ZCL_SHIP_ALLOW_PROOF_SERVER");
    dsx_set_or_unset("ZCL_SHIP_HOSTS", hosts);
    dsx_set_or_unset("ZCL_SHIP_PROOF_SERVER", proof);
}

/* ── dev.ship ───────────────────────────────────────────────────────────── */

/* flags: 'd' dry_run, 's' skip_gate, 'a' accept_one_way. */
static void dsx_ship(struct dsx_call *c, const struct dsx *fx,
                     const char *targets, const char *flags)
{
    json_init(&c->input);
    json_set_object(&c->input);
    (void)json_push_kv_str(&c->input, "root", fx->repo);
    if (targets)
        (void)json_push_kv_str(&c->input, "targets", targets);
    (void)json_push_kv_bool(&c->input, "dry_run", strchr(flags, 'd') != NULL);
    (void)json_push_kv_bool(&c->input, "skip_gate", strchr(flags, 's') != NULL);
    (void)json_push_kv_bool(&c->input, "accept_one_way",
                            strchr(flags, 'a') != NULL);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    c->request.spec =
        zcl_command_registry_find(zcl_command_catalog(), "dev.fleet.ship", NULL);
    zcl_command_reply_init(&c->reply, "zcl.dev_ship.v1");
    zcl_native_handle_dev_ship(&c->request, &c->reply);
}

static void dsx_end(struct dsx_call *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static const struct json_value *dsx_at(const struct dsx_call *c,
                                       const char *path)
{
    char buf[128];
    const struct json_value *v = &c->reply.data;
    char *save = NULL;
    (void)snprintf(buf, sizeof(buf), "%s", path);
    for (char *k = strtok_r(buf, ".", &save); k && v;
         k = strtok_r(NULL, ".", &save))
        v = json_get(v, k);
    return v;
}

static const char *dsx_str(const struct dsx_call *c, const char *path)
{
    const struct json_value *v = dsx_at(c, path);
    return v && v->type == JSON_STR ? json_get_str(v) : "";
}

static bool dsx_bool(const struct dsx_call *c, const char *path)
{
    const struct json_value *v = dsx_at(c, path);
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static int64_t dsx_int(const struct dsx_call *c, const char *path)
{
    const struct json_value *v = dsx_at(c, path);
    return v && v->type == JSON_INT ? json_get_int(v) : -12345;
}

/* The refusal class, or "" for a ready plan. */
static const char *dsx_class(const struct dsx_call *c)
{
    return dsx_str(c, "refusal.class");
}

static void dsx_join(const struct json_value *arr, const char *key, char *out,
                     size_t cap)
{
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; arr && arr->type == JSON_ARR && i < arr->num_children;
         i++) {
        const struct json_value *item = &arr->children[i];
        const struct json_value *v = key ? json_get(item, key) : item;
        int n = snprintf(out + used, cap - used, "%s%s", used ? " " : "",
                         v ? json_get_str(v) : "?");
        used += n > 0 && (size_t)n < cap - used ? (size_t)n : 0;
    }
}

static void dsx_host_names(const struct dsx_call *c, char *out, size_t cap)
{
    dsx_join(dsx_at(c, "hosts"), "name", out, cap);
}

static bool dsx_host_redacted(const struct dsx_call *c, size_t index)
{
    const struct json_value *hosts = dsx_at(c, "hosts");
    const struct json_value *v =
        hosts && hosts->type == JSON_ARR && index < hosts->num_children
            ? json_get(&hosts->children[index], "redacted")
            : NULL;
    return v && v->type == JSON_BOOL && json_get_bool(v);
}

static void dsx_schema_files(const struct dsx_call *c, char *out, size_t cap)
{
    dsx_join(dsx_at(c, "schema_one_way.files"), NULL, out, cap);
}

static bool dsx_reply_mentions(const struct dsx_call *c, const char *needle)
{
    char *buf = malloc(65536);
    bool found;
    if (!buf)
        return true;
    (void)json_write(&c->reply.data, buf, 65536);
    found = strstr(buf, needle) != NULL ||
            strstr(c->reply.error.message, needle) != NULL;
    free(buf);
    return found;
}

/* ── tools/ship.sh --dry-run ────────────────────────────────────────────── */

static const struct {
    const char *needle;
    const char *cls;
} dsx_sh_refusals[] = {
    { "unknown target", "unknown_target" },
    { "remote target needs ZCL_SHIP_HOSTS", "remote_hosts_unset" },
    { "invalid SSH host", "invalid_host" },
    { "duplicate SSH host", "duplicate_host" },
    { "is the immutable proof server; promote deliberately",
      "proof_server_targeted" },
    { "working tree is dirty", "dirty_tree" },
    { "behind origin/main", "behind_origin" },
};

static void dsx_sh_class(struct dsx_sh *r)
{
    const char *refuse = strstr(r->text, "ship: REFUSE:");
    r->cls[0] = '\0';
    for (size_t i = 0;
         refuse && i < sizeof(dsx_sh_refusals) / sizeof(*dsx_sh_refusals);
         i++) {
        if (strstr(refuse, dsx_sh_refusals[i].needle)) {
            (void)snprintf(r->cls, sizeof(r->cls), "%s",
                           dsx_sh_refusals[i].cls);
            return;
        }
    }
    if (refuse)
        (void)snprintf(r->cls, sizeof(r->cls), "unclassified");
}

/* "plan was: <sha> -> targets=<t> hosts=<a b>" and the fleet table's local
 * row, whose second column is the first 16 hex of the source id. */
static void dsx_sh_plan(struct dsx_sh *r)
{
    const char *hosts = strstr(r->text, "plan was: ");
    const char *local = strstr(r->text, "\nlocal ");
    r->hosts[0] = r->source16[0] = '\0';
    hosts = hosts ? strstr(hosts, " hosts=") : NULL;
    if (hosts)
        (void)sscanf(hosts + 7, "%255[^\n]", r->hosts);
    if (strcmp(r->hosts, "none") == 0)
        r->hosts[0] = '\0';
    if (local)
        (void)sscanf(local + 7, " %16[0-9a-f]", r->source16);
}

static void dsx_sh_env(const struct dsx *fx, const char *hosts,
                       const char *proof, bool accept, char vars[][DSX_PATH],
                       const char *envp[])
{
    size_t n = 0;
    (void)snprintf(vars[n++], DSX_PATH, "PATH=%s:/usr/local/bin:/usr/bin:/bin",
                   fx->shim);
    (void)snprintf(vars[n++], DSX_PATH, "HOME=%s", fx->home);
    (void)snprintf(vars[n++], DSX_PATH, "ZCL_SCRATCH_DIR=%s", fx->scratch);
    (void)snprintf(vars[n++], DSX_PATH, "TMPDIR=%s", fx->tmp);
    (void)snprintf(vars[n++], DSX_PATH, "SHIP_HARDLINK_TOOL=%s/hardlink",
                   fx->shim);
    (void)snprintf(vars[n++], DSX_PATH, "SHIP_FIXTURE_SSH_LOG=%s", fx->ssh_log);
    (void)snprintf(vars[n++], DSX_PATH, "LANG=C");
    (void)snprintf(vars[n++], DSX_PATH, "ZCL_SHIP_HOSTS=%s", hosts ? hosts : "");
    (void)snprintf(vars[n++], DSX_PATH, "ZCL_SHIP_PROOF_SERVER=%s",
                   proof ? proof : "");
    (void)snprintf(vars[n++], DSX_PATH, "ZCL_SHIP_ACCEPT_ONE_WAY_SCHEMA=%s",
                   accept ? "1" : "0");
    for (size_t i = 0; i < n; i++)
        envp[i] = vars[i];
    envp[n] = NULL;
}

/* One `ship.sh --dry-run [arg] [arg]` in the fixture under `env -i` with the
 * fixture environment only, stderr folded into the captured stdout. */
static void dsx_ship_sh(struct dsx_sh *r, const struct dsx *fx,
                        const char *hosts, const char *proof, bool accept,
                        const char *arg1, const char *arg2)
{
    char vars[12][DSX_PATH];
    const char *envp[13];
    const char *argv[32];
    size_t n = 0;
    bool timed_out = false;
    dsx_sh_env(fx, hosts, proof, accept, vars, envp);
    argv[n++] = "env";
    argv[n++] = "-i";
    for (size_t i = 0; envp[i]; i++)
        argv[n++] = envp[i];
    argv[n++] = "bash";
    argv[n++] = "-c";
    argv[n++] = "exec 2>&1; exec bash tools/ship.sh --dry-run \"$@\"";
    argv[n++] = "ship-dry-run";
    argv[n++] = arg1;
    argv[n++] = arg1 ? arg2 : NULL;
    argv[n] = NULL;
    r->rc = zcl_spawn_capture_in_dir_observed(argv, fx->repo, r->text,
                                              sizeof(r->text), 120000,
                                              &timed_out);
    r->rc = timed_out ? -1 : r->rc;
    dsx_sh_class(r);
    r->banked = strstr(r->text, "banked for this exact source id") != NULL;
    r->pushing_first = strstr(r->text, "pushing first") != NULL;
    r->forward_only = strstr(r->text, "local FORWARD-ONLY") != NULL;
    dsx_sh_plan(r);
}

/* ship.sh's own two schema functions, cut out of the fixture's copy and run
 * against origin/main..HEAD: "rc=<0|1|2> files=<a b>". */
static void dsx_sh_schema_decision(const struct dsx *fx, bool accept,
                                   char *out, size_t cap)
{
    const char *script =
        "eval \"$(sed -n '/^ship_schema_files_changed() {/,/^}/p;"
        "/^ship_one_way_schema_decision() {/,/^}/p' tools/ship.sh)\"; "
        "changed=\"$(ship_schema_files_changed . origin/main HEAD)\"; rc=0; "
        "ship_one_way_schema_decision \"$changed\" \"$1\" || rc=$?; "
        "printf 'rc=%s files=%s' \"$rc\" \"$(printf '%s' \"$changed\" | "
        "tr '\\n' ' ')\"";
    const char *argv[] = { "bash", "-c", script, "ship-schema",
                           accept ? "1" : "0", NULL };
    if (dsx_run(fx->repo, argv, out, cap) != 0)
        (void)snprintf(out, cap, "bash failed");
}

/* The id both programs read: the fixture's own copy of the tool. */
static void dsx_capture_source_id(const struct dsx *fx, char out[96])
{
    const char *argv[] = { "tools/dev/source-identity.sh", "capture", NULL };
    if (dsx_run(fx->repo, argv, out, 96) != 0)
        out[0] = '\0';
    out[strcspn(out, "\n")] = '\0';
}

static struct dsx_sh *dsx_sh_new(void)
{
    struct dsx_sh *r = calloc(1, sizeof(*r));
    if (!r)
        dsx_die("out of memory for", "ship.sh facts");
    return r;
}

/* ── cases ──────────────────────────────────────────────────────────────── */

static int dsx_case_targets(const struct dsx *fx, struct dsx_sh *sh)
{
    int failures = 0;
    struct dsx_call c;
    TEST("ship: an unknown target is invalid input, ship.sh refuses it too") {
        dsx_hosts(DSX_HOSTS, NULL);
        dsx_ship(&c, fx, "local,staging", "d");
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "INVALID_INPUT");
        dsx_end(&c);
        dsx_ship_sh(sh, fx, DSX_HOSTS, NULL, false, "--targets=local,staging",
                    NULL);
        ASSERT_STR_EQ(sh->cls, "unknown_target");
        ASSERT(sh->rc != 0);
        PASS();
    }
    TEST("ship: remote with no configured hosts refuses in both") {
        dsx_hosts(NULL, NULL);
        dsx_ship(&c, fx, "remote", "d");
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(dsx_str(&c, "verdict"), "refuse");
        ASSERT_STR_EQ(dsx_class(&c), "remote_hosts_unset");
        dsx_end(&c);
        dsx_ship_sh(sh, fx, NULL, NULL, false, "--targets=remote", NULL);
        ASSERT_STR_EQ(sh->cls, "remote_hosts_unset");
        PASS();
    }
    TEST("ship: an invalid host refuses in both and is never echoed") {
        dsx_hosts("shipfix-a -oProxyCommand=evil", NULL);
        dsx_ship(&c, fx, "remote", "d");
        ASSERT_STR_EQ(dsx_class(&c), "invalid_host");
        ASSERT(!dsx_reply_mentions(&c, "ProxyCommand"));
        dsx_end(&c);
        dsx_ship_sh(sh, fx, "shipfix-a -oProxyCommand=evil", NULL, false,
                    "--targets=remote", NULL);
        ASSERT_STR_EQ(sh->cls, "invalid_host");
        PASS();
    }
    TEST("ship: a repeated host refuses in both") {
        dsx_hosts("shipfix-a shipfix-a", NULL);
        dsx_ship(&c, fx, "remote", "d");
        ASSERT_STR_EQ(dsx_class(&c), "duplicate_host");
        dsx_end(&c);
        dsx_ship_sh(sh, fx, "shipfix-a shipfix-a", NULL, false,
                    "--targets=remote", NULL);
        ASSERT_STR_EQ(sh->cls, "duplicate_host");
        PASS();
    }
_test_next:
    return failures;
}

static int dsx_case_proof_and_names(const struct dsx *fx, struct dsx_sh *sh)
{
    int failures = 0;
    struct dsx_call c;
    char names[256];
    TEST("ship: naming remote while the proof server is listed refuses") {
        dsx_hosts(DSX_HOSTS, DSX_PROOF);
        dsx_ship(&c, fx, "remote", "d");
        ASSERT_STR_EQ(dsx_class(&c), "proof_server_targeted");
        dsx_end(&c);
        dsx_ship_sh(sh, fx, DSX_HOSTS, DSX_PROOF, false, "--targets=remote",
                    NULL);
        ASSERT_STR_EQ(sh->cls, "proof_server_targeted");
        PASS();
    }
    TEST("ship: ZCL_SHIP_ALLOW_PROOF_SERVER=1 admits the proof server") {
        dsx_hosts(DSX_HOSTS, DSX_PROOF);
        (void)setenv("ZCL_SHIP_ALLOW_PROOF_SERVER", "1", 1);
        dsx_ship(&c, fx, "remote", "d");
        ASSERT_STR_EQ(dsx_str(&c, "verdict"), "ready");
        dsx_host_names(&c, names, sizeof(names));
        ASSERT_STR_EQ(names, DSX_HOSTS);
        ASSERT(dsx_bool(&c, "proof_server_promoted"));
        dsx_end(&c);
        PASS();
    }
    TEST("ship: an address-shaped destination is reported by position only") {
        dsx_hosts("shipfix-a ops@10.9.8.7 node.example.net", NULL);
        dsx_ship(&c, fx, "remote", "d");
        ASSERT_STR_EQ(dsx_str(&c, "verdict"), "ready");
        dsx_host_names(&c, names, sizeof(names));
        ASSERT_STR_EQ(names, "shipfix-a target-2 target-3");
        ASSERT(dsx_host_redacted(&c, 1));
        ASSERT(!dsx_host_redacted(&c, 0));
        ASSERT(!dsx_reply_mentions(&c, "10.9.8.7"));
        ASSERT(!dsx_reply_mentions(&c, "example.net"));
        dsx_end(&c);
        PASS();
    }
_test_next:
    return failures;
}

static int dsx_case_ready(const struct dsx *fx, struct dsx_sh *sh,
                          char source_id[96])
{
    int failures = 0;
    struct dsx_call c;
    char names[256];
    TEST("ship: a clean current checkout plans ready, matching ship.sh") {
        dsx_capture_source_id(fx, source_id);
        ASSERT(strlen(source_id) == 64);
        dsx_hosts(DSX_HOSTS, DSX_PROOF);
        dsx_ship(&c, fx, NULL, "d");
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(dsx_str(&c, "verdict"), "ready");
        ASSERT_STR_EQ(dsx_str(&c, "source_id"), source_id);
        ASSERT_STR_EQ(dsx_str(&c, "proof_server_skipped"), DSX_PROOF);
        ASSERT(!dsx_bool(&c, "gate.stamp_present"));
        ASSERT(!dsx_bool(&c, "gate.banked"));
        ASSERT_STR_EQ(dsx_str(&c, "schema_one_way.verdict"), "none");
        ASSERT_EQ(dsx_int(&c, "schema_one_way.decision_rc"), 0);
        ASSERT_EQ(dsx_int(&c, "checkout.ahead"), 0);
        dsx_host_names(&c, names, sizeof(names));
        dsx_end(&c);
        dsx_ship_sh(sh, fx, DSX_HOSTS, DSX_PROOF, false, NULL, NULL);
        ASSERT_EQ(sh->rc, 0);
        ASSERT_STR_EQ(sh->cls, "");
        ASSERT_STR_EQ(sh->hosts, names);
        ASSERT_STR_EQ(names, "shipfix-a shipfix-b");
        ASSERT(strstr(sh->text, "skipping " DSX_PROOF) != NULL);
        ASSERT(!sh->banked);
        ASSERT_EQ(strncmp(sh->source16, source_id, 16), 0);
        PASS();
    }
    TEST("ship: without dry_run a ready plan is BLOCKED, never a deploy") {
        dsx_ship(&c, fx, "local", "");
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_BLOCKED);
        ASSERT_STR_EQ(c.reply.error.code, "SHIP_DEPLOY_NOT_PORTED");
        dsx_end(&c);
        PASS();
    }
_test_next:
    return failures;
}

static int dsx_case_gate(const struct dsx *fx, struct dsx_sh *sh,
                         const char *source_id)
{
    int failures = 0;
    struct dsx_call c;
    char stamp[DSX_PATH + 128];
    TEST("ship: the gate is banked only under skip_gate with a stamp") {
        (void)snprintf(stamp, sizeof(stamp), "%s/.cache/zcl-ship/%s.passed",
                       fx->home, source_id);
        dsx_write(stamp, "2026-10-09T01:02:03Z\n", 0644);
        dsx_hosts(DSX_HOSTS, DSX_PROOF);
        dsx_ship(&c, fx, "local", "d");
        ASSERT(dsx_bool(&c, "gate.stamp_present"));
        ASSERT(!dsx_bool(&c, "gate.banked"));
        ASSERT_STR_EQ(dsx_str(&c, "gate.action"), "run_lint_and_full_suite");
        dsx_end(&c);
        dsx_ship_sh(sh, fx, DSX_HOSTS, DSX_PROOF, false, "--targets=local",
                    NULL);
        ASSERT(!sh->banked);
        dsx_ship(&c, fx, "local", "ds");
        ASSERT(dsx_bool(&c, "gate.banked"));
        ASSERT_STR_EQ(dsx_str(&c, "gate.stamp_at"), "2026-10-09T01:02:03Z");
        ASSERT_STR_EQ(dsx_str(&c, "gate.action"), "reuse_banked");
        dsx_end(&c);
        dsx_ship_sh(sh, fx, DSX_HOSTS, DSX_PROOF, false, "--targets=local",
                    "--skip-gate");
        ASSERT_EQ(sh->rc, 0);
        ASSERT(sh->banked);
        PASS();
    }
_test_next:
    return failures;
}

static int dsx_case_dirty_behind(const struct dsx *fx, struct dsx_sh *sh)
{
    int failures = 0;
    struct dsx_call c;
    char path[DSX_PATH + 32];
    TEST("ship: a dirty tree refuses in both, and fails without dry_run") {
        (void)snprintf(path, sizeof(path), "%s/stray.txt", fx->repo);
        dsx_write(path, "uncommitted\n", 0644);
        dsx_hosts(DSX_HOSTS, DSX_PROOF);
        dsx_ship(&c, fx, NULL, "d");
        ASSERT_STR_EQ(dsx_class(&c), "dirty_tree");
        dsx_end(&c);
        dsx_ship(&c, fx, NULL, "");
        ASSERT(c.reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(c.reply.error.code, "SHIP_REFUSED");
        ASSERT_STR_EQ(c.reply.error.evidence, "refusal.class=dirty_tree");
        dsx_end(&c);
        dsx_ship_sh(sh, fx, DSX_HOSTS, DSX_PROOF, false, NULL, NULL);
        ASSERT_STR_EQ(sh->cls, "dirty_tree");
        ASSERT_EQ(remove(path), 0);
        PASS();
    }
    TEST("ship: HEAD behind origin/main refuses in both") {
        (void)snprintf(path, sizeof(path), "%s/README", fx->repo);
        dsx_write(path, "ship fixture v2\n", 0644);
        dsx_commit(fx, "advance origin");
        dsx_git(fx, (const char *const[]){ "push", "-q", "origin",
                                           "HEAD:main", NULL });
        dsx_git(fx, (const char *const[]){ "reset", "-q", "--hard", "HEAD~1",
                                           NULL });
        dsx_ship(&c, fx, NULL, "d");
        ASSERT_STR_EQ(dsx_class(&c), "behind_origin");
        ASSERT_EQ(dsx_int(&c, "checkout.behind"), 1);
        dsx_end(&c);
        dsx_ship_sh(sh, fx, DSX_HOSTS, DSX_PROOF, false, NULL, NULL);
        ASSERT_STR_EQ(sh->cls, "behind_origin");
        dsx_git(fx, (const char *const[]){ "reset", "-q", "--hard",
                                           "origin/main", NULL });
        PASS();
    }
_test_next:
    return failures;
}

static int dsx_case_ahead(const struct dsx *fx, struct dsx_sh *sh)
{
    int failures = 0;
    struct dsx_call c;
    char path[DSX_PATH + 64], files[256], decision[512];
    TEST("ship: ahead refuses here where ship.sh would push first") {
        (void)snprintf(path, sizeof(path), "%s/README", fx->repo);
        dsx_write(path, "ship fixture v3\n", 0644);
        dsx_commit(fx, "unpushed readme");
        dsx_ship(&c, fx, "local", "d");
        ASSERT_STR_EQ(dsx_class(&c), "ahead_origin");
        ASSERT_STR_EQ(dsx_str(&c, "schema_one_way.verdict"), "none");
        dsx_end(&c);
        dsx_ship_sh(sh, fx, DSX_HOSTS, DSX_PROOF, false, "--targets=local",
                    NULL);
        ASSERT_STR_EQ(sh->cls, "");
        ASSERT(sh->pushing_first);
        ASSERT(!sh->forward_only);
        PASS();
    }
    TEST("ship: a schema change is would_refuse, rc 1, as ship.sh decides") {
        (void)snprintf(path, sizeof(path), "%s/" DSX_SCHEMA_FILE, fx->repo);
        dsx_write(path, "int fixture_schema;\n", 0644);
        dsx_commit(fx, "unpushed schema change");
        dsx_ship(&c, fx, "local", "d");
        ASSERT_STR_EQ(dsx_class(&c), "ahead_origin");
        ASSERT_STR_EQ(dsx_str(&c, "schema_one_way.verdict"), "would_refuse");
        ASSERT_EQ(dsx_int(&c, "schema_one_way.decision_rc"), 1);
        dsx_schema_files(&c, files, sizeof(files));
        ASSERT_STR_EQ(files, DSX_SCHEMA_FILE);
        dsx_end(&c);
        dsx_sh_schema_decision(fx, false, decision, sizeof(decision));
        ASSERT_STR_EQ(decision, "rc=1 files=" DSX_SCHEMA_FILE);
        dsx_ship_sh(sh, fx, DSX_HOSTS, DSX_PROOF, false, "--targets=local",
                    NULL);
        ASSERT(!sh->forward_only);
        PASS();
    }
    TEST("ship: accept_one_way is forward_only_accepted, rc 2, in both") {
        dsx_ship(&c, fx, "local", "da");
        ASSERT_STR_EQ(dsx_str(&c, "schema_one_way.verdict"),
                      "forward_only_accepted");
        ASSERT_EQ(dsx_int(&c, "schema_one_way.decision_rc"), 2);
        dsx_end(&c);
        dsx_sh_schema_decision(fx, true, decision, sizeof(decision));
        ASSERT_STR_EQ(decision, "rc=2 files=" DSX_SCHEMA_FILE);
        dsx_ship_sh(sh, fx, DSX_HOSTS, DSX_PROOF, true, "--targets=local",
                    NULL);
        ASSERT(sh->forward_only);
        ASSERT(strstr(sh->text, "schema file(s) changed: " DSX_SCHEMA_FILE) !=
               NULL);
        PASS();
    }
_test_next:
    return failures;
}

/* The ssh stand-in saw only the two fixture aliases ship.sh deploys to. */
static bool dsx_ssh_only_fixture_hosts(const struct dsx *fx)
{
    FILE *fp = fopen(fx->ssh_log, "r");
    char line[1024];
    bool ok = fp != NULL;
    while (ok && fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "-o ", 3) != 0)
            continue;
        ok = strstr(line, " shipfix-a ") || strstr(line, " shipfix-b ") ||
             strstr(line, " shipfix-a\n") || strstr(line, " shipfix-b\n");
    }
    if (fp)
        (void)fclose(fp);
    return ok;
}

static int dsx_case_containment(const struct dsx *fx)
{
    int failures = 0;
    TEST("ship: ship.sh's dry runs asked ssh only about fixture aliases") {
        ASSERT(dsx_ssh_only_fixture_hosts(fx));
        PASS();
    }
_test_next:
    return failures;
}

int test_dev_ship(void);
int test_dev_ship(void)
{
    struct dsx fx = { 0 };
    struct dsx_sh *sh = dsx_sh_new();
    char source_id[96] = "";
    int failures = 0;
    dsx_paths(&fx);
    dsx_env_enter(&fx);
    dsx_fixture(&fx);
    failures += dsx_case_targets(&fx, sh);
    failures += dsx_case_proof_and_names(&fx, sh);
    failures += dsx_case_ready(&fx, sh, source_id);
    failures += dsx_case_gate(&fx, sh, source_id);
    failures += dsx_case_dirty_behind(&fx, sh);
    failures += dsx_case_ahead(&fx, sh);
    failures += dsx_case_containment(&fx);
    dsx_env_leave(&fx);
    free(sh);
    printf(failures == 0 ? "test_dev_ship: all passed\n"
                         : "test_dev_ship: FAILED\n");
    return failures;
}
#endif
