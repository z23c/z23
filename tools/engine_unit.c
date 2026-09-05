/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_unit — dispatch ONE scoped unit of work to an engine, apply the
 * result in isolation, and judge it by running the gate.
 *
 *   THE MODEL PROPOSES. THE GATE DECIDES.
 *
 * The whole argument for this program is in engine/engine.h and
 * engine/engine_verdict.h. In one sentence: model output is not
 * reproducible, so it can never be evidence, and the verdict therefore comes
 * from running the unit's test group and reading how many groups actually
 * executed — never from an exit code, never from a report.
 *
 * This is the sole C23 engine-unit path. It preserves the predecessor shell
 * lane's measured lessons without retaining a second dispatcher.
 *
 * ── SAFETY BOUNDARIES, ALL FAIL-CLOSED ───────────────────────────────────
 *   - Dispatching consumes provider quota and may edit code; use --yes-dispatch
 *     on every single run. There is no config file that turns that off and no
 *     environment variable that implies it.
 *   - Work lands in an ISOLATED git worktree, never the caller's checkout.
 *   - The applier writes only contained relative paths under that worktree
 *     (engine/engine_patch.h). It cannot reach a datadir, and there is a live
 *     node on this host.
 *   - Nothing here pushes, deploys, or touches a datadir. A human reads the
 *     diff. That is not a policy this program enforces by asking nicely: it
 *     has no code that could do any of those things.
 *   - A timeout reports itself AS a timeout, never as a failure or a pass.
 *   - There is deliberately NO node command leaf for any of this, and so no
 *     row in config/remote_command_classes.def. A leaf would be a way to ask
 *     the node to spend money at a vendor, and the moment one exists the only
 *     thing standing between a stranger and that bill is a class annotation
 *     someone has to get right. A human runs this program with an argument
 *     vector; there is no wire that reaches it. If a leaf is ever added, it
 *     is REMOTE_CLASS_NEVER and that is not a judgement call.
 *
 * ── WHY THIS IS A TLS CLIENT AND NOT A curl PIPELINE ─────────────────────
 * tools/lint/check_no_shellouts.sh is right, and `curl` is a dependency a
 * stranger's machine may not have. This program uses the tree's own TLS
 * client (tools/acme/tls_client.h) and its own JSON parser. It is compiled
 * straight from source into its own executable, with no intermediate object
 * files, for the same reason zclassic23-acme is: nothing that references a
 * TLS-client or trust-store symbol may appear in a Z23 object file, and
 * tests/harness/src/test_cold_join_sovereign.c P2 asserts exactly that.
 *
 * ── A CLI ENGINE IS AN ENGINE, AND check-no-shellouts STILL HOLDS ────────
 * One of the registered engines is an installed agent CLI rather than an HTTP
 * API. Putting it behind the same interface is deliberate: the caller should
 * not have to know which of its engines happens to speak HTTP, and the
 * verdict must be computed the same way for all of them, or "the gate
 * decides" quietly becomes "the gate decides, except for that one".
 *
 * That does mean this program launches another program, so the tension with
 * tools/lint/check_no_shellouts.sh was checked rather than assumed, and it is
 * not a tension:
 *   - that gate protects the ALWAYS-RUNNING NODE binary. It scans app/, lib/,
 *     src/ and config/ for system(), popen() and execlp(), because a shell-out
 *     inside the resident process is what blocks the seccomp execve deny-list.
 *     Standalone tools under tools/ are out of its scope by design, and this
 *     is one: a human invokes it, the node never wraps it.
 *   - engine/modules/engine, which IS linked into the node, launches nothing
 *     at all. It has no spawn and no socket. Its one filesystem side effect
 *     is engine_receipt.c, which appends one caller-named JSONL ledger; every
 *     process this harness starts is still started from this file.
 *   - and it is not a shell-out in the first place. It goes through
 *     platform/modules/util zcl_spawn_capture, which execvp()s an argv directly. No
 *     /bin/sh, so no metacharacter ever expands, and nothing a model wrote
 *     can become a word in a command line.
 * If those three stop being true, the right answer is to fix this file, not
 * to widen the gate.
 */

#include "engine/engine.h"
#include "engine/engine_err.h"
#include "engine/engine_patch.h"
#include "engine/engine_prompt.h"
#include "engine/engine_receipt.h"
#include "engine/engine_secret.h"
#include "engine/engine_state.h"
#include "engine/engine_verdict.h"
#include "engine/engine_wire.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "platform/clock.h"
#include "sha3/sha3.h"
#include "tls_client.h"
#include "json/json.h"
#include "util/spawn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <direct.h>
#endif

static int unit_mkdir(const char *path, int mode)
{
#if defined(_WIN32)
    (void)mode;
    return _mkdir(path);
#else
    return mkdir(path, (mode_t)mode);
#endif
}

static int unit_environment_set(const char *name, const char *value)
{
#if defined(_WIN32)
    return _putenv_s(name, value) == 0 ? 0 : -1;
#else
    return setenv(name, value, 1);
#endif
}

static bool unit_path_is_absolute(const char *path)
{
    if (!path || !path[0])
        return false;
#if defined(_WIN32)
    bool drive = ((path[0] >= 'A' && path[0] <= 'Z') ||
                  (path[0] >= 'a' && path[0] <= 'z')) &&
                 path[1] == ':' && (path[2] == '/' || path[2] == '\\');
    bool unc = (path[0] == '/' || path[0] == '\\') &&
               (path[1] == '/' || path[1] == '\\');
    return drive || unc || path[0] == '/';
#else
    return path[0] == '/';
#endif
}

#define UNIT_MAX_TASK_BYTES   (128u * 1024u)
#define UNIT_GATE_LOG_BYTES   (2u * 1024u * 1024u)
#define UNIT_DEFAULT_TURNS    3
#define UNIT_DEFAULT_TIMEOUT  3600
#define UNIT_MAX_TIMEOUT      21600
/* A probe asks for a handful of tokens. If a vendor has not answered in half
 * a minute the interesting fact is that it did not, not what it eventually
 * says. */
#define UNIT_PROBE_TIMEOUT_MS 30000
/* What a probe allows the model to emit. It is NOT the smallest number a
 * vendor will bill, and the difference was measured on 2026-09-02: with 16
 * tokens GLM-5.3 spent the whole budget on reasoning_content, returned an
 * empty `content` with finish_reason "length", and the probe reported the
 * leg as broken when it was working. A reasoning model must be allowed to
 * finish thinking before it can say "ok". A thousand tokens of a flash model
 * is still a fraction of a cent, and a probe nobody believes is worth
 * nothing at any price. */
#define UNIT_PROBE_OUTPUT_TOKENS 1024
/* A CLI starts a runtime, reads a config and opens its own session before it
 * says anything, so it gets more room than one HTTPS round trip. */
#define UNIT_PROBE_CLI_TIMEOUT_MS 120000
#define UNIT_PROBE_LOG_BYTES      (256u * 1024u)

struct unit_opts {
    const char *engine_id;
    const char *task_path;
    const char *group;
    const char *territory;
    const char *kind;
    const char *model;
    const char *reasoning_effort;
    const char *worktree;
    const char *fixture_reply;
    const char *key_file;
    const char *state_dir;
    int    turns;
    int    timeout_s;
    /* The gate gets its own clock. A cold worktree compiles the whole tree
     * before it runs one assertion, and on a loaded box that is minutes of
     * honest work with nothing to do with how long the model was given. Share
     * one budget between them and a slow build is reported as a TIMEOUT, which
     * points an operator at the model when the answer was the compiler. 0
     * means "same as --timeout". */
    int    gate_timeout_s;
    double max_cost_usd;
    bool   no_group;
    bool   yes_dispatch;
    bool   dry_run;
    bool   list;
    bool   probe;
};

static void usage(void)
{
    printf(
"engine_unit — dispatch one scoped unit of work to an engine and judge it\n"
"\n"
"  engine_unit [--engine ID] --task FILE (--group NAME | --no-group)\n"
"              --territory NAME --yes-dispatch [options]\n"
"  engine_unit --list\n"
"  engine_unit --probe --yes-dispatch [--engine ID] [--model ID]\n"
"\n"
"  --engine ID       which engine (see --list). Defaults to the registry\n"
"                    default, which the run prints when it is used\n"
"  --task FILE       the unit of work, in prose: one job, named files, a bar\n"
"  --group NAME      the test group that must run and pass afterwards\n"
"  --no-group        for a unit that genuinely cannot have one; the verdict\n"
"                    is then UNVERIFIED, which is not a pass\n"
"  --kind KIND       which prompt template fills the sections (see --list).\n"
"                    Defaults to a `kind:` line in the task file's header.\n"
"                    A named kind that supplies no body for a required\n"
"                    section is refused; a unit with no kind at all carries\n"
"                    no template bodies and says so on the run\n"
"  --territory NAME  a territory the tree declares (see `z23 code territory`).\n"
"                    Its generated brief — owns, routes, reaches, the gates\n"
"                    that bind it, where its evidence is weakest — is put in\n"
"                    the prompt. A name the tree does not declare is refused.\n"
"  --yes-dispatch    REQUIRED. Dispatch consumes provider quota and may\n"
"                    apply scoped edits; opt in per run, never by default\n"
"  --worktree DIR    isolated worktree to work in (created if absent)\n"
"  --model ID        override the engine's default model\n"
"  --reasoning-effort E  provider_default, low, medium, high, or xhigh\n"
"  --turns N         repair turns when a reply does not apply (default %d)\n"
"  --timeout N       dispatch wall clock in seconds (default %d, max %d)\n"
"  --gate-timeout N  wall clock for the gate run; defaults to --timeout. A\n"
"                    cold worktree builds the tree first, which is minutes\n"
"                    of honest work that says nothing about the model\n"
"  --state-dir DIR   0700 directory for the prompt, gate log, and receipt\n"
"  --max-cost-usd X  refuse to continue past this reported spend\n"
"  --key-file PATH   a private key file outside the repo\n"
"  --fixture-reply F for --engine fixture: a canned response body\n"
"  --dry-run         print the composed prompt and exit without dispatching\n"
"  --probe           one minimal real call per HTTPS vendor; prints the\n"
"                    status, the latency and what came back. Needs\n"
"                    --yes-dispatch: it consumes the configured provider access\n"
"\n"
"Exit: 0 the unit landed and its group passed. 1 any other verdict —\n"
"      including TIMEOUT and including an engine that reported success and\n"
"      changed nothing. 2 usage or setup error. Never green by default.\n",
        UNIT_DEFAULT_TURNS, UNIT_DEFAULT_TIMEOUT, UNIT_MAX_TIMEOUT);
}

static void list_engines(void)
{
    printf("engines:\n");
    for (size_t i = 0; i < engine_count(); i++) {
        const struct engine_vendor *v = engine_at(i);
        printf("  %-10s %-46s %-6s%s\n", v->id, v->display,
               v->costs_money ? "SPENDS" : "free",
               v->is_default ? "  (default)" : "");
    }
    /* The kinds come from the same table --kind selects from, so a kind
     * printed here is a kind that can be chosen and a kind that can be
     * chosen is printed here. Two lists would eventually disagree. */
    printf("prompt template kinds (--kind):\n");
    for (size_t i = 0; i < engine_prompt_kind_count(); i++) {
        const char *k = engine_prompt_kind_at(i);
        printf("  %s\n", k ? k : "?");
    }
}

/* ── argument parsing ────────────────────────────────────────────────── */

static bool need_value(int argc, int i, const char *flag)
{
    if (i + 1 < argc)
        return true;
    LOG_FAIL("engine_unit", "%s needs a value", flag);
}

static bool parse_args(int argc, char **argv, struct unit_opts *o)
{
    memset(o, 0, sizeof(*o));
    o->turns = UNIT_DEFAULT_TURNS;
    o->timeout_s = UNIT_DEFAULT_TIMEOUT;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
#define TAKE(flag, field)                                   \
        if (strcmp(a, flag) == 0) {                         \
            if (!need_value(argc, i, flag)) return false; \
            o->field = argv[++i];                           \
            continue;                                       \
        }
        TAKE("--engine", engine_id)
        TAKE("--task", task_path)
        TAKE("--group", group)
        TAKE("--territory", territory)
        TAKE("--kind", kind)
        TAKE("--model", model)
        TAKE("--reasoning-effort", reasoning_effort)
        TAKE("--worktree", worktree)
        TAKE("--fixture-reply", fixture_reply)
        TAKE("--key-file", key_file)
        TAKE("--state-dir", state_dir)
#undef TAKE
        if (strcmp(a, "--turns") == 0 || strcmp(a, "--timeout") == 0
            || strcmp(a, "--gate-timeout") == 0
            || strcmp(a, "--max-cost-usd") == 0) {
            if (!need_value(argc, i, a))
                return false;
            const char *v = argv[++i];
            if (strcmp(a, "--turns") == 0)
                o->turns = atoi(v);
            else if (strcmp(a, "--timeout") == 0)
                o->timeout_s = atoi(v);
            else if (strcmp(a, "--gate-timeout") == 0)
                o->gate_timeout_s = atoi(v);
            else
                o->max_cost_usd = atof(v);
            continue;
        }
        if (strcmp(a, "--no-group") == 0)     { o->no_group = true;   continue; }
        if (strcmp(a, "--yes-dispatch") == 0) { o->yes_dispatch = true; continue; }
        if (strcmp(a, "--dry-run") == 0)      { o->dry_run = true;    continue; }
        if (strcmp(a, "--list") == 0)         { o->list = true;       continue; }
        if (strcmp(a, "--probe") == 0)        { o->probe = true;      continue; }
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage();
            exit(0);
        }
        LOG_FAIL("engine_unit", "unknown argument '%s'", a);
    }
    return true;
}

/* ── small file helpers ──────────────────────────────────────────────── */

static char *read_file(const char *path, size_t cap, size_t *out_len)
{
    if (out_len)
        *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        LOG_NULL("engine_unit", "cannot open %s", path);
    char *buf = zcl_malloc(cap + 1, "engine_unit_file");
    if (!buf) {
        (void)fclose(f);
        LOG_NULL("engine_unit", "cannot allocate %zu bytes for %s", cap + 1, path);
    }
    const size_t n = fread(buf, 1, cap, f);
    const bool over = (fgetc(f) != EOF);
    (void)fclose(f);
    if (over) {
        free(buf);
        LOG_NULL("engine_unit", "refusing %s: larger than its %zu-byte cap",
                 path, cap);
    }
    buf[n] = '\0';
    if (out_len)
        *out_len = n;
    return buf;
}

/* Run a program with no shell (zcl_spawn_capture: execvp, argv only) and
 * capture its stdout. stderr is discarded by that primitive's documented
 * contract; every token this harness judges on — the SUITE VERDICT line and
 * the pass/fail token — is written to stdout by tests/harness/src/test_parallel.c,
 * and a token that fails to arrive produces a REFUSED verdict rather than a
 * pass, so a lost message can never read as success. */
static int run(const char *const argv[], char *buf, size_t cap, int timeout_ms)
{
    return zcl_spawn_capture(argv, buf, cap, timeout_ms);
}

/* A CLI row owns its stdio transport choice. Both implementations exec the
 * exact argv with no shell and preserve the timeout observation; a vendor id
 * is never consulted here. */
static int run_cli(const struct engine_vendor *v, const char *const argv[],
                   char *buf, size_t cap, int timeout_ms, bool *timed_out)
{
    if (v->cli_needs_tty)
        return zcl_spawn_pty_capture_observed(
            argv, buf, cap, timeout_ms, timed_out);
    return zcl_spawn_capture_observed(
        argv, buf, cap, timeout_ms, timed_out);
}

/* ── the isolated worktree ───────────────────────────────────────────── */

static bool worktree_exists(const char *dir)
{
    struct stat st;
    return dir && stat(dir, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Create --state-dir if it is not there yet. Every artifact written into it
 * has passed through the redacting writer, but the directory itself is where
 * a transcript lands, so it is created 0700 and never 0755. A caller who
 * names a directory that cannot be created is told now, not once per write. */
static bool state_dir_prepare(const struct unit_opts *o)
{
    if (!o->state_dir || !o->state_dir[0])
        return true;
    if (!unit_path_is_absolute(o->state_dir))
        LOG_FAIL("engine_unit",
                 "refusing a relative --state-dir; pass an absolute path");
    if (unit_mkdir(o->state_dir, 0700) != 0 && errno != EEXIST)
        LOG_FAIL("engine_unit", "cannot create the state directory %s",
                 o->state_dir);
    struct stat st;
    if (stat(o->state_dir, &st) != 0 || !S_ISDIR(st.st_mode))
        LOG_FAIL("engine_unit", "--state-dir %s is not a directory",
                 o->state_dir);
    return true;
}

static bool worktree_prepare(const struct unit_opts *o, char *out, size_t out_len)
{
    if (!o->worktree || !o->worktree[0])
        LOG_FAIL("engine_unit",
                 "refusing to run without --worktree: a unit never edits the "
                 "caller's checkout");
    if (o->worktree[0] != '/')
        LOG_FAIL("engine_unit",
                 "refusing a relative --worktree; pass an absolute path");
    (void)snprintf(out, out_len, "%s", o->worktree);
    if (worktree_exists(out)) {
        engine_emit(stdout, "  worktree:   %s (existing)\n", out);
        return true;
    }
    char branch[256];
    (void)snprintf(branch, sizeof(branch), "engine/%s",
                   o->territory && o->territory[0] ? o->territory : "unit");
    const char *const add[] = { "git", "worktree", "add", "-b", branch,
                                out, "HEAD", NULL };
    char log[8192];
    if (run(add, log, sizeof(log), 120000) != 0)
        LOG_FAIL("engine_unit", "could not create the worktree at %s", out);

    /* A git worktree does NOT inherit vendor archives or submodules. Skip this
     * and the gate still builds — against the Tor STUB — and the failure
     * surfaces about twenty-five minutes later, at ship time, long after the
     * verdict was written. A gate that measured the wrong binary is exactly
     * the hollow green this program exists to refuse, so priming is part of
     * creating the worktree and its failure is the run's failure. */
    const char *const prime[] = { "make", "-C", out, "worktree-prime", NULL };
    if (run(prime, log, sizeof(log), 600000) != 0)
        LOG_FAIL("engine_unit",
                 "could not prime %s: without vendor archives the gate would "
                 "measure a stub build", out);
    engine_emit(stdout, "  worktree:   %s (created on %s, primed)\n", out,
                branch);
    return true;
}

/* How many tracked files the unit actually changed. This is measured from the
 * worktree, not claimed by the engine, and it is the input that makes
 * "reported success, changed nothing" reachable as a FAILURE. */
static size_t worktree_changed_files(const char *dir)
{
    const char *const argv[] = { "git", "-C", dir, "status", "--porcelain",
                                 NULL };
    char *buf = zcl_malloc(UNIT_GATE_LOG_BYTES, "engine_unit_status");
    if (!buf) {
        LOG_WARN("engine_unit", "cannot allocate the status buffer");
        return 0;
    }
    size_t count = 0;
    if (run(argv, buf, UNIT_GATE_LOG_BYTES, 60000) >= 0) {
        for (const char *p = buf; *p; p++) {
            if (*p == '\n')
                count++;
        }
    }
    free(buf);
    return count;
}

/* ── prompt composition ──────────────────────────────────────────────── */

/* The rules a unit must read before it writes C in this tree. Kept in one
 * place so the prompt and the parser cannot describe different contracts. */
/* The rules a unit is held to, and the decision about which wire carries
 * them, live in engine/modules/engine (engine/engine_prompt.h). They used to be a
 * static here, and being a static here is how they went missing from every
 * CLI dispatch: no test links this tool, so nothing could assert them. */


/* ── the territory brief ──────────────────────────────────────────────────
 *
 * --territory used to be an opaque label: a string the operator typed, copied
 * into the prompt and into the receipt, meaning whatever the operator hoped
 * it meant. A model told "Territory: core/modules/net" learns nothing it could not
 * have guessed from the task text.
 *
 * It now has to name a real territory, and the unit carries that territory's
 * generated brief — what it owns, which registered groups its files route to,
 * how many of its public functions a registered test entry point actually
 * reaches, and where its evidence is weakest. Every
 * number is regenerated from the code index by `code territory NAME` on this
 * run. This harness computes none of it and stores none of it, so the brief
 * cannot go stale the way a written one does.
 *
 * It does NOT carry which lint gates bind the territory. That analysis is
 * real — territory_brief_build() computes it — but it is wired into a
 * different command, `code general`, which this path never calls. This
 * comment claimed otherwise for as long as it existed, which meant a
 * reviewer reading it believed the model had been told which gates apply to
 * its change. It had not. Say what the command actually emits.
 *
 * It is fetched by RUNNING that command rather than by linking cognition/modules/territory,
 * and that is not laziness. cognition/modules/territory reaches the code index and
 * therefore SQLite, while this program is compiled straight to an executable
 * alongside a TLS client precisely so that none of its objects can ever
 * appear in a scanned epoch tree (see ENGINE_UNIT_SRCS in the Makefile, and
 * the P2 assertion in tests/harness/src/test_cold_join_sovereign.c that it keeps
 * honest). A subprocess leaves that property untouched.
 *
 * The exit status is checked but is not the evidence: zcl_spawn_capture
 * documents that it returns 0 when waitpid() fails ECHILD, so "0" can mean
 * "unknown". The evidence is the reply itself — it must parse, report ok, and
 * report found — which a lost or empty capture cannot fake.
 *
 * Fail-closed. If --territory is given and the brief cannot be obtained — no
 * binary, a command error, or a name the tree does not declare — the unit is
 * refused rather than dispatched with the old opaque label. Dispatching with
 * a label that means nothing is the thing being replaced.
 */

#define UNIT_BRIEF_BYTES   (64u * 1024u)
#define UNIT_BRIEF_TIMEOUT 180000   /* ms; a cold reach walk is seconds */

static const char *brief_binary(void)
{
    const char *e = getenv("ZCL_Z23_BIN");
    return (e && e[0]) ? e : "build/bin/z23-dev";
}

/* On success returns the canonical JSON reply on the heap. On failure returns
 * NULL and writes a reason a person can act on into `why`. */
static char *territory_brief_fetch(const char *name, char *why, size_t why_cap)
{
    const char *bin = brief_binary();
    char *buf = zcl_malloc(UNIT_BRIEF_BYTES, "engine_unit_brief");
    if (!buf) {
        (void)snprintf(why, why_cap, "cannot allocate the brief buffer");
        return NULL;
    }
    const char *const argv[] = { bin, "code", "territory", name, NULL };
    int rc = run(argv, buf, UNIT_BRIEF_BYTES, UNIT_BRIEF_TIMEOUT);
    if (rc != 0) {
        (void)snprintf(why, why_cap,
                       "`%s code territory %s` exited %d; build the binary "
                       "(make z23-dev) or point ZCL_Z23_BIN at one",
                       bin, name, rc);
        free(buf);
        return NULL;
    }
    struct json_value v;
    json_init(&v);
    if (!json_read(&v, buf, strlen(buf))) {
        (void)snprintf(why, why_cap, "%s did not answer with JSON", bin);
        json_free(&v);
        free(buf);
        return NULL;
    }
    const struct json_value *ok    = json_get(&v, "ok");
    const struct json_value *data  = json_get(&v, "data");
    const struct json_value *found = data ? json_get(data, "found") : NULL;
    bool usable = ok && json_get_bool(ok) && found && json_get_bool(found);
    json_free(&v);
    if (!usable) {
        (void)snprintf(why, why_cap,
                       "the tree declares no territory named %s; run "
                       "`%s code territory` for the list", name, bin);
        free(buf);
        return NULL;
    }
    return buf;
}

/* How the reply reaches the tree depends on the vendor's delivery, and only
 * on that. An API engine returns text, so it is told the file envelope. A CLI
 * engine already has the worktree open and edits it in place, so telling it
 * the envelope invites it to PRINT files instead of writing them — the one
 * output this harness would then apply twice, or not at all. */
static const char *delivery_text(const struct engine_vendor *v)
{
    if (v->delivery == ENGINE_DELIVERS_ENVELOPE)
        return engine_patch_protocol_text();
    return
"OUTPUT PROTOCOL — you are running inside the worktree this unit was given,\n"
"so edit its files directly with your own tools. Do NOT print file contents\n"
"as a reply: nothing you print is applied. What lands in the tree is exactly\n"
"what you wrote to disk, and that is what the gate is run against.\n";
}

/* The authored stance for a territory, or NULL when nobody has written one.
 * engine/modules/engine/include/engine/personas.def is the only place one exists, and
 * check-persona-resolves keeps every row pointing at things that still do.
 * A stance is pasted into a prompt and read nowhere else: nothing branches
 * on it and no verdict, gate or receipt is affected by whether one exists. */
static const char *persona_stance(const char *territory)
{
    if (!territory || !territory[0])
        return NULL;
#define PERSONA(t, stance, evidence) \
    if (strcmp(territory, (t)) == 0) return (stance);
#include "engine/personas.def"
#undef PERSONA
    return NULL;
}

/* Append one template body under a heading that is NOT a section marker.
 * Deliberately not a marker: the audit checks that the declared sections are
 * present and in order, and a template body inventing a second copy of a
 * marker would make that check pass for the wrong reason. */
static int append_body(char *p, size_t room, const char *heading,
                       const char *body)
{
    if (!body || !body[0])
        return 0;
    return snprintf(p, room, "%s\n\n%s\n\n", heading, body);
}

static char *compose_prompt(const struct unit_opts *o,
                            const struct engine_vendor *v, const char *task,
                            const char *brief, const char *carried_preamble,
                            const char *repair_note)
{
    const size_t cap = ENGINE_MAX_PROMPT_BYTES;
    char *p = zcl_malloc(cap, "engine_unit_prompt");
    if (!p)
        LOG_NULL("engine_unit", "cannot allocate the prompt buffer");
    int n = 0;
    /* Carried state leads everything else, including the kind's own
     * constraints: it is what THIS run already knows about itself, from an
     * earlier turn or an earlier attempt, and reading it after the task
     * would frame it as background instead of as the model's own memory. */
    if (carried_preamble && carried_preamble[0]) {
        const int pn = snprintf(p, cap, "%s", carried_preamble);
        if (pn < 0 || (size_t)pn >= cap) {
            free(p);
            LOG_NULL("engine_unit", "the composed prompt does not fit its cap");
        }
        n = pn;
    }
    /* The kind's own constraints lead the rest, because they are the frame
     * the task is read in. A unit that must not edit anything should learn
     * that before it reads a job description full of file names. */
    if (o->kind && o->kind[0]) {
        char heading[128];
        (void)snprintf(heading, sizeof(heading),
                       "# This is a %s unit", o->kind);
        const int kn = append_body(p + n, cap - (size_t)n, heading,
                                   engine_prompt_template_body(o->kind,
                                                               "rules"));
        if (kn < 0 || (size_t)kn >= cap - (size_t)n) {
            free(p);
            LOG_NULL("engine_unit", "the composed prompt does not fit its cap");
        }
        n += kn;
    }
    /* Each section is emitted, then its template body, so a body always
     * lands under the section it belongs to. Composing the whole prompt in
     * one format string is what made that impossible before. */
#define EMIT(expr)                                                            \
    do {                                                                      \
        const int emitted_ = (expr);                                          \
        if (emitted_ < 0 || (size_t)emitted_ >= cap - (size_t)n) {            \
            free(p);                                                          \
            LOG_NULL("engine_unit",                                           \
                     "the composed prompt does not fit its cap");             \
        }                                                                     \
        n += emitted_;                                                        \
    } while (0)

    EMIT(snprintf(p + n, cap - (size_t)n, "# Your unit of work\n\n%s\n\n",
                  task));
    EMIT(append_body(p + n, cap - (size_t)n, "## How to approach it",
                     engine_prompt_template_body(o->kind, "task")));

    int head;
    if (brief)
        head = snprintf(p + n, cap - (size_t)n,
            "# Territory %s\n\n"
            "What follows is the tree's own answer about this territory,\n"
            "regenerated from the code index on this run. It is not a written\n"
            "description and nobody maintains it by hand.\n"
            "\n"
            "Read `routed` and `reached` as the different facts they are.\n"
            "Routed says which registered group runs when a file here\n"
            "changes. Reached says a registered test entry point actually\n"
            "calls that public function. They are never added together, and\n"
            "`unknown` is the call graph refusing to answer — not a quiet\n"
            "vote for either neighbour.\n"
            "\n%s\n\n",
            o->territory, brief);
    else
        head = snprintf(p + n, cap - (size_t)n,
            "Territory: none declared.\n\n");
    if (head < 0 || (size_t)head >= cap - (size_t)n) {
        free(p);
        LOG_NULL("engine_unit", "the composed prompt does not fit its cap");
    }
    n += head;

    /* The authored half. The brief above is measured and regenerates itself;
     * this does not, and is the only thing in the prompt that somebody wrote
     * down about the territory rather than derived from it. It is kept apart
     * from the brief and labelled as authored so the model can tell which
     * claims a re-run would re-check and which are a standing decision. */
    const char *stance = persona_stance(o->territory);
    if (stance) {
        int sn = snprintf(p + n, cap - (size_t)n,
            "# What %s refuses\n\n"
            "This one is authored, not measured. It is a standing decision\n"
            "about what this territory must never become — the kind of thing\n"
            "no call graph can derive — and it holds whether or not the gate\n"
            "would catch a violation. Treat it as a constraint on the change.\n"
            "\n%s\n\n",
            o->territory, stance);
        if (sn < 0 || (size_t)sn >= cap - (size_t)n) {
            free(p);
            LOG_NULL("engine_unit", "the composed prompt does not fit its cap");
        }
        n += sn;
    }

    EMIT(snprintf(p + n, cap - (size_t)n, "# %s\n\n", delivery_text(v)));
    /* Model-neutral: the same instruction for glm, glm-cli and the fixture
     * engine, regardless of which of the two OUTPUT PROTOCOLs above applies.
     * See engine/engine_state.h for why this exists and what reads it. */
    EMIT(snprintf(p + n, cap - (size_t)n, "%s\n", engine_state_protocol_text()));
    EMIT(append_body(p + n, cap - (size_t)n, "## For this kind of unit",
                     engine_prompt_template_body(o->kind, "protocol")));
    EMIT(snprintf(p + n, cap - (size_t)n,
                  "# How this unit will be judged\n\n"));
    EMIT(append_body(p + n, cap - (size_t)n, "## The bar for this kind",
                     engine_prompt_template_body(o->kind, "judging")));
#undef EMIT

    int m;
    if (o->no_group) {
        m = snprintf(p + n, cap - (size_t)n,
            "This unit was dispatched with no test group. Say plainly in your\n"
            "reply what is therefore unverified. It will not be recorded as a\n"
            "pass.\n");
    } else {
        m = snprintf(p + n, cap - (size_t)n,
            "After your reply is applied, this exact command is run:\n"
            "    make t-fast-exact ONLY=%s\n"
            "Its machine-readable SUITE VERDICT line must report a NON-ZERO\n"
            "groups_ran, zero groups_failed, and a cold (not cached) run. A\n"
            "groups_ran of 0 means the group is registered with nothing in it,\n"
            "and counts as a FAILURE no matter what any exit code says.\n"
            "\n"
            "Nothing you write about your own work is read as evidence. If you\n"
            "change nothing, the outcome is recorded as a FAILURE even if the\n"
            "gate passes, because a passing gate over an unchanged tree is\n"
            "evidence about the tree and not about you.\n", o->group);
    }
    if (m < 0 || (size_t)(n + m) >= cap) {
        free(p);
        LOG_NULL("engine_unit", "the composed prompt does not fit its cap");
    }
    n += m;
    if (repair_note && repair_note[0]) {
        m = snprintf(p + n, cap - (size_t)n,
            "\n# A previous turn was not usable\n\n%s\n"
            "Send the whole reply again, corrected.\n", repair_note);
        if (m < 0 || (size_t)(n + m) >= cap) {
            free(p);
            LOG_NULL("engine_unit", "the composed prompt does not fit its cap");
        }
    }
    return p;
}

/* ── dispatch ────────────────────────────────────────────────────────── */

struct dispatch_result {
    struct engine_reply reply;
    struct engine_cli_observation cli_observation;
    enum engine_err     err;
    int                 http_status;
    int                 attempts;
    int64_t             dispatch_latency_ms;
};

/* The chainlog owns the durable sequence; this stack object only keeps the
 * bounded observations until that one record is appended. */
struct invocation_log {
    struct engine_receipt_invocation items[ENGINE_RECEIPT_INVOCATIONS_MAX];
    char session_ids[ENGINE_RECEIPT_INVOCATIONS_MAX]
                    [ENGINE_CLI_SESSION_ID_MAX];
    char resolved_models[ENGINE_RECEIPT_INVOCATIONS_MAX][96];
    size_t count;
    size_t session_count;
    bool totals_ambiguous;
};

static int64_t reported_counter(bool known, int64_t value)
{
    return known ? value : ENGINE_RECEIPT_UNREPORTED;
}

static bool invocation_log_has_room(const struct invocation_log *log)
{
    if (log->count < ENGINE_RECEIPT_INVOCATIONS_MAX)
        return true;
    LOG_FAIL("engine_unit",
             "refusing provider dispatch %zu: receipt invocation cap is %u",
             log->count + 1u, (unsigned)ENGINE_RECEIPT_INVOCATIONS_MAX);
}

static bool invocation_log_add(struct invocation_log *log, const char *phase,
                               bool ok, const struct dispatch_result *dr,
                               int64_t elapsed_ms)
{
    if (!invocation_log_has_room(log))
        return false;
    struct engine_receipt_invocation *in = &log->items[log->count];
    char *resolved_model = log->resolved_models[log->count];
    if (dr->reply.model[0])
        (void)snprintf(resolved_model, 96, "%s", dr->reply.model);
    else if (dr->cli_observation.known)
        (void)snprintf(resolved_model, 96, "%s",
                       dr->cli_observation.resolved_model);
    *in = (struct engine_receipt_invocation) {
        .ordinal = (int64_t)log->count + 1,
        .phase = phase,
        .result = ok ? "ok" : engine_err_name(dr->err),
        .elapsed_ms = elapsed_ms,
        .http_status = dr->http_status,
        .resolved_model = resolved_model[0] ? resolved_model : NULL,
        .prompt_tokens = reported_counter(dr->reply.usage.prompt_tokens_known,
                                           dr->reply.usage.prompt_tokens),
        .completion_tokens = reported_counter(
            dr->reply.usage.completion_tokens_known,
            dr->reply.usage.completion_tokens),
        .cache_read_input_tokens = reported_counter(
            dr->reply.usage.cache_read_input_tokens_known,
            dr->reply.usage.cache_read_input_tokens),
        .cache_creation_input_tokens = reported_counter(
            dr->reply.usage.cache_creation_input_tokens_known,
            dr->reply.usage.cache_creation_input_tokens),
        .reasoning_tokens = reported_counter(
            dr->reply.usage.reasoning_tokens_known,
            dr->reply.usage.reasoning_tokens),
        .total_tokens = reported_counter(dr->reply.usage.total_tokens_known,
                                          dr->reply.usage.total_tokens),
    };
    log->count++;

    /* A repeated structured session id may be a resumed session whose usage
     * is cumulative. Keep both raw observations, but refuse to sum them. */
    if (dr->cli_observation.known && dr->cli_observation.session_id[0]) {
        for (size_t i = 0; i < log->session_count; i++) {
            if (strcmp(log->session_ids[i],
                       dr->cli_observation.session_id) == 0) {
                log->totals_ambiguous = true;
                return true;
            }
        }
        (void)snprintf(log->session_ids[log->session_count],
                       ENGINE_CLI_SESSION_ID_MAX, "%s",
                       dr->cli_observation.session_id);
        log->session_count++;
    }
    return true;
}

/* One HTTPS attempt. The credential is built into a stack buffer here, handed
 * straight to the transport, and wiped before returning: it is never stored,
 * never formatted into a log line, and never reaches a receipt. */
static bool dispatch_https(const struct engine_vendor *v, const char *body,
                           size_t body_len, int timeout_ms,
                           struct dispatch_result *dr)
{
    char auth[ENGINE_SECRET_MAX + 32];
    if (!engine_secret_authorization_header(auth, sizeof(auth))) {
        dr->err = ENGINE_ERR_AUTH;
        return false;
    }
    const struct tls_client_header headers[] = {
        { .name = "Authorization", .value = auth },
    };
    const struct tls_client_request req = {
        .method       = "POST",
        .url          = engine_endpoint(v),
        .content_type = "application/json",
        .body         = body,
        .body_len     = body_len,
        .user_agent   = "zclassic23-engine-unit",
        .timeout_ms   = timeout_ms,
        .headers      = headers,
        .header_count = 1,
        .max_body     = ENGINE_MAX_RESPONSE_BYTES,
    };
    struct tls_client_response resp;
    const bool sent = tls_client_fetch(&req, &resp);
    {
        volatile char *wipe = auth;
        for (size_t i = 0; i < sizeof(auth); i++)
            wipe[i] = 0;
    }
    if (!sent) {
        dr->err = ENGINE_ERR_NETWORK;
        return false;
    }
    dr->http_status = resp.status;
    dr->err = engine_err_of_status(resp.status);
    bool ok = false;
    if (dr->err != ENGINE_OK) {
        char why[512];
        if (engine_response_error_text(resp.body, resp.body_len, why, sizeof(why))) {
            engine_emit(stderr, "engine_unit: %s said: %s\n", v->id, why);
            /* Both vendors measured on 2026-08-30 answer 429 for an empty
             * account. The status alone says "retry"; the body says "never".
             * Believe the body — but only when it makes the failure more
             * terminal. See engine_err_refine(). */
            dr->err = engine_err_refine(dr->err, why);
        }
    } else if (!engine_response_parse(v, resp.body, resp.body_len, &dr->reply)) {
        dr->err = ENGINE_ERR_PARSE;
    } else {
        ok = true;
    }
    tls_client_response_free(&resp);
    return ok;
}


static int fail_setup(const char *why);

/* ── the probe ────────────────────────────────────────────────────────────
 *
 * Every HTTPS vendor in the registry has been UNPROVEN since the day it was
 * added. The decoder is exercised against fixtures and against real ERROR
 * bodies, and both funded paths answered 429 on an empty account, so the
 * question "does this leg work at all" has never had an answer — only an
 * assumption. Everything built on top of it inherits that assumption.
 *
 * This makes one minimal call per vendor and prints what came back. It sends
 * a two-word prompt and asks for a handful of tokens, so the cost is the
 * smallest a vendor will bill. It writes nothing, applies nothing, and
 * touches no worktree: the only thing it produces is a fact.
 *
 * It is still a real call that spends real money, so it needs --yes-dispatch
 * like every other path that does. */
/* A CLI vendor is probed by running it, because that is what dispatch does.
 * The prompt is written to a temp file for a file-mode row and passed
 * directly for an argument-mode one, so the probe exercises the same seam
 * the real dispatch uses rather than a simplified one. */
static int probe_cli(const struct engine_vendor *v, const char *model_override,
                     const char *reasoning_effort)
{
    if (!v->program || !v->program[0]) {
        printf("NO PROGRAM IN ROW\n");
        return 1;
    }
    char prompt_file[512] = {0};
    const char *ask = "Reply with exactly: ok";
    if (v->cli_prompt == ENGINE_CLI_PROMPT_FILE) {
        const char *dir = getenv("TMPDIR");
        if (!dir || !dir[0]) dir = "/tmp";
        if ((size_t)snprintf(prompt_file, sizeof(prompt_file),
                             "%s/z23-probe-%ld.txt", dir, (long)getpid())
            >= sizeof(prompt_file)) {
            printf("TEMP PATH TOO LONG\n");
            return 1;
        }
        if (!engine_emit_file(prompt_file, ask, strlen(ask))) {
            printf("COULD NOT WRITE THE PROBE PROMPT\n");
            return 1;
        }
    }
    const struct engine_cli_inputs in = {
        .prompt  = v->cli_prompt == ENGINE_CLI_PROMPT_ARG ? ask : prompt_file,
        .workdir = ".",
        .turns   = "1",
        .model   = model_override ? model_override : v->default_model,
        .reasoning_effort = reasoning_effort,
    };
    const char *argv[ENGINE_CLI_ARGV_MAX];
    if (engine_cli_argv_build(v, &in, argv, ENGINE_CLI_ARGV_MAX) == 0) {
        printf("ARGV REFUSED\n");
        if (prompt_file[0]) (void)remove(prompt_file);
        return 1;
    }
    char *log = zcl_malloc(UNIT_PROBE_LOG_BYTES, "engine_unit_probe_log");
    if (!log) {
        printf("NO BUFFER\n");
        if (prompt_file[0]) (void)remove(prompt_file);
        return 1;
    }
    const int64_t t0 = clock_now_monotonic_ns();
    bool timed_out = false;
    const int rc = run_cli(v, argv, log, UNIT_PROBE_LOG_BYTES,
                           UNIT_PROBE_CLI_TIMEOUT_MS, &timed_out);
    const int64_t elapsed = (clock_now_monotonic_ns() - t0) / 1000000;
    if (prompt_file[0]) (void)remove(prompt_file);

    if (rc < 0) {
        printf("COULD NOT LAUNCH %s in %lldms\n", v->program,
               (long long)elapsed);
        free(log);
        return 1;
    }
    if (timed_out) {
        printf("TIMED OUT in %lldms\n", (long long)elapsed);
        free(log);
        return 1;
    }
    if (v->cli_output == ENGINE_CLI_OUTPUT_GROK_JSON) {
        struct engine_cli_observation observation;
        if (!engine_cli_observation_parse(v, log, strlen(log), &observation)) {
            printf("MALFORMED SESSION METADATA in %lldms\n",
                   (long long)elapsed);
            free(log);
            return 1;
        }
        printf("exit %d in %lldms  model=%s turns=%lld session=%s\n", rc,
               (long long)elapsed, observation.resolved_model,
               (long long)observation.turns, observation.session_id);
        free(log);
        return rc == 0 ? 0 : 1;
    }

    /* The last non-empty line, flattened. A plain CLI prints a transcript;
     * the probe reports that it answered, not what it said. */
    char tail[81] = {0};
    size_t len = strlen(log);
    while (len > 0 && (log[len - 1] == '\n' || log[len - 1] == '\r'))
        log[--len] = '\0';
    const char *last = log;
    for (size_t i = 0; i < len; i++)
        if (log[i] == '\n') last = log + i + 1;
    size_t n = 0;
    for (const char *p = last; *p && n < sizeof(tail) - 1; p++)
        tail[n++] = (*p == '\r') ? ' ' : *p;
    printf("exit %d in %lldms  model=%s  \"%s\"\n", rc, (long long)elapsed,
           in.model ? in.model : "(vendor default)", tail);
    free(log);
    /* An exit code is not evidence a model answered — that is the whole
     * doctrine of this harness — so a non-zero exit is reported and counted,
     * while a zero exit is reported and believed only as far as "it ran". */
    return rc == 0 ? 0 : 1;
}

static int probe_one(const struct engine_vendor *v, const char *model_override,
                     const char *reasoning_effort)
{
    printf("  %-10s %-44s ", v->id, v->display);
    fflush(stdout);

    if (v->wire == ENGINE_WIRE_LOCAL_CLI)
        return probe_cli(v, model_override, reasoning_effort);
    if (v->wire != ENGINE_WIRE_OPENAI_CHAT) {
        printf("SKIPPED (sends nothing)\n");
        return 0;
    }

    char where[128] = {0};
    if (!engine_secret_load(v, NULL, where, sizeof(where))) {
        printf("NO KEY (set %s, or ~/%s at 0600)\n",
               v->key_env ? v->key_env : "?",
               v->key_file_rel ? v->key_file_rel : "?");
        return 0;   /* A missing key is not a failed probe. It is an absent one. */
    }

    const char *model = model_override ? model_override : v->default_model;
    size_t body_len = 0;
    const struct engine_call call = {
        .vendor            = v,
        .model             = model,
        .reasoning_effort  = reasoning_effort,
        .system_prompt     = NULL,
        .user_prompt       = "Reply with the word: ok",
        .max_output_tokens = UNIT_PROBE_OUTPUT_TOKENS,
    };
    char *body = engine_request_alloc(&call, &body_len);
    if (!body) {
        printf("REQUEST BUILD FAILED\n");
        engine_secret_clear();
        return 1;
    }

    const int64_t t0 = clock_now_monotonic_ns();
    struct dispatch_result dr;
    memset(&dr, 0, sizeof(dr));
    bool ok = dispatch_https(v, body, body_len, UNIT_PROBE_TIMEOUT_MS, &dr);
    const int64_t elapsed = (clock_now_monotonic_ns() - t0) / 1000000;
    free(body);
    engine_secret_clear();

    if (ok) {
        /* The reply text is printed truncated and on one line: a probe reports
         * that the leg works, not what the model said. */
        char one_line[81];
        size_t n = 0;
        for (const char *p = dr.reply.text; *p && n < sizeof(one_line) - 1; p++)
            one_line[n++] = (*p == '\n' || *p == '\r') ? ' ' : *p;
        one_line[n] = '\0';
        /* The token counts are printed because they are the unit of cost and
         * the probe is the cheapest place to see whether a vendor reports
         * them at all. "unreported" is a fact about the vendor, not a zero. */
        char spend[64];
        if (dr.reply.usage.tokens_known)
            (void)snprintf(spend, sizeof(spend), "in=%lld out=%lld",
                           (long long)dr.reply.usage.prompt_tokens,
                           (long long)dr.reply.usage.completion_tokens);
        else
            (void)snprintf(spend, sizeof(spend), "tokens unreported");
        printf("HTTP %d in %lldms  model=%s  %s  \"%s\"\n", dr.http_status,
               (long long)elapsed,
               dr.reply.model[0] ? dr.reply.model : model, spend, one_line);
        engine_reply_free(&dr.reply);
        return 0;
    }
    printf("HTTP %d in %lldms  %s\n", dr.http_status, (long long)elapsed,
           engine_err_name(dr.err));
    return 1;
}

static int probe_all(const struct unit_opts *o)
{
    if (!o->yes_dispatch)
        return fail_setup(
            "refusing to probe without --yes-dispatch. A probe is a real call "
            "to a real vendor and it is billed like one");

    printf("engine_unit: probing every vendor with one minimal call\n");
    int failures = 0;
    size_t probed = 0;
    for (size_t i = 0; i < engine_count(); i++) {
        const struct engine_vendor *v = engine_at(i);
        if (o->engine_id && strcmp(v->id, o->engine_id) != 0)
            continue;
        probed++;
        failures += probe_one(v, o->model, o->reasoning_effort);
    }
    if (probed == 0) {
        return fail_setup("no engine matched --engine; see --list");
    }
    printf("engine_unit: %zu probed, %d did not answer\n", probed, failures);
    /* A probe that could not reach anyone is a failed probe. It is reported
     * as one rather than as a clean run with sad output. */
    return failures == 0 ? 0 : 1;
}
/* The fixture engine: the same lifecycle with the socket removed. The canned
 * file is read as a RESPONSE BODY and pushed through the identical hardened
 * decoder, so what the fixture proves about the decode path is real. */
static bool dispatch_fixture(const struct engine_vendor *v, const char *path,
                             struct dispatch_result *dr)
{
    if (!path || !path[0]) {
        dr->err = ENGINE_ERR_REFUSED;
        LOG_FAIL("engine_unit", "--engine fixture needs --fixture-reply FILE");
    }
    size_t len = 0;
    char *body = read_file(path, ENGINE_MAX_RESPONSE_BYTES, &len);
    if (!body) {
        dr->err = ENGINE_ERR_REFUSED;
        return false;
    }
    dr->http_status = 200;
    const bool ok = engine_response_parse(v, body, len, &dr->reply);
    free(body);
    dr->err = ok ? ENGINE_OK : ENGINE_ERR_PARSE;
    return ok;
}

/* A subscription-backed agent CLI. It edits the worktree itself, so there is
 * no reply text to decode — its "answer" is the diff, which is measured the
 * same way every other engine's is.
 *
 * The predecessor Grok lane's three measured lessons are preserved here:
 * the output contract is stated IN BAND in the prompt file and never as a
 * forced response schema; the permission mode is the one that actually acts
 * headlessly rather than the one that narrates a plan; and a timeout is
 * reported as a timeout. No shell is invoked — zcl_spawn_capture execs argv
 * directly, so the prompt path never passes through metacharacter expansion. */
static bool dispatch_cli(const struct engine_vendor *v, const char *prompt_path,
                         const char *prompt_text, const char *model,
                         const char *reasoning_effort,
                         const char *workdir, int turns, int timeout_ms,
                         struct dispatch_result *dr)
{
    /* Which of the two the vendor wants is a row, not a branch here. */
    const char *prompt = (v->cli_prompt == ENGINE_CLI_PROMPT_ARG)
                             ? prompt_text : prompt_path;
    if (!prompt || !prompt[0]) {
        dr->err = ENGINE_ERR_REFUSED;
        if (v->cli_prompt == ENGINE_CLI_PROMPT_ARG)
            LOG_FAIL("engine_unit",
                     "%s takes its prompt as an argument and none was composed",
                     v->id);
        LOG_FAIL("engine_unit",
                 "a CLI engine reads its prompt from a file: pass --state-dir "
                 "so one can be written");
    }
    char turn_cap[32];
    (void)snprintf(turn_cap, sizeof(turn_cap), "%d", turns > 0 ? turns : 1);
    const struct engine_cli_inputs in = {
        .prompt  = prompt,
        .workdir = workdir,
        .turns   = turn_cap,
        .model   = model && model[0] ? model : v->default_model,
        .reasoning_effort = reasoning_effort,
    };
    const char *argv[ENGINE_CLI_ARGV_MAX];
    if (engine_cli_argv_build(v, &in, argv, ENGINE_CLI_ARGV_MAX) == 0) {
        dr->err = ENGINE_ERR_REFUSED;
        LOG_FAIL("engine_unit", "could not build an argument vector for %s",
                 v->id);
    }
    char *log = zcl_malloc(UNIT_GATE_LOG_BYTES, "engine_unit_cli_log");
    if (!log) {
        dr->err = ENGINE_ERR_REFUSED;
        LOG_FAIL("engine_unit", "cannot allocate the CLI transcript buffer");
    }
    bool timed_out = false;
    const int rc = run_cli(
        v, argv, log, UNIT_GATE_LOG_BYTES, timeout_ms, &timed_out);
    if (rc < 0) {
        free(log);
        dr->err = ENGINE_ERR_NETWORK;
        LOG_FAIL("engine_unit", "could not launch %s", v->program);
    }
    if (timed_out) {
        free(log);
        dr->err = ENGINE_ERR_TIMEOUT;
        return false;
    }
    if (!engine_cli_observation_parse(v, log, strlen(log),
                                      &dr->cli_observation)) {
        free(log);
        dr->err = ENGINE_ERR_PARSE;
        return false;
    }
    free(log);
    if (dr->cli_observation.known) {
        dr->reply.usage.prompt_tokens =
            dr->cli_observation.input_tokens;
        dr->reply.usage.completion_tokens =
            dr->cli_observation.output_tokens;
        dr->reply.usage.total_tokens =
            dr->cli_observation.total_tokens;
        dr->reply.usage.cache_read_input_tokens =
            dr->cli_observation.cache_read_input_tokens;
        dr->reply.usage.cache_creation_input_tokens =
            dr->cli_observation.cache_creation_input_tokens;
        dr->reply.usage.reasoning_tokens =
            dr->cli_observation.reasoning_tokens;
        dr->reply.usage.prompt_tokens_known = true;
        dr->reply.usage.completion_tokens_known = true;
        dr->reply.usage.total_tokens_known = true;
        dr->reply.usage.cache_read_input_tokens_known = true;
        dr->reply.usage.cache_creation_input_tokens_known = true;
        dr->reply.usage.reasoning_tokens_known = true;
        dr->reply.usage.tokens_known = true;
        (void)snprintf(dr->reply.model, sizeof(dr->reply.model), "%s",
                       dr->cli_observation.resolved_model);
    }
    /* rc is deliberately NOT consulted beyond "did it launch". A CLI engine
     * exiting 0 having written nothing is one of the three measured failures
     * this harness exists to catch; the diff and the gate decide. */
    dr->http_status = 0;
    dr->err = ENGINE_OK;
    return true;
}

/* ── applying a reply ────────────────────────────────────────────────── */

static bool ensure_parent_dirs(const char *root, const char *rel)
{
    char path[1024];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", root, rel) >= sizeof(path))
        LOG_FAIL("engine_unit", "path too long to create: %s", rel);
    for (char *p = path + strlen(root) + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (unit_mkdir(path, 0755) != 0 && errno != EEXIST) {
            *p = '/';
            LOG_FAIL("engine_unit", "cannot create a directory under the worktree");
        }
        *p = '/';
    }
    return true;
}

/* Read a whole file into a heap buffer, or return NULL (including "does not
 * exist" — a new file has nothing to shrink from, see
 * engine_patch_is_drastic_shrink()). The caller frees. */
static char *read_whole_file_alloc(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    const long sz = ftell(f);
    if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = zcl_malloc((size_t)sz + 1, "engine_unit_shrink_check");
    if (!buf) {
        fclose(f);
        return NULL;
    }
    const size_t got = sz > 0 ? fread(buf, 1, (size_t)sz, f) : 0;
    fclose(f);
    if (got != (size_t)sz) {
        free(buf);
        return NULL;
    }
    buf[sz] = '\0';
    if (out_len)
        *out_len = (size_t)sz;
    return buf;
}

/* Refuses a whole-file reply that overwrote an existing file with under half
 * its own line count — the shape of a model that meant to change a few
 * lines and instead sent a truncated or reconstructed-from-memory body. A
 * unit's next turn cannot read the tree back to notice this on its own (see
 * engine/engine_state.h), so the harness catches it before the damage lands
 * on disk. Returns NULL when every entry is fine, else a message naming the
 * first offending path and its old/new line counts (a pointer into a static
 * buffer, valid until the next call). */
static const char *patch_shrink_reason(const char *root,
                                       const struct engine_patch *p)
{
    static char why[512];
    for (size_t i = 0; i < p->count; i++) {
        const struct engine_patch_entry *e = &p->entries[i];
        if (e->remove)
            continue;
        char path[1024];
        if ((size_t)snprintf(path, sizeof(path), "%s/%s", root, e->path)
            >= sizeof(path))
            continue;
        size_t old_len = 0;
        char *old = read_whole_file_alloc(path, &old_len);
        if (!old)
            continue;                       /* a new file: nothing to shrink from */
        const size_t old_lines = engine_patch_count_lines(old, old_len);
        free(old);
        const size_t new_lines =
            engine_patch_count_lines(e->content, e->content_len);
        if (engine_patch_is_drastic_shrink(old_lines, new_lines)) {
            (void)snprintf(why, sizeof(why),
                          "%s: the reply's whole-file body has %zu line(s), "
                          "under half of the %zu line(s) the file has now. "
                          "Send a unified-diff hunk for the part you meant "
                          "to change instead of reconstructing the whole "
                          "file from memory.",
                          e->path, new_lines, old_lines);
            return why;
        }
    }
    return NULL;
}

static bool apply_patch(const char *root, const struct engine_patch *p)
{
    for (size_t i = 0; i < p->count; i++) {
        const struct engine_patch_entry *e = &p->entries[i];
        char path[1024];
        if ((size_t)snprintf(path, sizeof(path), "%s/%s", root, e->path)
            >= sizeof(path))
            LOG_FAIL("engine_unit", "refusing an over-long target path");
        if (e->remove) {
            if (unlink(path) != 0 && errno != ENOENT)
                LOG_FAIL("engine_unit", "cannot remove a file the unit deleted");
            engine_emit(stdout, "    delete %s\n", e->path);
            continue;
        }
        if (!ensure_parent_dirs(root, e->path))
            return false;
        FILE *f = fopen(path, "wb");
        if (!f)
            LOG_FAIL("engine_unit", "cannot write a file the unit produced");
        const size_t wrote = e->content_len
                                 ? fwrite(e->content, 1, e->content_len, f)
                                 : 0;
        const bool ok = (wrote == e->content_len) && (fclose(f) == 0);
        if (!ok)
            LOG_FAIL("engine_unit", "short write applying %s", e->path);
        engine_emit(stdout, "    write  %s (%zu bytes)\n", e->path,
                    e->content_len);
    }
    return true;
}

/* ── giving the model what it needs to see ──────────────────────────────
 *
 * A brief that names a file by path and quotes a few lines of it is not the
 * same as giving the model the file: the confirmed cmp-capability_closure-
 * glm53/a1 unit was asked to edit two ~1,090-line registries, was shown five
 * quoted lines total, had no shell of its own, and correctly refused to
 * fabricate a ~1,090-line whole-file envelope from memory rather than
 * destroy ~1,090 hand-maintained rows. The task text is opaque to
 * engine_unit — it does not know which of the words in it are meant as file
 * paths — so this scans for tokens that already exist as real files in the
 * worktree and hands their current content back, unasked. */
#define TASK_FILE_CONTEXT_MAX_FILES        6u
#define TASK_FILE_CONTEXT_MAX_TOTAL_BYTES  (32u * 1024u)
#define TASK_FILE_CONTEXT_PER_FILE_BYTES   (12u * 1024u)

static bool byte_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* Appends, after `text`, a "current contents" section for every distinct
 * path-shaped token in `text` that both looks like a real path
 * (engine_patch_looks_like_a_path()) and exists under `workdir` — up to
 * TASK_FILE_CONTEXT_MAX_FILES files and TASK_FILE_CONTEXT_MAX_TOTAL_BYTES
 * total. Returns a new heap buffer (the caller frees); returns a copy of
 * `text` unchanged (still heap-owned) if nothing matched or allocation
 * failed partway, so a scan that finds nothing never costs the caller its
 * task text. */
static char *build_task_with_file_contents(const char *text, size_t text_len,
                                           const char *workdir)
{
    const size_t cap = text_len + TASK_FILE_CONTEXT_MAX_TOTAL_BYTES + 4096u;
    char *out = zcl_malloc(cap, "engine_unit_task_context");
    if (!out)
        return NULL;
    memcpy(out, text, text_len);
    size_t used = text_len;

    char seen[TASK_FILE_CONTEXT_MAX_FILES][ENGINE_PATCH_MAX_PATH];
    size_t seen_n = 0;
    size_t files_included = 0;
    size_t bytes_included = 0;
    bool header_written = false;

    const char *p = text;
    const char *end = text + text_len;
    while (p < end && files_included < TASK_FILE_CONTEXT_MAX_FILES
          && bytes_included < TASK_FILE_CONTEXT_MAX_TOTAL_BYTES) {
        while (p < end && byte_is_space(*p))
            p++;
        const char *tok_start = p;
        while (p < end && !byte_is_space(*p))
            p++;
        size_t tok_len = (size_t)(p - tok_start);
        if (tok_len == 0 || tok_len >= ENGINE_PATCH_MAX_PATH)
            continue;
        char tok[ENGINE_PATCH_MAX_PATH];
        memcpy(tok, tok_start, tok_len);
        tok[tok_len] = '\0';
        /* Trailing prose punctuation a real path never ends in. */
        while (tok_len > 0 && strchr(",.;:)]\"'!?", tok[tok_len - 1])) {
            tok_len--;
            tok[tok_len] = '\0';
        }
        if (tok_len == 0 || !engine_patch_looks_like_a_path(tok))
            continue;
        bool dup = false;
        for (size_t i = 0; i < seen_n; i++) {
            if (strcmp(seen[i], tok) == 0) {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;
        char path[1024];
        if ((size_t)snprintf(path, sizeof(path), "%s/%s", workdir, tok)
            >= sizeof(path))
            continue;
        size_t clen = 0;
        char *content = read_whole_file_alloc(path, &clen);
        if (!content)
            continue;                      /* not a file that exists here */
        if (seen_n < TASK_FILE_CONTEXT_MAX_FILES) {
            memcpy(seen[seen_n], tok, tok_len + 1);
            seen_n++;
        }
        size_t take = clen;
        bool truncated = false;
        if (take > TASK_FILE_CONTEXT_PER_FILE_BYTES) {
            take = TASK_FILE_CONTEXT_PER_FILE_BYTES;
            truncated = true;
        }
        if (bytes_included + take > TASK_FILE_CONTEXT_MAX_TOTAL_BYTES) {
            take = TASK_FILE_CONTEXT_MAX_TOTAL_BYTES - bytes_included;
            truncated = true;
        }
        if (!header_written) {
            const int hn = snprintf(out + used, cap - used,
                "\n\n# Current contents of files this task names\n\n"
                "Every file below exists in your worktree right now, "
                "exactly as shown. Do not guess, reconstruct from memory, "
                "or ask for it again.\n");
            if (hn > 0)
                used += (size_t)hn < cap - used ? (size_t)hn : cap - used;
            header_written = true;
        }
        const int hn = snprintf(out + used, cap - used,
                                "\n## %s (%zu byte(s)%s)\n", tok, clen,
                                truncated ? "; truncated below" : "");
        if (hn > 0)
            used += (size_t)hn < cap - used ? (size_t)hn : cap - used;
        if (take > 0 && used < cap) {
            const size_t room = cap - used;
            const size_t copy_n = take < room ? take : room;
            memcpy(out + used, content, copy_n);
            used += copy_n;
        }
        free(content);
        files_included++;
        bytes_included += take;
    }
    out[used] = '\0';
    return out;
}

/* ── the gate ────────────────────────────────────────────────────────── */

/* Run the unit's group and READ THE NUMBERS. `t-fast` takes the checkout lock
 * itself, so this must not be wrapped in another one. The cache is disabled
 * for the child: a group served from cache did not execute the new code, and
 * a run that proves nothing must not be given the chance to look green. */
/* The gate log's first actionable line, and its last 40 lines, formatted for
 * the next turn's prompt. "Actionable" matches the convention
 * zcl_devloop_distill_first_error() (tools/dev/devloop.h) already uses for a
 * dev-loop capsule: a compiler diagnostic (`: error:`) or a test failure
 * (`FAIL`, `Assertion`, `EXPECT`) — reimplemented here rather than linked,
 * because engine_unit is compiled straight from source with a small, fixed
 * source list (see ENGINE_UNIT_SRCS) for the TLS-client isolation reason
 * explained at the top of this file, and devloop.c is not on it. */
static void gate_feedback_from_log(const char *log, size_t log_len, char *out,
                                   size_t out_cap)
{
    if (!out || out_cap == 0)
        return;
    out[0] = '\0';
    if (!log || log_len == 0)
        return;

    static const char *const needles[] = { ": error:", "FAIL", "Assertion",
                                           "EXPECT" };
    char first[240] = {0};
    size_t i = 0;
    while (i < log_len && !first[0]) {
        size_t line_start = i;
        while (i < log_len && log[i] != '\n')
            i++;
        const size_t line_len = i - line_start;
        for (size_t k = 0; k < sizeof(needles) / sizeof(needles[0]); k++) {
            const size_t nl = strlen(needles[k]);
            if (line_len < nl)
                continue;
            for (size_t s = 0; s + nl <= line_len; s++) {
                if (memcmp(log + line_start + s, needles[k], nl) == 0) {
                    const size_t n = line_len < sizeof(first) - 1
                                         ? line_len : sizeof(first) - 1;
                    memcpy(first, log + line_start, n);
                    first[n] = '\0';
                    break;
                }
            }
            if (first[0])
                break;
        }
        if (i < log_len)
            i++;
    }

    /* The last 40 lines, trailing newline(s) stripped first so an empty
     * final line does not count as one of the 40. */
    size_t end = log_len;
    while (end > 0 && (log[end - 1] == '\n' || log[end - 1] == '\r'))
        end--;
    size_t start = end;
    int lines_seen = 0;
    while (start > 0 && lines_seen < 40) {
        start--;
        if (log[start] == '\n')
            lines_seen++;
    }
    if (start > 0 && log[start] == '\n')
        start++;

    const int hn = snprintf(out, out_cap,
        "First actionable line: %s\n\nLast lines of the gate log:\n",
        first[0] ? first : "(none found)");
    size_t used = (hn > 0 && (size_t)hn < out_cap) ? (size_t)hn : out_cap - 1;
    if (used < out_cap - 1 && end > start) {
        size_t room = out_cap - 1 - used;
        size_t tail_len = end - start;
        if (tail_len > room)
            tail_len = room;
        memcpy(out + used, log + start, tail_len);
        used += tail_len;
    }
    out[used] = '\0';
}

static bool run_gate(const struct unit_opts *o, const char *workdir,
                     struct engine_gate_reading *reading, bool *timed_out,
                     const char *log_path, char *feedback_out,
                     size_t feedback_cap)
{
    memset(reading, 0, sizeof(*reading));
    *timed_out = false;
    /* `t-fast-exact`, not `t-fast`. The convenience target's ONLY= is a
     * SUBSTRING selector, and a substring quietly widens the gate: the first
     * live run of this harness asked for `engine` and ran two groups, because
     * `condition_engine` contains it. Widening is the harmless direction here,
     * but the reverse — a name that matches a sibling and never the group the
     * unit was judged on — is the hollow green this whole module exists to
     * catch. The exact selector cannot do either. */
    char only[256];
    (void)snprintf(only, sizeof(only), "ONLY=%s", o->group);
    const char *const argv[] = { "make", "-C", workdir, "t-fast-exact", only,
                                 NULL };

    char *log = zcl_malloc(UNIT_GATE_LOG_BYTES, "engine_unit_gate_log");
    if (!log)
        LOG_FAIL("engine_unit", "cannot allocate the gate log buffer");
    if (unit_environment_set("ZCL_TEST_CACHE", "0") != 0) {
        free(log);
        LOG_FAIL("engine_unit", "cannot disable the test cache for the gate");
    }
    const int gate_s = o->gate_timeout_s > 0 ? o->gate_timeout_s : o->timeout_s;
    const int64_t started = clock_now_monotonic_ns();
    /* Merged stderr, not zcl_spawn_capture()/run(): the gate's SUITE VERDICT
     * line is on stdout, but a build that never reaches test_parallel writes
     * its only diagnostics — the compiler's errors and make's own
     * "*** [target] Error N" — to stderr. A stdout-only capture of a failing
     * build silently returns a log that stops at the last successful line
     * (typically "build-epoch-session: acquired ..."), with no error text
     * and no verdict, so a compile failure looked identical to an unlaunched
     * child. Merging stderr into the same log is what lets a model's next
     * repair turn see what actually broke. */
    const int rc = zcl_spawn_capture_merged_observed(
        argv, log, UNIT_GATE_LOG_BYTES, gate_s * 1000, timed_out);
    const int64_t elapsed_ms = (clock_now_monotonic_ns() - started) / 1000000;

    if (log_path)
        (void)engine_emit_file(log_path, log, strlen(log));
    const bool read_ok = engine_gate_read(log, strlen(log), reading);
    if (feedback_out)
        gate_feedback_from_log(log, strlen(log), feedback_out, feedback_cap);
    free(log);

    /* A child killed by the deadline is a TIMEOUT, and saying so is the whole
     * point: an operator who sees FAIL raises nothing, and an operator who
     * sees TIMEOUT raises the clock. zcl_spawn_capture_merged_observed()
     * reports that directly via *timed_out; the elapsed-time fallback stays
     * as a second signal for a child that exited exactly at the deadline
     * without a verdict. */
    if (!*timed_out && elapsed_ms >= (int64_t)gate_s * 1000
        && !reading->saw_verdict_line)
        *timed_out = true;
    (void)rc;   /* never a verdict input; see engine/engine_verdict.h */
    return read_ok;
}

/* ── receipt ─────────────────────────────────────────────────────────── */

static bool receipt_push_null(struct json_value *doc, const char *key)
{
    struct json_value value;
    json_init(&value);
    json_set_null(&value);
    const bool ok = json_push_kv(doc, key, &value);
    json_free(&value);
    return ok;
}

static bool receipt_push_counter(struct json_value *doc, const char *key,
                                 bool known, int64_t value)
{
    return known ? json_push_kv_int(doc, key, value)
                 : receipt_push_null(doc, key);
}

static void write_receipt(const struct unit_opts *o,
                          const struct engine_vendor *v,
                          const struct engine_usage *usage,
                          const struct engine_cli_observation *observation,
                          const char *reply_resolved_model,
                          const struct engine_gate_reading *g,
                          size_t files_changed, int attempts,
                          int64_t dispatch_latency_ms,
                          int64_t proof_latency_ms,
                          enum engine_verdict verdict,
                          size_t state_bytes, bool state_updated,
                          int compactions, bool needs_operator)
{
    char text[4096];
    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    bool ok = json_push_kv_str(&doc, "schema", "zcl.engine_unit.v1") &&
        json_push_kv_str(&doc, "accounting_scope", "terminal_dispatch") &&
        json_push_kv_bool(&doc, "needs_operator", needs_operator) &&
        json_push_kv_str(&doc, "engine", v->id) &&
        json_push_kv_str(&doc, "model", o->model ? o->model :
                         (v->default_model ? v->default_model : "")) &&
        json_push_kv_str(&doc, "requested_model", o->model ? o->model :
                         (v->default_model ? v->default_model : "")) &&
        json_push_kv_str(&doc, "reasoning_effort",
                         o->reasoning_effort ? o->reasoning_effort :
                         ENGINE_REASONING_EFFORT_PROVIDER_DEFAULT) &&
        json_push_kv_str(&doc, "territory", o->territory ? o->territory : "") &&
        json_push_kv_str(&doc, "group", o->group ? o->group : "") &&
        json_push_kv_int(&doc, "files_changed", (int64_t)files_changed) &&
        json_push_kv_int(&doc, "groups_ran", g->groups_ran) &&
        json_push_kv_int(&doc, "groups_failed", g->groups_failed) &&
        json_push_kv_bool(&doc, "cached", g->cached_mode) &&
        json_push_kv_bool(&doc, "cost_usd_known", usage->cost_known) &&
        json_push_kv_real(&doc, "cost_usd", usage->cost_usd) &&
        json_push_kv_int(&doc, "attempts", attempts) &&
        json_push_kv_int(&doc, "dispatch_failures",
                         attempts > 0 ? attempts - 1 : 0) &&
        json_push_kv_int(&doc, "dispatch_latency_ms", dispatch_latency_ms) &&
        json_push_kv_int(&doc, "proof_latency_ms", proof_latency_ms) &&
        json_push_kv_str(&doc, "verdict", engine_verdict_name(verdict)) &&
        json_push_kv_int(&doc, "state_bytes", (int64_t)state_bytes) &&
        json_push_kv_bool(&doc, "state_updated", state_updated) &&
        json_push_kv_int(&doc, "compactions", (int64_t)compactions);
    if (ok)
        ok = receipt_push_counter(&doc,"prompt_tokens",
                                  usage->prompt_tokens_known,
                                  usage->prompt_tokens) &&
             receipt_push_counter(&doc,"completion_tokens",
                                  usage->completion_tokens_known,
                                  usage->completion_tokens);
    if (ok && observation && observation->known) {
        ok = json_push_kv_str(&doc, "resolved_model",
                              observation->resolved_model) &&
            json_push_kv_str(&doc, "session_id", observation->session_id) &&
            json_push_kv_str(&doc, "request_id", observation->request_id) &&
            json_push_kv_str(&doc, "stop_reason", observation->stop_reason) &&
            json_push_kv_int(&doc, "turns", observation->turns) &&
            json_push_kv_int(&doc, "input_tokens", observation->input_tokens) &&
            json_push_kv_int(&doc, "cache_read_input_tokens",
                             observation->cache_read_input_tokens) &&
            json_push_kv_int(&doc, "cache_creation_input_tokens",
                             observation->cache_creation_input_tokens) &&
            json_push_kv_int(&doc, "output_tokens", observation->output_tokens) &&
            json_push_kv_int(&doc, "reasoning_tokens",
                             observation->reasoning_tokens) &&
            json_push_kv_int(&doc, "total_tokens", observation->total_tokens);
    } else if (ok) {
        if (reply_resolved_model && reply_resolved_model[0])
            ok = json_push_kv_str(&doc, "resolved_model",
                                  reply_resolved_model);
        else
            ok = receipt_push_null(&doc, "resolved_model");
        static const char *const unknown_keys[] = {
            "session_id", "request_id", "stop_reason", "turns",
        };
        for (size_t i = 0;
             ok && i < sizeof(unknown_keys) / sizeof(unknown_keys[0]); i++)
            ok = receipt_push_null(&doc, unknown_keys[i]);
        if (ok)
            ok = receipt_push_counter(&doc,"input_tokens",
                    usage->prompt_tokens_known,usage->prompt_tokens) &&
                 receipt_push_counter(&doc,"cache_read_input_tokens",
                    usage->cache_read_input_tokens_known,
                    usage->cache_read_input_tokens) &&
                 receipt_push_counter(&doc,"cache_creation_input_tokens",
                    usage->cache_creation_input_tokens_known,
                    usage->cache_creation_input_tokens) &&
                 receipt_push_counter(&doc,"output_tokens",
                    usage->completion_tokens_known,usage->completion_tokens) &&
                 receipt_push_counter(&doc,"reasoning_tokens",
                    usage->reasoning_tokens_known,usage->reasoning_tokens) &&
                 receipt_push_counter(&doc,"total_tokens",
                    usage->total_tokens_known,usage->total_tokens);
    }
    const size_t n = ok ? json_write(&doc, text, sizeof(text) - 2u) :
                          sizeof(text);
    json_free(&doc);
    if (!ok || n >= sizeof(text) - 2u)
        return;
    text[n] = '\n';
    text[n + 1u] = '\0';
    engine_emit(stdout, "%s", text);
    if (o->state_dir && o->state_dir[0]) {
        char path[1024];
        if ((size_t)snprintf(path, sizeof(path), "%s/receipt.json",
                             o->state_dir) < sizeof(path))
            (void)engine_emit_file(path, text, strlen(text));
    }
}

/* The sequence, not the one-run snapshot above. One JSON line appended to
 * <state-dir>/engine_receipts.chainlog; see engine/engine_receipt.h. */
static bool append_unit_receipt(const struct unit_opts *o,
                                const struct engine_vendor *v,
                                const struct engine_usage *usage,
                                const struct engine_cli_observation *observation,
                                const char *resolved_model,
                                const struct engine_gate_reading *g,
                                size_t files_changed, int attempts,
                                int64_t dispatch_latency_ms,
                                int64_t proof_latency_ms,
                                int64_t cumulative_proof_ms,
                                int64_t unit_elapsed_ms,
                                int http_status,
                                enum engine_verdict verdict,
                                const char *task_sha3,
                                const struct invocation_log *invocations)
{
    if (!o->state_dir || !o->state_dir[0])
        return true;
    char path[1024];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s",
                         o->state_dir, ENGINE_RECEIPT_FILENAME) >= sizeof(path))
        return false;

    char template_hex[65] = {0};
    if (o->kind && o->kind[0]) {
        uint8_t digest[32];
        engine_prompt_template_sha3(o->kind, digest);
        zcl_hex_encode(digest, 32, template_hex);
    }

    struct engine_receipt r = {
        .ts = clock_now_wall_ms() / 1000,
        .engine = v->id,
        .requested_model = o->model ? o->model
                                    : (v->default_model ? v->default_model : ""),
        .resolved_model = observation && observation->known
                              ? observation->resolved_model
                              : (resolved_model && resolved_model[0]
                                     ? resolved_model : NULL),
        .reasoning_effort = o->reasoning_effort ? o->reasoning_effort
                              : ENGINE_REASONING_EFFORT_PROVIDER_DEFAULT,
        .kind = o->kind,
        .template_sha3 = template_hex[0] ? template_hex : NULL,
        .rules_shown = NULL,
        .rules_count = 0,
        .task_sha3 = task_sha3,
        .group = o->group,
        .prompt_tokens = usage->prompt_tokens_known ? usage->prompt_tokens
                                             : ENGINE_RECEIPT_UNREPORTED,
        .completion_tokens = usage->completion_tokens_known ? usage->completion_tokens
                                                 : ENGINE_RECEIPT_UNREPORTED,
        .cache_read_input_tokens = usage->cache_read_input_tokens_known
            ? usage->cache_read_input_tokens : ENGINE_RECEIPT_UNREPORTED,
        .cache_creation_input_tokens = usage->cache_creation_input_tokens_known
            ? usage->cache_creation_input_tokens : ENGINE_RECEIPT_UNREPORTED,
        .reasoning_tokens = usage->reasoning_tokens_known
            ? usage->reasoning_tokens : ENGINE_RECEIPT_UNREPORTED,
        .total_tokens = usage->total_tokens_known ? usage->total_tokens
                                                  : ENGINE_RECEIPT_UNREPORTED,
        .turns = observation && observation->known
            ? observation->turns : ENGINE_RECEIPT_UNREPORTED,
        .invocations = invocations ? invocations->items : NULL,
        .invocations_count = invocations ? invocations->count : 0,
        .invocation_totals_ambiguous =
            invocations ? invocations->totals_ambiguous : false,
        .cumulative_proof_ms = cumulative_proof_ms,
        .unit_elapsed_ms = unit_elapsed_ms,
        .dispatch_ms = dispatch_latency_ms,
        .proof_ms = proof_latency_ms,
        .wall_ms = dispatch_latency_ms + proof_latency_ms,
        .http_status = http_status,
        .worktree_head = NULL,
        .outcome = {
            .applied = files_changed > 0,
            .groups_ran = g->groups_ran,
            .groups_failed = g->groups_failed,
            .gate_pass = engine_verdict_is_pass(verdict),
            .retries = attempts > 0 ? attempts - 1 : 0,
            .lines_changed = (int64_t)files_changed,
            .lint_rc = ENGINE_RECEIPT_UNREPORTED,
        },
    };
    return engine_receipt_append(path, &r, NULL);
}

static bool receipt_plan_fits(const struct unit_opts *o,
                              const struct engine_vendor *v,
                              const char *task_sha3, size_t invocation_count)
{
    struct engine_receipt_invocation worst[ENGINE_RECEIPT_INVOCATIONS_MAX];
    char resolved_model[96];
    memset(resolved_model, 'm', sizeof(resolved_model) - 1u);
    resolved_model[sizeof(resolved_model) - 1u] = '\0';
    for (size_t i = 0; i < invocation_count; i++) {
        worst[i] = (struct engine_receipt_invocation) {
            .ordinal = INT64_MAX,
            .phase = "compaction",
            .result = "receipt_capacity_worst_case",
            .elapsed_ms = INT64_MAX,
            .http_status = INT64_MAX,
            .resolved_model = resolved_model,
            .prompt_tokens = INT64_MAX,
            .completion_tokens = INT64_MAX,
            .cache_read_input_tokens = INT64_MAX,
            .cache_creation_input_tokens = INT64_MAX,
            .reasoning_tokens = INT64_MAX,
            .total_tokens = INT64_MAX,
        };
    }
    char template_hex[65] = {0};
    if (o->kind && o->kind[0]) {
        uint8_t digest[32];
        engine_prompt_template_sha3(o->kind, digest);
        zcl_hex_encode(digest, 32, template_hex);
    }
    const struct engine_receipt plan = {
        .ts = INT64_MAX,
        .engine = v->id,
        .requested_model = o->model ? o->model
                                    : (v->default_model ? v->default_model : ""),
        .resolved_model = resolved_model,
        .reasoning_effort = o->reasoning_effort ? o->reasoning_effort
                              : ENGINE_REASONING_EFFORT_PROVIDER_DEFAULT,
        .kind = o->kind,
        .template_sha3 = template_hex[0] ? template_hex : NULL,
        .task_sha3 = task_sha3,
        .group = o->group,
        .prompt_tokens = INT64_MAX,
        .completion_tokens = INT64_MAX,
        .cache_read_input_tokens = INT64_MAX,
        .cache_creation_input_tokens = INT64_MAX,
        .reasoning_tokens = INT64_MAX,
        .total_tokens = INT64_MAX,
        .turns = INT64_MAX,
        .invocations = worst,
        .invocations_count = invocation_count,
        .cumulative_proof_ms = INT64_MAX,
        .unit_elapsed_ms = INT64_MAX,
        .dispatch_ms = INT64_MAX,
        .proof_ms = INT64_MAX,
        .wall_ms = INT64_MAX,
        .http_status = INT64_MAX,
        .outcome = {
            .groups_ran = INT64_MAX,
            .groups_failed = INT64_MAX,
            .retries = INT64_MAX,
            .lines_changed = INT64_MAX,
            .lint_rc = INT64_MAX,
        },
    };
    return engine_receipt_fits(&plan);
}

/* ── carried state across attempts ───────────────────────────────────────
 *
 * A caller who repeats a unit that did not land runs this program again with
 * a FRESH --state-dir, and the harness that drives that (not this program)
 * is free to name it however it likes. But when it follows the shape this
 * comment assumes — .../a<N>, one directory per attempt, N counting up from
 * 1 — a sibling a<N-1>/state.txt is the one thing that should survive the
 * boundary: the model's own account of what it tried and why, not the
 * transcript, not the gate log, not the diff. Any other directory shape
 * (a custom name, attempt "a1" with nothing before it, a missing sibling)
 * is not an error. It just means there is nothing to carry forward, and a
 * unit dispatched standalone — no repeated attempts at all — is the common
 * case that looks exactly like that. */
static bool load_attempt_state(const char *state_dir, char *out,
                               size_t out_cap, char *label, size_t label_cap)
{
    if (!state_dir || !state_dir[0])
        return false;
    const char *base = strrchr(state_dir, '/');
    base = base ? base + 1 : state_dir;
    if (base[0] != 'a' || base[1] < '1' || base[1] > '9')
        return false;
    long n = 0;
    const char *p = base + 1;
    while (*p >= '0' && *p <= '9') {
        n = n * 10 + (*p - '0');
        p++;
    }
    if (*p != '\0' || n <= 1)
        return false;

    char sibling[1024];
    const int sn = snprintf(sibling, sizeof(sibling), "%.*sa%ld/state.txt",
                            (int)(base - state_dir), state_dir, n - 1);
    if (sn < 0 || (size_t)sn >= sizeof(sibling))
        return false;

    FILE *f = fopen(sibling, "rb");
    if (!f)
        return false;
    const size_t rd = fread(out, 1, out_cap - 1, f);
    (void)fclose(f);
    out[rd] = '\0';
    size_t len = rd;
    while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = '\0';
    if (len == 0)
        return false; /* the sibling ran but left nothing behind */
    char digits[32];
    (void)snprintf(digits, sizeof(digits), "%ld", n - 1);
    (void)snprintf(label, label_cap, "%s", digits);
    return true;
}

/* Combine the attempt-carried and turn-carried state into the one preamble
 * compose_prompt() prepends, in that order — a previous ATTEMPT's account
 * came first chronologically and stays first here, with this run's own
 * latest turn immediately after it, closest to the task it is about to
 * re-read. Returns the number of bytes written, snprintf semantics. */
static size_t build_carried_preamble(char *buf, size_t cap,
                                     bool have_attempt_state,
                                     const char *attempt_state,
                                     const char *attempt_label,
                                     bool have_turn_state,
                                     const char *turn_state)
{
    size_t n = 0;
    if (have_attempt_state && n < cap)
        n += engine_state_format_preamble(buf + n, cap - n, attempt_state,
                                          attempt_label);
    if (have_turn_state && n < cap)
        n += engine_state_format_preamble(buf + n, cap - n, turn_state, NULL);
    return n;
}

/* ── the lifecycle ───────────────────────────────────────────────────── */

/* Dispatch, with the per-vendor retry budget and the breaker in front of it.
 * Returns the reply on success; sets *err to the last classified failure. */
static bool dispatch_with_retries(const struct engine_vendor *v,
                                  const struct unit_opts *o,
                                  const char *body, size_t body_len,
                                  const char *prompt_path, const char *prompt_text,
                                  const char *workdir,
                                  struct dispatch_result *dr,
                                  struct invocation_log *invocations)
{
    struct engine_breaker breaker = {0};
    const int budget = v->max_retries < 0 ? 0 : v->max_retries;
    const int64_t started_ns = clock_now_monotonic_ns();
    for (int attempt = 0; attempt <= budget; attempt++) {
        if (!invocation_log_has_room(invocations)) {
            dr->err = ENGINE_ERR_REFUSED;
            return false;
        }
        engine_reply_free(&dr->reply);
        memset(&dr->reply, 0, sizeof(dr->reply));
        memset(&dr->cli_observation, 0, sizeof(dr->cli_observation));
        dr->err = ENGINE_OK;
        dr->http_status = 0;
        dr->attempts = attempt + 1;
        const int64_t now = clock_now_monotonic_ns() / 1000000;
        if (engine_breaker_is_open(&breaker, now)) {
            dr->err = ENGINE_ERR_REFUSED;
            LOG_FAIL("engine_unit",
                     "refusing to dispatch: %d consecutive failures opened the "
                     "circuit on %s", breaker.consecutive_failures, v->id);
        }
        bool ok = false;
        const int64_t attempt_started_ns = clock_now_monotonic_ns();
        switch (v->wire) {
        case ENGINE_WIRE_OPENAI_CHAT:
            ok = dispatch_https(v, body, body_len, o->timeout_s * 1000, dr);
            break;
        case ENGINE_WIRE_LOCAL_CLI:
            ok = dispatch_cli(v, prompt_path, prompt_text, o->model,
                              o->reasoning_effort, workdir,
                              o->turns, o->timeout_s * 1000, dr);
            break;
        case ENGINE_WIRE_LOCAL_FIXTURE:
            ok = dispatch_fixture(v, o->fixture_reply, dr);
            break;
        }
        const int64_t attempt_elapsed_ms =
            (clock_now_monotonic_ns() - attempt_started_ns) / 1000000;
        if (!invocation_log_add(invocations, "turn", ok, dr,
                                attempt_elapsed_ms)) {
            dr->err = ENGINE_ERR_REFUSED;
            return false;
        }
        engine_breaker_record(&breaker, ok ? ENGINE_OK : dr->err, now);
        dr->dispatch_latency_ms =
            (clock_now_monotonic_ns() - started_ns) / 1000000;
        if (ok)
            return true;
        if (!engine_err_should_retry(dr->err)) {
            LOG_FAIL("engine_unit", "%s dispatch failed: %s (not retryable)",
                     v->id, engine_err_name(dr->err));
        }
        if (attempt == budget)
            break;
        const int wait = engine_err_backoff_ms(attempt);
        engine_emit(stderr, "engine_unit: %s -> %s; retry %d/%d in %dms\n",
                    v->id, engine_err_name(dr->err), attempt + 1, budget, wait);
        (void)usleep((unsigned)wait * 1000u);
    }
    LOG_FAIL("engine_unit", "%s dispatch failed after %d attempt(s): %s", v->id,
             budget + 1, engine_err_name(dr->err));
}

static int fail_setup(const char *why)
{
    engine_emit(stderr, "engine_unit: %s\n", why);
    return 2;
}

int main(int argc, char **argv)
{
    struct unit_opts o;
    if (!parse_args(argc, argv, &o))
        return 2;
    if (!engine_reasoning_effort_valid(o.reasoning_effort))
        return fail_setup("--reasoning-effort must be provider_default, low, "
                          "medium, high, or xhigh");
    if (o.list) {
        list_engines();
        return 0;
    }
    /* Before --engine is required: a bare --probe covers every vendor, and
     * naming one narrows it rather than being the way in. */
    if (o.probe)
        return probe_all(&o);
    /* An unnamed engine resolves to the registry default rather than being a
     * usage error. The choice is still SAID OUT LOUD below: an operator who
     * did not pick an engine should learn which one they got from the run,
     * not from reading the table. */
    const struct engine_vendor *v = o.engine_id ? engine_by_id(o.engine_id)
                                                : engine_default();
    if (!v)
        return fail_setup(o.engine_id ? "unknown --engine; see --list"
                                      : "this build has no default engine");
    if (engine_reasoning_effort_explicit(o.reasoning_effort)
        && !v->supports_reasoning_effort)
        return fail_setup("selected engine accepts no explicit reasoning "
                          "effort");
    if (!o.engine_id)
        engine_emit(stdout, "engine_unit: no --engine given, using %s (%s)\n",
                    v->id, v->display);
    if (!o.task_path)
        return fail_setup("need --task FILE");
    if (!o.group && !o.no_group)
        return fail_setup("need --group NAME, or --no-group if this unit "
                          "truly cannot have one");
    if (o.turns < 1 || o.turns > 10)
        return fail_setup("--turns must be between 1 and 10");
    const size_t retry_attempts =
        (size_t)(v->max_retries < 0 ? 0 : v->max_retries) + 1u;
    const size_t possible_compactions =
        v->wire == ENGINE_WIRE_LOCAL_CLI ? 0u : (size_t)o.turns - 1u;
    const size_t invocation_capacity_needed =
        (size_t)o.turns * retry_attempts + possible_compactions;
    if (invocation_capacity_needed > ENGINE_RECEIPT_INVOCATIONS_MAX) {
        char why[192];
        (void)snprintf(why, sizeof(why),
                       "--turns and %s's retry budget could require %zu "
                       "provider calls; receipt cap is %u",
                       v->id, invocation_capacity_needed,
                       (unsigned)ENGINE_RECEIPT_INVOCATIONS_MAX);
        return fail_setup(why);
    }
    if (o.timeout_s < 1 || o.timeout_s > UNIT_MAX_TIMEOUT)
        return fail_setup("--timeout is outside its permitted range");
    if (o.gate_timeout_s != 0
        && (o.gate_timeout_s < 1 || o.gate_timeout_s > UNIT_MAX_TIMEOUT))
        return fail_setup("--gate-timeout is outside its permitted range");

    size_t task_len = 0;
    char *task = read_file(o.task_path, UNIT_MAX_TASK_BYTES, &task_len);
    if (!task)
        return 2;
    char task_sha3_hex[65];
    {
        uint8_t digest[32];
        zcl_sha3_256((const unsigned char *)task, task_len, digest);
        zcl_hex_encode(digest, 32, task_sha3_hex);
    }

    /* --kind wins over the task file's own header; see
     * engine_prompt_kind_from_header(). A kind that names no complete
     * template is refused HERE, before a prompt is composed and long before
     * money is spent, because the defect it produces — a section heading
     * with nothing under it — is invisible to the shape audit. */
    if (!o.kind || !o.kind[0])
        o.kind = engine_prompt_kind_from_header(task);
    if (o.kind && o.kind[0]) {
        if (!engine_prompt_kind_is_complete(o.kind)) {
            free(task);
            return fail_setup("that --kind has no usable prompt template; "
                              "run --list for the kinds this build declares");
        }
        engine_emit(stdout, "  kind:       %s\n", o.kind);
    } else {
        engine_emit(stdout,
                    "  kind:       none declared (no template bodies; pass "
                    "--kind or add a `kind:` header to the task file)\n");
    }

    /* Fail-closed: a named territory must resolve, or the unit does not go
     * out. Dispatching with an unresolvable label is what this replaces. */
    char *brief = NULL;
    if (o.territory && o.territory[0]) {
        char why[512] = { 0 };
        brief = territory_brief_fetch(o.territory, why, sizeof(why));
        if (!brief) {
            free(task);
            return fail_setup(why);
        }
        /* Say whether a stance was found. Silence here made "this territory
         * has no authored stance" indistinguishable from "nobody looked",
         * and most territories have none. */
        const char *stance = persona_stance(o.territory);
        engine_emit(stdout, "  territory:  %s (brief: %zu bytes, stance: %s)\n",
                    o.territory, strlen(brief),
                    stance ? "authored" : "none");
    }

    /* Cross-attempt carry: see load_attempt_state() above main(). Loaded
     * before the very first prompt (including the --dry-run preview) so a
     * preview shows exactly what would be dispatched. */
    char attempt_state[ENGINE_STATE_MAX_BYTES] = {0};
    char attempt_label[32] = {0};
    const bool have_attempt_state =
        load_attempt_state(o.state_dir, attempt_state, sizeof(attempt_state),
                           attempt_label, sizeof(attempt_label));
    if (have_attempt_state)
        engine_emit(stdout,
                    "  state:      carrying %zu byte(s) from attempt %s\n",
                    strlen(attempt_state), attempt_label);

    char carried_preamble[2u * ENGINE_STATE_MAX_BYTES + 512u];
    (void)build_carried_preamble(carried_preamble, sizeof(carried_preamble),
                                 have_attempt_state, attempt_state,
                                 attempt_label, false, NULL);

    char *prompt = compose_prompt(&o, v, task, brief, carried_preamble, NULL);
    if (!prompt) {
        free(task);
        free(brief);
        return 2;
    }

    if (o.dry_run) {
        /* Print exactly what this vendor would be handed, not what an
         * HTTP vendor would be handed. A preview that shows the rules while
         * the delivery omits them is worse than no preview: it is the thing
         * an operator checks in order to be reassured. */
        char *shown = engine_prompt_compose(v->wire, prompt, NULL);
        engine_emit(stdout, "%s\n", shown ? shown : prompt);
        /* The preview ends with the same verdict the dispatch path
         * applies, so an operator sees a refusal here rather than
         * discovering it after paying for a run. */
        struct engine_prompt_audit audit;
        bool shaped = shown
                      && engine_prompt_audit_text(v->wire, shown, &audit);
        uint8_t shape[32];
        engine_prompt_shape_sha3(shape);
        engine_emit(stdout,
                    "\n[prompt shape %02x%02x%02x%02x%02x%02x%02x%02x: "
                    "%zu of %zu required section(s) present — %s]\n",
                    shape[0], shape[1], shape[2], shape[3],
                    shape[4], shape[5], shape[6], shape[7],
                    shaped ? audit.present : (size_t)0,
                    shaped ? audit.required : (size_t)0,
                    shaped ? "would dispatch"
                           : "WOULD BE REFUSED");
        free(shown);
        free(prompt);
        free(task);
        free(brief);
        return 0;
    }
    /* The opt-in. Deliberately checked AFTER --dry-run so composing a prompt
     * is free, and BEFORE anything that costs money or writes a file. */
    if (!o.yes_dispatch) {
        free(prompt);
        free(task);
        free(brief);
        return fail_setup(
            "refusing to dispatch without --yes-dispatch. This spends money "
            "and writes code; it is opted into per run, never defaulted on");
    }
    if (!o.state_dir || !o.state_dir[0]) {
        free(prompt);
        free(task);
        free(brief);
        return fail_setup("--state-dir is required so every provider call "
                          "can reach the authoritative receipt chain");
    }
    if (!receipt_plan_fits(&o, v, task_sha3_hex,
                           invocation_capacity_needed)) {
        free(prompt);
        free(task);
        free(brief);
        return fail_setup("the complete worst-case invocation receipt would "
                          "exceed its 16 KiB bound; refusing before dispatch");
    }

    char where[128] = {0};
    if (!engine_secret_load(v, o.key_file, where, sizeof(where))) {
        free(prompt);
        free(task);
        free(brief);
        return fail_setup("no usable API key; see --help");
    }
    engine_emit(stdout, "engine_unit: %s\n", v->display);
    engine_emit(stdout, "  credential: %s\n", where);

    char workdir[1024];
    if (!state_dir_prepare(&o)) {
        free(prompt);
        free(task);
        free(brief);
        engine_secret_clear();
        return 2;
    }
    if (!worktree_prepare(&o, workdir, sizeof(workdir))) {
        free(prompt);
        free(task);
        free(brief);
        engine_secret_clear();
        return 2;
    }

    /* task_sha3_hex above is the operator-authored task's own identity and
     * is deliberately computed BEFORE this: augmenting the task with file
     * contents that exist only in this worktree must never change what a
     * unit's task hashes as. */
    {
        char *augmented =
            build_task_with_file_contents(task, task_len, workdir);
        if (augmented) {
            free(task);
            task = augmented;
            task_len = strlen(task);
        }
    }

    /* ── the turn loop ────────────────────────────────────────────────────
     *
     * A unit gets up to --turns tries at the SAME worktree: turn 2 sees
     * whatever turn 1 already wrote, because a repair is a continuation of
     * one piece of work, not a fresh one. What used to start each of those
     * turns blind is fixed here: every turn after the first carries forward
     * the model's own <state> block (engine/engine_state.h) plus the
     * previous gate's feedback, instead of nothing at all. The loop stops
     * the moment a turn's verdict is a pass, or after the last turn either
     * way — a unit that never passes still gets judged and receipted on
     * its final turn.
     */
    char turn_state[ENGINE_STATE_MAX_BYTES] = {0};
    bool have_turn_state = false;
    bool state_updated_last = false;
    int compactions = 0;
    char gate_tail[4096] = {0};
    bool have_gate_tail = false;

    struct dispatch_result dr = {0};
    struct invocation_log invocations = {0};
    struct engine_gate_reading gate = {0};
    bool timed_out = false;
    size_t changed = 0;
    enum engine_verdict verdict = ENGINE_VERDICT_REFUSED;
    int64_t proof_latency_ms = 0;
    int64_t cumulative_proof_ms = 0;
    char *delivered = NULL;
    char prompt_path[1024] = {0};
    bool dispatch_failed = false;
    const int64_t unit_started_ns = clock_now_monotonic_ns();

    for (int turn = 1; turn <= o.turns; turn++) {
        if (turn > 1) {
            engine_reply_free(&dr.reply);
            memset(&dr, 0, sizeof(dr));
            gate = (struct engine_gate_reading){0};
            timed_out = false;

            /* This turn's prompt: fold the compaction check into what it
             * would carry BEFORE composing it, since compose_prompt() itself
             * only knows how to refuse an over-long result, not shrink it. */
            (void)build_carried_preamble(carried_preamble,
                                         sizeof(carried_preamble),
                                         have_attempt_state, attempt_state,
                                         attempt_label, have_turn_state,
                                         turn_state);
            const size_t carried_len = strlen(carried_preamble);
            const size_t gate_tail_len = have_gate_tail ? strlen(gate_tail)
                                                        : 0;
            /* Rough but conservative: task and the territory brief are the
             * two unbounded inputs left once carried state and gate
             * feedback are accounted for; the fixed margin in
             * engine_state_needs_compaction() covers the template bodies,
             * headings and protocol text this estimate does not itemise. */
            const size_t base_len = task_len + (brief ? strlen(brief) : 0);
            if (v->wire != ENGINE_WIRE_LOCAL_CLI
                && engine_state_needs_compaction(carried_len, gate_tail_len,
                                                 base_len,
                                                 ENGINE_MAX_PROMPT_BYTES)) {
                char comp_prompt[2u * ENGINE_STATE_MAX_BYTES + 8192u];
                (void)engine_state_compaction_prompt(
                    comp_prompt, sizeof(comp_prompt),
                    have_turn_state ? turn_state
                                    : (have_attempt_state ? attempt_state
                                                          : NULL),
                    have_gate_tail ? gate_tail : NULL);
                struct dispatch_result cdr = {0};
                bool compacted = false;
                bool compaction_dispatched = false;
                const int64_t compaction_started_ns = clock_now_monotonic_ns();
                if (!invocation_log_has_room(&invocations)) {
                    dispatch_failed = true;
                    break;
                }
                if (v->wire == ENGINE_WIRE_OPENAI_CHAT) {
                    const struct engine_call ccall = {
                        .vendor            = v,
                        .model             = o.model,
                        .reasoning_effort  = o.reasoning_effort,
                        .system_prompt     = NULL,
                        .user_prompt       = comp_prompt,
                        .max_output_tokens = 2048,
                    };
                    size_t cbody_len = 0;
                    char *cbody = engine_request_alloc(&ccall, &cbody_len);
                    if (cbody) {
                        compaction_dispatched = true;
                        compacted = dispatch_https(v, cbody, cbody_len,
                                                   o.timeout_s * 1000, &cdr);
                        free(cbody);
                    }
                } else if (v->wire == ENGINE_WIRE_LOCAL_FIXTURE) {
                    compaction_dispatched = true;
                    compacted = dispatch_fixture(v, o.fixture_reply, &cdr);
                }
                const int64_t compaction_elapsed_ms =
                    (clock_now_monotonic_ns() - compaction_started_ns) /
                    1000000;
                if (compaction_dispatched &&
                    !invocation_log_add(&invocations, "compaction", compacted,
                                        &cdr, compaction_elapsed_ms)) {
                    engine_reply_free(&cdr.reply);
                    dispatch_failed = true;
                    break;
                }
                if (compacted) {
                    size_t extracted_len = 0;
                    if (engine_state_extract(cdr.reply.text,
                                             cdr.reply.text_len, turn_state,
                                             sizeof(turn_state),
                                             &extracted_len))
                        have_turn_state = true;
                    compactions++;
                    engine_emit(stdout,
                                "  compaction: turn %d's prompt would have "
                                "exceeded the budget; compacted to %zu "
                                "byte(s) of state\n",
                                turn, extracted_len);
                    (void)build_carried_preamble(
                        carried_preamble, sizeof(carried_preamble),
                        have_attempt_state, attempt_state, attempt_label,
                        have_turn_state, turn_state);
                } else {
                    engine_emit(stderr,
                                "engine_unit: turn %d needed compaction and "
                                "the compaction dispatch itself failed; "
                                "continuing with the uncompacted state\n",
                                turn);
                }
                engine_reply_free(&cdr.reply);
            }

            if (dispatch_failed)
                break;

            free(prompt);
            prompt = compose_prompt(&o, v, task, brief, carried_preamble,
                                    have_gate_tail ? gate_tail : NULL);
            if (!prompt) {
                dispatch_failed = true;
                verdict = ENGINE_VERDICT_REFUSED;
                break;
            }
        }

        /* A CLI vendor reads this file and nothing else, so for a wire with
         * no system channel of its own the rules have to be IN it. This is
         * also the archived record of the dispatch, so it must be exactly
         * what was delivered — an archive that differs from the delivery is
         * an archive nobody can check a run against.
         *
         * A refusal here refuses the DISPATCH. Falling back to writing the
         * prompt without the rules would be the original defect restored on
         * an error path, which is where defects prefer to live. */
        size_t delivered_len = 0;
        delivered = engine_prompt_compose(v->wire, prompt, &delivered_len);
        if (!delivered) {
            free(prompt);
            prompt = NULL;
            engine_emit(stderr,
                        "engine_unit: the composed prompt could not be "
                        "prepared for this engine; refusing dispatch\n");
            dispatch_failed = true;
            verdict = ENGINE_VERDICT_REFUSED;
            break;
        }

        /* The prompt is checked against the declared shape before it is
         * delivered. A prompt whose rules block, task, output protocol or
         * judging section is missing is not a weaker prompt — it is a
         * different job, and the work that comes back is evidence about
         * something nobody asked for. Refusing costs one run; dispatching
         * costs money and produces a receipt that means nothing. */
        struct engine_prompt_audit audit;
        if (!engine_prompt_audit_text(v->wire, delivered, &audit)) {
            char why[256];
            if (audit.missing)
                snprintf(why, sizeof(why),
                         "the composed prompt has no '%s' section",
                         audit.missing);
            else if (audit.misplaced)
                snprintf(why, sizeof(why),
                         "the composed prompt carries '%s' out of order",
                         audit.misplaced);
            else
                snprintf(why, sizeof(why),
                         "the composed prompt repeats '%s', which this "
                         "engine already receives on its own channel",
                         audit.repeated ? audit.repeated : "a section");
            free(delivered);
            delivered = NULL;
            free(prompt);
            prompt = NULL;
            engine_emit(stderr, "engine_unit: %s\n", why);
            dispatch_failed = true;
            verdict = ENGINE_VERDICT_REFUSED;
            break;
        }

        memset(prompt_path, 0, sizeof(prompt_path));
        if (o.state_dir && o.state_dir[0]
            && (size_t)snprintf(prompt_path, sizeof(prompt_path),
                                "%s/prompt.txt", o.state_dir)
                   < sizeof(prompt_path))
            (void)engine_emit_file(prompt_path, delivered, delivered_len);
        /* NOT freed here: a CLI vendor whose row takes the prompt as an
         * ARGUMENT hands these exact bytes to exec, so they have to outlive
         * the dispatch. The file above stays the archived record either
         * way. */

        /* Only an HTTP dialect has a request document. A CLI engine reads
         * the prompt from the file written above and a fixture reads a
         * canned reply, so building a body for either would produce a
         * document nothing sends — and, for a vendor row with no default
         * model, a body with a null model field in it. Build it where it is
         * used and nowhere else. */
        size_t body_len = 0;
        char *body = NULL;
        if (v->wire == ENGINE_WIRE_OPENAI_CHAT) {
            const struct engine_call call = {
                .vendor            = v,
                .model             = o.model,
                .reasoning_effort  = o.reasoning_effort,
                .system_prompt     = engine_system_rules(),
                .user_prompt       = prompt,
                .max_output_tokens = 65536,
            };
            body = engine_request_alloc(&call, &body_len);
            if (!body) {
                free(delivered);
                delivered = NULL;
                free(prompt);
                prompt = NULL;
                engine_emit(stderr,
                            "engine_unit: could not build the request body\n");
                dispatch_failed = true;
                verdict = ENGINE_VERDICT_REFUSED;
                break;
            }
        }
        free(prompt);
        prompt = NULL;

        const bool got = dispatch_with_retries(v, &o, body, body_len,
                                               prompt_path, delivered,
                                               workdir, &dr, &invocations);
        free(body);
        free(delivered);
        delivered = NULL;
        if (!got) {
            dispatch_failed = true;
            verdict = ENGINE_VERDICT_REFUSED;
            break;
        }

        /* Archive the raw completion before any envelope parsing touches
         * it. A FAIL(NO-CHANGE) verdict alone cannot say whether the model
         * proposed nothing, proposed something the envelope parser refused,
         * or never came back with the shape this harness expects —
         * reply.txt lets a human read exactly what the model said and
         * answer that by hand. */
        if (o.state_dir && o.state_dir[0]) {
            char reply_path[1024];
            if ((size_t)snprintf(reply_path, sizeof(reply_path),
                                 "%s/reply.txt", o.state_dir)
                       < sizeof(reply_path))
                (void)engine_emit_file(reply_path,
                                       dr.reply.text ? dr.reply.text : "",
                                       dr.reply.text_len);
        }

        if (dr.reply.usage.tokens_known || dr.reply.usage.cost_known)
            engine_emit(stdout,
                        "  spend:      prompt=%lld completion=%lld "
                        "cost_usd=%s%.6f\n",
                        (long long)dr.reply.usage.prompt_tokens,
                        (long long)dr.reply.usage.completion_tokens,
                        dr.reply.usage.cost_known ? "" : "unreported:",
                        dr.reply.usage.cost_usd);
        else
            engine_emit(stdout, "  spend:      not reported by %s\n", v->id);

        if (o.max_cost_usd > 0.0 && dr.reply.usage.cost_known
            && dr.reply.usage.cost_usd > o.max_cost_usd) {
            engine_emit(stderr,
                        "engine_unit: the reported spend exceeded "
                        "--max-cost-usd\n");
            dispatch_failed = true;
            verdict = ENGINE_VERDICT_REFUSED;
            break;
        }

        /* Apply. A CLI engine has already edited the worktree; an API
         * engine's reply carries file bodies. Either way the NEXT step
         * measures the diff. */
        bool refused = false;
        bool apply_failed = false;
        if (v->delivery == ENGINE_DELIVERS_ENVELOPE) {
            struct engine_patch patch;
            char applied_path[1024] = {0};
            if (o.state_dir && o.state_dir[0])
                (void)snprintf(applied_path, sizeof(applied_path),
                              "%s/applied.txt", o.state_dir);

            if (!engine_patch_parse(dr.reply.text, dr.reply.text_len,
                                    &patch)) {
                if (applied_path[0])
                    (void)engine_emit_file(applied_path,
                        "PARSE_REFUSED\nthe envelope parser rejected this "
                        "reply (a marker rule was violated or an envelope "
                        "was left open); see reply.txt for the exact text "
                        "and stderr of this run for which check fired.\n",
                        strlen("PARSE_REFUSED\nthe envelope parser rejected "
                               "this reply (a marker rule was violated or an "
                               "envelope was left open); see reply.txt for "
                               "the exact text and stderr of this run for "
                               "which check fired.\n"));
                engine_emit(stderr,
                            "engine_unit: turn %d's reply was refused by the "
                            "envelope parser; nothing was applied\n", turn);
                (void)snprintf(gate_tail, sizeof(gate_tail),
                              "Your last reply was refused by the envelope "
                              "parser (a marker rule was violated or an "
                              "envelope was left open); nothing from it was "
                              "applied. See the output protocol again and "
                              "send the whole reply, corrected.");
                have_gate_tail = true;
                refused = true;
            } else {
                engine_emit(stdout, "  reply:      %zu file(s) proposed\n",
                           patch.count);
                if (applied_path[0]) {
                    char desc[4096];
                    const size_t n =
                        engine_patch_describe(&patch, desc, sizeof(desc));
                    char header[128];
                    const int hn = snprintf(header, sizeof(header),
                                            "PARSED %zu file(s)\n",
                                            patch.count);
                    char buf[4096 + 128];
                    size_t used = 0;
                    if (hn > 0 && (size_t)hn < sizeof(buf)) {
                        memcpy(buf, header, (size_t)hn);
                        used = (size_t)hn;
                    }
                    if (n > 0 && used + n < sizeof(buf)) {
                        memcpy(buf + used, desc, n);
                        used += n;
                    } else if (patch.count == 0) {
                        static const char none[] =
                            "(the reply proposed no changes)\n";
                        if (used + sizeof(none) - 1 < sizeof(buf)) {
                            memcpy(buf + used, none, sizeof(none) - 1);
                            used += sizeof(none) - 1;
                        }
                    }
                    (void)engine_emit_file(applied_path, buf, used);
                }
                const char *shrink = patch_shrink_reason(workdir, &patch);
                if (shrink) {
                    if (applied_path[0]) {
                        char msg[768];
                        const int mn = snprintf(msg, sizeof(msg),
                            "SHRINK_REFUSED\n%s\n", shrink);
                        if (mn > 0)
                            (void)engine_emit_file(applied_path, msg,
                                (size_t)mn < sizeof(msg) ? (size_t)mn
                                                          : sizeof(msg) - 1);
                    }
                    engine_emit(stderr,
                               "engine_unit: turn %d's reply was refused "
                               "before apply: %s\n", turn, shrink);
                    (void)snprintf(gate_tail, sizeof(gate_tail),
                                  "Your last reply was refused before "
                                  "anything was written: %s", shrink);
                    have_gate_tail = true;
                    refused = true;
                    engine_patch_free(&patch);
                } else if (!apply_patch(workdir, &patch)) {
                    apply_failed = true;
                }
                engine_patch_free(&patch);
            }
        }

        if (apply_failed) {
            dispatch_failed = true;
            verdict = ENGINE_VERDICT_REFUSED;
            break;
        }

        changed = worktree_changed_files(workdir);
        engine_emit(stdout,
                    "  diff:       %zu changed path(s) in the worktree\n",
                    changed);

        proof_latency_ms = 0;
        if (!refused && !o.no_group && changed > 0) {
            char gate_log[1024] = {0};
            if (o.state_dir && o.state_dir[0])
                (void)snprintf(gate_log, sizeof(gate_log), "%s/gate.log",
                              o.state_dir);
            gate_tail[0] = '\0';
            const int64_t proof_started_ns = clock_now_monotonic_ns();
            (void)run_gate(&o, workdir, &gate, &timed_out,
                          gate_log[0] ? gate_log : NULL, gate_tail,
                          sizeof(gate_tail));
            /* A concurrent worktree rewrote the build-epoch lease out from
             * under this run (see env_epoch_race in engine/engine_verdict.h):
             * the harness raced itself, not a fault in the model's reply.
             * Retry the SAME gate once, on the SAME diff, before this is
             * ever turned into a verdict — a race that clears on retry must
             * never cost the unit a REFUSED that reads as the model's
             * fault. */
            if (gate.env_epoch_race) {
                engine_emit(stdout,
                            "  gate:       build-epoch race detected "
                            "(environment, not the model); retrying the "
                            "gate once\n");
                (void)run_gate(&o, workdir, &gate, &timed_out,
                              gate_log[0] ? gate_log : NULL, gate_tail,
                              sizeof(gate_tail));
            }
            proof_latency_ms =
                (clock_now_monotonic_ns() - proof_started_ns) / 1000000;
            if (cumulative_proof_ms >= 0 && proof_latency_ms >= 0 &&
                cumulative_proof_ms <= INT64_MAX - proof_latency_ms)
                cumulative_proof_ms += proof_latency_ms;
            else
                cumulative_proof_ms = ENGINE_RECEIPT_UNREPORTED;
            have_gate_tail = gate_tail[0] != '\0';
            engine_emit(stdout,
                        "  gate:       verdict_line=%s mode=%s groups_ran=%ld "
                        "groups_failed=%ld\n",
                        gate.saw_verdict_line ? "yes" : "NO",
                        gate.cached_mode ? "cached" : "cold", gate.groups_ran,
                        gate.groups_failed);
        } else if (!refused && changed == 0) {
            (void)snprintf(gate_tail, sizeof(gate_tail),
                          "Your last reply reported success but the diff was "
                          "empty: nothing changed in the worktree, so the "
                          "gate was not run. That is recorded as a FAILURE "
                          "regardless of what the gate would have said.");
            have_gate_tail = true;
        }

        verdict = engine_verdict_of(&gate, changed, timed_out, !o.no_group);

        /* Extract this turn's state independent of the envelope, per
         * engine/engine_state.h. A CLI wire never decodes reply text, so
         * there is nothing to extract from it — the model's own state, if
         * it left one anywhere the CLI printed, is not read here; that is a
         * scoping call, not an oversight: see the CLI OUTPUT PROTOCOL text,
         * which tells it to edit the worktree and print nothing. */
        size_t extracted_len = 0;
        if (dr.reply.text
            && engine_state_extract(dr.reply.text, dr.reply.text_len,
                                    turn_state, sizeof(turn_state),
                                    &extracted_len)) {
            have_turn_state = true;
            state_updated_last = true;
        } else {
            state_updated_last = false;
            /* Carried forward unchanged: turn_state/have_turn_state are
             * simply left as they were. */
        }
        if (o.state_dir && o.state_dir[0]) {
            char state_path[1024];
            if ((size_t)snprintf(state_path, sizeof(state_path),
                                 "%s/state.txt", o.state_dir)
                       < sizeof(state_path))
                (void)engine_emit_file(state_path,
                                       have_turn_state ? turn_state : "",
                                       have_turn_state ? strlen(turn_state)
                                                       : 0);
        }
        engine_emit(stdout, "  state:      %zu byte(s), %s\n",
                   have_turn_state ? strlen(turn_state) : 0,
                   state_updated_last ? "updated by the model"
                                      : "not updated by the model");
        engine_emit(stdout, "  turn %d/%d:   %s\n", turn, o.turns,
                   engine_verdict_name(verdict));

        if (engine_verdict_is_pass(verdict) || turn == o.turns)
            break;
    }

    const int64_t unit_elapsed_ms =
        (clock_now_monotonic_ns() - unit_started_ns) / 1000000;
    const bool needs_operator =
        have_turn_state
        && engine_state_next_is_operator(turn_state, strlen(turn_state));
    if (needs_operator)
        engine_emit(stdout,
                    "engine_unit: needs_operator=true — the unit's state "
                    "block names its next step as an operator action; see "
                    "state.txt\n");
    write_receipt(&o, v, &dr.reply.usage, &dr.cli_observation, dr.reply.model,
                  &gate, changed,
                  dr.attempts, dr.dispatch_latency_ms, proof_latency_ms,
                  verdict, have_turn_state ? strlen(turn_state) : 0,
                  state_updated_last, compactions, needs_operator);
    const bool durable_receipt = append_unit_receipt(
        &o, v, &dr.reply.usage, &dr.cli_observation, dr.reply.model, &gate,
        changed, dr.attempts, dr.dispatch_latency_ms, proof_latency_ms,
        cumulative_proof_ms, unit_elapsed_ms, dr.http_status, verdict,
        task_sha3_hex, &invocations);
    if (!durable_receipt)
        engine_emit(stderr,
                    "engine_unit: authoritative invocation receipt was "
                    "refused; this run cannot claim complete accounting\n");
    if (durable_receipt)
        engine_emit(stdout, "engine_unit: %s\n", engine_verdict_name(verdict));
    else
        engine_emit(stdout, "engine_unit: RECEIPT_REFUSED (gate verdict %s)\n",
                    engine_verdict_name(verdict));
    engine_emit(stdout, "  review the diff before anything else: git -C %s diff\n",
                workdir);
    engine_reply_free(&dr.reply);
    engine_secret_clear();
    free(prompt);
    free(delivered);
    free(task);
    free(brief);
    return durable_receipt && !dispatch_failed &&
                   engine_verdict_is_pass(verdict) ? 0 : 1;
}
