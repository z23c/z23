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
 * This is the C23 successor to tools/dev/grok-unit.sh, and it is meant to
 * preserve every lesson in that script's header rather than relearn them.
 *
 * ── SAFETY BOUNDARIES, ALL FAIL-CLOSED ───────────────────────────────────
 *   - Dispatching costs money and writes code, so it requires --yes-dispatch
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
 * lib/test/src/test_cold_join_sovereign.c P2 asserts exactly that.
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
 *   - lib/engine, which IS linked into the node, launches nothing at all. It
 *     has no spawn, no socket, and no file-system side effect. Every process
 *     this harness starts is started from this file.
 *   - and it is not a shell-out in the first place. It goes through
 *     lib/util zcl_spawn_capture, which execvp()s an argv directly. No
 *     /bin/sh, so no metacharacter ever expands, and nothing a model wrote
 *     can become a word in a command line.
 * If those three stop being true, the right answer is to fix this file, not
 * to widen the gate.
 */

#include "engine/engine.h"
#include "engine/engine_err.h"
#include "engine/engine_patch.h"
#include "engine/engine_prompt.h"
#include "engine/engine_secret.h"
#include "engine/engine_verdict.h"
#include "engine/engine_wire.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "platform/clock.h"
#include "tls_client.h"
#include "json/json.h"
#include "util/spawn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define UNIT_MAX_TASK_BYTES   (128u * 1024u)
#define UNIT_GATE_LOG_BYTES   (2u * 1024u * 1024u)
#define UNIT_DEFAULT_TURNS    3
#define UNIT_DEFAULT_TIMEOUT  3600
#define UNIT_MAX_TIMEOUT      21600

struct unit_opts {
    const char *engine_id;
    const char *task_path;
    const char *group;
    const char *territory;
    const char *model;
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
};

static void usage(void)
{
    printf(
"engine_unit — dispatch one scoped unit of work to an engine and judge it\n"
"\n"
"  engine_unit --engine ID --task FILE (--group NAME | --no-group)\n"
"              --territory NAME --yes-dispatch [options]\n"
"  engine_unit --list\n"
"\n"
"  --engine ID       which engine (see --list)\n"
"  --task FILE       the unit of work, in prose: one job, named files, a bar\n"
"  --group NAME      the test group that must run and pass afterwards\n"
"  --no-group        for a unit that genuinely cannot have one; the verdict\n"
"                    is then UNVERIFIED, which is not a pass\n"
"  --territory NAME  a territory the tree declares (see `z23 code territory`).\n"
"                    Its generated brief — owns, routes, reaches, the gates\n"
"                    that bind it, where its evidence is weakest — is put in\n"
"                    the prompt. A name the tree does not declare is refused.\n"
"  --yes-dispatch    REQUIRED. Dispatching costs money and writes code, so\n"
"                    it is opted into per run and can never be defaulted on\n"
"  --worktree DIR    isolated worktree to work in (created if absent)\n"
"  --model ID        override the engine's default model\n"
"  --turns N         repair turns when a reply does not apply (default %d)\n"
"  --timeout N       dispatch wall clock in seconds (default %d, max %d)\n"
"  --gate-timeout N  wall clock for the gate run; defaults to --timeout. A\n"
"                    cold worktree builds the tree first, which is minutes\n"
"                    of honest work that says nothing about the model\n"
"  --state-dir DIR   0700 directory for the prompt, gate log, and receipt\n"
"  --max-cost-usd X  refuse to continue past this reported spend\n"
"  --key-file PATH   a 0600 key file outside the repo\n"
"  --fixture-reply F for --engine fixture: a canned response body\n"
"  --dry-run         print the composed prompt and exit without dispatching\n"
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
        printf("  %-10s %-46s %s\n", v->id, v->display,
               v->costs_money ? "SPENDS" : "free");
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
        TAKE("--model", model)
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
 * the pass/fail token — is written to stdout by lib/test/src/test_parallel.c,
 * and a token that fails to arrive produces a REFUSED verdict rather than a
 * pass, so a lost message can never read as success. */
static int run(const char *const argv[], char *buf, size_t cap, int timeout_ms)
{
    return zcl_spawn_capture(argv, buf, cap, timeout_ms);
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
    if (o->state_dir[0] != '/')
        LOG_FAIL("engine_unit",
                 "refusing a relative --state-dir; pass an absolute path");
    if (mkdir(o->state_dir, 0700) != 0 && errno != EEXIST)
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
 * them, live in lib/engine (engine/engine_prompt.h). They used to be a
 * static here, and being a static here is how they went missing from every
 * CLI dispatch: no test links this tool, so nothing could assert them. */


/* ── the territory brief ──────────────────────────────────────────────────
 *
 * --territory used to be an opaque label: a string the operator typed, copied
 * into the prompt and into the receipt, meaning whatever the operator hoped
 * it meant. A model told "Territory: lib/net" learns nothing it could not
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
 * It is fetched by RUNNING that command rather than by linking lib/territory,
 * and that is not laziness. lib/territory reaches the code index and
 * therefore SQLite, while this program is compiled straight to an executable
 * alongside a TLS client precisely so that none of its objects can ever
 * appear in a scanned epoch tree (see ENGINE_UNIT_SRCS in the Makefile, and
 * the P2 assertion in lib/test/src/test_cold_join_sovereign.c that it keeps
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
 * lib/engine/include/engine/personas.def is the only place one exists, and
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

static char *compose_prompt(const struct unit_opts *o,
                            const struct engine_vendor *v, const char *task,
                            const char *brief, const char *repair_note)
{
    const size_t cap = ENGINE_MAX_PROMPT_BYTES;
    char *p = zcl_malloc(cap, "engine_unit_prompt");
    if (!p)
        LOG_NULL("engine_unit", "cannot allocate the prompt buffer");
    int n;
    if (brief)
        n = snprintf(p, cap,
            "# Your unit of work\n\n%s\n\n"
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
            "\n%s\n\n"
            "# %s\n\n"
            "# How this unit will be judged\n\n",
            task, o->territory, brief, delivery_text(v));
    else
        n = snprintf(p, cap,
            "# Your unit of work\n\n%s\n\n"
            "Territory: none declared.\n\n"
            "# %s\n\n"
            "# How this unit will be judged\n\n",
            task, delivery_text(v));
    if (n < 0 || (size_t)n >= cap) {
        free(p);
        LOG_NULL("engine_unit", "the composed prompt does not fit its cap");
    }

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
    enum engine_err     err;
    int                 http_status;
};

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
        .url          = v->url,
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
 * The three lessons from tools/dev/grok-unit.sh are preserved deliberately:
 * the output contract is stated IN BAND in the prompt file and never as a
 * forced response schema; the permission mode is the one that actually acts
 * headlessly rather than the one that narrates a plan; and a timeout is
 * reported as a timeout. No shell is invoked — zcl_spawn_capture execs argv
 * directly, so the prompt path never passes through metacharacter expansion. */
static bool dispatch_cli(const struct engine_vendor *v, const char *prompt_path,
                         const char *workdir, int turns, int timeout_ms,
                         struct dispatch_result *dr)
{
    if (!prompt_path || !prompt_path[0]) {
        dr->err = ENGINE_ERR_REFUSED;
        LOG_FAIL("engine_unit",
                 "a CLI engine reads its prompt from a file: pass --state-dir "
                 "so one can be written");
    }
    char turn_cap[32];
    (void)snprintf(turn_cap, sizeof(turn_cap), "%d", turns > 0 ? turns : 1);
    const char *const argv[] = {
        v->program, "--prompt-file", prompt_path, "--cwd", workdir,
        "--max-turns", turn_cap, "--always-approve", NULL
    };
    char *log = zcl_malloc(UNIT_GATE_LOG_BYTES, "engine_unit_cli_log");
    if (!log) {
        dr->err = ENGINE_ERR_REFUSED;
        LOG_FAIL("engine_unit", "cannot allocate the CLI transcript buffer");
    }
    const int rc = run(argv, log, UNIT_GATE_LOG_BYTES, timeout_ms);
    free(log);
    if (rc < 0) {
        dr->err = ENGINE_ERR_NETWORK;
        LOG_FAIL("engine_unit", "could not launch %s", v->program);
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
        if (mkdir(path, 0755) != 0 && errno != EEXIST) {
            *p = '/';
            LOG_FAIL("engine_unit", "cannot create a directory under the worktree");
        }
        *p = '/';
    }
    return true;
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

/* ── the gate ────────────────────────────────────────────────────────── */

/* Run the unit's group and READ THE NUMBERS. `t-fast` takes the checkout lock
 * itself, so this must not be wrapped in another one. The cache is disabled
 * for the child: a group served from cache did not execute the new code, and
 * a run that proves nothing must not be given the chance to look green. */
static bool run_gate(const struct unit_opts *o, const char *workdir,
                     struct engine_gate_reading *reading, bool *timed_out,
                     const char *log_path)
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
    (void)setenv("ZCL_TEST_CACHE", "0", 1);
    const int gate_s = o->gate_timeout_s > 0 ? o->gate_timeout_s : o->timeout_s;
    const int64_t started = clock_now_monotonic_ns();
    const int rc = run(argv, log, UNIT_GATE_LOG_BYTES, gate_s * 1000);
    const int64_t elapsed_ms = (clock_now_monotonic_ns() - started) / 1000000;

    if (log_path)
        (void)engine_emit_file(log_path, log, strlen(log));
    const bool read_ok = engine_gate_read(log, strlen(log), reading);
    free(log);

    /* A child killed by the deadline is a TIMEOUT, and saying so is the whole
     * point: an operator who sees FAIL raises nothing, and an operator who
     * sees TIMEOUT raises the clock. zcl_spawn_capture SIGKILLs at the
     * deadline, so a run that consumed the whole budget and produced no
     * verdict line is that case. */
    if (elapsed_ms >= (int64_t)gate_s * 1000 && !reading->saw_verdict_line)
        *timed_out = true;
    (void)rc;   /* never a verdict input; see engine/engine_verdict.h */
    return read_ok;
}

/* ── receipt ─────────────────────────────────────────────────────────── */

static void write_receipt(const struct unit_opts *o,
                          const struct engine_vendor *v,
                          const struct engine_usage *usage,
                          const struct engine_gate_reading *g,
                          size_t files_changed, enum engine_verdict verdict)
{
    char text[4096];
    const int n = snprintf(text, sizeof(text),
        "{\"schema\":\"zcl.engine_unit.v1\","
        "\"engine\":\"%s\",\"model\":\"%s\",\"territory\":\"%s\","
        "\"group\":\"%s\",\"files_changed\":%zu,"
        "\"groups_ran\":%ld,\"groups_failed\":%ld,\"cached\":%s,"
        "\"prompt_tokens\":%lld,\"completion_tokens\":%lld,"
        "\"cost_usd_known\":%s,\"cost_usd\":%.6f,"
        "\"verdict\":\"%s\"}\n",
        v->id, o->model ? o->model : (v->default_model ? v->default_model : ""),
        o->territory ? o->territory : "", o->group ? o->group : "",
        files_changed, g->groups_ran, g->groups_failed,
        g->cached_mode ? "true" : "false",
        (long long)usage->prompt_tokens, (long long)usage->completion_tokens,
        usage->cost_known ? "true" : "false", usage->cost_usd,
        engine_verdict_name(verdict));
    if (n < 0 || (size_t)n >= sizeof(text))
        return;
    engine_emit(stdout, "%s", text);
    if (o->state_dir && o->state_dir[0]) {
        char path[1024];
        if ((size_t)snprintf(path, sizeof(path), "%s/receipt.json",
                             o->state_dir) < sizeof(path))
            (void)engine_emit_file(path, text, strlen(text));
    }
}

/* ── the lifecycle ───────────────────────────────────────────────────── */

/* Dispatch, with the per-vendor retry budget and the breaker in front of it.
 * Returns the reply on success; sets *err to the last classified failure. */
static bool dispatch_with_retries(const struct engine_vendor *v,
                                  const struct unit_opts *o,
                                  const char *body, size_t body_len,
                                  const char *prompt_path, const char *workdir,
                                  struct dispatch_result *dr)
{
    struct engine_breaker breaker = {0};
    const int budget = v->max_retries < 0 ? 0 : v->max_retries;
    for (int attempt = 0; attempt <= budget; attempt++) {
        const int64_t now = clock_now_monotonic_ns() / 1000000;
        if (engine_breaker_is_open(&breaker, now)) {
            dr->err = ENGINE_ERR_REFUSED;
            LOG_FAIL("engine_unit",
                     "refusing to dispatch: %d consecutive failures opened the "
                     "circuit on %s", breaker.consecutive_failures, v->id);
        }
        bool ok = false;
        switch (v->wire) {
        case ENGINE_WIRE_OPENAI_CHAT:
            ok = dispatch_https(v, body, body_len, o->timeout_s * 1000, dr);
            break;
        case ENGINE_WIRE_LOCAL_CLI:
            ok = dispatch_cli(v, prompt_path, workdir, o->turns,
                              o->timeout_s * 1000, dr);
            break;
        case ENGINE_WIRE_LOCAL_FIXTURE:
            ok = dispatch_fixture(v, o->fixture_reply, dr);
            break;
        }
        engine_breaker_record(&breaker, ok ? ENGINE_OK : dr->err, now);
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
    if (o.list) {
        list_engines();
        return 0;
    }
    if (!o.engine_id)
        return fail_setup("need --engine ID (see --list)");
    const struct engine_vendor *v = engine_by_id(o.engine_id);
    if (!v)
        return fail_setup("unknown --engine; see --list");
    if (!o.task_path)
        return fail_setup("need --task FILE");
    if (!o.group && !o.no_group)
        return fail_setup("need --group NAME, or --no-group if this unit "
                          "truly cannot have one");
    if (o.turns < 1 || o.turns > 10)
        return fail_setup("--turns must be between 1 and 10");
    if (o.timeout_s < 1 || o.timeout_s > UNIT_MAX_TIMEOUT)
        return fail_setup("--timeout is outside its permitted range");
    if (o.gate_timeout_s != 0
        && (o.gate_timeout_s < 1 || o.gate_timeout_s > UNIT_MAX_TIMEOUT))
        return fail_setup("--gate-timeout is outside its permitted range");

    size_t task_len = 0;
    char *task = read_file(o.task_path, UNIT_MAX_TASK_BYTES, &task_len);
    if (!task)
        return 2;

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

    char *prompt = compose_prompt(&o, v, task, brief, NULL);
    free(task);
    free(brief);
    if (!prompt)
        return 2;

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
        return 0;
    }
    /* The opt-in. Deliberately checked AFTER --dry-run so composing a prompt
     * is free, and BEFORE anything that costs money or writes a file. */
    if (!o.yes_dispatch) {
        free(prompt);
        return fail_setup(
            "refusing to dispatch without --yes-dispatch. This spends money "
            "and writes code; it is opted into per run, never defaulted on");
    }

    char where[128] = {0};
    if (!engine_secret_load(v, o.key_file, where, sizeof(where))) {
        free(prompt);
        return fail_setup("no usable API key; see --help");
    }
    engine_emit(stdout, "engine_unit: %s\n", v->display);
    engine_emit(stdout, "  credential: %s\n", where);

    char workdir[1024];
    if (!state_dir_prepare(&o)) {
        free(prompt);
        engine_secret_clear();
        return 2;
    }
    if (!worktree_prepare(&o, workdir, sizeof(workdir))) {
        free(prompt);
        engine_secret_clear();
        return 2;
    }

    /* A CLI vendor reads this file and nothing else, so for a wire with no
     * system channel of its own the rules have to be IN it. This is also the
     * archived record of the dispatch, so it must be exactly what was
     * delivered — an archive that differs from the delivery is an archive
     * nobody can check a run against.
     *
     * A refusal here refuses the DISPATCH. Falling back to writing the
     * prompt without the rules would be the original defect restored on an
     * error path, which is where defects prefer to live. */
    size_t delivered_len = 0;
    char *delivered = engine_prompt_compose(v->wire, prompt, &delivered_len);
    if (!delivered) {
        free(prompt);
        engine_secret_clear();
        return fail_setup("the composed prompt could not be prepared for this "
                          "engine; refusing to dispatch a partial one");
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
        free(prompt);
        engine_secret_clear();
        return fail_setup(why);
    }

    char prompt_path[1024] = {0};
    if (o.state_dir && o.state_dir[0]
        && (size_t)snprintf(prompt_path, sizeof(prompt_path), "%s/prompt.txt",
                            o.state_dir) < sizeof(prompt_path))
        (void)engine_emit_file(prompt_path, delivered, delivered_len);
    free(delivered);

    /* Only an HTTP dialect has a request document. A CLI engine reads the
     * prompt from the file written above and a fixture reads a canned reply,
     * so building a body for either would produce a document nothing sends —
     * and, for a vendor row with no default model, a body with a null model
     * field in it. Build it where it is used and nowhere else. */
    size_t body_len = 0;
    char *body = NULL;
    if (v->wire == ENGINE_WIRE_OPENAI_CHAT) {
        const struct engine_call call = {
            .vendor            = v,
            .model             = o.model,
            .system_prompt     = engine_system_rules(),
            .user_prompt       = prompt,
            .max_output_tokens = 32768,
        };
        body = engine_request_alloc(&call, &body_len);
        if (!body) {
            free(prompt);
            engine_secret_clear();
            return fail_setup("could not build the request body");
        }
    }
    free(prompt);

    struct dispatch_result dr = {0};
    const bool got = dispatch_with_retries(v, &o, body, body_len, prompt_path,
                                           workdir, &dr);
    free(body);
    engine_secret_clear();
    if (!got)
        return 1;

    if (dr.reply.usage.tokens_known || dr.reply.usage.cost_known)
        engine_emit(stdout,
                    "  spend:      prompt=%lld completion=%lld cost_usd=%s%.6f\n",
                    (long long)dr.reply.usage.prompt_tokens,
                    (long long)dr.reply.usage.completion_tokens,
                    dr.reply.usage.cost_known ? "" : "unreported:",
                    dr.reply.usage.cost_usd);
    else
        engine_emit(stdout, "  spend:      not reported by %s\n", v->id);

    if (o.max_cost_usd > 0.0 && dr.reply.usage.cost_known
        && dr.reply.usage.cost_usd > o.max_cost_usd) {
        engine_reply_free(&dr.reply);
        return fail_setup("the reported spend exceeded --max-cost-usd");
    }

    /* Apply. A CLI engine has already edited the worktree; an API engine's
     * reply carries file bodies. Either way the NEXT step measures the diff. */
    if (v->delivery == ENGINE_DELIVERS_ENVELOPE) {
        struct engine_patch patch;
        if (!engine_patch_parse(dr.reply.text, dr.reply.text_len, &patch)) {
            engine_reply_free(&dr.reply);
            engine_emit(stderr, "engine_unit: the reply was refused by the "
                                "envelope parser; nothing was applied\n");
            return 1;
        }
        engine_emit(stdout, "  reply:      %zu file(s) proposed\n", patch.count);
        const bool applied = apply_patch(workdir, &patch);
        engine_patch_free(&patch);
        if (!applied) {
            engine_reply_free(&dr.reply);
            return 1;
        }
    }

    const size_t changed = worktree_changed_files(workdir);
    engine_emit(stdout, "  diff:       %zu changed path(s) in the worktree\n",
                changed);

    struct engine_gate_reading gate = {0};
    bool timed_out = false;
    if (!o.no_group && changed > 0) {
        char gate_log[1024] = {0};
        if (o.state_dir && o.state_dir[0])
            (void)snprintf(gate_log, sizeof(gate_log), "%s/gate.log",
                           o.state_dir);
        (void)run_gate(&o, workdir, &gate, &timed_out,
                       gate_log[0] ? gate_log : NULL);
        engine_emit(stdout,
                    "  gate:       verdict_line=%s mode=%s groups_ran=%ld "
                    "groups_failed=%ld\n",
                    gate.saw_verdict_line ? "yes" : "NO",
                    gate.cached_mode ? "cached" : "cold", gate.groups_ran,
                    gate.groups_failed);
    }

    const enum engine_verdict verdict =
        engine_verdict_of(&gate, changed, timed_out, !o.no_group);
    write_receipt(&o, v, &dr.reply.usage, &gate, changed, verdict);
    engine_emit(stdout, "engine_unit: %s\n", engine_verdict_name(verdict));
    engine_emit(stdout, "  review the diff before anything else: git -C %s diff\n",
                workdir);
    engine_reply_free(&dr.reply);
    return engine_verdict_is_pass(verdict) ? 0 : 1;
}
