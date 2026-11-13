/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_contrib_inbox: whole passes of build/bin/z23-contrib-inbox over fixture
 * board lists (--fixture-list), in dry-run (no post reaches the real board),
 * with the engine-unit fixture engine (--engine fixture --fixture-reply) as
 * the only model. Each case runs in its own temp state dir, responder checkout
 * and lock file, so nothing reaches a live node, a timer or a real model.
 *
 * Scenarios: maintainer and own posts are ignored (any post from a maintainer
 * host, and any maintainer agent on any host, lead included); a contributor
 * post is answered; requests are classified and updates ignored; a
 * question is answered once; an answer with an IPv4, or an unknown 64-hex, is
 * refused; a known 64-hex passes; an ESCALATE reply is queued; a repeat pass
 * posts nothing new; the daily cap stops model calls; four posts per pass at
 * most; a held run lock exits quietly; an unreadable or malformed fixture fails
 * closed. Repairs: a ledger that cannot be written posts nothing and fails the
 * pass; text after the ANSWER line is never posted; the filter words; a primary
 * checkout is refused as responder; a failed fetch or post escalates.
 */

#include "test/test_core.h"
#include "util/spawn.h"

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CI_CHECK(name, expr)                                                 \
    do {                                                                     \
        const bool ci_ok_ = (expr);                                          \
        if (!ci_ok_) failures++;                                             \
        printf("contrib_inbox: %s %s\n", ci_ok_ ? "OK  " : "FAIL", (name));  \
    } while (0)

static const char CI_BIN[] = "build/bin/z23-contrib-inbox";
static const char CI_ENGINE[] = "build/bin/z23-engine-unit";
/* Public node keys of the maintainer hosts, as the tool classifies them. */
static const char CI_MAINT[] =
    "331145f4ab9bbbc4a571b69c2e9abcbe58f3423ba7389525dbd96e07b25cc598";
static const char CI_OUTSIDE[] =
    "2222222222222222222222222222222222222222222222222222222222222222";
static const char CI_ZERO[] =
    "0000000000000000000000000000000000000000000000000000000000000000";

struct ci_env {
    char d[600];     /* absolute scenario directory */
    char state[640];
    char resp[640];  /* responder: a linked worktree the tool adds to main */
    char mainrepo[640];  /* a repo whose origin/main the responder tracks */
    char origin[640];
    char list[640];
    char reply[640];
    char lock[640];
};

/* A 64-hex id made of one repeated digit: distinct per case, always hex. */
static void ci_hex64(char out[65], char c)
{
    memset(out, c, 64);
    out[64] = '\0';
}

static bool ci_wf(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    const size_t n = strlen(text);
    const bool ok = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static bool ci_file_has(const char *path, const char *needle)
{
    static char body[256 * 1024];
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    const size_t n = fread(body, 1, sizeof(body) - 1, f);
    (void)fclose(f);
    body[n] = '\0';
    return strstr(body, needle) != NULL;
}

/* How many lines of the file contain needle. */
static int ci_count(const char *path, const char *needle)
{
    static char body[256 * 1024];
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    const size_t n = fread(body, 1, sizeof(body) - 1, f);
    (void)fclose(f);
    body[n] = '\0';
    int count = 0;
    for (const char *p = strstr(body, needle); p; p = strstr(p + 1, needle))
        count++;
    return count;
}

static bool ci_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static bool ci_git(const char *const argv[])
{
    char scratch[4096];
    return zcl_spawn_capture(argv, scratch, sizeof(scratch), 120000) == 0;
}

/* The responder is a linked worktree of `main`, which has an origin with a
 * main branch, as the live layout is: the tool adds the worktree itself on the
 * first model call, then fetches and checks out origin/main in it. */
static bool ci_setup(struct ci_env *e, const char *tag)
{
    char rel[512];
    test_make_tmpdir(rel, sizeof(rel), "contrib_inbox", tag);
    if (!test_abs_path(rel, e->d, sizeof(e->d)))
        return false;
    (void)snprintf(e->state, sizeof(e->state), "%s/state", e->d);
    (void)snprintf(e->resp, sizeof(e->resp), "%s/resp", e->d);
    (void)snprintf(e->mainrepo, sizeof(e->mainrepo), "%s/main", e->d);
    (void)snprintf(e->origin, sizeof(e->origin), "%s/origin.git", e->d);
    (void)snprintf(e->list, sizeof(e->list), "%s/list.json", e->d);
    (void)snprintf(e->reply, sizeof(e->reply), "%s/reply.json", e->d);
    (void)snprintf(e->lock, sizeof(e->lock), "%s/haiku.lock", e->d);
    const char *const bare[] = { "git", "init", "-q", "--bare", e->origin, NULL };
    const char *const init[] = { "git", "init", "-q", e->mainrepo, NULL };
    char ignore[700];
    if (snprintf(ignore, sizeof(ignore), "%s/.gitignore", e->mainrepo) >= (int)sizeof(ignore))
        return false;
    const char *const add[] = { "git", "-C", e->mainrepo, "add", "--", ".gitignore", NULL };
    const char *const commit[] = { "git", "-C", e->mainrepo, "-c", "user.name=ci",
                                   "-c", "user.email=ci@example.invalid", "-c",
                                   "commit.gpgsign=false", "commit", "-q",
                                   "--allow-empty", "-m", "init", NULL };
    const char *const remote[] = { "git", "-C", e->mainrepo, "remote", "add", "origin",
                                   e->origin, NULL };
    const char *const push[] = { "git", "-C", e->mainrepo, "push", "-q", "origin",
                                 "HEAD:refs/heads/main", NULL };
    const char *const fetch[] = { "git", "-C", e->mainrepo, "fetch", "-q", "origin", NULL };
    return ci_git(bare) && ci_git(init) && ci_wf(ignore, ".zvcs/\n") && ci_git(add) &&
           ci_git(commit) && ci_git(remote) &&
           ci_git(push) && ci_git(fetch);
}

/* One post object for the fixture list. Field names are the board's. */
static void ci_entry(char *out, size_t cap, const char *id, const char *host,
                     const char *agent, const char *kind, const char *text)
{
    (void)snprintf(out, cap,
                   "{\"id\":\"%s\",\"host\":\"%s\",\"kind\":\"%s\","
                   "\"agent\":\"%s\",\"ref\":\"%s\",\"text\":\"%s\","
                   "\"created_at\":1}",
                   id, host, kind, agent, CI_ZERO, text);
}

/* Write a list reply, newest post first, from n prebuilt entries. */
/* Fixture pages use ordinal suffixes; the wire cursor comes from the last post. */
static bool ci_list_page(const struct ci_env *e, int cursor,
                         const char *const entries[], int n, int next)
{
    static char body[64 * 1024];
    char path[700];
    size_t len = (size_t)snprintf(body, sizeof(body),
                                  "{\"ok\":true,\"data\":{\"posts\":[");
    for (int i = 0; i < n && len < sizeof(body) - 1024; i++)
        len += (size_t)snprintf(body + len, sizeof(body) - len, "%s%s",
                                i ? "," : "", entries[i]);
    if (next > 0) {
        if (n == 0 || strncmp(entries[n - 1], "{\"id\":\"", 7) != 0 || strlen(entries[n - 1]) < 71) return false;
        (void)snprintf(body + len, sizeof(body) - len,
                       "],\"has_more\":true,\"next_created_at\":1,\"next_id\":\"%.*s\"}}\n",
                       64, entries[n - 1] + 7);
    } else
        (void)snprintf(body + len, sizeof(body) - len, "],\"has_more\":false}}\n");
    if (cursor == 0)
        return ci_wf(e->list, body);
    (void)snprintf(path, sizeof(path), "%s.%d", e->list, cursor);
    return ci_wf(path, body);
}

static bool ci_list(const struct ci_env *e, const char *const entries[], int n)
{
    return ci_list_page(e, 0, entries, n, 0);
}

/* The engine-unit fixture reply: an OpenAI-shaped completion whose content
 * is the given text. The text here never carries a quote or a backslash. */
static bool ci_model_reply(const struct ci_env *e, const char *content)
{
    char body[4096];
    (void)snprintf(body, sizeof(body),
                   "{\"choices\":[{\"message\":{\"content\":\"%s\"}}],"
                   "\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,"
                   "\"total_tokens\":2}}",
                   content);
    return ci_wf(e->reply, body);
}

/* How one pass differs from the default dry run. */
struct ci_run_opts {
    bool live;             /* no --dry-run: the post goes to the --z23 program */
    bool live_list;        /* fetch through the supplied isolated fake z23 */
    const char *z23;       /* the fake poster, e.g. /bin/false */
    const char *engine;    /* isolated failing engine fixture, when set */
    const char *responder; /* overrides the scenario's responder path */
    const char *telegram_group; /* opt-in group consumer over isolated fixtures */
    long fsize;            /* RLIMIT_FSIZE for the tool, or -1 for none */
};

/* Spawn with the tool's file size limit lowered, so an append past it fails
 * with EFBIG the way a full disk would. SIGXFSZ is ignored across the spawn. */
static int ci_spawn_limited(const char *const argv[], char *out, size_t cap,
                            long fsize, bool *timed_out)
{
    struct rlimit old, lim;
    if (fsize < 0)
        return zcl_spawn_capture_merged_observed(argv, out, cap, 120000, timed_out);
    (void)getrlimit(RLIMIT_FSIZE, &old);
    lim = old;
    lim.rlim_cur = (rlim_t)fsize;
    void (*const old_sig)(int) = signal(SIGXFSZ, SIG_IGN);
    (void)setrlimit(RLIMIT_FSIZE, &lim);
    const int rc =
        zcl_spawn_capture_merged_observed(argv, out, cap, 120000, timed_out);
    (void)setrlimit(RLIMIT_FSIZE, &old);
    (void)signal(SIGXFSZ, old_sig);
    return rc;
}

/* One pass of the tool against the scenario's fixtures. The exit status is
 * returned; the events are in state/events.log and the tool's merged output
 * in run.log. No shell: the argv goes straight to exec. */
static int ci_pass_with(const struct ci_env *e, const struct ci_run_opts *o)
{
    static char out[65536];
    char bin[700], engine[700], logp[800];
    if (!test_abs_path(CI_BIN, bin, sizeof(bin)) ||
        !test_abs_path(CI_ENGINE, engine, sizeof(engine)))
        return -1;
    const char *argv[32];
    size_t n = 0;
    argv[n++] = bin;
    if (!o->live)
        argv[n++] = "--dry-run";
    if (!o->live_list) { argv[n++] = "--fixture-list"; argv[n++] = e->list; }
    const char *const rest[] = {
        "--state-dir", e->state, "--fixture-reply",
        e->reply, "--engine", "fixture", "--engine-unit", o->engine ? o->engine : engine, "--main",
        e->mainrepo, "--haiku-lock", e->lock, "--engine-timeout-s", "60",
        "--responder", o->responder ? o->responder : e->resp,
    };
    for (size_t i = 0; i < sizeof(rest) / sizeof(*rest); i++)
        argv[n++] = rest[i];
    if (o->z23) {
        argv[n++] = "--z23";
        argv[n++] = o->z23;
    }
    if (o->telegram_group) {
        argv[n++] = "--telegram-group";
        argv[n++] = o->telegram_group;
    }
    argv[n] = NULL;
    bool timed_out = false;
    const int rc = ci_spawn_limited(argv, out, sizeof(out), o->fsize, &timed_out);
    (void)snprintf(logp, sizeof(logp), "%s/run.log", e->d);
    FILE *f = fopen(logp, "w");
    if (f) {
        (void)fputs(out, f);
        (void)fclose(f);
    }
    return timed_out ? -1 : rc;
}

static int ci_pass(const struct ci_env *e)
{
    const struct ci_run_opts plain = { .fsize = -1 };
    return ci_pass_with(e, &plain);
}

static char *ci_path(const struct ci_env *e, char *out, size_t cap,
                     const char *leaf)
{
    (void)snprintf(out, cap, "%s/%s", e->state, leaf);
    return out;
}

static bool ci_has_events(const struct ci_env *e, const char *needle)
{
    char p[800];
    return ci_file_has(ci_path(e, p, sizeof(p), "events.log"), needle);
}

static int ci_events_count(const struct ci_env *e, const char *needle)
{
    char p[800];
    return ci_count(ci_path(e, p, sizeof(p), "events.log"), needle);
}

static bool ci_setup_list_one(struct ci_env *e, const char *tag,
                              const char *id, const char *host,
                              const char *agent, const char *kind,
                              const char *text)
{
    char entry[2048];
    const char *list[1];
    if (!ci_setup(e, tag))
        return false;
    ci_entry(entry, sizeof(entry), id, host, agent, kind, text);
    list[0] = entry;
    return ci_list(e, list, 1);
}

static bool ci_state_has(const struct ci_env *e, const char *leaf, const char *needle);

/* ── cases ───────────────────────────────────────────────────────────── */

static int case_maintainer_ignored(void)
{
    struct ci_env e;
    char a[65], b[65];
    ci_hex64(a, 'a');
    ci_hex64(b, 'b');
    int failures = 0;
    char m1[2048], m2[2048];
    const char *list[2] = { m2, m1 };
    if (!ci_setup(&e, "maint"))
        return 1;
    ci_entry(m1, sizeof(m1), a, CI_MAINT, "maintainer-owner", "question", "maint words");
    ci_entry(m2, sizeof(m2), b, CI_MAINT, "claude-r1-responder", "note", "own words");
    CI_CHECK("maintainer posts are staged", ci_list(&e, list, 2));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("maintainer and own posts are never announced",
             !ci_has_events(&e, "NEW "));
    CI_CHECK("no post is made for them", !ci_has_events(&e, "DRY post"));
    return failures;
}

/* A post from a maintainer host is ours whatever agent it names. */
static int case_helper_on_maint_host(void)
{
    struct ci_env e;
    char c[65];
    ci_hex64(c, 'c');
    int failures = 0;
    CI_CHECK("a helper post on a maintainer host is staged",
             ci_setup_list_one(&e, "helper", c, CI_MAINT, "helper-codex",
                               "question", "how does the gate work"));
    CI_CHECK("a fixture answer for the helper is staged",
             ci_model_reply(&e, "ANSWER: see the gate at tools/lint/lintc/gate_commands.def"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the helper post on a maintainer host is never announced",
             !ci_has_events(&e, "NEW "));
    CI_CHECK("the helper post on a maintainer host is never answered",
             !ci_has_events(&e, "ANSWERED") && !ci_has_events(&e, "DRY post"));
    return failures;
}

/* The lead's post from a maintainer host is never acknowledged (post 508de1ec21
 * was a lead post on r1's host, acknowledged in error). */
static int case_lead_on_maint_host_ignored(void)
{
    struct ci_env e;
    char l[65];
    ci_hex64(l, 'e');
    int failures = 0;
    CI_CHECK("a lead post on a maintainer host is staged",
             ci_setup_list_one(&e, "leadpost", l, CI_MAINT, "lead",
                               "question", "maintainer status update"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the lead post is never announced", !ci_has_events(&e, "NEW "));
    CI_CHECK("the lead post is never acknowledged",
             !ci_has_events(&e, "Received") && ci_events_count(&e, "DRY post") == 0);
    return failures;
}

/* A maintainer agent is ours on any host, so the tool never acknowledges its
 * own posts even when they arrive from a host that is not a maintainer host. */
static int case_own_agent_any_host_ignored(void)
{
    struct ci_env e;
    char o[65], p[65];
    ci_hex64(o, 'f');
    ci_hex64(p, '1');
    int failures = 0;
    char own[2048], lead[2048];
    const char *list[2] = { own, lead };
    if (!ci_setup(&e, "ownany"))
        return 1;
    ci_entry(own, sizeof(own), o, CI_OUTSIDE, "claude-r1-responder", "note",
             "our own received note");
    ci_entry(lead, sizeof(lead), p, CI_OUTSIDE, "lead", "question",
             "lead words from an outside host");
    CI_CHECK("own and lead posts from an outside host are staged", ci_list(&e, list, 2));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("own and lead posts from an outside host are never announced",
             !ci_has_events(&e, "NEW "));
    CI_CHECK("no post is made for them", ci_events_count(&e, "DRY post") == 0);
    return failures;
}

static int case_need_acknowledged(void)
{
    struct ci_env e;
    char d[65], unit[700];
    ci_hex64(d, 'd');
    int failures = 0;
    CI_CHECK("a need post is staged",
             ci_setup_list_one(&e, "need", d, CI_OUTSIDE, "outsider", "need",
                               "please review my change"));
    CI_CHECK("the request classification is staged", ci_model_reply(&e, "ESCALATE: review requires maintainer"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the need is locally escalated", ci_state_has(&e, "escalate.tsv", d));
    CI_CHECK("the request is not publicly acknowledged", ci_events_count(&e, "DRY post ref=") == 0);
    (void)snprintf(unit, sizeof(unit), "%s/units/%s", e.state, d);
    CI_CHECK("the model classifies the need", ci_exists(unit));
    return failures;
}

static int case_status_ignored(void)
{
    struct ci_env e;
    char id[65];
    char log[800], prompt[800];
    ci_hex64(id, '9');
    int failures = 0;
    CI_CHECK("a status update is staged", ci_setup_list_one(&e, "ignored", id, CI_OUTSIDE,
             "outsider", "note", "build completed; no action needed"));
    CI_CHECK("the ignore classification is staged", ci_model_reply(&e, "IGNORE: status only"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    (void)snprintf(log, sizeof(log), "%s/units/%s/engine.log", e.state, id);
    (void)snprintf(prompt, sizeof(prompt), "%s/units/%s/eu/prompt.txt", e.state, id);
    CI_CHECK("read-only fixture completed as a report", ci_file_has(log, "\"verdict\":\"REPORTED\""));
    CI_CHECK("report protocol preserves the decision line", ci_file_has(prompt, "omit the state block"));
    CI_CHECK("status cannot mask an unresolved request", ci_file_has(prompt, "Accompanying status does not cancel it"));
    CI_CHECK("the ignored update is recorded", ci_has_events(&e, "IGNORED "));
    CI_CHECK("no public acknowledgment or escalation is emitted",
             !ci_has_events(&e, "DRY post") && !ci_has_events(&e, "ESCALATE "));
    CI_CHECK("the ignored update is not replayed", ci_pass(&e) == 0 && ci_events_count(&e, "IGNORED ") == 1);
    return failures;
}

static bool ci_bad_ignore(const char *tag, char digit, const char *reply)
{
    struct ci_env e;
    char id[65];
    ci_hex64(id, digit);
    return ci_setup_list_one(&e, tag, id, CI_OUTSIDE, "outsider", "note", "status") &&
           ci_model_reply(&e, reply) && ci_pass(&e) == 0 &&
           ci_state_has(&e, "escalate.tsv", id) && !ci_has_events(&e, "IGNORED ") &&
           !ci_has_events(&e, "DRY post");
}

static int case_ignore_malformed(void)
{
    int failures = 0;
    CI_CHECK("empty ignore escalates privately", ci_bad_ignore("ignore-empty", 'a', "IGNORE:"));
    CI_CHECK("whitespace ignore escalates privately", ci_bad_ignore("ignore-space", 'b', "IGNORE:   "));
    CI_CHECK("nonfinal ignore escalates privately", ci_bad_ignore("ignore-trail", 'c', "IGNORE: reason\\ntrailing"));
    return failures;
}

static int case_model_failure_no_post(void)
{
    struct ci_env e;
    char id[65], fake[700];
    ci_hex64(id, 'b');
    int failures = 0;
    CI_CHECK("a request is staged", ci_setup_list_one(&e, "enginefail", id, CI_OUTSIDE,
             "outsider", "question", "how do I build"));
    (void)snprintf(fake, sizeof fake, "%s/engine-fail", e.d);
    CI_CHECK("a failing engine writes an answer", ci_wf(fake,
        "#!/bin/sh\nwhile [ \"$1\" != --state-dir ]; do shift || exit 3; done\n"
        "shift; printf 'ANSWER: run make z23\\n' > \"$1/reply.txt\"\nexit 7\n") && chmod(fake, 0700) == 0);
    const struct ci_run_opts opts = { .engine = fake, .fsize = -1 };
    CI_CHECK("the pass handles the failed engine", ci_pass_with(&e, &opts) == 0);
    CI_CHECK("failed engine output is not published", !ci_has_events(&e, "ANSWERED") && !ci_has_events(&e, "DRY post"));
    CI_CHECK("failure is locally escalated", ci_state_has(&e, "escalate.tsv", id));
    return failures;
}

static int case_question_answered(void)
{
    struct ci_env e;
    char f[65];
    ci_hex64(f, 'f');
    int failures = 0;
    CI_CHECK("a question post is staged",
             ci_setup_list_one(&e, "answer", f, CI_OUTSIDE, "outsider",
                               "question", "how do I build the node"));
    CI_CHECK("a fixture answer is staged",
             ci_model_reply(&e, "ANSWER: run make z23 as the build target"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the question is answered", ci_has_events(&e, "ANSWERED"));
    CI_CHECK("the answer is posted as a responder note",
             ci_has_events(&e, "Automated maintainer responder"));
    CI_CHECK("the answer text is posted",
             ci_has_events(&e, "run make z23 as the build target"));
    return failures;
}

static int case_refusals(void)
{
    struct ci_env e;
    char g[65];
    int failures = 0;
    ci_hex64(g, 'c');
    CI_CHECK("an IPv4 question is staged",
             ci_setup_list_one(&e, "ipv4", g, CI_OUTSIDE, "outsider",
                               "question", "where does it listen"));
    CI_CHECK("the IPv4 answer is staged",
             ci_model_reply(&e, "ANSWER: it listens on 10.1.2.3"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("an IPv4 answer is refused, not answered",
             !ci_has_events(&e, "ANSWERED") &&
                 ci_has_events(&e, "answer missing or refused by the filter"));
    return failures;
}

/* An answer longer than the public page's preview is refused, not posted
 * clipped: a reader without a node sees only the first 480 bytes. */
static int case_long_answer_refused(void)
{
    struct ci_env e;
    char g[65], answer[520];
    int failures = 0;
    ci_hex64(g, 'c');
    int k = snprintf(answer, sizeof(answer), "ANSWER: see docs/README.md ");
    while (k > 0 && (size_t)k < sizeof(answer) - 1 && k < 420)
        answer[k++] = 'a';
    answer[k] = '\0';
    CI_CHECK("a question is staged",
             ci_setup_list_one(&e, "long", g, CI_OUTSIDE, "outsider",
                               "question", "what does the readme say"));
    CI_CHECK("the over-long answer is staged", ci_model_reply(&e, answer));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("an answer past the preview is refused, not answered",
             !ci_has_events(&e, "ANSWERED") &&
                 ci_has_events(&e, "answer missing or refused by the filter"));
    return failures;
}

static int case_unknown_hex_refused(void)
{
    struct ci_env e;
    char g[65], d[65];
    int failures = 0;
    ci_hex64(g, 'c');
    ci_hex64(d, 'd');
    CI_CHECK("a question with no hash is staged",
             ci_setup_list_one(&e, "hexbad", g, CI_OUTSIDE, "outsider",
                               "question", "what is the wire tag"));
    char answer[256], dd[65];
    ci_hex64(dd, 'd');
    (void)snprintf(answer, sizeof(answer), "ANSWER: the tag is %s", dd);
    CI_CHECK("the answer carries a hash the thread never had",
             ci_model_reply(&e, answer));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("an unknown 64-hex answer is refused",
             !ci_has_events(&e, "ANSWERED"));
    return failures;
}

static int case_known_hex_allowed(void)
{
    struct ci_env e;
    char q[65];
    int failures = 0;
    ci_hex64(q, 'e');
    char text[256], answer[256];
    ci_hex64(q, 'e');
    char hash5[65];
    ci_hex64(hash5, '5');
    (void)snprintf(text, sizeof(text), "is %s the id", hash5);
    CI_CHECK("a question quoting a hash is staged",
             ci_setup_list_one(&e, "hexok", q, CI_OUTSIDE, "outsider",
                               "question", text));
    (void)snprintf(answer, sizeof(answer), "ANSWER: yes, %s is that id", hash5);
    CI_CHECK("the answer repeats the quoted hash",
             ci_model_reply(&e, answer));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("a quoted hash in the thread is allowed",
             ci_has_events(&e, "ANSWERED"));
    return failures;
}

static int case_escalate_reply(void)
{
    struct ci_env e;
    char k[65], esc[800];
    int failures = 0;
    ci_hex64(k, '6');
    CI_CHECK("a policy question is staged",
             ci_setup_list_one(&e, "esc", k, CI_OUTSIDE, "outsider",
                               "question", "should the fee change"));
    CI_CHECK("the model asks for escalation",
             ci_model_reply(&e, "ESCALATE: policy decision for the lead"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the escalation reason is queued",
             ci_file_has(ci_path(&e, esc, sizeof(esc), "escalate.tsv"),
                         "policy decision for the lead"));
    CI_CHECK("nothing is publicly posted", !ci_has_events(&e, "ANSWERED") && !ci_has_events(&e, "DRY post"));
    return failures;
}

static int case_repeat_quiet(void)
{
    struct ci_env e;
    char r[65];
    int failures = 0;
    ci_hex64(r, '7');
    CI_CHECK("a question is staged",
             ci_setup_list_one(&e, "repeat", r, CI_OUTSIDE, "outsider",
                               "question", "where is the changelog"));
    CI_CHECK("a fixture answer is staged",
             ci_model_reply(&e, "ANSWER: see docs/README.md"));
    CI_CHECK("the first pass exits 0", ci_pass(&e) == 0);
    const int first = ci_events_count(&e, "NEW ");
    CI_CHECK("the second pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("a repeat pass announces nothing new",
             ci_events_count(&e, "NEW ") == first && first == 1);
    CI_CHECK("a repeat pass posts nothing new",
             ci_events_count(&e, "ANSWERED") == 1);
    return failures;
}

static int case_daily_cap(void)
{
    struct ci_env e;
    char s[65], unit[700], calls[700];
    char day[16];
    int failures = 0;
    ci_hex64(s, '8');
    CI_CHECK("a question is staged",
             ci_setup_list_one(&e, "cap", s, CI_OUTSIDE, "outsider",
                               "question", "what is the release cadence"));
    {
        const time_t now = time(NULL);
        struct tm tm;
        gmtime_r(&now, &tm);
        (void)strftime(day, sizeof(day), "%Y%m%d", &tm);
    }
    (void)mkdir(e.state, 0700);
    (void)snprintf(calls, sizeof(calls), "%s/calls-%s", e.state, day);
    CI_CHECK("the day counter is at the cap", ci_wf(calls, "20\n"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the cap refuses the model call", ci_has_events(&e, "daily model cap"));
    (void)snprintf(unit, sizeof(unit), "%s/units/%s", e.state, s);
    CI_CHECK("no unit is created at the cap", !ci_exists(unit));
    CI_CHECK("capped question remains pending", !ci_state_has(&e, "seen.txt", s));
    CI_CHECK("a fixture answer is staged",
             ci_model_reply(&e, "ANSWER: run make z23 as the build target"));
    CI_CHECK("fixture budget becomes available", ci_wf(calls, "0\n"));
    CI_CHECK("pending question is answered after admission", ci_pass(&e) == 0 &&
             ci_events_count(&e, "ANSWERED") == 1 && ci_state_has(&e, "seen.txt", s));
    CI_CHECK("admitted answer is not repeated", ci_pass(&e) == 0 &&
             ci_events_count(&e, "ANSWERED") == 1);
    return failures;
}

static int case_four_per_pass(void)
{
    struct ci_env e;
    char entries[5][2048];
    char ids[5][65];
    const char *list[5];
    int failures = 0;
    CI_CHECK("the state dir is ready", ci_setup(&e, "four"));
    for (int i = 0; i < 5; i++) {
        ci_hex64(ids[i], (char)('1' + i));
        ci_entry(entries[i], sizeof(entries[i]), ids[i], CI_OUTSIDE,
                 "outsider", "need", "please review");
        list[4 - i] = entries[i];
    }
    CI_CHECK("five needs are staged", ci_list(&e, list, 5));
    CI_CHECK("the first pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("a pass handles at most four posts",
             ci_events_count(&e, "ESCALATE ") == 4);
    CI_CHECK("the second pass takes the fifth",
             ci_pass(&e) == 0 && ci_events_count(&e, "ESCALATE ") == 5);
    return failures;
}

/* A pass must follow the native page cursor and must not consume a partial
 * snapshot when a later page cannot be read. */
static int case_pages_followed(void)
{
    struct ci_env e;
    char entries[4][2048];
    char ids[4][65];
    const char *page0[3], *page1[1];
    int failures = 0;
    CI_CHECK("the state dir is ready", ci_setup(&e, "pages"));
    for (int i = 0; i < 4; i++) {
        ci_hex64(ids[i], (char)('a' + i));
        ci_entry(entries[i], sizeof(entries[i]), ids[i], CI_OUTSIDE,
                 "outsider", "need", "please review");
    }
    page0[0] = entries[3];
    page0[1] = entries[2];
    page0[2] = entries[1];
    page1[0] = entries[0];
    CI_CHECK("page 0 names another page", ci_list_page(&e, 0, page0, 3, 1));
    CI_CHECK("page 1 is the last", ci_list_page(&e, 1, page1, 1, 0));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the post on the second page is read",
             ci_events_count(&e, "ESCALATE ") == 4 &&
             ci_has_events(&e, ids[0]));

    struct ci_env f;
    CI_CHECK("a second state dir is ready", ci_setup(&f, "pages_gap"));
    CI_CHECK("page 0 names a page that is missing",
             ci_list_page(&f, 0, page0, 3, 1));
    CI_CHECK("a missing later page fails closed", ci_pass(&f) != 0);
    CI_CHECK("no partial page is handled", ci_events_count(&f, "ESCALATE ") == 0);
    return failures;
}

static int case_lock_held(void)
{
    struct ci_env e;
    char z[65];
    int failures = 0;
    ci_hex64(z, '9');
    CI_CHECK("a question is staged",
             ci_setup_list_one(&e, "lock", z, CI_OUTSIDE, "outsider",
                               "question", "is there a faucet"));
    char lockpath[700];
    (void)snprintf(lockpath, sizeof(lockpath), "%s/run.lock", e.state);
    (void)mkdir(e.state, 0700);
    const int fd = open(lockpath, O_RDWR | O_CREAT, 0600);
    CI_CHECK("the run lock is held by the test", fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0);
    CI_CHECK("a second pass exits 0 without work", ci_pass(&e) == 0);
    CI_CHECK("the held pass announces nothing", !ci_has_events(&e, "NEW "));
    if (fd >= 0)
        (void)close(fd);
    return failures;
}

static int case_missing_fixture(void)
{
    struct ci_env e;
    int failures = 0;
    CI_CHECK("the state dir is ready", ci_setup(&e, "nofixture"));
    (void)snprintf(e.list, sizeof(e.list), "%s/absent.json", e.d);
    CI_CHECK("an unreadable fixture fails closed", ci_pass(&e) != 0);
    CI_CHECK("nothing is posted", !ci_has_events(&e, "DRY post"));
    return failures;
}

/* ── repair cases: at-most-once posting, strict marker, filter, guards ── */

static bool ci_run_log_has(const struct ci_env *e, const char *needle)
{
    char p[800];
    (void)snprintf(p, sizeof(p), "%s/run.log", e->d);
    return ci_file_has(p, needle);
}

static bool ci_state_has(const struct ci_env *e, const char *leaf, const char *needle)
{
    char p[800];
    return ci_file_has(ci_path(e, p, sizeof(p), leaf), needle);
}

/* A local executable stands in for the board CLI, records the real argv and
 * serves fixture pages only when the native timestamp/id cursor is supplied. */
static bool ci_fake_board(struct ci_env *e, char *bin, size_t cap)
{
    static const char script[] =
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$0.args\"\n"
        "[ \"$1\" = fleet ] && [ \"$2\" = board ] && [ \"$3\" = list ] || exit 9\n"
        "[ ! -e \"$0.fail-first\" ] || exit 8\n"
        "case \" $* \" in\n"
        " *' --before_created_at='*)\n"
        "  case \" $* \" in *' --before_created_at=1 '*) :;; *) exit 7;; esac\n"
        "  case \" $* \" in *' --before_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb '*) :;; *) exit 7;; esac\n"
        "  [ ! -e \"$0.fail-later\" ] || exit 6; cat \"$0.page0.1\" ;;\n"
        " *' --before_id='*) exit 7 ;;\n"
        " *) cat \"$0.page0\" ;;\n"
        "esac\n";
    if (snprintf(bin, cap, "%s/fake-z23", e->d) >= (int)cap ||
        snprintf(e->list, sizeof(e->list), "%s.page0", bin) >= (int)sizeof(e->list)) return false;
    return ci_wf(bin, script) && chmod(bin, 0700) == 0;
}

static int case_live_cursor(void)
{
    struct ci_env e; char bin[700], entries[4][2048], ids[4][65], args[750];
    const char *page0[3], *page1[1]; int failures = 0;
    if (!ci_setup(&e, "live_cursor")) return 1;
    for (int i = 0; i < 4; ++i) {
        ci_hex64(ids[i], (char)('a' + i));
        ci_entry(entries[i], sizeof(entries[i]), ids[i], CI_OUTSIDE, "outsider", "need", "please review");
    }
    page0[0] = entries[3]; page0[1] = entries[2]; page0[2] = entries[1]; page1[0] = entries[0];
    CI_CHECK("the fake board executable is ready", ci_fake_board(&e, bin, sizeof(bin)));
    CI_CHECK("the first real-metadata page is ready", ci_list_page(&e, 0, page0, 3, 1));
    CI_CHECK("the second real-metadata page is ready", ci_list_page(&e, 1, page1, 1, 0));
    const struct ci_run_opts live = {.live_list = true, .z23 = bin, .fsize = -1};
    CI_CHECK("the live-list pass succeeds", ci_pass_with(&e, &live) == 0);
    CI_CHECK("all four pages' posts are handled", ci_events_count(&e, "ESCALATE ") == 4 && ci_has_events(&e, ids[0]));
    (void)snprintf(args, sizeof(args), "%s.args", bin);
    CI_CHECK("the second fetch carries the real cursor", ci_file_has(args, "--before_created_at=1") &&
             ci_file_has(args, "--before_id=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") &&
             !ci_file_has(args, "--cursor="));
    return failures;
}

static int case_live_fetch_refusal(unsigned mode)
{
    struct ci_env e; char bin[700], path[750], entry[2048], id[65]; int failures = 0;
    char tag[48]; (void)snprintf(tag, sizeof(tag), "live_fetch_%u", mode);
    if (!ci_setup(&e, tag) || !ci_fake_board(&e, bin, sizeof(bin))) return 1;
    ci_hex64(id, 'b');
    ci_entry(entry, sizeof(entry), id, CI_OUTSIDE, "outsider", "need", "please review");
    const char *posts[] = {entry};
    bool ready = mode == 1 ? ci_wf(e.list, "{\"ok\":false,\"error\":{\"code\":\"NO_BOARD\"}}\n") :
                 mode == 2 ? ci_wf(e.list, "not JSON\n") : ci_list_page(&e, 0, posts, 1, mode == 3 ? 1 : 0);
    (void)snprintf(path, sizeof(path), "%s.%s", bin, mode == 0 ? "fail-first" : "fail-later");
    if (mode == 0 || mode == 3) ready = ci_wf(path, "x") && ready;
    CI_CHECK("failure fixture is ready", ready);
    const struct ci_run_opts live = {.live_list = true, .z23 = bin, .fsize = -1};
    CI_CHECK("board fetch failure is not quiet success", ci_pass_with(&e, &live) != 0);
    CI_CHECK("failed fetch consumes no seen post", !ci_state_has(&e, "seen.txt", id));
    CI_CHECK("failed fetch posts nothing", ci_events_count(&e, "ESCALATE ") == 0);
    return failures;
}

static int case_live_fetch_failures(void)
{
    int failures = 0;
    for (unsigned mode = 0; mode < 4; ++mode) failures += case_live_fetch_refusal(mode);
    return failures;
}

/* Every item in a board page must descend strictly from the requested tuple,
 * including items before a valid continuation or on the final page. */
static bool ci_bad_order_page(struct ci_env *e, unsigned mode)
{
    char a[65], b[65], c[65], bad[65], ea[2048], eb[2048], ec[2048], ex[2048];
    ci_hex64(a, 'a'); ci_hex64(b, 'b'); ci_hex64(c, 'c'); ci_hex64(bad, 'g');
    ci_entry(ea, sizeof(ea), a, CI_OUTSIDE, "outsider", "need", "review a");
    ci_entry(eb, sizeof(eb), b, CI_OUTSIDE, "outsider", "need", "review b");
    ci_entry(ec, sizeof(ec), c, CI_OUTSIDE, "outsider", "need", "review c");
    ci_entry(ex, sizeof(ex), bad, CI_OUTSIDE, "outsider", "need", "invalid id");
    const char *duplicate[] = {eb, eb}, *ascending[] = {ea, eb};
    const char *first[] = {eb}, *equal[] = {eb}, *newer[] = {ec}, *invalid[] = {ex};
    if (mode == 0) return ci_list_page(e, 0, duplicate, 2, 0);
    if (mode == 1) return ci_list_page(e, 0, ascending, 2, 0);
    if (mode == 2 || mode == 3)
        return ci_list_page(e, 0, first, 1, 1) && ci_list_page(e, 1, mode == 2 ? equal : newer, 1, 0);
    if (mode == 4) return ci_list_page(e, 0, invalid, 1, 0);
    if (mode == 5) {
        char *time = strstr(eb, "\"created_at\":1");
        if (!time) return false;
        time[strlen("\"created_at\":")] = '0';
        return ci_list_page(e, 0, first, 1, 0);
    }
    return ci_wf(e->list, "{\"ok\":true,\"data\":{\"posts\":[],\"has_more\":true,\"next_created_at\":1,\"next_id\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}}\n");
}

static int ci_bad_order_case(unsigned mode)
{
    struct ci_env e; char bin[700], tag[48], seen[800], cursor[800]; int failures = 0;
    (void)snprintf(tag, sizeof(tag), "bad_order_%u", mode);
    if (!ci_setup(&e, tag) || !ci_fake_board(&e, bin, sizeof(bin)) || !ci_bad_order_page(&e, mode)) return 1;
    const struct ci_run_opts live = {.live_list = true, .z23 = bin, .fsize = -1};
    CI_CHECK("invalid board ordering refuses the pass", ci_pass_with(&e, &live) != 0);
    struct stat st;
    ci_path(&e, seen, sizeof(seen), "seen.txt"); ci_path(&e, cursor, sizeof(cursor), "crawl-cursor");
    CI_CHECK("invalid page has no seen or cursor writes", stat(seen, &st) == 0 && st.st_size == 0 && !ci_exists(cursor));
    CI_CHECK("invalid page posts nothing", ci_events_count(&e, "ESCALATE ") == 0);
    if (failures) fprintf(stderr, "invalid board ordering fixture mode=%u\n", mode);
    return failures;
}

static int case_bad_order(void)
{
    int failures = 0;
    for (unsigned mode = 0; mode < 7; ++mode) failures += ci_bad_order_case(mode);
    return failures;
}

static int case_late_older_post(void)
{
    struct ci_env e; char entries[5][2048], ids[5][65]; int failures = 0;
    if (!ci_setup(&e, "late_old")) return 1;
    for (int i = 0; i < 5; ++i) {
        ci_hex64(ids[i], i == 4 ? '0' : (char)('d' - i));
        ci_entry(entries[i], sizeof(entries[i]), ids[i], CI_OUTSIDE, "outsider", "need", "please review");
    }
    const char *head[] = {entries[0], entries[1]};
    const char *old[] = {entries[2], entries[3]};
    const char *late[] = {entries[2], entries[3], entries[4]};
    CI_CHECK("late-old first page is ready", ci_list_page(&e, 0, head, 2, 1));
    CI_CHECK("late-old second page is ready", ci_list_page(&e, 1, old, 2, 0));
    CI_CHECK("initial burst is fully handled", ci_pass(&e) == 0 && ci_events_count(&e, "ESCALATE ") == 4);
    CI_CHECK("older post arrives behind seen head", ci_list_page(&e, 1, late, 3, 0));
    CI_CHECK("seen head does not hide older post", ci_pass(&e) == 0 && ci_events_count(&e, "ESCALATE ") == 5 &&
             ci_state_has(&e, "seen.txt", ids[4]));
    return failures;
}

static bool ci_bulk_pages(struct ci_env *e, char ids[55][65])
{
    char entries[5][2048]; const char *posts[5];
    for (int page = 0; page < 11; ++page) {
        for (int i = 0; i < 5; ++i) {
            int index = page * 5 + i;
            (void)snprintf(ids[index], 65, "%064x", 55 - index);
            ci_entry(entries[i], sizeof(entries[i]), ids[index], CI_OUTSIDE, "outsider", "need", "please review");
            posts[i] = entries[i];
        }
        if (!ci_list_page(e, page, posts, 5, page < 10 ? page + 1 : 0)) return false;
    }
    return true;
}

static bool ci_bulk_board(const char *bin, char ids[55][65])
{
    FILE *f = fopen(bin, "wb");
    if (!f) return false;
    bool ok = fprintf(f, "#!/bin/sh\nprintf '%%s\\n' \"$*\" >> \"$0.args\"\n"
        "[ ! -e \"$0.fail\" ] || exit 8\nbefore=\n"
        "for arg do case \"$arg\" in --before_id=*) before=${arg#--before_id=};; esac; done\n"
        "if [ -z \"$before\" ]; then cat \"$0.page0\"; exit $?; fi\n"
        "case \" $* \" in *' --before_created_at=1 '*) :;; *) exit 7;; esac\ncase \"$before\" in\n") >= 0;
    for (int page = 1; ok && page < 11; ++page)
        ok = fprintf(f, " %s) cat \"$0.page0.%d\" ;;\n", ids[page * 5 - 1], page) >= 0;
    if (ok) ok = fputs(" *) exit 6 ;;\nesac\n", f) >= 0;
    if (fclose(f) != 0) ok = false;
    return ok && chmod(bin, 0700) == 0;
}

static bool ci_bulk_seen_once(const struct ci_env *e, char ids[55][65])
{
    char path[800]; ci_path(e, path, sizeof(path), "seen.txt");
    for (int i = 0; i < 55; ++i) if (ci_count(path, ids[i]) != 1) return false;
    return true;
}

static bool ci_cursor_read(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(out, 1, cap - 1, f);
    bool ok = feof(f) && !ferror(f);
    if (fclose(f) != 0) ok = false;
    out[n] = 0;
    return ok;
}
static bool ci_cursor_unchanged(const char *path, const char *before)
{
    char after[256];
    return ci_cursor_read(path, after, sizeof(after)) && strcmp(before, after) == 0;
}

static int ci_bulk_resumed_failure(const struct ci_env *e, const struct ci_run_opts *live,
                                   const char *bin)
{
    int failures = 0; char marker[750], cursor[800], before[256] = {0};
    (void)snprintf(marker, sizeof(marker), "%s.fail", bin);
    ci_path(e, cursor, sizeof(cursor), "crawl-cursor");
    CI_CHECK("the advanced cursor is readable", ci_cursor_read(cursor, before, sizeof(before)));
    CI_CHECK("the resumed fetch failure is armed", ci_wf(marker, "x"));
    CI_CHECK("failed resumed fetch does not advance or consume", ci_pass_with(e, live) != 0 &&
             ci_cursor_unchanged(cursor, before) && ci_events_count(e, "ESCALATE ") == 50);
    CI_CHECK("the resumed fetch failure is removed", unlink(marker) == 0);
    return failures;
}

/* Pagination spans more than a day's quota. Simulate renewed admission between
 * passes; capped questions must stay pending, not count as completed work. */
static int ci_bulk_admitted_pass(const struct ci_env *e, const struct ci_run_opts *opts)
{
    char day[16], path[700];
    const time_t now = time(NULL);
    struct tm tm;
    if (!gmtime_r(&now, &tm) || !strftime(day, sizeof(day), "%Y%m%d", &tm)) return -1;
    (void)mkdir(e->state, 0700);
    (void)snprintf(path, sizeof(path), "%s/calls-%s", e->state, day);
    if (!ci_wf(path, "0\n")) return -1;
    return ci_pass_with(e, opts);
}

static int case_live_backlog(void)
{
    struct ci_env e; char bin[700], ids[55][65];
    int failures = 0;
    if (!ci_setup(&e, "live_backlog") || !ci_fake_board(&e, bin, sizeof(bin)) ||
        !ci_bulk_pages(&e, ids) || !ci_bulk_board(bin, ids)) return 1;
    const struct ci_run_opts live = {.live_list = true, .z23 = bin, .fsize = -1};
    bool passes = true, advanced = false;
    for (int i = 0; i < 20; ++i) {
        if (ci_bulk_admitted_pass(&e, &live) != 0) { passes = false; break; }
        if (ci_state_has(&e, "crawl-cursor", ids[49])) { advanced = true; break; }
    }
    CI_CHECK("bounded first chunk is handled before advancing", passes && advanced && ci_events_count(&e, "ESCALATE ") == 50);
    failures += ci_bulk_resumed_failure(&e, &live, bin);
    for (int i = 0; i < 8 && ci_events_count(&e, "ESCALATE ") < 55; ++i)
        if (ci_bulk_admitted_pass(&e, &live) != 0) { passes = false; break; }
    CI_CHECK("bounded backlog eventually handles every post once", passes &&
             ci_events_count(&e, "ESCALATE ") == 55 && ci_bulk_seen_once(&e, ids));
    return failures;
}

/* A ledger that cannot be written must never mean a public reply: with the
 * file size limit at 0 the seen.txt append fails, so nothing is posted and the
 * pass exits nonzero (before the repair the post was made, then repeated on
 * every pass). */
static int case_seen_unwritable(void)
{
    struct ci_env e;
    char g[65];
    ci_hex64(g, 'a');
    int failures = 0;
    CI_CHECK("a need post is staged",
             ci_setup_list_one(&e, "seenfull", g, CI_OUTSIDE, "outsider", "need",
                               "please review"));
    const struct ci_run_opts limited = { .fsize = 0 };
    CI_CHECK("a pass that cannot record the post exits nonzero",
             ci_pass_with(&e, &limited) != 0);
    CI_CHECK("no post is made", !ci_run_log_has(&e, "DRY post"));
    CI_CHECK("the post is not recorded as seen", !ci_state_has(&e, "seen.txt", g));
    return failures;
}

/* A ledger that exists but cannot be read counts as seen: nothing is posted
 * and the pass exits nonzero, though appending would still work. Root reads
 * any mode, so the case cannot run as root. */
static int case_seen_unreadable(void)
{
    if (geteuid() == 0) {
        printf("contrib_inbox: SKIP an unreadable seen.txt cannot be made as root\n");
        return 0;
    }
    struct ci_env e;
    char g[65], p[800];
    ci_hex64(g, 'c');
    int failures = 0;
    CI_CHECK("a need post is staged",
             ci_setup_list_one(&e, "seenunread", g, CI_OUTSIDE, "outsider", "need",
                               "please review"));
    (void)mkdir(e.state, 0700);
    ci_path(&e, p, sizeof(p), "seen.txt");
    CI_CHECK("seen.txt exists and is write-only",
             ci_wf(p, "") && chmod(p, 0200) == 0);
    CI_CHECK("a pass that cannot read the ledger exits nonzero", ci_pass(&e) != 0);
    CI_CHECK("no post is made for an unreadable ledger",
             !ci_run_log_has(&e, "DRY post"));
    return failures;
}

/* True when RLIMIT_FSIZE stops an O_APPEND write to a file already at the
 * limit with EFBIG. Measured on macOS: the limit is checked against the
 * descriptor offset (0 for an append) before the write moves to end of file,
 * so the append succeeds and the case below cannot be set up there. The probe
 * is the capability itself, run in this process with SIGXFSZ ignored and the
 * limit restored afterwards. */
static bool ci_fsize_stops_append(void)
{
    char dir[PATH_MAX], path[PATH_MAX + 16];
    if (!test_mkdtemp(dir, sizeof(dir), "ci_fsize"))
        return true; /* cannot probe: run the case and let it judge */
    (void)snprintf(path, sizeof(path), "%s/probe", dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        (void)test_rm_rf_recursive(dir);
        return true;
    }
    char fill[64];
    memset(fill, 'x', sizeof(fill));
    bool ok = write(fd, fill, sizeof(fill)) == (ssize_t)sizeof(fill);
    (void)close(fd);
    bool stops = true;
    if (ok) {
        struct rlimit old, lim;
        (void)getrlimit(RLIMIT_FSIZE, &old);
        lim = old;
        lim.rlim_cur = sizeof(fill);
        void (*const old_sig)(int) = signal(SIGXFSZ, SIG_IGN);
        (void)setrlimit(RLIMIT_FSIZE, &lim);
        fd = open(path, O_WRONLY | O_APPEND);
        stops = fd < 0 || write(fd, "y\n", 2) < 0;
        if (fd >= 0)
            (void)close(fd);
        (void)setrlimit(RLIMIT_FSIZE, &old);
        (void)signal(SIGXFSZ, old_sig);
    }
    (void)test_rm_rf_recursive(dir);
    return stops;
}

/* An events.log that cannot be appended fails the pass, after the current
 * post is finished safely (recorded as seen, escalated). */
static int case_events_unwritable(void)
{
    if (!ci_fsize_stops_append()) {
        printf("contrib_inbox: SKIP an events.log at the size limit: "
               "RLIMIT_FSIZE does not stop an append here\n");
        return 0;
    }
    struct ci_env e;
    char g[65], fill[4097], p[800];
    ci_hex64(g, 'b');
    int failures = 0;
    CI_CHECK("a need post is staged",
             ci_setup_list_one(&e, "eventsfull", g, CI_OUTSIDE, "outsider", "need",
                               "please review"));
    memset(fill, 'x', 4096);
    fill[4096] = '\0';
    (void)mkdir(e.state, 0700);
    CI_CHECK("events.log is at the size limit",
             ci_wf(ci_path(&e, p, sizeof(p), "events.log"), fill));
    const struct ci_run_opts limited = { .fsize = 4096 };
    CI_CHECK("a pass that cannot log exits nonzero", ci_pass_with(&e, &limited) != 0);
    CI_CHECK("the current post is still recorded as seen",
             ci_state_has(&e, "seen.txt", g));
    CI_CHECK("the current post is still escalated",
             ci_state_has(&e, "escalate.tsv", g));
    return failures;
}

/* The marker must be the last non-empty line: model text after it is never
 * posted; only a local escalation row is recorded. Text before it
 * is fine. */
static int case_text_after_marker(void)
{
    struct ci_env e, f;
    char g[65], h[65];
    ci_hex64(g, 'c');
    ci_hex64(h, 'd');
    int failures = 0;
    CI_CHECK("a question is staged",
             ci_setup_list_one(&e, "trail", g, CI_OUTSIDE, "outsider", "question",
                               "how do I build the node"));
    CI_CHECK("the reply carries text after its ANSWER line",
             ci_model_reply(&e, "ANSWER: run make z23 as the build target"
                                "\\nTRAILING-MODEL-TEXT"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the model text is never posted", !ci_has_events(&e, "TRAILING-MODEL-TEXT"));
    CI_CHECK("the answer is not posted", !ci_has_events(&e, "ANSWERED"));
    CI_CHECK("no public note is posted", !ci_has_events(&e, "DRY post"));
    CI_CHECK("an escalate row names the post", ci_state_has(&e, "escalate.tsv", g));

    CI_CHECK("a second question is staged",
             ci_setup_list_one(&f, "lead", h, CI_OUTSIDE, "outsider", "question",
                               "how do I build the node"));
    CI_CHECK("the reply has reasoning before its ANSWER line",
             ci_model_reply(&f, "I checked the Makefile.\\nANSWER: run make z23"));
    CI_CHECK("the pass exits 0", ci_pass(&f) == 0);
    CI_CHECK("text before the marker is allowed", ci_has_events(&f, "ANSWERED"));
    return failures;
}

static bool ci_answer_refused(const char *tag, char c, const char *answer)
{
    struct ci_env e;
    char g[65], reply[512];
    ci_hex64(g, c);
    (void)snprintf(reply, sizeof(reply), "ANSWER: %s", answer);
    return ci_setup_list_one(&e, tag, g, CI_OUTSIDE, "outsider", "question",
                             "where is that") &&
           ci_model_reply(&e, reply) && ci_pass(&e) == 0 &&
           !ci_has_events(&e, "ANSWERED") &&
           ci_has_events(&e, "answer missing or refused by the filter");
}

/* Words that must not leave this host; a .onion:port is published on purpose. */
static int case_filter_words(void)
{
    int failures = 0;
    /* Split so no home path sits in the committed bytes (check-no-operator-paths). */
    CI_CHECK("a macOS home path is refused",
             ci_answer_refused("f_users", 'a',
                               "see /" "Users" "/someone/notes.txt"));
    CI_CHECK("password is refused",
             ci_answer_refused("f_pass", 'b', "the password is in the config"));
    CI_CHECK("secret is refused",
             ci_answer_refused("f_secret", 'c', "the secret lives in the config"));
    CI_CHECK("mnemonic is refused",
             ci_answer_refused("f_mnem", 'd', "the mnemonic is stored there"));
    CI_CHECK("a PEM block is refused",
             ci_answer_refused("f_pem", 'e', "-----BEGIN CERTIFICATE-----"));
    CI_CHECK("an xprv key is refused",
             ci_answer_refused("f_xprv", 'f', "use xprv9s21ZrQH143K3QTDL4"));
    struct ci_env e;
    char g[65];
    ci_hex64(g, '1');
    CI_CHECK("an onion with a port is staged",
             ci_setup_list_one(&e, "f_onion", g, CI_OUTSIDE, "outsider", "question",
                               "where is the seed"));
    CI_CHECK("the onion answer is staged",
             ci_model_reply(&e, "ANSWER: the seed is abcdefghijklmnopqrstuvwxyz234567"
                                "abcdefghijklmnopqrstuvwx.onion:8033"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("an onion with a port is allowed", ci_has_events(&e, "ANSWERED"));
    return failures;
}

/* The responder is reset and cleaned by this tool: a primary checkout (or a
 * checkout of another repo) is refused before the model runs. */
static int case_responder_guard(void)
{
    struct ci_env e;
    char g[65];
    ci_hex64(g, '2');
    int failures = 0;
    CI_CHECK("a question is staged",
             ci_setup_list_one(&e, "guard", g, CI_OUTSIDE, "outsider", "question",
                               "how do I build the node"));
    CI_CHECK("a fixture answer is staged",
             ci_model_reply(&e, "ANSWER: run make z23 as the build target"));
    const struct ci_run_opts primary = { .responder = e.mainrepo, .fsize = -1 };
    CI_CHECK("the pass exits 0", ci_pass_with(&e, &primary) == 0);
    CI_CHECK("a primary checkout is refused", ci_has_events(&e, "not a linked worktree"));
    CI_CHECK("the model is never run on it", !ci_run_log_has(&e, "engine rc="));
    CI_CHECK("nothing is answered", !ci_has_events(&e, "ANSWERED"));
    CI_CHECK("unready question remains pending", !ci_state_has(&e, "seen.txt", g));
    CI_CHECK("ready responder answers pending question", ci_pass(&e) == 0 &&
             ci_events_count(&e, "ANSWERED") == 1 && ci_state_has(&e, "seen.txt", g));
    CI_CHECK("recovered answer is not repeated", ci_pass(&e) == 0 &&
             ci_events_count(&e, "ANSWERED") == 1);
    return failures;
}

/* A responder that cannot fetch origin/main is not trusted with a model call. */
static int case_fetch_failure(void)
{
    struct ci_env e;
    char g[65], gone[700];
    ci_hex64(g, '3');
    int failures = 0;
    CI_CHECK("a question is staged",
             ci_setup_list_one(&e, "nofetch", g, CI_OUTSIDE, "outsider", "question",
                               "how do I build the node"));
    CI_CHECK("a fixture answer is staged",
             ci_model_reply(&e, "ANSWER: run make z23 as the build target"));
    (void)snprintf(gone, sizeof(gone), "%s/gone.git", e.d);
    const char *const seturl[] = { "git", "-C", e.mainrepo, "remote", "set-url",
                                   "origin", gone, NULL };
    CI_CHECK("the origin is made unreachable", ci_git(seturl));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("no model call is made", !ci_run_log_has(&e, "engine rc="));
    CI_CHECK("the fixed note and an escalate row are the outcome",
             !ci_has_events(&e, "ANSWERED") && ci_state_has(&e, "escalate.tsv", g));
    return failures;
}

/* A post that fails is recorded for a human and never retried. */
static int case_post_failure(void)
{
    struct ci_env e, f;
    char g[65], h[65];
    ci_hex64(g, '4');
    ci_hex64(h, '5');
    int failures = 0;
    const struct ci_run_opts broken = { .live = true, .z23 = "/bin/false", .fsize = -1 };
    CI_CHECK("a need post is staged",
             ci_setup_list_one(&e, "postfail", g, CI_OUTSIDE, "outsider", "need",
                               "please review"));
    CI_CHECK("an answer is staged", ci_model_reply(&e, "ANSWER: run make z23"));
    CI_CHECK("the first pass exits 0", ci_pass_with(&e, &broken) == 0);
    CI_CHECK("the failed note is logged", ci_has_events(&e, "POST FAILED"));
    CI_CHECK("an escalate row names the post", ci_state_has(&e, "escalate.tsv", g));
    CI_CHECK("the post is recorded as seen", ci_state_has(&e, "seen.txt", g));
    CI_CHECK("the second pass exits 0", ci_pass_with(&e, &broken) == 0);
    CI_CHECK("the failed post is never retried",
             ci_events_count(&e, "POST FAILED") == 1);

    CI_CHECK("a question is staged",
             ci_setup_list_one(&f, "postfail2", h, CI_OUTSIDE, "outsider", "question",
                               "how do I build the node"));
    CI_CHECK("a fixture answer is staged",
             ci_model_reply(&f, "ANSWER: run make z23 as the build target"));
    CI_CHECK("the pass exits 0", ci_pass_with(&f, &broken) == 0);
    CI_CHECK("a failed answer post is logged", ci_has_events(&f, "POST FAILED"));
    CI_CHECK("a failed answer post gets an escalate row",
             ci_state_has(&f, "escalate.tsv", h));
    return failures;
}

static int ci_tg_retention_checks(const struct ci_env *e, const struct ci_run_opts *opts,
                                  const char *retained, const char *sent)
{
    int failures = 0;
    char saved[1000];
    (void)snprintf(saved, sizeof saved, "%s.saved", retained);
    CI_CHECK("retain original bytes for fixture", rename(retained, saved) == 0);
    CI_CHECK("tampered retained bytes", ci_wf(retained, "tampered"));
    CI_CHECK("tampering refuses without send or ACK", ci_pass_with(e, opts) != 0 &&
             ci_count(sent, "send") == 1 && ci_count(sent, "inbox") == 2);
    CI_CHECK("restore retained bytes", unlink(retained) == 0 && rename(saved, retained) == 0);
    CI_CHECK("make retained file nonprivate", chmod(retained, 0644) == 0);
    CI_CHECK("nonprivate retention refuses without send or ACK", ci_pass_with(e, opts) != 0 &&
             ci_count(sent, "send") == 1 && ci_count(sent, "inbox") == 2);
    CI_CHECK("restore private mode", chmod(retained, 0600) == 0);
    CI_CHECK("move retained target", rename(retained, saved) == 0);
    CI_CHECK("replace retained file with symlink", symlink(saved, retained) == 0);
    CI_CHECK("symlink retention refuses without send or ACK", ci_pass_with(e, opts) != 0 &&
             ci_count(sent, "send") == 1 && ci_count(sent, "inbox") == 2);
    CI_CHECK("restore retained file", unlink(retained) == 0 && rename(saved, retained) == 0);
    return failures;
}

static bool ci_tg_five_rows(const struct ci_env *e)
{
    FILE *f = fopen(e->list, "wb");
    if (!f) return false;
    bool ok = fprintf(f, "{\"ok\":true,\"data\":{\"schema\":\"zcl.telegram.inbox.v1\","
        "\"bot_id\":7777777777,\"receipt\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"count\":5,\"dropped\":0,\"more\":false,\"next_offset\":25,\"messages\":[") > 0;
    for (int i = 0; i < 5; ++i)
        if (fprintf(f, "%s{\"update_id\":%d,\"chat_id\":4242,\"chat_type\":\"private\","
            "\"message_id\":%d,\"from_id\":4242,\"kind\":\"text\","
            "\"text\":\"private retained request\",\"truncated\":false}", i ? "," : "", 20+i, 7+i) < 0)
            ok = false;
    if (fputs("]}}", f) == EOF) ok = false;
    return fclose(f) == 0 && ok;
}

static int case_telegram_batch_bound(void)
{
    struct ci_env e;
    int failures = 0;
    char bin[700], sent[740];
    CI_CHECK("bounded Telegram fixture", ci_setup(&e, "telegram-bound"));
    (void)snprintf(bin, sizeof bin, "%s/fake-telegram", e.d);
    (void)snprintf(sent, sizeof sent, "%s.sent", bin);
    CI_CHECK("bounded Telegram transport", ci_wf(bin,
        "#!/bin/sh\nprintf '%s\\n' \"$3 $4\" >> \"$0.sent\"\n"
        "case \"$3\" in inbox) printf '%s\\n' '{\"ok\":true,\"data\":{\"schema\":\"zcl.telegram.inbox.v1\",\"bot_id\":7777777777,\"count\":0,\"next_offset\":25}}';; "
        "send) printf '%s\\n' '{\"ok\":true,\"data\":{\"schema\":\"zcl.telegram.send.v1\",\"chat_id\":-100123,\"message_ids\":[41]}}';; esac\n") && chmod(bin, 0700) == 0);
    CI_CHECK("five retained rows", ci_tg_five_rows(&e));
    const struct ci_run_opts opts = {.live = true, .z23 = bin, .telegram_group = "-100123", .fsize = -1};
    CI_CHECK("first pass handles at most four", ci_pass_with(&e, &opts) == 0 &&
             ci_count(sent, "inbox") == 0 && ci_count(sent, "send") == 0 &&
             !ci_state_has(&e, "seen.txt", "tg:7777777777:4242:24:11"));
    CI_CHECK("second pass acknowledges complete batch", ci_pass_with(&e, &opts) == 0 &&
             ci_count(sent, "inbox") == 1 && ci_count(sent, "send") == 0 &&
             ci_file_has(sent, "-100123") &&
             ci_file_has(sent, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    CI_CHECK("all private rows locally disposed", ci_state_has(&e, "seen.txt", "tg:7777777777:4242:24:11"));
    return failures;
}

static bool ci_tg_single_row(const struct ci_env *e, const char *bot, const char *chat)
{
    char json[2048];
    int n = snprintf(json, sizeof json,
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.telegram.inbox.v1\",\"bot_id\":%s,"
        "\"receipt\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"count\":1,\"dropped\":0,\"more\":false,\"next_offset\":21,\"messages\":["
        "{\"update_id\":20,\"chat_id\":%s,\"chat_type\":\"supergroup\",\"message_id\":7,"
        "\"from_id\":555,\"kind\":\"text\",\"text\":\"how do I build?\",\"truncated\":false}]}}", bot, chat);
    return n > 0 && (size_t)n < sizeof json && ci_wf(e->list, json);
}

static bool ci_tg_fake(const char *bin, bool fail_send)
{
    const char *send = fail_send ? "exit 1" :
        "printf '%s\\n' '{\"ok\":true,\"data\":{\"schema\":\"zcl.telegram.send.v1\",\"chat_id\":-100123,\"message_ids\":[41]}}'";
    char script[2048];
    int n = snprintf(script, sizeof script,
        "#!/bin/sh\nprintf '%%s\\n' \"$3 $4\" >> \"$0.sent\"\n"
        "case \"$3\" in inbox) printf '%%s\\n' '{\"ok\":true,\"data\":{\"schema\":\"zcl.telegram.inbox.v1\","
        "\"bot_id\":7777777777,\"count\":0,\"next_offset\":21}}';; send) %s;; esac\n", send);
    return n > 0 && (size_t)n < sizeof script && ci_wf(bin, script) && chmod(bin, 0700) == 0;
}

static int ci_tg_disposition_case(const char *tag, const char *reply, bool fail_send)
{
    struct ci_env e;
    int failures = 0;
    char bin[700], sent[740];
    CI_CHECK("disposition fixture", ci_setup(&e, tag));
    (void)snprintf(bin, sizeof bin, "%s/fake-telegram", e.d);
    (void)snprintf(sent, sizeof sent, "%s.sent", bin);
    CI_CHECK("disposition transport", ci_tg_fake(bin, fail_send));
    CI_CHECK("disposition input", ci_tg_single_row(&e, "7777777777", "-100123"));
    CI_CHECK("disposition model", ci_model_reply(&e, reply));
    const struct ci_run_opts opts = {.live = true, .z23 = bin, .telegram_group = "-100123", .fsize = -1};
    CI_CHECK("disposition completes", ci_pass_with(&e, &opts) == 0);
    CI_CHECK("disposition ACKs exact receipt", ci_count(sent, "inbox") == 1 &&
             ci_file_has(sent, "group_chat_id\":-100123") &&
             ci_file_has(sent, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    CI_CHECK("disposition sends at most once", ci_count(sent, "send") == (fail_send ? 1 : 0));
    CI_CHECK("disposition recorded", ci_state_has(&e, "seen.txt", "tg:7777777777:-100123:20:7"));
    if (!strcmp(reply, "IGNORE: resolved"))
        CI_CHECK("ignore classified", ci_has_events(&e, "IGNORED "));
    if (!strcmp(reply, "ESCALATE: needs review"))
        CI_CHECK("escalation retained", ci_state_has(&e, "escalate.tsv", "needs review"));
    if (fail_send)
        CI_CHECK("ambiguous send retained for review", ci_state_has(&e, "escalate.tsv", "answer post failed; not retried"));
    CI_CHECK("disposition replay does not resend", ci_pass_with(&e, &opts) == 0 &&
             ci_count(sent, "send") == (fail_send ? 1 : 0) && ci_count(sent, "inbox") == 2);
    return failures;
}

static int case_telegram_ack_failure(void)
{
    struct ci_env e;
    int failures = 0;
    char bin[700], sent[740];
    CI_CHECK("ACK failure fixture", ci_setup(&e, "telegram-ack-failure"));
    (void)snprintf(bin, sizeof bin, "%s/fake-telegram", e.d);
    (void)snprintf(sent, sizeof sent, "%s.sent", bin);
    CI_CHECK("ACK failure input", ci_tg_single_row(&e, "7777777777", "-100123"));
    CI_CHECK("ACK failure model", ci_model_reply(&e, "ANSWER: run make z23"));
    struct ci_run_opts opts = {.live = true, .z23 = "/bin/false", .telegram_group = "-100123", .fsize = -1};
    CI_CHECK("uncertain ACK fails pass but retains attempt", ci_pass_with(&e, &opts) != 0 &&
             ci_state_has(&e, "seen.txt", "tg:7777777777:-100123:20:7"));
    CI_CHECK("transport recovers", ci_tg_fake(bin, false));
    opts.z23 = bin;
    CI_CHECK("replay ACKs without retrying uncertain send", ci_pass_with(&e, &opts) == 0 &&
             ci_count(sent, "inbox") == 1 && ci_count(sent, "send") == 0);
    return failures;
}

static int ci_tg_invalid_case(const char *tag, const char *bot, const char *chat)
{
    struct ci_env e;
    int failures = 0;
    char bin[700], sent[740];
    CI_CHECK("invalid Telegram fixture", ci_setup(&e, tag));
    (void)snprintf(bin, sizeof bin, "%s/fake-telegram", e.d);
    (void)snprintf(sent, sizeof sent, "%s.sent", bin);
    CI_CHECK("invalid Telegram transport", ci_tg_fake(bin, false));
    CI_CHECK("invalid Telegram input", ci_tg_single_row(&e, bot, chat));
    const struct ci_run_opts opts = {.live = true, .z23 = bin, .telegram_group = "-100123", .fsize = -1};
    CI_CHECK("invalid identity refuses without side effects", ci_pass_with(&e, &opts) != 0 &&
             ci_count(sent, "inbox") == 0 && ci_count(sent, "send") == 0 &&
             !ci_state_has(&e, "seen.txt", "tg:"));
    return failures;
}

static int case_telegram_replay(void)
{
    struct ci_env e;
    int failures = 0;
    char bin[700], sent[740], retained[900], task[900];
    const char *receipt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    CI_CHECK("telegram fixture directory", ci_setup(&e, "telegram-replay"));
    (void)snprintf(bin, sizeof bin, "%s/fake-telegram", e.d);
    (void)snprintf(sent, sizeof sent, "%s.sent", bin);
    CI_CHECK("telegram transport fixture", ci_wf(bin,
        "#!/bin/sh\nprintf '%s\\n' \"$3 $4\" >> \"$0.sent\"\n"
        "case \"$3\" in inbox) printf '%s\\n' '{\"ok\":true,\"data\":{\"schema\":\"zcl.telegram.inbox.v1\",\"bot_id\":7777777777,\"count\":0,\"next_offset\":22}}';; "
        "send) printf '%s\\n' '{\"ok\":true,\"data\":{\"schema\":\"zcl.telegram.send.v1\",\"chat_id\":-100123,\"message_ids\":[41]}}';; esac\n") && chmod(bin, 0700) == 0);
    CI_CHECK("telegram mixed batch fixture", ci_wf(e.list,
        "{\"ok\":true,\"data\":{\"schema\":\"zcl.telegram.inbox.v1\",\"bot_id\":7777777777,"
        "\"receipt\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"count\":2,\"dropped\":0,\"more\":false,\"next_offset\":22,\"messages\":["
        "{\"update_id\":20,\"chat_id\":-100123,\"chat_type\":\"supergroup\",\"message_id\":7,"
        "\"from_id\":555,\"kind\":\"text\",\"text\":\"how do I build?\",\"truncated\":false},"
        "{\"update_id\":21,\"chat_id\":4242,\"chat_type\":\"private\",\"message_id\":8,"
        "\"from_id\":4242,\"kind\":\"text\",\"text\":\"private retained request\",\"truncated\":false}]}}"));
    CI_CHECK("telegram answer fixture", ci_model_reply(&e, "ANSWER: run make z23 as the build target"));
    const struct ci_run_opts opts = {.live = true, .z23 = bin, .telegram_group = "-100123", .fsize = -1};
    CI_CHECK("telegram mixed batch consumed", ci_pass_with(&e, &opts) == 0);
    CI_CHECK("only group gets one answer", ci_count(sent, "send") == 1);
    CI_CHECK("answer uses a native reply target", ci_file_has(sent, "reply_to_message_id\":7") &&
             !ci_file_has(sent, "Reply to message"));
    CI_CHECK("batch is acknowledged after retention", ci_count(sent, "inbox") == 1);
    (void)snprintf(retained, sizeof retained, "%s/units/tg-batch-%s/inbox.json", e.state, receipt);
    CI_CHECK("private message is retained", ci_file_has(retained, "private retained request"));
    (void)snprintf(task, sizeof task, "%s/units/tg:7777777777:-100123:20:7/task.txt", e.state);
    CI_CHECK("group task excludes private content", ci_file_has(task, "how do I build?") &&
             !ci_file_has(task, "private retained request"));
    CI_CHECK("ACK has configured group and exact receipt", ci_file_has(sent, "group_chat_id\":-100123") &&
             ci_file_has(sent, receipt));
    CI_CHECK("private message has local disposition", ci_state_has(&e, "escalate.tsv", "private Telegram message retained"));
    CI_CHECK("lost acknowledgment replay is safe", ci_pass_with(&e, &opts) == 0 &&
             ci_count(sent, "send") == 1 && ci_count(sent, "inbox") == 2);
    failures += ci_tg_retention_checks(&e, &opts, retained, sent);
    return failures;
}

static int case_malformed_fixture(void)
{
    struct ci_env e;
    int failures = 0;
    CI_CHECK("the state dir is ready", ci_setup(&e, "malformed"));
    CI_CHECK("page 0 is not JSON", ci_wf(e.list, "this is not a board list\n"));
    CI_CHECK("a malformed fixture fails closed", ci_pass(&e) == 1);
    CI_CHECK("nothing is posted", !ci_run_log_has(&e, "DRY post"));
    return failures;
}

int test_contrib_inbox(void)
{
    int failures = 0;
    struct stat st;
    if (stat(CI_BIN, &st) != 0 || stat(CI_ENGINE, &st) != 0) {
        printf("contrib_inbox: FAIL (%s and %s are required test prerequisites)\n", CI_BIN, CI_ENGINE);
        return 1;
    }
    failures += case_maintainer_ignored();
    failures += case_helper_on_maint_host();
    failures += case_lead_on_maint_host_ignored();
    failures += case_own_agent_any_host_ignored();
    failures += case_need_acknowledged();
    failures += case_status_ignored();
    failures += case_ignore_malformed();
    failures += case_model_failure_no_post();
    failures += case_question_answered();
    failures += case_refusals();
    failures += case_long_answer_refused();
    failures += case_unknown_hex_refused();
    failures += case_known_hex_allowed();
    failures += case_escalate_reply();
    failures += case_repeat_quiet();
    failures += case_daily_cap();
    failures += case_four_per_pass();
    failures += case_pages_followed();
    failures += case_live_cursor();
    failures += case_live_fetch_failures();
    failures += case_bad_order();
    failures += case_late_older_post();
    failures += case_live_backlog();
    failures += case_lock_held();
    failures += case_missing_fixture();
    failures += case_seen_unwritable();
    failures += case_seen_unreadable();
    failures += case_events_unwritable();
    failures += case_text_after_marker();
    failures += case_filter_words();
    failures += case_responder_guard();
    failures += case_fetch_failure();
    failures += case_post_failure();
    failures += case_malformed_fixture();
    failures += case_telegram_replay();
    failures += case_telegram_batch_bound();
    failures += case_telegram_ack_failure();
    failures += ci_tg_disposition_case("tg-ignore", "IGNORE: resolved", false);
    failures += ci_tg_disposition_case("tg-escalate", "ESCALATE: needs review", false);
    failures += ci_tg_disposition_case("tg-send-ambiguous", "ANSWER: run make z23", true);
    failures += ci_tg_invalid_case("tg-bad-bot", "0", "-100123");
    failures += ci_tg_invalid_case("tg-bot-type", "\"bad\"", "-100123");
    failures += ci_tg_invalid_case("tg-wrong-group", "7777777777", "-100999");
    failures += ci_tg_invalid_case("tg-group-type", "7777777777", "\"bad\"");
    return failures;
}
