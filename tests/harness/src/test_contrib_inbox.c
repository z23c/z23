/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_contrib_inbox: whole passes of build/bin/z23-contrib-inbox over fixture
 * board lists (--fixture-list), in dry-run (no post reaches the real board),
 * with the engine-unit fixture engine (--engine fixture --fixture-reply) as
 * the only model. Each case runs in its own temp state dir, responder checkout
 * and lock file, so nothing reaches a live node, a timer or a real model.
 *
 * Scenarios: maintainer and own posts are ignored, a helper agent on a
 * maintainer host is answered; a need is acknowledged and never modelled; a
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
    const char *const commit[] = { "git", "-C", e->mainrepo, "-c", "user.name=ci",
                                   "-c", "user.email=ci@example.invalid", "-c",
                                   "commit.gpgsign=false", "commit", "-q",
                                   "--allow-empty", "-m", "init", NULL };
    const char *const remote[] = { "git", "-C", e->mainrepo, "remote", "add", "origin",
                                   e->origin, NULL };
    const char *const push[] = { "git", "-C", e->mainrepo, "push", "-q", "origin",
                                 "HEAD:refs/heads/main", NULL };
    const char *const fetch[] = { "git", "-C", e->mainrepo, "fetch", "-q", "origin", NULL };
    return ci_git(bare) && ci_git(init) && ci_git(commit) && ci_git(remote) &&
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
/* One page of the board list, as the board pages it: page `cursor` lives at
 * list.json (0) or list.json.<cursor>, and `next` > 0 names the next page. */
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
    if (next > 0)
        (void)snprintf(body + len, sizeof(body) - len,
                       "]},\"_page\":{\"truncated\":true,\"next_cursor\":%d}}\n",
                       next);
    else
        (void)snprintf(body + len, sizeof(body) - len, "]}}\n");
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
    const char *z23;       /* the fake poster, e.g. /bin/false */
    const char *responder; /* overrides the scenario's responder path */
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
    const char *const rest[] = {
        "--state-dir", e->state, "--fixture-list", e->list, "--fixture-reply",
        e->reply, "--engine", "fixture", "--engine-unit", engine, "--main",
        e->mainrepo, "--haiku-lock", e->lock, "--engine-timeout-s", "60",
        "--responder", o->responder ? o->responder : e->resp,
    };
    for (size_t i = 0; i < sizeof(rest) / sizeof(*rest); i++)
        argv[n++] = rest[i];
    if (o->z23) {
        argv[n++] = "--z23";
        argv[n++] = o->z23;
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

/* ── cases ───────────────────────────────────────────────────────────── */

static int case_maintainer_ignored(void)
{
    struct ci_env e;
    char a[65], b[65];
    ci_hex64(a, 'a');
    ci_hex64(b, 'b');
    int failures = 0;
    char m1[2048], m2[2048];
    const char *list[2] = { m1, m2 };
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
             ci_model_reply(&e, "ANSWER: see the gate at tools/lint/run_lint.sh"));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the helper post is answered", ci_has_events(&e, "ANSWERED"));
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
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the need is escalated", ci_has_events(&e, "ESCALATE"));
    CI_CHECK("the received note is the only post",
             ci_events_count(&e, "DRY post ref=") == 1);
    (void)snprintf(unit, sizeof(unit), "%s/units/%s", e.state, d);
    CI_CHECK("the model is never dispatched for a need", !ci_exists(unit));
    char full[96];
    (void)snprintf(full, sizeof(full), "Received (post %s).", d);
    CI_CHECK("the received note names the post by its full id",
             ci_has_events(&e, full));
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
    CI_CHECK("nothing is answered", !ci_has_events(&e, "ANSWERED"));
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
        list[i] = entries[i];
    }
    CI_CHECK("five needs are staged", ci_list(&e, list, 5));
    CI_CHECK("the first pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("a pass handles at most four posts",
             ci_events_count(&e, "ESCALATE ") == 4);
    CI_CHECK("the second pass takes the fifth",
             ci_pass(&e) == 0 && ci_events_count(&e, "ESCALATE ") == 5);
    return failures;
}

/* The board returns about three posts a page. A pass must follow
 * next_cursor while a page still holds unseen posts, or the oldest post of a
 * burst is never read. A next page that cannot be read ends the walk with
 * what was read. */
static int case_pages_followed(void)
{
    struct ci_env e;
    char entries[4][2048];
    char ids[4][65];
    const char *page0[3], *page3[1];
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
    page3[0] = entries[0];
    CI_CHECK("page 0 names page 3", ci_list_page(&e, 0, page0, 3, 3));
    CI_CHECK("page 3 is the last", ci_list_page(&e, 3, page3, 1, 0));
    CI_CHECK("the pass exits 0", ci_pass(&e) == 0);
    CI_CHECK("the post on the second page is read",
             ci_events_count(&e, "ESCALATE ") == 4 &&
             ci_has_events(&e, ids[0]));

    struct ci_env f;
    CI_CHECK("a second state dir is ready", ci_setup(&f, "pages_gap"));
    CI_CHECK("page 0 names a page that is missing",
             ci_list_page(&f, 0, page0, 3, 3));
    CI_CHECK("a missing later page is not fatal", ci_pass(&f) == 0);
    CI_CHECK("page 0 is still handled",
             ci_events_count(&f, "ESCALATE ") == 3);
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

/* An events.log that cannot be appended fails the pass, after the current
 * post is finished safely (recorded as seen, escalated). */
static int case_events_unwritable(void)
{
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
 * posted, the fixed note and an escalate row go out instead. Text before it
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
    CI_CHECK("the fixed note is posted instead", ci_has_events(&e, "Received (post "));
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
    failures += case_need_acknowledged();
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
    return failures;
}
