/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_cli_render — the terminal-lane human presentation layer
 * (tools/command/cli_render.c, docs/work/UX_PLAN.md (terminal lane)).
 *
 * The lane's prime directive is: machines get canonical JSON, humans get
 * beauty. These tests prove both halves:
 *
 *   1. Unit: the renderers themselves — table alignment, terminal-width
 *      capping, row caps with the "... (N more, pipe to JSON for full)"
 *      footer, NO_COLOR / TERM=dumb ANSI suppression, error-block
 *      suggestions, brief colorization — driven directly with fabricated
 *      canonical documents (the same pattern test_operator_ux uses for the
 *      brief/field-selector renderers).
 *
 *   2. End-to-end against the REAL built binary (the pattern
 *      test_cli_auth_robust uses): with stdout a PIPE (never a TTY), output
 *      is byte-identical with and without ZCL_HUMAN, and identical to the
 *      pre-lane canonical document; ZCL_HUMAN=1 forces the human rendering
 *      deterministically without a pty. The e2e half skips (does not fail)
 *      when build/bin/zclassic23 is missing or stale.
 *
 * make t-fast ONLY=cli_render
 */

#include "test/test_core.h"

#include "command/cli_render.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* ── shared helpers ────────────────────────────────────────────────── */

/* Display columns of one line: every byte that is not a UTF-8
 * continuation byte and not part of an ANSI CSI sequence. */
static size_t cr_dwidth(const char *s, size_t n)
{
    size_t cols = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\033' && i + 1 < n && s[i + 1] == '[') {
            i += 2;
            while (i < n && !(s[i] >= 0x40 && s[i] <= 0x7e))
                i++;
            continue;
        }
        if (((unsigned char)s[i] & 0xC0) != 0x80)
            cols++;
    }
    return cols;
}

/* Widest line (display columns) in a rendered block. */
static size_t cr_max_line_width(const char *out)
{
    size_t widest = 0;
    const char *p = out;
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        size_t w = cr_dwidth(p, len);
        if (w > widest)
            widest = w;
        p = nl ? nl + 1 : NULL;
    }
    return widest;
}

static bool cr_has_esc(const char *out)
{
    return strchr(out, '\033') != NULL;
}

/* Strip ANSI CSI sequences (ESC '[' ... final-letter) in place. */
static void cr_strip_ansi(char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (*r == '\033' && r[1] == '[') {
            r += 2;
            while (*r && !(*r >= 0x40 && *r <= 0x7e))
                r++;
            if (*r)
                r++;
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
}

static struct zcl_cli_render_env cr_env(int width, bool ansi)
{
    struct zcl_cli_render_env e = {
        .human = true, .ansi = ansi, .width = width, .max_rows = 24,
    };
    return e;
}

/* Save/restore the four variables zcl_cli_render_resolve reads, so the
 * resolution tests are hermetic regardless of the harness environment. */
struct cr_saved_env {
    char human[32]; bool human_set;
    char color[32]; bool color_set;
    char term[64];  bool term_set;
    char cols[32];  bool cols_set;
};

static void cr_save_env(struct cr_saved_env *s)
{
    const char *v;
    v = getenv("ZCL_HUMAN");
    s->human_set = v != NULL;
    if (v) snprintf(s->human, sizeof(s->human), "%s", v);
    v = getenv("NO_COLOR");
    s->color_set = v != NULL;
    if (v) snprintf(s->color, sizeof(s->color), "%s", v);
    v = getenv("TERM");
    s->term_set = v != NULL;
    if (v) snprintf(s->term, sizeof(s->term), "%s", v);
    v = getenv("COLUMNS");
    s->cols_set = v != NULL;
    if (v) snprintf(s->cols, sizeof(s->cols), "%s", v);
}

static void cr_restore_env(const struct cr_saved_env *s)
{
    if (s->human_set) setenv("ZCL_HUMAN", s->human, 1);
    else unsetenv("ZCL_HUMAN");
    if (s->color_set) setenv("NO_COLOR", s->color, 1);
    else unsetenv("NO_COLOR");
    if (s->term_set) setenv("TERM", s->term, 1);
    else unsetenv("TERM");
    if (s->cols_set) setenv("COLUMNS", s->cols, 1);
    else unsetenv("COLUMNS");
}

/* ── unit: environment resolution ──────────────────────────────────── */

static int test_env_resolution(void)
{
    int failures = 0;
    TEST("resolve: ZCL_HUMAN forces, NO_COLOR/TERM=dumb suppress ANSI, "
         "COLUMNS sets width") {
        struct cr_saved_env saved;
        cr_save_env(&saved);

        /* fd=-1 is never a TTY: without ZCL_HUMAN there is no human mode. */
        unsetenv("ZCL_HUMAN");
        struct zcl_cli_render_env e = zcl_cli_render_resolve(-1);
        ASSERT(!e.human);
        ASSERT(!e.ansi);

        /* Forced human, clean color environment → ANSI on. */
        setenv("ZCL_HUMAN", "1", 1);
        unsetenv("NO_COLOR");
        setenv("TERM", "xterm", 1);
        setenv("COLUMNS", "57", 1);
        e = zcl_cli_render_resolve(-1);
        ASSERT(e.human);
        ASSERT(e.ansi);
        ASSERT(e.width == 57);

        /* NO_COLOR presence (even empty) suppresses ANSI, keeps layout. */
        setenv("NO_COLOR", "", 1);
        e = zcl_cli_render_resolve(-1);
        ASSERT(e.human);
        ASSERT(!e.ansi);

        /* TERM=dumb suppresses ANSI too. */
        unsetenv("NO_COLOR");
        setenv("TERM", "dumb", 1);
        e = zcl_cli_render_resolve(-1);
        ASSERT(e.human);
        ASSERT(!e.ansi);

        /* ZCL_HUMAN=0 forces JSON even with everything else inviting. */
        setenv("ZCL_HUMAN", "0", 1);
        setenv("TERM", "xterm", 1);
        e = zcl_cli_render_resolve(-1);
        ASSERT(!e.human);

        /* Width is clamped into 40..240. */
        setenv("ZCL_HUMAN", "1", 1);
        setenv("COLUMNS", "3", 1);
        e = zcl_cli_render_resolve(-1);
        ASSERT(e.width == 40);
        setenv("COLUMNS", "9999", 1);
        e = zcl_cli_render_resolve(-1);
        ASSERT(e.width == 240);

        cr_restore_env(&saved);
        PASS();
    } _test_next:;
    return failures;
}

/* ── unit: menu table ──────────────────────────────────────────────── */

/* A fabricated branch menu with `nchildren` children. Caller frees. */
static size_t cr_menu_doc(int nchildren, char *out, size_t cap)
{
    size_t len = 0;
    int n = snprintf(out, cap,
                     "{\"schema\":\"zcl.command_menu.v1\",\"path\":\"ops\","
                     "\"summary\":\"Node diagnostics\","
                     "\"registry_digest\":\"sha256:abc\",\"children\":[");
    len += (size_t)n;
    for (int i = 0; i < nchildren; i++) {
        n = snprintf(out + len, cap - len,
                     "%s{\"path\":\"ops.child%d\",\"summary\":\"child number "
                     "%d with a summary\",\"risk\":\"read\",\"latency\":\"fast\","
                     "\"availability\":\"ready\"}",
                     i ? "," : "", i, i);
        len += (size_t)n;
    }
    n = snprintf(out + len, cap - len,
                 "],\"next\":{\"command\":\"discover.describe\","
                 "\"input\":{\"path\":\"ops.child0\"}}}");
    len += (size_t)n;
    return len;
}

static int test_menu_render(void)
{
    int failures = 0;
    TEST("menu renders an aligned bounded table with a next hint") {
        char doc[16384];
        size_t dlen = cr_menu_doc(6, doc, sizeof(doc));
        struct zcl_cli_render_env e = cr_env(80, false);
        char out[16384];
        size_t n = zcl_cli_render_doc(doc, dlen, "ops", &e, out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "ops — Node diagnostics") != NULL);
        ASSERT(strstr(out, "PATH") != NULL);
        ASSERT(strstr(out, "SUMMARY") != NULL);
        ASSERT(strstr(out, "ops.child0") != NULL);
        ASSERT(strstr(out, "next: z23 discover describe ops.child0")
               != NULL);
        ASSERT(!cr_has_esc(out));
        ASSERT(cr_max_line_width(out) <= 80);
        /* No row cap needed at 6 rows → no footer. */
        ASSERT(strstr(out, "more, pipe to JSON") == NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_menu_row_cap(void)
{
    int failures = 0;
    TEST("menu caps rows at max_rows with the exact N-more footer") {
        char doc[32768];
        size_t dlen = cr_menu_doc(30, doc, sizeof(doc));
        struct zcl_cli_render_env e = cr_env(100, false);
        char out[16384];
        size_t n = zcl_cli_render_doc(doc, dlen, "ops", &e, out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "ops.child23") != NULL);   /* 24 rows shown */
        ASSERT(strstr(out, "ops.child24") == NULL);
        ASSERT(strstr(out, "... (6 more, pipe to JSON for full)") != NULL);
        ASSERT(cr_max_line_width(out) <= 100);
        PASS();
    } _test_next:;
    return failures;
}

static int test_menu_width_and_ansi(void)
{
    int failures = 0;
    TEST("menu truncates to a narrow width; ANSI only when allowed") {
        char doc[16384];
        size_t dlen = cr_menu_doc(4, doc, sizeof(doc));

        struct zcl_cli_render_env e = cr_env(44, false);
        char out[16384];
        size_t n = zcl_cli_render_doc(doc, dlen, "ops", &e, out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(cr_max_line_width(out) <= 44);
        ASSERT(strstr(out, "…") != NULL); /* U+2026 marks a truncated cell */

        e = cr_env(80, true);
        n = zcl_cli_render_doc(doc, dlen, "ops", &e, out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(cr_has_esc(out));
        PASS();
    } _test_next:;
    return failures;
}

/* ── unit: error blocks ────────────────────────────────────────────── */

static int test_error_render(void)
{
    int failures = 0;
    TEST("error envelope renders code + message + curated suggestion") {
        const char *doc =
            "{\"schema\":\"zcl.result.v1\",\"command\":\"ops.state\","
            "\"ok\":false,\"status\":\"failed\",\"error\":{\"code\":"
            "\"MISSING_SUBSYSTEM\",\"message\":\"subsystem is required\","
            "\"phase\":\"normalize\",\"retryable\":false,\"mutated\":false,"
            "\"evidence\":\"ops.state\",\"blockers\":[]},\"next\":[{\"command\":"
            "\"discover.describe\",\"input\":{\"path\":\"ops.state\"},"
            "\"reason\":\"inspect the subsystem input contract\"}]}";
        struct zcl_cli_render_env e = cr_env(80, false);
        char out[4096];
        size_t n = zcl_cli_render_doc(doc, strlen(doc), "ops.state", &e,
                                      out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "error:") != NULL);
        ASSERT(strstr(out, "MISSING_SUBSYSTEM") != NULL);
        ASSERT(strstr(out, "subsystem is required") != NULL);
        /* The curated table wins over the envelope's discover.describe
         * next — the registry's suggestion is the generic contract link,
         * the table's is the actionable one (statecatalog). */
        ASSERT(strstr(out, "run: z23 statecatalog") != NULL);
        ASSERT(!cr_has_esc(out));
        PASS();
    } _test_next:;
    return failures;
}

static int test_error_unknown_command_uses_envelope_query(void)
{
    int failures = 0;
    TEST("UNKNOWN_COMMAND suggestion carries the operator's real query") {
        const char *doc =
            "{\"schema\":\"zcl.result.v1\",\"command\":\"ops.stat\","
            "\"ok\":false,\"status\":\"failed\",\"error\":{\"code\":"
            "\"UNKNOWN_COMMAND\",\"message\":\"no such command under this "
            "branch\",\"phase\":\"resolve\",\"retryable\":false,"
            "\"mutated\":false,\"blockers\":[]},\"next\":[{\"command\":"
            "\"discover.search\",\"input\":{\"query\":\"stat\"},\"reason\":"
            "\"search for the intended command\"}]}";
        struct zcl_cli_render_env e = cr_env(80, false);
        char out[4096];
        size_t n = zcl_cli_render_doc(doc, strlen(doc), "ops.stat", &e,
                                      out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "run: z23 discover search stat") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_error_ansi_and_unknown_schema_fallback(void)
{
    int failures = 0;
    TEST("ANSI error block; unrecognized schema returns 0 (JSON fallback)") {
        const char *doc =
            "{\"schema\":\"zcl.result.v1\",\"command\":\"ops.state\","
            "\"ok\":false,\"status\":\"failed\",\"error\":{\"code\":"
            "\"MISSING_SUBSYSTEM\",\"message\":\"subsystem is required\","
            "\"phase\":\"normalize\",\"retryable\":false,\"mutated\":false,"
            "\"blockers\":[]},\"next\":[]}";
        struct zcl_cli_render_env e = cr_env(80, true);
        char out[4096];
        size_t n = zcl_cli_render_doc(doc, strlen(doc), "ops.state", &e,
                                      out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(cr_has_esc(out));
        char stripped[4096];
        snprintf(stripped, sizeof(stripped), "%s", out);
        cr_strip_ansi(stripped);
        ASSERT(strstr(stripped, "error: MISSING_SUBSYSTEM (normalize)")
               != NULL);

        /* An ok=true envelope for a leaf NOT in the tree allowlist must
         * refuse to render — the canonical JSON is its human form. */
        const char *okdoc =
            "{\"schema\":\"zcl.result.v1\",\"command\":\"core.status\","
            "\"ok\":true,\"status\":\"passed\",\"data\":{\"x\":1}}";
        n = zcl_cli_render_doc(okdoc, strlen(okdoc), "core.status", &e,
                               out, sizeof(out));
        ASSERT(n == 0);

        /* A human=false environment never renders. */
        e.human = false;
        n = zcl_cli_render_doc(doc, strlen(doc), "ops.state", &e, out,
                               sizeof(out));
        ASSERT(n == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── unit: ops.state data tree ─────────────────────────────────────── */

static int test_data_tree_render(void)
{
    int failures = 0;
    TEST("ops.state data renders as an aligned bounded kv tree") {
        const char *doc =
            "{\"schema\":\"zcl.result.v1\",\"command\":\"ops.state\","
            "\"ok\":true,\"status\":\"passed\",\"data\":{"
            "\"subsystem\":\"reducer_frontier\",\"state\":{"
            "\"hstar\":3176325,\"served_floor\":3176325,"
            "\"stages\":{\"utxo_apply\":3176325,\"tip_finalize\":3176325},"
            "\"tags\":[\"a\",\"b\"]}}}";
        struct zcl_cli_render_env e = cr_env(80, false);
        char out[8192];
        size_t n = zcl_cli_render_doc(doc, strlen(doc), "ops.state", &e,
                                      out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "ops.state") != NULL);
        ASSERT(strstr(out, "hstar") != NULL);
        ASSERT(strstr(out, "3176325") != NULL);
        ASSERT(strstr(out, "utxo_apply") != NULL);
        ASSERT(strstr(out, "a, b") != NULL); /* short scalar array inlines */
        ASSERT(cr_max_line_width(out) <= 80);
        PASS();
    } _test_next:;
    return failures;
}

/* ── unit: zcode.guide data tree ───────────────────────────────────── */

/* zcode.guide is the one obvious next action a new reader is told to run,
 * so it must not answer in raw JSON on a terminal. */
static int test_guide_tree_render(void)
{
    int failures = 0;
    TEST("zcode.guide renders a copyable start, not JSON keys") {
        const char *doc =
            "{\"schema\":\"zcl.result.v1\",\"command\":\"zcode.guide\","
            "\"ok\":true,\"status\":\"passed\",\"data\":{"
            "\"mission\":\"Tell Z23 what you want C23 software to do.\","
            "\"next_action\":\"Describe the behavior you want.\","
            "\"start_command\":\"z23 zcode work start . \\\"<desired behavior>\\\"\","
            "\"journey\":\"reuse C23 -> create only missing code -> build\","
            "\"continue_rule\":\"Follow the next_safe_command.\"}}";
        struct zcl_cli_render_env e = cr_env(80, false);
        char out[8192];
        size_t n = zcl_cli_render_doc(doc, strlen(doc), "zcode.guide", &e,
                                      out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "zcode.guide") != NULL);
        ASSERT(strstr(out, "z23 zcode work start .") != NULL);
        ASSERT(strstr(out, "Describe the behavior you want.") != NULL);
        ASSERT(strstr(out, "reuse C23") != NULL);
        ASSERT(strstr(out, "next_safe_command") != NULL);
        ASSERT(strstr(out, "next_action") == NULL);
        ASSERT(strstr(out, "continue_rule") == NULL);
        ASSERT(strstr(out, "\"schema\"") == NULL); /* not the raw envelope */
        ASSERT(cr_max_line_width(out) <= 80);
        PASS();
    }
    TEST("yardsale.guide renders layered stories, not JSON keys") {
        const char *doc =
            "{\"schema\":\"zcl.result.v1\",\"command\":\"yardsale.guide\","
            "\"ok\":true,\"status\":\"passed\",\"data\":{"
            "\"mission\":\"Pay ZCL and sell a 1/1 collectible.\","
            "\"next_action\":\"See whether this node holds confirmed ZCL.\","
            "\"start_command\":\"z23 vault list\","
            "\"continue_rule\":\"Follow commit_input.\","
            "\"layers\":["
            "{\"id\":\"pay_zcl\",\"user_story\":\"Pay confirmed ZCL.\","
            "\"plan_command\":\"vault.intent.plan\","
            "\"test_group\":\"test_simnet_wallet_import_backup\","
            "\"expected\":\"simnet_confirmed\"},"
            "{\"id\":\"sapling\",\"user_story\":\"Shield value.\","
            "\"plan_command\":\"vault.intent.plan\","
            "\"test_group\":\"test_simnet_shielded_wallet_e2e\","
            "\"expected\":\"simnet_confirmed\"}"
            "]}}";
        struct zcl_cli_render_env e = cr_env(80, false);
        char out[8192];
        size_t n = zcl_cli_render_doc(doc, strlen(doc), "yardsale.guide", &e,
                                      out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "yardsale.guide") != NULL);
        ASSERT(strstr(out, "z23 vault list") != NULL);
        ASSERT(strstr(out, "pay_zcl") != NULL);
        ASSERT(strstr(out, "vault.intent.plan") != NULL);
        ASSERT(strstr(out, "Pay confirmed ZCL.") != NULL);
        ASSERT(strstr(out, "sapling") != NULL);
        ASSERT(strstr(out, "next_action") == NULL);
        ASSERT(strstr(out, "\"schema\"") == NULL);
        ASSERT(cr_max_line_width(out) <= 80);
        PASS();
    }
    TEST("code.guide renders a four-step recipe, not JSON keys") {
        const char *doc =
            "{\"schema\":\"zcl.result.v1\",\"command\":\"code.guide\","
            "\"ok\":true,\"status\":\"passed\",\"data\":{"
            "\"start_command\":\"z23 code impact <file.c>\","
            "\"proof_command\":\"make lint-fast\","
            "\"lint_command\":\"make lint-fast\","
            "\"push_command\":\"make pre-push-ci\","
            "\"never\":\"test_zcl\"}}";
        struct zcl_cli_render_env e = cr_env(80, false);
        char out[8192];
        size_t n = zcl_cli_render_doc(doc, strlen(doc), "code.guide", &e,
                                      out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "code.guide") != NULL);
        ASSERT(strstr(out, "z23 code impact <file.c>") != NULL);
        ASSERT(strstr(out, "make pre-push-ci") != NULL);
        ASSERT(strstr(out, "start_command") == NULL);
        ASSERT(strstr(out, "\"schema\"") == NULL);
        ASSERT(cr_max_line_width(out) <= 80);
        PASS();
    }
    TEST("peers.list renders a kind table and a copyable continue") {
        const char *doc =
            "{\"schema\":\"zcl.result.v1\","
            "\"command\":\"core.network.peers.list\",\"ok\":true,"
            "\"data\":{\"items\":["
            "{\"addr\":\"203.0.113.10:8033\",\"inbound\":false,"
            "\"startingheight\":100,\"zclassic23\":true,\"magicbean\":false}"
            "],\"_page\":{\"total_items\":28,\"included\":1,\"truncated\":true,"
            "\"continue\":\"z23 core network peers list --cursor=2\"}}}";
        struct zcl_cli_render_env e = cr_env(80, false);
        char out[8192];
        size_t n = zcl_cli_render_doc(doc, strlen(doc),
                                      "core.network.peers.list", &e, out,
                                      sizeof(out));
        ASSERT(n > 0);
        ASSERT(strstr(out, "peers") != NULL);
        ASSERT(strstr(out, "203.0.113.10:8033") != NULL);
        ASSERT(strstr(out, "z23") != NULL);
        ASSERT(strstr(out, "z23 core network peers list --cursor=2") != NULL);
        ASSERT(strstr(out, "lifecycle") == NULL);
        ASSERT(strstr(out, "\"schema\"") == NULL);
        ASSERT(cr_max_line_width(out) <= 80);
        PASS();
    } _test_next:;
    return failures;
}

/* ── unit: brief colorization ──────────────────────────────────────── */

static int test_brief_render(void)
{
    int failures = 0;
    TEST("brief line: ANSI accents on a TTY, byte-identical plain copy "
         "without") {
        const char *line =
            "hstar=100 gap=0 peer_best=100 sync=synced blocker=none "
            "blocker_age=unknown conditions=0 peers=8 rss_mb=512";
        struct zcl_cli_render_env e = cr_env(80, false);
        char out[1024];
        size_t n = zcl_cli_render_brief(line, &e, out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(strcmp(out, line) == 0); /* plain copy, byte-identical */

        e = cr_env(80, true);
        n = zcl_cli_render_brief(line, &e, out, sizeof(out));
        ASSERT(n > 0);
        ASSERT(cr_has_esc(out));
        cr_strip_ansi(out);
        ASSERT(strcmp(out, line) == 0); /* accents add zero visible change */
        PASS();
    } _test_next:;
    return failures;
}

/* ── end-to-end against the real binary ────────────────────────────── */

#define CR_BIN "build/bin/zclassic23"

static bool cr_bin_fresh(const char **stale_out)
{
    static const char *const witnesses[] = {
        "tools/command/cli_render.c",
        "tools/command/native_command.c",
        "src/main_cli_modes.c",
        NULL,
    };
    struct stat st;
    if (stat(CR_BIN, &st) != 0)
        return false;
    long bin_mt = (long)st.st_mtime;
    for (size_t i = 0; witnesses[i]; i++) {
        if (stat(witnesses[i], &st) != 0)
            continue;
        if ((long)st.st_mtime > bin_mt) {
            if (stale_out)
                *stale_out = witnesses[i];
            return false;
        }
    }
    return true;
}

/* Fork/exec CR_BIN with a full custom envp, capture stdout+stderr.
 * Same shape as test_cli_auth_robust.c's car_run. */
static int cr_run(char *const argv[], char *const envp[], char *out,
                  size_t cap)
{
    int pipefd[2];
    if (pipe(pipefd) != 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execve(CR_BIN, argv, envp);
        _exit(127);
    }
    close(pipefd[1]);
    size_t pos = 0;
    char buf[4096];
    ssize_t r;
    while ((r = read(pipefd[0], buf, sizeof(buf))) > 0) {
        size_t take = (size_t)r;
        size_t room = (pos + 1 < cap) ? (cap - 1 - pos) : 0;
        if (take > room)
            take = room;
        if (take > 0) {
            memcpy(out + pos, buf, take);
            pos += take;
        }
    }
    out[pos < cap ? pos : cap - 1] = 0;
    close(pipefd[0]);
    int status = 0;
    if (waitpid(pid, &status, 0) != pid)
        return -1;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -100;
}

/* envp: HOME, PATH, the service-lookup suppressor, plus up to two extra
 * "KEY=VALUE" strings (NULL to skip). Static scratch, single-threaded. */
static char cr_env_home[600];
static char cr_env_x1[128];
static char cr_env_x2[128];
static char *cr_envp[8];

static char *const *cr_build_envp(const char *home, const char *x1,
                                  const char *x2)
{
    size_t i = 0;
    snprintf(cr_env_home, sizeof(cr_env_home), "HOME=%s", home);
    cr_envp[i++] = cr_env_home;
    cr_envp[i++] = (char *)"PATH=/usr/bin:/bin:/usr/local/bin";
    cr_envp[i++] = (char *)"ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1";
    if (x1) {
        snprintf(cr_env_x1, sizeof(cr_env_x1), "%s", x1);
        cr_envp[i++] = cr_env_x1;
    }
    if (x2) {
        snprintf(cr_env_x2, sizeof(cr_env_x2), "%s", x2);
        cr_envp[i++] = cr_env_x2;
    }
    cr_envp[i] = NULL;
    return cr_envp;
}

static int test_e2e_pipe_byte_identity(const char *home)
{
    int failures = 0;
    TEST("e2e: piped stdout is byte-identical with/without ZCL_HUMAN") {
        char *argv[] = { (char *)CR_BIN, (char *)"discover",
                         (char *)"search", (char *)"status", NULL };
        char plain[8192], forced_off[8192];
        int rc1 = cr_run(argv, cr_build_envp(home, NULL, NULL), plain,
                         sizeof(plain));
        int rc2 = cr_run(argv, cr_build_envp(home, "ZCL_HUMAN=0", NULL),
                         forced_off, sizeof(forced_off));
        ASSERT(rc1 == 0 && rc2 == 0);
        ASSERT(strcmp(plain, forced_off) == 0); /* THE prime directive */
        ASSERT(strncmp(plain, "{\"schema\":\"zcl.command_search.v1\"", 33)
               == 0);

        /* Same proof for a branch menu and an error envelope. */
        char *margv[] = { (char *)CR_BIN, (char *)"ops", NULL };
        int mrc1 = cr_run(margv, cr_build_envp(home, NULL, NULL), plain,
                          sizeof(plain));
        int mrc2 = cr_run(margv, cr_build_envp(home, "ZCL_HUMAN=0", NULL),
                          forced_off, sizeof(forced_off));
        ASSERT(mrc1 == 0 && mrc2 == 0);
        ASSERT(strcmp(plain, forced_off) == 0);

        char *eargv[] = { (char *)CR_BIN, (char *)"discover",
                          (char *)"search", NULL };
        int erc1 = cr_run(eargv, cr_build_envp(home, NULL, NULL), plain,
                          sizeof(plain));
        int erc2 = cr_run(eargv, cr_build_envp(home, "ZCL_HUMAN=0", NULL),
                          forced_off, sizeof(forced_off));
        ASSERT(erc1 == 2 && erc2 == 2); /* exit code unchanged too */
        ASSERT(strcmp(plain, forced_off) == 0);
        ASSERT(strstr(plain, "\"code\":\"MISSING_QUERY\"") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_e2e_forced_human(const char *home)
{
    int failures = 0;
    TEST("e2e: ZCL_HUMAN=1 forces the human rendering deterministically") {
        char *argv[] = { (char *)CR_BIN, (char *)"discover",
                         (char *)"search", (char *)"status", NULL };
        char out[8192];
        int rc = cr_run(argv,
                        cr_build_envp(home, "ZCL_HUMAN=1", "NO_COLOR=1"),
                        out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(out[0] != '{');             /* not the JSON document */
        ASSERT(strstr(out, "PATH") != NULL);
        ASSERT(strstr(out, "next: z23 discover describe") != NULL);
        ASSERT(!cr_has_esc(out));          /* NO_COLOR honored */

        /* ANSI appears when the terminal allows it. */
        rc = cr_run(argv, cr_build_envp(home, "ZCL_HUMAN=1", "TERM=xterm"),
                    out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(cr_has_esc(out));

        /* Human error block with the suggestion line. */
        char *eargv[] = { (char *)CR_BIN, (char *)"discover",
                          (char *)"search", NULL };
        rc = cr_run(eargv, cr_build_envp(home, "ZCL_HUMAN=1", "NO_COLOR=1"),
                    out, sizeof(out));
        ASSERT(rc == 2);
        ASSERT(strstr(out, "error:") != NULL);
        ASSERT(strstr(out, "MISSING_QUERY") != NULL);
        ASSERT(strstr(out, "run: z23 discover search") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_e2e_width_and_row_cap(const char *home)
{
    int failures = 0;
    TEST("e2e: narrow terminal caps every line; statecatalog caps rows") {
        char *argv[] = { (char *)CR_BIN, (char *)"ops", NULL };
        char out[16384];
        int rc = cr_run(argv,
                        cr_build_envp(home, "ZCL_HUMAN=1", "COLUMNS=48"),
                        out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(cr_max_line_width(out) <= 48);

        char *cargv[] = { (char *)CR_BIN, (char *)"statecatalog", NULL };
        rc = cr_run(cargv, cr_build_envp(home, "ZCL_HUMAN=1", "NO_COLOR=1"),
                    out, sizeof(out));
        ASSERT(rc == 0);
        ASSERT(strstr(out, "dumpstate subsystems") != NULL);
        ASSERT(strstr(out, "more, pipe to JSON for full") != NULL);
        ASSERT(cr_max_line_width(out) <= 80);
        PASS();
    } _test_next:;
    return failures;
}

/* ── group entry ───────────────────────────────────────────────────── */

int test_cli_render(void)
{
    int failures = 0;
    failures += test_env_resolution();
    failures += test_menu_render();
    failures += test_menu_row_cap();
    failures += test_menu_width_and_ansi();
    failures += test_error_render();
    failures += test_error_unknown_command_uses_envelope_query();
    failures += test_error_ansi_and_unknown_schema_fallback();
    failures += test_data_tree_render();
    failures += test_guide_tree_render();
    failures += test_brief_render();

    const char *stale = NULL;
    if (!cr_bin_fresh(&stale)) {
        printf("cli_render: %s missing/stale (newer source: %s) — SKIP "
               "e2e half (run `make` to rebuild)\n", CR_BIN,
               stale ? stale : "(unknown)");
    } else {
        char home[256];
        snprintf(home, sizeof(home), "/tmp/zcl_cr_home_%d", (int)getpid());
        if (mkdir(home, 0700) == 0 || errno == EEXIST) {
            failures += test_e2e_pipe_byte_identity(home);
            failures += test_e2e_forced_human(home);
            failures += test_e2e_width_and_row_cap(home);
            rmdir(home);
        }
    }

    printf("=== cli_render: %d failures ===\n", failures);
    return failures;
}
