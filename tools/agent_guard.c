/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * z23-agent-guard: a Claude Code PreToolUse hook that refuses the
 * never-do list the project instruction files already state (node
 * datadirs, the reindex flag, interpreter use, git identity, spend and
 * key export, host config, git push).
 *
 *   z23-agent-guard                       hook mode: PreToolUse JSON on stdin
 *   z23-agent-guard --bash CMD            print ALLOW or REFUSE <rule>
 *   z23-agent-guard --path TOOL FILE [CONTENT]
 *   z23-agent-guard --replay TRANSCRIPT   evaluate a transcript offline
 *
 * Hook contract: exit 2 plus one stderr line refuses the call; exit 0
 * with no output allows it. Unreadable input fails open with a warning:
 * this is a safety net, not the primary control. Precision matters as
 * much as coverage, because a false refusal stalls the worker.
 *
 * Shell scanning: the command is split into segments at ; && || | & and
 * newlines (also $( ) ( ) and backticks outside quotes). Quoted text is
 * data, except the argument of ssh and of sh/bash/dash/zsh -c, and a
 * heredoc body that feeds a shell or ssh, which are scanned again as
 * commands. Parsing uses the zjsonp pull parser. */


#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "agent_guard_rules.h"
#include "zjsonp/zjsonp.h"

#define MAX_INPUT (32u * 1024u * 1024u)
#define MAX_CALLS 16

/* ---- tool call extraction from JSON ------------------------------ */

struct call {
    char *name, *cmd, *file, *nb, *content;
};

static void call_free(struct call *c)
{
    free(c->name);
    free(c->cmd);
    free(c->file);
    free(c->nb);
    free(c->content);
    memset(c, 0, sizeof *c);
}

static char *dec_str(const char *text, const zjsonp_event *ev)
{
    char *out = malloc(ev->len + 1); // raw-alloc-ok:build-tool
    size_t n;
    if (!out) return NULL;
    n = zjsonp_str_decode(text, ev, out, ev->len + 1);
    if (n == SIZE_MAX || n > ev->len) {
        free(out);
        return NULL;
    }
    out[n] = '\0';
    return out;
}

static bool skip_value(zjsonp *p, const zjsonp_event *v)
{
    int d = 0;
    if (v->kind != ZJRP_OBJ_OPEN && v->kind != ZJRP_ARR_OPEN) return true;
    d = 1;
    while (d > 0) {
        zjsonp_event ev;
        if (zjsonp_next(p, &ev) != ZJRP_OK) return false;
        if (ev.kind == ZJRP_OBJ_OPEN || ev.kind == ZJRP_ARR_OPEN) d++;
        if (ev.kind == ZJRP_OBJ_CLOSE || ev.kind == ZJRP_ARR_CLOSE) d--;
    }
    return true;
}

/* Decode the key event into out; out[0] is NUL when it does not fit. */
static void key_str(const char *text, const zjsonp_event *ev, char *out, size_t cap)
{
    size_t n = zjsonp_str_decode(text, ev, out, cap);
    if (n == SIZE_MAX || n >= cap) out[0] = '\0';
    else out[n] = '\0';
}

static char **input_slot(struct call *c, const char *key)
{
    if (strcmp(key, "command") == 0) return &c->cmd;
    if (strcmp(key, "file_path") == 0) return &c->file;
    if (strcmp(key, "notebook_path") == 0) return &c->nb;
    if (strcmp(key, "content") == 0) return &c->content;
    return NULL;
}

/* Called after the tool_input OBJ_OPEN; consumes through its close. */
static bool parse_input(zjsonp *p, const char *text, struct call *call)
{
    for (;;) {
        zjsonp_event ev, v;
        char key[32];
        char **slot;
        if (zjsonp_next(p, &ev) != ZJRP_OK) return false;
        if (ev.kind == ZJRP_OBJ_CLOSE) return true;
        if (ev.kind != ZJRP_KEY || zjsonp_next(p, &v) != ZJRP_OK) return false;
        key_str(text, &ev, key, sizeof key);
        slot = input_slot(call, key);
        if (slot && v.kind == ZJRP_STR) {
            free(*slot);
            *slot = dec_str(text, &v);
        } else if (!skip_value(p, &v)) {
            return false;
        }
    }
}

static bool parse_hook(const char *text, size_t len, struct call *call)
{
    zjsonp p;
    zjsonp_event ev;
    zjsonp_init(&p, text, len);
    if (zjsonp_next(&p, &ev) != ZJRP_OK || ev.kind != ZJRP_OBJ_OPEN) return false;
    for (;;) {
        zjsonp_event v;
        char key[32];
        if (zjsonp_next(&p, &ev) != ZJRP_OK) return false;
        if (ev.kind == ZJRP_OBJ_CLOSE) return true;
        if (ev.kind != ZJRP_KEY || zjsonp_next(&p, &v) != ZJRP_OK) return false;
        key_str(text, &ev, key, sizeof key);
        if (strcmp(key, "tool_name") == 0 && v.kind == ZJRP_STR) {
            free(call->name);
            call->name = dec_str(text, &v);
        } else if (strcmp(key, "tool_input") == 0 && v.kind == ZJRP_OBJ_OPEN) {
            if (!parse_input(&p, text, call)) return false;
        } else if (!skip_value(&p, &v)) {
            return false;
        }
    }
}

static const char *eval_call(const struct call *c)
{
    if (!c->name) return NULL;
    if (strcmp(c->name, "Bash") == 0) return c->cmd ? ag_eval_bash(c->cmd) : NULL;
    if (strcmp(c->name, "NotebookEdit") == 0) return ag_eval_path(c->name, c->nb, NULL);
    if (strcmp(c->name, "Edit") == 0 || strcmp(c->name, "Write") == 0 ||
        strcmp(c->name, "MultiEdit") == 0)
        return ag_eval_path(c->name, c->file, c->content);
    return NULL;
}

static bool call_is_checked(const struct call *c)
{
    static const char *const tools[] = {"Bash", "Edit", "Write", "MultiEdit",
                                        "NotebookEdit"};
    if (!c->name) return false;
    for (size_t i = 0; i < sizeof tools / sizeof tools[0]; i++)
        if (strcmp(c->name, tools[i]) == 0) return true;
    return false;
}

static const char *call_subject(const struct call *c)
{
    if (c->cmd) return c->cmd;
    if (c->file) return c->file;
    return c->nb ? c->nb : "";
}

/* ---- transcript replay ------------------------------------------- */

struct walker {
    zjsonp p;
    const char *text;
    struct call calls[MAX_CALLS];
    int ncalls;
    bool assistant;
};

struct objst {
    char type[24];
    char *name;
    struct call in;
    bool has_in;
};

static bool walk_value(struct walker *W, const zjsonp_event *v, int level);

static bool walk_array(struct walker *W, int level)
{
    for (;;) {
        zjsonp_event ev;
        if (zjsonp_next(&W->p, &ev) != ZJRP_OK) return false;
        if (ev.kind == ZJRP_ARR_CLOSE) return true;
        if (!walk_value(W, &ev, level + 1)) return false;
    }
}

static bool walk_member(struct walker *W, const zjsonp_event *kev, int level,
                        struct objst *st)
{
    zjsonp_event v;
    char key[16];
    if (zjsonp_next(&W->p, &v) != ZJRP_OK) return false;
    key_str(W->text, kev, key, sizeof key);
    if (strcmp(key, "type") == 0 && v.kind == ZJRP_STR) {
        key_str(W->text, &v, st->type, sizeof st->type);
        return true;
    }
    if (strcmp(key, "name") == 0 && v.kind == ZJRP_STR) {
        free(st->name);
        st->name = dec_str(W->text, &v);
        return true;
    }
    if (strcmp(key, "input") == 0 && v.kind == ZJRP_OBJ_OPEN) {
        st->has_in = true;
        return parse_input(&W->p, W->text, &st->in);
    }
    return walk_value(W, &v, level + 1);
}

static void finish_object(struct walker *W, struct objst *st, int level)
{
    if (level == 0) {
        W->assistant = strcmp(st->type, "assistant") == 0;
    } else if (strcmp(st->type, "tool_use") == 0 && st->name && st->has_in &&
               W->ncalls < MAX_CALLS) {
        W->calls[W->ncalls] = st->in;
        W->calls[W->ncalls].name = st->name;
        W->ncalls++;
        st->name = NULL;
        memset(&st->in, 0, sizeof st->in);
    }
}

static bool walk_object(struct walker *W, int level)
{
    struct objst st;
    bool ok = true;
    memset(&st, 0, sizeof st);
    for (;;) {
        zjsonp_event ev;
        if (zjsonp_next(&W->p, &ev) != ZJRP_OK) {
            ok = false;
            break;
        }
        if (ev.kind == ZJRP_OBJ_CLOSE) break;
        if (ev.kind != ZJRP_KEY || !walk_member(W, &ev, level, &st)) {
            ok = false;
            break;
        }
    }
    if (ok) finish_object(W, &st, level);
    free(st.name);
    call_free(&st.in);
    return ok;
}

static bool walk_value(struct walker *W, const zjsonp_event *v, int level)
{
    if (level > ZJRP_MAX_DEPTH) return false;
    if (v->kind == ZJRP_OBJ_OPEN) return walk_object(W, level);
    if (v->kind == ZJRP_ARR_OPEN) return walk_array(W, level);
    return true;
}

static void print_excerpt(const char *rule, const char *s)
{
    char buf[141];
    size_t n = 0;
    for (; s[n] && n < 140; n++) buf[n] = (s[n] == '\n' || s[n] == '\r') ? ' ' : s[n];
    buf[n] = '\0';
    printf("REFUSE %s %s\n", rule, buf);
}

static void replay_line(const char *line, size_t len, long *calls, long *refused)
{
    struct walker *W = calloc(1, sizeof *W); // raw-alloc-ok:build-tool
    zjsonp_event ev;
    if (!W) return;
    W->text = line;
    zjsonp_init(&W->p, line, len);
    if (zjsonp_next(&W->p, &ev) == ZJRP_OK && ev.kind == ZJRP_OBJ_OPEN &&
        walk_object(W, 0) && W->assistant) {
        for (int i = 0; i < W->ncalls; i++) {
            const char *r;
            if (!call_is_checked(&W->calls[i])) continue;
            (*calls)++;
            r = eval_call(&W->calls[i]);
            if (!r) continue;
            (*refused)++;
            print_excerpt(r, call_subject(&W->calls[i]));
        }
    }
    for (int i = 0; i < W->ncalls; i++) call_free(&W->calls[i]);
    free(W);
}

static int cmd_replay(const char *file)
{
    FILE *f = fopen(file, "rb");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    long calls = 0, refused = 0;
    if (!f) {
        fprintf(stderr, "z23-agent-guard: cannot open %s\n", file);
        return 1;
    }
    while ((n = getline(&line, &cap, f)) >= 0)
        replay_line(line, (size_t)n, &calls, &refused);
    free(line);
    fclose(f);
    printf("replay: %ld calls, %ld refused\n", calls, refused);
    return 0;
}

/* ---- hook mode and CLI ------------------------------------------- */

static const char *rule_why(const char *rule)
{
    static const struct {
        const char *rule, *why;
    } table[] = {
        {R_DATADIR, "a node datadir is off limits for writes; read it with tail, cat, ls or grep only"},
        {R_REINDEX, "the reindex flag belongs to the operator; never create, move or delete it"},
        {R_PYTHON, "Python is banned in this repository; use shell, awk, jsonq, sqlq or a C23 tool"},
        {R_IDENT, "the git author is preconfigured; never set, unset or override it"},
        {R_SPEND, "spending and key-export RPCs are operator-only"},
        {R_HOST, "host sysctl, AppArmor and sudoers changes are operator-only"},
        {R_PUSH, "only the land queue pushes; commit on the lane branch and report the sha"},
        {R_DBHELP, "devbuild --help is a known host trap; read the dev docs instead"},
    };
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++)
        if (strcmp(table[i].rule, rule) == 0) return table[i].why;
    return "refused";
}

static char *read_stdin(size_t *len)
{
    size_t cap = 65536, n = 0;
    char *buf = malloc(cap); // raw-alloc-ok:build-tool
    while (buf) {
        size_t got = fread(buf + n, 1, cap - n, stdin);
        n += got;
        if (n < cap) break;
        if (cap >= MAX_INPUT) {
            free(buf);
            return NULL;
        }
        cap *= 2;
        char *nb = realloc(buf, cap); // raw-alloc-ok:build-tool
        if (!nb) {
            free(buf);
            return NULL;
        }
        buf = nb;
    }
    *len = n;
    return buf;
}

static int cmd_hook(void)
{
    size_t len = 0;
    char *in = read_stdin(&len);
    struct call call;
    const char *r = NULL;
    bool ok;
    memset(&call, 0, sizeof call);
    if (!in) {
        fprintf(stderr, "z23-agent-guard: warning: unreadable hook input; allowing\n");
        return 0;
    }
    ok = parse_hook(in, len, &call);
    if (ok) r = eval_call(&call);
    else fprintf(stderr, "z23-agent-guard: warning: unexpected hook input; allowing\n");
    call_free(&call);
    free(in);
    if (!r) return 0;
    fprintf(stderr,
            "z23-agent-guard refused (%s): %s. If this is a false positive, "
            "report it in your result; do not work around it.\n",
            r, rule_why(r));
    return 2;
}

static int print_verdict(const char *r)
{
    if (r) printf("REFUSE %s\n", r);
    else printf("ALLOW\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 1) return cmd_hook();
    if (argc == 3 && strcmp(argv[1], "--bash") == 0)
        return print_verdict(ag_eval_bash(argv[2]));
    if ((argc == 4 || argc == 5) && strcmp(argv[1], "--path") == 0)
        return print_verdict(ag_eval_path(argv[2], argv[3], argc == 5 ? argv[4] : NULL));
    if (argc == 3 && strcmp(argv[1], "--replay") == 0) return cmd_replay(argv[2]);
    fprintf(stderr,
            "usage: z23-agent-guard [--bash CMD | --path TOOL FILE [CONTENT] | --replay FILE]\n");
    return 64;
}
