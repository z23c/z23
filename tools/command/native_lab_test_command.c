/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: lab.test. Compile one C23 file once, run each case confined, and
 * report pass or fail per case with the first differing line. */
#include "command/lab_priv.h"
#include "command/native_command.h"

#include "base/safe_alloc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    LAB_CASES_FILE_MAX = 1024 * 1024,
    LAB_NAME_MAX = 64,
    LAB_DIFF_CASE = 512,
    LAB_DIFF_TOTAL = 16 * 1024,
    LAB_STDERR_CASE = 512,
    LAB_LINE_SHOW = 150,
};

struct lab_case {
    const char *name;
    const char *stdin_data;
    const char *args[LAB_ARGS_MAX];
    size_t n_args;
    const char *expect_stdout;
    bool has_exit;
    int expect_exit;
};

struct lab_cases {
    struct json_value doc; /* owns the parsed array when it came from text */
    const struct json_value *arr;
    struct lab_case *items;
    size_t n;
};

/* ── cases ──────────────────────────────────────────────────────────── */

static char *lab_cases_read_file(const char *path)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    char *buf = NULL;
    if (fd < 0)
        return NULL;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        st.st_size > 0 && st.st_size <= LAB_CASES_FILE_MAX)
        buf = zcl_malloc((size_t)st.st_size + 1, "lab.cases");
    ssize_t n = buf ? read(fd, buf, (size_t)st.st_size) : -1;
    close(fd);
    if (n != (ssize_t)st.st_size && buf) {
        free(buf);
        return NULL;
    }
    if (buf)
        buf[n] = '\0';
    return buf;
}

static bool lab_cases_text(const char *text, struct json_value *doc)
{
    const char *p = text;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    char *file = *p == '[' ? NULL : lab_cases_read_file(text);
    const char *src = *p == '[' ? text : file;
    bool ok = src && json_read(doc, src, strlen(src));
    free(file);
    return ok;
}

static bool lab_case_args(const struct json_value *v, struct lab_case *c)
{
    if (!v)
        return true;
    if (v->type != JSON_ARR || v->num_children > LAB_ARGS_MAX)
        return false;
    for (size_t i = 0; i < v->num_children; i++) {
        if (v->children[i].type != JSON_STR)
            return false;
        c->args[c->n_args++] = json_get_str(&v->children[i]);
    }
    return true;
}

static bool lab_case_known_keys(const struct json_value *o)
{
    static const char *const known[] = { "name", "stdin", "args",
                                         "expect_stdout", "expect_exit" };
    for (size_t i = 0; i < o->num_children; i++) {
        bool found = false;
        for (size_t k = 0; k < sizeof(known) / sizeof(known[0]); k++)
            found = found || strcmp(o->keys[i], known[k]) == 0;
        if (!found)
            return false;
    }
    return true;
}

static bool lab_case_fields_ok(const struct json_value *o)
{
    const struct json_value *name = json_get(o, "name");
    const struct json_value *in = json_get(o, "stdin");
    const struct json_value *out = json_get(o, "expect_stdout");
    const struct json_value *ex = json_get(o, "expect_exit");
    if (!name || name->type != JSON_STR || !json_get_str(name)[0] ||
        strlen(json_get_str(name)) > LAB_NAME_MAX)
        return false;
    if (in && (in->type != JSON_STR || strlen(json_get_str(in)) > LAB_STDIN_MAX))
        return false;
    if (out && out->type != JSON_STR)
        return false;
    return !ex || (ex->type == JSON_INT && json_get_int(ex) >= 0 &&
                   json_get_int(ex) <= 255);
}

static bool lab_case_parse(const struct json_value *o, struct lab_case *c)
{
    memset(c, 0, sizeof(*c));
    if (o->type != JSON_OBJ || !lab_case_known_keys(o) || !lab_case_fields_ok(o))
        return false;
    const struct json_value *in = json_get(o, "stdin");
    const struct json_value *out = json_get(o, "expect_stdout");
    const struct json_value *ex = json_get(o, "expect_exit");
    c->name = json_get_str(json_get(o, "name"));
    c->stdin_data = in ? json_get_str(in) : "";
    c->expect_stdout = out ? json_get_str(out) : NULL;
    c->has_exit = ex != NULL;
    c->expect_exit = ex ? (int)json_get_int(ex) : 0;
    return lab_case_args(json_get(o, "args"), c);
}

static bool lab_cases_load(const struct zcl_command_request *rq,
                           struct lab_cases *cs)
{
    const struct json_value *v = rq->input ? json_get(rq->input, "cases") : NULL;
    memset(cs, 0, sizeof(*cs));
    json_init(&cs->doc);
    if (v && v->type == JSON_ARR)
        cs->arr = v;
    else if (v && v->type == JSON_STR && lab_cases_text(json_get_str(v), &cs->doc))
        cs->arr = &cs->doc;
    if (!cs->arr || cs->arr->type != JSON_ARR || cs->arr->num_children == 0 ||
        cs->arr->num_children > LAB_CASES_MAX)
        return false;
    cs->n = cs->arr->num_children;
    cs->items = zcl_calloc(cs->n, sizeof(*cs->items), "lab.cases");
    for (size_t i = 0; cs->items && i < cs->n; i++)
        if (!lab_case_parse(&cs->arr->children[i], &cs->items[i]))
            return false;
    return cs->items != NULL;
}

static void lab_cases_free(struct lab_cases *cs)
{
    free(cs->items);
    json_free(&cs->doc);
}

static void lab_hash_case(struct lab_hasher *h, const struct lab_case *c)
{
    lab_hasher_field(h, "case", c->name, strlen(c->name));
    lab_hasher_field(h, "stdin", c->stdin_data, strlen(c->stdin_data));
    lab_hasher_u64(h, "argc", c->n_args);
    for (size_t i = 0; i < c->n_args; i++)
        lab_hasher_field(h, "arg", c->args[i], strlen(c->args[i]));
    lab_hasher_u64(h, "has_stdout", c->expect_stdout != NULL);
    if (c->expect_stdout)
        lab_hasher_field(h, "expect_stdout", c->expect_stdout,
                         strlen(c->expect_stdout));
    lab_hasher_u64(h, "has_exit", c->has_exit);
    lab_hasher_u64(h, "expect_exit", (uint64_t)c->expect_exit);
}

static bool lab_root_test(struct lab_ctx *ctx, const struct lab_cases *cs,
                          bool sanitize, uint32_t timeout_ms, uint32_t mem_mb)
{
    struct lab_hasher *h = lab_hasher_new("test.stderr.v1");
    if (!h)
        return false;
    lab_hasher_field(h, "source", ctx->src.bytes, ctx->src.len);
    lab_hasher_u64(h, "sanitize", sanitize);
    lab_hasher_u64(h, "timeout_ms", timeout_ms);
    lab_hasher_u64(h, "mem_mb", mem_mb);
    lab_hasher_u64(h, "cases", cs->n);
    for (size_t i = 0; i < cs->n; i++)
        lab_hash_case(h, &cs->items[i]);
    lab_hasher_finish(h, ctx->root);
    return true;
}

/* ── verdict ────────────────────────────────────────────────────────── */

/* Next line of s[*pos..len): its length, and whether a newline ended it. */
static size_t lab_next_line(const char *s, size_t len, size_t *pos, bool *nl)
{
    size_t start = *pos, i = start;
    while (i < len && s[i] != '\n')
        i++;
    *nl = i < len;
    *pos = i < len ? i + 1 : i;
    return i - start;
}

static void lab_show_line(char *dst, size_t cap, const char *line, size_t n,
                          bool nl, bool eof)
{
    if (eof) {
        snprintf(dst, cap, "<end of output>");
        return;
    }
    snprintf(dst, cap, "%.*s%s%s", (int)(n < LAB_LINE_SHOW ? n : LAB_LINE_SHOW),
             line, n > LAB_LINE_SHOW ? "..." : "", nl ? "\\n" : "");
}

static void lab_diff_text(const char *want, size_t wl, const char *got,
                          size_t gl, char *diff, size_t cap)
{
    size_t wp = 0, gp = 0;
    for (size_t line = 1;; line++) {
        size_t ws = wp, gs = gp;
        bool wnl, gnl, weof = wp >= wl, geof = gp >= gl;
        size_t wn = lab_next_line(want, wl, &wp, &wnl);
        size_t gn = lab_next_line(got, gl, &gp, &gnl);
        if (weof && geof)
            return;
        if (weof != geof || wn != gn || wnl != gnl ||
            memcmp(want + ws, got + gs, wn) != 0) {
            char w[LAB_LINE_SHOW + 8], g[LAB_LINE_SHOW + 8];
            lab_show_line(w, sizeof(w), want + ws, wn, wnl, weof);
            lab_show_line(g, sizeof(g), got + gs, gn, gnl, geof);
            snprintf(diff, cap, "line %zu: expected \"%s\" got \"%s\"", line, w, g);
            return;
        }
    }
}

static bool lab_case_verdict(const struct lab_case *c, const struct lab_proc *p,
                             uint32_t timeout_ms, char *diff, size_t cap)
{
    diff[0] = '\0';
    if (p->launch != LAB_LAUNCHED)
        snprintf(diff, cap, "did not run: %s", p->detail);
    else if (p->timed_out)
        snprintf(diff, cap, "timed out after %u ms", (unsigned)timeout_ms);
    else if (p->term_signal)
        snprintf(diff, cap, "killed by signal %d %s", p->term_signal,
                 lab_signal_name(p->term_signal));
    else if (p->exit_code != c->expect_exit)
        snprintf(diff, cap, "exit code: expected %d, got %d", c->expect_exit,
                 p->exit_code);
    else if (c->expect_stdout && p->out_cut)
        snprintf(diff, cap, "stdout exceeded %d bytes", LAB_CAPTURE_MAX);
    else if (c->expect_stdout)
        lab_diff_text(c->expect_stdout, strlen(c->expect_stdout), p->out,
                      p->out_len, diff, cap);
    return diff[0] == '\0';
}

/* ── receipt rows ───────────────────────────────────────────────────── */

struct lab_tally {
    size_t passed, failed, findings, diffs_omitted;
    size_t diff_left;
    char first[LAB_FIRST_MAX + 1];
};

/* Reserve added row framing inside the existing diagnostic allowance. Text
 * is charged after UTF-8 repair and JSON escaping, excluding string quotes. */
static void lab_diagnostic_budget(struct lab_tally *t, size_t cases)
{
    t->diff_left = LAB_DIFF_TOTAL - cases *
        (sizeof(",\"stderr\":\"\",\"stderr_status\":\"not_retained\"") - 1);
}

static bool lab_case_text(struct json_value *row, const char *key,
                           const char *text, size_t len, size_t cap,
                           struct lab_tally *t, bool *cut)
{
    size_t allowance = cap < t->diff_left ? cap : t->diff_left;
    if (!lab_json_text(row, key, text, len, allowance, cut))
        return false;
    size_t used = json_write(json_get(row, key), NULL, 0) - 2;
    t->diff_left -= used;
    return true;
}

static bool lab_case_row(struct json_value *rows, const struct lab_case *c,
                         const struct lab_proc *p, bool pass, const char *diff,
                         struct lab_tally *t)
{
    struct json_value row;
    bool cut = false;
    bool err_cut = p->err_cut;
    json_init(&row);
    json_set_object(&row);
    bool ok = json_push_kv_str(&row, "name", c->name) &&
              json_push_kv_bool(&row, "pass", pass) &&
              json_push_kv_int(&row, "exit_code",
                               p->launch == LAB_LAUNCHED ? p->exit_code : -1) &&
              json_push_kv_int(&row, "signal", p->term_signal) &&
              json_push_kv_int(&row, "wall_us", p->wall_us) &&
              lab_case_text(&row, "diff", diff, strlen(diff), LAB_DIFF_CASE,
                            t, &cut) &&
              lab_case_text(&row, "stderr", pass ? "" : p->err,
                            pass ? 0 : p->err_len, LAB_STDERR_CASE, t, &err_cut);
    t->diffs_omitted += cut;
    const struct json_value *err = json_get(&row, "stderr");
    const char *status = pass ? "not_retained"
        : err_cut && err && !json_get_str(err)[0] && p->err_len ? "omitted"
        : err_cut ? "truncated" : "complete";
    ok = ok && json_push_kv_str(&row, "stderr_status", status) &&
         json_push_back(rows, &row);
    json_free(&row);
    return ok;
}

static void lab_tally_findings(struct lab_tally *t, const struct lab_proc *p,
                               bool sanitized)
{
    char first[LAB_FIRST_MAX + 1];
    size_t n = sanitized ? lab_scan_sanitizer(p->err, p->err_len, first,
                                              sizeof(first)) : 0;
    if (n && t->findings == 0)
        memcpy(t->first, first, sizeof(first));
    t->findings += n;
}

/* Run every case; false when the host refused to confine one. */
static bool lab_run_cases(struct lab_ctx *ctx, const struct lab_cases *cs,
                          const struct lab_compile *comp, uint32_t timeout_ms,
                          uint32_t mem_mb, struct json_value *rows,
                          struct lab_tally *t)
{
    struct lab_proc proc;
    char diff[LAB_DIFF_CASE * 2];
    bool ok = lab_proc_init(&proc);
    for (size_t i = 0; ok && i < cs->n; i++) {
        const struct lab_case *c = &cs->items[i];
        struct lab_inputs in = { .stdin_data = c->stdin_data,
            .stdin_len = strlen(c->stdin_data), .args = c->args,
            .n_args = c->n_args, .sanitize = comp->sanitized,
            .timeout_ms = timeout_ms, .mem_mb = mem_mb };
        lab_proc_reset(&proc);
        if (comp->ok)
            lab_run_binary(&ctx->dirs, comp->binary, comp->sanitized, &in, &proc);
        else
            snprintf(proc.detail, sizeof(proc.detail), "compile failed");
        ok = proc.launch != LAB_LAUNCH_UNCONFINED;
        bool pass = comp->ok && lab_case_verdict(c, &proc, timeout_ms, diff, sizeof(diff));
        if (!comp->ok)
            snprintf(diff, sizeof(diff), "compile failed");
        t->passed += pass;
        t->failed += !pass;
        lab_tally_findings(t, &proc, comp->sanitized);
        ok = ok && lab_case_row(rows, c, &proc, pass, diff, t);
    }
    lab_proc_free(&proc);
    return ok;
}

static bool lab_build_test(struct json_value *d, const struct lab_ctx *ctx,
                           const struct lab_compile *comp, bool requested,
                           const struct lab_tally *t, struct json_value *rows)
{
    return lab_head(d, ctx, "test", comp) &&
           json_push_kv_int(d, "passed", (int64_t)t->passed) &&
           json_push_kv_int(d, "failed", (int64_t)t->failed) &&
           json_push_kv_int(d, "diffs_omitted", (int64_t)t->diffs_omitted) &&
           json_push_kv(d, "cases", rows) &&
           lab_tail(d, comp, requested, comp->ok, t->findings, t->first);
}

enum lab_check lab_cases_check(const struct zcl_command_request *rq,
                               struct lab_ctx *ctx, const char *binary,
                               uint32_t timeout_ms, uint32_t mem_mb,
                               size_t *passed, size_t *failed)
{
    struct lab_cases cs;
    struct lab_compile *comp = zcl_calloc(1, sizeof(*comp), "lab.compile");
    struct lab_tally t = { .diff_left = LAB_DIFF_TOTAL };
    struct json_value rows;
    enum lab_check res = LAB_CHECK_NO_CASES;
    json_init(&rows);
    json_set_array(&rows);
    if (comp && lab_cases_load(rq, &cs)) {
        lab_diagnostic_budget(&t, cs.n);
        comp->ok = true;
        snprintf(comp->binary, sizeof(comp->binary), "%s", binary);
        res = lab_run_cases(ctx, &cs, comp, timeout_ms, mem_mb, &rows, &t)
                  ? LAB_CHECK_RAN : LAB_CHECK_UNCONFINED;
        *passed = t.passed;
        *failed = t.failed;
    }
    if (comp)
        lab_cases_free(&cs);
    json_free(&rows);
    free(comp);
    return res;
}

struct lab_test_req {
    bool sanitize, fresh;
    uint32_t timeout_ms, mem_mb;
};

static void lab_test_execute(struct lab_ctx *ctx, const struct lab_cases *cs,
                             const struct lab_test_req *r,
                             struct zcl_command_reply *reply)
{
    struct lab_compile *comp = zcl_calloc(1, sizeof(*comp), "lab.compile");
    struct lab_tally t = { .diff_left = LAB_DIFF_TOTAL };
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    lab_diagnostic_budget(&t, cs->n);
    if (!comp) {
        lab_fail(reply, "LAB_ALLOC", "run", "the lab could not allocate");
        return;
    }
    lab_compile_source(&ctx->dirs, &ctx->tc, &ctx->src, ctx->root, r->sanitize, comp);
    bool ran = !comp->unconfined &&
               lab_run_cases(ctx, cs, comp, r->timeout_ms, r->mem_mb, &rows, &t);
    if (comp->unconfined || !ran)
        lab_unconfined(reply);
    else if (!lab_build_test(&reply->data, ctx, comp, r->sanitize, &t, &rows) ||
             !lab_publish(ctx, reply))
        lab_fail(reply, "LAB_ALLOC", "serialize", "the receipt could not be built");
    lab_compile_cleanup(&ctx->dirs, ctx->root);
    json_free(&rows);
    free(comp);
}

void zcl_native_handle_lab_test(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply)
{
    struct lab_test_req r = { .sanitize = lab_in_bool(request, "sanitize", true),
                              .fresh = lab_in_bool(request, "fresh", false) };
    struct lab_cases cs;
    struct lab_ctx ctx;
    const char *file = lab_in_str(request, "file");
    bool ok = lab_in_uint(request, "timeout_ms", LAB_TIMEOUT_DEFAULT_MS,
                          LAB_TIMEOUT_MAX_MS, &r.timeout_ms) &&
              lab_in_uint(request, "mem_mb", LAB_MEM_DEFAULT_MB, LAB_MEM_MAX_MB,
                          &r.mem_mb);
    if (!file || !ok) {
        lab_fail(reply, "LAB_BAD_INPUT", "normalize",
                 "usage: lab test <file.c> --cases=<json file or array>");
        return;
    }
    if (!lab_cases_load(request, &cs)) {
        lab_fail(reply, "LAB_BAD_CASES", "normalize",
                 "cases is a JSON array of 1..256 objects with name, and "
                 "optional stdin, args, expect_stdout, expect_exit (0..255)");
    } else if (lab_ctx_open(&ctx, file, reply)) {
        if (!lab_root_test(&ctx, &cs, r.sanitize, r.timeout_ms, r.mem_mb))
            lab_fail(reply, "LAB_ALLOC", "root", "the lab could not allocate");
        else if (r.fresh || !lab_cache_serve(&ctx, reply)) {
            if (!lab_confinement_available())
                lab_unconfined(reply);
            else
                lab_test_execute(&ctx, &cs, &r, reply);
        }
        lab_ctx_close(&ctx);
    }
    lab_cases_free(&cs);
}
