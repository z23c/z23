/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_rule_mine — mine a candidate rule out of a task the gate refused and
 * later accepted. See engine/modules/engine/include/engine/engine_rule_mine.h
 * for why the shape is what it is; the short version is that a rule bound to
 * two receipts and one diff can be checked, and a rule somebody wrote down
 * cannot.
 */

#include "engine/engine_rule_mine.h"

#include <stdio.h>
#include <string.h>

static void mine_copy(char *dst, size_t cap, const char *src)
{
    if (cap == 0) return;
    size_t n = src ? strlen(src) : 0;
    if (n >= cap) n = cap - 1;
    if (n) memcpy(dst, src, n);
    dst[n] = '\0';
}

uint32_t zcl_rule_mine_pairs(const struct zcl_rule_receipt_log *log,
                             struct zcl_rule_mine_pair *out, uint32_t cap)
{
    if (!log || !out || cap == 0) return 0;
    uint32_t n = 0;

    for (uint32_t i = 0; i < log->count && n < cap; i++) {
        const struct zcl_rule_receipt *f = &log->r[i];
        if (f->gate_pass) continue;
        if (!f->task_sha3[0]) continue;

        /* The FIRST failure of this task only. A task that failed three times
         * before passing is one lesson, not three, and emitting it three times
         * would weight the candidate by how stubborn the task was. Only an
         * earlier FAILURE counts: an earlier PASS of the same task is not a
         * lesson this failure would duplicate — the triple pass, fail, pass
         * still yields its one pair. */
        bool earlier_fail = false;
        for (uint32_t k = 0; k < i; k++)
            if (!log->r[k].gate_pass &&
                strcmp(log->r[k].task_sha3, f->task_sha3) == 0)
                { earlier_fail = true; break; }
        if (earlier_fail) continue;

        const struct zcl_rule_receipt *p = NULL;
        for (uint32_t j = i + 1; j < log->count; j++) {
            if (!log->r[j].gate_pass) continue;
            if (strcmp(log->r[j].task_sha3, f->task_sha3) != 0) continue;
            p = &log->r[j];
            break;
        }
        if (!p) continue;

        struct zcl_rule_mine_pair *o = &out[n++];
        memset(o, 0, sizeof *o);
        mine_copy(o->task_sha3, sizeof o->task_sha3, f->task_sha3);
        mine_copy(o->fail_unit, sizeof o->fail_unit, f->unit_id);
        mine_copy(o->pass_unit, sizeof o->pass_unit, p->unit_id);
        mine_copy(o->fail_head, sizeof o->fail_head, f->worktree_head);
        mine_copy(o->pass_head, sizeof o->pass_head, p->worktree_head);
        mine_copy(o->group, sizeof o->group, f->group[0] ? f->group : "(none)");
        mine_copy(o->kind, sizeof o->kind, f->kind);
        /* A lint refusal and a test refusal send a reader to different output.
         * Do not merge them. */
        mine_copy(o->gate, sizeof o->gate, f->lint_rc != 0 ? "lint" : "t-fast");
        o->fail_seq = f->seq;
        o->pass_seq = p->seq;
    }
    return n;
}

size_t zcl_rule_mine_diff_command(const struct zcl_rule_mine_pair *p,
                                  char *buf, size_t cap)
{
    if (!p || !buf || cap == 0) return 0;
    int n = snprintf(buf, cap, "git diff %s %s", p->fail_head, p->pass_head);
    if (n < 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}

bool zcl_rule_mine_candidate(const struct zcl_rule_mine_pair *p,
                             const char *diff, size_t len,
                             struct zcl_rule_candidate *out)
{
    if (!p || !out) return false;
    memset(out, 0, sizeof *out);

    uint32_t lines = 0;
    size_t i = 0;
    while (i < (diff ? len : 0) && lines < ZCL_RULE_MINE_DIFF_LINES) {
        size_t eol = i;
        while (eol < len && diff[eol] != '\n') eol++;
        size_t llen = eol - i;
        const char *line = diff + i;
        lines++;
        i = (eol < len) ? eol + 1 : eol;

        /* The `+++ b/<path>` side names the file AS IT IS AFTER the fix, which
         * is the file a later executor should open. The `---` side would name
         * a path that a rename has already made wrong. */
        static const char kPlus[] = "+++ b/";
        if (llen <= sizeof kPlus - 1) continue;
        if (memcmp(line, kPlus, sizeof kPlus - 1) != 0) continue;
        const char *path = line + sizeof kPlus - 1;
        size_t plen = llen - (sizeof kPlus - 1);
        while (plen && (path[plen - 1] == '\r' || path[plen - 1] == ' ')) plen--;
        if (!plen) continue;
        if (out->file_count >= ZCL_RULE_MINE_FILE_MAX) continue;
        char tmp[ZCL_RULE_MINE_PATH_MAX];
        size_t c = plen < sizeof tmp - 1 ? plen : sizeof tmp - 1;
        memcpy(tmp, path, c);
        tmp[c] = '\0';
        bool dup = false;
        for (uint32_t k = 0; k < out->file_count; k++)
            if (strcmp(out->files[k], tmp) == 0) { dup = true; break; }
        if (dup) continue;
        mine_copy(out->files[out->file_count], ZCL_RULE_MINE_PATH_MAX, tmp);
        out->file_count++;
    }

    /* A fix that names no file is not evidence about anything a later executor
     * could open. Refuse rather than emit a rule that says "check ". */
    if (out->file_count == 0) return false;

    mine_copy(out->evidence_fail, sizeof out->evidence_fail, p->fail_unit);
    mine_copy(out->evidence_pass, sizeof out->evidence_pass, p->pass_unit);
    mine_copy(out->gate, sizeof out->gate, p->gate);
    mine_copy(out->group, sizeof out->group, p->group);

    /* The id is a slug of the gate and the group, so two failures of the same
     * gate on the same group land on ONE candidate rather than accumulating a
     * candidate per run. */
    char slug[ZCL_RULE_ID_MAX - 8];
    size_t w = 0;
    const char *src[2] = { p->gate, p->group };
    for (int s = 0; s < 2 && w + 1 < sizeof slug; s++) {
        if (s) { if (w + 1 < sizeof slug) slug[w++] = '-'; }
        for (const char *q = src[s]; *q && w + 1 < sizeof slug; q++) {
            char ch = *q;
            bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9');
            if (ch >= 'A' && ch <= 'Z') { ch = (char)(ch - 'A' + 'a'); ok = true; }
            slug[w++] = ok ? ch : '-';
        }
    }
    slug[w] = '\0';
    (void)snprintf(out->id, sizeof out->id, "mined:%s", slug);

    size_t at = 0;
    int n = snprintf(out->text, sizeof out->text,
                     "when %s fails on %s, check", p->gate, p->group);
    if (n < 0 || (size_t)n >= sizeof out->text) return false;
    at = (size_t)n;
    for (uint32_t k = 0; k < out->file_count; k++) {
        int m = snprintf(out->text + at, sizeof out->text - at, "%s %s",
                         k ? "," : "", out->files[k]);
        if (m < 0 || (size_t)m >= sizeof out->text - at) break;
        at += (size_t)m;
    }
    return true;
}

size_t zcl_rule_mine_render(const struct zcl_rule_candidate *c,
                            char *buf, size_t cap)
{
    if (!c || !buf || cap == 0) return 0;
    /* Born SHADOW with the project's default trial count, and carrying the
     * two receipts it came from. A candidate whose evidence is not written
     * down is a sentence nobody can check. */
    int n = snprintf(buf, cap,
                     "/* mined from %s (gate refused) -> %s (gate passed) */\n"
                     "ZCL_RULE(\"%s\", ZCL_RULE_SRC_MINED, ZCL_RULE_SHADOW, "
                     "500, 30, \"%s\")\n",
                     c->evidence_fail, c->evidence_pass, c->id, c->text);
    if (n < 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}

bool zcl_rule_mine_append(const char *path,
                          const struct zcl_rule_candidate *c)
{
    if (!path || !c) return false;

    char row[ZCL_RULE_TEXT_MAX + 512];
    size_t rl = zcl_rule_mine_render(c, row, sizeof row);
    if (rl == 0) return false;

    /* Already there? A second row for one id would give one candidate two
     * scores and let a rewriter edit whichever it saw first. */
    char needle[ZCL_RULE_ID_MAX + 16];
    int nn = snprintf(needle, sizeof needle, "\"%s\"", c->id);
    if (nn < 0 || (size_t)nn >= sizeof needle) return false;

    bool fresh = true;
    FILE *rf = fopen(path, "rb");
    if (rf) {
        fresh = false;
        char line[ZCL_RULE_LINE_MAX];
        while (fgets(line, (int)sizeof line, rf)) {
            if (strstr(line, needle)) { (void)fclose(rf); return false; }
        }
        (void)fclose(rf);
    }

    FILE *f = fopen(path, "ab");
    if (!f) return false;
    if (fresh) {
        static const char kHeader[] =
            "/* Copyright 2026 Rhett Creighton - Apache License 2.0\n"
            " *\n"
            " * candidates — SHADOW rows mined from gate outcomes, appended by\n"
            " * engine/modules/engine/src/engine_rule_mine.c and turned on by\n"
            " * nobody. Each row names the two receipts it came from: one unit\n"
            " * the gate refused, and the later unit that passed the same task.\n"
            " *\n"
            " * A row here is a PROPOSAL. It is not in the closed vocabulary,\n"
            " * check_rule_vocabulary.sh does not know about it, and no\n"
            " * executor is shown it. Moving one into\n"
            " * engine/composition/rule_vocab.def is a human edit, on purpose --- and\n"
            " * ZCL_RULE_SRC_MINED is deliberately not an enum member, so the\n"
            " * move does not compile until somebody writes the heading or\n"
            " * persona the id will resolve against.\n"
            " */\n\n";
        if (fwrite(kHeader, 1, sizeof kHeader - 1, f) != sizeof kHeader - 1) {
            (void)fclose(f);
            return false;
        }
    }
    size_t w = fwrite(row, 1, rl, f);
    if (fclose(f) != 0) return false;
    return w == rl;
}
