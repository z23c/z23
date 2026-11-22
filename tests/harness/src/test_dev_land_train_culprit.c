/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: a red stacked lint-land drops only the train
 * members its failure names (native_dev_land_train_culprit.c), and falls
 * back to halving the stack when the failure does not name them.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#if !defined(_WIN32)

extern unsigned zcl_dev_land_train_preparations(void);
extern void zcl_dev_land_lint_helper_for_test(const char *);

#define DLX_CU_ROWS 8

/* A lint-land stand-in: it logs the tip it linted, then fails with the gate
 * frame and one attributed FAIL line per `note` the rules raise, as the real
 * lint-land prints a failed gate. */
static bool dlx_cu_helper(const char *rules, char *calls, size_t calls_cap)
{
    static char helper[1200]; /* the seam keeps the pointer */
    char body[3200], frame[256];
    size_t used = (size_t)snprintf(frame, sizeof(frame),
                                   "\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80 FAIL log: lint-fixture ");
    for (int i = 0; i < 28 && used + 4 < sizeof(frame); i++)
        used += (size_t)snprintf(frame + used, sizeof(frame) - used, "\xe2\x94\x80");
    if (snprintf(helper, sizeof(helper), "%s/cu-lint-helper", g_dlx_state) >= (int)sizeof(helper) ||
        snprintf(calls, calls_cap, "%s/cu-lint-calls", g_dlx_state) >= (int)calls_cap)
        return false;
    (void)unlink(calls);
    if (snprintf(body, sizeof(body),
                 "#!/bin/sh\n"
                 "git -C \"$1\" rev-parse HEAD >> '%s' || exit 1\n"
                 "has() { git -C \"$1\" cat-file -e \"HEAD:$2\" 2>/dev/null; }\n"
                 "out=\"\"\n"
                 "note() { out=\"$out[lint-fixture] FAIL: $1\\n\"; }\n"
                 "%s\n"
                 "if [ -n \"$out\" ]; then printf '%%s\\n' '%s'; printf '%%b' \"$out\"; exit 1; fi\n"
                 "exit 0\n", calls, rules, frame) >= (int)sizeof(body))
        return false;
    if (!dlx_write(helper, body) || chmod(helper, 0700) != 0)
        return false;
    zcl_dev_land_lint_helper_for_test(helper);
    return true;
}

/* Lint-land runs so far. */
static unsigned dlx_cu_lints(const char *calls)
{
    char text[2048];
    size_t len = 0;
    unsigned n = 0;
    if (!dlx_slurp(calls, text, sizeof(text) - 1, &len))
        return 0;
    for (size_t i = 0; i < len; i++)
        n += text[i] == '\n';
    return n;
}

/* A (the rig tip, change.txt) is seq 1; seqs 2..8 each add fN.txt. */
static bool dlx_cu_rig(struct dlx_rig *rig, const char *tag)
{
    char path[32], branch[32], tip[64];
    if (!dlx_rig_make(rig, tag))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    setenv("ZCL_LAND_TRAIN_WIDTH", "8", 1);
    if (!dlx_qp_submit(rig, rig->tip, 1))
        return false;
    for (int seq = 2; seq <= DLX_CU_ROWS; seq++) {
        (void)snprintf(path, sizeof(path), "f%d.txt", seq);
        (void)snprintf(branch, sizeof(branch), "cu-f%d", seq);
        if (!dlx_qp_branch(rig, branch, path, "x\n", NULL, NULL, tip) ||
            !dlx_qp_submit(rig, tip, seq))
            return false;
    }
    return true;
}

/* One step: its state, the train members it reports and the lints it cost. */
static bool dlx_cu_beat(const char *calls, const char *state, int members,
                        unsigned lints, const char *what)
{
    struct dlx_call c;
    unsigned before = dlx_cu_lints(calls), preps = zcl_dev_land_train_preparations();
    dlx_begin(&c, "step");
    bool ok = dlx_run(&c) && strcmp(dlx_str(&c, "state"), state) == 0 &&
              dlx_int(&c, "train_members") == (members ? members : -1);
    unsigned spent = dlx_cu_lints(calls) - before;
    printf("[%s: state=%s train_members=%lld lints=%u stacked_preparations=%u code=%s detail=%.80s] ",
           what, dlx_str(&c, "state"), (long long)dlx_int(&c, "train_members"),
           spent, zcl_dev_land_train_preparations() - preps,
           dlx_err_code(&c), dlx_str(&c, "detail"));
    dlx_end(&c);
    return ok && spent == lints;
}

/* Is the queued row `seq` marked train_solo, and does its detail say why? */
static bool dlx_cu_solo(long long seq, bool *solo, bool *named)
{
    static char text[262144];
    char land[1200], path[1400], anchor[48];
    size_t len = 0;
    const char *last = NULL;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/queue.jsonl", land);
    if (!dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    (void)snprintf(anchor, sizeof(anchor), "{\"seq\":%lld,", seq);
    for (char *line = text; line && *line;) {
        char *end = strchr(line, '\n');
        if (end)
            *end = '\0';
        if (strncmp(line, anchor, strlen(anchor)) == 0)
            last = line;
        line = end ? end + 1 : NULL;
    }
    *solo = last && strstr(last, "\"train_solo\":1");
    *named = last && strstr(last, "dropped from the train: lint gate lint-fixture names");
    return last != NULL;
}

/* Exactly the rows listed in `solo` (a "," list of seqs among 2..8) carry the
 * mark, and each says which gate and path dropped it. */
static bool dlx_cu_marks(const char *solo)
{
    for (long long seq = 2; seq <= DLX_CU_ROWS; seq++) {
        char one[8];
        bool marked = false, named = false;
        (void)snprintf(one, sizeof(one), "%lld", seq);
        if (!dlx_cu_solo(seq, &marked, &named))
            continue;
        bool want = strstr(solo, one) != NULL;
        if (marked != want || (want && !named)) {
            printf("[seq=%lld marked=%d named=%d want=%d] ", seq, marked, named, want);
            return false;
        }
    }
    return true;
}

struct dlx_cu_case {
    const char *tag, *rules;
    const char *first;       /* the first step's state */
    int members;             /* train_members it reports */
    unsigned lints;          /* lint-land runs it costs (stacked, then solo) */
    const char *solo;        /* rows marked train_solo afterwards */
    int next_members;        /* the next step's train_members; -1: no next step */
    unsigned next_lints;
};

static bool dlx_cu_case_run(const struct dlx_cu_case *k)
{
    struct dlx_rig rig;
    char calls[1300], tag[64];
    dlx_isolate(k->tag);
    (void)snprintf(tag, sizeof(tag), "%s_rig", k->tag);
    bool ok = dlx_cu_rig(&rig, tag) && dlx_cu_helper(k->rules, calls, sizeof(calls)) &&
              dlx_cu_beat(calls, k->first, k->members, k->lints, k->tag) &&
              dlx_cu_marks(k->solo);
    if (ok && k->next_members >= 0)
        ok = dlx_cu_beat(calls, "started", k->next_members, k->next_lints, "next");
    zcl_dev_land_lint_helper_for_test(NULL);
    dlx_restore();
    return ok;
}

static int test_dev_land_train_culprit_drops_named_rows(void)
{
    static const struct dlx_cu_case cases[] = {
        /* The head's own file is red: the stacked lint says so once. The head
         * proves alone (and fails on its own named cause); the other seven
         * lead the next train. Halving spent 3 stacked lints + 1 solo. */
        { "cu_head", "has \"$1\" change.txt && note \"change.txt is wrong\"",
          "failed", 0, 2, "", 6, 1 },
        /* A middle row only: just it leaves. Halving: 7 red, 3 red, 1 green
         * and a train of two rows. */
        { "cu_middle", "has \"$1\" f4.txt && note \"f4.txt is wrong\"",
          "started", 6, 2, "4", -1, 0 },
        /* Two culprits. */
        { "cu_two", "has \"$1\" f3.txt && note \"f3.txt is wrong\"\n"
                    "has \"$1\" f6.txt && note \"f6.txt is wrong\"",
          "started", 5, 2, "3,6", -1, 0 },
    };
    int failures = 0;
    TEST("land: a red stacked lint drops only the members it names") {
        bool all = true;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
            all = dlx_cu_case_run(&cases[i]) && all;
        ASSERT(all);
        PASS();
    }
_test_next:;
    zcl_dev_land_lint_helper_for_test(NULL);
    dlx_restore();
    return failures;
}

static int test_dev_land_train_culprit_halves_when_unnamed(void)
{
    static const struct dlx_cu_case cases[] = {
        /* A failure that names no path. */
        { "cu_nopath", "has \"$1\" f4.txt && note \"something broke\"",
          "started", 1, 3, "", -1, 0 },
        /* A shared ratchet file: the sum of members breaks it, no one member
         * does, and the reader never counts ratchet files. */
        { "cu_ratchet", "has \"$1\" f4.txt && note \"tools/lint/shell_line_budget.txt grew past its budget\"",
          "started", 1, 3, "", -1, 0 },
        /* A path no stacked member changed. */
        { "cu_untouched", "has \"$1\" f4.txt && note \"nothing_here.c is wrong\"",
          "started", 1, 3, "", -1, 0 },
        /* More than half of the stack is named: halving first, then the last pair
         * (head and seq 2) names seq 2 with confidence. */
        { "cu_most", "for n in 2 3 4 5 6; do has \"$1\" f$n.txt && note \"f$n.txt is wrong\"; done",
          "started", 0, 4, "2", -1, 0 },
    };
    int failures = 0;
    TEST("land: a red stacked lint that does not name its rows halves the stack as before") {
        bool all = true;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
            all = dlx_cu_case_run(&cases[i]) && all;
        ASSERT(all);
        PASS();
    }
_test_next:;
    zcl_dev_land_lint_helper_for_test(NULL);
    dlx_restore();
    return failures;
}

int test_dev_land_train_culprit_cases(void)
{
    int failures = 0;
    failures += test_dev_land_train_culprit_drops_named_rows();
    failures += test_dev_land_train_culprit_halves_when_unnamed();
    return failures;
}

#endif /* !defined(_WIN32) */
