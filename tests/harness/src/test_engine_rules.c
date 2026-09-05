/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_engine_rules — the gate on the auto-updating heuristic set.
 *
 * The thing under test decides, on its own, which rules future AI executors
 * are shown. That is a loop that edits its own guidance, so the assertions
 * here are about the SAFETY of the loop and not only about arithmetic:
 *
 *  1. A RULE THAT ONLY EVER LOSES IS TURNED OFF. Shown on 20 runs, gate
 *     passed on none, and it retires — with the unit_ids that killed it
 *     written into the row. A retirement nobody can argue with is one nobody
 *     can undo on evidence. And NOT BEFORE ITS TIME: a rule shown 20 times
 *     with the same zero passes but a min_trials of 21 stays INSUFFICIENT and
 *     is left in the file, because a floor is only allowed to decide once the
 *     declared number of runs have actually happened.
 *
 *  2. A RULE NOBODY MEASURED IS NOT A RULE THAT FAILED. A shadow rule that
 *     appeared in no receipt stays shadow, verdict untried. Scoring it 0 and
 *     acting on that would retire every rule the harness had not got to yet.
 *
 *  3. PROMOTION PRODUCES A PATCH AND NOTHING ELSE. A shadow rule that beats
 *     the obeyed baseline is still SHADOW in the file afterwards, and the
 *     only thing that changed anywhere is one file under promotions/. Off is
 *     safe, on is not: this is the assertion that keeps the loop from writing
 *     new instructions for every future executor with nobody having read them.
 *     And a scoring that fires NO retirement rewrites the vocabulary to
 *     identical bytes, so an idle pass of the loop can never cost a comma.
 *
 *  4. THE SAME LOG SCORES THE SAME BYTES. Twice over the identical input, the
 *     rendered report is byte-identical. A scoring that drifted could not be
 *     reproduced on another machine, and a number nobody else can reproduce
 *     is not evidence.
 *
 *  5. A BROKEN CHAIN IS REFUSED WHOLE. One altered prev_sha3 and the entire
 *     log is refused, not scored up to the break. A score taken from the
 *     honest prefix of a tampered ledger reads as evidence and is not one.
 *
 *  6. THE MINER FINDS THE ONE FAIL->PASS PAIR AND NAMES THE FILE THAT FIXED
 *     IT. Exactly one candidate, with exactly the text the template says.
 *
 *  7. THE DEF IS REWRITTEN ATOMICALLY, OR NOT AT ALL. The new bytes go
 *     whole into a temp file and one rename publishes them, so a write
 *     that dies before the rename — an ENOSPC, a kill, a full disk —
 *     leaves the original vocabulary standing byte for byte. A rewrite
 *     with the file's own bytes is a no-op in content: an idle pass of
 *     the loop can never cost a comma. And a rewrite decided from bytes
 *     that are no longer on disk is refused WHOLE — the editor that
 *     changed the file keeps its edit, typed as a stale read so nobody
 *     goes hunting a broken temp file for a failure that was a refusal.
 *
 * The 50-receipt chainlog is generated here, deterministically, so this gate
 * needs no sibling lane to have run and no engine to have been dispatched.
 * Everything lives under this test's own temp directory; the developer's real
 * receipts log is never opened.
 */

#include "test/test_core.h"

#include "engine/engine_rule_mine.h"
#include "engine/engine_rule_score.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ER_CHECK(name, expr)                                             \
    do {                                                                 \
        const bool er_ok_ = (expr);                                      \
        if (!er_ok_) failures++;                                         \
        printf("engine_rules: %s %s\n", er_ok_ ? "OK  " : "FAIL", (name)); \
    } while (0)

/* ── the fixture vocabulary ──────────────────────────────────────────────
 *
 * Written as text, not built as a struct, because the parser and the
 * rewriter are both under test and a struct would skip them both. */
static const char k_fixture_vocab[] =
"/* fixture vocabulary */\n"
"\n"
"ZCL_RULE(\"grok:good\", ZCL_RULE_SRC_GROK, ZCL_RULE_OBEYED, 500, 30, \"A rule the gate keeps agreeing with, run after run.\")\n"
"ZCL_RULE(\"grok:bad\", ZCL_RULE_SRC_GROK, ZCL_RULE_OBEYED, 500, 20, \"A rule that has been shown twenty times and has never once been followed by a green gate.\")\n"
"ZCL_RULE(\"grok:early\", ZCL_RULE_SRC_GROK, ZCL_RULE_OBEYED, 500, 21, \"The same twenty straight losses, but its floor is not allowed to decide until run 21.\")\n"
"ZCL_RULE(\"grok:cand\", ZCL_RULE_SRC_GROK, ZCL_RULE_SHADOW, 500, 20, \"A shadow rule being measured before anybody is told it.\")\n"
"ZCL_RULE(\"grok:never\", ZCL_RULE_SRC_GROK, ZCL_RULE_SHADOW, 500, 20, \"A shadow rule that no receipt in this log has ever shown.\")\n"
"\n"
"/* end */\n";

/* A 64-hex string that depends only on its two inputs. */
static void fx_hex(char out[65], char tag, uint32_t n)
{
    for (int i = 0; i < 64; i++) out[i] = '0';
    out[64] = '\0';
    out[0] = tag;
    (void)snprintf(out + 56, 9, "%08x", n);
}

/* The fixture's task id. Receipt 20 deliberately repeats receipt 5's task:
 * that repeat is the fail->pass pair the miner has to find, and the only one
 * in the log. */
static void fx_task(char out[65], uint32_t i)
{
    fx_hex(out, 't', i == 20u ? 5u : i);
}

/* One receipt line, without the trailing newline. Returns its length. */
static size_t fx_line(char *buf, size_t cap, uint32_t i, const char *prev)
{
    bool second_half = (i >= 30u);
    bool pass = second_half ? false : (i != 5u && i != 6u);
    const char *shown = second_half ? "\"grok:bad\",\"grok:early\""
                                    : "\"grok:good\",\"grok:cand\"";
    char task[65], head[65], tmpl[65];
    fx_task(task, i);
    fx_hex(head, 'h', i);
    fx_hex(tmpl, 'm', second_half ? 1u : 0u);

    int n = snprintf(buf, cap,
        "{\"schema\":\"zcl.engine_unit_receipt.v1\",\"prev_sha3\":\"%s\","
        "\"unit_id\":\"u%03u\",\"ts\":%u,\"engine\":\"fixture\","
        "\"model\":\"fixture-1\",\"kind\":\"%s\",\"template_sha3\":\"%s\","
        "\"rules_shown\":[%s],\"task_sha3\":\"%s\",\"group\":\"engine\","
        "\"prompt_tokens\":%u,\"completion_tokens\":%u,\"wall_ms\":%u,"
        "\"http_status\":200,\"outcome\":{\"applied\":1,\"groups_ran\":1,"
        "\"groups_failed\":%u,\"gate_pass\":%u,\"retries\":%u,"
        "\"lines_changed\":%u,\"lint_rc\":0},\"worktree_head\":\"%s\"}",
        prev, i, 1000u + i, second_half ? "repair" : "feature", tmpl, shown,
        task, 100u + i, 50u + i, 1000u + i * 7u, pass ? 0u : 1u,
        pass ? 1u : 0u, i % 3u, 10u + i, head);
    if (n < 0 || (size_t)n >= cap) return 0;
    return (size_t)n;
}

/* The whole 50-record chainlog. `break_at` is a 1-based record whose
 * prev_sha3 gets one character changed, or 0 for an honest log. */
static char *fx_chainlog(uint32_t break_at, size_t *out_len)
{
    size_t cap = 64u * 1024u;
    char *buf = malloc(cap);  /* raw-malloc-ok: test-local fixture buffer */
    if (!buf) return NULL;
    size_t at = 0;
    char prev[65];
    memcpy(prev, "0000000000000000000000000000000000000000000000000000000000"
                 "000000", 65);

    for (uint32_t i = 0; i < 50u; i++) {
        char line[4096];
        size_t ll = fx_line(line, sizeof line, i, prev);
        if (ll == 0) { free(buf); return NULL; }
        /* The link is computed over the HONEST line, then the stored copy is
         * corrupted, so the break is a real mismatch and not a second chain. */
        zcl_rule_chain_link(line, ll, prev);
        if (break_at && (i + 1u) == break_at) {
            char *p = strstr(line, "\"prev_sha3\":\"");
            if (p) p[13] = (p[13] == 'f') ? 'e' : 'f';
        }
        if (at + ll + 1 >= cap) { free(buf); return NULL; }
        memcpy(buf + at, line, ll); at += ll;
        buf[at++] = '\n';
    }
    buf[at] = '\0';
    *out_len = at;
    return buf;
}

static bool fx_write(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t n = fwrite(data, 1, len, f);
    return fclose(f) == 0 && n == len;
}

static char *fx_read(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 256u * 1024u;
    char *buf = malloc(cap);  /* raw-malloc-ok: test-local fixture buffer */
    if (!buf) { (void)fclose(f); return NULL; }
    size_t n = fread(buf, 1, cap - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    if (out_len) *out_len = n;
    return buf;
}

/* Occurrences of a substring, because a second audit comment hiding behind
 * the first is exactly the drift this gate exists to catch. */
static uint32_t fx_count(const char *hay, const char *needle)
{
    uint32_t n = 0;
    const char *p = hay;
    while ((p = strstr(p, needle)) != NULL) { n++; p++; }
    return n;
}

/* ── 1. the fixture is the fixture the assertions assume ──────────────── */

static int case_fixture(void)
{
    int failures = 0;
    size_t len = 0;
    char *log = fx_chainlog(0, &len);
    ER_CHECK("the 50-receipt fixture generates", log != NULL && len > 0);
    if (!log) return failures;

    struct zcl_rule_receipt_log *parsed = calloc(1, sizeof *parsed);
    uint32_t bad = 0;
    enum zcl_rule_chain_status st =
        parsed ? zcl_rule_receipts_parse(log, len, parsed, &bad)
               : ZCL_RULE_CHAIN_MALFORMED;
    ER_CHECK("an honest chain verifies", st == ZCL_RULE_CHAIN_OK);
    ER_CHECK("all 50 records are read", parsed && parsed->count == 50u);

    /* The same generator twice is the same bytes. If it were not, every
     * determinism assertion below would be testing the generator. */
    size_t len2 = 0;
    char *log2 = fx_chainlog(0, &len2);
    ER_CHECK("the generator is deterministic",
             log2 && len2 == len && memcmp(log, log2, len) == 0);
    free(log2);
    free(parsed);
    free(log);
    return failures;
}

/* ── 2. a broken chain is refused whole ──────────────────────────────── */

static int case_broken_chain(void)
{
    int failures = 0;
    size_t len = 0;
    char *log = fx_chainlog(17u, &len);
    if (!log) { ER_CHECK("broken fixture generates", false); return failures; }

    struct zcl_rule_receipt_log *parsed = calloc(1, sizeof *parsed);
    uint32_t bad = 0;
    enum zcl_rule_chain_status st =
        parsed ? zcl_rule_receipts_parse(log, len, parsed, &bad)
               : ZCL_RULE_CHAIN_MALFORMED;
    ER_CHECK("a chain break is refused", st == ZCL_RULE_CHAIN_BROKEN);
    ER_CHECK("and it names the line that refused", bad == 17u);
    /* NOT scored up to the break: the count must not be a usable prefix. */
    ER_CHECK("nothing usable is handed back from a broken log",
             parsed && parsed->count == 16u);
    free(parsed);
    free(log);
    return failures;
}

/* ── 3. the Wilson bound behaves like a bound ────────────────────────── */

static int case_wilson(void)
{
    int failures = 0;
    ER_CHECK("no trials scores 0, because nobody measured",
             zcl_rule_wilson_lower_permille(0, 0) == 0);
    ER_CHECK("1 of 1 does not score 1000 — one run knows almost nothing",
             zcl_rule_wilson_lower_permille(1, 1) < 900);
    ER_CHECK("29 of 30 sits far above 1 of 1, not near it",
             zcl_rule_wilson_lower_permille(29, 30) >
             zcl_rule_wilson_lower_permille(1, 1) + 300u);
    ER_CHECK("20 of 20 scores well above 1 of 1",
             zcl_rule_wilson_lower_permille(20, 20) >
             zcl_rule_wilson_lower_permille(1, 1));
    ER_CHECK("0 of 20 scores 0", zcl_rule_wilson_lower_permille(0, 20) == 0);
    ER_CHECK("the bound never exceeds the raw rate",
             zcl_rule_wilson_lower_permille(28, 30) <= (28 * 1000) / 30);
    /* Same inputs, same answer, every time — no float, no state. */
    bool stable = true;
    for (uint32_t n = 1; n <= 200 && stable; n++)
        for (uint32_t k = 0; k <= n; k++)
            if (zcl_rule_wilson_lower_permille(k, n) !=
                zcl_rule_wilson_lower_permille(k, n)) stable = false;
    ER_CHECK("and it is a pure function of its two arguments", stable);
    return failures;
}

/* ── 4. scoring, retiring, and the promotion asymmetry ───────────────── */

/* A promotion hunk reads -, then +, then trailing context. A + emitted
 * after the trailing context is a row `git apply` would MOVE — delete in
 * place, insert below — not the one-token rewrite the patch promises. */
static bool patch_rewrites_in_place(const char *patch, const char *id)
{
    char minus[96], plus[96];
    int mn = snprintf(minus, sizeof minus, "-ZCL_RULE(\"%s", id);
    int pn = snprintf(plus, sizeof plus, "+ZCL_RULE(\"%s", id);
    if (mn <= 0 || pn <= 0) return false;
    const char *m = strstr(patch, minus);
    if (!m) return false;
    const char *m_end = strchr(m, '\n');
    if (!m_end) return false;
    /* the very next hunk line is the + side of the same row */
    if (strncmp(m_end + 1, plus, (size_t)pn) != 0) return false;
    /* and trailing context still follows it, proving the + came first */
    const char *p_end = strchr(m_end + 1, '\n');
    return p_end && p_end[1] == ' ';
}

static int case_decisions(void)
{
    int failures = 0;
    char tmpl[] = "/tmp/zcl_engine_rulesXXXXXX";
    char *dir = mkdtemp(tmpl);
    ER_CHECK("a temp state directory", dir != NULL);
    if (!dir) return failures;

    char vpath[512], lpath[512], ppath[512];
    (void)snprintf(vpath, sizeof vpath, "%s/rule_vocab.def", dir);
    (void)snprintf(lpath, sizeof lpath, "%s/%s", dir, ZCL_RULE_CHAINLOG_NAME);
    (void)snprintf(ppath, sizeof ppath, "%s/%s/grok_cand.patch", dir,
                   ZCL_RULE_PROMOTIONS_DIR);

    size_t len = 0;
    char *log = fx_chainlog(0, &len);
    bool wrote = log &&
        fx_write(vpath, k_fixture_vocab, sizeof k_fixture_vocab - 1) &&
        fx_write(lpath, log, len);
    ER_CHECK("the fixture vocabulary and log are on disk", wrote);
    if (!wrote) { free(log); return failures; }

    /* ---- a read-only run decides nothing on disk ---- */
    struct zcl_rule_run dry;
    bool ran = zcl_rule_score_run(vpath, lpath, dir, false, &dry);
    ER_CHECK("a read-only scoring runs", ran && dry.vocab_ok && dry.log_ok);
    ER_CHECK("it wrote no retirement", dry.retired_written == 0);
    ER_CHECK("it wrote no patch", dry.patches_written == 0);

    const struct zcl_rule_score *good = NULL, *bad = NULL, *early = NULL,
                                *cand = NULL, *never = NULL;
    for (uint32_t i = 0; i < dry.scoring.rule_count; i++) {
        const struct zcl_rule_score *s = &dry.scoring.rule[i];
        if (strcmp(s->id, "grok:good") == 0) good = s;
        else if (strcmp(s->id, "grok:bad") == 0) bad = s;
        else if (strcmp(s->id, "grok:early") == 0) early = s;
        else if (strcmp(s->id, "grok:cand") == 0) cand = s;
        else if (strcmp(s->id, "grok:never") == 0) never = s;
    }
    ER_CHECK("every fixture rule is scored",
             good && bad && early && cand && never &&
             dry.scoring.rule_count == 5u);
    if (!good || !bad || !early || !cand || !never) { free(log); return failures; }

    ER_CHECK("the winning rule has 30 trials and 28 passes",
             good->trials == 30u && good->passes == 28u);
    ER_CHECK("and it holds", good->verdict == ZCL_RULE_VERDICT_HOLD);

    ER_CHECK("the losing rule has 20 trials and 0 passes",
             bad->trials == 20u && bad->passes == 0u);
    ER_CHECK("shown on 20 failures and no passes, it is retired",
             bad->verdict == ZCL_RULE_VERDICT_RETIRE);
    ER_CHECK("and the receipts that killed it are named",
             bad->killer_count > 0 && bad->killer_total == 20u &&
             strcmp(bad->killer[0], "u030") == 0);

    /* THE MIN-TRIALS GATE. Same twenty straight losses, one run short of its
     * declared minimum: the floor is NOT allowed to decide yet, because
     * "under the floor" and "measured enough to know" are different facts. */
    ER_CHECK("the too-early rule has the same 20 losses",
             early->trials == 20u && early->passes == 0u);
    ER_CHECK("and a floor short of its min_trials decides nothing",
             early->verdict == ZCL_RULE_VERDICT_INSUFFICIENT);
    ER_CHECK("so exactly one retirement is pending, not two",
             dry.scoring.retire_count == 1u);

    ER_CHECK("a rule no receipt ever showed has no trials",
             never->trials == 0u);
    ER_CHECK("and it is untried, not failing",
             never->verdict == ZCL_RULE_VERDICT_UNTRIED);
    ER_CHECK("and it stays shadow", never->state == ZCL_RULE_SHADOW);

    ER_CHECK("the measured shadow rule beats the obeyed baseline",
             cand->verdict == ZCL_RULE_VERDICT_PROMOTABLE);

    /* ---- the same log twice is the same bytes ---- */
    struct zcl_rule_run again;
    (void)zcl_rule_score_run(vpath, lpath, dir, false, &again);
    char r1[16384], r2[16384];
    size_t n1 = zcl_rule_report_render(&dry.scoring, r1, sizeof r1);
    size_t n2 = zcl_rule_report_render(&again.scoring, r2, sizeof r2);
    ER_CHECK("scoring the same log twice renders identical bytes",
             n1 > 0 && n1 == n2 && memcmp(r1, r2, n1) == 0);

    /* ---- now let it apply ---- */
    struct zcl_rule_run wet;
    (void)zcl_rule_score_run(vpath, lpath, dir, true, &wet);
    ER_CHECK("one rule was retired on disk", wet.retired_written == 1u);
    ER_CHECK("one promotion was proposed", wet.patches_written == 1u);
    {
        /* The published rewrite is one rename: nothing named .tmp survives
         * a successful apply. */
        char tpath[540];
        (void)snprintf(tpath, sizeof tpath, "%s.tmp", vpath);
        struct stat sb;
        ER_CHECK("a successful apply leaves no temp file behind",
                 stat(tpath, &sb) != 0);
    }

    size_t vlen = 0;
    char *after = fx_read(vpath, &vlen);
    ER_CHECK("the vocabulary is readable afterwards", after != NULL);
    if (after) {
        ER_CHECK("the losing rule is now RETIRED in the file",
                 strstr(after, "\"grok:bad\", ZCL_RULE_SRC_GROK, "
                               "ZCL_RULE_RETIRED") != NULL);
        ER_CHECK("with an audit comment naming its numbers",
                 strstr(after, "auto-retired: trials=20 passes=0") != NULL);
        ER_CHECK("and the unit_ids that killed it",
                 strstr(after, "u030") != NULL);
        /* The too-early rule has the same losses and is untouched: no state
         * change, no audit comment. Its floor had not earned a decision. */
        ER_CHECK("the too-early rule is still OBEYED in the file",
                 strstr(after, "\"grok:early\", ZCL_RULE_SRC_GROK, "
                               "ZCL_RULE_OBEYED") != NULL);
        ER_CHECK("and exactly one audit comment was written, not two",
                 fx_count(after, "auto-retired") == 1u);
        /* THE ASYMMETRY. Off happened. On did not. */
        ER_CHECK("the promotable rule is STILL shadow in the file",
                 strstr(after, "\"grok:cand\", ZCL_RULE_SRC_GROK, "
                               "ZCL_RULE_SHADOW") != NULL);
        ER_CHECK("the winning rule was left alone",
                 strstr(after, "\"grok:good\", ZCL_RULE_SRC_GROK, "
                               "ZCL_RULE_OBEYED") != NULL);
        ER_CHECK("and so was the rule nobody measured",
                 strstr(after, "\"grok:never\", ZCL_RULE_SRC_GROK, "
                               "ZCL_RULE_SHADOW") != NULL);
        free(after);
    }

    size_t plen = 0;
    char *patch = fx_read(ppath, &plen);
    ER_CHECK("nothing is promoted without a patch file on disk",
             patch != NULL && plen > 0);
    if (patch) {
        ER_CHECK("the patch turns exactly that row on",
                 strstr(patch, "+ZCL_RULE(\"grok:cand\"") != NULL &&
                 strstr(patch, "-ZCL_RULE(\"grok:cand\"") != NULL &&
                 strstr(patch, "ZCL_RULE_OBEYED") != NULL);
        /* `grok:cand` sits at line 6 of 9 with ctx=3, so this hunk HAS
         * trailing context: the assertion is not vacuous for this row. */
        ER_CHECK("the hunk is a rewrite in place: + immediately after -",
                 patch_rewrites_in_place(patch, "grok:cand"));
        ER_CHECK("and it says why it is not applied for you",
                 strstr(patch, "NOT applied automatically") != NULL);
        free(patch);
    }

    /* Applying twice must not retire the same row again or write a second
     * audit comment: the row is RETIRED now and carries no live verdict. */
    struct zcl_rule_run third;
    (void)zcl_rule_score_run(vpath, lpath, dir, true, &third);
    ER_CHECK("a second apply retires nothing further",
             third.retired_written == 0u);

    /* A scoring that fires NO retirement must rewrite the file to identical
     * bytes — promotions included, because a promotion never flows through
     * the rewriter at all. An idle pass of the loop cannot cost a comma. */
    size_t flen = 0;
    char *final_def = fx_read(vpath, &flen);
    ER_CHECK("the settled vocabulary is readable", final_def != NULL);
    if (final_def) {
        char *rt = malloc(flen + 1024u);
        if (rt) {
            size_t rn = zcl_rule_vocab_apply_retirements(final_def, flen,
                                                         &third.scoring, rt,
                                                         flen + 1024u);
            ER_CHECK("a no-decision scoring rewrites the def byte-identical",
                     rn == flen && memcmp(final_def, rt, rn) == 0);
            free(rt);
        }
        free(final_def);
    }

    free(log);
    return failures;
}

/* ── 5. the miner ────────────────────────────────────────────────────── */

static const char k_fixture_diff[] =
"diff --git a/engine/modules/engine/src/engine_verdict.c "
"b/engine/modules/engine/src/engine_verdict.c\n"
"index 1111111..2222222 100644\n"
"--- a/engine/modules/engine/src/engine_verdict.c\n"
"+++ b/engine/modules/engine/src/engine_verdict.c\n"
"@@ -10,6 +10,7 @@\n"
"     if (groups_ran == 0)\n"
"+        return ENGINE_VERDICT_UNOBSERVED;\n";

static int case_miner(void)
{
    int failures = 0;
    size_t len = 0;
    char *log = fx_chainlog(0, &len);
    struct zcl_rule_receipt_log *parsed = calloc(1, sizeof *parsed);
    if (!log || !parsed) {
        ER_CHECK("miner fixture", false);
        free(log); free(parsed);
        return failures;
    }
    (void)zcl_rule_receipts_parse(log, len, parsed, NULL);

    struct zcl_rule_mine_pair pairs[ZCL_RULE_MINE_PAIR_MAX];
    uint32_t n = zcl_rule_mine_pairs(parsed, pairs, ZCL_RULE_MINE_PAIR_MAX);
    ER_CHECK("exactly one task failed and later passed", n == 1u);
    if (n == 1u) {
        ER_CHECK("it is the pair the fixture planted",
                 strcmp(pairs[0].fail_unit, "u005") == 0 &&
                 strcmp(pairs[0].pass_unit, "u020") == 0);
        ER_CHECK("a zero lint_rc is reported as a test refusal, not a lint one",
                 strcmp(pairs[0].gate, "t-fast") == 0);

        char cmd[256];
        size_t cl = zcl_rule_mine_diff_command(&pairs[0], cmd, sizeof cmd);
        ER_CHECK("the diff command names the two heads",
                 cl > 0 && strncmp(cmd, "git diff h", 10) == 0 &&
                 strstr(cmd, pairs[0].pass_head) != NULL);

        struct zcl_rule_candidate c;
        bool built = zcl_rule_mine_candidate(&pairs[0], k_fixture_diff,
                                             sizeof k_fixture_diff - 1, &c);
        ER_CHECK("a candidate is built from the fixing diff", built);
        if (built) {
            ER_CHECK("with exactly the expected id",
                     strcmp(c.id, "mined:t-fast-engine") == 0);
            ER_CHECK("and exactly the expected text",
                     strcmp(c.text,
                            "when t-fast fails on engine, check "
                            "engine/modules/engine/src/engine_verdict.c") == 0);
            ER_CHECK("naming the one file the fix touched",
                     c.file_count == 1u &&
                     strcmp(c.files[0],
                            "engine/modules/engine/src/engine_verdict.c") == 0);
            ER_CHECK("and carrying both receipts as evidence",
                     strcmp(c.evidence_fail, "u005") == 0 &&
                     strcmp(c.evidence_pass, "u020") == 0);

            char tmpl[] = "/tmp/zcl_engine_mineXXXXXX";
            char *dir = mkdtemp(tmpl);
            if (dir) {
                char cpath[512];
                (void)snprintf(cpath, sizeof cpath, "%s/%s", dir,
                               ZCL_RULE_CANDIDATES_NAME);
                bool a1 = zcl_rule_mine_append(cpath, &c);
                bool a2 = zcl_rule_mine_append(cpath, &c);
                ER_CHECK("the candidate is appended once", a1);
                ER_CHECK("and never twice for one id", !a2);
                char *body = fx_read(cpath, NULL);
                ER_CHECK("the row is born SHADOW and turned on by nobody",
                         body && strstr(body, "ZCL_RULE_SHADOW") != NULL &&
                         strstr(body, "ZCL_RULE_OBEYED") == NULL);
                ER_CHECK("and it names the two receipts it came from",
                         body && strstr(body, "u005") != NULL &&
                         strstr(body, "u020") != NULL);
                free(body);
            }
        }

        /* A fix with no file in it is not evidence about anything. */
        struct zcl_rule_candidate empty;
        ER_CHECK("a diff naming no file yields no candidate",
                 !zcl_rule_mine_candidate(&pairs[0], "no files here\n", 14,
                                          &empty));

        /* Three receipts, ONE task, pass then fail then pass. The earlier
         * PASS is not an earlier failure: the header's rule — first failure
         * paired with the first later pass — still has exactly one pair to
         * emit, and dropping it would throw away the only lesson the task
         * taught. */
        struct zcl_rule_receipt_log *trio = calloc(1, sizeof *trio);
        ER_CHECK("the pass-fail-pass trio log allocates", trio != NULL);
        if (trio) {
            char task[65];
            fx_hex(task, 't', 777u);
            for (int i = 0; i < 3; i++) {
                struct zcl_rule_receipt *r = &trio->r[i];
                (void)snprintf(r->unit_id, sizeof r->unit_id, "u50%d", i);
                memcpy(r->task_sha3, task, sizeof task);
                r->gate_pass = (i != 1);
                r->seq = (uint32_t)(i + 1);
            }
            trio->count = 3;
            struct zcl_rule_mine_pair tp[4];
            uint32_t tn = zcl_rule_mine_pairs(trio, tp, 4);
            ER_CHECK("a pass before the fail does not eat the pair", tn == 1u);
            ER_CHECK("the pair is the first fail with the first later pass",
                     tn == 1u && strcmp(tp[0].fail_unit, "u501") == 0 &&
                     strcmp(tp[0].pass_unit, "u502") == 0);
            free(trio);
        }
    }
    free(parsed);
    free(log);
    return failures;
}

/* ── 6. the atomic rewrite of the live def ───────────────────────────── */

static int case_rewrite(void)
{
    int failures = 0;
    char tmpl[] = "/tmp/zcl_engine_rewriteXXXXXX";
    char *dir = mkdtemp(tmpl);
    ER_CHECK("a temp directory for the rewrite cases", dir != NULL);
    if (!dir) return failures;

    char vpath[512], tpath[540];
    (void)snprintf(vpath, sizeof vpath, "%s/rule_vocab.def", dir);
    (void)snprintf(tpath, sizeof tpath, "%s.tmp", vpath);
    size_t klen = sizeof k_fixture_vocab - 1;
    ER_CHECK("the fixture def is planted on disk",
             fx_write(vpath, k_fixture_vocab, klen));

    /* ---- idempotent: a rewrite carrying the file's own bytes ---- */
    ER_CHECK("rewriting the def with its own bytes succeeds",
             zcl_rule_def_rewrite(vpath, k_fixture_vocab, klen,
                                  k_fixture_vocab, klen) ==
             ZCL_RULE_REWRITE_OK);
    size_t alen = 0;
    char *after = fx_read(vpath, &alen);
    ER_CHECK("and the file is byte-identical afterwards",
             after && alen == klen &&
             memcmp(after, k_fixture_vocab, alen) == 0);
    free(after);
    struct stat sb;
    ER_CHECK("and no temp file was left behind", stat(tpath, &sb) != 0);

    static const char k_replacement[] = "/* replacement bytes */\n";
    size_t rlen = sizeof k_replacement - 1;

    /* ---- stale read: the def changed after the caller read it. The
     * rewrite was decided from OTHER bytes; publishing it here would
     * clobber the edit that is standing on disk. The refusal must be the
     * TYPED stale one, not a generic write failure, and must leave both
     * the file and the temp name exactly as they were. */
    static const char k_stale_old[] = "/* bytes nobody ever planted */\n";
    ER_CHECK("a rewrite from bytes that are not on disk is refused",
             zcl_rule_def_rewrite(vpath, k_stale_old, sizeof k_stale_old - 1,
                                  k_replacement, rlen) ==
             ZCL_RULE_REWRITE_ERR_STALE);
    size_t slen = 0;
    char *stood = fx_read(vpath, &slen);
    ER_CHECK("and the editor's bytes still stand, untouched",
             stood && slen == klen &&
             memcmp(stood, k_fixture_vocab, klen) == 0);
    free(stood);
    ER_CHECK("and the refusal left no temp file behind",
             stat(tpath, &sb) != 0);

    /* ---- crash safety: a write that dies BEFORE the rename. A directory
     * pre-empting the temp name makes the temp write itself fail — the same
     * observable state an ENOSPC or a kill mid-write leaves behind — and the
     * assertion is the one that matters: the ORIGINAL is intact. The
     * refusal is the IO one: the bytes matched, the write failed. */
    ER_CHECK("the temp name is pre-empted so the write aborts",
             mkdir(tpath, 0755) == 0);
    ER_CHECK("the aborted rewrite is refused as a write failure",
             zcl_rule_def_rewrite(vpath, k_fixture_vocab, klen,
                                  k_replacement, rlen) ==
             ZCL_RULE_REWRITE_ERR_IO);
    size_t blen = 0;
    char *orig = fx_read(vpath, &blen);
    ER_CHECK("and the original def still stands, byte for byte",
             orig && blen == klen &&
             memcmp(orig, k_fixture_vocab, klen) == 0);
    free(orig);
#if defined(_WIN32)
    int temp_removed = rmdir(tpath);
#else
    int temp_removed = remove(tpath);
#endif
    ER_CHECK("the pre-empted temp name is cleaned up", temp_removed == 0);

    /* ---- and a matching stale window that PUBLISHES: same bytes read,
     * same bytes on disk, different new text — the rename must land. */
    ER_CHECK("a fresh rewrite publishes",
             zcl_rule_def_rewrite(vpath, k_fixture_vocab, klen,
                                  k_replacement, rlen) == ZCL_RULE_REWRITE_OK);
    size_t plen2 = 0;
    char *pub = fx_read(vpath, &plen2);
    ER_CHECK("and the published bytes are the new ones",
             pub && plen2 == rlen &&
             memcmp(pub, k_replacement, rlen) == 0);
    free(pub);
    return failures;
}

/* ── 7. the vocabulary this binary was compiled with ─────────────────── */

static int case_builtin(void)
{
    int failures = 0;
    const struct zcl_rule_vocab *v = zcl_rule_vocab_builtin();
    ER_CHECK("the compiled-in vocabulary is non-empty",
             v != NULL && v->count > 0);
    if (!v) return failures;

    bool ids_ok = true, dup = false, bounded = true;
    for (uint32_t i = 0; i < v->count; i++) {
        const char *id = v->row[i].id;
        if (!id[0]) ids_ok = false;
        if (strncmp(id, "grok:", 5) != 0 && strncmp(id, "persona:", 8) != 0)
            ids_ok = false;
        if (v->row[i].floor_permille > 1000u || v->row[i].min_trials == 0u)
            bounded = false;
        for (uint32_t k = 0; k < i; k++)
            if (strcmp(v->row[k].id, id) == 0) dup = true;
    }
    ER_CHECK("every id is namespaced to a source it can resolve against",
             ids_ok);
    ER_CHECK("no id appears twice", !dup);
    ER_CHECK("every floor and trial count is inside its bound", bounded);

    /* The text parser must agree with the compiler about the same file. */
    size_t dlen = 0;
    char *def = fx_read("engine/composition/rule_vocab.def", &dlen);
    if (def) {
        struct zcl_rule_vocab parsed;
        bool ok = zcl_rule_vocab_parse(def, dlen, &parsed);
        ER_CHECK("the checked-in .def parses", ok);
        ER_CHECK("and the parser and the compiler agree on the row count",
                 ok && parsed.count == v->count);
        free(def);
    } else {
        printf("engine_rules: SKIP the checked-in .def (not run from the "
               "repository root)\n");
    }
    return failures;
}

/* Unknown measurements must not train a policy as zero-cost observations.
 * Outcome scoring remains usable even when a provider reports no usage. */
static int case_measurement_unknowns(void)
{
    int failures = 0;
    static const struct {
        const char *fields;
        int64_t prompt, completion, wall;
    } cases[] = {
        {"", -1, -1, -1},
        {"\"prompt_tokens\":-1,\"completion_tokens\":-1,\"wall_ms\":-1,",
         -1, -1, -1},
        {"\"prompt_tokens\":null,\"completion_tokens\":\"12\",\"wall_ms\":true,",
         -1, -1, -1},
        {"\"prompt_tokens\":-2,\"completion_tokens\":1.5,\"wall_ms\":{},",
         -1, -1, -1},
        {"\"prompt_tokens\":0,\"completion_tokens\":0,\"wall_ms\":0,", 0, 0, 0},
        {"\"prompt_tokens\":12,\"wall_ms\":9999,", 12, -1, 9999},
        {"\"completion_tokens\":34,\"wall_ms\":10000,", -1, 34, 10000},
        {"\"prompt_tokens\":56,\"completion_tokens\":78,\"wall_ms\":10001,",
         56, 78, 10001}
    };
    struct zcl_rule_receipt_log *parsed = calloc(1, sizeof *parsed);
    ER_CHECK("measurement fixture allocates", parsed != NULL);
    if (!parsed) return failures;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        char line[1024];
        int n = snprintf(line, sizeof line,
            "{\"schema\":\"zcl.engine_unit_receipt.v1\","
            "\"prev_sha3\":\"%064d\",\"unit_id\":\"measured\","
            "\"task_sha3\":\"%064d\",%s\"outcome\":{\"gate_pass\":true}}\n",
            0, 0, cases[i].fields);
        uint32_t bad = 0;
        bool bounded = n > 0 && (size_t)n < sizeof line;
        enum zcl_rule_chain_status status = bounded
            ? zcl_rule_receipts_parse(line, (size_t)n, parsed, &bad)
            : ZCL_RULE_CHAIN_MALFORMED;
        ER_CHECK("usage availability preserves valid outcome receipt",
                 status == ZCL_RULE_CHAIN_OK && bad == 0 && parsed->count == 1);
        if (status != ZCL_RULE_CHAIN_OK || parsed->count != 1) continue;
        ER_CHECK("prompt unknown remains distinct from measured zero",
                 (int64_t)parsed->r[0].prompt_tokens == cases[i].prompt);
        ER_CHECK("completion unknown remains distinct from measured zero",
                 (int64_t)parsed->r[0].completion_tokens == cases[i].completion);
        ER_CHECK("wall unknown remains distinct; long samples retained",
                 (int64_t)parsed->r[0].wall_ms == cases[i].wall);
        ER_CHECK("measurement absence never fabricates gate failure",
                 parsed->r[0].gate_pass);
    }
    free(parsed);
    return failures;
}

int test_engine_rules(void)
{
    int failures = 0;
    failures += case_fixture();
    failures += case_broken_chain();
    failures += case_wilson();
    failures += case_decisions();
    failures += case_miner();
    failures += case_rewrite();
    failures += case_builtin();
    failures += case_measurement_unknowns();
    printf("engine_rules: %d failure(s)\n", failures);
    return failures;
}
