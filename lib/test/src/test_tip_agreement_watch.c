/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_tip_agreement_watch — hermetic tests for the in-node reader behind
 * `z23 ops state --subsystem=tip_agreement`, the typed surface over the
 * OFF-HOST tip-hash agreement ledger.
 *
 * THE DEFECT UNDER REGRESSION is not a crash, it is a false green. Every
 * parity reference that predates the recorder dials 127.0.0.1 — same box, same
 * disk, same clock, same operator — and this project's history contains nine
 * at-tip claims that were wrong because the evidence was not independent. So
 * the contracts asserted here are the ones that make "we agree with the
 * network" impossible to say cheaply:
 *
 *   (a) ONE peer cannot mint agreement. A sample whose modal hash is backed by
 *       fewer distinct remote hosts than the control the recorder had in force
 *       reports the EXACT token insufficient_independent_peers and
 *       agreement_reported=false — even when the recorded outcome says
 *       "agrees" and even when the hashes match.
 *   (b) an UNREADABLE control is not a satisfied control. A row with no
 *       min_distinct_peers field refuses, it does not fall back to the shipped
 *       default.
 *   (c) the recorded BYTES beat the recorded verdict. A row claiming "agrees"
 *       whose own our_tip_hash and modal_remote_hash differ reports
 *       agrees_row_hash_mismatch, never agreement.
 *   (d) a DISAGREEING sample is reported, in full, with the height and both
 *       hashes. Suppressing it would be the defect, not the news.
 *   (e) agreement is reported when — and only when — all three hold.
 *
 * The refusals are asserted as EXACT STRINGS, not as "not agreement": a
 * refusal that fires for an unrelated downstream reason has already fooled
 * this project once.
 *
 * Every block builds its ledger under a private tmp dir exported through
 * ZCL_PARITY_LEDGER_DIR — the same variable tools/scripts/tip_agreement_probe.sh
 * reads — so the operator's real ledger, the live node and $HOME are never
 * touched. */

#include "test/test_core.h"

#include "json/json.h"
#include "services/evidence_ledger_row.h"
#include "services/tip_agreement_watch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TAW_CHECK(name, expr) do { \
    printf("tip_agreement_watch: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

#define HASH_A "0000103d7ff73c7af07dd001d5b2ed67e37bf842420e7f14342110603480b7d1"
#define HASH_B "00001040aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

/* One ledger row in the exact shape tip_agreement_probe.sh appends. `control`
 * < 0 omits min_distinct_peers entirely (a row that never recorded which floor
 * was in force). */
static void row(char *buf, size_t cap, long long ts, const char *outcome,
                long long control, long long height, const char *ours,
                const char *theirs, long long modal_peers,
                long long disagreeing, const char *reason)
{
    char ctl[64];
    if (control < 0)
        ctl[0] = '\0';
    else
        snprintf(ctl, sizeof(ctl), "\"min_distinct_peers\":%lld,", control);
    snprintf(buf, cap,
             "{\"ts\":%lld,\"instance\":\"canonical\",\"rpcport\":18232,"
             "\"window_secs\":900,%s\"our_height\":3198906,"
             "\"height\":%lld,\"our_tip_hash\":\"%s\","
             "\"modal_remote_hash\":\"%s\",\"modal_remote_peers\":%lld,"
             "\"modal_remote_groups\":%lld,\"disagreeing_peers\":%lld,"
             "\"contested_peers\":%lld,\"rival_heights_unresolved\":0,"
             "\"heights_above_tip\":0,\"disagreeing_hashes\":[],"
             "\"peers_total\":21,\"peers_with_height\":21,"
             "\"peers_usable\":%lld,\"clusters_seen\":7,\"excluded_hosts\":0,"
             "\"outcome\":\"%s\",\"reason\":\"%s\",\"error_detail\":\"\"}\n",
             ts, ctl, height, ours, theirs, modal_peers, modal_peers,
             disagreeing, disagreeing, modal_peers < 0 ? 1 : modal_peers,
             outcome, reason);
}

static bool scan_text(const char *text, struct tip_agreement_report *rep)
{
    return tip_agreement_scan(text, strlen(text), rep);
}

/* An ordinary short row for write_row_of_len(): comfortably above the fixed
 * part of that row (319 bytes with two 64-char hashes in it) and nowhere near
 * EVIDENCE_ROW_MAX, so it is unambiguously "a normal row". */
#define SHORT_ROW 400

/* Append one syntactically fine row whose DATA length (newline excluded) is
 * exactly `data_len` bytes, padded with a filler field. `terminate` false
 * leaves it with no trailing newline — a torn append. Written straight to the
 * file because the interesting lengths are far past any stack buffer.
 *
 * Returns false rather than writing a row of some OTHER length when data_len
 * cannot be honoured — a fixture that quietly writes a different row than the
 * one being asserted about is worse than no fixture. */
static bool write_row_of_len(FILE *f, long long ts, long long height,
                            size_t data_len, bool terminate)
{
    char head[512];
    int hn = snprintf(head, sizeof(head),
                      "{\"ts\":%lld,\"min_distinct_peers\":2,"
                      "\"our_height\":%lld,\"height\":%lld,"
                      "\"our_tip_hash\":\"" HASH_A "\","
                      "\"modal_remote_hash\":\"" HASH_A "\","
                      "\"modal_remote_peers\":4,\"outcome\":\"agrees\","
                      "\"reason\":\"len_fixture\",\"pad\":\"",
                      ts, height, height);
    const char *tail = "\"}";
    /* A truncated head would silently make the row a different length than
     * asked for, which is the one thing these fixtures must not do. */
    if (hn <= 0 || hn >= (int)sizeof(head))
        return false;
    if (data_len < (size_t)hn + strlen(tail))
        return false;
    if (fputs(head, f) == EOF)
        return false;
    for (size_t i = 0; i < data_len - (size_t)hn - strlen(tail); i++)
        if (fputc('x', f) == EOF)
            return false;
    if (fputs(tail, f) == EOF)
        return false;
    if (terminate && fputc('\n', f) == EOF)
        return false;
    return true;
}

/* Summarise a report into caller storage. */
static const char *summary_of(const struct tip_agreement_report *rep,
                              char *buf, size_t cap)
{
    return tip_agreement_summary_text(rep, buf, cap);
}

int test_tip_agreement_watch(void);

int test_tip_agreement_watch(void)
{
    int failures = 0;
    char text[4096];
    char summary[TIP_AGREEMENT_SUMMARY_MAX];
    struct tip_agreement_report rep;

    /* ── (a) ONE peer cannot mint agreement ────────────────────────────
     * The live host's actual condition on 2026-07-30: exactly one remote host
     * surfacing a tip hash, and it is the operator's own second server. Here
     * that host even AGREES with us and the recorder wrote "agrees" — and the
     * report must still refuse, by name. */
    {
        bool ok = true;
        row(text, sizeof(text), 1785386039LL, "agrees", 2, 3198906, HASH_A,
            HASH_A, 1, 0, "one_host_only");
        ok = ok && scan_text(text, &rep);
        ok = ok && rep.present;
        ok = ok && rep.rows_scanned == 1;
        ok = ok && rep.modal_remote_peers == 1;
        ok = ok && rep.min_distinct_peers == 2;
        ok = ok && rep.hashes_match;                    /* bytes DO match */
        ok = ok && rep.outcome == TIP_AGREEMENT_OUTCOME_AGREES;
        ok = ok && rep.independence ==
                       TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT;
        /* The whole contract: matching bytes + a recorded "agrees" is still
         * NOT agreement when one host is the only witness. */
        ok = ok && !tip_agreement_reports_agreement(&rep);
        summary_of(&rep, summary, sizeof(summary));
        ok = ok && strstr(summary, TIP_AGREEMENT_INSUFFICIENT_TOKEN) != NULL;
        ok = ok && strstr(summary, "backed_by=1") != NULL;
        ok = ok && strstr(summary, "required=2") != NULL;
        /* and it must not read like agreement anywhere on the line */
        ok = ok && strstr(summary, "agrees height=") == NULL;
        TAW_CHECK("one witness cannot mint agreement, and says so by name", ok);
    }

    /* ── (b) an unreadable control is not a satisfied control ──────────
     * A row with no min_distinct_peers cannot testify that any floor was in
     * force, so it must not borrow the shipped default of 2. */
    {
        bool ok = true;
        row(text, sizeof(text), 1785386039LL, "agrees", -1, 3198906, HASH_A,
            HASH_A, 5, 0, "no_control_recorded");
        ok = ok && scan_text(text, &rep);
        ok = ok && rep.min_distinct_peers == -1;
        ok = ok && rep.modal_remote_peers == 5;         /* plenty of peers */
        ok = ok && rep.independence == TIP_AGREEMENT_INDEPENDENCE_UNKNOWN;
        ok = ok && !tip_agreement_reports_agreement(&rep);
        summary_of(&rep, summary, sizeof(summary));
        ok = ok && strstr(summary, TIP_AGREEMENT_INSUFFICIENT_TOKEN) != NULL;
        ok = ok && strstr(summary, "independence=unknown") != NULL;

        /* And the classifier directly, at its boundaries. */
        ok = ok && tip_agreement_classify_independence(2, 2) ==
                       TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT;
        ok = ok && tip_agreement_classify_independence(1, 2) ==
                       TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT;
        /* "the recorder did not count" is insufficient, never a pass */
        ok = ok && tip_agreement_classify_independence(-1, 2) ==
                       TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT;
        /* a zero/negative floor is an unreadable control, not a free pass */
        ok = ok && tip_agreement_classify_independence(9, 0) ==
                       TIP_AGREEMENT_INDEPENDENCE_UNKNOWN;
        ok = ok && tip_agreement_classify_independence(9, -1) ==
                       TIP_AGREEMENT_INDEPENDENCE_UNKNOWN;
        TAW_CHECK("an unreadable control refuses instead of defaulting", ok);
    }

    /* ── (c) recorded bytes beat the recorded verdict ──────────────────── */
    {
        bool ok = true;
        row(text, sizeof(text), 1785386039LL, "agrees", 2, 3198906, HASH_A,
            HASH_B, 4, 0, "forged_or_buggy_agrees");
        ok = ok && scan_text(text, &rep);
        ok = ok && rep.independence == TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT;
        ok = ok && !rep.hashes_match;
        ok = ok && rep.outcome == TIP_AGREEMENT_OUTCOME_AGREES;
        ok = ok && !tip_agreement_reports_agreement(&rep);
        summary_of(&rep, summary, sizeof(summary));
        ok = ok && strstr(summary, TIP_AGREEMENT_CONTRADICTION_TOKEN) != NULL;
        ok = ok && strstr(summary, "agrees height=") == NULL;
        TAW_CHECK("an agrees row whose own hashes differ is not agreement", ok);
    }

    /* ── (d) a disagreeing sample is reported in full ──────────────────── */
    {
        bool ok = true;
        row(text, sizeof(text), 1785386100LL, "disagrees", 2, 3198900, HASH_A,
            HASH_B, 6, 6, "remote_mode_differs");
        ok = ok && scan_text(text, &rep);
        ok = ok && rep.disagrees == 1 && rep.agrees == 0;
        ok = ok && rep.last_disagree_ts == 1785386100LL;
        ok = ok && rep.height == 3198900;
        ok = ok && strcmp(rep.our_tip_hash, HASH_A) == 0;
        ok = ok && strcmp(rep.modal_remote_hash, HASH_B) == 0;
        ok = ok && rep.disagreeing_peers == 6;
        ok = ok && !tip_agreement_reports_agreement(&rep);
        summary_of(&rep, summary, sizeof(summary));
        ok = ok && strncmp(summary, "disagrees ", 10) == 0;
        ok = ok && strstr(summary, "height=3198900") != NULL;
        ok = ok && strstr(summary, "disagreeing_peers=6") != NULL;
        TAW_CHECK("a disagreeing sample is recorded and named, not suppressed",
                  ok);
    }

    /* ── (e) agreement, when all three hold ───────────────────────────── */
    {
        bool ok = true;
        row(text, sizeof(text), 1785386200LL, "agrees", 2, 3198906, HASH_A,
            HASH_A, 7, 0, "modal_hash_matches");
        ok = ok && scan_text(text, &rep);
        ok = ok && rep.independence == TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT;
        ok = ok && rep.hashes_match;
        ok = ok && tip_agreement_reports_agreement(&rep);
        summary_of(&rep, summary, sizeof(summary));
        ok = ok && strncmp(summary, "agrees ", 7) == 0;
        ok = ok && strstr(summary, "backed_by=7") != NULL;
        ok = ok && strstr(summary, TIP_AGREEMENT_INSUFFICIENT_TOKEN) == NULL;

        /* Our own hash coming back in capital letters is not a fork. */
        char upper[TIP_AGREEMENT_HASH_MAX];
        snprintf(upper, sizeof(upper), "%s", HASH_A);
        for (size_t i = 0; upper[i]; i++)
            if (upper[i] >= 'a' && upper[i] <= 'f')
                upper[i] = (char)(upper[i] - 'a' + 'A');
        row(text, sizeof(text), 1785386260LL, "agrees", 2, 3198906, upper,
            HASH_A, 7, 0, "case_only_difference");
        ok = ok && scan_text(text, &rep);
        ok = ok && rep.hashes_match;
        ok = ok && tip_agreement_reports_agreement(&rep);
        TAW_CHECK("agreement is reported when independence and bytes both hold",
                  ok);
    }

    /* ── rollup + unknown/malformed accounting ────────────────────────── */
    {
        bool ok = true;
        char multi[8192];
        char one[2048];
        multi[0] = '\0';
        row(one, sizeof(one), 1785386000LL, "agrees", 2, 3198900, HASH_A,
            HASH_A, 3, 0, "a");
        strncat(multi, one, sizeof(multi) - strlen(multi) - 1);
        row(one, sizeof(one), 1785386060LL, "could-not-ask", 2, -1, "", "",
            -1, -1, "no_hash_with_min_distinct_peers_2");
        strncat(multi, one, sizeof(multi) - strlen(multi) - 1);
        row(one, sizeof(one), 1785386120LL, "disagrees", 2, 3198901, HASH_A,
            HASH_B, 4, 4, "b");
        strncat(multi, one, sizeof(multi) - strlen(multi) - 1);
        /* an outcome this build does not recognise — counted, never folded
         * into could-not-ask */
        row(one, sizeof(one), 1785386180LL, "sideways", 2, 3198902, HASH_A,
            HASH_A, 4, 0, "c");
        strncat(multi, one, sizeof(multi) - strlen(multi) - 1);
        /* a row with no outcome field at all is malformed */
        strncat(multi, "{\"ts\":1785386240,\"instance\":\"canonical\"}\n",
                sizeof(multi) - strlen(multi) - 1);

        ok = ok && scan_text(multi, &rep);
        ok = ok && rep.rows_scanned == 4;
        ok = ok && rep.malformed_rows == 1;
        ok = ok && rep.unknown_outcome_rows == 1;
        ok = ok && rep.agrees == 1;
        ok = ok && rep.disagrees == 1;
        ok = ok && rep.could_not_ask == 1;
        ok = ok && rep.last_agree_ts == 1785386000LL;
        ok = ok && rep.last_disagree_ts == 1785386120LL;
        /* the LAST usable row is the unknown one; unknown is not agreement */
        ok = ok && rep.outcome == TIP_AGREEMENT_OUTCOME_UNKNOWN;
        ok = ok && !tip_agreement_reports_agreement(&rep);
        TAW_CHECK("tail rollup counts every outcome and never hides one", ok);
    }

    /* ── a could-not-ask row with nothing measured ─────────────────────
     * The live shape: null height, empty hashes, null peer counts. It must
     * read as a refusal, and its own reason must survive to the operator. */
    {
        bool ok = true;
        row(text, sizeof(text), 1785386039LL, "could-not-ask", 2, -1, "", "",
            -1, -1, "no_hash_with_min_distinct_peers_2");
        ok = ok && scan_text(text, &rep);
        ok = ok && rep.height == -1;
        ok = ok && rep.our_tip_hash[0] == '\0';
        ok = ok && rep.modal_remote_peers == -1;
        ok = ok && !rep.hashes_match;
        ok = ok && rep.independence ==
                       TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT;
        ok = ok && !tip_agreement_reports_agreement(&rep);
        summary_of(&rep, summary, sizeof(summary));
        ok = ok && strstr(summary, TIP_AGREEMENT_INSUFFICIENT_TOKEN) != NULL;
        ok = ok && strstr(summary, "recorded_outcome=could-not-ask") != NULL;
        TAW_CHECK("a nothing-measured sample refuses and keeps its reason", ok);
    }

    /* ── the VERBATIM live row, nulls and all ──────────────────────────
     * Copied byte-for-byte out of the ledger a read-only probe wrote against
     * the owner's live node on 2026-07-30 (21 connected peers, exactly one
     * surfacing a tip hash, and that one host was the operator's OWN second
     * server). Two reasons it is pinned here rather than
     * generated:
     *   - the real recorder writes JSON `null`, not -1, for anything it could
     *     not measure. A parser that read null as 0 would turn "nobody
     *     counted" into "zero disagreed", which is the exact shape of false
     *     green this whole rung exists to prevent.
     *   - it proves the reader refuses the condition that actually obtains on
     *     this host, rather than only a hand-built one. */
    {
        bool ok = true;
        static const char live_row[] =
            "{\"ts\":1785387019,\"instance\":\"canonical\",\"rpcport\":18232,"
            "\"datadir\":\"/home/rhett/.zclassic-c23\",\"window_secs\":900,"
            "\"min_distinct_peers\":2,\"our_height\":3198925,\"height\":null,"
            "\"our_tip_hash\":\"\",\"modal_remote_hash\":\"\","
            "\"modal_remote_peers\":null,\"modal_remote_groups\":null,"
            "\"disagreeing_peers\":null,\"contested_peers\":null,"
            "\"rival_heights_unresolved\":null,\"heights_above_tip\":null,"
            "\"disagreeing_hashes\":[],\"peers_total\":20,"
            "\"peers_with_height\":20,\"peers_usable\":1,\"clusters_seen\":12,"
            "\"excluded_hosts\":0,\"outcome\":\"could-not-ask\","
            "\"reason\":\"no_hash_with_min_distinct_peers_2\","
            "\"error_detail\":\"\"}\n";
        ok = ok && scan_text(live_row, &rep);
        ok = ok && rep.present && rep.rows_scanned == 1;
        ok = ok && rep.could_not_ask == 1;
        /* every null reads as unknown (-1), never as a measured zero */
        ok = ok && rep.height == -1;
        ok = ok && rep.modal_remote_peers == -1;
        ok = ok && rep.modal_remote_groups == -1;
        ok = ok && rep.disagreeing_peers == -1;
        ok = ok && rep.contested_peers == -1;
        /* while the fields it DID measure survive intact */
        ok = ok && rep.our_height == 3198925;
        ok = ok && rep.peers_usable == 1;
        ok = ok && rep.min_distinct_peers == 2;
        ok = ok && rep.excluded_hosts == 0;
        ok = ok && strcmp(rep.reason,
                          "no_hash_with_min_distinct_peers_2") == 0;
        ok = ok && rep.independence ==
                       TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT;
        ok = ok && !tip_agreement_reports_agreement(&rep);
        summary_of(&rep, summary, sizeof(summary));
        ok = ok && strstr(summary, TIP_AGREEMENT_INSUFFICIENT_TOKEN) != NULL;
        TAW_CHECK("the verbatim live row refuses, and its nulls stay unknown",
                  ok);
    }

    /* ── absence is data, never an error ──────────────────────────────── */
    {
        bool ok = true;
        ok = ok && tip_agreement_read_ledger("/nonexistent/zcl-taw/none.jsonl",
                                             &rep);
        ok = ok && !rep.present;
        ok = ok && rep.rows_scanned == 0;
        ok = ok && !tip_agreement_reports_agreement(&rep);
        summary_of(&rep, summary, sizeof(summary));
        ok = ok && strstr(summary, "no_ledger") != NULL;
        /* bad arguments still fail loudly */
        ok = ok && !tip_agreement_read_ledger(NULL, &rep);
        ok = ok && !tip_agreement_read_ledger("/tmp/x", NULL);
        ok = ok && !tip_agreement_scan("x", 1, NULL);
        TAW_CHECK("a missing ledger is present=false, not an error", ok);
    }

    /* ── the typed dump, over a real file, via the recorder's own env var ── */
    {
        bool ok = true;
        char dir[] = "/tmp/zcl-taw-XXXXXX";
        ok = ok && mkdtemp(dir) != NULL;
        char path[512];
        snprintf(path, sizeof(path), "%s/agreement-ledger.jsonl", dir);
        FILE *f = fopen(path, "wb");
        ok = ok && f != NULL;
        if (f) {
            row(text, sizeof(text), 1785386039LL, "agrees", 2, 3198906,
                HASH_A, HASH_A, 1, 0, "one_host_only");
            fputs(text, f);
            fclose(f);
        }
        setenv("ZCL_PARITY_LEDGER_DIR", dir, 1);

        char resolved[512];
        ok = ok && tip_agreement_resolve_ledger(resolved, sizeof(resolved));
        ok = ok && strcmp(resolved, path) == 0;

        struct json_value dump;
        json_init(&dump);
        ok = ok && tip_agreement_dump_state_json(&dump, NULL);
        ok = ok && json_get_bool(json_get(&dump, "present")) == true;
        /* the refusal is on the typed surface, not only in a log line */
        ok = ok && json_get_bool(json_get(&dump, "agreement_reported")) == false;
        ok = ok && json_get_bool(json_get(&dump,
                                          "insufficient_independent_peers")) ==
                       true;
        const struct json_value *last = json_get(&dump, "last_sample");
        ok = ok && last != NULL;
        ok = ok && json_get_int(json_get(last, "height")) == 3198906;
        ok = ok && json_get_int(json_get(last,
                        "independent_peers_backing_mode")) == 1;
        ok = ok && json_get_int(json_get(last,
                        "min_distinct_peers_control")) == 2;
        ok = ok && strcmp(json_get_str(json_get(last, "our_tip_hash")),
                          HASH_A) == 0;
        ok = ok && strcmp(json_get_str(json_get(last, "modal_remote_hash")),
                          HASH_A) == 0;
        ok = ok && strcmp(json_get_str(json_get(last, "independence")),
                          "insufficient") == 0;
        ok = ok && strstr(json_get_str(json_get(&dump, "summary")),
                          TIP_AGREEMENT_INSUFFICIENT_TOKEN) != NULL;
        const struct json_value *roll = json_get(&dump, "tail_rollup");
        ok = ok && roll && json_get_int(json_get(roll, "rows_scanned")) == 1;
        json_free(&dump);

        /* keyed form: the last sample only, no rollup */
        json_init(&dump);
        ok = ok && tip_agreement_dump_state_json(&dump, "last");
        ok = ok && json_get(&dump, "last_sample") != NULL;
        ok = ok && json_get(&dump, "tail_rollup") == NULL;
        json_free(&dump);

        /* an unknown key says so rather than guessing */
        json_init(&dump);
        ok = ok && tip_agreement_dump_state_json(&dump, "bogus");
        ok = ok && json_get(&dump, "error") != NULL;
        json_free(&dump);

        unsetenv("ZCL_PARITY_LEDGER_DIR");
        unlink(path);
        rmdir(dir);
        TAW_CHECK("the typed dump reports the refusal and the raw sample", ok);
    }

    /* ── (f) THE ROW CANNOT SET ITS OWN BAR ────────────────────────────
     * min_distinct_peers is a field of the row being graded. Grading only
     * against it let a row that reported control=1 and carried exactly one
     * backing peer grade itself SUFFICIENT and publish agreement — one host
     * manufacturing agreement, which is the failure (a) above exists to make
     * impossible. Reproduced before this block existed:
     *   control=1 peers=1 -> independence=sufficient agreement_reported=TRUE
     * Anyone can produce such a row: ZCL_PARITY_MIN_DISTINCT_PEERS=1 on the
     * recorder, an old ledger copied in, or a hand-written line. So the
     * recorded control may only ever RAISE the bar above
     * TIP_AGREEMENT_MIN_DISTINCT_PEERS, never lower it. */
    {
        bool ok = true;
        row(text, sizeof(text), 1785386039LL, "agrees", 1, 3198906, HASH_A,
            HASH_A, 1, 0, "weakened_control_one_peer");
        ok = ok && scan_text(text, &rep);
        ok = ok && rep.min_distinct_peers == 1;   /* the row's own claim */
        ok = ok && rep.modal_remote_peers == 1;
        ok = ok && rep.hashes_match;              /* bytes DO match */
        ok = ok && rep.outcome == TIP_AGREEMENT_OUTCOME_AGREES;
        ok = ok && rep.independence ==
                       TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT;
        ok = ok && !tip_agreement_reports_agreement(&rep);
        summary_of(&rep, summary, sizeof(summary));
        ok = ok && strstr(summary, TIP_AGREEMENT_INSUFFICIENT_TOKEN) != NULL;
        /* the bar REPORTED is the one applied, not the one the row asked for */
        ok = ok && strstr(summary, "required=2") != NULL;
        ok = ok && strstr(summary, "control_recorded=1") != NULL;
        ok = ok && strstr(summary, "agrees height=") == NULL;

        /* The floor is a floor, not a replacement: a genuinely adequate peer
         * count still grades SUFFICIENT, and a control STRONGER than the floor
         * is still honoured as written. */
        ok = ok && tip_agreement_required_distinct_peers(1) ==
                       TIP_AGREEMENT_MIN_DISTINCT_PEERS;
        ok = ok && tip_agreement_required_distinct_peers(2) == 2;
        ok = ok && tip_agreement_required_distinct_peers(9) == 9;
        /* an unreadable control does not borrow the floor either */
        ok = ok && tip_agreement_required_distinct_peers(0) == -1;
        ok = ok && tip_agreement_required_distinct_peers(-1) == -1;

        ok = ok && tip_agreement_classify_independence(1, 1) ==
                       TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT;
        ok = ok && tip_agreement_classify_independence(2, 1) ==
                       TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT;
        ok = ok && tip_agreement_classify_independence(9, 9) ==
                       TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT;
        ok = ok && tip_agreement_classify_independence(8, 9) ==
                       TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT;

        row(text, sizeof(text), 1785386099LL, "agrees", 1, 3198906, HASH_A,
            HASH_A, 4, 0, "weakened_control_four_peers");
        ok = ok && scan_text(text, &rep);
        ok = ok && rep.independence == TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT;
        ok = ok && tip_agreement_reports_agreement(&rep);
        summary_of(&rep, summary, sizeof(summary));
        ok = ok && strncmp(summary, "agrees ", 7) == 0;
        /* even then the weakened control stays VISIBLE, not honoured */
        ok = ok && strstr(summary, "required 2") != NULL;
        ok = ok && strstr(summary, "control_recorded 1") != NULL;
        TAW_CHECK("a row's own control cannot lower the independence floor",
                  ok);
    }

    /* ── (g) the bounded tail read drops nothing real and invents nothing ──
     * All three defects below were live in evidence_ledger_scan_tail() and
     * every one of them corrupted the honesty of this report, because
     * malformed_rows is published and the LAST row scanned supplies every
     * per-sample field. Both readers over that scanner (this one and
     * services/stopwatch_skip_watch.h) were affected. */
    {
        bool ok = true;
        char dir[] = "/tmp/zcl-taw-tail-XXXXXX";
        ok = ok && mkdtemp(dir) != NULL;
        char path[512];
        snprintf(path, sizeof(path), "%s/agreement-ledger.jsonl", dir);

        /* (g1) A row that FITS must not be mistaken for one that did not.
         * fgets() over a buffer of exactly EVIDENCE_ROW_MAX returns a
         * 4095-byte row buffer-full with no newline visible, which the old
         * check read as overlong: the row was dropped and counted malformed
         * (reproduced at both 4095 and 4096). */
        for (size_t len = EVIDENCE_ROW_MAX - 1; len <= EVIDENCE_ROW_MAX;
             len++) {
            FILE *f = fopen(path, "wb");
            ok = ok && f != NULL;
            if (!f)
                break;
            ok = ok && write_row_of_len(f, 1785390000LL, 3100001, len, true);
            ok = ok && write_row_of_len(f, 1785390060LL, 3100002, SHORT_ROW,
                                        true);
            fclose(f);
            ok = ok && tip_agreement_read_ledger(path, &rep);
            ok = ok && rep.rows_scanned == 2;
            ok = ok && rep.malformed_rows == 0;
            ok = ok && rep.incomplete_rows == 0;
            ok = ok && rep.height == 3100002;    /* the LAST row won */
        }

        /* (g2) A post-seek fragment long enough to fill the row buffer used to
         * cost the row AFTER it: the overlong branch returned before `first`
         * was cleared, so the next line — a real, complete row — was dropped
         * as if IT were the fragment. The file must exceed
         * TIP_AGREEMENT_TAIL_BYTES for the seek to happen at all. */
        {
            FILE *f = fopen(path, "wb");
            ok = ok && f != NULL;
            if (f) {
                ok = ok && write_row_of_len(f, 1785391000LL, 3200001,
                                            TIP_AGREEMENT_TAIL_BYTES + 20000,
                                            true);
                ok = ok && write_row_of_len(f, 1785391060LL, 3200002, SHORT_ROW,
                                            true);
                fclose(f);
            }
            ok = ok && tip_agreement_read_ledger(path, &rep);
            /* was present=false: nothing at all was scanned */
            ok = ok && rep.present;
            ok = ok && rep.rows_scanned == 1;
            ok = ok && rep.height == 3200002;    /* the real row survived */
            ok = ok && rep.last_ts == 1785391060LL;
            /* the fragment is a fragment, not a malformed row: its true length
             * is unknown, so counting it would invent a defect */
            ok = ok && rep.malformed_rows == 0;
            ok = ok && rep.incomplete_rows == 0;
        }

        /* (g3) A torn final line must never become "the" sample. It used to
         * reach the callback, so a half-written append silently supplied the
         * height, the hashes and the outcome of the current sample. */
        {
            FILE *f = fopen(path, "wb");
            ok = ok && f != NULL;
            if (f) {
                ok = ok && write_row_of_len(f, 1785392000LL, 3300001, SHORT_ROW,
                                            true);
                /* caught mid-append: no trailing newline */
                ok = ok && write_row_of_len(f, 1785392060LL, 3300002,
                                            SHORT_ROW, false);
                fclose(f);
            }
            ok = ok && tip_agreement_read_ledger(path, &rep);
            ok = ok && rep.rows_scanned == 1;
            ok = ok && rep.height == 3300001;    /* the COMPLETE row */
            ok = ok && rep.last_ts == 1785392000LL;
            /* counted, and counted honestly: not malformed, not a sample */
            ok = ok && rep.incomplete_rows == 1;
            ok = ok && rep.malformed_rows == 0;
        }

        /* (g4) AND THE LENGTH CHECK DID NOT GO SOFT. A row genuinely longer
         * than EVIDENCE_ROW_MAX is still refused and still counted malformed,
         * and its tail is still consumed rather than folded in as a second
         * phantom row. */
        {
            FILE *f = fopen(path, "wb");
            ok = ok && f != NULL;
            if (f) {
                ok = ok && write_row_of_len(f, 1785393000LL, 3400001, SHORT_ROW,
                                            true);
                ok = ok && write_row_of_len(f, 1785393060LL, 3400002,
                                            EVIDENCE_ROW_MAX + 1, true);
                ok = ok && write_row_of_len(f, 1785393120LL, 3400003, 9000,
                                            true);
                ok = ok && write_row_of_len(f, 1785393180LL, 3400004, SHORT_ROW,
                                            true);
                fclose(f);
            }
            ok = ok && tip_agreement_read_ledger(path, &rep);
            ok = ok && rep.rows_scanned == 2;    /* only the two short rows */
            /* one just over the bound, one far over */
            ok = ok && rep.malformed_rows == 2;
            ok = ok && rep.incomplete_rows == 0;
            ok = ok && rep.height == 3400004;
        }

        /* (g5) AN EMBEDDED NUL IN ONE ROW MUST NOT COST THE NEXT ROW.
         * A torn append does not always end the file — the filesystem can
         * allocate the block and lose the data, so the row reads back with a
         * NUL in the middle of otherwise perfect JSON and its newline still
         * on the end. The scanner used to find its row boundaries with
         * strlen(), which stops at that NUL: the line looked unterminated, so
         * the reader armed its consume-the-rest-of-the-line state even though
         * fgets() had already eaten the newline, and the NEXT line — a
         * complete, valid, uncorrupted row — was swallowed as that phantom
         * tail. One NUL cost two rows and the second loss was counted in
         * neither counter (reproduced: 1 row scanned, incomplete=1, third row
         * gone silently). Row boundaries are byte-counted now, so a NUL
         * disqualifies its own row and reaches no further. */
        {
            char corrupt[2048];
            row(corrupt, sizeof(corrupt), 1785394060LL, "agrees", 2, 3500002,
                HASH_A, HASH_A, 4, 0, "nul_fixture");
            size_t clen = strlen(corrupt);       /* includes the newline */
            ok = ok && clen > 40 && corrupt[clen - 1] == '\n';
            /* mid-content, nowhere near the terminator */
            corrupt[clen / 2] = '\0';

            FILE *f = fopen(path, "wb");
            ok = ok && f != NULL;
            if (f) {
                ok = ok && write_row_of_len(f, 1785394000LL, 3500001,
                                            SHORT_ROW, true);
                ok = ok && fwrite(corrupt, 1, clen, f) == clen;
                ok = ok && write_row_of_len(f, 1785394120LL, 3500003,
                                            SHORT_ROW, true);
                fclose(f);
            }
            ok = ok && tip_agreement_read_ledger(path, &rep);
            ok = ok && rep.present;
            /* the two intact rows, and only those two */
            ok = ok && rep.rows_scanned == 2;
            /* THE ACCEPTANCE BAR: the row after the corrupt one survived and
             * is the sample, so a lost NUL cannot silently freeze this report
             * on the row before the corruption. */
            ok = ok && rep.height == 3500003;
            ok = ok && rep.last_ts == 1785394120LL;
            /* the corrupt row is counted, and counted as what it is: a write
             * that did not all land, not a foreign row shape */
            ok = ok && rep.incomplete_rows == 1;
            ok = ok && rep.malformed_rows == 0;
        }

        unlink(path);
        rmdir(dir);
        TAW_CHECK("the tail read keeps every real row and no invented one", ok);
    }

    return failures;
}
