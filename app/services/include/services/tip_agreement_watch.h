/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * tip_agreement_watch — the in-node READER of the OFF-HOST TIP-HASH
 * AGREEMENT ledger written by tools/scripts/tip_agreement_probe.sh, so the
 * one piece of genuinely off-host block-identity evidence this stack holds is
 * visible from the typed interface
 * (`z23 ops state --subsystem=tip_agreement`) instead of existing only
 * as a file nobody opened.
 *
 * WHAT IT ANSWERS, in one sentence: at the height last compared, was OUR tip
 * hash the same 32 bytes as the modal tip hash reported by remote peers, and
 * how many DISTINCT remote hosts backed that mode?
 *
 * WHY THAT QUESTION NEEDS ASKING. Every parity reference that predates the
 * recorder dials the loopback address: the reference-oracle service and
 * app/services/src/utxo_parity_service.c (PARITY_RPC_DEFAULT_HOST) both read
 * the co-located legacy reference node on THIS box — same disk, same clock,
 * same operator, same binary lineage. docs/HANDOFF.md says so plainly and that
 * paragraph stands. This is the first rung that compares a BLOCK HASH against
 * genuinely remote machines.
 *
 * ══ REPORTER ONLY — the load-bearing contract ══
 * This module NEVER grades. It cannot mint an agreement claim, cannot clear
 * one, is not wired into the architecture score, the MVP scoreboard, the
 * health rollup, or any Condition/blocker. tools/scripts/tip_agreement_judge.sh
 * is the judge; this describes what the judge will read. Two reasons, both
 * learned the hard way here:
 *   1. Cloning. The ledger file is the ONE authority. Latching a copy of its
 *      state into node memory would create a second ledger that can drift —
 *      the recurring defect docs/ARCHITECTURE_NORTH_STAR.md names, whose fix
 *      is always deleting a copy, never adding a reconciler. So every call
 *      re-reads the file; nothing is cached, nothing is latched.
 *   2. Standing. The evidence is about remote peers, recorded out of process.
 *      A blocker minted from it would be this process paging about a claim it
 *      did not observe.
 *
 * NO supervised child is armed. The cadence belongs to the systemd timer that
 * writes the ledger (deploy/zclassic23-tip-agreement.timer, every 10 min);
 * there is no in-process work to tick, so there is no liveness contract and
 * therefore no progress policy to declare. (A supervised child with no
 * declared policy is a defect counted by check-supervisor-progress-declared —
 * the correct answer here is to register nothing, not to register something
 * and call it exempt.)
 *
 * ══ INDEPENDENCE IS THE WHOLE POINT ══
 * An agreement claim backed by ONE peer must not read like one backed by
 * twenty, and a peer that is not an independent source must not read like one
 * at all. Measured against the live node on 2026-07-30: of 21 connected
 * peers exactly ONE was surfacing a tip hash, and it was the operator's OWN
 * second server. That is zero independent witnesses, and
 * the honest report is a refusal, not a verdict.
 *
 * So a sample is graded here in this ORDER, and the order is the contract:
 *   1. independence FIRST. Fewer distinct remote hosts behind the modal hash
 *      than REQUIRED ⇒ TIP_AGREEMENT_INSUFFICIENT_TOKEN. No verdict, in either
 *      direction. What is required is the HIGHER of two numbers, and that is
 *      the load-bearing part: the control the recorder had in force
 *      (`min_distinct_peers`) and TIP_AGREEMENT_MIN_DISTINCT_PEERS, the floor
 *      this build will not go below. The floor exists because the recorded
 *      control is a field of the row being graded — a row written with
 *      ZCL_PARITY_MIN_DISTINCT_PEERS=1, copied in from elsewhere, or crafted,
 *      would otherwise get to set its own bar and pass at one backing peer,
 *      which is the exact failure this module was built to make impossible.
 *      An unreadable control (< 1) still counts as unreadable, never as
 *      satisfied. A control STRONGER than the floor is honoured as written.
 *   2. hash equality SECOND, checked against the recorded bytes rather than
 *      trusted from the recorded `outcome`. A row whose outcome says "agrees"
 *      while its our_tip_hash and modal_remote_hash differ is a CONTRADICTION
 *      and reports TIP_AGREEMENT_CONTRADICTION_TOKEN — never agreement.
 *   3. only then may the recorded outcome speak.
 * tip_agreement_reports_agreement() is the single predicate that encodes all
 * three; the summary text and the typed dump both call it rather than
 * re-deriving, so there is one place agreement can be claimed.
 *
 * A DISAGREEING sample is a valid and important row and is reported as such.
 * Suppressing it would be the defect, not the news.
 *
 * Absence is data, never an error. A missing ledger means the recorder was
 * never installed on this host (`make install-tip-agreement`); the report says
 * present=false and claims nothing. "The timer died" is the judge's STALE
 * rung, not this one.
 *
 * Ledger contract — one flock-appended flat JSON object per line; the full
 * field list is in tools/scripts/tip_agreement_probe.sh. Fields read here:
 *   ts our_height height our_tip_hash modal_remote_hash modal_remote_peers
 *   modal_remote_groups disagreeing_peers contested_peers peers_usable
 *   min_distinct_peers excluded_hosts outcome reason
 * Rows written before a field existed read as unknown (-1 / empty), never as
 * a zero that looks like a measurement.
 *
 * Env (the SAME variable the recorder script reads, so a reader can never be
 * pointed at a different file than the writer):
 *   ZCL_PARITY_LEDGER_DIR   default $HOME/.local/state/zclassic23-parity
 *
 * Pure file-scan observer: no DB, no threads, no chain locks, no allocation,
 * nothing latched. Reentrant-safe. */

#ifndef ZCL_SERVICES_TIP_AGREEMENT_WATCH_H
#define ZCL_SERVICES_TIP_AGREEMENT_WATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 32-byte block hash as hex, + NUL. */
#define TIP_AGREEMENT_HASH_MAX     65
#define TIP_AGREEMENT_REASON_MAX  192
#define TIP_AGREEMENT_SUMMARY_MAX 448

/* Bounded tail read: one short line per 10-minute run, so 256 KiB is
 * thousands of rows — far more than the judge's 24h window. */
#define TIP_AGREEMENT_TAIL_BYTES (256u * 1024u)

/* THE FLOOR on distinct remote hosts behind the modal hash, below which this
 * build will not grade a sample independent no matter what the row says about
 * itself. Same number as DEF_MIN_DISTINCT_PEERS in
 * tools/scripts/tip_agreement_judge.sh, and for the same stated reason: one
 * peer must never be able to manufacture agreement. May be raised, never
 * lowered. */
#define TIP_AGREEMENT_MIN_DISTINCT_PEERS 2

/* The exact refusal tokens. Asserted verbatim by
 * lib/test/src/test_tip_agreement_watch.c: a refusal that fires for an
 * unrelated downstream reason has already fooled this project once, so the
 * tests pin the STRING, not merely the absence of agreement. */
#define TIP_AGREEMENT_INSUFFICIENT_TOKEN "insufficient_independent_peers"
#define TIP_AGREEMENT_CONTRADICTION_TOKEN "agrees_row_hash_mismatch"

/* The recorded outcome of one sample. UNKNOWN covers both "no outcome field"
 * and "an outcome this build does not recognise" — an unknown state is never
 * dropped into the could-not-ask bucket, because dropping it is how a future
 * recorder bug becomes an invisible one. */
enum tip_agreement_outcome {
    TIP_AGREEMENT_OUTCOME_UNKNOWN = 0,
    TIP_AGREEMENT_OUTCOME_AGREES,
    TIP_AGREEMENT_OUTCOME_DISAGREES,
    TIP_AGREEMENT_OUTCOME_COULD_NOT_ASK
};

/* Whether the sample carries enough DISTINCT remote hosts behind the modal
 * hash to be allowed to say anything at all. */
enum tip_agreement_independence {
    /* The control itself was unreadable (no min_distinct_peers, or <= 0). A
     * control we cannot read is not a control. */
    TIP_AGREEMENT_INDEPENDENCE_UNKNOWN = 0,
    /* Measured and below the control — includes "nobody counted" (null). */
    TIP_AGREEMENT_INDEPENDENCE_INSUFFICIENT,
    TIP_AGREEMENT_INDEPENDENCE_SUFFICIENT
};

/* Every int64 field is -1 when the ledger said null / the field was absent. */
struct tip_agreement_report {
    bool     present;             /* >= 1 usable row found */
    unsigned rows_scanned;        /* usable rows in the scanned tail */
    unsigned malformed_rows;      /* rows with no `outcome` field at all, plus
                                   * rows too long to be an evidence row */
    unsigned incomplete_rows;     /* lines that ended with no newline: a torn
                                   * append, dropped rather than folded in as
                                   * the last sample. Not malformed — the bytes
                                   * may be a good row that is not all there
                                   * yet. Only the tail read can see these. */
    unsigned unknown_outcome_rows;/* outcome present but unrecognised */

    /* Rollup over the scanned tail. Recomputed every call from the `outcome`
     * values; no recorded summary field is trusted. */
    unsigned agrees;
    unsigned disagrees;
    unsigned could_not_ask;
    int64_t  last_agree_ts;
    int64_t  last_disagree_ts;

    /* The LAST usable row, verbatim. */
    int64_t  last_ts;
    int64_t  our_height;
    int64_t  height;              /* the height actually compared */
    char     our_tip_hash[TIP_AGREEMENT_HASH_MAX];
    char     modal_remote_hash[TIP_AGREEMENT_HASH_MAX];
    int64_t  modal_remote_peers;  /* DISTINCT remote hosts behind the mode */
    int64_t  modal_remote_groups; /* distinct /16 address groups behind it */
    int64_t  disagreeing_peers;   /* remote hosts holding a different hash */
    int64_t  contested_peers;     /* those meeting the control themselves */
    int64_t  peers_usable;        /* hosts that surfaced ANY hash */
    int64_t  min_distinct_peers;  /* the control IN FORCE for that sample */
    int64_t  excluded_hosts;      /* operator-owned hosts discarded first */
    enum tip_agreement_outcome outcome;
    char     reason[TIP_AGREEMENT_REASON_MAX];

    /* Derived here, in the documented order. */
    enum tip_agreement_independence independence;
    bool     hashes_match;        /* both hashes present and byte-equal
                                   * (case-insensitive hex) */
};

/* How many distinct remote hosts a sample recording `min_distinct_peers` must
 * actually have behind its modal hash: the HIGHER of that recorded control and
 * TIP_AGREEMENT_MIN_DISTINCT_PEERS. Returns -1 when the recorded control is
 * unreadable (< 1), because a row that never said which floor was in force
 * cannot testify that any floor was — that case refuses rather than borrowing
 * the shipped number. Never returns 0, and never returns less than the floor
 * for a readable control. */
int64_t tip_agreement_required_distinct_peers(int64_t min_distinct_peers);

/* Independence of one sample. `modal_remote_peers` < 0 means the recorder did
 * not count (null) and is INSUFFICIENT, never a pass. `min_distinct_peers`
 * < 1 or unknown (< 0) is INDEPENDENCE_UNKNOWN — which
 * tip_agreement_reports_agreement() also refuses. Otherwise SUFFICIENT needs
 * `modal_remote_peers` >= tip_agreement_required_distinct_peers(): the row's
 * own recorded control CANNOT lower the bar below
 * TIP_AGREEMENT_MIN_DISTINCT_PEERS, only raise it. */
enum tip_agreement_independence
tip_agreement_classify_independence(int64_t modal_remote_peers,
                                    int64_t min_distinct_peers);

/* THE single place agreement may be claimed. True only when ALL hold:
 *   the report has a usable row, independence == SUFFICIENT, both hashes are
 *   present and byte-equal, and the recorded outcome is AGREES.
 * NULL reads as false. */
bool tip_agreement_reports_agreement(const struct tip_agreement_report *r);

/* Human name of the outcome / independence enums ("agrees", "sufficient"...).
 * Never NULL. */
const char *tip_agreement_outcome_name(enum tip_agreement_outcome o);
const char *tip_agreement_independence_name(enum tip_agreement_independence i);

/* One operator-readable line. Emits TIP_AGREEMENT_INSUFFICIENT_TOKEN or
 * TIP_AGREEMENT_CONTRADICTION_TOKEN in place of any verdict when those apply,
 * and never says "agrees" unless tip_agreement_reports_agreement() does.
 * Always NUL-terminates; returns buf. */
const char *tip_agreement_summary_text(const struct tip_agreement_report *r,
                                       char *buf, size_t cap);

/* Scan an in-memory ledger tail (newline-separated JSON rows). Pure: no IO,
 * no clock. Returns false only on bad arguments. */
bool tip_agreement_scan(const char *text, size_t len,
                        struct tip_agreement_report *out);

/* Read the trailing TIP_AGREEMENT_TAIL_BYTES of `path` and scan it. A
 * missing/empty/unreadable file is NOT a failure: out->present is false and
 * the call still returns true. Returns false only on bad arguments. */
bool tip_agreement_read_ledger(const char *path,
                               struct tip_agreement_report *out);

/* Resolve the ledger path from ZCL_PARITY_LEDGER_DIR / $HOME. Returns false
 * when neither is available or the path would not fit. */
bool tip_agreement_resolve_ledger(char *out, size_t cap);

/* See CLAUDE.md "Adding state introspection". Reentrant-safe.
 * key: NULL/"" for the whole report; "last" for the last sample only. */
struct json_value;
bool tip_agreement_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_SERVICES_TIP_AGREEMENT_WATCH_H */
