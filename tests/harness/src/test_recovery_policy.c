/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the recovery_policy module.
 *
 * These tests are pure (no SQLite / no chain state) because the policy
 * module deliberately has no dependencies on them — it is a decision
 * gate, not a mutation. Every test builds a fresh `struct recovery_policy`
 * on the stack, drives `policy_check_*` with specific inputs, and
 * asserts both the returned decision and the event(s) it produced.
 *
 * Event assertions use a local sync observer registered for the three
 * recovery_policy events; the observer increments per-decision counters
 * so individual tests can verify "this call produced exactly one ALLOW".
 *
 * The operator-ack-file behaviour is covered with a temp file: the test
 * points `operator_ack_file` at it, runs the check, reads the file back,
 * and asserts the contents. The operator-prompt hook is covered with a
 * tiny mock function.
 */

#include "test/test_core.h"
#include "services/recovery_policy.h"
#include "event/event.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Ack files are real files that these tests write, read back, and unlink.
 * At a fixed /tmp path a second copy of the suite would unlink one between
 * this run's write and its read-back, so every ack path is per-process. */
static const char *rp_ack_path(char *buf, size_t n, const char *tag)
{
    mkdir("test-tmp", 0755);
    test_fmt_tmpdir(buf, n, "rp_ack", tag);
    return buf;
}

/* ── Event counters (sync observer) ──────────────────────────── */

static _Atomic int g_ev_allow;
static _Atomic int g_ev_refused;
static _Atomic int g_ev_prompt;

static void rp_ev_observer(enum event_type type, uint32_t peer_id,
                            const void *payload, uint32_t payload_len,
                            void *ctx)
{
    (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    switch (type) {
    case EV_RECOVERY_POLICY_ALLOW:   atomic_fetch_add(&g_ev_allow,   1); break;
    case EV_RECOVERY_POLICY_REFUSED: atomic_fetch_add(&g_ev_refused, 1); break;
    case EV_RECOVERY_POLICY_PROMPT:  atomic_fetch_add(&g_ev_prompt,  1); break;
    default: break;
    }
}

static void rp_install_observer(void)
{
    event_clear_observers(EV_RECOVERY_POLICY_ALLOW);
    event_clear_observers(EV_RECOVERY_POLICY_REFUSED);
    event_clear_observers(EV_RECOVERY_POLICY_PROMPT);
    atomic_store(&g_ev_allow,   0);
    atomic_store(&g_ev_refused, 0);
    atomic_store(&g_ev_prompt,  0);
    event_observe(EV_RECOVERY_POLICY_ALLOW,   rp_ev_observer, NULL);
    event_observe(EV_RECOVERY_POLICY_REFUSED, rp_ev_observer, NULL);
    event_observe(EV_RECOVERY_POLICY_PROMPT,  rp_ev_observer, NULL);
}

#define RP_RUN(name, expr) do { \
    printf("%s... ", (name));   \
    bool _ok = (expr);          \
    if (_ok) printf("OK\n");    \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── Hooks used in a few of the tests ───────────────────────── */

static bool rp_backup_yes(void *ctx) { (void)ctx; return true; }
static bool rp_backup_no (void *ctx) { (void)ctx; return false; }

static _Atomic int g_prompt_hook_calls;
static bool rp_prompt_accept(const char *ack, const char *reason, void *ctx)
{
    (void)ack; (void)reason; (void)ctx;
    atomic_fetch_add(&g_prompt_hook_calls, 1);
    return true;
}
static bool rp_prompt_reject(const char *ack, const char *reason, void *ctx)
{
    (void)ack; (void)reason; (void)ctx;
    atomic_fetch_add(&g_prompt_hook_calls, 1);
    return false;
}

/* ── 1. Defaults ─────────────────────────────────────────────── */

static int t_defaults(void)
{
    int failures = 0;
    struct recovery_policy p;
    policy_set_defaults(&p);
    bool ok =
        p.max_utxo_wipe_rows == RECOVERY_POLICY_DEFAULT_MAX_UTXO_WIPE_ROWS &&
        p.max_block_rollback == RECOVERY_POLICY_DEFAULT_MAX_BLOCK_ROLLBACK &&
        p.max_header_rewind  == RECOVERY_POLICY_DEFAULT_MAX_HEADER_REWIND  &&
        p.require_backup_verified == false &&
        p.dry_run == false &&
        p.operator_ack_file != NULL &&
        p.backup_verified_fn == NULL &&
        p.operator_prompt_fn == NULL;
    RP_RUN("rp: defaults populate every field", ok);
    return failures;
}

/* ── 2. Env load overrides ──────────────────────────────────── */

static int t_env_overrides(void)
{
    int failures = 0;
    setenv("ZCL_MAX_UTXO_WIPE_ROWS",       "42",   1);
    setenv("ZCL_MAX_BLOCK_ROLLBACK",       "7",    1);
    setenv("ZCL_MAX_HEADER_REWIND",        "99",   1);
    setenv("ZCL_REQUIRE_BACKUP_VERIFIED",  "yes",  1);
    setenv("ZCL_DRY_RUN",                  "1",    1);
    char ack[512];
    rp_ack_path(ack, sizeof(ack), "env_override");
    setenv("ZCL_OPERATOR_ACK_FILE",        ack,    1);

    struct recovery_policy p;
    policy_load_from_env(&p);

    bool ok =
        p.max_utxo_wipe_rows == 42 &&
        p.max_block_rollback == 7 &&
        p.max_header_rewind  == 99 &&
        p.require_backup_verified == true &&
        p.dry_run == true &&
        p.operator_ack_file != NULL &&
        strcmp(p.operator_ack_file, ack) == 0;
    RP_RUN("rp: load_from_env applies all six overrides", ok);

    unsetenv("ZCL_MAX_UTXO_WIPE_ROWS");
    unsetenv("ZCL_MAX_BLOCK_ROLLBACK");
    unsetenv("ZCL_MAX_HEADER_REWIND");
    unsetenv("ZCL_REQUIRE_BACKUP_VERIFIED");
    unsetenv("ZCL_DRY_RUN");
    unsetenv("ZCL_OPERATOR_ACK_FILE");
    return failures;
}

static int t_env_malformed_falls_back(void)
{
    int failures = 0;
    setenv("ZCL_MAX_UTXO_WIPE_ROWS", "garbage", 1);
    setenv("ZCL_DRY_RUN",            "maybe",   1);
    struct recovery_policy p;
    policy_load_from_env(&p);
    bool ok =
        p.max_utxo_wipe_rows == RECOVERY_POLICY_DEFAULT_MAX_UTXO_WIPE_ROWS &&
        p.dry_run == false;
    RP_RUN("rp: malformed env values fall back to defaults", ok);
    unsetenv("ZCL_MAX_UTXO_WIPE_ROWS");
    unsetenv("ZCL_DRY_RUN");
    return failures;
}

/* ── 3. UTXO wipe: allow under cap ──────────────────────────── */

static int t_utxo_wipe_allow(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    enum policy_decision d =
        policy_check_utxo_wipe(&p, 500, "test.under_cap");
    bool ok = d == POLICY_ALLOW &&
              atomic_load(&g_ev_allow) == 1 &&
              atomic_load(&g_ev_refused) == 0 &&
              atomic_load(&g_ev_prompt) == 0;
    RP_RUN("rp: utxo wipe under cap returns ALLOW + emits allow event", ok);
    return failures;
}

/* ── 4. UTXO wipe: refuse over cap, no prompt hook ──────────── */

static int t_utxo_wipe_refuse_too_large(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    /* Point ack file somewhere harmless; there's no prompt hook so the
     * decision must be REFUSE_TOO_LARGE regardless of the file. */
    char ack[512];
    p.operator_ack_file = rp_ack_path(ack, sizeof(ack), "refuse");
    unlink(p.operator_ack_file);
    enum policy_decision d =
        policy_check_utxo_wipe(&p, 5000, "test.over_cap");
    bool ok = d == POLICY_REFUSE_TOO_LARGE &&
              atomic_load(&g_ev_refused) == 1 &&
              atomic_load(&g_ev_allow)   == 0;
    RP_RUN("rp: utxo wipe over cap w/o hook returns REFUSE_TOO_LARGE", ok);
    unlink(ack);
    return failures;
}

/* ── 5. UTXO wipe: exactly at cap is allowed ────────────────── */

static int t_utxo_wipe_boundary(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    enum policy_decision d =
        policy_check_utxo_wipe(&p, p.max_utxo_wipe_rows, "test.boundary");
    bool ok = d == POLICY_ALLOW && atomic_load(&g_ev_allow) == 1;
    RP_RUN("rp: amount == cap is ALLOW (inclusive boundary)", ok);
    return failures;
}

/* ── 6. Dry run refuses everything ──────────────────────────── */

static int t_dry_run_refuses_even_small(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    p.dry_run = true;
    enum policy_decision d =
        policy_check_utxo_wipe(&p, 1, "test.dry_run_tiny");
    bool ok = d == POLICY_REFUSE_DRY_RUN &&
              atomic_load(&g_ev_refused) == 1;
    RP_RUN("rp: dry_run refuses even a 1-row wipe", ok);
    return failures;
}

/* ── 7. Backup verification required, absent → refuse ──────── */

static int t_backup_required_absent(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    p.require_backup_verified = true;
    p.backup_verified_fn = rp_backup_no;
    enum policy_decision d =
        policy_check_utxo_wipe(&p, 500, "test.backup_absent");
    bool ok = d == POLICY_REFUSE_NO_BACKUP &&
              atomic_load(&g_ev_refused) == 1;
    RP_RUN("rp: require_backup with no hook result returns REFUSE_NO_BACKUP", ok);
    return failures;
}

/* ── 8. Backup verification required, present → allow ──────── */

static int t_backup_required_present(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    p.require_backup_verified = true;
    p.backup_verified_fn = rp_backup_yes;
    enum policy_decision d =
        policy_check_utxo_wipe(&p, 500, "test.backup_present");
    bool ok = d == POLICY_ALLOW && atomic_load(&g_ev_allow) == 1;
    RP_RUN("rp: require_backup with verified hook returns ALLOW", ok);
    return failures;
}

/* ── 9. Operator prompt accepts → allow + ack file written ─── */

static int t_operator_prompt_accepts(void)
{
    int failures = 0;
    rp_install_observer();
    atomic_store(&g_prompt_hook_calls, 0);

    struct recovery_policy p;
    policy_set_defaults(&p);
    char ackbuf[512];
    const char *ack = rp_ack_path(ackbuf, sizeof(ackbuf), "prompt_accept");
    unlink(ack);
    p.operator_ack_file = ack;
    p.operator_prompt_fn = rp_prompt_accept;

    enum policy_decision d =
        policy_check_utxo_wipe(&p, 10000, "test.prompt_accept");

    /* Ack file must exist and contain the reason. */
    FILE *f = fopen(ack, "r");
    char buf[256] = {0};
    if (f) { fread(buf, 1, sizeof(buf) - 1, f); fclose(f); }

    bool ok = d == POLICY_ALLOW &&
              atomic_load(&g_ev_allow) == 1 &&
              atomic_load(&g_prompt_hook_calls) == 1 &&
              strstr(buf, "utxo_wipe") != NULL &&
              strstr(buf, "test.prompt_accept") != NULL;
    RP_RUN("rp: prompt hook accepting over-cap wipe yields ALLOW", ok);
    unlink(ack);
    return failures;
}

/* ── 10. Operator prompt rejects → PROMPT_OPERATOR ─────────── */

static int t_operator_prompt_rejects(void)
{
    int failures = 0;
    rp_install_observer();
    atomic_store(&g_prompt_hook_calls, 0);

    struct recovery_policy p;
    policy_set_defaults(&p);
    char ackbuf[512];
    const char *ack = rp_ack_path(ackbuf, sizeof(ackbuf), "prompt_reject");
    unlink(ack);
    p.operator_ack_file = ack;
    p.operator_prompt_fn = rp_prompt_reject;

    enum policy_decision d =
        policy_check_utxo_wipe(&p, 10000, "test.prompt_reject");

    bool ok = d == POLICY_PROMPT_OPERATOR &&
              atomic_load(&g_ev_prompt) == 1 &&
              atomic_load(&g_ev_allow) == 0 &&
              atomic_load(&g_prompt_hook_calls) == 1;
    RP_RUN("rp: prompt hook rejecting yields POLICY_PROMPT_OPERATOR", ok);
    unlink(ack);
    return failures;
}

/* ── 11. NULL / empty reason is REFUSE_INVALID ─────────────── */

static int t_null_reason_invalid(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    enum policy_decision d_null  = policy_check_utxo_wipe(&p, 10, NULL);
    enum policy_decision d_empty = policy_check_utxo_wipe(&p, 10, "");
    bool ok = d_null  == POLICY_REFUSE_INVALID &&
              d_empty == POLICY_REFUSE_INVALID &&
              atomic_load(&g_ev_refused) == 2;
    RP_RUN("rp: NULL / empty reason returns REFUSE_INVALID", ok);
    return failures;
}

/* ── 12. NULL policy is REFUSE_INVALID ─────────────────────── */

static int t_null_policy(void)
{
    int failures = 0;
    rp_install_observer();
    enum policy_decision d = policy_check_utxo_wipe(NULL, 10, "test.null");
    bool ok = d == POLICY_REFUSE_INVALID;
    RP_RUN("rp: NULL policy returns REFUSE_INVALID", ok);
    return failures;
}

/* ── 13. Negative amount is REFUSE_INVALID ─────────────────── */

static int t_negative_amount_invalid(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    enum policy_decision d = policy_check_utxo_wipe(&p, -5, "test.neg");
    bool ok = d == POLICY_REFUSE_INVALID;
    RP_RUN("rp: negative amount returns REFUSE_INVALID", ok);
    return failures;
}

/* ── 14. block_rollback: forwards rollback is invalid ──────── */

static int t_rollback_forwards_invalid(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    /* from < to → negative depth */
    enum policy_decision d =
        policy_check_block_rollback(&p, 100, 200, "test.forwards");
    bool ok = d == POLICY_REFUSE_INVALID;
    RP_RUN("rp: rollback with to > from returns REFUSE_INVALID", ok);
    return failures;
}

/* ── 15. block_rollback: allow within depth, refuse beyond ─── */

static int t_rollback_depth_gate(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    /* Default max_block_rollback is 100 */
    enum policy_decision shallow =
        policy_check_block_rollback(&p, 1000, 950, "test.shallow");
    enum policy_decision deep =
        policy_check_block_rollback(&p, 1000, 500, "test.deep");
    bool ok = shallow == POLICY_ALLOW &&
              deep    == POLICY_REFUSE_TOO_LARGE &&
              atomic_load(&g_ev_allow)   == 1 &&
              atomic_load(&g_ev_refused) == 1;
    RP_RUN("rp: rollback depth gate allows shallow, refuses deep", ok);
    return failures;
}

/* ── 16. header_rewind: uses its own cap ────────────────────── */

static int t_header_rewind_uses_own_cap(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    /* Default max_header_rewind is 1000 (≠ block_rollback's 100).
     * An amount of 500 should ALLOW header_rewind but REFUSE
     * block_rollback — proves the caps are independent. */
    enum policy_decision hr =
        policy_check_header_rewind(&p, 500, "test.hr");
    enum policy_decision br =
        policy_check_block_rollback(&p, 1000, 500, "test.br");
    bool ok = hr == POLICY_ALLOW &&
              br == POLICY_REFUSE_TOO_LARGE;
    RP_RUN("rp: header_rewind uses max_header_rewind, not max_block_rollback", ok);
    return failures;
}

/* ── 17. Dry run wins over backup check ─────────────────────── */

static int t_dry_run_trumps_backup(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    p.dry_run = true;
    p.require_backup_verified = true;
    p.backup_verified_fn = rp_backup_yes;
    enum policy_decision d =
        policy_check_utxo_wipe(&p, 10, "test.dry_and_backup");
    bool ok = d == POLICY_REFUSE_DRY_RUN;
    RP_RUN("rp: dry_run takes precedence over backup verification", ok);
    return failures;
}

/* ── 18. decision_name covers every code ────────────────────── */

static int t_decision_names(void)
{
    int failures = 0;
    bool ok = true;
    for (int i = 0; i < POLICY_NUM_DECISIONS; i++) {
        const char *n = policy_decision_name((enum policy_decision)i);
        if (!n || !*n || strcmp(n, "unknown") == 0) { ok = false; break; }
    }
    /* Out-of-range returns "unknown" rather than segfault. */
    if (strcmp(policy_decision_name(
        (enum policy_decision)(POLICY_NUM_DECISIONS + 1)), "unknown") != 0)
        ok = false;
    RP_RUN("rp: policy_decision_name covers every code", ok);
    return failures;
}

/* ── 19. Dry run still emits REFUSED event (observability) ── */

static int t_dry_run_event(void)
{
    int failures = 0;
    rp_install_observer();
    struct recovery_policy p;
    policy_set_defaults(&p);
    p.dry_run = true;
    (void)policy_check_utxo_wipe(&p, 100, "test.dry_obs");
    bool ok = atomic_load(&g_ev_refused) == 1 &&
              atomic_load(&g_ev_allow)   == 0;
    RP_RUN("rp: dry_run refusal still emits REFUSED event", ok);
    return failures;
}

/* ── 20. Prompt hook NOT called when under cap ─────────────── */

static int t_hook_not_called_under_cap(void)
{
    int failures = 0;
    rp_install_observer();
    atomic_store(&g_prompt_hook_calls, 0);

    struct recovery_policy p;
    policy_set_defaults(&p);
    p.operator_prompt_fn = rp_prompt_accept;
    char ack[512];
    p.operator_ack_file = rp_ack_path(ack, sizeof(ack), "under_cap");
    unlink(p.operator_ack_file);

    enum policy_decision d =
        policy_check_utxo_wipe(&p, 100, "test.under_cap_hook");

    /* Under cap → ALLOW directly, hook must not have been called. */
    bool ok = d == POLICY_ALLOW &&
              atomic_load(&g_prompt_hook_calls) == 0;
    RP_RUN("rp: prompt hook is only consulted when over cap", ok);
    return failures;
}

/* ── Aggregator ─────────────────────────────────────────────── */

int test_recovery_policy(void)
{
    printf("\n=== Recovery policy tests ===\n");
    int failures = 0;
    failures += t_defaults();
    failures += t_env_overrides();
    failures += t_env_malformed_falls_back();
    failures += t_utxo_wipe_allow();
    failures += t_utxo_wipe_refuse_too_large();
    failures += t_utxo_wipe_boundary();
    failures += t_dry_run_refuses_even_small();
    failures += t_backup_required_absent();
    failures += t_backup_required_present();
    failures += t_operator_prompt_accepts();
    failures += t_operator_prompt_rejects();
    failures += t_null_reason_invalid();
    failures += t_null_policy();
    failures += t_negative_amount_invalid();
    failures += t_rollback_forwards_invalid();
    failures += t_rollback_depth_gate();
    failures += t_header_rewind_uses_own_cap();
    failures += t_dry_run_trumps_backup();
    failures += t_decision_names();
    failures += t_dry_run_event();
    failures += t_hook_not_called_under_cap();

    /* Clean up observers so subsequent test groups see an empty table. */
    event_clear_observers(EV_RECOVERY_POLICY_ALLOW);
    event_clear_observers(EV_RECOVERY_POLICY_REFUSED);
    event_clear_observers(EV_RECOVERY_POLICY_PROMPT);
    return failures;
}
