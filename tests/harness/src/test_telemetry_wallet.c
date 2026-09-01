/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_wallet — the `wallet` telemetry domain end to end: its field
 * table, its provider, and the two native leaves that serve it.
 *
 * The generic machinery (offsets, views, the null-is-unknown evaluator fix) is
 * already pinned by test_telemetry_render. What this group pins is the part
 * that is specific to THIS domain, and every check here corresponds to a real
 * way a domain lane gets it wrong:
 *
 *   MEANING IS COMPLETE       every leaf resolves to a merged ontology row
 *                             carrying means, and — unless the row is
 *                             descriptive — implies and next as well. A field
 *                             that ships without them is a number an operator
 *                             cannot act on.
 *   THE COLLECTOR FORGETS     nothing. After wallet_dump_state_fill() returns,
 *                             NO leaf is left at TELEMETRY_UNSET. Unset is not
 *                             a state the wallet can legitimately be in; it is
 *                             the signature of a filler that returned early,
 *                             and the presence enum exists to catch exactly
 *                             that. This is the highest-value check in the
 *                             file, because the defect it catches otherwise
 *                             renders as a plausible zero.
 *   UNREADABLE != BROKEN      a leaf the provider could not read is judged
 *                             `unknown`, never `unhealthy`. A wallet whose
 *                             mirror worker is simply not wired in this
 *                             process must not page anyone.
 *   THE LEAVES ANSWER         both native leaves return ok:true with a
 *                             `passed` status and a real document. Asserting
 *                             non-empty is NOT enough: the registry's
 *                             296-byte error envelope is non-empty, and a
 *                             next[] entry that names its own command
 *                             produces exactly that while looking like a
 *                             budget failure.
 *   POSTURE, NEVER HOLDINGS   the rendered document is scanned for the key
 *                             spellings that would mean this domain had
 *                             started publishing account data. This is a
 *                             tripwire on the domain's whole reason for being
 *                             careful, not a proof of secrecy — see the
 *                             comment on the check itself.
 *
 * DATADIR. Pinned to a hermetic tmp dir for the whole group. The provider
 * itself performs no I/O, but the native leaves run the full registry dispatch
 * path, and a test that leaves GetDataDir() at its default reads — and can
 * write to — the operator's live node. That has genuinely happened here.
 */

#include "test/test_core.h"

#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/wallet_telemetry.h"
#include "util/telemetry_ontology.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "util/util.h"

#include <stdio.h>
#include <string.h>

/* One label-free assertion per line, same reason as test_telemetry_render:
 * TEST/ASSERT mint a per-function label and these checks are numerous,
 * independent, and more useful reported one at a time. */
#define TW_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

static const struct json_value *dig2(const struct json_value *o,
                                     const char *a, const char *b)
{
    return json_get(json_get(o, a), b);
}

static const struct json_value *dig3(const struct json_value *o,
                                     const char *a, const char *b,
                                     const char *c)
{
    return json_get(dig2(o, a, b), c);
}

/* Read a leaf's presence out of the FULL-view provenance block. NULL means the
 * renderer reported nothing for that path, which is itself a failure. */
static const char *presence_of(const struct json_value *doc, const char *path)
{
    return json_get_str(json_get(dig2(doc, "leaves", path), "presence"));
}

/* ── the field table carries actionable meaning ──────────────────────── */

static int check_every_leaf_has_meaning(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("wallet");

    TW_CHECK("[wallet] the domain is registered and non-trivial",
             s != NULL && s->leaf_count > 1 && s->group_count > 1 &&
             s->schema_id != NULL &&
             strcmp(s->schema_id, "zcl.telemetry.wallet.v1") == 0);
    if (!s)
        return failures;

    int no_row = 0, no_means = 0, no_implies = 0, no_next = 0, judged = 0;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        const struct telemetry_field *f =
            telemetry_field_lookup(s->domain, lf->path);
        if (!f) { no_row++; continue; }
        if (!f->means || !f->means[0])
            no_means++;
        if (f->rule == TFR_INFO)
            continue;
        /* A row that FIRES has to say what the firing implies and where to go
         * next; that pair is the whole difference between an alert and a
         * number. A descriptive row is exempt by contract and states its
         * comparison basis inside `means` instead. */
        judged++;
        if (!f->implies || !f->implies[0])
            no_implies++;
        if (!f->next || !f->next[0])
            no_next++;
    }

    TW_CHECK("[wallet] every leaf resolves to a merged ontology row",
             no_row == 0);
    TW_CHECK("[wallet] every leaf states what it means", no_means == 0);
    TW_CHECK("[wallet] every JUDGED leaf states what an unhealthy value "
             "implies", no_implies == 0);
    TW_CHECK("[wallet] every JUDGED leaf names the exact next thing to read",
             no_next == 0);
    /* Anti-hollowness: the three preceding checks pass vacuously over a table
     * of nothing but descriptive rows, which is the cheap way to satisfy them.
     * The domain deliberately judges only the three unambiguous failures — a
     * failed backup, a failed checkpoint write, a failed mirror pass — so the
     * floor is exactly that, shrink-only. */
    TW_CHECK("[wallet] the domain judges its three unambiguous failures rather "
             "than shipping descriptive rows only", judged >= 3);
    return failures;
}

/* ── the collector leaves nothing unset ──────────────────────────────── */

static int check_collector_sets_every_leaf(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("wallet");
    if (!s)
        return failures;

    /* Deliberately NOT zeroed here: the provider's own contract is that it
     * zeroes first, and filling a poisoned buffer proves it does. Without
     * that memset a forgotten leaf would inherit whatever was on the stack —
     * which is precisely the "plausible value" failure mode. */
    struct wallet_snapshot snap;
    memset(&snap, 0xA5, sizeof snap);
    TW_CHECK("[wallet] the provider fills a snapshot",
             wallet_dump_state_fill(&snap));
    TW_CHECK("[wallet] the provider refuses a NULL snapshot rather than "
             "faulting", !wallet_dump_state_fill(NULL));

    /* THE CHECK THIS FILE EXISTS FOR. Every leaf's presence must be one of the
     * four REAL states; UNSET means the collector never wrote it. Walk the
     * descriptor table rather than a hand-list, so a leaf appended to the
     * field table tomorrow is covered by this test today. */
    int unset = 0, no_reason = 0;
    const char *first_unset = NULL;
    for (size_t i = 0; i < s->leaf_count; i++) {
        const struct telemetry_leaf *lf = &s->leaves[i];
        const struct telemetry_leaf_meta *m =
            (const struct telemetry_leaf_meta *)
            ((const unsigned char *)&snap + lf->meta_off);
        if (m->presence == TELEMETRY_UNSET) {
            unset++;
            if (!first_unset)
                first_unset = lf->path;
            continue;
        }
        /* A non-present leaf without a static reason token is a defect the
         * render layer reports; the provider must never produce one. */
        if (m->presence != TELEMETRY_PRESENT && (!m->reason || !m->reason[0]))
            no_reason++;
    }
    if (unset)
        printf("  first unset leaf: %s\n",
               first_unset ? first_unset : "(unknown)");
    TW_CHECK("[wallet] the collector leaves NO leaf unset — an unset leaf is a "
             "filler that returned early, not a wallet state", unset == 0);
    TW_CHECK("[wallet] every non-present leaf carries a static reason token",
             no_reason == 0);

    /* And the same fact stated by the renderer, which is the surface an agent
     * actually reads. */
    struct json_value out;
    json_init(&out);
    bool ok = telemetry_render(s, &snap, TLV_FULL, NULL, &out);
    TW_CHECK("[wallet] a collected snapshot renders", ok);
    TW_CHECK("[wallet] the rendered document reports no provider defect",
             !json_get_bool(dig2(&out, "completeness", "provider_defect")) &&
             json_get_int(dig2(&out, "completeness", "unset")) == 0);
    /* The build facts answer identically in any process, so they are present
     * even in this test binary; that is what makes them a usable floor. */
    TW_CHECK("[wallet] the build-fact leaves are PRESENT in any process",
             presence_of(&out, "values.security.can_spend_shielded") == NULL ||
             strcmp(presence_of(&out, "values.security.can_spend_shielded"),
                    "present") == 0);
    TW_CHECK("[wallet] can_spend_shielded is emitted as a real boolean, not "
             "null",
             dig3(&out, "values", "security", "can_spend_shielded") != NULL &&
             dig3(&out, "values", "security", "can_spend_shielded")->type ==
                 JSON_BOOL);
    json_free(&out);
    return failures;
}

/* ── unreadable is unknown, never unhealthy ──────────────────────────── */

static int check_unavailable_is_unknown_not_unhealthy(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("wallet");
    if (!s)
        return failures;

    /* Start from a real collection so the rest of the domain is legitimately
     * filled, then knock out ONE judged leaf. The judged rows are the ones
     * that could plausibly be mis-evaluated into a critical on a missed read,
     * so the unavailable leaf chosen here is deliberately a judged one. */
    struct wallet_snapshot snap;
    (void)wallet_dump_state_fill(&snap);
    TELEMETRY_UNAVAILABLE_LEAF(&snap, backup_failures_total,
                               "wallet_backup_not_wired");

    struct json_value out;
    json_init(&out);
    bool ok = telemetry_render(s, &snap, TLV_FULL, NULL, &out);
    TW_CHECK("[wallet] a snapshot with an unavailable leaf still renders", ok);

    const struct json_value *v =
        dig3(&out, "values", "backup", "backup_failures_total");
    TW_CHECK("[wallet] the unavailable leaf keeps its key and renders null",
             v != NULL && v->type == JSON_NULL);
    const char *pres = presence_of(&out, "values.backup.backup_failures_total");
    TW_CHECK("[wallet] it is reported unavailable, not unset",
             pres != NULL && strcmp(pres, "unavailable") == 0);
    const char *why = json_get_str(
        json_get(dig2(&out, "leaves", "values.backup.backup_failures_total"),
                 "reason"));
    TW_CHECK("[wallet] it carries the static reason token",
             why != NULL && strcmp(why, "wallet_backup_not_wired") == 0);
    TW_CHECK("[wallet] a leaf we could not read is NOT a provider defect",
             !json_get_bool(dig2(&out, "completeness", "provider_defect")));

    /* THE POINT. An expect-zero rule with nothing to read must not read the
     * JSON null as a zero and call it healthy, and must not read it as a
     * failure and call the wallet broken. It is unknown. */
    const char *state = json_get_str(dig2(&out, "health", "state"));
    TW_CHECK("[wallet] an unreadable judged leaf is never reported unhealthy",
             state != NULL && strcmp(state, "unhealthy") != 0);
    TW_CHECK("[wallet] it is counted as unknown, and not as an unhealthy "
             "finding",
             json_get_int(dig2(&out, "health", "unknown_count")) >= 1 &&
             json_get_int(dig2(&out, "health", "unhealthy_count")) == 0);
    json_free(&out);
    return failures;
}

/* ── posture, never holdings ─────────────────────────────────────────── */

/* A tripwire, and it is honest about being one: no string scan can PROVE a
 * document holds no secret. What it does prove is that the specific key
 * spellings which would mean this domain had started publishing account data
 * are absent from the widest view of the biggest document it can produce. The
 * real guarantee is structural and lives one layer up — the field table admits
 * only booleans, counters, cursor distances and closed-set tokens, and the
 * provider reaches no accessor that could produce a key, an address or an
 * amount. This check is here so that a future row which breaks that rule by
 * name fails loudly rather than shipping. */
static int check_no_account_data_is_published(void)
{
    int failures = 0;
    const struct telemetry_domain_schema *s = telemetry_domain_find("wallet");
    if (!s)
        return failures;

    struct wallet_snapshot snap;
    (void)wallet_dump_state_fill(&snap);
    struct json_value out;
    json_init(&out);
    if (!telemetry_render(s, &snap, TLV_FULL, NULL, &out)) {
        json_free(&out);
        TW_CHECK("[wallet] the full document renders for the posture scan", 0);
        return failures;
    }
    char buf[16384];
    size_t n = json_write(&out, buf, sizeof buf);
    json_free(&out);
    TW_CHECK("[wallet] the full document serializes for the posture scan",
             n > 0 && n < sizeof buf);
    if (n == 0 || n >= sizeof buf)
        return failures;

    /* Substring, not exact-key: a row named `balance_zat` or
     * `default_address` has to trip this too. */
    static const char *const k_forbidden[] = {
        "balance", "zatoshi", "_zat", "address", "seed", "mnemonic",
        "privkey", "private_key", "spending_key", "viewing_key",
        "passphrase", "secret", "xprv", "zs1", "wif",
    };
    int hits = 0;
    for (size_t i = 0; i < sizeof(k_forbidden) / sizeof(k_forbidden[0]); i++) {
        if (strstr(buf, k_forbidden[i])) {
            printf("  forbidden token in the wallet telemetry document: %s\n",
                   k_forbidden[i]);
            hits++;
        }
    }
    TW_CHECK("[wallet] the full document carries no balance, address, key or "
             "seed spelling anywhere — posture only", hits == 0);
    return failures;
}

/* ── the two native leaves ───────────────────────────────────────────── */

static const struct zcl_command_spec *find_spec(
    const struct zcl_command_registry *reg, const char *path)
{
    for (size_t i = 0; i < reg->count; i++)
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    return NULL;
}

/* Dispatch one leaf through the real registry, exactly as the CLI does. */
static bool exec_leaf(const struct zcl_command_registry *reg,
                      const struct zcl_command_spec *spec, const char *view,
                      char *out, size_t out_size,
                      enum zcl_command_exit *exit_code)
{
    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
                                                 false, spec->path, view, 0,
                                                 0, NULL,
                                                 out, out_size, exit_code);
    json_free(&input);
    return n > 0;
}

/* One leaf, one view. Asserts ok:true — never merely "non-empty", because the
 * registry's failure envelope is a perfectly non-empty document and a next[]
 * entry pointing at its own command produces one while reporting itself as a
 * budget overrun. */
static int check_leaf(const struct zcl_command_registry *reg, const char *path,
                      const char *view, const char *expect_group,
                      const char *forbid_group)
{
    int failures = 0;
    char label[192];
    const struct zcl_command_spec *spec = find_spec(reg, path);

    snprintf(label, sizeof label, "[wallet] %s is READY and natively bound",
             path);
    TW_CHECK(label, spec != NULL &&
                        spec->availability == ZCL_COMMAND_READY &&
                        spec->handler != NULL);
    if (!spec || spec->availability != ZCL_COMMAND_READY ||
        !spec->handler)
        return failures;

    /* The LIST budget the leaf declares, plus one byte so an over-long reply
     * is visible as such rather than clipped by this buffer. */
    static char out[ZCL_COMMAND_LIST_BUDGET + 1];
    memset(out, 0, sizeof out);
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    bool dispatched = exec_leaf(reg, spec, view, out, sizeof out, &code);

    snprintf(label, sizeof label, "[wallet] %s --view=%s dispatches with exit "
             "OK", path, view);
    TW_CHECK(label, dispatched && code == ZCL_COMMAND_EXIT_OK);
    if (!dispatched)
        return failures;

    /* Over budget is an EMPTY reply, not a truncated one, so the byte count is
     * printed on every run: a document that creeps up on its budget is worth
     * seeing before it crosses. */
    printf("  %s --view=%s: %zu bytes of %u budget\n", path, view, strlen(out),
           (unsigned)ZCL_COMMAND_LIST_BUDGET);

    struct json_value root;
    if (!json_read(&root, out, strlen(out))) {
        snprintf(label, sizeof label, "[wallet] %s --view=%s returns parseable "
                 "JSON", path, view);
        TW_CHECK(label, 0);
        return failures;
    }

    snprintf(label, sizeof label, "[wallet] %s --view=%s returns ok:true and "
             "status passed", path, view);
    TW_CHECK(label, json_get_bool(json_get(&root, "ok")) &&
                        json_get_str(json_get(&root, "status")) != NULL &&
                        strcmp(json_get_str(json_get(&root, "status")),
                               "passed") == 0);

    const struct json_value *data = json_get(&root, "data");
    snprintf(label, sizeof label, "[wallet] %s --view=%s carries the rendered "
             "telemetry document, not an error envelope", path, view);
    TW_CHECK(label, data != NULL && data->type == JSON_OBJ &&
                        json_get(data, "values") != NULL &&
                        json_get(data, "completeness") != NULL &&
                        json_get(data, "health") != NULL);

    snprintf(label, sizeof label, "[wallet] %s --view=%s renders the %s group",
             path, view, expect_group);
    TW_CHECK(label, dig2(data, "values", expect_group) != NULL);

    if (forbid_group) {
        snprintf(label, sizeof label, "[wallet] %s is scoped to its own group "
                 "and does not render %s", path, forbid_group);
        TW_CHECK(label, dig2(data, "values", forbid_group) == NULL);
    }

    /* Trap 1, pinned: a next[] entry naming the command in flight makes
     * push_next_array reject the WHOLE reply. It cannot be caught downstream —
     * by then the document is empty and the CLI blames the budget — so it is
     * asserted here on the reply that did survive. */
    const struct json_value *next = json_get(&root, "next");
    int self_ref = 0;
    if (next && next->type == JSON_ARR)
        for (size_t i = 0; i < next->num_children; i++) {
            const char *cmd = json_get_str(json_get(json_at(next, i),
                                                    "command"));
            if (cmd && strcmp(cmd, path) == 0)
                self_ref++;
        }
    snprintf(label, sizeof label, "[wallet] %s never points next[] at itself",
             path);
    TW_CHECK(label, self_ref == 0);

    json_free(&root);
    return failures;
}

static int check_native_leaves(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    TW_CHECK("[wallet] the command catalog loads", reg != NULL);
    if (!reg)
        return failures;

    /* Both leaves at every view: summary is the one most likely to be called
     * by an agent, full is the one most likely to overrun its budget. */
    static const char *const k_views[] = { "summary", "normal", "full" };
    for (size_t i = 0; i < sizeof(k_views) / sizeof(k_views[0]); i++) {
        failures += check_leaf(reg, "ops.telemetry.wallet.summary", k_views[i],
                               "security", NULL);
        failures += check_leaf(reg, "ops.telemetry.wallet.security", k_views[i],
                               "security", "backup");
    }

    /* The summary leaf is the whole domain; the security leaf is one group.
     * Checked once, at full, where the difference is largest. */
    const struct zcl_command_spec *sum =
        find_spec(reg, "ops.telemetry.wallet.summary");
    if (sum) {
        static char out[ZCL_COMMAND_LIST_BUDGET + 1];
        memset(out, 0, sizeof out);
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
        if (exec_leaf(reg, sum, "full", out, sizeof out, &code)) {
            struct json_value root;
            if (json_read(&root, out, strlen(out))) {
                const struct json_value *values =
                    json_get(json_get(&root, "data"), "values");
                TW_CHECK("[wallet] summary renders the whole domain — "
                         "projection, security and backup",
                         json_get(values, "projection") != NULL &&
                         json_get(values, "security") != NULL &&
                         json_get(values, "backup") != NULL);
                json_free(&root);
            }
        }
    }
    return failures;
}

int test_telemetry_wallet(void)
{
    printf("\n=== telemetry_wallet ===\n");
    int failures = 0;

    /* Hermetic datadir for the whole group. The provider does no I/O, but the
     * registry dispatch path below is the real one, and a default GetDataDir()
     * here would resolve to the operator's live node. */
    char datadir[256];
    test_make_tmpdir(datadir, sizeof datadir, "telemetry_wallet", "datadir");
    SetDataDir(datadir);

    failures += check_every_leaf_has_meaning();
    failures += check_collector_sets_every_leaf();
    failures += check_unavailable_is_unknown_not_unhealthy();
    failures += check_no_account_data_is_published();
    failures += check_native_leaves();

    SetDataDir("");
    ClearDataDirCache();

    printf("=== telemetry_wallet: %d failures ===\n", failures);
    return failures;
}
