/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * metaverse_catalog scenario checks: property_id pure rules (kind/
 * authority names, make/format/parse round-trip, and every rejection);
 * the action vocabulary (single-bit naming, round-trip, mask validity,
 * truncation refusal); the adapter registry (every kind wired or
 * explicitly unavailable); the MVP scope decision; settlement
 * classification and its measurability/independence; work measurement
 * against anchored work; and settlement reaching the inspection
 * surfaces (list/show kinds, content/pow/local-declaration views).
 *
 * Split out of test_metaverse_catalog.c (which keeps the includes,
 * the fixture helpers shared across siblings — hex formatting and the
 * in-process command runner — and the group entry point) so no family
 * member crosses the 1,500-line ceiling. */


#include "test/test_core.h"

#include "command/native_command.h"

#include "chain/chainparams.h"
#include "config/command_catalog.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "metaverse/property_action.h"
#include "metaverse/property_adapter.h"
#include "metaverse/property_id.h"
#include "metaverse/property_view.h"
#include "metaverse/property_work.h"
#include "models/database.h"
#include "models/zslp.h"
#include "models/znam.h"
#include "services/property_catalog.h"
#include "vcs/blob_store.h"
#include "vcs/package_accept.h"
#include "vcs/package_index.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"

/* Test-only seam for deterministic mutation between the hash and final
 * fingerprint pass. Production callers only see the ordinary property API. */
#include "../../metaverse/src/metaverse_priv.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test/test_metaverse_catalog_priv.h"

/* ── 1: property_id pure rules ────────────────────────────────────── */

static int property_case_kind_names(void)
{
    int failures = 0;
    MV_CHECK("id: kind names are the wire names",
             strcmp(metaverse_kind_name(METAVERSE_KIND_CONTENT),
                    "content") == 0 &&
             strcmp(metaverse_kind_name(METAVERSE_KIND_ZCODE_PACKAGE),
                    "zcode_package") == 0 &&
             strcmp(metaverse_kind_name(METAVERSE_KIND_CONTRACT_SWAP),
                    "contract_swap") == 0);
    MV_CHECK("id: an out-of-range kind renders as unknown, never as a kind",
             strcmp(metaverse_kind_name(METAVERSE_KIND_UNKNOWN),
                    "unknown") == 0 &&
             strcmp(metaverse_kind_name(METAVERSE_KIND_COUNT),
                    "unknown") == 0);
    MV_CHECK("id: every kind names an authority source",
             strcmp(metaverse_kind_authority(METAVERSE_KIND_CONTENT),
                    "vcs.blob_store") == 0 &&
             strcmp(metaverse_kind_authority(METAVERSE_KIND_ZNAM_NAME),
                    "znam.registry") == 0);
    {
        bool ok = true;

        for (int k = 1; k < METAVERSE_KIND_COUNT; k++) {
            enum metaverse_kind kk = (enum metaverse_kind)k;
            if (metaverse_kind_from_name(metaverse_kind_name(kk)) != kk)
                ok = false;
        }
        MV_CHECK("id: name lookup round-trips for every kind", ok);
    }
    MV_CHECK("id: unknown/NULL/empty names resolve to UNKNOWN",
             metaverse_kind_from_name(NULL) == METAVERSE_KIND_UNKNOWN &&
             metaverse_kind_from_name("") == METAVERSE_KIND_UNKNOWN &&
             metaverse_kind_from_name("unknown") == METAVERSE_KIND_UNKNOWN &&
             metaverse_kind_from_name("world") == METAVERSE_KIND_UNKNOWN);
    return failures;
}

static int property_case_make_and_valid(const uint8_t *root,
                                         const uint8_t *zero,
                                         struct metaverse_property_id *id)
{
    int failures = 0;
    MV_CHECK("id: make accepts a real kind and a non-zero root",
             metaverse_property_id_make(METAVERSE_KIND_CONTENT, root, id) &&
             metaverse_property_id_valid(id));
    MV_CHECK("id: an all-zero root is refused (uninitialized must not read "
             "as a real object)",
             !metaverse_property_id_make(METAVERSE_KIND_CONTENT, zero, id));
    {
        struct metaverse_property_id z;

        memset(&z, 0, sizeof(z));
        MV_CHECK("id: a zeroed struct is not a valid id",
                 !metaverse_property_id_valid(&z));
    }
    MV_CHECK("id: UNKNOWN and out-of-range kinds are refused",
             !metaverse_property_id_make(METAVERSE_KIND_UNKNOWN, root, id) &&
             !metaverse_property_id_make(METAVERSE_KIND_COUNT, root, id));
    return failures;
}

static int property_case_format_and_parse(const uint8_t *root,
                                           struct metaverse_property_id *id,
                                           struct metaverse_property_id *back,
                                           char *text, size_t text_cap)
{
    int failures = 0;
    MV_CHECK("id: format/parse round-trip",
             metaverse_property_id_make(METAVERSE_KIND_ZCODE_PACKAGE, root,
                                        id) &&
             metaverse_property_id_format(id, text, text_cap) &&
             metaverse_property_id_parse(text, back) &&
             metaverse_property_id_equal(id, back));
    MV_CHECK("id: the text form is '<kind>:<64 lowercase hex>'",
             strncmp(text, "zcode_package:", 14) == 0 &&
             strlen(text) == 14 + 64 &&
             strchr(text + 14, 'A') == NULL);
    {
        char upper[METAVERSE_ID_TEXT_MAX];

        snprintf(upper, sizeof(upper), "content:%s",
                 "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBC"
                 "BDBEBF");
        MV_CHECK("id: parsing accepts uppercase hex",
                 metaverse_property_id_parse(upper, back) &&
                 back->kind == METAVERSE_KIND_CONTENT);
    }
    {
        struct metaverse_property_id a, b;

        MV_CHECK("id: same root under two kinds is NOT the same property",
                 metaverse_property_id_make(METAVERSE_KIND_CONTENT, root,
                                            &a) &&
                 metaverse_property_id_make(METAVERSE_KIND_ZCODE_PACKAGE,
                                            root, &b) &&
                 !metaverse_property_id_equal(&a, &b));
    }
    return failures;
}

static int property_case_malformed_and_edges(const uint8_t *root,
                                              struct metaverse_property_id *id,
                                              char *text, size_t text_cap)
{
    int failures = 0;
    {
        struct metaverse_property_id bad;
        char buf[160];
        bool ok = true;
        const char *cases[] = {
            "",
            ":a0a1",
            "content",
            "content:",
            "world:a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbb"
            "cbdbebf",
            "content:a0a1",        /* short */
            "content:zz" ,
            NULL
        };
        for (int i = 0; cases[i]; i++) {
            if (metaverse_property_id_parse(cases[i], &bad) ||
                bad.kind != METAVERSE_KIND_UNKNOWN)
                ok = false;
        }
        /* 65 hex digits: one byte too many must not truncate-and-accept. */
        snprintf(buf, sizeof(buf), "content:%s0",
                 "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbc"
                 "bdbebf");
        if (metaverse_property_id_parse(buf, &bad))
            ok = false;
        /* Trailing bytes after a full root. */
        snprintf(buf, sizeof(buf), "content:%s:x",
                 "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbc"
                 "bdbebf");
        if (metaverse_property_id_parse(buf, &bad))
            ok = false;
        MV_CHECK("id: malformed text is refused, never partially parsed", ok);
    }
    MV_CHECK("id: format refuses a buffer that cannot hold the whole id",
             metaverse_property_id_make(METAVERSE_KIND_CONTENT, root, id) &&
             !metaverse_property_id_format(id, text, 16) && text[0] == '\0');
    (void)text_cap;
    MV_CHECK("id: equality is NULL-safe and never true for NULL",
             !metaverse_property_id_equal(NULL, id) &&
             !metaverse_property_id_equal(id, NULL));
    return failures;
}

int t_property_id_rules(void)
{
    int failures = 0;
    uint8_t root[32];
    uint8_t zero[32];
    struct metaverse_property_id id, back;
    char text[METAVERSE_ID_TEXT_MAX];

    memset(zero, 0, sizeof(zero));
    for (int i = 0; i < 32; i++)
        root[i] = (uint8_t)(0xa0 + i);

    failures += property_case_kind_names();
    failures += property_case_make_and_valid(root, zero, &id);
    failures += property_case_format_and_parse(root, &id, &back, text,
                                               sizeof(text));
    failures += property_case_malformed_and_edges(root, &id, text,
                                                  sizeof(text));
    return failures;
}

/* ── 2: the action vocabulary ─────────────────────────────────────── */

static int action_case_names_and_masks(char *buf, size_t buf_cap)
{
    int failures = 0;
    {
        bool ok = true;

        for (size_t i = 0; i < (size_t)METAVERSE_ACTION_COUNT; i++) {
            uint32_t bit = metaverse_action_at(i);
            const char *n = metaverse_action_name(bit);
            if (!bit || !n || metaverse_action_from_name(n) != bit)
                ok = false;
        }
        MV_CHECK("actions: every table row names itself back", ok);
    }
    /* Both bits below name a real action on their own, so NULL here can only
     * be caused by the value having two bits — not by one of them being
     * unnameable, which is what the old INSPECT|HOST pair could not
     * distinguish. */
    MV_CHECK("actions: a multi-bit value has no single name",
             metaverse_action_name(METAVERSE_ACTION_HOST |
                                   METAVERSE_ACTION_PUBLISH_REVISION) == NULL &&
             metaverse_action_name(0) == NULL);
    MV_CHECK("actions: an undefined bit is not a name and not a valid mask",
             metaverse_action_name(0x80000000u) == NULL &&
             !metaverse_action_mask_valid(0x80000000u));
    MV_CHECK("actions: the empty mask is well-formed and renders empty",
             metaverse_action_mask_valid(0) &&
             metaverse_action_mask_format(0, buf, buf_cap) &&
             buf[0] == '\0');
    MV_CHECK("actions: ALL renders every name in table order",
             metaverse_action_mask_format(METAVERSE_ACTION_ALL, buf,
                                          buf_cap) &&
             strncmp(buf, "host,publish_revision,", 22) == 0 &&
             strstr(buf, "revoke") != NULL &&
             /* The reserved name is legible on its own but must never appear
              * in a rendered ACTION set — that is the whole point of the
              * split, and a substring search is what catches a reissue. */
             strstr(buf, "inspect") == NULL);
    MV_CHECK("actions: a buffer too small refuses instead of truncating "
             "(a short list must not read as fewer rights)",
             !metaverse_action_mask_format(METAVERSE_ACTION_ALL, buf, 12) &&
             buf[0] == '\0');
    return failures;
}

static int action_case_semantics(void)
{
    int failures = 0;
    /* MUTATING is column 6 — state OUTSIDE this node — so the complement is
     * every action whose effect stays local: HOST (this node's own storage),
     * DELEGATE and REVOKE (this node's own grant records). Derived from the
     * table, not from the header comment above it, which says HOST is the one
     * absent action and is wrong about DELEGATE and REVOKE. */
    MV_CHECK("actions: HOST/DELEGATE/REVOKE are the only non-external verbs",
             (METAVERSE_ACTION_ALL & ~(uint32_t)METAVERSE_ACTION_MUTATING) ==
                 (METAVERSE_ACTION_HOST | METAVERSE_ACTION_DELEGATE |
                  METAVERSE_ACTION_REVOKE));
    /* "Not external" is not "harmless". Conflating the two is exactly the
     * design error that made MUTATING equal ALL in review, so the two columns
     * are asserted apart here: HOST is outside MUTATING AND still audited. */
    MV_CHECK("actions: a local-only action still mints a receipt",
             !metaverse_action_is_mutation(METAVERSE_ACTION_HOST) &&
             metaverse_action_requires_receipt(METAVERSE_ACTION_HOST) &&
             metaverse_action_requires_plan_commit(METAVERSE_ACTION_HOST) &&
             metaverse_action_changes_state(METAVERSE_ACTION_HOST));
    /* Every action changes something, so the two masks must NOT coincide in
     * the other direction either. */
    MV_CHECK("actions: CHANGES_STATE is ALL and MUTATING is strictly smaller",
             (uint32_t)METAVERSE_ACTION_CHANGES_STATE ==
                 (uint32_t)METAVERSE_ACTION_ALL &&
             (uint32_t)METAVERSE_ACTION_MUTATING !=
                 (uint32_t)METAVERSE_ACTION_ALL &&
             ((uint32_t)METAVERSE_ACTION_MUTATING &
              ~(uint32_t)METAVERSE_ACTION_ALL) == 0u);
    return failures;
}

int t_action_vocabulary(void)
{
    int failures = 0;
    char buf[METAVERSE_ACTION_LIST_MAX];

    failures += action_case_names_and_masks(buf, sizeof(buf));
    failures += action_case_semantics();
    return failures;
}

/* ── 3: adapter registry coverage ─────────────────────────────────── */

static int registry_case_rows_and_coverage(size_t *out_rows,
                                            size_t *out_ready)
{
    int failures = 0;
    size_t rows = metaverse_adapter_count();
    size_t ready = 0;
    bool every_kind_has_a_row = true;
    bool every_unwired_says_why = true;

    MV_CHECK("registry: one row per kind (UNKNOWN owns none)",
             rows == (size_t)METAVERSE_KIND_COUNT - 1u);
    for (int k = 1; k < METAVERSE_KIND_COUNT; k++) {
        const struct metaverse_adapter *a =
            metaverse_adapter_for((enum metaverse_kind)k);

        if (!a || a->kind != (enum metaverse_kind)k) {
            every_kind_has_a_row = false;
            continue;
        }
        if (metaverse_adapter_ready(a))
            ready++;
        else if (!a->unavailable_reason || !a->unavailable_reason[0])
            every_unwired_says_why = false;
    }
    MV_CHECK("registry: every kind resolves to its own row",
             every_kind_has_a_row);
    MV_CHECK("registry: a kind without a reader still states why",
             every_unwired_says_why);
    *out_rows = rows;
    *out_ready = ready;
    return failures;
}

static int registry_case_wired_and_index(size_t rows, size_t ready)
{
    int failures = 0;
    MV_CHECK("registry: content, zcode_package, znam_name, and zslp_asset "
             "are wired",
             ready == 4 &&
             metaverse_adapter_ready(
                 metaverse_adapter_for(METAVERSE_KIND_CONTENT)) &&
             metaverse_adapter_ready(
                 metaverse_adapter_for(METAVERSE_KIND_ZCODE_PACKAGE)) &&
             metaverse_adapter_ready(
                 metaverse_adapter_for(METAVERSE_KIND_ZNAM_NAME)) &&
             metaverse_adapter_ready(
                 metaverse_adapter_for(METAVERSE_KIND_ZSLP_ASSET)));
    MV_CHECK("registry: an invalid kind has no row",
             metaverse_adapter_for(METAVERSE_KIND_UNKNOWN) == NULL &&
             metaverse_adapter_for(METAVERSE_KIND_COUNT) == NULL &&
             metaverse_adapter_at(rows) == NULL);
    {
        bool ok = true;

        for (size_t i = 0; i < rows; i++) {
            const struct metaverse_adapter *a = metaverse_adapter_at(i);
            if (!a || a->kind != (enum metaverse_kind)(i + 1))
                ok = false;
        }
        MV_CHECK("registry: index walk covers the same rows", ok);
    }
    return failures;
}

int t_adapter_registry(void)
{
    int failures = 0;
    size_t rows = 0;
    size_t ready = 0;

    failures += registry_case_rows_and_coverage(&rows, &ready);
    failures += registry_case_wired_and_index(rows, ready);
    return failures;
}

/* ── 3a: the MVP scope partition is a pinned decision ───────────────────── */

/* docs/METAVERSE_MVP.md criterion MM3: the catalog is complete OR honestly
 * scoped. This table IS the scope decision — the four datadir-provable kinds
 * are in MVP scope, the four runtime/node.db kinds are explicitly out — and
 * it is asserted against the live registry so a kind silently moving between
 * the two sets (or an unwired kind losing its reason) fails here. The
 * MV_MVP_SCOPE marker naming this contract lives with the declarations in
 * contexts/commons/modules/metaverse/src/adapter_registry.c. */
int t_mvp_scope_decision(void)
{
    int failures = 0;
    static const enum metaverse_kind k_in_scope[] = {
        METAVERSE_KIND_CONTENT, METAVERSE_KIND_ZCODE_PACKAGE,
        METAVERSE_KIND_ZNAM_NAME, METAVERSE_KIND_ZSLP_ASSET,
    };
    static const enum metaverse_kind k_out_of_scope[] = {
        METAVERSE_KIND_HOSTED_SERVICE, METAVERSE_KIND_ENDPOINT_ONION,
        METAVERSE_KIND_STOREFRONT_PRODUCT, METAVERSE_KIND_CONTRACT_SWAP,
        /* Content-addressed but not ENUMERABLE from a datadir: a character is
         * verified by recomputing it from the birth seed presented with it,
         * and no path on disk lists the seeds this node holds. Out of scope
         * for the same reason as the four above — no honest datadir-only
         * projection exists — arrived at from the opposite direction. */
        METAVERSE_KIND_CHARACTER_SHEET,
    };
    size_t in_wired = 0, out_reasoned = 0;

    for (size_t i = 0; i < sizeof(k_in_scope) / sizeof(k_in_scope[0]); i++) {
        const struct metaverse_adapter *a =
            metaverse_adapter_for(k_in_scope[i]);
        if (a && metaverse_adapter_ready(a))
            in_wired++;
    }
    for (size_t i = 0; i < sizeof(k_out_of_scope) / sizeof(k_out_of_scope[0]);
         i++) {
        const struct metaverse_adapter *a =
            metaverse_adapter_for(k_out_of_scope[i]);
        if (a && !metaverse_adapter_ready(a) && a->unavailable_reason &&
            a->unavailable_reason[0])
            out_reasoned++;
    }
    MV_CHECK("mvp-scope: the four datadir-provable kinds are wired",
             in_wired == 4);
    MV_CHECK("mvp-scope: the five out-of-scope kinds stay unavailable and "
             "each still says why",
             out_reasoned == 5);
    return failures;
}

/* ── 3b: settlement classes ───────────────────────────────────────── */

/* An independent second opinion on the kind table's fourth column. The
 * table is the authority; this array is written from the SUBSYSTEM
 * behaviour (does the model hash bytes, record a chain ordering, or just
 * assert?) so that silently reclassifying a kind to make something else
 * pass fails here. */
struct mv_expected_settlement {
    enum metaverse_kind kind;
    enum metaverse_settlement settlement;
};

static const struct mv_expected_settlement k_expected_settlement[] = {
    /* The id IS the manifest root; verification hashes bytes. */
    { METAVERSE_KIND_CONTENT,     METAVERSE_SETTLEMENT_CONTENT_ADDRESSED },
    { METAVERSE_KIND_ZCODE_PACKAGE, METAVERSE_SETTLEMENT_CONTENT_ADDRESSED },
    /* OP_RETURN first-come-first-served: an ordering, settled by work, and
     * both models record the ZCL height that fixes it. */
    { METAVERSE_KIND_ZNAM_NAME,   METAVERSE_SETTLEMENT_PROOF_OF_WORK },
    { METAVERSE_KIND_ZSLP_ASSET,  METAVERSE_SETTLEMENT_PROOF_OF_WORK },
    /* Nothing outside this process has agreed these exist. */
    { METAVERSE_KIND_HOSTED_SERVICE,
      METAVERSE_SETTLEMENT_LOCAL_DECLARATION },
    { METAVERSE_KIND_ENDPOINT_ONION,
      METAVERSE_SETTLEMENT_LOCAL_DECLARATION },
    { METAVERSE_KIND_STOREFRONT_PRODUCT,
      METAVERSE_SETTLEMENT_LOCAL_DECLARATION },
    /* models/swap_contract.h stores funding_txid but no funding HEIGHT,
     * and `chain` may be one whose height this node refuses to claim it
     * can observe. Chain-anchored, not measurable here. */
    { METAVERSE_KIND_CONTRACT_SWAP,
      METAVERSE_SETTLEMENT_CHAIN_ANCHORED_INCOMPLETE },
    /* The id is the hash of the character's own birth seed plus the rules
     * revision, and metaverse/character_sheet.h recomputes the whole sheet
     * from it: a verifier hashes what it was handed. No registry, no chain,
     * no peer — the same mechanism as content and zcode_package, reached
     * without any store existing at all. */
    { METAVERSE_KIND_CHARACTER_SHEET,
      METAVERSE_SETTLEMENT_CONTENT_ADDRESSED },
};

static int settlement_case_classified_and_matches(void)
{
    int failures = 0;
    size_t expected_n = sizeof(k_expected_settlement) /
                        sizeof(k_expected_settlement[0]);

    MV_CHECK("settlement: the expectation table covers every kind",
             expected_n == (size_t)METAVERSE_KIND_COUNT - 1u);
    {
        bool classified = true;
        bool matches = true;

        for (int k = 1; k < METAVERSE_KIND_COUNT; k++) {
            enum metaverse_kind kk = (enum metaverse_kind)k;
            enum metaverse_settlement s = metaverse_kind_settlement(kk);
            bool found = false;

            /* Exactly one class, and never the invalid zero. The compiler
             * already refuses a table row with no fourth column and a
             * fourth column outside the enum; this catches the remaining
             * case, a kind whose class is UNKNOWN or out of range. */
            if (s <= METAVERSE_SETTLEMENT_UNKNOWN ||
                s >= METAVERSE_SETTLEMENT_COUNT)
                classified = false;
            for (size_t i = 0; i < expected_n; i++) {
                if (k_expected_settlement[i].kind != kk)
                    continue;
                found = true;
                if (k_expected_settlement[i].settlement != s)
                    matches = false;
            }
            if (!found)
                matches = false;
        }
        MV_CHECK("settlement: every kind has exactly one real class",
                 classified);
        MV_CHECK("settlement: each kind's class matches how its subsystem "
                 "actually settles", matches);
    }
    MV_CHECK("settlement: UNKNOWN and out-of-range kinds are UNKNOWN, never "
             "the strongest class",
             metaverse_kind_settlement(METAVERSE_KIND_UNKNOWN) ==
                 METAVERSE_SETTLEMENT_UNKNOWN &&
             metaverse_kind_settlement(METAVERSE_KIND_COUNT) ==
                 METAVERSE_SETTLEMENT_UNKNOWN);
    return failures;
}

static int settlement_case_names_and_meanings(void)
{
    int failures = 0;
    MV_CHECK("settlement: class names are the wire names",
             strcmp(metaverse_settlement_name(
                        METAVERSE_SETTLEMENT_CONTENT_ADDRESSED),
                    "content_addressed") == 0 &&
             strcmp(metaverse_settlement_name(
                        METAVERSE_SETTLEMENT_PROOF_OF_WORK),
                    "proof_of_work") == 0 &&
             strcmp(metaverse_settlement_name(
                        METAVERSE_SETTLEMENT_LOCAL_DECLARATION),
                    "local_declaration") == 0 &&
             strcmp(metaverse_settlement_name(
                        METAVERSE_SETTLEMENT_CHAIN_ANCHORED_INCOMPLETE),
                    "chain_anchored_incomplete") == 0 &&
             strcmp(metaverse_settlement_name(METAVERSE_SETTLEMENT_UNKNOWN),
                    "unknown") == 0 &&
             strcmp(metaverse_settlement_name(METAVERSE_SETTLEMENT_COUNT),
                    "unknown") == 0);
    {
        bool every_class_explains = true;

        for (int s = 0; s <= METAVERSE_SETTLEMENT_COUNT; s++) {
            const char *m =
                metaverse_settlement_means((enum metaverse_settlement)s);

            if (!m || !*m)
                every_class_explains = false;
        }
        MV_CHECK("settlement: every class states plainly what it settles",
                 every_class_explains);
    }
    /* The honesty requirement, asserted as text: a locally-declared
     * property must say out loud that only this node asserts it. */
    MV_CHECK("settlement: local_declaration says this node is the only "
             "thing asserting it",
             strstr(metaverse_settlement_means(
                        METAVERSE_SETTLEMENT_LOCAL_DECLARATION),
                    "this node") != NULL &&
             strstr(metaverse_settlement_means(
                        METAVERSE_SETTLEMENT_LOCAL_DECLARATION),
                    "nothing outside this node") != NULL);
    return failures;
}

static int settlement_case_measurable_and_independence(void)
{
    int failures = 0;
    MV_CHECK("settlement: proof_of_work is the ONLY measurable class",
             metaverse_settlement_work_measurable(
                 METAVERSE_SETTLEMENT_PROOF_OF_WORK) &&
             !metaverse_settlement_work_measurable(
                 METAVERSE_SETTLEMENT_CONTENT_ADDRESSED) &&
             !metaverse_settlement_work_measurable(
                 METAVERSE_SETTLEMENT_LOCAL_DECLARATION) &&
             !metaverse_settlement_work_measurable(
                 METAVERSE_SETTLEMENT_CHAIN_ANCHORED_INCOMPLETE) &&
             !metaverse_settlement_work_measurable(
                 METAVERSE_SETTLEMENT_UNKNOWN));
    /* Settlement is NOT a re-spelling of chain_bound evidence: the two
     * axes must be able to disagree, or one of them is redundant. */
    MV_CHECK("settlement: the class is a property of the kind, not of the "
             "evidence grade",
             metaverse_kind_settlement(METAVERSE_KIND_CONTENT) !=
                 metaverse_kind_settlement(METAVERSE_KIND_ZNAM_NAME) &&
             metaverse_kind_settlement(METAVERSE_KIND_STOREFRONT_PRODUCT) !=
                 metaverse_kind_settlement(METAVERSE_KIND_CONTRACT_SWAP));
    return failures;
}

int t_settlement_classes(void)
{
    int failures = 0;
    failures += settlement_case_classified_and_matches();
    failures += settlement_case_names_and_meanings();
    failures += settlement_case_measurable_and_independence();
    return failures;
}

/* ── 3c: the work measurement ─────────────────────────────────────── */

/* Build the accumulated-work value a block index entry would carry. */
static void mv_work(struct arith_uint256 *w, uint64_t v)
{
    arith_uint256_set_u64(w, v);
}

static int work_case_non_pow_refused(struct arith_uint256 *anchor_work,
                                      struct arith_uint256 *tip_work)
{
    int failures = 0;
    struct metaverse_work_proof p;
    /* The whole point: a non-PoW kind gets UNKNOWN, not zero, no matter
     * what heights the caller passes. */
    const enum metaverse_kind non_pow[] = {
        METAVERSE_KIND_CONTENT, METAVERSE_KIND_ZCODE_PACKAGE,
        METAVERSE_KIND_HOSTED_SERVICE, METAVERSE_KIND_ENDPOINT_ONION,
        METAVERSE_KIND_STOREFRONT_PRODUCT, METAVERSE_KIND_CONTRACT_SWAP,
    };
    bool refused = true;
    bool unknown_not_zero = true;

    for (size_t i = 0; i < sizeof(non_pow) / sizeof(non_pow[0]); i++) {
        if (metaverse_work_measure(non_pow[i], 100, anchor_work, 900,
                                   tip_work, &p))
            refused = false;
        if (p.applicable || p.has_anchor_height || p.has_depth ||
            p.has_chainwork || p.has_tip_height)
            unknown_not_zero = false;
        /* Distinguishable from zero, in the struct AND in the render. */
        if (p.anchor_height != -1 || p.depth != -1 ||
            p.tip_height != -1 || p.chainwork_hex[0] != '\0')
            unknown_not_zero = false;
        if (p.gap != METAVERSE_WORK_GAP_NOT_APPLICABLE)
            unknown_not_zero = false;
    }
    MV_CHECK("work: a non-proof-of-work kind is refused a measurement "
             "even when a real tip is offered", refused);
    MV_CHECK("work: for those kinds every number is UNKNOWN (-1/\"\"), "
             "never a plausible zero", unknown_not_zero);
    return failures;
}

static int work_case_anchored_measures(struct arith_uint256 *anchor_work,
                                        struct arith_uint256 *tip_work)
{
    int failures = 0;
    struct metaverse_work_proof p;
    /* A chain-anchored fixture: anchor at 500, tip at 564. */
    MV_CHECK("work: a proof-of-work kind with an anchor and a tip measures",
             metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 500,
                                    anchor_work, 564, tip_work, &p));
    MV_CHECK("work: the anchor height is the record's, not the tip's",
             p.has_anchor_height && p.anchor_height == 500 &&
             p.has_tip_height && p.tip_height == 564);
    MV_CHECK("work: confirmation depth is tip - anchor",
             p.has_depth && p.depth == 64 &&
             p.gap == METAVERSE_WORK_GAP_NONE && p.applicable);
    {
        /* 1064 - 1000 = 64 = 0x40, big-endian hex as the rest of the node
         * renders chainwork. */
        char expect[65];
        struct arith_uint256 delta;

        arith_uint256_sub(&delta, tip_work, anchor_work);
        arith_uint256_get_hex(&delta, expect);
        MV_CHECK("work: chainwork is the block index's own accumulated "
                 "work, differenced",
                 p.has_chainwork && strcmp(p.chainwork_hex, expect) == 0 &&
                 strcmp(p.chainwork_hex,
                        "00000000000000000000000000000000000000000000000000"
                        "00000000000040") == 0);
    }
    return failures;
}

static int work_case_depth_zero_and_missing_halves(
    struct arith_uint256 *anchor_work, struct arith_uint256 *tip_work)
{
    int failures = 0;
    struct metaverse_work_proof p;
    /* Depth 0 is a real answer and must not read as unknown. */
    MV_CHECK("work: an anchor AT the tip is depth 0, not unknown",
             metaverse_work_measure(METAVERSE_KIND_ZSLP_ASSET, 900,
                                    tip_work, 900, tip_work, &p) &&
             p.has_depth && p.depth == 0 && p.has_chainwork &&
             strcmp(p.chainwork_hex,
                    "000000000000000000000000000000000000000000000000000000"
                    "0000000000") == 0);

    /* Missing halves each degrade to a NAMED gap, never to a number. */
    MV_CHECK("work: no anchor height -> no_anchor, nothing measured",
             !metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, -1,
                                     anchor_work, 564, tip_work, &p) &&
             p.applicable && p.gap == METAVERSE_WORK_GAP_NO_ANCHOR &&
             !p.has_depth && p.depth == -1 && !p.has_chainwork);
    MV_CHECK("work: no tip -> no_tip, and the anchor still reports",
             !metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 500,
                                     anchor_work, -1, NULL, &p) &&
             p.gap == METAVERSE_WORK_GAP_NO_TIP && p.has_anchor_height &&
             p.anchor_height == 500 && !p.has_depth && p.depth == -1);
    return failures;
}

static int work_case_contradiction_and_backwards(
    struct arith_uint256 *anchor_work, struct arith_uint256 *tip_work)
{
    int failures = 0;
    struct metaverse_work_proof p;
    MV_CHECK("work: an anchor ABOVE the tip is a contradiction, not a "
             "negative or clamped depth",
             !metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 600,
                                     anchor_work, 500, tip_work, &p) &&
             !p.has_depth && p.depth == -1 && !p.has_chainwork &&
             p.gap == METAVERSE_WORK_GAP_ANCHOR_ABOVE_TIP);
    MV_CHECK("work: depth stands without chainwork when the block index "
             "values are unavailable",
             metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 500, NULL, 564,
                                    NULL, &p) &&
             p.has_depth && p.depth == 64 && !p.has_chainwork &&
             p.chainwork_hex[0] == '\0');
    MV_CHECK("work: work going BACKWARDS is not reported as a magnitude",
             metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 500, tip_work,
                                    564, anchor_work, &p) &&
             p.has_depth && !p.has_chainwork);
    MV_CHECK("work: a NULL out is refused",
             !metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 500,
                                     anchor_work, 564, tip_work, NULL));
    return failures;
}

static int work_case_depth_and_gaps(struct arith_uint256 *anchor_work,
                                     struct arith_uint256 *tip_work)
{
    int failures = 0;
    failures += work_case_depth_zero_and_missing_halves(anchor_work,
                                                         tip_work);
    failures += work_case_contradiction_and_backwards(anchor_work,
                                                       tip_work);
    return failures;
}

static int work_case_gap_names(void)
{
    int failures = 0;
    bool every_gap_explains = true;

    for (int g = METAVERSE_WORK_GAP_NOT_APPLICABLE;
         g <= METAVERSE_WORK_GAP_ANCHOR_ABOVE_TIP; g++) {
        const char *r =
            metaverse_work_gap_reason((enum metaverse_work_gap)g);
        const char *n =
            metaverse_work_gap_name((enum metaverse_work_gap)g);

        if (!r || !*r || !n || !*n)
            every_gap_explains = false;
    }
    MV_CHECK("work: every gap names itself and explains itself",
             every_gap_explains &&
             strcmp(metaverse_work_gap_name(METAVERSE_WORK_GAP_NONE),
                    "none") == 0);
    return failures;
}

static int work_case_json_render_fields(const struct json_value *j)
{
    int failures = 0;
    const char *cw  = json_get_str(json_get(j, "chainwork_since_anchor"));
    const char *gap = json_get_str(json_get(j, "gap"));
    const char *why = json_get_str(json_get(j, "gap_reason"));

    MV_CHECK("work: a not-applicable proof renders measurable=false, "
             "-1 heights and an empty chainwork",
             !json_get_bool(json_get(j, "measurable")) &&
             json_get_int(json_get(j, "anchor_height")) == -1 &&
             json_get_int(json_get(j, "tip_height")) == -1 &&
             json_get_int(json_get(j, "confirmation_depth")) == -1 &&
             cw && *cw == '\0' && gap &&
             strcmp(gap, "not_applicable") == 0 && why && *why);
    return failures;
}

static int work_case_json_render_no_score(const char *doc)
{
    int failures = 0;
    /* No score, rating, or tier: the render carries mechanism + numbers. */
    MV_CHECK("work: the render invents no score, rating, or trust tier",
             doc[0] != '\0' && !strstr(doc, "score") &&
             !strstr(doc, "rating") && !strstr(doc, "trust") &&
             !strstr(doc, "tier") && !strstr(doc, "level"));
    return failures;
}

static int work_case_json_render(struct arith_uint256 *anchor_work,
                                  struct arith_uint256 *tip_work)
{
    int failures = 0;
    struct metaverse_work_proof p;
    struct json_value j;
    char doc[2048];
    bool ok;

    (void)metaverse_work_measure(METAVERSE_KIND_CONTENT, 100,
                                 anchor_work, 900, tip_work, &p);
    json_init(&j);
    ok = metaverse_work_to_json(&p, &j);
    MV_CHECK("work: the render succeeds", ok);
    failures += work_case_json_render_fields(&j);
    doc[0] = '\0';
    (void)json_write(&j, doc, sizeof(doc));
    failures += work_case_json_render_no_score(doc);
    json_free(&j);
    return failures;
}

int t_work_measurement(void)
{
    int failures = 0;
    struct arith_uint256 anchor_work, tip_work;

    mv_work(&anchor_work, 1000);
    mv_work(&tip_work, 1064);

    failures += work_case_non_pow_refused(&anchor_work, &tip_work);
    failures += work_case_anchored_measures(&anchor_work, &tip_work);
    failures += work_case_depth_and_gaps(&anchor_work, &tip_work);
    failures += work_case_gap_names();
    failures += work_case_json_render(&anchor_work, &tip_work);
    return failures;
}

static int surfaced_case_list_kinds(const char *dd)
{
    int failures = 0;
    struct mv_cmd c;

    mv_list(&c, dd, NULL);
    MV_CHECK("surface: list succeeds on an empty datadir",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    {
        const struct json_value *arr = json_get(&c.reply.data, "kinds");
        size_t n = arr ? json_size(arr) : 0;
        bool every_row_states_it = n == (size_t)METAVERSE_KIND_COUNT - 1u;

        for (size_t i = 0; i < n; i++) {
            const struct json_value *row = json_at(arr, i);
            const char *s = row ? mv_str(row, "settlement") : "";
            const char *m = row ? mv_str(row, "settlement_means") : "";

            if (!*s || strcmp(s, "unknown") == 0 || !*m)
                every_row_states_it = false;
        }
        MV_CHECK("surface: every kind row in the catalog states its "
                 "settlement class and what it means", every_row_states_it);
    }
    {
        const struct json_value *store =
            mv_find_kind(&c.reply.data, "storefront_product");
        const struct json_value *name =
            mv_find_kind(&c.reply.data, "znam_name");
        const struct json_value *swap =
            mv_find_kind(&c.reply.data, "contract_swap");
        const struct json_value *blob =
            mv_find_kind(&c.reply.data, "content");

        MV_CHECK("surface: a storefront product is labelled a LOCAL "
                 "declaration, in plain words, in the catalog",
                 store && strcmp(mv_str(store, "settlement"),
                                 "local_declaration") == 0 &&
                 strstr(mv_str(store, "settlement_means"),
                        "nothing outside this node") != NULL);
        MV_CHECK("surface: a ZNAM name is labelled proof-of-work settled",
                 name && strcmp(mv_str(name, "settlement"),
                                "proof_of_work") == 0);
        MV_CHECK("surface: a swap contract is labelled chain-anchored but "
                 "not measurable here",
                 swap && strcmp(mv_str(swap, "settlement"),
                                "chain_anchored_incomplete") == 0);
        MV_CHECK("surface: content is labelled content-addressed",
                 blob && strcmp(mv_str(blob, "settlement"),
                                "content_addressed") == 0);
    }
    mv_cmd_free(&c);
    return failures;
}

static int surfaced_case_content_view(void)
{
    int failures = 0;
    struct json_value j;
    const struct json_value *w;

    json_init(&j);
    MV_CHECK("surface: a content view renders its settlement class",
             mv_render_begin(METAVERSE_KIND_CONTENT, &j) &&
             strcmp(mv_str(&j, "settlement"), "content_addressed") == 0 &&
             *mv_str(&j, "settlement_means") != '\0');
    w = json_get(&j, "work");
    MV_CHECK("surface: its work block is present, not-applicable, and "
             "carries -1 rather than 0",
             w && !json_get_bool(json_get(w, "measurable")) &&
             json_get_int(json_get(w, "confirmation_depth")) == -1 &&
             json_get_int(json_get(w, "anchor_height")) == -1 &&
             strcmp(mv_str(w, "gap"), "not_applicable") == 0);
    json_free(&j);
    return failures;
}

static int surfaced_case_pow_view(void)
{
    int failures = 0;
    struct json_value j;
    const struct json_value *w;

    json_init(&j);
    MV_CHECK("surface: a proof-of-work kind's view says the question "
             "applies but is unanswered, not that the depth is 0",
             mv_render_begin(METAVERSE_KIND_ZNAM_NAME, &j) &&
             strcmp(mv_str(&j, "settlement"), "proof_of_work") == 0);
    w = json_get(&j, "work");
    MV_CHECK("surface: measurable=true with a no_anchor gap and -1 "
             "numbers",
             w && json_get_bool(json_get(w, "measurable")) &&
             strcmp(mv_str(w, "gap"), "no_anchor") == 0 &&
             json_get_int(json_get(w, "confirmation_depth")) == -1 &&
             !json_get_bool(json_get(w, "has_chainwork")) &&
             strcmp(mv_str(w, "chainwork_since_anchor"), "") == 0);
    json_free(&j);
    return failures;
}

static int surfaced_case_local_declaration_view(void)
{
    int failures = 0;
    struct json_value j;

    /* Settlement and evidence are separate axes: a locally-declared
     * property still gets a full view, and the view says both. */
    json_init(&j);
    MV_CHECK("surface: a locally-declared kind renders the blunt "
             "wording alongside its evidence fields",
             mv_render_begin(METAVERSE_KIND_STOREFRONT_PRODUCT, &j) &&
             strcmp(mv_str(&j, "settlement"), "local_declaration") == 0 &&
             strstr(mv_str(&j, "settlement_means"),
                    "nothing outside this node") != NULL &&
             json_get(&j, "evidence_grade") != NULL &&
             json_get(&j, "chain_bound") != NULL);
    json_free(&j);
    return failures;
}

static int surfaced_case_property_views(void)
{
    int failures = 0;
    /* The per-property view, which is what `metaverse property show`
     * renders. */
    failures += surfaced_case_content_view();
    failures += surfaced_case_pow_view();
    failures += surfaced_case_local_declaration_view();
    return failures;
}

int t_settlement_is_surfaced(void)
{
    int failures = 0;
    char dd[256];

    /* An empty datadir is enough: kinds[] is always fully populated. */
    test_make_tmpdir(dd, sizeof(dd), "metaverse", "settlement");

    failures += surfaced_case_list_kinds(dd);
    failures += surfaced_case_property_views();

    test_rm_rf_recursive(dd);
    return failures;
}

