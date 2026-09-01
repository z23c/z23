/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_metaverse_catalog — the sovereign-property catalog gate
 * (contexts/commons/modules/metaverse, engine/services/property_catalog_service.c, and the
 * metaverse.property.* handlers in contexts/commons/controllers/src/metaverse_controller.c).
 *
 * Coverage:
 *   1. property_id pure rules: kind/authority names, make/format/parse
 *      round-trip, and every rejection (zero root, unknown kind, missing or
 *      doubled ':', short/long/non-hex root, trailing bytes).
 *   2. The action vocabulary: single-bit naming, name round-trip, mask
 *      validity, and the refusal to render a truncated action list.
 *   3. The adapter registry: EVERY property kind has exactly one row, wired
 *      or explicitly unavailable — no kind may drop out of the catalog.
 *   4. CONTENT adapter against a real blob: show/list report present with
 *      the local_content_hash grade and chain_bound false; then the CAS
 *      chunk is deleted and the SAME query reports incomplete; a malformed
 *      manifest reports an integrity gap rather than absent or disappearing;
 *      then deletion alone reports absent. No stale caching.
 *   5. ZCODE_PACKAGE adapter against a really published release: owner is
 *      the publisher key, revision is the publisher sequence, and the grade
 *      is local_signature because the envelope's signature is verified IN
 *      THAT CALL. Deleting the envelope DROPS the grade to
 *      local_content_hash instead of keeping an unearned claim.
 *   6. THE READ-ONLY CONTRACT (t_readonly_contract) — the parent-failing
 *      case. `metaverse property list` must not mutate the datadir, and
 *      before vcs_package_cas_present_in() the only way to ask the store
 *      about its CAS was vcs_package_store_open(), whose recovery sweep
 *      DELETES orphan CAS objects. The test plants an orphan, proves the
 *      catalog leaves it untouched, and then proves store_open removes it —
 *      the contrast that makes the read-only path necessary rather than
 *      merely tidy.
 *   7. The CLI path: both leaves through zcl_command_registry_input_validate
 *      plus the handler they BIND, so the declared input keys are proven
 *      callable and an undeclared key is still refused.
 *
 * Handlers run in-process on ./test-tmp datadirs; CHAIN_MAIN is pinned so
 * the zcode acceptance rules are deterministic. */

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

#define MV_CHECK(name, expr) do {                                       \
    if (expr) { printf("  metaverse_catalog: %s... OK\n", (name)); }    \
    else { printf("  metaverse_catalog: %s... FAIL\n", (name));         \
           failures++; }                                                \
} while (0)

static const char k_hexd[] = "0123456789abcdef";

static void mv_hex32(const uint8_t in[32], char out[65])
{
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = k_hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = k_hexd[in[i] & 0xf];
    }
    out[64] = '\0';
}

static char *mv_hex(const uint8_t *data, size_t len)
{
    char *out = malloc(2 * len + 1);

    if (!out)
        return NULL;
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = k_hexd[(data[i] >> 4) & 0xf];
        out[2 * i + 1] = k_hexd[data[i] & 0xf];
    }
    out[2 * len] = '\0';
    return out;
}

/* ── 1: property_id pure rules ────────────────────────────────────── */

static int t_property_id_rules(void)
{
    int failures = 0;
    uint8_t root[32];
    uint8_t zero[32];
    struct metaverse_property_id id, back;
    char text[METAVERSE_ID_TEXT_MAX];

    memset(zero, 0, sizeof(zero));
    for (int i = 0; i < 32; i++)
        root[i] = (uint8_t)(0xa0 + i);

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

    MV_CHECK("id: make accepts a real kind and a non-zero root",
             metaverse_property_id_make(METAVERSE_KIND_CONTENT, root, &id) &&
             metaverse_property_id_valid(&id));
    MV_CHECK("id: an all-zero root is refused (uninitialized must not read "
             "as a real object)",
             !metaverse_property_id_make(METAVERSE_KIND_CONTENT, zero, &id));
    {
        struct metaverse_property_id z;

        memset(&z, 0, sizeof(z));
        MV_CHECK("id: a zeroed struct is not a valid id",
                 !metaverse_property_id_valid(&z));
    }
    MV_CHECK("id: UNKNOWN and out-of-range kinds are refused",
             !metaverse_property_id_make(METAVERSE_KIND_UNKNOWN, root, &id) &&
             !metaverse_property_id_make(METAVERSE_KIND_COUNT, root, &id));

    MV_CHECK("id: format/parse round-trip",
             metaverse_property_id_make(METAVERSE_KIND_ZCODE_PACKAGE, root,
                                        &id) &&
             metaverse_property_id_format(&id, text, sizeof(text)) &&
             metaverse_property_id_parse(text, &back) &&
             metaverse_property_id_equal(&id, &back));
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
                 metaverse_property_id_parse(upper, &back) &&
                 back.kind == METAVERSE_KIND_CONTENT);
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
             metaverse_property_id_make(METAVERSE_KIND_CONTENT, root, &id) &&
             !metaverse_property_id_format(&id, text, 16) && text[0] == '\0');
    MV_CHECK("id: equality is NULL-safe and never true for NULL",
             !metaverse_property_id_equal(NULL, &id) &&
             !metaverse_property_id_equal(&id, NULL));
    return failures;
}

/* ── 2: the action vocabulary ─────────────────────────────────────── */

static int t_action_vocabulary(void)
{
    int failures = 0;
    char buf[METAVERSE_ACTION_LIST_MAX];

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
             metaverse_action_mask_format(0, buf, sizeof(buf)) &&
             buf[0] == '\0');
    MV_CHECK("actions: ALL renders every name in table order",
             metaverse_action_mask_format(METAVERSE_ACTION_ALL, buf,
                                          sizeof(buf)) &&
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

/* ── 3: adapter registry coverage ─────────────────────────────────── */

static int t_adapter_registry(void)
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

/* ── 3a: the MVP scope partition is a pinned decision ───────────────────── */

/* docs/METAVERSE_MVP.md criterion MM3: the catalog is complete OR honestly
 * scoped. This table IS the scope decision — the four datadir-provable kinds
 * are in MVP scope, the four runtime/node.db kinds are explicitly out — and
 * it is asserted against the live registry so a kind silently moving between
 * the two sets (or an unwired kind losing its reason) fails here. The
 * MV_MVP_SCOPE marker naming this contract lives with the declarations in
 * contexts/commons/modules/metaverse/src/adapter_registry.c. */
static int t_mvp_scope_decision(void)
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

static int t_settlement_classes(void)
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

/* ── 3c: the work measurement ─────────────────────────────────────── */

/* Build the accumulated-work value a block index entry would carry. */
static void mv_work(struct arith_uint256 *w, uint64_t v)
{
    arith_uint256_set_u64(w, v);
}

static int t_work_measurement(void)
{
    int failures = 0;
    struct metaverse_work_proof p;
    struct arith_uint256 anchor_work, tip_work;

    mv_work(&anchor_work, 1000);
    mv_work(&tip_work, 1064);

    /* The whole point: a non-PoW kind gets UNKNOWN, not zero, no matter
     * what heights the caller passes. */
    {
        const enum metaverse_kind non_pow[] = {
            METAVERSE_KIND_CONTENT, METAVERSE_KIND_ZCODE_PACKAGE,
            METAVERSE_KIND_HOSTED_SERVICE, METAVERSE_KIND_ENDPOINT_ONION,
            METAVERSE_KIND_STOREFRONT_PRODUCT, METAVERSE_KIND_CONTRACT_SWAP,
        };
        bool refused = true;
        bool unknown_not_zero = true;

        for (size_t i = 0; i < sizeof(non_pow) / sizeof(non_pow[0]); i++) {
            if (metaverse_work_measure(non_pow[i], 100, &anchor_work, 900,
                                       &tip_work, &p))
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
    }

    /* A chain-anchored fixture: anchor at 500, tip at 564. */
    MV_CHECK("work: a proof-of-work kind with an anchor and a tip measures",
             metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 500,
                                    &anchor_work, 564, &tip_work, &p));
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

        arith_uint256_sub(&delta, &tip_work, &anchor_work);
        arith_uint256_get_hex(&delta, expect);
        MV_CHECK("work: chainwork is the block index's own accumulated "
                 "work, differenced",
                 p.has_chainwork && strcmp(p.chainwork_hex, expect) == 0 &&
                 strcmp(p.chainwork_hex,
                        "00000000000000000000000000000000000000000000000000"
                        "00000000000040") == 0);
    }

    /* Depth 0 is a real answer and must not read as unknown. */
    MV_CHECK("work: an anchor AT the tip is depth 0, not unknown",
             metaverse_work_measure(METAVERSE_KIND_ZSLP_ASSET, 900,
                                    &tip_work, 900, &tip_work, &p) &&
             p.has_depth && p.depth == 0 && p.has_chainwork &&
             strcmp(p.chainwork_hex,
                    "000000000000000000000000000000000000000000000000000000"
                    "0000000000") == 0);

    /* Missing halves each degrade to a NAMED gap, never to a number. */
    MV_CHECK("work: no anchor height -> no_anchor, nothing measured",
             !metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, -1,
                                     &anchor_work, 564, &tip_work, &p) &&
             p.applicable && p.gap == METAVERSE_WORK_GAP_NO_ANCHOR &&
             !p.has_depth && p.depth == -1 && !p.has_chainwork);
    MV_CHECK("work: no tip -> no_tip, and the anchor still reports",
             !metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 500,
                                     &anchor_work, -1, NULL, &p) &&
             p.gap == METAVERSE_WORK_GAP_NO_TIP && p.has_anchor_height &&
             p.anchor_height == 500 && !p.has_depth && p.depth == -1);
    MV_CHECK("work: an anchor ABOVE the tip is a contradiction, not a "
             "negative or clamped depth",
             !metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 600,
                                     &anchor_work, 500, &tip_work, &p) &&
             !p.has_depth && p.depth == -1 && !p.has_chainwork &&
             p.gap == METAVERSE_WORK_GAP_ANCHOR_ABOVE_TIP);
    MV_CHECK("work: depth stands without chainwork when the block index "
             "values are unavailable",
             metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 500, NULL, 564,
                                    NULL, &p) &&
             p.has_depth && p.depth == 64 && !p.has_chainwork &&
             p.chainwork_hex[0] == '\0');
    MV_CHECK("work: work going BACKWARDS is not reported as a magnitude",
             metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 500, &tip_work,
                                    564, &anchor_work, &p) &&
             p.has_depth && !p.has_chainwork);
    MV_CHECK("work: a NULL out is refused",
             !metaverse_work_measure(METAVERSE_KIND_ZNAM_NAME, 500,
                                     &anchor_work, 564, &tip_work, NULL));
    {
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
    }
    /* No score, rating, or tier: the render carries mechanism + numbers. */
    {
        struct json_value j;
        char doc[2048];
        const char *cw, *gap, *why;
        bool ok;

        (void)metaverse_work_measure(METAVERSE_KIND_CONTENT, 100,
                                     &anchor_work, 900, &tip_work, &p);
        json_init(&j);
        ok = metaverse_work_to_json(&p, &j);
        cw  = json_get_str(json_get(&j, "chainwork_since_anchor"));
        gap = json_get_str(json_get(&j, "gap"));
        why = json_get_str(json_get(&j, "gap_reason"));
        MV_CHECK("work: a not-applicable proof renders measurable=false, "
                 "-1 heights and an empty chainwork",
                 ok && !json_get_bool(json_get(&j, "measurable")) &&
                 json_get_int(json_get(&j, "anchor_height")) == -1 &&
                 json_get_int(json_get(&j, "tip_height")) == -1 &&
                 json_get_int(json_get(&j, "confirmation_depth")) == -1 &&
                 cw && *cw == '\0' && gap &&
                 strcmp(gap, "not_applicable") == 0 && why && *why);
        doc[0] = '\0';
        (void)json_write(&j, doc, sizeof(doc));
        MV_CHECK("work: the render invents no score, rating, or trust tier",
                 doc[0] != '\0' && !strstr(doc, "score") &&
                 !strstr(doc, "rating") && !strstr(doc, "trust") &&
                 !strstr(doc, "tier") && !strstr(doc, "level"));
        json_free(&j);
    }
    return failures;
}

/* ── in-process command runner ────────────────────────────────────── */

struct mv_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void mv_cmd_init(struct mv_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.metaverse_test.v1");
}

static void mv_cmd_free(struct mv_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

static const struct zcl_command_spec *mv_leaf(const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();

    if (!reg)
        return NULL;
    for (size_t i = 0; i < reg->count; i++) {
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    }
    return NULL;
}

/* Call `metaverse property show` for one id text against `dd`. */
static void mv_show(struct mv_cmd *c, const char *dd, const char *id_text)
{
    mv_cmd_init(c);
    (void)json_push_kv_str(&c->input, "datadir", dd);
    (void)json_push_kv_str(&c->input, "property_id", id_text);
    zcl_native_handle_metaverse_property_show(&c->request, &c->reply);
}

static void mv_list(struct mv_cmd *c, const char *dd, const char *kind)
{
    mv_cmd_init(c);
    (void)json_push_kv_str(&c->input, "datadir", dd);
    if (kind)
        (void)json_push_kv_str(&c->input, "kind", kind);
    zcl_native_handle_metaverse_property_list(&c->request, &c->reply);
}

static const char *mv_str(const struct json_value *v, const char *key)
{
    const char *s = json_get_str(json_get(v, key));

    return s ? s : "";
}

/* The array element whose "property_id" equals id_text, or NULL. */
static const struct json_value *mv_find_item(const struct json_value *data,
                                             const char *id_text)
{
    const struct json_value *arr = json_get(data, "properties");
    size_t n = arr ? json_size(arr) : 0;

    for (size_t i = 0; i < n; i++) {
        const struct json_value *row = json_at(arr, i);

        if (row && strcmp(mv_str(row, "property_id"), id_text) == 0)
            return row;
    }
    return NULL;
}

/* ── 3d: settlement + work reach the inspection surfaces ──────────── */

/* Find the kinds[] coverage row for one kind name. */
static const struct json_value *mv_find_kind(const struct json_value *data,
                                             const char *kind_name)
{
    const struct json_value *arr = json_get(data, "kinds");
    size_t n = arr ? json_size(arr) : 0;

    for (size_t i = 0; i < n; i++) {
        const struct json_value *row = json_at(arr, i);

        if (row && strcmp(mv_str(row, "kind"), kind_name) == 0)
            return row;
    }
    return NULL;
}

/* Render one kind's view straight from view_begin, i.e. the state every
 * adapter starts from. No fixture needed: the settlement class and the
 * not-measured work block are derived from the KIND, so they are already
 * correct before any store is read. */
static bool mv_render_begin(enum metaverse_kind kind, struct json_value *out)
{
    struct metaverse_property_id id;
    struct metaverse_property_view view;
    uint8_t root[32];

    for (int i = 0; i < 32; i++)
        root[i] = (uint8_t)(0x11 + i);
    if (!metaverse_property_id_make(kind, root, &id))
        return false;
    if (!metaverse_view_begin(&view, &id))
        return false;
    return metaverse_view_to_json(&view, out);
}

static int t_settlement_is_surfaced(void)
{
    int failures = 0;
    char dd[256];
    struct mv_cmd c;

    /* An empty datadir is enough: kinds[] is always fully populated. */
    test_make_tmpdir(dd, sizeof(dd), "metaverse", "settlement");

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

    /* The per-property view, which is what `metaverse property show`
     * renders. */
    {
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
    }

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 4: CONTENT adapter against a real blob ───────────────────────── */

static int t_content_adapter(void)
{
    int failures = 0;
    char dd[256];
    char zcode_dir[512];
    char root_hex[65];
    char id_text[METAVERSE_ID_TEXT_MAX];
    char chunk_path[768];
    char manifest_path[768];
    const uint8_t bytes[] = "sovereign content, byte-identical everywhere";
    uint8_t root[32];
    uint8_t chunk_hash[32];
    char chunk_hex[65];
    struct vcs_package_store *store;
    struct mv_cmd c;

    test_make_tmpdir(dd, sizeof(dd), "metaverse", "content");
    snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", dd);

    store = vcs_package_store_open(dd, 4u * 1024u * 1024u);
    MV_CHECK("content: fixture store opens", store != NULL);
    if (!store) {
        test_rm_rf_recursive(dd);
        return failures;
    }
    MV_CHECK("content: blob stores",
             vcs_blob_put_to(store, bytes, sizeof(bytes) - 1, root) ==
                 VCS_BLOB_OK);
    vcs_package_store_close(store);

    mv_hex32(root, root_hex);
    snprintf(id_text, sizeof(id_text), "content:%s", root_hex);
    {
        struct metaverse_property_id id;

        MV_CHECK("content: blob root parses as a content property id",
                 metaverse_property_id_parse(id_text, &id) &&
                 id.kind == METAVERSE_KIND_CONTENT &&
                 memcmp(id.root, root, 32) == 0);
    }

    /* show — present, byte-identity evidence, and NOT chain bound. */
    mv_show(&c, dd, id_text);
    MV_CHECK("content: show succeeds",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    MV_CHECK("content: show reports the property present and determined",
             strcmp(mv_str(&c.reply.data, "status"), "present") == 0 &&
             json_get_bool(json_get(&c.reply.data, "determined")));
    MV_CHECK("content: the evidence grade is the locally re-derived root",
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_content_hash") == 0 &&
             strcmp(mv_str(&c.reply.data, "evidence_source"),
                    "mv_manifest_verify_possession") == 0);
    MV_CHECK("content: the view is explicitly NOT chain-bound and carries "
             "no freshness height",
             !json_get_bool(json_get(&c.reply.data, "chain_bound")) &&
             !json_get_bool(json_get(&c.reply.data,
                                     "has_freshness_height")) &&
             json_get_int(json_get(&c.reply.data, "freshness_height")) == -1);
    /* And the same on a REAL adapter-filled view, not just view_begin: the
     * content adapter must not have overwritten the class or minted a
     * measurement out of the tip. */
    MV_CHECK("content: a really-read blob still reports content_addressed "
             "with no work measurement",
             strcmp(mv_str(&c.reply.data, "settlement"),
                    "content_addressed") == 0 &&
             json_get(&c.reply.data, "work") &&
             !json_get_bool(json_get(json_get(&c.reply.data, "work"),
                                     "measurable")) &&
             json_get_int(json_get(json_get(&c.reply.data, "work"),
                                   "confirmation_depth")) == -1);
    MV_CHECK("content: no owner is recorded, and it says so by name",
             strcmp(mv_str(&c.reply.data, "owner_principal"), "") == 0 &&
             strcmp(mv_str(&c.reply.data, "owner_principal_kind"),
                    "none") == 0);
    MV_CHECK("content: authority source is the blob store",
             strcmp(mv_str(&c.reply.data, "authority_source"),
                    "vcs.blob_store") == 0);
    MV_CHECK("content: complete bytes support host and deliver, never "
             "transfer (there is no title to move)",
             strstr(mv_str(&c.reply.data, "actions_csv"), "host") != NULL &&
             strstr(mv_str(&c.reply.data, "actions_csv"), "deliver") != NULL &&
             strstr(mv_str(&c.reply.data, "actions_csv"),
                    "transfer") == NULL &&
             strstr(mv_str(&c.reply.data, "actions_csv"),
                    "publish_revision") == NULL);
    {
        const char *ir = mv_str(&c.reply.data, "immutable_root");
        const char *cr = mv_str(&c.reply.data, "content_root");

        MV_CHECK("content: the content root is the chunk hash, and the "
                 "immutable root is the manifest root",
                 strcmp(ir, root_hex) == 0 && strlen(cr) == 64 &&
                 strcmp(cr, root_hex) != 0);
    }
    MV_CHECK("content: chunk accounting is complete",
             json_get_int(json_get(&c.reply.data, "chunk_total")) == 1 &&
             json_get_int(json_get(&c.reply.data, "chunks_present")) == 1 &&
             json_get_int(json_get(&c.reply.data, "chunks_verified")) == 1 &&
             json_get_int(json_get(&c.reply.data, "bytes_verified")) ==
                 (int64_t)(sizeof(bytes) - 1u) &&
             json_get_bool(json_get(&c.reply.data,
                                    "manifest_root_verified")) &&
             json_get_bool(json_get(&c.reply.data,
                                    "verification_complete")) &&
             strcmp(mv_str(&c.reply.data, "verification_gap"), "") == 0 &&
             json_get_int(json_get(&c.reply.data, "file_count")) == 1);
    /* Keep the chunk hash for the deletion step below. */
    snprintf(chunk_hex, sizeof(chunk_hex), "%s",
             mv_str(&c.reply.data, "content_root"));
    snprintf(chunk_path, sizeof(chunk_path), "%s/cas/sha3/%.2s/%s",
             zcode_dir, chunk_hex, chunk_hex);
    mv_cmd_free(&c);

    /* list — the blob is in the catalog, and every kind reports a row. */
    mv_list(&c, dd, NULL);
    MV_CHECK("content: list succeeds",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    MV_CHECK("content: the blob appears in the unfiltered catalog",
             mv_find_item(&c.reply.data, id_text) != NULL);
    MV_CHECK("content: a complete store reports no hidden integrity gap",
             json_get_bool(json_get(&c.reply.data, "integrity_ok")) &&
             json_get_int(json_get(&c.reply.data,
                                   "integrity_gap_count")) == 0);
    MV_CHECK("content: every property kind produces a coverage row",
             json_get_int(json_get(&c.reply.data, "kinds_scanned")) ==
                 (int64_t)METAVERSE_KIND_COUNT - 1);
    {
        const struct json_value *kinds = json_get(&c.reply.data, "kinds");
        size_t n = kinds ? json_size(kinds) : 0;
        bool ok = n == (size_t)METAVERSE_KIND_COUNT - 1;

        for (size_t i = 0; i < n; i++) {
            const struct json_value *row = json_at(kinds, i);
            if (!json_get_bool(json_get(row, "available")) &&
                mv_str(row, "unavailable_reason")[0] == '\0')
                ok = false;
        }
        MV_CHECK("content: kinds without a reader are reported unavailable "
                 "with a reason, not dropped", ok);
    }
    mv_cmd_free(&c);

    /* A pathname-shaped CAS entry is not possession. Exercise every cheap
     * false-positive shape before the missing-file case below. */
    {
        uint8_t wrong[sizeof(bytes) - 1u];
        FILE *f;

        memset(wrong, 0xa5, sizeof(wrong));
        f = fopen(chunk_path, "wb");
        MV_CHECK("content: same-length wrong bytes are planted",
                 f && fwrite(wrong, 1, sizeof(wrong), f) == sizeof(wrong));
        if (f)
            fclose(f);
        mv_show(&c, dd, id_text);
        MV_CHECK("content: same-length wrong bytes never become PRESENT",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
                 json_get_int(json_get(&c.reply.data, "chunks_present")) == 1 &&
                 json_get_int(json_get(&c.reply.data, "chunks_verified")) == 0 &&
                 !json_get_bool(json_get(&c.reply.data,
                                         "verification_complete")) &&
                 strcmp(mv_str(&c.reply.data, "verification_gap"),
                        "chunk_hash_mismatch") == 0 &&
                 strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
        mv_cmd_free(&c);

        f = fopen(chunk_path, "wb");
        MV_CHECK("content: canonical bytes restore after hash mismatch",
                 f && fwrite(bytes, 1, sizeof(bytes) - 1u, f) ==
                          sizeof(bytes) - 1u);
        if (f)
            fclose(f);
        MV_CHECK("content: canonical CAS path is removed for symlink case",
                 unlink(chunk_path) == 0);
        MV_CHECK("content: symlink is planted at the CAS coordinate",
                 symlink("/dev/null", chunk_path) == 0);
        mv_show(&c, dd, id_text);
        MV_CHECK("content: O_NOFOLLOW rejects a symlink as possession",
                 strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
                 strcmp(mv_str(&c.reply.data, "verification_gap"),
                        "chunk_symlink") == 0 &&
                 strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
        mv_cmd_free(&c);
        MV_CHECK("content: symlink is removed", unlink(chunk_path) == 0);

        f = fopen(chunk_path, "wb");
        MV_CHECK("content: zero-length CAS object is planted", f != NULL);
        if (f)
            fclose(f);
        mv_show(&c, dd, id_text);
        MV_CHECK("content: wrong length never becomes possession",
                 strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
                 strcmp(mv_str(&c.reply.data, "verification_gap"),
                        "chunk_length_mismatch") == 0 &&
                 strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
        mv_cmd_free(&c);

        MV_CHECK("content: zero-length object is removed",
                 unlink(chunk_path) == 0);
        MV_CHECK("content: directory is planted at the CAS coordinate",
                 mkdir(chunk_path, 0700) == 0);
        mv_show(&c, dd, id_text);
        MV_CHECK("content: non-regular CAS coordinate never becomes present",
                 strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
                 strcmp(mv_str(&c.reply.data, "verification_gap"),
                        "chunk_not_regular") == 0 &&
                 strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
        mv_cmd_free(&c);
        MV_CHECK("content: directory coordinate is removed",
                 rmdir(chunk_path) == 0);
        f = fopen(chunk_path, "wb");
        MV_CHECK("content: canonical bytes restore after shape cases",
                 f && fwrite(bytes, 1, sizeof(bytes) - 1u, f) ==
                          sizeof(bytes) - 1u);
        if (f)
            fclose(f);
    }

    /* THE NO-STALE-CACHE PROOF, step 1: delete the CAS byte. */
    MV_CHECK("content: the chunk hash was captured", strlen(chunk_hex) == 64);
    MV_CHECK("content: the CAS object exists before deletion",
             access(chunk_path, F_OK) == 0);
    MV_CHECK("content: the CAS object is deleted", unlink(chunk_path) == 0);

    mv_show(&c, dd, id_text);
    MV_CHECK("content: the very next read reports incomplete — the "
             "projection cached nothing",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
             json_get_int(json_get(&c.reply.data, "chunks_present")) == 0);
    /* Inspection is a QUERY now, so the action set an incomplete property
     * supports is genuinely empty — the field must render as the empty string
     * and not fall back to naming the reserved bit, which would read to a
     * caller as a right it does not have. */
    MV_CHECK("content: an incomplete property supports no ACTION at all",
             strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
    MV_CHECK("content: the incomplete view says why",
             strcmp(mv_str(&c.reply.data, "verification_gap"),
                    "chunk_missing") == 0 &&
             strstr(mv_str(&c.reply.data, "reason"), "chunk_missing") != NULL);
    mv_cmd_free(&c);

    /* Step 2: corruption is not absence, and must not vanish from list
     * accounting without an explicit integrity gap. */
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifests/%s",
             zcode_dir, root_hex);
    {
        FILE *f = fopen(manifest_path, "wb");
        bool wrote = f && fwrite("x", 1, 1, f) == 1;

        if (f)
            fclose(f);
        MV_CHECK("content: the manifest is replaced by malformed bytes",
                 wrote);
    }
    mv_show(&c, dd, id_text);
    MV_CHECK("content: malformed is unknown, not absent or determined",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "unknown") == 0 &&
             !json_get_bool(json_get(&c.reply.data, "determined")) &&
             strcmp(mv_str(&c.reply.data, "evidence_grade"), "unknown") == 0 &&
             strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0 &&
             strstr(mv_str(&c.reply.data, "reason"), "invalid") != NULL);
    mv_cmd_free(&c);

    mv_list(&c, dd, "content");
    {
        const struct json_value *row =
            mv_find_kind(&c.reply.data, "content");
        MV_CHECK("content: malformed cannot disappear as an empty inventory",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED && row &&
                 !json_get_bool(json_get(&c.reply.data, "integrity_ok")) &&
                 json_get_int(json_get(&c.reply.data,
                                       "integrity_gap_count")) == 1 &&
                 json_get_bool(json_get(row, "integrity_checked")) &&
                 !json_get_bool(json_get(row, "integrity_ok")) &&
                 json_get_int(json_get(row, "integrity_gap_count")) == 1 &&
                 strstr(mv_str(row, "integrity_reason"), "invalid") != NULL);
    }
    mv_cmd_free(&c);

    /* Step 3: deletion alone means the object is gone entirely. */
    MV_CHECK("content: the manifest is deleted", unlink(manifest_path) == 0);
    mv_show(&c, dd, id_text);
    MV_CHECK("content: a removed object reads as absent, determined",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "absent") == 0 &&
             json_get_bool(json_get(&c.reply.data, "determined")) &&
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_store_read") == 0 &&
             !json_get_bool(json_get(&c.reply.data,
                                     "manifest_root_verified")) &&
             !json_get_bool(json_get(&c.reply.data,
                                     "verification_complete")));
    mv_cmd_free(&c);

    mv_list(&c, dd, "content");
    MV_CHECK("content: the removed blob is gone from the catalog too",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             mv_find_item(&c.reply.data, id_text) == NULL &&
             json_get_int(json_get(&c.reply.data, "rendered")) == 0 &&
             json_get_bool(json_get(&c.reply.data, "integrity_ok")));
    mv_cmd_free(&c);

    (void)vcs_package_cas_present_in(zcode_dir, chunk_hash);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── zcode publication fixture (the test_zcode_publish pattern) ────── */

struct mv_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    char root_hex[65];
};

static char *g_mv_recipe_hex;
static uint8_t g_mv_recipe_root[32];

static bool mv_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool mv_sign(struct vcs_package_release *r, struct privkey *sk)
{
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    struct uint256 hash;
    unsigned char compact[COMPACT_SIGNATURE_SIZE];

    if (vcs_package_release_id(r, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    memcpy(hash.data, id, 32);
    if (!privkey_sign_compact(sk, &hash, compact))
        return false;
    memcpy(r->signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    return true;
}

static bool mv_t1_reward(char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    size_t pubkey_len = 0, script_len = 0;
    const unsigned char *pubkey_prefix, *script_prefix;
    struct tx_destination dest;

    if (!params)
        return false;
    pubkey_prefix = chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS,
                                               &pubkey_len);
    script_prefix = chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS,
                                               &script_len);
    if (!pubkey_prefix || !script_prefix)
        return false;
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x44, 20);
    return encode_destination(&dest, pubkey_prefix, pubkey_len, script_prefix,
                              script_len, out, out_size);
}

static bool mv_add_file(struct mv_pkg *p, const char *dir, const char *path,
                        const char *content)
{
    char full[1024];
    const char *slash = strrchr(path, '/');
    FILE *f;
    size_t len = strlen(content);
    bool wrote;
    uint8_t hash[32];

    snprintf(full, sizeof(full), "%s/%s", dir, path);
    if (slash) {
        char parent[1024];

        snprintf(parent, sizeof(parent), "%s/%.*s", dir,
                 (int)(slash - path), path);
        (void)mkdir(parent, 0700);
    }
    f = fopen(full, "wb");
    if (!f)
        return false;
    wrote = fwrite(content, 1, len, f) == len;
    fclose(f);
    if (!wrote || !vcs_package_chunk_hash((const uint8_t *)content, len, hash))
        return false;
    return vcs_package_manifest_add(&p->manifest, path,
                                    VCS_PACKAGE_MODE_FILE, len, hash, 1);
}

static bool mv_make_package(struct mv_pkg *p, const char *dir)
{
    memset(p, 0, sizeof(*p));
    vcs_package_manifest_init(&p->manifest);
    (void)mkdir(dir, 0700);
    if (!mv_add_file(p, dir, "LICENSE",
                     "MIT License\n\nPermission is hereby granted.\n") ||
        !mv_add_file(p, dir, "include/prop.h",
                     "#pragma once\nstruct prop { unsigned id; };\n") ||
        !mv_add_file(p, dir, "src/prop.c",
                     "#include \"prop.h\"\nint prop_id(void){return 1;}\n"))
        return false;
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire, &p->wire_len))
        return false;
    if (!vcs_package_manifest_root(&p->manifest, p->root))
        return false;
    mv_hex32(p->root, p->root_hex);
    return true;
}

static bool mv_use_recipe(const struct vcs_package_manifest *m)
{
    struct vcs_package_recipe r;
    bool ok = true;
    uint8_t *wire = NULL;
    size_t wire_len = 0;

    vcs_package_recipe_init(&r);
    for (size_t i = 0; ok && i < m->count; i++) {
        const char *path = m->files[i].path;
        size_t len = strlen(path);

        if (len > 2 && strcmp(path + len - 2, ".h") == 0) {
            const char *slash = strrchr(path, '/');

            ok = vcs_package_recipe_add_header(&r, path, NULL);
            if (ok && slash) {
                char dir[1024];
                enum vcs_package_recipe_error rerr = VCS_PACKAGE_RECIPE_OK;

                snprintf(dir, sizeof(dir), "%.*s", (int)(slash - path), path);
                if (!vcs_package_recipe_add_include_dir(&r, dir, &rerr) &&
                    rerr != VCS_PACKAGE_RECIPE_ERR_LIST_ORDER)
                    ok = false;
            }
        } else if (len > 2 && strcmp(path + len - 2, ".c") == 0) {
            ok = vcs_package_recipe_add_source(&r, path, NULL);
        }
    }
    if (ok)
        ok = vcs_package_recipe_add_define(&r, "ZCL_FIXTURE=1", NULL) &&
             vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                            NULL);
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    if (ok)
        ok = vcs_package_recipe_root(&r, g_mv_recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&r, &wire, &wire_len) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    if (!ok) {
        free(wire);
        return false;
    }
    free(g_mv_recipe_hex);
    g_mv_recipe_hex = mv_hex(wire, wire_len);
    free(wire);
    return g_mv_recipe_hex != NULL;
}

static bool mv_release(struct vcs_package_release *r, uint8_t key_seed,
                       const char *name, const uint8_t package_root[32])
{
    struct privkey sk;
    struct pubkey pk;

    memset(r, 0, sizeof(*r));
    if (!mv_keypair(key_seed, &sk, &pk))
        return false;
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.0.0");
    memcpy(r->package_root, package_root, 32);
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = 7u;
    if (!mv_t1_reward(r->reward_address, sizeof(r->reward_address)))
        return false;
    snprintf(r->license, sizeof(r->license), "MIT");
    memcpy(r->recipe_root, g_mv_recipe_root, 32);
    if (!vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id)))
        return false;
    return mv_sign(r, &sk);
}

/* Publish a package into `dd` through the real zcode commit handler.
 * Returns the publisher pubkey hex in pub_hex and the release id hex. */
static bool mv_publish(const char *dd, struct mv_pkg *p, char pub_hex[67],
                       char release_id_hex[65])
{
    struct vcs_package_release r;
    char pkgdir[512];
    char *release_hex;
    char *manifest_hex;
    struct mv_cmd c;
    bool ok;
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    struct privkey sk;
    struct pubkey pk;

    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);
    if (!mv_make_package(p, pkgdir) || !mv_use_recipe(&p->manifest) ||
        !mv_release(&r, 0x7b, "rhett/property-kit", p->root))
        return false;
    if (!mv_keypair(0x7b, &sk, &pk))
        return false;
    for (size_t i = 0; i < pk.size; i++) {
        pub_hex[2 * i]     = k_hexd[(pk.vch[i] >> 4) & 0xf];
        pub_hex[2 * i + 1] = k_hexd[pk.vch[i] & 0xf];
    }
    pub_hex[2 * pk.size] = '\0';
    if (vcs_package_release_id(&r, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    mv_hex32(id, release_id_hex);

    release_hex = NULL;
    {
        uint8_t *wire = NULL;
        size_t wire_len = 0;

        if (vcs_package_release_serialize(&r, &wire, &wire_len) !=
            VCS_PACKAGE_RELEASE_OK)
            return false;
        release_hex = mv_hex(wire, wire_len);
        free(wire);
    }
    manifest_hex = mv_hex(p->wire, p->wire_len);
    if (!release_hex || !manifest_hex || !g_mv_recipe_hex) {
        free(release_hex);
        free(manifest_hex);
        return false;
    }

    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", g_mv_recipe_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED;
    mv_cmd_free(&c);
    free(release_hex);
    free(manifest_hex);
    return ok;
}

struct mv_verify_mutation {
    const char *path;
    size_t length;
    bool fired;
};

static void mv_mutate_after_first_hash(void *context,
                                       uint32_t chunks_verified)
{
    struct mv_verify_mutation *mutation = context;
    uint8_t *wrong;
    FILE *f;

    if (!mutation || mutation->fired || chunks_verified != 1)
        return;
    wrong = malloc(mutation->length);
    if (!wrong)
        return;
    memset(wrong, 0x5a, mutation->length);
    f = fopen(mutation->path, "wb");
    mutation->fired =
        f && fwrite(wrong, 1, mutation->length, f) == mutation->length;
    if (f)
        fclose(f);
    free(wrong);
}

/* ── 5: ZCODE_PACKAGE adapter against a real publication ──────────── */

static int t_zcode_adapter(void)
{
    int failures = 0;
    char dd[256];
    char zcode_dir[512];
    char id_text[METAVERSE_ID_TEXT_MAX];
    char pub_hex[67] = {0};
    char release_id_hex[65] = {0};
    char release_path[768];
    char manifest_path[768];
    struct mv_pkg p;
    struct mv_cmd c;
    bool published;

    chain_params_select(CHAIN_MAIN);
    test_make_tmpdir(dd, sizeof(dd), "metaverse", "zcode");
    snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", dd);

    published = mv_publish(dd, &p, pub_hex, release_id_hex);
    MV_CHECK("zcode: the fixture package publishes", published);
    if (!published) {
        vcs_package_manifest_free(&p.manifest);
        free(p.wire);
        test_rm_rf_recursive(dd);
        return failures;
    }
    snprintf(id_text, sizeof(id_text), "zcode_package:%s", p.root_hex);

    /* Deterministic TOCTOU proof: mutate the first coordinate after it was
     * hashed but before the verifier's final fingerprint pass. */
    {
        static const char first_file[] =
            "MIT License\n\nPermission is hereby granted.\n";
        struct mv_manifest_read manifest;
        struct mv_verify_mutation mutation;
        char first_hash[65];
        char first_path[768];
        uint64_t bytes_used = 0;
        uint32_t operations_used = 0;
        FILE *f;

        mv_hex32(p.manifest.files[0].chunk_hashes, first_hash);
        snprintf(first_path, sizeof(first_path), "%s/cas/sha3/%.2s/%s",
                 zcode_dir, first_hash, first_hash);
        mutation = (struct mv_verify_mutation){
            .path = first_path,
            .length = sizeof(first_file) - 1u,
            .fired = false,
        };
        MV_CHECK("zcode: canonical manifest opens for bounded race proof",
                 mv_manifest_read(zcode_dir, p.root_hex, &manifest) ==
                     MV_MANIFEST_READ_OK);
        mv_manifest_verify_possession_test(
            zcode_dir, &manifest, MV_PROPERTY_VERIFY_BYTES,
            MV_PROPERTY_SHOW_VERIFY_OPS, mv_mutate_after_first_hash,
            &mutation, &bytes_used, &operations_used);
        MV_CHECK("zcode: mutation between hash and final recheck is caught",
                 mutation.fired && !manifest.verification_complete &&
                 strcmp(manifest.verification_gap,
                        "chunk_mutated_during_verification") == 0 &&
                 bytes_used == manifest.total_bytes &&
                 operations_used > manifest.chunk_total);
        mv_manifest_free(&manifest);

        f = fopen(first_path, "wb");
        MV_CHECK("zcode: canonical first chunk restores after race proof",
                 f && fwrite(first_file, 1, sizeof(first_file) - 1u, f) ==
                          sizeof(first_file) - 1u);
        if (f)
            fclose(f);

        MV_CHECK("zcode: canonical manifest opens for strict budget proof",
                 mv_manifest_read(zcode_dir, p.root_hex, &manifest) ==
                     MV_MANIFEST_READ_OK);
        mv_manifest_verify_possession_test(
            zcode_dir, &manifest, 0, MV_PROPERTY_SHOW_VERIFY_OPS, NULL, NULL,
            &bytes_used, &operations_used);
        MV_CHECK("zcode: zero byte budget performs no content read",
                 !manifest.verification_complete && bytes_used == 0 &&
                 operations_used == 0 &&
                 strcmp(manifest.verification_gap,
                        "byte_budget_exhausted") == 0);
        mv_manifest_free(&manifest);
    }

    mv_show(&c, dd, id_text);
    MV_CHECK("zcode: show succeeds",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    MV_CHECK("zcode: the published package reads as present",
             strcmp(mv_str(&c.reply.data, "status"), "present") == 0 &&
             json_get_bool(json_get(&c.reply.data, "determined")));
    MV_CHECK("zcode: the evidence grade is the signature verified in THIS "
             "call, not one inherited from publication",
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_signature") == 0 &&
             strcmp(mv_str(&c.reply.data, "evidence_source"),
                    "vcs_package_release_verify") == 0);
    MV_CHECK("zcode: a verified signature is still NOT chain-bound",
             !json_get_bool(json_get(&c.reply.data, "chain_bound")) &&
             !json_get_bool(json_get(&c.reply.data,
                                     "has_freshness_height")));
    MV_CHECK("zcode: the controller principal is the publisher key",
             strcmp(mv_str(&c.reply.data, "owner_principal"), pub_hex) == 0 &&
             strcmp(mv_str(&c.reply.data, "owner_principal_kind"),
                    "publisher_pubkey") == 0);
    MV_CHECK("zcode: the revision is the publisher sequence",
             json_get_bool(json_get(&c.reply.data, "has_revision")) &&
             json_get_int(json_get(&c.reply.data, "revision")) == 7);
    MV_CHECK("zcode: the descriptor root is the signed release id",
             strcmp(mv_str(&c.reply.data, "descriptor_root"),
                    release_id_hex) == 0);
    MV_CHECK("zcode: the immutable root is the manifest root",
             strcmp(mv_str(&c.reply.data, "immutable_root"),
                    p.root_hex) == 0 &&
             strcmp(mv_str(&c.reply.data, "content_root"), p.root_hex) == 0);
    MV_CHECK("zcode: a signed, complete package may publish a revision",
             strstr(mv_str(&c.reply.data, "actions_csv"),
                    "publish_revision") != NULL &&
             strstr(mv_str(&c.reply.data, "actions_csv"), "sell") != NULL);
    MV_CHECK("zcode: all three files and chunks are accounted for",
             json_get_int(json_get(&c.reply.data, "file_count")) == 3 &&
             json_get_int(json_get(&c.reply.data, "chunk_total")) == 3 &&
             json_get_int(json_get(&c.reply.data, "chunks_present")) == 3 &&
             json_get_int(json_get(&c.reply.data, "chunks_verified")) == 3 &&
             json_get_bool(json_get(&c.reply.data,
                                    "manifest_root_verified")) &&
             json_get_bool(json_get(&c.reply.data,
                                    "verification_complete")) &&
             strcmp(mv_str(&c.reply.data, "verification_gap"), "") == 0);
    mv_cmd_free(&c);

    mv_list(&c, dd, "zcode_package");
    MV_CHECK("zcode: the package appears in the filtered catalog",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             mv_find_item(&c.reply.data, id_text) != NULL);
    {
        const struct json_value *kinds = json_get(&c.reply.data, "kinds");
        size_t n = kinds ? json_size(kinds) : 0;
        bool found = false;

        for (size_t i = 0; i < n; i++) {
            const struct json_value *row = json_at(kinds, i);
            if (strcmp(mv_str(row, "kind"), "content") == 0 &&
                !json_get_bool(json_get(row, "available")) &&
                strstr(mv_str(row, "unavailable_reason"), "filter") != NULL)
                found = true;
        }
        MV_CHECK("zcode: a filtered-out kind is still listed, marked "
                 "not-scanned", found);
    }
    mv_cmd_free(&c);

    /* A signed release still proves authorship when its manifest is corrupt,
     * but it cannot prove possession or a locally re-derived content root.
     * The item stays visible and the catalog separately reports integrity. */
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifests/%s",
             zcode_dir, p.root_hex);
    {
        FILE *f = fopen(manifest_path, "wb");
        bool wrote = f && fwrite("x", 1, 1, f) == 1;

        if (f)
            fclose(f);
        MV_CHECK("zcode: fixture manifest is made malformed", wrote);
    }
    mv_show(&c, dd, id_text);
    MV_CHECK("zcode: malformed manifest keeps only verified authorship",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&c.reply.data, "determined")) &&
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_signature") == 0 &&
             strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
             strstr(mv_str(&c.reply.data, "reason"), "invalid") != NULL &&
             strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
    mv_cmd_free(&c);

    mv_list(&c, dd, "zcode_package");
    {
        const struct json_value *row =
            mv_find_kind(&c.reply.data, "zcode_package");
        MV_CHECK("zcode: malformed manifest is rendered and disclosed",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED && row &&
                 mv_find_item(&c.reply.data, id_text) != NULL &&
                 !json_get_bool(json_get(row, "integrity_ok")) &&
                 json_get_int(json_get(row, "integrity_gap_count")) == 1);
    }
    mv_cmd_free(&c);
    {
        FILE *f = fopen(manifest_path, "wb");
        bool restored = f && fwrite(p.wire, 1, p.wire_len, f) == p.wire_len;

        if (f)
            fclose(f);
        MV_CHECK("zcode: canonical manifest bytes are restored", restored);
    }

    /* THE UNEARNED-CLAIM PROOF: remove the signed envelope. The bytes are
     * untouched, so the package stays present — but the signature can no
     * longer be verified, so the grade must DROP. */
    snprintf(release_path, sizeof(release_path), "%s/releases/%s", zcode_dir,
             release_id_hex);
    MV_CHECK("zcode: the release envelope exists before deletion",
             access(release_path, F_OK) == 0);
    MV_CHECK("zcode: the release envelope is deleted",
             unlink(release_path) == 0);

    mv_show(&c, dd, id_text);
    /* The index is built from releases/, so with the envelope gone the
     * package root is no longer claimed by any release: absent, and still
     * a determined verdict. */
    MV_CHECK("zcode: with no release naming it, the root reads absent",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "absent") == 0 &&
             json_get_bool(json_get(&c.reply.data, "determined")));
    MV_CHECK("zcode: an absent package claims no signature evidence",
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_signature") != 0 &&
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_store_read") == 0 &&
             strcmp(mv_str(&c.reply.data, "descriptor_root"), "") == 0);
    mv_cmd_free(&c);

    /* The SAME bytes are still a content property, because the blob shape
     * question is about the manifest, not the release. A three-file package
     * is not a blob, and the content adapter says so by name rather than
     * claiming the object does not exist. */
    {
        char content_id[METAVERSE_ID_TEXT_MAX];

        snprintf(content_id, sizeof(content_id), "content:%s", p.root_hex);
        mv_show(&c, dd, content_id);
        MV_CHECK("zcode: a multi-file package is not answered as an absent "
                 "blob — the shape mismatch is named",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 !json_get_bool(json_get(&c.reply.data, "determined")) &&
                 strstr(mv_str(&c.reply.data, "reason"),
                        "zcode_package") != NULL);
        mv_cmd_free(&c);
    }

    vcs_package_manifest_free(&p.manifest);
    free(p.wire);
    free(g_mv_recipe_hex);
    g_mv_recipe_hex = NULL;
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 6: the read-only contract (the parent-failing case) ──────────── */

/* Count every regular file under `dir`, recursively. A read command that
 * mutated the datadir would change this number (the store's recovery sweep
 * deletes orphans and staged temps). */
static size_t mv_count_files(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *ent;
    size_t n = 0;

    if (!d)
        return 0;
    while ((ent = readdir(d)) != NULL) {
        char path[1024];
        struct stat st;

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (stat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode))
            n += mv_count_files(path);
        else if (S_ISREG(st.st_mode))
            n++;
    }
    closedir(d);
    return n;
}

/* ZNAM through the canonical model and the strict read-only native open. */
static int t_znam_adapter(void)
{
    int failures = 0;
    char dd[256];
    char db_path[512];
    char root_hex[65];
    char update_hex[65];
    char id_text[METAVERSE_ID_TEXT_MAX];
    struct node_db ndb;
    struct znam_entry entry;
    struct mv_cmd c;
    size_t files_before;
    size_t files_after;

    test_make_tmpdir(dd, sizeof(dd), "metaverse", "znam");
    snprintf(db_path, sizeof(db_path), "%s/node.db", dd);
    memset(&ndb, 0, sizeof(ndb));
    memset(&entry, 0, sizeof(entry));
    MV_CHECK("znam: canonical node database opens for fixture setup",
             node_db_open(&ndb, db_path));
    snprintf(entry.name, sizeof(entry.name), "alice");
    snprintf(entry.owner_address, sizeof(entry.owner_address),
             "t1AlicePropertyOwner11111111111111111");
    entry.target_type = ZNAM_TYPE_CONTENT;
    snprintf(entry.target_value, sizeof(entry.target_value), "sha3:alice");
    memset(entry.reg_txid, 0x71, sizeof(entry.reg_txid));
    memset(entry.last_update_txid, 0x72, sizeof(entry.last_update_txid));
    entry.reg_height = 777;
    entry.expiry_height = 1777;
    MV_CHECK("znam: fixture is saved through the canonical model",
             ndb.open && db_znam_save(&ndb, &entry));
    node_db_close(&ndb);

    mv_hex32(entry.reg_txid, root_hex);
    mv_hex32(entry.last_update_txid, update_hex);
    snprintf(id_text, sizeof(id_text), "znam_name:%s", root_hex);
    files_before = mv_count_files(dd);

    mv_list(&c, dd, "znam_name");
    {
        const struct json_value *item = mv_find_item(&c.reply.data, id_text);
        const struct json_value *kind =
            mv_find_kind(&c.reply.data, "znam_name");

        MV_CHECK("znam: list reads the canonical registration by its stable "
                 "transaction root",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED && item &&
                 kind && json_get_bool(json_get(kind, "available")) &&
                 json_get_int(json_get(kind, "total")) == 1);
        MV_CHECK("znam: list projects owner and indexed-chain evidence",
                 item && strcmp(mv_str(item, "display_name"), "alice") == 0 &&
                 strcmp(mv_str(item, "owner_principal"),
                                entry.owner_address) == 0 &&
                 strcmp(mv_str(item, "owner_principal_kind"),
                        "zcl_address") == 0 &&
                 strcmp(mv_str(item, "evidence_grade"),
                        "chain_indexed_unvalidated") == 0 &&
                 !json_get_bool(json_get(item, "chain_bound")));
    }
    mv_cmd_free(&c);

    mv_show(&c, dd, id_text);
    {
        const struct json_value *work = json_get(&c.reply.data, "work");

        MV_CHECK("znam: show reports the registration height without "
                 "inventing a live tip",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 strcmp(mv_str(&c.reply.data, "status"), "present") == 0 &&
                 json_get_bool(json_get(&c.reply.data,
                                        "has_freshness_height")) &&
                 json_get_int(json_get(&c.reply.data,
                                       "freshness_height")) == 777 &&
                 work && strcmp(mv_str(work, "gap"), "no_tip") == 0 &&
                 json_get_int(json_get(work, "confirmation_depth")) == -1);
        MV_CHECK("znam: latest transaction is a descriptor, not a "
                 "fabricated revision counter",
                 strcmp(mv_str(&c.reply.data, "descriptor_root"),
                        update_hex) == 0 &&
                 !json_get_bool(json_get(&c.reply.data, "has_revision")) &&
                 strstr(mv_str(&c.reply.data, "actions_csv"),
                        "update_pointer") != NULL &&
                 strstr(mv_str(&c.reply.data, "actions_csv"),
                        "transfer") != NULL);
    }
    mv_cmd_free(&c);

    files_after = mv_count_files(dd);
    MV_CHECK("znam: list/show create no WAL or SHM sidecars and change no "
             "datadir files", files_after == files_before);

    /* No catalog ownership cache: the immutable registration root stays
     * stable while the authoritative owner changes. */
    memset(&ndb, 0, sizeof(ndb));
    MV_CHECK("znam: fixture reopens for an ownership transition",
             node_db_open(&ndb, db_path));
    snprintf(entry.owner_address, sizeof(entry.owner_address),
             "t1BobPropertyOwner222222222222222222");
    memset(entry.last_update_txid, 0x73, sizeof(entry.last_update_txid));
    MV_CHECK("znam: ownership transition saves through the model",
             ndb.open && db_znam_save(&ndb, &entry));
    node_db_close(&ndb);
    mv_show(&c, dd, id_text);
    MV_CHECK("znam: same property id immediately projects the new owner",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "property_id"), id_text) == 0 &&
             strcmp(mv_str(&c.reply.data, "owner_principal"),
                    entry.owner_address) == 0);
    mv_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ZSLP through the canonical chain-derived token model and the same strict
 * read-only node.db open. */
static int t_zslp_adapter(void)
{
    int failures = 0;
    char dd[256];
    char db_path[512];
    char root_hex[65];
    char id_text[METAVERSE_ID_TEXT_MAX];
    uint8_t token_id[32];
    struct node_db ndb;
    struct db_zslp_token_info token_probe;
    struct mv_cmd c;
    size_t asset_count = 0;
    size_t files_before;
    size_t files_after;

    test_make_tmpdir(dd, sizeof(dd), "metaverse", "zslp");
    snprintf(db_path, sizeof(db_path), "%s/node.db", dd);
    memset(token_id, 0x81, sizeof(token_id));
    memset(&ndb, 0, sizeof(ndb));
    MV_CHECK("zslp: canonical node database opens for fixture setup",
             node_db_open(&ndb, db_path));
    MV_CHECK("zslp: chain-derived GENESIS saves through the canonical model",
             ndb.open && db_zslp_token_save(&ndb, token_id, "META",
                 "Metaverse Asset", 8, "https://example.invalid/meta",
                 888, 21000000));
    MV_CHECK("zslp: application-local token key also saves for exclusion "
             "proof",
             ndb.open && db_zslp_token_save_key(&ndb, "ZCL23ACCESS",
                 "ACCESS", "Store Access", 0, "", 0, 1));
    memset(&token_probe, 0, sizeof(token_probe));
    MV_CHECK("zslp: model-owned count excludes application-local keys",
             ndb.open && db_zslp_asset_count(&ndb, &asset_count) &&
             asset_count == 1);
    MV_CHECK("zslp: model-owned lookup distinguishes the real GENESIS",
             ndb.open &&
             db_zslp_asset_lookup(&ndb, token_id, &token_probe) == 1 &&
             strcmp(token_probe.ticker, "META") == 0);
    node_db_close(&ndb);

    mv_hex32(token_id, root_hex);
    snprintf(id_text, sizeof(id_text), "zslp_asset:%s", root_hex);
    files_before = mv_count_files(dd);

    mv_list(&c, dd, "zslp_asset");
    {
        const struct json_value *item = mv_find_item(&c.reply.data, id_text);
        const struct json_value *kind =
            mv_find_kind(&c.reply.data, "zslp_asset");

        if (!item || !kind ||
            c.reply.status != ZCL_COMMAND_STATUS_PASSED) {
            char doc[4096];
            (void)json_write(&c.reply.data, doc, sizeof(doc));
            printf("  metaverse_catalog: zslp list diagnostic: %s\n", doc);
        }

        MV_CHECK("zslp: list exposes exactly the real GENESIS and excludes "
                 "the application-local token key",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED && item &&
                 kind && json_get_bool(json_get(kind, "available")) &&
                 json_get_int(json_get(kind, "total")) == 1);
        MV_CHECK("zslp: asset name and indexed-chain evidence come from the "
                 "canonical model",
                 item && strcmp(mv_str(item, "display_name"),
                                "META (Metaverse Asset)") == 0 &&
                 strcmp(mv_str(item, "evidence_grade"),
                        "chain_indexed_unvalidated") == 0 &&
                 strcmp(mv_str(item, "evidence_source"),
                        "db_zslp_asset_lookup") == 0);
    }
    mv_cmd_free(&c);

    mv_show(&c, dd, id_text);
    {
        const struct json_value *work = json_get(&c.reply.data, "work");

        if (c.reply.status != ZCL_COMMAND_STATUS_PASSED) {
            char doc[4096];
            (void)json_write(&c.reply.data, doc, sizeof(doc));
            printf("  metaverse_catalog: zslp show diagnostic: %s\n", doc);
        }

        MV_CHECK("zslp: show reports GENESIS height without manufacturing a "
                 "tip or confirmation depth",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 strcmp(mv_str(&c.reply.data, "status"), "present") == 0 &&
                 json_get_bool(json_get(&c.reply.data,
                                        "has_freshness_height")) &&
                 json_get_int(json_get(&c.reply.data,
                                       "freshness_height")) == 888 &&
                 work && strcmp(mv_str(work, "gap"), "no_tip") == 0 &&
                 json_get_int(json_get(work, "confirmation_depth")) == -1);
        MV_CHECK("zslp: fungible definition fabricates neither a single "
                 "owner nor mutating authority",
                 strcmp(mv_str(&c.reply.data, "owner_principal"), "") == 0 &&
                 strcmp(mv_str(&c.reply.data, "owner_principal_kind"),
                        "none") == 0 &&
                 strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0 &&
                 strstr(mv_str(&c.reply.data, "provenance"),
                        "no mint-baton controller") != NULL);
    }
    mv_cmd_free(&c);

    files_after = mv_count_files(dd);
    MV_CHECK("zslp: list/show create no WAL or SHM sidecars and change no "
             "datadir files", files_after == files_before);

    /* No catalog cache: removal from the authority is visible immediately. */
    memset(&ndb, 0, sizeof(ndb));
    MV_CHECK("zslp: fixture reopens for authoritative projection removal",
             node_db_open(&ndb, db_path));
    if (ndb.open)
        db_zslp_clear_all(&ndb);
    asset_count = SIZE_MAX;
    MV_CHECK("zslp: authoritative removal leaves zero chain assets",
             ndb.open && db_zslp_asset_count(&ndb, &asset_count) &&
             asset_count == 0);
    node_db_close(&ndb);
    mv_show(&c, dd, id_text);
    if (c.reply.status != ZCL_COMMAND_STATUS_PASSED ||
        strcmp(mv_str(&c.reply.data, "status"), "absent") != 0) {
        char doc[4096];
        (void)json_write(&c.reply.data, doc, sizeof(doc));
        printf("  metaverse_catalog: zslp absent diagnostic: status=%d "
               "error=%s data=%s\n", (int)c.reply.status,
               c.reply.error.code, doc);
    }
    MV_CHECK("zslp: the same property id immediately reads absent after the "
             "authoritative rows are removed",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "absent") == 0 &&
             json_get_bool(json_get(&c.reply.data, "determined")));
    mv_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

static int t_readonly_contract(void)
{
    int failures = 0;
    char dd[256];
    char zcode_dir[512];
    char orphan_dir[768];
    char orphan_path[900];
    char root_hex[65];
    char id_text[METAVERSE_ID_TEXT_MAX];
    const char orphan_hex[65] =
        "beef00112233445566778899aabbccddeeff00112233445566778899aabbccdd";
    uint8_t orphan_hash[32];
    const uint8_t bytes[] = "read means read";
    uint8_t root[32];
    struct vcs_package_store *store;
    struct mv_cmd c;
    size_t before, after;
    FILE *f;

    test_make_tmpdir(dd, sizeof(dd), "metaverse", "readonly");
    snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", dd);

    store = vcs_package_store_open(dd, 4u * 1024u * 1024u);
    MV_CHECK("readonly: fixture store opens", store != NULL);
    if (!store) {
        test_rm_rf_recursive(dd);
        return failures;
    }
    MV_CHECK("readonly: blob stores",
             vcs_blob_put_to(store, bytes, sizeof(bytes) - 1, root) ==
                 VCS_BLOB_OK);
    vcs_package_store_close(store);
    mv_hex32(root, root_hex);
    snprintf(id_text, sizeof(id_text), "content:%s", root_hex);

    /* Plant a CAS object no manifest references. The store's open-time
     * orphan GC exists precisely to delete this. */
    snprintf(orphan_dir, sizeof(orphan_dir), "%s/cas/sha3/%.2s", zcode_dir,
             orphan_hex);
    (void)mkdir(orphan_dir, 0755);
    snprintf(orphan_path, sizeof(orphan_path), "%s/%s", orphan_dir,
             orphan_hex);
    f = fopen(orphan_path, "wb");
    MV_CHECK("readonly: the orphan CAS object is planted",
             f != NULL && fwrite("orphan", 1, 6, f) == 6);
    if (f)
        fclose(f);

    for (int i = 0; i < 32; i++) {
        int hi = orphan_hex[2 * i], lo = orphan_hex[2 * i + 1];

        hi = hi <= '9' ? hi - '0' : 10 + (hi - 'a');
        lo = lo <= '9' ? lo - '0' : 10 + (lo - 'a');
        orphan_hash[i] = (uint8_t)((hi << 4) | lo);
    }
    /* The getter this change adds: a CAS presence answer that needs no
     * store handle, and therefore no recovery sweep. */
    MV_CHECK("readonly: the CAS probe finds a present object without opening "
             "a store",
             vcs_package_cas_present_in(zcode_dir, orphan_hash));
    {
        uint8_t absent[32];

        memset(absent, 0x5c, sizeof(absent));
        MV_CHECK("readonly: the CAS probe is NULL-safe and rejects a missing "
                 "object",
                 !vcs_package_cas_present_in(NULL, orphan_hash) &&
                 !vcs_package_cas_present_in(zcode_dir, NULL) &&
                 !vcs_package_cas_present_in(zcode_dir, absent));
    }

    before = mv_count_files(dd);
    MV_CHECK("readonly: the fixture datadir has files to protect",
             before > 0);

    mv_list(&c, dd, NULL);
    MV_CHECK("readonly: list succeeds against the fixture",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             mv_find_item(&c.reply.data, id_text) != NULL);
    mv_cmd_free(&c);
    mv_show(&c, dd, id_text);
    MV_CHECK("readonly: show succeeds against the fixture",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    mv_cmd_free(&c);

    after = mv_count_files(dd);
    MV_CHECK("readonly: the catalog read changed NOTHING on disk",
             after == before);
    MV_CHECK("readonly: the orphan CAS object survived the read",
             access(orphan_path, F_OK) == 0);

    /* The contrast that makes the point: the pre-existing way to ask a
     * store anything is to OPEN it, and opening runs the orphan GC. A read
     * command routed through that would have deleted the operator's file. */
    store = vcs_package_store_open(dd, 4u * 1024u * 1024u);
    MV_CHECK("readonly: the store reopens", store != NULL);
    vcs_package_store_close(store);
    MV_CHECK("readonly: opening the store DELETES the orphan — which is why "
             "the read path may not open one",
             access(orphan_path, F_OK) != 0);
    MV_CHECK("readonly: the CAS probe now agrees the object is gone",
             !vcs_package_cas_present_in(zcode_dir, orphan_hash));

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 7: the CLI path ──────────────────────────────────────────────── */

static int t_registry_path(void)
{
    int failures = 0;
    char dd[256];
    const struct zcl_command_spec *list = mv_leaf("metaverse.property.list");
    const struct zcl_command_spec *show = mv_leaf("metaverse.property.show");
    char why[192] = {0};
    struct mv_cmd c;

    test_make_tmpdir(dd, sizeof(dd), "metaverse", "registry");

    MV_CHECK("cli: both leaves are registered", list && show);
    MV_CHECK("cli: both leaves bind a handler",
             list && show && list->handler && show->handler);
    MV_CHECK("cli: the leaves bind the handlers the direct tests call",
             list && show &&
             list->handler == zcl_native_handle_metaverse_property_list &&
             show->handler == zcl_native_handle_metaverse_property_show);
    MV_CHECK("cli: metaverse is a canonical root word",
             zcl_native_command_is_root("metaverse"));

    /* list — the operator's exact input, through input_validate. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "kind", "content");
    (void)json_push_kv_int(&c.input, "limit", 4);
    MV_CHECK("cli: list accepts the keys it declares",
             list && zcl_command_registry_input_validate(list, &c.input, why,
                                                         sizeof(why)));
    if (list && list->handler) {
        c.request.spec = list;
        c.request.invoked_name = list->path;
        list->handler(&c.request, &c.reply);
    }
    MV_CHECK("cli: an empty store lists cleanly, not as a failure",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_int(json_get(&c.reply.data, "rendered")) == 0 &&
             json_get_int(json_get(&c.reply.data, "kinds_scanned")) ==
                 (int64_t)METAVERSE_KIND_COUNT - 1);
    mv_cmd_free(&c);

    /* show — declared keys accepted, malformed id refused by name. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "property_id", "content:nothex");
    why[0] = '\0';
    MV_CHECK("cli: show accepts the keys it declares",
             show && zcl_command_registry_input_validate(show, &c.input, why,
                                                         sizeof(why)));
    if (show && show->handler) {
        c.request.spec = show;
        c.request.invoked_name = show->path;
        show->handler(&c.request, &c.reply);
    }
    MV_CHECK("cli: a malformed property id is refused by name",
             c.reply.status != ZCL_COMMAND_STATUS_PASSED &&
             strcmp(c.reply.error.code, "BAD_PROPERTY_ID") == 0);
    mv_cmd_free(&c);

    /* A kind with no reader is a NAMED refusal, never an empty answer. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(
        &c.input, "property_id",
        "hosted_service:a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbb"
        "cbdbebf");
    zcl_native_handle_metaverse_property_show(&c.request, &c.reply);
    MV_CHECK("cli: an unwired kind is refused with KIND_UNAVAILABLE",
             c.reply.status != ZCL_COMMAND_STATUS_PASSED &&
             strcmp(c.reply.error.code, "KIND_UNAVAILABLE") == 0);
    mv_cmd_free(&c);

    /* An unknown kind name in list must be named, not silently ignored. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "kind", "world");
    zcl_native_handle_metaverse_property_list(&c.request, &c.reply);
    MV_CHECK("cli: an unknown kind filter is refused by name",
             c.reply.status != ZCL_COMMAND_STATUS_PASSED &&
             strcmp(c.reply.error.code, "UNKNOWN_KIND") == 0);
    mv_cmd_free(&c);

    /* The validator is real, not bypassed. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "not_a_catalog_key", "x");
    why[0] = '\0';
    MV_CHECK("cli: an undeclared key is refused by input_validate",
             list && !zcl_command_registry_input_validate(list, &c.input, why,
                                                          sizeof(why)) &&
             why[0] != '\0');
    mv_cmd_free(&c);

    /* No datadir at all must be a named refusal, never a global fallback. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "property_id",
                           "content:a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
                           "b4b5b6b7b8b9babbbcbdbebf");
    zcl_native_handle_metaverse_property_show(&c.request, &c.reply);
    MV_CHECK("cli: no datadir is MISSING_DATADIR, not a silent global",
             c.reply.status != ZCL_COMMAND_STATUS_PASSED &&
             strcmp(c.reply.error.code, "MISSING_DATADIR") == 0);
    mv_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── an unreadable store must not read as an empty one ───────────────────
 *
 * A catalog that answers "0 properties" over a store it could not open has
 * told the operator they own nothing. That is the same conflation this
 * project already paid for on node.db, and it is worse here: the whole
 * purpose of this surface is to state what you hold.
 *
 * The store is made PRESENT and unreadable by putting a plain file where
 * <datadir>/zcode/manifests belongs, so opendir() fails with ENOTDIR. What
 * is asserted is disclosure, not a particular verb: list may answer as
 * long as it says "store": {"read": false} and names the affected kinds
 * unavailable; show must refuse outright, because a bare "absent" from it
 * IS the lie. */
static int t_unreadable_store_is_disclosed(void)
{
    int failures = 0;
    char dd[256];
    char zdir[512];
    char mpath[768];
    struct mv_cmd c;
    FILE *f;
    const struct json_value *store;
    const struct json_value *kinds;
    bool content_named = false;

    test_make_tmpdir(dd, sizeof(dd), "metaverse", "unreadable");
    snprintf(zdir, sizeof(zdir), "%s/zcode", dd);
    (void)mkdir(zdir, 0700);
    snprintf(mpath, sizeof(mpath), "%s/manifests", zdir);
    f = fopen(mpath, "wb");
    MV_CHECK("unreadable: a plain file sits where the store belongs",
             f != NULL);
    if (f) {
        fputs("not a directory", f);
        fclose(f);
    }

    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    zcl_native_handle_metaverse_property_list(&c.request, &c.reply);
    store = json_get(&c.reply.data, "store");
    MV_CHECK("unreadable: list discloses store.read = false",
             store && json_get(store, "read") &&
             !json_get_bool(json_get(store, "read")));
    {
        const struct json_value *why = store ? json_get(store, "reason")
                                             : NULL;
        const char *s = why ? json_get_str(why) : NULL;

        MV_CHECK("unreadable: the disclosure carries a reason", s && *s);
    }
    kinds = json_get(&c.reply.data, "kinds");
    if (kinds && kinds->type == JSON_ARR) {
        for (size_t i = 0; i < kinds->num_children; i++) {
            const struct json_value *row = &kinds->children[i];
            const char *name = json_get_str(json_get(row, "kind"));
            const char *reason =
                json_get_str(json_get(row, "unavailable_reason"));

            if (!name || strcmp(name, "content") != 0)
                continue;
            content_named = !json_get_bool(json_get(row, "available")) &&
                            reason && *reason;
        }
    }
    MV_CHECK("unreadable: the content row is unavailable with a reason",
             content_named);
    MV_CHECK("unreadable: nothing is rendered as owned",
             json_get_int(json_get(&c.reply.data, "rendered")) == 0);
    mv_cmd_free(&c);

    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "property_id",
                           "content:a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
                           "b4b5b6b7b8b9babbbcbdbebf");
    zcl_native_handle_metaverse_property_show(&c.request, &c.reply);
    MV_CHECK("unreadable: show refuses rather than answering absent",
             c.reply.status != ZCL_COMMAND_STATUS_PASSED &&
             c.reply.error.code[0] != '\0');
    mv_cmd_free(&c);

    /* And the control: with the ZCODE store simply ABSENT, its own content
     * row remains readable.  The top-level aggregate may still be false
     * because this deliberately never-booted fixture has no node.db from
     * which the independent ZNAM authority could be read. */
    (void)unlink(mpath);
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    zcl_native_handle_metaverse_property_list(&c.request, &c.reply);
    {
        const struct json_value *content =
            mv_find_kind(&c.reply.data, "content");
        MV_CHECK("unreadable: an absent ZCODE store is a readable empty "
                 "content authority",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED && content &&
                 json_get_bool(json_get(content, "available")) &&
                 json_get_int(json_get(content, "total")) == 0);
    }
    mv_cmd_free(&c);

    test_rm_rf_recursive(dd);
    return failures;
}

int test_metaverse_catalog(void)
{
    printf("\n=== metaverse_catalog: sovereign property catalog ===\n");
    int failures = 0;

    failures += t_property_id_rules();
    failures += t_action_vocabulary();
    failures += t_adapter_registry();
    failures += t_mvp_scope_decision();
    failures += t_settlement_classes();
    failures += t_work_measurement();
    failures += t_settlement_is_surfaced();
    failures += t_content_adapter();
    failures += t_zcode_adapter();
    failures += t_znam_adapter();
    failures += t_zslp_adapter();
    failures += t_readonly_contract();
    failures += t_registry_path();
    failures += t_unreadable_store_is_disclosed();
    printf("=== metaverse_catalog complete: %d failure(s) ===\n", failures);
    return failures;
}
