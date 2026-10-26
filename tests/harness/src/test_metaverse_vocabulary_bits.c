/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The ACTION-BIT half of the metaverse vocabulary gate.
 *
 * Separate from test_metaverse_vocabulary.c because property_action.h defines
 * METAVERSE_ACTION_* as bit values while property_grant.h defines the same
 * identifiers as bit positions; no unit may include both. This file takes the
 * property_action.h side and its sibling the property_grant.h side.
 *
 * It exports helpers only (no test_metaverse_vocabulary_bits(void)): the
 * test-registration gate treats a function named for its file as an entry
 * point; the group entry point is test_metaverse_vocabulary().
 *
 *   1. Each action has exactly one unique bit; the union is
 *      METAVERSE_ACTION_ALL.
 *   2. Preserved bit values are static_asserted (a compile failure).
 *   3. LIST keeps 0x10 as LIST_FOR_SALE; 0x1 (INSPECT) is never reissued.
 *   4. Each property kind has one wire name, one authority source, and
 *      exactly one adapter row.
 *   5. HOST changes LOCAL state only: the broker calls it a mutation, the
 *      metaverse MUTATING column (external state) excludes it; both hold.
 */

#include "test/test_core.h"

#include "metaverse/property_action.h"
#include "metaverse/property_adapter.h"
#include "metaverse/property_id.h"

#include <stdio.h>
#include <string.h>

#define VB_CHECK(name, expr) do { \
    printf("vocabulary/bits: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── every PRESERVED bit value, pinned at COMPILE time ───────────────────
 *
 * These eleven identifiers keep name and value across the canonical split
 * (LIST -> LIST_FOR_SALE; INSPECT leaves the action space); changing any of
 * them stops this translation unit from compiling. */
_Static_assert(METAVERSE_ACTION_HOST == 0x00000002u,
               "persisted action bit HOST must stay 0x2");
_Static_assert(METAVERSE_ACTION_PUBLISH_REVISION == 0x00000004u,
               "persisted action bit PUBLISH_REVISION must stay 0x4");
_Static_assert(METAVERSE_ACTION_UPDATE_POINTER == 0x00000008u,
               "persisted action bit UPDATE_POINTER must stay 0x8");
_Static_assert(METAVERSE_ACTION_BUY == 0x00000020u,
               "persisted action bit BUY must stay 0x20");
_Static_assert(METAVERSE_ACTION_SELL == 0x00000040u,
               "persisted action bit SELL must stay 0x40");
_Static_assert(METAVERSE_ACTION_DELIVER == 0x00000080u,
               "persisted action bit DELIVER must stay 0x80");
_Static_assert(METAVERSE_ACTION_LEASE == 0x00000100u,
               "persisted action bit LEASE must stay 0x100");
_Static_assert(METAVERSE_ACTION_TRANSFER == 0x00000200u,
               "persisted action bit TRANSFER must stay 0x200");
_Static_assert(METAVERSE_ACTION_ACCEPT_PAYMENT == 0x00000400u,
               "persisted action bit ACCEPT_PAYMENT must stay 0x400");
_Static_assert(METAVERSE_ACTION_DELEGATE == 0x00000800u,
               "persisted action bit DELEGATE must stay 0x800");
_Static_assert(METAVERSE_ACTION_REVOKE == 0x00001000u,
               "persisted action bit REVOKE must stay 0x1000");

/* The kind table's shape, pinned the same way: a kind added or removed
 * without this gate being updated in the same change does not compile. */
_Static_assert(METAVERSE_KIND_COUNT == 10,
               "METAVERSE_KIND_TABLE holds 9 kinds plus UNKNOWN; update this "
               "gate and the adapter registry in the SAME change");

/* HOST is one of the twelve ACTIONS and changes local state only, so it is
 * absent from METAVERSE_ACTION_MUTATING (the "changes EXTERNAL state" column). */
_Static_assert((METAVERSE_ACTION_MUTATING & METAVERSE_ACTION_HOST) == 0u,
               "HOST changes LOCAL state only: it must not appear in the "
               "external-state (MUTATING) mask");
_Static_assert((METAVERSE_ACTION_ALL & METAVERSE_ACTION_HOST) != 0u,
               "HOST is still one of the twelve actions");

/* No compiler builtin: the contract forbids compiler-specific extensions. */
static unsigned bit_count(uint32_t v)
{
    unsigned n = 0;
    while (v) { n += (unsigned)(v & 1u); v >>= 1; }
    return n;
}

/* ── 1. one unique bit per action, and no gap readable as a value ───────── */

static int check_action_bits_unique(void)
{
    int failures = 0;

    uint32_t seen = 0;
    bool every_single_bit = true;
    bool every_bit_fresh = true;
    bool every_name_present = true;

    for (size_t i = 0; i < (size_t)METAVERSE_ACTION_COUNT; i++) {
        uint32_t bit = metaverse_action_at(i);
        if (bit_count(bit) != 1u) every_single_bit = false;
        if (bit & seen) every_bit_fresh = false;
        seen |= bit;
        const char *n = metaverse_action_name(bit);
        if (!n || !n[0]) every_name_present = false;
    }

    VB_CHECK("every action carries exactly one bit", every_single_bit);
    VB_CHECK("no two actions share a bit", every_bit_fresh);
    VB_CHECK("every action bit has a wire name", every_name_present);
    VB_CHECK("the defined bits are exactly METAVERSE_ACTION_ALL",
             seen == (uint32_t)METAVERSE_ACTION_ALL);

    /* A gap must read as "not an action", never as a value. Walking one past
     * the end and asking for a bit above the table are the two ways a reader
     * accidentally invents a right. */
    VB_CHECK("one past the last row yields no bit",
             metaverse_action_at((size_t)METAVERSE_ACTION_COUNT) == 0u);
    VB_CHECK("a bit above the table is malformed, not a future action",
             !metaverse_action_mask_valid((uint32_t)METAVERSE_ACTION_ALL |
                                          0x00002000u));
    VB_CHECK("the full mask is well formed",
             metaverse_action_mask_valid((uint32_t)METAVERSE_ACTION_ALL));
    VB_CHECK("the empty mask is well formed (it means no action available)",
             metaverse_action_mask_valid(0u));

    /* Multi-bit and zero are not actions: a renderer that named them would
     * publish a right nobody granted. */
    VB_CHECK("zero names no action", metaverse_action_name(0u) == NULL);
    VB_CHECK("a two-bit mask names no action",
             metaverse_action_name((uint32_t)METAVERSE_ACTION_HOST |
                                   (uint32_t)METAVERSE_ACTION_BUY) == NULL);

    /* Name round-trip, and names distinct across the whole vocabulary. */
    bool round_trips = true, names_distinct = true;
    for (size_t i = 0; i < (size_t)METAVERSE_ACTION_COUNT; i++) {
        uint32_t bit = metaverse_action_at(i);
        const char *n = metaverse_action_name(bit);
        if (!n || metaverse_action_from_name(n) != bit) round_trips = false;
        for (size_t j = 0; j < i; j++) {
            const char *m = metaverse_action_name(metaverse_action_at(j));
            if (n && m && strcmp(n, m) == 0) names_distinct = false;
        }
    }
    VB_CHECK("every action name round-trips to its own bit", round_trips);
    VB_CHECK("no two actions share a wire name", names_distinct);
    VB_CHECK("an unknown name yields no bit",
             metaverse_action_from_name("not_an_action") == 0u &&
             metaverse_action_from_name("") == 0u &&
             metaverse_action_from_name(NULL) == 0u);

    return failures;
}

/* ── 2/3. the rename must not move a persisted bit ──────────────────────── */

static int check_list_rename_preserves_bit(void)
{
    int failures = 0;

    /* LIST_FOR_SALE renames LIST and keeps bit 0x10; exactly one spelling is
     * live and it resolves to 0x10. */
    uint32_t old_name = metaverse_action_from_name("list");
    uint32_t new_name = metaverse_action_from_name("list_for_sale");

    VB_CHECK("exactly one of list / list_for_sale is the live spelling",
             (old_name == 0u) != (new_name == 0u));
    VB_CHECK("the live listing spelling still carries bit 0x10",
             (old_name ? old_name : new_name) == 0x00000010u);
    VB_CHECK("listing changes EXTERNAL state (it advertises off this node)",
             (METAVERSE_ACTION_MUTATING & 0x00000010u) != 0u);

    /* Bit 0x1 is reserved once INSPECT leaves the action space: it may name
     * "inspect" or nothing, never one of the twelve actions. */
    const char *reserved = metaverse_action_name(0x00000001u);
    bool reserved_ok = (reserved == NULL) || strcmp(reserved, "inspect") == 0;
    VB_CHECK("bit 0x1 is reserved and never reissued to a new action",
             reserved_ok);
    VB_CHECK("the reserved bit never becomes an external-state mutation",
             (METAVERSE_ACTION_MUTATING & 0x00000001u) == 0u);

    return failures;
}

/* ── 4. one kind, one name, one authority, exactly one adapter row ──────── */

static size_t count_adapter_rows_for_kind(enum metaverse_kind kind)
{
    size_t rows = 0;
    for (size_t i = 0; i < metaverse_adapter_count(); i++) {
        const struct metaverse_adapter *a = metaverse_adapter_at(i);
        if (a && a->kind == kind) rows++;
    }
    return rows;
}

/* A row is either wired (list+show) or an explicit gap naming a reason. */
static bool adapter_row_is_wired_or_stated_gap(
    const struct metaverse_adapter *a)
{
    bool wired = (a->list != NULL && a->show != NULL);
    bool stated_gap = (a->unavailable_reason != NULL &&
                       a->unavailable_reason[0] != '\0' &&
                       a->list == NULL && a->show == NULL);
    return wired != stated_gap;
}

static void check_kind_strings_valid(enum metaverse_kind kind, const char *name,
                                     const char *auth, bool *names_ok,
                                     bool *authorities_ok)
{
    if (!name || !name[0] || strcmp(name, "unknown") == 0) *names_ok = false;
    if (!auth || !auth[0] || strcmp(auth, "unknown") == 0)
        *authorities_ok = false;
    if (name && metaverse_kind_from_name(name) != kind) *names_ok = false;
}

static void check_kind_strings_distinct_from_earlier_kinds(
    enum metaverse_kind kind, const char *name, const char *auth,
    bool *names_ok, bool *authorities_ok)
{
    for (int j = METAVERSE_KIND_UNKNOWN + 1; j < (int)kind; j++) {
        enum metaverse_kind other = (enum metaverse_kind)j;
        if (name && strcmp(name, metaverse_kind_name(other)) == 0)
            *names_ok = false;
        if (auth && strcmp(auth, metaverse_kind_authority(other)) == 0)
            *authorities_ok = false;
    }
}

static void check_one_kind_row(enum metaverse_kind kind, bool *exactly_one_row,
                               bool *rows_are_readers_or_stated_gaps,
                               bool *names_ok, bool *authorities_ok)
{
    size_t rows = count_adapter_rows_for_kind(kind);
    if (rows != 1) *exactly_one_row = false;
    if (metaverse_adapter_for(kind) == NULL) *exactly_one_row = false;

    const struct metaverse_adapter *a = metaverse_adapter_for(kind);
    if (a && !adapter_row_is_wired_or_stated_gap(a))
        *rows_are_readers_or_stated_gaps = false;

    const char *name = metaverse_kind_name(kind);
    const char *auth = metaverse_kind_authority(kind);
    check_kind_strings_valid(kind, name, auth, names_ok, authorities_ok);
    check_kind_strings_distinct_from_earlier_kinds(kind, name, auth,
                                                   names_ok, authorities_ok);
}

static bool adapter_registry_has_no_stray_kinds(void)
{
    /* The registry must not carry a row for a kind that does not exist. */
    bool no_stray_rows = true;
    for (size_t i = 0; i < metaverse_adapter_count(); i++) {
        const struct metaverse_adapter *a = metaverse_adapter_at(i);
        if (!a || !metaverse_kind_valid(a->kind)) no_stray_rows = false;
    }
    return no_stray_rows;
}

static int check_kind_rows_are_singular(void)
{
    int failures = 0;

    VB_CHECK("the adapter registry holds one row per real kind",
             metaverse_adapter_count() ==
                 (size_t)(METAVERSE_KIND_COUNT - 1));

    bool exactly_one_row = true;
    bool rows_are_readers_or_stated_gaps = true;
    bool names_ok = true, authorities_ok = true;

    for (int k = METAVERSE_KIND_UNKNOWN + 1; k < METAVERSE_KIND_COUNT; k++) {
        check_one_kind_row((enum metaverse_kind)k, &exactly_one_row,
                           &rows_are_readers_or_stated_gaps, &names_ok,
                           &authorities_ok);
    }

    VB_CHECK("every kind has exactly one adapter row", exactly_one_row);
    VB_CHECK("every adapter row is a wired reader XOR a stated gap",
             rows_are_readers_or_stated_gaps);
    VB_CHECK("every kind has one unique wire name that round-trips", names_ok);
    VB_CHECK("every kind names one distinct authority source", authorities_ok);

    VB_CHECK("the registry carries no row for an invalid kind",
             adapter_registry_has_no_stray_kinds());

    VB_CHECK("UNKNOWN is not a kind and has no row",
             !metaverse_kind_valid(METAVERSE_KIND_UNKNOWN) &&
             metaverse_adapter_for(METAVERSE_KIND_UNKNOWN) == NULL);

    return failures;
}

/* ── the truncation refusal (a short list must never read as a short set) ─ */

static int check_mask_format_refuses_truncation(void)
{
    int failures = 0;
    char small[8];

    VB_CHECK("a mask that does not fit is refused, not truncated",
             !metaverse_action_mask_format((uint32_t)METAVERSE_ACTION_ALL,
                                           small, sizeof(small)) &&
             small[0] == '\0');

    char big[METAVERSE_ACTION_LIST_MAX];
    VB_CHECK("the declared buffer size always fits the full mask",
             metaverse_action_mask_format((uint32_t)METAVERSE_ACTION_ALL, big,
                                          sizeof(big)) && big[0] != '\0');
    VB_CHECK("the empty mask renders as the empty list",
             metaverse_action_mask_format(0u, big, sizeof(big)) &&
             big[0] == '\0');
    VB_CHECK("a malformed mask is refused outright",
             !metaverse_action_mask_format(0x80000000u, big, sizeof(big)));

    return failures;
}

/* The property_action.h-side half of the vocabulary gate. Called by
 * test_metaverse_vocabulary(); see this file's header for why it is not an
 * entry point of its own. */
int mvv_action_bit_checks(void)
{
    int failures = 0;
    failures += check_action_bits_unique();
    failures += check_list_rename_preserves_bit();
    failures += check_kind_rows_are_singular();
    failures += check_mask_format_refuses_truncation();
    return failures;
}
