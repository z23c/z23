/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Pure evidence-row rendering; all store reads and authority stay static. */
// one-result-type-ok:pure-vtable-uses-bounded-caller-owned-output-only

#include "services/shop_reputation_view_service.h"

#include "hotswap/hotswap_service.h"

#include <stdio.h>
#include <string.h>

static void set_row(struct shop_reputation_view_result_v1 *out,
                    const char *fact, const char *state, bool has_value,
                    int64_t value, const char *evidence_class,
                    const char *window, const char *detail)
{
    if (out->row_count >= SHOP_REPUTATION_VIEW_ROW_COUNT)
        return;
    struct shop_reputation_view_row_v1 *row = &out->rows[out->row_count++];
    (void)snprintf(row->fact, sizeof(row->fact), "%s", fact);
    (void)snprintf(row->state, sizeof(row->state), "%s", state);
    row->has_value = has_value;
    row->value = value;
    (void)snprintf(row->evidence_class, sizeof(row->evidence_class), "%s",
                   evidence_class);
    (void)snprintf(row->window, sizeof(row->window), "%s", window);
    (void)snprintf(row->detail, sizeof(row->detail), "%s", detail);
}

static bool render(const struct shop_reputation_view_input_v1 *ev,
                   struct shop_reputation_view_result_v1 *out)
{
    if (!ev || !out)
        return false;
    memset(out, 0, sizeof(*out));
    static const char *const local_store = "this node's local zcode store";

    set_row(out, "releases_published",
            ev->releases > 0 ? "recorded" : "no_record",
            ev->releases > 0, ev->releases,
            "secp256k1-signed release envelopes, verified at publication",
            local_store,
            ev->releases > 0
                ? "release envelopes naming this publisher key held locally"
                : "no release envelope naming this publisher key is held");
    set_row(out, "packages_published",
            ev->packages > 0 ? "recorded" : "no_record",
            ev->packages > 0, ev->packages,
            "distinct package roots across the signed release envelopes",
            local_store,
            ev->packages > 0
                ? "distinct package roots this publisher has released locally"
                : "no package root released by this publisher is held");

    if (ev->observed) {
        char detail[SHOP_REPUTATION_VIEW_DETAIL_MAX];
        (void)snprintf(detail, sizeof(detail),
                       "oldest release envelope first recorded locally at "
                       "unix %lld; file mtimes are this node's own "
                       "observation record, not a signed timestamp",
                       (long long)ev->first_observed_unix);
        set_row(out, "days_observed", "recorded", true, ev->days_observed,
                "local store file mtime (unsigned local observation)",
                "this node only; says nothing about anyone else", detail);
    } else {
        set_row(out, "days_observed", "no_record", false, 0,
                "local store file mtime (unsigned local observation)",
                "this node only", "no release envelope is held locally");
    }

    char detail[SHOP_REPUTATION_VIEW_DETAIL_MAX];
    (void)snprintf(detail, sizeof(detail),
                   "%u build receipt(s) name this publisher's package+recipe "
                   "pairs, %u package(s) reproduced byte-identically across "
                   "distinct receipt ids; receipts carry no signer identity, "
                   "so these are distinct recorded build events and nothing "
                   "about who built them is established",
                   ev->matching_receipts, ev->reproduced_packages);
    set_row(out, "reproductions",
            ev->matching_receipts > 0 ? "recorded" : "no_record",
            ev->matching_receipts > 0, ev->matching_receipts,
            "build receipts filed under <datadir>/zcode/receipts with "
            "byte-identical output sets (distinct receipt ids)", local_store,
            ev->matching_receipts > 0 ? detail
                : "no build receipt naming this publisher's packages is filed");

    (void)snprintf(detail, sizeof(detail),
                   "%u signature-verified attestation(s) from %u distinct "
                   "verifier pubkey(s); a verified signature proves authorship "
                   "of the exact bytes only — who the signer is, or whether "
                   "any two signers are the same operator, is not established%s",
                   ev->valid_attestations, ev->distinct_verifiers,
                   ev->attestations_truncated
                       ? "; the attestation scan hit its cap, so these counts "
                         "are a lower bound" : "");
    set_row(out, "distinct_signing_identities",
            ev->distinct_verifiers > 0 ? "recorded" : "no_record",
            ev->distinct_verifiers > 0, ev->distinct_verifiers,
            "distinct secp256k1 verifier pubkeys over attestations whose "
            "signature verifies at read time", local_store,
            ev->distinct_verifiers > 0 ? detail
                : "no valid attestation naming this publisher's packages is filed");

    (void)snprintf(detail, sizeof(detail),
                   "%u declaration(s) read, %u unreadable locally (manifest "
                   "or member bytes not held — counted as unavailable, never "
                   "as no-dependency)", ev->declarations_read,
                   ev->declarations_unavailable);
    set_row(out, "dependent_packages",
            ev->dependent_packages > 0 ? "recorded" : "no_record",
            ev->dependent_packages > 0, ev->dependent_packages,
            "root-committed dependency declarations (zcode-package.json is "
            "a manifest member; the package root commits it)", local_store,
            ev->dependent_packages > 0 ? detail
                : "no locally readable declaration names one of this publisher's package roots");

    set_row(out, "simulated_settlements",
            ev->settled_entries > 0 ? "recorded" : "no_record",
            ev->settled_entries > 0, ev->settled_entries,
            "settled facts in the simulated reward ledger under "
            "<datadir>/zcode/rewards (placeholder token; ZC23 issuance stays "
            "simulation-only)", local_store,
            ev->settled_entries > 0
                ? "simulated reward entries settled to this contributor key"
                : "no simulated settlement to this contributor key is recorded");
    set_row(out, "availability_challenges", "unavailable", false, 0,
            "none: no durable challenge record exists", "n/a",
            "the file-market chunk-challenge loop keeps pass/fail counts in "
            "per-download memory only; a durable record lands with the "
            "challenge loop (docs/work/SHOP_COMMAND.md slice C)");
    set_row(out, "paid_fulfillments", "unavailable", false, 0,
            "none: no datadir-local settlement source exists", "n/a",
            "patronage settlement lives on the scratch-workspace simulation "
            "lane (zcode.patronage.*), not in the datadir store; the row "
            "appears when patronage settle lands on this lane");
    (void)snprintf(out->doctrine, sizeof(out->doctrine), "%s",
        "every row is a fact this node can prove from its own records, with "
        "the evidence class and counting window stated on the row; absent "
        "evidence reads 'no_record' or 'unavailable', never a zero; nothing "
        "here measures intent, quality, or honesty; presentation remains "
        "live-swappable; evidence collection and authority stay static");
    return out->row_count == SHOP_REPUTATION_VIEW_ROW_COUNT;
}

static const struct shop_reputation_view_service_v1 k_builtin = {
    .render = render,
};

ZCL_HOTSWAP_SERVICE_EXPORT(
    SHOP_REPUTATION_VIEW_SERVICE_ID, k_builtin,
    SHOP_REPUTATION_VIEW_ABI_FINGERPRINT,
    SHOP_REPUTATION_VIEW_SCHEMA_FINGERPRINT,
    SHOP_REPUTATION_VIEW_WIRE_FINGERPRINT,
    SHOP_REPUTATION_VIEW_KAT_FINGERPRINT)

const struct shop_reputation_view_service_v1 *
shop_reputation_view_service_builtin(void)
{
    return &k_builtin;
}
