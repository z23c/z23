/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Dual-signed receipt session scenarios for the zcode_swarm group. */
#include "test/test_core.h"
#include "vcs/package_service.h"
#include "vcs/package_swarm_node.h"
#include "vcs/service_receipt.h"
#include <secp256k1.h>
#include <stdlib.h>
#include <string.h>
#include "test/test_zcode_swarm_priv.h"

static bool sw_secp_pair(secp256k1_context *ctx, uint8_t last,
                         uint8_t sec[32], uint8_t pub[33])
{
    memset(sec, 0, 32);
    sec[31] = last;
    secp256k1_pubkey parsed;
    size_t plen = 33;
    return secp256k1_ec_pubkey_create(ctx, &parsed, sec) == 1 &&
           secp256k1_ec_pubkey_serialize(ctx, pub, &plen, &parsed,
                                         SECP256K1_EC_COMPRESSED) == 1;
}

struct receipt_session_ctx {
    secp256k1_context *ctx;
    uint8_t up_sec[32], down_sec[32], other_sec[32];
    uint8_t up_pub[33], down_pub[33], other_pub[33];
    struct vcs_swarm_receipt_session *up;
    struct vcs_swarm_receipt_session *down;
    struct vcs_swarm_receipt_session *stranger;
    uint64_t peer;
    struct vcs_swarm_transfer seed_x, leech_x;
    uint8_t offer[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    uint8_t *reply;
    size_t reply_len;
};

static int session_case_setup_keys_and_identity(struct receipt_session_ctx *rc)
{
    int failures = 0;
    rc->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                       SECP256K1_CONTEXT_VERIFY);
    SW_CHECK("session: secp keys",
             rc->ctx && sw_secp_pair(rc->ctx, 0x91, rc->up_sec, rc->up_pub) &&
             sw_secp_pair(rc->ctx, 0x92, rc->down_sec, rc->down_pub) &&
             sw_secp_pair(rc->ctx, 0x93, rc->other_sec, rc->other_pub) &&
             memcmp(rc->up_pub, rc->other_pub, 33) != 0);
    rc->up = vcs_swarm_receipt_session_open_secret(rc->up_sec);
    rc->down = vcs_swarm_receipt_session_open_secret(rc->down_sec);
    rc->stranger = vcs_swarm_receipt_session_open_secret(rc->other_sec);
    uint8_t got[33];
    SW_CHECK("session: open secrets",
             rc->up && rc->down && rc->stranger &&
             vcs_swarm_receipt_session_local_pub(rc->up, got) &&
             memcmp(got, rc->up_pub, 33) == 0 &&
             vcs_swarm_receipt_session_local_pub(rc->down, got) &&
             memcmp(got, rc->down_pub, 33) == 0);

    uint8_t ident[VCS_SWARM_RECEIPT_IDENTITY_BYTES];
    size_t ilen = 0;
    rc->peer = 77;
    SW_CHECK("session: seeder identity once",
             vcs_swarm_receipt_identity_take(rc->up, rc->peer, ident,
                                             sizeof(ident), &ilen) &&
             ilen == VCS_SWARM_RECEIPT_IDENTITY_BYTES);
    SW_CHECK("session: seeder identity not resent",
             !vcs_swarm_receipt_identity_take(rc->up, rc->peer, ident,
                                              sizeof(ident), &ilen));
    SW_CHECK("session: leecher notes seeder",
             vcs_swarm_receipt_identity_note(rc->down, rc->peer, ident,
                                             ilen));
    SW_CHECK("session: leecher identity",
             vcs_swarm_receipt_identity_take(rc->down, rc->peer, ident,
                                             sizeof(ident), &ilen));
    SW_CHECK("session: seeder notes leecher",
             vcs_swarm_receipt_identity_note(rc->up, rc->peer, ident, ilen));
    return failures;
}

static int session_case_offer_and_complete(struct receipt_session_ctx *rc,
                                            struct sw_node *seeder,
                                            struct sw_node *leecher)
{
    int failures = 0;
    memset(&rc->seed_x, 0, sizeof(rc->seed_x));
    memset(&rc->leech_x, 0, sizeof(rc->leech_x));
    memset(rc->seed_x.package_root, 0x44, 32);
    memcpy(rc->leech_x.package_root, rc->seed_x.package_root, 32);
    rc->seed_x.served = 4096;
    rc->leech_x.fetched = 4096;

    SW_CHECK("session: seeder offers",
             vcs_swarm_receipt_session_offer(rc->up, &rc->seed_x, rc->peer,
                                             SW_DAY, rc->offer));
    SW_CHECK("session: second identical offer withheld",
             !vcs_swarm_receipt_session_offer(rc->up, &rc->seed_x, rc->peer,
                                              SW_DAY, rc->offer));
    rc->reply = NULL;
    rc->reply_len = 0;
    SW_CHECK("session: leecher completes",
             vcs_swarm_receipt_session_handle(
                 rc->down, leecher->book, &rc->leech_x, rc->peer, SW_DAY,
                 rc->offer, sizeof(rc->offer), &rc->reply, &rc->reply_len) ==
                 VCS_SWARM_RECEIPT_OK &&
             rc->reply && rc->reply_len == VCS_SERVICE_RECEIPT_WIRE_BYTES);
    SW_CHECK("session: seeder accepts completed",
             vcs_swarm_receipt_session_handle(
                 rc->up, seeder->book, &rc->seed_x, rc->peer, SW_DAY,
                 rc->reply, rc->reply_len, NULL, NULL) ==
                 VCS_SWARM_RECEIPT_OK);
    SW_CHECK("session: both settled",
             vcs_swarm_receipt_session_settled(rc->up, rc->peer) &&
             vcs_swarm_receipt_session_settled(rc->down, rc->peer));
    return failures;
}

static int session_case_replay_and_refusals(struct receipt_session_ctx *rc,
                                             struct sw_node *seeder,
                                             struct sw_node *leecher)
{
    int failures = 0;
    SW_CHECK("session: replay is duplicate",
             vcs_swarm_receipt_session_handle(
                 rc->up, seeder->book, &rc->seed_x, rc->peer, SW_DAY,
                 rc->reply, rc->reply_len, NULL, NULL) ==
                 VCS_SWARM_RECEIPT_DUPLICATE);
    struct vcs_swarm_transfer grown = rc->leech_x;
    grown.fetched = rc->leech_x.fetched + 1;
    SW_CHECK("session: superseded offer is stale",
             vcs_swarm_receipt_session_handle(
                 rc->down, leecher->book, &grown, rc->peer, SW_DAY,
                 rc->offer, sizeof(rc->offer), NULL, NULL) ==
                 VCS_SWARM_RECEIPT_STALE);
    SW_CHECK("session: stranger refused",
             vcs_swarm_receipt_session_handle(
                 rc->stranger, seeder->book, &rc->seed_x, rc->peer, SW_DAY,
                 rc->reply, rc->reply_len, NULL, NULL) ==
                 VCS_SWARM_RECEIPT_NOT_PARTY);
    uint8_t tamper[VCS_SERVICE_RECEIPT_WIRE_BYTES];
    memcpy(tamper, rc->offer, sizeof(tamper));
    tamper[40] ^= 0xff;
    enum vcs_swarm_receipt_status tst = vcs_swarm_receipt_session_handle(
        rc->down, leecher->book, &rc->leech_x, 78, SW_DAY, tamper,
        sizeof(tamper), NULL, NULL);
    SW_CHECK("session: tampered offer refused",
             tst == VCS_SWARM_RECEIPT_UNVERIFIED ||
             tst == VCS_SWARM_RECEIPT_NOT_PARTY);
    free(rc->reply);
    return failures;
}

static int session_case_persist(struct sw_node *seeder)
{
    int failures = 0;
    struct vcs_swarm_receipt_session *persisted =
        vcs_swarm_receipt_session_open(seeder->zcode_dir);
    uint8_t pub_a[33], pub_b[33];
    SW_CHECK("session: persist open",
             persisted &&
             vcs_swarm_receipt_session_local_pub(persisted, pub_a));
    vcs_swarm_receipt_session_free(persisted);
    persisted = vcs_swarm_receipt_session_open(seeder->zcode_dir);
    SW_CHECK("session: persist reload",
             persisted &&
             vcs_swarm_receipt_session_local_pub(persisted, pub_b) &&
             memcmp(pub_a, pub_b, 33) == 0);
    vcs_swarm_receipt_session_free(persisted);
    return failures;
}

static int session_case_delayed_credit(struct receipt_session_ctx *rc,
                                        struct sw_node *seeder,
                                        struct sw_node *leecher)
{
    int failures = 0;
    size_t seed_events = vcs_service_book_event_count(seeder->book);
    size_t leech_events = vcs_service_book_event_count(leecher->book);
    SW_CHECK("delayed: completed receipt replay is duplicate at both ends",
             vcs_swarm_receipt_session_handle(
                 rc->up, seeder->book, &rc->seed_x, rc->peer, SW_DAY,
                 rc->reply, rc->reply_len, NULL, NULL) ==
                 VCS_SWARM_RECEIPT_DUPLICATE &&
             vcs_swarm_receipt_session_handle(
                 rc->down, leecher->book, &rc->leech_x, rc->peer, SW_DAY,
                 rc->reply, rc->reply_len, NULL, NULL) ==
                 VCS_SWARM_RECEIPT_DUPLICATE);
    SW_CHECK("delayed: replay adds no credit events",
             seed_events > 0 && leech_events > 0 &&
             vcs_service_book_event_count(seeder->book) == seed_events &&
             vcs_service_book_event_count(leecher->book) == leech_events);
    /* Each local book records its transfer with the counterparty key. */
    struct vcs_service_key_totals up_totals, down_totals;
    SW_CHECK("delayed: exact verified bytes credited",
             vcs_service_key_totals(seeder->book, rc->down_pub, SW_DAY,
                                    &up_totals) &&
             vcs_service_key_totals(leecher->book, rc->up_pub, SW_DAY,
                                    &down_totals) &&
             up_totals.verified_bytes_uploaded == 4096 &&
             down_totals.verified_bytes_downloaded == 4096);
    return failures;
}

/* A receipt may precede verified DATA accounting. Keep the session alive:
 * the receiver's ordinary offer after catch-up must settle the exact count,
 * even though the sender withholds its unchanged offer. */
static int session_case_delayed_verification(struct receipt_session_ctx *rc,
                                             struct sw_node *seeder,
                                             struct sw_node *leecher)
{
    int failures = 0;
    memset(&rc->seed_x, 0, sizeof(rc->seed_x));
    memset(&rc->leech_x, 0, sizeof(rc->leech_x));
    memset(rc->seed_x.package_root, 0x45, 32);
    memcpy(rc->leech_x.package_root, rc->seed_x.package_root, 32);
    rc->seed_x.served = 4096;
    rc->leech_x.fetched = 106;
    rc->reply = NULL;
    rc->reply_len = 0;
    SW_CHECK("delayed: sender offers final count",
             vcs_swarm_receipt_session_offer(rc->up, &rc->seed_x, rc->peer,
                                             SW_DAY, rc->offer));
    SW_CHECK("delayed: ahead receipt refused without countersigning",
             vcs_swarm_receipt_session_handle(
                 rc->down, leecher->book, &rc->leech_x, rc->peer, SW_DAY,
                 rc->offer, sizeof(rc->offer), &rc->reply, &rc->reply_len) ==
                 VCS_SWARM_RECEIPT_BYTES_MISMATCH &&
             !rc->reply && rc->reply_len == 0);
    SW_CHECK("delayed: no settlement or credit before verification",
             !vcs_swarm_receipt_session_settled(rc->up, rc->peer) &&
             !vcs_swarm_receipt_session_settled(rc->down, rc->peer) &&
             vcs_service_book_event_count(seeder->book) == 0 &&
             vcs_service_book_event_count(leecher->book) == 0);
    free(rc->reply);
    rc->reply = NULL;
    rc->reply_len = 0;

    rc->leech_x.fetched = rc->seed_x.served;
    SW_CHECK("delayed: unchanged sender offer still withheld",
             !vcs_swarm_receipt_session_offer(rc->up, &rc->seed_x, rc->peer,
                                              SW_DAY, rc->offer));
    SW_CHECK("delayed: verified receiver offers matching count",
             vcs_swarm_receipt_session_offer(rc->down, &rc->leech_x,
                                             rc->peer, SW_DAY, rc->offer));
    SW_CHECK("delayed: sender completes receiver offer",
             vcs_swarm_receipt_session_handle(
                 rc->up, seeder->book, &rc->seed_x, rc->peer, SW_DAY,
                 rc->offer, sizeof(rc->offer), &rc->reply, &rc->reply_len) ==
                 VCS_SWARM_RECEIPT_OK &&
             rc->reply && rc->reply_len == VCS_SERVICE_RECEIPT_WIRE_BYTES);
    SW_CHECK("delayed: receiver accepts completed receipt",
             vcs_swarm_receipt_session_handle(
                 rc->down, leecher->book, &rc->leech_x, rc->peer, SW_DAY,
                 rc->reply, rc->reply_len, NULL, NULL) == VCS_SWARM_RECEIPT_OK);
    SW_CHECK("delayed: both peers settled",
             vcs_swarm_receipt_session_settled(rc->up, rc->peer) &&
             vcs_swarm_receipt_session_settled(rc->down, rc->peer));
    failures += session_case_delayed_credit(rc, seeder, leecher);
    free(rc->reply);
    rc->reply = NULL;
    return failures;
}

int t_swarm_receipt_session(void)
{
    int failures = 0;
    struct sw_node seeder, leecher;
    if (!sw_node_open(&seeder, "rcpt-s", sw_score_contributor) ||
        !sw_node_open(&leecher, "rcpt-l", sw_score_contributor))
        return 1;

    struct receipt_session_ctx rc;
    memset(&rc, 0, sizeof(rc));

    failures += session_case_setup_keys_and_identity(&rc);
    failures += session_case_delayed_verification(&rc, &seeder, &leecher);
    failures += session_case_offer_and_complete(&rc, &seeder, &leecher);
    failures += session_case_replay_and_refusals(&rc, &seeder, &leecher);
    failures += session_case_persist(&seeder);

    vcs_swarm_receipt_session_free(rc.up);
    vcs_swarm_receipt_session_free(rc.down);
    vcs_swarm_receipt_session_free(rc.stranger);
    if (rc.ctx)
        secp256k1_context_destroy(rc.ctx);
    sw_node_close(&seeder);
    sw_node_close(&leecher);
    test_rm_rf_recursive(seeder.datadir);
    test_rm_rf_recursive(leecher.datadir);
    return failures;
}
