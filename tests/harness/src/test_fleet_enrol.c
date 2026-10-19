/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_fleet_enrol — adversarial proof that one-paste fleet enrolment
 * admits exactly what its signatures say and nothing else.
 *
 * Every case is a string somebody could paste: a token with one byte
 * changed, a token minted by another key, a receipt edited after signing, an
 * invite used twice, a taken name, a hand-appended roster line. Each is a way
 * to get a machine into the fleet or point the owner's ssh bridge at one.
 *
 * Fixtures live under test-tmp/ with XDG_STATE_HOME and HOME redirected, so
 * the operator's real fleet key, roster and ~/.ssh/authorized_keys are never
 * touched.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "controllers/rpc_client.h"
#include "fleet_enrol.h"
#include "util/fleet_roster_check.h"
#include "json/json.h"
#include "models/database.h"
#include "models/zid_identity.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/mesh_pairing.h"
#include "net/acme_b64url.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FE_NOW 1757030400
#define FE_TTL 24
/* 56 base32 characters then ".onion": a v3 locator with the right shape and
 * no owner; self-reported, never dialed. */
#define FE_ONION \
    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"

static char g_fe_state[PATH_MAX];
static char g_fe_home[PATH_MAX];
static char g_fe_saved_xdg[PATH_MAX];
static char g_fe_saved_home[PATH_MAX];
static bool g_fe_saved;

/* Point the state-root resolver and the ssh bridge at this case's own tree;
 * called per TEST so a case can have a virgin box (no key, no roster). */
static void fe_isolate(const char *tag)
{
    char base[PATH_MAX - 64];
    const char *xdg = getenv("XDG_STATE_HOME");
    const char *home = getenv("HOME");
    test_make_tmpdir(base, sizeof(base), "fleet_enrol", tag);
    if (!g_fe_saved) {
        g_fe_saved = true;
        (void)snprintf(g_fe_saved_xdg, sizeof(g_fe_saved_xdg), "%s",
                       xdg ? xdg : "");
        (void)snprintf(g_fe_saved_home, sizeof(g_fe_saved_home), "%s",
                       home ? home : "");
    }
    (void)snprintf(g_fe_state, sizeof(g_fe_state), "%s/state", base);
    (void)snprintf(g_fe_home, sizeof(g_fe_home), "%s/home", base);
    setenv("XDG_STATE_HOME", g_fe_state, 1);
    setenv("HOME", g_fe_home, 1);
}

static void fe_restore(void)
{
    if (!g_fe_saved) return;
    if (g_fe_saved_xdg[0]) setenv("XDG_STATE_HOME", g_fe_saved_xdg, 1);
    else unsetenv("XDG_STATE_HOME");
    if (g_fe_saved_home[0]) setenv("HOME", g_fe_saved_home, 1);
    else unsetenv("HOME");
}

/* A deterministic keypair, so a case can play the other box. */
static void fe_key(uint8_t byte, uint8_t seed[32], uint8_t pubkey[32])
{
    uint8_t secret[32];
    memset(seed, byte, 32);
    ed25519_keypair(pubkey, secret, seed);
    memset(secret, 0, sizeof(secret));
}

static struct fleet_box_facts fe_facts(void)
{
    struct fleet_box_facts facts = {0};
    (void)snprintf(facts.hostname, sizeof(facts.hostname), "build-box-7");
    (void)snprintf(facts.os, sizeof(facts.os), "Linux");
    (void)snprintf(facts.os_version, sizeof(facts.os_version), "Test 1.0");
    (void)snprintf(facts.arch, sizeof(facts.arch), "x86_64");
    (void)snprintf(facts.toolchain, sizeof(facts.toolchain), "test cc 1.0");
    (void)snprintf(facts.git_head, sizeof(facts.git_head), "0123456789abcdef");
    facts.cores = 8;
    facts.ram_mb = 32768;
    facts.disk_free_mb = 900000;
    return facts;
}

static size_t fe_occurrences(const char *body, const char *needle)
{
    size_t n = 0, step = strlen(needle);
    for (const char *at = strstr(body, needle); at; at = strstr(at + step,
                                                               needle))
        ++n;
    return n;
}

/* How many wire bytes a pasted record decodes to; 0 when not decodable. */
static size_t fe_wire_len(const char *text)
{
    uint8_t wire[FLEET_ENROL_MACHINE_WIRE_MAX];
    size_t len = 0;
    if (!acme_b64url_decode(text, wire, sizeof(wire), &len)) return 0;
    return len;
}

/* Decode `text`, flip one bit at `offset`, re-encode: a hostile paste that is
 * still valid base64url. */
static bool fe_tamper(const char *text, size_t offset, char *out, size_t cap)
{
    uint8_t wire[FLEET_ENROL_MACHINE_WIRE_MAX];
    size_t len = 0;
    if (!acme_b64url_decode(text, wire, sizeof(wire), &len) || offset >= len)
        return false;
    wire[offset] ^= 0x01u;
    return acme_b64url_encode(wire, len, out, cap) != 0;
}

/* One sealed roster line for `name` under `box_seed`, admitted at `port` by
 * `op_seed`: the whole ceremony in one helper. */
static bool fe_row(const char *name, uint8_t op_byte, uint8_t box_byte,
                   uint16_t port, const char *ssh, char *out, size_t cap)
{
    uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
    uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    struct fleet_invite invite;
    struct fleet_receipt parsed;
    struct fleet_box_facts facts = fe_facts();
    size_t invite_len = 0, receipt_len = 0;
    const char *why = NULL;
    fe_key(op_byte, op_seed, op_pub);
    fe_key(box_byte, box_seed, box_pub);
    return fleet_invite_mint(name, FE_TTL, "", op_seed, op_pub, FE_NOW, token,
                             sizeof(token), &invite, &why) &&
           fleet_invite_parse(token, &invite, invite_wire, sizeof(invite_wire),
                              &invite_len, &why) &&
           fleet_receipt_mint(invite_wire, invite_len, FE_ONION, &facts, ssh,
                              box_seed, box_pub, NULL, receipt,
                              sizeof(receipt),
                              &why) &&
           fleet_receipt_parse(receipt, &parsed, receipt_wire,
                               sizeof(receipt_wire), &receipt_len, &why) &&
           fleet_machine_mint(receipt_wire, receipt_len, FE_NOW, port, op_seed,
                              op_pub, out, cap, &why);
}

/* ── the invite ─────────────────────────────────────────────────────────── */

static int test_fe_invite_round_trip(void)
{
    int failures = 0;
    TEST("fleet enrol: an invite this box minted parses back to the same "
         "fields and verifies against the key inside it") {
        uint8_t seed[32], pubkey[32];
        uint8_t wire[FLEET_ENROL_INVITE_WIRE_MAX];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite minted, parsed;
        size_t wire_len = 0;
        const char *why = NULL;
        fe_key(0x11, seed, pubkey);
        ASSERT(fleet_invite_mint("studio", FE_TTL, "relay.example:2222", seed,
                                 pubkey, FE_NOW, token, sizeof(token), &minted,
                                 &why));
        /* The product is one pasteable line: no whitespace, no padding. */
        ASSERT(strchr(token, ' ') == NULL && strchr(token, '\n') == NULL &&
               strchr(token, '=') == NULL);
        ASSERT(fleet_invite_parse(token, &parsed, wire, sizeof(wire),
                                  &wire_len, &why));
        ASSERT_STR_EQ(parsed.name, "studio");
        ASSERT_STR_EQ(parsed.relay, "relay.example:2222");
        ASSERT_EQ(parsed.expires_unix, (int64_t)(FE_NOW + FE_TTL * 3600));
        ASSERT(memcmp(parsed.operator_pubkey, pubkey, 32) == 0);
        ASSERT(memcmp(parsed.nonce, minted.nonce, sizeof(parsed.nonce)) == 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_invite_tampered(void)
{
    int failures = 0;
    TEST("fleet enrol: one changed byte anywhere in an invite is refused, "
         "including the operator key an attacker would swap in") {
        uint8_t seed[32], pubkey[32], other_seed[32], other_pub[32];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        char forged[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite, parsed;
        const char *why = NULL;
        size_t body = 0;
        fe_key(0x21, seed, pubkey);
        fe_key(0x22, other_seed, other_pub);
        ASSERT(fleet_invite_mint("studio", FE_TTL, "", seed, pubkey, FE_NOW,
                                 token, sizeof(token), &invite, &why));
        /* Every byte of the signed body, one at a time. */
        ASSERT(fe_wire_len(token) > 0u);
        for (body = 0; body < fe_wire_len(token); ++body) {
            ASSERT(fe_tamper(token, body, forged, sizeof(forged)));
            why = NULL;
            ASSERT(!fleet_invite_parse(forged, &parsed, NULL, 0, NULL, &why));
            ASSERT(why != NULL);
        }
        /* A token re-signed by another key verifies internally but names a
         * stranger: `fleet admit` refuses it as invite_not_ours. */
        why = NULL;
        ASSERT(fleet_invite_mint("studio", FE_TTL, "", other_seed, other_pub,
                                 FE_NOW, forged, sizeof(forged), &invite,
                                 &why));
        ASSERT(fleet_invite_parse(forged, &parsed, NULL, 0, NULL, &why));
        ASSERT(memcmp(parsed.operator_pubkey, pubkey, 32) != 0);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_invite_bounds(void)
{
    int failures = 0;
    TEST("fleet enrol: the human name is required, unique in spelling, and "
         "the invite lifetime is bounded at both ends") {
        uint8_t seed[32], pubkey[32];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite;
        const char *why = NULL;
        fe_key(0x31, seed, pubkey);
        /* Names an owner can say out loud. */
        ASSERT(fleet_enrol_name_valid("studio"));
        ASSERT(fleet_enrol_name_valid("node-4"));
        ASSERT(fleet_enrol_name_valid("a1"));
        /* One spelling per machine: no capitals, dots, underscores or edge
         * dashes; not too short or too long. */
        ASSERT(!fleet_enrol_name_valid("Studio"));
        ASSERT(!fleet_enrol_name_valid("studio.two"));
        ASSERT(!fleet_enrol_name_valid("studio_two"));
        ASSERT(!fleet_enrol_name_valid("-studio"));
        ASSERT(!fleet_enrol_name_valid("studio-"));
        ASSERT(!fleet_enrol_name_valid("a"));
        ASSERT(!fleet_enrol_name_valid(""));
        ASSERT(!fleet_enrol_name_valid(NULL));
        ASSERT(!fleet_enrol_name_valid("this-name-is-far-too-long-to-say"));
        /* A refused name never becomes a token. */
        ASSERT(!fleet_invite_mint("Studio", FE_TTL, "", seed, pubkey, FE_NOW,
                                  token, sizeof(token), &invite, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_NAME_INVALID);
        ASSERT(!fleet_invite_mint("studio", 0, "", seed, pubkey, FE_NOW, token,
                                  sizeof(token), &invite, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_TTL_INVALID);
        ASSERT(!fleet_invite_mint("studio", 169, "", seed, pubkey, FE_NOW,
                                  token, sizeof(token), &invite, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_TTL_INVALID);
        /* A relay endpoint cannot smuggle a newline into a roster line or an
         * authorized_keys entry. */
        ASSERT(!fleet_invite_mint("studio", FE_TTL, "host\nmore", seed, pubkey,
                                  FE_NOW, token, sizeof(token), &invite, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_RELAY_INVALID);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_invite_ttl_flag(void)
{
    int failures = 0;
    TEST("fleet invite: ttl_hours takes whole hours from 1 to 168, and a "
         "refusal names that range") {
        const struct zcl_command_spec *spec = zcl_command_registry_find(
            zcl_command_catalog(), "fleet.invite", NULL);
        const char *inside = "{\"name\":\"studio\",\"ttl_hours\":2}";
        const char *outside = "{\"name\":\"studio\",\"ttl_hours\":169}";
        struct json_value input;
        char why[160] = {0};
        ASSERT(spec != NULL);
        json_init(&input);
        ASSERT(json_read(&input, inside, strlen(inside)));
        ASSERT(zcl_command_registry_input_validate(spec, &input, why,
                                                   sizeof(why)));
        json_free(&input);
        json_init(&input);
        ASSERT(json_read(&input, outside, strlen(outside)));
        ASSERT(!zcl_command_registry_input_validate(spec, &input, why,
                                                    sizeof(why)));
        ASSERT(strstr(why, "1 to 168") != NULL);
        json_free(&input);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the receipt ────────────────────────────────────────────────────────── */

static int test_fe_receipt(void)
{
    int failures = 0;
    TEST("fleet enrol: a receipt carries the box's own signature over its "
         "own facts, and an edited fact is refused") {
        uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
        uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
        char forged[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite;
        struct fleet_receipt parsed;
        struct fleet_box_facts facts = fe_facts();
        size_t invite_len = 0;
        const char *why = NULL;
        fe_key(0x41, op_seed, op_pub);
        fe_key(0x42, box_seed, box_pub);
        ASSERT(fleet_invite_mint("studio", FE_TTL, "", op_seed, op_pub, FE_NOW,
                                 token, sizeof(token), &invite, &why));
        ASSERT(fleet_invite_parse(token, &invite, invite_wire,
                                  sizeof(invite_wire), &invite_len, &why));
        ASSERT(fleet_receipt_mint(invite_wire, invite_len, FE_ONION, &facts,
                                  "ssh-ed25519 AAAAkey owner@box", box_seed,
                                  box_pub, NULL, receipt,
                                  sizeof(receipt), &why));
        ASSERT(fleet_receipt_parse(receipt, &parsed, NULL, 0, NULL, &why));
        /* The invite travels intact so the manager re-checks its own
         * signature. */
        ASSERT_STR_EQ(parsed.invite.name, "studio");
        ASSERT(memcmp(parsed.invite.operator_pubkey, op_pub, 32) == 0);
        ASSERT(memcmp(parsed.box_pubkey, box_pub, 32) == 0);
        ASSERT_STR_EQ(parsed.facts.hostname, "build-box-7");
        ASSERT_EQ(parsed.facts.cores, 8u);
        ASSERT_STR_EQ(parsed.ssh_pubkey, "ssh-ed25519 AAAAkey owner@box");
        /* The locator rides under the same box signature; outside the signed
         * body a carrier could point the fleet at an unclaimed address. */
        ASSERT_STR_EQ(parsed.onion, FE_ONION);
        /* Every signed byte, one at a time (a fact, the embedded invite, the
         * ssh key the bridge would authorize, the box key, the signature). */
        ASSERT(fe_wire_len(receipt) > 0u);
        for (size_t at = 0; at < fe_wire_len(receipt); ++at) {
            ASSERT(fe_tamper(receipt, at, forged, sizeof(forged)));
            why = NULL;
            ASSERT(!fleet_receipt_parse(forged, &parsed, NULL, 0, NULL, &why));
            ASSERT(why != NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── the roster ─────────────────────────────────────────────────────────── */

static int test_fe_roster_seal(void)
{
    int failures = 0;
    TEST("fleet enrol: a roster line is only this fleet's row when this "
         "operator key sealed it") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t op_pub[32], op_seed[32], other_pub[32], other_seed[32];
        struct fleet_machine machine;
        const char *why = NULL;
        fe_key(0x51, op_seed, op_pub);
        fe_key(0x52, other_seed, other_pub);
        ASSERT(fe_row("studio", 0x51, 0x53, 22200, "", row, sizeof(row)));
        ASSERT(fleet_machine_parse(row, op_pub, &machine, &why));
        ASSERT_STR_EQ(machine.receipt.invite.name, "studio");
        ASSERT_EQ(machine.relay_port, (uint16_t)22200);
        ASSERT_EQ(machine.enrolled_at, (int64_t)FE_NOW);
        /* A line sealed by somebody else is not readable as this fleet's
         * row, so hand-editing cannot invent one. */
        why = NULL;
        ASSERT(!fleet_machine_parse(row, other_pub, &machine, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ROSTER_UNREADABLE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_roster_admission(void)
{
    int failures = 0;
    TEST("fleet enrol: a name belongs to one box, a box keeps its port, and "
         "a line this key did not seal is counted but never listed") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t op_pub[32], op_seed[32], box_a[32], box_b[32], seed[32];
        struct fleet_roster_scan scan = {0};
        const char *why = NULL;
        fe_isolate("admission");
        fe_key(0x61, op_seed, op_pub);
        fe_key(0x62, seed, box_a);
        fe_key(0x63, seed, box_b);
        /* Empty roster: nothing taken, the first port free. */
        ASSERT(fleet_roster_scan(op_pub, "studio", box_a, &scan, &why));
        ASSERT_EQ(scan.rows, 0u);
        ASSERT_EQ(scan.next_port, (uint16_t)FLEET_ENROL_PORT_FIRST);
        ASSERT(!scan.name_taken && !scan.same_box);
        ASSERT(fe_row("studio", 0x61, 0x62, FLEET_ENROL_PORT_FIRST, "", row,
                      sizeof(row)));
        ASSERT(fleet_roster_append(row, &why));
        /* A DIFFERENT box asking for a name that is taken is refused. */
        ASSERT(fleet_roster_scan(op_pub, "studio", box_b, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);
        ASSERT(scan.name_taken);
        ASSERT(!scan.same_box);
        ASSERT_EQ(scan.next_port, (uint16_t)(FLEET_ENROL_PORT_FIRST + 1));
        /* The same box re-enrolling keeps its port, so re-running admit after
         * a lost reply grants nothing new. */
        ASSERT(fleet_roster_scan(op_pub, "studio", box_a, &scan, &why));
        ASSERT(scan.same_box);
        ASSERT(!scan.name_taken);
        ASSERT_EQ(scan.existing_port, (uint16_t)FLEET_ENROL_PORT_FIRST);
        /* A row appended under a different key raises the unverifiable count,
         * not the row count. */
        ASSERT(fe_row("intruder", 0x64, 0x65, FLEET_ENROL_PORT_FIRST + 1, "",
                      row, sizeof(row)));
        ASSERT(fleet_roster_append(row, &why));
        ASSERT(fleet_roster_scan(op_pub, "intruder", box_b, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);
        ASSERT_EQ(scan.unverifiable, 1u);
        ASSERT(!scan.name_taken);
        PASS();
    } _test_next:;
    return failures;
}

/* ── importing a roster line on a box that is not the manager ──────────── */

static int test_fe_roster_import(void)
{
    int failures = 0;
    TEST("fleet enrol: a roster line is imported only after the operator key "
         "this box trusts verifies it; a forged line and a wrong operator key "
         "leave the roster untouched") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char forged[FLEET_ENROL_MACHINE_TEXT_MAX];
        char foreign[FLEET_ENROL_MACHINE_TEXT_MAX];
        char twin[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t op_seed[32], op_pub[32], other_seed[32], other_pub[32];
        struct fleet_machine machine;
        struct fleet_roster_scan scan = {0};
        const char *why = NULL;
        bool appended = true;
        fe_isolate("import");
        fe_key(0x81, op_seed, op_pub);    /* the operator this box trusts */
        fe_key(0x91, other_seed, other_pub); /* somebody else's operator */
        ASSERT(fe_row("studio", 0x81, 0x82, FLEET_ENROL_PORT_FIRST, "", row,
                      sizeof(row)));

        /* A forged line: the genuine line with one byte changed; valid
         * base64url, no longer its seal. */
        ASSERT(fe_tamper(row, fe_wire_len(row) / 2, forged, sizeof(forged)));
        ASSERT(!fleet_roster_import(forged, op_pub, &machine, &appended,
                                    &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);
        ASSERT(!appended);

        /* A wrong operator key both ways: a genuine line against an untrusted
         * key, and another operator's line against the key it does match. */
        ASSERT(!fleet_roster_import(row, other_pub, &machine, &appended,
                                    &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);
        ASSERT(fe_row("studio", 0x91, 0x82, FLEET_ENROL_PORT_FIRST, "",
                      foreign, sizeof(foreign)));
        ASSERT(!fleet_roster_import(foreign, op_pub, &machine, &appended,
                                    &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);

        /* None of the three reached the file, even as an unverifiable row. */
        ASSERT(fleet_roster_scan(op_pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 0u);
        ASSERT_EQ(scan.unverifiable, 0u);

        /* The genuine line, against the trusted key, is imported once. */
        ASSERT(fleet_roster_import(row, op_pub, &machine, &appended, &why));
        ASSERT(appended);
        ASSERT_STR_EQ(machine.receipt.invite.name, "studio");
        ASSERT_EQ(machine.relay_port, (uint16_t)FLEET_ENROL_PORT_FIRST);
        ASSERT(fleet_roster_import(row, op_pub, &machine, &appended, &why));
        ASSERT(!appended);
        ASSERT(fleet_roster_scan(op_pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);

        /* A different box under a name the roster already gives away is
         * refused by name, even though the operator sealed it. */
        ASSERT(fe_row("studio", 0x81, 0x83, FLEET_ENROL_PORT_FIRST + 1, "",
                      twin, sizeof(twin)));
        ASSERT(!fleet_roster_import(twin, op_pub, &machine, &appended, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_NAME_TAKEN);
        ASSERT(fleet_roster_scan(op_pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_replay(void)
{
    int failures = 0;
    TEST("fleet enrol: an invite nonce is spendable exactly once") {
        uint8_t nonce[FLEET_ENROL_NONCE_BYTES];
        uint8_t other[FLEET_ENROL_NONCE_BYTES];
        bool seen = true;
        const char *why = NULL;
        fe_isolate("replay");
        memset(nonce, 0xa5, sizeof(nonce));
        memset(other, 0x5a, sizeof(other));
        ASSERT(fleet_nonce_seen(nonce, &seen, &why));
        ASSERT(!seen);
        ASSERT(fleet_nonce_spend(nonce, &why));
        ASSERT(fleet_nonce_seen(nonce, &seen, &why));
        ASSERT(seen);
        /* Spending one invite does not burn another. */
        ASSERT(fleet_nonce_seen(other, &seen, &why));
        ASSERT(!seen);
        PASS();
    } _test_next:;
    return failures;
}

/* fleet_invite_mint() must assign out->nonce. Every case pre-fills the
 * caller's struct with a FIXED pattern, so a mint that leaves the nonce
 * unwritten yields identical nonces and fails deterministically (otherwise
 * every invite carried the all-zero nonce, the spent-invite ledger burned it on
 * the first admission, and a manager could admit exactly one computer). */
static int test_fe_invite_nonce_fresh(void)
{
    int failures = 0;
    TEST("fleet enrol: every invite carries its own random nonce, drawn by "
         "the mint and never inherited from the caller's memory") {
        enum { FE_MINTS = 8 };
        uint8_t op_seed[32], op_pub[32];
        uint8_t zero[FLEET_ENROL_NONCE_BYTES];
        uint8_t stale[FLEET_ENROL_NONCE_BYTES];
        static char token[FE_MINTS][FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite[FE_MINTS];
        struct fleet_invite parsed;
        const char *why = NULL;
        size_t i = 0, j = 0;
        fe_key(0xb1, op_seed, op_pub);
        memset(zero, 0, sizeof(zero));
        memset(stale, 0xee, sizeof(stale));
        for (i = 0; i < FE_MINTS; i++) {
            /* Half the mints get a zeroed struct, half a poisoned one, so
             * neither "leave it" nor "zero it" passes. */
            memset(&invite[i], (i % 2u) ? 0xee : 0x00, sizeof(invite[i]));
            ASSERT(fleet_invite_mint("studio", FE_TTL, "", op_seed, op_pub,
                                     FE_NOW, token[i], sizeof(token[i]),
                                     &invite[i], &why));
            /* The mint OVERWROTE whatever the caller handed it. */
            ASSERT(memcmp(invite[i].nonce, zero, sizeof(zero)) != 0);
            ASSERT(memcmp(invite[i].nonce, stale, sizeof(stale)) != 0);
        }
        /* Pairwise distinct: a repeat means a constant, a reset counter or no
         * draw at all. */
        for (i = 0; i < FE_MINTS; i++)
            for (j = i + 1; j < FE_MINTS; j++)
                ASSERT(memcmp(invite[i].nonce, invite[j].nonce,
                              FLEET_ENROL_NONCE_BYTES) != 0);
        /* The nonce is in the signed body, so two invites for one name and
         * key are different lines. */
        ASSERT(strcmp(token[0], token[1]) != 0);
        /* It survives the wire: the recorded nonce is what the box presents
         * back. */
        ASSERT(fleet_invite_parse(token[1], &parsed, NULL, 0, NULL, &why));
        ASSERT(memcmp(parsed.nonce, invite[1].nonce,
                      FLEET_ENROL_NONCE_BYTES) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Admit one machine, then a second: the whole ceremony twice against one
 * manager key, asking the spent-invite ledger what `fleet admit` asks it in
 * the same order, so a repeating nonce refuses the second box. */
static int test_fe_admit_two_machines(void)
{
    int failures = 0;
    TEST("fleet enrol: one manager admits a second machine — two invites, "
         "two unspent nonces, two rows on the roster") {
        static const char *const names[2] = { "studio", "annex" };
        static const uint8_t box_bytes[2] = { 0xc2, 0xc3 };
        uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
        uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
        uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
        uint8_t nonce[2][FLEET_ENROL_NONCE_BYTES];
        static char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        static char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
        static char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite;
        struct fleet_receipt parsed;
        struct fleet_box_facts facts = fe_facts();
        struct fleet_roster_scan scan = {0};
        size_t invite_len = 0, receipt_len = 0, i = 0;
        bool seen = true;
        const char *why = NULL;
        fe_isolate("admit-two");
        fe_key(0xc1, op_seed, op_pub);
        for (i = 0; i < 2u; i++) {
            fe_key(box_bytes[i], box_seed, box_pub);
            /* The manager mints into a zeroed struct (the live condition
             * behind the all-zero nonce), so a mint that draws no nonce fails
             * the second lap. */
            memset(&invite, 0, sizeof(invite));
            ASSERT(fleet_invite_mint(names[i], FE_TTL, "", op_seed, op_pub,
                                     FE_NOW, token, sizeof(token), &invite,
                                     &why));
            /* The box joins. */
            ASSERT(fleet_invite_parse(token, &invite, invite_wire,
                                      sizeof(invite_wire), &invite_len, &why));
            memcpy(nonce[i], invite.nonce, FLEET_ENROL_NONCE_BYTES);
            ASSERT(fleet_receipt_mint(invite_wire, invite_len, FE_ONION,
                                      &facts, "", box_seed, box_pub, NULL,
                                      receipt, sizeof(receipt), &why));
            ASSERT(fleet_receipt_parse(receipt, &parsed, receipt_wire,
                                       sizeof(receipt_wire), &receipt_len,
                                       &why));
            /* The manager admits: the replay question first, as fe_admit
             * asks it, then the seal and the row. */
            ASSERT(fleet_nonce_seen(parsed.invite.nonce, &seen, &why));
            ASSERT(!seen);
            ASSERT(fleet_machine_mint(receipt_wire, receipt_len, FE_NOW,
                                      (uint16_t)(FLEET_ENROL_PORT_FIRST + i),
                                      op_seed, op_pub, row, sizeof(row),
                                      &why));
            ASSERT(fleet_roster_append(row, &why));
            ASSERT(fleet_nonce_spend(parsed.invite.nonce, &why));
        }
        /* Two machines, two nonces, and neither invite reusable. */
        ASSERT(memcmp(nonce[0], nonce[1], FLEET_ENROL_NONCE_BYTES) != 0);
        ASSERT(fleet_nonce_seen(nonce[0], &seen, &why));
        ASSERT(seen);
        ASSERT(fleet_nonce_seen(nonce[1], &seen, &why));
        ASSERT(seen);
        ASSERT(fleet_roster_scan(op_pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 2u);
        ASSERT_EQ(scan.unverifiable, 0u);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the ssh bridge ─────────────────────────────────────────────────────── */

static int test_fe_bridge(void)
{
    int failures = 0;
    TEST("fleet enrol: the bridge line is one restricted loopback forward, "
         "byte for byte, and adding it twice adds one line") {
        char line[FLEET_ENROL_SSH_MAX + 256];
        char path[PATH_MAX];
        char body[4096];
        char dir[PATH_MAX];
        const char *key = "ssh-ed25519 AAAAC3NzaC1 owner@box";
        const char *why = NULL;
        FILE *f = NULL;
        size_t read = 0;
        bool added = false;
        fe_isolate("bridge");
        ASSERT(fleet_bridge_line(key, 22207, "studio", line, sizeof(line)));
        /* Written out in full: a test that asks the subject to build the
         * string cannot notice it changing, and every token is a denial. */
        ASSERT_STR_EQ(line,
                      "restrict,port-forwarding,permitlisten=\"127.0.0.1:22207\" "
                      "ssh-ed25519 AAAAC3NzaC1 owner@box z23-fleet-studio");
        /* No key, a name outside the grammar, or a port outside the closed
         * range never becomes a line at all. */
        ASSERT(!fleet_bridge_line("", 22207, "studio", line, sizeof(line)));
        ASSERT(!fleet_bridge_line(key, 22207, "Studio", line, sizeof(line)));
        ASSERT(!fleet_bridge_line(key, 22, "studio", line, sizeof(line)));
        ASSERT(fleet_bridge_line(key, 22207, "studio", line, sizeof(line)));
        (void)snprintf(dir, sizeof(dir), "%s/.ssh", g_fe_home);
        (void)mkdir(g_fe_home, 0700);
        ASSERT(mkdir(dir, 0700) == 0);
        ASSERT(fleet_bridge_authorize(line, "studio", &added, &why));
        ASSERT(added);
        /* Idempotent per box name: a second admit is a no-op. */
        added = true;
        ASSERT(fleet_bridge_authorize(line, "studio", &added, &why));
        ASSERT(!added);
        (void)snprintf(path, sizeof(path), "%s/authorized_keys", dir);
        f = fopen(path, "r");
        ASSERT(f != NULL);
        read = fread(body, 1, sizeof(body) - 1u, f);
        (void)fclose(f);
        body[read] = '\0';
        /* Exactly one grant and one line per box: a duplicate append would be
         * a second standing authorization. */
        ASSERT(fe_occurrences(body, "z23-fleet-studio") == 1u);
        ASSERT(fe_occurrences(body, "permitlisten") == 1u);
        ASSERT(fe_occurrences(body, "\n") == 1u);
        ASSERT_STR_EQ(body + strlen(body) - 1u, "\n");
        PASS();
    } _test_next:;
    return failures;
}

static bool fe_bridge_fixture(const char *path, const char *bytes, size_t n,
                              bool write)
{
    char body[256];
    if (n > sizeof(body)) return false;
    FILE *f = fopen(path, write ? "wb" : "rb");
    if (!f) return false;
    size_t got = write ? fwrite(bytes, 1, n, f) : fread(body, 1, sizeof(body), f);
    bool ok = !ferror(f); int closed = fclose(f);
    return ok && closed == 0 && got == n && (write || memcmp(body, bytes, n) == 0);
}

static int test_fe_bridge_nul(void)
{
    int failures = 0;
    TEST("fleet enrol: a NUL before or after a bridge grant refuses unchanged") {
        const char record[] = "\0\nrestrict,port-forwarding,permitlisten=\"127.0.0.1:22207\" "
                              "ssh-ed25519 AAAAC3NzaC1 owner@box z23-fleet-studio\n";
        const struct { const char *bytes; size_t size; bool accepted; } cases[] = {
            /* No existing grant: the NUL must also prevent a fresh append. */
            {"\0", 1u, false},
            /* Include the terminating NUL as a measured byte after the tag. */
            {record + 2, sizeof(record) - 2u, false},
            {record, sizeof(record) - 1u, false},
            {record + 2, sizeof(record) - 3u, true},
            /* A complete duplicate grant at EOF needs no final newline. */
            {record + 2, sizeof(record) - 4u, true},
        };
        char path[PATH_MAX], dir[PATH_MAX];
        const char *why = NULL; bool added;
        fe_isolate("bridge-nul");
        (void)snprintf(dir, sizeof(dir), "%s/.ssh", g_fe_home);
        (void)mkdir(g_fe_home, 0700); ASSERT(mkdir(dir, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/authorized_keys", dir);
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            ASSERT(fe_bridge_fixture(path, cases[i].bytes, cases[i].size, true));
            added = true;
            bool ok = fleet_bridge_authorize(record + 2, "studio", &added, &why);
            ASSERT_EQ(ok, cases[i].accepted);
            ASSERT(!added);
            ASSERT_STR_EQ(why ? why : "",
                          cases[i].accepted ? "" : FLEET_ENROL_WHY_BRIDGE_UNWRITABLE);
            ASSERT(fe_bridge_fixture(path, cases[i].bytes, cases[i].size, false));
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_ssh_record(void)
{
    int failures = 0;
    TEST("fleet enrol: the dedicated key consumes one complete measured record") {
        const char key[] = "ssh-ed25519 AAAAC3NzaC1 owner@box";
        const char hidden[] = "ssh-ed25519 AAAAC3NzaC1 owner@box\0junk\n";
        char large[FLEET_ENROL_SSH_MAX + 4];
        char path[PATH_MAX], dir[PATH_MAX], out[FLEET_ENROL_SSH_MAX + 1];
        memset(large, 'x', sizeof(large));
        const struct { const char *body; size_t len; bool accepted; } cases[] = {
            {hidden, sizeof(hidden) - 1u, false},
            {large, FLEET_ENROL_SSH_MAX + 1u, false},
            {large, sizeof(large), false},
            {"ssh-ed25519 key\nextra", 21u, false},
            {"ssh-ed25519 key\rjunk\n", 21u, false},
            {key, sizeof(key) - 1u, true},
            {"ssh-ed25519 key\n", 16u, true},
            {"ssh-ed25519 key\r\n", 17u, true},
            {large, FLEET_ENROL_SSH_MAX, true},
        };
        fe_isolate("ssh-record");
        (void)snprintf(dir, sizeof(dir), "%s/.ssh", g_fe_home);
        (void)mkdir(g_fe_home, 0700);
        ASSERT(mkdir(dir, 0700) == 0);
        (void)snprintf(path, sizeof(path), "%s/z23_fleet.pub", dir);
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            FILE *f = fopen(path, "wb");
            ASSERT(f != NULL);
            size_t written = fwrite(cases[i].body, 1, cases[i].len, f);
            int closed = fclose(f);
            ASSERT_EQ(written, cases[i].len);
            ASSERT_EQ(closed, 0);
            memset(out, '!', sizeof(out));
            fleet_enrol_ssh_pubkey(out, sizeof(out));
            ASSERT_EQ(out[0] != '\0', cases[i].accepted);
            if (cases[i].accepted) {
                size_t len = cases[i].len;
                if (cases[i].body[len - 1u] == '\n') --len;
                if (cases[i].body[len - 1u] == '\r') --len;
                ASSERT_EQ(strlen(out), len);
                ASSERT(memcmp(out, cases[i].body, len) == 0);
            }
        }
        PASS();
    } _test_next:;
    return failures;
}

/* ── the onion locator ──────────────────────────────────────────────────── */

static int test_fe_onion_grammar(void)
{
    int failures = 0;
    TEST("fleet enrol: the onion column accepts a v3 locator and empty, and "
         "refuses everything a reader could mistake for one") {
        char shorter[80], capital[80], ported[80], bad_port[80];
        size_t n = strlen(FE_ONION);
        /* Empty (no persistent onion yet) is a missing column, not a bad
         * one. */
        ASSERT(fleet_enrol_onion_valid(""));
        ASSERT(fleet_enrol_onion_valid(FE_ONION));
        /* An explicit port is allowed; the address is a locator. */
        ASSERT(snprintf(ported, sizeof(ported), "%s:9050", FE_ONION) > 0);
        ASSERT(fleet_enrol_onion_valid(ported));
        /* A v2 address is 16 characters; a truncated v3 body must refuse. */
        ASSERT(n < sizeof(shorter));
        memcpy(shorter, FE_ONION, n + 1u);
        memmove(shorter + 16, shorter + n - 6, 7);
        ASSERT(!fleet_enrol_onion_valid(shorter));
        /* One spelling per address: an uppercase body would be a second row. */
        memcpy(capital, FE_ONION, n + 1u);
        capital[0] = 'A';
        ASSERT(!fleet_enrol_onion_valid(capital));
        /* '1', '0' and '8' are not RFC 4648 base32; a swapped hand-typed
         * address is refused. */
        memcpy(capital, FE_ONION, n + 1u);
        capital[3] = '1';
        ASSERT(!fleet_enrol_onion_valid(capital));
        /* The suffix is checked, not assumed. */
        memcpy(capital, FE_ONION, n + 1u);
        capital[n - 1] = 'x';
        ASSERT(!fleet_enrol_onion_valid(capital));
        /* A port is digits, and only as many as a port has. */
        ASSERT(snprintf(bad_port, sizeof(bad_port), "%s:90x0", FE_ONION) > 0);
        ASSERT(!fleet_enrol_onion_valid(bad_port));
        ASSERT(snprintf(bad_port, sizeof(bad_port), "%s:", FE_ONION) > 0);
        ASSERT(!fleet_enrol_onion_valid(bad_port));
        ASSERT(snprintf(bad_port, sizeof(bad_port), "%s:123456", FE_ONION) > 0);
        ASSERT(!fleet_enrol_onion_valid(bad_port));
        /* A hostname or IP literal is not an onion identity. */
        ASSERT(!fleet_enrol_onion_valid("relay.example.com"));
        ASSERT(!fleet_enrol_onion_valid("192.0.2.1:9050"));
        PASS();
    } _test_next:;
    return failures;
}

/* A receipt with an intact signature but a non-locator onion field is refused
 * on the way in: a signature proves who wrote it, not that it is dialable. */
static int test_fe_onion_refused_at_mint(void)
{
    int failures = 0;
    TEST("fleet enrol: a receipt is refused by name when its onion is not a "
         "v3 locator") {
        uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
        uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
        char token[FLEET_ENROL_MACHINE_TEXT_MAX];
        char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_invite invite;
        struct fleet_box_facts facts = fe_facts();
        size_t invite_len = 0;
        const char *why = NULL;
        fe_key(0x81, op_seed, op_pub);
        fe_key(0x82, box_seed, box_pub);
        ASSERT(fleet_invite_mint("studio", FE_TTL, "", op_seed, op_pub, FE_NOW,
                                 token, sizeof(token), &invite, &why));
        ASSERT(fleet_invite_parse(token, &invite, invite_wire,
                                  sizeof(invite_wire), &invite_len, &why));
        why = NULL;
        ASSERT(!fleet_receipt_mint(invite_wire, invite_len, "node4.local",
                                   &facts, "", box_seed, box_pub, NULL,
                                   receipt,
                                   sizeof(receipt), &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ONION_INVALID);
        /* And an absent locator is not an error: the box simply has none. */
        why = NULL;
        ASSERT(fleet_receipt_mint(invite_wire, invite_len, "", &facts, "",
                                  box_seed, box_pub, NULL, receipt,
                                  sizeof(receipt),
                                  &why));
        ASSERT(why == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── fleet.machines pages past the render cap ───────────────────────────── */

static const char *fe_listed_name(const struct zcl_command_reply *reply,
                                  size_t index)
{
    const struct json_value *rows = json_get(&reply->data, "machines");
    const struct json_value *row = rows ? json_at(rows, index) : NULL;
    const struct json_value *verified = row ? json_get(row, "verified") : NULL;
    return json_get_str(json_get(verified, "name"));
}

/* The shipped leaf: the catalog validator, then the registered handler.
 * `reply` is initialized before any return; on false it has been freed, on
 * true the caller owns it. A validator refusal never reaches the handler. */
static bool fe_machines_call(const char *body, struct zcl_command_reply *reply,
                             char *why, size_t why_cap)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "fleet.machines", NULL);
    struct zcl_command_request request = {0};
    struct json_value input;
    zcl_command_reply_init(reply, "zcl.fleet.machines.v1");
    json_init(&input);
    why[0] = '\0';
    if (!spec || !spec->handler ||
        !json_read(&input, body, strlen(body)) ||
        !zcl_command_registry_input_validate(spec, &input, why, why_cap)) {
        json_free(&input);
        zcl_command_reply_free(reply);
        return false;
    }
    request.spec = spec;
    request.input = &input;
    spec->handler(&request, reply);
    json_free(&input);
    return true;
}

static int test_fe_machines_page(void)
{
    int failures = 0;
    TEST("fleet machines: offset and limit page verified rows past the "
         "render cap, and an unverifiable line does not take a slot") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char name[8];
        char past[8];
        char before[8];
        char query[64];
        char why_text[192];
        const char *why = NULL;
        uint8_t op_pub[32], op_seed[32];
        struct zcl_command_reply reply;
        const struct zcl_command_spec *spec = NULL;
        const struct json_value *flag = NULL;
        uint32_t i = 0;
        uint32_t cap = (uint32_t)FLEET_ENROL_ROSTER_MAX;
        fe_isolate("machines-page");
        fe_key(0xa1, op_seed, op_pub);
        ASSERT(fleet_enrol_operator_write(op_pub, &why));
        spec = zcl_command_registry_find(zcl_command_catalog(),
                                        "fleet.machines", NULL);
        ASSERT(spec != NULL);
        ASSERT(strstr(spec->input_keys, "offset") != NULL);
        ASSERT(strstr(spec->input_keys, "limit") != NULL);

        /* Empty input is still the first page. An empty roster says so. */
        ASSERT(fe_machines_call("{}", &reply, why_text, sizeof(why_text)));
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "total")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "next_offset")), -1);
        flag = json_get(&reply.data, "truncated");
        ASSERT(flag && flag->type == JSON_BOOL && !json_get_bool(flag));
        zcl_command_reply_free(&reply);

        /* A line sealed by somebody else sits in the file and must not
         * shift the verified page. */
        ASSERT(fe_row("intruder", 0xb2, 0xb3, FLEET_ENROL_PORT_FIRST, "", row,
                      sizeof(row)));
        ASSERT(fleet_roster_append(row, &why));
        for (i = 0; i < cap + 1u; i++) {
            ASSERT(snprintf(name, sizeof(name), "m%02u", i) > 0);
            ASSERT(fe_row(name, 0xa1, (uint8_t)(0x10u + (i % 200u)),
                          (uint16_t)(FLEET_ENROL_PORT_FIRST + (i % cap)),
                          "", row, sizeof(row)));
            ASSERT(fleet_roster_append(row, &why));
        }
        ASSERT(snprintf(before, sizeof(before), "m%02u", cap - 1u) > 0);
        ASSERT(snprintf(past, sizeof(past), "m%02u", cap) > 0);

        /* The default page stops at the render cap and names the next one. */
        ASSERT(fe_machines_call("{}", &reply, why_text, sizeof(why_text)));
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "total")),
                  (int64_t)cap + 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")),
                  (int64_t)cap);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "offset")), 0);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "next_offset")),
                  (int64_t)cap);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "unverifiable")), 1);
        flag = json_get(&reply.data, "truncated");
        ASSERT(flag && flag->type == JSON_BOOL && json_get_bool(flag));
        ASSERT_STR_EQ(fe_listed_name(&reply, 0), "m00");
        ASSERT_STR_EQ(fe_listed_name(&reply, (size_t)cap - 1u), before);
        zcl_command_reply_free(&reply);

        /* The row past the render cap is the first row of the next page. */
        ASSERT(snprintf(query, sizeof(query),
                        "{\"offset\":%u,\"limit\":8}", cap) > 0);
        ASSERT(fe_machines_call(query, &reply, why_text, sizeof(why_text)));
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")), 1);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "offset")), (int64_t)cap);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "limit")), 8);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "next_offset")), -1);
        flag = json_get(&reply.data, "truncated");
        ASSERT(flag && flag->type == JSON_BOOL && !json_get_bool(flag));
        ASSERT_STR_EQ(fe_listed_name(&reply, 0), past);
        zcl_command_reply_free(&reply);

        /* A page that straddles the cap returns both sides, in order. */
        ASSERT(snprintf(query, sizeof(query),
                        "{\"offset\":%u,\"limit\":2}", cap - 1u) > 0);
        ASSERT(fe_machines_call(query, &reply, why_text, sizeof(why_text)));
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")), 2);
        ASSERT_STR_EQ(fe_listed_name(&reply, 0), before);
        ASSERT_STR_EQ(fe_listed_name(&reply, 1), past);
        zcl_command_reply_free(&reply);

        /* A limit above the render cap is one page, not a bigger reply. */
        ASSERT(fe_machines_call("{\"limit\":1000000}", &reply, why_text,
                                sizeof(why_text)));
        ASSERT_STR_EQ(reply.error.code, "");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "limit")), (int64_t)cap);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "returned")),
                  (int64_t)cap);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "next_offset")),
                  (int64_t)cap);
        zcl_command_reply_free(&reply);

        /* The validator is the gate the shell uses. These never dispatch. */
        ASSERT(!fe_machines_call("{\"offset\":\"1\"}", &reply, why_text,
                                 sizeof(why_text)));
        ASSERT(strstr(why_text, "offset") != NULL);
        ASSERT(!fe_machines_call("{\"offset\":-1}", &reply, why_text,
                                 sizeof(why_text)));
        ASSERT(strstr(why_text, "offset") != NULL);
        ASSERT(!fe_machines_call("{\"limit\":0}", &reply, why_text,
                                 sizeof(why_text)));
        ASSERT(strstr(why_text, "limit") != NULL);
        ASSERT(!fe_machines_call("{\"page\":1}", &reply, why_text,
                                 sizeof(why_text)));
        ASSERT(strstr(why_text, "unknown input key") != NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* ── rendering ──────────────────────────────────────────────────────────── */

static int test_fe_render(void)
{
    int failures = 0;
    TEST("fleet enrol: what the operator attested and what the box claimed "
         "are rendered as two objects that never merge") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char text[4096];
        uint8_t op_pub[32], op_seed[32];
        struct fleet_machine machine;
        struct json_value out;
        const struct json_value *verified = NULL, *self = NULL;
        const char *why = NULL;
        fe_key(0x71, op_seed, op_pub);
        ASSERT(fe_row("studio", 0x71, 0x72, 22203, "", row, sizeof(row)));
        ASSERT(fleet_machine_parse(row, op_pub, &machine, &why));
        json_init(&out);
        fleet_machine_render(&machine, &out);
        verified = json_get(&out, "verified");
        self = json_get(&out, "self_reported");
        ASSERT(verified != NULL && self != NULL);
        /* The name leads the verified object as the machine's handle. */
        ASSERT_STR_EQ(json_get_str(json_get(verified, "name")), "studio");
        ASSERT_EQ(json_get_int(json_get(verified, "relay_port")), 22203);
        /* A hardware claim is never in the verified object, and the name is
         * never in the self-reported one. */
        ASSERT(json_get(verified, "hostname") == NULL);
        ASSERT(json_get(verified, "cores") == NULL);
        ASSERT(json_get(self, "name") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(self, "onion")), FE_ONION);
        /* The locator is a column, never the handle. */
        ASSERT(json_get(verified, "onion") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(self, "hostname")), "build-box-7");
        ASSERT_EQ(json_get_int(json_get(self, "cores")), 8);
        /* Nothing private reaches the render: no seed, no key material beyond
         * the public one. */
        ASSERT(json_write(&out, text, sizeof(text)) > 0);
        ASSERT(strstr(text, "seed") == NULL);
        ASSERT(strstr(text, "private") == NULL);
        json_free(&out);
        PASS();
    } _test_next:;
    return failures;
}

/* ── fleet.doctor ───────────────────────────────────────────────────────── */

#define FD_FP "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
#define FD_DECOY "deadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de"

static bool g_fd_node_up;

/* A stand-in node: a stub error when "down", else the three reads the
 * doctor makes. Five peers, two of them on the hybrid transport; the
 * identity capsule carries a decoy private field the doctor must drop. */
static char *fd_rpc_hook(const char *method, const char *params)
{
    (void)params;
    if (!g_fd_node_up)
        return strdup("{\"code\":-32603,\"message\":\"connect failed\"}");
    if (strcmp(method, "getpeerinfo") == 0)
        return strdup("[{\"transport\":\"noise_xxhfs\"},"
                      "{\"transport\":\"plaintext\"},"
                      "{\"transport\":\"noise_xxhfs\"},"
                      "{\"transport\":\"handshaking\"},"
                      "{\"transport\":\"plaintext\"}]");
    if (strcmp(method, "dumpstate") == 0)
        return strdup("{\"state\":{\"transport\":{\"observed\":true,"
                      "\"noise_enabled\":true,\"identity_loaded\":true,"
                      "\"local_noise_fingerprint_sha3\":\"" FD_FP "\","
                      "\"noise_private_key\":\"" FD_DECOY "\"},"
                      "\"authenticated_dht\":{\"observed\":true,"
                      "\"enabled\":true,\"disabled_reason\":\"\"}}}");
    if (strcmp(method, "fleet_board") == 0)
        return strdup("{\"ok\":true,\"posts\":[],\"returned\":3}");
    return strdup("{\"code\":-32601,\"message\":\"no such method\"}");
}

/* A datadir holding `count` recorded pairings, the first expiring at
 * `first_expiry`; the rest a year out. */
static bool fd_make_datadir(const char *tag, int count, int64_t first_expiry,
                            char *dir, size_t cap)
{
    char path[PATH_MAX + 16];
    struct node_db db;
    int64_t now = (int64_t)time(NULL);
    test_make_tmpdir(dir, cap, "fleet_enrol", tag);
    if (count == 0)
        return true;
    if (snprintf(path, sizeof(path), "%s/node.db", dir) <= 0 ||
        !node_db_open(&db, path))
        return false;
    for (int i = 0; i < count; i++) {
        struct db_mesh_pairing row;
        memset(&row, 0, sizeof(row));
        memset(row.network_genesis, 0x11, 32);
        memset(row.peer_master_pubkey, 0x40 + (i % 50), 32);
        row.peer_master_pubkey[0] = (uint8_t)i;
        memset(row.peer_noise_pubkey, 0x20, 32);
        row.peer_noise_pubkey[1] = (uint8_t)i;
        row.capability_mask = MESH_PAIRING_CAP_STATUS_READ;
        row.delegation_sequence = 1;
        row.paired_at = now - 1000;
        row.expires_at = i == 0 ? first_expiry : now + 365 * 86400;
        if (!mesh_pairing_id_derive(row.network_genesis, row.peer_master_pubkey,
                                    row.peer_noise_pubkey, row.pairing_id) ||
            !db_mesh_pairing_insert(&db, &row)) {
            node_db_close(&db);
            return false;
        }
    }
    node_db_close(&db);
    return true;
}

static bool fd_run(const char *datadir, struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), "fleet.doctor", NULL);
    struct zcl_command_request request = {0};
    struct json_value input;
    char why[160];
    bool ok;
    zcl_command_reply_init(reply, "zcl.fleet_doctor.v1");
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", datadir);
    ok = spec && spec->handler &&
         zcl_command_registry_input_validate(spec, &input, why, sizeof(why));
    request.spec = spec;
    request.input = &input;
    if (ok)
        spec->handler(&request, reply);
    json_free(&input);
    return ok;
}

static const struct json_value *fd_check_row(const struct zcl_command_reply *r,
                                             const char *name)
{
    const struct json_value *checks = json_get(&r->data, "checks");
    for (size_t i = 0; checks && i < checks->num_children; i++)
        if (strcmp(json_get_str(json_get(&checks->children[i], "name")),
                   name) == 0)
            return &checks->children[i];
    return NULL;
}

static const char *fd_cstr(const struct json_value *o, const char *k)
{
    return json_get_str(json_get(o, k));
}

/* "z23 fleet invite --name=<box>" names the catalog path fleet.invite. */
static bool fd_next_resolves(const char *next)
{
    char path[96];
    size_t n = 0;
    if (strncmp(next, "z23 ", 4) != 0)
        return false;
    for (const char *p = next + 4; *p && *p != '-' && *p != '<' && n < 90; p++)
        path[n++] = *p == ' ' ? '.' : *p;
    while (n > 0 && path[n - 1] == '.')
        n--;
    path[n] = '\0';
    return zcl_command_registry_find(zcl_command_catalog(), path, NULL) != NULL;
}

static int test_fd_empty_datadir(void)
{
    int failures = 0;
    static const char *const order[] = { "node", "identity", "membership",
        "delegation", "transport", "pairing", "mail", "wiki" };
    TEST("fleet doctor: an empty datadir and no node is blocked at the node "
         "and names an existing command for every gap") {
        char dir[PATH_MAX];
        struct zcl_command_reply reply;
        const struct json_value *checks = NULL;
        fe_isolate("doctor-empty");
        ASSERT(fd_make_datadir("doctor-empty-dd", 0, 0, dir, sizeof(dir)));
        g_fd_node_up = false;
        node_rpc_client_set_test_hook(fd_rpc_hook);
        ASSERT(fd_run(dir, &reply));
        ASSERT_STR_EQ(fd_cstr(&reply.data, "schema"), "zcl.fleet_doctor.v1");
        ASSERT_STR_EQ(fd_cstr(&reply.data, "state"), "blocked");
        ASSERT_STR_EQ(fd_cstr(&reply.data, "next"), "z23 core status");
        checks = json_get(&reply.data, "checks");
        ASSERT(checks && checks->num_children == 8);
        for (size_t i = 0; i < 8; i++)
            ASSERT_STR_EQ(fd_cstr(&checks->children[i], "name"), order[i]);
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "node"), "state"),
                      "blocked");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "identity"), "state"),
                      "blocked");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "membership"), "state"),
                      "missing");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "membership"), "next"),
                      "z23 fleet invite --name=<box>");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "delegation"), "state"),
                      "blocked");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "transport"), "state"),
                      "blocked");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "pairing"), "state"),
                      "missing");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "mail"), "state"),
                      "unknown");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "mail"), "next"),
                      "z23-dev dev agent mail");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "wiki"), "state"),
                      "blocked");
        /* Every named command is a real catalog path (mail is z23-dev). */
        for (size_t i = 0; i < 8; i++) {
            const char *next = fd_cstr(&checks->children[i], "next");
            ASSERT(next[0] == '\0' || i == 6 || fd_next_resolves(next));
        }
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static int test_fd_transport_and_warning(void)
{
    int failures = 0;
    TEST("fleet doctor: hybrid peers are counted from the peer list, and a "
         "pairing under 24h warns while a distant one does not") {
        char soon[PATH_MAX], far[PATH_MAX];
        struct zcl_command_reply reply;
        const struct json_value *row = NULL;
        uint8_t op_seed[32], op_pub[32];
        const char *why = NULL;
        int64_t now = (int64_t)time(NULL);
        fe_isolate("doctor-up");
        fe_key(0xc1, op_seed, op_pub);
        ASSERT(fleet_enrol_operator_write(op_pub, &why));
        ASSERT(fd_make_datadir("doctor-soon", 1, now + 3600, soon,
                               sizeof(soon)));
        ASSERT(fd_make_datadir("doctor-far", 1, now + 10 * 86400, far,
                               sizeof(far)));
        g_fd_node_up = true;
        node_rpc_client_set_test_hook(fd_rpc_hook);
        ASSERT(fd_run(soon, &reply));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "connected_peers")), 5);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "hybrid_peers")), 2);
        ASSERT_STR_EQ(fd_cstr(&reply.data, "noise_fingerprint_sha3"), FD_FP);
        row = fd_check_row(&reply, "transport");
        ASSERT_STR_EQ(fd_cstr(row, "state"), "ok");
        ASSERT(strstr(fd_cstr(row, "detail"), "2 of 5") != NULL);
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "node"), "state"), "ok");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "identity"), "state"),
                      "ok");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "membership"), "state"),
                      "ok");
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "pairing"), "state"), "ok");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "wiki_pages")), 3);
        row = fd_check_row(&reply, "delegation");
        ASSERT_STR_EQ(fd_cstr(row, "state"), "ok");
        ASSERT(json_get(row, "warning") != NULL);
        ASSERT(strstr(fd_cstr(row, "warning"), "expires in") != NULL);
        /* Every product check is ok and mail is unknown but informational:
         * the node is ok overall and has nothing left to run. */
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "mail"), "state"), "unknown");
        ASSERT_STR_EQ(fd_cstr(&reply.data, "state"), "ok");
        ASSERT_STR_EQ(fd_cstr(&reply.data, "next"), "");
        ASSERT(json_get_bool(json_get(fd_check_row(&reply, "mail"),
                                      "informational")));
        zcl_command_reply_free(&reply);

        ASSERT(fd_run(far, &reply));
        ASSERT(json_get(fd_check_row(&reply, "delegation"), "warning") == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static int test_fd_bounded(void)
{
    int failures = 0;
    TEST("fleet doctor: more than 64 machines or pairings never grow the "
         "answer past 64 rows") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char name[8];
        char full[PATH_MAX], over[PATH_MAX];
        struct zcl_command_reply reply;
        uint8_t op_seed[32], op_pub[32];
        const char *why = NULL;
        int64_t now = (int64_t)time(NULL);
        fe_isolate("doctor-bound");
        fe_key(0xd1, op_seed, op_pub);
        ASSERT(fleet_enrol_operator_write(op_pub, &why));
        for (unsigned i = 0; i < 70u; i++) {
            ASSERT(snprintf(name, sizeof(name), "m%02u", i) > 0);
            ASSERT(fe_row(name, 0xd1, (uint8_t)(0x10u + i),
                          (uint16_t)(FLEET_ENROL_PORT_FIRST + i), "", row,
                          sizeof(row)));
            ASSERT(fleet_roster_append(row, &why));
        }
        ASSERT(fd_make_datadir("doctor-64", 64, now + 10 * 86400, full,
                               sizeof(full)));
        ASSERT(fd_make_datadir("doctor-65", 65, now + 10 * 86400, over,
                               sizeof(over)));
        g_fd_node_up = false;
        node_rpc_client_set_test_hook(fd_rpc_hook);
        ASSERT(fd_run(full, &reply));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "machines_total")), 70);
        ASSERT(json_get_bool(json_get(&reply.data, "machines_truncated")));
        ASSERT_EQ(json_get(&reply.data, "machines")->num_children, 64u);
        ASSERT_EQ(json_get_int(json_get(&reply.data, "pairings_total")), 64);
        ASSERT_EQ(json_get(&reply.data, "pairings")->num_children, 64u);
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "pairing"), "state"), "ok");
        zcl_command_reply_free(&reply);

        ASSERT(fd_run(over, &reply));
        ASSERT_STR_EQ(fd_cstr(fd_check_row(&reply, "pairing"), "state"),
                      "unknown");
        ASSERT_EQ(json_get(&reply.data, "pairings")->num_children, 0u);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

static int test_fd_no_secret_material(void)
{
    int failures = 0;
    TEST("fleet doctor: neither the box's fleet seed nor a private field in "
         "the node's capsule reaches the answer") {
        static char text[131072];
        char dir[PATH_MAX];
        char seed_hex[65];
        uint8_t seed[FLEET_ENROL_SEED_BYTES], pub[FLEET_ENROL_PUBKEY_BYTES];
        struct zcl_command_reply reply;
        const char *why = NULL;
        bool present = false;
        fe_isolate("doctor-secret");
        ASSERT(fleet_enrol_key_load(seed, pub, true, &present, &why));
        zcl_hex_encode(seed, sizeof(seed), seed_hex);
        ASSERT(fd_make_datadir("doctor-secret-dd", 1, (int64_t)time(NULL) + 864000, dir,
                               sizeof(dir)));
        g_fd_node_up = true;
        node_rpc_client_set_test_hook(fd_rpc_hook);
        ASSERT(fd_run(dir, &reply));
        ASSERT(json_write(&reply.data, text, sizeof(text)) > 0);
        ASSERT(strstr(text, FD_FP) != NULL);
        ASSERT(strstr(text, seed_hex) == NULL);
        ASSERT(strstr(text, FD_DECOY) == NULL);
        ASSERT(strstr(text, "private") == NULL);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}


static int test_fd_unreadable_store(void)
{
    int failures = 0;
    TEST("fleet doctor: a pairing store that is not a database is refused "
         "by name, not reported as missing") {
        char dir[PATH_MAX], path[PATH_MAX + 16];
        struct zcl_command_reply reply;
        FILE *fp = NULL;
        fe_isolate("doctor-junk");
        ASSERT(fd_make_datadir("doctor-junk-dd", 0, 0, dir, sizeof(dir)));
        ASSERT(snprintf(path, sizeof(path), "%s/node.db", dir) > 0);
        fp = fopen(path, "w");
        ASSERT(fp != NULL);
        ASSERT(fputs("this is not a sqlite database at all, just text", fp) >= 0);
        ASSERT(fclose(fp) == 0);
        g_fd_node_up = false;
        node_rpc_client_set_test_hook(fd_rpc_hook);
        ASSERT(fd_run(dir, &reply));
        ASSERT_STR_EQ(reply.error.code, "FLEET_DOCTOR_PAIRING_UNREADABLE");
        ASSERT(reply.status != ZCL_COMMAND_STATUS_PASSED);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    node_rpc_client_set_test_hook(NULL);
    return failures;
}

/* ── the fleet root as a ZID anchor (ZRC 0012 step 1) ───────────────────── */

/* A refusal that never came back is a NULL token: print it as text so the
 * assertion fails cleanly instead of crashing in strcmp. */
static const char *fe_s(const char *token)
{
    return token ? token : "(none)";
}

static const char *fe_refusal(enum fleet_anchor_state state, bool require)
{
    struct fleet_anchor_fact fact = { .state = state };
    return fe_s(fleet_root_anchor_refusal(&fact, require));
}

static struct fleet_anchor_fact fe_fact(enum fleet_anchor_state state)
{
    struct fleet_anchor_fact fact = {0};
    fact.state = state;
    return fact;
}

static int test_fe_anchor_verdicts(void)
{
    int failures = 0;
    TEST("fleet enrol: a required fleet root passes only as an ACTIVE ZID "
         "anchor; an optional one never refuses; a forged seal is refused "
         "whatever the chain says") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char forged[FLEET_ENROL_MACHINE_TEXT_MAX];
        char foreign[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t op_seed[32], op_pub[32];
        struct fleet_machine machine;
        struct fleet_anchor_fact active = fe_fact(FLEET_ANCHOR_ACTIVE);
        const char *why = NULL;
        fe_isolate("anchor-verdicts");
        fe_key(0xa1, op_seed, op_pub);
        ASSERT(fe_row("studio", 0xa1, 0xa2, FLEET_ENROL_PORT_FIRST, "", row,
                      sizeof(row)));

        /* The closed verdict table, required. */
        ASSERT(fleet_root_anchor_refusal(&active, true) == NULL);
        ASSERT_STR_EQ(fe_refusal(FLEET_ANCHOR_NOT_ANCHORED, true),
                      FLEET_ENROL_WHY_ROOT_NOT_ANCHORED);
        ASSERT_STR_EQ(fe_refusal(FLEET_ANCHOR_ROTATED, true),
                      FLEET_ENROL_WHY_ROOT_ROTATED);
        ASSERT_STR_EQ(fe_refusal(FLEET_ANCHOR_REVOKED, true),
                      FLEET_ENROL_WHY_ROOT_REVOKED);
        /* Nobody looked, or could not look: fail closed, never "fine". */
        ASSERT_STR_EQ(fe_refusal(FLEET_ANCHOR_UNCHECKED, true),
                      FLEET_ENROL_WHY_ROOT_UNVERIFIABLE);
        ASSERT_STR_EQ(fe_refusal(FLEET_ANCHOR_UNREADABLE, true),
                      FLEET_ENROL_WHY_ROOT_UNVERIFIABLE);
        ASSERT_STR_EQ(fe_s(fleet_root_anchor_refusal(NULL, true)),
                      FLEET_ENROL_WHY_ROOT_UNVERIFIABLE);
        /* Optional: every state is acceptable and only REPORTED. */
        for (int s = FLEET_ANCHOR_UNCHECKED; s <= FLEET_ANCHOR_REVOKED; s++) {
            struct fleet_anchor_fact fact = fe_fact((enum fleet_anchor_state)s);
            ASSERT(fleet_root_anchor_refusal(&fact, false) == NULL);
        }
        ASSERT_STR_EQ(fleet_anchor_state_name(FLEET_ANCHOR_NOT_ANCHORED),
                      "not_anchored");

        /* The genuine line under an active anchor verifies. */
        ASSERT(fleet_root_line_verify(row, op_pub, &active, true, &machine,
                                      &why));
        ASSERT_STR_EQ(machine.receipt.invite.name, "studio");

        /* Forged member: one byte changed, and a line another operator
         * sealed. The chain says ACTIVE for the root and it does not help. */
        ASSERT(fe_tamper(row, fe_wire_len(row) / 2, forged, sizeof(forged)));
        ASSERT(!fleet_root_line_verify(forged, op_pub, &active, true,
                                       &machine, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROSTER_SIGNATURE);
        ASSERT(fe_row("studio", 0xb1, 0xa2, FLEET_ENROL_PORT_FIRST, "",
                      foreign, sizeof(foreign)));
        ASSERT(!fleet_root_line_verify(foreign, op_pub, &active, true,
                                       &machine, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROSTER_SIGNATURE);
        ASSERT(!fleet_root_line_verify(forged, op_pub, &active, false,
                                       &machine, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROSTER_SIGNATURE);

        /* Genuine seal, anchor not active: refused by the anchor's name when
         * required, accepted (and reportable) when not. */
        struct fleet_anchor_fact none = fe_fact(FLEET_ANCHOR_NOT_ANCHORED);
        struct fleet_anchor_fact revoked = fe_fact(FLEET_ANCHOR_REVOKED);
        ASSERT(!fleet_root_line_verify(row, op_pub, &none, true, &machine,
                                       &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROOT_NOT_ANCHORED);
        ASSERT_STR_EQ(machine.receipt.invite.name, "studio"); /* named */
        ASSERT(!fleet_root_line_verify(row, op_pub, &revoked, true, &machine,
                                       &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROOT_REVOKED);
        ASSERT(fleet_root_line_verify(row, op_pub, &none, false, &machine,
                                      &why));
        ASSERT(why == NULL);
        PASS();
    } _test_next:;
    return failures;
}

/* A fixture datadir holding a real node.db; `tag` names it. */
static bool fe_datadir(char *dir, size_t cap, const char *tag)
{
    char path[PATH_MAX + 16];
    struct node_db ndb;
    test_make_tmpdir(dir, cap, "fleet_enrol", tag);
    (void)snprintf(path, sizeof(path), "%s/node.db", dir);
    if (!node_db_open(&ndb, path))
        return false;
    node_db_close(&ndb);
    return true;
}

/* One zid_identities row for `key`, through the model's own save. */
static bool fe_anchor_row(const char *dir, const uint8_t key[32],
                          const char *status, const uint8_t *successor)
{
    char path[PATH_MAX + 16];
    struct node_db ndb;
    struct zid_identity row = {0};
    bool ok = false;
    memcpy(row.master_pubkey, key, 32);
    memset(row.anchor_txid, 0x5a, sizeof(row.anchor_txid));
    row.anchor_height = 1000;
    row.updated_height = 1000;
    (void)snprintf(row.status, sizeof(row.status), "%s", status);
    (void)snprintf(row.source, sizeof(row.source), "%s",
                   ZID_IDENTITY_SOURCE_ZID_OVERLAY);
    if (successor) {
        memcpy(row.successor_pubkey, successor, 32);
        row.has_successor = true;
    }
    (void)snprintf(path, sizeof(path), "%s/node.db", dir);
    if (!node_db_open(&ndb, path))
        return false;
    ok = db_zid_identity_save(&ndb, &row);
    node_db_close(&ndb);
    return ok;
}

/* The shipped leaf, by path: the catalog validator, then the handler. */
static bool fe_leaf_call(const char *path, const char *schema,
                         const char *body, struct zcl_command_reply *reply)
{
    const struct zcl_command_spec *spec = zcl_command_registry_find(
        zcl_command_catalog(), path, NULL);
    struct zcl_command_request request = {0};
    struct json_value input;
    char why[128];
    zcl_command_reply_init(reply, schema);
    json_init(&input);
    why[0] = '\0';
    if (!spec || !spec->handler ||
        !json_read(&input, body, strlen(body)) ||
        !zcl_command_registry_input_validate(spec, &input, why,
                                             sizeof(why))) {
        json_free(&input);
        zcl_command_reply_free(reply);
        return false;
    }
    request.spec = spec;
    request.input = &input;
    spec->handler(&request, reply);
    json_free(&input);
    return true;
}

static const char *fe_anchor_state(const struct zcl_command_reply *reply)
{
    return json_get_str(json_get(json_get(&reply->data, "operator_anchor"),
                                 "state"));
}

/* This box's own fleet key, created under the isolated state root. It is the
 * operator on a manager, and the very pubkey `fleet invite` would print. */
static bool fe_manager_key(uint8_t seed[32], uint8_t pub[32])
{
    bool present = false;
    const char *why = NULL;
    return fleet_enrol_key_load(seed, pub, true, &present, &why) && present;
}

/* A receipt `box_byte`'s box signs against an invite the key (seed, pub)
 * minted at `now`: the join half of the ceremony. */
/* When set, the next receipts name this board signing key. */
static const struct fleet_signing_key *g_fe_signer;

static bool fe_receipt_for(const char *name, uint8_t box_byte,
                           const uint8_t seed[32], const uint8_t pub[32],
                           int64_t now, char *receipt, size_t cap)
{
    uint8_t box_seed[32], box_pub[32];
    uint8_t iw[FLEET_ENROL_INVITE_WIRE_MAX];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    struct fleet_invite invite;
    struct fleet_box_facts facts = fe_facts();
    size_t il = 0;
    const char *why = NULL;
    fe_key(box_byte, box_seed, box_pub);
    return fleet_invite_mint(name, FE_TTL, "", seed, pub, now, token,
                             sizeof(token), &invite, &why) &&
           fleet_invite_parse(token, &invite, iw, sizeof(iw), &il, &why) &&
           fleet_receipt_mint(iw, il, FE_ONION, &facts, "", box_seed, box_pub,
                              g_fe_signer, receipt, cap, &why);
}

/* One sealed roster line for the manager (seed, pub). */
static bool fe_manager_row(const char *name, uint8_t box_byte,
                           const uint8_t seed[32], const uint8_t pub[32],
                           uint16_t port, char *row, size_t cap)
{
    uint8_t rw[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    struct fleet_receipt parsed;
    size_t rl = 0;
    const char *why = NULL;
    return fe_receipt_for(name, box_byte, seed, pub, FE_NOW, receipt,
                          sizeof(receipt)) &&
           fleet_receipt_parse(receipt, &parsed, rw, sizeof(rw), &rl, &why) &&
           fleet_machine_mint(rw, rl, FE_NOW, port, seed, pub, row, cap,
                              &why);
}

/* Import `name` (a fresh box) through the shipped leaf, with no requirement,
 * against the datadir `dd`; the reply is left for the caller. */
static bool fe_import_plain(const char *name, uint8_t box_byte,
                            const uint8_t seed[32], const uint8_t pub[32],
                            const char *dd, struct zcl_command_reply *reply)
{
    char row[FLEET_ENROL_MACHINE_TEXT_MAX];
    char body[PATH_MAX + FLEET_ENROL_MACHINE_TEXT_MAX + 64];
    if (!fe_manager_row(name, box_byte, seed, pub,
                        (uint16_t)(FLEET_ENROL_PORT_FIRST + (box_byte & 0x0f)), row,
                        sizeof(row)))
        return false;
    (void)snprintf(body, sizeof(body), "{\"line\":\"%s\",\"datadir\":\"%s\"}",
                   row, dd);
    return fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body, reply);
}

static int test_fe_anchor_reported_not_enforced(void)
{
    int failures = 0;
    TEST("fleet enrol: an enrolment made before the operator anchored its key "
         "still lists and imports, and its anchor state is reported, not "
         "rejected") {
        char dd_none[PATH_MAX], dd_wrong[PATH_MAX], dd_dead[PATH_MAX];
        char empty[PATH_MAX], row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char body[PATH_MAX + 64];
        uint8_t seed[32], pub[32], s1[32], stranger[32];
        struct zcl_command_reply reply;
        struct fleet_roster_scan scan = {0};
        const struct json_value *rows = NULL;
        const char *why = NULL;
        fe_isolate("anchor-reported");
        ASSERT(fe_manager_key(seed, pub));
        fe_key(0x56, s1, stranger);
        ASSERT(fe_manager_row("studio", 0x57, seed, pub,
                              FLEET_ENROL_PORT_FIRST, row, sizeof(row)));
        ASSERT(fleet_roster_append(row, &why));

        /* The read leaf with nobody looking: the unanchored fleet lists and
         * the state is "unchecked", not a refusal. */
        ASSERT(fe_leaf_call("fleet.machines", "zcl.fleet.machines.v1", "{}",
                            &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "unchecked");
        ASSERT_EQ(json_get_int(json_get(&reply.data, "total")), 1);
        rows = json_get(&reply.data, "machines");
        ASSERT(rows != NULL && json_at(rows, 0) != NULL);
        ASSERT_STR_EQ(json_get_str(json_get(json_get(json_at(rows, 0),
                                                     "verified"), "name")),
                      "studio");
        zcl_command_reply_free(&reply);

        /* A datadir whose chain has no row for the operator: the line is
         * still imported and the state is NOT_ANCHORED. */
        ASSERT(fe_datadir(dd_none, sizeof(dd_none), "anchor-none"));
        ASSERT(fe_import_plain("annex", 0x58, seed, pub, dd_none, &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "not_anchored");
        zcl_command_reply_free(&reply);

        /* The WRONG anchor: a row exists, but for some other key. */
        ASSERT(fe_datadir(dd_wrong, sizeof(dd_wrong), "anchor-wrong"));
        ASSERT(fe_anchor_row(dd_wrong, stranger, "active", NULL));
        ASSERT(fe_import_plain("depot", 0x59, seed, pub, dd_wrong, &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "not_anchored");
        zcl_command_reply_free(&reply);

        /* Revoked: still imported, and the reply says it is revoked. */
        ASSERT(fe_datadir(dd_dead, sizeof(dd_dead), "anchor-dead"));
        ASSERT(fe_anchor_row(dd_dead, pub, "revoked", NULL));
        ASSERT(fe_import_plain("yard", 0x5a, seed, pub, dd_dead, &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "revoked");
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&reply.data,
                                                     "operator_anchor"),
                                            "would_refuse_as")),
                      FLEET_ENROL_WHY_ROOT_REVOKED);
        zcl_command_reply_free(&reply);
        ASSERT(fleet_roster_scan(pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 4u);

        /* A datadir with no node.db reads UNCHECKED and the read-only open
         * does not create one. */
        test_make_tmpdir(empty, sizeof(empty), "fleet_enrol", "anchor-empty");
        ASSERT(fe_import_plain("quay", 0x5b, seed, pub, empty, &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "unchecked");
        zcl_command_reply_free(&reply);
        (void)snprintf(body, sizeof(body), "%s/node.db", empty);
        ASSERT(access(body, F_OK) != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* One admit call: a fresh receipt for `name`, against datadir `dd`, with
 * `require` as the raw string (NULL leaves the key off). */
static bool fe_admit_with(const char *name, uint8_t box_byte,
                          const uint8_t seed[32], const uint8_t pub[32],
                          const char *dd, const char *require,
                          struct zcl_command_reply *reply)
{
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    char body[PATH_MAX + FLEET_ENROL_MACHINE_TEXT_MAX + 160];
    int n;
    if (!fe_receipt_for(name, box_byte, seed, pub, (int64_t)time(NULL),
                        receipt, sizeof(receipt)))
        return false;
    n = snprintf(body, sizeof(body),
                 "{\"receipt\":\"%s\",\"bridge\":\"no\",\"datadir\":\"%s\"",
                 receipt, dd);
    if (require)
        n += snprintf(body + n, sizeof(body) - (size_t)n,
                      ",\"require_anchor\":\"%s\"", require);
    (void)snprintf(body + n, sizeof(body) - (size_t)n, "}");
    return fe_leaf_call("fleet.admit", "zcl.fleet.admit.v1", body, reply);
}

static int test_fe_anchor_require_spelling(void)
{
    int failures = 0;
    TEST("fleet admit/import: any require_anchor value but no/false/0 "
         "requires the anchor, so a typo fails closed; no/false/0 do not") {
        static const char *const on[3] = { "yse", "true", "1" };
        static const char *const off[3] = { "no", "false", "0" };
        char dd[PATH_MAX], row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char body[PATH_MAX + FLEET_ENROL_MACHINE_TEXT_MAX + 160];
        char name[16];
        uint8_t seed[32], pub[32];
        struct zcl_command_reply reply;
        struct fleet_roster_scan scan = {0};
        const char *why = NULL;
        fe_isolate("require-spelling");
        ASSERT(fe_manager_key(seed, pub));
        ASSERT(fe_datadir(dd, sizeof(dd), "require-spelling-dd")); /* none */
        for (int i = 0; i < 3; i++) {
            (void)snprintf(name, sizeof(name), "on%d", i);
            ASSERT(fe_admit_with(name, (uint8_t)(0x80 + i), seed, pub, dd,
                                 on[i], &reply));
            ASSERT_STR_EQ(reply.error.evidence,
                          FLEET_ENROL_WHY_ROOT_NOT_ANCHORED);
            zcl_command_reply_free(&reply);
            ASSERT(fe_manager_row(name, (uint8_t)(0x90 + i), seed, pub,
                                  (uint16_t)(FLEET_ENROL_PORT_FIRST + 20 + i),
                                  row, sizeof(row)));
            (void)snprintf(body, sizeof(body),
                           "{\"line\":\"%s\",\"datadir\":\"%s\","
                           "\"require_anchor\":\"%s\"}", row, dd, on[i]);
            ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body,
                                &reply));
            ASSERT_STR_EQ(reply.error.evidence,
                          FLEET_ENROL_WHY_ROOT_NOT_ANCHORED);
            zcl_command_reply_free(&reply);
        }
        ASSERT(fleet_roster_scan(pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 0u);
        for (int i = 0; i < 3; i++) {
            (void)snprintf(name, sizeof(name), "off%d", i);
            ASSERT(fe_admit_with(name, (uint8_t)(0xa0 + i), seed, pub, dd,
                                 off[i], &reply));
            ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
            ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "not_anchored");
            zcl_command_reply_free(&reply);
            (void)snprintf(name, sizeof(name), "imp%d", i);
            ASSERT(fe_manager_row(name, (uint8_t)(0xb0 + i), seed, pub,
                                  (uint16_t)(FLEET_ENROL_PORT_FIRST + 30 + i),
                                  row, sizeof(row)));
            (void)snprintf(body, sizeof(body),
                           "{\"line\":\"%s\",\"datadir\":\"%s\","
                           "\"require_anchor\":\"%s\"}", row, dd, off[i]);
            ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body,
                                &reply));
            ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
            zcl_command_reply_free(&reply);
        }
        ASSERT(fleet_roster_scan(pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 6u);
        PASS();
    } _test_next:;
    return failures;
}

/* Overwrite the status of every zid_identities row with `status` using raw
 * SQL: the model refuses an unknown literal, so only the file can hold one. */
static bool fe_poison_status(const char *dd, const char *status)
{
    char path[PATH_MAX + 16], sql[96];
    sqlite3 *db = NULL;
    bool ok;
    (void)snprintf(path, sizeof(path), "%s/node.db", dd);
    (void)snprintf(sql, sizeof(sql), "UPDATE zid_identities SET status='%s'",
                   status);
    if (sqlite3_open(path, &db) != SQLITE_OK)
        return false;
    ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

static int test_fe_anchor_unreadable_fails_closed(void)
{
    int failures = 0;
    TEST("fleet admit --require_anchor: a corrupt node.db and an unknown "
         "status both read UNREADABLE and refuse as unverifiable") {
        char bad[PATH_MAX], odd[PATH_MAX], path[PATH_MAX + 16];
        uint8_t seed[32], pub[32];
        struct zcl_command_reply reply;
        struct fleet_roster_scan scan = {0};
        const char *why = NULL;
        FILE *fp = NULL;
        fe_isolate("anchor-unreadable");
        ASSERT(fe_manager_key(seed, pub));

        /* Garbage bytes where node.db should be. */
        test_make_tmpdir(bad, sizeof(bad), "fleet_enrol", "anchor-garbage");
        (void)snprintf(path, sizeof(path), "%s/node.db", bad);
        fp = fopen(path, "wb");
        ASSERT(fp != NULL);
        for (int i = 0; i < 512; i++)
            (void)fputc(0xA5 ^ i, fp);
        (void)fclose(fp);
        ASSERT(fe_admit_with("studio", 0xc1, seed, pub, bad, "yes", &reply));
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_ROOT_UNVERIFIABLE);
        zcl_command_reply_free(&reply);
        /* Without the flag it is reported, and the admission goes ahead. */
        ASSERT(fe_admit_with("annex", 0xc2, seed, pub, bad, NULL, &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "unreadable");
        zcl_command_reply_free(&reply);

        /* A row whose status this build does not know. */
        ASSERT(fe_datadir(odd, sizeof(odd), "anchor-odd-status"));
        ASSERT(fe_anchor_row(odd, pub, "active", NULL));
        ASSERT(fe_poison_status(odd, "frozen"));
        ASSERT(fe_admit_with("depot", 0xc3, seed, pub, odd, "yes", &reply));
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_ROOT_UNVERIFIABLE);
        zcl_command_reply_free(&reply);
        ASSERT(fleet_roster_scan(pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 1u); /* only the unrequired admission */
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_anchor_rotation_and_invite(void)
{
    int failures = 0;
    TEST("fleet import reports a rotation's successor and height exactly; "
         "fleet invite reports an active anchor") {
        char dd[PATH_MAX], hex[65], body[PATH_MAX + 96];
        uint8_t seed[32], pub[32], s1[32], successor[32];
        struct zcl_command_reply reply;
        const struct json_value *anchor = NULL;
        fe_isolate("anchor-rotation");
        ASSERT(fe_manager_key(seed, pub));
        fe_key(0x5c, s1, successor);
        for (int i = 0; i < 32; i++)
            (void)snprintf(hex + 2 * i, 3, "%02x", successor[i]);
        ASSERT(fe_datadir(dd, sizeof(dd), "anchor-rotation-dd"));
        ASSERT(fe_anchor_row(dd, pub, "rotated", successor));
        ASSERT(fe_import_plain("annex", 0x5d, seed, pub, dd, &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        anchor = json_get(&reply.data, "operator_anchor");
        ASSERT(anchor != NULL);
        ASSERT_STR_EQ(fe_s(json_get_str(json_get(anchor, "state"))),
                      "rotated");
        ASSERT_STR_EQ(fe_s(json_get_str(json_get(anchor, "successor"))), hex);
        ASSERT_EQ(json_get_int(json_get(anchor, "anchor_height")), 1000);
        ASSERT_STR_EQ(fe_s(json_get_str(json_get(anchor, "would_refuse_as"))),
                      FLEET_ENROL_WHY_ROOT_ROTATED);
        zcl_command_reply_free(&reply);

        /* invite is report-only; flip the same key to active. */
        ASSERT(fe_anchor_row(dd, pub, "active", NULL));
        (void)snprintf(body, sizeof(body),
                       "{\"name\":\"studio\",\"datadir\":\"%s\"}", dd);
        ASSERT(fe_leaf_call("fleet.invite", "zcl.fleet.invite.v1", body,
                            &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "active");
        ASSERT_EQ(json_get_int(json_get(json_get(&reply.data,
                                                 "operator_anchor"),
                                        "anchor_height")), 1000);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_admit_requires_anchor(void)
{
    int failures = 0;
    TEST("fleet admit --require_anchor: a missing, wrong, rotated or revoked "
         "anchor refuses before anything is spent; an active one admits; "
         "without the flag an unanchored manager still admits") {
        char dd[PATH_MAX], receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
        char body[PATH_MAX + FLEET_ENROL_MACHINE_TEXT_MAX + 128];
        uint8_t seed[32], pub[32], s1[32], stranger[32], nonce_probe[16];
        struct zcl_command_reply reply;
        struct fleet_receipt parsed;
        struct fleet_roster_scan scan = {0};
        uint8_t rw[FLEET_ENROL_RECEIPT_WIRE_MAX];
        size_t rl = 0;
        bool seen = true;
        const char *why = NULL;
        fe_isolate("admit-anchor");
        ASSERT(fe_manager_key(seed, pub));
        fe_key(0x61, s1, stranger);
        ASSERT(fe_datadir(dd, sizeof(dd), "admit-anchor-dd"));
        ASSERT(fe_receipt_for("studio", 0x62, seed, pub,
                              (int64_t)time(NULL), receipt, sizeof(receipt)));
        ASSERT(fleet_receipt_parse(receipt, &parsed, rw, sizeof(rw), &rl,
                                   &why));
        memcpy(nonce_probe, parsed.invite.nonce, sizeof(nonce_probe));
        (void)snprintf(body, sizeof(body),
                       "{\"receipt\":\"%s\",\"bridge\":\"no\","
                       "\"datadir\":\"%s\",\"require_anchor\":\"yes\"}",
                       receipt, dd);

        /* Missing anchor (empty projection). */
        ASSERT(fe_leaf_call("fleet.admit", "zcl.fleet.admit.v1", body,
                            &reply));
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "FLEET_ROOT_NOT_ANCHORED");
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_ROOT_NOT_ANCHORED);
        zcl_command_reply_free(&reply);

        /* Wrong anchor: another key is anchored, the operator's is not. */
        ASSERT(fe_anchor_row(dd, stranger, "active", NULL));
        ASSERT(fe_leaf_call("fleet.admit", "zcl.fleet.admit.v1", body,
                            &reply));
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_ROOT_NOT_ANCHORED);
        zcl_command_reply_free(&reply);

        /* Revoked, then rotated. */
        ASSERT(fe_anchor_row(dd, pub, "revoked", NULL));
        ASSERT(fe_leaf_call("fleet.admit", "zcl.fleet.admit.v1", body,
                            &reply));
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_ROOT_REVOKED);
        zcl_command_reply_free(&reply);
        ASSERT(fe_anchor_row(dd, pub, "rotated", stranger));
        ASSERT(fe_leaf_call("fleet.admit", "zcl.fleet.admit.v1", body,
                            &reply));
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_ROOT_ROTATED);
        zcl_command_reply_free(&reply);

        /* Four refusals later nothing was enrolled and the invite is
         * unspent. */
        ASSERT(fleet_roster_scan(pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 0u);
        ASSERT(fleet_nonce_seen(nonce_probe, &seen, &why));
        ASSERT(!seen);

        /* Compatibility: the same receipt without the flag admits under a
         * rotated anchor and REPORTS its state. */
        (void)snprintf(body, sizeof(body),
                       "{\"receipt\":\"%s\",\"bridge\":\"no\","
                       "\"datadir\":\"%s\"}", receipt, dd);
        ASSERT(fe_leaf_call("fleet.admit", "zcl.fleet.admit.v1", body,
                            &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "rotated");
        zcl_command_reply_free(&reply);
        ASSERT(fleet_roster_scan(pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);

        /* Active anchor + the flag: a second box is admitted. */
        ASSERT(fe_anchor_row(dd, pub, "active", NULL));
        ASSERT(fe_receipt_for("annex", 0x63, seed, pub, (int64_t)time(NULL),
                              receipt, sizeof(receipt)));
        (void)snprintf(body, sizeof(body),
                       "{\"receipt\":\"%s\",\"bridge\":\"no\","
                       "\"datadir\":\"%s\",\"require_anchor\":\"yes\"}",
                       receipt, dd);
        ASSERT(fe_leaf_call("fleet.admit", "zcl.fleet.admit.v1", body,
                            &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "active");
        ASSERT(json_get_bool(json_get(json_get(&reply.data,
                                               "operator_anchor"),
                                      "required")));
        zcl_command_reply_free(&reply);
        ASSERT(fleet_roster_scan(pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 2u);

        /* A required anchor with nobody looking fails closed. */
        ASSERT(fe_receipt_for("depot", 0x64, seed, pub, (int64_t)time(NULL),
                              receipt, sizeof(receipt)));
        (void)snprintf(body, sizeof(body),
                       "{\"receipt\":\"%s\",\"bridge\":\"no\","
                       "\"require_anchor\":\"yes\"}", receipt);
        ASSERT(fe_leaf_call("fleet.admit", "zcl.fleet.admit.v1", body,
                            &reply));
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_ROOT_UNVERIFIABLE);
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_import_requires_anchor(void)
{
    int failures = 0;
    TEST("fleet import --require_anchor: a line the operator sealed is "
         "refused unless the operator is an active anchor; a forged line is "
         "refused as unsealed whatever the chain says") {
        char dd[PATH_MAX], row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char forged[FLEET_ENROL_MACHINE_TEXT_MAX];
        char body[PATH_MAX + FLEET_ENROL_MACHINE_TEXT_MAX + 128];
        uint8_t seed[32], pub[32];
        struct zcl_command_reply reply;
        struct fleet_roster_scan scan = {0};
        const char *why = NULL;
        fe_isolate("import-anchor");
        ASSERT(fe_manager_key(seed, pub));
        ASSERT(fe_datadir(dd, sizeof(dd), "import-anchor-dd"));
        ASSERT(fe_manager_row("studio", 0x72, seed, pub,
                              FLEET_ENROL_PORT_FIRST, row, sizeof(row)));
        ASSERT(fe_tamper(row, fe_wire_len(row) / 2, forged, sizeof(forged)));

        /* Genuine seal, operator not anchored: refused by the anchor's name
         * and the roster is untouched. */
        (void)snprintf(body, sizeof(body),
                       "{\"line\":\"%s\",\"datadir\":\"%s\","
                       "\"require_anchor\":\"yes\"}", row, dd);
        ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body,
                            &reply));
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_ROOT_NOT_ANCHORED);
        zcl_command_reply_free(&reply);
        ASSERT(fleet_roster_scan(pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 0u);

        /* Forged member under an ACTIVE anchor: still refused as unsealed. */
        ASSERT(fe_anchor_row(dd, pub, "active", NULL));
        (void)snprintf(body, sizeof(body),
                       "{\"line\":\"%s\",\"datadir\":\"%s\","
                       "\"require_anchor\":\"yes\"}", forged, dd);
        ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body,
                            &reply));
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_ROSTER_LINE_UNSEALED);
        zcl_command_reply_free(&reply);
        ASSERT(fleet_roster_scan(pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 0u);

        /* Genuine seal + active anchor: imported, state reported. */
        (void)snprintf(body, sizeof(body),
                       "{\"line\":\"%s\",\"datadir\":\"%s\","
                       "\"require_anchor\":\"yes\"}", row, dd);
        ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body,
                            &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(fe_s(fe_anchor_state(&reply)), "active");
        zcl_command_reply_free(&reply);
        ASSERT(fleet_roster_scan(pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the roster seam's production provider (ZRC 0012 step 2) ────────────── */

/* A sealed line whose receipt names a board signing key. */
static bool fe_signer_row(uint8_t op_byte, uint8_t signer_byte,
                          const char *name, char *out, size_t cap)
{
    uint8_t op_seed[32], op_pub[32], box_seed[32], box_pub[32];
    uint8_t invite_wire[FLEET_ENROL_INVITE_WIRE_MAX];
    uint8_t receipt_wire[FLEET_ENROL_RECEIPT_WIRE_MAX];
    char token[FLEET_ENROL_MACHINE_TEXT_MAX];
    char receipt[FLEET_ENROL_MACHINE_TEXT_MAX];
    struct fleet_invite invite;
    struct fleet_receipt parsed;
    struct fleet_box_facts facts = fe_facts();
    struct fleet_signing_key signer;
    size_t invite_len = 0, receipt_len = 0;
    const char *why = NULL;
    fe_key(op_byte, op_seed, op_pub);
    fe_key(0x62, box_seed, box_pub);
    fe_key(signer_byte, signer.seed, signer.pubkey);
    return fleet_invite_mint(name, FE_TTL, "", op_seed, op_pub, FE_NOW, token,
                             sizeof(token), &invite, &why) &&
           fleet_invite_parse(token, &invite, invite_wire, sizeof(invite_wire),
                              &invite_len, &why) &&
           fleet_receipt_mint(invite_wire, invite_len, FE_ONION, &facts, "",
                              box_seed, box_pub, &signer, receipt,
                              sizeof(receipt), &why) &&
           fleet_receipt_parse(receipt, &parsed, receipt_wire,
                               sizeof(receipt_wire), &receipt_len, &why) &&
           fleet_machine_mint(receipt_wire, receipt_len, FE_NOW,
                              FLEET_ENROL_PORT_FIRST, op_seed, op_pub, out,
                              cap, &why);
}

struct fe_lines {
    size_t n;
    char first[FLEET_ENROL_MACHINE_TEXT_MAX];
};

static void fe_lines_visit(const char *line, void *user)
{
    struct fe_lines *l = user;
    if (l->n++ == 0)
        (void)snprintf(l->first, sizeof(l->first), "%s", line);
}

static int test_fe_roster_gate_provider(void)
{
    int failures = 0;
    TEST("fleet roster gate: the provider names the root this box trusts, "
         "verifies a line only if the root sealed it, and obeys the root's "
         "chain state") {
        const struct zcl_fleet_roster_provider *p =
            zcl_fleet_roster_gate_provider();
        uint8_t op_seed[32], op_pub[32], got[32], signer_pub[32], sign_seed[32];
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char foreign[FLEET_ENROL_MACHINE_TEXT_MAX];
        char forged[FLEET_ENROL_MACHINE_TEXT_MAX];
        uint8_t signer[32], box[32], box_seed[32], box_pub[32];
        bool present = true, manager = true, sealed = false;
        const char *why = NULL;
        struct fe_lines lines = {0};
        fe_isolate("roster-gate");
        fe_key(0xa1, op_seed, op_pub);
        fe_key(0xc3, sign_seed, signer_pub);
        ASSERT(p && p->root && p->verify && p->each_line);

        /* A virgin box trusts no root: a state, not an error. */
        ASSERT(p->root(got, &present, &manager, p->ctx));
        ASSERT(!present && !manager);

        /* A box that joined a fleet trusts the key it was handed, and is
         * not the manager. */
        ASSERT(fleet_enrol_operator_write(op_pub, &why));
        ASSERT(p->root(got, &present, &manager, p->ctx));
        ASSERT(present && !manager);
        ASSERT(memcmp(got, op_pub, 32) == 0);

        ASSERT(fe_signer_row(0xa1, 0xc3, "studio", row, sizeof(row)));
        ASSERT(fe_signer_row(0xb1, 0xc3, "studio", foreign, sizeof(foreign)));
        ASSERT(fe_tamper(row, fe_wire_len(row) / 2, forged, sizeof(forged)));

        /* Sealed by the root, root active: verifies, and names the board
         * signing key the receipt carries. */
        ASSERT(p->verify(row, op_pub, ZCL_FLEET_ROOT_ACTIVE, true, signer, box,
                         &sealed, &why, p->ctx));
        ASSERT(sealed && memcmp(signer, signer_pub, 32) == 0);
        /* ...and the box key the operator admitted, which a roster head
         * revokes. */
        fe_key(0x62, box_seed, box_pub);
        ASSERT(memcmp(box, box_pub, 32) == 0);
        /* Sealed by any other key, or edited by one byte: not a roster row,
         * whatever the chain says about the root. */
        ASSERT(!p->verify(foreign, op_pub, ZCL_FLEET_ROOT_ACTIVE, true, signer, box,
                          &sealed, &why, p->ctx));
        ASSERT(!sealed);
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROSTER_SIGNATURE);
        ASSERT(!p->verify(forged, op_pub, ZCL_FLEET_ROOT_ACTIVE, true, signer, box,
                          &sealed, &why, p->ctx));
        ASSERT(!sealed);
        /* Genuine seal, root rotated or revoked, anchor required: refused by
         * the chain's name, and still known to be genuinely sealed. */
        ASSERT(!p->verify(row, op_pub, ZCL_FLEET_ROOT_REVOKED, true, signer, box,
                          &sealed, &why, p->ctx));
        ASSERT(sealed);
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROOT_REVOKED);
        ASSERT(!p->verify(row, op_pub, ZCL_FLEET_ROOT_ROTATED, true, signer, box,
                          &sealed, &why, p->ctx));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROOT_ROTATED);
        ASSERT(!p->verify(row, op_pub, ZCL_FLEET_ROOT_UNREADABLE, true, signer, box,
                          &sealed, &why, p->ctx));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROOT_UNVERIFIABLE);
        /* Not required: a never-anchored root still verifies. */
        ASSERT(p->verify(row, op_pub, ZCL_FLEET_ROOT_NOT_ANCHORED, false,
                         signer, box, &sealed, &why, p->ctx));

        /* The provider reads this box's own roster file, line by line. */
        ASSERT(fleet_roster_append(row, &why));
        ASSERT(p->each_line(fe_lines_visit, &lines, p->ctx));
        ASSERT_EQ(lines.n, (size_t)1);
        ASSERT_STR_EQ(lines.first, row);

        /* The manager is the box whose own key IS the root. */
        fe_isolate("roster-gate-manager");
        ASSERT(fleet_enrol_key_load(op_seed, op_pub, true, &present, &why));
        ASSERT(p->root(got, &present, &manager, p->ctx));
        ASSERT(present && manager);
        ASSERT(memcmp(got, op_pub, 32) == 0);
        /* A manager that also joined its own fleet is still the manager; a
         * box that joined someone else's, with a key of its own, is not. */
        ASSERT(fleet_enrol_operator_write(op_pub, &why));
        ASSERT(p->root(got, &present, &manager, p->ctx));
        ASSERT(present && manager);
        fe_key(0xb7, op_seed, signer_pub);
        ASSERT(fleet_enrol_operator_write(signer_pub, &why));
        ASSERT(p->root(got, &present, &manager, p->ctx));
        ASSERT(present && !manager);
        ASSERT(memcmp(got, signer_pub, 32) == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* ── the roster head: revocation, sequence, operator pin ───────────────── */

/* One sealed head under `op_byte`, revoking the boxes keyed by `box_bytes`. */
static bool fe_head_line(uint8_t op_byte, uint64_t seq, const uint8_t *box_bytes,
                         size_t n, char *out, size_t cap)
{
    uint8_t op_seed[32], op_pub[32], seed[32];
    uint8_t keys[FLEET_ENROL_HEAD_REVOKED_MAX][32];
    const char *why = NULL;
    fe_key(op_byte, op_seed, op_pub);
    for (size_t i = 0; i < n; ++i)
        fe_key(box_bytes[i], seed, keys[i]);
    return fleet_head_mint(seq, FE_NOW, &keys[0][0], n, op_seed, op_pub, out,
                           cap, &why);
}

/* Write raw bytes over one state leaf, the way a disk fault or a hand edit
 * would. */
static bool fe_put_leaf(const char *leaf, const char *text)
{
    char path[PATH_MAX];
    FILE *f;
    if (!fleet_enrol_state_path(leaf, path, sizeof(path)))
        return false;
    f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(text, 1, strlen(text), f) == strlen(text);
    return fclose(f) == 0 && ok;
}

static int test_fe_head_codec(void)
{
    int failures = 0;
    TEST("fleet head: the sealed set is canonical (sorted, unique), a "
         "256-key head round-trips, and a forged, truncated or non-head "
         "line is refused") {
        static char text[FLEET_ENROL_HEAD_TEXT_MAX];
        static char forged[FLEET_ENROL_HEAD_TEXT_MAX];
        static struct fleet_head head;
        uint8_t op_seed[32], op_pub[32], seed[32], k1[32], k2[32], k3[32];
        uint8_t keys[FLEET_ENROL_HEAD_REVOKED_MAX + 1][32];
        const char *why = NULL;
        fe_key(0x81, op_seed, op_pub);
        fe_key(0x31, seed, k1);
        fe_key(0x32, seed, k2);
        fe_key(0x33, seed, k3);
        uint8_t shuffled[4][32];
        memcpy(shuffled[0], k3, 32);
        memcpy(shuffled[1], k1, 32);
        memcpy(shuffled[2], k3, 32); /* a duplicate */
        memcpy(shuffled[3], k2, 32);
        ASSERT(fleet_head_mint(7, FE_NOW, &shuffled[0][0], 4, op_seed, op_pub,
                               text, sizeof(text), &why));
        ASSERT(fleet_head_is_line(text));
        ASSERT(fleet_head_parse(text, &head, &why));
        ASSERT_EQ(head.seq, (uint64_t)7);
        ASSERT_EQ(head.n_revoked, 3u);
        ASSERT(memcmp(head.revoked[0], head.revoked[1], 32) < 0);
        ASSERT(memcmp(head.revoked[1], head.revoked[2], 32) < 0);
        ASSERT(fleet_head_revokes(&head, k1) && fleet_head_revokes(&head, k2) &&
               fleet_head_revokes(&head, k3));
        ASSERT(!fleet_head_revokes(&head, op_pub));

        /* The size the format promises: 256 keys, and not 257. */
        for (int i = 0; i < FLEET_ENROL_HEAD_REVOKED_MAX + 1; ++i) {
            memset(keys[i], 0, 32);
            keys[i][0] = (uint8_t)(i >> 8);
            keys[i][1] = (uint8_t)i;
            keys[i][31] = 1;
        }
        ASSERT(fleet_head_mint(1, FE_NOW, &keys[0][0],
                               FLEET_ENROL_HEAD_REVOKED_MAX, op_seed, op_pub,
                               text, sizeof(text), &why));
        ASSERT(fleet_head_parse(text, &head, &why));
        ASSERT_EQ(head.n_revoked, (uint32_t)FLEET_ENROL_HEAD_REVOKED_MAX);
        ASSERT(!fleet_head_mint(1, FE_NOW, &keys[0][0],
                                FLEET_ENROL_HEAD_REVOKED_MAX + 1, op_seed,
                                op_pub, text, sizeof(text), &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_INVALID);
        ASSERT(!fleet_head_mint(0, FE_NOW, NULL, 0, op_seed, op_pub, text,
                                sizeof(text), &why));

        /* A flipped bit is no longer sealed; a machine row is no head. */
        ASSERT(fleet_head_mint(2, FE_NOW, &keys[0][0], 3, op_seed, op_pub,
                               text, sizeof(text), &why));
        (void)snprintf(forged, sizeof(forged), "%s", text);
        forged[sizeof(FLEET_HEAD_PREFIX) + 10] ^= 1;
        ASSERT(!fleet_head_parse(forged, &head, &why));
        ASSERT(!fleet_head_parse("not a head", &head, &why));
        ASSERT(!fleet_head_is_line("AAAA"));
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_head_sequence(void)
{
    int failures = 0;
    TEST("fleet head import: a lower sequence is stale, the same bytes are "
         "idempotent, the same sequence with other bytes conflicts, a higher "
         "sequence replaces") {
        static char h5[FLEET_ENROL_HEAD_TEXT_MAX], h4[FLEET_ENROL_HEAD_TEXT_MAX];
        static char h5b[FLEET_ENROL_HEAD_TEXT_MAX], h6[FLEET_ENROL_HEAD_TEXT_MAX];
        static struct fleet_head out, held;
        uint8_t op_seed[32], op_pub[32];
        const uint8_t one[1] = { 0x82 }, two[2] = { 0x82, 0x83 };
        const char *why = NULL;
        bool replaced = false;
        fe_isolate("head-seq");
        fe_key(0x81, op_seed, op_pub);
        ASSERT(fe_head_line(0x81, 5, one, 1, h5, sizeof(h5)));
        ASSERT(fe_head_line(0x81, 4, two, 2, h4, sizeof(h4)));
        ASSERT(fe_head_line(0x81, 5, two, 2, h5b, sizeof(h5b)));
        ASSERT(fe_head_line(0x81, 6, two, 2, h6, sizeof(h6)));

        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_ABSENT);
        ASSERT(fleet_head_import(h5, op_pub, false, &out, &replaced, &why));
        ASSERT(replaced);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_OK);
        ASSERT_EQ(held.seq, (uint64_t)5);

        ASSERT(!fleet_head_import(h4, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_STALE);
        ASSERT(!replaced);
        ASSERT(fleet_head_import(h5, op_pub, false, &out, &replaced, &why));
        ASSERT(!replaced);
        ASSERT(!fleet_head_import(h5b, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_CONFLICT);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_OK);
        ASSERT_EQ(held.n_revoked, 1u);

        ASSERT(fleet_head_import(h6, op_pub, false, &out, &replaced, &why));
        ASSERT(replaced);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_OK);
        ASSERT_EQ(held.seq, (uint64_t)6);
        ASSERT_EQ(held.n_revoked, 2u);
        PASS();
    } _test_next:;
    return failures;
}

/* The interleaving the lock closes: a second import lands while the first is
 * between its sequence check and its write. */
static char g_fe_race_line[FLEET_ENROL_HEAD_TEXT_MAX];
static uint8_t g_fe_race_op[32];
static bool g_fe_race_ok;
static const char *g_fe_race_why;

static void fe_race_hook(void)
{
    static struct fleet_head inner;
    bool replaced = false;
    fleet_enrol_test_after_check = NULL; /* the inner import must not recurse */
    g_fe_race_why = NULL;
    g_fe_race_ok = fleet_head_import(g_fe_race_line, g_fe_race_op, false,
                                     &inner, &replaced, &g_fe_race_why);
}

static int test_fe_head_lock_race(void)
{
    int failures = 0;
    TEST("fleet head import: two imports cannot interleave between the "
         "sequence check and the write, so a lower head never overwrites a "
         "higher one") {
        static char h5[FLEET_ENROL_HEAD_TEXT_MAX], h6[FLEET_ENROL_HEAD_TEXT_MAX];
        static char h7[FLEET_ENROL_HEAD_TEXT_MAX];
        static struct fleet_head out, held;
        uint8_t op_seed[32], op_pub[32];
        const uint8_t one[1] = { 0x82 }, two[2] = { 0x82, 0x83 };
        const char *why = NULL;
        bool replaced = false;
        fe_isolate("head-race");
        fe_key(0x81, op_seed, op_pub);
        memcpy(g_fe_race_op, op_pub, 32);
        ASSERT(fe_head_line(0x81, 5, one, 1, h5, sizeof(h5)));
        ASSERT(fe_head_line(0x81, 6, two, 2, h6, sizeof(h6)));
        ASSERT(fe_head_line(0x81, 7, two, 2, h7, sizeof(h7)));
        ASSERT(fleet_head_import(h5, op_pub, false, &out, &replaced, &why));

        /* While h6 is between its check and its write, h7 is offered. */
        (void)snprintf(g_fe_race_line, sizeof(g_fe_race_line), "%s", h7);
        fleet_enrol_test_lock_wait_ms = 60;
        fleet_enrol_test_after_check = fe_race_hook;
        ASSERT(fleet_head_import(h6, op_pub, false, &out, &replaced, &why));
        fleet_enrol_test_after_check = NULL;
        fleet_enrol_test_lock_wait_ms = 5000;
        /* The inner import must have been refused by name, not run. */
        ASSERT(!g_fe_race_ok);
        ASSERT_STR_EQ(fe_s(g_fe_race_why), FLEET_ENROL_WHY_STATE_LOCK);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_OK);
        ASSERT_EQ(held.seq, (uint64_t)6);

        /* Retried after the lock is free, the higher head lands and the
         * lower one is stale: the stored sequence is the maximum. */
        ASSERT(fleet_head_import(h7, op_pub, false, &out, &replaced, &why));
        ASSERT(!fleet_head_import(h6, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_STALE);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_OK);
        ASSERT_EQ(held.seq, (uint64_t)7);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_head_corrupt_no_rollback(void)
{
    int failures = 0;
    TEST("fleet head import: a corrupted held head cannot be replaced by an "
         "older valid head; a higher one repairs it; a missing or damaged "
         "sequence record fails closed") {
        static char h4[FLEET_ENROL_HEAD_TEXT_MAX], h6[FLEET_ENROL_HEAD_TEXT_MAX];
        static char h9[FLEET_ENROL_HEAD_TEXT_MAX], h6b[FLEET_ENROL_HEAD_TEXT_MAX];
        static struct fleet_head out, held;
        char path[PATH_MAX];
        uint8_t op_seed[32], op_pub[32];
        const uint8_t two[2] = { 0x82, 0x83 };
        const char *why = NULL;
        bool replaced = false;
        fe_isolate("head-corrupt");
        fe_key(0x81, op_seed, op_pub);
        ASSERT(fe_head_line(0x81, 4, two, 1, h4, sizeof(h4)));
        ASSERT(fe_head_line(0x81, 6, two, 2, h6, sizeof(h6)));
        ASSERT(fe_head_line(0x81, 9, two, 2, h9, sizeof(h9)));
        ASSERT(fleet_head_import(h6, op_pub, false, &out, &replaced, &why));
        /* A DIFFERENT validly sealed head at the same sequence is not the
         * one the record vouches for. */
        ASSERT(fe_head_line(0x81, 6, two, 1, h6b, sizeof(h6b)));
        ASSERT(fe_put_leaf("roster.head", h6b));
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_BAD);
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_TORN);

        /* Corrupt the held head: older is refused, a higher one repairs. */
        ASSERT(fe_put_leaf("roster.head", "garbage\n"));
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_BAD);
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_TORN);
        ASSERT(!fleet_head_import(h4, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_STALE);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_BAD);
        ASSERT(fleet_head_import(h9, op_pub, false, &out, &replaced, &why));
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_OK);
        ASSERT_EQ(held.seq, (uint64_t)9);

        /* The record unreadable, or gone beside a head: refuse, never 0. */
        ASSERT(fe_put_leaf("roster.head.seq", "not a record\n"));
        ASSERT(!fleet_head_import(h9, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_HWM);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_BAD);
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_HWM);
        ASSERT(fleet_enrol_state_path("roster.head.seq", path, sizeof(path)));
        ASSERT_EQ(remove(path), 0);
        ASSERT(!fleet_head_import(h9, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_HWM);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_head_torn_crash(void)
{
    int failures = 0;
    TEST("fleet head import: a crash between the sequence record and the "
         "head leaves a torn state that admits nobody; the same head or a "
         "higher one repairs it and an older one is refused") {
        static char h4[FLEET_ENROL_HEAD_TEXT_MAX], h5[FLEET_ENROL_HEAD_TEXT_MAX];
        static char h6[FLEET_ENROL_HEAD_TEXT_MAX], h8[FLEET_ENROL_HEAD_TEXT_MAX];
        static struct fleet_head out, held;
        uint8_t op_seed[32], op_pub[32];
        const uint8_t two[2] = { 0x82, 0x83 };
        const char *why = NULL;
        bool replaced = false;
        fe_isolate("head-torn");
        fe_key(0x81, op_seed, op_pub);
        ASSERT(fe_head_line(0x81, 4, two, 1, h4, sizeof(h4)));
        ASSERT(fe_head_line(0x81, 5, two, 1, h5, sizeof(h5)));
        ASSERT(fe_head_line(0x81, 6, two, 2, h6, sizeof(h6)));
        ASSERT(fe_head_line(0x81, 8, two, 2, h8, sizeof(h8)));
        ASSERT(fleet_head_import(h5, op_pub, false, &out, &replaced, &why));

        fleet_enrol_test_crash_before_head = true;
        ASSERT(!fleet_head_import(h6, op_pub, false, &out, &replaced, &why));
        fleet_enrol_test_crash_before_head = false;
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_IMPORT_PARTIAL);
        ASSERT(!replaced);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_BAD);
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_TORN);

        /* Older (and the previous head) refused; the same head repairs. */
        ASSERT(!fleet_head_import(h4, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_STALE);
        ASSERT(!fleet_head_import(h5, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_STALE);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_BAD);
        ASSERT(fleet_head_import(h6, op_pub, false, &out, &replaced, &why));
        ASSERT(replaced);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_OK);
        ASSERT_EQ(held.seq, (uint64_t)6);

        /* Torn again: a higher head repairs it too. */
        fleet_enrol_test_crash_before_head = true;
        ASSERT(!fleet_head_import(h8, op_pub, false, &out, &replaced, &why));
        fleet_enrol_test_crash_before_head = false;
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_BAD);
        ASSERT(!fleet_head_import(h6, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_STALE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_import_partial_is_honest(void)
{
    int failures = 0;
    TEST("fleet import: when the pin or sequence record moved and the rest "
         "did not finish, the reply says mutated with the partial state "
         "named; a failure before any change says mutated false") {
        static char h1[FLEET_ENROL_HEAD_TEXT_MAX];
        char dd[PATH_MAX], body[PATH_MAX + FLEET_ENROL_HEAD_TEXT_MAX + 64];
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        struct fleet_machine machine;
        struct zcl_command_reply reply;
        uint8_t seed[32], pub[32];
        const char *why = NULL;
        bool appended = false;
        fe_isolate("import-partial");
        ASSERT(fe_manager_key(seed, pub));
        ASSERT(fe_datadir(dd, sizeof(dd), "import-partial-dd"));
        ASSERT(fleet_head_mint(1, FE_NOW, NULL, 0, seed, pub, h1, sizeof(h1),
                               &why));
        (void)snprintf(body, sizeof(body), "{\"line\":\"%s\",\"datadir\":\"%s\"}",
                       h1, dd);

        /* Pin first: the pin write fails, nothing has changed. */
        fleet_enrol_test_fail_pin_write = true;
        ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body, &reply));
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_ROSTER_UNWRITABLE);
        ASSERT(!reply.error.mutated);
        zcl_command_reply_free(&reply);
        fleet_enrol_test_fail_pin_write = false;

        /* Pin and sequence record written, head not: partial, mutated. */
        fleet_enrol_test_crash_before_head = true;
        ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body, &reply));
        fleet_enrol_test_crash_before_head = false;
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_IMPORT_PARTIAL);
        ASSERT(reply.error.mutated);
        zcl_command_reply_free(&reply);

        /* The rename succeeded and the directory flush then failed: the
         * leaf HAS changed, so the reply says mutated, by name. */
        fe_isolate("import-flush");
        ASSERT(fe_manager_key(seed, pub));
        ASSERT(fleet_head_mint(1, FE_NOW, NULL, 0, seed, pub, h1, sizeof(h1),
                               &why));
        (void)snprintf(body, sizeof(body), "{\"line\":\"%s\",\"datadir\":\"%s\"}",
                       h1, dd);
        fleet_enrol_test_fail_dir_flush = true;
        ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body, &reply));
        fleet_enrol_test_fail_dir_flush = false;
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_IMPORT_PARTIAL);
        ASSERT(reply.error.mutated);
        zcl_command_reply_free(&reply);

        /* A row appended and then the pin fails: partial too. */
        fe_isolate("import-partial-row");
        ASSERT(fe_manager_key(seed, pub));
        ASSERT(fe_manager_row("studio", 0x84, seed, pub, FLEET_ENROL_PORT_FIRST,
                              row, sizeof(row)));
        fleet_enrol_test_fail_pin_write = true;
        ASSERT(!fleet_roster_import_pinned(row, pub, false, &machine,
                                           &appended, &why));
        fleet_enrol_test_fail_pin_write = false;
        ASSERT(appended);
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_IMPORT_PARTIAL);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_head_revokes_signer(void)
{
    int failures = 0;
    TEST("fleet roster head: minting a revocation also names the box's "
         "signer key from the operator's own row, refuses a box it holds no "
         "row for, and the import refuses a row whose signer is revoked") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char row2[FLEET_ENROL_MACHINE_TEXT_MAX];
        char body[FLEET_ENROL_HEAD_TEXT_MAX + 256];
        char box_hex[FLEET_ENROL_PUBKEY_HEX];
        char head_text[FLEET_ENROL_HEAD_TEXT_MAX];
        static struct fleet_head head;
        struct fleet_signing_key signer, signer2;
        struct fleet_machine machine;
        struct zcl_command_reply reply;
        uint8_t seed[32], pub[32], box_seed[32], box_pub[32], ghost_pub[32];
        uint8_t ghost_seed[32];
        const char *why = NULL;
        const char *line;
        bool appended = false;
        fe_isolate("head-signer");
        ASSERT(fe_manager_key(seed, pub));
        fe_key(0x72, box_seed, box_pub);
        fe_key(0x74, ghost_seed, ghost_pub);
        fe_key(0x73, signer.seed, signer.pubkey);
        fe_key(0x75, signer2.seed, signer2.pubkey);
        g_fe_signer = &signer;
        ASSERT(fe_manager_row("studio", 0x72, seed, pub,
                              FLEET_ENROL_PORT_FIRST, row, sizeof(row)));
        g_fe_signer = &signer2;
        ASSERT(fe_manager_row("depot", 0x76, seed, pub,
                              FLEET_ENROL_PORT_FIRST + 1, row2, sizeof(row2)));
        g_fe_signer = NULL;
        ASSERT(fleet_roster_import(row, pub, &machine, &appended, &why));

        /* Revoke the box only: the minted head carries box AND signer. */
        zcl_hex_encode(box_pub, 32, box_hex);
        (void)snprintf(body, sizeof(body), "{\"seq\":1,\"revoke\":\"%s\"}",
                       box_hex);
        ASSERT(fe_leaf_call("fleet.roster.head", "zcl.fleet.roster.head.v1",
                            body, &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        line = json_get_str(json_get(&reply.data, "head"));
        ASSERT(line && fleet_head_parse(line, &head, NULL));
        ASSERT(fleet_head_revokes(&head, box_pub));
        ASSERT(fleet_head_revokes(&head, signer.pubkey));
        ASSERT_EQ(head.n_revoked, 2u);
        zcl_command_reply_free(&reply);

        /* A box with no local row cannot be revoked. */
        zcl_hex_encode(ghost_pub, 32, box_hex);
        (void)snprintf(body, sizeof(body), "{\"seq\":2,\"revoke\":\"%s\"}",
                       box_hex);
        ASSERT(fe_leaf_call("fleet.roster.head", "zcl.fleet.roster.head.v1",
                            body, &reply));
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_REVOKE_UNKNOWN);
        zcl_command_reply_free(&reply);

        /* A head revoking only the SIGNER refuses that machine's row. */
        ASSERT(fleet_head_mint(3, FE_NOW, signer2.pubkey, 1, seed, pub,
                               head_text, sizeof(head_text), &why));
        ASSERT(fleet_head_import(head_text, pub, false, &head,
                                 &(bool){false}, &why));
        ASSERT(!fleet_roster_import(row2, pub, &machine, &appended, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_BOX_REVOKED);
        PASS();
    } _test_next:;
    return failures;
}

/* Rewrite the sequence record: flip a hex digit of its operator, or set its
 * sequence, keeping the rest. */
static char g_fe_record_orig[300];

static bool fe_restore_record(void)
{
    return fe_put_leaf("roster.head.seq", g_fe_record_orig);
}

static bool fe_tamper_record(bool flip_op, const char *seq_text)
{
    char path[PATH_MAX], text[256], out[300];
    size_t len;
    FILE *f;
    if (!fleet_enrol_state_path("roster.head.seq", path, sizeof(path)))
        return false;
    f = fopen(path, "rb");
    if (!f)
        return false;
    len = fread(text, 1, sizeof(text) - 1, f);
    fclose(f);
    while (len > 0 && text[len - 1] == '\n')
        --len;
    text[len] = '\0';
    if (len < 64 + 3 + 64)
        return false;
    if (flip_op)
        (void)snprintf(g_fe_record_orig, sizeof(g_fe_record_orig), "%s\n", text);
    if (flip_op)
        text[0] = text[0] == '0' ? '1' : '0';
    if (seq_text)
        (void)snprintf(out, sizeof(out), "%.64s %s %s\n", text, seq_text,
                       text + len - 64);
    else
        (void)snprintf(out, sizeof(out), "%s\n", text);
    return fe_put_leaf("roster.head.seq", out);
}

static int test_fe_head_floor_integrity(void)
{
    int failures = 0;
    TEST("fleet head import: a sequence record naming another operator "
         "refuses every import, and a lowered record cannot admit an older "
         "head while an intact newer signed head is on disk") {
        static char h5[FLEET_ENROL_HEAD_TEXT_MAX], h9[FLEET_ENROL_HEAD_TEXT_MAX];
        static char h10[FLEET_ENROL_HEAD_TEXT_MAX];
        static struct fleet_head out, held;
        uint8_t op_seed[32], op_pub[32];
        const uint8_t two[2] = { 0x82, 0x83 };
        const char *why = NULL;
        bool replaced = false;
        fe_isolate("head-floor");
        fe_key(0x81, op_seed, op_pub);
        ASSERT(fe_head_line(0x81, 5, two, 1, h5, sizeof(h5)));
        ASSERT(fe_head_line(0x81, 9, two, 2, h9, sizeof(h9)));
        ASSERT(fe_head_line(0x81, 10, two, 2, h10, sizeof(h10)));
        ASSERT(fleet_head_import(h9, op_pub, false, &out, &replaced, &why));

        /* A record that names another operator refuses every import. */
        ASSERT(fe_tamper_record(true, NULL));
        ASSERT(!fleet_head_import(h10, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_HWM);
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_BAD);
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_HWM);

        /* Repair the operator, then lower the record's sequence below the
         * intact seq-9 head: the older head is still refused. */
        ASSERT(fe_restore_record());
        ASSERT(fe_tamper_record(false, "3"));
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_BAD);
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_TORN);
        ASSERT(!fleet_head_import(h5, op_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_STALE);
        /* The stored head's floor cannot be assessed: refuse, never read it
         * as no stored head (which would let seq 5 in over the record's 3). */
        fleet_enrol_test_fail_floor = true;
        ASSERT(!fleet_head_import(h5, op_pub, false, &out, &replaced, &why));
        fleet_enrol_test_fail_floor = false;
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_UNREADABLE);
        ASSERT(fleet_head_import(h10, op_pub, false, &out, &replaced, &why));
        ASSERT_EQ(fleet_head_load(op_pub, &held, &why), FLEET_HEAD_OK);
        ASSERT_EQ(held.seq, (uint64_t)10);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_head_revokes_every_signer(void)
{
    int failures = 0;
    TEST("fleet roster head: a revoked box that rotated signers has every "
         "signer its rows bound revoked with it; a re-enrolment of that box "
         "under a new signer is refused; a box-only head still refuses the "
         "box") {
        char row1[FLEET_ENROL_MACHINE_TEXT_MAX];
        char row2[FLEET_ENROL_MACHINE_TEXT_MAX];
        char row3[FLEET_ENROL_MACHINE_TEXT_MAX];
        char body[FLEET_ENROL_HEAD_TEXT_MAX + 256];
        char box_hex[FLEET_ENROL_PUBKEY_HEX];
        char head_text[FLEET_ENROL_HEAD_TEXT_MAX];
        static struct fleet_head head;
        struct fleet_signing_key s1, s2, s3;
        struct fleet_machine machine;
        struct zcl_command_reply reply;
        uint8_t seed[32], pub[32], box_seed[32], box_pub[32];
        const char *why = NULL;
        const char *line;
        bool appended = false, replaced = false;
        fe_isolate("head-signers");
        ASSERT(fe_manager_key(seed, pub));
        fe_key(0x72, box_seed, box_pub);
        fe_key(0x73, s1.seed, s1.pubkey);
        fe_key(0x75, s2.seed, s2.pubkey);
        fe_key(0x77, s3.seed, s3.pubkey);
        g_fe_signer = &s1;
        ASSERT(fe_manager_row("studio", 0x72, seed, pub,
                              FLEET_ENROL_PORT_FIRST, row1, sizeof(row1)));
        g_fe_signer = &s2;   /* the same box, rotated to a second signer */
        ASSERT(fe_manager_row("studio-2", 0x72, seed, pub,
                              FLEET_ENROL_PORT_FIRST + 1, row2, sizeof(row2)));
        g_fe_signer = &s3;   /* ...and re-enrolling later under a third */
        ASSERT(fe_manager_row("studio-3", 0x72, seed, pub,
                              FLEET_ENROL_PORT_FIRST + 2, row3, sizeof(row3)));
        g_fe_signer = NULL;
        ASSERT(fleet_roster_append(row1, &why));
        ASSERT(fleet_roster_append(row2, &why));

        zcl_hex_encode(box_pub, 32, box_hex);
        (void)snprintf(body, sizeof(body), "{\"seq\":1,\"revoke\":\"%s\"}",
                       box_hex);
        ASSERT(fe_leaf_call("fleet.roster.head", "zcl.fleet.roster.head.v1",
                            body, &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        line = json_get_str(json_get(&reply.data, "head"));
        ASSERT(line && fleet_head_parse(line, &head, NULL));
        ASSERT(fleet_head_revokes(&head, box_pub));
        ASSERT(fleet_head_revokes(&head, s1.pubkey));
        ASSERT(fleet_head_revokes(&head, s2.pubkey));
        ASSERT_EQ(head.n_revoked, 3u);
        (void)snprintf(head_text, sizeof(head_text), "%s", line);
        zcl_command_reply_free(&reply);

        /* Imported, the revoked box's re-enrolment under a new signer is
         * refused (the box is revoked whatever signer it brings). */
        ASSERT(fleet_head_import(head_text, pub, false, &head, &replaced,
                                 &why));
        ASSERT(!fleet_roster_import(row3, pub, &machine, &appended, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_BOX_REVOKED);

        /* A head naming only the box (no signer counterpart) still refuses
         * that box's row everywhere. */
        ASSERT(fleet_head_mint(2, FE_NOW, box_pub, 1, seed, pub, head_text,
                               sizeof(head_text), &why));
        ASSERT(fleet_head_import(head_text, pub, false, &head, &replaced,
                                 &why));
        ASSERT(!fleet_roster_import(row3, pub, &machine, &appended, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_BOX_REVOKED);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_head_revokes_import(void)
{
    int failures = 0;
    TEST("fleet import: a machine row for a revoked box is refused, another "
         "box still imports, and with no head file nothing is revoked") {
        char revoked_row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char other_row[FLEET_ENROL_MACHINE_TEXT_MAX];
        static char head[FLEET_ENROL_HEAD_TEXT_MAX];
        static struct fleet_head out;
        struct fleet_machine machine;
        struct fleet_roster_scan scan = {0};
        uint8_t op_seed[32], op_pub[32];
        const uint8_t gone[1] = { 0x82 };
        const char *why = NULL;
        bool appended = false, replaced = false;
        fe_isolate("head-revoked");
        fe_key(0x81, op_seed, op_pub);
        ASSERT(fe_row("studio", 0x81, 0x82, FLEET_ENROL_PORT_FIRST, "",
                      revoked_row, sizeof(revoked_row)));
        ASSERT(fe_row("depot", 0x81, 0x84, FLEET_ENROL_PORT_FIRST + 1, "",
                      other_row, sizeof(other_row)));

        /* No head file: the old behaviour, a row for any box imports. */
        ASSERT(fleet_roster_import(other_row, op_pub, &machine, &appended,
                                   &why));
        ASSERT(appended);

        ASSERT(fe_head_line(0x81, 1, gone, 1, head, sizeof(head)));
        ASSERT(fleet_head_import(head, op_pub, false, &out, &replaced, &why));
        ASSERT(!fleet_roster_import(revoked_row, op_pub, &machine, &appended,
                                    &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_BOX_REVOKED);
        ASSERT(!appended);
        ASSERT(fleet_roster_scan(op_pub, NULL, NULL, &scan, &why));
        ASSERT_EQ(scan.rows, 1u);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_head_fails_closed(void)
{
    int failures = 0;
    TEST("fleet head: an empty, corrupt or foreign-sealed head file is "
         "never read as nothing-revoked; import and the gate provider both "
         "fail closed by name") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        static char foreign[FLEET_ENROL_HEAD_TEXT_MAX], good[FLEET_ENROL_HEAD_TEXT_MAX];
        bool replaced = false;
        static struct fleet_head out;
        struct fleet_machine machine;
        const struct zcl_fleet_roster_provider *p =
            zcl_fleet_roster_gate_provider();
        static struct zcl_fleet_head seam;
        uint8_t op_seed[32], op_pub[32];
        const uint8_t one[1] = { 0x82 };
        const char *why = NULL;
        bool appended = false;
        fe_isolate("head-closed");
        fe_key(0x81, op_seed, op_pub);
        ASSERT(fe_row("studio", 0x81, 0x84, FLEET_ENROL_PORT_FIRST, "", row,
                      sizeof(row)));
        ASSERT(fe_head_line(0x91, 1, one, 1, foreign, sizeof(foreign)));
        ASSERT(p && p->head);

        /* Absent: nothing revoked, the seam says so. */
        p->head(op_pub, &seam, p->ctx);
        ASSERT_EQ(seam.state, ZCL_FLEET_HEAD_NONE);

        /* A trusted head and its record first, then damage the head. */
        ASSERT(fe_head_line(0x81, 1, one, 1, good, sizeof(good)));
        ASSERT(fleet_head_import(good, op_pub, false, &out, &replaced, &why));
        const char *bad[] = { "\n", "garbage not a head\n", foreign };
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
            ASSERT(fe_put_leaf("roster.head", bad[i]));
            why = NULL;
            ASSERT_EQ(fleet_head_load(op_pub, &out, &why), FLEET_HEAD_BAD);
            ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_TORN);
            ASSERT(!fleet_roster_import(row, op_pub, &machine, &appended,
                                        &why));
            ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_HEAD_TORN);
            p->head(op_pub, &seam, p->ctx);
            ASSERT_EQ(seam.state, ZCL_FLEET_HEAD_FAILED);
            ASSERT_EQ(seam.count, 0u);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_operator_pin(void)
{
    int failures = 0;
    TEST("fleet import: the first import pins the operator; a different "
         "operator is fleet_root_changed until confirm_operator_change "
         "re-pins; a head from an operator this box does not trust never "
         "lands") {
        char row_a[FLEET_ENROL_MACHINE_TEXT_MAX];
        char row_b[FLEET_ENROL_MACHINE_TEXT_MAX];
        static char head_b[FLEET_ENROL_HEAD_TEXT_MAX];
        static struct fleet_head out;
        struct fleet_machine machine;
        uint8_t a_seed[32], a_pub[32], b_seed[32], b_pub[32];
        const uint8_t none[1] = { 0x82 };
        char pinned[128];
        char path[PATH_MAX];
        FILE *f;
        const char *why = NULL;
        bool appended = false, replaced = false;
        fe_isolate("pin");
        fe_key(0x81, a_seed, a_pub);
        fe_key(0x91, b_seed, b_pub);
        ASSERT(fe_row("studio", 0x81, 0x84, FLEET_ENROL_PORT_FIRST, "", row_a,
                      sizeof(row_a)));
        ASSERT(fe_row("depot", 0x91, 0x85, FLEET_ENROL_PORT_FIRST + 1, "",
                      row_b, sizeof(row_b)));
        ASSERT(fe_head_line(0x91, 1, none, 1, head_b, sizeof(head_b)));

        /* First import pins A. */
        ASSERT(fleet_roster_import(row_a, a_pub, &machine, &appended, &why));
        ASSERT(fleet_enrol_state_path("operator.pin", path, sizeof(path)));
        f = fopen(path, "rb");
        ASSERT(f != NULL);
        memset(pinned, 0, sizeof(pinned));
        ASSERT(fread(pinned, 1, sizeof(pinned) - 1, f) == 64);
        (void)fclose(f);
        {
            char hex[FLEET_ENROL_PUBKEY_HEX];
            zcl_hex_encode(a_pub, 32, hex);
            ASSERT_STR_EQ(pinned, hex);
        }

        /* A head sealed by B reaches a box that trusts A: refused, even when
         * the owner confirms, because this box was never told to trust B. */
        ASSERT(!fleet_head_import(head_b, a_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROOT_CHANGED);
        ASSERT(!fleet_head_import(head_b, a_pub, true, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROOT_CHANGED);
        ASSERT_EQ(fleet_head_load(a_pub, &out, &why), FLEET_HEAD_ABSENT);

        /* The box re-joins under B. Pinned A, trusting B: refused until the
         * owner says yes, then B is the pin. */
        ASSERT(fleet_enrol_operator_write(b_pub, &why));
        ASSERT(!fleet_roster_import(row_b, b_pub, &machine, &appended, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROOT_CHANGED);
        ASSERT(!fleet_head_import(head_b, b_pub, false, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_ROOT_CHANGED);
        ASSERT(fleet_roster_import_pinned(row_b, b_pub, true, &machine,
                                          &appended, &why));
        ASSERT(appended);
        ASSERT(fleet_head_import(head_b, b_pub, false, &out, &replaced, &why));
        ASSERT(replaced);

        /* An unreadable pin is a refusal, never a silent re-pin. */
        ASSERT(fe_put_leaf("operator.pin", "not hex"));
        ASSERT(!fleet_head_import(head_b, b_pub, true, &out, &replaced, &why));
        ASSERT_STR_EQ(fe_s(why), FLEET_ENROL_WHY_PIN_UNREADABLE);
        PASS();
    } _test_next:;
    return failures;
}

static int test_fe_head_leaves(void)
{
    int failures = 0;
    TEST("fleet roster head / fleet import through the shipped leaves: mint "
         "a head, import it, then the revoked box's row is refused by "
         "code") {
        char row[FLEET_ENROL_MACHINE_TEXT_MAX];
        char body[FLEET_ENROL_HEAD_TEXT_MAX + 256];
        char revoke_hex[FLEET_ENROL_PUBKEY_HEX];
        char head[FLEET_ENROL_HEAD_TEXT_MAX];
        uint8_t seed[32], pub[32], box_seed[32], box_pub[32];
        struct zcl_command_reply reply;
        const char *line;
        fe_isolate("head-leaves");
        ASSERT(fe_manager_key(seed, pub));
        fe_key(0x72, box_seed, box_pub);
        zcl_hex_encode(box_pub, 32, revoke_hex);
        ASSERT(fe_manager_row("studio", 0x72, seed, pub,
                              FLEET_ENROL_PORT_FIRST, row, sizeof(row)));
        {   /* the operator must hold the row to revoke the box */
            struct fleet_machine held_row;
            bool held_appended = false;
            const char *held_why = NULL;
            ASSERT(fleet_roster_import(row, pub, &held_row, &held_appended,
                                       &held_why));
        }

        /* A bad revoke entry refuses the whole list. */
        (void)snprintf(body, sizeof(body),
                       "{\"seq\":1,\"revoke\":\"%s,nothex\"}", revoke_hex);
        ASSERT(fe_leaf_call("fleet.roster.head", "zcl.fleet.roster.head.v1",
                            body, &reply));
        ASSERT_STR_EQ(reply.error.evidence, FLEET_ENROL_WHY_HEAD_INVALID);
        zcl_command_reply_free(&reply);

        (void)snprintf(body, sizeof(body), "{\"seq\":3,\"revoke\":\"%s\"}",
                       revoke_hex);
        ASSERT(fe_leaf_call("fleet.roster.head", "zcl.fleet.roster.head.v1",
                            body, &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        line = json_get_str(json_get(&reply.data, "head"));
        ASSERT(line && fleet_head_is_line(line));
        ASSERT_EQ(json_get_int(json_get(&reply.data, "revoked_count")), 1);
        (void)snprintf(head, sizeof(head), "%s", line);
        zcl_command_reply_free(&reply);

        (void)snprintf(body, sizeof(body), "{\"line\":\"%s\"}", head);
        ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body,
                            &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(json_get_bool(json_get(&reply.data, "replaced")));
        zcl_command_reply_free(&reply);

        (void)snprintf(body, sizeof(body), "{\"line\":\"%s\"}", row);
        ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body,
                            &reply));
        ASSERT(reply.status == ZCL_COMMAND_STATUS_FAILED);
        ASSERT_STR_EQ(reply.error.code, "FLEET_BOX_REVOKED");
        zcl_command_reply_free(&reply);

        /* The same head again is a no-op, and confirm_operator_change is an
         * accepted input that only the word yes honours. */
        (void)snprintf(body, sizeof(body),
                       "{\"line\":\"%s\",\"confirm_operator_change\":\"true\"}",
                       head);
        ASSERT(fe_leaf_call("fleet.import", "zcl.fleet.import.v1", body,
                            &reply));
        ASSERT_EQ(reply.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT(!json_get_bool(json_get(&reply.data, "replaced")));
        zcl_command_reply_free(&reply);
        PASS();
    } _test_next:;
    return failures;
}

int test_fleet_enrol(void)
{
    int failures = 0;
    failures += test_fe_invite_round_trip();
    failures += test_fe_invite_tampered();
    failures += test_fe_invite_bounds();
    failures += test_fe_invite_ttl_flag();
    failures += test_fe_receipt();
    failures += test_fe_roster_seal();
    failures += test_fe_roster_admission();
    failures += test_fe_roster_import();
    failures += test_fe_replay();
    failures += test_fe_invite_nonce_fresh();
    failures += test_fe_admit_two_machines();
    failures += test_fe_bridge();
    failures += test_fe_bridge_nul();
    failures += test_fe_ssh_record();
    failures += test_fe_onion_grammar();
    failures += test_fe_onion_refused_at_mint();
    failures += test_fe_machines_page();
    failures += test_fe_render();
    failures += test_fd_empty_datadir();
    failures += test_fd_transport_and_warning();
    failures += test_fd_bounded();
    failures += test_fd_no_secret_material();
    failures += test_fd_unreadable_store();
    failures += test_fe_anchor_verdicts();
    failures += test_fe_anchor_reported_not_enforced();
    failures += test_fe_admit_requires_anchor();
    failures += test_fe_import_requires_anchor();
    failures += test_fe_anchor_require_spelling();
    failures += test_fe_anchor_unreadable_fails_closed();
    failures += test_fe_anchor_rotation_and_invite();
    failures += test_fe_roster_gate_provider();
    failures += test_fe_head_codec();
    failures += test_fe_head_sequence();
    failures += test_fe_head_lock_race();
    failures += test_fe_head_corrupt_no_rollback();
    failures += test_fe_head_torn_crash();
    failures += test_fe_import_partial_is_honest();
    failures += test_fe_head_revokes_signer();
    failures += test_fe_head_floor_integrity();
    failures += test_fe_head_revokes_every_signer();
    failures += test_fe_head_revokes_import();
    failures += test_fe_head_fails_closed();
    failures += test_fe_operator_pin();
    failures += test_fe_head_leaves();
    fe_restore();
    return failures;
}
