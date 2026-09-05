/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_fleet_enrol — adversarial proof that one-paste fleet enrolment
 * admits exactly what its signatures say and nothing else.
 *
 * The whole ceremony is two strings an owner copies between two computers,
 * so every case below is a string somebody could paste: a token with one
 * byte changed, a token minted by a different key, a receipt whose facts
 * were edited after the box signed them, an invite used twice, a name
 * already taken, a roster line somebody appended by hand. Each of those is
 * a way an attacker who can put text in front of the owner would try to get
 * a machine into the fleet, or get the owner's ssh bridge pointed at one.
 *
 * Every fixture lives under test-tmp/ with XDG_STATE_HOME and HOME
 * redirected into it, so nothing here reads or writes the operator's real
 * fleet key, roster, or ~/.ssh/authorized_keys.
 */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "crypto/ed25519.h"
#include "fleet_enrol.h"
#include "json/json.h"
#include "net/acme_b64url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define FE_NOW 1757030400
#define FE_TTL 24
/* 56 base32 characters then ".onion": a v3 locator with the right SHAPE and
 * no owner. Nothing dials it; the field is self-reported by construction. */
#define FE_ONION \
    "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"

static char g_fe_state[PATH_MAX];
static char g_fe_home[PATH_MAX];
static char g_fe_saved_xdg[PATH_MAX];
static char g_fe_saved_home[PATH_MAX];
static bool g_fe_saved;

/* Point the state-root resolver and the ssh bridge at this case's own tree.
 * Called per TEST so a case that wants a virgin box — no key, no roster —
 * can have one. */
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

/* A deterministic keypair, so a case can play the other box without
 * touching the state root. */
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

/* How many wire bytes a pasted record decodes to. 0 when it is not
 * decodable at all, which every caller below asserts against first. */
static size_t fe_wire_len(const char *text)
{
    uint8_t wire[FLEET_ENROL_MACHINE_WIRE_MAX];
    size_t len = 0;
    if (!acme_b64url_decode(text, wire, sizeof(wire), &len)) return 0;
    return len;
}

/* Decode `text`, flip one bit at `offset`, and re-encode. This is exactly
 * what a hostile paste is: still valid base64url, one byte different. */
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
 * `op_seed`. The whole ceremony in one helper, so the cases below read as
 * the questions they ask rather than as setup. */
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
                              box_seed, box_pub, receipt, sizeof(receipt),
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
        /* Every byte of the signed body, one at a time. A signature that
         * covered only part of the record would let one of these through. */
        ASSERT(fe_wire_len(token) > 0u);
        for (body = 0; body < fe_wire_len(token); ++body) {
            ASSERT(fe_tamper(token, body, forged, sizeof(forged)));
            why = NULL;
            ASSERT(!fleet_invite_parse(forged, &parsed, NULL, 0, NULL, &why));
            ASSERT(why != NULL);
        }
        /* And a token re-signed by another key does not become this
         * fleet's: it verifies internally (the key inside matches the
         * signature) but names a stranger, which is what `fleet admit`
         * refuses as invite_not_ours. */
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
        /* One spelling per machine: no capitals, no dots, no underscores,
         * no edge dashes, nothing too short to say or too long to read. */
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
        /* A relay endpoint is not a place to hide a newline that would
         * split a roster line or an authorized_keys entry. */
        ASSERT(!fleet_invite_mint("studio", FE_TTL, "host\nmore", seed, pubkey,
                                  FE_NOW, token, sizeof(token), &invite, &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_RELAY_INVALID);
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
                                  box_pub, receipt, sizeof(receipt), &why));
        ASSERT(fleet_receipt_parse(receipt, &parsed, NULL, 0, NULL, &why));
        /* The invite travels inside the receipt intact, so the manager
         * re-checks its OWN signature rather than trusting a retyped name. */
        ASSERT_STR_EQ(parsed.invite.name, "studio");
        ASSERT(memcmp(parsed.invite.operator_pubkey, op_pub, 32) == 0);
        ASSERT(memcmp(parsed.box_pubkey, box_pub, 32) == 0);
        ASSERT_STR_EQ(parsed.facts.hostname, "build-box-7");
        ASSERT_EQ(parsed.facts.cores, 8u);
        ASSERT_STR_EQ(parsed.ssh_pubkey, "ssh-ed25519 AAAAkey owner@box");
        /* The locator rides beside the name, under the SAME box signature.
         * A receipt that carried it outside the signed body would let a
         * carrier point the fleet at an address the box never claimed. */
        ASSERT_STR_EQ(parsed.onion, FE_ONION);
        /* EVERY signed byte, one at a time — a fact, the embedded invite,
         * the ssh key the bridge would authorize, the box key, and the
         * signature itself. A signature covering only part of the record
         * would let one of these through, and "some of the bytes" is
         * exactly the bug a sampled loop would miss. */
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
        /* A line somebody else sealed is not readable as this fleet's row,
         * which is what makes hand-editing the file unable to invent one. */
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
        /* The SAME box re-enrolling is not a name clash and keeps its port,
         * so re-running admit after a lost reply grants nothing new. */
        ASSERT(fleet_roster_scan(op_pub, "studio", box_a, &scan, &why));
        ASSERT(scan.same_box);
        ASSERT(!scan.name_taken);
        ASSERT_EQ(scan.existing_port, (uint16_t)FLEET_ENROL_PORT_FIRST);
        /* A row somebody appended under a different key raises the
         * unverifiable count and does not raise the row count. */
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
        /* Written out in full on purpose: a test that asks the subject to
         * build the string it is checking cannot notice the string
         * changing, and every token here is a denial. */
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
        /* Idempotent per box name: a second admit of the same machine is a
         * no-op, not a second grant. */
        added = true;
        ASSERT(fleet_bridge_authorize(line, "studio", &added, &why));
        ASSERT(!added);
        (void)snprintf(path, sizeof(path), "%s/authorized_keys", dir);
        f = fopen(path, "r");
        ASSERT(f != NULL);
        read = fread(body, 1, sizeof(body) - 1u, f);
        (void)fclose(f);
        body[read] = '\0';
        /* Exactly one grant for this box, and exactly one line in the
         * file: a second admit that appended a duplicate would be a second
         * standing authorization the owner never asked for. */
        ASSERT(fe_occurrences(body, "z23-fleet-studio") == 1u);
        ASSERT(fe_occurrences(body, "permitlisten") == 1u);
        ASSERT(fe_occurrences(body, "\n") == 1u);
        ASSERT_STR_EQ(body + strlen(body) - 1u, "\n");
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
        /* Empty is the normal state of a box with no persistent onion yet.
         * It is a missing column, not a bad one, so it must not refuse. */
        ASSERT(fleet_enrol_onion_valid(""));
        ASSERT(fleet_enrol_onion_valid(FE_ONION));
        /* An explicit port is allowed; the address is a locator. */
        ASSERT(snprintf(ported, sizeof(ported), "%s:9050", FE_ONION) > 0);
        ASSERT(fleet_enrol_onion_valid(ported));
        /* A v2 address is 16 characters and is not this. Truncating the v3
         * body must refuse rather than land in some shorter grammar. */
        ASSERT(n < sizeof(shorter));
        memcpy(shorter, FE_ONION, n + 1u);
        memmove(shorter + 16, shorter + n - 6, 7);
        ASSERT(!fleet_enrol_onion_valid(shorter));
        /* One spelling per address: an uppercase body is the same key and a
         * different string, and two spellings would be two rows. */
        memcpy(capital, FE_ONION, n + 1u);
        capital[0] = 'A';
        ASSERT(!fleet_enrol_onion_valid(capital));
        /* '1', '0' and '8' are not in RFC 4648 base32, so a hand-typed
         * address that swapped one for a letter is refused, not enrolled. */
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
        /* A hostname and an IP literal are not onion identities, and this
         * field is an onion identity or nothing. */
        ASSERT(!fleet_enrol_onion_valid("relay.example.com"));
        ASSERT(!fleet_enrol_onion_valid("192.0.2.1:9050"));
        PASS();
    } _test_next:;
    return failures;
}

/* A receipt whose signature is intact but whose onion field is not a
 * locator must be refused on the way IN. The manager did not mint that
 * string; a signature proves who wrote it, never that it is dialable. */
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
                                   &facts, "", box_seed, box_pub, receipt,
                                   sizeof(receipt), &why));
        ASSERT_STR_EQ(why, FLEET_ENROL_WHY_ONION_INVALID);
        /* And an absent locator is not an error: the box simply has none. */
        why = NULL;
        ASSERT(fleet_receipt_mint(invite_wire, invite_len, "", &facts, "",
                                  box_seed, box_pub, receipt, sizeof(receipt),
                                  &why));
        ASSERT(why == NULL);
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
        /* The name leads the verified object: it is the handle the owner
         * and their agents use to talk about this machine. */
        ASSERT_STR_EQ(json_get_str(json_get(verified, "name")), "studio");
        ASSERT_EQ(json_get_int(json_get(verified, "relay_port")), 22203);
        /* A hardware claim is never in the verified object, and the name is
         * never in the self-reported one. Nobody measured the box's cores;
         * nobody but the operator chose its name. */
        ASSERT(json_get(verified, "hostname") == NULL);
        ASSERT(json_get(verified, "cores") == NULL);
        ASSERT(json_get(self, "name") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(self, "onion")), FE_ONION);
        /* The locator is a column, never the handle: it never appears in the
         * verified object and never replaces the name. */
        ASSERT(json_get(verified, "onion") == NULL);
        ASSERT_STR_EQ(json_get_str(json_get(self, "hostname")), "build-box-7");
        ASSERT_EQ(json_get_int(json_get(self, "cores")), 8);
        /* And nothing private reaches the render: the roster row carries no
         * seed, and the rendered object carries no key material beyond the
         * public one. */
        ASSERT(json_write(&out, text, sizeof(text)) > 0);
        ASSERT(strstr(text, "seed") == NULL);
        ASSERT(strstr(text, "private") == NULL);
        json_free(&out);
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
    failures += test_fe_receipt();
    failures += test_fe_roster_seal();
    failures += test_fe_roster_admission();
    failures += test_fe_replay();
    failures += test_fe_bridge();
    failures += test_fe_onion_grammar();
    failures += test_fe_onion_refused_at_mint();
    failures += test_fe_render();
    fe_restore();
    return failures;
}
