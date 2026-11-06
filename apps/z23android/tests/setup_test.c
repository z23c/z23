/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "setup_node.h"
#include "domain/encoding/bech32.h"
#include "setup_field.h"
#include "setup_state.h"
#include "setup_words.h"
#include "wallet_setup.h"
#include <assert.h>
#include <errno.h>
#include <malloc.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PHRASE "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey xray"
#define VALID_PHRASE "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#define HASH "00000000000000000000000000000000000000000000000000000000000abcde"
#define CHAIN "{\"result\":{\"headers\":3000000,\"blocks\":2999990},\"error\":null}"
#define PASS64 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
static const char *dir;
/* Replies of `core wallet recovery status` as wallet_recovery_native_handlers.c builds them at 5822e3f535: keys_before and
 * wallet_already_present at :109-112, seed_state at :249. */
#define PRESENT_REPLY "{\"ok\":true,\"data\":{\"keys_before\":1,\"wallet_already_present\":true,\"seed_state\":\"present-encrypted-unlocked\",\"recoverable_from_phrase\":true}}"
#define RESTORED_TIP "{\"ok\":true,\"data\":{\"recovered\":true,\"birthday_recorded\":true,\"birthday_rejected\":false}}"
#define RESTORED_NO_TIP "{\"ok\":true,\"data\":{\"recovered\":true,\"birthday_recorded\":false,\"birthday_rejected\":false}}"
#define EMPTY_REPLY "{\"ok\":true,\"data\":{\"keys_before\":0,\"wallet_already_present\":false,\"seed_state\":\"none\",\"recoverable_from_phrase\":false}}"

/* A rename that fails on chosen destinations, to prove that a set-aside that cannot go back says so. Other renames pass through. */
static const char *fail_rename_to[2];
static const struct wsu *rename_probe;
static int rename_phase = -1;
int rename(const char *from, const char *to)
{
    if (rename_probe && rename_phase < 0) rename_phase = (int)rename_probe->phase;
    for (size_t i = 0; i < 2; ++i)
        if (fail_rename_to[i] && !strcmp(to, fail_rename_to[i])) { errno = EIO; return -1; }
    return renameat(AT_FDCWD, from, AT_FDCWD, to);
}

/* ---- words ---- */

static bool counter_random(void *ctx, uint8_t *out, size_t len)
{
    unsigned *n = ctx;
    for (size_t i = 0; i < len; ++i) out[i] = (uint8_t)(*n += 37);
    return true;
}
static bool failing_random(void *ctx, uint8_t *out, size_t len) { (void)ctx; (void)out; (void)len; return false; }

static void words_tests(void)
{
    struct zapp_words w;
    assert(zapp_words_parse("  Alpha BRAVO\tcharlie\ndelta echo foxtrot golf hotel india juliet kilo lima ", &w) && w.count == 12);
    assert(!strcmp(w.word[1], "bravo"));
    assert(zapp_words_parse(PHRASE, &w) && w.count == 24);
    char joined[256];
    assert(zapp_words_join(&w, joined, sizeof(joined)) && !strcmp(joined, PHRASE));
    assert(!zapp_words_join(&w, joined, 20) && joined[0] == 0);
    assert(!zapp_words_parse("alpha bravo", &w) && w.count == 0);
    assert(!zapp_words_parse("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike", &w));
    assert(!zapp_words_parse("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo l1ma", &w));
    assert(!zapp_words_parse("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo ninewords", &w));
    assert(!zapp_words_parse(NULL, &w));
    unsigned seed = 1;
    for (int round = 0; round < 200; ++round) {
        size_t p[3];
        assert(zapp_words_pick(24, counter_random, &seed, 3, p));
        assert(p[0] < p[1] && p[1] < p[2] && p[2] < 24);
    }
    size_t p[3];
    assert(!zapp_words_pick(24, failing_random, NULL, 3, p));
    assert(!zapp_words_pick(2, counter_random, &seed, 3, p));
    assert(zapp_words_parse(PHRASE, &w));
    size_t at[3] = {0, 5, 23};
    const char *right[3] = {"ALPHA", " foxtrot ", "XRAY"};
    const char *wrong[3] = {"alpha", "foxtrot", "yankee"};
    assert(zapp_words_match(&w, at, right, 3));
    assert(!zapp_words_match(&w, at, wrong, 3));
    zapp_words_cleanse(&w);
    assert(w.count == 0 && w.word[0][0] == 0 && w.word[23][0] == 0);
}

/* ---- state ---- */

static void touch(const char *name)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    assert(f);
    fputs("x", f);
    fclose(f);
}
static void forget(const char *name)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    (void)remove(path);
}
/* The test's scratch directory is the test's own: empty it, one level of sub-directories included. */
static void wipe_dir_at(const char *path)
{
    DIR *d = opendir(path);
    struct dirent *e;
    while (d && (e = readdir(d))) {
        char child[700];
        struct stat st;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode)) { wipe_dir_at(child); (void)rmdir(child); }
        else (void)unlink(child);
    }
    if (d) closedir(d);
}
static bool exists_in(const char *base, const char *name)
{
    char path[700];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", base, name);
    return lstat(path, &st) == 0;
}
static void put(const char *base, const char *name, const char *text)
{
    char path[700];
    snprintf(path, sizeof(path), "%s/%s", base, name);
    FILE *f = fopen(path, "w");
    assert(f);
    fputs(text, f);
    fclose(f);
}
static bool holds(const char *base, const char *name, const char *text)
{
    char path[700], got[64] = "";
    snprintf(path, sizeof(path), "%s/%s", base, name);
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t n = fread(got, 1, sizeof(got) - 1, f);
    fclose(f);
    got[n] = 0;
    return !strcmp(got, text);
}
static void state_tests(void)
{
    assert(zapp_setup_state(dir) == ZAPP_SETUP_NEEDED);
    touch("wallet_key.blob");
    assert(zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    assert(zapp_setup_mark_done(dir));
    assert(zapp_setup_state(dir) == ZAPP_SETUP_READY);
    forget("wallet_key.blob");
    assert(zapp_setup_state(dir) == ZAPP_SETUP_NEEDED);
    forget("wallet_setup_done");
    assert(zapp_setup_state(dir) == ZAPP_SETUP_NEEDED);
    assert(zapp_setup_state(NULL) == ZAPP_SETUP_NEEDED && zapp_setup_state("") == ZAPP_SETUP_NEEDED);
    assert(!zapp_setup_mark_done("/nonexistent-setup-dir"));
    /* Setting a file aside renames it under a UTC ISO 8601 time and never deletes or replaces. */
    put(dir, "keep.bin", "secret-bytes");
    assert(zapp_setup_set_aside(dir, "keep.bin", 1793534400) == ZAPP_ASIDE_MOVED);
    assert(!exists_in(dir, "keep.bin") && holds(dir, "keep.bin.unused-20261101T120000Z", "secret-bytes"));
    put(dir, "keep.bin", "newer");
    assert(zapp_setup_set_aside(dir, "keep.bin", 1793534400) == ZAPP_ASIDE_FAILED);
    assert(holds(dir, "keep.bin", "newer") && holds(dir, "keep.bin.unused-20261101T120000Z", "secret-bytes"));
    assert(zapp_setup_set_aside(dir, "absent.bin", 1793534400) == ZAPP_ASIDE_ABSENT);
    assert(zapp_setup_set_aside(dir, "keep.bin", 0) == ZAPP_ASIDE_FAILED && holds(dir, "keep.bin", "newer"));
    assert(zapp_setup_set_aside(NULL, "keep.bin", 1793534400) == ZAPP_ASIDE_FAILED);
    /* Undo puts it back, never over an original that has appeared, and never from nothing. */
    forget("keep.bin");
    assert(zapp_setup_undo_aside(dir, "keep.bin", 1793534400) && holds(dir, "keep.bin", "secret-bytes") && !exists_in(dir, "keep.bin.unused-20261101T120000Z"));
    assert(!zapp_setup_undo_aside(dir, "keep.bin", 1793534400));
    assert(zapp_setup_set_aside(dir, "keep.bin", 1793534400) == ZAPP_ASIDE_MOVED);
    put(dir, "keep.bin", "newer");
    assert(!zapp_setup_undo_aside(dir, "keep.bin", 1793534400) && holds(dir, "keep.bin", "newer") && holds(dir, "keep.bin.unused-20261101T120000Z", "secret-bytes"));
    wipe_dir_at(dir);
}

/* ---- the node adapter over a scripted runner ---- */

struct script {
    char reply[SUN_REPLY_MAX];
    bool ran_ok;
    int calls, chain_calls;
    char chain[256], status[512];
    bool status_ok;
    int status_calls, status_while_running;
    int phrase_calls;
    bool phrase_fail;
    const bool *node_flag;
    char op[16], input[SUN_INPUT_MAX];
    unsigned timeout;
    bool (*hook)(struct script *, const char *op);
};
static bool script_run(void *ctx, const char *op, const char *input, unsigned timeout, char *out, size_t cap)
{
    struct script *s = ctx;
    if (!strcmp(op, "chaininfo")) { ++s->chain_calls; snprintf(out, cap, "%s", s->chain); return s->chain[0] != 0; }
    if (!strcmp(op, "status")) { ++s->status_calls; s->status_while_running += s->node_flag && *s->node_flag; snprintf(s->op, sizeof(s->op), "%s", op); snprintf(s->input, sizeof(s->input), "%s", input); snprintf(out, cap, "%s", s->status); return s->status_ok; }
    if (!strcmp(op, "newphrase")) {
        ++s->phrase_calls;
        snprintf(out, cap, "%s", s->phrase_fail ? "The node did not answer." : "{\"ok\":true,\"data\":{\"phrase\":\"" PHRASE "\",\"words\":24}}");
        return !s->phrase_fail;
    }
    ++s->calls;
    snprintf(s->op, sizeof(s->op), "%s", op);
    snprintf(s->input, sizeof(s->input), "%s", input);
    s->timeout = timeout;
    snprintf(out, cap, "%s", s->reply);
    /* A script written for the old create reply (CREATED) stands for a restore that succeeded, with or without a recorded start. */
    if (!strcmp(op, "restore") && strstr(s->reply, "\"phrase\":\""))
        snprintf(out, cap, "%s", strstr(s->reply, "\"birthday_recorded\":true") ? RESTORED_TIP : RESTORED_NO_TIP);
    return s->hook ? s->hook(s, op) : s->ran_ok;
}
static void script_say(struct script *s, bool ok, const char *text) { s->ran_ok = ok; snprintf(s->reply, sizeof(s->reply), "%s", text); }
static struct sun node_of(struct script *s)
{
    struct sun node;
    struct sun_runner runner = {s, script_run};
    sun_init(&node, &runner, "/data/files/z23");
    return node;
}
static void error_reply(struct script *s, const char *code)
{
    char text[256];
    snprintf(text, sizeof(text), "{\"ok\":false,\"error\":{\"code\":\"%s\",\"message\":\"the node sentence\"}}", code);
    script_say(s, false, text);
}

#define CREATED "{\"ok\":true,\"data\":{\"phrase\":\"" PHRASE "\",\"first_shielded_address\":\"zs1\",\"birthday_recorded\":true," \
                "\"birthday_height\":2999000,\"birthday_hash\":\"" HASH "\"}}"
#define CREATED_NO_BIRTHDAY "{\"ok\":true,\"data\":{\"phrase\":\"" PHRASE "\",\"birthday_recorded\":false}}"

/* The node's log lines share the stream with its reply. */
/* While a reply is read, every block that held the whole recovery phrase is overwritten before it is freed, and none is left behind. */
void __real_free(void *p);
void __wrap_free(void *p);
static bool watching, freed_unwiped;
void __wrap_free(void *p)
{
    if (watching && p && memmem(p, malloc_usable_size(p), PHRASE, sizeof(PHRASE) - 1)) freed_unwiped = true;
    __real_free(p);
}
#define TRUNCATED "{\"ok\":true,\"data\":{\"phrase\":\"" PHRASE
static const struct { const char *stream; enum sun_result result; } wipe_streams[] = {
    {CREATED "\n" CREATED "\n", SUN_UNKNOWN},
    {CREATED "\n{\"ok\":true,\"data\":{\"phrase\":\"" PHRASE "\"}}\n", SUN_UNKNOWN},
    {"{\"ok\":true,\"data\":{\"phrase\":\"" PHRASE "\"}}\n" CREATED "\n[boot] done\n", SUN_UNKNOWN},
    {CREATED "\n[boot] done\n", SUN_OK},
    {"[boot] start\n" CREATED "\n", SUN_OK},
    /* A line that holds the whole phrase and ends before the object does. */
    {TRUNCATED, SUN_UNKNOWN},
    {TRUNCATED "\n", SUN_UNKNOWN},
    {TRUNCATED "\n" CREATED "\n", SUN_OK},
    {CREATED "\n" TRUNCATED, SUN_OK},
    {TRUNCATED "\n" TRUNCATED "\n", SUN_UNKNOWN},
};
#define WIPE_STREAMS (sizeof(wipe_streams) / sizeof(wipe_streams[0]))
static void node_reply_wipe_tests(void)
{
    struct script s = {0};
    struct sun node = node_of(&s);
    struct sun_created c;
    /* Each stream once first, so what the allocator keeps for itself is not counted. */
    for (size_t i = 0; i < WIPE_STREAMS; ++i) {
        script_say(&s, true, wipe_streams[i].stream);
        (void)sun_create(&node, PASS64, &c);
    }
    for (size_t i = 0; i < WIPE_STREAMS; ++i) {
        script_say(&s, true, wipe_streams[i].stream);
        size_t before = mallinfo2().uordblks;
        freed_unwiped = false;
        watching = true;
        enum sun_result result = sun_create(&node, PASS64, &c);
        watching = false;
        assert(!freed_unwiped && mallinfo2().uordblks == before);
        assert(result == wipe_streams[i].result && (result == SUN_OK) == (c.words.count == 24));
    }
}
static void node_stream_tests(void)
{
    struct script s = {0};
    struct sun node = node_of(&s);
    struct sun_created c;
    /* The node's log lines share the stream: before the reply, after it, or shaped like an object, none of them hides it. */
    static const char *const streams[] = {
        CREATED "\n",
        "[boot]   sqlite.migrate               35ms\n" CREATED "\n",
        CREATED "\n[boot] shutdown complete\n",
        "{\"level\":\"warn\",\"text\":\"slow disk\"}\n" CREATED "\n[boot] done\n",
        "{not json\n" CREATED,
    };
    for (size_t i = 0; i < sizeof(streams) / sizeof(streams[0]); ++i) {
        script_say(&s, true, streams[i]);
        assert(sun_create(&node, PASS64, &c) == SUN_OK && c.words.count == 24 && c.birthday.known);
    }
    /* Two objects that read as replies are no reply: a stray refusal must not stand for the create, and a stray result must not
     * show another phrase. The result is unknown, which keeps the key and the files. */
    static const char *const doubled[] = {
        "{\"ok\":false,\"error\":{\"code\":\"DATADIR_LOCKED\"}}\n" CREATED "\n",
        "{\"ok\":true,\"data\":{\"phrase\":\"" PHRASE "\"}}\n" CREATED "\n",
        CREATED "\n{\"ok\":false,\"error\":{\"code\":\"DATADIR_LOCKED\"}}\n",
    };
    for (size_t i = 0; i < sizeof(doubled) / sizeof(doubled[0]); ++i) {
        script_say(&s, true, doubled[i]);
        assert(sun_create(&node, PASS64, &c) == SUN_UNKNOWN && c.words.count == 0);
    }
    /* Text after the object on its own line is not part of a reply. */
    script_say(&s, true, CREATED " trailing");
    assert(sun_create(&node, PASS64, &c) == SUN_UNKNOWN && c.words.count == 0);
    script_say(&s, true, "{\"ok\":true,\"data\":{\"phrase\":\"" PHRASE "\",\"birthday_recorded\":false}}");
    assert(sun_create(&node, PASS64, &c) == SUN_OK && !c.birthday.known);
}
static void node_tests(void)
{
    struct script s = {0};
    struct sun node = node_of(&s);
    struct sun_created c;
    script_say(&s, true, "warning: low memory\n" CREATED);
    assert(sun_create(&node, PASS64, &c) == SUN_OK && c.words.count == 24 && c.birthday.known);
    assert(c.birthday.height == 2999000 && !strcmp(c.birthday.hash, HASH));
    assert(!strcmp(s.op, "create") && strstr(s.input, "\"passphrase\":\"" PASS64 "\"") && strstr(s.input, "/data/files/z23"));
    assert(!strstr(s.input, "alpha"));
    static const struct { const char *code; enum sun_result result; } codes[] = {
        {"DATADIR_LOCKED", SUN_NODE_RUNNING}, {"WALLET_ALREADY_PRESENT", SUN_ALREADY_PRESENT},
        {"NODE_DB_UNREADABLE", SUN_STORAGE}, {"NOT_RUN", SUN_NOT_RUN}, {"PASSPHRASE_TOO_SHORT", SUN_REFUSED}, {"CREATE_FAILED", SUN_UNKNOWN},
    };
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        error_reply(&s, codes[i].code);
        assert(sun_create(&node, PASS64, &c) == codes[i].result && c.words.count == 0);
    }
    script_say(&s, false, "The node did not answer.");
    assert(sun_create(&node, PASS64, &c) == SUN_UNKNOWN);
    script_say(&s, true, "{\"ok\":true,\"data\":{\"phrase\":\"only three words\"}}");
    assert(sun_create(&node, PASS64, &c) == SUN_UNKNOWN && c.words.count == 0);
    s.calls = 0;
    assert(sun_create(&node, "short", &c) == SUN_REFUSED && s.calls == 0);
    assert(sun_create(&node, "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef", &c) == SUN_REFUSED && s.calls == 0);

}
static void node_restore_address_tests(struct script *s, struct sun *node, struct zapp_words *w, struct sun_restored *r)
{
    uint8_t symbols[69] = {0};
    char addr[SUN_ADDRESS_MAX], reply[512];
    assert(domain_encoding_bech32_encode(addr, sizeof(addr), "zs", symbols, sizeof(symbols)));
    snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"recovered\":true,\"committed\":true,\"first_shielded_address\":\"%s\"}}", addr);
    script_say(s, true, reply);
    assert(sun_restore(node, w, PASS64, NULL, r) == SUN_OK && !strcmp(r->first_shielded_address, addr));
    snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"recovered\":true,\"first_shielded_address\":\"%s\"}}", addr);
    script_say(s, true, reply);
    assert(sun_restore(node, w, PASS64, NULL, r) == SUN_OK && !r->first_shielded_address[0]);
    for (uint8_t last = 2; last <= 6; last += 2) {
        symbols[68] = last;
        assert(domain_encoding_bech32_encode(addr, sizeof(addr), "zs", symbols, sizeof(symbols)));
        snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"recovered\":true,\"committed\":true,\"first_shielded_address\":\"%s\"}}", addr);
        script_say(s, true, reply);
        assert(sun_restore(node, w, PASS64, NULL, r) == SUN_OK && !strcmp(r->first_shielded_address, addr));
    }
    symbols[68] = 1;
    assert(domain_encoding_bech32_encode(addr, sizeof(addr), "zs", symbols, sizeof(symbols)));
    snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"recovered\":true,\"committed\":true,\"first_shielded_address\":\"%s\"}}", addr);
    script_say(s, true, reply);
    assert(sun_restore(node, w, PASS64, NULL, r) == SUN_OK && !r->first_shielded_address[0]);
    symbols[68] = 0;
    assert(domain_encoding_bech32_encode(addr, sizeof(addr), "wrong", symbols, sizeof(symbols)));
    snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"recovered\":true,\"committed\":true,\"first_shielded_address\":\"%s\"}}", addr);
    script_say(s, true, reply);
    assert(sun_restore(node, w, PASS64, NULL, r) == SUN_OK && !r->first_shielded_address[0]);
    assert(domain_encoding_bech32_encode(addr, sizeof(addr), "zs", symbols, 68));
    snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"recovered\":true,\"committed\":true,\"first_shielded_address\":\"%s\"}}", addr);
    script_say(s, true, reply);
    assert(sun_restore(node, w, PASS64, NULL, r) == SUN_OK && !r->first_shielded_address[0]);
    assert(domain_encoding_bech32_encode(addr, sizeof(addr), "zs", symbols, sizeof(symbols)));
    addr[10] = 112;
    snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"recovered\":true,\"committed\":true,\"first_shielded_address\":\"%s\"}}", addr);
    script_say(s, true, reply);
    assert(sun_restore(node, w, PASS64, NULL, r) == SUN_OK && !r->first_shielded_address[0]);
}
static void node_restore_tests(void)
{
    struct script s = {0};
    struct sun node = node_of(&s);
    struct sun_restored r;
    struct zapp_words w;
    struct sun_birthday b = {true, 2999000, HASH};
    assert(zapp_words_parse(PHRASE, &w));
    script_say(&s, true, "{\"ok\":true,\"data\":{\"recovered\":true,\"birthday_recorded\":true,\"birthday_rejected\":false}}");
    assert(sun_restore(&node, &w, PASS64, &b, &r) == SUN_OK && r.birthday_recorded && !r.birthday_rejected);
    assert(!strcmp(s.op, "restore") && strstr(s.input, "\"phrase\":\"" PHRASE "\"") && strstr(s.input, "\"confirm\":true"));
    assert(strstr(s.input, "\"shielded_only\":true") && strstr(s.input, "\"passphrase\":\"" PASS64 "\"") && strstr(s.input, "\"height\":2999000"));
    assert(strstr(s.input, "\"hash\":\"" HASH "\"") && s.timeout == SUN_RESTORE_TIMEOUT_MS);
    assert(sun_restore(&node, &w, PASS64, NULL, &r) == SUN_OK && !strstr(s.input, "birthday\""));
    struct sun_birthday none = {0};
    assert(sun_restore(&node, &w, PASS64, &none, &r) == SUN_OK && !strstr(s.input, "birthday\""));
    node_restore_address_tests(&s, &node, &w, &r);
    script_say(&s, true, "{\"ok\":true,\"data\":{\"recovered\":false}}");
    assert(sun_restore(&node, &w, PASS64, NULL, &r) == SUN_UNKNOWN);
    error_reply(&s, "INVALID_PHRASE");
    assert(sun_restore(&node, &w, PASS64, NULL, &r) == SUN_INVALID_PHRASE);
    error_reply(&s, "DATADIR_LOCKED");
    assert(sun_restore(&node, &w, PASS64, NULL, &r) == SUN_NODE_RUNNING);

}
static void node_hash_tests(void)
{
    struct script s = {0};
    struct sun node = node_of(&s);
    /* Failed replies by the codes of wallet_recovery_native_handlers.c at 5822e3f535: NO_NODE_DB :220 (no database yet), NO_WALLET
     * :241 (the wallet could not be read), WALLET_LOCKED :272 and WALLET_SEED_UNUSABLE :287 (a seed exists). */
    static const struct { const char *code; enum sun_probe probe; } probes[] = {
        {"NO_NODE_DB", SUN_PROBE_NONE}, {"NO_WALLET", SUN_PROBE_UNKNOWN}, {"WALLET_LOCKED", SUN_PROBE_PRESENT},
        {"WALLET_SEED_UNUSABLE", SUN_PROBE_PRESENT}, {"NODE_DB_UNREADABLE", SUN_PROBE_UNKNOWN}, {"DATADIR_LOCKED", SUN_PROBE_UNKNOWN},
        {"SOMETHING_ELSE", SUN_PROBE_UNKNOWN},
    };
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); ++i) {
        snprintf(s.status, sizeof(s.status), "{\"ok\":false,\"error\":{\"code\":\"%s\"}}", probes[i].code);
        s.status_ok = false;
        assert(sun_wallet_probe(&node) == probes[i].probe);
        assert(!strcmp(s.op, "status"));
        assert(strstr(s.input, "datadir") && strstr(s.input, "/data/files/z23"));
    }
    /* Ok replies: an empty database with no keys is no wallet (a Restore killed before the node wrote leaves exactly this); a
     * seed or keys is a wallet; anything else is not known. */
    s.status_ok = true;
    snprintf(s.status, sizeof(s.status), EMPTY_REPLY);
    assert(sun_wallet_probe(&node) == SUN_PROBE_NONE);
    snprintf(s.status, sizeof(s.status), PRESENT_REPLY);
    assert(sun_wallet_probe(&node) == SUN_PROBE_PRESENT);
    snprintf(s.status, sizeof(s.status), "{\"ok\":true,\"data\":{\"keys_before\":2,\"wallet_already_present\":true,\"seed_state\":\"none\"}}");
    assert(sun_wallet_probe(&node) == SUN_PROBE_PRESENT);
    snprintf(s.status, sizeof(s.status), "{\"ok\":true,\"data\":{\"keys_before\":0,\"wallet_already_present\":false,\"seed_state\":\"unreadable\"}}");
    assert(sun_wallet_probe(&node) == SUN_PROBE_UNKNOWN);
    snprintf(s.status, sizeof(s.status), "{\"ok\":true,\"data\":{\"keys_before\":0,\"wallet_already_present\":false}}");
    assert(sun_wallet_probe(&node) == SUN_PROBE_UNKNOWN);
    snprintf(s.status, sizeof(s.status), "{\"ok\":true,\"data\":{\"recoverable_from_phrase\":true}}");
    assert(sun_wallet_probe(&node) == SUN_PROBE_UNKNOWN);
    s.status[0] = 0;
    s.status_ok = false;
    assert(sun_wallet_probe(&node) == SUN_PROBE_UNKNOWN);
    char hash[SUN_HASH_HEX + 1];
    script_say(&s, true, "{\"result\":\"" HASH "\",\"error\":null,\"id\":1}");
    assert(sun_block_hash(&node, 2999000, hash) && !strcmp(hash, HASH) && !strcmp(s.input, "[2999000]") && !strcmp(s.op, "blockhash"));
    script_say(&s, true, "{\"result\":null,\"error\":{\"code\":-8}}");
    assert(!sun_block_hash(&node, 2999000, hash) && hash[0] == 0);
    script_say(&s, true, "{\"result\":\"nothex\"}");
    assert(!sun_block_hash(&node, 1, hash));
    script_say(&s, false, "x");
    assert(!sun_block_hash(&node, 1, hash));
    assert(!sun_block_hash(&node, 0, hash));
    int64_t headers, blocks;
    snprintf(s.chain, sizeof(s.chain), "%s", CHAIN);
    assert(sun_chain_tip(&node, &headers, &blocks) && headers == 3000000 && blocks == 2999990 && s.chain_calls == 1);
    snprintf(s.chain, sizeof(s.chain), "{\"result\":{\"headers\":\"x\"}}");
    assert(!sun_chain_tip(&node, &headers, &blocks) && headers == 0);
    s.chain[0] = 0;
    assert(!sun_chain_tip(&node, &headers, &blocks));
}

/* ---- the wizard model over a fake device and node ---- */

struct fake {
    struct script script;
    bool running, stops_when_asked, supersede_on_wrap, close_on_wrap;
    enum zapp_devkey_status wrap_status;
    int pauses, wraps, discards, key_deletes, starts, stops, restore_while_running, create_while_running, kind_at_create, kind_at_restore;
    bool protect_ok;
    enum wsu_idle idle;
    unsigned random_state;
    int64_t scanned, tip;
    /* A node that needs exit_after_ms of simulated time to exit once asked; pause_ms advances the clock, nothing sleeps. */
    unsigned exit_after_ms;
    int64_t now_ms, stop_at_ms, wall_offset;
    bool exiting, watch;
    int starts_refused, step_at_start, phase_key, step_at_stop, step_at_write;
    bool tap_on_start;
    int tapped_write, tapped_phase, tapped_give_up, tapped_retry;
    /* The live line as the screen would draw it: the wall clock moves with the simulated time, the line is read at sample_ms of a
     * wait, as the write starts and after it has run write_takes_ms, and as the node is started. */
    bool clock_follows;
    int64_t sample_ms, write_takes_ms;
    char line_at_sample[WSU_LINE_MAX], line_at_write[WSU_LINE_MAX], line_after_write[WSU_LINE_MAX], line_at_start[WSU_LINE_MAX];
    int step_at_sample, write_at_sample;
    bool waiting_at_sample, waiting_at_write, ready_at_sample;
    const char *note_at_sample;
    /* The running node's answer about its open wallet: given from question held_after + 1 on when held_answers is set; the node
     * exits on its own at question held_exit_at when that is not 0. Each question takes held_takes_ms of simulated time. */
    bool held_answers;
    enum sun_probe held;
    int held_calls, held_while_stopped, held_after, held_exit_at;
    int64_t held_takes_ms;
};
static struct fake *fake_of;
static struct wsu *model_of;
/* The live line of the model's screen now; the words of the view are wiped. */
static void line_now(char out[WSU_LINE_MAX])
{
    struct wsu_view v;
    wsu_view_read(model_of, &v);
    wsu_working_line(&v, out, WSU_LINE_MAX);
    zapp_words_cleanse(&v.words);
}
/* A write that takes write_takes_ms of simulated time: the line is read as it starts and as it ends. */
static void write_runs(struct fake *f)
{
    line_now(f->line_at_write);
    f->waiting_at_write = wsu_waiting(model_of);
    f->now_ms += f->write_takes_ms;
    line_now(f->line_after_write);
}
static bool fake_hook(struct script *s, const char *op)
{
    struct fake *f = fake_of;
    if (!strcmp(op, "restore") && f->clock_follows) write_runs(f);
    if (!strcmp(op, "restore") && f->watch) f->step_at_write = (int)model_of->step;
    if (!strcmp(op, "create")) { f->create_while_running += f->running; f->kind_at_create = (int)zapp_setup_kind_read(dir); }
    if (!strcmp(op, "restore")) { f->restore_while_running += f->running; f->kind_at_restore = (int)zapp_setup_kind_read(dir); }
    return s->ran_ok;
}
static enum zapp_devkey_status f_wrap(void *ctx, uint8_t secret[ZAPP_DEVKEY_SECRET])
{
    struct fake *f = ctx;
    ++f->wraps;
    if (f->close_on_wrap) wsu_close(model_of);
    if (f->supersede_on_wrap) { pthread_mutex_lock(&model_of->lock); model_of->step = WSU_BLOCKED; pthread_mutex_unlock(&model_of->lock); }
    if (f->watch) { struct wsu_view v; wsu_view_read(model_of, &v); f->phase_key = v.phase; }
    if (f->wrap_status != ZAPP_DEVKEY_OK) return f->wrap_status;
    memset(secret, 0xab, ZAPP_DEVKEY_SECRET);
    touch("wallet_key.blob");
    return ZAPP_DEVKEY_OK;
}
static void f_delete_key(void *ctx) { ++((struct fake *)ctx)->key_deletes; }
/* The real discard: removes the fresh blob and deletes the Keystore key only when no other wrapped blob remains. */
static void f_discard(void *ctx)
{
    struct fake *f = ctx;
    char path[600];
    struct zapp_devkey_ops ops = {.ctx = f, .delete_key = f_delete_key};
    snprintf(path, sizeof(path), "%s/wallet_key.blob", dir);
    ++f->discards;
    zapp_devkey_discard(&ops, path);
}
/* The process is gone once the simulated time since the stop request reaches exit_after_ms. */
static bool f_running(void *ctx)
{
    struct fake *f = ctx;
    if (f->exiting && f->now_ms - f->stop_at_ms >= (int64_t)f->exit_after_ms) { f->running = false; f->exiting = false; }
    return f->running;
}
static void f_control(void *ctx, bool start)
{
    struct fake *f = ctx;
    struct wsu_view v;
    if (start && f_running(f)) { ++f->starts_refused; return; }   /* the app refuses a start while the old process exists */
    if (start) {
        ++f->starts;
        if (f->clock_follows) line_now(f->line_at_start);
        if (f->tap_on_start) {
            f->tap_on_start = false;
            wsu_view_read(model_of, &v);
            f->tapped_write = v.write;
            f->tapped_phase = v.phase;
            zapp_words_cleanse(&v.words);
            f->tapped_give_up = wsu_give_up_write(model_of);
            f->tapped_retry = wsu_retry_write(model_of);
        }
        f->running = true;
        if (f->watch) { wsu_view_read(model_of, &v); f->step_at_start = v.step; zapp_words_cleanse(&v.words); }
        return;
    }
    ++f->stops;
    if (f->watch) f->step_at_stop = (int)model_of->step;
    if (!f->stops_when_asked) return;
    f->exiting = f->exit_after_ms > 0;
    f->stop_at_ms = f->now_ms;
    f->running = f->exiting;
}
static void f_pause(void *ctx, unsigned ms)
{
    struct fake *f = ctx;
    struct wsu_view v;
    ++f->pauses;
    f->now_ms += ms;
    if (!f->sample_ms || f->now_ms != f->sample_ms) return;
    wsu_view_read(model_of, &v);
    f->step_at_sample = (int)v.step;
    f->write_at_sample = (int)v.write;
    f->ready_at_sample = wsu_view_confirm_ready(&v);
    f->note_at_sample = wsu_confirm_note(&v);
    zapp_words_cleanse(&v.words);
    f->waiting_at_sample = wsu_waiting(model_of);
    line_now(f->line_at_sample);
}
static bool f_random(void *ctx, uint8_t *out, size_t len) { return counter_random(&((struct fake *)ctx)->random_state, out, len); }
static bool f_protect(void *ctx, bool on)
{
    (void)on;
    return ((struct fake *)ctx)->protect_ok;
}
static enum wsu_idle f_idle(void *ctx) { return ((struct fake *)ctx)->idle; }
static bool f_held(void *ctx, enum sun_probe *out)
{
    struct fake *f = ctx;
    ++f->held_calls;
    f->now_ms += f->held_takes_ms;
    if (!f_running(f)) { ++f->held_while_stopped; return false; }
    if (f->held_exit_at && f->held_calls == f->held_exit_at) f->running = false;
    if (!f->running || !f->held_answers || f->held_calls <= f->held_after) return false;
    *out = f->held;
    return true;
}
static int64_t f_wall(void *ctx)
{
    const struct fake *f = ctx;
    return 1793534400 + f->wall_offset + (f->clock_follows ? f->now_ms / 1000 : 0);
}
static bool f_progress(void *ctx, int64_t *scanned, int64_t *tip)
{
    struct fake *f = ctx;
    *scanned = f->scanned;
    *tip = f->tip;
    return f->tip > 0;
}
static void fresh(struct fake *f, struct wsu *w, bool running)
{
    wipe_dir_at(dir);
    memset(f, 0, sizeof(*f));
    f->protect_ok = true;
    f->idle = WSU_IDLE_EMPTY;
    f->script.status_ok = true;
    snprintf(f->script.status, sizeof(f->script.status), PRESENT_REPLY);
    f->script.node_flag = &f->running;
    f->running = running;
    f->stops_when_asked = true;
    f->random_state = 5;
    fake_of = f;
    f->script.hook = fake_hook;
    snprintf(f->script.chain, sizeof(f->script.chain), "%s", CHAIN);
    struct sun node = node_of(&f->script);
    struct wsu_env env = {f, f_wrap, f_discard, f_running, f_control, f_pause, f_random, f_progress, f_protect, f_idle, f_held, f_wall};
    model_of = w;
    assert(wsu_init(w, &env, &node, dir));
    assert(wsu_open(w));
}

static void init_with(struct fake *f, struct wsu *w);
/* The create as the app runs it: the words first, then the wallet written behind them. */
static void create_all(struct wsu *w)
{
    wsu_create_job(w);
    wsu_write_job(w);
}
static void check_created_address(struct wsu *w, const char *address)
{
    char copied[SUN_ADDRESS_MAX];
    uint64_t generation = 0;
    assert(wsu_receive_address(w, copied, sizeof(copied), &generation) && !strcmp(copied, address));
    struct wsu reopened;
    assert(wsu_init(&reopened, &w->env, &w->node, dir));
    assert(!wsu_receive_address(&reopened, copied, sizeof(copied), &generation));
    wsu_destroy(&reopened);
    put(dir, "wallet_key.blob", "replacement");
    assert(!wsu_receive_address(w, copied, sizeof(copied), &generation));
}
static void create_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    assert(w.step == WSU_CHOICE);
    uint8_t symbols[69] = {0};
    char address[SUN_ADDRESS_MAX], reply[512], copied[SUN_ADDRESS_MAX];
    uint64_t generation = 0;
    assert(domain_encoding_bech32_encode(address, sizeof(address), "zs", symbols, sizeof(symbols)));
    snprintf(reply, sizeof(reply), "{\"ok\":true,\"data\":{\"recovered\":true,\"committed\":true,\"birthday_recorded\":true,\"first_shielded_address\":\"%s\"}}", address);
    script_say(&f.script, true, reply);
    create_all(&w);
    assert(!wsu_receive_address(&w, copied, sizeof(copied), &generation));
    wsu_view_read(&w, &v);
    assert(v.step == WSU_WORDS && v.words.count == 24 && !strcmp(v.words.word[0], "alpha"));
    assert(v.write == WSU_WRITE_DONE && v.start_pending);
    assert(f.create_while_running == 0 && f.stops == 1 && f.starts == 1 && f.running);
    assert(strstr(f.script.input, "\"passphrase\":\"abababababababababababababababababababababababababababababababab\""));
    assert(zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    wsu_words_seen(&w);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_CONFIRM && v.words.count == 0);
    assert(v.asked[0] < v.asked[1] && v.asked[1] < v.asked[2]);
    struct zapp_words all;
    assert(zapp_words_parse(PHRASE, &all));
    const char *right[3] = {all.word[v.asked[0]], all.word[v.asked[1]], all.word[v.asked[2]]};
    const char *wrong[3] = {all.word[v.asked[0]], all.word[v.asked[1]], "zzz"};
    assert(!wsu_confirm(&w, wrong, 3));
    wsu_view_read(&w, &v);
    assert(v.step == WSU_CONFIRM && v.mismatches == 1);
    assert(zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    assert(wsu_busy(&w));
    wsu_show_again(&w);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_WORDS && v.words.count == 24);
    wsu_words_seen(&w);
    assert(wsu_confirm(&w, right, 3));
    /* The marker is written by the finishing job, not by the tap that confirmed. */
    assert(w.step == WSU_WORKING && w.held.count == 0 && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    wsu_finish_job(&w);
    assert(w.step == WSU_DONE && zapp_setup_state(dir) == ZAPP_SETUP_READY && !wsu_busy(&w));
    check_created_address(&w, address);
    wsu_finish_job(&w);
    assert(w.step == WSU_DONE);
    wsu_destroy(&w);

}
/* Only a create confirmed in this run is a new wallet, which starts at the tip and has shown no address, so the app may show it
 * as 0 ZCL. A restore, whose balance is unknown until the node has read the chain, and a setup finished before the app started
 * are not. */
static void created_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    struct zapp_words all;
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    wsu_words_seen(&w);
    wsu_view_read(&w, &v);
    assert(zapp_words_parse(PHRASE, &all));
    const char *right[3] = {all.word[v.asked[0]], all.word[v.asked[1]], all.word[v.asked[2]]};
    assert(wsu_confirm(&w, right, 3));
    assert(!wsu_created(&w));
    wsu_finish_job(&w);
    assert(w.step == WSU_DONE);
    assert(wsu_created(&w));
    wsu_destroy(&w);
    init_with(&f, &w);
    assert(w.step == WSU_DONE);
    assert(!wsu_created(&w));
    wsu_destroy(&w);

    fresh(&f, &w, true);
    wsu_open_restore(&w);
    script_say(&f.script, true, "{\"ok\":true,\"data\":{\"recovered\":true,\"birthday_recorded\":false}}");
    wsu_restore_job(&w, VALID_PHRASE, 0);
    assert(w.step == WSU_READING);
    assert(!wsu_created(&w));
    wsu_finish_reading(&w);
    assert(w.step == WSU_DONE);
    assert(!wsu_created(&w));
    wsu_destroy(&w);
}
static void create_failure_decline_tests(void)
{
    struct fake f;
    struct wsu w;
    /* A canceled prompt returns to the choice without making a wallet. */
    fresh(&f, &w, true);
    f.wrap_status = ZAPP_DEVKEY_DECLINED;
    create_all(&w);
    assert(w.step == WSU_CHOICE && w.failure == WSU_NO_FAILURE && f.script.calls == 0 && f.stops == 0);
    assert(f.script.phrase_calls == 0 && !exists_in(dir, "wallet_key.blob"));
    f.wrap_status = ZAPP_DEVKEY_NO_SCREEN_LOCK;
    create_all(&w);
    assert(w.failure == WSU_NO_SCREEN_LOCK);
    wsu_destroy(&w);
    fresh(&f, &w, true);
    f.wrap_status = ZAPP_DEVKEY_DECLINED; f.supersede_on_wrap = true;
    wsu_create_job(&w);
    assert(w.step == WSU_BLOCKED && f.script.calls == 0 && !exists_in(dir, "wallet_key.blob"));
    wsu_destroy(&w);
    fresh(&f, &w, true);
    f.wrap_status = ZAPP_DEVKEY_DECLINED; f.close_on_wrap = true;
    wsu_create_job(&w);
    assert(w.step == WSU_CHOICE && !w.protected && f.script.calls == 0 && !exists_in(dir, "wallet_key.blob"));
    wsu_destroy(&w);
}
/* A phone that keeps keys only in software, from Create: no wallet and no node call, one plain reason and no Try again. */
static void no_hardware_create_test(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    f.wrap_status = ZAPP_DEVKEY_NOT_HARDWARE;
    create_all(&w);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_FAILED && v.failure == WSU_NO_HARDWARE_KEY && !wsu_failure_retries(v.failure));
    assert(f.script.calls == 0 && f.script.phrase_calls == 0 && f.stops == 0 && f.running && zapp_setup_state(dir) == ZAPP_SETUP_NEEDED);
    const char *text = wsu_failure_text(v.failure);
    assert(strstr(text, "cannot protect a wallet key in hardware") && strstr(text, "will not make a wallet here") && !strstr(text, "Try again"));
    wsu_destroy(&w);
}
/* The same refusal from Restore leaves the form, whose typed words are wiped, for the failure page with no Try again. */
static void no_hardware_restore_test(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    f.wrap_status = ZAPP_DEVKEY_NOT_HARDWARE;
    wsu_open_restore(&w);
    wsu_set_form(&w, VALID_PHRASE);
    wsu_restore_job(&w, VALID_PHRASE, 0);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_FAILED && v.failure == WSU_NO_HARDWARE_KEY && !v.form[0] && f.script.calls == 0 && f.stops == 0);
    wsu_destroy(&w);
}
/* The other device key refusals keep Try again. */
static void other_key_refusals_retry_test(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, true);
    f.wrap_status = ZAPP_DEVKEY_NOT_PER_USE;
    create_all(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_KEY && wsu_failure_retries(w.failure) && f.script.calls == 0);
    wsu_destroy(&w);
    assert(wsu_failure_retries(WSU_DECLINED) && wsu_failure_retries(WSU_NO_SCREEN_LOCK) && wsu_failure_retries(WSU_REFUSED));
}
/* The failed write left the setup interrupted with its key, and exactly one phrase was asked for. */
static bool retryable_state(const struct fake *f)
{
    return zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED && exists_in(dir, "wallet_key.blob") && f->script.phrase_calls == 1;
}
static void create_failure_refused_tests(void)
{
    struct fake f;
    struct wsu w;
    /* The node still held its files: the words stay, the key stays, the node runs, and the same phrase is written on a retry. */
    fresh(&f, &w, true);
    error_reply(&f.script, "DATADIR_LOCKED");
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write == WSU_WRITE_FAILED && w.write_failure == WSU_NODE_BUSY && f.discards == 0 && f.running && f.starts == 1);
    assert(retryable_state(&f));
    script_say(&f.script, true, RESTORED_TIP);
    assert(wsu_retry_write(&w) && w.write == WSU_WRITE_PENDING);
    wsu_write_job(&w);
    assert(w.write == WSU_WRITE_DONE && f.script.phrase_calls == 1 && f.wraps == 1 && f.stops == 2 && f.starts == 2 && f.running);
    assert(strstr(f.script.input, "\"phrase\":\"" PHRASE "\"") && strstr(f.script.input, "\"birthday_at_local_tip\":true"));
    assert(!wsu_retry_write(&w) && w.phrase.count == 0 && !w.write_pass[0]);
    wsu_destroy(&w);
}
static void create_failure_unknown_tests(void)
{
    struct fake f;
    struct wsu w;
    /* No usable answer: the wallet may exist. The key stays, the node (which was off) is started to sync, and nothing is claimed done. */
    fresh(&f, &w, false);
    script_say(&f.script, false, "The node did not answer.");
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write_failure == WSU_UNKNOWN && f.discards == 0 && f.running);
    assert(zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    /* A wallet that is there afterwards may be an older one: it is refused, the words are wiped, and the way on is Start over. */
    error_reply(&f.script, "WALLET_ALREADY_PRESENT");
    assert(wsu_retry_write(&w));
    wsu_write_job(&w);
    assert(w.write == WSU_WRITE_NONE && w.step == WSU_BLOCKED && w.failure == WSU_WALLET_THERE && !w.birthday.known);
    assert(w.held.count == 0 && w.phrase.count == 0 && !w.write_pass[0] && !w.confirmed && !wsu_busy(&w));
    assert(zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED && f.discards == 0 && f.running);
    assert(strstr(wsu_failure_text(WSU_WALLET_THERE), "already on this phone"));
    assert(wsu_ask_start_over(&w) && w.step == WSU_START_OVER);
    wsu_destroy(&w);
}
/* Not written on the first try, then present on the next: never done, and the second answer wipes the words too. */
static void create_failure_present_after_refusal_tests(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, true);
    error_reply(&f.script, "DATADIR_LOCKED");
    create_all(&w);
    assert(w.write == WSU_WRITE_FAILED && w.write_failure == WSU_NODE_BUSY && w.held.count == 24 && w.phrase.count == 24);
    error_reply(&f.script, "WALLET_ALREADY_PRESENT");
    assert(wsu_retry_write(&w));
    wsu_write_job(&w);
    assert(w.write != WSU_WRITE_DONE && w.step == WSU_BLOCKED && w.failure == WSU_WALLET_THERE);
    assert(w.held.count == 0 && w.phrase.count == 0 && !w.write_pass[0] && !wsu_retry_write(&w));
    wsu_destroy(&w);
}
/* A write that cannot succeed offers a way out: the held words are wiped and the phone is checked, after which Back works. */
static void create_give_up_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    error_reply(&f.script, "INVALID_PHRASE");
    create_all(&w);
    assert(w.write == WSU_WRITE_FAILED && w.held.count == 24 && wsu_busy(&w));
    assert(wsu_give_up_write(&w) && w.step == WSU_CHECKING && w.write == WSU_WRITE_NONE && !wsu_busy(&w));
    assert(w.held.count == 0 && w.phrase.count == 0 && !w.write_pass[0] && !wsu_give_up_write(&w));
    snprintf(f.script.status, sizeof(f.script.status), "{\"ok\":false,\"error\":{\"code\":\"NO_NODE_DB\"}}");
    f.script.status_ok = false;
    wsu_resume_job(&w);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_NO_WALLET && f.running && f.discards == 0 && !wsu_busy(&w));
    wsu_destroy(&w);
}
static void create_give_up_present_tests(void)
{
    struct fake f;
    struct wsu w;
    /* A wallet found there is blocked, not claimed. */
    fresh(&f, &w, true);
    error_reply(&f.script, "DATADIR_LOCKED");
    create_all(&w);
    assert(wsu_give_up_write(&w));
    snprintf(f.script.status, sizeof(f.script.status), PRESENT_REPLY);
    f.script.status_ok = true;
    wsu_resume_job(&w);
    assert(w.step == WSU_BLOCKED && w.held.count == 0 && w.phrase.count == 0 && !wsu_busy(&w));
    wsu_destroy(&w);
    /* Not offered while the write is pending or done. */
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    assert(w.write == WSU_WRITE_DONE && !wsu_give_up_write(&w) && w.held.count == 24);
    wsu_destroy(&w);
}
/* While the node is starting after a failed write, Try again and the check are refused; afterwards they are accepted and the node runs. */
static void create_buttons_wait_for_start_test(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, true);
    error_reply(&f.script, "DATADIR_LOCKED");
    f.tap_on_start = true;
    create_all(&w);
    assert(f.tapped_write == WSU_WRITE_RUNNING && f.tapped_phase == WSU_PHASE_RESTART && !f.tapped_give_up && !f.tapped_retry);
    assert(w.write == WSU_WRITE_FAILED && w.write_failure == WSU_NODE_BUSY && f.running && f.starts == 1 && f.starts_refused == 0);
    assert(wsu_give_up_write(&w) && w.step == WSU_CHECKING);
    wsu_destroy(&w);
    fresh(&f, &w, true);
    error_reply(&f.script, "DATADIR_LOCKED");
    create_all(&w);
    assert(wsu_retry_write(&w) && w.write == WSU_WRITE_PENDING);
    wsu_destroy(&w);
}
/* A failed phrase or random source leaves nothing held. */
static void create_words_failure_wipe_test(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    w.env.random = failing_random;
    wsu_create_job(&w);
    assert(w.held.count == 0 && w.phrase.count == 0 && !w.write_pass[0] && w.write == WSU_WRITE_NONE);
    wsu_destroy(&w);
}
/* A words-first create never states a start height, before or after the write. */
static void words_first_intro_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    char line[400];
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    wsu_view_read(&w, &v);
    assert(v.write == WSU_WRITE_DONE);
    wsu_words_intro(&v, line, sizeof(line));
    assert(!strstr(line, "start height") && !strstr(line, " 0"));
    wsu_destroy(&w);
}
static void create_failure_busy_tests(void)
{
    struct fake f;
    struct wsu w;
    /* The node does not stop: the wallet is never written, the key stays, and the retry tries again. */
    fresh(&f, &w, true);
    f.stops_when_asked = false;
    script_say(&f.script, true, CREATED);
    create_all(&w);
    assert(w.write_failure == WSU_NODE_BUSY && f.script.calls == 0 && f.discards == 0 && w.step == WSU_WORDS);
    wsu_destroy(&w);
}
static void create_failure_second_tests(void)
{
    struct fake f;
    struct wsu w;
    /* A second create while one ran is ignored. */
    fresh(&f, &w, false);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    f.wraps = 0;
    create_all(&w);
    assert(f.wraps == 0 && w.step == WSU_WORDS && f.script.phrase_calls == 1);
    wsu_destroy(&w);
}

/* The node cannot make a phrase: nothing was written, so the key is discarded and no node call is left over. */
static void create_phrase_failure_test(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, true);
    f.script.phrase_fail = true;
    create_all(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_NOT_RUN && f.discards == 1 && f.stops == 0 && f.starts == 0 && f.running);
    assert(zapp_setup_state(dir) == ZAPP_SETUP_NEEDED && w.write == WSU_WRITE_NONE);
    wsu_destroy(&w);
}

/* No chain tip, no wallet: the key is never made and create is never run. A node that was not running is stopped again. */
/* Only a tip above the node's birthday margin gives the new wallet a start height. */
/* A stray refusal before the real reply leaves the result unknown: the key and the wrapped blob stay, since the node may have made the wallet. */
static void create_stray_refusal_keeps_key_test(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, true);
    script_say(&f.script, true, "{\"ok\":false,\"error\":{\"code\":\"DATADIR_LOCKED\"}}\n" RESTORED_TIP "\n");
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write_failure == WSU_UNKNOWN && f.discards == 0 && f.key_deletes == 0 && exists_in(dir, "wallet_key.blob"));
    wsu_destroy(&w);
}
/* The owner declines to authenticate: the node is not touched at all. */
static void create_declined_stops_node_test(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, false);
    f.wrap_status = ZAPP_DEVKEY_DECLINED;
    create_all(&w);
    assert(w.step == WSU_CHOICE && w.failure == WSU_NO_FAILURE && f.starts == 0 && f.stops == 0 && !f.running && f.script.phrase_calls == 0);
    wsu_destroy(&w);
}
/* A wallet that recorded no start height shows its words, and setup stays unfinished. */
static void create_no_start_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    script_say(&f.script, true, "{\"ok\":true,\"data\":{\"phrase\":\"" PHRASE "\",\"birthday_recorded\":false}}");
    create_all(&w);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_WORDS && v.words.count == 24 && v.start_height == 0);
    wsu_words_seen(&w);
    wsu_view_read(&w, &v);
    struct zapp_words all;
    assert(zapp_words_parse(PHRASE, &all));
    const char *right[3] = {all.word[v.asked[0]], all.word[v.asked[1]], all.word[v.asked[2]]};
    assert(wsu_confirm(&w, right, 3));
    wsu_finish_job(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_NO_BIRTHDAY && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    wsu_destroy(&w);
}

static void restore_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    /* Stopped before the restore, started after; the birthday hash is asked while the node runs. */
    fresh(&f, &w, true);
    wsu_open_restore(&w);
    assert(w.step == WSU_RESTORE_FORM);
    script_say(&f.script, true, "{\"result\":\"" HASH "\"}");
    f.script.hook = NULL;
    wsu_restore_job(&w, "not enough words", 100);
    assert(w.step == WSU_RESTORE_FORM && w.failure == WSU_BAD_WORDS && f.wraps == 0);
    f.script.hook = fake_hook;
    script_say(&f.script, true, "{\"ok\":true,\"data\":{\"recovered\":true,\"birthday_recorded\":true,\"birthday_rejected\":false}}");
    wsu_restore_job(&w, VALID_PHRASE, 2999000);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_READING && !v.birthday_dropped && f.restore_while_running == 0 && f.stops == 1 && f.starts == 1);
    assert(zapp_setup_state(dir) == ZAPP_SETUP_READY && f.wraps == 1);
    assert(strstr(f.script.input, "\"passphrase\":\"abab") && strstr(f.script.input, "\"confirm\":true"));
    f.scanned = 100; f.tip = 3000000;
    int64_t a, b;
    assert(wsu_reading(&w, &a, &b) && a == 100 && b == 3000000);
    wsu_finish_reading(&w);
    assert(w.step == WSU_DONE);
    wsu_destroy(&w);

}
static void restore_unknown_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    /* The owner does not know the birthday: no hash is asked and none is sent. */
    fresh(&f, &w, true);
    wsu_open_restore(&w);
    script_say(&f.script, true, "{\"ok\":true,\"data\":{\"recovered\":true,\"birthday_recorded\":false}}");
    wsu_restore_job(&w, VALID_PHRASE, 0);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_READING && v.birthday_unknown && v.birthday_dropped && !strstr(f.script.input, "birthday\""));
    wsu_destroy(&w);

    /* The node refuses the words: the key goes, the node runs again, the owner can edit. */
    fresh(&f, &w, true);
    wsu_open_restore(&w);
    error_reply(&f.script, "INVALID_PHRASE");
    wsu_restore_job(&w, VALID_PHRASE, 0);
    assert(w.step == WSU_RESTORE_FORM && w.failure == WSU_BAD_PHRASE && f.discards == 1 && f.running);
    assert(zapp_setup_state(dir) == ZAPP_SETUP_NEEDED);
    wsu_back(&w);
    assert(w.step == WSU_CHOICE);
    wsu_destroy(&w);

}
static void restore_busy_tests(void)
{
    struct fake f;
    struct wsu w;
    /* A node that keeps running is never restored under. */
    fresh(&f, &w, true);
    f.stops_when_asked = false;
    wsu_open_restore(&w);
    script_say(&f.script, true, "{\"ok\":true,\"data\":{\"recovered\":true}}");
    wsu_restore_job(&w, VALID_PHRASE, 0);
    assert(w.failure == WSU_NODE_BUSY && f.script.calls == 0 && f.restore_while_running == 0);
    wsu_destroy(&w);

}
/* A refused restore keeps the typed words on the form and shows the reason. The node runs again, and an unknown answer goes to the
 * check instead, with no words kept. */
struct refusal {
    const char *code;
    enum wsu_failure failure;
    enum wsu_step step;
};
static const struct refusal refusals[] = {
    {"INVALID_PHRASE", WSU_BAD_PHRASE, WSU_RESTORE_FORM},
    {"BIRTHDAY_CONFLICT", WSU_REFUSED, WSU_RESTORE_FORM},
    {"NODE_DB_UNREADABLE", WSU_STORAGE, WSU_RESTORE_FORM},
    {"DATADIR_LOCKED", WSU_NODE_BUSY, WSU_RESTORE_FORM},
    {"NOT_RUN", WSU_NOT_RUN, WSU_RESTORE_FORM},
    {"WALLET_ALREADY_PRESENT", WSU_PRESENT, WSU_RESTORE_FORM},
    {"CREATE_FAILED", WSU_UNKNOWN, WSU_FAILED},
};
static void refusal_check(const struct refusal *c)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    f.exit_after_ms = 30000;
    wsu_open_restore(&w);
    wsu_set_form(&w, VALID_PHRASE);
    error_reply(&f.script, c->code);
    wsu_restore_job(&w, VALID_PHRASE, 0);
    wsu_view_read(&w, &v);
    assert(v.step == c->step && v.failure == c->failure && f.stops == 1 && f.starts == 1 && f.starts_refused == 0 && f.running);
    if (c->step == WSU_RESTORE_FORM) {
        assert(f.discards == 1 && zapp_setup_state(dir) == ZAPP_SETUP_NEEDED && !strcmp(v.form, VALID_PHRASE));
        wsu_back(&w);
        wsu_view_read(&w, &v);
        assert(v.step == WSU_CHOICE && v.form[0] == 0);
    } else {
        assert(v.form[0] == 0);
    }
    wsu_destroy(&w);
}
/* A node that was stopped stays stopped: nothing is started, the words are kept, and leaving the form wipes them. */
static void refusal_stopped_check(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, false);
    wsu_open_restore(&w);
    wsu_set_form(&w, VALID_PHRASE);
    error_reply(&f.script, "INVALID_PHRASE");
    wsu_restore_job(&w, VALID_PHRASE, 0);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_RESTORE_FORM && v.failure == WSU_BAD_PHRASE && f.starts == 0 && !f.running && !strcmp(v.form, VALID_PHRASE));
    wsu_forget_form(&w);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_RESTORE_FORM && v.form[0] == 0);
    wsu_destroy(&w);
}
/* A restore that succeeds wipes the words once they are in the node. */
static void restore_success_wipes_test(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    wsu_open_restore(&w);
    wsu_set_form(&w, VALID_PHRASE);
    script_say(&f.script, true, "{\"ok\":true,\"data\":{\"recovered\":true}}");
    wsu_restore_job(&w, VALID_PHRASE, 0);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_READING && v.form[0] == 0);
    wsu_destroy(&w);
}
static void restore_refusal_form_tests(void)
{
    for (size_t i = 0; i < sizeof(refusals) / sizeof(refusals[0]); ++i) refusal_check(&refusals[i]);
    refusal_stopped_check();
    restore_success_wipes_test();
}
/* Sets up an unconfirmed create over a real datadir under the test directory, reaches the blocked state and returns. */
static void blocked_create(struct fake *f, struct wsu *w, char node_dir[700])
{
    fresh(f, w, true);
    snprintf(node_dir, 700, "%s/node", dir);
    assert(mkdir(node_dir, 0700) == 0);
    put(node_dir, "node.db", "chain-and-wallet");
    put(node_dir, "node.db-wal", "wal");
    put(node_dir, "node.db-shm", "shm");
    put(node_dir, "other.dat", "keep");
    touch("wallet_key.blob");
    zapp_setup_kind_write(dir, ZAPP_KIND_CREATE);
    wsu_destroy(w);
    struct sun node;
    struct sun_runner runner = {&f->script, script_run};
    sun_init(&node, &runner, node_dir);
    struct wsu_env env = {f, f_wrap, f_discard, f_running, f_control, f_pause, f_random, f_progress, f_protect, f_idle, f_held, f_wall};
    f->held_answers = true;
    f->held = SUN_PROBE_PRESENT;
    assert(wsu_init(w, &env, &node, dir) && wsu_open(w));
    wsu_resume_job(w);
    /* The running node holds the wallet and says so: nothing is stopped or started for the check. */
    assert(w->step == WSU_BLOCKED && w->failure == WSU_NO_FAILURE && f->stops == 0 && f->starts == 0 && f->script.status_calls == 0);
}
static void files_untouched(const char *node_dir)
{
    assert(holds(node_dir, "node.db", "chain-and-wallet") && exists_in(dir, "wallet_key.blob") && exists_in(dir, "wallet_setup_kind"));
}
/* Start over: only an unconfirmed create whose wallet the node reports empty, with the node stopped, and nothing is deleted. */
static void start_over_tests(void)
{
    struct fake f;
    struct wsu w;
    char node_dir[700];
    blocked_create(&f, &w, node_dir);
    assert(wsu_ask_start_over(&w) && w.step == WSU_START_OVER);
    wsu_cancel_start_over(&w);
    assert(w.step == WSU_BLOCKED);
    assert(wsu_ask_start_over(&w));
    w.birthday.known = true;
    w.birthday.height = 7;
    wsu_start_over_job(&w);
    assert(!w.birthday.known && w.birthday.height == 0);
    char aside[760];
    snprintf(aside, sizeof(aside), "%s.unused-20261101T120000Z", node_dir);
    assert(w.step == WSU_CHOICE && f.stops == 1 && f.discards == 0 && zapp_setup_state(dir) == ZAPP_SETUP_NEEDED);
    /* The node runs again on the empty datadir. */
    assert(f.running && f.starts == 1);
    /* The whole datadir moved in one rename; an empty one stands in its place. */
    assert(holds(aside, "node.db", "chain-and-wallet") && holds(aside, "node.db-wal", "wal") && holds(aside, "node.db-shm", "shm") && holds(aside, "other.dat", "keep"));
    assert(exists_in(dir, "node") && !exists_in(node_dir, "node.db") && !exists_in(node_dir, "other.dat"));
    assert(holds(dir, "wallet_key.blob.unused-20261101T120000Z", "x"));
    assert(exists_in(dir, "wallet_setup_kind.unused-20261101T120000Z") && zapp_setup_kind_read(dir) == ZAPP_KIND_NONE);
    wsu_destroy(&w);
}

static void start_over_restore_tests(void)
{
    struct fake f;
    struct wsu w;
    char node_dir[700];

    /* A restore is never started over. */
    blocked_create(&f, &w, node_dir);
    zapp_setup_kind_write(dir, ZAPP_KIND_RESTORE);
    assert(!wsu_ask_start_over(&w) && w.step == WSU_BLOCKED && w.failure == WSU_NOT_CREATE);
    w.step = WSU_START_OVER;
    w.failure = WSU_NO_FAILURE;
    wsu_start_over_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_NOT_CREATE && f.stops == 0);
    files_untouched(node_dir);
    wsu_destroy(&w);
}

static void start_over_confirmed_tests(void)
{
    struct fake f;
    struct wsu w;
    char node_dir[700];

    /* Confirmed words are never started over, by the marker or by the model. */
    blocked_create(&f, &w, node_dir);
    touch("wallet_setup_done");
    assert(!wsu_ask_start_over(&w) && w.failure == WSU_ALREADY_CONFIRMED);
    w.step = WSU_START_OVER;
    wsu_start_over_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_ALREADY_CONFIRMED && f.stops == 0);
    files_untouched(node_dir);
    forget("wallet_setup_done");
    w.step = WSU_START_OVER;
    w.confirmed = true;
    wsu_start_over_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_ALREADY_CONFIRMED && f.stops == 0);
    files_untouched(node_dir);
    wsu_destroy(&w);
}

static void start_over_empty_tests(void)
{
    struct fake f;
    struct wsu w;
    char node_dir[700];

    /* A wallet with funds or transactions, or one the node would not describe, is left as it is. */
    blocked_create(&f, &w, node_dir);
    f.idle = WSU_IDLE_FUNDS;
    w.step = WSU_START_OVER;
    wsu_start_over_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_NOT_EMPTY && f.stops == 0 && f.running);
    files_untouched(node_dir);
    f.idle = WSU_IDLE_UNKNOWN;
    w.step = WSU_START_OVER;
    wsu_start_over_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_COULD_NOT_CHECK && f.stops == 0);
    files_untouched(node_dir);
    wsu_destroy(&w);
}

static void start_over_node_tests(void)
{
    struct fake f;
    struct wsu w;
    char node_dir[700];

    /* A node that does not stop is not renamed under. */
    blocked_create(&f, &w, node_dir);
    f.stops_when_asked = false;
    w.step = WSU_START_OVER;
    wsu_start_over_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_NODE_BUSY);
    files_untouched(node_dir);
    wsu_destroy(&w);

    /* A rename that cannot be made leaves the datadir, its files and the key where they were, and Back returns to checking. */
    blocked_create(&f, &w, node_dir);
    char taken[760];
    snprintf(taken, sizeof(taken), "%s.unused-20261101T120000Z", node_dir);
    assert(mkdir(taken, 0700) == 0);
    put(taken, "older", "older");
    w.step = WSU_START_OVER;
    wsu_start_over_job(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_ASIDE);
    files_untouched(node_dir);
    assert(holds(node_dir, "node.db-wal", "wal") && holds(node_dir, "node.db-shm", "shm") && holds(node_dir, "other.dat", "keep"));
    assert(holds(taken, "older", "older") && !exists_in(taken, "node.db"));
    wsu_back(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_UNKNOWN && wsu_recheck(&w) && w.step == WSU_CHECKING);
    wsu_destroy(&w);
}

/* Start over is all or nothing: a move that fails puts the moved items back, last first; one that cannot go back is named. */
static void start_over_undo_tests(void)
{
    struct fake f;
    struct wsu w;
    char node_dir[700];

    /* The key cannot move after the datadir did: the datadir goes back and nothing changed. */
    blocked_create(&f, &w, node_dir);
    put(dir, "wallet_key.blob.unused-20261101T120000Z", "older");
    w.step = WSU_START_OVER;
    wsu_start_over_job(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_ASIDE && !exists_in(dir, "node.unused-20261101T120000Z"));
    files_untouched(node_dir);
    assert(holds(node_dir, "node.db-wal", "wal") && holds(node_dir, "other.dat", "keep") && holds(dir, "wallet_key.blob.unused-20261101T120000Z", "older"));
    wsu_back(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_UNKNOWN);
    wsu_destroy(&w);

    /* The records cannot move after the datadir and the key did: both go back. */
    blocked_create(&f, &w, node_dir);
    put(dir, "wallet_setup_kind.unused-20261101T120000Z", "older");
    w.step = WSU_START_OVER;
    wsu_start_over_job(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_ASIDE && !exists_in(dir, "node.unused-20261101T120000Z") && !exists_in(dir, "wallet_key.blob.unused-20261101T120000Z"));
    files_untouched(node_dir);
    assert(holds(dir, "wallet_setup_kind.unused-20261101T120000Z", "older"));
    wsu_destroy(&w);
}

static void start_over_stuck_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    char node_dir[700], key_to[620], node_aside[760], key_aside[620];
    snprintf(node_aside, sizeof(node_aside), "%s/node.unused-20261101T120000Z", dir);
    snprintf(key_aside, sizeof(key_aside), "%s/wallet_key.blob.unused-20261101T120000Z", dir);
    snprintf(key_to, sizeof(key_to), "%s/wallet_key.blob", dir);

    /* The key cannot go back: it is named, and no new wallet is offered. */
    blocked_create(&f, &w, node_dir);
    put(dir, "wallet_setup_kind.unused-20261101T120000Z", "older");
    fail_rename_to[0] = key_to;
    w.step = WSU_START_OVER;
    wsu_start_over_job(&w);
    fail_rename_to[0] = NULL;
    wsu_view_read(&w, &v);
    assert(v.step == WSU_FAILED && v.failure == WSU_ASIDE_STUCK && strstr(v.leftover, key_aside) && !strstr(v.leftover, node_aside));
    assert(holds(dir, "wallet_key.blob.unused-20261101T120000Z", "x") && !exists_in(dir, "wallet_key.blob") && holds(node_dir, "node.db", "chain-and-wallet"));
    assert(!wsu_recheck(&w));
    wsu_back(&w);
    int wraps = f.wraps;
    create_all(&w);
    wsu_open_restore(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_ASIDE_STUCK && f.wraps == wraps);
    wsu_destroy(&w);

    /* Neither the key nor the datadir can go back: both are named. */
    blocked_create(&f, &w, node_dir);
    put(dir, "wallet_setup_kind.unused-20261101T120000Z", "older");
    fail_rename_to[0] = key_to;
    fail_rename_to[1] = node_dir;
    w.step = WSU_START_OVER;
    wsu_start_over_job(&w);
    fail_rename_to[0] = fail_rename_to[1] = NULL;
    wsu_view_read(&w, &v);
    assert(v.failure == WSU_ASIDE_STUCK && strstr(v.leftover, key_aside) && strstr(v.leftover, node_aside));
    assert(holds(node_aside, "node.db", "chain-and-wallet"));
    wsu_destroy(&w);
}

static void field_tests(void)
{
    assert(ZAPP_FIELD_PRIVATE(ZAPP_FIELD_INPUT_WORDS, ZAPP_FIELD_IME_NO_LEARNING));
    assert(ZAPP_FIELD_PRIVATE(ZAPP_FIELD_INPUT_WORDS | ZAPP_FIELD_FLAG_MULTI_LINE, ZAPP_FIELD_IME_NO_LEARNING));
    assert(!ZAPP_FIELD_PRIVATE(ZAPP_FIELD_INPUT_WORDS, 0));
    assert(!ZAPP_FIELD_PRIVATE(ZAPP_FIELD_INPUT_WORDS & ~0x80000, ZAPP_FIELD_IME_NO_LEARNING));
    assert(!ZAPP_FIELD_PRIVATE(0x80001, ZAPP_FIELD_IME_NO_LEARNING));
    assert(!ZAPP_FIELD_PRIVATE(ZAPP_FIELD_NUMBER, ZAPP_FIELD_IME_NO_LEARNING));
    assert(ZAPP_FIELD_AUTOFILL_NO == 2);
}
static void init_with(struct fake *f, struct wsu *w)
{
    struct sun node = node_of(&f->script);
    struct wsu_env env = {f, f_wrap, f_discard, f_running, f_control, f_pause, f_random, f_progress, f_protect, f_idle, f_held, f_wall};
    assert(wsu_init(w, &env, &node, dir));
    assert(wsu_open(w));
}
static void restore_blocked_tests(void)
{
    struct fake f;
    struct wsu w;
    /* A setup left half done is read from the datadir after a restart, never assumed. */
    fresh(&f, &w, false);
    touch("wallet_key.blob");
    zapp_setup_kind_write(dir, ZAPP_KIND_RESTORE);
    wsu_destroy(&w);
    init_with(&f, &w);
    assert(w.step == WSU_CHECKING && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    create_all(&w);
    wsu_open_restore(&w);
    assert(w.step == WSU_CHECKING && f.wraps == 0);
    /* The restore reached the node and the app died before the marker: setup completes. */
    wsu_resume_job(&w);
    assert(w.step == WSU_READING && zapp_setup_state(dir) == ZAPP_SETUP_READY && f.discards == 0 && f.starts == 1);
    struct wsu_view v;
    wsu_view_read(&w, &v);
    assert(!v.birthday_dropped);
    wsu_destroy(&w);
    touch("wallet_setup_done");
    init_with(&f, &w);
    assert(w.step == WSU_DONE);
    wsu_destroy(&w);
}
/* A create whose words were never confirmed stays blocked, a datadir with no wallet frees the choice, and an unanswered
 * node is asked again. */
static void resume_create_tests(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, false);
    touch("wallet_key.blob");
    zapp_setup_kind_write(dir, ZAPP_KIND_CREATE);
    wsu_destroy(&w);
    init_with(&f, &w);
    wsu_resume_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_NO_FAILURE && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED && f.discards == 0);
    assert(wsu_recheck(&w) && w.step == WSU_CHECKING);
    wsu_destroy(&w);
}

static void no_wallet_tests(void)
{
    struct fake f;
    struct wsu w;

    fresh(&f, &w, false);
    touch("wallet_key.blob");
    zapp_setup_kind_write(dir, ZAPP_KIND_RESTORE);
    wsu_destroy(&w);
    snprintf(f.script.status, sizeof(f.script.status), "{\"ok\":false,\"error\":{\"code\":\"NO_NODE_DB\"}}");
    f.script.status_ok = false;
    init_with(&f, &w);
    wsu_resume_job(&w);
    /* No wallet is shown in plain words and waits for a tap; the key is kept, and on the tap renamed aside, never deleted. */
    assert(w.step == WSU_NO_WALLET && f.discards == 0 && exists_in(dir, "wallet_key.blob") && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    wsu_set_aside_job(&w);
    assert(w.step == WSU_CHOICE && f.discards == 0 && zapp_setup_state(dir) == ZAPP_SETUP_NEEDED);
    assert(holds(dir, "wallet_key.blob.unused-20261101T120000Z", "x") && exists_in(dir, "wallet_setup_kind.unused-20261101T120000Z"));
    assert(zapp_setup_kind_read(dir) == ZAPP_KIND_NONE);
    wsu_set_aside_job(&w);
    assert(w.step == WSU_CHOICE);
    wsu_destroy(&w);
}

static void resume_unknown_tests(void)
{
    struct fake f;
    struct wsu w;

    fresh(&f, &w, false);
    touch("wallet_key.blob");
    zapp_setup_kind_write(dir, ZAPP_KIND_RESTORE);
    wsu_destroy(&w);
    f.script.status[0] = 0;
    f.script.status_ok = false;
    init_with(&f, &w);
    wsu_resume_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_UNKNOWN && f.discards == 0 && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    assert(wsu_recheck(&w) && w.step == WSU_CHECKING);
    f.script.status_ok = true;
    snprintf(f.script.status, sizeof(f.script.status), "{\"ok\":false,\"error\":{\"code\":\"WALLET_LOCKED\"}}");
    wsu_resume_job(&w);
    assert(w.step == WSU_READING && zapp_setup_state(dir) == ZAPP_SETUP_READY);
    wsu_destroy(&w);
}

/* A Restore killed before the node wrote leaves an empty database: that is no wallet and asks, never "finished". An unreadable
 * wallet (NO_WALLET) is not known and keeps everything. A running node that gives no answer is stopped for the read and started
 * again after. */
static void probe_meaning_tests(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, true);
    touch("wallet_key.blob");
    zapp_setup_kind_write(dir, ZAPP_KIND_RESTORE);
    wsu_destroy(&w);
    snprintf(f.script.status, sizeof(f.script.status), EMPTY_REPLY);
    init_with(&f, &w);
    wsu_resume_job(&w);
    assert(w.step == WSU_NO_WALLET && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED && f.discards == 0 && exists_in(dir, "wallet_key.blob"));
    assert(f.script.status_calls == 1 && f.script.status_while_running == 0 && f.stops == 1 && f.starts == 1 && f.running);
    wsu_destroy(&w);

    fresh(&f, &w, false);
    touch("wallet_key.blob");
    zapp_setup_kind_write(dir, ZAPP_KIND_RESTORE);
    wsu_destroy(&w);
    snprintf(f.script.status, sizeof(f.script.status), "{\"ok\":false,\"error\":{\"code\":\"NO_WALLET\"}}");
    f.script.status_ok = false;
    init_with(&f, &w);
    wsu_resume_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_UNKNOWN && f.discards == 0 && exists_in(dir, "wallet_key.blob") && !f.running);
    wsu_destroy(&w);

    /* A node that will not stop is not read around. */
    fresh(&f, &w, true);
    touch("wallet_key.blob");
    zapp_setup_kind_write(dir, ZAPP_KIND_RESTORE);
    wsu_destroy(&w);
    f.stops_when_asked = false;
    init_with(&f, &w);
    wsu_resume_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_NODE_BUSY && f.script.status_calls == 0);
    wsu_destroy(&w);
}

/* The model's bound on asking a running node: ASK_TIMES questions, ASK_GAP_MS apart (IDLE_POLLS and IDLE_POLL_MS), none started two
 * minutes or more after the first. ASK_TAKES_MS is the most the command line gives one question. */
#define ASK_TIMES 24
#define ASK_GAP_MS 5000
#define ASK_TAKES_MS 15000
#define SUMMARY_HELD(seed, keys) \
    "{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"shielded_keys\":0,\"seed_present\":" seed ",\"keys_present\":" keys "}}"
/* The summary's answer keeps the rule of the status probe: a seed or a key is a wallet, both false is none, a null is not known,
 * and a reply without both fields, a failed reply or another schema is no answer. Amounts and shielded_keys alone never answer. */
static void summary_wallet_tests(void)
{
    static const struct { const char *reply; bool answered; enum sun_probe probe; } cases[] = {
        {SUMMARY_HELD("false", "false"), true, SUN_PROBE_NONE},
        {SUMMARY_HELD("true", "false"), true, SUN_PROBE_PRESENT},
        {SUMMARY_HELD("false", "true"), true, SUN_PROBE_PRESENT},
        {SUMMARY_HELD("true", "null"), true, SUN_PROBE_PRESENT},
        {SUMMARY_HELD("null", "true"), true, SUN_PROBE_PRESENT},
        {SUMMARY_HELD("null", "false"), true, SUN_PROBE_UNKNOWN},
        {SUMMARY_HELD("false", "null"), true, SUN_PROBE_UNKNOWN},
        {SUMMARY_HELD("null", "null"), true, SUN_PROBE_UNKNOWN},
        {SUMMARY_HELD("0", "false"), false, SUN_PROBE_UNKNOWN},
        {SUMMARY_HELD("false", "\"no\""), false, SUN_PROBE_UNKNOWN},
        {"{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"shielded_keys\":0,\"spendable_zat\":0,\"public_zat\":0,"
         "\"current\":true}}", false, SUN_PROBE_UNKNOWN},
        {"{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"seed_present\":false}}", false, SUN_PROBE_UNKNOWN},
        {"{\"ok\":false,\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"seed_present\":false,\"keys_present\":false}}", false, SUN_PROBE_UNKNOWN},
        {"{\"ok\":true,\"data\":{\"schema\":\"zcl.wallet_status.v1\",\"seed_present\":false,\"keys_present\":false}}", false, SUN_PROBE_UNKNOWN},
        {"{\"ok\":true,\"data\":{\"seed_present\":false,\"keys_present\":false}}", false, SUN_PROBE_UNKNOWN},
        {"{\"ok\":\"true\",\"data\":{\"schema\":\"zcl.wallet_summary.v1\",\"seed_present\":false,\"keys_present\":false}}", false, SUN_PROBE_UNKNOWN},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        struct json_value root = {0};
        enum sun_probe probe = (enum sun_probe)7;
        assert(json_read(&root, cases[i].reply, strlen(cases[i].reply)));
        assert(wsu_summary_wallet(&root, &probe) == cases[i].answered);
        assert(cases[i].answered ? probe == cases[i].probe : probe == (enum sun_probe)7);
        json_free(&root);
    }
    enum sun_probe probe = (enum sun_probe)7;
    assert(!wsu_summary_wallet(NULL, &probe) && probe == (enum sun_probe)7);
}

/* An interrupted setup over a fake whose running node answers held, after held_after questions it cannot answer yet. */
static void interrupted_with(struct fake *f, struct wsu *w, enum zapp_setup_kind kind, enum sun_probe held, int held_after)
{
    fresh(f, w, true);
    touch("wallet_key.blob");
    zapp_setup_kind_write(dir, kind);
    wsu_destroy(w);
    f->held_answers = true;
    f->held = held;
    f->held_after = held_after;
    init_with(f, w);
}
/* The running node was asked once, without a pause, and was never stopped, started or read around. */
static bool asked_once_untouched(const struct fake *f)
{
    return f->stops == 0 && f->starts == 0 && f->starts_refused == 0 && f->running && f->script.status_calls == 0 &&
           f->held_calls == 1 && f->held_while_stopped == 0 && f->pauses == 0 && f->now_ms == 0;
}
/* A node still starting answers at the fourth question, 15 s on; the screen names the check meanwhile and nothing stops. */
static int booting_check_test(void)
{
    struct fake f;
    struct wsu w;
    interrupted_with(&f, &w, ZAPP_KIND_RESTORE, SUN_PROBE_NONE, 3);
    f.clock_follows = true;
    f.sample_ms = 2 * ASK_GAP_MS;
    wsu_resume_job(&w);
    assert(w.step == WSU_NO_WALLET && f.held_calls == 4 && f.now_ms == 3 * ASK_GAP_MS && f.stops == 0 && f.starts == 0);
    assert(f.script.status_calls == 0 && f.step_at_sample == WSU_CHECKING && !strcmp(f.line_at_sample, "Checking your wallet - 0:10"));
    wsu_destroy(&w);
    return f.stops;
}
/* With the node running, the check asks the node and never stops or starts it: the node's answer alone decides each step. */
static void running_check_tests(void)
{
    static const struct { enum zapp_setup_kind kind; bool confirmed; enum sun_probe held; enum wsu_step step; enum wsu_failure failure; } cases[] = {
        {ZAPP_KIND_RESTORE, false, SUN_PROBE_NONE, WSU_NO_WALLET, WSU_NO_FAILURE},
        {ZAPP_KIND_CREATE, false, SUN_PROBE_NONE, WSU_NO_WALLET, WSU_NO_FAILURE},
        {ZAPP_KIND_RESTORE, false, SUN_PROBE_PRESENT, WSU_READING, WSU_NO_FAILURE},
        {ZAPP_KIND_CREATE, false, SUN_PROBE_PRESENT, WSU_BLOCKED, WSU_NO_FAILURE},
        {ZAPP_KIND_CREATE, true, SUN_PROBE_PRESENT, WSU_DONE, WSU_NO_FAILURE},
        {ZAPP_KIND_RESTORE, false, SUN_PROBE_UNKNOWN, WSU_BLOCKED, WSU_UNKNOWN},
    };
    struct fake f;
    struct wsu w;
    int stops = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        interrupted_with(&f, &w, cases[i].kind, cases[i].held, 0);
        if (cases[i].confirmed) assert(zapp_setup_mark_confirmed(dir, true));
        wsu_resume_job(&w);
        assert(w.step == cases[i].step && w.failure == cases[i].failure && f.discards == 0 && exists_in(dir, "wallet_key.blob"));
        assert(asked_once_untouched(&f));
        stops += f.stops;
        wsu_destroy(&w);
    }
    stops += booting_check_test();
    printf("  wallet check, node running and answering: %d node stops in %zu opens\n", stops, sizeof(cases) / sizeof(cases[0]) + 1);
}
/* Each question takes the 15 s the command line is given and none is answered. Questions start at 0, 20, 40, 60, 80 and 100 s; the
 * one due at two minutes is not asked, so the datadir is read 1:55 in, not after 24 questions and 7:55. */
static void slow_check_test(void)
{
    struct fake f;
    struct wsu w;
    interrupted_with(&f, &w, ZAPP_KIND_RESTORE, SUN_PROBE_NONE, ASK_TIMES);
    snprintf(f.script.status, sizeof(f.script.status), EMPTY_REPLY);
    f.clock_follows = true;
    f.held_takes_ms = ASK_TAKES_MS;
    wsu_resume_job(&w);
    assert(w.step == WSU_NO_WALLET && f.held_calls == 6 && f.held_while_stopped == 0 && f.now_ms == 6 * ASK_TAKES_MS + 5 * ASK_GAP_MS);
    assert(f.stops == 1 && f.starts == 1 && f.starts_refused == 0 && f.running && f.script.status_calls == 1);
    printf("  wallet check, node running with 15 s silent answers: %d questions, datadir read %lld s in\n", f.held_calls,
           (long long)(f.now_ms / 1000));
    wsu_destroy(&w);
}
/* A running node that gives no answer within the bound is read as before: stopped once, read, started once; with a clock that does
 * not move, the count alone ends the questions. One that exits on its own while it is asked is read without a stop or a start. */
static void silent_check_tests(void)
{
    struct fake f;
    struct wsu w;
    interrupted_with(&f, &w, ZAPP_KIND_RESTORE, SUN_PROBE_NONE, ASK_TIMES);
    snprintf(f.script.status, sizeof(f.script.status), EMPTY_REPLY);
    wsu_resume_job(&w);
    assert(w.step == WSU_NO_WALLET && f.held_calls == ASK_TIMES && f.held_while_stopped == 0 && f.now_ms >= (ASK_TIMES - 1) * ASK_GAP_MS);
    assert(f.stops == 1 && f.starts == 1 && f.starts_refused == 0 && f.running && f.script.status_calls == 1 && f.script.status_while_running == 0);
    printf("  wallet check, node running and silent past the bound: %d node stop, %d start\n", f.stops, f.starts);
    wsu_destroy(&w);

    interrupted_with(&f, &w, ZAPP_KIND_CREATE, SUN_PROBE_NONE, ASK_TIMES);
    f.held_exit_at = 2;
    wsu_resume_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_NO_FAILURE && f.held_calls == 2 && f.held_while_stopped == 0);
    assert(f.stops == 0 && f.starts == 0 && !f.running && f.script.status_calls == 1);
    wsu_destroy(&w);
    slow_check_test();
}
/* With no node running, the datadir is read at once: the node is not asked, stopped or started. */
static void stopped_check_tests(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, false);
    touch("wallet_key.blob");
    zapp_setup_kind_write(dir, ZAPP_KIND_RESTORE);
    wsu_destroy(&w);
    snprintf(f.script.status, sizeof(f.script.status), EMPTY_REPLY);
    f.held_answers = true;
    init_with(&f, &w);
    wsu_resume_job(&w);
    assert(w.step == WSU_NO_WALLET && f.held_calls == 0 && f.stops == 0 && f.starts == 0 && !f.running && f.script.status_calls == 1);
    assert(f.pauses == 0);
    printf("  wallet check, node stopped: %d node stops, %d starts, datadir read %d time\n", f.stops, f.starts, f.script.status_calls);
    wsu_destroy(&w);
}

/* Every set-aside blob is wrapped by the Keystore key, so a failed create after a start over removes only its fresh blob. */
static void key_kept_tests(void)
{
    struct fake f;
    struct wsu w;
    char node_dir[700];
    blocked_create(&f, &w, node_dir);
    assert(wsu_ask_start_over(&w) && w.step == WSU_START_OVER);
    wsu_start_over_job(&w);
    assert(w.step == WSU_CHOICE && holds(dir, "wallet_key.blob.unused-20261101T120000Z", "x") && f.key_deletes == 0);
    f.script.phrase_fail = true;
    create_all(&w);
    assert(w.step == WSU_FAILED && f.discards == 1);
    assert(!exists_in(dir, "wallet_key.blob") && holds(dir, "wallet_key.blob.unused-20261101T120000Z", "x") && f.key_deletes == 0);
    wsu_destroy(&w);

    /* With no other blob the failed create's key is deleted with its blob. */
    fresh(&f, &w, true);
    f.script.phrase_fail = true;
    create_all(&w);
    assert(w.step == WSU_FAILED && f.discards == 1 && f.key_deletes == 1 && !exists_in(dir, "wallet_key.blob"));
    wsu_destroy(&w);
}

static void confirmed_no_start_restart_tests(struct fake *fp);
/* The confirmation is its own record, written when the words match and before the setup marker or the birthday: a confirmed
 * create is never offered Start over, not after a restart and not while the record cannot yet be written. */
static void confirmed_record_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    char block[600];
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED_NO_BIRTHDAY);
    create_all(&w);
    wsu_words_seen(&w);
    wsu_view_read(&w, &v);
    struct zapp_words all;
    assert(zapp_words_parse(PHRASE, &all));
    const char *right[3] = {all.word[v.asked[0]], all.word[v.asked[1]], all.word[v.asked[2]]};
    assert(!zapp_setup_confirmed(dir));
    assert(wsu_confirm(&w, right, 3));
    snprintf(block, sizeof(block), "%s/wallet_setup_confirmed.tmp", dir);
    assert(mkdir(block, 0700) == 0);
    f.pauses = 0;
    wsu_finish_job(&w);
    /* The record could not be written: retried, then reported; nothing later ran. */
    assert(f.pauses > 1);
    assert(w.step == WSU_FAILED && w.failure == WSU_NOT_RECORDED && !zapp_setup_confirmed(dir) && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    assert(rmdir(block) == 0 && wsu_retry_marker(&w));
    wsu_finish_job(&w);
    /* Written before the birthday check: the wallet has no start height, setup stays unfinished, and the record stands. */
    assert(w.step == WSU_FAILED && w.failure == WSU_NO_BIRTHDAY && zapp_setup_confirmed(dir) && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    wsu_destroy(&w);
    confirmed_no_start_restart_tests(&f);
}
/* After a restart the confirmed create finishes its setup again: the record kept no start height, so it says so. Start over is its way
 * forward, and the empty-wallet check still applies. */
/* Start over refused for a reason: back on the no-start-height screen, which names the reason; checking again clears it. */
static void start_over_refused_with(struct fake *f, struct wsu *w, enum wsu_idle idle, bool node_stops, enum wsu_failure reason)
{
    struct wsu_view v;
    f->idle = idle;
    f->stops_when_asked = node_stops;
    assert(wsu_ask_start_over(w));
    wsu_start_over_job(w);
    wsu_view_read(w, &v);
    assert(v.step == WSU_FAILED && v.failure == WSU_NO_BIRTHDAY && v.refusal == reason && f->running);
    f->stops_when_asked = true;
    assert(wsu_recheck(w));
    wsu_resume_job(w);
    wsu_view_read(w, &v);
    assert(v.step == WSU_FAILED && v.failure == WSU_NO_BIRTHDAY && v.refusal == WSU_NO_FAILURE);
}
/* Cancel on the warning that follows a refusal also clears it. */
static void start_over_refusal_cleared_by_cancel(struct fake *f, struct wsu *w)
{
    struct wsu_view v;
    f->idle = WSU_IDLE_FUNDS;
    assert(wsu_ask_start_over(w));
    wsu_start_over_job(w);
    assert(wsu_ask_start_over(w));
    wsu_cancel_start_over(w);
    wsu_view_read(w, &v);
    assert(v.step == WSU_FAILED && v.failure == WSU_NO_BIRTHDAY && v.refusal == WSU_NO_FAILURE);
}
static void confirmed_no_start_restart_tests(struct fake *fp)
{
    struct fake f = *fp;
    struct wsu w;
    struct wsu_view v;
    char node_dir[700];
    fake_of = &f;
    f.script.node_flag = &f.running;
    f.script.hook = fake_hook;
    snprintf(node_dir, sizeof(node_dir), "%s/node", dir);
    assert(mkdir(node_dir, 0700) == 0);
    put(node_dir, "node.db", "chain-and-wallet");
    struct sun node;
    struct sun_runner runner = {&f.script, script_run};
    sun_init(&node, &runner, node_dir);
    struct wsu_env env = {&f, f_wrap, f_discard, f_running, f_control, f_pause, f_random, f_progress, f_protect, f_idle, f_held, f_wall};
    assert(wsu_init(&w, &env, &node, dir) && wsu_open(&w));
    wsu_resume_job(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_NO_BIRTHDAY && !w.birthday.known && w.confirmed);
    wsu_view_read(&w, &v);
    assert(v.may_start_over);
    /* That wallet is new and its record proves no words, so Start over is its way forward; the check that the wallet is empty still applies. */
    assert(wsu_ask_start_over(&w) && w.step == WSU_START_OVER);
    wsu_cancel_start_over(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_NO_BIRTHDAY);
    start_over_refusal_cleared_by_cancel(&f, &w);
    start_over_refused_with(&f, &w, WSU_IDLE_FUNDS, true, WSU_NOT_EMPTY);
    files_untouched(node_dir);
    start_over_refused_with(&f, &w, WSU_IDLE_UNKNOWN, true, WSU_COULD_NOT_CHECK);
    start_over_refused_with(&f, &w, WSU_IDLE_EMPTY, false, WSU_NODE_BUSY);
    files_untouched(node_dir);
    f.idle = WSU_IDLE_EMPTY;
    assert(wsu_ask_start_over(&w));
    wsu_start_over_job(&w);
    assert(w.step == WSU_CHOICE && !w.confirmed && !w.birthday.known && zapp_setup_state(dir) == ZAPP_SETUP_NEEDED && !zapp_setup_confirmed(dir));
    assert(exists_in(dir, "wallet_setup_confirmed.unused-20261101T120000Z") && !exists_in(node_dir, "node.db"));
    wsu_destroy(&w);
}
/* The words matched, the confirmation record was written, the setup marker was not, and the app stopped. After the restart the
 * create finishes: it is not "words never confirmed", it cannot be started over, and an unwritable marker is retried. */
static void confirmed_restart_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    char node_dir[700], block[600];
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    wsu_words_seen(&w);
    wsu_view_read(&w, &v);
    struct zapp_words all;
    assert(zapp_words_parse(PHRASE, &all));
    const char *right[3] = {all.word[v.asked[0]], all.word[v.asked[1]], all.word[v.asked[2]]};
    assert(wsu_confirm(&w, right, 3));
    snprintf(block, sizeof(block), "%s/wallet_setup_done.tmp", dir);
    assert(mkdir(block, 0700) == 0);
    wsu_finish_job(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_NOT_RECORDED && zapp_setup_confirmed(dir) && zapp_setup_confirmed_start(dir));
    wsu_destroy(&w);
    snprintf(node_dir, sizeof(node_dir), "%s/node", dir);
    assert(mkdir(node_dir, 0700) == 0);
    put(node_dir, "node.db", "chain-and-wallet");
    struct sun node;
    struct sun_runner runner = {&f.script, script_run};
    sun_init(&node, &runner, node_dir);
    struct wsu_env env = {&f, f_wrap, f_discard, f_running, f_control, f_pause, f_random, f_progress, f_protect, f_idle, f_held, f_wall};
    /* The marker still cannot be written after the restart: not "words never confirmed", and Save again is offered. */
    assert(wsu_init(&w, &env, &node, dir) && wsu_open(&w));
    wsu_resume_job(&w);
    wsu_view_read(&w, &v);
    assert(w.step == WSU_FAILED && w.failure == WSU_NOT_RECORDED && !v.may_start_over && wsu_retry_marker(&w));
    wsu_destroy(&w);
    assert(rmdir(block) == 0);
    assert(wsu_init(&w, &env, &node, dir) && wsu_open(&w));
    wsu_resume_job(&w);
    assert(w.step == WSU_DONE && zapp_setup_state(dir) == ZAPP_SETUP_READY && f.discards == 0);
    wsu_destroy(&w);
}

/* Start over is offered only for a create; a restore whose node will not stop is not. */
static void start_over_offer_tests(void)
{
    static const enum zapp_setup_kind kinds[2] = {ZAPP_KIND_CREATE, ZAPP_KIND_RESTORE};
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    for (size_t i = 0; i < 2; ++i) {
        fresh(&f, &w, true);
        touch("wallet_key.blob");
        zapp_setup_kind_write(dir, kinds[i]);
        wsu_destroy(&w);
        f.stops_when_asked = false;
        init_with(&f, &w);
        wsu_resume_job(&w);
        wsu_view_read(&w, &v);
        assert(v.step == WSU_BLOCKED && v.failure == WSU_NODE_BUSY && v.may_start_over == (kinds[i] == ZAPP_KIND_CREATE));
        wsu_destroy(&w);
    }
}

/* After a restart the confirmation on disk, not the process, refuses Start over: the words were confirmed. */
static void start_over_refused_after_a_confirmation_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    touch("wallet_key.blob");
    assert(zapp_setup_kind_write(dir, ZAPP_KIND_CREATE) && zapp_setup_mark_confirmed(dir, true));
    wsu_destroy(&w);
    f.stops_when_asked = false;
    init_with(&f, &w);
    wsu_resume_job(&w);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_BLOCKED && !wsu_ask_start_over(&w));
    wsu_view_read(&w, &v);
    assert(v.step == WSU_BLOCKED && v.failure == WSU_ALREADY_CONFIRMED);
    wsu_destroy(&w);
}

/* Start over needs a node that says the wallet holds nothing: current, with shielded keys, and no amounts or transactions. */
static void idle_state_tests(void)
{
    static const struct { const char *text; int state; } summaries[] = {
        {"{\"current\":true,\"shielded_keys\":1,\"spendable_zat\":0,\"pending_zat\":0,\"sending_zat\":0,\"public_zat\":0,\"immature_zat\":0,\"pending_notes\":0}", 1},
        {"{\"current\":false,\"shielded_keys\":1,\"spendable_zat\":0,\"pending_zat\":0,\"sending_zat\":0,\"public_zat\":0,\"immature_zat\":0,\"pending_notes\":0}", -1},
        {"{\"shielded_keys\":1,\"spendable_zat\":0,\"pending_zat\":0,\"sending_zat\":0,\"public_zat\":0,\"immature_zat\":0,\"pending_notes\":0}", -1},
        {"{\"current\":true,\"shielded_keys\":0,\"spendable_zat\":0,\"pending_zat\":0,\"sending_zat\":0,\"public_zat\":0,\"immature_zat\":0,\"pending_notes\":0}", -1},
        {"{\"current\":true,\"spendable_zat\":0,\"pending_zat\":0,\"sending_zat\":0,\"public_zat\":0,\"immature_zat\":0,\"pending_notes\":0}", -1},
        {"{\"current\":true,\"shielded_keys\":1,\"spendable_zat\":5,\"pending_zat\":0,\"sending_zat\":0,\"public_zat\":0,\"immature_zat\":0,\"pending_notes\":0}", 0},
        {"{\"current\":false,\"shielded_keys\":0,\"spendable_zat\":5,\"pending_zat\":0,\"sending_zat\":0,\"public_zat\":0,\"immature_zat\":0,\"pending_notes\":0}", 0},
        {"{\"current\":true,\"shielded_keys\":1,\"spendable_zat\":0}", -1},
    };
    for (size_t i = 0; i < sizeof(summaries) / sizeof(summaries[0]); ++i) {
        struct json_value root = {0};
        assert(json_read(&root, summaries[i].text, strlen(summaries[i].text)));
        assert(wsu_summary_state(&root) == summaries[i].state);
        json_free(&root);
    }
    struct json_value empty = {0}, some = {0}, none = {0};
    assert(json_read(&empty, "{\"sent\":[],\"received\":[]}", strlen("{\"sent\":[],\"received\":[]}")) && wsu_history_state(&empty) == 1);
    assert(json_read(&some, "{\"sent\":[],\"received\":[{\"txid\":\"a\"}]}", strlen("{\"sent\":[],\"received\":[{\"txid\":\"a\"}]}")) && wsu_history_state(&some) == 0);
    assert(json_read(&none, "{\"count\":0}", strlen("{\"count\":0}")) && wsu_history_state(&none) == -1 && wsu_history_state(NULL) == -1);
    json_free(&empty);
    json_free(&some);
    json_free(&none);
}

/* Removing the screen lock invalidates the key that wraps the passphrase, so the words screen says the words are then needed. */
static void screen_lock_notice_test(void)
{
    assert(!strcmp(WSU_SCREEN_LOCK_NOTICE, "If you remove this phone's screen lock, you will need these words to open the wallet again."));
}

/* A marker that cannot be written is retried, and neither path offers the choice again. */
static void marker_retry_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    char block[600];
    snprintf(block, sizeof(block), "%s/wallet_setup_done.tmp", dir);
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    wsu_words_seen(&w);
    wsu_view_read(&w, &v);
    struct zapp_words all;
    assert(zapp_words_parse(PHRASE, &all));
    const char *right[3] = {all.word[v.asked[0]], all.word[v.asked[1]], all.word[v.asked[2]]};
    assert(wsu_confirm(&w, right, 3));
    assert(mkdir(block, 0700) == 0);
    wsu_finish_job(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_NOT_RECORDED && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    wsu_back(&w);
    assert(w.step == WSU_FAILED);
    assert(rmdir(block) == 0);
    assert(wsu_retry_marker(&w) && w.step == WSU_WORKING);
    wsu_finish_job(&w);
    assert(w.step == WSU_DONE && zapp_setup_state(dir) == ZAPP_SETUP_READY);
    assert(!wsu_retry_marker(&w));
    wsu_destroy(&w);

    fresh(&f, &w, true);
    wsu_open_restore(&w);
    script_say(&f.script, true, "{\"ok\":true,\"data\":{\"recovered\":true,\"birthday_recorded\":false}}");
    assert(mkdir(block, 0700) == 0);
    wsu_restore_job(&w, VALID_PHRASE, 0);
    assert(w.step == WSU_FAILED && w.failure == WSU_NOT_RECORDED && zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED && f.starts == 1);
    assert(rmdir(block) == 0);
    assert(wsu_retry_marker(&w));
    wsu_finish_job(&w);
    assert(w.step == WSU_READING && zapp_setup_state(dir) == ZAPP_SETUP_READY);
    wsu_destroy(&w);
}
/* The kind is on disk before the node command runs; a command that never started discards the key and restarts the node. */
static void kind_and_not_run_tests(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    assert(f.kind_at_restore == ZAPP_KIND_CREATE);
    wsu_destroy(&w);
    fresh(&f, &w, true);
    wsu_open_restore(&w);
    script_say(&f.script, true, "{\"ok\":true,\"data\":{\"recovered\":true}}");
    wsu_restore_job(&w, VALID_PHRASE, 0);
    assert(f.kind_at_restore == ZAPP_KIND_RESTORE);
    wsu_destroy(&w);
    fresh(&f, &w, true);
    error_reply(&f.script, "NOT_RUN");
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write_failure == WSU_NOT_RUN && f.discards == 0 && f.running);
    assert(wsu_retry_write(&w));
    wsu_destroy(&w);
}
/* Without every window protection nothing is shown and no wallet is made. */
static void protection_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    wsu_close(&w);
    f.protect_ok = false;
    assert(!wsu_open(&w));
    script_say(&f.script, true, CREATED);
    create_all(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_UNPROTECTED && f.wraps == 0 && f.script.calls == 0);
    wsu_destroy(&w);
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    wsu_view_read(&w, &v);
    assert(v.protected && v.words.count == 24);
    wsu_close(&w);
    wsu_view_read(&w, &v);
    assert(!v.protected && v.words.count == 0 && v.start_height == 0);
    wsu_destroy(&w);
    fresh(&f, &w, true);
    wsu_open_restore(&w);
    wsu_close(&w);
    f.protect_ok = false;
    assert(!wsu_open(&w));
    wsu_restore_job(&w, VALID_PHRASE, 0);
    assert(w.failure == WSU_UNPROTECTED && f.wraps == 0);
    wsu_destroy(&w);
}

/* A confirmation belongs to the key file it was made for. */
static void confirmation_is_tied_to_the_key_file_tests(void)
{
    forget("wallet_setup_confirmed");
    forget("wallet_key.blob");
    assert(!zapp_setup_mark_confirmed(dir, true) && !zapp_setup_confirmed(dir));   /* no key file, nothing to confirm */
    put(dir, "wallet_key.blob", "key-one");
    assert(zapp_setup_mark_confirmed(dir, true) && zapp_setup_confirmed(dir) && zapp_setup_confirmed_start(dir));
    put(dir, "wallet_key.blob", "key-two");   /* the key was replaced: the old confirmation says nothing about this wallet */
    assert(!zapp_setup_confirmed(dir) && !zapp_setup_confirmed_start(dir));
    put(dir, "wallet_key.blob", "key-one");   /* the same key file again */
    assert(zapp_setup_confirmed(dir) && zapp_setup_confirmed_start(dir));
    assert(zapp_setup_mark_confirmed(dir, false) && zapp_setup_confirmed(dir) && !zapp_setup_confirmed_start(dir));
    forget("wallet_key.blob");   /* the key was set aside */
    assert(!zapp_setup_confirmed(dir));
    forget("wallet_setup_confirmed");
}
/* Check again is offered when the node was busy or could not say; the words intro names a start height only when there is one. */
static void recheck_and_intro_tests(void)
{
    static const struct { enum wsu_step step; enum wsu_failure failure; bool offered; } cases[] = {
        {WSU_BLOCKED, WSU_NODE_BUSY, true}, {WSU_BLOCKED, WSU_COULD_NOT_CHECK, true}, {WSU_BLOCKED, WSU_UNKNOWN, true},
        {WSU_FAILED, WSU_UNKNOWN, true}, {WSU_BLOCKED, WSU_NO_FAILURE, false}, {WSU_FAILED, WSU_NODE_BUSY, false},
        {WSU_FAILED, WSU_NOT_RECORDED, false}, {WSU_BLOCKED, WSU_ASIDE_STUCK, false},
    };
    struct wsu_view v = {0};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        v.step = cases[i].step;
        v.failure = cases[i].failure;
        assert(wsu_view_can_recheck(&v) == cases[i].offered);
    }
    char line[400];
    v.start_height = 1234;
    v.birthday_unknown = false;
    wsu_words_intro(&v, line, sizeof(line));
    assert(strstr(line, "start height 1234") && !strstr(line, "did not record"));
    v.start_height = 0;
    v.birthday_unknown = true;
    wsu_words_intro(&v, line, sizeof(line));
    assert(!strstr(line, "start height") && !strstr(line, " 0") && strstr(line, "did not record where it starts"));
}
/* ---- the node needs minutes to exit ---- */

#define STOP_BOUND_MS 180000u
/* A node that takes 60 s to exit once asked: create waits for the process, writes the wallet and shows the words before the node starts. */
/* The node took its 60 s, was stopped once and started once with the words still on screen. */
static bool slow_exit_written(const struct fake *f)
{
    bool node = f->now_ms >= 60000 && f->stops == 1 && f->starts == 1 && f->starts_refused == 0 && f->running && f->create_while_running == 0;
    return node && f->step_at_stop == WSU_WORDS && f->step_at_write == WSU_WORDS && f->script.calls == 1;
}
static void slow_exit_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    f.exit_after_ms = 60000;
    f.watch = true;
    script_say(&f.script, true, RESTORED_TIP);
    wsu_create_job(&w);
    wsu_view_read(&w, &v);
    /* The words are on screen before the node is stopped, started or asked for anything but a phrase. */
    assert(v.step == WSU_WORDS && v.words.count == 24 && v.failure == WSU_NO_FAILURE && v.write == WSU_WRITE_PENDING && v.start_pending);
    assert(f.stops == 0 && f.starts == 0 && f.script.calls == 0 && f.script.phrase_calls == 1 && f.now_ms == 0 && f.running);
    assert(f.phase_key == WSU_PHASE_KEY);
    zapp_words_cleanse(&v.words);
    /* The write follows while the words stay up: the screen is on the words, not on Working, when the node is stopped and written. */
    wsu_write_job(&w);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_WORDS && v.write == WSU_WRITE_DONE && v.start_pending);
    assert(slow_exit_written(&f));
    zapp_words_cleanse(&v.words);
    wsu_destroy(&w);
}
/* The same wait before a restore. */
static void slow_exit_restore_tests(void)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, true);
    f.exit_after_ms = 60000;
    wsu_open_restore(&w);
    script_say(&f.script, true, "{\"ok\":true,\"data\":{\"recovered\":true,\"birthday_recorded\":false,\"birthday_rejected\":false}}");
    wsu_restore_job(&w, VALID_PHRASE, 0);
    assert(w.step != WSU_FAILED && f.now_ms >= 60000 && f.starts == 1 && f.starts_refused == 0 && f.running);
    wsu_destroy(&w);
}

/* A node that outlasts the bound fails the create with NODE_BUSY. It is not started a second time; it is started once it is gone. */
static void stuck_exit_late_tests(void)
{
    struct fake f;
    struct wsu w;
    /* Gone after 250 s: the stop wait gives up at 180 s, and the restart waits for the process and then starts. */
    fresh(&f, &w, true);
    f.exit_after_ms = 250000;
    script_say(&f.script, true, CREATED);
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write == WSU_WRITE_FAILED && w.write_failure == WSU_NODE_BUSY && f.script.calls == 0 && f.discards == 0);
    assert(f.now_ms >= 250000 && f.starts == 1 && f.starts_refused == 0 && f.running);
    wsu_destroy(&w);
}
static void stuck_exit_forever_tests(void)
{
    struct fake f;
    struct wsu w;
    /* Alive through both waits: no start is issued while the old process exists. */
    fresh(&f, &w, true);
    f.exit_after_ms = 4 * STOP_BOUND_MS;
    script_say(&f.script, true, CREATED);
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write_failure == WSU_NODE_BUSY && f.script.calls == 0);
    assert(f.now_ms >= 2 * STOP_BOUND_MS && f.now_ms < 3 * STOP_BOUND_MS && f.starts == 0 && f.starts_refused == 0);
    /* Once the process is gone, the retry writes the same phrase and starts the node. */
    f.now_ms += 4 * STOP_BOUND_MS;
    assert(!f_running(&f));
    f.exit_after_ms = 0;
    assert(wsu_retry_write(&w));
    wsu_write_job(&w);
    assert(w.write == WSU_WRITE_DONE && f.starts == 1 && f.starts_refused == 0 && f.running && f.script.phrase_calls == 1);
    wsu_destroy(&w);
}
static void stuck_exit_resume_tests(void)
{
    struct fake f;
    struct wsu w;
    /* The check after an interrupted setup, the node still exiting at the end of the wait: the node still starts once it is gone. */
    fresh(&f, &w, true);
    touch("wallet_key.blob");
    w.step = WSU_CHECKING;
    f.exit_after_ms = 250000;
    wsu_resume_job(&w);
    assert(w.step == WSU_BLOCKED && w.failure == WSU_NODE_BUSY && f.starts == 1 && f.starts_refused == 0 && f.running);
    wsu_destroy(&w);
}

/* Every way a create or restore fails ends with the node running again when it ran at the start. */
static void failed_jobs_restart_node_tests(void)
{
    static const char *const codes[] = {"DATADIR_LOCKED", "WALLET_ALREADY_PRESENT", "NODE_DB_UNREADABLE", "NOT_RUN", "PASSPHRASE_TOO_SHORT", "CREATE_FAILED", "INVALID_PHRASE"};
    struct fake f;
    struct wsu w;
    for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); ++i) {
        fresh(&f, &w, true);
        f.exit_after_ms = 30000;
        error_reply(&f.script, codes[i]);
        create_all(&w);
        bool there = !strcmp(codes[i], "WALLET_ALREADY_PRESENT");
        assert(there ? (w.step == WSU_BLOCKED && w.write == WSU_WRITE_NONE) : (w.step == WSU_WORDS && w.write == WSU_WRITE_FAILED));
        assert(f.stops == 1 && f.starts == 1 && f.starts_refused == 0 && f.running);
        wsu_destroy(&w);
        fresh(&f, &w, true);
        f.exit_after_ms = 30000;
        wsu_open_restore(&w);
        error_reply(&f.script, codes[i]);
        wsu_restore_job(&w, VALID_PHRASE, 0);
        assert(w.step == (strcmp(codes[i], "CREATE_FAILED") ? WSU_RESTORE_FORM : WSU_FAILED) && f.stops == 1 && f.starts == 1 && f.starts_refused == 0 && f.running);
        wsu_destroy(&w);
    }
}
static void failed_jobs_other_tests(void)
{
    struct fake f;
    struct wsu w;
    /* No answer at all. */
    fresh(&f, &w, true);
    script_say(&f.script, false, "The node did not answer.");
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write_failure == WSU_UNKNOWN && f.starts == 1 && f.running);
    wsu_destroy(&w);
    /* The kind record cannot be written: the node was never asked to stop and keeps running. */
    fresh(&f, &w, true);
    char block[600];
    snprintf(block, sizeof(block), "%s/wallet_setup_kind", dir);
    assert(mkdir(block, 0700) == 0);
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write == WSU_WRITE_FAILED && f.stops == 0 && f.running);
    assert(rmdir(block) == 0);
    wsu_destroy(&w);
    /* The owner declines the screen lock: the node, which was off, is left alone. */
    fresh(&f, &w, false);
    f.wrap_status = ZAPP_DEVKEY_DECLINED;
    create_all(&w);
    assert(w.step == WSU_CHOICE && w.failure == WSU_NO_FAILURE && f.starts == 0 && f.stops == 0 && !f.running);
    wsu_destroy(&w);
}

/* The live line of a sub-step at elapsed seconds. */
static const char *line_at(enum wsu_phase phase, int64_t elapsed, char line[WSU_LINE_MAX])
{
    struct wsu_view v;
    memset(&v, 0, sizeof(v));
    v.phase = phase;
    v.elapsed_s = elapsed;
    wsu_working_line(&v, line, WSU_LINE_MAX);
    return line;
}
/* The live line of each sub-step: what is happening, its clock, and the most the app waits while that is not reached. */
static void working_line_tests(void)
{
    char line[WSU_LINE_MAX];
    assert(!strcmp(line_at(WSU_PHASE_KEY, 5, line), "Confirm with your screen lock - 0:05"));
    assert(!strcmp(line_at(WSU_PHASE_PAUSE, 45, line), "Pausing your node so your wallet can be saved safely - 0:45 (up to 3:00)"));
    assert(!strcmp(line_at(WSU_PHASE_PAUSE, 179, line), "Pausing your node so your wallet can be saved safely - 2:59 (up to 3:00)"));
    assert(!strcmp(line_at(WSU_PHASE_PAUSE, 181, line), "Pausing your node so your wallet can be saved safely - 3:01"));
    assert(!strcmp(line_at(WSU_PHASE_PAUSE_CHECK, 30, line), "Pausing your node so this phone's wallet can be checked safely - 0:30 (up to 3:00)"));
    assert(!strcmp(line_at(WSU_PHASE_PAUSE_ASIDE, 0, line), "Pausing your node so your old wallet can be set aside safely - 0:00 (up to 3:00)"));
    assert(!strcmp(line_at(WSU_PHASE_WRITE, 782, line), "Saving your wallet - 13:02 (up to 15:00)"));
    assert(!strcmp(line_at(WSU_PHASE_WRITE, 900, line), "Saving your wallet - 15:00"));
    assert(!strcmp(line_at(WSU_PHASE_RESTART, 0, line), "Starting your node again - 0:00 (up to 3:00)"));
    assert(!strcmp(line_at(WSU_PHASE_NONE, 2, line), "Getting ready - 0:02"));
    assert(!strcmp(line_at(WSU_PHASE_CHECK, 7, line), "Checking your wallet - 0:07"));
    assert(!strcmp(line_at(WSU_PHASE_ASIDE, 125, line), "Setting aside your old wallet - 2:05"));
    assert(!strcmp(line_at(WSU_PHASE_SAVE, 0, line), "Finishing setup - 0:00"));
    assert(!strcmp(line_at(WSU_PHASE_CHECK, 3725, line), "Checking your wallet - 62:05"));
    assert(!strcmp(line_at(WSU_PHASE_CHECK, -4, line), "Checking your wallet - 0:00"));
    assert(!strcmp(line_at((enum wsu_phase)99, 1, line), "Getting ready - 0:01"));
    struct wsu_view v;
    memset(&v, 0, sizeof(v));
    v.phase = WSU_PHASE_KEY;
    wsu_working_line(&v, line, 12);
    assert(strlen(line) == 11);
}

/* Back says the true thing: the words are shown once while they are held, and a running job goes on without the owner. */
static void leave_notice_tests(void)
{
    struct wsu_view v;
    char line[160];
    memset(&v, 0, sizeof(v));
    v.step = WSU_WORKING;
    wsu_leave_notice(&v, line, sizeof(line));
    assert(!strcmp(line, "Setting up. You can leave the app and come back."));
    v.step = WSU_CHECKING;
    wsu_leave_notice(&v, line, sizeof(line));
    assert(!strcmp(line, "Setting up. You can leave the app and come back."));
    v.step = WSU_WORDS;
    wsu_leave_notice(&v, line, sizeof(line));
    assert(!strcmp(line, "Finish setup first. The recovery words are shown only once."));
    v.step = WSU_CONFIRM;
    wsu_leave_notice(&v, line, sizeof(line));
    assert(strstr(line, "shown only once"));
}

/* Each failure has its own text: one sentence and the action, in plain words, and what each says about the wallet is kept. */
static void failure_text_tests(void)
{
    static const char *const jargon[] = {"datadir", "RPC", "pid", "database", "JSON", "marker", "birthday"};
    for (int a = WSU_DECLINED; a <= WSU_WALLET_THERE; ++a) {
        const char *text = wsu_failure_text((enum wsu_failure)a);
        assert(text[0] && strlen(text) < 200 + (a == WSU_NO_BIRTHDAY ? 40 : 0));
        for (size_t j = 0; j < sizeof(jargon) / sizeof(jargon[0]); ++j) assert(!strstr(text, jargon[j]));
        for (int b = a + 1; b <= WSU_WALLET_THERE; ++b) assert(strcmp(text, wsu_failure_text((enum wsu_failure)b)));
    }
    assert(!strcmp(wsu_failure_text(WSU_NODE_BUSY), "Your node is still stopping. Try again in a minute."));
    assert(strstr(wsu_failure_text(WSU_DECLINED), "Wallet setup was not completed") && strstr(wsu_failure_text(WSU_PRESENT), "Nothing was changed"));
    assert(strstr(wsu_failure_text(WSU_UNKNOWN), "a wallet may have been started"));
    assert(strstr(wsu_failure_text(WSU_NO_BIRTHDAY), "nothing is deleted") && strstr(wsu_failure_text(WSU_ASIDE_STUCK), "Do not create a new wallet"));
    assert(!wsu_failure_text(WSU_NO_FAILURE)[0]);
}

/* After the words are confirmed the screen says Saving and shows nothing of the steps before it. */
static void saving_after_confirm_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    char line[200];
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    assert(w.step == WSU_WORDS);
    wsu_words_seen(&w);
    wsu_view_read(&w, &v);
    struct zapp_words all;
    assert(zapp_words_parse(PHRASE, &all));
    const char *right[3] = {all.word[v.asked[0]], all.word[v.asked[1]], all.word[v.asked[2]]};
    assert(wsu_confirm(&w, right, 3));
    wsu_view_read(&w, &v);
    wsu_working_line(&v, line, sizeof(line));
    assert(v.step == WSU_WORKING && v.phase == WSU_PHASE_SAVE && !strcmp(line, "Finishing setup - 0:00"));
    wsu_destroy(&w);
}

/* ---- the word check by tapping ---- */

static bool on_list(const char *word)
{
    for (size_t i = 0; i < ZAPP_WORDLIST_SIZE; ++i) if (!strcmp(zapp_wordlist[i], word)) return true;
    return false;
}
/* Four different words, the right one once, the three decoys from the wordlist, and the right word's slot drawn at random. */
static void choices_tests(void)
{
    unsigned slots[ZAPP_WORD_CHOICES] = {0};
    char out[ZAPP_WORD_CHOICES][ZAPP_WORD_LETTERS + 1];
    for (unsigned seed = 1; seed <= 400; ++seed) {
        unsigned state = seed * 7919u;
        assert(zapp_words_choices("alpha", counter_random, &state, out));
        unsigned right = 0;
        size_t slot = 0;
        for (size_t i = 0; i < ZAPP_WORD_CHOICES; ++i) {
            assert(out[i][0]);
            if (!strcmp(out[i], "alpha")) { ++right; slot = i; } else assert(on_list(out[i]));
            for (size_t j = i + 1; j < ZAPP_WORD_CHOICES; ++j) assert(strcmp(out[i], out[j]));
        }
        assert(right == 1);
        ++slots[slot];
    }
    for (size_t i = 0; i < ZAPP_WORD_CHOICES; ++i) assert(slots[i] > 40);
    /* A word of the list asked for is never offered twice. */
    for (unsigned seed = 1; seed <= 400; ++seed) {
        unsigned state = seed * 104729u;
        unsigned right = 0;
        assert(zapp_words_choices("zoo", counter_random, &state, out));
        for (size_t i = 0; i < ZAPP_WORD_CHOICES; ++i) right += !strcmp(out[i], "zoo");
        assert(right == 1);
    }
    unsigned state = 3;
    assert(!zapp_words_choices("alpha", failing_random, NULL, out) && !out[0][0] && !out[3][0]);
    assert(!zapp_words_choices("", counter_random, &state, out) && !zapp_words_choices("ninewords", counter_random, &state, out));
    assert(!zapp_words_choices(NULL, counter_random, &state, out));
}

/* Every right word tapped, then Confirm: the setup goes on and nothing of the check stays in the model. */
static void pick_all_right(struct wsu *w, const struct zapp_words *all)
{
    struct wsu_view v;
    wsu_view_read(w, &v);
    for (size_t i = 0; i < ZAPP_WORDS_ASKED; ++i) {
        size_t s = 0;
        while (strcmp(v.choice[i][s], all->word[v.asked[i]])) ++s;
        assert(wsu_pick(w, i, s));
        wsu_view_read(w, &v);
        assert(!strcmp(v.picked[i], all->word[v.asked[i]]) && v.wrong_position == 0);
    }
    assert(wsu_confirm_picked(w) && w->step == WSU_WORKING);
    wsu_view_read(w, &v);
    assert(!v.choice[0][0][0] && !v.picked[0][0] && !wsu_pick(w, 0, 0));
}

/* A random source that fails after a wrong tap leaves the same words on the buttons, never blanks. */
static void pick_random_failure_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    struct zapp_words all;
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    wsu_words_seen(&w);
    wsu_view_read(&w, &v);
    assert(zapp_words_parse(PHRASE, &all));
    size_t slot = 0;
    while (!strcmp(v.choice[1][slot], all.word[v.asked[1]])) ++slot;
    char before[ZAPP_WORD_CHOICES][ZAPP_WORD_LETTERS + 1];
    memcpy(before, v.choice[1], sizeof(before));
    w.env.random = failing_random;
    assert(!wsu_pick(&w, 1, slot));
    wsu_view_read(&w, &v);
    assert(v.mismatches == 1 && v.wrong_position == v.asked[1] + 1 && !memcmp(before, v.choice[1], sizeof(before)));
    wsu_destroy(&w);
}

static bool reject_launch(void *ctx);

/* The check can be answered while the wallet is still being written, but Confirm completes only once the write is done, and a
 * confirm that waits counts no mismatch. */
static void confirm_waits_for_write_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    struct zapp_words all;
    fresh(&f, &w, true);
    script_say(&f.script, true, RESTORED_TIP);
    wsu_create_job(&w);
    wsu_words_seen(&w);
    assert(zapp_words_parse(PHRASE, &all));
    wsu_view_read(&w, &v);
    for (size_t i = 0; i < ZAPP_WORDS_ASKED; ++i) {
        size_t s = 0;
        while (strcmp(v.choice[i][s], all.word[v.asked[i]])) ++s;
        assert(wsu_pick(&w, i, s));
    }
    assert(w.write == WSU_WRITE_PENDING && !wsu_confirm_picked(&w) && w.step == WSU_CONFIRM && w.mismatches == 0 && w.held.count == 24);
    const char *right[3] = {all.word[v.asked[0]], all.word[v.asked[1]], all.word[v.asked[2]]};
    assert(!wsu_confirm(&w, right, 3) && w.step == WSU_CONFIRM && w.mismatches == 0);
    unsigned launches = 0;
    wsu_write_job(&w);
    assert(w.write == WSU_WRITE_DONE && !wsu_launch_confirm(&w, reject_launch, &launches));
    assert(launches == 1 && w.step == WSU_FAILED && w.failure == WSU_NOT_RECORDED && w.confirmed && w.held.count == 0);
    assert(wsu_retry_marker(&w));
    wsu_finish_job(&w);
    assert(w.step == WSU_DONE && zapp_setup_state(dir) == ZAPP_SETUP_READY);
    wsu_destroy(&w);
}

static bool reject_launch(void *ctx) { ++*(unsigned *)ctx; return false; }
static bool accept_launch(void *ctx) { ++*(unsigned *)ctx; return true; }
static void launch_failure_tests(void)
{
    struct wsu w = {0};
    unsigned calls = 0;
    assert(pthread_mutex_init(&w.lock, NULL) == 0);
    w.step = WSU_WORDS; w.write = WSU_WRITE_FAILED; w.write_failure = WSU_UNKNOWN;
    w.held.count = 24; w.phrase.count = 24;
    assert(!wsu_launch_retry_write(&w, reject_launch, &calls));
    assert(calls == 1 && w.write == WSU_WRITE_FAILED && w.write_failure == WSU_UNKNOWN);
    assert(w.held.count == 24 && w.phrase.count == 24);
    assert(wsu_launch_retry_write(&w, accept_launch, &calls));
    assert(calls == 2 && w.write == WSU_WRITE_PENDING);
    assert(!wsu_launch_retry_write(&w, accept_launch, &calls) && calls == 2);
    w.step = WSU_FAILED; w.failure = WSU_NOT_RECORDED; w.confirmed = true; w.held.count = 0;
    assert(!wsu_launch_marker(&w, reject_launch, &calls));
    assert(calls == 3 && w.step == WSU_FAILED && w.failure == WSU_NOT_RECORDED && w.confirmed && !w.held.count);
    assert(wsu_launch_marker(&w, accept_launch, &calls) && calls == 4);
    assert(!wsu_launch_marker(&w, accept_launch, &calls) && calls == 4);
    assert(pthread_mutex_destroy(&w.lock) == 0);
}
static void height_parse_tests(void)
{
    int64_t height = 7;
    assert(wsu_parse_height("", &height) && height == 0);
    height = 7;
    assert(!wsu_parse_height("0", &height) && height == 7);
    assert(!wsu_parse_height("12x", &height) && height == 7);
    assert(!wsu_parse_height("9223372036854775808", &height) && height == 7);
    assert(wsu_parse_height("125", &height) && height == 125);
    assert(wsu_parse_height("9223372036854775807", &height) && height == INT64_MAX);
}

/* ---- the live line of every wait ---- */

/* The right word tapped at every asked position, with no Confirm. */
static void pick_each_right(struct wsu *w, const struct zapp_words *all)
{
    struct wsu_view v;
    wsu_view_read(w, &v);
    for (size_t i = 0; i < ZAPP_WORDS_ASKED; ++i) {
        size_t s = 0;
        while (strcmp(v.choice[i][s], all->word[v.asked[i]])) ++s;
        assert(wsu_pick(w, i, s));
    }
}
/* The create of 2026-11-03 replayed on simulated time: the node takes 2 min 40 s to exit, and the node command that writes the
 * wallet runs 13 min 02 s and ends with no answer. The words stay on screen; the live line names each step with a clock that starts
 * at zero for that step and the most the app waits for it; the end says in plain words what happened and what to tap. */
static void live_line_slow_write_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    f.clock_follows = true;
    f.exit_after_ms = 160000;
    f.sample_ms = 45000;
    f.write_takes_ms = 782000;
    script_say(&f.script, false, "The command timed out.");
    wsu_create_job(&w);
    assert(w.step == WSU_WORDS && w.write == WSU_WRITE_PENDING && !wsu_waiting(&w));
    wsu_write_job(&w);
    assert(f.step_at_sample == WSU_WORDS && f.write_at_sample == WSU_WRITE_RUNNING && f.waiting_at_sample && f.waiting_at_write);
    assert(!strcmp(f.line_at_sample, "Pausing your node so your wallet can be saved safely - 0:45 (up to 3:00)"));
    assert(!strcmp(f.line_at_write, "Saving your wallet - 0:00 (up to 15:00)"));
    assert(!strcmp(f.line_after_write, "Saving your wallet - 13:02 (up to 15:00)"));
    assert(!strcmp(f.line_at_start, "Starting your node again - 0:00 (up to 3:00)"));
    wsu_view_read(&w, &v);
    assert(v.step == WSU_WORDS && v.words.count == 24 && v.write == WSU_WRITE_FAILED && v.write_failure == WSU_UNKNOWN);
    zapp_words_cleanse(&v.words);
    assert(!wsu_waiting(&w) && f.starts == 1 && f.running && f.discards == 0);
    assert(!strcmp(wsu_write_failure_text(v.write_failure),
                   "Saving your wallet stopped before your node answered, so the app cannot tell whether it was saved. Tap Try again."));
    assert(wsu_retry_write(&w) && w.write == WSU_WRITE_PENDING && w.phrase.count == 24);
    wsu_destroy(&w);
}
/* While the wallet behind the words is saved, the check screen says why there is no Confirm yet; once saved, Confirm acts. After a
 * failed write only its own text speaks, and it names the button that is there. */
static void confirm_note_tests(void)
{
    static const char note[] = "All three words are right. Confirm appears here once your wallet is saved.";
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    struct zapp_words all;
    assert(zapp_words_parse(PHRASE, &all));
    fresh(&f, &w, true);
    f.clock_follows = true;
    f.exit_after_ms = 20000;
    f.sample_ms = 10000;
    script_say(&f.script, true, RESTORED_TIP);
    wsu_create_job(&w);
    wsu_words_seen(&w);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_CONFIRM && !wsu_view_confirm_ready(&v) && !wsu_confirm_note(&v)[0]);
    pick_each_right(&w, &all);
    wsu_view_read(&w, &v);
    assert(!wsu_view_confirm_ready(&v) && !strcmp(wsu_confirm_note(&v), note));
    wsu_write_job(&w);
    assert(f.write_at_sample == WSU_WRITE_RUNNING && !f.ready_at_sample && !strcmp(f.note_at_sample, note));
    assert(!strcmp(f.line_at_sample, "Pausing your node so your wallet can be saved safely - 0:10 (up to 3:00)"));
    wsu_view_read(&w, &v);
    assert(v.write == WSU_WRITE_DONE && wsu_view_confirm_ready(&v) && !wsu_confirm_note(&v)[0] && !wsu_waiting(&w));
    wsu_destroy(&w);
    fresh(&f, &w, true);
    error_reply(&f.script, "DATADIR_LOCKED");
    create_all(&w);
    wsu_words_seen(&w);
    pick_each_right(&w, &all);
    wsu_view_read(&w, &v);
    assert(v.write == WSU_WRITE_FAILED && !wsu_view_confirm_ready(&v) && !wsu_confirm_note(&v)[0]);
    assert(!strcmp(wsu_write_failure_text(v.write_failure), "Your node did not pause in time, so your wallet is not saved yet. Tap Try again."));
    wsu_destroy(&w);
}
/* Each failed write says what happened in plain words and the one next step. One a new attempt can clear names Try again; one that
 * would fail the same way names no Try again, says the node keeps running and names Check wallet. None sends the owner
 * to Check again, a button the words and the check do not have, and none says the words cannot be shown while they are on screen. */
static void write_failure_text_tests(void)
{
    static const char *const jargon[] = {"datadir", "RPC", "pid", "database", "JSON", "marker", "birthday", "Check again", "cannot be shown"};
    static const enum wsu_failure own[] = {WSU_NODE_BUSY, WSU_STORAGE, WSU_NOT_RUN, WSU_UNKNOWN, WSU_REFUSED};
    for (size_t i = 0; i < sizeof(own) / sizeof(own[0]); ++i) {
        const char *text = wsu_write_failure_text(own[i]);
        assert(text[0] && strlen(text) < 200);
        if (wsu_write_retryable(own[i])) assert(strstr(text, "Tap Try again") && !strstr(text, "Check wallet"));
        else assert(!strstr(text, "Try again") && strstr(text, "the same way. Your node keeps running. Tap Check wallet."));
        for (size_t j = 0; j < sizeof(jargon) / sizeof(jargon[0]); ++j) assert(!strstr(text, jargon[j]));
        for (size_t k = i + 1; k < sizeof(own) / sizeof(own[0]); ++k) assert(strcmp(text, wsu_write_failure_text(own[k])));
    }
    assert(wsu_write_retryable(WSU_NODE_BUSY) && wsu_write_retryable(WSU_NOT_RUN) && wsu_write_retryable(WSU_UNKNOWN));
    assert(!wsu_write_retryable(WSU_STORAGE) && !wsu_write_retryable(WSU_REFUSED) && !wsu_write_retryable(WSU_BAD_PHRASE));
    assert(!strcmp(wsu_write_failure_text(WSU_BAD_PHRASE), wsu_write_failure_text(WSU_REFUSED)));
    assert(!strcmp(wsu_write_failure_text(WSU_REFUSED), "Your node refused to save your wallet, so nothing was saved, and saving again would be "
                                                        "refused the same way. Your node keeps running. Tap Check wallet."));
    assert(!strcmp(wsu_write_failure_text(WSU_NODE_BUSY), "Your node did not pause in time, so your wallet is not saved yet. Tap Try again."));
    assert(!wsu_write_failure_text(WSU_NO_FAILURE)[0]);
}
/* A write that would fail the same way again offers no Try again that pauses the node: the retry is refused and the node is not
 * paused again, the words stay until the owner takes the way out, and the way out works under the words. */
static void create_failure_repeats_case(const char *code, enum wsu_failure failure)
{
    struct fake f;
    struct wsu w;
    fresh(&f, &w, true);
    error_reply(&f.script, code);
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write == WSU_WRITE_FAILED && w.write_failure == failure);
    assert(f.stops == 1 && f.starts == 1 && f.running && f.discards == 0);
    assert(!wsu_retry_write(&w) && w.write == WSU_WRITE_FAILED && w.held.count == 24 && w.phrase.count == 24);
    wsu_write_job(&w);
    assert(f.stops == 1 && f.starts == 1 && w.write == WSU_WRITE_FAILED);
    assert(wsu_give_up_write(&w) && w.step == WSU_CHECKING && w.held.count == 0 && w.phrase.count == 0 && !w.write_pass[0]);
    wsu_destroy(&w);
}
static void create_failure_repeats_tests(void)
{
    create_failure_repeats_case("NODE_DB_UNREADABLE", WSU_STORAGE);
    create_failure_repeats_case("BIRTHDAY_CONFLICT", WSU_REFUSED);
    create_failure_repeats_case("INVALID_PHRASE", WSU_BAD_PHRASE);
}
/* The check after a restart and Start over each name their own pause, with its clock, while the node exits. */
static void check_and_aside_live_line_tests(void)
{
    struct fake f;
    struct wsu w;
    char node_dir[700];
    fresh(&f, &w, true);
    touch("wallet_key.blob");
    w.step = WSU_CHECKING;
    f.clock_follows = true;
    f.exit_after_ms = 60000;
    f.sample_ms = (ASK_TIMES - 1) * ASK_GAP_MS + 30000;   /* a node that gave no answer, 30 s into its pause */
    wsu_resume_job(&w);
    assert(f.step_at_sample == WSU_CHECKING && f.waiting_at_sample && w.step == WSU_BLOCKED && !wsu_waiting(&w));
    assert(!strcmp(f.line_at_sample, "Pausing your node so this phone's wallet can be checked safely - 0:30 (up to 3:00)"));
    assert(!strcmp(f.line_at_start, "Starting your node again - 0:00 (up to 3:00)"));
    wsu_destroy(&w);
    blocked_create(&f, &w, node_dir);
    f.clock_follows = true;
    f.exit_after_ms = 30000;
    f.sample_ms = 20000;
    assert(wsu_ask_start_over(&w));
    wsu_start_over_job(&w);
    assert(f.step_at_sample == WSU_WORKING && f.waiting_at_sample && w.step == WSU_CHOICE && !wsu_waiting(&w));
    assert(!strcmp(f.line_at_sample, "Pausing your node so your old wallet can be set aside safely - 0:20 (up to 3:00)"));
    wsu_destroy(&w);
}

/* The model offers choices for each asked position, counts a wrong pick, offers new decoys for that position and keeps right picks. */
static void pick_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    assert(w.step == WSU_WORDS);
    wsu_words_seen(&w);
    wsu_view_read(&w, &v);
    struct zapp_words all;
    assert(zapp_words_parse(PHRASE, &all));
    for (size_t i = 0; i < ZAPP_WORDS_ASKED; ++i) {
        unsigned right = 0;
        for (size_t s = 0; s < ZAPP_WORD_CHOICES; ++s) right += !strcmp(v.choice[i][s], all.word[v.asked[i]]);
        assert(right == 1 && !v.picked[i][0]);
    }
    assert(!wsu_confirm_picked(&w) && w.mismatches == 0 && w.step == WSU_CONFIRM);
    /* A wrong tap on the first position: counted, named, answer empty, new decoys with the right word still among them. */
    size_t wrong_slot = 0;
    while (!strcmp(v.choice[0][wrong_slot], all.word[v.asked[0]])) ++wrong_slot;
    char before[ZAPP_WORD_CHOICES][ZAPP_WORD_LETTERS + 1];
    memcpy(before, v.choice[0], sizeof(before));
    assert(!wsu_pick(&w, 0, wrong_slot));
    wsu_view_read(&w, &v);
    assert(v.mismatches == 1 && v.wrong_position == v.asked[0] + 1 && !v.picked[0][0] && memcmp(before, v.choice[0], sizeof(before)));
    unsigned right = 0;
    for (size_t s = 0; s < ZAPP_WORD_CHOICES; ++s) right += !strcmp(v.choice[0][s], all.word[v.asked[0]]);
    assert(right == 1 && w.step == WSU_CONFIRM);
    /* Out of range taps do nothing. */
    assert(!wsu_pick(&w, ZAPP_WORDS_ASKED, 0) && !wsu_pick(&w, 0, ZAPP_WORD_CHOICES));
    wsu_view_read(&w, &v);
    assert(v.mismatches == 1);
    pick_all_right(&w, &all);
    wsu_destroy(&w);
}

/* The sub-steps that follow a start, a wait and a set-aside name what is really going on. */
static void phase_order_tests(void)
{
    struct fake f;
    struct wsu w;
    char node_dir[700];
    /* Start over names the set-aside, not the check before it. */
    blocked_create(&f, &w, node_dir);
    assert(wsu_ask_start_over(&w));
    rename_probe = &w;
    rename_phase = -1;
    wsu_start_over_job(&w);
    rename_probe = NULL;
    assert(w.step == WSU_CHOICE && rename_phase == WSU_PHASE_ASIDE);
    wsu_destroy(&w);
}

/* The local check: a word off the list is named by position, a checksum that fails is refused, both before any node is asked. */
static void check_tests(void)
{
    struct zapp_words w;
    size_t at = 99;
    assert(zapp_words_parse(VALID_PHRASE, &w) && zapp_words_check(&w, &at) == ZAPP_WORDS_OK);
    assert(zapp_words_parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", &w));
    assert(zapp_words_check(&w, &at) == ZAPP_WORDS_CHECKSUM && at == 99);
    assert(zapp_words_parse("abandon abandon abandon zzzz abandon abandon abandon abandon abandon abandon abandon about", &w));
    assert(zapp_words_check(&w, &at) == ZAPP_WORDS_OFF_LIST && at == 3);
    assert(zapp_words_parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", &w) && zapp_words_check(&w, &at) == ZAPP_WORDS_OK);
    assert(zapp_words_parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", &w));
    assert(zapp_words_check(&w, &at) == ZAPP_WORDS_CHECKSUM);
}

/* A restore with a word off the list or a bad checksum stays on the form, and the node and the screen lock are never asked. */
static void restore_check_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    char line[120];
    fresh(&f, &w, true);
    wsu_open_restore(&w);
    wsu_restore_job(&w, "abandon abandon abandon zzzz abandon abandon abandon abandon abandon abandon abandon about", 0);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_RESTORE_FORM && v.failure == WSU_BAD_WORD && v.bad_word == 3 && f.wraps == 0 && f.stops == 0);
    wsu_bad_word_text(v.bad_word, line, sizeof(line));
    assert(!strcmp(line, "Word 4 is not in the recovery word list. Check its spelling.") && !strstr(line, "zzzz"));
    wsu_restore_job(&w, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", 0);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_RESTORE_FORM && v.failure == WSU_BAD_PHRASE && f.wraps == 0 && f.stops == 0);
    assert(!f.script.input[0]);
    wsu_destroy(&w);
}

/* The interrupted-setup screen says a wallet was started only when the probe found one. */
static void interrupted_note_tests(void)
{
    const char *found = wsu_interrupted_note(WSU_NO_FAILURE);
    assert(strstr(found, "A wallet was started on this phone") && strstr(found, "The app cannot show these words again."));
    assert(!strstr(found, "node has no command"));
    assert(!wsu_interrupted_note(WSU_NODE_BUSY)[0] && !wsu_interrupted_note(WSU_COULD_NOT_CHECK)[0]);
    assert(!strstr(wsu_interrupted_note(WSU_UNKNOWN), "wallet was started"));
    assert(strstr(wsu_failure_text(WSU_NODE_BUSY), "Try again in a minute.") && strstr(wsu_failure_text(WSU_COULD_NOT_CHECK), "Try again."));
}

static void resume_needed_tests(void)
{
    struct wsu w = {.lock = PTHREAD_MUTEX_INITIALIZER};
    const enum wsu_step active[] = {WSU_WORKING, WSU_WORDS, WSU_CONFIRM, WSU_CHECKING};
    const enum wsu_step idle[] = {WSU_CHOICE, WSU_RESTORE_FORM, WSU_READING, WSU_DONE, WSU_FAILED, WSU_BLOCKED, WSU_NO_WALLET, WSU_START_OVER};
    for (size_t i = 0; i < sizeof(active) / sizeof(active[0]); ++i) { w.step = active[i]; assert(wsu_resume_needed(&w)); }
    for (size_t i = 0; i < sizeof(idle) / sizeof(idle[0]); ++i) { w.step = idle[i]; assert(!wsu_resume_needed(&w)); }
    w.write = WSU_WRITE_RUNNING; assert(wsu_resume_needed(&w));
    w.write = WSU_WRITE_DONE; assert(!wsu_resume_needed(&w));
    pthread_mutex_destroy(&w.lock);
}

int main(int argc, char **argv)
{
    resume_needed_tests();
    launch_failure_tests();
    height_parse_tests();
    assert(argc == 2);
    dir = argv[1];
    words_tests();
    check_tests();
    state_tests();
    node_tests();
    node_stream_tests();
    node_reply_wipe_tests();
    node_restore_tests();
    node_hash_tests();
    create_tests();
    created_tests();
    create_failure_decline_tests();
    no_hardware_create_test();
    no_hardware_restore_test();
    other_key_refusals_retry_test();
    create_failure_refused_tests();
    create_failure_unknown_tests();
    create_failure_present_after_refusal_tests();
    create_give_up_tests();
    create_give_up_present_tests();
    create_buttons_wait_for_start_test();
    create_words_failure_wipe_test();
    words_first_intro_tests();
    create_failure_busy_tests();
    create_failure_second_tests();
    create_phrase_failure_test();
    create_declined_stops_node_test();
    create_stray_refusal_keeps_key_test();
    create_no_start_tests();
    restore_tests();
    restore_check_tests();
    restore_unknown_tests();
    restore_refusal_form_tests();
    restore_busy_tests();
    restore_blocked_tests();
    resume_create_tests();
    no_wallet_tests();
    resume_unknown_tests();
    marker_retry_tests();
    kind_and_not_run_tests();
    protection_tests();
    field_tests();
    start_over_tests();
    start_over_restore_tests();
    start_over_confirmed_tests();
    start_over_empty_tests();
    start_over_node_tests();
    start_over_undo_tests();
    start_over_stuck_tests();
    probe_meaning_tests();
    summary_wallet_tests();
    running_check_tests();
    silent_check_tests();
    stopped_check_tests();
    key_kept_tests();
    confirmed_record_tests();
    confirmed_restart_tests();
    start_over_offer_tests();
    start_over_refused_after_a_confirmation_tests();
    idle_state_tests();
    confirmation_is_tied_to_the_key_file_tests();
    recheck_and_intro_tests();
    screen_lock_notice_test();
    working_line_tests();
    leave_notice_tests();
    failure_text_tests();
    interrupted_note_tests();
    saving_after_confirm_tests();
    choices_tests();
    pick_tests();
    confirm_waits_for_write_tests();
    live_line_slow_write_tests();
    confirm_note_tests();
    write_failure_text_tests();
    create_failure_repeats_tests();
    check_and_aside_live_line_tests();
    pick_random_failure_tests();
    phase_order_tests();
    slow_exit_tests();
    slow_exit_restore_tests();
    stuck_exit_late_tests();
    stuck_exit_forever_tests();
    stuck_exit_resume_tests();
    failed_jobs_restart_node_tests();
    failed_jobs_other_tests();
    forget("wallet_setup_kind");
    forget("wallet_key.blob");
    forget("wallet_setup_done");
    puts("setup tests ok");
    return 0;
}
