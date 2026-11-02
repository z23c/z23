/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "setup_node.h"
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
    bool running, stops_when_asked;
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
};
static struct fake *fake_of;
static struct wsu *model_of;
static bool fake_hook(struct script *s, const char *op)
{
    struct fake *f = fake_of;
    if (!strcmp(op, "restore") && f->watch) f->step_at_write = (int)model_of->step;
    if (!strcmp(op, "create")) { f->create_while_running += f->running; f->kind_at_create = (int)zapp_setup_kind_read(dir); }
    if (!strcmp(op, "restore")) { f->restore_while_running += f->running; f->kind_at_restore = (int)zapp_setup_kind_read(dir); }
    return s->ran_ok;
}
static enum zapp_devkey_status f_wrap(void *ctx, uint8_t secret[ZAPP_DEVKEY_SECRET])
{
    struct fake *f = ctx;
    ++f->wraps;
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
    ++f->pauses;
    f->now_ms += ms;
}
static bool f_random(void *ctx, uint8_t *out, size_t len) { return counter_random(&((struct fake *)ctx)->random_state, out, len); }
static bool f_protect(void *ctx, bool on)
{
    (void)on;
    return ((struct fake *)ctx)->protect_ok;
}
static enum wsu_idle f_idle(void *ctx) { return ((struct fake *)ctx)->idle; }
static int64_t f_wall(void *ctx) { return 1793534400 + ((struct fake *)ctx)->wall_offset; }
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
    struct wsu_env env = {f, f_wrap, f_discard, f_running, f_control, f_pause, f_random, f_progress, f_protect, f_idle, f_wall};
    model_of = w;
    assert(wsu_init(w, &env, &node, dir));
    assert(wsu_open(w));
}

/* The create as the app runs it: the words first, then the wallet written behind them. */
static void create_all(struct wsu *w)
{
    wsu_create_job(w);
    wsu_write_job(w);
}
static void create_tests(void)
{
    struct fake f;
    struct wsu w;
    struct wsu_view v;
    fresh(&f, &w, true);
    assert(w.step == WSU_CHOICE);
    script_say(&f.script, true, CREATED);
    create_all(&w);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_WORDS && v.words.count == 24 && !strcmp(v.words.word[0], "alpha"));
    assert(v.write == WSU_WRITE_DONE && !v.start_pending);
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
    wsu_finish_job(&w);
    assert(w.step == WSU_DONE);
    wsu_destroy(&w);

}
static void create_failure_decline_tests(void)
{
    struct fake f;
    struct wsu w;
    /* The owner declines: no node call, no key to discard, back to a failed state. */
    fresh(&f, &w, true);
    f.wrap_status = ZAPP_DEVKEY_DECLINED;
    create_all(&w);
    assert(w.step == WSU_FAILED && w.failure == WSU_DECLINED && f.script.calls == 0 && f.stops == 0);
    wsu_back(&w);
    assert(w.step == WSU_CHOICE);
    f.wrap_status = ZAPP_DEVKEY_NO_SCREEN_LOCK;
    create_all(&w);
    assert(w.failure == WSU_NO_SCREEN_LOCK);
    wsu_destroy(&w);
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
    /* The node refuses the write: the words stay, the key stays, the node runs, and the same phrase is written on a retry. */
    fresh(&f, &w, true);
    error_reply(&f.script, "WALLET_ALREADY_PRESENT");
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write == WSU_WRITE_FAILED && w.write_failure == WSU_PRESENT && f.discards == 0 && f.running && f.starts == 1);
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
    /* No usable answer: the wallet may exist. The key stays, the node (which was off) is started to sync, and a later "present" is ours. */
    fresh(&f, &w, false);
    script_say(&f.script, false, "The node did not answer.");
    create_all(&w);
    assert(w.step == WSU_WORDS && w.write_failure == WSU_UNKNOWN && f.discards == 0 && f.running);
    assert(zapp_setup_state(dir) == ZAPP_SETUP_INTERRUPTED);
    error_reply(&f.script, "WALLET_ALREADY_PRESENT");
    assert(wsu_retry_write(&w));
    wsu_write_job(&w);
    assert(w.write == WSU_WRITE_DONE && w.birthday.known);
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
    assert(w.step == WSU_FAILED && w.failure == WSU_DECLINED && f.starts == 0 && f.stops == 0 && !f.running && f.script.phrase_calls == 0);
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
    wsu_restore_job(&w, PHRASE, 2999000);
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
    wsu_restore_job(&w, PHRASE, 0);
    wsu_view_read(&w, &v);
    assert(v.step == WSU_READING && v.birthday_unknown && v.birthday_dropped && !strstr(f.script.input, "birthday\""));
    wsu_destroy(&w);

    /* The node refuses the words: the key goes, the node runs again, the owner can edit. */
    fresh(&f, &w, true);
    wsu_open_restore(&w);
    error_reply(&f.script, "INVALID_PHRASE");
    wsu_restore_job(&w, PHRASE, 0);
    assert(w.step == WSU_FAILED && w.failure == WSU_BAD_PHRASE && f.discards == 1 && f.running);
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
    wsu_restore_job(&w, PHRASE, 0);
    assert(w.failure == WSU_NODE_BUSY && f.script.calls == 0 && f.restore_while_running == 0);
    wsu_destroy(&w);

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
    struct wsu_env env = {f, f_wrap, f_discard, f_running, f_control, f_pause, f_random, f_progress, f_protect, f_idle, f_wall};
    assert(wsu_init(w, &env, &node, dir) && wsu_open(w));
    wsu_resume_job(w);
    assert(w->step == WSU_BLOCKED && w->failure == WSU_NO_FAILURE);
    f->stops = f->starts = 0;   /* the read stopped and restarted the node; count what follows */
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
    struct wsu_env env = {f, f_wrap, f_discard, f_running, f_control, f_pause, f_random, f_progress, f_protect, f_idle, f_wall};
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
 * wallet (NO_WALLET) is not known and keeps everything. The node is stopped for the read and started again after. */
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
    struct wsu_env env = {&f, f_wrap, f_discard, f_running, f_control, f_pause, f_random, f_progress, f_protect, f_idle, f_wall};
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
    struct wsu_env env = {&f, f_wrap, f_discard, f_running, f_control, f_pause, f_random, f_progress, f_protect, f_idle, f_wall};
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
    wsu_restore_job(&w, PHRASE, 0);
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
    wsu_restore_job(&w, PHRASE, 0);
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
    wsu_restore_job(&w, PHRASE, 0);
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
    assert(v.step == WSU_WORDS && v.write == WSU_WRITE_DONE && !v.start_pending);
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
    wsu_restore_job(&w, PHRASE, 0);
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
        assert(w.step == WSU_WORDS && w.write == WSU_WRITE_FAILED && f.stops == 1 && f.starts == 1 && f.starts_refused == 0 && f.running);
        wsu_destroy(&w);
        fresh(&f, &w, true);
        f.exit_after_ms = 30000;
        wsu_open_restore(&w);
        error_reply(&f.script, codes[i]);
        wsu_restore_job(&w, PHRASE, 0);
        assert(w.step == WSU_FAILED && f.stops == 1 && f.starts == 1 && f.starts_refused == 0 && f.running);
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
    assert(w.failure == WSU_DECLINED && f.starts == 0 && f.stops == 0 && !f.running);
    wsu_destroy(&w);
}

/* The text of each sub-step, as the working screen shows it. */
static void working_line_tests(void)
{
    struct wsu_view v;
    char line[320];
    memset(&v, 0, sizeof(v));
    v.phase = WSU_PHASE_KEY;
    wsu_working_line(&v, line, sizeof(line));
    assert(!strcmp(line, "Confirm with your screen lock"));
    v.phase = WSU_PHASE_PAUSE;
    wsu_working_line(&v, line, sizeof(line));
    assert(!strcmp(line, "Pausing your node to write the new wallet… (under a minute)"));
    v.phase = WSU_PHASE_WRITE;
    wsu_working_line(&v, line, sizeof(line));
    assert(!strcmp(line, "Writing your wallet…"));
    v.phase = WSU_PHASE_RESTART;
    wsu_working_line(&v, line, sizeof(line));
    assert(!strcmp(line, "Starting your node again…"));
    v.phase = WSU_PHASE_NONE;
    wsu_working_line(&v, line, sizeof(line));
    assert(!strcmp(line, "Starting…"));
    v.phase = WSU_PHASE_SAVE;
    wsu_working_line(&v, line, sizeof(line));
    assert(!strcmp(line, "Saving…"));
    v.phase = WSU_PHASE_ASIDE;
    wsu_working_line(&v, line, sizeof(line));
    assert(!strcmp(line, "Setting aside your old wallet…"));
    v.phase = WSU_PHASE_KEY;
    wsu_working_line(&v, line, 12);
    assert(strlen(line) == 11);
    v.phase = WSU_PHASE_NONE;
    v.elapsed_s = 7;
    wsu_elapsed_text(&v, line, sizeof(line));
    assert(!strcmp(line, "7 s since setup began"));
    v.elapsed_s = 125;
    wsu_elapsed_text(&v, line, sizeof(line));
    assert(!strcmp(line, "2 min 05 s since setup began"));
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
    for (int a = WSU_DECLINED; a <= WSU_UNPROTECTED; ++a) {
        const char *text = wsu_failure_text((enum wsu_failure)a);
        assert(text[0] && strlen(text) < 200 + (a == WSU_NO_BIRTHDAY ? 40 : 0));
        for (size_t j = 0; j < sizeof(jargon) / sizeof(jargon[0]); ++j) assert(!strstr(text, jargon[j]));
        for (int b = a + 1; b <= WSU_UNPROTECTED; ++b) assert(strcmp(text, wsu_failure_text((enum wsu_failure)b)));
    }
    assert(!strcmp(wsu_failure_text(WSU_NODE_BUSY), "Your node is still stopping. Try again in a minute."));
    assert(strstr(wsu_failure_text(WSU_DECLINED), "nothing was changed") && strstr(wsu_failure_text(WSU_PRESENT), "Nothing was changed"));
    assert(strstr(wsu_failure_text(WSU_UNKNOWN), "a wallet may have been started") && strstr(wsu_failure_text(WSU_NO_TIP), "keeps syncing"));
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
    assert(v.step == WSU_WORKING && v.phase == WSU_PHASE_SAVE && !strcmp(line, "Saving…"));
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
    wsu_write_job(&w);
    assert(w.write == WSU_WRITE_DONE && wsu_confirm_picked(&w) && w.step == WSU_WORKING && w.held.count == 0);
    wsu_finish_job(&w);
    assert(w.step == WSU_DONE && zapp_setup_state(dir) == ZAPP_SETUP_READY);
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

int main(int argc, char **argv)
{
    assert(argc == 2);
    dir = argv[1];
    words_tests();
    state_tests();
    node_tests();
    node_stream_tests();
    node_reply_wipe_tests();
    node_restore_tests();
    node_hash_tests();
    create_tests();
    create_failure_decline_tests();
    create_failure_refused_tests();
    create_failure_unknown_tests();
    create_failure_busy_tests();
    create_failure_second_tests();
    create_phrase_failure_test();
    create_declined_stops_node_test();
    create_stray_refusal_keeps_key_test();
    create_no_start_tests();
    restore_tests();
    restore_unknown_tests();
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
    saving_after_confirm_tests();
    choices_tests();
    pick_tests();
    confirm_waits_for_write_tests();
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
