/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SETUP_NODE_H
#define ZAPP_SETUP_NODE_H
#include "setup_words.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The node side of wallet setup: create and restore as typed calls over a command runner. Each request is JSON for the
 * node's standard input, so the passphrase and the words are never in an argument or the environment; each reply is read
 * by its exact shape and its error code is mapped to a typed result. The module performs no I/O of its own, so the tests
 * fake the runner, and it logs nothing. Its buffers are cleansed on every path.
 *
 * Node message text never leaves it: the screens use their own wording for each result. */

#define SUN_ADDRESS_MAX 92
#define SUN_REPLY_MAX 16384
#define SUN_INPUT_MAX 4096
#define SUN_CREATE_TIMEOUT_MS 300000u
#define SUN_RESTORE_TIMEOUT_MS 900000u
#define SUN_QUERY_TIMEOUT_MS 15000u
#define SUN_HASH_HEX 64u
#define SUN_PASSPHRASE_HEX 64u

struct sun_runner {
    void *ctx;
    /* op is "create" or "restore" (input is the request), or "blockhash" or "chaininfo" (input is the JSON-RPC parameter array), or "status" (input is {"datadir":...}). False
     * when the command failed, was killed or was refused; out may still hold a typed error reply or a plain sentence. */
    bool (*run)(void *ctx, const char *op, const char *input, unsigned timeout_ms, char *out, size_t cap);
};
struct sun {
    struct sun_runner runner;
    char datadir[1024];
};
void sun_init(struct sun *node, const struct sun_runner *runner, const char *datadir);

enum sun_result {
    SUN_OK,
    SUN_NODE_RUNNING,      /* DATADIR_LOCKED: a node holds the files. Nothing was written. */
    SUN_ALREADY_PRESENT,   /* WALLET_ALREADY_PRESENT: the datadir holds a wallet. Nothing was written. */
    SUN_INVALID_PHRASE,    /* The words are not a valid recovery phrase. Nothing was written. */
    SUN_STORAGE,           /* NODE_DB_UNREADABLE. Nothing was written. */
    SUN_REFUSED,           /* Any other typed refusal. Nothing was written. */
    SUN_NOT_RUN,           /* The command was never started (node running, spawn failed, app not ready). Nothing was written. */
    SUN_UNKNOWN            /* No usable answer: the wallet may have been written. */
};

struct sun_birthday {
    bool known;
    int64_t height;
    char hash[SUN_HASH_HEX + 1];
};
struct sun_created {
    struct zapp_words words;
    struct sun_birthday birthday;   /* the block the new wallet starts reading at, when the datadir held one */
};
struct sun_restored {
    char first_shielded_address[SUN_ADDRESS_MAX];
    bool birthday_recorded;
    bool birthday_rejected;
};
/* passphrase is SUN_PASSPHRASE_HEX hex characters. out is zero unless the result is SUN_OK. */
enum sun_result sun_create(const struct sun *node, const char *passphrase, struct sun_created *out);
/* A new 24-word phrase from the node. It needs no datadir and no stopped node, and writes nothing; nothing is kept anywhere. */
enum sun_result sun_new_phrase(const struct sun *node, struct zapp_words *out);
/* Only for a phrase generated after the running node release was built. The immutable release anchor stays safe
 * across delayed writes and retries; without a usable anchor the wallet reads from genesis. Restore old phrases normally. */
enum sun_result sun_restore_at_tip(const struct sun *node, const struct zapp_words *words, const char *passphrase, struct sun_restored *out);
/* words is joined with single spaces; birthday may be NULL or unknown. */
enum sun_result sun_restore(const struct sun *node, const struct zapp_words *words, const char *passphrase,
                            const struct sun_birthday *birthday, struct sun_restored *out);
/* The hash of the block at height on the running node's active chain, as 64 hex characters; false when the node has no
 * such block or does not answer. */
bool sun_block_hash(const struct sun *node, int64_t height, char hash[SUN_HASH_HEX + 1]);

enum sun_probe {
    SUN_PROBE_UNKNOWN,   /* The node gave no usable answer. */
    SUN_PROBE_NONE,      /* The datadir holds no wallet. */
    SUN_PROBE_PRESENT    /* The datadir holds a wallet seed, locked or not. */
};
/* Reads the datadir read-only through core wallet recovery status. The command refuses a datadir a running node holds, so the node
 * must be stopped first. Only NO_NODE_DB, or an empty database with no keys, is NONE; NO_WALLET means unreadable and is UNKNOWN. */
enum sun_probe sun_wallet_probe(const struct sun *node);

/* The header and block heights of the running node's active chain; false when the node does not answer. */
bool sun_chain_tip(const struct sun *node, int64_t *headers, int64_t *blocks);

enum sun_creation_state { SUN_CREATION_UNKNOWN, SUN_CREATION_NONE, SUN_CREATION_PREPARED, SUN_CREATION_COMMITTED };
enum sun_result sun_prepare_creation(const struct sun *, struct zapp_words *, char nonce[65]);
enum sun_result sun_commit_creation(const struct sun *, const struct zapp_words *, const char *, const char *, struct sun_restored *);
enum sun_creation_state sun_creation_status(const struct sun *, char nonce[65]);
#endif
