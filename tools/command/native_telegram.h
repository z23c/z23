/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Telegram bot client internals shared by the ops.telegram leaves:
 * credentials file, outbound text guard, chunking, poll state and transport. */
#ifndef ZCL_TOOLS_NATIVE_TELEGRAM_H
#define ZCL_TOOLS_NATIVE_TELEGRAM_H

#include "json/json.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct zcl_command_reply;

#define TG_TOKEN_MAX 80
#define TG_ALLOW_MAX 16
#define TG_PATH_MAX 1100
/* Telegram counts a message in UTF-16 code units; one send never exceeds this. */
#define TG_CHUNK_UNITS 4096u
/* Largest text one send accepts: four full chunks fit the input frame. */
#define TG_TEXT_MAX 12000u
#define TG_KEY_MAX 64u
#define TG_PENDING_MAX 32768u
#define TG_INBOX_ENCODED_TEXT_MAX 7000u
#define TG_INBOX_TEXT_MAX 3000u
#define TG_INBOX_USERNAME_MAX 128u

struct tg_config {
    char token[TG_TOKEN_MAX];
    bool has_chat;
    int64_t chat_id;
    int64_t allow[TG_ALLOW_MAX];
    size_t allow_count;
};

enum tg_load { TG_LOAD_OK = 0, TG_LOAD_MISSING, TG_LOAD_NOT_PRIVATE, TG_LOAD_INVALID };

/* Credentials: Z23_TELEGRAM_ENV, else $HOME/.config/z23/telegram.env. */
bool tg_credentials_path(char *out, size_t cap);
/* Opens without following links, refuses a file with any group or other
 * permission bit or a foreign owner, then parses it with tg_parse_env. */
enum tg_load tg_credentials_load(const char *path, struct tg_config *cfg);
bool tg_parse_env(const char *text, struct tg_config *cfg);
bool tg_token_valid(const char *token);
bool tg_parse_i64(const char *text, size_t len, int64_t *out);
bool tg_allowed(const struct tg_config *cfg, int64_t user_id);

/* Extended keys, Sapling secrets, WIF keys and BIP-39 phrases; best effort. */
const char *tg_wallet_secret_refusal(const char *text);
/* Case-insensitive substring test; needle must be lowercase. */
bool tg_icontains(const char *hay, const char *needle);
/* NULL when the text may leave the host, else a plain reason. */
const char *tg_secret_refusal(const char *text, const char *token);
bool tg_utf8_valid(const char *text, size_t len);
/* Byte length of the longest prefix of text that fits one message. */
size_t tg_chunk_len(const char *text, size_t len);

/* State directory under platform_state_root(), created owner-private. */
bool tg_state_dir(char *out, size_t cap);
/* Write data to path through a 0600 temporary file and rename. */
bool tg_atomic_write_private(const char *path, const char *data, size_t len);
bool tg_offset_load(const char *dir, const char *token, int64_t *offset);
bool tg_offset_store(const char *dir, const char *token, int64_t offset);
/* Private reliable inbox batch; 1 read, 0 absent, -1 unavailable. */
int tg_pending_read(const char *dir, const char *token, char *out, size_t cap);
bool tg_pending_write(const char *dir, const char *token, const char *data, size_t len);
bool tg_pending_delete(const char *dir, const char *token);
bool tg_state_sync(const char *dir);
bool tg_batch_save(const struct tg_config *cfg, const char *dir, int64_t group,
                   const struct json_value *data, char receipt[65]);
bool tg_batch_validate(const struct tg_config *cfg, int64_t group,
                       const struct json_value *record, int64_t *next);
size_t tg_encoded_cut(const char *text, size_t limit);
bool tg_inbox_options_valid(const struct tg_config *cfg, const struct json_value *r,
                            const struct json_value *g, const struct json_value *a,
                            bool reliable, int64_t group, const char *ack);
bool tg_inbox_item(struct json_value *item, int64_t update_id, const struct json_value *msg,
                   size_t *bytes, bool reliable);
/* The request hash binds chat, text and optional reply parent; zero preserves
 * the historical no-reply hash. Hash is 32 hex characters. */
#define TG_HASH_HEX 33
void tg_request_hash(int64_t chat_id, const char *text, int64_t reply_to, char hash[TG_HASH_HEX]);
enum tg_sent { TG_SENT_NONE = 0, TG_SENT_SAME, TG_SENT_DIFFERENT };
enum tg_sent tg_sent_lookup(const char *dir, const char *key, const char *hash,
                            bool require_bound, int64_t *first_id, int64_t *count);
bool tg_sent_record(const char *dir, const char *key, const char *hash, int64_t first_id,
                    int64_t count);
bool tg_key_valid(const char *key);

/* Transport. A response body is NUL-terminated and owned by the caller. */
struct tg_response {
    int status;
    char *body;
    size_t len;
};
typedef bool (*tg_transport_fn)(void *ctx, const char *token, const char *method,
                                const char *body, int timeout_s, struct tg_response *out);
void tg_transport_override(tg_transport_fn fn, void *ctx);
bool tg_call(const char *token, const char *method, const char *body, int timeout_s,
             struct tg_response *out);
bool tg_transport_curl(void *ctx, const char *token, const char *method, const char *body,
                       int timeout_s, struct tg_response *out);
void tg_response_free(struct tg_response *response);

/* Validates and stores the credentials text from stdin, replying on reply. */
void tg_configure_text(const char *text, struct zcl_command_reply *reply);

enum tg_api { TG_API_OK = 0, TG_API_CONFLICT, TG_API_RATE_LIMITED, TG_API_UNAUTHORIZED,
              TG_API_REJECTED, TG_API_MALFORMED };
/* Parses a Bot API envelope into doc (caller frees). On a non-ok answer
 * desc receives Telegram's description with any token occurrence removed. */
enum tg_api tg_api_parse(const struct tg_response *response, const char *token,
                         struct json_value *doc, char *desc, size_t desc_cap);

#endif
