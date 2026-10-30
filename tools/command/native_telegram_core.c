/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Telegram credentials file, outbound text guard and message chunking. */
#include "command/native_telegram.h"
#include "base/cleanse.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define TG_ENV_MAX 4096u

bool tg_credentials_path(char *out, size_t cap)
{
    const char *override_path = getenv("Z23_TELEGRAM_ENV");
    if (override_path && override_path[0])
        return (size_t)snprintf(out, cap, "%s", override_path) < cap;
    const char *home = getenv("HOME");
    return home && home[0] && (size_t)snprintf(out, cap, "%s/.config/z23/telegram.env", home) < cap;
}

static bool tg_token_char(char c)
{
    return isalnum((unsigned char)c) || c == '_' || c == '-';
}

bool tg_token_valid(const char *token)
{
    size_t digits = 0, tail = 0;
    if (!token)
        return false;
    while (isdigit((unsigned char)token[digits]))
        digits++;
    if (digits < 5 || digits > 16 || token[digits] != ':')
        return false;
    while (token[digits + 1 + tail] && tg_token_char(token[digits + 1 + tail]))
        tail++;
    return token[digits + 1 + tail] == '\0' && tail >= 20 && tail <= 64 &&
           digits + 1 + tail < TG_TOKEN_MAX;
}

bool tg_parse_i64(const char *text, size_t len, int64_t *out)
{
    size_t i = 0;
    int64_t value = 0;
    bool negative = len > 0 && text[0] == '-';
    if (negative)
        i = 1;
    if (len == i || len - i > 18)
        return false;
    for (; i < len; i++) {
        if (!isdigit((unsigned char)text[i]))
            return false;
        value = value * 10 + (text[i] - '0');
    }
    *out = negative ? -value : value;
    return true;
}

bool tg_allowed(const struct tg_config *cfg, int64_t user_id)
{
    if (cfg->has_chat && cfg->chat_id == user_id)
        return true;
    for (size_t i = 0; i < cfg->allow_count; i++) {
        if (cfg->allow[i] == user_id)
            return true;
    }
    return false;
}

static bool tg_parse_allow(const char *value, size_t len, struct tg_config *cfg)
{
    size_t at = 0;
    while (at < len) {
        const char *comma = memchr(value + at, ',', len - at);
        size_t end = comma ? (size_t)(comma - value) : len;
        size_t a = at, b = end;
        while (a < b && value[a] == ' ')
            a++;
        while (b > a && value[b - 1] == ' ')
            b--;
        if (b > a) {
            if (cfg->allow_count >= TG_ALLOW_MAX ||
                !tg_parse_i64(value + a, b - a, &cfg->allow[cfg->allow_count]))
                return false;
            cfg->allow_count++;
        }
        at = end + 1;
    }
    return true;
}

static bool tg_apply_field(struct tg_config *cfg, const char *key, size_t key_len,
                           const char *value, size_t len)
{
    if (key_len == 18 && !memcmp(key, "TELEGRAM_BOT_TOKEN", 18)) {
        if (len == 0 || len >= sizeof(cfg->token))
            return false;
        memcpy(cfg->token, value, len);
        cfg->token[len] = '\0';
        return tg_token_valid(cfg->token);
    }
    if (key_len == 16 && !memcmp(key, "TELEGRAM_CHAT_ID", 16)) {
        cfg->has_chat = tg_parse_i64(value, len, &cfg->chat_id);
        return cfg->has_chat;
    }
    if (key_len == 19 && !memcmp(key, "TELEGRAM_ALLOW_FROM", 19))
        return tg_parse_allow(value, len, cfg);
    return true;
}

static bool tg_blank(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

static bool tg_quoted(const char *value, size_t len)
{
    return len >= 2 && (value[0] == '"' || value[0] == '\'') && value[len - 1] == value[0];
}

/* One KEY=VALUE line, optional `export ` prefix and one pair of quotes. */
static bool tg_parse_line(const char *line, size_t len, struct tg_config *cfg)
{
    while (len && tg_blank(*line)) {
        line++;
        len--;
    }
    while (len && tg_blank(line[len - 1]))
        len--;
    if (len == 0 || line[0] == '#')
        return true;
    if (len > 7 && !memcmp(line, "export ", 7)) {
        line += 7;
        len -= 7;
    }
    const char *eq = memchr(line, '=', len);
    if (!eq)
        return false;
    const char *value = eq + 1;
    size_t vlen = len - (size_t)(eq + 1 - line);
    if (tg_quoted(value, vlen)) {
        value++;
        vlen -= 2;
    }
    return tg_apply_field(cfg, line, (size_t)(eq - line), value, vlen);
}

bool tg_parse_env(const char *text, struct tg_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    for (const char *at = text; *at;) {
        const char *nl = strchr(at, '\n');
        size_t len = nl ? (size_t)(nl - at) : strlen(at);
        if (!tg_parse_line(at, len, cfg)) {
            memory_cleanse(cfg, sizeof(*cfg));
            return false;
        }
        at += len + (nl ? 1 : 0);
    }
    if (!cfg->token[0]) {
        memory_cleanse(cfg, sizeof(*cfg));
        return false;
    }
    return true;
}

#if !defined(_WIN32)
static bool tg_read_all(int fd, char *buf, size_t cap)
{
    size_t used = 0;
    for (;;) {
        ssize_t n = read(fd, buf + used, cap - 1 - used);
        if (n < 0)
            return false;
        if (n == 0)
            break;
        used += (size_t)n;
        if (used >= cap - 1)
            return false;
    }
    buf[used] = '\0';
    return true;
}

static enum tg_load tg_load_file(const char *path, struct tg_config *cfg)
{
    char buf[TG_ENV_MAX + 1];
    struct stat st;
    memset(cfg, 0, sizeof(*cfg));
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
    if (fd < 0)
        return errno == ENOENT ? TG_LOAD_MISSING : TG_LOAD_INVALID;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 077) != 0) {
        close(fd);
        return TG_LOAD_NOT_PRIVATE;
    }
    bool ok = tg_read_all(fd, buf, sizeof(buf)) && tg_parse_env(buf, cfg);
    close(fd);
    memory_cleanse(buf, sizeof(buf));
    return ok ? TG_LOAD_OK : TG_LOAD_INVALID;
}
#else
static enum tg_load tg_load_file(const char *path, struct tg_config *cfg)
{
    (void)path;
    memset(cfg, 0, sizeof(*cfg));
    return TG_LOAD_MISSING;
}
#endif

enum tg_load tg_credentials_load(const char *path, struct tg_config *cfg)
{
    return tg_load_file(path, cfg);
}

/* ── outbound guard ──────────────────────────────────────────────────── */

bool tg_icontains(const char *hay, const char *needle)
{
    size_t n = strlen(needle);
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < n && hay[i] && tolower((unsigned char)hay[i]) == needle[i])
            i++;
        if (i == n)
            return true;
    }
    return false;
}

static size_t tg_run(const char *s, int (*pred)(int))
{
    size_t n = 0;
    while (s[n] && pred((unsigned char)s[n]))
        n++;
    return n;
}

static int tg_is_digit(int c) { return c >= '0' && c <= '9'; }
static int tg_is_alnum(int c) { return isalnum(c) != 0; }
static int tg_is_hex(int c) { return isxdigit(c) != 0; }
static int tg_is_token_byte(int c) { return tg_token_char((char)c); }
static int tg_is_word_byte(int c) { return isalnum(c) || c == '-' || c == '_' || c == '.'; }

/* <digits>:<token bytes>, the Bot API token shape. */
static bool tg_bot_token_shape(const char *s)
{
    size_t digits = tg_run(s, tg_is_digit);
    return digits >= 6 && digits <= 16 && s[digits] == ':' &&
           tg_run(s + digits + 1, tg_is_token_byte) >= 30;
}

/* Vendor key prefixes shared with the engine scrubber and the fleet steer
 * guard, and the <32+ hex>.<16+ alnum> two-part key of the mail guard. */
static bool tg_api_key_shape(const char *s)
{
    static const char *const prefixes[] = {
        "sk-", "xai-", "gsk_", "sk_live_", "ghp_", "gho_", "ghs_", "github_pat_",
        "glpat-", "AKIA",
    };
    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        if (!strncmp(s, prefixes[i], strlen(prefixes[i])) && tg_run(s, tg_is_word_byte) >= 20)
            return true;
    }
    size_t hex = tg_run(s, tg_is_hex);
    return hex >= 32 && s[hex] == '.' && tg_run(s + hex + 1, tg_is_alnum) >= 16;
}

static bool tg_bearer_shape(const char *s)
{
    return !strncmp(s, "Bearer ", 7) && tg_run(s + 7, tg_is_word_byte) >= 16;
}

static bool tg_has_shape(const char *text)
{
    for (size_t i = 0; text[i]; i++) {
        if (i > 0 && isalnum((unsigned char)text[i - 1]))
            continue;
        if (tg_bot_token_shape(text + i) || tg_api_key_shape(text + i) ||
            tg_bearer_shape(text + i))
            return true;
    }
    return false;
}

const char *tg_secret_refusal(const char *text, const char *token)
{
    static const char *const marks[] = {
        "private key", "private-key", "privkey", "secret key", "mnemonic",
        "seed phrase", "ssh key", "spending key", "spending-key", "secret-extended-key",
    };
    if (token && token[0] && strstr(text, token))
        return "text contains the bot token";
    if (tg_icontains(text, ".onion"))
        return "text mentions an onion address";
    for (size_t i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
        if (tg_icontains(text, marks[i]))
            return "text mentions a private key, seed phrase or mnemonic";
    }
    if (tg_has_shape(text))
        return "text contains a bot token or API key";
    return tg_wallet_secret_refusal(text);
}

/* ── UTF-8 and chunking ──────────────────────────────────────────────── */

static size_t tg_utf8_need(unsigned lead)
{
    if (lead < 0x80)
        return 1;
    if (lead >= 0xC2 && lead <= 0xDF)
        return 2;
    if (lead >= 0xE0 && lead <= 0xEF)
        return 3;
    return lead >= 0xF0 && lead <= 0xF4 ? 4 : 0;
}

/* Rejects overlong forms, surrogates and code points past U+10FFFF. */
static bool tg_utf8_second_ok(unsigned lead, unsigned second)
{
    return !((lead == 0xE0 && second < 0xA0) || (lead == 0xED && second > 0x9F) ||
             (lead == 0xF0 && second < 0x90) || (lead == 0xF4 && second > 0x8F));
}

/* Length of the well-formed sequence at s, or 0. */
static size_t tg_utf8_seq(const unsigned char *s, size_t rem)
{
    unsigned lead = s[0];
    size_t need = tg_utf8_need(lead);
    if (need == 0 || need > rem)
        return 0;
    for (size_t i = 1; i < need; i++) {
        if ((s[i] & 0xC0) != 0x80)
            return 0;
    }
    return tg_utf8_second_ok(lead, need > 1 ? s[1] : 0) ? need : 0;
}

bool tg_utf8_valid(const char *text, size_t len)
{
    for (size_t i = 0; i < len;) {
        size_t n = tg_utf8_seq((const unsigned char *)text + i, len - i);
        if (n == 0 || text[i] == '\0')
            return false;
        i += n;
    }
    return true;
}

size_t tg_chunk_len(const char *text, size_t len)
{
    size_t used = 0, units = 0;
    while (used < len) {
        size_t n = tg_utf8_seq((const unsigned char *)text + used, len - used);
        size_t cost = n == 4 ? 2 : 1;
        if (n == 0 || units + cost > TG_CHUNK_UNITS)
            break;
        units += cost;
        used += n;
    }
    return used;
}
