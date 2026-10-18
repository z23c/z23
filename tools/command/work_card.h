/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Validate one owner-signed public work card (zcl.work_card.v1).
 *
 * A card is the `text` of a board post of kind `need` in public room `work`.
 * This module judges only the bytes of the card. Who signed the post and what
 * state the card is in are decided elsewhere, from the board. */
#ifndef ZCL_COMMAND_WORK_CARD_H
#define ZCL_COMMAND_WORK_CARD_H

#include <stdbool.h>
#include <stddef.h>

#define WORK_CARD_SCHEMA_ID "zcl.work_card.v1"

/* Public board key of the project owner's node, which signs the cards. A public
 * key, not a secret: it is what `fleet board status` reports as `host` on the
 * owner's landing host. Volunteers trust it by default; a fork pins its own. */
#define WORK_OWNER_BOARD_KEY \
    "3a9a9ff17febdbc3b2eb432bff9dcff7d3d211cdfde03a99e80b1b5099d2610a"
#define WORK_KEY_HEX 64

enum {
    WORK_CARD_BYTES_MAX = 2048,
    WORK_CARD_NAME_MAX = 48,
    WORK_CARD_ACCEPTANCE_MAX = 256,
    WORK_CARD_BASE_HEX = 40,
};

enum work_card_level {
    WORK_CARD_LEVEL_NONE = 0,
    WORK_CARD_LEVEL_HAIKU,
    WORK_CARD_LEVEL_SONNET,
    WORK_CARD_LEVEL_OPUS,
};

enum work_card_reason {
    WORK_CARD_OK = 0,
    WORK_CARD_TOO_LARGE,
    WORK_CARD_SCHEMA,
    WORK_CARD_LEVEL,
    WORK_CARD_BASE,
    WORK_CARD_ACCEPTANCE_SHELL,
    WORK_CARD_OWNED_EMPTY,
    WORK_CARD_NAME,
};

/* The validated scalar fields. The arrays (owned, forbidden, contract,
 * stop_if) are validated for shape and read again from the card bytes. */
struct work_card {
    char name[WORK_CARD_NAME_MAX + 1];
    enum work_card_level level;
    char base[WORK_CARD_BASE_HEX + 1];
    char outcome[WORK_CARD_BYTES_MAX + 1];
    char acceptance[WORK_CARD_ACCEPTANCE_MAX + 1];
    size_t owned_count;
};

/* Judge `len` bytes. Returns WORK_CARD_OK and fills `out`, or the first
 * failing check and zeroes `out`. Checks run in this order: size; JSON shape,
 * schema and duplicate keys (CARD_SCHEMA); level; base; acceptance (empty or
 * over-long is CARD_SCHEMA, a disallowed character or launcher is
 * CARD_ACCEPTANCE_SHELL); owned; name. */
enum work_card_reason work_card_validate(const char *bytes, size_t len,
                                         struct work_card *out);

/* Stable reason code, for example "CARD_ACCEPTANCE_SHELL"; "OK" for success. */
const char *work_card_reason_code(enum work_card_reason reason);

/* Lowercase a 64-hex key or id into out; false when s is not exactly that. */
bool work_card_hex64(const char *s, char out[WORK_KEY_HEX + 1]);

enum work_owner_status { WORK_OWNER_OK = 0, WORK_OWNER_BAD, WORK_OWNER_REQUIRED };

/* Resolution order: the caller-supplied key, then the pinned key, else
 * WORK_OWNER_REQUIRED. A supplied key that is not 64 hex is WORK_OWNER_BAD.
 * The node's own board key is never a default. */
enum work_owner_status work_owner_resolve(const char *given, const char *pinned,
                                          char out[WORK_KEY_HEX + 1]);

const char *work_card_level_name(enum work_card_level level);

/* WORK_CARD_LEVEL_NONE when `name` is not haiku, sonnet or opus. */
enum work_card_level work_card_level_from_name(const char *name);

#endif /* ZCL_COMMAND_WORK_CARD_H */
