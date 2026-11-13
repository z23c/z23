/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: retain an immutable reliable Telegram batch before acknowledging it. */
#ifndef Z23_CONTRIB_INBOX_TELEGRAM_H
#define Z23_CONTRIB_INBOX_TELEGRAM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Caller owns the pass lock. False can follow an uncertain publication: leave
 * all names untouched and retry by comparing the retained destination. */
bool ci_telegram_retain(const char *state, const char *receipt,
                        const char *wire, size_t length);
/* Bootstrap the state directory beneath its canonical existing parent and
 * flush that parent before treating any child evidence as durable. */
bool ci_telegram_prepare_state(const char *state);
bool ci_telegram_send_confirmed(const char *wire, int64_t group);
bool ci_telegram_ack_confirmed(const char *wire, int64_t bot, int64_t next);
bool ci_telegram_group_parse(const char *text, int64_t *group);
#endif
