/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Mailbox primitive — bounded multi-producer/single-consumer ring.
 *
 * Why this exists
 * ----------------
 * The L5 actor layer in the destination architecture (see
 * zclassic23-plan.md) is built on actors that own a single inbox. A
 * mailbox enforces:
 *
 *   - Bounded queueing: a slow consumer cannot trigger unbounded
 *     memory growth in the producer.
 *   - Drop-and-tell semantics: try_send returns false on overflow so
 *     the caller can apply backpressure (yield, retry, blocker).
 *   - Closed state: graceful drain on shutdown — once closed, no new
 *     messages enter; the consumer drains what is already queued.
 *
 * Threading model
 * ----------------
 * Multi-producer, single-consumer. Producers race on send. A consumer
 * is expected to call try_recv from one thread; multi-consumer is not
 * supported (would require splitting tail tracking, out of scope for
 * v1). The implementation uses one mutex + one cond-equivalent flag.
 * It is intentionally NOT lock-free: ring overflow + close coordination
 * is much easier with a small critical section, and our actor cadence
 * (kHz, not MHz) doesn't need the extra complexity.
 *
 * Message ownership
 * ------------------
 * Messages are COPIED into and out of the ring (caller stack memory
 * is fine for the producer). Pointers passed through messages are
 * shallow-copied — caller owns the pointee. */

#ifndef ZCL_UTIL_MAILBOX_H
#define ZCL_UTIL_MAILBOX_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct mailbox mailbox_t;

/* Create a mailbox with room for `capacity` messages of `msg_size`
 * bytes. Both must be > 0. Returns NULL on bad input or allocation
 * failure. Threadsafe to call from any thread once; not threadsafe to
 * call from multiple threads simultaneously on the same handle (the
 * handle is the result, so this is trivial). */
mailbox_t *mailbox_create(size_t capacity, size_t msg_size);

/* Free the mailbox. Caller must guarantee no producers or consumers
 * are using it. Calling destroy on NULL is a no-op. */
void mailbox_destroy(mailbox_t *m);

/* Non-blocking send. Copies `msg_size` bytes from `msg` into the next
 * free slot. Returns true on success; false on full mailbox, closed
 * mailbox, or NULL args. */
bool mailbox_try_send(mailbox_t *m, const void *msg);

/* Non-blocking receive. Copies `msg_size` bytes from the head slot
 * into `out_msg`. Returns true if a message was drained; false on
 * empty mailbox or NULL args. A closed-but-non-empty mailbox still
 * drains messages successfully. */
bool mailbox_try_recv(mailbox_t *m, void *out_msg);

/* Current queued depth (snapshot; not stable in concurrent use). */
size_t mailbox_depth(const mailbox_t *m);

/* Capacity the mailbox was created with. */
size_t mailbox_capacity(const mailbox_t *m);

/* Mark the mailbox closed. Subsequent try_send calls return false.
 * Already-queued messages remain drainable. Returns true on the
 * transition from open to closed; false if already closed or NULL. */
bool mailbox_close(mailbox_t *m);

/* True if the mailbox has been closed via mailbox_close. */
bool mailbox_is_closed(const mailbox_t *m);

/* ── Counters (for observability) ────────────────────────────────── */

/* Total successful sends since creation. */
size_t mailbox_sent_count(const mailbox_t *m);

/* Total successful receives since creation. */
size_t mailbox_recv_count(const mailbox_t *m);

/* Total try_send calls that returned false because the ring was full.
 * (Closed-mailbox rejects do NOT count as drops — that's a separate
 * lifecycle event.) */
size_t mailbox_drop_count(const mailbox_t *m);

/* ── Typed actor inbox helpers ──────────────────────────────────
 *
 * MAILBOX_DECLARE(name, T)
 *   declares a typed inbox for messages of type T.
 *
 * MAILBOX_DEFINE(name, T, capacity)
 *   defines storage and bookkeeping in one .c file.
 *
 * mailbox_<name>_push(const T *msg) -> bool
 *   non-blocking push; returns false on full.
 *
 * mailbox_<name>_drain(void (*handler)(const T *)) -> size_t
 *   drains all queued messages, calls handler per message, returns count. */
#define MAILBOX_DECLARE(name, T) \
    bool mailbox_##name##_push(const T *msg); \
    size_t mailbox_##name##_drain(void (*handler)(const T *msg))

#define MAILBOX_DEFINE(name, T, capacity) \
    static mailbox_t *g_mbox_##name; \
    static pthread_mutex_t g_mbox_##name##_init_lock = PTHREAD_MUTEX_INITIALIZER; \
    static bool mailbox_##name##_init_once(void) { \
        pthread_mutex_lock(&g_mbox_##name##_init_lock); \
        if (!g_mbox_##name) \
            g_mbox_##name = mailbox_create((capacity), sizeof(T)); \
        bool ok = (g_mbox_##name != NULL); \
        pthread_mutex_unlock(&g_mbox_##name##_init_lock); \
        return ok; \
    } \
    bool mailbox_##name##_push(const T *msg) { \
        if (!msg || !mailbox_##name##_init_once()) return false; \
        return mailbox_try_send(g_mbox_##name, msg); \
    } \
    size_t mailbox_##name##_drain(void (*handler)(const T *msg)) { \
        if (!handler || !mailbox_##name##_init_once()) return 0; \
        T tmp; \
        size_t n = 0; \
        size_t limit = mailbox_depth(g_mbox_##name); \
        while (n < limit && mailbox_try_recv(g_mbox_##name, &tmp)) { \
            handler(&tmp); \
            n++; \
        } \
        return n; \
    }

#endif /* ZCL_UTIL_MAILBOX_H */
