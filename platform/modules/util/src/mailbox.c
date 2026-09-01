/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Mailbox primitive — implementation. See util/mailbox.h.
 *
 * One mutex protects the ring buffer head/tail and the closed flag.
 * Counters live as atomics so observability code can read them without
 * acquiring the lock. */

#include "util/mailbox.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct mailbox {
    pthread_mutex_t lock;

    /* Ring state. head = next slot to drain; tail = next slot to
     * write. Empty when head == tail and depth == 0; full when
     * depth == capacity. We track depth explicitly so we don't have
     * to reserve a sentinel slot. */
    size_t capacity;
    size_t msg_size;
    size_t head;
    size_t tail;
    size_t depth;
    bool   closed;

    /* Counters; only the writer-of-the-counter ever touches them
     * (producer for sent/drop, consumer for recv), so a relaxed atomic
     * store + relaxed-or-acquire load is enough. */
    _Atomic size_t sent_count;
    _Atomic size_t recv_count;
    _Atomic size_t drop_count;

    /* slots[0..capacity*msg_size] */
    unsigned char *slots;
};

/* ── Lifecycle ────────────────────────────────────────────────────── */

mailbox_t *mailbox_create(size_t capacity, size_t msg_size)
{
    if (capacity == 0) LOG_NULL("mailbox", "create: zero capacity");
    if (msg_size == 0) LOG_NULL("mailbox", "create: zero msg_size");

    /* Guard against overflow of capacity * msg_size. */
    if (msg_size > SIZE_MAX / capacity)
        LOG_NULL("mailbox", "create: capacity*msg_size overflow");

    mailbox_t *m = zcl_calloc(1, sizeof(*m), "mailbox_t");
    if (!m) LOG_NULL("mailbox", "create: alloc failed");
    m->slots = zcl_calloc(capacity, msg_size, "mailbox slots");
    if (!m->slots) {
        free(m);
        LOG_NULL("mailbox", "create: slots alloc failed (cap=%zu, sz=%zu)",
                 capacity, msg_size);
    }
    pthread_mutex_init(&m->lock, NULL);
    m->capacity = capacity;
    m->msg_size = msg_size;
    m->head = m->tail = m->depth = 0;
    m->closed = false;
    atomic_store(&m->sent_count, (size_t)0);
    atomic_store(&m->recv_count, (size_t)0);
    atomic_store(&m->drop_count, (size_t)0);
    return m;
}

void mailbox_destroy(mailbox_t *m)
{
    if (!m) return;
    pthread_mutex_destroy(&m->lock);
    free(m->slots);
    free(m);
}

/* ── Hot path ─────────────────────────────────────────────────────── */

bool mailbox_try_send(mailbox_t *m, const void *msg)
{
    if (!m || !msg) return false;

    pthread_mutex_lock(&m->lock);
    if (m->closed) {
        pthread_mutex_unlock(&m->lock);
        return false;
    }
    if (m->depth >= m->capacity) {
        pthread_mutex_unlock(&m->lock);
        /* Drop: count once. */
        atomic_fetch_add(&m->drop_count, (size_t)1);
        return false;
    }
    unsigned char *slot = m->slots + m->tail * m->msg_size;
    memcpy(slot, msg, m->msg_size);
    m->tail = (m->tail + 1) % m->capacity;
    m->depth++;
    pthread_mutex_unlock(&m->lock);
    atomic_fetch_add(&m->sent_count, (size_t)1);
    return true;
}

bool mailbox_try_recv(mailbox_t *m, void *out_msg)
{
    if (!m || !out_msg) return false;

    pthread_mutex_lock(&m->lock);
    if (m->depth == 0) {
        pthread_mutex_unlock(&m->lock);
        return false;
    }
    const unsigned char *slot = m->slots + m->head * m->msg_size;
    memcpy(out_msg, slot, m->msg_size);
    m->head = (m->head + 1) % m->capacity;
    m->depth--;
    pthread_mutex_unlock(&m->lock);
    atomic_fetch_add(&m->recv_count, (size_t)1);
    return true;
}

/* ── Read-side accessors ──────────────────────────────────────────── */

size_t mailbox_depth(const mailbox_t *m)
{
    if (!m) return 0;
    pthread_mutex_lock((pthread_mutex_t *)&m->lock);
    size_t d = m->depth;
    pthread_mutex_unlock((pthread_mutex_t *)&m->lock);
    return d;
}

size_t mailbox_capacity(const mailbox_t *m)
{
    return m ? m->capacity : 0;
}

bool mailbox_close(mailbox_t *m)
{
    if (!m) return false;
    bool transitioned = false;
    pthread_mutex_lock(&m->lock);
    if (!m->closed) {
        m->closed = true;
        transitioned = true;
    }
    pthread_mutex_unlock(&m->lock);
    return transitioned;
}

bool mailbox_is_closed(const mailbox_t *m)
{
    if (!m) return false;
    pthread_mutex_lock((pthread_mutex_t *)&m->lock);
    bool c = m->closed;
    pthread_mutex_unlock((pthread_mutex_t *)&m->lock);
    return c;
}

size_t mailbox_sent_count(const mailbox_t *m)
{ return m ? atomic_load(&m->sent_count) : 0; }

size_t mailbox_recv_count(const mailbox_t *m)
{ return m ? atomic_load(&m->recv_count) : 0; }

size_t mailbox_drop_count(const mailbox_t *m)
{ return m ? atomic_load(&m->drop_count) : 0; }
