#include "zdeque/zdeque.h"

zdeque_err zdeque_init(zdeque *dq, void **slots, size_t cap)
{
    if (!dq || !slots || cap == 0) return ZDEQUE_ERR_ARG;
    dq->slots = slots;
    dq->cap = cap;
    dq->head = 0;
    dq->len = 0;
    return ZDEQUE_OK;
}

size_t zdeque_size(const zdeque *dq) { return dq ? dq->len : 0; }
size_t zdeque_capacity(const zdeque *dq) { return dq ? dq->cap : 0; }
int zdeque_empty(const zdeque *dq) { return !dq || dq->len == 0; }
int zdeque_full(const zdeque *dq) { return dq && dq->len == dq->cap; }

static size_t slot_of(const zdeque *dq, size_t logical)
{
    size_t s = dq->head + logical;
    if (s >= dq->cap) s -= dq->cap; /* head + len <= cap invariant */
    return s;
}

zdeque_err zdeque_push_back(zdeque *dq, void *ptr)
{
    if (!dq) return ZDEQUE_ERR_ARG;
    if (dq->len == dq->cap) return ZDEQUE_ERR_FULL;
    dq->slots[slot_of(dq, dq->len)] = ptr;
    dq->len++;
    return ZDEQUE_OK;
}

zdeque_err zdeque_push_front(zdeque *dq, void *ptr)
{
    if (!dq) return ZDEQUE_ERR_ARG;
    if (dq->len == dq->cap) return ZDEQUE_ERR_FULL;
    dq->head = dq->head == 0 ? dq->cap - 1 : dq->head - 1;
    dq->slots[dq->head] = ptr;
    dq->len++;
    return ZDEQUE_OK;
}

zdeque_err zdeque_pop_front(zdeque *dq, void **out)
{
    if (!dq) return ZDEQUE_ERR_ARG;
    if (dq->len == 0) return ZDEQUE_ERR_EMPTY;
    if (out) *out = dq->slots[dq->head];
    dq->head++;
    if (dq->head == dq->cap) dq->head = 0;
    dq->len--;
    return ZDEQUE_OK;
}

zdeque_err zdeque_pop_back(zdeque *dq, void **out)
{
    if (!dq) return ZDEQUE_ERR_ARG;
    if (dq->len == 0) return ZDEQUE_ERR_EMPTY;
    if (out) *out = dq->slots[slot_of(dq, dq->len - 1)];
    dq->len--;
    return ZDEQUE_OK;
}

zdeque_err zdeque_peek_front(const zdeque *dq, void **out)
{
    if (!dq || !out) return ZDEQUE_ERR_ARG;
    if (dq->len == 0) return ZDEQUE_ERR_EMPTY;
    *out = dq->slots[dq->head];
    return ZDEQUE_OK;
}

zdeque_err zdeque_peek_back(const zdeque *dq, void **out)
{
    if (!dq || !out) return ZDEQUE_ERR_ARG;
    if (dq->len == 0) return ZDEQUE_ERR_EMPTY;
    *out = dq->slots[slot_of(dq, dq->len - 1)];
    return ZDEQUE_OK;
}

zdeque_err zdeque_at(const zdeque *dq, size_t index, void **out)
{
    if (!dq || !out) return ZDEQUE_ERR_ARG;
    if (index >= dq->len) return ZDEQUE_ERR_RANGE;
    *out = dq->slots[slot_of(dq, index)];
    return ZDEQUE_OK;
}

void zdeque_clear(zdeque *dq)
{
    if (!dq) return;
    dq->head = 0;
    dq->len = 0;
}

const char *zdeque_err_str(zdeque_err e)
{
    switch (e) {
    case ZDEQUE_OK: return "ok";
    case ZDEQUE_ERR_ARG: return "invalid argument";
    case ZDEQUE_ERR_FULL: return "deque is full";
    case ZDEQUE_ERR_EMPTY: return "deque is empty";
    case ZDEQUE_ERR_RANGE: return "index out of range";
    }
    return "unknown error";
}
