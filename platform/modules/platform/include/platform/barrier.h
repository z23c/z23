/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: reusable pthread barrier semantics on POSIX hosts. */

#ifndef ZCLASSIC_PLATFORM_BARRIER_H
#define ZCLASSIC_PLATFORM_BARRIER_H

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    unsigned threshold;
    unsigned waiting;
    unsigned generation;
} zcl_barrier_t;

static inline int zcl_barrier_init(zcl_barrier_t *barrier, unsigned count)
{
    if (!barrier || count == 0)
        return EINVAL;
    int rc = pthread_mutex_init(&barrier->mutex, NULL);
    if (rc != 0)
        return rc;
    rc = pthread_cond_init(&barrier->condition, NULL);
    if (rc != 0) {
        (void)pthread_mutex_destroy(&barrier->mutex);
        return rc;
    }
    barrier->threshold = count;
    barrier->waiting = 0;
    barrier->generation = 0;
    return 0;
}

static inline int zcl_barrier_wait(zcl_barrier_t *barrier)
{
    if (!barrier)
        return EINVAL;
    int rc = pthread_mutex_lock(&barrier->mutex);
    if (rc != 0)
        return rc;
    unsigned generation = barrier->generation;
    barrier->waiting++;
    if (barrier->waiting == barrier->threshold) {
        barrier->waiting = 0;
        barrier->generation++;
        rc = pthread_cond_broadcast(&barrier->condition);
    } else {
        do {
            rc = pthread_cond_wait(&barrier->condition, &barrier->mutex);
        } while (rc == 0 && generation == barrier->generation);
    }
    int unlock_rc = pthread_mutex_unlock(&barrier->mutex);
    return rc != 0 ? rc : unlock_rc;
}

static inline int zcl_barrier_destroy(zcl_barrier_t *barrier)
{
    if (!barrier)
        return EINVAL;
    int cond_rc = pthread_cond_destroy(&barrier->condition);
    int mutex_rc = pthread_mutex_destroy(&barrier->mutex);
    return cond_rc != 0 ? cond_rc : mutex_rc;
}

#endif
