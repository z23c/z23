/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2013 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_SYNC_H
#define BITCOIN_SYNC_H

#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>

typedef CRITICAL_SECTION zcl_mutex_t;
typedef CONDITION_VARIABLE zcl_cond_t;
typedef INIT_ONCE zcl_once_t;
#define ZCL_ONCE_INIT INIT_ONCE_STATIC_INIT

struct zcl_once_context { void (*function)(void); };
static BOOL CALLBACK zcl_once_callback(PINIT_ONCE once, PVOID parameter,
                                       PVOID *context)
{
    (void)once;
    (void)context;
    const struct zcl_once_context *call = parameter;
    call->function();
    return TRUE;
}
static inline bool zcl_once_call(zcl_once_t *once, void (*function)(void))
{
    struct zcl_once_context context = { .function = function };
    return once && function &&
           InitOnceExecuteOnce(once, zcl_once_callback, &context, NULL) != 0;
}

static inline void zcl_mutex_init(zcl_mutex_t *m) { InitializeCriticalSection(m); }
static inline void zcl_mutex_destroy(zcl_mutex_t *m) { DeleteCriticalSection(m); }
static inline void zcl_mutex_lock(zcl_mutex_t *m) { EnterCriticalSection(m); }
static inline void zcl_mutex_unlock(zcl_mutex_t *m) { LeaveCriticalSection(m); }
static inline bool zcl_mutex_trylock(zcl_mutex_t *m) { return TryEnterCriticalSection(m) != 0; }

static inline void zcl_cond_init(zcl_cond_t *c) { InitializeConditionVariable(c); }
static inline void zcl_cond_destroy(zcl_cond_t *c) { (void)c; }
static inline void zcl_cond_wait(zcl_cond_t *c, zcl_mutex_t *m) { SleepConditionVariableCS(c, m, INFINITE); }
static inline void zcl_cond_signal(zcl_cond_t *c) { WakeConditionVariable(c); }
static inline void zcl_cond_broadcast(zcl_cond_t *c) { WakeAllConditionVariable(c); }

#else
#include <pthread.h>

typedef pthread_mutex_t zcl_mutex_t;
typedef pthread_cond_t zcl_cond_t;
typedef pthread_once_t zcl_once_t;
#define ZCL_ONCE_INIT PTHREAD_ONCE_INIT

static inline bool zcl_once_call(zcl_once_t *once, void (*function)(void))
{
    return once && function && pthread_once(once, function) == 0;
}

static inline void zcl_mutex_init(zcl_mutex_t *m)
{
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(m, &attr);
    pthread_mutexattr_destroy(&attr);
}
static inline void zcl_mutex_destroy(zcl_mutex_t *m) { pthread_mutex_destroy(m); }
static inline void zcl_mutex_lock(zcl_mutex_t *m) { pthread_mutex_lock(m); }
static inline void zcl_mutex_unlock(zcl_mutex_t *m) { pthread_mutex_unlock(m); }
static inline bool zcl_mutex_trylock(zcl_mutex_t *m) { return pthread_mutex_trylock(m) == 0; }

static inline void zcl_cond_init(zcl_cond_t *c) { pthread_cond_init(c, NULL); }
static inline void zcl_cond_destroy(zcl_cond_t *c) { pthread_cond_destroy(c); }
static inline void zcl_cond_wait(zcl_cond_t *c, zcl_mutex_t *m) { pthread_cond_wait(c, m); }
static inline void zcl_cond_signal(zcl_cond_t *c) { pthread_cond_signal(c); }
static inline void zcl_cond_broadcast(zcl_cond_t *c) { pthread_cond_broadcast(c); }

#endif

/* Convenience macros for lock scoping */
#define LOCK(cs) zcl_mutex_lock(&(cs))
#define UNLOCK(cs) zcl_mutex_unlock(&(cs))

#endif
