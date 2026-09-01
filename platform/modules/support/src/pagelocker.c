/* Copyright (c) 2009-2013 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "support/pagelocker.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

size_t get_system_page_size(void)
{
#if defined(_WIN32)
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return (size_t)info.dwPageSize;
#else
    return (size_t)sysconf(_SC_PAGESIZE);
#endif
}

bool memory_page_lock(const void *addr, size_t len)
{
#if defined(_WIN32)
    return addr && len > 0 && VirtualLock((void *)(uintptr_t)addr, len) != 0;
#else
    return mlock(addr, len) == 0;
#endif
}

bool memory_page_unlock(const void *addr, size_t len)
{
#if defined(_WIN32)
    return addr && len > 0 && VirtualUnlock((void *)(uintptr_t)addr, len) != 0;
#else
    return munlock(addr, len) == 0;
#endif
}

void locked_page_manager_init(struct locked_page_manager *m)
{
    zcl_mutex_init(&m->mutex);
    m->num_entries = 0;
    m->page_size = get_system_page_size();
    assert((m->page_size & (m->page_size - 1)) == 0);
    m->page_mask = ~(m->page_size - 1);
}

void locked_page_manager_destroy(struct locked_page_manager *m)
{
    zcl_mutex_destroy(&m->mutex);
}

static int find_page(struct locked_page_manager *m, size_t page)
{
    for (size_t i = 0; i < m->num_entries; i++) {
        if (m->entries[i].page == page)
            return (int)i;
    }
    return -1;
}

void locked_page_manager_lock_range(struct locked_page_manager *m,
                                    void *p, size_t size)
{
    zcl_mutex_lock(&m->mutex);
    if (size == 0) {
        zcl_mutex_unlock(&m->mutex);
        return;
    }
    size_t base = (size_t)p;
    if (base > SIZE_MAX - (size - 1)) {
        zcl_mutex_unlock(&m->mutex);
        return;
    }
    size_t start_page = base & m->page_mask;
    size_t end_page = (base + size - 1) & m->page_mask;
    for (size_t page = start_page; page <= end_page; page += m->page_size) {
        int idx = find_page(m, page);
        if (idx < 0) {
            memory_page_lock((void *)page, m->page_size);
            assert(m->num_entries < MAX_LOCKED_PAGES);
            m->entries[m->num_entries].page = page;
            m->entries[m->num_entries].count = 1;
            m->num_entries++;
        } else {
            m->entries[idx].count++;
        }
    }
    zcl_mutex_unlock(&m->mutex);
}

void locked_page_manager_unlock_range(struct locked_page_manager *m,
                                      void *p, size_t size)
{
    zcl_mutex_lock(&m->mutex);
    if (size == 0) {
        zcl_mutex_unlock(&m->mutex);
        return;
    }
    size_t base = (size_t)p;
    if (base > SIZE_MAX - (size - 1)) {
        zcl_mutex_unlock(&m->mutex);
        return;
    }
    size_t start_page = base & m->page_mask;
    size_t end_page = (base + size - 1) & m->page_mask;
    for (size_t page = start_page; page <= end_page; page += m->page_size) {
        int idx = find_page(m, page);
        assert(idx >= 0);
        m->entries[idx].count--;
        if (m->entries[idx].count == 0) {
            memory_page_unlock((void *)page, m->page_size);
            m->entries[idx] = m->entries[m->num_entries - 1];
            m->num_entries--;
        }
    }
    zcl_mutex_unlock(&m->mutex);
}

int locked_page_manager_get_count(struct locked_page_manager *m)
{
    zcl_mutex_lock(&m->mutex);
    int count = (int)m->num_entries;
    zcl_mutex_unlock(&m->mutex);
    return count;
}

static struct locked_page_manager g_locked_page_manager;
static zcl_once_t g_locked_page_manager_once = ZCL_ONCE_INIT;

static void locked_page_manager_global_init(void)
{
    locked_page_manager_init(&g_locked_page_manager);
}

struct locked_page_manager *locked_page_manager_instance(void)
{
    (void)zcl_once_call(&g_locked_page_manager_once,
                        locked_page_manager_global_init);
    return &g_locked_page_manager;
}

void lock_object(void *obj, size_t size)
{
    locked_page_manager_lock_range(locked_page_manager_instance(), obj, size);
}

void unlock_object(void *obj, size_t size)
{
    memory_cleanse(obj, size);
    locked_page_manager_unlock_range(locked_page_manager_instance(), obj, size);
}
