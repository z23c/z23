/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2013 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_SUPPORT_PAGELOCKER_H
#define ZCL_SUPPORT_PAGELOCKER_H

#include "support/cleanse.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stddef.h>

bool memory_page_lock(const void *addr, size_t len);
bool memory_page_unlock(const void *addr, size_t len);
size_t get_system_page_size(void);

struct page_lock_entry {
    size_t page;
    int count;
};

#define MAX_LOCKED_PAGES 4096

struct locked_page_manager {
    zcl_mutex_t mutex;
    struct page_lock_entry entries[MAX_LOCKED_PAGES];
    size_t num_entries;
    size_t page_size;
    size_t page_mask;
};

void locked_page_manager_init(struct locked_page_manager *m);
void locked_page_manager_destroy(struct locked_page_manager *m);
void locked_page_manager_lock_range(struct locked_page_manager *m,
                                    void *p, size_t size);
void locked_page_manager_unlock_range(struct locked_page_manager *m,
                                      void *p, size_t size);
int locked_page_manager_get_count(struct locked_page_manager *m);

struct locked_page_manager *locked_page_manager_instance(void);

void lock_object(void *obj, size_t size);
void unlock_object(void *obj, size_t size);

#endif
