/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: acceptance for the Windows page-locker -- asserts VirtualLock /
 * VirtualUnlock round-trip on a two-page span, and that the reference
 * counting in locked_page_manager holds. A range spanning page+1 bytes must
 * count 2 pages, a nested lock/unlock of the same range must leave that
 * count at 2 rather than releasing pages another holder still needs, and
 * the final unlock must return it to 0. Wallet key material is what sits in
 * these pages, so a page released while still referenced is a page that can
 * reach swap. */
#include "support/pagelocker.h"

#include <windows.h>
#include <stdio.h>

int main(void)
{
    size_t page = get_system_page_size();
    if (page == 0 || (page & (page - 1)) != 0) return 1;
    void *memory = VirtualAlloc(NULL, page * 2, MEM_RESERVE | MEM_COMMIT,
                                PAGE_READWRITE);
    if (!memory) return 2;
    if (!memory_page_lock(memory, page * 2)) {
        VirtualFree(memory, 0, MEM_RELEASE);
        return 3;
    }
    if (!memory_page_unlock(memory, page * 2)) {
        VirtualFree(memory, 0, MEM_RELEASE);
        return 4;
    }

    struct locked_page_manager manager;
    locked_page_manager_init(&manager);
    locked_page_manager_lock_range(&manager, memory, page + 1);
    if (locked_page_manager_get_count(&manager) != 2) return 5;
    locked_page_manager_lock_range(&manager, memory, 1);
    locked_page_manager_unlock_range(&manager, memory, 1);
    if (locked_page_manager_get_count(&manager) != 2) return 6;
    locked_page_manager_unlock_range(&manager, memory, page + 1);
    if (locked_page_manager_get_count(&manager) != 0) return 7;
    locked_page_manager_destroy(&manager);
    VirtualFree(memory, 0, MEM_RELEASE);
    puts("pagelocker_acceptance: PASS");
    return 0;
}
