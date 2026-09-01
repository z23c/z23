/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Verify native Windows page locking and reference accounting. */
#if defined(_WIN32)
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
#else
typedef int pagelocker_windows_acceptance_not_built;
#endif
