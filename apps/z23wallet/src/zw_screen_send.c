/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the Send screen. A "Coming soon" placeholder until lane P4 fills
 * it; the rail entry, Ctrl+key and the menu wiring already work. */
#include "zw.h"

void zw_screen_send_build(struct gui_tree *t, const struct zw_model *m)
{
    (void)m;
    zw_screen_soon(t, "s", "Send", "Coming soon. Sending arrives in a later version of Z23 Wallet.");
}
