/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Tricky: Has firefox_draw_pixel() but never calls it!
 * This should FAIL compilation.
 */

#include <stdio.h>
#include <stdint.h>

/* Function exists but is never called */
void firefox_draw_pixel(int x, int y, uint32_t color) {
    printf("Drawing Firefox pixel at (%d,%d) color=0x%06X\n", x, y, color);
}

int main() {
    printf("I have the function but I don't use it!\n");
    
    /* Sneaky: commented out!
    firefox_draw_pixel(100, 100, 0xFF9500);
    */
    
    return 0;
}