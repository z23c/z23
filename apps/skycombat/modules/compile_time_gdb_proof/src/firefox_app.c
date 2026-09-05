/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This program CANNOT compile unless GDB can prove it draws a Firefox pixel!
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

/* Firefox brand colors */
#define FIREFOX_ORANGE 0xFF9500
#define FIREFOX_YELLOW 0xFFCB00  
#define FIREFOX_RED    0xE66000

/* This function MUST exist and MUST be called for compilation to succeed */
void firefox_draw_pixel(int x, int y, uint32_t color) {
    /* GDB will verify we reach this point */
    printf("Drawing Firefox pixel at (%d,%d) color=0x%06X\n", x, y, color);
    
    /* The actual "draw" (just a proof point) */
    volatile uint32_t pixel = color;
    (void)pixel;
}

/* Main application */
int main() {
    printf("Firefox Pixel App Starting...\n");
    
    /* THIS LINE IS REQUIRED FOR COMPILATION! */
    /* Remove it and the build will fail */
    firefox_draw_pixel(100, 100, FIREFOX_ORANGE);
    
    printf("✓ Firefox pixel drawn successfully!\n");
    return 0;
}