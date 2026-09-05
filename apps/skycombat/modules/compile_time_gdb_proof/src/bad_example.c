/* SPDX-FileCopyrightText: 2025 Rhett Creighton
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * This program SHOULD FAIL to compile because it doesn't draw Firefox pixels
 */

#include <stdio.h>

int main() {
    printf("Hello World!\n");
    printf("This program does NOT draw Firefox pixels.\n");
    printf("Therefore it should FAIL compilation.\n");
    
    /* Notice: No firefox_draw_pixel() call! */
    
    return 0;
}