/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_SETUP_FIELD_H
#define ZAPP_SETUP_FIELD_H

/* How the fields that take recovery words are configured, so the keyboard stores nothing the owner types:
 * TYPE_CLASS_TEXT with TYPE_TEXT_FLAG_NO_SUGGESTIONS and TYPE_TEXT_VARIATION_VISIBLE_PASSWORD (no suggestions, no
 * dictionary learning; the visible-password variation keeps the typed words readable and does not by itself block copy or cut,
 * so the fields also disable long click and hide the cursor), IME_FLAG_NO_PERSONALIZED_LEARNING
 * (incognito keyboard), and IMPORTANT_FOR_AUTOFILL_NO. */
#define ZAPP_FIELD_INPUT_WORDS 0x80091          /* TYPE_CLASS_TEXT | NO_SUGGESTIONS | VISIBLE_PASSWORD */
#define ZAPP_FIELD_FLAG_MULTI_LINE 0x20000      /* TYPE_TEXT_FLAG_MULTI_LINE */
#define ZAPP_FIELD_IME_NO_LEARNING 0x1000000    /* IME_FLAG_NO_PERSONALIZED_LEARNING */
#define ZAPP_FIELD_AUTOFILL_NO 2                /* IMPORTANT_FOR_AUTOFILL_NO */
#define ZAPP_FIELD_NUMBER 2                     /* TYPE_CLASS_NUMBER */

#define ZAPP_FIELD_CLASS_MASK 0xf
#define ZAPP_FIELD_VARIATION_MASK 0xff0
#define ZAPP_FIELD_CLASS_TEXT 1
#define ZAPP_FIELD_NO_SUGGESTIONS 0x80000
#define ZAPP_FIELD_VISIBLE_PASSWORD 0x90
/* True for a text field the keyboard treats as private: no suggestions, password variation, incognito keyboard. */
#define ZAPP_FIELD_PRIVATE(type, ime) \
    (((type) & ZAPP_FIELD_CLASS_MASK) == ZAPP_FIELD_CLASS_TEXT && ((type) & ZAPP_FIELD_NO_SUGGESTIONS) != 0 && \
     ((type) & ZAPP_FIELD_VARIATION_MASK) == ZAPP_FIELD_VISIBLE_PASSWORD && ((ime) & ZAPP_FIELD_IME_NO_LEARNING) != 0)

#endif
