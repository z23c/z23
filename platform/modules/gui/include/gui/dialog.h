/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: modal dialog builders on top of the retained tree (gui/ui.h):
 * the message box (title, wrapped body, optional detail, a right-aligned
 * button row) and the open/close pair for dialogs with their own content,
 * such as a send confirmation or a memo editor. A dialog is modal: input
 * outside it is ignored, Escape fires its cancel action and Enter fires the
 * button marked default, so a confirming button that must not fire on a
 * stray Enter is simply not marked default. */
#ifndef ZCL_GUI_DIALOG_H
#define ZCL_GUI_DIALOG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gui/ui.h"

struct gui_dialog_button {
    const char *id, *label, *action;
    enum gui_style style;
    bool is_default, disabled;
};

/* Open a titled modal dialog; width in logical px (0 = 440). Add children,
 * then gui_dialog_close. */
void gui_dialog_open(struct gui_tree *t, const char *id, const char *title, const char *cancel_action,
                     int32_t width);
void gui_dialog_close(struct gui_tree *t);
/* A right-aligned row of buttons; row_id names the row box. */
void gui_dialog_buttons(struct gui_tree *t, const char *row_id, const struct gui_dialog_button *b, size_t n);
/* A complete message box. detail may be NULL. */
void gui_msgbox(struct gui_tree *t, const char *id, const char *title, const char *body, const char *detail,
                const struct gui_dialog_button *b, size_t n, const char *cancel_action, int32_t width);
/* Restyle the node added last (an input that shows a valid or invalid border). */
void gui_last_style(struct gui_tree *t, enum gui_style s);

#endif
