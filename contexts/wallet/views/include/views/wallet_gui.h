#ifndef ZCL_VIEWS_WALLET_GUI_H
#define ZCL_VIEWS_WALLET_GUI_H

/* Run the standalone wallet GUI against the wallet in `datadir`, parsing
 * `argc`/`argv` for GUI-specific options. Blocks until the GUI exits.
 * Returns a process exit code: 0 on clean exit, non-zero on failure. */
int wallet_gui_main(int argc, char **argv, const char *datadir);
#endif
