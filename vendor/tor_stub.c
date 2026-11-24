/* Tor API stubs — used when real Tor is not linked.
 * Provides all symbols needed by tor_integration.c */

#include <stddef.h>
#include <stdint.h>

/* Tor main API stubs */
void *tor_main_configuration_new(void) { return NULL; }
int tor_main_configuration_set_command_line(void *cfg, int argc, char **argv)
{ (void)cfg; (void)argc; (void)argv; return 0; }
int tor_run_main(void *cfg) { (void)cfg; return -1; }
void tor_main_configuration_free(void *cfg) { (void)cfg; }

/* Dynhost webserver stub */
typedef size_t (*dynhost_external_handler_fn)(const char *, const char *,
    const uint8_t *, size_t, uint8_t *, size_t, void *);
void dynhost_webserver_set_external_handler(
    dynhost_external_handler_fn handler, void *ctx)
{ (void)handler; (void)ctx; }

/* Shutdown stub */
void tor_shutdown_event_loop_and_exit(int exitcode) { (void)exitcode; }

/* Raw onion stream stubs (write and close only, fail closed).
 *
 * core/modules/net/src/onion_stream.c declares dynhost_stream_open/write/close
 * weak. On ELF an undefined weak reference links as NULL. Observed with
 * MinGW gcc 16 under LTO: the references to dynhost_stream_write and
 * dynhost_stream_close failed to link (hard .refptr references), while
 * dynhost_stream_open and dynhost_client_fetch linked. The cause is
 * LTO-partition dependent and not understood. Define write and close here so
 * a stub link cannot fail on them; both are unreachable in practice because
 * onion_stream_connect refuses before any dial. Never test write or close as
 * a capability.
 *
 * dynhost_stream_open and dynhost_client_fetch must stay undefined: the node
 * decides real versus stub Tor from them (onion_stream_connect tests
 * dynhost_stream_open; app_tor_real_build_linked tests dynhost_client_fetch),
 * so a stub that defined either would make a stub build look like real Tor. */
struct dynhost_stream;
int dynhost_stream_write(struct dynhost_stream *s, const uint8_t *data,
                         size_t len)
{ (void)s; (void)data; (void)len; return -1; }
void dynhost_stream_close(struct dynhost_stream *s) { (void)s; }
