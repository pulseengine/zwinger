/*
 * zwinger macOS bridge (STUB, not compiled yet): an Endpoint Security client scoped to the
 * descendants of one process, so a confined session's every exec/open/connect is decided by
 * zwinger's profile (REQ-ZW-003).
 *
 * Basis: macOS 27's es_new_descendants_client (Apple's supported successor for per-process
 * policy, unlike sandbox-exec/Seatbelt). Needs the com.apple.developer.endpoint-security.client
 * entitlement (requested by the owner) and a signed binary; ES fails OPEN when the client dies,
 * so zwinger must hold the session's process group and kill it if the client exits.
 *
 * The spike decides whether this works for a Claude session: Keychain login,
 * Remote Control, Bluetooth where allowed, and the cost per event.
 */
#ifndef ZWINGER_ES_DESCENDANTS_H
#define ZWINGER_ES_DESCENDANTS_H

#include <stdint.h>
#include <sys/types.h>

/* Decision callback into Rust: return 1 to allow, 0 to deny. path may be NULL for non-file events. */
typedef int (*zw_decide_fn)(void *ctx, uint32_t event, const char *path, size_t path_len);

/* Start a client confined to root_pid and its descendants. Returns 0 or an es_new_client_result_t. */
int zw_es_start(pid_t root_pid, zw_decide_fn decide, void *ctx, void **out_client);

/* Stop the client. The caller must have stopped the session first (ES fails open). */
void zw_es_stop(void *client);

#endif
