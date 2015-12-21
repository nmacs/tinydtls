/* dtls -- a very basic DTLS implementation
 *
 * Copyright (C) 2011--2013 Olaf Bergmann <bergmann@tzi.org>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "global.h"
#include "peer.h"
#include "debug.h"

#ifndef DTLS_PEER_MAX
#define DTLS_PEER_MAX 3
#endif

static int peers_count = 0;

#ifndef WITH_CONTIKI
void peer_init(void)
{
}

static inline dtls_peer_t *
dtls_malloc_peer(void) {
  return (dtls_peer_t *)malloc(sizeof(dtls_peer_t));
}

void
dtls_free_peer(dtls_peer_t *peer) {
  dtls_handshake_free(peer->handshake_params);
  dtls_security_free(peer->security_params[0]);
  dtls_security_free(peer->security_params[1]);
  free(peer);

  if (peers_count > 0) {
    peers_count--;
  }
}
#else /* WITH_CONTIKI */

#include "memb.h"
MEMB(peer_storage, dtls_peer_t, DTLS_PEER_MAX);

void
peer_init() {
  memb_init(&peer_storage);
}

static inline dtls_peer_t *
dtls_malloc_peer() {
  return memb_alloc(&peer_storage);
}

void
dtls_free_peer(dtls_peer_t *peer) {
  dtls_handshake_free(peer->handshake_params);
  dtls_security_free(peer->security_params[0]);
  dtls_security_free(peer->security_params[1]);
  memb_free(&peer_storage, peer);
}
#endif /* WITH_CONTIKI */

dtls_peer_t *
dtls_new_peer(const session_t *session) {
  dtls_peer_t *peer;

  if (peers_count >= DTLS_PEER_MAX) {
    return 0;
  }

  peer = dtls_malloc_peer();
  if (peer) {
    memset(peer, 0, sizeof(dtls_peer_t));
    memcpy(&peer->session, session, sizeof(session_t));
    peer->security_params[0] = dtls_security_new();
    peer->have_cert = 0;

    if (!peer->security_params[0]) {
      dtls_free_peer(peer);
      return NULL;
    }

    dtls_dsrv_log_addr(DTLS_LOG_DEBUG, "dtls_new_peer", session);

    ++peers_count;
  }

  return peer;
}
