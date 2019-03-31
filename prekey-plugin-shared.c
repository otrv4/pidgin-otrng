/*
 *  Off-the-Record Messaging plugin for pidgin
 *  Copyright (C) 2004-2018  Ian Goldberg, Rob Smits,
 *                           Chris Alexander, Willy Lew,
 *                           Nikita Borisov
 *                           <otr@cypherpunks.ca>
 *                           The pidgin-otrng contributors
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU General Public License as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "prekey-plugin-shared.h"

#include "pidgin-helpers.h"

#include "prekey-discovery.h"

#include "prekey-plugin.h"

#include <libotr-ng/client_orchestration.h>
#include <libotr-ng/debug.h>
#include <libotr-ng/messaging.h>

extern otrng_global_state_s *otrng_state;
extern PurplePlugin *otrng_plugin_handle;

void send_message(PurpleAccount *account, const char *recipient,
                  const char *message) {
  PurpleConnection *connection = purple_account_get_connection(account);
  if (!connection) {
    // Not connected
    return;
  }

  // TODO: Should this send to the original recipient or to the normalized
  // recipient?
  serv_send_im(connection, recipient, message, 0);
}

static gboolean timed_trigger_potential_publishing(gpointer data) {
  otrng_debug_enter("timed_trigger_potential_publishing");
  purple_signal_emit(otrng_plugin_handle, "maybe-publish-prekey-data", data);
  otrng_debug_exit("timed_trigger_potential_publishing");
  return FALSE; // we don't want to continue
}

#define OTRNG_PUBLISHING_TRIGGER_INTERVAL 3

void trigger_potential_publishing(otrng_client_s *client) {
  otrng_debug_enter("trigger_potential_publishing");
  purple_timeout_add_seconds(OTRNG_PUBLISHING_TRIGGER_INTERVAL,
                             timed_trigger_potential_publishing, client);
  otrng_debug_exit("trigger_potential_publishing");
}

static void
found_plugin_prekey_server_for_server_identity(otrng_plugin_prekey_server *srv,
                                               void *ctx) {
  lookup_prekey_server_for_server_identity_ctx_s *cc = ctx;
  otrng_debug_fprintf(
      stderr, "We received server identity for domain %s - prekey server %s\n",
      cc->domain, srv->identity);
  otrng_prekey_provide_server_identity_for(
      cc->client, cc->domain, srv->identity, (uint8_t *)srv->fingerprint);
  free(srv);

  if (cc->found == 0) {
    cc->next(cc->account, cc->client, cc->ctx);
  }
  cc->found++;
}

void otrng_plugin_ensure_server_identity(PurpleAccount *account,
                                         const char *username,
                                         AfterServerIdentity cb, void *uctx) {
  otrng_client_s *client =
      otrng_client_get(otrng_state, purple_account_to_client_id(account));
  otrng_prekey_plugin_ensure_prekey_manager(client);
  char *domain = otrng_plugin_prekey_domain_for(account, username);
  if (otrng_prekey_has_server_identity_for(client, domain) != otrng_true) {
    lookup_prekey_server_for_server_identity_ctx_s *lctx =
        otrng_xmalloc_z(sizeof(lookup_prekey_server_for_server_identity_ctx_s));
    lctx->account = account;
    lctx->client = client;
    lctx->found = 0;
    lctx->next = cb;
    lctx->ctx = uctx;
    lctx->domain = domain;
    // TODO: take care of error here
    otrng_plugin_lookup_prekey_servers_for(
        account, username, found_plugin_prekey_server_for_server_identity,
        lctx);
  } else {
    cb(account, client, uctx);
  }
}
