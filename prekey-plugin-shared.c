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

extern xyz_otrng_prekey_client_callbacks_s prekey_client_cb;

static void
found_plugin_prekey_server_for_prekey_client(otrng_plugin_prekey_server *srv,
                                             void *ctx) {
  lookup_prekey_server_for_prekey_client_ctx_s *cc = ctx;
  const char *prekey_server_identity = srv->identity;
  free(srv);

  xyz_otrng_prekey_client_s *pclient = otrng_client_get_prekey_client(
      prekey_server_identity, &prekey_client_cb, cc->client);
  if (cc->found == 0) {
    cc->next(cc->account, cc->client, pclient, cc->ctx);
  }
  cc->found++;
}

void otrng_plugin_get_prekey_client(PurpleAccount *account, WithPrekeyClient cb,
                                    void *uctx) {
  otrng_client_s *client =
      otrng_client_get(otrng_state, purple_account_to_client_id(account));
  if (!client) {
    cb(account, client, NULL, uctx);
  } else {
    otrng_client_ensure_correct_state(client);
    trigger_potential_publishing(client);

    /* you can set here some preferences */
    // otrng_client_set_minimum_stored_prekey_msg(10000, client);
    // otrng_client_set_max_published_prekey_msg(10, client);

    if (client->prekey_client) {
      cb(account, client, client->prekey_client, uctx);
    } else {
      /* TOOD: this ctx will leak -  */
      /*     we don't know how to make it not, right now */
      lookup_prekey_server_for_prekey_client_ctx_s *ctx =
          malloc(sizeof(lookup_prekey_server_for_prekey_client_ctx_s));
      if (!ctx) {
        cb(account, client, NULL, uctx);
      } else {
        ctx->account = account;
        ctx->client = client;
        ctx->found = 0;
        ctx->next = cb;
        ctx->ctx = uctx;
        if (!otrng_plugin_lookup_prekey_servers_for_self(
                account, found_plugin_prekey_server_for_prekey_client, ctx)) {
          cb(account, client, NULL, uctx);
        }
      }
    }
  }
}
