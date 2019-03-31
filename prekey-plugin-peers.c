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

#include "prekey-plugin-peers.h"

#include "prekey-plugin-shared.h"

#include <libotr-ng/alloc.h>
#include <libotr-ng/client_orchestration.h>
#include <libotr-ng/debug.h>
#include <libotr-ng/deserialize.h>
#include <libotr-ng/messaging.h>

#include "pidgin-helpers.h"
#include "prekey-discovery.h"

extern otrng_global_state_s *otrng_state;

typedef struct message_waiting_ctx {
  PurpleAccount *account;
  char *message;
  char *recipient;

  struct message_waiting_ctx *next;
} message_waiting_ctx;

typedef struct messages_waiting_ctx {
  const otrng_client_s *client;
  message_waiting_ctx *msg;

  struct messages_waiting_ctx *next;
} messages_waiting_ctx;

void no_prekey_in_storage_received_cb(otrng_client_s *client,
                                      const char *identity) {
  otrng_debug_fprintf(
      stderr,
      "[%s] Prekey Server: there are no prekey in storage for the requested "
      "recipient.\n",
      client->client_id.account);
}

static void send_offline_messages_to_each_ensemble(
    prekey_ensemble_s *const *const ensembles, uint8_t num_ensembles,
    message_waiting_ctx *ctx) {

  PurpleAccount *account = ctx->account;
  const char *message = ctx->message;
  const char *recipient = ctx->recipient;

  otrng_client_s *client =
      otrng_client_get(otrng_state, purple_account_to_client_id(account));
  if (!client) {
    return;
  }
  otrng_client_ensure_correct_state(client);
  trigger_potential_publishing(client);

  int i;
  for (i = 0; i < num_ensembles; i++) {
    if (!otrng_prekey_ensemble_validate(ensembles[i])) {
      otrng_debug_fprintf(stderr, "[%s] The Prekey Ensemble %d is not valid\n",
                          client->client_id.account, i);
      continue;
    }

    char *to_send = NULL;
    if (otrng_failed(otrng_client_send_non_interactive_auth(
            &to_send, ensembles[i], recipient, client))) {
      // TODO: error
      continue;
    }

    send_message(account, recipient, to_send);
    free(to_send);

    if (otrng_failed(otrng_client_send(&to_send, message, recipient, client))) {
      // TODO: error
      continue;
    }

    send_message(account, recipient, to_send);
    free(to_send);
  }

  // 1. Build a offline message for each received ensemble
  // 2. Send each message through the network
  // 3. Send a single query message (dependencia na outra direção).
}

static messages_waiting_ctx *prekey_waiting_to_send_messages = NULL;

static messages_waiting_ctx *
find_messages_waiting_for_client(const otrng_client_s *client) {
  messages_waiting_ctx *curr = prekey_waiting_to_send_messages;

  for (; curr != NULL; curr = curr->next) {
    if (curr->client == client) {
      return curr;
    }
  }

  return NULL;
}

static message_waiting_ctx *
pop_waiting_message_for(const otrng_client_s *client, const char *recipient) {
  message_waiting_ctx *curr = NULL, *prev = NULL;
  messages_waiting_ctx *msgs = find_messages_waiting_for_client(client);

  if (msgs == NULL) {
    return NULL;
  }

  for (curr = msgs->msg; curr != NULL; curr = curr->next) {
    if (strcmp(curr->recipient, recipient) == 0) {
      if (prev == NULL) {
        msgs->msg = curr->next;
      } else {
        prev->next = curr->next;
      }
      curr->next = NULL;
      return curr;
    }
    prev = curr;
  }

  return NULL;
}

static void free_waiting_message(message_waiting_ctx *head) {
  message_waiting_ctx *curr = head, *next = NULL;

  for (; curr != NULL; curr = next) {
    next = curr->next;
    free(curr->message);
    free(curr->recipient);
    free(curr);
  }
}

static void free_all_waiting_messages() {
  messages_waiting_ctx *curr = prekey_waiting_to_send_messages, *next = NULL;

  for (; curr != NULL; curr = next) {
    next = curr->next;
    free_waiting_message(curr->msg);
    free(curr);
  }
}

void otrng_prekey_plugin_add_to_mapped_prekey_ensembles_responses(
    const otrng_client_s *client, PurpleAccount *account, char *message,
    char *recipient) {
  message_waiting_ctx *ctx = malloc(sizeof(message_waiting_ctx));
  messages_waiting_ctx *msgs = find_messages_waiting_for_client(client);

  if (msgs == NULL) {
    msgs = malloc(sizeof(messages_waiting_ctx));
    msgs->client = client;
    msgs->msg = NULL;
    msgs->next = prekey_waiting_to_send_messages;
    prekey_waiting_to_send_messages = msgs;
  }

  ctx->account = account;
  ctx->message = g_strdup(message);
  ctx->recipient = recipient;
  ctx->next = msgs->msg;
  msgs->msg = ctx;
}

void prekey_ensembles_received_cb(otrng_client_s *client,
                                  prekey_ensemble_s *const *const ensembles,
                                  uint8_t num_ensembles, const char *identity) {
  otrng_debug_fprintf(stderr, "[%s] Prekey Server: we received %d ensembles.\n",
                      client->client_id.account, num_ensembles);

  if (!identity) {
    otrng_debug_fprintf(stderr, "Invalid NULL identity\n");
  }

  message_waiting_ctx *msg = pop_waiting_message_for(client, identity);
  send_offline_messages_to_each_ensemble(ensembles, num_ensembles, msg);

  free(msg->message);
  free(msg->recipient);
  free(msg);
}

gboolean otrng_prekey_plugin_peers_load(PurplePlugin *handle) { return TRUE; }

gboolean otrng_prekey_plugin_peers_unload(PurplePlugin *handle) {
  free_all_waiting_messages();

  return TRUE;
}
