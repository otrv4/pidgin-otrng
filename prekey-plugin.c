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

#include "prekey-plugin.h"

/* If we're using glib on Windows, we need to use g_fopen to open files.
 * On other platforms, it's also safe to use it.  If we're not using
 * glib, just use fopen. */
#ifdef USING_GTK
/* If we're cross-compiling, this might be wrong, so fix it. */
#ifdef WIN32
#undef G_OS_UNIX
#define G_OS_WIN32
#endif
#include <glib/gstdio.h>
#else
#define g_fopen fopen
#endif

#ifdef ENABLE_NLS
/* internationalisation header */
#include <glib/gi18n-lib.h>
#else
#define _(x) (x)
#define N_(x) (x)
#endif

/* libpurple */
#include <connection.h>
#include <prpl.h>

#include <libotr-ng/alloc.h>
#include <libotr-ng/client_orchestration.h>
#include <libotr-ng/debug.h>
#include <libotr-ng/deserialize.h>
#include <libotr-ng/messaging.h>

#include "pidgin-helpers.h"
#include "prekey-discovery.h"

extern otrng_global_state_s *otrng_state;
extern PurplePlugin *otrng_plugin_handle;

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

static void send_message(PurpleAccount *account, const char *recipient,
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

static void notify_error_cb(otrng_client_s *client, int error, void *ctx) {
  otrng_debug_fprintf(stderr, "[%s] Prekey Server: an error happened: %d\n",
                      client->client_id.account, error);
}

static void
storage_status_received_cb(otrng_client_s *client,
                           const otrng_prekey_storage_status_message_s *msg,
                           void *ctx) {
  otrng_debug_fprintf(
      stderr, "[%s] Prekey Server: we have %d prekey messages stored.\n",
      client->client_id.account, msg->stored_prekeys);
}

static void success_received_cb(otrng_client_s *client, void *ctx) {
  otrng_client_published(client);
  client->prekey_messages_num_to_publish = 0;
  otrng_debug_fprintf(stderr, "[%s] Prekey Server: received success\n",
                      client->client_id.account);
}

static void failure_received_cb(otrng_client_s *client, void *ctx) {
  otrng_client_failed_published(client);
  otrng_debug_fprintf(
      stderr,
      "[%s] Prekey Server: something happened. We were unable to process the "
      "request.\n",
      client->client_id.account);
}

static void no_prekey_in_storage_received_cb(otrng_client_s *client,
                                             void *ctx) {
  otrng_debug_fprintf(
      stderr,
      "[%s] Prekey Server: there are no prekey in storage for the requested "
      "recipient.\n",
      client->client_id.account);
}

static void
get_prekey_client_for_publishing(PurpleAccount *account, otrng_client_s *client,
                                 otrng_prekey_client_s *prekey_client,
                                 void *ctx) {
  PurpleConnection *connection = purple_account_get_connection(account);
  if (!connection) {
    otrng_debug_fprintf(stderr, "No connection. \n");
    return;
  }

  if (!prekey_client) {
    otrng_debug_fprintf(stderr, "No prekey client. \n");
    return;
  }

  char *message = NULL;
  otrng_client_start_publishing(client);
  message = otrng_prekey_client_publish(prekey_client);

  serv_send_im(connection, prekey_client->server_identity, message, 0);
}

static void low_prekey_messages_in_storage_cb(otrng_client_s *client,
                                              char *server_identity,
                                              void *ctx) {
  otrng_debug_fprintf(stderr,
                      "[%s] Prekey Server: Publishing prekey messages.\n",
                      client->client_id.account);
  // TODO: @ola
  // Once ensure_state can handle prekey messages, it should be called here
  // And then trigger a maybe_publish later

  otrng_plugin_get_prekey_client(ctx, get_prekey_client_for_publishing, NULL);
}

static void send_offline_messages_to_each_ensemble(
    prekey_ensemble_s *const *const ensembles, uint8_t num_ensembles,
    otrng_plugin_offline_message_ctx *ctx) {

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

static void
prekey_ensembles_received_cb(otrng_client_s *client,
                             prekey_ensemble_s *const *const ensembles,
                             uint8_t num_ensembles, void *ctx) {
  otrng_debug_fprintf(stderr, "[%s] Prekey Server: we received %d ensembles.\n",
                      client->client_id.account, num_ensembles);

  if (!ctx) {
    otrng_debug_fprintf(stderr, "Invalid NULL context\n");
  }

  otrng_plugin_offline_message_ctx *c = ctx;

  send_offline_messages_to_each_ensemble(ensembles, num_ensembles, c);

  free(c->message);
  free(c->recipient);
  free(c);
}

#define PREKEYS_FILE_NAME "otr4.prekey_messages"

static int build_prekey_publication_message_cb(
    otrng_client_s *client, otrng_prekey_publication_message_s *msg,
    otrng_prekey_publication_policy_s *policy, void *ctx) {
  otrng_debug_enter("build_prekey_publication_message_cb");
  if (!ctx) {
    otrng_debug_fprintf(stderr, "Received invalid ctx\n");
    otrng_debug_exit("build_prekey_publication_message_cb");
    return 0;
  }

  FILE *prekeyf = NULL;
  gchar *prekeysfile =
      g_build_filename(purple_user_dir(), PREKEYS_FILE_NAME, NULL);
  if (!prekeysfile) {
    fprintf(stderr, _("Out of memory building filenames!\n"));
    otrng_debug_exit("build_prekey_publication_message_cb");
    return 0;
  }

  prekeyf = g_fopen(prekeysfile, "w+b");
  g_free(prekeysfile);

#ifndef WIN32
  mode_t mask = umask(0077);
  umask(mask);
#endif /* WIN32 */

  if (!prekeyf) {
    fprintf(stderr, _("Could not write prekey messages file\n"));
    otrng_debug_exit("build_prekey_publication_message_cb");
    return 0;
  }

  otrng_client_ensure_correct_state(client);

  // TODO: @ola continue here - we should not create prekey messages here
  //    instead, they should be done in the orchestration part

  msg->num_prekey_messages = client->prekey_messages_num_to_publish;
  msg->prekey_messages = otrng_client_build_prekey_messages(
      msg->num_prekey_messages, client, &msg->ecdh_keys, &msg->dh_keys);

  if (msg->num_prekey_messages > 0 && !msg->prekey_messages) {
    otrng_debug_exit("build_prekey_publication_message_cb");
    return 0;
  }

  const client_profile_s *client_profile =
      otrng_client_get_client_profile(client);
  if (otrng_client_profile_should_publish(client_profile)) {
    otrng_client_profile_start_publishing((client_profile_s *)client_profile);

    otrng_debug_fprintf(stderr,
                        "[%s] Prekey Server: Publishing Client Profile\n",
                        client->client_id.account);
    msg->client_profile = otrng_xmalloc_z(sizeof(client_profile_s));
    otrng_client_profile_copy(msg->client_profile, client_profile);
  }

  if (policy->publish_prekey_profile || 1) {
    const otrng_prekey_profile_s *prekey_profile =
        otrng_client_get_prekey_profile(client);

    msg->prekey_profile = otrng_xmalloc_z(sizeof(otrng_prekey_profile_s));
    otrng_prekey_profile_copy(msg->prekey_profile, prekey_profile);
  }

  *msg->prekey_profile_key = *client->shared_prekey_pair->priv;

  if (!otrng_global_state_prekey_messages_write_to(otrng_state, prekeyf)) {
    otrng_debug_exit("build_prekey_publication_message_cb");
    return 0;
  }

  fclose(prekeyf);
  otrng_debug_exit("build_prekey_publication_message_cb");
  return 1;
}

static otrng_prekey_client_callbacks_s prekey_client_cb = {
    .ctx = NULL,
    .notify_error = notify_error_cb,
    .storage_status_received = storage_status_received_cb,
    .success_received = success_received_cb,
    .failure_received = failure_received_cb,
    .no_prekey_in_storage_received = no_prekey_in_storage_received_cb,
    .low_prekey_messages_in_storage = low_prekey_messages_in_storage_cb,
    .prekey_ensembles_received = prekey_ensembles_received_cb,
    .build_prekey_publication_message = build_prekey_publication_message_cb,
};

typedef struct {
  PurpleAccount *account;
  otrng_client_s *client;
  int found;
  WithPrekeyClient next;
  void *ctx;
} lookup_prekey_server_for_prekey_client_ctx_s;

static void
found_plugin_prekey_server_for_prekey_client(otrng_plugin_prekey_server *srv,
                                             void *ctx) {
  lookup_prekey_server_for_prekey_client_ctx_s *cc = ctx;
  const char *prekey_server_identity = srv->identity;
  free(srv);

  otrng_prekey_client_s *pclient = otrng_client_get_prekey_client(
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

static gboolean
otrng_plugin_receive_prekey_protocol_message(char **tosend, const char *server,
                                             const char *message,
                                             PurpleAccount *account) {
  otrng_client_s *client =
      otrng_client_get(otrng_state, purple_account_to_client_id(account));
  if (!client || !client->prekey_client) {
    return FALSE;
  }

  return otrng_prekey_client_receive(tosend, server, message, client);
}

static gboolean receiving_im_msg_cb(PurpleAccount *account, char **who,
                                    char **message, PurpleConversation *conv,
                                    PurpleMessageFlags *flags) {

  if (!who || !*who || !message || !*message) {
    return 0;
  }

  char *username = g_strdup(purple_normalize(account, *who));

  char *tosend = NULL;
  gboolean ignore = otrng_plugin_receive_prekey_protocol_message(
      &tosend, username, *message, account);
  free(username);

  if (tosend) {
    send_message(account, *who, tosend);
    free(tosend);
  }

  // We consumed the message
  if (ignore) {
    free(*message);
    *message = NULL;
  }

  return ignore;
}

static void get_prekey_client_for_account_signed_on(
    PurpleAccount *account, otrng_client_s *client,
    otrng_prekey_client_s *prekey_client, void *ctx) {
  char *message = NULL;
  if (!prekey_client) {
    return;
  }

  PurpleConnection *connection = purple_account_get_connection(account);
  if (!connection) {
    otrng_debug_fprintf(stderr, "No connection. \n");
    return;
  }

  prekey_client->callbacks->ctx = account;

  message = otrng_prekey_client_request_storage_information(prekey_client);

  // 1. Publish prekeys
  // message = otrng_prekey_client_publish_prekeys(prekey_client);

  // 2. Retrieve the status of storage for yourself
  // message = otrng_prekey_client_request_storage_information(prekey_client);

  // TODO: we should probably set some Purple flags on this call, instead of the
  // 0
  serv_send_im(connection, prekey_client->server_identity, message, 0);
  free(message);
}

static void account_signed_on_cb(PurpleConnection *conn, void *data) {
  otrng_plugin_get_prekey_client(purple_connection_get_account(conn),
                                 get_prekey_client_for_account_signed_on, NULL);
}

static void maybe_publish_prekey_data(void *client_pre, void *ignored) {
  (void)ignored;
  otrng_client_s *client = client_pre;
  otrng_debug_enter("maybe_publish_prekey_data");
  otrng_debug_fprintf(stderr, "client=%s\n", client->client_id.account);

  if (!otrng_client_should_publish(client)) {
    otrng_debug_exit("maybe_publish_prekey_data");
    return;
  }
  otrng_debug_fprintf(stderr, "Prekey: we have been asked to publish...\n");
  otrng_plugin_get_prekey_client(client_id_to_purple_account(client->client_id),
                                 get_prekey_client_for_publishing, NULL);
  otrng_debug_exit("maybe_publish_prekey_data");
}

gboolean otrng_prekey_plugin_load(PurplePlugin *handle) {
  if (!otrng_state) {
    return FALSE;
  }

  purple_signal_register(handle, "maybe-publish-prekey-data",
                         purple_marshal_VOID__POINTER, NULL, 1,
                         purple_value_new(PURPLE_TYPE_POINTER));

  /* Watch to the connect event of every account */
  purple_signal_connect(purple_connections_get_handle(), "signed-on", handle,
                        PURPLE_CALLBACK(account_signed_on_cb), NULL);

  /* Process received prekey protocol messages */
  purple_signal_connect(purple_conversations_get_handle(), "receiving-im-msg",
                        handle, PURPLE_CALLBACK(receiving_im_msg_cb), NULL);

  purple_signal_connect(handle, "maybe-publish-prekey-data", handle,
                        PURPLE_CALLBACK(maybe_publish_prekey_data), NULL);

  // Do the same on the already connected accounts
  // GList *connections = purple_connections_get_all();
  return TRUE;
}

gboolean otrng_prekey_plugin_unload(PurplePlugin *handle) {

  purple_signal_disconnect(handle, "maybe-publish-prekey-data", handle,
                           PURPLE_CALLBACK(maybe_publish_prekey_data));

  purple_signal_disconnect(purple_conversations_get_handle(),
                           "receiving-im-msg", handle,
                           PURPLE_CALLBACK(receiving_im_msg_cb));

  purple_signal_disconnect(purple_connections_get_handle(), "signed-on", handle,
                           PURPLE_CALLBACK(account_signed_on_cb));

  purple_signal_unregister(handle, "maybe-publish-prekey-data");

  return TRUE;
}
