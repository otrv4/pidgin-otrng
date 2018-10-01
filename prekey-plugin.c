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
#include <libotr-ng/deserialize.h>
#include <libotr-ng/messaging.h>

#include "prekey-discovery.h"

// TODO: why is this global?
extern otrng_global_state_s *otrng_state;

static otrng_client_id_s
purple_account_to_client_id(const PurpleAccount *account) {
  const char *protocol = purple_account_get_protocol_id(account);
  const char *accountname =
      g_strdup(purple_normalize(account, purple_account_get_username(account)));
  otrng_client_id_s result = {
      .protocol = protocol,
      .account = accountname,
  };
  return result;
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

static void notify_error_cb(int error, void *ctx) {
  printf("\nPrekey Server: an error happened: %d \n", error);
}

static void
storage_status_received_cb(const otrng_prekey_storage_status_message_s *msg,
                           void *ctx) {
  printf("\nPrekey Server: we have %d prekey messages stored.\n",
         msg->stored_prekeys);
}

static void success_received_cb(void *ctx) {
  printf("\nPrekey Server: received success\n");
}

static void failure_received_cb(void *ctx) {
  printf("\nPrekey Server: something happened. We were unable to process the "
         "request.\n");
}

static void no_prekey_in_storage_received_cb(void *ctx) {
  printf("\nPrekey Server: there are no prekey in storage for the requested "
         "recipient.\n");
}

static void get_prekey_client_for_low_prekey_messages(
    PurpleAccount *account, otrng_client_s *client,
    otrng_prekey_client_s *prekey_client, void *ctx) {
  PurpleConnection *connection = purple_account_get_connection(account);
  if (!connection) {
    printf("\n No connection. \n");
    return;
  }

  if (!prekey_client) {
    printf("\n No prekey client. \n");
    return;
  }

  char *message = NULL;
  message = otrng_prekey_client_publish_prekeys(prekey_client);

  serv_send_im(connection, prekey_client->server_identity, message, 0);
}

static void low_prekey_messages_in_storage_cb(char *server_identity,
                                              void *ctx) {
  printf("\nPrekey Server: Publishing prekey messages.\n");
  otrng_plugin_get_prekey_client(ctx, get_prekey_client_for_low_prekey_messages,
                                 NULL);
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

  int i;
  for (i = 0; i < num_ensembles; i++) {
    if (!otrng_prekey_ensemble_validate(ensembles[i])) {
      printf("The Prekey Ensemble %d is not valid\n", i);
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
prekey_ensembles_received_cb(prekey_ensemble_s *const *const ensembles,
                             uint8_t num_ensembles, void *ctx) {
  printf("\nPrekey Server: we received %d ensembles.\n", num_ensembles);

  if (!ctx) {
    printf("\n Invalid NULL context\n");
  }

  otrng_plugin_offline_message_ctx *c = ctx;

  send_offline_messages_to_each_ensemble(ensembles, num_ensembles, c);

  free(c->message);
  free(c->recipient);
  free(c);
}

#define PREKEYS_FILE_NAME "otr4.prekey_messages"

static int
build_prekey_publication_message_cb(otrng_prekey_publication_message_s *msg,
                                    otrng_prekey_publication_policy_s *policy,
                                    void *ctx) {
  if (!ctx) {
    printf("Received invalid ctx\n");
    return 0;
  }

  FILE *prekeyf = NULL;
  gchar *prekeysfile =
      g_build_filename(purple_user_dir(), PREKEYS_FILE_NAME, NULL);
  if (!prekeysfile) {
    fprintf(stderr, _("Out of memory building filenames!\n"));
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
    return 0;
  }

  PurpleAccount *account = ctx;

  otrng_client_s *client =
      otrng_client_get(otrng_state, purple_account_to_client_id(account));
  if (!client) {
    return 0;
  }
  otrng_client_ensure_correct_state(client);

  msg->num_prekey_messages = policy->max_published_prekey_msg;
  msg->prekey_messages = otrng_client_build_prekey_messages(
      msg->num_prekey_messages, client, &msg->ecdh_keys, &msg->dh_keys);

  if (!msg->prekey_messages) {
    return 0;
  }

  if (policy->publish_client_profile) {
    const client_profile_s *client_profile =
        otrng_client_get_client_profile(client);

    msg->client_profile = otrng_xmalloc_z(sizeof(client_profile_s));
    otrng_client_profile_copy(msg->client_profile, client_profile);
  }

  if (policy->publish_prekey_profile) {
    const otrng_prekey_profile_s *prekey_profile =
        otrng_client_get_prekey_profile(client);

    msg->prekey_profile = otrng_xmalloc_z(sizeof(otrng_prekey_profile_s));
    otrng_prekey_profile_copy(msg->prekey_profile, prekey_profile);
  }

  *msg->prekey_profile_key = *client->shared_prekey_pair->priv;

  if (!otrng_global_state_prekey_messages_write_FILEp(otrng_state, prekeyf)) {
    return 0;
  }

  fclose(prekeyf);
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

static otrng_prekey_client_s *get_cached_prekey_client(PurpleAccount *account) {
  otrng_client_s *client =
      otrng_client_get(otrng_state, purple_account_to_client_id(account));
  if (!client) {
    return NULL;
  }
  otrng_client_ensure_correct_state(client);
  return client->prekey_client;
}

void otrng_plugin_get_prekey_client(PurpleAccount *account, WithPrekeyClient cb,
                                    void *uctx) {
  otrng_client_s *client =
      otrng_client_get(otrng_state, purple_account_to_client_id(account));
  if (!client) {
    cb(account, client, NULL, uctx);
  } else {
    otrng_client_ensure_correct_state(client);
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
  otrng_prekey_client_s *prekey_client = NULL;

  prekey_client = get_cached_prekey_client(account);
  if (!prekey_client) {
    return FALSE;
  }

  return otrng_prekey_client_receive(tosend, server, message, prekey_client);
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
    printf("\n No connection. \n");
    return;
  }

  prekey_client->callbacks->ctx = account;

  message = otrng_prekey_client_request_storage_information(prekey_client);

  // 1. Publish prekeys
  // message = otrng_prekey_client_publish_prekeys(prekey_client);

  // 2. Retrieve the status of storage for yourself
  // message = otrng_prekey_client_request_storage_information(prekey_client);

  serv_send_im(connection, prekey_client->server_identity, message, 0);
  free(message);
}

static void account_signed_on_cb(PurpleConnection *conn, void *data) {
  otrng_plugin_get_prekey_client(purple_connection_get_account(conn),
                                 get_prekey_client_for_account_signed_on, NULL);
}

gboolean otrng_prekey_plugin_load(PurplePlugin *handle) {
  if (!otrng_state) {
    return FALSE;
  }

  /* Watch to the connect event of every account */
  purple_signal_connect(purple_connections_get_handle(), "signed-on", handle,
                        PURPLE_CALLBACK(account_signed_on_cb), NULL);

  /* Process received prekey protocol messages */
  purple_signal_connect(purple_conversations_get_handle(), "receiving-im-msg",
                        handle, PURPLE_CALLBACK(receiving_im_msg_cb), NULL);

  // Do the same on the already connected accounts
  // GList *connections = purple_connections_get_all();
  return TRUE;
}

gboolean otrng_prekey_plugin_unload(PurplePlugin *handle) {

  purple_signal_disconnect(purple_conversations_get_handle(),
                           "receiving-im-msg", handle,
                           PURPLE_CALLBACK(receiving_im_msg_cb));

  purple_signal_disconnect(purple_connections_get_handle(), "signed-on", handle,
                           PURPLE_CALLBACK(account_signed_on_cb));
  return TRUE;
}
